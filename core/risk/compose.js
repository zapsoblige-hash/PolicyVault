"use strict";

/*
 * PolicyVault risk adapter framework — DENY-WINS COMPOSITION.
 *
 * Composition semantics (Program D invariant 2, hard):
 *   DENY  wins over  REVIEW  wins over  ALLOW.
 *
 *   - An adapter error, timeout, or malformed/unknown verdict NEVER
 *     yields ALLOW: it is mapped through `onAdapterError`, which is
 *     validated to be REVIEW or DENY only.
 *   - An empty adapter set resolves through `onEmpty`; for an
 *     organization whose context declares `riskPolicy.reviewRequired`,
 *     the default is REVIEW and an explicit `onEmpty: "ALLOW"` is
 *     REFUSED as contradictory configuration.
 *   - Risk decisions can only RESTRICT: applyRiskToPolicyDecision is
 *     structurally incapable of returning ALLOW when the policy gate
 *     (SDK preflight / covenant rules) said DENY — there is no code
 *     path that consults the risk verdict once the policy decision is
 *     DENY. On-chain, the covenant enforces its rules regardless of
 *     anything this module returns.
 */

const {
  RISK_VERDICTS,
  VERDICT_ALLOW,
  VERDICT_REVIEW,
  VERDICT_DENY,
  RiskRefusal,
  requireJsonSafe,
  isPlainObject,
  validateAdapterDefinition,
  validateVerdictResult
} = require("./interface");

const POLICY_ALLOW = "ALLOW";
const POLICY_DENY = "DENY";
const POLICY_DECISIONS = Object.freeze([POLICY_ALLOW, POLICY_DENY]);

const DEFAULT_TIMEOUT_MS = 5_000;

function refuse(code, message) {
  throw new RiskRefusal(code, message);
}

/*
 * Composition configuration. Unknown values refuse; `onAdapterError`
 * may not be ALLOW under any configuration (an erroring control never
 * silently allows).
 */
function normalizeCompositionConfig(config = {}, context = undefined) {
  if (!isPlainObject(config)) {
    refuse("RISK_CONFIG_INVALID", "composition config must be a plain object");
  }
  const allowed = new Set(["onAdapterError", "onEmpty", "timeoutMs"]);
  for (const key of Object.keys(config)) {
    if (!allowed.has(key)) {
      refuse("RISK_CONFIG_INVALID", `unknown composition config field ${JSON.stringify(key)} — unknown fields fail closed`);
    }
  }

  let reviewRequired = false;
  if (context !== undefined && context !== null) {
    if (!isPlainObject(context)) {
      refuse("RISK_CONTEXT_INVALID", "organizationContext must be a plain object");
    }
    const rp = context.riskPolicy;
    if (rp !== undefined) {
      if (!isPlainObject(rp)) {
        refuse("RISK_CONTEXT_INVALID", "organizationContext.riskPolicy must be a plain object");
      }
      if (rp.reviewRequired !== undefined && typeof rp.reviewRequired !== "boolean") {
        refuse("RISK_CONTEXT_INVALID", "organizationContext.riskPolicy.reviewRequired must be a boolean");
      }
      reviewRequired = rp.reviewRequired === true;
    }
  }

  const onAdapterError = config.onAdapterError === undefined ? VERDICT_REVIEW : config.onAdapterError;
  if (onAdapterError !== VERDICT_REVIEW && onAdapterError !== VERDICT_DENY) {
    refuse(
      "RISK_CONFIG_INVALID",
      `onAdapterError must be REVIEW or DENY (got ${JSON.stringify(config.onAdapterError)}) — an erroring adapter may never resolve to ALLOW`
    );
  }

  const onEmpty = config.onEmpty === undefined ? (reviewRequired ? VERDICT_REVIEW : VERDICT_ALLOW) : config.onEmpty;
  if (!RISK_VERDICTS.includes(onEmpty)) {
    refuse("RISK_CONFIG_INVALID", `onEmpty must be one of ${RISK_VERDICTS.join("|")} (got ${JSON.stringify(config.onEmpty)})`);
  }
  if (reviewRequired && onEmpty === VERDICT_ALLOW) {
    refuse(
      "RISK_CONFIG_CONFLICT",
      "organizationContext.riskPolicy.reviewRequired is true but onEmpty is ALLOW — a review-required organization may not silently allow with no adapters configured"
    );
  }

  const timeoutMs = config.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : config.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) {
    refuse("RISK_CONFIG_INVALID", "timeoutMs must be an integer in [1, 600000]");
  }

  return Object.freeze({ onAdapterError, onEmpty, timeoutMs, reviewRequired });
}

/* Pure deny-wins fold over a non-empty verdict list. Unknown refuse. */
function composeVerdicts(verdicts) {
  if (!Array.isArray(verdicts) || verdicts.length === 0) {
    refuse("RISK_COMPOSE_INVALID", "composeVerdicts requires a non-empty verdict array (the empty set resolves through onEmpty)");
  }
  let decision = VERDICT_ALLOW;
  for (const v of verdicts) {
    if (!RISK_VERDICTS.includes(v)) {
      refuse("ADAPTER_VERDICT_UNKNOWN", `unknown verdict ${JSON.stringify(v)} — verdicts are exactly ${RISK_VERDICTS.join("|")}`);
    }
    if (v === VERDICT_DENY) decision = VERDICT_DENY;
    else if (v === VERDICT_REVIEW && decision === VERDICT_ALLOW) decision = VERDICT_REVIEW;
  }
  return decision;
}

/* Deep-freeze a structured clone so no adapter can mutate the intent or
 * context seen by other adapters or by the caller. */
function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      deepFreeze(value[key]);
    }
    Object.freeze(value);
  }
  return value;
}

function runWithTimeout(evaluate, intent, context, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve({ outcome: "TIMEOUT" });
      }
    }, timeoutMs);
    let p;
    try {
      p = Promise.resolve(evaluate(intent, context));
    } catch (err) {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        resolve({ outcome: "ERROR", error: err });
      }
      return;
    }
    p.then(
      (value) => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          resolve({ outcome: "OK", value });
        }
      },
      (err) => {
        clearTimeout(timer);
        if (!settled) {
          settled = true;
          resolve({ outcome: "ERROR", error: err });
        }
      }
    );
  });
}

/*
 * Evaluate a transaction intent against a set of adapters and compose.
 *
 *   evaluateRisk({ adapters, intent, context, config })
 *     -> { decision, results, codes, config }
 *
 * Every adapter runs (no short-circuit) so the audit record carries the
 * complete set of reasons; composition happens after. Results keep the
 * adapter order. Adapters receive a deep-frozen structured clone of the
 * intent manifest and organization context — data only, never key
 * material (none exists server-side: docs/hosted-threat-model.md §3).
 */
async function evaluateRisk({ adapters, intent, context = {}, config = {} } = {}) {
  if (!Array.isArray(adapters)) {
    refuse("RISK_COMPOSE_INVALID", "adapters must be an array of adapter definitions");
  }
  const defs = adapters.map((d) => validateAdapterDefinition(d));
  const names = new Set();
  for (const d of defs) {
    if (names.has(d.name)) {
      refuse("ADAPTER_DUPLICATE", `adapter ${d.name} appears twice in the evaluation set`);
    }
    names.add(d.name);
  }

  if (!isPlainObject(intent)) {
    refuse("RISK_INTENT_INVALID", "transactionIntent must be a plain object (the intent manifest)");
  }
  requireJsonSafe(intent, "intent");
  const normalizedConfig = normalizeCompositionConfig(config, context);
  if (context !== undefined && context !== null) {
    requireJsonSafe(context, "context");
  }

  const frozenIntent = deepFreeze(structuredClone(intent));
  const frozenContext = deepFreeze(structuredClone(context ?? {}));

  if (defs.length === 0) {
    return Object.freeze({
      decision: normalizedConfig.onEmpty,
      results: Object.freeze([]),
      codes: Object.freeze(normalizedConfig.onEmpty === VERDICT_ALLOW ? [] : ["RISK_ADAPTER_SET_EMPTY"]),
      config: normalizedConfig
    });
  }

  const results = await Promise.all(
    defs.map(async (def) => {
      const timeoutMs = def.timeoutMs ?? normalizedConfig.timeoutMs;
      const run = await runWithTimeout(def.evaluate, frozenIntent, frozenContext, timeoutMs);
      if (run.outcome === "OK") {
        try {
          const validated = validateVerdictResult(run.value, def.name);
          return Object.freeze({
            adapter: def.name,
            adapterVersion: def.adapterVersion,
            status: "OK",
            verdict: validated.verdict,
            reasons: validated.reasons
          });
        } catch (err) {
          return Object.freeze({
            adapter: def.name,
            adapterVersion: def.adapterVersion,
            status: "ERROR",
            errorCode: err && err.code === "ADAPTER_VERDICT_UNKNOWN" ? "ADAPTER_VERDICT_UNKNOWN" : "ADAPTER_VERDICT_INVALID",
            verdict: normalizedConfig.onAdapterError,
            reasons: Object.freeze([
              Object.freeze({
                code: "ADAPTER_VERDICT_INVALID",
                message: `adapter ${def.name} returned an invalid verdict result and was mapped to ${normalizedConfig.onAdapterError} (never ALLOW): ${err.message}`
              })
            ])
          });
        }
      }
      if (run.outcome === "TIMEOUT") {
        return Object.freeze({
          adapter: def.name,
          adapterVersion: def.adapterVersion,
          status: "TIMEOUT",
          errorCode: "ADAPTER_TIMEOUT",
          verdict: normalizedConfig.onAdapterError,
          reasons: Object.freeze([
            Object.freeze({
              code: "ADAPTER_TIMEOUT",
              message: `adapter ${def.name} exceeded ${timeoutMs}ms and was mapped to ${normalizedConfig.onAdapterError} (never ALLOW)`
            })
          ])
        });
      }
      return Object.freeze({
        adapter: def.name,
        adapterVersion: def.adapterVersion,
        status: "ERROR",
        errorCode: "ADAPTER_ERROR",
        verdict: normalizedConfig.onAdapterError,
        reasons: Object.freeze([
          Object.freeze({
            code: "ADAPTER_ERROR",
            message: `adapter ${def.name} threw and was mapped to ${normalizedConfig.onAdapterError} (never ALLOW): ${run.error && run.error.message ? run.error.message : "unknown error"}`
          })
        ])
      });
    })
  );

  const decision = composeVerdicts(results.map((r) => r.verdict));
  const codes = [...new Set(results.flatMap((r) => r.reasons.map((reason) => reason.code)))].sort();

  return Object.freeze({
    decision,
    results: Object.freeze(results),
    codes: Object.freeze(codes),
    config: normalizedConfig
  });
}

/*
 * THE POLICY GATE (invariant 2, structural form).
 *
 * `policyDecision` is the outcome of PolicyVault's own policy pipeline
 * (SDK preflight mirroring covenant rules; ultimately Kaspa consensus
 * itself). `riskDecision` is the composed adapter outcome. The result
 * can only be MORE restrictive than the policy decision:
 *
 *   policy DENY  -> DENY (risk is never consulted; no branch exists
 *                   that can return anything else)
 *   policy ALLOW -> the risk decision (ALLOW passes, REVIEW holds for
 *                   humans, DENY refuses)
 *
 * Unknown inputs refuse. There is no configuration, flag, or verdict
 * value that upgrades a policy DENY.
 */
function applyRiskToPolicyDecision({ policyDecision, riskDecision } = {}) {
  if (!POLICY_DECISIONS.includes(policyDecision)) {
    refuse(
      "POLICY_DECISION_UNKNOWN",
      `policyDecision must be one of ${POLICY_DECISIONS.join("|")} (got ${JSON.stringify(policyDecision)}) — unknown decisions fail closed`
    );
  }
  if (policyDecision === POLICY_DENY) {
    /* Covenant/policy denial is final. The risk verdict — including
     * ALLOW — is intentionally not consulted on this branch. */
    return Object.freeze({ final: POLICY_DENY, source: "policy" });
  }
  if (!RISK_VERDICTS.includes(riskDecision)) {
    refuse(
      "ADAPTER_VERDICT_UNKNOWN",
      `riskDecision must be one of ${RISK_VERDICTS.join("|")} (got ${JSON.stringify(riskDecision)}) — unknown verdicts fail closed`
    );
  }
  return Object.freeze({ final: riskDecision, source: riskDecision === VERDICT_ALLOW ? "policy+risk" : "risk" });
}

module.exports = {
  POLICY_ALLOW,
  POLICY_DENY,
  POLICY_DECISIONS,
  DEFAULT_TIMEOUT_MS,
  normalizeCompositionConfig,
  composeVerdicts,
  evaluateRisk,
  applyRiskToPolicyDecision
};
