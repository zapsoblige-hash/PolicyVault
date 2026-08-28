"use strict";

/*
 * PolicyVault post-launch risk adapter framework (Program D) — adapter
 * contract + strict validation. Design: docs/postlaunch/risk-adapter-spec.md.
 *
 * INVARIANT (hard, stated everywhere): off-chain risk/compliance
 * adapters may make PolicyVault MORE restrictive; they may NEVER
 * override a covenant denial and never substitute for covenant
 * verification. An adapter verdict is advice consumed BEFORE signing/
 * submission; Kaspa consensus neither knows nor cares that adapters
 * exist. A risk ALLOW never bypasses policy (see compose.js
 * applyRiskToPolicyDecision — structurally incapable of upgrading a
 * policy DENY).
 *
 * Fail-closed rules:
 *   - unknown adapter contract versions REFUSE at registration;
 *   - unknown/missing verdict strings REFUSE at evaluation (they are
 *     handled as adapter errors, which can only produce REVIEW or DENY);
 *   - a REVIEW/DENY verdict must carry at least one structured reason;
 *   - verdict payloads must be JSON-safe: BigInt refuses (consensus
 *     amounts travel as base-10 decimal strings), non-finite numbers
 *     refuse, undefined/functions/non-plain objects refuse.
 */

const RISK_ADAPTER_CONTRACT_VERSION = "policyvault-risk-adapter/1";

const VERDICT_ALLOW = "ALLOW";
const VERDICT_REVIEW = "REVIEW";
const VERDICT_DENY = "DENY";
const RISK_VERDICTS = Object.freeze([VERDICT_ALLOW, VERDICT_REVIEW, VERDICT_DENY]);

/*
 * Integration capability catalogue (informational routing metadata —
 * capabilities grant nothing). Extensions must use the "x-" prefix;
 * anything else unknown refuses.
 */
const ADAPTER_CAPABILITIES = Object.freeze([
  "kyt", //             know-your-transaction chain analytics
  "aml", //             anti-money-laundering screening
  "sanctions", //       sanctions / watchlist address screening
  "fraud-scoring", //   behavioral fraud / anomaly scores
  "vendor-validation", // vendor master-data match
  "erp", //             ERP integration (PO / three-way match)
  "procurement", //     procurement workflow checks
  "invoice", //         invoice validation
  "accounting", //      accounting / ledger-coding checks
  "custom-policy", //   custom enterprise policy APIs
  "ai-classifier" //    AI/ML transaction classifiers
]);

class RiskRefusal extends Error {
  constructor(code, message) {
    super(`risk: ${message}`);
    this.name = "RiskRefusal";
    this.code = code;
    this.failClosed = true;
  }
}

function refuse(code, message) {
  throw new RiskRefusal(code, message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/*
 * JSON-safety walk for adapter inputs and outputs. Refuses BigInt
 * (amounts must already be decimal strings), undefined, functions,
 * symbols, non-finite numbers, and non-plain objects. Finite numbers
 * are permitted for non-consensus quantities (scores, counts); sompi
 * amounts MUST be decimal strings — spec rule, enforced at the intent
 * builders that produce manifests.
 */
function requireJsonSafe(value, path) {
  if (value === null) return;
  const t = typeof value;
  if (t === "string" || t === "boolean") return;
  if (t === "number") {
    if (!Number.isFinite(value)) refuse("JSON_UNSAFE", `non-finite number at ${path} — failing closed`);
    return;
  }
  if (t === "bigint") refuse("JSON_UNSAFE", `BigInt at ${path} — consensus integers must travel as decimal strings`);
  if (t === "undefined") refuse("JSON_UNSAFE", `undefined at ${path}`);
  if (t === "function" || t === "symbol") refuse("JSON_UNSAFE", `${t} at ${path} — not JSON`);
  if (Array.isArray(value)) {
    value.forEach((v, i) => requireJsonSafe(v, `${path}[${i}]`));
    return;
  }
  if (t === "object") {
    if (!isPlainObject(value)) refuse("JSON_UNSAFE", `non-plain object at ${path} — refusing`);
    for (const key of Object.keys(value)) {
      requireJsonSafe(value[key], `${path}.${key}`);
    }
    return;
  }
  refuse("JSON_UNSAFE", `unsupported type ${t} at ${path}`);
}

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/*
 * Validate one adapter definition. Returns a frozen normalized
 * definition; refuses on anything unknown or malformed.
 *
 *   { name, adapterVersion, contractVersion, capabilities, evaluate,
 *     timeoutMs? }
 */
function validateAdapterDefinition(def) {
  if (!isPlainObject(def)) {
    refuse("ADAPTER_DEFINITION_INVALID", "adapter definition must be a plain object");
  }
  const allowed = new Set(["name", "adapterVersion", "contractVersion", "capabilities", "evaluate", "timeoutMs"]);
  for (const key of Object.keys(def)) {
    if (!allowed.has(key)) {
      refuse("ADAPTER_DEFINITION_INVALID", `unknown adapter definition field ${JSON.stringify(key)} — unknown fields fail closed`);
    }
  }
  if (typeof def.name !== "string" || !NAME_RE.test(def.name)) {
    refuse("ADAPTER_DEFINITION_INVALID", "adapter name must match /^[a-z0-9][a-z0-9-]{0,63}$/");
  }
  if (def.contractVersion !== RISK_ADAPTER_CONTRACT_VERSION) {
    refuse(
      "ADAPTER_CONTRACT_UNKNOWN",
      `adapter ${def.name} declares contract ${JSON.stringify(def.contractVersion)} — only ${RISK_ADAPTER_CONTRACT_VERSION} is supported; unknown contract versions fail closed`
    );
  }
  if (typeof def.adapterVersion !== "string" || def.adapterVersion.length === 0 || def.adapterVersion.length > 64) {
    refuse("ADAPTER_DEFINITION_INVALID", `adapter ${def.name} must declare a non-empty adapterVersion string`);
  }
  if (!Array.isArray(def.capabilities) || def.capabilities.length === 0) {
    refuse("ADAPTER_DEFINITION_INVALID", `adapter ${def.name} must declare a non-empty capabilities array`);
  }
  const capabilities = def.capabilities.map((c) => {
    if (typeof c !== "string" || (!ADAPTER_CAPABILITIES.includes(c) && !/^x-[a-z0-9][a-z0-9-]{0,61}$/.test(c))) {
      refuse(
        "ADAPTER_CAPABILITY_UNKNOWN",
        `adapter ${def.name} declares unknown capability ${JSON.stringify(c)} — known: ${ADAPTER_CAPABILITIES.join(", ")} (or an "x-" extension); unknown capabilities fail closed`
      );
    }
    return c;
  });
  if (typeof def.evaluate !== "function") {
    refuse("ADAPTER_DEFINITION_INVALID", `adapter ${def.name} must provide an evaluate(intent, context) function`);
  }
  let timeoutMs;
  if (def.timeoutMs !== undefined) {
    if (!Number.isSafeInteger(def.timeoutMs) || def.timeoutMs < 1 || def.timeoutMs > 600_000) {
      refuse("ADAPTER_DEFINITION_INVALID", `adapter ${def.name} timeoutMs must be an integer in [1, 600000]`);
    }
    timeoutMs = def.timeoutMs;
  }
  return Object.freeze({
    name: def.name,
    adapterVersion: def.adapterVersion,
    contractVersion: def.contractVersion,
    capabilities: Object.freeze(capabilities),
    evaluate: def.evaluate,
    ...(timeoutMs !== undefined ? { timeoutMs } : {})
  });
}

/*
 * Validate one adapter's verdict result. Exact shape:
 *   { verdict: "ALLOW"|"REVIEW"|"DENY", reasons: [{code, message, evidence?}] }
 * Unknown verdict strings, unknown result fields, or a restrictive
 * verdict without a reason all REFUSE (the caller maps refusals through
 * the error policy, which can only yield REVIEW or DENY — never ALLOW).
 */
function validateVerdictResult(raw, adapterName) {
  if (!isPlainObject(raw)) {
    refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} returned a non-object verdict result`);
  }
  const allowed = new Set(["verdict", "reasons"]);
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} returned unknown result field ${JSON.stringify(key)} — unknown fields fail closed`);
    }
  }
  if (!RISK_VERDICTS.includes(raw.verdict)) {
    refuse(
      "ADAPTER_VERDICT_UNKNOWN",
      `adapter ${adapterName} returned unknown verdict ${JSON.stringify(raw.verdict)} — verdicts are exactly ${RISK_VERDICTS.join("|")}; unknown verdicts fail closed`
    );
  }
  if (!Array.isArray(raw.reasons)) {
    refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} must return a reasons array`);
  }
  const reasons = raw.reasons.map((r, i) => {
    if (!isPlainObject(r)) {
      refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} reasons[${i}] must be an object`);
    }
    const reasonAllowed = new Set(["code", "message", "evidence"]);
    for (const key of Object.keys(r)) {
      if (!reasonAllowed.has(key)) {
        refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} reasons[${i}] has unknown field ${JSON.stringify(key)}`);
      }
    }
    if (typeof r.code !== "string" || !/^[A-Z0-9_]{1,64}$/.test(r.code)) {
      refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} reasons[${i}].code must match /^[A-Z0-9_]{1,64}$/`);
    }
    if (typeof r.message !== "string" || r.message.length === 0 || r.message.length > 2000) {
      refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} reasons[${i}].message must be a non-empty string (max 2000 chars)`);
    }
    if (r.evidence !== undefined) {
      requireJsonSafe(r.evidence, `adapter ${adapterName} reasons[${i}].evidence`);
    }
    return Object.freeze({ code: r.code, message: r.message, ...(r.evidence !== undefined ? { evidence: r.evidence } : {}) });
  });
  if ((raw.verdict === VERDICT_REVIEW || raw.verdict === VERDICT_DENY) && reasons.length === 0) {
    refuse("ADAPTER_VERDICT_INVALID", `adapter ${adapterName} returned ${raw.verdict} with no reasons — a restriction must be explainable`);
  }
  return Object.freeze({ verdict: raw.verdict, reasons: Object.freeze(reasons) });
}

/* Ordered adapter registry; duplicate names refuse. */
function createAdapterRegistry() {
  const byName = new Map();
  return Object.freeze({
    register(def) {
      const normalized = validateAdapterDefinition(def);
      if (byName.has(normalized.name)) {
        refuse("ADAPTER_DUPLICATE", `adapter ${normalized.name} is already registered`);
      }
      byName.set(normalized.name, normalized);
      return normalized;
    },
    get(name) {
      return byName.get(name);
    },
    list() {
      return Object.freeze([...byName.values()]);
    },
    size() {
      return byName.size;
    }
  });
}

module.exports = {
  RISK_ADAPTER_CONTRACT_VERSION,
  RISK_VERDICTS,
  VERDICT_ALLOW,
  VERDICT_REVIEW,
  VERDICT_DENY,
  ADAPTER_CAPABILITIES,
  RiskRefusal,
  requireJsonSafe,
  isPlainObject,
  validateAdapterDefinition,
  validateVerdictResult,
  createAdapterRegistry
};
