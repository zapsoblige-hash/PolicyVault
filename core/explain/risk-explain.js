"use strict";

function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}


/*
 * PolicyVault risk-evaluation EXPLANATIONS (v1).
 *
 * Turns a risk evaluation document — the core/risk `evaluateRisk` result
 * ({ decision, results, codes, config }) or the server's stored/presented
 * evaluation record (server/src/risk.js, schema
 * "policyvault-risk-evaluation/v1": the same four fields plus
 * schema/status/ids) — into:
 *
 *   structured(evaluation)    -> "policyvault-risk-explanation/1"
 *   humanReadable(evaluation) -> deterministic English lines
 *
 * THIS RENDERS; IT NEVER RE-DECIDES RISK. Every line narrates fields the
 * risk pipeline already computed (docs/postlaunch/risk-adapter-spec.md
 * §5.4). Risk adapters are RESTRICTIVE-ONLY hosted coordination: a risk
 * ALLOW authorizes nothing, and no risk verdict can override a policy
 * DENY (core/risk/compose.js applyRiskToPolicyDecision is structurally
 * incapable of it). The covenant remains the only security boundary.
 *
 * FAIL-CLOSED RULES (the governance-explain §7.1 stored-label-distrust
 * pattern, applied to every SELF-CONSISTENCY property of the record
 * that is recomputable from the record itself):
 *   - The composed `decision` is RECOMPUTED from the stored per-adapter
 *     verdicts with the deny-wins fold (DENY > REVIEW > ALLOW); any
 *     divergence refuses (DECISION_MISMATCH — a tampered stored decision
 *     is never narrated).
 *   - The `codes` list is RECOMPUTED (sorted unique reason codes; for an
 *     empty adapter set, [] on ALLOW / ["RISK_ADAPTER_SET_EMPTY"]
 *     otherwise); divergence refuses (CODES_MISMATCH).
 *   - An ERROR/TIMEOUT result whose resolved verdict is ALLOW refuses
 *     (ERROR_PATH_ALLOW — spec §5.2: an erroring control never resolves
 *     permissive); when the composition config is present the resolved
 *     verdict must equal config.onAdapterError.
 *   - A stored lifecycle `status` inconsistent with the decision refuses
 *     (STATUS_MISMATCH: ALLOWED⇔ALLOW, DENIED⇔DENY, REVIEW_HELD/
 *     RELEASED⇔REVIEW, CONSUMED⇔ALLOW|REVIEW).
 *   - Unknown decisions, verdicts, statuses, schema versions, and
 *     malformed entries refuse. Both entry points are TOTAL: they never
 *     throw; malformed input and internal errors produce a REFUSAL
 *     explanation.
 *
 * INTEGRITY BOUNDARY (stated honestly — carried in every explanation):
 * unlike a governance classification, which every consumer recomputes
 * from the proposal's before/after tuples, the per-adapter verdicts are
 * stored EVIDENCE of past adapter executions — they are not
 * re-derivable in this runtime (the adapters ran elsewhere, earlier).
 * What this module verifies is the record's SELF-CONSISTENCY (decision,
 * codes, error semantics, status all recomputed/cross-checked from the
 * per-adapter results); a record forged consistently in every field is
 * not detectable here. The `intent`↔`intentHash` binding is separately
 * re-verified server-side before any released hold is trusted
 * (server/src/risk.js assertEvaluationIntegrity), and none of this is
 * covenant authority: even a fully forged risk record can only
 * coordinate — it cannot move funds past the covenant.
 *
 * Portable shared core: pure CommonJS, zero dependencies (not even
 * core/risk — the verdict vocabulary is mirrored here as frozen
 * constants so the module stays dependency-free in the browser bundle;
 * core/explain/test pins the mirror against core/risk's exports).
 */

const RISK_EXPLANATION_VERSION_1 = "policyvault-risk-explanation/1";

const RISK_EXPLANATION_VERDICTS = Object.freeze({
  EXPLAINED: "EXPLAINED",
  REFUSED: "REFUSED"
});

/* Mirrors of the core/risk vocabulary (pinned by core/explain/test). */
const DECISION_ALLOW = "ALLOW";
const DECISION_REVIEW = "REVIEW";
const DECISION_DENY = "DENY";
const RISK_DECISIONS = Object.freeze([DECISION_ALLOW, DECISION_REVIEW, DECISION_DENY]);
const RESULT_STATUSES = Object.freeze(["OK", "ERROR", "TIMEOUT"]);
const EVALUATION_SCHEMA_V1 = "policyvault-risk-evaluation/v1";
const LIFECYCLE_STATUSES = Object.freeze(["ALLOWED", "DENIED", "REVIEW_HELD", "RELEASED", "CONSUMED"]);
const EMPTY_SET_CODE = "RISK_ADAPTER_SET_EMPTY";

const TRUST_NOTE =
  "This explanation renders a stored risk evaluation; it grants nothing and decides nothing. Risk adapters are restrictive-only hosted coordination: a risk ALLOW never authorizes a spend (the SDK policy preflight and ultimately the Kaspa covenant decide independently), and no risk verdict can override a policy DENY. The composed decision, reason codes, and error semantics were recomputed from the stored per-adapter results before rendering — a divergent record refuses — but the per-adapter verdicts themselves are stored evidence of past adapter executions, not re-derivable in this runtime.";

const HEADLINES = Object.freeze({
  [DECISION_ALLOW]:
    "RISK ALLOW: no configured risk control added a restriction — the operation may proceed to PolicyVault's own policy pipeline (which decides independently).",
  [DECISION_REVIEW]:
    "RISK REVIEW: this operation is held for human review — an authorized reviewer (never the acting signer) must release the EXACT reviewed intent before it can proceed.",
  [DECISION_DENY]:
    "RISK DENY: the organization's risk controls refuse this operation. A denial is final for this evaluation — it cannot be released; if it is wrong, change the organization's risk configuration and submit a fresh request."
});

const STATUS_LINES = Object.freeze({
  ALLOWED: "Evaluation status: ALLOWED — recorded as durable evidence; no hold exists.",
  DENIED: "Evaluation status: DENIED — final for this evaluation.",
  REVIEW_HELD: "Evaluation status: REVIEW_HELD — waiting for an authorized reviewer's release (the acting signer can never release their own hold).",
  RELEASED: "Evaluation status: RELEASED — an authorized reviewer released the exact reviewed intent; it may execute once (a changed intent is a new evaluation).",
  CONSUMED: "Evaluation status: CONSUMED — a real build consumed this evaluation."
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isObjectLike(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isHex64(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

const ADAPTER_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/; // core/risk/interface.js NAME_RE
const REASON_CODE_RE = /^[A-Z0-9_]{1,64}$/; // core/risk/interface.js reason-code rule

function refusalDocument(reason, failures) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  return deepFreeze({
    explanationVersion: RISK_EXPLANATION_VERSION_1,
    verdict: RISK_EXPLANATION_VERDICTS.REFUSED,
    refusal: { reason: String(reason), codes, failures: failures.map((f) => ({ code: String(f.code), detail: String(f.detail) })) },
    decision: null,
    status: null,
    evaluationId: null,
    intentHash: null,
    adapterCount: null,
    errorCount: null,
    reviewRequired: null,
    emptyAdapterSet: null,
    headline: null,
    perAdapter: null,
    codes: null,
    note: TRUST_NOTE
  });
}

/* Pure deny-wins fold — the exact core/risk/compose.js composeVerdicts
 * semantics, re-stated locally so this module stays dependency-free
 * (equality with core/risk is pinned by core/explain/test). Verdicts are
 * validated upstream. */
function denyWins(verdicts) {
  let decision = DECISION_ALLOW;
  for (const v of verdicts) {
    if (v === DECISION_DENY) decision = DECISION_DENY;
    else if (v === DECISION_REVIEW && decision === DECISION_ALLOW) decision = DECISION_REVIEW;
  }
  return decision;
}

/* ------------------------------------------------------------------ */
/* strict validation of the evaluation document                        */
/* ------------------------------------------------------------------ */

/* Returns { problems: [{code, detail}] }. */
function validateEvaluation(evaluation) {
  const problems = [];
  const push = (code, detail) => problems.push({ code, detail });

  if (!isObjectLike(evaluation)) {
    push("INVALID_EVALUATION", "the evaluation must be the object returned by core/risk evaluateRisk or the server's stored risk-evaluation record");
    return { problems };
  }

  if (Object.prototype.hasOwnProperty.call(evaluation, "schema") && evaluation.schema !== EVALUATION_SCHEMA_V1) {
    push("UNKNOWN_SCHEMA_VERSION", `evaluation schema ${JSON.stringify(evaluation.schema)} is unknown — unknown versions fail closed`);
  }
  if (!RISK_DECISIONS.includes(evaluation.decision)) {
    push("UNKNOWN_DECISION", `decision ${JSON.stringify(evaluation.decision)} is unknown — decisions are exactly ${RISK_DECISIONS.join("|")}; failing closed`);
  }
  if (!Array.isArray(evaluation.results)) {
    push("INVALID_EVALUATION", "results must be an array of per-adapter results");
  }
  if (!Array.isArray(evaluation.codes) || evaluation.codes.some((c) => typeof c !== "string")) {
    push("INVALID_EVALUATION", "codes must be an array of strings");
  }

  /* Optional composition config (always present on real producer output;
   * validated strictly when present). */
  let config = null;
  if (evaluation.config !== undefined && evaluation.config !== null) {
    if (!isObjectLike(evaluation.config)) {
      push("INVALID_EVALUATION", "config must be the composition-config object when present");
    } else {
      config = evaluation.config;
      const allowed = new Set(["onAdapterError", "onEmpty", "timeoutMs", "reviewRequired"]);
      for (const k of Object.keys(config)) {
        if (!allowed.has(k)) push("INVALID_EVALUATION", `config has unknown field ${JSON.stringify(k)} — unknown fields fail closed`);
      }
      if (config.onAdapterError !== DECISION_REVIEW && config.onAdapterError !== DECISION_DENY) {
        push("INVALID_EVALUATION", `config.onAdapterError must be REVIEW or DENY (got ${JSON.stringify(config.onAdapterError)}) — an erroring adapter may never resolve to ALLOW`);
      }
      if (!RISK_DECISIONS.includes(config.onEmpty)) {
        push("INVALID_EVALUATION", `config.onEmpty must be one of ${RISK_DECISIONS.join("|")}`);
      }
      if (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 600000) {
        push("INVALID_EVALUATION", "config.timeoutMs must be an integer in [1, 600000]");
      }
      if (typeof config.reviewRequired !== "boolean") {
        push("INVALID_EVALUATION", "config.reviewRequired must be a boolean");
      }
    }
  }

  /* Optional server-record fields. */
  if (Object.prototype.hasOwnProperty.call(evaluation, "status") && evaluation.status !== undefined && evaluation.status !== null) {
    if (!LIFECYCLE_STATUSES.includes(evaluation.status)) {
      push("UNKNOWN_STATUS", `evaluation status ${JSON.stringify(evaluation.status)} is unknown — statuses are exactly ${LIFECYCLE_STATUSES.join("|")}; failing closed`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "intentHash") && evaluation.intentHash !== undefined && evaluation.intentHash !== null && !isHex64(evaluation.intentHash)) {
    push("INVALID_EVALUATION", "intentHash must be 32-byte lowercase hex when present");
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "evaluationId") && evaluation.evaluationId !== undefined && evaluation.evaluationId !== null && (typeof evaluation.evaluationId !== "string" || evaluation.evaluationId.length === 0 || evaluation.evaluationId.length > 128)) {
    push("INVALID_EVALUATION", "evaluationId must be a non-empty string when present");
  }

  /* Per-adapter results. */
  if (Array.isArray(evaluation.results)) {
    evaluation.results.forEach((r, i) => {
      if (!isObjectLike(r)) {
        push("INVALID_EVALUATION", `results[${i}] must be an object`);
        return;
      }
      if (typeof r.adapter !== "string" || !ADAPTER_NAME_RE.test(r.adapter)) {
        push("INVALID_EVALUATION", `results[${i}].adapter must be an adapter name (/^[a-z0-9][a-z0-9-]{0,63}$/)`);
      }
      if (typeof r.adapterVersion !== "string" || r.adapterVersion.length === 0 || r.adapterVersion.length > 64) {
        push("INVALID_EVALUATION", `results[${i}].adapterVersion must be a non-empty string`);
      }
      if (!RESULT_STATUSES.includes(r.status)) {
        push("UNKNOWN_RESULT_STATUS", `results[${i}].status ${JSON.stringify(r.status)} is unknown — statuses are exactly ${RESULT_STATUSES.join("|")}; failing closed`);
        return; // status-dependent rules below would be meaningless
      }
      if (!RISK_DECISIONS.includes(r.verdict)) {
        push("UNKNOWN_VERDICT", `results[${i}].verdict ${JSON.stringify(r.verdict)} is unknown — verdicts are exactly ${RISK_DECISIONS.join("|")}; failing closed`);
        return;
      }
      if (!Array.isArray(r.reasons)) {
        push("INVALID_EVALUATION", `results[${i}].reasons must be an array`);
        return;
      }
      r.reasons.forEach((reason, j) => {
        if (!isObjectLike(reason)) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}] must be an object`);
          return;
        }
        if (typeof reason.code !== "string" || !REASON_CODE_RE.test(reason.code)) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}].code must match /^[A-Z0-9_]{1,64}$/`);
        }
        if (typeof reason.message !== "string" || reason.message.length === 0 || reason.message.length > 2000) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}].message must be a non-empty string (max 2000 chars)`);
        }
      });
      if ((r.verdict === DECISION_REVIEW || r.verdict === DECISION_DENY) && r.reasons.length === 0) {
        push("INVALID_EVALUATION", `results[${i}] carries ${r.verdict} with no reasons — a restriction must be explainable (core/risk contract)`);
      }
      if (r.status === "ERROR" || r.status === "TIMEOUT") {
        if (typeof r.errorCode !== "string" || !REASON_CODE_RE.test(r.errorCode)) {
          push("INVALID_EVALUATION", `results[${i}] is ${r.status} but carries no machine errorCode`);
        }
        if (r.verdict === DECISION_ALLOW) {
          push("ERROR_PATH_ALLOW", `results[${i}] (adapter ${r.adapter}) is ${r.status} yet resolved to ALLOW — an erroring risk control never resolves permissive (risk-adapter-spec §5.2); integrity alarm, failing closed`);
        } else if (config && config.onAdapterError !== undefined && r.verdict !== config.onAdapterError) {
          push("ERROR_POLICY_MISMATCH", `results[${i}] (adapter ${r.adapter}) is ${r.status} and resolved to ${r.verdict}, but the stored error policy is ${config.onAdapterError} — integrity alarm, failing closed`);
        }
      } else if (r.errorCode !== undefined && r.errorCode !== null) {
        push("INVALID_EVALUATION", `results[${i}] is OK but carries an errorCode`);
      }
    });

    /* RECOMPUTE the composed decision and codes — stored labels are never
     * trusted over recomputation (the §7.1 integrity-alarm rule). */
    if (problems.length === 0) {
      let expectedDecision;
      let expectedCodes;
      if (evaluation.results.length === 0) {
        if (!config) {
          push("INVALID_EVALUATION", "an empty-adapter-set evaluation carries no composition config — the onEmpty resolution cannot be cross-checked; failing closed");
        } else {
          expectedDecision = config.onEmpty;
          expectedCodes = config.onEmpty === DECISION_ALLOW ? [] : [EMPTY_SET_CODE];
          if (config.reviewRequired === true && config.onEmpty === DECISION_ALLOW) {
            push("INVALID_EVALUATION", "config declares reviewRequired with onEmpty ALLOW — contradictory configuration the composition core refuses to produce");
          }
        }
      } else {
        expectedDecision = denyWins(evaluation.results.map((r) => r.verdict));
        expectedCodes = [...new Set(evaluation.results.flatMap((r) => r.reasons.map((reason) => reason.code)))].sort();
      }
      if (expectedDecision !== undefined) {
        if (expectedDecision !== evaluation.decision) {
          push(
            "DECISION_MISMATCH",
            `stored decision ${evaluation.decision} diverges from the deny-wins recomputation ${expectedDecision} over the stored per-adapter verdicts — integrity alarm, failing closed`
          );
        }
        if (JSON.stringify(expectedCodes) !== JSON.stringify([...evaluation.codes].sort())) {
          push("CODES_MISMATCH", "stored codes diverge from the codes recomputed from the stored per-adapter reasons — integrity alarm, failing closed");
        }
      }
    }

    /* Lifecycle-status ⇔ decision consistency (server records). */
    if (problems.length === 0 && typeof evaluation.status === "string") {
      const d = evaluation.decision;
      const s = evaluation.status;
      const consistent =
        (s === "ALLOWED" && d === DECISION_ALLOW) ||
        (s === "DENIED" && d === DECISION_DENY) ||
        ((s === "REVIEW_HELD" || s === "RELEASED") && d === DECISION_REVIEW) ||
        (s === "CONSUMED" && (d === DECISION_ALLOW || d === DECISION_REVIEW));
      if (!consistent) {
        push("STATUS_MISMATCH", `stored lifecycle status ${s} is inconsistent with decision ${d} — integrity alarm, failing closed`);
      }
    }
  }

  return { problems };
}

/* ------------------------------------------------------------------ */
/* per-adapter descriptions                                            */
/* ------------------------------------------------------------------ */

function reasonsText(reasons) {
  return reasons.map((r) => `${r.code}: ${r.message}${r.evidence !== undefined ? " [structured evidence attached]" : ""}`).join("; ");
}

function describeResult(r) {
  const who = `Adapter ${r.adapter} (version ${r.adapterVersion})`;
  if (r.status === "OK") {
    if (r.verdict === DECISION_ALLOW) {
      return r.reasons.length === 0
        ? `${who} declined to add a restriction.`
        : `${who} declined to add a restriction — ${reasonsText(r.reasons)}.`;
    }
    return `${who} returned ${r.verdict} — ${reasonsText(r.reasons)}.`;
  }
  const failMode = r.status === "TIMEOUT" ? "TIMED OUT" : "FAILED";
  return `${who} ${failMode} (${r.errorCode}) and was resolved to ${r.verdict} by the organization's error policy — an erroring risk control never resolves to ALLOW. ${reasonsText(r.reasons)}.`;
}

/* ------------------------------------------------------------------ */
/* structured + human-readable                                         */
/* ------------------------------------------------------------------ */

/*
 * Structured risk explanation. TOTAL: never throws; refusal on
 * malformed/self-inconsistent input.
 */
function structured(evaluation) {
  try {
    const { problems } = validateEvaluation(evaluation);
    if (problems.length > 0) {
      return refusalDocument("The risk evaluation is malformed or self-inconsistent — failing closed.", problems);
    }

    const errorCount = evaluation.results.filter((r) => r.status !== "OK").length;
    const perAdapter = evaluation.results.map((r) => ({
      adapter: r.adapter,
      adapterVersion: r.adapterVersion,
      status: r.status,
      verdict: r.verdict,
      errorCode: r.status === "OK" ? null : r.errorCode,
      reasons: r.reasons.map((reason) => ({
        code: reason.code,
        message: reason.message,
        hasEvidence: reason.evidence !== undefined && reason.evidence !== null
      })),
      description: describeResult(r)
    }));

    return deepFreeze({
      explanationVersion: RISK_EXPLANATION_VERSION_1,
      verdict: RISK_EXPLANATION_VERDICTS.EXPLAINED,
      refusal: null,
      decision: evaluation.decision,
      status: typeof evaluation.status === "string" ? evaluation.status : null,
      evaluationId: typeof evaluation.evaluationId === "string" ? evaluation.evaluationId : null,
      intentHash: typeof evaluation.intentHash === "string" ? evaluation.intentHash : null,
      adapterCount: evaluation.results.length,
      errorCount,
      reviewRequired: evaluation.config ? evaluation.config.reviewRequired === true : null,
      emptyAdapterSet: evaluation.results.length === 0,
      headline: HEADLINES[evaluation.decision],
      perAdapter,
      codes: [...evaluation.codes].sort(),
      note: TRUST_NOTE
    });
  } catch (e) {
    return refusalDocument("The risk explanation engine failed internally — failing closed.", [
      { code: "EXPLAIN_INTERNAL", detail: `${e.message}` }
    ]);
  }
}

function refusalLines(doc) {
  const lines = [];
  lines.push("RISK EXPLANATION REFUSED — do not act on this evaluation rendering.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  lines.push(
    "Re-fetch the evaluation from the server; if the divergence persists the stored record is corrupt or tampered — treat it as an integrity alarm and as RESTRICTIVE, never as an ALLOW."
  );
  return lines;
}

/*
 * Deterministic English lines for the risk hold UI. TOTAL: never throws.
 * Same input -> byte-identical output.
 */
function humanReadable(evaluation) {
  const doc = structured(evaluation);
  if (doc.verdict === RISK_EXPLANATION_VERDICTS.REFUSED) {
    return deepFreeze(refusalLines(doc));
  }
  const lines = [];
  lines.push(doc.headline);
  if (doc.status !== null) lines.push(STATUS_LINES[doc.status]);
  if (doc.emptyAdapterSet) {
    lines.push(`No risk adapters were configured for this evaluation — the organization's empty-set policy resolved it to ${doc.decision}.`);
    if (doc.reviewRequired === true) {
      lines.push("This organization requires review (riskPolicy.reviewRequired), so an empty adapter set can never resolve to a silent ALLOW.");
    }
  } else {
    for (const r of doc.perAdapter) {
      lines.push(`${r.verdict}: ${r.description}`);
    }
    lines.push(
      `Composition is deny-wins (DENY over REVIEW over ALLOW) across ${doc.adapterCount} adapter result(s); the composed decision above was recomputed from the stored per-adapter verdicts before rendering — a record whose stored decision diverges refuses to render.`
    );
  }
  if (doc.codes.length > 0) lines.push(`Codes: ${doc.codes.join(", ")}.`);
  if (doc.intentHash !== null) {
    lines.push(
      `Evaluated intent hash: ${doc.intentHash} — a released hold executes only the EXACT intent carrying this hash (the server re-verifies the intent↔hash binding from the stored record before trusting it).`
    );
  }
  lines.push(doc.note);
  return deepFreeze(lines);
}

module.exports = {
  RISK_EXPLANATION_VERSION_1,
  RISK_EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
