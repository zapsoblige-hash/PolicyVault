"use strict";

/*
 * First-party REFERENCE risk adapters (Program D server wiring,
 * docs/postlaunch/risk-adapter-spec.md). Registered per organization
 * through the org-controls configuration surface (server/src/
 * org-controls.js) and executed through core/risk evaluateRisk.
 *
 * INVARIANT (2), restated: an adapter can only make PolicyVault MORE
 * restrictive. Its maximum power — correct, misconfigured, or hostile —
 * is to say DENY or REVIEW; a risk ALLOW merely declines to add a
 * restriction and authorizes nothing. The covenant's caps, budgets,
 * allowlists, approval tiers, and conservation rules are enforced by
 * Kaspa consensus whether or not any adapter exists, agrees, errs, or
 * is compromised. Adapters receive intent DATA only — no key material
 * exists anywhere server-side to leak.
 *
 * Numeric safety: sompi amounts travel as base-10 decimal strings and
 * are parsed with BigInt; anything unreadable resolves restrictive
 * (DENY), never a guess — a screening control that cannot read the
 * amount never allows.
 *
 * Each type exposes:
 *   validateParams(params)  — strict, fail-closed (run at CONFIG SAVE
 *                             so bad configuration refuses early)
 *   build({ name, params, timeoutMs }) — a policyvault-risk-adapter/1
 *                             definition for core/risk evaluateRisk
 */

const { RISK_ADAPTER_CONTRACT_VERSION } = require("../../core/risk/interface");

const DIGITS_RE = /^(0|[1-9][0-9]*)$/;
const XONLY_RE = /^[0-9a-f]{64}$/;

function fail(code, message) {
  const e = new Error(`risk-adapters: ${message}`);
  e.code = code;
  e.status = 422;
  return e;
}

function parseSompiParam(value, field) {
  if (typeof value !== "string" || !DIGITS_RE.test(value)) {
    throw fail("RISK_ADAPTER_PARAMS_INVALID", `${field} must be a base-10 sompi digit string`);
  }
  const amount = BigInt(value);
  if (amount > 2n ** 63n - 1n) throw fail("RISK_ADAPTER_PARAMS_INVALID", `${field} exceeds the i64 domain`);
  return amount;
}

/* Strict read of the intent's spend amount. Returns { kind: "amount",
 * amount } | { kind: "none" } (not a spend) | { kind: "unreadable" }. */
function readSpendAmount(intent) {
  if (!intent || typeof intent !== "object") return { kind: "unreadable" };
  if (intent.action !== "agentSpend") return { kind: "none" };
  const raw = intent.payAmountSompi;
  if (typeof raw !== "string" || !DIGITS_RE.test(raw)) return { kind: "unreadable" };
  try {
    return { kind: "amount", amount: BigInt(raw) };
  } catch {
    return { kind: "unreadable" };
  }
}

const ALLOW = Object.freeze({ verdict: "ALLOW", reasons: [] });

/* ------------------------------------------------------------------ */
/* amount-threshold — REVIEW above a review line, DENY above a hard    */
/* maximum. Screens agentSpend intents; non-spend intents pass         */
/* (nothing to screen), unreadable amounts DENY (never guess).         */
/* ------------------------------------------------------------------ */
const amountThreshold = {
  capabilityNote: "custom-policy",
  validateParams(params) {
    const keys = Object.keys(params);
    for (const k of keys) {
      if (k !== "reviewAboveSompi" && k !== "denyAboveSompi") {
        throw fail("RISK_ADAPTER_PARAMS_INVALID", `amount-threshold params.${k} is not a known field`);
      }
    }
    const review = params.reviewAboveSompi !== undefined ? parseSompiParam(params.reviewAboveSompi, "reviewAboveSompi") : null;
    const deny = params.denyAboveSompi !== undefined ? parseSompiParam(params.denyAboveSompi, "denyAboveSompi") : null;
    if (review === null && deny === null) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "amount-threshold requires reviewAboveSompi and/or denyAboveSompi");
    }
    if (review !== null && deny !== null && deny < review) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "denyAboveSompi must be >= reviewAboveSompi");
    }
    return { review, deny };
  },
  build({ name, params, timeoutMs }) {
    const { review, deny } = amountThreshold.validateParams(params);
    return {
      name,
      adapterVersion: "policyvault-reference/1",
      contractVersion: RISK_ADAPTER_CONTRACT_VERSION,
      capabilities: ["custom-policy"],
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      async evaluate(intent) {
        const read = readSpendAmount(intent);
        if (read.kind === "none") return ALLOW;
        if (read.kind === "unreadable") {
          return {
            verdict: "DENY",
            reasons: [{ code: "AMOUNT_UNREADABLE", message: "the spend amount could not be read as a canonical sompi string — refusing (never guess)" }]
          };
        }
        if (deny !== null && read.amount > deny) {
          return {
            verdict: "DENY",
            reasons: [
              { code: "AMOUNT_ABOVE_DENY_LINE", message: `spend of ${read.amount} sompi exceeds the organization's hard maximum of ${deny} sompi`, evidence: { amountSompi: read.amount.toString(), denyAboveSompi: deny.toString() } }
            ]
          };
        }
        if (review !== null && read.amount > review) {
          return {
            verdict: "REVIEW",
            reasons: [
              { code: "AMOUNT_ABOVE_REVIEW_LINE", message: `spend of ${read.amount} sompi exceeds the organization's review line of ${review} sompi — human review required`, evidence: { amountSompi: read.amount.toString(), reviewAboveSompi: review.toString() } }
            ]
          };
        }
        return ALLOW;
      }
    };
  }
};

/* ------------------------------------------------------------------ */
/* recipient-allowlist — vendor-master style tag list: an agentSpend    */
/* recipient outside the organization's allowlisted set resolves        */
/* REVIEW (default) or DENY; unreadable recipients DENY. Non-spend      */
/* intents pass. This is an ORGANIZATIONAL control layered ABOVE the    */
/* covenant's own Merkle recipient allowlist, which consensus enforces  */
/* independently of this adapter.                                       */
/* ------------------------------------------------------------------ */
const recipientAllowlist = {
  capabilityNote: "vendor-validation",
  validateParams(params) {
    for (const k of Object.keys(params)) {
      if (k !== "allowedRecipients" && k !== "unknownRecipient") {
        throw fail("RISK_ADAPTER_PARAMS_INVALID", `recipient-allowlist params.${k} is not a known field`);
      }
    }
    if (!Array.isArray(params.allowedRecipients) || params.allowedRecipients.length === 0) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "recipient-allowlist requires a non-empty allowedRecipients array of x-only keys");
    }
    if (params.allowedRecipients.length > 4096) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "allowedRecipients exceeds 4096 entries");
    }
    const set = new Set();
    for (const [i, r] of params.allowedRecipients.entries()) {
      if (typeof r !== "string" || !XONLY_RE.test(r.toLowerCase())) {
        throw fail("RISK_ADAPTER_PARAMS_INVALID", `allowedRecipients[${i}] must be 64-hex x-only`);
      }
      set.add(r.toLowerCase());
    }
    const mode = params.unknownRecipient === undefined ? "REVIEW" : params.unknownRecipient;
    if (mode !== "REVIEW" && mode !== "DENY") {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", 'unknownRecipient must be "REVIEW" or "DENY" (an allowlist can never resolve ALLOW for an unknown recipient)');
    }
    return { set, mode };
  },
  build({ name, params, timeoutMs }) {
    const { set, mode } = recipientAllowlist.validateParams(params);
    return {
      name,
      adapterVersion: "policyvault-reference/1",
      contractVersion: RISK_ADAPTER_CONTRACT_VERSION,
      capabilities: ["vendor-validation"],
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      async evaluate(intent) {
        if (!intent || typeof intent !== "object" || intent.action !== "agentSpend") return ALLOW;
        const recipient = intent.recipient;
        if (typeof recipient !== "string" || !XONLY_RE.test(recipient.toLowerCase())) {
          return { verdict: "DENY", reasons: [{ code: "RECIPIENT_UNREADABLE", message: "the recipient could not be read as an x-only key — refusing (never guess)" }] };
        }
        if (set.has(recipient.toLowerCase())) return ALLOW;
        return {
          verdict: mode,
          reasons: [
            { code: "RECIPIENT_NOT_ALLOWLISTED", message: `recipient ${recipient.toLowerCase()} is not in the organization's allowlist (${set.size} entries)`, evidence: { recipient: recipient.toLowerCase() } }
          ]
        };
      }
    };
  }
};

/* ------------------------------------------------------------------ */
/* static-verdict — an operational fixture: always returns the          */
/* configured restrictive verdict (an org can force REVIEW on every     */
/* operation), or simulates failure modes (throw / hang / malformed)    */
/* which core/risk resolves via onAdapterError — REVIEW or DENY, never  */
/* ALLOW. Also the server-level test fixture for those semantics.       */
/* ------------------------------------------------------------------ */
const staticVerdict = {
  capabilityNote: "custom-policy",
  validateParams(params) {
    for (const k of Object.keys(params)) {
      if (!["verdict", "code", "message", "behavior", "delayMs"].includes(k)) {
        throw fail("RISK_ADAPTER_PARAMS_INVALID", `static-verdict params.${k} is not a known field`);
      }
    }
    const behavior = params.behavior === undefined ? "ok" : params.behavior;
    if (!["ok", "throw", "hang", "malformed"].includes(behavior)) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", 'static-verdict behavior must be "ok" | "throw" | "hang" | "malformed"');
    }
    if (behavior === "ok") {
      if (!["ALLOW", "REVIEW", "DENY"].includes(params.verdict)) {
        throw fail("RISK_ADAPTER_PARAMS_INVALID", "static-verdict requires verdict ALLOW|REVIEW|DENY");
      }
    }
    if (params.code !== undefined && (typeof params.code !== "string" || !/^[A-Z0-9_]{1,64}$/.test(params.code))) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "static-verdict code must match /^[A-Z0-9_]{1,64}$/");
    }
    if (params.message !== undefined && (typeof params.message !== "string" || params.message.length === 0 || params.message.length > 512)) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "static-verdict message must be a non-empty string (<=512 chars)");
    }
    if (params.delayMs !== undefined && (!Number.isInteger(params.delayMs) || params.delayMs < 0 || params.delayMs > 600000)) {
      throw fail("RISK_ADAPTER_PARAMS_INVALID", "static-verdict delayMs must be an integer 0..600000");
    }
    return {
      behavior,
      verdict: params.verdict,
      code: params.code ?? "STATIC_VERDICT",
      message: params.message ?? "organization static-verdict policy",
      delayMs: params.delayMs ?? 0
    };
  },
  build({ name, params, timeoutMs }) {
    const p = staticVerdict.validateParams(params);
    return {
      name,
      adapterVersion: "policyvault-reference/1",
      contractVersion: RISK_ADAPTER_CONTRACT_VERSION,
      capabilities: ["custom-policy"],
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      async evaluate() {
        if (p.delayMs > 0) await new Promise((r) => setTimeout(r, p.delayMs));
        if (p.behavior === "throw") throw new Error(p.message);
        if (p.behavior === "hang") return new Promise(() => {}); // resolved by the composition timeout, never ALLOW
        if (p.behavior === "malformed") return { verdict: "MAYBE", reasons: [] };
        if (p.verdict === "ALLOW") return ALLOW;
        return { verdict: p.verdict, reasons: [{ code: p.code, message: p.message }] };
      }
    };
  }
};

const ADAPTER_TYPES = Object.freeze({
  "amount-threshold": amountThreshold,
  "recipient-allowlist": recipientAllowlist,
  "static-verdict": staticVerdict
});

/*
 * Build the adapter definition set from a validated org-controls risk
 * block. Unknown types FAIL CLOSED (they should have been refused at
 * save time; a stored record this build cannot interpret must refuse
 * the OPERATION, never silently drop the control).
 */
function buildAdaptersFromConfig(riskConfig) {
  const out = [];
  for (const entry of riskConfig.adapters ?? []) {
    const type = ADAPTER_TYPES[entry.type];
    if (!type) {
      throw fail("RISK_ADAPTER_TYPE_UNKNOWN", `stored adapter type ${JSON.stringify(entry.type)} is unknown to this build — failing closed (the operation is refused, the control is never dropped)`);
    }
    out.push(type.build({ name: entry.name ?? entry.type, params: entry.params ?? {}, timeoutMs: entry.timeoutMs }));
  }
  return out;
}

module.exports = { ADAPTER_TYPES, buildAdaptersFromConfig };
