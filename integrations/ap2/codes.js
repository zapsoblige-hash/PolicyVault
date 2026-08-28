"use strict";

/*
 * AP2 adapter machine codes + deterministic human explanations (the G-1
 * lesson). Codes from docs/postlaunch/ap2-adapter-spec.md §3.2/§3.3/
 * §3.5/§4.5, plus the implementation-necessary codes listed at the
 * bottom (documented in the README and the implementation-evidence note).
 */

// Null-prototype base so a server-supplied code of `toString`/`constructor`
// resolves to undefined, never an inherited function (Hostile-AI H-6).
const EXPLANATIONS = Object.freeze(Object.assign(Object.create(null), {
  AP2_VCT_UNSUPPORTED: "the vct claim is not in the supported v0.2 set (exact match, version suffix included) — v0.1 W3C-VC mandates and unknown/near-miss types are refused, never translated.",
  AP2_ALG_UNSUPPORTED: "the JWS alg is not in the pinned allow-list (ES256) — `none`, symmetric algorithms, and unknown values refuse; the algorithm is never negotiated from the token.",
  AP2_SD_ALG_UNSUPPORTED: "the _sd_alg claim is absent, weak, or unknown — for INBOUND mandates absence refuses; there is no \"SHA-256 if absent\" default.",
  AP2_KEY_BINDING_INVALID: "holder key binding did not verify (missing/invalid KB-JWT, sd_hash mismatch, or missing cnf) — a partial or absent binding refuses.",
  AP2_DISCLOSURE_INCOMPLETE: "a constraint slot this deployment requires was not disclosed — an undisclosed slot is NEVER read as \"unconstrained\"; withholding disclosures cannot strip spending limits.",
  AP2_DISCLOSURE_INVALID: "a disclosure is malformed, duplicated, or not referenced by any _sd digest — refusing.",
  AP2_MANDATE_EXPIRED: "the mandate's exp is in the past (or iat is in the future beyond the allowed skew) — obtain a fresh mandate; nothing is cancelled server-side.",
  AP2_TRANSACTION_ID_INVALID: "transaction_id is absent or is not a base64url sha-256 digest (or does not match the disclosed checkout_jwt) — a payment with no valid transaction anchor cannot be made idempotency-safe, and the adapter never invents one.",
  AP2_CHECKOUT_HASH_MISMATCH: "checkout_hash does not recompute from the disclosed checkout_jwt under the pinned _sd_alg — refusing.",
  AP2_AMOUNT_INVALID: "payment_amount.amount is not a positive safe-integer JSON number in minor units (== sompi), or exceeds MAX_SOMPI — no float ever touches a consensus value and no conversion is ever performed.",
  AP2_CURRENCY_UNSUPPORTED: "payment_amount.currency is not the Kaspa instrument's pinned currency token — any ISO 4217 fiat code refuses; the adapter performs no currency conversion, ever.",
  AP2_INSTRUMENT_TYPE_UNSUPPORTED: "payment_instrument.type is not the supported Kaspa instrument type (exact match) — unknown instrument types refuse.",
  AP2_INSTRUMENT_UNKNOWN: "payment_instrument.id does not resolve to a configured (vault, agent) — the handle is an opaque PolicyVault-minted identifier, never a vault id, address, or key.",
  AP2_PAYEE_UNKNOWN: "payee.id is not in the operator-configured payee directory — destinations are resolved entirely PolicyVault-side and the adapter never offers to add one.",
  AP2_PAYEE_NOT_ALLOWLISTED: "the directory-resolved destination is not in the acting agent's covenant recipient allowlist — no mandate bytes, however signed, can name a destination PolicyVault has not already authorized.",
  AP2_METADATA_TOO_LARGE: "an audit-only metadata field exceeds its size cap.",
  AP2_CHECKOUT_JWT_TOO_LARGE: "the opaque checkout_jwt exceeds its size cap.",
  AP2_SCHEMA_UNKNOWN_FIELD: "the mandate carries a claim outside the closed v0.2 schema — a hidden claim is a hidden effect, so unknown claims refuse.",
  AP2_AMOUNT_OUT_OF_RANGE: "the payment violates the mandate's own payment.amount_range constraint — your own mandate forbids this.",
  AP2_MANDATE_BUDGET_EXCEEDED: "this payment would exceed the mandate's cumulative payment.budget, tracked adapter-side against prior attempts for the same open mandate.",
  AP2_PAYEE_NOT_IN_MANDATE: "the resolved payee is not in the mandate's payment.allowed_payees set.",
  AP2_INSTRUMENT_NOT_IN_MANDATE: "the payment instrument is not in the mandate's payment.allowed_payment_instruments set.",
  AP2_PISP_UNSUPPORTED: "the mandate requires a PISP — PolicyVault is never a PISP and never routes through one.",
  AP2_RECURRENCE_EXCEEDED: "the mandate's payment.agent_recurrence occurrence limit is exhausted.",
  AP2_EXECUTION_WINDOW: "now is outside the mandate's payment.execution_date window.",
  AP2_REFERENCE_MISMATCH: "the payment.reference linkage (conditional_transaction_id) does not match the presented checkout — refusing.",
  AP2_MERCHANT_NOT_ALLOWED: "the payee is outside the checkout mandate's allowed_merchants set.",
  AP2_LINE_ITEMS_MISMATCH: "the checkout line items disagree with payment_amount — a human question, held restrictively (fail closed in this adapter version), never a different paid amount.",
  AP2_CONSTRAINT_UNKNOWN: "the mandate carries a constraint type this adapter does not recognize — an unreadable control never allows.",
  AP2_CONSTRAINT_UNREADABLE: "a mandate constraint value could not be parsed — an unreadable control never allows.",
  AP2_TRUST_ANCHOR_UNCONFIGURED: "no SD-JWT trust anchors are configured for this deployment — mandate verification fails closed until the operator pins issuer keys (trust-anchor wiring is deployment configuration).",
  AP2_TRUST_ANCHOR_UNKNOWN: "the mandate's kid does not resolve to a pinned trust anchor — embedded jwk/jku/x5u key material is never trusted.",
  AP2_SIGNATURE_INVALID: "the JWS signature did not verify against the pinned trust anchor — the mandate is cryptographically unacceptable.",
  AP2_OPEN_MANDATE_REQUIRED: "the closed mandate is agent-signed (human-not-present) but no user-signed open mandate was presented — the operating mode is established from what was actually presented, never assumed.",
  AP2_ENVELOPE_INVALID: "the mandate envelope is malformed (size caps, base64url, JSON shape, or SD-JWT structure) — refusing before verification where the caps apply.",
  AP2_CALLER_INPUT_INVALID: "the adapter caller's own request body is outside the closed input schema.",
  AP2_ATTEMPT_IN_PROGRESS: "an attempt with this transaction_id is already being processed — retry shortly; at most one build can ever result.",
  IDEMPOTENCY_KEY_CONFLICT: "this transaction_id was already used with a DIFFERENT mandate digest — a re-presented mutated mandate can never extract a second or larger payment; a new payment requires a new mandate with a new transaction_id.",
  AP2_UPSTREAM_UNAVAILABLE: "PolicyVault's Agent API (or its live node, at the submit stage) is unavailable or reports a mismatched/unsynced network — failing closed.",
  AP2_SUBMIT_BLOCKED: "the live-network gate (networkId, sync, UTXO index) refused — the adapter never broadcasts against an unverified node.",
  AP2_PAYMENT_MISMATCH: "the pipeline's exact payment output does not equal the mandate amount/destination — refusing; equality is asserted from the derived intent, never assumed."
}));

function refusal(code) {
  const explanation = EXPLANATIONS[code];
  if (!explanation) throw new Error(`unknown AP2 machine code ${code} — codes are a closed set`);
  return { code, explanation };
}

class Ap2Refusal extends Error {
  constructor(code, detail) {
    const r = refusal(code);
    super(detail ? `${r.explanation} (${detail})` : r.explanation);
    this.name = "Ap2Refusal";
    this.code = code;
    this.explanation = r.explanation;
    this.detail = detail ?? null;
  }
}

module.exports = { EXPLANATIONS, refusal, Ap2Refusal };
