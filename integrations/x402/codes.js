"use strict";

/*
 * x402 adapter machine codes + deterministic human explanations (the G-1
 * lesson: a refusal nobody can read is an availability bug). Codes from
 * docs/postlaunch/x402-adapter-spec.md §3.2/§3.3/§4.5/§7.4, plus the
 * implementation-necessary envelope/upstream codes listed at the bottom
 * (each documented in the adapter README and the implementation-evidence
 * note — never invented silently).
 */

// Null-prototype base so a server-supplied code of `toString`/`constructor`
// resolves to undefined, never an inherited function (Hostile-AI H-6).
const EXPLANATIONS = Object.freeze(Object.assign(Object.create(null), {
  X402_VERSION_UNSUPPORTED: "the x402Version is not in this adapter's supported set (v2 only) — unknown versions are refused before any structural assumption, never routed to a default.",
  X402_SCHEME_UNSUPPORTED: "the payment scheme is not in this deployment's supported set (exact match only) — unknown schemes refuse, never a default.",
  X402_NETWORK_MISMATCH: "the requirement names a different network than this adapter's configured Kaspa network — cross-network material is refused; PolicyVault never silently switches network.",
  X402_ASSET_UNSUPPORTED: "the asset is not the configured native-KAS asset identifier — PolicyVault v0.4 covenants move native KAS only; no token, contract, or ISO-4217 asset is ever paid.",
  X402_AMOUNT_INVALID: "the amount is not a canonical sompi digit string (^(0|[1-9][0-9]*)$), is zero/negative, or exceeds MAX_SOMPI — no float is ever constructed and no unit conversion is ever performed.",
  X402_AMOUNT_NOT_STRING: "the amount is a JSON number — x402 amounts must be strings; a JSON number is refused outright so no float can ever touch a consensus value.",
  X402_DESTINATION_INVALID: "payTo is not a valid literal Kaspa address for the configured network (wrong prefix, bad charset, mixed case, non-ASCII, or rejected by the authoritative address parser).",
  X402_DESTINATION_NOT_LITERAL: "payTo is not a literal Kaspa address (role constant, name, URL, or other indirection) — indirection is a destination-substitution vector and is always refused.",
  X402_DESTINATION_NOT_ALLOWLISTED: "the destination decodes correctly but is not in the acting agent's covenant recipient allowlist — the adapter never adds a recipient; adding one is a governance-classified expansion requiring the owner's wallet signature.",
  X402_TIMEOUT_INVALID: "maxTimeoutSeconds is not an integer in 1..3600 — it bounds only the adapter's own deadline and must be a sane wall-clock value.",
  X402_FLOW_UNSUPPORTED: "the requirement does not declare extra.paymentFlow \"upfront\" — Kaspa has no delegated-pull primitive and PolicyVault never emulates one; only the pay-first (upfront) flow is supported.",
  X402_EXTRA_TOO_LARGE: "the scheme-specific extra object exceeds the audit-metadata size cap.",
  X402_RESOURCE_INVALID: "resource.url is not an absolute https URI within the size cap.",
  X402_METADATA_TOO_LARGE: "an audit-only metadata field (description/mimeType/error) exceeds its size cap.",
  X402_EXTENSIONS_TOO_LARGE: "the extensions object exceeds the audit-metadata size cap.",
  X402_SCHEMA_UNKNOWN_FIELD: "the document carries a field outside the closed x402 v2 schema — a hidden field is a hidden effect, so unknown keys refuse.",
  X402_NO_ACCEPTABLE_REQUIREMENT: "no accepts[] entry passed every gate — the adapter never picks the closest match.",
  X402_ATTEMPT_ID_REQUIRED: "the caller did not supply an attemptId — the adapter never mints one, because a self-minted id would make every network-level retry a fresh spend.",
  X402_ATTEMPT_IN_PROGRESS: "an attempt with this attemptId is already being processed — retry shortly; at most one build can ever result.",
  IDEMPOTENCY_KEY_CONFLICT: "this attemptId was already used with a DIFFERENT requirement digest — a mutated price or destination on retry can never extract a second or larger payment; use a fresh attemptId for a genuinely new purchase.",
  X402_DEADLINE_ELAPSED: "the adapter deadline derived from maxTimeoutSeconds elapsed before chain proof — nothing was cancelled (a broadcast Kaspa transaction is not cancellable); obtain a fresh 402 for a new attempt.",
  X402_PAYMENT_MISMATCH: "the pipeline's exact payment output does not equal the requirement amount/destination — refusing; the x402 exact rule requires equality and PolicyVault asserts it from the derived intent, never assumes it.",
  X402_SERVER_REFUSED_AFTER_SETTLEMENT: "the resource server refused the request AFTER the payment was chain-proven — PolicyVault paid and did not receive. This is escalated to a human and is never auto-retried.",
  X402_HEADER_INVALID: "the PAYMENT-REQUIRED header is not canonical base64 of well-formed JSON within the size/depth caps.",
  X402_CALLER_INPUT_INVALID: "the adapter caller's own request body is outside the closed input schema.",
  X402_UPSTREAM_UNAVAILABLE: "PolicyVault's Agent API (or its live node, at the submit stage) is unavailable or reports a mismatched/unsynced network — failing closed.",
  X402_SUBMIT_BLOCKED: "the live-network gate (networkId, sync, UTXO index) refused — the adapter never broadcasts against an unverified node."
}));

function refusal(code, extra = {}) {
  const explanation = EXPLANATIONS[code];
  if (!explanation) throw new Error(`unknown x402 machine code ${code} — codes are a closed set`);
  return { code, explanation, ...extra };
}

class X402Refusal extends Error {
  constructor(code, detail) {
    const r = refusal(code);
    super(detail ? `${r.explanation} (${detail})` : r.explanation);
    this.name = "X402Refusal";
    this.code = code;
    this.explanation = r.explanation;
    this.detail = detail ?? null;
  }
}

module.exports = { EXPLANATIONS, refusal, X402Refusal };
