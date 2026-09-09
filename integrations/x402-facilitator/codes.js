"use strict";

/*
 * CLOSED reason-code set of the x402 facilitator (spec §13, revision 3):
 * 5 RETRY · 2 PENDING · 24 REFUSE · 4 AUTH. Every code carries its class,
 * the HTTP status the service uses for it, and a deterministic human
 * explanation (a refusal nobody can read is an availability bug). Unknown
 * situations map to SCHEMA_INVALID or a RETRY code — never to validity.
 */

const CLASSES = Object.freeze({ RETRY: "RETRY", PENDING: "PENDING", REFUSE: "REFUSE", AUTH: "AUTH" });

// Null-prototype base so a caller-supplied code of `toString`/`constructor`
// resolves to undefined, never an inherited function.
const CODES = Object.freeze(Object.assign(Object.create(null), {
  /* RETRY — never a validity judgement */
  NODE_UNAVAILABLE: { cls: CLASSES.RETRY, http: 503, text: "the bound Kaspa node could not be reached or answered outside its budget — no judgement was made; retry." },
  NODE_UNSYNCED: { cls: CLASSES.RETRY, http: 503, text: "the bound Kaspa node reports it is not synced — the facilitator never judges payments against an unsynced node; retry." },
  UTXO_INDEX_UNAVAILABLE: { cls: CLASSES.RETRY, http: 503, text: "the bound Kaspa node has no UTXO index — the facilitator's only evidence source is the UTXO index; retry against an indexed node." },
  RPC_MALFORMED: { cls: CLASSES.RETRY, http: 503, text: "the node returned a response the facilitator refuses to interpret (missing or malformed fields) — never partially trusted; retry." },
  RATE_LIMITED: { cls: CLASSES.RETRY, http: 429, text: "this principal exceeded its request budget — availability protection only; retry after the window." },
  /* PENDING */
  PAYMENT_NOT_OBSERVED: { cls: CLASSES.PENDING, http: 200, text: "the exact outpoint is not (yet) present in the UTXO index of the destination — pending until the validity window plus the settlement depth elapse, then a final refusal; an output already spent is also unobservable (settle before spending)." },
  PAYMENT_PENDING_DEPTH: { cls: CLASSES.PENDING, http: 200, text: "the payment is observed on chain (CHAIN_SEEN) but its DAA depth is below the settlement policy minimum — retry after the depth is reached." },
  /* REFUSE */
  SCHEMA_INVALID: { cls: CLASSES.REFUSE, http: 200, text: "the request does not match the closed x402 Kaspa profile (unknown field, wrong type, malformed JSON, or an unknown situation) — refused." },
  VERSION_UNSUPPORTED: { cls: CLASSES.REFUSE, http: 200, text: "the x402Version is not 2 — unknown versions are refused, never routed to a default." },
  SCHEME_UNSUPPORTED: { cls: CLASSES.REFUSE, http: 200, text: "the scheme or extra.kaspaScheme is not the frozen `exact` + pv-x402-kaspa-exact-upfront/1 — refused." },
  FLOW_UNSUPPORTED: { cls: CLASSES.REFUSE, http: 200, text: "extra.paymentFlow is not \"upfront\" — Kaspa has no delegated-pull primitive and the facilitator never emulates one." },
  POLICY_UNSUPPORTED: { cls: CLASSES.REFUSE, http: 200, text: "extra.settlementPolicy is not a settlement policy this facilitator implements — unknown policies fail closed." },
  NETWORK_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "the requirement's network is not the exact identifier this facilitator is bound to (kaspa:mainnet or kaspa:testnet-10, byte-exact) — cross-network material is refused." },
  ASSET_UNSUPPORTED: { cls: CLASSES.REFUSE, http: 200, text: "the asset is neither KAS nor a pvad1:<descriptor-hash> from this facilitator's configured descriptors — allowlist only." },
  AMOUNT_INVALID: { cls: CLASSES.REFUSE, http: 200, text: "the amount is not a canonical positive decimal integer string in atomic units within the asset's bound — no float is ever constructed." },
  ADDRESS_INVALID: { cls: CLASSES.REFUSE, http: 200, text: "payTo is not a valid literal Kaspa address for the bound network (prefix, charset, checksum, or an unsupported address version)." },
  REQUIREMENTS_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "payload.accepted does not canonically equal the paymentRequirements presented alongside it — a mutated requirement never verifies." },
  REQUIREMENT_WINDOW_INVALID: { cls: CLASSES.REFUSE, http: 200, text: "the DAA validity window is not strictly increasing or exceeds MAX_WINDOW_DAA (36,000)." },
  REQUIREMENT_EXPIRED: { cls: CLASSES.REFUSE, http: 200, text: "the validity window plus the settlement depth elapsed without the payment being observed — final refusal." },
  REQUIREMENT_DESTINATION_REUSED: { cls: CLASSES.REFUSE, http: 200, text: "another settled requirement with the same network, payTo and amount has an overlapping DAA window — destinations must be unique per requirement; the facilitator refuses rather than guessing which request a payment belongs to." },
  PAYMENT_OUTSIDE_WINDOW: { cls: CLASSES.REFUSE, http: 200, text: "the observed inclusion DAA score lies outside [validFromDaaScore, validUntilDaaScore]." },
  OUTPUT_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "the outpoint exists but does not pay exactly the required amount to exactly the required destination as a plain (non-coinbase, covenant-free) KAS output — the exact scheme requires equality." },
  TXID_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "the supplied transaction bytes do not recompute to payload.transactionId." },
  PAYMENT_ALREADY_CLAIMED: { cls: CLASSES.REFUSE, http: 200, text: "this outpoint was already claimed by a different requirement — one payment settles at most one requirement." },
  REQUIREMENT_ALREADY_SETTLED: { cls: CLASSES.REFUSE, http: 200, text: "this requirement was already settled by a different outpoint — one requirement is settled at most once." },
  TOKEN_REDEEM_REQUIRED: { cls: CLASSES.REFUSE, http: 200, text: "token payments require transactionHex and outputRedeems covering every family output including outputIndex." },
  TOKEN_TEMPLATE_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "the supplied redeem does not hash to the observed P2SH script or does not corroborate an accepted template of the descriptor (geometry, in-VM hash, standardness)." },
  TOKEN_OWNER_MISMATCH: { cls: CLASSES.REFUSE, http: 200, text: "the decoded kcc20-state/1 owner does not equal payTo's owner encoding (or uses an owner scheme that can never equal an address)." },
  TOKEN_CONSERVATION_FAILED: { cls: CLASSES.REFUSE, http: 200, text: "the supplied transaction's family token inputs and outputs do not conserve, or a family output has no decodable redeem — inconsistent submission refused." },
  UNSUPPORTED_TOKEN_PROGRAM: { cls: CLASSES.REFUSE, http: 200, text: "the observed entry's covenant id is not the descriptor's token family, or the descriptor / template / owner scheme variant is not supported — fail closed." },
  BODY_TOO_LARGE: { cls: CLASSES.REFUSE, http: 413, text: "the request body exceeds the facilitator's byte cap — refused before parsing." },
  /* AUTH — HTTP 401/403; never a validity judgement, never a chain observation */
  CREDENTIAL_REQUIRED: { cls: CLASSES.AUTH, http: 401, text: "this endpoint requires an authenticated resource server (Authorization: Bearer <facilitator credential>) — no credential was presented." },
  CREDENTIAL_INVALID: { cls: CLASSES.AUTH, http: 401, text: "the presented credential is not an active facilitator credential (unknown, malformed, revoked, or expired) — nothing was observed, stored, or consumed." },
  SCOPE_FORBIDDEN: { cls: CLASSES.AUTH, http: 403, text: "the authenticated principal is not allowed this facilitator operation." },
  PRINCIPAL_FORBIDDEN: { cls: CLASSES.AUTH, http: 403, text: "the presented requirement is outside this principal's configured authority (network, destination, or resource origin)." }
}));

const CODE_NAMES = Object.freeze(Object.keys(CODES));

function describe(code) {
  const entry = CODES[code];
  if (!entry) throw new Error(`unknown x402 facilitator reason code ${JSON.stringify(code)} — the code set is closed`);
  return entry;
}

class FacilitatorRefusal extends Error {
  constructor(code, detail) {
    const entry = describe(code);
    super(detail ? `${entry.text} (${detail})` : entry.text);
    this.name = "FacilitatorRefusal";
    this.code = code;
    this.cls = entry.cls;
    this.http = entry.http;
    this.explanation = entry.text;
    this.detail = detail ?? null;
  }
}

function refuse(code, detail) {
  throw new FacilitatorRefusal(code, detail);
}

module.exports = { CLASSES, CODES, CODE_NAMES, describe, FacilitatorRefusal, refuse };
