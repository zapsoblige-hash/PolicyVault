"use strict";

/*
 * AP2 v0.2 mandate claims -> closed PolicyVault intent proposal
 * (ap2-adapter-spec.md §3, implemented field-for-field).
 *
 * Trust trichotomy, with no fourth category: every claim is a PROPOSAL
 * (normalized into the closed intent), a RESTRICTIVE-ONLY CONSTRAINT
 * (may only make PolicyVault MORE restrictive), or AUDIT-ONLY METADATA
 * (length-capped, recorded verbatim, read by nothing in the decision
 * path). Anything else refuses (AP2_SCHEMA_UNKNOWN_FIELD) — including
 * cryptographically valid, correctly key-bound, user-signed content.
 *
 * THE MANDATE MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE
 * COVENANT ENFORCES FINANCIAL AUTHORITY. THE SIGNER RETAINS CUSTODY.
 */

const { requireSafeMinorUnitsInteger, AmountError } = require("../lib/amounts-gate");
const { b64urlSha256 } = require("./sdjwt");
const { Ap2Refusal } = require("./codes");

const SUPPORTED_VCT = Object.freeze({
  CLOSED_PAYMENT: "mandate.payment.1",
  OPEN_PAYMENT: "mandate.payment.open.1",
  CLOSED_CHECKOUT: "mandate.checkout.1",
  OPEN_CHECKOUT: "mandate.checkout.open.1"
});
const SUPPORTED_VCT_SET = Object.freeze(new Set(Object.values(SUPPORTED_VCT)));

/* Per-vct CLOSED claim sets (after cnf/_sd/_sd_alg removal by the
 * verifier). Any other claim, at any depth of the classified tree,
 * refuses. These sets are this implementation's reading of the partially
 * open upstream schemas and are recorded as INTERIM in the
 * implementation-evidence note. */
const CLAIMS_CLOSED_PAYMENT = Object.freeze(new Set(["vct", "transaction_id", "payee", "payment_amount", "payment_instrument", "pisp", "execution_date", "risk_data", "iat", "exp"]));
const CLAIMS_OPEN_PAYMENT = Object.freeze(new Set(["vct", "constraints", "payee", "payment_amount", "payment_instrument", "pisp", "execution_date", "risk_data", "iat", "exp"]));
const CLAIMS_CLOSED_CHECKOUT = Object.freeze(new Set(["vct", "checkout_jwt", "checkout_hash", "iat", "exp"]));
const CLAIMS_OPEN_CHECKOUT = Object.freeze(new Set(["vct", "constraints", "delegate_payload", "iat", "exp"]));

const CAPS = Object.freeze({
  payeeNameBytes: 255,
  payeeWebsiteBytes: 2048,
  payeeIdBytes: 128,
  instrumentIdBytes: 128,
  instrumentDescriptionBytes: 255,
  checkoutJwtBytes: 16384,
  riskDataBytes: 8192,
  transactionIdChars: 43 // unpadded base64url of a sha-256 digest
});

function refuse(code, detail) {
  throw new Ap2Refusal(code, detail);
}

function byteLen(value) {
  return Buffer.byteLength(typeof value === "string" ? value : JSON.stringify(value ?? null), "utf8");
}

function gateVct(claims) {
  const vct = claims ? claims.vct : undefined;
  if (typeof vct !== "string" || !SUPPORTED_VCT_SET.has(vct)) {
    refuse("AP2_VCT_UNSUPPORTED", `vct ${JSON.stringify(vct ?? null)} — exact match against the v0.2 set, version suffix included`);
  }
  return vct;
}

function assertClosedClaims(claims, allowed, where) {
  for (const key of Object.keys(claims)) {
    if (!allowed.has(key)) refuse("AP2_SCHEMA_UNKNOWN_FIELD", `unknown claim ${JSON.stringify(key)} in ${where}`);
  }
}

function gateTransactionId(value) {
  if (typeof value !== "string" || value.length !== CAPS.transactionIdChars || !/^[A-Za-z0-9_-]+$/.test(value)) {
    refuse("AP2_TRANSACTION_ID_INVALID", "transaction_id must be the unpadded base64url sha-256 of the associated checkout_jwt (43 chars)");
  }
  return value;
}

function gatePayee(payee) {
  if (!payee || typeof payee !== "object" || Array.isArray(payee)) refuse("AP2_SCHEMA_UNKNOWN_FIELD", "payee must be an object");
  for (const k of Object.keys(payee)) {
    if (k !== "id" && k !== "name" && k !== "website") refuse("AP2_SCHEMA_UNKNOWN_FIELD", `unknown payee field ${JSON.stringify(k)}`);
  }
  if (typeof payee.id !== "string" || payee.id.length === 0 || byteLen(payee.id) > CAPS.payeeIdBytes) refuse("AP2_PAYEE_UNKNOWN", "payee.id must be a non-empty string within the id cap");
  if (payee.name !== undefined && (typeof payee.name !== "string" || byteLen(payee.name) > CAPS.payeeNameBytes)) refuse("AP2_METADATA_TOO_LARGE", "payee.name exceeds its cap");
  if (payee.website !== undefined && (typeof payee.website !== "string" || byteLen(payee.website) > CAPS.payeeWebsiteBytes)) refuse("AP2_METADATA_TOO_LARGE", "payee.website exceeds its cap");
  return { id: payee.id, name: payee.name ?? null, website: payee.website ?? null };
}

function gatePaymentAmount(paymentAmount, { currencyLiteral }) {
  if (!paymentAmount || typeof paymentAmount !== "object" || Array.isArray(paymentAmount)) refuse("AP2_AMOUNT_INVALID", "payment_amount must be an object");
  for (const k of Object.keys(paymentAmount)) {
    if (k !== "amount" && k !== "currency") refuse("AP2_SCHEMA_UNKNOWN_FIELD", `unknown payment_amount field ${JSON.stringify(k)}`);
  }
  // Currency FIRST: a fiat-denominated mandate is a refusal, not a quote
  // lookup — the adapter performs no conversion, ever.
  if (paymentAmount.currency !== currencyLiteral) {
    refuse("AP2_CURRENCY_UNSUPPORTED", `currency ${JSON.stringify(paymentAmount.currency ?? null)} != pinned instrument currency ${JSON.stringify(currencyLiteral)}`);
  }
  // The strict parser guarantees a JS number here could ONLY have come
  // from a plain safe-integer token (floats/exponents/leading zeros were
  // carried as raw-token strings and are refused by the typeof gate), so
  // the lexical token is the number's canonical decimal form.
  const value = paymentAmount.amount;
  let canonical;
  try {
    canonical = requireSafeMinorUnitsInteger(value, typeof value === "number" ? String(value) : null, { code: "AP2_AMOUNT_INVALID" });
  } catch (error) {
    if (error instanceof AmountError) refuse(error.code, error.message);
    throw error;
  }
  return canonical; // canonical sompi digit string; minor unit == sompi, identity mapping
}

function gateInstrument(instrument, { instrumentType, instruments }) {
  if (!instrument || typeof instrument !== "object" || Array.isArray(instrument)) refuse("AP2_SCHEMA_UNKNOWN_FIELD", "payment_instrument must be an object");
  for (const k of Object.keys(instrument)) {
    if (k !== "id" && k !== "type" && k !== "description") refuse("AP2_SCHEMA_UNKNOWN_FIELD", `unknown payment_instrument field ${JSON.stringify(k)}`);
  }
  if (instrument.type !== instrumentType) {
    refuse("AP2_INSTRUMENT_TYPE_UNSUPPORTED", `payment_instrument.type ${JSON.stringify(instrument.type ?? null)} != supported ${JSON.stringify(instrumentType)}`);
  }
  if (typeof instrument.id !== "string" || instrument.id.length === 0 || byteLen(instrument.id) > CAPS.instrumentIdBytes) {
    refuse("AP2_INSTRUMENT_UNKNOWN", "payment_instrument.id must be a non-empty opaque handle");
  }
  if (instrument.description !== undefined && (typeof instrument.description !== "string" || byteLen(instrument.description) > CAPS.instrumentDescriptionBytes)) {
    refuse("AP2_METADATA_TOO_LARGE", "payment_instrument.description exceeds its cap");
  }
  const resolved = instruments && typeof instruments === "object" ? instruments[instrument.id] : undefined;
  if (!resolved || typeof resolved.vaultId !== "string" || typeof resolved.agentPk !== "string") {
    refuse("AP2_INSTRUMENT_UNKNOWN", "payment_instrument.id does not resolve to a configured (vault, agent)");
  }
  return { handle: instrument.id, vaultId: resolved.vaultId, agentPk: resolved.agentPk, description: instrument.description ?? null };
}

/*
 * Normalize a VERIFIED closed Payment Mandate's claims (the verifier's
 * `claims` output plus its numberTokens accessor) into the proposal.
 * `payeeDirectory` is the operator-configured Map payeeId -> { address,
 * xOnlyPubkey } — payee.name/website are NEVER consulted for resolution.
 */
function normalizeClosedPaymentMandate(claims, { config, payeeDirectory }) {
  const vct = gateVct(claims);
  if (vct !== SUPPORTED_VCT.CLOSED_PAYMENT) refuse("AP2_VCT_UNSUPPORTED", `expected a closed Payment Mandate (${SUPPORTED_VCT.CLOSED_PAYMENT}), got ${vct}`);
  assertClosedClaims(claims, CLAIMS_CLOSED_PAYMENT, "closed Payment Mandate");

  const transactionId = gateTransactionId(claims.transaction_id);
  const payee = gatePayee(claims.payee);
  const payAmountSompi = gatePaymentAmount(claims.payment_amount, { currencyLiteral: config.currencyLiteral });
  const instrument = gateInstrument(claims.payment_instrument, { instrumentType: config.instrumentType, instruments: config.instruments });

  // pisp / risk_data: AUDIT-ONLY, size-capped, never a verdict.
  if (claims.risk_data !== undefined && byteLen(claims.risk_data) > CAPS.riskDataBytes) refuse("AP2_METADATA_TOO_LARGE", "risk_data exceeds its cap");

  // Destination: payee.id -> operator directory -> x-only key. Exact-id
  // resolution only (A-3/A-4: name/website never influence it).
  const directoryEntry = payeeDirectory.get(payee.id);
  if (!directoryEntry) refuse("AP2_PAYEE_UNKNOWN", `payee.id ${JSON.stringify(payee.id)} is not in the operator payee directory`);

  return {
    transactionId,
    payAmountSompi,
    recipientXOnly: directoryEntry.xOnlyPubkey,
    recipientAddress: directoryEntry.address,
    vaultId: instrument.vaultId,
    agentPk: instrument.agentPk,
    instrumentHandle: instrument.handle,
    payeeId: payee.id,
    exp: Number.isSafeInteger(claims.exp) ? claims.exp : null,
    executionDate: claims.execution_date ?? null,
    audit: {
      payeeRaw: { id: payee.id, name: payee.name, website: payee.website },
      riskDataRaw: claims.risk_data ?? null,
      pispRaw: claims.pisp ?? null
    }
  };
}

/*
 * Closed Checkout Mandate: `checkout_jwt` is an OPAQUE blob (AP2 is
 * "agnostic to the contents"; PolicyVault never parses it for amounts,
 * addresses, or authorizations) — digest-verified against checkout_hash
 * under the pinned _sd_alg, and cross-checked against the Payment
 * Mandate's transaction_id when disclosed. checkout_hash with the jwt
 * withheld is accepted ONLY as an opaque correlation anchor (A-26).
 */
function normalizeClosedCheckoutMandate(claims, { expectedTransactionId }) {
  const vct = gateVct(claims);
  if (vct !== SUPPORTED_VCT.CLOSED_CHECKOUT) refuse("AP2_VCT_UNSUPPORTED", `expected a closed Checkout Mandate (${SUPPORTED_VCT.CLOSED_CHECKOUT}), got ${vct}`);
  assertClosedClaims(claims, CLAIMS_CLOSED_CHECKOUT, "closed Checkout Mandate");
  if (typeof claims.checkout_hash !== "string" || claims.checkout_hash.length !== CAPS.transactionIdChars || !/^[A-Za-z0-9_-]+$/.test(claims.checkout_hash)) {
    refuse("AP2_CHECKOUT_HASH_MISMATCH", "checkout_hash must be an unpadded base64url sha-256 digest");
  }
  let checkoutJwt = null;
  if (claims.checkout_jwt !== undefined) {
    if (typeof claims.checkout_jwt !== "string" || byteLen(claims.checkout_jwt) > CAPS.checkoutJwtBytes) {
      refuse("AP2_CHECKOUT_JWT_TOO_LARGE", `checkout_jwt exceeds ${CAPS.checkoutJwtBytes} bytes or is not a string`);
    }
    checkoutJwt = claims.checkout_jwt;
    const recomputed = b64urlSha256(checkoutJwt);
    if (recomputed !== claims.checkout_hash) refuse("AP2_CHECKOUT_HASH_MISMATCH", "checkout_hash does not recompute from the disclosed checkout_jwt");
    if (expectedTransactionId !== undefined && recomputed !== expectedTransactionId) {
      refuse("AP2_TRANSACTION_ID_INVALID", "the Payment Mandate transaction_id does not match the disclosed checkout_jwt digest");
    }
  }
  return { checkoutHash: claims.checkout_hash, checkoutJwtDisclosed: checkoutJwt !== null };
}

/*
 * Extract RESTRICTIVE-ONLY constraints from an OPEN mandate's reassembled
 * claims. Enforces the no-silent-absence rule: every constraint type the
 * deployment REQUIRES must be present and disclosed — an undisclosed
 * required slot refuses (AP2_DISCLOSURE_INCOMPLETE), because reading
 * absence as permission would let a shopping agent silently strip its
 * own spending limits (A-18: the single most important test).
 */
function extractOpenMandateConstraints(claims, { expectedVct, requiredConstraintTypes }) {
  const vct = gateVct(claims);
  if (vct !== expectedVct) refuse("AP2_VCT_UNSUPPORTED", `expected ${expectedVct}, got ${vct}`);
  assertClosedClaims(claims, vct === SUPPORTED_VCT.OPEN_PAYMENT ? CLAIMS_OPEN_PAYMENT : CLAIMS_OPEN_CHECKOUT, `open mandate ${vct}`);
  const list = claims.constraints;
  if (list !== undefined && !Array.isArray(list)) refuse("AP2_SCHEMA_UNKNOWN_FIELD", "constraints must be an array");
  const constraints = [];
  const presentTypes = new Set();
  for (const entry of list ?? []) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.type !== "string") {
      // Structurally unreadable constraint: carried to the evaluator,
      // which DENYs it — an unreadable control never allows.
      constraints.push({ type: null, value: entry });
      continue;
    }
    presentTypes.add(entry.type);
    constraints.push({ type: entry.type, value: entry });
  }
  for (const required of requiredConstraintTypes ?? []) {
    if (!presentTypes.has(required)) {
      refuse("AP2_DISCLOSURE_INCOMPLETE", `required constraint slot ${JSON.stringify(required)} was not disclosed — absence is never read as "unconstrained"`);
    }
  }
  return constraints;
}

module.exports = {
  SUPPORTED_VCT,
  CAPS,
  normalizeClosedPaymentMandate,
  normalizeClosedCheckoutMandate,
  extractOpenMandateConstraints
};
