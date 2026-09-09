"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — structured error taxonomy.
 *
 * ADDITIVE VERSIONING (the same rule the covenant versions follow): the
 * v1 vocabulary in `core/signer/errors.js` is FROZEN and is NEVER mutated
 * or re-interpreted here. v2 re-declares every v1 code with its v1
 * meaning and adds the codes v1 had no vocabulary for — capability
 * probing, sighash negotiation, transaction-format pinning, transport
 * negotiation, user presence, request expiry, consumer cancellation,
 * request/response binding, replay, duplicate settlement, and
 * verified-bytes drift.
 *
 * A v2 adapter/consumer that emits a code outside THIS set has broken the
 * v2 contract: it is mapped, fail closed, to PROTOCOL_VIOLATION — never
 * passed through, never guessed into a "similar" meaning.
 *
 * Pure CommonJS. Zero external dependencies. No Node builtins. No imports
 * from server/ or sdk/. Browser-portable through web/core-bundle.js.
 */

const v1 = require("../errors");

const SIGNER_INTERFACE_VERSION_V2 = "policyvault-signer/2";

/*
 * CLOSED error-code vocabulary for interface v2.
 *
 * Block 1 — the v1 codes, carried forward with IDENTICAL meanings (an
 * adapter or consumer written against v1's taxonomy keeps its exact
 * classification when it is lifted to v2).
 *
 * Block 2 — v2 additions. Each exists because v1 had to collapse the
 * condition into a coarser code (or could not express it at all), which
 * is precisely why a NEW interface version rather than a v1 amendment.
 */
const SignerErrorCodesV2 = Object.freeze({
  /* ---- block 1: v1 codes, unchanged meanings ---- */
  SIGNER_NOT_FOUND: v1.SignerErrorCodes.SIGNER_NOT_FOUND,
  SIGNER_DISCONNECTED: v1.SignerErrorCodes.SIGNER_DISCONNECTED,
  SIGNER_LOCKED: v1.SignerErrorCodes.SIGNER_LOCKED,
  USER_REJECTED: v1.SignerErrorCodes.USER_REJECTED,
  WRONG_NETWORK: v1.SignerErrorCodes.WRONG_NETWORK,
  ACCOUNT_CHANGED: v1.SignerErrorCodes.ACCOUNT_CHANGED,
  UNSUPPORTED_CAPABILITY: v1.SignerErrorCodes.UNSUPPORTED_CAPABILITY,
  UNSUPPORTED_SCHEME: v1.SignerErrorCodes.UNSUPPORTED_SCHEME,
  INVALID_PUBLIC_KEY: v1.SignerErrorCodes.INVALID_PUBLIC_KEY,
  INVALID_SIGNATURE_RESPONSE: v1.SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
  SIGNER_TIMEOUT: v1.SignerErrorCodes.SIGNER_TIMEOUT,
  PROVIDER_ERROR: v1.SignerErrorCodes.PROVIDER_ERROR,
  PROTOCOL_VIOLATION: v1.SignerErrorCodes.PROTOCOL_VIOLATION,
  INTERFACE_VERSION_UNSUPPORTED: v1.SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
  REQUEST_INVALID: v1.SignerErrorCodes.REQUEST_INVALID,

  /* ---- block 2: v2 additions ---- */

  /* The signer does not declare (or returned something other than) the
   * sighash behaviour the request requires. PolicyVault emits SIGHASH_ALL
   * ONLY; a signer that cannot commit to signing all outputs cannot sign
   * a PolicyVault transaction. v1 could only express this as
   * UNSUPPORTED_CAPABILITY, which loses the reason. */
  UNSUPPORTED_SIGHASH: "UNSUPPORTED_SIGHASH",

  /* The signer does not speak the exact transaction serialization format
   * the request pins (v2 pins "kaspa-safe-json/1" — what the SDK builders
   * emit and what the finalizer re-derives the frozen txid from). */
  UNSUPPORTED_TRANSACTION_FORMAT: "UNSUPPORTED_TRANSACTION_FORMAT",

  /* The adapter's transport kind is not one the consumer accepts for this
   * request (e.g. a policy that refuses to hand a mainnet payload to a
   * deep-link transport). */
  TRANSPORT_UNSUPPORTED: "TRANSPORT_UNSUPPORTED",

  /* The consumer requires a HUMAN present at the signer for this request
   * and the adapter does not declare userPresence: "required". */
  USER_PRESENCE_REQUIRED: "USER_PRESENCE_REQUIRED",

  /* The request's own expiry elapsed — before invocation (stale request
   * replayed out of a queue) or before the signer settled. Distinct from
   * SIGNER_TIMEOUT, which is the CONSUMER's per-execution deadline. */
  REQUEST_EXPIRED: "REQUEST_EXPIRED",

  /* The consumer cancelled the request (navigation, policy revocation,
   * an approver withdrawing) before the signer settled. Distinct from
   * USER_REJECTED, which is the signer HOLDER declining. */
  REQUEST_CANCELLED: "REQUEST_CANCELLED",

  /* The response envelope is not bound to THIS request: requestId, nonce,
   * kind, network, signer address, scheme, sighash, transaction format or
   * declared interface version does not match. v1 had no envelope at all
   * (bare strings), so this condition was structurally undetectable. */
  RESPONSE_BINDING_MISMATCH: "RESPONSE_BINDING_MISMATCH",

  /* A response envelope (or its nonce) was already consumed — a transport
   * replayed an old, validly-signed answer at a new request. */
  REPLAY_DETECTED: "REPLAY_DETECTED",

  /* A second settlement arrived for a request that already reached a
   * terminal state (duplicate deep-link callback, double QR scan, a
   * relay delivering twice). */
  DUPLICATE_SETTLEMENT: "DUPLICATE_SETTLEMENT",

  /* The bytes that were signed are NOT the bytes that were locally
   * verified: the response's payload digest differs from the request's,
   * or the signed transaction's derived id differs from the unsigned
   * one's. The signature is discarded. */
  PAYLOAD_MUTATED: "PAYLOAD_MUTATED",

  /* A capability PROBE of the live signer contradicts what the adapter's
   * descriptor DECLARES. Declaring more than the provider can do is a
   * contract breach, refused before any signing. */
  CAPABILITY_MISMATCH: "CAPABILITY_MISMATCH"
});

const KNOWN_CODES_V2 = Object.freeze(new Set(Object.values(SignerErrorCodesV2)));

function isKnownErrorCodeV2(code) {
  return typeof code === "string" && KNOWN_CODES_V2.has(code);
}

function assertKnownErrorCodeV2(code) {
  if (!isKnownErrorCodeV2(code)) {
    const shown = typeof code === "string" ? JSON.stringify(code) : typeof code;
    const err = new Error(
      `unknown signer error code ${shown} — not in the ${SIGNER_INTERFACE_VERSION_V2} vocabulary; failing closed`
    );
    err.signerCode = SignerErrorCodesV2.PROTOCOL_VIOLATION;
    throw err;
  }
  return code;
}

/*
 * The one structured error type of interface v2. It deliberately extends
 * the v1 SignerError CLASS so that consumers holding a mixed v1/v2
 * registry can keep a single `instanceof` check and a single
 * `signerCode` read — but its constructor validates against the WIDER v2
 * vocabulary. `details` carries NON-SECRET diagnostics only (never key
 * material, never raw malformed payloads — shapes and digests only).
 */
class SignerErrorV2 extends v1.SignerError {
  constructor(code, message, { details, cause } = {}) {
    assertKnownErrorCodeV2(code);
    /* v1's constructor would refuse a v2-only code, so construct through
     * a code it accepts and restate the real classification afterwards.
     * PROTOCOL_VIOLATION is the fail-closed choice for that instant: if
     * anything below threw, the error still reads as a contract breach. */
    super(v1.SignerErrorCodes.PROTOCOL_VIOLATION, message || code, { details, cause });
    this.name = "SignerErrorV2";
    this.signerCode = code;
    this.interfaceVersion = SIGNER_INTERFACE_VERSION_V2;
  }
}

function signerErrorV2(code, message, extra) {
  return new SignerErrorV2(code, message, extra);
}

function isSignerErrorV2(e) {
  return e instanceof SignerErrorV2;
}

/*
 * Fail-closed normalization of ANYTHING thrown across the v2 adapter
 * boundary, with exactly the v1 rules widened to the v2 vocabulary:
 *
 *   1. a SignerErrorV2 passes through unchanged;
 *   2. a v1 SignerError (e.g. thrown by a lifted v1 adapter or by the
 *      shared v1 helpers this module reuses) is re-expressed as a
 *      SignerErrorV2 with the SAME code — v1 codes are all v2 codes;
 *   3. an error-like value carrying a KNOWN v2 signerCode is the
 *      sanctioned adapter-side classification: wrapped preserving code,
 *      message and cause;
 *   4. an error-like value carrying an UNKNOWN signerCode broke the
 *      contract -> PROTOCOL_VIOLATION, claimed code recorded;
 *   5. anything else -> PROVIDER_ERROR with the original as `cause`.
 */
function normalizeAdapterFailureV2(raw, context) {
  const where = context ? `${context}: ` : "";
  if (isSignerErrorV2(raw)) return raw;
  if (v1.isSignerError(raw)) {
    return new SignerErrorV2(raw.signerCode, raw.message, { details: raw.details, cause: raw.cause !== undefined ? raw.cause : raw });
  }
  const claimed = raw && typeof raw === "object" ? raw.signerCode : undefined;
  if (claimed !== undefined) {
    if (isKnownErrorCodeV2(claimed)) {
      return new SignerErrorV2(claimed, `${where}${(raw && raw.message) || claimed}`, { cause: raw });
    }
    return new SignerErrorV2(
      SignerErrorCodesV2.PROTOCOL_VIOLATION,
      `${where}adapter emitted unknown error code ${JSON.stringify(String(claimed))} — outside the ${SIGNER_INTERFACE_VERSION_V2} vocabulary; failing closed`,
      { details: { claimedCode: String(claimed) }, cause: raw }
    );
  }
  const message = raw && typeof raw === "object" && typeof raw.message === "string" && raw.message ? raw.message : String(raw);
  return new SignerErrorV2(SignerErrorCodesV2.PROVIDER_ERROR, `${where}${message}`, { cause: raw });
}

module.exports = {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  SignerErrorV2,
  signerErrorV2,
  isSignerErrorV2,
  isKnownErrorCodeV2,
  assertKnownErrorCodeV2,
  normalizeAdapterFailureV2
};
