"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — structured error taxonomy.
 *
 * Every failure that crosses the signer-adapter boundary is expressed as a
 * SignerError carrying a code from the CLOSED vocabulary below. The
 * vocabulary is frozen for interface v1: an adapter (or consumer) that
 * emits a code outside this set is treated as having BROKEN the interface
 * contract and its failure is mapped, fail closed, to PROTOCOL_VIOLATION —
 * never passed through, never guessed into a "similar" meaning, never
 * routed to a benign default.
 *
 * Design lineage (read-only reference, not imported):
 *   - web/wallet.js `WalletError` — the existing browser adapter categories
 *     (WALLET_NOT_FOUND, USER_REJECTED, WRONG_NETWORK, SIGNING_UNSUPPORTED,
 *     INVALID_SIGNATURE_RESPONSE, INVALID_PUBLIC_KEY, PROVIDER_ERROR, ...).
 *   - server/src/auth.js `AuthErrorCodes` — the hosted challenge/verify
 *     codes (server side; NOT duplicated here — authentication decisions
 *     stay server-side, this module only classifies signer-side failures).
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from
 * server/ or sdk/.
 */

const SIGNER_INTERFACE_VERSION = "policyvault-signer/1";

/* CLOSED error-code vocabulary for interface v1. */
const SignerErrorCodes = Object.freeze({
  /* Presence / session */
  SIGNER_NOT_FOUND: "SIGNER_NOT_FOUND", // provider not installed / not reachable
  SIGNER_DISCONNECTED: "SIGNER_DISCONNECTED", // no connected/active account
  SIGNER_LOCKED: "SIGNER_LOCKED", // provider present but locked; user action needed

  /* Human / policy decisions */
  USER_REJECTED: "USER_REJECTED", // the signer's holder declined the request

  /* Identity / environment binding (fail-closed identity boundary) */
  WRONG_NETWORK: "WRONG_NETWORK", // live or declared network != required network
  ACCOUNT_CHANGED: "ACCOUNT_CHANGED", // active identity changed before/during/after signing

  /* Capability negotiation */
  UNSUPPORTED_CAPABILITY: "UNSUPPORTED_CAPABILITY", // adapter does not offer a required feature
  UNSUPPORTED_SCHEME: "UNSUPPORTED_SCHEME", // required signature scheme not offered / not contract-defined

  /* Material validation */
  INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY", // provider public key claim malformed / unsupported encoding
  INVALID_SIGNATURE_RESPONSE: "INVALID_SIGNATURE_RESPONSE", // signing result malformed for the requested scheme/kind

  /* Lifecycle */
  SIGNER_TIMEOUT: "SIGNER_TIMEOUT", // approval deadline elapsed; request cancelled fail-closed

  /* Faults */
  PROVIDER_ERROR: "PROVIDER_ERROR", // unclassified provider/transport exception (cause preserved)
  PROTOCOL_VIOLATION: "PROTOCOL_VIOLATION", // adapter/consumer broke the interface contract (incl. unknown codes)
  INTERFACE_VERSION_UNSUPPORTED: "INTERFACE_VERSION_UNSUPPORTED", // version mismatch — fail closed, no downgrade
  REQUEST_INVALID: "REQUEST_INVALID" // malformed signing request / options refused before the signer is invoked
});

const KNOWN_CODES = Object.freeze(new Set(Object.values(SignerErrorCodes)));

/*
 * Throws when `code` is not part of the v1 vocabulary. Used both by the
 * SignerError constructor (a PolicyVault component must never mint an
 * unknown code) and by adapter-failure normalization (an adapter claiming
 * an unknown code is a contract breach).
 */
function assertKnownErrorCode(code) {
  if (typeof code !== "string" || !KNOWN_CODES.has(code)) {
    const shown = typeof code === "string" ? JSON.stringify(code) : typeof code;
    const err = new Error(`unknown signer error code ${shown} — not in the ${SIGNER_INTERFACE_VERSION} vocabulary; failing closed`);
    err.signerCode = SignerErrorCodes.PROTOCOL_VIOLATION;
    throw err;
  }
  return code;
}

function isKnownErrorCode(code) {
  return typeof code === "string" && KNOWN_CODES.has(code);
}

/*
 * The one structured error type of the interface. `signerCode` is the
 * machine-readable classification; `details` is an optional plain object of
 * NON-SECRET diagnostic fields (never key material, never seed phrases,
 * never raw provider payload dumps). `cause` preserves the original
 * exception for diagnostics without altering classification.
 */
class SignerError extends Error {
  constructor(code, message, { details, cause } = {}) {
    assertKnownErrorCode(code);
    super(message || code);
    this.name = "SignerError";
    this.signerCode = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

function signerError(code, message, extra) {
  return new SignerError(code, message, extra);
}

function isSignerError(e) {
  return e instanceof SignerError;
}

/*
 * Fail-closed normalization of ANYTHING thrown across the adapter
 * boundary into a SignerError:
 *
 *   1. A SignerError passes through unchanged (already classified by this
 *      module — its constructor enforced a known code).
 *   2. An error-like value carrying a KNOWN `signerCode` is the sanctioned
 *      way for adapters to classify their own failures (mirrors
 *      web/wallet.js `walletCategory`): it is wrapped preserving code,
 *      message, and the original as `cause`.
 *   3. An error-like value carrying an UNKNOWN `signerCode` broke the
 *      contract: mapped to PROTOCOL_VIOLATION with the claimed code
 *      recorded in details. NEVER passed through, NEVER guessed.
 *   4. Anything else (plain Error, string, undefined, ...) is an
 *      unclassified provider fault: PROVIDER_ERROR with cause preserved.
 *
 * `context` is a short human label ("signMessage", "getNetwork", ...)
 * prefixed into the message for diagnosability.
 */
function normalizeAdapterFailure(raw, context) {
  const where = context ? `${context}: ` : "";
  if (isSignerError(raw)) return raw;
  const claimed = raw && typeof raw === "object" ? raw.signerCode : undefined;
  if (claimed !== undefined) {
    if (isKnownErrorCode(claimed)) {
      return new SignerError(claimed, `${where}${raw.message || claimed}`, { cause: raw });
    }
    return new SignerError(
      SignerErrorCodes.PROTOCOL_VIOLATION,
      `${where}adapter emitted unknown error code ${JSON.stringify(String(claimed))} — outside the ${SIGNER_INTERFACE_VERSION} vocabulary; failing closed`,
      { details: { claimedCode: String(claimed) }, cause: raw }
    );
  }
  const message = raw && typeof raw === "object" && typeof raw.message === "string" && raw.message ? raw.message : String(raw);
  return new SignerError(SignerErrorCodes.PROVIDER_ERROR, `${where}${message}`, { cause: raw });
}

module.exports = {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  SignerError,
  signerError,
  isSignerError,
  isKnownErrorCode,
  assertKnownErrorCode,
  normalizeAdapterFailure
};
