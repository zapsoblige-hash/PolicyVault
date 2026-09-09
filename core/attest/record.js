"use strict";

/*
 * policyvault-execution-attestation/1 — RECORD BUILDER.
 *
 * The builder is deliberately unforgiving: it takes a COMPLETE body (the
 * closed key set in schema.js), validates shape AND cross-field
 * consistency, and only then stamps the canonical hash. There is no
 * default-filling, no coercion and no "best effort" — a caller that does
 * not know a fact must say so with the explicit NOT_AVAILABLE sentinel
 * (where the schema permits it) rather than let the builder invent one.
 *
 * A builder can therefore never emit a record that this project's own
 * verifier would refuse.
 */

const { attestationBodyOf, computeAttestationHashV1 } = require("./canonical");
const S = require("./schema");
const { verifyAttestation, approvalSignatureDigest } = require("./verify");

class AttestationError extends Error {
  constructor(code, message, failures = []) {
    super(message);
    this.name = "AttestationError";
    this.code = code;
    this.failures = failures;
  }
}

/*
 * body -> frozen record { ...body, attestationHash, signature: null }.
 * Throws AttestationError with the full failure list on anything invalid.
 */
function buildExecutionAttestation(body) {
  if (!S.isPlainObject(body)) {
    throw new AttestationError("ATTESTATION_INPUT_INVALID", "attestation body must be a plain object");
  }
  for (const key of ["attestationHash", "signature"]) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      throw new AttestationError("ATTESTATION_INPUT_INVALID", `the builder mints ${key}; do not supply it`);
    }
  }
  if (body.attestationVersion !== S.ATTESTATION_VERSION_1) {
    throw new AttestationError(
      "ATTESTATION_VERSION_UNSUPPORTED",
      `this builder emits exactly ${S.ATTESTATION_VERSION_1}; got ${JSON.stringify(body.attestationVersion)} — failing closed`
    );
  }
  let attestationHash;
  try {
    attestationHash = computeAttestationHashV1(body);
  } catch (e) {
    throw new AttestationError("ATTESTATION_NOT_CANONICAL", `attestation body does not canonicalize: ${e.message}`);
  }
  const record = { ...body, attestationHash, signature: null };

  /* SELF-CHECK: the builder runs the real verifier over its own output —
   * the same code an independent third party runs. */
  const verification = verifyAttestation(record);
  if (!verification.structural.ok) {
    throw new AttestationError(
      "ATTESTATION_INVALID",
      `refusing to emit an attestation this project's own verifier rejects: ${verification.failureCodes.join(", ")}`,
      verification.structural.failures
    );
  }
  return deepFreeze(record);
}

/*
 * Attach a detached signature to a finished record. THE RECORD HASH DOES
 * NOT CHANGE — the slot lives outside the hashed body by design, so a
 * deployment that later signs its attestations does not re-identify
 * records it already issued.
 *
 * NOTE (deliberate, permanent): PolicyVault does NOT implement an
 * attestation signing key here. Signing would be a per-deployment
 * operator key over evidence, and this codebase never introduces a
 * server-held key anywhere near funds. An attestation's authority is its
 * chain-verifiable facts; the slot exists so a deployment that wants
 * issuer provenance can add it additively, and the verifier reports any
 * attached signature as UNVERIFIED until a real key verifier exists.
 */
function attachSignature(record, signature) {
  if (!S.isPlainObject(record) || typeof record.attestationHash !== "string") {
    throw new AttestationError("ATTESTATION_INPUT_INVALID", "attachSignature needs a built attestation record");
  }
  if (!S.isPlainObject(signature)) {
    throw new AttestationError("ATTESTATION_INPUT_INVALID", "signature must be a plain object");
  }
  const next = deepFreeze({ ...record, signature: { ...signature } });
  const verification = verifyAttestation(next);
  if (!verification.structural.ok) {
    throw new AttestationError("ATTESTATION_INVALID", `signature slot rejected: ${verification.failureCodes.join(", ")}`, verification.structural.failures);
  }
  if (next.attestationHash !== record.attestationHash) {
    throw new AttestationError("ATTESTATION_INVALID", "internal: attaching a signature must never change the record hash");
  }
  return next;
}

/* Recompute the identity of an arbitrary record (envelope stripped). */
function recomputeAttestationHash(record) {
  return computeAttestationHashV1(attestationBodyOf(record));
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object") return value;
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return Object.freeze(value);
}

module.exports = {
  AttestationError,
  buildExecutionAttestation,
  attachSignature,
  recomputeAttestationHash,
  approvalSignatureDigest
};
