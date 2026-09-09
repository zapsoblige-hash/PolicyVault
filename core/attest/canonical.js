"use strict";

/*
 * PolicyVault EXECUTION ATTESTATION — canonical serialization + record hash.
 *
 * PORTABLE SHARED CORE (core/attest): pure CommonJS, zero external
 * dependencies, no sdk/ or server/ imports. The only Node builtin reached
 * is node:crypto sha256, and only indirectly through core/intent/canonical
 * (which isolates it behind sha256Hex for a future WebCrypto substitution).
 *
 * THE CANONICALIZER IS NOT REDEFINED HERE. core/intent/canonical.js is the
 * project's portable G-2 serializer (values-only, key-order-independent,
 * fail-closed on undefined/BigInt/non-finite/non-plain objects); a third
 * copy would be a drift surface, so this module imports it verbatim and
 * only adds its own HASH DOMAIN.
 *
 * Hash-domain separation: an execution-attestation hash must never collide
 * with an intent-manifest hash, an approval-package commitment, a frozen-tx
 * commitment, a governance proposal digest, or a state ID. The domain
 * string below is version-bound: a future attestation version defines its
 * own domain and never reuses this one.
 *
 * WHY THE ATTESTATION HASH CARRIES A TIMESTAMP AND THE MANIFEST HASH DOES
 * NOT: an intent manifest is content-addressed evidence about a transaction
 * (identical facts must hash identically forever, on any machine, through
 * any storage backend). An attestation is a POINT-IN-TIME OBSERVATION —
 * the same request legitimately yields different attestations as chain
 * depth grows — so producedAt and the observed DAA score are INSIDE the
 * hashed body. Two attestations of one request are expected to differ;
 * the hash identifies the exact observation, not the request.
 */

const { canonicalJsonStringify, sha256Hex } = require("../intent/canonical");

const ATTESTATION_HASH_DOMAIN_V1 = "policyvault-execution-attestation-hash/1\n";

/* Envelope keys that sit OUTSIDE the hashed body: a hash cannot cover
 * itself, and the OPTIONAL detached signature slot must be attachable to
 * (and strippable from) a finished record without changing its identity. */
const ENVELOPE_KEYS = Object.freeze(["attestationHash", "signature"]);

function fail(message, code = "ATTESTATION_CANONICAL_INVALID") {
  const e = new Error(`attest-canonical: ${message}`);
  e.code = code;
  throw e;
}

/*
 * The hashed BODY of a record: the record minus the envelope keys. Pure —
 * never mutates its input.
 */
function attestationBodyOf(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    fail("attestation record must be a plain object");
  }
  const body = {};
  for (const key of Object.keys(record)) {
    if (!ENVELOPE_KEYS.includes(key)) body[key] = record[key];
  }
  return body;
}

/*
 * sha256 over the domain prefix + canonical JSON of the body. The body
 * must NOT carry the envelope keys (strip them first with
 * attestationBodyOf) — a body that does is a caller defect, not a
 * different hash.
 */
function computeAttestationHashV1(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    fail("attestation body must be a plain object");
  }
  for (const key of ENVELOPE_KEYS) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      fail(`attestation body must not contain ${key} — strip the envelope before hashing`);
    }
  }
  return sha256Hex(ATTESTATION_HASH_DOMAIN_V1 + canonicalJsonStringify(body));
}

module.exports = {
  ATTESTATION_HASH_DOMAIN_V1,
  ENVELOPE_KEYS,
  canonicalJsonStringify,
  sha256Hex,
  attestationBodyOf,
  computeAttestationHashV1
};
