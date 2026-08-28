"use strict";

/*
 * Idempotency-key derivations for the x402 and AP2 adapters — EXACTLY the
 * derivations of x402-adapter-spec.md §3.4 and ap2-adapter-spec.md §3.4.
 *
 * A protocol retry must never duplicate a spend. The caller-supplied
 * anchor (x402 `attemptId`, AP2 Payment-Mandate `transaction_id`) is
 * MANDATORY — the adapter never mints its own (a self-minted id would
 * make every network-level retry a fresh spend). The derived key is sent
 * as the Agent API `Idempotency-Key` header, which the platform scopes
 * per authenticated identity (`machine:<identityId>`), so two adapters /
 * tenants can never collide or replay each other's keys.
 */

const { domainDigestHex } = require("./canonical");

const X402_REQUIREMENT_DOMAIN = "policyvault-x402-requirement-digest/1";
const X402_IDEMPOTENCY_DOMAIN = "policyvault-x402-idempotency/1";
const AP2_MANDATE_DOMAIN = "policyvault-ap2-mandate-digest/1";
const AP2_IDEMPOTENCY_DOMAIN = "policyvault-ap2-idempotency/1";

/* x402: digest of the untrusted requirement material the adapter decided
 * on. `resource` and `accepted` are the PARSED values (canonicalized —
 * representation-independent); the byte-verbatim echo (§4.6) is carried
 * separately as raw slices and is deliberately NOT the digest preimage. */
function x402RequirementDigest({ x402Version, resource, accepted }) {
  return domainDigestHex(X402_REQUIREMENT_DOMAIN, { x402Version, resource, accepted });
}

function x402IdempotencyKey({ attemptId, requirementDigest, vaultId, agentPk }) {
  for (const [k, v] of Object.entries({ attemptId, requirementDigest, vaultId, agentPk })) {
    if (typeof v !== "string" || !v) throw new Error(`x402IdempotencyKey: ${k} must be a non-empty string`);
  }
  return `pvx402-${domainDigestHex(X402_IDEMPOTENCY_DOMAIN, { attemptId, requirementDigest, vaultId, agentPk })}`;
}

/* AP2: digest of the decision-relevant closed-mandate content (spec §3.4
 * preimage list, verbatim). `exp` may be absent; canonical-json refuses
 * undefined, so absence is committed as null — one value, one encoding. */
function ap2MandateDigest({ vct, transaction_id, payee, payment_amount, payment_instrument, exp }) {
  return domainDigestHex(AP2_MANDATE_DOMAIN, {
    vct,
    transaction_id,
    payee,
    payment_amount,
    payment_instrument,
    exp: exp === undefined ? null : exp
  });
}

function ap2IdempotencyKey({ transaction_id, paymentMandateDigest, vaultId, agentPk }) {
  for (const [k, v] of Object.entries({ transaction_id, paymentMandateDigest, vaultId, agentPk })) {
    if (typeof v !== "string" || !v) throw new Error(`ap2IdempotencyKey: ${k} must be a non-empty string`);
  }
  return `pvap2-${domainDigestHex(AP2_IDEMPOTENCY_DOMAIN, { transaction_id, paymentMandateDigest, vaultId, agentPk })}`;
}

module.exports = {
  X402_REQUIREMENT_DOMAIN,
  X402_IDEMPOTENCY_DOMAIN,
  AP2_MANDATE_DOMAIN,
  AP2_IDEMPOTENCY_DOMAIN,
  x402RequirementDigest,
  x402IdempotencyKey,
  ap2MandateDigest,
  ap2IdempotencyKey
};
