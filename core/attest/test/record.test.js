"use strict";

/*
 * UNIT — policyvault-execution-attestation/1 record identity, builder
 * discipline, determinism, and the optional detached-signature slot.
 *
 * Layer: UNIT (pure core; no node, no store, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const A = require("../index");
const V = require("../testutil/vectors");

test("the record hash is sha256 over the domain-separated canonical body, and re-hashes exactly", () => {
  const rec = V.syntheticSpendAttestation();
  assert.equal(rec.attestationHash, A.recomputeAttestationHash(rec));
  assert.match(rec.attestationHash, /^[0-9a-f]{64}$/);

  /* Domain separation: the same body hashed under the intent-manifest
   * domain must NOT collide with the attestation hash. */
  const intent = require("../../intent/canonical");
  const body = A.attestationBodyOf(rec);
  assert.notEqual(intent.computeManifestHashV1(body), rec.attestationHash);
});

test("the hash is representation-independent: key reordering (a jsonb round trip) re-hashes identically", () => {
  const rec = V.syntheticSpendAttestation();
  const reordered = {};
  for (const key of Object.keys(rec).sort().reverse()) reordered[key] = rec[key];
  reordered.subject = Object.fromEntries(Object.entries(rec.subject).reverse());
  assert.equal(A.recomputeAttestationHash(reordered), rec.attestationHash);
  assert.equal(A.verifyAttestation(reordered).verdict, A.VERDICTS.STRUCTURE_VERIFIED);
});

test("building is deterministic: identical inputs yield an identical record and identical canonical bytes", () => {
  const a = V.syntheticSpendAttestation();
  const b = V.syntheticSpendAttestation();
  assert.equal(a.attestationHash, b.attestationHash);
  assert.equal(A.exportAttestationJson(a), A.exportAttestationJson(b));
});

test("the builder refuses to emit anything its own verifier would reject", () => {
  assert.throws(
    () => V.syntheticSpendAttestation({ outcome: { state: "VERIFIED_OUTCOME" } }),
    (e) => e.code === "ATTESTATION_INVALID" && e.failures.some((f) => f.code === "LADDER_STATE_MISMATCH")
  );
  assert.throws(
    () => V.syntheticSpendAttestation({ subject: { contractVersion: "policyvault-9.9" } }),
    (e) => e.code === "ATTESTATION_INVALID" && e.failures.some((f) => f.code === "CONTRACT_VERSION_UNSUPPORTED")
  );
});

test("the builder mints the envelope; a caller may not supply attestationHash or signature", () => {
  for (const key of ["attestationHash", "signature"]) {
    assert.throws(
      () => V.syntheticSpendAttestation({ [key]: null }),
      (e) => e.code === "ATTESTATION_INPUT_INVALID"
    );
  }
});

test("an unknown attestationVersion fails closed in the builder and the verifier — never routed to a default", () => {
  assert.throws(
    () => V.syntheticSpendAttestation({ attestationVersion: "policyvault-execution-attestation/2" }),
    (e) => e.code === "ATTESTATION_VERSION_UNSUPPORTED"
  );
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.attestationVersion = "policyvault-execution-attestation/2";
  const r = A.verifyAttestation(rec);
  assert.equal(r.verdict, A.VERDICTS.INVALID);
  assert.deepEqual(r.failureCodes, ["ATTESTATION_VERSION_UNSUPPORTED"]);
});

test("the OPTIONAL detached signature slot lives outside the identity: attaching one does not change the record hash, and is never reported verified", () => {
  const rec = V.syntheticSpendAttestation();
  const signed = A.attachSignature(rec, {
    scheme: A.SIGNATURE_SCHEME_1,
    keyId: "deployment-attestation-key-1",
    publicKey: V.H("ab"),
    value: "cd".repeat(64),
    signedAt: "2026-09-03T12:01:00.000Z"
  });
  assert.equal(signed.attestationHash, rec.attestationHash);
  const r = A.verifyAttestation(signed);
  assert.equal(r.structural.ok, true);
  assert.equal(r.signature.present, true);
  assert.equal(r.signature.verified, false, "no attestation-key verifier exists; a slot must never read as verified");
  assert.equal(r.signature.reason, "ATTESTATION_KEY_VERIFICATION_NOT_IMPLEMENTED");
  assert.ok(r.structural.warnings.some((w) => w.code === "SIGNATURE_PRESENT_UNVERIFIED"));
});

test("an unknown detached-signature scheme fails closed", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.signature = { scheme: "some-other-signature/1", keyId: "k", publicKey: V.H("ab"), value: "cd".repeat(64), signedAt: "2026-09-03T12:01:00.000Z" };
  rec.attestationHash = A.recomputeAttestationHash(rec);
  const r = A.verifyAttestation(rec);
  assert.equal(r.verdict, A.VERDICTS.INVALID);
  assert.ok(r.failureCodes.includes("SIGNATURE_SCHEME_UNKNOWN"));
});

test("POSITIVE VECTOR — the live testnet-10 v0.6 SELL leg builds, verifies, and reaches VERIFIED_OUTCOME on real observed facts", () => {
  const rec = V.liveTestnetSellAttestation();
  const doc = V.loadEvidence();
  const r = A.verifyAttestation(rec);
  assert.equal(r.structural.ok, true, JSON.stringify(r.structural.failures));
  assert.equal(r.verdict, A.VERDICTS.STRUCTURE_VERIFIED);
  assert.equal(r.chainConfirmed, false, "structure alone never confirms the chain");
  assert.equal(rec.outcome.txId, doc.summary.sellTxId);
  assert.equal(rec.outcome.state, "VERIFIED_OUTCOME");
  assert.equal(rec.subject.contractVersion, "policyvault-0.6");
  assert.equal(rec.outcome.chain.outputs.length, 5);
  /* the gaps in the source transcript are reported, never invented */
  assert.equal(rec.authorization.signerVisibleDigest, A.NOT_AVAILABLE);
  assert.equal(rec.subject.requestId, A.NOT_AVAILABLE);
  assert.ok(r.structural.warnings.some((w) => w.code === "SIGNER_DIGEST_NOT_RECORDED"));
});

test("POSITIVE VECTOR — a REFUSED authorization is exportable evidence with no ladder state and no transaction", () => {
  const rec = V.refusedAttestation();
  const r = A.verifyAttestation(rec);
  assert.equal(r.structural.ok, true, JSON.stringify(r.structural.failures));
  assert.equal(rec.outcome.reached.length, 0);
  assert.equal(rec.outcome.txId, null);
  assert.equal(rec.authorization.refusalCode, "AGENT_CAP_EXCEEDED");
});

test("NO SECRET SLOTS: the record key set has no place for keys, tokens, prompts, or personal data", () => {
  const rec = V.syntheticSpendAttestation();
  const text = JSON.stringify(rec).toLowerCase();
  for (const banned of ["privatekey", "secret", "seed", "mnemonic", "bearer", "token_hash", "tokenhash", "cookie", "password", "prompt", "email"]) {
    assert.ok(!text.includes(banned), `attestation must never carry ${banned}`);
  }
  /* raw approval signatures are 130-hex; only 64-hex digests may appear */
  for (const d of rec.approvals.approvalDigests) assert.match(d.signatureDigest, /^[0-9a-f]{64}$/);
});

test("approvalSignatureDigest is sha256 over the exact signature hex and refuses non-hex", () => {
  const crypto = require("node:crypto");
  const sig = "ab".repeat(65);
  assert.equal(A.approvalSignatureDigest(sig), crypto.createHash("sha256").update(sig, "utf8").digest("hex"));
  assert.throws(() => A.approvalSignatureDigest("nothex"), (e) => e.code === "ATTESTATION_INPUT_INVALID");
});
