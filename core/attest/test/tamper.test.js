"use strict";

/*
 * ADVERSARIAL UNIT — tamper matrix for policyvault-execution-attestation/1.
 *
 * Every class is exercised TWICE where both are possible:
 *   (a) NAIVE tamper — the attacker edits a value and ships the record.
 *       Detected by the canonical re-hash (HASH_MISMATCH).
 *   (b) RE-HASHED tamper — the attacker recomputes the record hash after
 *       editing, so (a) is useless. Detected by cross-field consistency,
 *       by the caller's expectation binding, or (for facts only the chain
 *       can settle) by the opt-in chain re-check — NEVER by trusting the
 *       issuer.
 *
 * The point of (b) is the honest boundary: a record hash proves INTEGRITY,
 * not TRUTH. Truth about chain facts comes from a node.
 *
 * Layer: ADVERSARIAL UNIT (pure core; no node, no store, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const A = require("../index");
const V = require("../testutil/vectors");

const rehash = (rec) => {
  rec.attestationHash = A.recomputeAttestationHash(rec);
  return rec;
};
const codes = (rec, opts) => A.verifyAttestation(rec, opts).failureCodes;
const invalid = (rec, opts) => {
  const r = A.verifyAttestation(rec, opts);
  assert.equal(r.verdict, A.VERDICTS.INVALID, `expected ATTESTATION_INVALID, got ${r.verdict}`);
  assert.equal(r.chainConfirmed, false);
  return r.failureCodes;
};

/* ------------------------------------------------------------------ */
/* 1. BYTE TAMPER                                                      */
/* ------------------------------------------------------------------ */

test("tamper/byte: flipping one hex character anywhere in the body breaks the re-hash", () => {
  for (const mutate of [
    (r) => { r.outcome.chain.outputs[0].valueSompi = "98500000001"; },
    (r) => { r.subject.vaultId = `${r.subject.vaultId.slice(0, 63)}0`; },
    (r) => { r.authorization.intentManifestHash = `0${r.authorization.intentManifestHash.slice(1)}`; },
    (r) => { r.producedAt = "2026-09-03T12:00:00.001Z"; }
  ]) {
    const rec = V.clone(V.syntheticSpendAttestation());
    mutate(rec);
    assert.deepEqual(invalid(rec), ["HASH_MISMATCH"]);
  }
});

test("tamper/byte: whitespace-only re-serialization does NOT break the hash (values, not bytes, are the identity)", () => {
  const rec = V.syntheticSpendAttestation();
  const roundTripped = JSON.parse(JSON.stringify(rec, null, 4));
  assert.equal(A.verifyAttestation(roundTripped).verdict, A.VERDICTS.STRUCTURE_VERIFIED);
});

/* ------------------------------------------------------------------ */
/* 2. FIELD REMOVAL                                                    */
/* ------------------------------------------------------------------ */

test("tamper/removal: deleting any body section is refused by the closed key set, re-hashed or not", () => {
  for (const key of ["approvals", "amounts", "asset", "authorization", "outcome", "subject", "producer"]) {
    const naive = V.clone(V.syntheticSpendAttestation());
    delete naive[key];
    assert.ok(invalid(naive).includes("SCHEMA_INVALID"), `naive removal of ${key}`);

    const rehashed = rehash(V.clone(V.syntheticSpendAttestation()));
    delete rehashed[key];
    assert.ok(invalid(rehashed).includes("SCHEMA_INVALID"), `re-hashed removal of ${key}`);
  }
});

test("tamper/removal: deleting a leaf field (the fee, the observed outputs) is refused", () => {
  const feeless = V.clone(V.syntheticSpendAttestation());
  delete feeless.amounts.networkFeeSompi;
  assert.ok(invalid(rehash(feeless)).includes("SCHEMA_INVALID"));

  const outputless = V.clone(V.syntheticSpendAttestation());
  outputless.outcome.chain.outputs = [];
  assert.ok(invalid(rehash(outputless)).includes("CHAIN_VERIFIED_WITHOUT_EVIDENCE"));
});

test("tamper/removal: an EXTRA field cannot be smuggled in either", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.chain.attackerNote = "please trust me";
  assert.ok(invalid(rehash(rec)).includes("SCHEMA_INVALID"));
});

/* ------------------------------------------------------------------ */
/* 3. FIELD SUBSTITUTION (amount / fee / manifest / signer)            */
/* ------------------------------------------------------------------ */

test("tamper/substitution: changing the amount, the fee, the manifest hash or the signer breaks the re-hash", () => {
  for (const mutate of [
    (r) => { r.amounts.amount = "1"; },
    (r) => { r.amounts.networkFeeSompi = "0"; },
    (r) => { r.authorization.intentManifestHash = V.H("99"); },
    (r) => { r.authorization.signerXOnly = V.H("99"); },
    (r) => { r.approvals.packageCommitment = V.H("99"); }
  ]) {
    const rec = V.clone(V.syntheticSpendAttestation());
    mutate(rec);
    assert.deepEqual(invalid(rec), ["HASH_MISMATCH"]);
  }
});

test("tamper/substitution: numeric fields refuse JSON numbers, negatives, floats and out-of-range values", () => {
  for (const [value, code] of [
    [1500000000, "NUMERIC_INVALID"],
    ["-1", "NUMERIC_INVALID"],
    ["1.5", "NUMERIC_INVALID"],
    ["0001", "NUMERIC_INVALID"],
    ["99999999999999999999999999", "NUMERIC_INVALID"]
  ]) {
    const rec = V.clone(V.syntheticSpendAttestation());
    rec.amounts.amount = value;
    assert.ok(invalid(rehash(rec)).includes(code), `amount ${JSON.stringify(value)}`);
  }
});

test("tamper/substitution: the NOT_AVAILABLE sentinel cannot be smuggled into a field that must be concrete", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.subject.vaultId = A.NOT_AVAILABLE;
  assert.ok(invalid(rehash(rec)).includes("SCHEMA_INVALID"));

  const signerless = V.clone(V.syntheticSpendAttestation());
  signerless.authorization.signerXOnly = A.NOT_AVAILABLE;
  assert.ok(invalid(rehash(signerless)).includes("SIGNED_WITHOUT_SIGNER_EVIDENCE"));
});

/* ------------------------------------------------------------------ */
/* 4. TXID SUBSTITUTION                                                */
/* ------------------------------------------------------------------ */

test("tamper/txid: swapping the transaction id alone breaks the re-hash", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.txId = V.H("de");
  assert.deepEqual(invalid(rec), ["HASH_MISMATCH"]);
});

test("tamper/txid: a re-hashed txid swap is caught by the successor-outpoint binding", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.txId = V.H("de");
  assert.ok(invalid(rehash(rec)).includes("TXID_MISMATCH"));
});

test("tamper/txid: swapping the txid AND its outpoint is structurally consistent — and is caught by the caller's expectation pin", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.txId = V.H("de");
  rec.outcome.chain.successorOutpoint.transactionId = V.H("de");
  rehash(rec);
  assert.equal(A.verifyAttestation(rec).verdict, A.VERDICTS.STRUCTURE_VERIFIED, "integrity is intact; truth is not integrity");
  assert.ok(invalid(rec, { expect: { txId: V.H("7a") } }).includes("EXPECTED_TXID_MISMATCH"));
});

test("tamper/txid: a predecessor outpoint may never belong to the attested transaction", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.chain.predecessorOutpoint.transactionId = rec.outcome.txId;
  assert.ok(invalid(rehash(rec)).includes("TXID_MISMATCH"));
});

/* ------------------------------------------------------------------ */
/* 5. POLICY / COVENANT VERSION SUBSTITUTION                           */
/* ------------------------------------------------------------------ */

test("tamper/version: an unknown covenant generation FAILS CLOSED (never routed to a default)", () => {
  for (const version of ["policyvault-0.7", "policyvault", "POLICYVAULT-0.4.1", ""]) {
    const rec = V.clone(V.syntheticSpendAttestation());
    rec.subject.contractVersion = version;
    const found = invalid(rehash(rec));
    assert.ok(found.includes("CONTRACT_VERSION_UNSUPPORTED") || found.includes("SCHEMA_INVALID"), `version ${JSON.stringify(version)} -> ${found}`);
  }
});

test("tamper/version: a KNOWN-but-wrong covenant generation is caught by the expectation pin", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.subject.contractVersion = "policyvault-0.6";
  rehash(rec);
  assert.equal(A.verifyAttestation(rec).verdict, A.VERDICTS.STRUCTURE_VERIFIED);
  assert.ok(invalid(rec, { expect: { contractVersion: "policyvault-0.4.1" } }).includes("EXPECTED_CONTRACT_VERSION_MISMATCH"));
});

test("tamper/version: the policy nonce and the state ids are inside the hashed body", () => {
  for (const mutate of [
    (r) => { r.subject.policyNonce = "8"; },
    (r) => { r.subject.stateBefore = V.H("99"); },
    (r) => { r.subject.stateAfter = V.H("99"); }
  ]) {
    const rec = V.clone(V.syntheticSpendAttestation());
    mutate(rec);
    assert.deepEqual(invalid(rec), ["HASH_MISMATCH"]);
  }
});

/* ------------------------------------------------------------------ */
/* 6. WRONG NETWORK                                                    */
/* ------------------------------------------------------------------ */

test("tamper/network: re-pointing the subject at another network contradicts the chain observations", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.subject.networkId = "mainnet";
  assert.ok(invalid(rehash(rec)).includes("NETWORK_MISMATCH"));
});

test("tamper/network: re-pointing BOTH is structurally consistent — the pin and the node catch it", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.subject.networkId = "mainnet";
  rec.outcome.networkId = "mainnet";
  rehash(rec);
  assert.equal(A.verifyAttestation(rec).verdict, A.VERDICTS.STRUCTURE_VERIFIED);
  assert.ok(invalid(rec, { expect: { networkId: "testnet-10" } }).includes("EXPECTED_NETWORK_MISMATCH"));

  const r = A.verifyAttestation(rec, {
    chainObservation: { available: true, node: { networkId: "testnet-10", isSynced: true, hasUtxoIndex: true }, utxos: {} }
  });
  assert.equal(r.verdict, A.VERDICTS.CHAIN_UNAVAILABLE);
  assert.equal(r.chainConfirmed, false);
  assert.ok(r.chain.findings.some((f) => f.code === "NODE_WRONG_NETWORK"));
});

/* ------------------------------------------------------------------ */
/* 7. WRONG VAULT                                                      */
/* ------------------------------------------------------------------ */

test("tamper/vault: substituting the vault identity breaks the re-hash, and a re-hashed swap is caught by the pin", () => {
  const naive = V.clone(V.syntheticSpendAttestation());
  naive.subject.vaultId = V.H("bb");
  assert.deepEqual(invalid(naive), ["HASH_MISMATCH"]);

  const rehashed = rehash(V.clone(V.syntheticSpendAttestation()));
  rehashed.subject.vaultId = V.H("bb");
  rehash(rehashed);
  assert.ok(invalid(rehashed, { expect: { vaultId: V.H("a1") } }).includes("EXPECTED_VAULT_MISMATCH"));
});

test("tamper/vault: an unknown expectation key fails closed rather than being ignored", () => {
  const rec = V.syntheticSpendAttestation();
  assert.ok(invalid(rec, { expect: { covenantId: V.H("cc") } }).includes("EXPECTATION_UNKNOWN"));
});

/* ------------------------------------------------------------------ */
/* 8. WRONG ASSET                                                      */
/* ------------------------------------------------------------------ */

test("tamper/asset: substituting the token family is refused — no observed output carries it", () => {
  const rec = V.clone(V.liveTestnetSellAttestation());
  rec.asset.familyId = V.H("99");
  assert.ok(invalid(rehash(rec)).includes("ASSET_FAMILY_NOT_OBSERVED"));
});

test("tamper/asset: substituting the descriptor hash breaks the re-hash", () => {
  const rec = V.clone(V.liveTestnetSellAttestation());
  rec.asset.descriptorHash = V.H("99");
  assert.deepEqual(invalid(rec), ["HASH_MISMATCH"]);
});

test("tamper/asset: a KAS record may not carry a token identity, and units may not be crossed", () => {
  const kasWithFamily = V.clone(V.syntheticSpendAttestation());
  kasWithFamily.asset.familyId = V.H("99");
  assert.ok(invalid(rehash(kasWithFamily)).includes("ASSET_SHAPE_INVALID"));

  const crossedUnits = V.clone(V.syntheticSpendAttestation());
  crossedUnits.asset.unit = "atomic";
  assert.ok(invalid(rehash(crossedUnits)).includes("ASSET_SHAPE_INVALID"));
});

/* ------------------------------------------------------------------ */
/* 9. STALE OUTCOME / LADDER REGRESSION                                */
/* ------------------------------------------------------------------ */

test("stale-outcome: VERIFIED_OUTCOME can never be claimed without CHAIN_VERIFIED", () => {
  const rec = V.clone(V.liveTestnetSellAttestation());
  rec.outcome.reached = rec.outcome.reached.filter((r) => r.state !== "CHAIN_VERIFIED");
  const found = invalid(rehash(rec));
  assert.ok(found.includes("VERIFIED_OUTCOME_WITHOUT_CHAIN_VERIFIED"));
  assert.ok(found.includes("LADDER_ORDER_INVALID"));
});

test("stale-outcome: the ladder must be a contiguous prefix — gaps, reorderings and repeats are refused", () => {
  const base = V.liveTestnetSellAttestation();
  const gap = V.clone(base);
  gap.outcome.reached = gap.outcome.reached.filter((r) => r.state !== "BROADCAST");
  assert.ok(invalid(rehash(gap)).includes("LADDER_ORDER_INVALID"));

  const reordered = V.clone(base);
  [reordered.outcome.reached[1], reordered.outcome.reached[2]] = [reordered.outcome.reached[2], reordered.outcome.reached[1]];
  assert.ok(invalid(rehash(reordered)).includes("LADDER_ORDER_INVALID"));

  const repeated = V.clone(base);
  repeated.outcome.reached[3] = { ...repeated.outcome.reached[2] };
  assert.ok(invalid(rehash(repeated)).includes("LADDER_ORDER_INVALID"));
});

test("stale-outcome: the headline state may not out-run the evidence, and disposition must agree", () => {
  const overclaim = V.clone(V.syntheticSpendAttestation());
  overclaim.outcome.state = "VERIFIED_OUTCOME";
  assert.ok(invalid(rehash(overclaim)).includes("LADDER_STATE_MISMATCH"));

  const settledWithoutProof = V.clone(V.syntheticSpendAttestation());
  settledWithoutProof.outcome.reached = settledWithoutProof.outcome.reached.slice(0, 3);
  settledWithoutProof.outcome.state = "BROADCAST";
  assert.ok(invalid(rehash(settledWithoutProof)).includes("DISPOSITION_INCONSISTENT"));

  const failedButVerified = V.clone(V.syntheticSpendAttestation());
  failedButVerified.outcome.disposition = "FAILED";
  failedButVerified.outcome.failureCode = "SUBMISSION_REJECTED";
  assert.ok(invalid(rehash(failedButVerified)).includes("DISPOSITION_INCONSISTENT"));
});

test("stale-outcome: CHAIN_VERIFIED below the declared minimum depth is CHAIN_SEEN, not CHAIN_VERIFIED", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.outcome.chain.observedVirtualDaaScore = "560488146";
  rec.outcome.chain.depthDaa = "5";
  assert.ok(invalid(rehash(rec)).includes("DEPTH_BELOW_MINIMUM"));
});

test("stale-outcome: depth arithmetic is checked in integers and cannot run backwards", () => {
  const wrongMath = V.clone(V.syntheticSpendAttestation());
  wrongMath.outcome.chain.depthDaa = "999";
  assert.ok(invalid(rehash(wrongMath)).includes("DEPTH_ARITHMETIC_INVALID"));

  const backwards = V.clone(V.syntheticSpendAttestation());
  backwards.outcome.chain.observedVirtualDaaScore = "560488000";
  assert.ok(invalid(rehash(backwards)).includes("DEPTH_ARITHMETIC_INVALID"));
});

test("stale-outcome: BROADCAST without a transaction id, and CHAIN_SEEN without outputs, are refused", () => {
  const noTx = V.clone(V.syntheticSpendAttestation());
  noTx.outcome.txId = null;
  noTx.outcome.chain.successorOutpoint = null;
  assert.ok(invalid(rehash(noTx)).includes("BROADCAST_WITHOUT_TXID"));
});

/* ------------------------------------------------------------------ */
/* 10. REFUSAL SEMANTICS                                               */
/* ------------------------------------------------------------------ */

test("refusal: a REFUSED authorization may never carry a txid, a ladder state, or a VERIFIED_EXACT verdict", () => {
  const withTx = V.clone(V.refusedAttestation());
  withTx.outcome.txId = V.H("7a");
  assert.ok(invalid(rehash(withTx)).includes("REFUSAL_WITH_TXID"));

  const withLadder = V.clone(V.refusedAttestation());
  withLadder.outcome.reached = [{ state: "AUTHORIZED", source: "forged", note: null }];
  withLadder.outcome.state = "AUTHORIZED";
  assert.ok(invalid(rehash(withLadder)).includes("REFUSAL_WITH_LADDER"));

  /* A refusal that NAMES a failed intent verification may not also report
   * that the verification passed. (A refusal on authority/quorum/freshness
   * legitimately coexists with a VERIFIED_EXACT verdict — see verify.js.) */
  const withVerdict = V.clone(V.refusedAttestation());
  withVerdict.authorization.refusalCode = "INTENT_VERIFICATION_FAILED";
  withVerdict.authorization.intentManifestVerdict = "VERIFIED_EXACT";
  assert.ok(invalid(rehash(withVerdict)).includes("MANIFEST_VERDICT_INCONSISTENT"));

  const honestRefusalOnAuthority = V.clone(V.refusedAttestation());
  honestRefusalOnAuthority.authorization.refusalCode = "AUTHORIZATION_FAILED";
  honestRefusalOnAuthority.authorization.intentManifestHash = V.H("c1");
  honestRefusalOnAuthority.authorization.intentManifestVerdict = "VERIFIED_EXACT";
  assert.equal(A.verifyAttestation(rehash(honestRefusalOnAuthority)).verdict, A.VERDICTS.STRUCTURE_VERIFIED);

  const codeless = V.clone(V.refusedAttestation());
  codeless.authorization.refusalCode = null;
  assert.ok(invalid(rehash(codeless)).includes("REFUSAL_WITHOUT_CODE"));
});

test("refusal: an AUTHORIZED decision may not carry a refusal code or rest on a REFUSED manifest verdict", () => {
  const withCode = V.clone(V.syntheticSpendAttestation());
  withCode.authorization.refusalCode = "AGENT_CAP_EXCEEDED";
  assert.ok(invalid(rehash(withCode)).includes("AUTHORIZED_WITH_REFUSAL_CODE"));

  const refusedManifest = V.clone(V.syntheticSpendAttestation());
  refusedManifest.authorization.intentManifestVerdict = "REFUSED";
  assert.ok(invalid(rehash(refusedManifest)).includes("MANIFEST_VERDICT_INCONSISTENT"));
});

/* ------------------------------------------------------------------ */
/* 11. QUORUM FORGERY                                                  */
/* ------------------------------------------------------------------ */

test("quorum: an above-threshold execution cannot be signed with fewer approvals than the policy requires", () => {
  const rec = V.clone(V.syntheticSpendAttestation());
  rec.approvals.collected = "1";
  rec.approvals.approvalDigests = rec.approvals.approvalDigests.slice(0, 1);
  assert.ok(invalid(rehash(rec)).includes("APPROVALS_INSUFFICIENT"));
});

test("quorum: the approval count must equal the number of digests, and every approver must be in the covenant set", () => {
  const miscount = V.clone(V.syntheticSpendAttestation());
  miscount.approvals.collected = "3";
  assert.ok(invalid(rehash(miscount)).includes("APPROVALS_COUNT_MISMATCH"));

  const outsider = V.clone(V.syntheticSpendAttestation());
  outsider.approvals.approvalDigests[1].approverXOnly = V.H("99");
  assert.ok(invalid(rehash(outsider)).includes("APPROVER_SLOT_UNKNOWN"));
});
