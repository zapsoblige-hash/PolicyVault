"use strict";

/*
 * UNIT — the BINDING language rules for rendered attestation text.
 *
 * A PolicyVault attestation is an evidence product. It must never claim,
 * imply, or borrow the vocabulary of an external approving body: no
 * "compliant", no "certified", no "approved by a regulator", no
 * equivalents. This suite enforces that mechanically over the real
 * renderer output for every vector and every verifier verdict, so the
 * rule cannot rot into a comment.
 *
 * Layer: UNIT (pure core; no node, no store, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const A = require("../index");
const V = require("../testutil/vectors");

const VECTORS = {
  "live testnet v0.6 SELL (VERIFIED_OUTCOME)": V.liveTestnetSellAttestation(),
  "synthetic v0.4.1 spend (CHAIN_VERIFIED, M-of-N)": V.syntheticSpendAttestation(),
  refused: V.refusedAttestation()
};

test("the forbidden vocabulary covers the terms the owner's rule names, and their equivalents", () => {
  for (const term of ["compliant", "compliance", "certified", "certification", "regulator", "regulatory", "audited", "endorsed", "guaranteed", "licensed"]) {
    assert.ok(A.FORBIDDEN_TERMS.includes(term), `${term} must be forbidden`);
  }
  assert.ok(A.FORBIDDEN_PHRASES.includes("approved by a regulator"));
  assert.ok(A.FORBIDDEN_PHRASES.includes("regulatory approval"));
});

test("the scanner catches the forbidden vocabulary, including inside hyphenated compounds and mixed case", () => {
  for (const text of [
    "this vault is COMPLIANT",
    "a certified outcome",
    "approved by a regulator",
    "regulatory approval obtained",
    "audit-ready evidence",
    "a legally binding record",
    "PolicyVault guarantees settlement"
  ]) {
    assert.ok(A.forbiddenLanguageHits(text).length > 0, `must flag: ${text}`);
    assert.throws(() => A.assertNoForbiddenLanguage(text), (e) => e.code === "ATTESTATION_LANGUAGE_FORBIDDEN");
  }
  assert.deepEqual(A.forbiddenLanguageHits("deterministic authorization evidence and a verified chain outcome"), []);
});

for (const [label, record] of Object.entries(VECTORS)) {
  test(`rendered summary contains no forbidden vocabulary — ${label}`, () => {
    const withoutVerdict = A.attestationSummary.humanReadable(record, null);
    assert.deepEqual(A.forbiddenLanguageHits(withoutVerdict), []);

    /* every verifier verdict path renders through the same text */
    const observations = [
      null,
      { available: false, reason: "node offline", node: null, utxos: {} },
      { available: true, reason: null, node: { networkId: record.subject.networkId, isSynced: true, hasUtxoIndex: true }, utxos: {} }
    ];
    for (const chainObservation of observations) {
      const verification = A.verifyAttestation(record, chainObservation === null ? {} : { chainObservation });
      const text = A.attestationSummary.humanReadable(record, verification);
      assert.deepEqual(A.forbiddenLanguageHits(text), [], `${label}: ${verification.verdict}`);
    }
  });
}

test("the sanctioned vocabulary is actually used by the renderer", () => {
  const text = A.attestationSummary.humanReadable(VECTORS["live testnet v0.6 SELL (VERIFIED_OUTCOME)"], null);
  assert.ok(text.includes("PolicyVault policy-execution attestation"));
  assert.ok(text.toUpperCase().includes("DETERMINISTIC AUTHORIZATION EVIDENCE"));
  assert.ok(text.toUpperCase().includes("VERIFIED CHAIN OUTCOME"));
});

test("a record that has NOT reached CHAIN_VERIFIED is never narrated as a verified chain outcome", () => {
  const rec = V.syntheticSpendAttestation({
    outcome: {
      state: "BROADCAST",
      disposition: "IN_PROGRESS",
      reached: [
        { state: "AUTHORIZED", source: "wallet-request-v4", note: null },
        { state: "SIGNED", source: "external-signer", note: null },
        { state: "BROADCAST", source: "node-submit", note: null }
      ],
      chain: { acceptingBlockDaaScore: null, observedVirtualDaaScore: null, depthDaa: null, minDepthDaa: null, successorStateId: null, covenantId: null, scriptSha256: null, outputs: [] }
    }
  });
  const text = A.attestationSummary.humanReadable(rec, A.verifyAttestation(rec));
  assert.ok(text.includes("NOT YET A VERIFIED CHAIN OUTCOME"));
  assert.deepEqual(A.forbiddenLanguageHits(text), []);
});

test("the structured summary mirrors the human one and never over-claims", () => {
  const rec = VECTORS["synthetic v0.4.1 spend (CHAIN_VERIFIED, M-of-N)"];
  const s = A.attestationSummary.structured(rec, A.verifyAttestation(rec));
  assert.equal(s.summaryVersion, "policyvault-execution-attestation-summary/1");
  assert.equal(s.highestState, "CHAIN_VERIFIED");
  assert.deepEqual(s.ladder, ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"]);
  assert.equal(s.chainConfirmed, false, "no chain check was run, so nothing is confirmed");
  assert.equal(A.attestationSummary.structured(rec, null).verdict, null);
});
