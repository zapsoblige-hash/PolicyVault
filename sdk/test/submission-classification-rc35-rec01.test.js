"use strict";
/*
 * UNIT — RC35-REC-01 (independent RC35 affected review, 2026-09-11): the shared three-way submit-outcome classifier
 * (sdk/src/submission-classification.js). The reviewer's finding: the node's RejectAlreadyAccepted answer ("transaction
 * {id} was already accepted by the consensus", mining/errors/src/mempool.rs) matched the single predicate
 * /\bRejected transaction / and was treated as a definitive rejection. Now: REJECTED / ALREADY_KNOWN / AMBIGUOUS, bound to
 * this attempt's transaction id; the persisted-negative helpers used by the identity arbiter and every recovery path.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { classifySubmitOutcome, isDefinitiveSubmitRejection, isAlreadyKnownSubmitAnswer, recordedNegativeIsEstablished, classifyRecordedNegative, ALREADY_KNOWN_REASONS } = require("../src/submission-classification");
const { answers } = require("./helpers/rc35-recovery-fixtures");

const ID = "600a5ea0b8f3c1d2e4a6b8c0d2e4f60718293a4b5c6d7e8f9012345678b87b43";
const OTHER = "ab".repeat(32);

test("REJECTED: a bound envelope whose reason is a rejection of THIS attempt (bare, SDK-prefixed, transport-wrapped, JS-form)", () => {
  const forms = [
    answers.nonStandard(ID),
    `wallet-submit-v4: submit failed: ${answers.nonStandard(ID)}`,
    `RPC Server (remote error) -> ${answers.nonStandard(ID)}`,
    answers.wrapped(answers.nonStandard(ID)),
    `Rejected transaction ${ID}: script ran, but verification failed`,
    answers.doubleSpendInMempool(ID, OTHER), // a DIFFERENT transaction spends our input: a rejection of THIS attempt
    `Rejected transaction ${ID.toUpperCase()}: insufficient fee` // the id is compared case-insensitively
  ];
  for (const m of forms) {
    const c = classifySubmitOutcome(m, ID);
    assert.equal(c.kind, "REJECTED", m.slice(0, 70));
    assert.equal(c.txId, ID);
    assert.equal(c.bound, true);
    assert.equal(isDefinitiveSubmitRejection(m, ID), true);
    assert.equal(isAlreadyKnownSubmitAnswer(m, ID), false);
  }
});

test("ALREADY_KNOWN: every already-known reason of the retained node source is a POSITIVE answer, never a rejection — in every envelope form", () => {
  const cases = [["RejectAlreadyAccepted", answers.alreadyAccepted(ID)], ["RejectDuplicate", answers.alreadyInMempool(ID)], ["RejectDuplicateOrphan", answers.alreadyInOrphanPool(ID)]];
  assert.equal(ALREADY_KNOWN_REASONS.length, 3);
  for (const [variant, plain] of cases) {
    for (const m of [plain, `wallet-submit-v4: submit failed: ${plain}`, `RPC Server (remote error) -> ${plain}`, answers.wrapped(plain)]) {
      const c = classifySubmitOutcome(m, ID);
      assert.equal(c.kind, "ALREADY_KNOWN", m.slice(0, 80));
      assert.equal(c.variant, variant);
      assert.equal(c.txId, ID);
      assert.equal(isDefinitiveSubmitRejection(m, ID), false, "an already-known answer is NEVER definitive");
      assert.equal(isAlreadyKnownSubmitAnswer(m, ID), true);
      assert.equal(isDefinitiveSubmitRejection(m), false, "also without a txid to bind to");
    }
  }
});

test("AMBIGUOUS: transport failures, an envelope naming ANOTHER transaction, and malformed envelopes keep claims", () => {
  const ambiguous = ["", null, undefined, "timeout", "request timed out after 30000ms", "WebSocket is not connected", "RPC Server (remote error) -> not connected", "connection reset by peer", "ECONNREFUSED 127.0.0.1:18210", "socket hang up", "node is not synced", "failed to serialize transaction for submission", answers.transportLost(),
    "Rejected transaction abc: too many sig ops" /* no 64-hex id: unbound */];
  for (const m of ambiguous) {
    const c = classifySubmitOutcome(m, ID);
    assert.equal(c.kind, "AMBIGUOUS", String(m).slice(0, 60));
    assert.equal(isDefinitiveSubmitRejection(m, ID), false);
    assert.equal(isAlreadyKnownSubmitAnswer(m, ID), false);
  }
  /* a bound-looking envelope for ANOTHER id is not this attempt's verdict */
  const foreign = classifySubmitOutcome(answers.nonStandard(OTHER), ID);
  assert.equal(foreign.kind, "AMBIGUOUS");
  assert.equal(foreign.txId, OTHER);
  assert.equal(foreign.bound, false);
  assert.equal(classifySubmitOutcome(answers.alreadyAccepted(OTHER), ID).kind, "AMBIGUOUS", "an already-known answer about another id is not about this attempt either");
  /* without a txid to compare against, an envelope is bound by definition (legacy callers) */
  assert.equal(classifySubmitOutcome(answers.nonStandard(OTHER)).kind, "REJECTED");
  assert.equal(classifySubmitOutcome(answers.nonStandard(OTHER)).bound, true);
});

test("persisted negatives: historical error strings and output-absence proofs stay UNKNOWN; the reviewer's false negative is FALSE_NEGATIVE; an absent / unbound answer is UNKNOWN", () => {
  const base = { state: "SUBMISSION_REJECTED", txId: ID };
  assert.equal(recordedNegativeIsEstablished({ ...base, error: answers.nonStandard(ID) }), false, "legacy error alone cannot prove historical nonacceptance");
  assert.equal(classifyRecordedNegative({ ...base, error: answers.nonStandard(ID) }), "UNKNOWN");
  assert.equal(recordedNegativeIsEstablished({ ...base, error: answers.alreadyAccepted(ID) }), false, "the reviewer's false negative");
  assert.equal(classifyRecordedNegative({ ...base, error: answers.alreadyAccepted(ID) }), "FALSE_NEGATIVE");
  assert.equal(classifyRecordedNegative({ ...base, error: answers.alreadyInMempool(ID) }), "FALSE_NEGATIVE");
  assert.equal(classifyRecordedNegative({ ...base, error: "connection closed before response" }), "UNKNOWN");
  assert.equal(classifyRecordedNegative({ ...base }), "UNKNOWN", "no recorded answer at all");
  assert.equal(classifyRecordedNegative({ ...base, error: answers.nonStandard(OTHER) }), "UNKNOWN", "a rejection of ANOTHER transaction proves nothing about this one");
  /* proofs */
  assert.equal(recordedNegativeIsEstablished({ ...base, error: answers.alreadyAccepted(ID), submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: ID, proof: { outputsAbsent: true, boundRejection: true } } }), false, "outputsAbsent alone cannot override an already-accepted answer");
  assert.equal(recordedNegativeIsEstablished({ ...base, submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: OTHER, proof: { outputsAbsent: true } } }), false, "a proof about another transaction does not count");
  assert.equal(recordedNegativeIsEstablished({ ...base, submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: ID, proof: {} } }), false, "a proof without the outputs-absent fact does not count");
  assert.equal(recordedNegativeIsEstablished({ ...base, state: "RECONCILIATION_REQUIRED", error: answers.nonStandard(ID) }), false, "only a SUBMISSION_REJECTED record is a negative");
  assert.equal(classifyRecordedNegative({ state: "SIGNED", txId: ID }), null);
});
