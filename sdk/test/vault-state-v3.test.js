"use strict";

/* UNIT — v0.3 exact live-state normalization (fail-closed, no JS Number). */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeTemplateV3,
  normalizeStateV3,
  normalizeStateV3ForRecovery,
  computeStateIdV3,
  stateToJsonV3,
  APPROVER_SENTINEL,
  MAX_APPROVERS
} = require("../src/vault-state-v3");

const OWNER = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const DELEGATE = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const A1 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const A2 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const A3 = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
const ROOT = "11".repeat(32);
const VAULT_ID = "22".repeat(32);

function baseStateInput(over = {}) {
  return {
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: DELEGATE,
    delegateActive: "1",
    maxPerSpend: "20000000000",
    periodBudget: "80000000000",
    periodLengthDaa: "864000",
    recipientRoot: ROOT,
    approvers: [A1, A2, A3],
    approvalM: "2",
    approvalThresholdAmount: "5000000000",
    policyNonce: "0",
    ...over
  };
}

test("valid template + state normalize; approvers padded to 10", () => {
  const t = normalizeTemplateV3({ owner: OWNER, vaultId: VAULT_ID });
  assert.equal(t.owner, OWNER);
  const s = normalizeStateV3(baseStateInput());
  assert.equal(s.approvers.length, MAX_APPROVERS);
  assert.equal(s.activeApproverCount, 3);
  assert.equal(s.approvers[3], APPROVER_SENTINEL);
  assert.equal(s.approvalM, 2n);
  assert.equal(typeof s.protectedValue, "bigint");
});

test("no-approval-tier: 0 approvers requires M==0 and threshold>=maxPerSpend", () => {
  const ok = normalizeStateV3(baseStateInput({ approvers: [], approvalM: "0", approvalThresholdAmount: "20000000000" }));
  assert.equal(ok.activeApproverCount, 0);
  assert.equal(ok.approvers[0], APPROVER_SENTINEL);
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [], approvalM: "1", approvalThresholdAmount: "20000000000" })), /approvalM must be 0 when there are no active approvers/);
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [], approvalM: "0", approvalThresholdAmount: "19999999999" })), /must set approvalThresholdAmount >= maxPerSpend/);
});

test("duplicate active approver key rejected (A2 at set time)", () => {
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [A1, A1, A3] })), /duplicates an earlier approver key/);
});

test("sentinel passed as an active approver rejected", () => {
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [A1, APPROVER_SENTINEL] })), /all-zero sentinel/);
});

test("too many approvers rejected", () => {
  const eleven = Array.from({ length: 11 }, (_, i) => `${(i + 1).toString(16).padStart(2, "0")}`.repeat(32));
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: eleven })), /max is 10/);
});

test("approvalM bounds enforced against active count", () => {
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [A1, A2, A3], approvalM: "4" })), /exceeds the active approver count/);
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [A1, A2, A3], approvalM: "0" })), /must be >= 1 when approvers are configured/);
  assert.equal(normalizeStateV3(baseStateInput({ approvers: [A1], approvalM: "1" })).approvalM, 1n);
});

test("malformed hex fields fail closed", () => {
  assert.throws(() => normalizeTemplateV3({ owner: "zz", vaultId: VAULT_ID }), /template.owner/);
  assert.throws(() => normalizeStateV3(baseStateInput({ recipientRoot: "11".repeat(31) })), /recipientRoot must be 32-byte/);
  assert.throws(() => normalizeStateV3(baseStateInput({ delegate: "abc" })), /state.delegate/);
  assert.throws(() => normalizeStateV3(baseStateInput({ approvers: [A1, "nothex"] })), /approvers\[1\]/);
});

test("numeric safety: negatives / bad decimals / budget<cap rejected", () => {
  assert.throws(() => normalizeStateV3(baseStateInput({ protectedValue: "-1" })), /protectedValue/);
  assert.throws(() => normalizeStateV3(baseStateInput({ periodBudget: "1", maxPerSpend: "2" })), /periodBudget must be >= state.maxPerSpend/);
  assert.throws(() => normalizeStateV3(baseStateInput({ approvalThresholdAmount: "-5" })), /approvalThresholdAmount/);
  assert.throws(() => normalizeStateV3(baseStateInput({ paused: "2" })), /paused out of range/);
  assert.throws(() => normalizeStateV3(baseStateInput({ periodStartDaa: "500000000000" })), /DAA lock-time threshold/);
});

test("state ID is deterministic and field-sensitive", () => {
  const t = normalizeTemplateV3({ owner: OWNER, vaultId: VAULT_ID });
  const s = normalizeStateV3(baseStateInput());
  const id1 = computeStateIdV3({ networkId: "testnet-10", template: t, state: s });
  const id2 = computeStateIdV3({ networkId: "testnet-10", template: t, state: normalizeStateV3(baseStateInput()) });
  assert.equal(id1, id2);
  const s2 = normalizeStateV3(baseStateInput({ approvalM: "3" }));
  assert.notEqual(id1, computeStateIdV3({ networkId: "testnet-10", template: t, state: s2 }));
  const s3 = normalizeStateV3(baseStateInput({ recipientRoot: "33".repeat(32) }));
  assert.notEqual(id1, computeStateIdV3({ networkId: "testnet-10", template: t, state: s3 }));
});

test("stateToJsonV3 is digit-string safe and complete", () => {
  const s = normalizeStateV3(baseStateInput());
  const j = stateToJsonV3(s);
  assert.equal(j.protectedValue, "100000000000");
  assert.equal(j.approvalM, "2");
  assert.equal(j.approverSlots.length, 10);
  assert.equal(typeof j.protectedValue, "string");
  assert.equal(j.recipientRoot, ROOT);
  assert.equal(j.policyNonce, "0");
});

test("stateToJsonV3 -> normalizeStateV3 round-trips through exact approverSlots", () => {
  const s = normalizeStateV3(baseStateInput());
  const j = stateToJsonV3(s);
  const { approvers: _drop, ...rest } = j;
  const back = normalizeStateV3(rest);
  assert.deepEqual([...back.approvers], [...s.approvers]);
  assert.equal(back.policyNonce, s.policyNonce);
  const t = normalizeTemplateV3({ owner: OWNER, vaultId: VAULT_ID });
  assert.equal(
    computeStateIdV3({ networkId: "testnet-10", template: t, state: back }),
    computeStateIdV3({ networkId: "testnet-10", template: t, state: s })
  );
});

test("policyNonce is REQUIRED — no implicit consensus-visible default", () => {
  const missing = baseStateInput();
  delete missing.policyNonce;
  assert.throws(() => normalizeStateV3(missing), /policyNonce/);
  assert.throws(() => normalizeStateV3(baseStateInput({ policyNonce: "-1" })), /policyNonce/);
});

test("approverSlots exact layout is preserved (never re-sorted) and duplicates rejected", () => {
  // A deliberately non-sorted but distinct layout must be preserved exactly.
  const slots = [A3, A1, ...Array.from({ length: 8 }, () => APPROVER_SENTINEL)];
  const s = normalizeStateV3(baseStateInput({ approvers: undefined, approverSlots: slots, approvalM: "2" }));
  assert.deepEqual([...s.approvers], slots);
  assert.equal(s.activeApproverCount, 2);
  const dup = [A1, A1, ...Array.from({ length: 8 }, () => APPROVER_SENTINEL)];
  assert.throws(
    () => normalizeStateV3(baseStateInput({ approvers: undefined, approverSlots: dup })),
    /duplicates an earlier active approver key/
  );
  assert.throws(
    () => normalizeStateV3(baseStateInput({ approvers: undefined, approverSlots: [A1] })),
    /exactly 10 slots/
  );
});

test("recovery-mode parse accepts malformed approval state that strict mode rejects", () => {
  // Duplicate active keys + M=0 with actives + budget<cap + paused/revoked:
  // strict fails closed, recovery parses the EXACT layout for ownerRecover.
  const malformed = baseStateInput({
    approvers: undefined,
    approverSlots: [A1, A1, A3, ...Array.from({ length: 7 }, () => APPROVER_SENTINEL)],
    approvalM: "0",
    approvalThresholdAmount: "1",
    maxPerSpend: "2",
    periodBudget: "1",
    paused: "1",
    delegateActive: "0"
  });
  assert.throws(() => normalizeStateV3(malformed), /duplicates|periodBudget/);
  const r = normalizeStateV3ForRecovery(malformed);
  assert.equal(r.recoveryParse, true);
  assert.equal(r.approvers[0], A1);
  assert.equal(r.approvers[1], A1);
  assert.equal(r.activeApproverCount, 3);
  assert.equal(r.approvalM, 0n);
  // Recovery parse still fails closed on SHAPE violations.
  assert.throws(() => normalizeStateV3ForRecovery({ ...malformed, delegate: "abc" }), /delegate/);
  assert.throws(() => normalizeStateV3ForRecovery({ ...malformed, protectedValue: "0" }), /protectedValue/);
});
