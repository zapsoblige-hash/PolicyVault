"use strict";

/* UNIT — canonical v0.3 state-transition derivation (20B at the SDK
 * layer): exact field changes, full preservation matrix, exact nonce
 * rules, fail-closed prerequisites, recovery-parse quarantine. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { normalizeStateV3, normalizeStateV3ForRecovery, APPROVER_SENTINEL } = require("../src/vault-state-v3");
const {
  spendSuccessorV3,
  rolloverSuccessorV3,
  pauseSuccessorV3,
  revokeSuccessorV3,
  rotateSuccessorV3,
  topUpSuccessorV3,
  migrateSuccessorV3,
  setRecipientRootSuccessorV3,
  setApproversSuccessorV3,
  recoverPlanV3
} = require("../src/vault-transitions-v3");

const A1 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const A2 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const A3 = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
const DELEGATE = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const NEW_DELEGATE = "dd".repeat(32);

function state(over = {}) {
  return normalizeStateV3({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "500000000",
    paused: "0",
    delegate: DELEGATE,
    delegateActive: "1",
    maxPerSpend: "20000000000",
    periodBudget: "80000000000",
    periodLengthDaa: "864000",
    recipientRoot: "44".repeat(32),
    approvers: [A1, A2, A3],
    approvalM: "2",
    approvalThresholdAmount: "5000000000",
    policyNonce: "3",
    ...over
  });
}

const FIELDS = [
  "protectedValue",
  "periodStartDaa",
  "periodSpent",
  "paused",
  "delegate",
  "delegateActive",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "recipientRoot",
  "approvalM",
  "approvalThresholdAmount",
  "policyNonce"
];

/* Assert every field EXCEPT the named ones is preserved exactly
 * (approver slots compared separately). */
function assertPreservedExcept(prev, succ, changed) {
  for (const f of FIELDS) {
    if (changed.includes(f)) continue;
    assert.equal(succ[f], prev[f], `${f} must be preserved exactly`);
  }
  if (!changed.includes("approvers")) {
    assert.deepEqual([...succ.approvers], [...prev.approvers], "approver slots must be preserved exactly");
  }
}

test("delegateSpend successor: principal/periodSpent move exactly; nonce preserved", () => {
  const prev = state();
  const succ = spendSuccessorV3(prev, "4000000000");
  assert.equal(succ.protectedValue, prev.protectedValue - 4000000000n);
  assert.equal(succ.periodSpent, prev.periodSpent + 4000000000n);
  assertPreservedExcept(prev, succ, ["protectedValue", "periodSpent"]);
});

test("rolloverAndSpend successor: periodStart advances by whole periods; periodSpent = pay", () => {
  const prev = state({ periodSpent: "70000000000" });
  const succ = rolloverSuccessorV3(prev, "4000000000", "2");
  assert.equal(succ.periodStartDaa, prev.periodStartDaa + 2n * prev.periodLengthDaa);
  assert.equal(succ.periodSpent, 4000000000n);
  assert.equal(succ.protectedValue, prev.protectedValue - 4000000000n);
  assertPreservedExcept(prev, succ, ["protectedValue", "periodStartDaa", "periodSpent"]);
});

test("spend prerequisites fail closed (cap, budget, paused, revoked, drain, zero)", () => {
  assert.throws(() => spendSuccessorV3(state(), "20000000001"), /maxPerSpend/);
  assert.throws(() => spendSuccessorV3(state({ periodSpent: "79000000000" }), "1000000001"), /period budget/);
  assert.throws(() => spendSuccessorV3(state({ paused: "1" }), "1"), /paused/);
  assert.throws(() => spendSuccessorV3(state({ delegateActive: "0" }), "1"), /revoked/);
  assert.throws(() => spendSuccessorV3(state({ protectedValue: "1000000000" }), "1000000000"), /positive successor/);
  assert.throws(() => spendSuccessorV3(state(), "0"), /greater than zero/);
  assert.throws(() => rolloverSuccessorV3(state(), "1", "0"), /periodsElapsed/);
  assert.throws(() => rolloverSuccessorV3(state(), "1", "1001"), /periodsElapsed/);
});

test("pause/unpause flip only `paused`; accounting untouched", () => {
  const prev = state();
  const paused = pauseSuccessorV3(prev, true);
  assert.equal(paused.paused, 1n);
  assertPreservedExcept(prev, paused, ["paused"]);
  const back = pauseSuccessorV3(paused, false);
  assert.equal(back.paused, 0n);
  assert.throws(() => pauseSuccessorV3(prev, false), /already active/);
  assert.throws(() => pauseSuccessorV3(paused, true), /already paused/);
});

test("revoke/rotate change only delegate fields; period accounting never resets", () => {
  const prev = state();
  const revoked = revokeSuccessorV3(prev);
  assert.equal(revoked.delegateActive, 0n);
  assert.equal(revoked.delegate, prev.delegate);
  assertPreservedExcept(prev, revoked, ["delegateActive"]);
  assert.throws(() => revokeSuccessorV3(revoked), /already revoked/);

  const rotated = rotateSuccessorV3(revoked, NEW_DELEGATE);
  assert.equal(rotated.delegate, NEW_DELEGATE);
  assert.equal(rotated.delegateActive, 1n);
  assert.equal(rotated.periodSpent, prev.periodSpent, "rotation must NOT grant a fresh budget");
  assert.equal(rotated.periodStartDaa, prev.periodStartDaa);
  assertPreservedExcept(revoked, rotated, ["delegate", "delegateActive"]);
});

test("topUp increases principal exactly; nonce and accounting preserved", () => {
  const prev = state();
  const succ = topUpSuccessorV3(prev, "7000000000");
  assert.equal(succ.protectedValue, prev.protectedValue + 7000000000n);
  assertPreservedExcept(prev, succ, ["protectedValue"]);
});

test("migratePolicy: only limits change; nonce +1 exactly; unknown keys fail closed", () => {
  const prev = state();
  const succ = migrateSuccessorV3(prev, { maxPerSpend: "10000000000", periodLengthDaa: "432000" });
  assert.equal(succ.maxPerSpend, 10000000000n);
  assert.equal(succ.periodLengthDaa, 432000n);
  assert.equal(succ.policyNonce, prev.policyNonce + 1n);
  assertPreservedExcept(prev, succ, ["maxPerSpend", "periodLengthDaa", "policyNonce"]);
  assert.throws(() => migrateSuccessorV3(prev, { recipientRoot: "55".repeat(32) }), /cannot change recipientRoot/);
  assert.throws(() => migrateSuccessorV3(prev, { delegate: NEW_DELEGATE }), /cannot change delegate/);
  assert.throws(() => migrateSuccessorV3(prev, { periodSpent: "0" }), /cannot change periodSpent/);
});

test("migratePolicy refuses to strand a 0-approver vault above its threshold", () => {
  // 0 approvers, threshold == cap: raising the cap would make spends above
  // the (unraisable-by-migrate) threshold impossible (M>=1 with no
  // approvers). The SDK fails closed; remedy is ownerSetApprovers first.
  const prev = state({ approvers: [], approvalM: "0", approvalThresholdAmount: "20000000000" });
  assert.throws(() => migrateSuccessorV3(prev, { maxPerSpend: "30000000000" }), /approvalThresholdAmount >= maxPerSpend/);
});

test("setRecipientRoot: root + nonce only", () => {
  const prev = state();
  const succ = setRecipientRootSuccessorV3(prev, "55".repeat(32));
  assert.equal(succ.recipientRoot, "55".repeat(32));
  assert.equal(succ.policyNonce, prev.policyNonce + 1n);
  assertPreservedExcept(prev, succ, ["recipientRoot", "policyNonce"]);
});

test("setApprovers: atomic slots+M+threshold with nonce +1; zero-approver target refused", () => {
  const prev = state();
  const succ = setApproversSuccessorV3(prev, { approvers: [A1, A2], approvalM: "1", approvalThresholdAmount: "9000000000" });
  assert.equal(succ.activeApproverCount, 2);
  assert.equal(succ.approvalM, 1n);
  assert.equal(succ.approvalThresholdAmount, 9000000000n);
  assert.equal(succ.policyNonce, prev.policyNonce + 1n);
  assertPreservedExcept(prev, succ, ["approvers", "approvalM", "approvalThresholdAmount", "policyNonce"]);

  assert.throws(
    () => setApproversSuccessorV3(prev, { approvers: [], approvalM: "0", approvalThresholdAmount: "20000000000" }),
    /zero-approver/
  );
  assert.throws(() => setApproversSuccessorV3(prev, { approvers: [A1, A1], approvalM: "1", approvalThresholdAmount: "0" }), /duplicates/);
  assert.throws(() => setApproversSuccessorV3(prev, { approvers: [A1], approvalM: "2", approvalThresholdAmount: "0" }), /exceeds the active approver count/);
});

test("recoverPlan is terminal: full protected value to the owner key", () => {
  const prev = state();
  const plan = recoverPlanV3(prev, "11".repeat(32));
  assert.equal(plan.terminal, true);
  assert.equal(plan.payoutValue, prev.protectedValue);
  assert.equal(plan.payoutXOnly, "11".repeat(32));
});

test("recovery-mode parses are quarantined from every ordinary transition", () => {
  const malformed = normalizeStateV3ForRecovery({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "1",
    delegate: DELEGATE,
    delegateActive: "0",
    maxPerSpend: "2",
    periodBudget: "1",
    periodLengthDaa: "864000",
    recipientRoot: "44".repeat(32),
    approverSlots: [A1, A1, ...Array.from({ length: 8 }, () => APPROVER_SENTINEL)],
    approvalM: "0",
    approvalThresholdAmount: "1",
    policyNonce: "0"
  });
  for (const [name, run] of [
    ["spend", () => spendSuccessorV3(malformed, "1")],
    ["rollover", () => rolloverSuccessorV3(malformed, "1", "1")],
    ["pause", () => pauseSuccessorV3(malformed, true)],
    ["revoke", () => revokeSuccessorV3(malformed)],
    ["rotate", () => rotateSuccessorV3(malformed, NEW_DELEGATE)],
    ["topUp", () => topUpSuccessorV3(malformed, "1")],
    ["migrate", () => migrateSuccessorV3(malformed, {})],
    ["setRoot", () => setRecipientRootSuccessorV3(malformed, "55".repeat(32))],
    ["setApprovers", () => setApproversSuccessorV3(malformed, { approvers: [A1], approvalM: "1", approvalThresholdAmount: "0" })]
  ]) {
    assert.throws(run, /recovery-mode/, `${name} must reject a recovery parse`);
  }
  // …but recovery planning itself works from the malformed state.
  const plan = recoverPlanV3(malformed, "11".repeat(32));
  assert.equal(plan.payoutValue, 100000000000n);
});
