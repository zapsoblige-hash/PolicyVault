"use strict";

/* SDK — canonical v0.4 state transitions (Checkpoint E §E3): successor
 * derivation for all 8 entrypoints, the frozen field-preservation matrix,
 * exact policyNonce rules, single-leaf agent accounting, and fail-closed
 * behavior on malformed/stale/recovery-mode state. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { normalizeStateV4, normalizeStateV4ForRecovery, stateToJsonV4 } = require("../src/vault-state-v4");
const { buildAgentTreeV4, generateAgentProofV4, foldAgentPolicyV4, agentLeafHash } = require("../src/agent-merkle-v4");
const {
  agentSpendSuccessorV4,
  setAgentRootSuccessorV4,
  setApproversSuccessorV4,
  topUpSuccessorV4,
  topUpReserveSuccessorV4,
  pauseSuccessorV4,
  recoverPlanV4
} = require("../src/vault-transitions-v4");

const PK = (v) => v.toString(16).padStart(2, "0").repeat(32);

function policy(v, over = {}) {
  return {
    agentPk: PK(v),
    maxPerSpend: "20000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: "5000000000",
    agentMaxFeePerTx: "100000000",
    agentRecipientRoot: "ab".repeat(32),
    ...over
  };
}

const AGENTS = [policy(0x30), policy(0x31, { maxPerSpend: "90000000000", periodBudget: "90000000000" })];
const TREE = buildAgentTreeV4(AGENTS);

function state(over = {}) {
  return normalizeStateV4({
    protectedValue: "1000000000000",
    feeReserve: "500000000",
    paused: "0",
    agentRoot: TREE.root,
    approvers: [PK(0x20), PK(0x21), PK(0x22)],
    approvalM: "2",
    policyNonce: "3",
    ...over
  });
}

function spendArgs(over = {}) {
  const proof = generateAgentProofV4(TREE, PK(0x30));
  return {
    agentPolicy: proof.policy,
    agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
    payAmount: "4000000000",
    periodsElapsed: "0",
    reserveConsumed: "50000000",
    ...over
  };
}

test("E3: agentSpend derives the exact covenant successor (below threshold)", () => {
  const s = state();
  const r = agentSpendSuccessorV4(s, spendArgs());
  assert.equal(r.successor.protectedValue, 1000000000000n - 4000000000n);
  assert.equal(r.successor.feeReserve, 500000000n - 50000000n);
  assert.equal(r.successor.paused, 0n);
  assert.equal(r.successor.policyNonce, 3n, "spend preserves policyNonce");
  assert.deepEqual([...r.successor.approvers], [...s.approvers], "spend preserves approver slots");
  assert.equal(r.successor.approvalM, s.approvalM);
  assert.equal(r.aboveThreshold, false);
  assert.equal(r.lockTime, 0n);
  assert.equal(r.newSpent, 4000000000n);
  assert.equal(r.newStart, 541000000n);
  // successor agentRoot is the single-leaf fold of the advanced leaf
  const folded = foldAgentPolicyV4(r.newPolicy, r.agentProof.siblingsHex, r.agentProof.pathBits);
  assert.equal(r.successor.agentRoot, folded);
  assert.notEqual(r.successor.agentRoot, s.agentRoot);
  // the OTHER agent's leaf is preserved in the successor tree
  const advanced = TREE.agents.map((a) => (a.agentPk === PK(0x30) ? r.newPolicy : a));
  const rebuilt = buildAgentTreeV4(advanced);
  assert.equal(rebuilt.root, r.successor.agentRoot);
  assert.equal(agentLeafHash(rebuilt.agents.find((a) => a.agentPk === PK(0x31))).toString("hex"),
    agentLeafHash(TREE.agents.find((a) => a.agentPk === PK(0x31))).toString("hex"));
});

test("E3: rollover advances start, resets spent to pay, sets CLTV lock time", () => {
  const spent = buildAgentTreeV4([policy(0x30, { periodSpent: "48000000000" })]);
  const proof = generateAgentProofV4(spent, PK(0x30));
  const s = state({ agentRoot: spent.root });
  const r = agentSpendSuccessorV4(s, {
    agentPolicy: proof.policy,
    agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
    payAmount: "4000000000",
    periodsElapsed: "2",
    reserveConsumed: "0"
  });
  assert.equal(r.newStart, 541000000n + 2n * 864000n);
  assert.equal(r.newSpent, 4000000000n);
  assert.equal(r.lockTime, r.newStart, "rollover lockTime must be >= newStart (CLTV)");
});

test("E3: agentSpend fail-closed matrix", () => {
  const s = state();
  // paused
  assert.throws(() => agentSpendSuccessorV4(state({ paused: "1" }), spendArgs()), /paused/);
  // stale/foreign proof
  assert.throws(() => agentSpendSuccessorV4(state({ agentRoot: "cd".repeat(32) }), spendArgs()), /does not verify/);
  // over per-spend cap (pay == cap is legal and covered elsewhere)
  assert.throws(() => agentSpendSuccessorV4(s, spendArgs({ payAmount: "20000000001" })), /maxPerSpend/);
  // over period budget
  {
    const spent = buildAgentTreeV4([policy(0x30, { periodSpent: "49000000000" })]);
    const proof = generateAgentProofV4(spent, PK(0x30));
    assert.throws(
      () =>
        agentSpendSuccessorV4(state({ agentRoot: spent.root }), {
          agentPolicy: proof.policy,
          agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
          payAmount: "2000000000",
          reserveConsumed: "0"
        }),
      /period budget/
    );
  }
  // periodsElapsed out of range
  assert.throws(() => agentSpendSuccessorV4(s, spendArgs({ periodsElapsed: "1001" })), /periodsElapsed/);
  // zero payment
  assert.throws(() => agentSpendSuccessorV4(s, spendArgs({ payAmount: "0" })), /greater than zero/);
  // spend would zero the protected value
  {
    const tiny = state({ protectedValue: "4000000000", feeReserve: "0" });
    assert.throws(() => agentSpendSuccessorV4(tiny, spendArgs({ reserveConsumed: "0" })), /positive successor/);
  }
  // reserveConsumed over the agent's own fee cap
  assert.throws(() => agentSpendSuccessorV4(s, spendArgs({ reserveConsumed: "100000001" })), /agentMaxFeePerTx/);
  // reserveConsumed over the available reserve
  assert.throws(
    () => agentSpendSuccessorV4(state({ feeReserve: "10000000" }), spendArgs({ reserveConsumed: "20000000" })),
    /available fee reserve/
  );
  // negative reserveConsumed is unparseable
  assert.throws(() => agentSpendSuccessorV4(s, spendArgs({ reserveConsumed: "-1" })));
  // above threshold with no approver tier
  assert.throws(
    () => agentSpendSuccessorV4(state({ approvers: [], approvalM: "0" }), spendArgs({ payAmount: "6000000000" })),
    /NO_APPROVER|no approver configuration/
  );
  // recovery-mode parse refused for ordinary transitions
  const rec = normalizeStateV4ForRecovery(stateToJsonV4(s));
  assert.throws(() => agentSpendSuccessorV4(rec, spendArgs()), /recovery-mode/);
});

test("E3: aboveThreshold computed against the LEAF threshold", () => {
  const s = state();
  assert.equal(agentSpendSuccessorV4(s, spendArgs({ payAmount: "5000000000" })).aboveThreshold, false, "pay == threshold is agent-only");
  assert.equal(agentSpendSuccessorV4(s, spendArgs({ payAmount: "5000000001" })).aboveThreshold, true);
});

/* Owner-op field preservation matrix (frozen spec §4). */
function assertPreserved(succ, s, except = []) {
  const fields = ["protectedValue", "feeReserve", "paused", "agentRoot", "approvalM", "policyNonce"];
  for (const f of fields) {
    if (!except.includes(f)) {
      assert.equal(succ[f], s[f], `${f} must be preserved`);
    }
  }
  if (!except.includes("approvers")) {
    assert.deepEqual([...succ.approvers], [...s.approvers], "approver slots must be preserved");
  }
}

test("E3: ownerSetAgentRoot — root replaced, nonce +1, everything else preserved", () => {
  const s = state();
  const succ = setAgentRootSuccessorV4(s, "cd".repeat(32));
  assert.equal(succ.agentRoot, "cd".repeat(32));
  assert.equal(succ.policyNonce, s.policyNonce + 1n);
  assertPreserved(succ, s, ["agentRoot", "policyNonce"]);
});

test("E3: ownerSetApprovers — slots+M replaced atomically, nonce +1, zero-approver refused", () => {
  const s = state();
  const succ = setApproversSuccessorV4(s, { approvers: [PK(0x25), PK(0x26)], approvalM: "2" });
  assert.equal(succ.approvalM, 2n);
  assert.equal(succ.activeApproverCount, 2);
  assert.equal(succ.policyNonce, s.policyNonce + 1n);
  assertPreserved(succ, s, ["approvers", "approvalM", "policyNonce"]);
  assert.throws(() => setApproversSuccessorV4(s, { approvers: [], approvalM: "0" }), /zero-approver/);
  assert.throws(() => setApproversSuccessorV4(s, { approvers: [PK(0x25)], approvalM: "2" }), /exceeds the active approver count/);
  assert.throws(() => setApproversSuccessorV4(s, { approvers: [PK(0x25), PK(0x25)], approvalM: "1" }), /duplicates/);
  assert.throws(() => setApproversSuccessorV4(s, { approvalM: "1" }), /requires the new approver set/);
});

test("E3: ownerTopUp / ownerTopUpReserve move exactly one value dimension, nonce preserved", () => {
  const s = state();
  const up = topUpSuccessorV4(s, "7000000000");
  assert.equal(up.protectedValue, s.protectedValue + 7000000000n);
  assertPreserved(up, s, ["protectedValue"]);
  const upR = topUpReserveSuccessorV4(s, "300000000");
  assert.equal(upR.feeReserve, s.feeReserve + 300000000n);
  assertPreserved(upR, s, ["feeReserve"]);
  assert.throws(() => topUpSuccessorV4(s, "0"), /greater than zero/);
  assert.throws(() => topUpReserveSuccessorV4(s, "0"), /greater than zero/);
});

test("E3: pause/unpause flip only `paused`; double-flip refused", () => {
  const s = state();
  const paused = pauseSuccessorV4(s, true);
  assert.equal(paused.paused, 1n);
  assertPreserved(paused, s, ["paused"]);
  assert.throws(() => pauseSuccessorV4(s, false), /already/);
  const unpaused = pauseSuccessorV4(paused, false);
  assert.equal(unpaused.paused, 0n);
  assertPreserved(unpaused, s, []);
  assert.throws(() => pauseSuccessorV4(paused, true), /already/);
});

test("E3: recoverPlanV4 is terminal — payout = protected + reserve; accepts recovery parses; never fabricates a successor", () => {
  const s = state();
  const plan = recoverPlanV4(s, PK(0x01));
  assert.equal(plan.terminal, true);
  assert.equal(plan.payoutValue, s.protectedValue + s.feeReserve);
  assert.equal(plan.payoutXOnly, PK(0x01));
  assert.equal(plan.successor, undefined);
  // recovery parse of a MALFORMED state (duplicate approvers, garbage root, M inconsistent)
  const malformed = normalizeStateV4ForRecovery({
    protectedValue: "5",
    feeReserve: "0",
    paused: "1",
    agentRoot: "ef".repeat(32),
    approverSlots: [PK(9), PK(9), ...Array.from({ length: 8 }, () => "00".repeat(32))],
    approvalM: "7",
    policyNonce: "12"
  });
  const p2 = recoverPlanV4(malformed, PK(0x01));
  assert.equal(p2.payoutValue, 5n, "empty reserve never traps recovery");
  // every ordinary transition refuses the recovery parse
  for (const f of [
    () => setAgentRootSuccessorV4(malformed, "cd".repeat(32)),
    () => setApproversSuccessorV4(malformed, { approvers: [PK(3)], approvalM: "1" }),
    () => topUpSuccessorV4(malformed, "1"),
    () => topUpReserveSuccessorV4(malformed, "1"),
    () => pauseSuccessorV4(malformed, false)
  ]) {
    assert.throws(f, /recovery-mode/);
  }
});

test("E3: strict normalizer rejects malformed states (fail closed)", () => {
  assert.throws(() => normalizeStateV4({ ...stateToJsonV4(state()), approvalM: "11" }));
  assert.throws(() => normalizeStateV4({ ...stateToJsonV4(state()), protectedValue: "0" }));
  const dup = stateToJsonV4(state());
  dup.approverSlots[1] = dup.approverSlots[0];
  assert.throws(() => normalizeStateV4(dup), /duplicates/);
});
