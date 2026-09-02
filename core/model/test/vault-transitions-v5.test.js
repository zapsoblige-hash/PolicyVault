"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const m = require("../agent-merkle-v5");
const tr = require("../vault-transitions-v5");

const A = (i, extra = {}) => ({
  agentPk: i.toString(16).padStart(2, "0").repeat(32),
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: "60000",
  agentMaxCarryKas: "25000000",
  agentRecipientRoot: "ab".repeat(32),
  ...extra
});
const tree = m.buildTokenAgentTreeV5([A(0x22), A(0x11)]);
const proof = m.generateTokenAgentProofV5(tree, "22".repeat(32));
const state = { feeReserve: "500000000", paused: "0", agentRoot: tree.root, policyNonce: "0" };
const honest = () => ({
  agentPolicy: proof.policy,
  agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
  spendAmount: "200",
  tokenPositionAmount: "300",
  periodsElapsed: 0n,
  reserveConsumed: "50000",
  tokenInputKas: "200000000",
  selfCarryKas: "180000000",
  recipientCarryKas: "20000000"
});

test("honest token agent spend: token conservation, accounting, KAS domain, successor root", () => {
  const plan = tr.tokenAgentSpendSuccessorV5(state, honest());
  assert.equal(plan.tokenSelfAfter, 100n);
  assert.equal(plan.newSpent, 200n);
  assert.equal(plan.successor.feeReserve, 499950000n);
  assert.equal(plan.successor.policyNonce, 0n);
  const expected = m.applyTokenAgentSpendV5(tree, "22".repeat(32), { newPeriodStartDaa: "5000", newTokenPeriodSpent: "200" }).tree.root;
  assert.equal(plan.successor.agentRoot, expected);
  const states = tr.tokenContinuationStatesV5({ controllerCovenantId: "cc".repeat(32), recipientPk: "33".repeat(32), plan });
  assert.deepEqual(states.selfNew, { ownerIdentifier: "cc".repeat(32), identifierType: 2, amount: 100n, isMinter: false });
  assert.deepEqual(states.recipientNew, { ownerIdentifier: "33".repeat(32), identifierType: 0, amount: 200n, isMinter: false });
  /* rollover: the committed tree says 350 spent this period; two periods later the budget resets */
  const spentTree = m.buildTokenAgentTreeV5([A(0x22, { tokenPeriodSpent: "350" }), A(0x11)]);
  const spentProof = m.generateTokenAgentProofV5(spentTree, "22".repeat(32));
  const spentState = { ...state, agentRoot: spentTree.root };
  assert.throws(() => tr.tokenAgentSpendSuccessorV5(spentState, { ...honest(), agentPolicy: spentProof.policy, agentProof: { siblingsHex: spentProof.siblingsHex, pathBits: spentProof.pathBits } }), /remaining token period budget/);
  const roll = tr.tokenAgentSpendSuccessorV5(spentState, { ...honest(), agentPolicy: spentProof.policy, agentProof: { siblingsHex: spentProof.siblingsHex, pathBits: spentProof.pathBits }, periodsElapsed: 2n });
  assert.equal(roll.lockTime, 7000n);
  assert.equal(roll.newSpent, 200n);
  assert.equal(roll.newStart, 7000n);
});

test("refusals mirror the covenant (fail closed, coded)", () => {
  const refuse = (patch, code) => {
    let err;
    try {
      tr.tokenAgentSpendSuccessorV5(patch.state ?? state, { ...honest(), ...patch });
    } catch (e) {
      err = e;
    }
    assert.ok(err, "must refuse");
    if (code) assert.equal(err.code, code, err.message);
  };
  refuse({ spendAmount: "251" }, "OVER_CAP");
  refuse({ spendAmount: "0" }, "ZERO_SPEND");
  refuse({ spendAmount: "200", tokenPositionAmount: "100" }, "INSUFFICIENT_TOKENS");
  refuse({ agentPolicy: { ...proof.policy, tokenPeriodSpent: "200" }, spendAmount: "250" }, "AGENT_PROOF_INVALID"); // tree says 0 spent
  refuse({ agentPolicy: { ...proof.policy, tokenMaxPerSpend: "1000" } }, "AGENT_PROOF_INVALID"); // forged leaf
  refuse({ reserveConsumed: "60001" }, "OVER_AGENT_FEE_CAP");
  refuse({ recipientCarryKas: "25000001" }, "OVER_CARRY_CAP");
  refuse({ selfCarryKas: "179999999" }, "TOKEN_FAMILY_KAS_LEAK");
  refuse({ state: { ...state, paused: "1" } }, "PAUSED");
  refuse({ state: { ...state, feeReserve: "1000" } }, "INSUFFICIENT_RESERVE");
  refuse({ state: { recoveryParse: true, ...state } }, "RECOVERY_STATE_ONLY");
  /* budget: 0 + 250 ok, then second spend 200 -> over budget */
  const first = tr.tokenAgentSpendSuccessorV5(state, { ...honest(), spendAmount: "250" });
  const nextTree = m.applyTokenAgentSpendV5(tree, "22".repeat(32), { newPeriodStartDaa: "5000", newTokenPeriodSpent: "250" }).tree;
  const nextProof = m.generateTokenAgentProofV5(nextTree, "22".repeat(32));
  let err;
  try {
    tr.tokenAgentSpendSuccessorV5(first.successor, { ...honest(), agentPolicy: nextProof.policy, agentProof: { siblingsHex: nextProof.siblingsHex, pathBits: nextProof.pathBits }, spendAmount: "200", tokenPositionAmount: "50" });
  } catch (e) {
    err = e;
  }
  assert.equal(err.code, "INSUFFICIENT_TOKENS");
  try {
    tr.tokenAgentSpendSuccessorV5(first.successor, { ...honest(), agentPolicy: nextProof.policy, agentProof: { siblingsHex: nextProof.siblingsHex, pathBits: nextProof.pathBits }, spendAmount: "200", tokenPositionAmount: "500" });
  } catch (e) {
    err = e;
  }
  assert.equal(err.code, "OVER_BUDGET");
});

test("owner ops and recover plan", () => {
  const root2 = "99".repeat(32);
  const a = tr.setAgentRootSuccessorV5(state, root2);
  assert.equal(a.successor.policyNonce, 1n);
  assert.equal(a.opSelector, 0);
  const t = tr.topUpReserveSuccessorV5(state, "100000000");
  assert.equal(t.successor.feeReserve, 600000000n);
  assert.equal(t.opSelector, 1);
  assert.throws(() => tr.topUpReserveSuccessorV5(state, "0"));
  const p = tr.pauseSuccessorV5(state, true);
  assert.equal(p.successor.paused, 1n);
  assert.throws(() => tr.pauseSuccessorV5(state, false), /not paused/);
  const u = tr.pauseSuccessorV5(p.successor, false);
  assert.equal(u.opSelector, 3);
  const r = tr.recoverPlanV5(state, "11".repeat(32), "300");
  assert.equal(r.payout, 500000000n);
  assert.deepEqual(r.tokenRecipient, { ownerIdentifier: "11".repeat(32), identifierType: 0, amount: 300n, isMinter: false });
  assert.equal(tr.recoverPlanV5(state, "11".repeat(32), null).tokenRecipient, null);
});
