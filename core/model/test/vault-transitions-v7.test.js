"use strict";

/*
 * UNIT — v0.7 ROOTED VAULT transitions: owner selectors 0..4 and their
 * REQUIRED root authority, break-glass recovery to the genesis-pinned cold
 * destination, and the delegate spend that never touches the root and whose
 * math is the frozen v0.5 math verbatim.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  tokenAgentSpendSuccessorV7,
  tokenContinuationStatesV7,
  setAgentRootSuccessorV7,
  topUpReserveSuccessorV7,
  pauseSuccessorV7,
  emergencyPauseSuccessorV7,
  recoverPlanV7,
  ownerOpSuccessorV7
} = require("../vault-transitions-v7");
const { tokenAgentSpendSuccessorV5 } = require("../vault-transitions-v5");
const { buildTokenAgentTreeV5, generateTokenAgentProofV5 } = require("../agent-merkle-v5");
const { buildRecipientTree } = require("../recipient-merkle-v3");
const { OWNER_SCHEMES } = require("../token-amounts");

const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const AGENT = H(0x62);
const OTHER = H(0x65);
const RECIPIENT = H(0x63);
const TEMPLATE = { recoveryPk: H(0x51) };

const rTree = buildRecipientTree([RECIPIENT]);
const policy = (pk, over = {}) => ({
  agentPk: pk,
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: "100000000",
  agentMaxCarryKas: "25000000",
  agentRecipientRoot: rTree.root,
  ...over
});
const agents = [policy(AGENT), policy(OTHER)];
const tree = buildTokenAgentTreeV5(agents);
const proof = generateTokenAgentProofV5(tree, AGENT);
const state = (over = {}) => ({ feeReserve: "500000000", paused: "0", agentRoot: tree.root, policyNonce: "3", ...over });

const spendParams = {
  agentPolicy: proof.policy,
  agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits },
  spendAmount: "200",
  tokenPositionAmount: "300",
  periodsElapsed: 0n,
  reserveConsumed: "50000",
  tokenInputKas: "200000000",
  selfCarryKas: "180000000",
  recipientCarryKas: "20000000"
};

function refuses(fn, code) {
  assert.throws(fn, (e) => {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

test("owner selectors 0-3 ride a FULL-quorum AUTHORIZE root successor", () => {
  const rootSet = setAgentRootSuccessorV7(state(), H(0xaa));
  assert.equal(rootSet.opSelector, 0);
  assert.equal(rootSet.rootAuthority.rootActionName, "authorize");
  assert.equal(rootSet.rootAuthority.expectFrozenAfter, 0n);
  assert.equal(rootSet.rootAuthority.quorum, "ownerM");
  assert.equal(rootSet.requiresRootInput, true);
  assert.equal(rootSet.successor.agentRoot, H(0xaa));
  assert.equal(rootSet.successor.policyNonce, 4n, "setAgentRoot advances the policy nonce");

  const top = topUpReserveSuccessorV7(state(), "100000000");
  assert.equal(top.opSelector, 1);
  assert.equal(top.successor.feeReserve, 600000000n);
  assert.equal(top.successor.policyNonce, 3n, "topUpReserve never moves the nonce");

  const pause = pauseSuccessorV7(state(), true);
  assert.equal(pause.opSelector, 2);
  assert.equal(pause.rootAuthority.rootActionName, "authorize");
  assert.equal(pause.successor.paused, 1n);

  const unpause = pauseSuccessorV7(state({ paused: "1" }), false);
  assert.equal(unpause.opSelector, 3);
  assert.equal(unpause.rootAuthority.rootActionName, "authorize", "unpausing needs the FULL quorum");
  assert.equal(unpause.successor.paused, 0n);
});

test("selector 4 is the emergency pause: same state effect, strictly lighter authority", () => {
  const emergency = emergencyPauseSuccessorV7(state());
  const ordinary = pauseSuccessorV7(state(), true);
  assert.deepEqual(emergency.successor, ordinary.successor, "identical, AUTHORITY-REDUCING state effect");
  assert.equal(emergency.opSelector, 4);
  assert.equal(emergency.rootAuthority.rootActionName, "freeze");
  assert.equal(emergency.rootAuthority.expectFrozenAfter, 1n);
  assert.equal(emergency.rootAuthority.quorum, "emergencyK");
  assert.throws(() => emergencyPauseSuccessorV7(state({ paused: "1" })), /already paused/);
});

test("break-glass recovery pays the GENESIS-PINNED cold destination, never a chosen one", () => {
  const plan = recoverPlanV7(state(), TEMPLATE, "300");
  assert.equal(plan.terminal, true);
  assert.equal(plan.payout, 500000000n);
  assert.equal(plan.payoutTo, TEMPLATE.recoveryPk);
  assert.equal(plan.tokenRecipient.ownerIdentifier, TEMPLATE.recoveryPk);
  assert.equal(plan.tokenRecipient.identifierType, OWNER_SCHEMES.P2PK);
  assert.equal(plan.tokenRecipient.amount, 300n, "the ENTIRE position moves");
  assert.equal(plan.rootAuthority.rootActionName, "authorize", "terminating needs the FULL quorum");
  assert.equal(recoverPlanV7(state(), TEMPLATE, null).tokenRecipient, null);
  assert.throws(() => recoverPlanV7(state(), {}, "300"), /template.recoveryPk/);
  assert.throws(() => recoverPlanV7(state(), undefined, "300"), /vault template is required/);
});

test("the delegate spend is the frozen v0.5 math and never touches the root", () => {
  const v7 = tokenAgentSpendSuccessorV7(state(), spendParams);
  const v5 = tokenAgentSpendSuccessorV5(state(), spendParams);
  assert.equal(v7.requiresRootInput, false, "an agent spend has NO root input");
  assert.equal(v7.rootAuthority, null);
  assert.deepEqual(v7.successor, v5.successor, "v0.7 must not fork the v0.5 spend math");
  assert.equal(v7.spendAmount, 200n);
  assert.equal(v7.tokenSelfAfter, 100n);
  assert.equal(v7.successor.feeReserve, 499950000n);

  const states = tokenContinuationStatesV7({ controllerCovenantId: H(0x43), recipientPk: RECIPIENT, plan: v7 });
  assert.equal(states.selfNew.identifierType, OWNER_SCHEMES.COVENANT_ID);
  assert.equal(states.recipientNew.ownerIdentifier, RECIPIENT);
  assert.equal(states.recipientNew.amount, 200n);

  refuses(() => tokenAgentSpendSuccessorV7(state({ paused: "1" }), spendParams), "PAUSED");
  refuses(() => tokenAgentSpendSuccessorV7(state(), { ...spendParams, spendAmount: "251" }), "OVER_CAP");
  refuses(() => tokenAgentSpendSuccessorV7(state(), { ...spendParams, tokenPositionAmount: "100" }), "INSUFFICIENT_TOKENS");
  refuses(() => tokenAgentSpendSuccessorV7(state(), { ...spendParams, recipientCarryKas: "25000001" }), "OVER_CARRY_CAP");
});

test("owner-op dispatch fails closed on an unknown action", () => {
  assert.equal(ownerOpSuccessorV7("ownerPause", state(), {}).opSelector, 2);
  assert.equal(ownerOpSuccessorV7("ownerEmergencyPause", state(), {}).opSelector, 4);
  assert.equal(ownerOpSuccessorV7("ownerTopUpReserve", state(), { topUpReserveAmountSompi: "1" }).externalFunding, 1n);
  assert.equal(ownerOpSuccessorV7("ownerSetAgentRoot", state(), { newAgentRoot: H(0xab) }).successor.agentRoot, H(0xab));
  refuses(() => ownerOpSuccessorV7("ownerRecover", state(), {}), "UNKNOWN_ACTION");
  refuses(() => ownerOpSuccessorV7("tokenAgentSpend", state(), {}), "UNKNOWN_ACTION");
});
