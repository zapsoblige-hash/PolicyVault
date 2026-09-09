"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const am = require("../agent-merkle-v6");

const pk = (b) => b.repeat(32);
const policy = (agentPk, extra = {}) => ({
  agentPk,
  tokenMaxPerSpend: "600",
  tokenPeriodBudget: "1000",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: "60000",
  agentMaxCarryKas: "25000000",
  kasMaxPerSwap: "50000",
  kasPeriodBudget: "80000",
  kasPeriodSpent: "0",
  agentRecipientRoot: "00".repeat(32),
  ...extra
});

test("leaf preimage is 149 bytes under domain 0x50563601 with all twelve fields", () => {
  const pre = am.tokenAgentLeafPreimageV6(policy(pk("62")));
  assert.equal(pre.length, am.LEAF_PREIMAGE_LEN_V6);
  assert.deepEqual([...pre.subarray(0, 4)], [0x50, 0x56, 0x36, 0x01]);
  assert.equal(pre[pre.length - 1], 0x00);
  /* kasMaxPerSwap (LE64) sits after the seven v0.5 num8 fields: 4 + 32 + 7*8 = 92 */
  assert.equal(new DataView(pre.buffer, pre.byteOffset + 92, 8).getBigUint64(0, true), 50_000n);
  assert.equal(new DataView(pre.buffer, pre.byteOffset + 100, 8).getBigUint64(0, true), 80_000n);
});

test("closed layout: v0.5 (nine-field) policies and unknown fields are refused; zero KAS caps allowed", () => {
  const { kasMaxPerSwap, kasPeriodBudget, kasPeriodSpent, ...v5 } = policy(pk("62"));
  assert.throws(() => am.normalizeTokenAgentPolicyV6(v5), /kasMaxPerSwap/);
  assert.throws(() => am.normalizeTokenAgentPolicyV6({ ...policy(pk("62")), foo: 1 }), /closed layout/);
  const noBuy = am.normalizeTokenAgentPolicyV6(policy(pk("62"), { kasMaxPerSwap: "0", kasPeriodBudget: "0" }));
  assert.equal(noBuy.kasMaxPerSwap, 0n);
  assert.throws(() => am.normalizeTokenAgentPolicyV6(policy(pk("62"), { kasMaxPerSwap: "100", kasPeriodBudget: "50" })), /unusable BUY cap/);
});

test("tree/proof/fold agree with the canonical rebuild for both accounting domains", () => {
  const tree = am.buildTokenAgentTreeV6([policy(pk("62")), policy(pk("65")), policy(pk("61"))]);
  assert.equal(tree.realCount, 3);
  assert.equal(tree.leafCount, 4);
  const proof = am.generateTokenAgentProofV6(tree, pk("65"));
  assert.ok(am.verifyTokenAgentProofV6({ root: tree.root, policy: proof.policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
  const adv = am.applyTokenAgentAdvanceV6(tree, pk("65"), { newPeriodStartDaa: "5000", newTokenPeriodSpent: "500", newKasPeriodSpent: "41877" });
  assert.equal(adv.newPolicy.kasPeriodSpent, 41_877n);
  const folded = am.foldTokenAgentPolicyV6(adv.newPolicy, proof.siblingsHex, proof.pathBits);
  assert.equal(folded, adv.tree.root);
  /* a forged claim (larger caps) never folds to the committed root */
  const forged = { ...proof.policy, kasMaxPerSwap: "1000000000", kasPeriodBudget: "1000000000" };
  assert.ok(!am.verifyTokenAgentProofV6({ root: tree.root, policy: forged, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
});

test("padding leaf is unspendable and distinct from the v0.5 padding domain", () => {
  const v5 = require("../agent-merkle-v5");
  assert.notEqual(am.PADDING_LEAF_HEX, v5.PADDING_LEAF_HEX);
  const empty = am.buildTokenAgentTreeV6([]);
  assert.equal(empty.root, am.PADDING_LEAF_HEX);
});
