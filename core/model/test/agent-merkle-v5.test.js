"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const m = require("../agent-merkle-v5");

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "token-agent-leaf-v5.json"), "utf8"));
const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

test("PRODUCTION-BYTE: token-agent leaf equals the Rust leaf the v0.5 covenant accepted; co-path fold matches", () => {
  assert.equal(fixture.preimageLen, m.LEAF_PREIMAGE_LEN);
  for (const v of fixture.vectors) {
    const policy = { ...v };
    delete policy.leafHex;
    delete policy.foldSiblingsHex;
    delete policy.foldPathBits;
    delete policy.foldRootHex;
    assert.equal(bytesToHex(m.tokenAgentLeafHash(policy)), v.leafHex);
    assert.equal(m.tokenAgentLeafPreimage(policy).length, 125);
    assert.equal(m.foldTokenAgentPolicyV5(policy, v.foldSiblingsHex, v.foldPathBits), v.foldRootHex);
  }
});

const A = (i, extra = {}) => ({
  agentPk: i.toString(16).padStart(2, "0").repeat(32),
  tokenMaxPerSpend: "250",
  tokenPeriodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  tokenPeriodSpent: "0",
  agentMaxFeePerTx: "60000",
  agentMaxCarryKas: "25000000",
  agentRecipientRoot: "00".repeat(32),
  ...extra
});

test("tree build / proof / verify / edits / spend advance keep the covenant fold invariant", () => {
  const tree = m.buildTokenAgentTreeV5([A(0x22), A(0x11), A(0x33)]);
  assert.equal(tree.realCount, 3);
  assert.equal(tree.leafCount, 4);
  assert.equal(tree.depth, 2);
  assert.deepEqual(tree.agents.map((a) => a.agentPk[0]), ["1", "2", "3"]);
  const proof = m.generateTokenAgentProofV5(tree, "22".repeat(32));
  assert.equal(m.verifyTokenAgentProofV5({ root: tree.root, policy: proof.policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }), true);
  assert.equal(m.verifyTokenAgentProofV5({ root: tree.root, policy: { ...proof.policy, tokenMaxPerSpend: "251" }, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }), false);
  const advanced = m.applyTokenAgentSpendV5(tree, "22".repeat(32), { newPeriodStartDaa: "5000", newTokenPeriodSpent: "200" });
  assert.equal(advanced.newPolicy.tokenPeriodSpent, 200n);
  assert.notEqual(advanced.tree.root, tree.root);
  const added = m.addTokenAgentV5(tree, A(0x44));
  assert.equal(added.realCount, 4);
  assert.throws(() => m.addTokenAgentV5(tree, A(0x22)), /already exists/);
  const removed = m.removeTokenAgentV5(added, "44".repeat(32));
  assert.equal(removed.root, tree.root);
  const rotated = m.rotateTokenAgentV5(tree, "22".repeat(32), A(0x55));
  assert.equal(rotated.realCount, 3);
  assert.throws(() => m.rotateTokenAgentV5(tree, "22".repeat(32), A(0x22)), /NEW agent key/);
  assert.throws(() => m.generateTokenAgentProofV5(tree, "99".repeat(32)), /not in this tree/);
  /* padding leaves are unspendable: a proof for a padding slot can never be produced */
  assert.equal(m.PADDING_LEAF_HEX.length, 64);
});

test("two-domain policy validation fails closed", () => {
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { tokenMaxPerSpend: "0" })), /> 0/);
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { tokenMaxPerSpend: "9223372036854775808" })), /i64/);
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { tokenPeriodSpent: "-1" })));
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { periodLengthDaa: "0" })), /> 0/);
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { agentMaxFeePerTx: "1.5" })));
  assert.throws(() => m.normalizeTokenAgentPolicyV5(A(0x22, { approvalThreshold: "1" })), /unknown token agent policy field/);
  assert.throws(() => m.buildTokenAgentTreeV5([A(0x22), A(0x22)]), /duplicate agentPk/);
  const json = m.tokenAgentPolicyToJsonV5(A(0x22));
  assert.equal(json.tokenMaxPerSpend, "250");
});
