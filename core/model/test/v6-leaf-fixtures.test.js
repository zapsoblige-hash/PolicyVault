"use strict";
/* The v0.6 leaf bytes pinned to the SAME Rust leaf functions the real-engine
 * v0.6 production suite accepts (tests/vm/tests/v6_fixture_capture.rs). */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const am = require("../agent-merkle-v6");
const sp = require("../swap-policy-v6");

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

test("token-agent leaf v6 matches the Rust fixture byte-for-byte (leaf + depth-2 fold)", () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "token-agent-leaf-v6.json"), "utf8"));
  assert.equal(fixture.leafDomain, hex(am.TOKEN_AGENT_LEAF_DOMAIN_V6));
  assert.equal(fixture.preimageLen, am.LEAF_PREIMAGE_LEN_V6);
  assert.ok(fixture.vectors.length >= 4);
  for (const v of fixture.vectors) {
    const { leafHex, foldSiblingsHex, foldPathBits, foldRootHex, ...policy } = v;
    assert.equal(hex(am.tokenAgentLeafHashV6(policy)), leafHex);
    assert.equal(am.foldTokenAgentPolicyV6(policy, foldSiblingsHex, BigInt(foldPathBits)), foldRootHex);
  }
});

test("swap-policy leaf v6 matches the Rust fixture byte-for-byte (leaf + depth-2 fold)", () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "swap-policy-leaf-v6.json"), "utf8"));
  assert.equal(fixture.leafDomain, hex(sp.SWAP_POLICY_LEAF_DOMAIN_V6));
  assert.equal(fixture.preimageLen, sp.LEAF_PREIMAGE_LEN_SWAP);
  assert.ok(fixture.vectors.length >= 3);
  for (const v of fixture.vectors) {
    const { leafHex, foldSiblingsHex, foldPathBits, foldRootHex, ...policy } = v;
    assert.equal(hex(sp.swapPolicyLeafHashV6(policy)), leafHex);
    assert.equal(sp.foldSwapPolicyV6(policy, foldSiblingsHex, BigInt(foldPathBits)), foldRootHex);
  }
});
