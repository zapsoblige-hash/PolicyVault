"use strict";

/* SDK — Checkpoint E §E2: the v0.3 recipient-Merkle module is REUSED for
 * v0.4 (per-agent recipient trees). The v0.4 covenant's recipient
 * semantics are byte-identical to v0.3's (requireAgentRecipient in
 * tools/gen_v4.js: leaf = sha256(0x50563301 || recipientPk), node =
 * sha256(left||right), depth <= 16, LSB-first path bits, bits fully
 * consumed) — so no fork/adapter exists. This suite pins that byte
 * compatibility EXPLICITLY with an independent reimplementation of the
 * v0.4 covenant walk, so any future drift in the reused module fails
 * here before it can reach consensus. End-to-end proof on the real
 * production covenant: tests/vm/tests/v4_sdk_integration.rs. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  LEAF_DOMAIN,
  MAX_DEPTH,
  buildRecipientTree,
  generateRecipientProof,
  verifyRecipientProof,
  leafHash
} = require("../src/recipient-merkle-v3");
const { AGENT_LEAF_DOMAIN, AGENT_PADDING_DOMAIN, agentLeafPreimage } = require("../src/agent-merkle-v4");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const PK = (v) => v.toString(16).padStart(2, "0").repeat(32);

/* Independent reimplementation of the v0.4 covenant's requireAgentRecipient
 * membership walk (tools/gen_v4.js), written from the covenant text — NOT
 * from the reused SDK module. */
function covenantWalkV4(recipientHex, siblingsHex, pathBits) {
  let node = sha256(Buffer.concat([Buffer.from([0x50, 0x56, 0x33, 0x01]), Buffer.from(recipientHex, "hex")]));
  const siblings = Buffer.from(siblingsHex, "hex");
  if (siblings.length % 32 !== 0 || siblings.length > 16 * 32) throw new Error("covenant would abort");
  let bits = BigInt(pathBits);
  if (bits < 0n || bits >= 65536n) throw new Error("covenant would abort");
  for (let i = 0; i < siblings.length / 32; i++) {
    const sib = siblings.subarray(i * 32, i * 32 + 32);
    node = bits % 2n === 1n ? sha256(Buffer.concat([sib, node])) : sha256(Buffer.concat([node, sib]));
    bits /= 2n;
  }
  if (bits !== 0n) throw new Error("covenant would abort (bits != 0)");
  return node.toString("hex");
}

test("E2: frozen v0.4 recipient parameters match the reused v0.3 module exactly", () => {
  assert.deepEqual([...LEAF_DOMAIN], [0x50, 0x56, 0x33, 0x01], "recipient leaf domain must be the frozen 0x50563301");
  assert.equal(MAX_DEPTH, 16, "recipient depth cap must be the frozen 16");
});

test("E2: SDK recipient proofs reproduce the v0.4 covenant walk byte-for-byte", () => {
  for (const n of [1, 2, 3, 7, 16]) {
    const recipients = Array.from({ length: n }, (_, i) => PK(0x40 + i));
    const tree = buildRecipientTree(recipients);
    for (const r of tree.recipients) {
      const proof = generateRecipientProof(tree, r);
      const walked = covenantWalkV4(r, proof.siblingsHex, proof.pathBits);
      assert.equal(walked, tree.root, `covenant walk must land on the SDK root (n=${n})`);
      assert.ok(verifyRecipientProof({ root: tree.root, recipient: r, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
    }
  }
});

test("E2: leaf bytes are the exact 36-byte v0.4 preimage", () => {
  const r = PK(0x44);
  const expected = sha256(Buffer.concat([Buffer.from([0x50, 0x56, 0x33, 0x01]), Buffer.from(r, "hex")]));
  assert.equal(leafHash(r).toString("hex"), expected.toString("hex"));
});

test("E2: domain separation across the three v0.4 preimage families (36/64/124) and the padding domain", () => {
  // recipient leaf preimage: 36 bytes; node: 64; agent leaf: 124; padding: 4.
  assert.equal(Buffer.concat([LEAF_DOMAIN, Buffer.alloc(32)]).length, 36);
  assert.equal(
    agentLeafPreimage({
      agentPk: PK(1),
      maxPerSpend: "1",
      periodBudget: "1",
      periodLengthDaa: "1",
      periodStartDaa: "0",
      periodSpent: "0",
      approvalThreshold: "0",
      agentMaxFeePerTx: "0",
      agentRecipientRoot: "00".repeat(32)
    }).length,
    124
  );
  assert.deepEqual([...AGENT_LEAF_DOMAIN], [0x50, 0x56, 0x34, 0x01]);
  assert.deepEqual([...AGENT_PADDING_DOMAIN], [0x50, 0x56, 0x34, 0x00]);
  // the four domains are pairwise distinct
  const domains = [[...LEAF_DOMAIN].join(","), [...AGENT_LEAF_DOMAIN].join(","), [...AGENT_PADDING_DOMAIN].join(",")];
  assert.equal(new Set(domains).size, 3);
});
