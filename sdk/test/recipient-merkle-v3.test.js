"use strict";

/* UNIT — v0.3 canonical recipient Merkle tree/proof/verify (20C at the
 * SDK layer; production-covenant proof lives in tests/vm
 * v3_sdk_integration.rs). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  MAX_DEPTH,
  leafHash,
  buildRecipientTree,
  generateRecipientProof,
  verifyRecipientProof
} = require("../src/recipient-merkle-v3");

const K = (i) => i.toString(16).padStart(4, "0").repeat(16);
const R1 = "aa".repeat(32);
const R2 = "bb".repeat(32);
const R3 = "cc".repeat(32);

test("leaf is exactly SHA256(0x50563301 || xonly)", () => {
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x50, 0x56, 0x33, 0x01]), Buffer.from(R1, "hex")]))
    .digest("hex");
  assert.equal(leafHash(R1).toString("hex"), expected);
});

test("deterministic canonical tree: order and duplicates never change the root", () => {
  const a = buildRecipientTree([R1, R2, R3]);
  const b = buildRecipientTree([R3, R1, R2, R1, R1]); // shuffled + duplicated
  assert.equal(a.root, b.root);
  assert.equal(b.recipients.length, 3); // duplicates collapse
});

test("single recipient: depth 0, empty proof, root == leaf (covenant-proven shape)", () => {
  const t = buildRecipientTree([R1]);
  assert.equal(t.depth, 0);
  assert.equal(t.root, leafHash(R1).toString("hex"));
  const p = generateRecipientProof(t, R1);
  assert.equal(p.siblingsHex, "");
  assert.equal(p.pathBits, 0n);
  assert.equal(verifyRecipientProof({ root: t.root, recipient: R1, siblingsHex: "", pathBits: 0n }), true);
});

test("zero recipients fails closed", () => {
  assert.throws(() => buildRecipientTree([]), /non-empty/);
});

test("every member of a non-power-of-two tree proves membership", () => {
  const recipients = Array.from({ length: 11 }, (_, i) => K(i + 1)); // 11 -> padded to 16, depth 4
  const t = buildRecipientTree(recipients);
  assert.equal(t.depth, 4);
  for (const r of t.recipients) {
    const p = generateRecipientProof(t, r);
    assert.equal(p.siblingsHex.length / 64, 4);
    assert.equal(verifyRecipientProof({ root: t.root, recipient: r, siblingsHex: p.siblingsHex, pathBits: p.pathBits }), true);
  }
});

test("depth matrix 1..16: generated proofs verify", () => {
  for (const depth of [1, 2, 4, 8, 12, 16]) {
    const n = 1 << depth;
    const recipients = [R1];
    for (let i = 0; recipients.length < n; i++) {
      recipients.push(K(i));
    }
    const t = buildRecipientTree(recipients);
    assert.equal(t.depth, depth, `depth ${depth}`);
    const p = generateRecipientProof(t, R1);
    assert.equal(verifyRecipientProof({ root: t.root, recipient: R1, siblingsHex: p.siblingsHex, pathBits: p.pathBits }), true, `depth ${depth}`);
  }
});

test("more than 65,536 recipients fails closed", () => {
  // Constructing 65,537 distinct keys is cheap; the tree must refuse.
  const recipients = [];
  for (let i = 0; recipients.length <= (1 << 16); i++) {
    recipients.push(i.toString(16).padStart(8, "0").repeat(8));
  }
  assert.throws(() => buildRecipientTree(recipients), /exceeds the maximum/);
});

test("proof forgery matrix rejected", () => {
  const t = buildRecipientTree([R1, R2, R3, K(9), K(10), K(11), K(12), K(13)]);
  const p = generateRecipientProof(t, R1);
  const ok = { root: t.root, recipient: R1, siblingsHex: p.siblingsHex, pathBits: p.pathBits };
  assert.equal(verifyRecipientProof(ok), true);

  // wrong recipient (not proven by this proof)
  assert.equal(verifyRecipientProof({ ...ok, recipient: R2 }), false);
  // wrong root
  assert.equal(verifyRecipientProof({ ...ok, root: "99".repeat(32) }), false);
  // mutated sibling byte
  const mutated = (parseInt(p.siblingsHex.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + p.siblingsHex.slice(2);
  assert.equal(verifyRecipientProof({ ...ok, siblingsHex: mutated }), false);
  // reordered siblings
  const reordered = p.siblingsHex.slice(64, 128) + p.siblingsHex.slice(0, 64) + p.siblingsHex.slice(128);
  assert.equal(verifyRecipientProof({ ...ok, siblingsHex: reordered }), false);
  // wrong path bits
  assert.equal(verifyRecipientProof({ ...ok, pathBits: p.pathBits ^ 1n }), false);
  // truncated / extended proofs
  assert.equal(verifyRecipientProof({ ...ok, siblingsHex: p.siblingsHex.slice(0, -64) }), false);
  assert.equal(verifyRecipientProof({ ...ok, siblingsHex: p.siblingsHex + "00".repeat(32) }), false);
  // foreign tree's proof
  const foreign = buildRecipientTree([K(21), K(22), K(23), K(24)]);
  const fp = generateRecipientProof(foreign, K(21));
  assert.equal(verifyRecipientProof({ root: t.root, recipient: K(21), siblingsHex: fp.siblingsHex, pathBits: fp.pathBits }), false);
  // excess path bits beyond the walked depth must fail (covenant bits==0)
  assert.equal(verifyRecipientProof({ ...ok, pathBits: p.pathBits | (1n << 15n) }), false);
});

test("malformed proofs fail closed (throw, matching covenant aborts)", () => {
  const t = buildRecipientTree([R1, R2]);
  const p = generateRecipientProof(t, R1);
  // ragged sibling buffer (not a multiple of 32)
  assert.throws(() => verifyRecipientProof({ root: t.root, recipient: R1, siblingsHex: p.siblingsHex + "00", pathBits: p.pathBits }), /hex|multiple/);
  // depth > 16
  assert.throws(
    () => verifyRecipientProof({ root: t.root, recipient: R1, siblingsHex: "00".repeat(32 * 17), pathBits: 0n }),
    /exceeds the covenant maximum/
  );
  // pathBits out of range
  assert.throws(() => verifyRecipientProof({ root: t.root, recipient: R1, siblingsHex: p.siblingsHex, pathBits: 65536n }), /out of range/);
  // non-member proof generation refused
  assert.throws(() => generateRecipientProof(t, R3), /not in this tree/);
});
