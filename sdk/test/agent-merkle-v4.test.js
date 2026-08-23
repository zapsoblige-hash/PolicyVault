"use strict";

/* SDK — canonical v0.4 agent-policy Merkle tree (Checkpoint E §E1).
 * Byte-exact leaf construction, canonical ordering, unspendable padding,
 * single-leaf updates preserving unrelated leaves, and the adversarial
 * proof matrix. Production-covenant execution proof lives in tests/vm
 * v4_sdk_integration.rs. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  AGENT_LEAF_DOMAIN,
  AGENT_PADDING_DOMAIN,
  PADDING_LEAF_HEX,
  MAX_AGENT_DEPTH,
  MAX_AGENTS,
  normalizeAgentPolicyV4,
  agentLeafPreimage,
  agentLeafHash,
  buildAgentTreeV4,
  generateAgentProofV4,
  verifyAgentProofV4,
  foldAgentPolicyV4,
  addAgentV4,
  removeAgentV4,
  updateAgentPolicyV4,
  rotateAgentV4,
  applyAgentSpendV4
} = require("../src/agent-merkle-v4");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();

/* Deterministic distinct x-only keys (test identities, not real points). */
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

test("E1: leaf preimage is the exact frozen 124-byte layout", () => {
  const p = policy(0x30, {
    maxPerSpend: "1",
    periodBudget: "2",
    periodLengthDaa: "3",
    periodStartDaa: "4",
    periodSpent: "5",
    approvalThreshold: "6",
    agentMaxFeePerTx: "7"
  });
  const pre = agentLeafPreimage(p);
  assert.equal(pre.length, 124);
  assert.deepEqual([...pre.subarray(0, 4)], [0x50, 0x56, 0x34, 0x01]);
  assert.equal(pre.subarray(4, 36).toString("hex"), PK(0x30));
  // seven num8 fields, little-endian fixed width, exact offsets
  const num = (off) => pre.readBigUInt64LE(off);
  assert.equal(num(36), 1n); // maxPerSpend
  assert.equal(num(44), 2n); // periodBudget
  assert.equal(num(52), 3n); // periodLengthDaa
  assert.equal(num(60), 4n); // periodStartDaa
  assert.equal(num(68), 5n); // periodSpent
  assert.equal(num(76), 6n); // approvalThreshold
  assert.equal(num(84), 7n); // agentMaxFeePerTx
  assert.equal(pre.subarray(92, 124).toString("hex"), "ab".repeat(32));
  assert.equal(agentLeafHash(p).toString("hex"), sha256(pre).toString("hex"));
});

test("E1: num8 injectivity at large values — 1-off fields change the leaf", () => {
  const big = policy(0x30, {
    periodLengthDaa: (1n << 40n).toString(),
    periodStartDaa: ((1n << 32n) + 7n).toString(),
    approvalThreshold: ((1n << 53n) + 123n).toString(),
    agentMaxFeePerTx: ((1n << 33n) + 1n).toString()
  });
  const base = agentLeafHash(big).toString("hex");
  for (const tweak of [
    { approvalThreshold: ((1n << 53n) + 124n).toString() },
    { periodStartDaa: ((1n << 32n) + 8n).toString() },
    { agentMaxFeePerTx: ((1n << 33n) + 2n).toString() },
    { periodLengthDaa: ((1n << 40n) + 1n).toString() }
  ]) {
    assert.notEqual(agentLeafHash({ ...big, ...tweak }).toString("hex"), base);
  }
});

test("E1: policy normalization fails closed on malformed inputs", () => {
  assert.throws(() => normalizeAgentPolicyV4(null));
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { agentPk: "zz".repeat(32) })));
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { agentPk: "aa".repeat(31) })));
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { maxPerSpend: "0" })), /greater than zero/);
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { periodBudget: "-5" })));
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { periodSpent: "1.5" })));
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { periodSpent: 42 })), /BigInt or decimal string/);
  assert.throws(() => normalizeAgentPolicyV4(policy(1, { agentRecipientRoot: "ab".repeat(31) })));
});

test("E1: deterministic root independent of caller insertion order", () => {
  const set = [policy(5), policy(3), policy(9), policy(1), policy(7)];
  const roots = new Set();
  for (let rot = 0; rot < set.length; rot++) {
    const shuffled = [...set.slice(rot), ...set.slice(0, rot)].reverse();
    roots.add(buildAgentTreeV4(shuffled).root);
  }
  assert.equal(roots.size, 1, "one logical agent set must have exactly one root");
});

test("E1: duplicate agentPk is rejected (no duplicate budget lanes)", () => {
  assert.throws(() => buildAgentTreeV4([policy(1), policy(2), policy(1, { maxPerSpend: "999" })]), /duplicate agentPk/);
});

test("E1: padding is the unspendable constant, never a duplicated real leaf", () => {
  assert.equal(PADDING_LEAF_HEX, sha256(AGENT_PADDING_DOMAIN).toString("hex"));
  assert.notDeepEqual([...AGENT_PADDING_DOMAIN], [...AGENT_LEAF_DOMAIN]);
  // 3 agents -> padded to 4: the 4th leaf must be PADDING_LEAF, not agent #3.
  const tree = buildAgentTreeV4([policy(1), policy(2), policy(3)]);
  assert.equal(tree.leafCount, 4);
  assert.equal(tree.realCount, 3);
  assert.equal(tree.levels[0][3].toString("hex"), PADDING_LEAF_HEX);
  const lastLeaf = agentLeafHash(tree.agents[2]).toString("hex");
  assert.notEqual(tree.levels[0][3].toString("hex"), lastLeaf, "padding must never equal a real leaf");
  // The duplicate-last-padding root (the FORBIDDEN scheme) must differ.
  const dupPadRoot = (() => {
    let level = tree.agents.map((a) => agentLeafHash(a));
    while ((level.length & (level.length - 1)) !== 0) level.push(level[level.length - 1]);
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(sha256(Buffer.concat([level[i], level[i + 1]])));
      level = next;
    }
    return level[0].toString("hex");
  })();
  assert.notEqual(tree.root, dupPadRoot);
});

test("E1: empty agent set is canonical and unspendable", () => {
  const tree = buildAgentTreeV4([]);
  assert.equal(tree.root, PADDING_LEAF_HEX);
  assert.equal(tree.realCount, 0);
  assert.equal(tree.depth, 0);
  assert.throws(() => generateAgentProofV4(tree, PK(1)), /not in this tree/);
});

test("E1: depth bounds — 4096 agents build (depth 12), 4097 rejected", () => {
  const agents = [];
  for (let i = 0; i < MAX_AGENTS; i++) {
    agents.push(policy(0, { agentPk: i.toString(16).padStart(8, "0").repeat(8) }));
  }
  const tree = buildAgentTreeV4(agents);
  assert.equal(tree.depth, MAX_AGENT_DEPTH);
  assert.equal(tree.leafCount, MAX_AGENTS);
  assert.throws(
    () => buildAgentTreeV4([...agents, policy(0, { agentPk: "f".repeat(8).padStart(64, "e") })]),
    /exceeds the maximum/
  );
});

test("E1: proof generate/verify across depths incl. depth 0", () => {
  for (const n of [1, 2, 3, 5, 8, 9]) {
    const agents = Array.from({ length: n }, (_, i) => policy(i + 1));
    const tree = buildAgentTreeV4(agents);
    for (const a of tree.agents) {
      const proof = generateAgentProofV4(tree, a.agentPk);
      assert.equal(proof.root, tree.root);
      assert.equal(proof.siblingsHex.length / 64, tree.depth);
      assert.ok(
        verifyAgentProofV4({ root: tree.root, policy: a, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }),
        `proof for agent in ${n}-agent tree`
      );
    }
  }
  // single agent: depth 0, root == leaf, empty proof
  const one = buildAgentTreeV4([policy(1)]);
  assert.equal(one.root, agentLeafHash(one.agents[0]).toString("hex"));
  const p = generateAgentProofV4(one, one.agents[0].agentPk);
  assert.equal(p.siblingsHex, "");
  assert.equal(p.pathBits, 0n);
});

test("E1 adversarial: key A + leaf B / policy borrowing / fee-cap borrowing", () => {
  const a = policy(1);
  const b = policy(2, { maxPerSpend: "99999999999", agentMaxFeePerTx: "500000000" });
  const tree = buildAgentTreeV4([a, b]);
  const proofB = generateAgentProofV4(tree, b.agentPk);
  // key A presented with B's leaf position/proof
  assert.equal(verifyAgentProofV4({ root: tree.root, policy: a, siblingsHex: proofB.siblingsHex, pathBits: proofB.pathBits }), false);
  // A borrows B's cap (A's key, B's limits)
  const borrowCap = { ...b, agentPk: a.agentPk };
  const proofA = generateAgentProofV4(tree, a.agentPk);
  assert.equal(verifyAgentProofV4({ root: tree.root, policy: borrowCap, siblingsHex: proofA.siblingsHex, pathBits: proofA.pathBits }), false);
  // A borrows only B's fee cap
  const borrowFee = { ...a, agentMaxFeePerTx: b.agentMaxFeePerTx };
  assert.equal(verifyAgentProofV4({ root: tree.root, policy: borrowFee, siblingsHex: proofA.siblingsHex, pathBits: proofA.pathBits }), false);
});

test("E1 adversarial: sibling tamper / delete / insert / move / wrong path bit", () => {
  const agents = [policy(1), policy(2), policy(3), policy(4)];
  const tree = buildAgentTreeV4(agents);
  const target = tree.agents[1];
  const proof = generateAgentProofV4(tree, target.agentPk);
  const ok = { root: tree.root, policy: target, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits };
  assert.ok(verifyAgentProofV4(ok));

  // modified sibling byte
  const tampered = proof.siblingsHex.slice(0, 10) + (proof.siblingsHex[10] === "0" ? "1" : "0") + proof.siblingsHex.slice(11);
  assert.equal(verifyAgentProofV4({ ...ok, siblingsHex: tampered }), false);

  // deleted sibling level (truncated proof)
  assert.equal(verifyAgentProofV4({ ...ok, siblingsHex: proof.siblingsHex.slice(0, -64) }), false);

  // inserted sibling level (extended proof)
  assert.equal(verifyAgentProofV4({ ...ok, siblingsHex: proof.siblingsHex + "cd".repeat(32) }), false);

  // moved: another agent's co-path with this target's leaf
  const other = generateAgentProofV4(tree, tree.agents[3].agentPk);
  assert.equal(verifyAgentProofV4({ ...ok, siblingsHex: other.siblingsHex, pathBits: other.pathBits }), false);

  // wrong path bit
  assert.equal(verifyAgentProofV4({ ...ok, pathBits: proof.pathBits ^ 1n }), false);

  // excess path bits beyond depth
  assert.equal(verifyAgentProofV4({ ...ok, pathBits: proof.pathBits | (1n << BigInt(tree.depth)) }), false);

  // forged root
  assert.equal(verifyAgentProofV4({ ...ok, root: "cd".repeat(32) }), false);

  // malformed shapes throw (as the covenant aborts)
  assert.throws(() => verifyAgentProofV4({ ...ok, siblingsHex: proof.siblingsHex.slice(0, -2) })); // not 32-aligned
  assert.throws(() => verifyAgentProofV4({ ...ok, siblingsHex: "cd".repeat(32 * (MAX_AGENT_DEPTH + 1)) })); // depth 13
  assert.throws(() => verifyAgentProofV4({ ...ok, pathBits: BigInt(MAX_AGENTS) })); // out of range
  assert.throws(() => verifyAgentProofV4({ ...ok, pathBits: -1n }));
});

test("E1: single-leaf spend update preserves every unrelated leaf and matches the consensus fold", () => {
  const agents = [policy(1), policy(2), policy(3), policy(4), policy(5)];
  const tree = buildAgentTreeV4(agents);
  const target = tree.agents[2];
  const before = tree.agents.map((a) => agentLeafHash(a).toString("hex"));
  const proof = generateAgentProofV4(tree, target.agentPk);

  const { tree: after, previousPolicy, newPolicy } = applyAgentSpendV4(tree, target.agentPk, {
    newPeriodStartDaa: target.periodStartDaa,
    newPeriodSpent: (target.periodSpent + 700n).toString()
  });

  // the covenant's own successor root: fold(newLeaf) up the OLD co-path
  const folded = foldAgentPolicyV4(newPolicy, proof.siblingsHex, proof.pathBits);
  assert.equal(after.root, folded, "SDK successor tree must equal the consensus single-leaf fold");
  assert.notEqual(after.root, tree.root);

  // unrelated leaves byte-identical; padding untouched
  const afterLeaves = after.agents.map((a) => agentLeafHash(a).toString("hex"));
  for (let i = 0; i < before.length; i++) {
    if (after.agents[i].agentPk === target.agentPk) {
      assert.notEqual(afterLeaves[i], before[i], "the target leaf must change");
      assert.equal(previousPolicy.periodSpent + 700n, newPolicy.periodSpent);
    } else {
      assert.equal(afterLeaves[i], before[i], `unrelated leaf ${i} must be preserved`);
    }
  }
  for (let i = after.realCount; i < after.leafCount; i++) {
    assert.equal(after.levels[0][i].toString("hex"), PADDING_LEAF_HEX, "padding slots must remain the unspendable constant");
  }

  // stale proof: the pre-update proof no longer verifies against the new root
  assert.equal(
    verifyAgentProofV4({ root: after.root, policy: target, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }),
    false,
    "stale pre-update membership must fail against the successor root"
  );
});

test("E1: add / remove / update / rotate are canonical rebuilds", () => {
  const tree = buildAgentTreeV4([policy(1), policy(2)]);

  const added = addAgentV4(tree, policy(3));
  assert.equal(added.realCount, 3);
  assert.equal(added.root, buildAgentTreeV4([policy(3), policy(1), policy(2)]).root, "insertion order free");
  assert.throws(() => addAgentV4(tree, policy(1)), /already exists/);

  const removed = removeAgentV4(added, PK(2));
  assert.equal(removed.realCount, 2);
  assert.equal(removed.root, buildAgentTreeV4([policy(1), policy(3)]).root);
  assert.throws(() => removeAgentV4(removed, PK(2)), /nothing to remove/);

  const repoliced = updateAgentPolicyV4(tree, policy(2, { maxPerSpend: "123" }));
  assert.equal(repoliced.root, buildAgentTreeV4([policy(1), policy(2, { maxPerSpend: "123" })]).root);
  assert.throws(() => updateAgentPolicyV4(tree, policy(9)), /not in this tree/);

  const rotated = rotateAgentV4(tree, PK(2), policy(7));
  assert.equal(rotated.root, buildAgentTreeV4([policy(1), policy(7)]).root);
  assert.throws(() => rotateAgentV4(tree, PK(2), policy(2, { maxPerSpend: "5" })), /NEW agent key/);
  assert.throws(() => rotateAgentV4(tree, PK(9), policy(8)), /cannot rotate/);

  // per-agent pause = remove the leaf (policy/root modification, no new consensus field)
  const pausedOne = removeAgentV4(tree, PK(1));
  assert.throws(() => generateAgentProofV4(pausedOne, PK(1)), /not in this tree/);
});
