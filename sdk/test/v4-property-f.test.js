"use strict";

/* SDK — Checkpoint F property/fuzz tests (§F12) + input-surface review
 * (§F16) for the highest-risk PURE v0.4 components: the agent tree, state
 * normalization/serialization, transition derivation, and the approval
 * package commitment. Deterministic seeds only — every failure is
 * reproducible. Offline. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

const {
  buildAgentTreeV4,
  generateAgentProofV4,
  verifyAgentProofV4,
  agentLeafHash,
  PADDING_LEAF_HEX,
  normalizeAgentPolicyV4,
  MAX_AGENTS
} = require("../src/agent-merkle-v4");
const { normalizeStateV4, stateToJsonV4 } = require("../src/vault-state-v4");
const { parseSompi } = require("../src/amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("../src/vault-state");

/* Deterministic PRNG (mulberry32) — reproducible fuzzing. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const PK = (v) => v.toString(16).padStart(2, "0").repeat(32);
function randPolicy(r, id) {
  const big = () => BigInt(1 + Math.floor(r() * 1e12)).toString();
  return {
    agentPk: PK(id),
    maxPerSpend: big(),
    periodBudget: big(),
    periodLengthDaa: big(),
    periodStartDaa: BigInt(Math.floor(r() * 1e9)).toString(),
    periodSpent: BigInt(Math.floor(r() * 1e9)).toString(),
    approvalThreshold: big(),
    agentMaxFeePerTx: big(),
    agentRecipientRoot: crypto.createHash("sha256").update(`r${id}`).digest("hex")
  };
}

test("F12 property: same logical agent set in any insertion order yields the same root (200 seeds)", () => {
  for (let seed = 1; seed <= 200; seed++) {
    const r = rng(seed);
    const n = 1 + Math.floor(r() * 12);
    const ids = [];
    while (ids.length < n) {
      const id = 1 + Math.floor(r() * 200);
      if (!ids.includes(id)) ids.push(id);
    }
    const agents = ids.map((id) => randPolicy(r, id));
    const root = buildAgentTreeV4(agents).root;
    // shuffle
    const shuffled = agents.slice();
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(r() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    assert.equal(buildAgentTreeV4(shuffled).root, root, `seed ${seed}: order-independent root`);
  }
});

test("F12 property: proof verifies iff the agent is an actual member; padding is never a member (150 seeds)", () => {
  for (let seed = 1; seed <= 150; seed++) {
    const r = rng(seed + 1000);
    const n = 1 + Math.floor(r() * 10);
    const ids = [];
    while (ids.length < n) {
      const id = 1 + Math.floor(r() * 200);
      if (!ids.includes(id)) ids.push(id);
    }
    const agents = ids.map((id) => randPolicy(r, id));
    const tree = buildAgentTreeV4(agents);
    for (const a of tree.agents) {
      const proof = generateAgentProofV4(tree, a.agentPk);
      assert.ok(verifyAgentProofV4({ root: tree.root, policy: a, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }));
    }
    // a non-member key cannot get a proof (keep ids < 256 so PK() is valid hex)
    let nonMember = 201 + Math.floor(r() * 54);
    while (ids.includes(nonMember)) nonMember++;
    assert.throws(() => generateAgentProofV4(tree, PK(nonMember)), /not in this tree/);
    // padding leaf appears in the leaf level whenever n is not a power of two,
    // but is never returned as an agent
    const isPow2 = (tree.leafCount & (tree.leafCount - 1)) === 0 && tree.leafCount === tree.realCount;
    if (!isPow2) {
      assert.ok(tree.levels[0].some((l) => l.toString("hex") === PADDING_LEAF_HEX), `seed ${seed}: padding present`);
    }
    assert.ok(!tree.agents.some((a) => agentLeafHash(a).toString("hex") === PADDING_LEAF_HEX), "no agent leaf equals padding");
  }
});

test("F12 property: replacing one leaf changes only its authenticated path; unrelated leaves stay members (120 seeds)", () => {
  for (let seed = 1; seed <= 120; seed++) {
    const r = rng(seed + 2000);
    const n = 2 + Math.floor(r() * 10);
    const ids = [];
    while (ids.length < n) {
      const id = 1 + Math.floor(r() * 200);
      if (!ids.includes(id)) ids.push(id);
    }
    const agents = ids.map((id) => randPolicy(r, id));
    const tree = buildAgentTreeV4(agents);
    const targetIdx = Math.floor(r() * tree.realCount);
    const targetPk = tree.agents[targetIdx].agentPk;
    const updated = tree.agents.map((a) => (a.agentPk === targetPk ? { ...a, periodSpent: (BigInt(a.periodSpent) + 1n).toString() } : a));
    const tree2 = buildAgentTreeV4(updated);
    assert.notEqual(tree2.root, tree.root);
    // every OTHER agent still verifies under the new root with a fresh proof,
    // and its leaf bytes are unchanged
    for (const a of tree.agents) {
      if (a.agentPk === targetPk) continue;
      const before = agentLeafHash(a).toString("hex");
      const a2 = tree2.agents.find((x) => x.agentPk === a.agentPk);
      assert.equal(agentLeafHash(a2).toString("hex"), before, "unrelated leaf bytes preserved");
      const p2 = generateAgentProofV4(tree2, a.agentPk);
      assert.ok(verifyAgentProofV4({ root: tree2.root, policy: a2, siblingsHex: p2.siblingsHex, pathBits: p2.pathBits }));
    }
  }
});

test("F12 property: no duplicate-key set normalizes; distinct keys always do (100 seeds)", () => {
  for (let seed = 1; seed <= 100; seed++) {
    const r = rng(seed + 3000);
    const id = 1 + Math.floor(r() * 200);
    const p = randPolicy(r, id);
    assert.throws(() => buildAgentTreeV4([p, { ...randPolicy(r, id + 1), agentPk: p.agentPk }]), /duplicate agentPk/);
    // distinct keys OK
    assert.doesNotThrow(() => buildAgentTreeV4([p, randPolicy(r, id === 200 ? id - 1 : id + 1)]));
  }
});

test("F12 property: state serialize -> parse -> serialize is byte-identical (150 seeds)", () => {
  for (let seed = 1; seed <= 150; seed++) {
    const r = rng(seed + 4000);
    const activeCount = Math.floor(r() * 11); // 0..10
    const slots = [];
    const used = new Set();
    for (let i = 0; i < activeCount; i++) {
      let id = 1 + Math.floor(r() * 250);
      while (used.has(id)) id++;
      used.add(id);
      slots.push(PK(id));
    }
    while (slots.length < 10) slots.push("00".repeat(32));
    const json = {
      protectedValue: BigInt(1 + Math.floor(r() * 1e12)).toString(),
      feeReserve: BigInt(Math.floor(r() * 1e10)).toString(),
      paused: r() < 0.5 ? "0" : "1",
      agentRoot: crypto.createHash("sha256").update(`s${seed}`).digest("hex"),
      approverSlots: slots,
      approvalM: activeCount === 0 ? "0" : String(1 + Math.floor(r() * activeCount)),
      policyNonce: BigInt(Math.floor(r() * 1e9)).toString()
    };
    const once = stateToJsonV4(normalizeStateV4(json));
    const twice = stateToJsonV4(normalizeStateV4(once));
    assert.deepEqual(twice, once, `seed ${seed}: idempotent state round-trip`);
  }
});

test("F12 property: leaf preimage is injective over field tuples (fuzz 300)", () => {
  const seen = new Map();
  for (let seed = 1; seed <= 300; seed++) {
    const r = rng(seed + 5000);
    const p = normalizeAgentPolicyV4(randPolicy(r, 1 + (seed % 200)));
    const h = agentLeafHash(p).toString("hex");
    const key = JSON.stringify([p.agentPk, p.maxPerSpend.toString(), p.periodBudget.toString(), p.periodLengthDaa.toString(), p.periodStartDaa.toString(), p.periodSpent.toString(), p.approvalThreshold.toString(), p.agentMaxFeePerTx.toString(), p.agentRecipientRoot]);
    if (seen.has(h)) {
      assert.equal(seen.get(h), key, `hash collision for distinct field tuples at seed ${seed}`);
    }
    seen.set(h, key);
  }
});

/* ---------------------------------------------------------- F16 input surface */

test("F16: numeric parsing fails closed on Number, negatives, over-range; accepts BigInt/decimal-string", () => {
  assert.throws(() => parseSompi(42), /BigInt or decimal string/); // no Number (float risk)
  assert.throws(() => parseSompi(-1n), /negative/);
  assert.throws(() => parseSompi("-1"), /base-10 digit string/);
  assert.throws(() => parseSompi("1.5"), /base-10 digit string/);
  assert.throws(() => parseSompi("0x10"), /base-10 digit string/);
  assert.throws(() => parseSompi(" 10"), /base-10 digit string/);
  assert.throws(() => parseSompi("100000000000000000000000000000"), /maximum representable sompi/); // > MAX_SOMPI
  // boundary values that MUST parse
  assert.equal(parseSompi(String(2n ** 32n)), 2n ** 32n);
  assert.equal(parseSompi(String(2n ** 53n + 1n)), 2n ** 53n + 1n); // beyond Number.MAX_SAFE_INTEGER
  assert.equal(parseSompi(0n), 0n);
});

test("F16: hex normalization CANONICALIZES casing/whitespace (bijection, collision-free) and rejects 0x/odd/width", () => {
  const good = "ab".repeat(32);
  assert.equal(normalizeHex(good, 32, "x"), good);
  // uppercase and surrounding whitespace canonicalize to the SAME lowercase
  // value — safe (a bijection on valid hex; no two distinct byte strings map
  // together), so identity is preserved rather than rejected.
  assert.equal(normalizeHex(good.toUpperCase(), 32, "x"), good);
  assert.equal(normalizeHex("  " + good + "  ", 32, "x"), good);
  assert.equal(normalizeHex("AbAb".repeat(16), 32, "x"), good);
  // structurally invalid inputs still fail closed
  assert.throws(() => normalizeHex("0x" + good, 32, "x"), /.*/); // 0x prefix -> non-hex char
  assert.throws(() => normalizeHex("ab".repeat(31), 32, "x"), /.*/); // wrong width
  assert.throws(() => normalizeHex("abc", 32, "x"), /.*/); // odd length / short
  assert.throws(() => normalizeHex("gg".repeat(32), 32, "x"), /.*/); // non-hex
});

test("F16: x-only pubkey normalization rejects compressed keys, sentinel-length confusion, non-hex", () => {
  const xonly = "cd".repeat(32); // 32 bytes
  assert.equal(normalizeXOnlyPubkey(xonly, "k"), xonly);
  // 33-byte compressed pubkey (02/03 prefix) must be rejected as an x-only key
  assert.throws(() => normalizeXOnlyPubkey("02" + xonly, "k"), /.*/);
  assert.throws(() => normalizeXOnlyPubkey("03" + "cd".repeat(32), "k"), /.*/);
  assert.throws(() => normalizeXOnlyPubkey("zz".repeat(32), "k"), /.*/);
  // all-zero is a valid 32-byte value structurally (the covenant treats it as
  // the approver sentinel); it must at least parse as 32-byte hex
  assert.equal(normalizeXOnlyPubkey("00".repeat(32), "k"), "00".repeat(32));
});

test("F16: agent policy normalization rejects out-of-range and Number inputs", () => {
  const base = randPolicy(rng(1), 5);
  assert.throws(() => normalizeAgentPolicyV4({ ...base, maxPerSpend: 100 }), /BigInt or decimal string/);
  assert.throws(() => normalizeAgentPolicyV4({ ...base, maxPerSpend: "0" }), /greater than zero/);
  assert.throws(() => normalizeAgentPolicyV4({ ...base, periodSpent: "-5" }), /.*/);
  assert.throws(() => normalizeAgentPolicyV4({ ...base, agentRecipientRoot: "ab".repeat(31) }), /.*/);
  // MAX_AGENTS is exactly the depth-12 capacity
  assert.equal(MAX_AGENTS, 4096);
});
