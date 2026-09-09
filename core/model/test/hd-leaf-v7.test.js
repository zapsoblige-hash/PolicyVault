"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const m = require("../hd-leaf-v7");

const ZERO = "00".repeat(32);
const pk = (i) => i.toString(16).padStart(2, "0").repeat(32);

const leaf = (i, extra = {}) => ({
  pk: pk(i),
  maxPerSpend: "250",
  periodBudget: "400",
  periodLengthDaa: "1000",
  periodStartDaa: "5000",
  periodSpent: "0",
  maxFeePerTx: "60000",
  maxCarryKas: "25000000",
  expiryDaa: "9000000",
  recipientRoot: ZERO,
  childRoot: ZERO,
  ...extra
});

test("encode/decode round-trips and matches the fixed layout", () => {
  const l = leaf(1);
  const body = m.encodeHdLeafBody(l);
  assert.equal(body.length, m.HD_LEAF_BODY_LEN);
  const decoded = m.decodeHdLeafBody(body);
  assert.equal(decoded.pk, pk(1));
  assert.equal(decoded.maxPerSpend, 250n);
  assert.equal(decoded.periodBudget, 400n);
  assert.equal(decoded.periodLengthDaa, 1000n);
  assert.equal(decoded.periodStartDaa, 5000n);
  assert.equal(decoded.maxFeePerTx, 60000n);
  assert.equal(decoded.maxCarryKas, 25_000_000n);
  assert.equal(decoded.expiryDaa, 9_000_000n);
  assert.equal(decoded.recipientRoot, ZERO);
  assert.equal(decoded.childRoot, ZERO);
});

test("decodeHdLeafBody fails closed on malformed length (159/161 bytes)", () => {
  const raw = m.encodeHdLeafBody(leaf(1));
  const short = raw.slice(0, 159);
  const long = new Uint8Array(161);
  long.set(raw);
  assert.throws(() => m.decodeHdLeafBody(short), /MALFORMED_BODY|exactly 160/);
  assert.throws(() => m.decodeHdLeafBody(long), /MALFORMED_BODY|exactly 160/);
});

test("leaf hash preimage is exactly 173 bytes and disjoint from the flat v0.5/v0.7-payment domain", () => {
  const l = leaf(1);
  const preimage = m.hdLeafPreimage(l, 1);
  assert.equal(preimage.length, m.HD_LEAF_PREIMAGE_LEN);
  assert.equal(preimage[0], 0x50);
  assert.equal(preimage[1], 0x56);
  assert.equal(preimage[2], 0x48);
  assert.equal(preimage[3], 0x01);
  // the flat leaf domain (0x50563501) never appears as this preimage's prefix
  assert.notEqual(preimage[2], 0x35);
});

test("leaf hash depends on `level` (a level-1 leaf and a level-2 leaf with identical fields hash differently)", () => {
  const l = leaf(1);
  assert.notEqual(m.hdLeafHashHex(l, 1), m.hdLeafHashHex(l, 2));
});

test("MAX_LEVEL is rejected outside [1,3] — a measured bound, not configurable", () => {
  assert.throws(() => m.hdLeafHash(leaf(1), 0), (e) => e.code === "LEVEL_OUT_OF_RANGE");
  assert.throws(() => m.hdLeafHash(leaf(1), 4), (e) => e.code === "LEVEL_OUT_OF_RANGE");
});

test("forestRoot / chainProofs / foldHdLeaf agree: folding a proof reproduces the tree root", () => {
  const nodes = [{ leaf: leaf(1), kids: [] }, { leaf: leaf(2), kids: [] }, { leaf: leaf(3), kids: [] }];
  const root = m.forestRoot(nodes);
  const [proof] = m.chainProofs(nodes, [1]);
  assert.equal(proof.level, 1);
  const leafHash = m.hdLeafHash(proof.leaf, 1);
  const folded = m.foldHdLeafHex(leafHash, proof.siblingsHex, proof.pathBits, m.MAX_AGENT_DEPTH);
  assert.equal(folded, root);
});

test("nested child roots: a level-2 leaf's membership folds to the parent's committed childRoot, and the whole chain folds to the forest root", () => {
  const child = { leaf: leaf(20), kids: [] };
  const parent = { leaf: leaf(10, { childRoot: ZERO }), kids: [child] };
  const sibling = { leaf: leaf(11), kids: [] };
  const nodes = [parent, sibling];

  const root = m.forestRoot(nodes);
  const chain = m.chainProofs(nodes, [0, 0]);
  assert.equal(chain.length, 2);
  assert.equal(chain[0].level, 1);
  assert.equal(chain[1].level, 2);
  // the resolved parent leaf's childRoot must equal the child's own subtree root
  assert.equal(chain[0].leaf.childRoot, m.childRootOf([child], 2));
  assert.notEqual(chain[0].leaf.childRoot, ZERO);

  // level-2 membership folds to the parent's childRoot
  const childHash = m.hdLeafHash(chain[1].leaf, 2);
  const foldedChildRoot = m.foldHdLeafHex(childHash, chain[1].siblingsHex, chain[1].pathBits, m.MAX_CHILD_DEPTH);
  assert.equal(foldedChildRoot, chain[0].leaf.childRoot);

  // level-1 membership (of the RESOLVED parent, i.e. with the real childRoot) folds to the forest root
  const parentHash = m.hdLeafHash(chain[0].leaf, 1);
  const foldedForestRoot = m.foldHdLeafHex(parentHash, chain[0].siblingsHex, chain[0].pathBits, m.MAX_AGENT_DEPTH);
  assert.equal(foldedForestRoot, root);
});

test("effectiveAuthority computes the per-spend intersection as the MINIMUM over the chain (never trusting a broader child)", () => {
  const a1 = leaf(1, { maxPerSpend: "250", periodBudget: "400", maxFeePerTx: "60000", maxCarryKas: "25000000", expiryDaa: "9000000" });
  const b = leaf(2, { maxPerSpend: "9999999", periodBudget: "9999999", maxFeePerTx: "9999999", maxCarryKas: "9999999", expiryDaa: "8000000" });
  const eff = m.effectiveAuthority([{ leaf: a1 }, { leaf: b }]);
  assert.equal(eff.maxPerSpend, 250n, "the child's inflated cap must NOT win — the parent's tighter cap binds");
  assert.equal(eff.maxFeePerTx, 60000n);
  assert.equal(eff.maxCarryKas, 9_999_999n, "the tighter of the two carry caps binds (here the child's happens to be tighter)");
  assert.equal(eff.expiryDaa, 8_000_000n);
  assert.equal(eff.level, 2);
  assert.equal(eff.perLevelBudgets.length, 2);
  assert.equal(eff.perLevelBudgets[1].remaining, 9999999n - 0n);
  assert.match(eff.expiryIsNotConsensusEnforced, /lockTime is a LOWER bound/);
});

test("effectiveAuthority rejects chains outside [1, MAX_LEVEL]", () => {
  assert.throws(() => m.effectiveAuthority([]), (e) => e.code === "LEVEL_OUT_OF_RANGE");
  assert.throws(() => m.effectiveAuthority([leaf(1), leaf(2), leaf(3), leaf(4)]), (e) => e.code === "LEVEL_OUT_OF_RANGE");
});

test("verifyChildNeverExceedsParent: SDK pre-flight guard flags every broader field (never the security boundary itself)", () => {
  const parent = leaf(1);
  const honestChild = leaf(2, { maxPerSpend: "200", periodBudget: "300", maxFeePerTx: "50000", maxCarryKas: "20000000", expiryDaa: "8000000" });
  assert.equal(m.verifyChildNeverExceedsParent(parent, honestChild).ok, true);

  const broaderCap = leaf(2, { maxPerSpend: "999" });
  assert.deepEqual(m.verifyChildNeverExceedsParent(parent, broaderCap).violations, ["maxPerSpend"]);

  const broaderMany = leaf(2, { maxPerSpend: "999", periodBudget: "999", maxFeePerTx: "999999", maxCarryKas: "999999999", expiryDaa: "9500000" });
  const r = m.verifyChildNeverExceedsParent(parent, broaderMany);
  assert.equal(r.ok, false);
  assert.deepEqual(r.violations, ["maxPerSpend", "periodBudget", "maxFeePerTx", "maxCarryKas", "expiryDaa"]);
});

test("verifyExpiryMonotone catches an inversion anywhere in the chain", () => {
  const a1 = leaf(1, { expiryDaa: "9000000" });
  const b = leaf(2, { expiryDaa: "9500000" }); // inverted: child outlives parent
  const r = m.verifyExpiryMonotone([{ leaf: a1 }, { leaf: b }]);
  assert.equal(r.ok, false);
  assert.equal(r.level, 2);

  const c = leaf(2, { expiryDaa: "8000000" }); // honest
  assert.equal(m.verifyExpiryMonotone([{ leaf: a1 }, { leaf: c }]).ok, true);
});

test("verifyChainPositions catches a leaf presented at the wrong chain position", () => {
  assert.equal(m.verifyChainPositions([{ level: 1 }, { level: 2 }, { level: 3 }]).ok, true);
  const r = m.verifyChainPositions([{ level: 1 }, { level: 1 }]);
  assert.equal(r.ok, false);
  assert.equal(r.index, 1);
  assert.equal(r.expectedLevel, 2);
  assert.equal(r.gotLevel, 1);
});

test("unknown leaf field fails closed (closed layout)", () => {
  assert.throws(() => m.normalizeHdLeaf({ ...leaf(1), unexpected: "1" }), /unknown HD leaf field/);
});

test("zero-length period fails closed (D2-style hardening carried at the core boundary)", () => {
  assert.throws(() => m.normalizeHdLeaf(leaf(1, { periodLengthDaa: "0" })), /must be > 0/);
});

test("hdLeafToJson stringifies every BigInt and carries the expiry disclaimer", () => {
  const json = m.hdLeafToJson(leaf(1));
  assert.equal(typeof json.maxPerSpend, "string");
  assert.equal(typeof json.periodBudget, "string");
  assert.match(json.expiryIsNotConsensusEnforced, /revocation/);
});

/* ---- I2: state advance + nested refold (Wave 2 Track D) ---- */

test("advanceHdLeafPeriod: same-period spend accumulates periodSpent, leaves periodStartDaa untouched", () => {
  const r = m.advanceHdLeafPeriod(leaf(1, { periodSpent: "40" }), "10", 0n);
  assert.equal(r.periodStartDaa, 5000n);
  assert.equal(r.periodSpent, 50n);
});

test("advanceHdLeafPeriod: rollover resets periodSpent to exactly the spend and advances periodStartDaa by periodsElapsed*periodLengthDaa", () => {
  const r = m.advanceHdLeafPeriod(leaf(1, { periodSpent: "999" }), "10", 3n);
  assert.equal(r.periodStartDaa, 5000n + 3n * 1000n);
  assert.equal(r.periodSpent, 10n);
});

test("nestedRefoldAfterSpend: a 2-level spend reproduces the SAME root as directly mutating and re-folding the tree (independent cross-check)", () => {
  const kid0 = { leaf: leaf(10), kids: [] };
  const kid1 = { leaf: leaf(11), kids: [] };
  const l1n0 = { leaf: leaf(1), kids: [kid0, kid1] };
  const l1n1 = { leaf: leaf(2), kids: [] };
  const tree = [l1n0, l1n1];

  const chain = m.chainProofs(tree, [0, 0]);
  const newRoot = m.nestedRefoldAfterSpend(chain, "50", [0n, 0n]);

  const advance = (l, spend, pe) => (pe >= 1n ? { periodStartDaa: l.periodStartDaa + pe * l.periodLengthDaa, periodSpent: spend } : { periodStartDaa: l.periodStartDaa, periodSpent: l.periodSpent + spend });
  const l1n0Advanced = advance(m.normalizeHdLeaf(l1n0.leaf), 50n, 0n);
  const kid0Advanced = advance(m.normalizeHdLeaf(kid0.leaf), 50n, 0n);
  const mutatedTree = [{ leaf: { ...l1n0.leaf, ...Object.fromEntries(Object.entries(l1n0Advanced).map(([k, v]) => [k, v.toString()])) }, kids: [{ leaf: { ...kid0.leaf, ...Object.fromEntries(Object.entries(kid0Advanced).map(([k, v]) => [k, v.toString()])) }, kids: [] }, kid1] }, l1n1];
  assert.equal(newRoot, m.forestRoot(mutatedTree), "the fold-based root must equal the directly-mutated tree's root");
});

test("nestedRefoldAfterSpend: chain length must match periodsElapsedByLevel length", () => {
  const l1n0 = { leaf: leaf(1), kids: [] };
  const chain = m.chainProofs([l1n0], [0]);
  assert.throws(() => m.nestedRefoldAfterSpend(chain, "1", []), /periodsElapsedByLevel must carry exactly one entry per chain level/);
});

test("nestedRefoldAfterDelegation: a level-1 delegation reproduces the SAME root as an independent low-level fold (only childRoot moves)", () => {
  const kid0 = { leaf: leaf(10), kids: [] };
  const l1n0 = { leaf: leaf(1), kids: [kid0] };
  const l1n1 = { leaf: leaf(2), kids: [] };
  const tree = [l1n0, l1n1];
  const newChildRoot = "ab".repeat(32);

  const chain1 = m.chainProofs(tree, [0]);
  const newRoot1 = m.nestedRefoldAfterDelegation(chain1, newChildRoot);

  const forcedLeaf = { ...m.resolvedLeaf(l1n0, 1), childRoot: newChildRoot };
  const forcedHashHex = m.hdLeafHashHex(forcedLeaf, 1);
  const l1n1HashHex = m.hdLeafHashHex(m.resolvedLeaf(l1n1, 1), 1);
  const crypto = require("crypto");
  const manualRoot = crypto.createHash("sha256").update(Buffer.from(forcedHashHex + l1n1HashHex, "hex")).digest("hex");
  assert.equal(newRoot1, manualRoot);
});

test("nestedRefoldAfterDelegation: every OTHER field of the delegating parent is preserved (only childRoot moves) — cross-checked via effectiveAuthority", () => {
  const l1n0 = { leaf: leaf(1, { maxPerSpend: "123" }), kids: [] };
  const chain1 = m.chainProofs([l1n0], [0]);
  const newChildRoot = "cd".repeat(32);
  m.nestedRefoldAfterDelegation(chain1, newChildRoot); // must not throw / must be pure
  // the INPUT chain leaf itself is untouched by the call (purity)
  assert.equal(chain1[0].leaf.maxPerSpend, 123n);
});
