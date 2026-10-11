"use strict";
/*
 * RC45 R2-01 — the delegate period-start rule core: the exact vectors the
 * rule's helpers must satisfy, fixed BEFORE the helpers exist. Internal
 * RED-first regression material; not an audit.
 *
 * The rule (for a v0.4.1 / v0.7-kas agent registry N built against its
 * root-verified predecessor P; empty P for a creation):
 *   - committed leaf fields: agentPk, maxPerSpend, periodBudget,
 *     periodLengthDaa, periodStartDaa, periodSpent, approvalThreshold,
 *     agentMaxFeePerTx, agentRecipientRoot;
 *   - a leaf of N whose agentPk is in P and whose nine committed fields equal
 *     that predecessor leaf is CARRIED (committed unchanged, no node read);
 *     every other leaf is ANCHORED;
 *   - anchor at build: an ANCHORED leaf commits
 *     periodStartDaa = max(requested, D) with D the configured synced node's
 *     canonical virtual DAA score (unreadable or non-canonical: refuse
 *     PERIOD_START_REQUIRED); every other field exactly as requested; the
 *     agent root is recomputed from the committed leaves; no ANCHORED leaf
 *     means no node read;
 *   - freshness before the point of no return: refuse PERIOD_START_STALE when
 *     an ANCHORED leaf has D - periodStartDaa > W(periodLengthDaa), with
 *     W(L) = max(L - 6,000, 600) DAA (a 10-minute acceptance margin, a
 *     1-minute floor);
 *   - registry-to-root integrity: a checked registry must be an array whose
 *     fold normalizeRegistry(entries).tree.root equals the agent root about
 *     to be committed, else REGISTRY_ROOT_MISMATCH (never the non-array-as-
 *     empty default of normalizeRegistry).
 *
 * WHY THIS FILE HOLDS ON b89f0f7 AND CLAIMS NO RED: the helpers that carry
 * the rule (sdk/src/manifest-v4.js and sdk/src/chain.js additions) are new
 * API, so a leg calling them would fail on a missing export, which is never
 * RED. The rule's behaviour is pinned RED through the real builders and
 * check points (rc45-r2-02-v4-anchor.test.js, rc45-r2-03-v4-commit-
 * freshness.test.js). This file fixes, ahead of the implementation:
 *   1. the vector tables (VECTORS below) the helpers must reproduce — the
 *      implementation adds the legs that run the runtime helpers over these
 *      same tables, unchanged;
 *   2. a test-local REFERENCE MODEL of the rule built only from existing
 *      runtime primitives (normalizeRegistry, the R1-05 canonical DAA parser)
 *      and its agreement with every vector;
 *   3. the vectors' sabotage sensitivity: each listed mutation of the rule
 *      (max -> min, unconditional replace, agentPk-only carry, a BigInt()
 *      DAA read, the margin set to 0, the floor removed, a non-array
 *      registry folded as empty) disagrees with the reference on at least
 *      one vector, so a helper carrying that mutation cannot pass the
 *      implementation's legs;
 *   4. the spend-capacity property behind the rule (>= 10,000 seeded random
 *      tuples): moving a start later with the spent amount unchanged never
 *      grants more at any consensus time, and an anchored leaf has exactly
 *      one budget at the build;
 *   5. the W(L) and immediately-spendable vectors that the web suites copy
 *      inline (no vector file is added under web/).
 *
 * ADDED WITH THE IMPLEMENTATION (the "runtime" legs at the end of this file;
 * they need the new exports, so they hold from the implementation on, not on
 * b89f0f7): the exported runtime helpers of sdk/src/manifest-v4.js and
 * sdk/src/chain.js run over every row of the same VECTORS tables, unchanged,
 * and must agree with the reference model, which stays the oracle. The node
 * read is the REAL chain.readAnchorDaa body over a TEST node client (the R2
 * kit's useNodeClient replaces the rusty-kaspa client constructor; no seam
 * replaces readAnchorDaa here). The immediately-spendable table has no
 * runtime helper in this item (the web review lines copy it).
 *
 * Layers: UNIT / PROPERTY. Pure; no store, no key, and no node is dialed (the
 * runtime read runs over a TEST node client on ws://127.0.0.1:1). BigInt only.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const chain = require("../src/chain");
const { normalizeRegistry } = require("../src/manifest-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");

/* ---------------- constants of the rule ---------------- */
const ACCEPT_MARGIN_DAA = 6000n; // 10 minutes at 10 DAA per second
const MIN_WINDOW_DAA = 600n; // 1 minute
const DAA_PER_SECOND = 10n;
const NINE = Object.freeze(["agentPk", "maxPerSpend", "periodBudget", "periodLengthDaa", "periodStartDaa", "periodSpent", "approvalThreshold", "agentMaxFeePerTx", "agentRecipientRoot"]);
const KAS = 100000000n;
const D = 545000000n; // a realistic build-time DAA score
const DAY = 864000n, HOUR = 36000n;

/* ---------------- deterministic TEST keys (x-only only; nothing signs) ---------------- */
const kaspa = require(require("../src/config").loadConfig({ dataRoot: require("node:os").tmpdir() }).rustyKaspaModule);
/* A valid x-only key: the x coordinate of k*G for a TEST scalar k. */
const xonly = (tag) => new kaspa.PrivateKey(crypto.createHash("sha256").update(`rc45-r2-01-${tag}`).digest("hex")).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const PK = Object.freeze({ a: xonly("agent-a"), b: xonly("agent-b"), c: xonly("agent-c"), r1: xonly("recipient-1"), r2: xonly("recipient-2") });

function leaf(agentPk, over = {}) {
  const recipients = over.recipients ?? [PK.r1];
  const e = {
    agentPk, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: DAY.toString(),
    periodStartDaa: (D - 5n * DAY).toString(), periodSpent: (3n * KAS).toString(), approvalThreshold: (5n * KAS).toString(),
    agentMaxFeePerTx: KAS.toString(), ...over, recipients
  };
  e.agentRecipientRoot = buildRecipientTree(e.recipients).root;
  return Object.freeze(e);
}
const P = Object.freeze([leaf(PK.a), leaf(PK.b, { periodStartDaa: (D - 1000n).toString(), periodSpent: "0" })]);

/* ---------------- the reference model (test-local; existing primitives only) ---------------- */
function refusal(code, message) { return Object.assign(new Error(message), { code }); }
const max = (x, y) => (x > y ? x : y), min = (x, y) => (x < y ? x : y);
function makeModel(mut = {}) {
  const margin = mut.marginZero ? 0n : ACCEPT_MARGIN_DAA;
  const windowDaa = (L) => (mut.noFloor ? L - margin : max(L - margin, MIN_WINDOW_DAA));
  const readDaa = (raw) => {
    if (mut.bigintRead) { try { return BigInt(raw); } catch { throw refusal("PERIOD_START_REQUIRED", "the node DAA could not be read"); } }
    const v = chain.canonicalDaaScore(raw);
    if (v === null) throw refusal("PERIOD_START_REQUIRED", "the node DAA is not canonical");
    return v;
  };
  const carried = (p, n) => (mut.pkOnlyCarry ? Boolean(p) : Boolean(p) && NINE.every((f) => String(p[f]) === String(n[f])));
  const anchoredPks = (prev, next) => next.filter((n) => !carried(prev.find((p) => p.agentPk === n.agentPk), n)).map((n) => n.agentPk);
  const fold = (entries) => {
    if (!Array.isArray(entries) && !mut.nonArrayEmpty) throw refusal("REGISTRY_ROOT_MISMATCH", "the registry is not an array");
    return normalizeRegistry(entries).tree.root;
  };
  const anchorStart = (requested, d) => (mut.minAnchor ? min(requested, d) : mut.replaceAnchor ? d : max(requested, d));
  return {
    windowDaa, readDaa, anchoredPks, fold,
    /* anchor at build: rawDaa is read only when some leaf is ANCHORED */
    anchor(prev, next, rawDaa) {
      const pks = new Set(anchoredPks(prev, next));
      if (pks.size === 0) return { entries: next.map((n) => ({ ...n })), anchoredAgentPks: [], root: fold(next) };
      const d = readDaa(typeof rawDaa === "function" ? rawDaa() : rawDaa);
      const entries = next.map((n) => (pks.has(n.agentPk) ? { ...n, periodStartDaa: anchorStart(BigInt(n.periodStartDaa), d).toString() } : { ...n }));
      return { entries, anchoredAgentPks: [...pks], root: fold(entries) };
    },
    /* freshness: the first stale ANCHORED leaf, or null */
    stale(prev, next, d) {
      for (const pk of anchoredPks(prev, next)) {
        const n = next.find((e) => e.agentPk === pk);
        if (d - BigInt(n.periodStartDaa) > windowDaa(BigInt(n.periodLengthDaa))) return pk;
      }
      return null;
    },
    integrity(entries, committedAgentRoot) {
      const root = fold(entries);
      if (root.toLowerCase() !== String(committedAgentRoot).toLowerCase()) throw refusal("REGISTRY_ROOT_MISMATCH", "the registry does not fold to the committed root");
      return root;
    }
  };
}
const REF = makeModel();
const outcome = (fn) => { try { return { ok: fn() }; } catch (e) { return { code: e.code ?? "THROW" }; } };

/* Spend capacity of one leaf at consensus time T (budget B, length L, spent sigma, start S). */
function pay({ S, B, L, sigma }, T) { return S < T ? ((T - 1n - S) / L + 1n) * B - sigma : B - sigma; }
function immediatelySpendable(S, sigma, B, L, D0) { const v = S >= D0 ? B - sigma : ((D0 - 1n - S) / L + 1n) * B - sigma; return v > 0n ? v : 0n; }

/* ---------------- THE VECTORS ---------------- */
const changedField = (f) => {
  const a = P[0];
  switch (f) {
    case "agentPk": { const { agentPk, ...rest } = a; void agentPk; return leaf(PK.c, rest); }
    case "agentRecipientRoot": return leaf(PK.a, { ...a, recipients: [PK.r1, PK.r2] });
    case "periodStartDaa": return leaf(PK.a, { ...a, periodStartDaa: (BigInt(a.periodStartDaa) + 1n).toString() });
    case "periodLengthDaa": return leaf(PK.a, { ...a, periodLengthDaa: HOUR.toString() });
    default: return leaf(PK.a, { ...a, [f]: (BigInt(a[f]) + 1n).toString() });
  }
};
const VECTORS = Object.freeze({
  /* W(L): [L, W, minutes] */
  window: Object.freeze([
    [HOUR, 30000n, 50n], [6n * HOUR, 210000n, 350n], [DAY, 858000n, 1430n], [7n * DAY, 6042000n, 10070n],
    [6600n, 600n, 1n], [6601n, 601n, null], [600n, 600n, 1n], [1n, 600n, 1n]
  ]),
  /* freshness: [label, S, L, D, stale?] */
  fresh: Object.freeze([
    ["1 h at W", D, HOUR, D + 30000n, false], ["1 h at W + 1", D, HOUR, D + 30001n, true],
    ["6 h at W", D, 6n * HOUR, D + 210000n, false], ["6 h at W + 1", D, 6n * HOUR, D + 210001n, true],
    ["1 d at W", D, DAY, D + 858000n, false], ["1 d at W + 1", D, DAY, D + 858001n, true],
    ["1 w at W", D, 7n * DAY, D + 6042000n, false], ["1 w at W + 1", D, 7n * DAY, D + 6042001n, true],
    ["6,600 at the floor", D, 6600n, D + 600n, false], ["6,600 past the floor", D, 6600n, D + 601n, true],
    ["1,200 at the floor", D, 1200n, D + 600n, false], ["1,200 past the floor", D, 1200n, D + 601n, true],
    ["600 at the floor", D, 600n, D + 600n, false], ["600 past the floor", D, 600n, D + 601n, true],
    ["1 at the floor", D, 1n, D + 600n, false], ["1 past the floor", D, 1n, D + 601n, true],
    ["checked at the build", D, 600n, D, false], ["a future start", D + 5000n, HOUR, D, false],
    ["an earlier start 0 (built without the anchor)", 0n, DAY, D, true], ["a lagging start D - 5L", D - 5n * DAY, DAY, D, true]
  ]),
  /* canonical node DAA: [label, raw, BigInt or null] */
  daa: Object.freeze([
    ["bigint", 545000000n, 545000000n], ["safe integer", 545000000, 545000000n], ["digit string", "545000000", 545000000n], ["zero string", "0", 0n],
    ["hex string", "0x10", null], ["signed string", "-1", null], ["fractional string", "1.5", null], ["empty string", "", null],
    ["padded string", " 545000000", null], ["plus-signed string", "+545000000", null], ["undefined", undefined, null], ["null", null, null],
    ["object", { virtualDaaScore: "545000000" }, null], ["negative integer", -1, null], ["unsafe integer", 2 ** 53, null], ["negative bigint", -1n, null],
    ["boolean", true, null], ["array", [545000000], null], ["fractional number", 1.5, null]
  ]),
  /* anchor at build: [label, prev, next, raw DAA (a function = a read that throws), expected starts by agentPk | refusal code, anchored pks] */
  anchor: Object.freeze([
    ["every leaf carried: no read, nothing changes", P, P, () => { throw refusal("PERIOD_START_REQUIRED", "a carried-only registry must not read the node"); }, Object.fromEntries(P.map((e) => [e.agentPk, e.periodStartDaa])), []],
    ["a new leaf with start 0 commits D; carried leaves unchanged", P, [...P, leaf(PK.c, { periodStartDaa: "0", periodSpent: "0" })], D.toString(), { [PK.a]: P[0].periodStartDaa, [PK.b]: P[1].periodStartDaa, [PK.c]: D.toString() }, [PK.c]],
    ["a new leaf with a stale start D - 3L commits D", P, [...P, leaf(PK.c, { periodStartDaa: (D - 3n * DAY).toString() })], D, { [PK.c]: D.toString() }, [PK.c]],
    ["a new leaf with a future start keeps it", P, [...P, leaf(PK.c, { periodStartDaa: (D + 5000n).toString() })], D, { [PK.c]: (D + 5000n).toString() }, [PK.c]],
    ["a new leaf whose start equals D keeps it", P, [...P, leaf(PK.c, { periodStartDaa: D.toString() })], D, { [PK.c]: D.toString() }, [PK.c]],
    ["a creation (empty predecessor) anchors every leaf", [], P, D, { [PK.a]: D.toString(), [PK.b]: D.toString() }, [PK.a, PK.b]],
    ...NINE.map((f) => {
      const changed = changedField(f);
      const want = f === "periodStartDaa" ? D.toString() : max(BigInt(changed.periodStartDaa), D).toString();
      return [`the predecessor leaf with ${f} changed is ANCHORED (start ${f === "agentPk" ? "of the new key" : "re-anchored"}), the other leaf carried`, P, [changed, P[1]], D, { [changed.agentPk]: want, [PK.b]: P[1].periodStartDaa }, [changed.agentPk]];
    }),
    ["an unreadable node refuses when a leaf is ANCHORED", P, [...P, leaf(PK.c, { periodStartDaa: "0" })], () => { throw refusal("PERIOD_START_REQUIRED", "node down"); }, "PERIOD_START_REQUIRED", null],
    ["a non-canonical node DAA (hex) refuses", P, [...P, leaf(PK.c, { periodStartDaa: "0" })], "0x207b9e40", "PERIOD_START_REQUIRED", null],
    ["a non-canonical node DAA (padded) refuses", P, [...P, leaf(PK.c, { periodStartDaa: "0" })], " 545000000", "PERIOD_START_REQUIRED", null]
  ]),
  /* registry-to-root integrity: [label, entries, committed root, ok?] */
  integrity: Object.freeze([
    ["the anchored registry and its own root", "anchored", "anchoredRoot", true],
    ["the anchored registry against the root of the un-anchored request", "anchored", "requestedRoot", false],
    ["the requested registry against the anchored root", "requested", "anchoredRoot", false],
    ["an empty array against the empty tree root", [], "emptyRoot", true],
    ["null against the empty tree root", null, "emptyRoot", false],
    ["undefined against the empty tree root", undefined, "emptyRoot", false],
    ["an object against the empty tree root", {}, "emptyRoot", false],
    ["a string against the empty tree root", "[]", "emptyRoot", false],
    ["the anchored registry against its root in upper case", "anchored", "anchoredRootUpper", true]
  ]),
  /* immediately spendable if confirmed now: [label, S, sigma, B, L, D, X] */
  immediate: Object.freeze([
    ["anchored at D: one budget minus spent", D, 3n * KAS, 50n * KAS, DAY, D, 47n * KAS],
    ["a future start: one budget", D + 5000n, 0n, 50n * KAS, DAY, D, 50n * KAS],
    ["one DAA into the period: one budget", D - 1n, 0n, 50n * KAS, DAY, D, 50n * KAS],
    ["exactly one period length behind: still one budget (a rollover needs S + L < T)", D - DAY, 0n, 50n * KAS, DAY, D, 50n * KAS],
    ["one period length and one DAA behind: two budgets", D - DAY - 1n, 0n, 50n * KAS, DAY, D, 100n * KAS],
    ["five period lengths behind with 3 KAS spent: five budgets", D - 5n * DAY, 3n * KAS, 50n * KAS, DAY, D, 247n * KAS],
    ["start 0 on a 1-day period at D", 0n, 0n, 50n * KAS, DAY, D, ((D - 1n) / DAY + 1n) * 50n * KAS],
    ["spent above one budget clamps to 0", D, 60n * KAS, 50n * KAS, DAY, D, 0n],
    ["a 600-DAA period 6,000 behind", D - 6000n, 0n, KAS, 600n, D, 10n * KAS]
  ])
});

/* ---------------- legs ---------------- */
test("RC45 R2-01: W(L) = max(L - 6,000, 600) DAA: 1 h -> 30,000 (50 min), 6 h -> 210,000, 1 d -> 858,000 (23 h 50 min), 1 w -> 6,042,000; every period of 6,600 DAA or less gets the 600-DAA floor", () => {
  for (const [L, W, minutes] of VECTORS.window) {
    assert.equal(REF.windowDaa(L), W, `W(${L})`);
    if (minutes !== null) assert.equal(W / DAA_PER_SECOND / 60n, minutes, `W(${L}) in minutes`);
  }
  assert.equal(ACCEPT_MARGIN_DAA / DAA_PER_SECOND, 600n, "the acceptance margin is 10 minutes");
});

test("RC45 R2-01: freshness boundary vectors: an ANCHORED leaf is fresh at exactly D - S = W(L) and stale at W(L) + 1 for 1 h, 6 h, 1 d, 1 w, 6,600, 1,200, 600 and 1; a start 0 or a lagging start built without the anchor is stale at a realistic D", () => {
  for (const [label, S, L, d, stale] of VECTORS.fresh) {
    const n = [leaf(PK.c, { periodStartDaa: S.toString(), periodLengthDaa: L.toString() })];
    assert.equal(REF.stale([], n, d) !== null, stale, label);
    assert.equal(REF.stale(n, n, d), null, `${label}: a CARRIED leaf is never checked`);
  }
});

test("RC45 R2-01: canonical node DAA vectors through the existing R1-05 parser: a non-negative bigint, safe integer or digit string is read; hex, signed, fractional, padded, empty, missing, null, object, unsafe, boolean and array values are refused (null), so they can never anchor", () => {
  for (const [label, raw, want] of VECTORS.daa) {
    assert.equal(chain.canonicalDaaScore(raw), want, label);
    const got = outcome(() => REF.readDaa(raw));
    if (want === null) assert.deepEqual(got, { code: "PERIOD_START_REQUIRED" }, `${label} refuses`);
    else assert.deepEqual(got, { ok: want }, `${label} reads`);
  }
});

test("RC45 R2-01: anchor-at-build vectors: CARRIED vs ANCHORED for each of the nine committed fields, max semantics (stale -> D, future kept, equal kept), entry order kept, the agent root recomputed from the committed leaves, no node read without an ANCHORED leaf, and an unreadable or non-canonical node DAA refuses", () => {
  for (const [label, prev, next, raw, want, pks] of VECTORS.anchor) {
    const got = outcome(() => REF.anchor(prev, next, raw));
    if (typeof want === "string") { assert.deepEqual(got, { code: want }, label); continue; }
    assert.ok(got.ok, `${label}: ${got.code ?? ""}`);
    assert.deepEqual(got.ok.anchoredAgentPks.slice().sort(), pks.slice().sort(), `${label}: the ANCHORED set`);
    assert.deepEqual(got.ok.entries.map((e) => e.agentPk), next.map((e) => e.agentPk), `${label}: entry order kept`);
    for (const [pk, start] of Object.entries(want)) assert.equal(got.ok.entries.find((e) => e.agentPk === pk).periodStartDaa, start, `${label}: start of ${pk.slice(0, 8)}`);
    got.ok.entries.forEach((e, i) => {
      for (const f of NINE.filter((x) => x !== "periodStartDaa")) assert.equal(String(e[f]), String(next[i][f]), `${label}: ${f} is committed exactly as requested`);
    });
    assert.equal(got.ok.root, normalizeRegistry(got.ok.entries).tree.root, `${label}: the root is the fold of the committed leaves`);
  }
});

test("RC45 R2-01: registry-to-root integrity vectors: the fold must equal the committed agent root (lower-case hex compare); a registry anchored without re-deriving its root refuses REGISTRY_ROOT_MISMATCH; null, undefined, an object and a string refuse (never treated as empty); an empty array against the empty tree's root passes", () => {
  const next = [...P, leaf(PK.c, { periodStartDaa: "0", periodSpent: "0" })];
  const anchored = REF.anchor(P, next, D).entries;
  const roots = { anchoredRoot: REF.fold(anchored), anchoredRootUpper: REF.fold(anchored).toUpperCase(), requestedRoot: REF.fold(next), emptyRoot: buildAgentTreeV4([]).root };
  assert.notEqual(roots.anchoredRoot, roots.requestedRoot, "anchoring a start changes the agent root");
  for (const [label, entries, rootName, ok] of VECTORS.integrity) {
    const e = entries === "anchored" ? anchored : entries === "requested" ? next : entries;
    assert.deepEqual(outcome(() => REF.integrity(e, roots[rootName])), ok ? { ok: normalizeRegistry(e).tree.root } : { code: "REGISTRY_ROOT_MISMATCH" }, label);
  }
});

test("RC45 R2-01: the fold primitives the integrity check builds on: normalizeRegistry(entries).tree.root equals the root the lifecycle planner derives (normalizeAgentPolicyV4 over agentRecipientRoot = buildRecipientTree(recipients).root, then buildAgentTreeV4); the fold is independent of entry order; normalizeRegistry folds a non-array as the EMPTY tree, which is exactly the default the integrity check must not use", () => {
  const next = [...P, leaf(PK.c, { periodStartDaa: D.toString() })];
  const planner = buildAgentTreeV4(next.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }))).root;
  assert.equal(normalizeRegistry(next).tree.root, planner);
  assert.equal(normalizeRegistry([...next].reverse()).tree.root, planner, "the agent tree sorts by agentPk");
  for (const nonArray of [null, undefined, {}, "[]"]) assert.equal(normalizeRegistry(nonArray).tree.root, buildAgentTreeV4([]).root, `normalizeRegistry(${JSON.stringify(nonArray)}) is the empty tree`);
});

test("RC45 R2-01: immediately-spendable vectors (the web review lines copy them inline): S >= D gives max(0, B - sigma); otherwise max(0, (floor((D - 1 - S) / L) + 1) * B - sigma), equal to the clamped spend capacity at T = D", () => {
  for (const [label, S, sigma, B, L, d, X] of VECTORS.immediate) {
    assert.equal(immediatelySpendable(S, sigma, B, L, d), X, label);
    const p = pay({ S, B, L, sigma }, d);
    assert.equal(X, p > 0n ? p : 0n, `${label}: equals the spend capacity at T = D`);
  }
});

test("RC45 R2-01: property (>= 10,000 seeded random tuples): Pay(max(S, D), T) <= Pay(S, T) at every sampled consensus time T; Pay(max(S, D), D) = B - sigma (no backlog at the build); a leaf fresh at the check (D - S <= W(L)) and accepted within the 6,000-DAA margin confirms with exactly B - sigma when L >= 6,600 and with at most floor(6,599 / L) extra budgets below that", () => {
  let counter = 0;
  const rand = (lo, hi) => { // inclusive, deterministic
    const h = crypto.createHash("sha256").update(`rc45-r2-01-property-${counter++}`).digest();
    return lo + (BigInt(`0x${h.toString("hex").slice(0, 24)}`) % (hi - lo + 1n));
  };
  const LENGTHS = [1n, 60n, 600n, 1200n, 6000n, 6599n, 6600n, 6601n, HOUR, 6n * HOUR, DAY, 7n * DAY];
  let tuples = 0, checks = 0;
  for (let i = 0; i < 10000; i++) {
    const L = i % 3 === 0 ? LENGTHS[Number(rand(0n, BigInt(LENGTHS.length - 1)))] : rand(1n, 8n * DAY);
    const B = rand(1n, 1000n * KAS), sigma = rand(0n, B), d = rand(1n, D);
    const S = rand(0n, 1n) === 0n ? rand(0n, d) : rand(d, d + 2n * L + 10n);
    const anchored = max(S, d);
    tuples += 1;
    for (let j = 0; j < 6; j++) {
      const T = j === 0 ? d : j === 1 ? d + 1n : rand(0n, d + 10n * L + 10000n);
      assert.ok(pay({ S: anchored, B, L, sigma }, T) <= pay({ S, B, L, sigma }, T), `tuple ${i}: Pay is non-increasing in the start (S=${S} D=${d} L=${L} T=${T})`);
      checks += 1;
    }
    assert.equal(pay({ S: anchored, B, L, sigma }, d), B - sigma, `tuple ${i}: an anchored leaf has exactly one budget at the build`);
    // freshness consequence: S' fresh at Dc, accepted at T in (Dc, Dc + margin]
    const Sf = rand(0n, D), Dc = Sf + rand(0n, REF.windowDaa(L)), T = Dc + rand(1n, ACCEPT_MARGIN_DAA);
    const got = pay({ S: Sf, B, L, sigma }, T);
    if (L >= 6600n) assert.equal(got, B - sigma, `tuple ${i}: no banked budget within the margin (L=${L})`);
    else assert.ok(got <= (6599n / L + 1n) * B - sigma, `tuple ${i}: at most floor(6,599 / L) extra budgets below 6,600 DAA (L=${L})`);
    checks += 2;
  }
  assert.ok(tuples >= 10000 && checks >= 60000, `${tuples} tuples, ${checks} checks`);
});

test("RC45 R2-01: the vectors are sabotage-sensitive: each mutation of the rule (anchor min instead of max; unconditional replace lowering a future start; carry decided on agentPk alone; a BigInt() node DAA read without the canonical check; the acceptance margin set to 0; the 600-DAA floor removed; a non-array registry folded as empty) disagrees with the reference model on at least one vector", () => {
  const MUTANTS = { minAnchor: "anchor min instead of max", replaceAnchor: "unconditional replace", pkOnlyCarry: "carry on agentPk alone", bigintRead: "BigInt() DAA read", marginZero: "margin 0", noFloor: "floor removed", nonArrayEmpty: "non-array folded as empty" };
  const evaluate = (model) => {
    const out = [];
    for (const [, L] of VECTORS.window) out.push(String(model.windowDaa(L)));
    for (const [, S, L, d] of VECTORS.fresh) { const n = [leaf(PK.c, { periodStartDaa: S.toString(), periodLengthDaa: L.toString() })]; out.push(String(model.stale([], n, d))); }
    for (const [, raw] of VECTORS.daa) out.push(JSON.stringify(outcome(() => String(model.readDaa(raw)))));
    for (const [, prev, next, raw] of VECTORS.anchor) out.push(JSON.stringify(outcome(() => { const r = model.anchor(prev, next, raw); return { e: r.entries.map((e) => e.periodStartDaa), pks: r.anchoredAgentPks.slice().sort(), root: r.root }; })));
    const next = [...P, leaf(PK.c, { periodStartDaa: "0" })], anchored = REF.anchor(P, next, D).entries, empty = buildAgentTreeV4([]).root;
    for (const [, entries, rootName] of VECTORS.integrity) {
      const e = entries === "anchored" ? anchored : entries === "requested" ? next : entries;
      const root = rootName === "anchoredRoot" ? REF.fold(anchored) : rootName === "anchoredRootUpper" ? REF.fold(anchored).toUpperCase() : rootName === "requestedRoot" ? REF.fold(next) : empty;
      out.push(JSON.stringify(outcome(() => model.integrity(e, root))));
    }
    return out;
  };
  const reference = evaluate(REF);
  for (const [mut, label] of Object.entries(MUTANTS)) {
    const mutant = evaluate(makeModel({ [mut]: true }));
    const killed = mutant.some((v, i) => v !== reference[i]);
    assert.ok(killed, `the vectors kill the mutation: ${label}`);
  }
});

/* ---------------- runtime legs: the exported helpers over the same VECTORS (added with the implementation) ---------------- */
const M4 = require("../src/manifest-v4");
const R2 = require("../testutil/rc45-r2-kit");
const { withDaa } = require("../testutil/rc45-r2-daa");
/* The configured node of the runtime read: the loopback URL nothing listens on; every answer comes from a TEST node client. */
const NODE_CONFIG = require("../src/config").loadConfig({ dataRoot: require("node:os").tmpdir(), rpcUrl: R2.LOOPBACK });
const STAGE = "rc45-r2-01 vectors";
const NODE_DOWN = "TEST node unavailable (ECONNREFUSED 127.0.0.1:1)";
const outcomeAsync = async (fn) => { try { return { ok: await fn() }; } catch (e) { return { code: e.code ?? "THROW" }; } };
/* A VECTORS raw DAA as a TEST node: a function (a read that throws) is a node that cannot be connected. */
const nodeFor = (raw) => (typeof raw === "function" ? { connectError: NODE_DOWN } : { virtualDaaScore: raw });
/* The runtime freshness verdict in the reference model's shape: null, or the agentPk the refusal names. */
function runtimeStale(prev, next, currentDaa) {
  try { M4.assertLeafStartsFresh({ predecessorEntries: prev, nextEntries: next, currentDaa, stage: STAGE }); return null; }
  catch (e) { if (e.code !== "PERIOD_START_STALE") throw e; return e.extra?.agentPk ?? "PERIOD_START_STALE without error.extra.agentPk"; }
}
const plannerRoot = (entries) => buildAgentTreeV4(entries.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }))).root;

test("RC45 R2-01 runtime: the rule's exported code constants are 6,000 and 600 DAA, and periodStartWindowDaa reproduces every W(L) row (BigInt or decimal-string length) and the reference model; a length that is not a positive integer refuses", () => {
  assert.equal(M4.PERIOD_START_ACCEPT_MARGIN_DAA, ACCEPT_MARGIN_DAA, "the acceptance margin constant");
  assert.equal(M4.PERIOD_START_MIN_WINDOW_DAA, MIN_WINDOW_DAA, "the minimum window constant");
  for (const [L, W, minutes] of VECTORS.window) {
    assert.equal(M4.periodStartWindowDaa(L), W, `W(${L})`);
    assert.equal(M4.periodStartWindowDaa(L.toString()), W, `W("${L}")`);
    assert.equal(M4.periodStartWindowDaa(L), REF.windowDaa(L), `W(${L}) agrees with the reference model`);
    if (minutes !== null) assert.equal(M4.periodStartWindowDaa(L) / DAA_PER_SECOND / 60n, minutes, `W(${L}) in minutes`);
  }
  for (const bad of [0n, -1n, "0", "-1", "1.5", "0x10", "", " 36000", null, undefined, 1.5, {}]) {
    assert.throws(() => M4.periodStartWindowDaa(bad), `W(${typeof bad === "string" ? JSON.stringify(bad) : String(bad)}) refuses`);
  }
});

test("RC45 R2-01 runtime: assertLeafStartsFresh reproduces every freshness row and the reference model: fresh at D - S = W(L); PERIOD_START_STALE at W(L) + 1 naming agentPk, periodStartDaa, currentDaa, periodLengthDaa and windowDaa in error.extra; a CARRIED leaf is never judged and needs no current DAA; lagging CARRIED predecessor leaves never decide the verdict; a current DAA that is not a non-negative BigInt refuses PERIOD_START_REQUIRED", () => {
  for (const [label, S, L, d, stale] of VECTORS.fresh) {
    const c = leaf(PK.c, { periodStartDaa: S.toString(), periodLengthDaa: L.toString() });
    const n = [c];
    assert.equal(runtimeStale([], n, d), REF.stale([], n, d), `${label}: agrees with the reference model`);
    assert.equal(runtimeStale([], n, d), stale ? PK.c : null, label);
    if (stale) {
      assert.throws(() => M4.assertLeafStartsFresh({ predecessorEntries: [], nextEntries: n, currentDaa: d, stage: STAGE }), (e) => {
        const x = e.extra ?? {};
        assert.equal(e.code, "PERIOD_START_STALE", label);
        assert.deepEqual(
          { agentPk: String(x.agentPk), periodStartDaa: String(x.periodStartDaa), currentDaa: String(x.currentDaa), periodLengthDaa: String(x.periodLengthDaa), windowDaa: String(x.windowDaa) },
          { agentPk: PK.c, periodStartDaa: S.toString(), currentDaa: d.toString(), periodLengthDaa: L.toString(), windowDaa: REF.windowDaa(L).toString() },
          `${label}: error.extra`);
        return true;
      }, `${label}: refused`);
    }
    /* CARRIED: never judged, and no current DAA is needed to say so. */
    assert.equal(runtimeStale(n, n, d), REF.stale(n, n, d), `${label}: CARRIED agrees with the reference model`);
    assert.equal(runtimeStale(n, n, d), null, `${label}: a CARRIED leaf is never judged`);
    assert.equal(runtimeStale(n, n, undefined), null, `${label}: a CARRIED-only registry needs no current DAA`);
    /* Next to the lagging CARRIED predecessor leaves (P[0] is five periods behind D): only the ANCHORED leaf decides. */
    assert.equal(runtimeStale(P, [...P, c], d), REF.stale(P, [...P, c], d), `${label}: with CARRIED neighbours agrees with the reference model`);
    assert.equal(runtimeStale(P, [...P, c], d), stale ? PK.c : null, `${label}: CARRIED neighbours never decide the verdict`);
  }
  const fresh = [leaf(PK.c, { periodStartDaa: D.toString() })];
  for (const bad of [undefined, null, Number(D), D.toString(), -1n, {}]) {
    assert.throws(() => M4.assertLeafStartsFresh({ predecessorEntries: [], nextEntries: fresh, currentDaa: bad, stage: STAGE }), (e) => e.code === "PERIOD_START_REQUIRED", `currentDaa ${typeof bad === "string" ? JSON.stringify(bad) : String(bad)} refuses`);
  }
});

test("RC45 R2-01 runtime: readCanonicalVirtualDaaScore over a mock rpc and the REAL readAnchorDaa over a TEST node client reproduce every canonical DAA row and the reference model (a canonical score is read; every other answer refuses PERIOD_START_REQUIRED); the read is one verified connection (connect, the network/sync/index gate, one DAA read) that is always closed; a failed DAA read, an unusable answer, an unsynced or unindexed node, another network and a connection that cannot open all refuse PERIOD_START_REQUIRED carrying the original cause", async () => {
  for (const [label, raw, want] of VECTORS.daa) {
    const ref = outcome(() => REF.readDaa(raw));
    const viaRpc = await outcomeAsync(() => chain.readCanonicalVirtualDaaScore(withDaa({}, raw)));
    assert.deepEqual(viaRpc, ref, `${label}: readCanonicalVirtualDaaScore agrees with the reference model`);
    assert.deepEqual(viaRpc, want === null ? { code: "PERIOD_START_REQUIRED" } : { ok: want }, `${label}: readCanonicalVirtualDaaScore`);
    const node = nodeFor(raw);
    const { got, log } = await R2.withNodeClient(NODE_CONFIG, node, async (client) => ({ got: await outcomeAsync(() => chain.readAnchorDaa(NODE_CONFIG)), log: client.log() }));
    assert.deepEqual(got, ref, `${label}: readAnchorDaa agrees with the reference model`);
    R2.assertNodeClientClosed(log, node, `${label}: readAnchorDaa`);
    assert.deepEqual(log.calls, ["connect", "getServerInfo", "getBlockDagInfo", "disconnect"], `${label}: one verified connection, one DAA read, closed`);
  }
  /* The DAA read itself fails, or answers no usable object. */
  const dagThrows = withDaa({ async getBlockDagInfo() { throw new Error("TEST dag read failed"); } }, D);
  await assert.rejects(chain.readCanonicalVirtualDaaScore(dagThrows), (e) => e.code === "PERIOD_START_REQUIRED" && e.message.includes("TEST dag read failed"), "a failed DAA read refuses with its cause");
  for (const answer of [null, undefined, "545000000", 545000000n, []]) {
    await assert.rejects(chain.readCanonicalVirtualDaaScore({ async getBlockDagInfo() { return answer; } }), (e) => e.code === "PERIOD_START_REQUIRED", `a DAG answer ${String(answer)} refuses`);
  }
  /* The node gate and the connection, through the REAL read. */
  const CAUSE = [[{ isSynced: false }, "not synced"], [{ hasUtxoIndex: false }, "no utxoindex"], [{ networkId: "mainnet" }, "mainnet"]];
  for (const [label, node] of R2.UNREADABLE_NODES) {
    const { err, log } = await R2.withNodeClient(NODE_CONFIG, node, async (client) => {
      let error = null;
      try { await chain.readAnchorDaa(NODE_CONFIG); } catch (e) { error = e; }
      return { err: error, log: client.log() };
    });
    assert.ok(err, `${label}: refused`);
    assert.equal(err.code, "PERIOD_START_REQUIRED", `${label}: PERIOD_START_REQUIRED (${err.message})`);
    if (node.connectError) assert.ok(err.message.includes(node.connectError), `${label}: the connect error is carried: ${err.message}`);
    for (const [gate, cause] of CAUSE) if (node.serverInfo && Object.keys(gate).every((k) => node.serverInfo[k] === gate[k])) assert.ok(err.message.includes(cause), `${label}: the gate's cause is carried: ${err.message}`);
    R2.assertNodeClientClosed(log, node, label);
    assert.equal(log.calls.filter((c) => c === "getBlockDagInfo").length, node.serverInfo || node.connectError ? 0 : 1, `${label}: the DAA is read only past the gate`);
  }
});

test("RC45 R2-01 runtime: anchoredLeafPks, committedLeafEqual and anchorRegistryStarts — with the REAL readAnchorDaa over a TEST node client as the read, made only when a leaf is ANCHORED — reproduce every anchor-at-build row and the reference model: the same ANCHORED set, the same committed entries in the same order (max semantics; every other field exactly as requested), the same agent root (the fold of the committed leaves, equal to the planner's), no node read without an ANCHORED leaf, PERIOD_START_REQUIRED for an unreadable or non-canonical node, inputs never mutated, and no anchor without a BigInt DAA", async () => {
  for (const [label, prev, next, raw, want, pks] of VECTORS.anchor) {
    const before = JSON.stringify([prev, next]);
    const ref = outcome(() => REF.anchor(prev, next, raw));
    const anchored = M4.anchoredLeafPks(prev, next);
    assert.deepEqual(anchored.slice().sort(), REF.anchoredPks(prev, next).slice().sort(), `${label}: the ANCHORED set agrees with the reference model`);
    if (pks !== null) assert.deepEqual(anchored.slice().sort(), pks.slice().sort(), `${label}: the ANCHORED set`);
    for (const n of next) {
      const p = prev.find((e) => e.agentPk === n.agentPk);
      if (!p) continue;
      const carried = REF.anchoredPks([p], [n]).length === 0;
      assert.equal(M4.committedLeafEqual(p, n), carried, `${label}: committedLeafEqual(${n.agentPk.slice(0, 8)}) agrees with the reference model`);
      assert.equal(M4.committedLeafEqual(n, p), carried, `${label}: committedLeafEqual is symmetric`);
    }
    const node = nodeFor(raw);
    const { got, log } = await R2.withNodeClient(NODE_CONFIG, node, async (client) => ({
      got: await outcomeAsync(async () => {
        const anchorDaa = M4.anchoredLeafPks(prev, next).length > 0 ? await chain.readAnchorDaa(NODE_CONFIG) : undefined;
        return M4.anchorRegistryStarts({ predecessorEntries: prev, nextEntries: next, anchorDaa });
      }),
      log: client.log()
    }));
    if (anchored.length === 0) assert.equal(log.connectAttempts, 0, `${label}: no node read without an ANCHORED leaf`);
    else { assert.equal(log.connectAttempts, 1, `${label}: one node read`); R2.assertNodeClientClosed(log, node, label); }
    assert.equal(JSON.stringify([prev, next]), before, `${label}: the inputs are not mutated`);
    if (ref.code !== undefined) {
      assert.deepEqual(got, ref, `${label}: refuses as the reference model does`);
      assert.equal(typeof want, "string", `${label}: a refusal row`);
      assert.deepEqual(got, { code: want }, label);
      continue;
    }
    assert.ok(got.ok, `${label}: ${got.code ?? ""}`);
    assert.deepEqual(got.ok.entries, ref.ok.entries, `${label}: the committed entries agree with the reference model`);
    assert.deepEqual(got.ok.anchoredAgentPks.slice().sort(), ref.ok.anchoredAgentPks.slice().sort(), `${label}: anchoredAgentPks agree with the reference model`);
    assert.equal(got.ok.root, ref.ok.root, `${label}: the agent root agrees with the reference model`);
    assert.deepEqual(got.ok.entries.map((e) => e.agentPk), next.map((e) => e.agentPk), `${label}: entry order kept`);
    for (const [pk, start] of Object.entries(want)) assert.equal(got.ok.entries.find((e) => e.agentPk === pk).periodStartDaa, start, `${label}: start of ${pk.slice(0, 8)}`);
    got.ok.entries.forEach((e, i) => {
      for (const f of NINE.filter((x) => x !== "periodStartDaa")) assert.equal(String(e[f]), String(next[i][f]), `${label}: ${f} is committed exactly as requested`);
      if (!anchored.includes(e.agentPk)) assert.equal(e.periodStartDaa, next[i].periodStartDaa, `${label}: a CARRIED start is committed unchanged`);
    });
    assert.equal(got.ok.root, normalizeRegistry(got.ok.entries).tree.root, `${label}: the root is the fold of the committed leaves`);
    assert.equal(got.ok.root, plannerRoot(got.ok.entries), `${label}: the root is the planner's root of the committed leaves`);
    /* No anchor without the node's canonical DAA as a non-negative BigInt; a CARRIED-only registry needs none. */
    if (anchored.length > 0) {
      for (const bad of [undefined, null, Number(D), D.toString(), -1n]) {
        assert.throws(() => M4.anchorRegistryStarts({ predecessorEntries: prev, nextEntries: next, anchorDaa: bad }), (e) => e.code === "PERIOD_START_REQUIRED", `${label}: anchorDaa ${typeof bad === "string" ? JSON.stringify(bad) : String(bad)} refuses`);
      }
    } else assert.deepEqual(M4.anchorRegistryStarts({ predecessorEntries: prev, nextEntries: next }), ref.ok, `${label}: a CARRIED-only registry anchors without a DAA`);
  }
  /* committedLeafEqual over the nine committed fields, one at a time (the agentPk row is a different key: never equal). */
  for (const f of NINE) {
    const changed = changedField(f);
    assert.equal(M4.committedLeafEqual(P[0], changed), false, `${f} changed: not CARRIED`);
    assert.equal(M4.committedLeafEqual(P[0], changed), REF.anchoredPks([P[0]], [changed]).length === 0, `${f} changed: agrees with the reference model`);
  }
  assert.equal(M4.committedLeafEqual(P[0], { ...P[0] }), true, "an identical copy is CARRIED");
  assert.equal(M4.committedLeafEqual(P[0], { ...P[0], agentRecipientRoot: undefined }), true, "the recipient root is derived from the recipients");
});

test("RC45 R2-01 runtime: assertRegistryFoldsToRoot reproduces every registry-to-root integrity row and the reference model (the fold must equal the committed root, lower-case hex compare; null, undefined, an object and a string refuse REGISTRY_ROOT_MISMATCH, never folded as empty; an empty array against the empty tree's root passes), over the registry anchorRegistryStarts commits; a committed root that is not 32-byte hex and an unfoldable registry refuse", () => {
  const next = [...P, leaf(PK.c, { periodStartDaa: "0", periodSpent: "0" })];
  const run = M4.anchorRegistryStarts({ predecessorEntries: P, nextEntries: next, anchorDaa: D });
  const refRun = REF.anchor(P, next, D);
  assert.deepEqual(run.entries, refRun.entries, "the runtime anchored registry equals the reference model's");
  assert.equal(run.root, refRun.root, "the runtime anchored root equals the reference model's");
  const anchored = run.entries;
  const roots = { anchoredRoot: run.root, anchoredRootUpper: run.root.toUpperCase(), requestedRoot: REF.fold(next), emptyRoot: buildAgentTreeV4([]).root };
  assert.notEqual(roots.anchoredRoot, roots.requestedRoot, "anchoring a start changes the agent root");
  for (const [label, entries, rootName, ok] of VECTORS.integrity) {
    const e = entries === "anchored" ? anchored : entries === "requested" ? next : entries;
    const ref = outcome(() => REF.integrity(e, roots[rootName]));
    const got = outcome(() => M4.assertRegistryFoldsToRoot({ entries: e, committedAgentRoot: roots[rootName], stage: STAGE }));
    assert.deepEqual(got, ref, `${label}: agrees with the reference model`);
    assert.equal(got.code, ok ? undefined : "REGISTRY_ROOT_MISMATCH", label);
  }
  for (const badRoot of [undefined, null, "", 5, "zz".repeat(32), `${roots.anchoredRoot}00`, roots.anchoredRoot.slice(2)]) {
    assert.deepEqual(outcome(() => M4.assertRegistryFoldsToRoot({ entries: anchored, committedAgentRoot: badRoot, stage: STAGE })), { code: "REGISTRY_ROOT_MISMATCH" }, `committed root ${JSON.stringify(badRoot)} refuses`);
  }
  const unfoldable = [{ ...P[0], agentRecipientRoot: "00".repeat(32) }];
  assert.throws(() => M4.assertRegistryFoldsToRoot({ entries: unfoldable, committedAgentRoot: REF.fold([P[0]]), stage: STAGE }), "a registry that cannot be folded refuses");
});

test("RC45 R2-01 runtime: property (1,000 seeded random tuples): the runtime helpers agree with the reference model on W(L), on what anchorRegistryStarts commits for a new leaf (start max(requested, D), the same entries and root) and on the freshness verdict of the requested and of the anchored leaf at a check-time DAA around the window boundary", () => {
  let counter = 0;
  const rand = (lo, hi) => { // inclusive, deterministic
    const h = crypto.createHash("sha256").update(`rc45-r2-01-runtime-${counter++}`).digest();
    return lo + (BigInt(`0x${h.toString("hex").slice(0, 24)}`) % (hi - lo + 1n));
  };
  const LENGTHS = [1n, 60n, 600n, 1200n, 6000n, 6599n, 6600n, 6601n, HOUR, 6n * HOUR, DAY, 7n * DAY];
  let tuples = 0, stales = 0, freshes = 0;
  for (let i = 0; i < 1000; i++) {
    const L = i % 2 === 0 ? LENGTHS[(i / 2) % LENGTHS.length] : rand(1n, 8n * DAY);
    const W = REF.windowDaa(L);
    assert.equal(M4.periodStartWindowDaa(L), W, `tuple ${i}: W(${L})`);
    const d = rand(1n, D);
    const S = rand(0n, 1n) === 0n ? rand(0n, d) : rand(d, d + 2n * L);
    const n = [leaf(PK.c, { periodStartDaa: S.toString(), periodLengthDaa: L.toString() })];
    const got = M4.anchorRegistryStarts({ predecessorEntries: [], nextEntries: n, anchorDaa: d });
    const ref = REF.anchor([], n, d);
    assert.equal(got.entries[0].periodStartDaa, max(S, d).toString(), `tuple ${i}: start max(${S}, ${d})`);
    assert.deepEqual(got.entries, ref.entries, `tuple ${i}: the committed entries agree with the reference model`);
    assert.equal(got.root, ref.root, `tuple ${i}: the root agrees with the reference model`);
    const base = max(S, d), pick = i % 4;
    const dc = pick === 0 ? base + W : pick === 1 ? base + W + 1n : rand(d, d + 2n * W + 2n);
    for (const entries of [n, got.entries]) {
      const verdict = runtimeStale([], entries, dc);
      assert.equal(verdict, REF.stale([], entries, dc), `tuple ${i}: the freshness verdict agrees with the reference model (S=${entries[0].periodStartDaa} L=${L} Dc=${dc})`);
      if (verdict === null) freshes += 1; else stales += 1;
    }
    tuples += 1;
  }
  assert.ok(tuples === 1000 && stales > 100 && freshes > 100, `${tuples} tuples, ${stales} stale and ${freshes} fresh verdicts`);
});
