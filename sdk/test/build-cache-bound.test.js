"use strict";

/*
 * PERMANENT REGRESSION — rc11 internal security review F-03 (2026-09-04) +
 * owner addendum §D (cleanup safety).
 *
 * RED before the fix (docs/postlaunch/audit-evidence/rc11-internal-review/):
 * every v4 genesis build persisted ~2.09 MB (artifact.json 2,060,530 B) that
 * nothing reclaimed; 71 builds filled a 128 MB data tmpfs and the next
 * legitimate build failed ENOSPC.
 *
 * This suite pins BOTH sides of the cleanup contract:
 *   1. hostile/abandoned artifacts are bounded and reclaimed (entry cap,
 *      byte cap, LRU order, grace window, minimal artifact payload, closed
 *      BUILD_CACHE_FULL refusal instead of ENOSPC when nothing may be evicted);
 *   2. a legitimate pending flow SURVIVES eviction: its durable request is
 *      untouched and finalize recompiles the evicted entry deterministically
 *      (stateId identity asserted) — cleanup never alters covenant state,
 *      chain truth, claims, receipts or reconciliation evidence.
 * Sabotage sensitivity: skipping enforceBuildCacheBound / minimizeArtifactFile
 * in any compiler, or returning a different buildDir from recompile, turns the
 * corresponding assertions RED.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const cache = require("../src/build-cache");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const baseConfig = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-")) });
const TOOLCHAIN = fs.existsSync(baseConfig.silvercPath) && fs.existsSync(ENCODER_PATH);
const SKIP = !TOOLCHAIN && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder";

function fakeEntry(dataRoot, subdir, name, bytes, ageMs) {
  const dir = path.join(dataRoot, subdir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "artifact.json"), JSON.stringify({ script: [0], state_layout: { start: 0, len: 0 }, pad: "x".repeat(Math.max(0, bytes - 80)) }));
  const t = new Date(Date.now() - ageMs);
  fs.utimesSync(path.join(dir, "artifact.json"), t, t);
  fs.utimesSync(dir, t, t);
  return dir;
}

test("config: buildCache caps are validated, bounded and env/override driven", () => {
  const c = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-")), buildCacheMaxEntries: 9, buildCacheMaxBytes: 2 * 1024 * 1024, buildCacheGraceMs: 0 });
  assert.deepEqual(c.buildCache, { maxEntries: 9, maxBytes: 2 * 1024 * 1024, graceMs: 0 });
  assert.equal(baseConfig.buildCache.maxEntries, cache.DEFAULT_MAX_ENTRIES);
  assert.equal(baseConfig.buildCache.maxBytes, cache.DEFAULT_MAX_BYTES);
  assert.throws(() => loadConfig({ dataRoot: baseConfig.dataRoot, buildCacheMaxEntries: 1 }), /buildCacheMaxEntries/);
  assert.throws(() => loadConfig({ dataRoot: baseConfig.dataRoot, buildCacheMaxBytes: 1 }), /buildCacheMaxBytes/);
});

test("minimizeArtifactFile keeps exactly the consumer keys, is atomic-by-rename and idempotent; script bytes untouched", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-min-"));
  const p = path.join(dir, "artifact.json");
  const script = Array.from({ length: 64 }, (_, i) => i);
  fs.writeFileSync(p, JSON.stringify({ contract_name: "X", compiler_version: "1", script, state_layout: { start: 3, len: 5 }, ast: { huge: "y".repeat(100000) }, debug_info: [1, 2, 3], abi: {} }));
  const before = fs.statSync(p).size;
  assert.equal(cache.minimizeArtifactFile(p), true);
  const after = JSON.parse(fs.readFileSync(p, "utf8"));
  assert.deepEqual(Object.keys(after).sort(), [...cache.ARTIFACT_KEEP].sort());
  assert.deepEqual(after.script, script);
  assert.deepEqual(after.state_layout, { start: 3, len: 5 });
  assert.ok(fs.statSync(p).size < before / 10, "artifact shrank by >10x");
  assert.equal(cache.minimizeArtifactFile(p), false, "second run is a no-op");
  assert.equal(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp")).length, 0, "no temp residue");
});

test("enforceBuildCacheBound: entry cap evicts strictly least-recently-used entries across ALL build-* subdirs; keep entry is never evicted; idempotent", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-lru-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 4, buildCacheGraceMs: 0 });
  const ages = { a: 5000, b: 4000, c: 3000, d: 2000, e: 1000 };
  fakeEntry(dataRoot, "build-v4_1", "a", 100, ages.a);
  fakeEntry(dataRoot, "build-v5", "b", 100, ages.b);
  fakeEntry(dataRoot, "build-v7-root", "c", 100, ages.c);
  fakeEntry(dataRoot, "build-v4_1", "d", 100, ages.d);
  fakeEntry(dataRoot, "build-kcc20", "e", 100, ages.e);
  fs.mkdirSync(path.join(dataRoot, "requests")); // non-cache dirs are never touched
  fs.writeFileSync(path.join(dataRoot, "requests", "r.json"), "{}");
  const keep = path.join(dataRoot, "build-v4_1", "new");
  fs.mkdirSync(keep, { recursive: true });
  const r = cache.enforceBuildCacheBound(config, { keep });
  // 5 existing + 1 new = 6 > 4 -> evict the 2 oldest (a, b)
  assert.equal(r.evicted, 2);
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v4_1", "a")), false);
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v5", "b")), false);
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v7-root", "c")), true);
  assert.equal(fs.existsSync(path.join(dataRoot, "build-kcc20", "e")), true);
  assert.equal(fs.existsSync(path.join(dataRoot, "requests", "r.json")), true);
  assert.equal(cache.enforceBuildCacheBound(config, { keep }).evicted, 0, "idempotent: nothing more to evict");
});

test("enforceBuildCacheBound: byte cap; grace window protects in-flight entries; impossible bound => closed BUILD_CACHE_FULL refusal (never ENOSPC)", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-bytes-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 1000, buildCacheMaxBytes: 1024 * 1024, buildCacheGraceMs: 60_000 });
  for (let i = 0; i < 6; i++) fakeEntry(dataRoot, "build-v4_1", `old${i}`, 300 * 1024, 120_000 + i * 1000); // 1.8 MB, old
  for (let i = 0; i < 2; i++) fakeEntry(dataRoot, "build-v4_1", `hot${i}`, 300 * 1024, 1000); // 600 KB, in-flight
  const keep = path.join(dataRoot, "build-v4_1", "new");
  fs.mkdirSync(keep, { recursive: true });
  const r = cache.enforceBuildCacheBound(config, { keep });
  assert.ok(r.evicted >= 4, `evicted old entries to satisfy the byte cap (evicted=${r.evicted})`);
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v4_1", "hot0")), true, "in-grace entries are never evicted");
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v4_1", "hot1")), true);
  // now make the cap impossible without touching in-grace entries: 4 in-flight entries (1.2 MB) > 1 MiB byte cap
  for (let i = 2; i < 4; i++) fakeEntry(dataRoot, "build-v4_1", `hot${i}`, 300 * 1024, 1000);
  const tight = loadConfig({ dataRoot, buildCacheMaxEntries: 1000, buildCacheMaxBytes: 1024 * 1024, buildCacheGraceMs: 60_000 });
  assert.throws(() => cache.enforceBuildCacheBound(tight, { keep }), (e) => e.code === "BUILD_CACHE_FULL");
  assert.equal(fs.existsSync(path.join(dataRoot, "build-v4_1", "hot0")), true, "a refusal deletes nothing");
});

test("HOSTILE GROWTH IS BOUNDED (real compiler): N distinct v4 states never exceed the caps and artifacts are minimal", { skip: SKIP }, () => {
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const vs4 = require("../../core/model/vault-state-v4");
  const { normalizeAgentPolicyV4, buildAgentTreeV4 } = require("../../core/model/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-real-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 4, buildCacheGraceMs: 0 });
  const KAS = 100000000n;
  const owner = "11".repeat(32);
  const policy = normalizeAgentPolicyV4({ agentPk: "22".repeat(32), maxPerSpend: (1n * KAS).toString(), periodBudget: (5n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "1", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), agentRecipientRoot: buildRecipientTree(["33".repeat(32)]).root });
  const agentRoot = buildAgentTreeV4([policy]).root;
  const sizes = [];
  for (let i = 1; i <= 7; i++) {
    const template = { owner, vaultId: i.toString(16).padStart(2, "0").repeat(32) }; // distinct state per hostile vaultId
    const state = vs4.normalizeStateV4({ protectedValue: (10n * KAS).toString(), feeReserve: (1n * KAS).toString(), paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
    const c = compileExactStateV4({ config, template, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 });
    const art = JSON.parse(fs.readFileSync(c.artifactPath, "utf8"));
    assert.deepEqual(Object.keys(art).sort(), [...cache.ARTIFACT_KEEP].sort(), "artifact is minimal");
    sizes.push(fs.statSync(c.artifactPath).size);
    const entries = cache.listCacheEntries(dataRoot);
    assert.ok(entries.length <= config.buildCache.maxEntries, `after build ${i}: ${entries.length} entries <= cap ${config.buildCache.maxEntries}`);
  }
  assert.ok(Math.max(...sizes) < 200 * 1024, `minimal v4 artifact is small (max ${Math.max(...sizes)} B, was ~2,060,530 B)`);
  assert.equal(cache.listCacheEntries(dataRoot).length, 4);
});

test("LEGITIMATE PENDING FLOW SURVIVES EVICTION (real toolchain): a BUILT v4 request whose cache entry was reclaimed still finalizes via deterministic recompile", { skip: SKIP }, async () => {
  const wr4 = require("../src/wallet-requests-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const vs4 = require("../../core/model/vault-state-v4");
  const { normalizeAgentPolicyV4, buildAgentTreeV4 } = require("../../core/model/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { makeDevSigner } = require("../src/signer-dev");
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-flow-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 4, buildCacheGraceMs: 0 });
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const KAS = 100000000n;
  const owner = KEY(1), agent = KEY(0x1e), recipient = KEY(0x28);
  const VAULT_ID = "5a".repeat(32);
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const entry = { agentPk: XO(agent), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)] };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  await persistManifestV4(config, { schema: MANIFEST_SCHEMA_V4, contractVersion: vs4.CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID, label: "flow", status: "ACTIVE", template, agentRegistry: [entry], live: { state: vs4.stateToJsonV4(state), stateId: vs4.computeStateIdV4({ networkId: config.networkId, template, state }), outpoint: { transactionId: "01".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) }, creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null });
  const fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agent)}ac` };
  const req = await wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agent), recipient: XO(recipient), fuel }, signerAddress: ADDR(agent) });
  assert.equal(req.state, "BUILT");
  const buildDir = req.build.encoderBuildDir;
  assert.equal(fs.existsSync(path.join(buildDir, "artifact.json")), true);
  // HOSTILE: flood the cache with 6 distinct states -> the pending request's entry is evicted
  for (let i = 1; i <= 6; i++) {
    const t2 = { owner: XO(owner), vaultId: i.toString(16).padStart(2, "0").repeat(32) };
    compileExactStateV4({ config, template: t2, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 });
  }
  assert.equal(fs.existsSync(path.join(buildDir, "artifact.json")), false, "the pending request's cache entry was reclaimed by the bound");
  const durable = await wr4.loadRequest(config, req.requestId);
  assert.equal(durable.state, "BUILT", "the durable request itself is untouched by cache cleanup");
  // the legitimate signer completes the flow: finalize recompiles the evicted entry deterministically
  const signed = makeDevSigner(config, { secretHex: "1e".repeat(32), expectedAddress: ADDR(agent) }).signInputs(req.transaction.unsignedSafeJson, req.transaction.signInputs);
  const finalized = await wr4.finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "PREFLIGHT_VERIFIED", `finalize after eviction: ${finalized.state} ${finalized.error || ""}`);
  assert.equal(fs.existsSync(path.join(buildDir, "artifact.json")), true, "recompiled into the SAME build dir (stateId identity)");
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(path.join(buildDir, "artifact.json"), "utf8"))).sort(), [...cache.ARTIFACT_KEEP].sort());
});

test("ensureBuildDir fails closed when the recompile does not reproduce the named directory", () => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-ens-")), "build-v4_1", "expected");
  assert.throws(() => cache.ensureBuildDir({ buildDir: dir, recompile: () => ({ buildDir: dir + "-other" }) }), (e) => e.code === "BUILD_DIR_MISMATCH");
  assert.throws(() => cache.ensureBuildDir({ buildDir: "", recompile: () => ({ buildDir: "" }) }), (e) => e.code === "BUILD_DIR_MISSING");
});

/* ---------------- rc12 internal review R-03 / R-07 (2026-09-05) ---------------- */

test("R-03: a cache SATURATED with in-grace entries never refuses the finalize-time recompile of an already-built request — ensureBuildDir force-evicts LRU and retries once; a FRESH build in the same state is still the closed BUILD_CACHE_FULL", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-r03-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 4, buildCacheMaxBytes: 64 * 1024 * 1024, buildCacheGraceMs: 600000 });
  for (let i = 0; i < 4; i++) fakeEntry(dataRoot, "build-v4_1", `fresh${i}`, 500, i * 1000); // all inside the grace window
  const evictedDir = path.join(dataRoot, "build-v4_1", "evicted-request");
  // a NEW build must still be refused fail-closed (grace protects the concurrent fresh builds)
  assert.throws(() => cache.enforceBuildCacheBound(config, { keep: path.join(dataRoot, "build-v4_1", "brand-new") }), (e) => e.code === "BUILD_CACHE_FULL");
  // the FINALIZE path of an already-built request recompiles: first attempt is refused by the bound, ensureBuildDir forces eviction and retries
  let attempts = 0;
  const recompile = () => {
    attempts += 1;
    cache.enforceBuildCacheBound(config, { keep: evictedDir }); // what every compiler does first (throws BUILD_CACHE_FULL while saturated)
    fs.mkdirSync(evictedDir, { recursive: true });
    fs.writeFileSync(path.join(evictedDir, "artifact.json"), JSON.stringify({ script: [1], state_layout: { start: 0, len: 0 } }));
    return { buildDir: evictedDir };
  };
  const recompiled = cache.ensureBuildDir({ buildDir: evictedDir, recompile, config });
  assert.equal(recompiled, true);
  assert.equal(attempts, 2, "one refused attempt, one forced-eviction retry");
  assert.ok(fs.existsSync(path.join(evictedDir, "artifact.json")));
  const remaining = cache.listCacheEntries(dataRoot).map((e) => path.basename(e.dir)).sort();
  assert.equal(remaining.length, 4, "entry cap holds after the retry");
  assert.ok(remaining.includes("evicted-request"));
  assert.ok(!remaining.includes("fresh3"), "the least-recently-used in-grace entry was the forced victim");
  // without config (no retry authority) the refusal still propagates closed
  fs.rmSync(evictedDir, { recursive: true, force: true });
  fakeEntry(dataRoot, "build-v4_1", "fresh9", 500, 0);
  assert.throws(() => cache.ensureBuildDir({ buildDir: evictedDir, recompile }), (e) => e.code === "BUILD_CACHE_FULL");
});

test("R-07: the byte cap is enforced AGAIN once the artifact's real size is known — the cache never persistently exceeds maxBytes after a compile", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-r07-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 16, buildCacheMaxBytes: 1024 * 1024, buildCacheGraceMs: 0 });
  fakeEntry(dataRoot, "build-v4_1", "old-a", 400 * 1024, 5000);
  fakeEntry(dataRoot, "build-v4_1", "old-b", 400 * 1024, 4000);
  const dir = path.join(dataRoot, "build-v4_1", "new-c");
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, "artifact.json");
  // pre-compile enforcement sees 800 KiB (< 1 MiB) and admits the new entry; the compiler then writes a 400 KiB artifact → 1.2 MiB
  cache.enforceBuildCacheBound(config, { keep: dir });
  // the bulk must live in a KEPT key (script), otherwise minimisation itself shrinks the entry
  fs.writeFileSync(p, JSON.stringify({ script: new Array(200 * 1024).fill(0), state_layout: { start: 0, len: 0 }, extra_ignored: "y".repeat(10) }));
  cache.minimizeArtifactFile(p, config);
  const after = cache.listCacheEntries(dataRoot);
  const bytes = after.reduce((a, e) => a + e.bytes, 0);
  assert.ok(bytes <= 1024 * 1024, `post-compile enforcement must bring the cache back under the cap (got ${bytes})`);
  assert.ok(after.some((e) => path.basename(e.dir) === "new-c"), "the entry just built is kept");
  assert.ok(!after.some((e) => path.basename(e.dir) === "old-a"), "LRU victim evicted post-compile");
});

test("N-03 (rc13 review): forced eviction on a finalize recompile never deletes an IN-PROGRESS entry of another process (no artifact yet, inside the grace window) — it evicts completed LRU entries instead", () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bc-n03-"));
  const config = loadConfig({ dataRoot, buildCacheMaxEntries: 4, buildCacheMaxBytes: 64 * 1024 * 1024, buildCacheGraceMs: 600000 });
  /* rc14 review T-01: the in-progress entry must be the LEAST-RECENTLY-USED one,
   * i.e. the entry a plain LRU pass would delete first — otherwise this test
   * cannot tell the guard from its absence. */
  const inProgress = path.join(dataRoot, "build-v4_1", "in-progress");
  fs.mkdirSync(inProgress, { recursive: true });
  fs.writeFileSync(path.join(inProgress, "source.sil"), "x"); // another process wrote source/args, silverc still running
  const tOld = new Date(Date.now() - 5000); fs.utimesSync(path.join(inProgress, "source.sil"), tOld, tOld); fs.utimesSync(inProgress, tOld, tOld); // oldest mtime, inside the 600 s grace
  fakeEntry(dataRoot, "build-v4_1", "done-old", 500, 3000);
  fakeEntry(dataRoot, "build-v4_1", "done-new", 500, 1000);
  fakeEntry(dataRoot, "build-v4_1", "done-newest", 500, 0);
  const lruFirst = cache.listCacheEntries(dataRoot).sort((a, b) => a.mtimeMs - b.mtimeMs)[0];
  assert.equal(path.basename(lruFirst.dir), "in-progress", "precondition: the in-progress entry IS the LRU candidate");
  const target = path.join(dataRoot, "build-v4_1", "finalizing");
  const r = cache.enforceBuildCacheBound(config, { keep: target, force: true });
  assert.equal(r.evicted, 1);
  assert.ok(fs.existsSync(inProgress), "the in-progress entry survives a forced eviction even though it is the LRU candidate");
  assert.ok(!fs.existsSync(path.join(dataRoot, "build-v4_1", "done-old")), "the oldest COMPLETED entry was the victim instead");
  // an ABANDONED in-progress entry (older than the grace window) is reclaimable
  const stale = path.join(dataRoot, "build-v4_1", "abandoned");
  fs.mkdirSync(stale, { recursive: true }); fs.writeFileSync(path.join(stale, "source.sil"), "x");
  const t = new Date(Date.now() - 700000); fs.utimesSync(path.join(stale, "source.sil"), t, t); fs.utimesSync(stale, t, t);
  cache.enforceBuildCacheBound(config, { keep: target, force: true });
  assert.ok(!fs.existsSync(stale), "an abandoned in-progress entry past the grace window is reclaimed");
});
