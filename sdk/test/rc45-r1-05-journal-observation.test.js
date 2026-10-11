"use strict";
/*
 * RC45 R1-05 — INVALID DEPTH EVIDENCE FAILS CLOSED AT THE JOURNALED-HISTORY
 * OBSERVATION (sdk/src/wallet-recovery-v4.js:598, request-scoped recovery of a
 * journaled RC42/RC44 record). Finding ST-02 = RC45-REV-SET-02 (= lead I-2) of
 * the independent candidate review rc45-patch-independent-01; remediation plan
 * R1 revision 2, R1-05 with conditions C4 and K1 ("The same rule applies to
 * the journaled-history observation at sdk/src/wallet-recovery-v4.js:598").
 * Internal RED-first regression material for the RC45 successor candidate;
 * not an audit. The Verify-pass judged entries are pinned in
 * sdk/test/rc45-r1-05-depth-evidence.test.js.
 *
 * The rule here: the judged entry is the observed exact original effect (the
 * record's own output at its expected address, `effect` at :598). Its RAW
 * blockDaaScore must be canonical (K1: a non-negative bigint, a non-negative
 * safe integer, or a string matching /^[0-9]+$/); anything else is an
 * observation failure and NOTHING is written. Request-scoped recovery answers
 * an observation failure PROTECTED_UNRESOLVED with no further write (CR2-L10;
 * this path's own catch says "chain observation is unavailable"); a rejection
 * carrying RECONCILE_FAILED or the observation-failure marker is accepted as
 * the equivalent 422 (reading recorded in the R1-05 RED record). A canonical
 * value greater than the virtual DAA score is below depth (PROTECTED_UNRESOLVED,
 * nothing written); bigint and safe-integer raw values are judged normally (K1).
 *
 * RED on dc7552e: `depth = vDaa - (effect.blockDaaScore ?? 0n)` over chain.js's
 * coercion, so with the effect observed DEEP but its raw value absent, empty,
 * hex, signed, padded, an array, a negative number / bigint or a boolean, the
 * journaled record is completed (EFFECT_PROVEN journal, manifest advance,
 * receipt, audit, claims released, CHAIN_VERIFIED / COMPLETE) on evidence the
 * plan declares invalid. The legs run at TRUE depth >= D on purpose: at true
 * depth 0 the invalid-evidence answer and the below-depth answer coincide
 * (both PROTECTED_UNRESOLVED with no write) and could not tell the rule apart.
 * HOLDS on dc7552e (and must keep holding): values chain.js's BigInt already
 * refuses (fractional, null, object) and the unsafe integer 2^53 (judged below
 * depth today) write nothing; the exact controls; > vDaa; K1 encodings; a
 * decoy whose value BigInt accepts.
 * Decoys (an unrelated covenant-less output at the effect's address): one
 * whose raw value BigInt accepts keeps the completion (holds). For one whose
 * value makes chain.js's BigInt throw (fractional, null, object), the plan's
 * "non-throwing coercion for entries that are not judged" (RC1-12) is written
 * for the Verify pass; read fail-closed here, the leg pins only that nothing
 * partial happens: either the exact completion or PROTECTED_UNRESOLVED with
 * nothing written (holds; reading recorded in the RED record).
 *
 * Population: the RC38 fixture's agentSpend base (sdk/testutil/
 * v4-transition-recovery-fixture.js: real v0.4.1 compiler, pv_call_encoder,
 * TEST-key signatures, pinned pv_vm_preflight) turned into journaled history
 * by the pinned df5b8de writer (sdk/testutil/rc45-f7-rc44-history.js scenario
 * "journal": RC44 request-scoped recovery with the recorded outpoint live ->
 * RECONCILIATION_REQUIRED with a PROTECTED journal and re-created claims; a
 * missing or mismatched POLICYVAULT_TEST_RC44_TREE FAILS). Node observations
 * only from the fixture's in-memory node (virtualDaaScore 90,000,000) passed as
 * `rpc`, its getUtxosByAddresses answer post-processed for the entries under
 * test only; every config names ws://127.0.0.1:1. TEST keys only.
 *
 * Layer: SDK (reconcileTransitionWalletRequestV4). Both stores: JSON always;
 * PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's
 * pg mode; a skipped PostgreSQL leg there is a FAIL).
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const fx = require("../testutil/v4-transition-recovery-fixture");
const H7 = require("../testutil/rc45-f7-rc44-history");
const H44 = require("../testutil/rc45-rc44-history");
const K = require("../testutil/rc45-f5-kit");
const { clone } = fx;
const { KAS, LOOPBACK } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const { openPgStore } = require(path.join(SDK_SRC, "store.js"));
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const VDAA = 90000000n; // the fixture node's virtualDaaScore
const roots = [], rc44Roots = [], stores = [], databases = [];
let admin = null, serial = 0, base = null, journaled = null;
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  base = await fx.baseFixture("agentSpend", fx.freshConfig({ rpcUrl: LOOPBACK }));
  roots.push(base.config.dataRoot);
  const rc44 = H7.runF7Rc44Scenario("journal", { snapshot: base.snapshot, requestId: base.request.requestId, track: (root) => rc44Roots.push(root) });
  assert.equal(rc44.result.phase, "PROTECTED", "the RC44 writer's protection journal");
  journaled = await fx.snapshot(fx.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK }));
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
  for (const root of rc44Roots) H44.removeOwnedRoot(root);
});

async function fresh(backend) {
  let config, pgDatabase = null, pgStore = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r105j_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = fx.freshConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, rpcUrl: LOOPBACK });
    pgStore = await openPgStore(config, { migrate: true }); stores.push(pgStore);
    assert.equal(fx.getStore(config).kind, "postgres");
  } else config = fx.freshConfig({ rpcUrl: LOOPBACK });
  roots.push(config.dataRoot);
  assert.equal(config.networkId, "testnet-10");
  await fx.install(config, journaled);
  const x = fx.caseFor({ ...base, snapshot: journaled }, config);
  x.pgStore = pgStore;
  x.snap = () => fx.snapshot(config);
  const r = await x.request();
  assert.equal(r.state, "RECONCILIATION_REQUIRED"); assert.equal(r.transitionRecovery?.phase, "PROTECTED", "journaled RC44 history");
  x.effectIndex = r.build.frozen.outputs.findIndex((o) => o.covenant !== null);
  return x;
}
async function release(x) {
  if (!x.pgStore) return;
  const i = stores.indexOf(x.pgStore);
  if (i >= 0) { stores.splice(i, 1); await x.pgStore.close(); }
}
/* Post-process the node's answer: `mutate` runs on every entry `pick` selects (raw node fields); `extra` may add entries. */
function rewriteAnswer(x, pick, mutate, extra = null) {
  const inner = x.rpc.getUtxosByAddresses.bind(x.rpc);
  let touched = 0;
  x.rpc.getUtxosByAddresses = async (args) => {
    const out = await inner(args);
    if (extra) out.entries.push(...extra(out.entries));
    for (const e of out.entries) if (pick(e)) { mutate(e, VDAA); touched += 1; }
    return out;
  };
  return { get touched() { return touched; } };
}
const isEffect = (x) => (e) => e.outpoint.transactionId === x.q.txId && Number(e.outpoint.index) === x.effectIndex;
/* The journaled record completed exactly (the RC38 fixture's completion check plus the journal's COMPLETE phase). */
async function assertCompleted(x, out) {
  assert.equal(out.outcome, "CHAIN_VERIFIED", `the journaled record completes (got ${out.outcome}: ${out.detail})`);
  await fx.assertComplete(x, base);
  assert.equal((await x.request()).transitionRecovery.phase, "COMPLETE");
}
/* Nothing written, and the answer is the observation failure (PROTECTED_UNRESOLVED or the equivalent 422 rejection). */
async function assertRefusedNoWrite(x, run, before, what) {
  const refused = run.error ? (run.error.code === "RECONCILE_FAILED" || run.error.observationError === true) : run.value?.outcome === "PROTECTED_UNRESOLVED";
  assert.ok(refused, `${what} is an observation failure: no completion (observed ${run.error ? `${run.error.code}: ${String(run.error.message).slice(0, 200)}` : `${run.value?.outcome}: ${run.value?.detail}`})`);
  assert.deepEqual(await x.snap(), before, "nothing is written");
}

/* Raw blockDaaScore values outside the canonical set (K1). `red`: RED on dc7552e with the effect observed DEEP. */
const INVALID = [
  ["absent", (e) => { delete e.blockDaaScore; }, true],
  ["the empty string", (e) => { e.blockDaaScore = ""; }, true],
  ["the hex string 0x0", (e) => { e.blockDaaScore = "0x0"; }, true],
  ["the signed string -1", (e) => { e.blockDaaScore = "-1"; }, true],
  ["the plus-signed decimal string +<score>", (e) => { e.blockDaaScore = `+${e.blockDaaScore}`; }, true],
  ["the space-padded decimal string ' <score>'", (e) => { e.blockDaaScore = ` ${e.blockDaaScore}`; }, true],
  ["the fractional string 0.5", (e) => { e.blockDaaScore = "0.5"; }, false],
  ["the negative number -1", (e) => { e.blockDaaScore = -1; }, true],
  ["the fractional number 0.5", (e) => { e.blockDaaScore = 0.5; }, false],
  ["the unsafe integer number 2^53", (e) => { e.blockDaaScore = 2 ** 53; }, false],
  ["the negative bigint -1n", (e) => { e.blockDaaScore = -1n; }, true],
  ["the boolean true", (e) => { e.blockDaaScore = true; }, true],
  ["null", (e) => { e.blockDaaScore = null; }, false],
  ["an object {}", (e) => { e.blockDaaScore = {}; }, false],
  ["a one-element array [<score>]", (e) => { e.blockDaaScore = [e.blockDaaScore]; }, true]
];
/* chain.js's BigInt coercion throws on these at dc7552e. */
const THROWS_ON_DC = new Set(["the fractional string 0.5", "the fractional number 0.5", "null", "an object {}"]);
const red = (claim) => (claim ? " [RED on dc7552e]" : "");

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R1-05 journal ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- controls ---------------- */
  leg("control: the exact original effect observed DEEP (raw blockDaaScore the decimal string \"1\") completes the journaled record exactly (EFFECT_PROVEN -> manifest, receipt, one CHAIN_VERIFIED audit row, claims released, COMPLETE)", async (x) => {
    x.settle();
    const out = await x.recover();
    await assertCompleted(x, out);
  });
  leg("control: the exact original effect observed at TRUE depth 0 (raw blockDaaScore = the virtual DAA score) is below the settlement depth: PROTECTED_UNRESOLVED with nothing written", async (x) => {
    x.setBlockDaaScore(VDAA.toString()); x.settle();
    const before = await x.snap();
    const out = await x.recover();
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED"); assert.match(String(out.detail), /below the settlement depth/);
    assert.deepEqual(await x.snap(), before);
  });

  /* ---------------- invalid raw values on the judged effect -> nothing written ---------------- */
  for (const [label, mutate, claim] of INVALID) {
    leg(`the journaled record's exact effect observed DEEP with the node's raw blockDaaScore ${label} is invalid depth evidence: no completion (PROTECTED_UNRESOLVED or the equivalent 422) and nothing written${red(claim)}`, async (x) => {
      x.settle();
      const seam = rewriteAnswer(x, isEffect(x), mutate);
      const before = await x.snap();
      const run = await settle(x.recover());
      await assertRefusedNoWrite(x, run, before, `a judged blockDaaScore of ${label}`);
      assert.ok(seam.touched >= 1, "the judged effect was answered with the invalid value");
    });
  }

  /* ---------------- a judged value greater than vDaa is below depth ---------------- */
  leg("the effect's canonical raw blockDaaScore GREATER than the virtual DAA score read first is below depth: PROTECTED_UNRESOLVED with nothing written, never a completion", async (x) => {
    x.settle();
    const seam = rewriteAnswer(x, isEffect(x), (e, vDaa) => { e.blockDaaScore = String(vDaa + 5n); });
    const before = await x.snap();
    const out = await x.recover();
    assert.equal(out.outcome, "PROTECTED_UNRESOLVED"); assert.match(String(out.detail), /below the settlement depth/);
    assert.deepEqual(await x.snap(), before);
    assert.ok(seam.touched >= 1);
  });

  /* ---------------- canonical raw encodings are judged normally (K1) ---------------- */
  for (const [label, encode] of [["a non-negative bigint (the rusty-kaspa v2.0.1 WASM getter encoding)", (n) => n], ["a non-negative safe-integer number", (n) => Number(n)]]) {
    leg(`K1: the effect's raw blockDaaScore as ${label} is judged normally: at true depth 0 PROTECTED_UNRESOLVED (below depth) with nothing written, observed deep the journaled record completes exactly`, async (x) => {
      x.settle();
      let score = VDAA;
      const seam = rewriteAnswer(x, isEffect(x), (e) => { e.blockDaaScore = encode(score); });
      const before = await x.snap();
      const shallow = await x.recover();
      assert.equal(shallow.outcome, "PROTECTED_UNRESOLVED", `below depth (got ${shallow.outcome}: ${shallow.detail})`); assert.match(String(shallow.detail), /below the settlement depth/);
      assert.deepEqual(await x.snap(), before);
      score = 1n;
      await assertCompleted(x, await x.recover());
      assert.ok(seam.touched >= 2);
    });
  }

  /* ---------------- decoys at the effect's address ---------------- */
  for (const [label, mutate] of INVALID) {
    const throwsOnDc = THROWS_ON_DC.has(label);
    /* PA-01 r1 rule 2 and RC1-12 (independent RED check, LOW coverage gap): an unjudged decoy never decides the
     * answer, whatever its raw value, including values BigInt rejects; the journaled record completes exactly. */
    leg(`decoy: an unrelated covenant-less output at the effect's address carrying the raw blockDaaScore ${label} is not judged: the journaled record completes exactly${throwsOnDc ? " [RED on dc7552e]" : ""}`, async (x) => {
      x.settle();
      const decoyTxId = K.hex("r105-journal-decoy");
      const seam = rewriteAnswer(x, (e) => e.outpoint.transactionId === decoyTxId, mutate, (entries) => {
        const effect = entries.find(isEffect(x));
        return effect ? [{ ...clone(effect), outpoint: { transactionId: decoyTxId, index: 0 }, amount: String(KAS), covenantId: null, blockDaaScore: "1" }] : [];
      });
      const run = await settle(x.recover());
      assert.ok(seam.touched >= 1, "the decoy was in the node's answer");
      assert.ok(run.error === null, `an unjudged output never fails the observation (got ${run.error && String(run.error.message).slice(0, 200)})`);
      await assertCompleted(x, run.value);
    });
  }
}
