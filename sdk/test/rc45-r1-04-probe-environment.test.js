"use strict";
/*
 * RC45 R1-04 — pv_tx_probe HARNESS FAILURES ARE ENVIRONMENT ERRORS (finding
 * ST-01 = RC45-REV-SET-01 of the independent candidate review
 * rc45-patch-independent-01; remediation plan R1 revision 2, R1-04 with
 * condition C10). Internal RED-first regression material for the RC45
 * successor candidate; not an audit. Adapted from the review-only probe
 * review-settlement-a-env (settlement reviewer, sha256 f4de7de7...).
 *
 * The rule (plan R1-04): validateIdentity's describeFrozenTx / runTxProbe
 * failures of these classes ONLY are environment errors, answered by the
 * Verify settlement pass with 422 RECONCILE_FAILED and nothing written:
 *   - missing binary (ENOENT): the binary absent at runTxProbe's pre-spawn
 *     check, and the spawn itself failing ENOENT;
 *   - spawn error (EAGAIN: a failed fork);
 *   - termination by signal (a real child killed by SIGKILL);
 *   - temp-file I/O error: create (ENOSPC at open), write (EIO at write),
 *     read (the probe cannot read its input file: the file is gone when the
 *     real pv_tx_probe opens it, and unlinking it then fails ENOENT; and,
 *     R1-04b, the file left present but unreadable (EACCES), so its unlink
 *     succeeds and only runTxProbe's "cannot read" branch marks the error;
 *     needs a non-root runner, as the rc45 runner is) and unlink (EIO at
 *     unlink after a successful probe run).
 * A probe rejection (the real pv_tx_probe ran and refused its input) or an
 * invalid output shape (not JSON; JSON without a 64-hex txId) stays a RECORD
 * defect: that record alone is excluded, so one bad record cannot make every
 * Verify 422. In a terminal settlement a loser that failed validation for an
 * environment reason aborts the pass with 422.
 *
 * RED on dc7552e: describeFrozenTx is not wrapped in environmentStep
 * (sdk/src/wallet-recovery-v4.js validateIdentity, frozen-tx-v3.js
 * runTxProbe), so validated() (reconcile-v4.js) silently excludes the record:
 * a terminal settlement writes RECOVERED with the loser left PENDING (settled
 * []), a non-terminal one completes the winner and leaves the loser, and a
 * failing primary turns the outage into a chain verdict (CHAIN_CONTRADICTION).
 * HOLDS on dc7552e (and must keep holding): probe rejection and invalid
 * output shape exclude only their record; a pv_vm_preflight spawn failure is
 * already an environment error (422).
 *
 * Fault seams (TEST only): child_process.spawnSync is wrapped BEFORE any
 * sdk/src module loads (frozen-tx-v3.js and vm-preflight.js destructure it at
 * load), and fs.writeFileSync / fs.existsSync / fs.unlinkSync are wrapped for
 * the pv_tx_probe temp file (os.tmpdir()/pv3-frozen-<pid>-<uuid>.json) and the
 * TX_PROBE_PATH pre-check only; every other path passes through. A fault is
 * aimed at ONE record by the exact canonical frozen-transaction JSON that
 * validateIdentity hands to the probe (never by call order), or at every
 * describe call. Real children are used wherever a real failure exists: a
 * spawn of a nonexistent binary path (ENOENT), /bin/sh killing itself with
 * SIGKILL, the real pv_tx_probe reading a removed input file, the real
 * pv_tx_probe refusing a version-2 descriptor, and /bin/sh printing a non-JSON
 * or wrongly shaped answer. A failed fork (EAGAIN) and the ENOSPC / EIO file
 * errors cannot be produced on demand and are returned / thrown in the exact
 * shape Node gives them. Every faulted leg asserts the fault actually fired,
 * so a moved I/O seam fails loudly instead of passing silently. The seams bind
 * to dc7552e's runTxProbe / withFrozenFile calls (spawnSync, writeFileSync,
 * existsSync after the write, unlinkSync).
 *
 * Population (CANDIDATE-WRITTEN, the probe's setup): per vault a delegate
 * agentSpend D (4 KAS) and the owner's break-glass Q on the genesis outpoint
 * L0, finalized apart with the real v0.4.1 compiler, pv_call_encoder,
 * deterministic dev signer (TEST keys) and pinned pv_vm_preflight, and merged
 * (sdk/testutil/rc45-f5-kit.js finalizeApart): D holds the only claim on L0.
 * cr: Q = ownerRecover (terminal); cp: Q = ownerPause (non-terminal). Q lands
 * on the explicit chain model of sdk/testutil/rc45-f5-kit.js and deepens to
 * D = 1,000 DAA. Nothing dials a node: every config names ws://127.0.0.1:1.
 *
 * Layers: SDK (reconcileVaultV4) and API (POST /vaults/:id/reconcile through
 * server/src/api.js handle, self-hosted; the route-level Verify wraps the
 * module-cache export of the REAL reconcileVaultV4 to pass the model's rpc,
 * plan r2 §8 rules CR-M14, CR2-L12). Both stores: JSON always; PostgreSQL
 * with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */

/* ---------------- fault seams: installed before any sdk/src module loads ---------------- */
const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const realSpawnSync = cp.spawnSync;
const real = { writeFileSync: fs.writeFileSync, existsSync: fs.existsSync, unlinkSync: fs.unlinkSync };
const FROZEN_TMP = /[\\/]pv3-frozen-\d+-[0-9a-f-]{36}\.json$/;
const PREFLIGHT_TMP = /[\\/]pv-preflight-\d+-[0-9a-f-]{36}\.json$/;
const fault = { plan: null, current: null, fired: 0, vmTarget: null, vmArmed: false, vmFired: 0, leftovers: [] };
let txProbePath = null;
const ioError = (code, errno, syscall, file, text) => Object.assign(new Error(`${code}: ${text}, ${syscall} '${file}'`), { code, errno, syscall, path: file });
const forkFailure = (name) => ({ pid: 0, output: [null, "", ""], stdout: "", stderr: "", status: null, signal: null,
  error: Object.assign(new Error(`spawnSync ${name} EAGAIN`), { code: "EAGAIN", errno: -11, syscall: `spawnSync ${name}`, path: name, spawnargs: [] }) });

fs.writeFileSync = function writeFileSyncSeam(file, data, options) {
  if (typeof file === "string" && FROZEN_TMP.test(file)) {
    const plan = fault.plan, hit = Boolean(plan && plan.target(String(data)));
    fault.current = { file, hit };
    if (hit && plan.cls === "tmp-create") {
      fault.current = null; fault.fired += 1;
      throw ioError("ENOSPC", -28, "open", file, "no space left on device");
    }
    if (hit && plan.cls === "tmp-write") {
      real.writeFileSync.call(fs, file, "", options); // open (create) succeeded; the write fails
      fault.leftovers.push(file); fault.current = null; fault.fired += 1;
      throw ioError("EIO", -5, "write", file, "i/o error");
    }
  }
  if (typeof file === "string" && PREFLIGHT_TMP.test(file)) fault.vmArmed = fault.vmTarget !== null && String(data) === fault.vmTarget;
  return real.writeFileSync.apply(fs, arguments);
};
fs.existsSync = function existsSyncSeam(file) {
  if (fault.plan && fault.plan.cls === "binary-absent" && fault.current && fault.current.hit && txProbePath !== null && file === txProbePath) {
    fault.fired += 1;
    return false;
  }
  return real.existsSync.apply(fs, arguments);
};
fs.unlinkSync = function unlinkSyncSeam(file) {
  if (typeof file === "string" && FROZEN_TMP.test(file)) {
    const cur = fault.current; fault.current = null;
    if (cur && cur.hit && fault.plan && fault.plan.cls === "tmp-unlink") {
      real.unlinkSync.call(fs, file); fault.fired += 1;
      throw ioError("EIO", -5, "unlink", file, "i/o error");
    }
  }
  return real.unlinkSync.apply(fs, arguments);
};
cp.spawnSync = function spawnSyncSeam(file, args, options) {
  const f = String(file);
  if (f.endsWith("pv_tx_probe") && Array.isArray(args) && args[0] === "describe" && fault.plan && fault.current && fault.current.hit) {
    const cls = fault.plan.cls;
    if (cls === "binary-enoent") { fault.fired += 1; return realSpawnSync.call(this, path.join(path.dirname(f), "pv_tx_probe.absent-TEST"), args, options); }
    if (cls === "spawn-eagain") { fault.fired += 1; return forkFailure(f); }
    if (cls === "signal") { fault.fired += 1; return realSpawnSync.call(this, "/bin/sh", ["-c", "kill -KILL $$"], options); }
    if (cls === "tmp-read") { fault.fired += 1; real.unlinkSync.call(fs, args[1]); return realSpawnSync.call(this, file, args, options); }
    // RC45 section 6 sabotage gap (R1-04 S4, rc45-suites-02): keep the input file present but unreadable, so the
    // harness's own unlink succeeds and only runTxProbe's "cannot read <path>" branch can mark the failure.
    if (cls === "tmp-read-eacces") {
      fault.fired += 1; fs.chmodSync(args[1], 0o000);
      try { return realSpawnSync.call(this, file, args, options); } finally { fs.chmodSync(args[1], 0o600); }
    }
    if (cls === "probe-rejects") {
      fault.fired += 1;
      real.writeFileSync.call(fs, args[1], JSON.stringify({ ...JSON.parse(fs.readFileSync(args[1], "utf8")), version: 2 }));
      return realSpawnSync.call(this, file, args, options);
    }
    if (cls === "invalid-json") { fault.fired += 1; return realSpawnSync.call(this, "/bin/sh", ["-c", "printf 'pv_tx_probe TEST: this is not json\\n'"], options); }
    if (cls === "bad-shape") { fault.fired += 1; return realSpawnSync.call(this, "/bin/sh", ["-c", "printf '{\"txId\":\"not-a-txid\",\"sighashAll\":[]}\\n'"], options); }
  }
  if (f.endsWith("pv_vm_preflight") && fault.vmArmed) { fault.vmFired += 1; return forkFailure(f); }
  return realSpawnSync.apply(this, arguments);
};

/* ---------------- the suite ---------------- */
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const ftx = require(path.join(SDK_SRC, "frozen-tx-v3.js"));
txProbePath = ftx.TX_PROBE_PATH;
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ cr: K.vault("r104-cr"), cp: K.vault("r104-cp") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);

async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  assert.equal(typeof txProbePath, "string");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r104-template-"), rpcUrl: LOOPBACK });
  const w = K.walletsFor(template), k = K.kitFor(cand, template, w);
  B = {};
  for (const [tag, action] of [["cr", "ownerRecover"], ["cp", "ownerPause"]]) {
    // Contested break-glass (CANDIDATE-WRITTEN, finalized apart and merged as rc45-t3 does): the delegate's agentSpend D
    // holds the only claim on L0; the owner's Q is PREFLIGHT_VERIFIED without a claim.
    const v = V[tag]; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, action); await K.sleep(3);
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B[tag] = { d: d.requestId, q: q.requestId };
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  fault.plan = null; fault.vmTarget = null; fault.vmArmed = false;
  for (const file of fault.leftovers) { try { real.unlinkSync.call(fs, file); } catch { /* gone */ } }
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r104-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r104_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config), api = F3.apiFor(config);
  const x = {
    config, store, model, pgDatabase, api,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    events: async () => (await require("../../server/src/events-store").getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 })).map((r) => JSON.stringify(r.event)),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc })
  };
  /* POST /vaults/:id/reconcile (self-hosted) through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
  x.verifyRoute = async (v) => {
    const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
    m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: model.rpc });
    try { return await api.call("POST", ["vaults", v.vaultId, "reconcile"], {}); } finally { m4.reconcileVaultV4 = real4; }
  };
  return x;
}
async function release(x) {
  fault.plan = null; fault.current = null; fault.vmTarget = null; fault.vmArmed = false;
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
/* The exact descriptor validateIdentity hands pv_tx_probe for `r` (its normalized frozen transaction, canonical JSON). */
const descriptorOf = (r) => ftx.canonicalFrozenTxJson(ftx.normalizeFrozenTxV3(r.build.frozen));
/* Run `fn` with the fault `cls` aimed at the records whose descriptor is in `targets` (or at every describe call). */
async function underFault(cls, targets, fn) {
  const set = targets === "all" ? null : new Set(targets.map(descriptorOf));
  fault.fired = 0; fault.current = null;
  fault.plan = { cls, target: (data) => set === null || set.has(data) };
  try { return await fn(); } finally { fault.plan = null; fault.current = null; }
}
/* Q lands on the explicit chain model and deepens to D (its inputs L0 and the owner's fuel live and deep first). */
function landAtDepth(x, q) {
  x.model.seedInputs(frozenOf(q), q.covenantId);
  x.model.confirm(frozenOf(q), q.txId);
  x.model.advance(SETTLE_DEPTH_DAA);
}
/* After the environment recovers, one healthy Verify settles everything the faulted pass refused to settle. */
async function healthyConverges(x, v, d, q, terminal) {
  const done = await resolved(() => x.verify(v), "a healthy Verify answers");
  assert.equal(done.status, "ADVANCED", `the healthy Verify completes the winner (got ${JSON.stringify(done)})`);
  assert.equal(done.txId, q.txId);
  const m = await x.rawManifest(v);
  if (terminal) { assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); } else assert.equal(m.status, "PAUSED");
  assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal((await x.rawRequest(d.requestId)).state, "STALE", "the loser is superseded STALE (plan L-15: losers are settled, never left PENDING)");
  assert.equal(await x.claimOn(d.predecessorOutpoint), null, "the loser's claim is released");
  assert.equal(await x.reservationOf(d), null, "the loser's reservation is released");
}

const ENV_CLASSES = [
  ["binary-absent", "missing binary: pv_tx_probe absent at runTxProbe's pre-spawn check"],
  ["binary-enoent", "missing binary: the spawn fails ENOENT (a real spawn of a nonexistent binary path)"],
  ["spawn-eagain", "spawn error: a failed fork (EAGAIN)"],
  ["signal", "termination by signal: the child is killed by SIGKILL (a real /bin/sh killing itself)"],
  ["tmp-create", "temp-file create error: ENOSPC at open"],
  ["tmp-write", "temp-file write error: EIO at write"],
  ["tmp-read", "temp-file read error: the real pv_tx_probe cannot read its input file (removed before it opens it; unlinking it then fails ENOENT)"],
  ["tmp-unlink", "temp-file unlink error: EIO at unlink after a successful probe run"],
  ["tmp-read-eacces", "temp-file read error: the real pv_tx_probe cannot read its input file (left present but unreadable, EACCES; its unlink then succeeds, so only the probe's own read failure marks the error)"]
];

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R1-04 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- environment classes -> 422 RECONCILE_FAILED, nothing written ---------------- */
  for (const [cls, label] of ENV_CLASSES) {
    leg(`terminal settlement (contested Close & recover confirmed at D): ${label} while validating the delegate LOSER aborts the pass with 422 RECONCILE_FAILED and nothing written (never RECOVERED with the loser left PENDING); a healthy Verify then writes RECOVERED with the loser STALE [RED on dc7552e]`, async (x) => {
      const d = await x.req(B.cr.d), q = await x.req(B.cr.q);
      assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId, "the delegate holds the only claim on L0");
      landAtDepth(x, q);
      const before = await x.snap();
      const run = await underFault(cls, [d], () => x.verify(V.cr).then((value) => ({ value, error: null }), (error) => ({ value: null, error })));
      assert.ok(fault.fired >= 1, `the ${cls} fault fired while the loser was validated`);
      assert.equal(run.error?.code, "RECONCILE_FAILED", `an environment failure of the pv_tx_probe harness aborts the terminal settlement with 422 (observed ${JSON.stringify(run.value ?? { message: run.error?.message })})`);
      assert.deepEqual(await x.snap(), before, "nothing is written");
      await healthyConverges(x, V.cr, d, q, true);
    });
    leg(`non-terminal settlement (contested Pause confirmed at D): ${label} while validating the delegate LOSER is a 422 RECONCILE_FAILED with nothing written (never a completed winner beside an unvalidated loser); a healthy Verify then completes the Pause and supersedes the loser [RED on dc7552e]`, async (x) => {
      const d = await x.req(B.cp.d), q = await x.req(B.cp.q);
      landAtDepth(x, q);
      const before = await x.snap();
      const run = await underFault(cls, [d], () => x.verify(V.cp).then((value) => ({ value, error: null }), (error) => ({ value: null, error })));
      assert.ok(fault.fired >= 1, `the ${cls} fault fired while the loser was validated`);
      assert.equal(run.error?.code, "RECONCILE_FAILED", `an environment failure of the pv_tx_probe harness is a 422 (observed ${JSON.stringify(run.value ?? { message: run.error?.message })})`);
      assert.deepEqual(await x.snap(), before, "nothing is written");
      await healthyConverges(x, V.cp, d, q, false);
    });
    leg(`harness down (every describe call fails): ${label} while validating the CONFIRMED primary (the owner's contested Pause at D) is a 422 RECONCILE_FAILED with nothing written, never a chain verdict (CHAIN_CONTRADICTION / UNKNOWN); a healthy Verify then completes the Pause [RED on dc7552e]`, async (x) => {
      const d = await x.req(B.cp.d), q = await x.req(B.cp.q);
      landAtDepth(x, q);
      const before = await x.snap();
      const run = await underFault(cls, "all", () => x.verify(V.cp).then((value) => ({ value, error: null }), (error) => ({ value: null, error })));
      assert.ok(fault.fired >= 1, `the ${cls} fault fired while the primary was validated`);
      assert.equal(run.error?.code, "RECONCILE_FAILED", `a harness outage is answered as unavailability (422), not as a chain verdict (observed ${JSON.stringify(run.value ?? { message: run.error?.message })})`);
      assert.deepEqual(await x.snap(), before, "nothing is written");
      await healthyConverges(x, V.cp, d, q, false);
    });
  }

  /* ---------------- the hosted Verify route answers the environment error 422 ---------------- */
  leg("hosted Verify route (self-hosted POST /vaults/:id/reconcile): a failed fork (EAGAIN) of pv_tx_probe while validating the terminal settlement's loser answers 422 RECONCILE_FAILED with nothing written and no vault.reconciled event [RED on dc7552e]", async (x) => {
    const d = await x.req(B.cr.d), q = await x.req(B.cr.q);
    landAtDepth(x, q);
    const before = await x.snap(), events = await x.events();
    const out = await underFault("spawn-eagain", [d], () => x.verifyRoute(V.cr));
    assert.ok(fault.fired >= 1, "the fault fired while the loser was validated");
    assert.equal(out.status, 422, `the route answers 422 (observed ${out.status} ${JSON.stringify(out.body?.reconcile ?? out.message)})`);
    assert.equal(out.code, "RECONCILE_FAILED");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assert.deepEqual(await x.events(), events, "no vault.reconciled event");
  });

  /* ---------------- record defects exclude only their record (HOLDS) ---------------- */
  leg("a probe REJECTION (the real pv_tx_probe refuses the loser's descriptor: version 2) is a record defect: only the loser is excluded; the terminal settlement completes (ADVANCED, RECOVERED) and the excluded loser stays byte-identical, so one bad record cannot make every Verify 422", async (x) => {
    const d = await x.req(B.cr.d), q = await x.req(B.cr.q), dBefore = await x.rawRequest(d.requestId);
    landAtDepth(x, q);
    const out = await underFault("probe-rejects", [d], () => resolved(() => x.verify(V.cr), "a probe rejection is no 422"));
    assert.ok(fault.fired >= 1, "the rejection fault fired while the loser was validated");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, q.txId); assert.equal(out.to, "RECOVERED");
    assert.equal((await x.rawManifest(V.cr)).status, "RECOVERED");
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the loser whose record failed validation is excluded and untouched");
  });
  leg("an invalid probe OUTPUT (not JSON) for the non-terminal loser is a record defect: only the loser is excluded; the Pause completes and the excluded loser stays byte-identical", async (x) => {
    const d = await x.req(B.cp.d), q = await x.req(B.cp.q), dBefore = await x.rawRequest(d.requestId);
    landAtDepth(x, q);
    const out = await underFault("invalid-json", [d], () => resolved(() => x.verify(V.cp), "an invalid probe output is no 422"));
    assert.ok(fault.fired >= 1, "the invalid-output fault fired while the loser was validated");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.txId, q.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the loser whose record failed validation is excluded and untouched");
  });
  leg("an invalid probe output SHAPE (JSON without a 64-hex txId) for the terminal loser is a record defect: only the loser is excluded; the terminal settlement completes and the excluded loser stays byte-identical", async (x) => {
    const d = await x.req(B.cr.d), q = await x.req(B.cr.q), dBefore = await x.rawRequest(d.requestId);
    landAtDepth(x, q);
    const out = await underFault("bad-shape", [d], () => resolved(() => x.verify(V.cr), "an invalid probe output shape is no 422"));
    assert.ok(fault.fired >= 1, "the shape fault fired while the loser was validated");
    assert.equal(out.status, "ADVANCED"); assert.equal(out.to, "RECOVERED");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the loser whose record failed validation is excluded and untouched");
  });
  leg("a probe REJECTION of the confirmed primary's own descriptor is a record defect, not unavailability: Verify answers (no 422) and writes nothing", async (x) => {
    const q = await x.req(B.cp.q);
    landAtDepth(x, q);
    const before = await x.snap();
    const out = await underFault("probe-rejects", [q], () => resolved(() => x.verify(V.cp), "a probe rejection of the primary is no 422"));
    assert.ok(fault.fired >= 1, "the rejection fault fired while the primary was validated");
    assert.notEqual(out.status, "ADVANCED", "an excluded record is never completed");
    assert.deepEqual(await x.snap(), before, "nothing is written");
  });
  leg("CONTROL (probe A0): a pv_vm_preflight spawn failure (EAGAIN) while validating the terminal settlement's loser is already an environment error: 422 RECONCILE_FAILED, nothing written", async (x) => {
    const d = await x.rawRequest(B.cr.d), q = await x.req(B.cr.q);
    landAtDepth(x, q);
    const before = await x.snap();
    fault.vmFired = 0; fault.vmTarget = JSON.stringify(d.finalTransaction); // the descriptor runPreflight writes for the loser's inputs
    let run;
    try { run = await x.verify(V.cr).then((value) => ({ value, error: null }), (error) => ({ value: null, error })); } finally { fault.vmTarget = null; fault.vmArmed = false; }
    assert.ok(fault.vmFired >= 1, "the VM harness fault fired while the loser was validated");
    assert.equal(run.error?.code, "RECONCILE_FAILED", `the VM harness spawn failure is a 422 (observed ${JSON.stringify(run.value)})`);
    assert.deepEqual(await x.snap(), before, "nothing is written");
  });
}
