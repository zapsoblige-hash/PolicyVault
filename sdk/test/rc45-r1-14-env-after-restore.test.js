"use strict";
/*
 * RC45 R1-14 (O2) — AN ENVIRONMENT FAILURE AFTER A WRITE IN THE SAME PASS SAYS
 * WHAT WAS WRITTEN (design amendment PA-R1-02 "R1-14", independent design check
 * conditions C2, C3 and C4; plan R1 revision 2 budget unchanged: text only, no
 * new field, code or order). Internal RED-first regression material for the
 * RC45 successor candidate; not an audit.
 *
 * The window (C2): at ecb9928 the only durable write that can come before an
 * environment error in the same Verify pass is restore() (settleLive, a
 * TERMINATED_UNKNOWN vault observed live at depth). After it come the
 * validated() calls of settleOneHop's lastHop and receiptFinishable; an R1-04
 * environment error there answers 422 RECONCILE_FAILED "… — nothing was
 * written" (reconcile-v4.js validated), which is false: the restore was
 * written. Rule (PA-R1-02 R1-14 with C2): that 422 keeps its code
 * (RECONCILE_FAILED), the pass's writes and their order are unchanged, and its
 * message replaces "nothing was written" with an exact statement that names
 * the restore and only the restore (C2: finishRecordedV4, settleOneHop,
 * completePositive and recoverEvidence validate every record before their
 * first write, so no request can have been settled before the failure; the
 * message names no settled request). An environment error before any write
 * keeps its "nothing was written" text. C4: request-scoped recovery
 * (settleJournalFree) quotes the pass's RECONCILE_FAILED message in its
 * PROTECTED_UNRESOLVED detail; after a restore that detail names the restore
 * and does not say "nothing was written".
 *
 * RED on ecb9928: after the restore the 422 message (SDK, hosted route) and
 * the request-scoped PROTECTED_UNRESOLVED detail say "nothing was written".
 * HOLDS on ecb9928 (and must keep holding): the code (422 RECONCILE_FAILED,
 * PROTECTED_UNRESOLVED), the durable effect of the failed pass (exactly the
 * restore: one manifest write and one reconciled_advanced {via: "restored"}
 * row); with no restore (a live vault) the same failure writes nothing and
 * says "nothing was written"; after the environment recovers, a healthy
 * Verify converges.
 *
 * C3 population: a TERMINATED_UNKNOWN vault whose lastTransition.newOutpoint
 * is the observed L at depth >= D, with validated() really reached after the
 * restore: a PENDING record on lastTransition.oldOutpoint (lastHop would
 * otherwise return before validating anything). CANDIDATE-WRITTEN (TEST keys
 * 0x11 owner / 0x21 agent; an F5 kit vault): the delegate's spend D and the
 * owner's Pause Q on L0, finalized apart and merged (D holds the only claim);
 * Q lands and deepens to D (depth); Verify completes Q and is stopped
 * (SYNTHETIC in-process store fault) at the loser's transition_superseded row,
 * so the manifest records Q's advance and D stays PENDING on L0 with its claim
 * and reservation (the R1-07 "sp" shape). SYNTHETIC RC44 case E (as review
 * probe P2b made it): the manifest rewritten TERMINATED_UNKNOWN with live =
 * null, lastTransition kept. The R1-04 environment class is injected at Q's
 * validation inside lastHop (the winners are validated first), aimed at Q by
 * the exact canonical frozen-transaction JSON validateIdentity hands to
 * pv_tx_probe, never by call order: temp-file create error (ENOSPC at open,
 * thrown in the exact shape Node gives it) and spawn error (a failed fork,
 * EAGAIN, returned in the exact shape spawnSync gives it). Every faulted leg
 * asserts the fault fired. Request-scoped recovery recovers D, whose own
 * validation (another descriptor) is never faulted.
 *
 * Fault seams (TEST only): child_process.spawnSync is wrapped BEFORE any
 * sdk/src module loads (frozen-tx-v3.js destructures it at load);
 * fs.writeFileSync is wrapped for the pv_tx_probe temp file only
 * (os.tmpdir()/pv3-frozen-<pid>-<uuid>.json); every other call passes through.
 *
 * Layers: SDK (reconcileVaultV4, reconcileTransitionWalletRequestV4) and API
 * (POST /vaults/:id/reconcile through the self-hosted server/src/api.js
 * handle; the route wraps the module-cache export of the REAL
 * reconcileVaultV4 to pass the model's rpc). Real v0.4.1 compiler,
 * pv_call_encoder, TEST-key signatures and the pinned pv_vm_preflight. Node
 * observations come only from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js; every config names ws://127.0.0.1:1, so nothing
 * can dial a node. Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */

/* ---------------- fault seams: installed before any sdk/src module loads ---------------- */
const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const realSpawnSync = cp.spawnSync, realWriteFileSync = fs.writeFileSync;
const FROZEN_TMP = /[\\/]pv3-frozen-\d+-[0-9a-f-]{36}\.json$/;
const fault = { plan: null, current: false, fired: 0, cause: null };
fs.writeFileSync = function writeFileSyncSeam(file, data, options) {
  if (typeof file === "string" && FROZEN_TMP.test(file)) {
    const hit = Boolean(fault.plan && fault.plan.target(String(data)));
    fault.current = hit;
    if (hit && fault.plan.cls === "tmp-create") {
      fault.current = false; fault.fired += 1;
      fault.cause = `ENOSPC: no space left on device, open '${file}'`;
      throw Object.assign(new Error(fault.cause), { code: "ENOSPC", errno: -28, syscall: "open", path: file });
    }
  }
  return realWriteFileSync.apply(fs, arguments);
};
cp.spawnSync = function spawnSyncSeam(file, args) {
  const f = String(file);
  if (f.endsWith("pv_tx_probe") && Array.isArray(args) && args[0] === "describe" && fault.plan && fault.current && fault.plan.cls === "spawn-eagain") {
    fault.current = false; fault.fired += 1;
    fault.cause = `spawnSync ${f} EAGAIN`;
    return { pid: 0, output: [null, "", ""], stdout: "", stderr: "", status: null, signal: null,
      error: Object.assign(new Error(fault.cause), { code: "EAGAIN", errno: -11, syscall: `spawnSync ${f}`, path: f, spawnargs: [] }) };
  }
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
const recovery4 = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ sp: K.vault("r114-restore-window") });
const NOTHING_WRITTEN = /nothing was written/i;
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (o) => (o.error ? `${o.error.code ?? "no code"}: ${String(o.error.message).slice(0, 400)}` : JSON.stringify(o.value).slice(0, 400));

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r114-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "self-hosted template");
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w);
  const v = V.sp; await K.seedVault(cand, template, v, w);
  const d = await k.agentSpend(v, 4); await K.sleep(3);
  const q = await k.ownerOp(v, "ownerPause");
  await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
  B = { d: d.requestId, q: q.requestId };
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  fault.plan = null; fault.current = false;
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r114-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r114_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  assert.equal(config.tenancyEnforced, false, "self-hosted case");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config), api = F3.apiFor(config);
  return {
    config, store, model, pgDatabase, api,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    recover: (requestId) => recovery4.reconcileTransitionWalletRequestV4({ config, requestId, rpc: model.rpc }),
    /* POST /vaults/:id/reconcile (self-hosted) through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
    async verifyRoute(v) {
      const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
      m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: model.rpc });
      try { return await api.call("POST", ["vaults", v.vaultId, "reconcile"], {}); } finally { m4.reconcileVaultV4 = real4; }
    }
  };
}
async function release(x) {
  fault.plan = null; fault.current = false;
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

/* One in-process store fault (the next matching durable step throws instead of being performed). SYNTHETIC interruption. */
function storeFault(store, when) {
  const names = ["write", "createExclusive", "remove", "appendAudit"], own = {};
  let fired = false;
  for (const name of names) {
    own[name] = Object.prototype.hasOwnProperty.call(store, name) ? store[name] : undefined;
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (!fired && when(name, args)) { fired = true; throw Object.assign(new Error(`TEST store fault at ${name}`), { code: "ECONNRESET" }); }
      return original(...args);
    };
  }
  return { get fired() { return fired; }, restore() { for (const name of names) { if (own[name] === undefined) delete store[name]; else store[name] = own[name]; } } };
}
/* The exact descriptor validateIdentity hands pv_tx_probe for `r` (its normalized frozen transaction, canonical JSON). */
const descriptorOf = (r) => ftx.canonicalFrozenTxJson(ftx.normalizeFrozenTxV3(r.build.frozen));
/* Run `fn` with the environment fault `cls` aimed at `target`'s describe call(s) only. */
async function underFault(cls, target, fn) {
  const descriptor = descriptorOf(target);
  fault.fired = 0; fault.current = false; fault.cause = null;
  fault.plan = { cls, target: (data) => data === descriptor };
  try { return await fn(); } finally { fault.plan = null; fault.current = false; }
}

/*
 * Q completes (Verify at depth) and the pass is stopped at its loser's transition_superseded row: the manifest records
 * Q's advance (lastTransition: L0 -> L1) and D stays PENDING on L0 = lastTransition.oldOutpoint with its claim and
 * reservation. With `terminated`, the manifest is then rewritten TERMINATED_UNKNOWN with live = null (SYNTHETIC RC44
 * case E), lastTransition kept, so the next pass restores the vault from lastRecordedLive.
 */
async function population(x, { terminated }) {
  const v = V.sp, q = await x.req(B.q), d = await x.req(B.d);
  x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const f = storeFault(x.store, (name, args) => name === "appendAudit" && args[0] && args[0].action === "transition_superseded");
  let first;
  try { first = await settle(x.verify(v)); } finally { f.restore(); }
  assert.equal(f.fired, true, `the completion reached the loser's transition_superseded row (${said(first)})`);
  assert.ok(first.error && /TEST store fault/.test(String(first.error.message)), `the fault stopped it (${said(first)})`);
  const m = await x.rawManifest(v);
  assert.equal(m.latestTransitionTxId, q.txId); assert.equal(m.lastTransition.txId, q.txId);
  assert.deepEqual(m.lastTransition.oldOutpoint, d.predecessorOutpoint, "D is on lastTransition.oldOutpoint");
  assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal((await x.rawRequest(d.requestId)).state, "PREFLIGHT_VERIFIED", "D is PENDING and not yet superseded");
  assert.equal(await recovery4.isPendingTransitionV4(x.config, d), true);
  assert.equal((await x.claimOn(d.predecessorOutpoint))?.txId, d.txId, "D still holds its claim on L0");
  if (terminated) {
    await x.store.write(Categories.VAULT, v.vaultId, { ...m, status: "TERMINATED_UNKNOWN", live: null }); // SYNTHETIC RC44 case E
    assert.equal((await x.rawManifest(v)).status, "TERMINATED_UNKNOWN");
  }
  return { v, q, d, m };
}
/* The failed pass's durable effect is exactly the restore: the manifest live again at Q's successor, one
 * reconciled_advanced {via: "restored"} row, and nothing else (no request, claim, reservation or receipt written). */
function assertExactlyTheRestore(beforeSnap, afterSnap, p, label) {
  const changed = Object.keys(afterSnap.records).filter((c) => JSON.stringify(afterSnap.records[c]) !== JSON.stringify(beforeSnap.records[c]));
  assert.deepEqual(changed, [Categories.VAULT], `${label}: only the manifest changed`);
  const m = (afterSnap.records[Categories.VAULT].find(([k]) => k === p.v.vaultId) ?? [])[1];
  assert.equal(m.status, "PAUSED", `${label}: the vault was restored (TERMINATED_UNKNOWN -> PAUSED, Q's ownerPause successor)`);
  assert.deepEqual({ transactionId: m.live.outpoint.transactionId, index: Number(m.live.outpoint.index) }, p.m.lastTransition.newOutpoint, `${label}: live = the recorded successor L1`);
  const added = afterSnap.audit.filter((row) => !beforeSnap.audit.some((b) => JSON.stringify(b) === JSON.stringify(row)));
  assert.deepEqual(added.map((row) => [row.action, row.via]), [["reconciled_advanced", "restored"]], `${label}: exactly one audit row, the restore's`);
  assert.equal(afterSnap.audit.length, beforeSnap.audit.length + 1, `${label}: no audit row removed or replaced`);
}
/* The failure text after a restore (C2): it names the restore and only the restore, never "nothing was written". */
function assertNamesTheRestore(text, cause, label) {
  assert.ok(typeof cause === "string" && text.includes(cause), `${label}: the environment cause is kept (${cause}); it says: ${text}`);
  const own = text.split(cause).join(" ");
  assert.doesNotMatch(own, NOTHING_WRITTEN, `${label}: after the restore was written the text never says "nothing was written" (PA-R1-02 R1-14); it says: ${text}`);
  assert.match(own, /\brestor/i, `${label}: it names the restore that was written before the failure; it says: ${text}`);
  assert.doesNotMatch(own, /\bsettled\b/i, `${label}: it names only the restore (C2: no request can be settled before the failure); it says: ${text}`);
}

const ENV = [["tmp-create", "a temp-file create error (ENOSPC at open)"], ["spawn-eagain", "a spawn error (a failed fork, EAGAIN)"]];
const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r114 = (name, fn) => test(`RC45 R1-14 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- RED: an environment failure after the restore ---------------- */
  for (const [cls, label] of ENV) {
    r114(`SDK Verify of the TERMINATED_UNKNOWN vault (L1 live at depth D): the pass restores the vault, then ${label} while lastHop validates the winner Q answers 422 RECONCILE_FAILED; its durable effect is exactly the restore, and its message names the restore and never says "nothing was written" [RED on ecb9928]`, async (x) => {
      const p = await population(x, { terminated: true });
      const beforeSnap = await x.snap();
      const run = await underFault(cls, p.q, () => settle(x.verify(p.v)));
      assert.ok(fault.fired >= 1, `the ${cls} fault fired at Q's validation`);
      assert.equal(run.error?.code, "RECONCILE_FAILED", `the environment failure keeps its code (got ${said(run)})`);
      assertExactlyTheRestore(beforeSnap, await x.snap(), p, "SDK");
      assertNamesTheRestore(String(run.error.message), fault.cause, "SDK 422 message");
    });
  }
  r114("hosted Verify route (self-hosted POST /vaults/:id/reconcile) of the TERMINATED_UNKNOWN vault: the restore, then a temp-file create error while lastHop validates Q answers 422 RECONCILE_FAILED; its durable effect is exactly the restore, and its message names the restore and never says \"nothing was written\" [RED on ecb9928]", async (x) => {
    const p = await population(x, { terminated: true });
    const beforeSnap = await x.snap();
    const r = await underFault("tmp-create", p.q, () => x.verifyRoute(p.v));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation");
    assert.equal(`${r.status} ${r.code}`, "422 RECONCILE_FAILED", `the route keeps its code (got ${r.status} ${r.code} ${r.message})`);
    assertExactlyTheRestore(beforeSnap, await x.snap(), p, "route");
    assertNamesTheRestore(String(r.message), fault.cause, "route 422 message");
  });
  r114("request-scoped recovery (C4: settleJournalFree) of the PENDING D on the TERMINATED_UNKNOWN vault: the pass restores the vault, then a temp-file create error while lastHop validates Q; the answer is PROTECTED_UNRESOLVED with D byte-identical and the durable effect exactly the restore, and its detail names the restore and never says \"nothing was written\" [RED on ecb9928]", async (x) => {
    const p = await population(x, { terminated: true });
    const dRaw = await x.rawRequest(p.d.requestId), beforeSnap = await x.snap();
    const run = await underFault("tmp-create", p.q, () => settle(x.recover(p.d.requestId)));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation inside the pass (D's own validation is another descriptor)");
    assert.equal(run.error, null, `request-scoped recovery answers (${said(run)})`);
    assert.equal(run.value.outcome, "PROTECTED_UNRESOLVED", `the pass's 422 is PROTECTED_UNRESOLVED (got ${run.value.outcome}: ${run.value.detail})`);
    assert.deepEqual(await x.rawRequest(p.d.requestId), dRaw, "D is byte-identical");
    assertExactlyTheRestore(beforeSnap, await x.snap(), p, "request-scoped recovery");
    assertNamesTheRestore(String(run.value.detail), fault.cause, "PROTECTED_UNRESOLVED detail");
  });

  /* ---------------- HOLDS ---------------- */
  r114("holds: the same failure with NO restore (the vault live at L1, depth D): SDK Verify answers 422 RECONCILE_FAILED saying \"nothing was written\", and nothing is written", async (x) => {
    const p = await population(x, { terminated: false });
    const beforeSnap = await x.snap();
    const run = await underFault("tmp-create", p.q, () => settle(x.verify(p.v)));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation");
    assert.equal(run.error?.code, "RECONCILE_FAILED", `got ${said(run)}`);
    assert.match(String(run.error.message), NOTHING_WRITTEN, "an environment error before any write keeps its text");
    assert.ok(String(run.error.message).includes(fault.cause), "and its cause");
    assert.deepEqual(await x.snap(), beforeSnap, "nothing is written");
  });
  r114("holds: the same failure with NO restore through the hosted Verify route: 422 RECONCILE_FAILED saying \"nothing was written\", and nothing is written", async (x) => {
    const p = await population(x, { terminated: false });
    const beforeSnap = await x.snap();
    const r = await underFault("tmp-create", p.q, () => x.verifyRoute(p.v));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation");
    assert.equal(`${r.status} ${r.code}`, "422 RECONCILE_FAILED", `got ${r.status} ${r.code} ${r.message}`);
    assert.match(String(r.message), NOTHING_WRITTEN);
    assert.deepEqual(await x.snap(), beforeSnap, "nothing is written");
  });
  r114("holds: request-scoped recovery of D with NO restore (the vault live): PROTECTED_UNRESOLVED whose detail says \"nothing was written\", D byte-identical, nothing written", async (x) => {
    const p = await population(x, { terminated: false });
    const beforeSnap = await x.snap();
    const run = await underFault("tmp-create", p.q, () => settle(x.recover(p.d.requestId)));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation inside the pass");
    assert.equal(run.error, null, `request-scoped recovery answers (${said(run)})`);
    assert.equal(run.value.outcome, "PROTECTED_UNRESOLVED");
    assert.match(String(run.value.detail), NOTHING_WRITTEN);
    assert.deepEqual(await x.snap(), beforeSnap, "nothing is written");
  });
  r114("holds (writes, order and codes unchanged): on the TERMINATED_UNKNOWN vault the failed pass writes exactly the restore and answers 422 RECONCILE_FAILED; once the environment recovers, a healthy Verify supersedes D (STALE, its claim and reservation released) and answers CONSISTENT {settled: [D, STALE]} on the live vault, and a further Verify writes nothing", async (x) => {
    const p = await population(x, { terminated: true });
    const beforeSnap = await x.snap();
    const run = await underFault("spawn-eagain", p.q, () => settle(x.verify(p.v)));
    assert.ok(fault.fired >= 1, "the fault fired at Q's validation");
    assert.equal(run.error?.code, "RECONCILE_FAILED", `got ${said(run)}`);
    assertExactlyTheRestore(beforeSnap, await x.snap(), p, "failed pass");
    const healthy = await settle(x.verify(p.v));
    assert.equal(healthy.error, null, `a healthy Verify answers (${said(healthy)})`);
    assert.equal(healthy.value.status, "CONSISTENT", `got ${said(healthy)}`);
    assert.deepEqual(healthy.value.settled, [{ requestId: p.d.requestId, action: "agentSpend", state: "STALE", txId: p.d.txId }]);
    assert.equal((await x.rawRequest(p.d.requestId)).state, "STALE");
    assert.equal(await x.claimOn(p.d.predecessorOutpoint), null, "D's claim is released");
    assert.equal(await x.reservationOf(p.d), null, "D's reservation is released");
    assert.equal((await x.rawManifest(p.v)).status, "PAUSED");
    const settled = await x.snap();
    await settle(x.verify(p.v));
    assert.deepEqual(await x.snap(), settled, "a further Verify writes nothing");
  });
}
