"use strict";
/*
 * RC45 R1-13 (O1) — A CLOSED VAULT'S REQUEST_RECOVERY_REQUIRED REPORTS WHAT
 * VERIFY SETTLED (design amendment PA-R1-02 "R1-13", independent design check
 * condition C1; plan R1 revision 2 budget unchanged: an existing field on an
 * existing answer). Internal RED-first regression material for the RC45
 * successor candidate; not an audit. The fixture-driven web legs are in
 * web/test/rc45-r1-13-closed-vault-web.test.js.
 *
 * The rule (PA-R1-02 R1-13): in step 3 (closed vault) finishRecordedV4 can
 * complete records into settled[] and the pass then answers
 * REQUEST_RECOVERY_REQUIRED because another record is still PENDING. That
 * answer carries `...(settled.length ? { settled } : {})`, the form settleLive's
 * REQUEST_RECOVERY_REQUIRED and CLAIM_PENDING already use. No other field
 * changes; with nothing settled the answer is exactly as today (no settled[]).
 * C1: the closed Verify map (web/refusal-explain.js verifyStatus) says
 * "nothing was written" for a recorded-closed REQUEST_RECOVERY_REQUIRED only
 * when settled[] is absent or empty, and lists the entries under their
 * existing labels ("Completed by this Verify").
 *
 * RED on ecb9928: the step-3 answer omits settled[] although Verify has just
 * completed a record (sdk/src/reconcile-v4.js :609-613), so the hosted route's
 * body omits it too and the closed map tells the owner "nothing was written".
 * HOLDS on ecb9928 (and must keep holding): the completion itself (the
 * executed record CHAIN_VERIFIED from its own receipt, no node call, the
 * PENDING record byte-identical); every existing field of the answer; a
 * further Verify writes nothing and answers without settled[], and the map
 * then still says "nothing was written".
 *
 * Population (CANDIDATE-WRITTEN; TEST keys 0x11 owner / 0x21 agent; an F5 kit
 * vault): the delegate's spend D and the owner's Pause Q on L0, finalized
 * apart and merged (D holds the only claim; the contested shape). D lands and
 * deepens to D (depth); Verify's completion of D is stopped (SYNTHETIC
 * in-process store fault) at D's CHAIN_VERIFIED relabel, after D's receipt,
 * the manifest advance, D's completion row and D's claims and reservation were
 * written or released, and before the losers: D stays PREFLIGHT_VERIFIED with
 * its own receipt and Q stays PREFLIGHT_VERIFIED (PENDING) on L0 (R1-06 probe
 * C's fault). The owner's Close & recover R on D's successor is submitted
 * (contested: SUBMITTED), lands and is completed by Verify at depth
 * (RECOVERED). Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and
 * the pinned pv_vm_preflight for every consensus byte. Node observations come
 * only from the explicit chain model of sdk/testutil/rc45-f5-kit.js; every
 * config names ws://127.0.0.1:1, so nothing can dial a node.
 *
 * Layers: SDK (reconcileVaultV4), API (POST /vaults/:id/reconcile through the
 * self-hosted server/src/api.js handle; the route wraps the module-cache
 * export of the REAL reconcileVaultV4 to pass the model's rpc, plan r2 §8
 * rules CR-M14, CR2-L12) and MAP (the real web/refusal-explain.js fed the
 * real route body). Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const RX = require("../../web/refusal-explain.js");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ cv: K.vault("r113-closed-vault") });
const CLOSED_REASON = "the recorded vault is closed; historical request evidence remains unresolved and protected; no new recovery or transaction is authorized";
const ANSWER_KEYS = Object.freeze(["pending", "reason", "recordedVaultClosed", "requestId", "status", "vaultId", "vaultStatus"]);
const NOTHING_WRITTEN = /nothing was written/i;
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (o) => (o.error ? `${o.error.code ?? "no code"}: ${String(o.error.message).slice(0, 240)}` : JSON.stringify(o.value).slice(0, 400));

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r113-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "self-hosted template");
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w);
  const v = V.cv; await K.seedVault(cand, template, v, w);
  const d = await k.agentSpend(v, 4); await K.sleep(3);
  const q = await k.ownerOp(v, "ownerPause");
  await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
  B = { d: d.requestId, q: q.requestId };
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r113-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r113_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  assert.equal(config.tenancyEnforced, false, "self-hosted case");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config), api = F3.apiFor(config);
  const x = {
    config, store, model, pgDatabase, api, k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    /* POST /vaults/:id/reconcile (self-hosted) through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
    async verifyRoute(v) {
      const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
      m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: model.rpc });
      try { return await api.call("POST", ["vaults", v.vaultId, "reconcile"], {}); } finally { m4.reconcileVaultV4 = real4; }
    }
  };
  return x;
}
async function release(x) {
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
const atRelabel = (r) => (name, args) => name === "write" && args[0] === Categories.REQUEST && args[1] === r.requestId && args[2] && args[2].state === "CHAIN_VERIFIED";

/*
 * The closed vault with a stranded executed record: D executes (CONFIRMED at depth over the contested Pause Q) and
 * Verify's completion of it stops at its relabel (D keeps its own receipt; Q is never superseded); the owner then
 * closes the vault (R on D's successor, completed by Verify at depth: RECOVERED). Returns the records as they stand.
 */
async function closedWithStrandedRecord(x) {
  const d = await x.req(B.d), q = await x.req(B.q), v = V.cv;
  x.model.seedInputs(frozenOf(q), q.covenantId);
  x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const f = storeFault(x.store, atRelabel(d));
  let run;
  try { run = await settle(x.verify(v)); } finally { f.restore(); }
  assert.equal(f.fired, true, `Verify's completion of D reached D's relabel (${said(run)})`);
  assert.ok(run.error && /TEST store fault/.test(String(run.error.message)), `the fault stopped it (${said(run)})`);
  assert.equal((await x.rawManifest(v)).latestTransitionTxId, d.txId, "the manifest is advanced by the executed D");
  assert.equal((await x.rawRequest(d.requestId)).state, "PREFLIGHT_VERIFIED", "D keeps its label");
  assert.equal((await x.receipt(d.txId))?.proof?.requestId, d.requestId, "D's own receipt is written");
  assert.equal((await x.rawRequest(q.requestId)).state, "PREFLIGHT_VERIFIED", "Q is never superseded (the fault came before the losers)");
  const r = await x.k.finalize(await x.k.ownerOp(v, "ownerRecover", "fuel2"), w.owner);
  assert.equal(r.state, "PREFLIGHT_VERIFIED", "the owner's Close & recover finalizes on D's successor (break-glass)");
  frozenOf(r).inputs.forEach((i, index) => { if (index > 0) x.model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 5000n); }); // the owner's fuel
  x.model.know(r); x.model.confirmOnSubmit = true;
  let sub;
  try { sub = await settle(x.submit(r.requestId)); } finally { x.model.confirmOnSubmit = false; }
  assert.equal(sub.error, null, `the recover is submitted (${said(sub)})`);
  x.model.advance(SETTLE_DEPTH_DAA);
  const closed = await settle(x.verify(v));
  assert.equal(closed.error, null, `Verify at depth answers (${said(closed)})`);
  assert.equal(closed.value.status, "ADVANCED"); assert.equal(closed.value.to, "RECOVERED");
  const m = await x.rawManifest(v);
  assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null);
  assert.equal((await x.rawRequest(d.requestId)).state, "PREFLIGHT_VERIFIED", "D is still unfinished on the closed vault");
  return { d, q, r, dReceipt: await x.receipt(d.txId), qRaw: await x.rawRequest(q.requestId) };
}
const completedEntry = (d) => ({ requestId: d.requestId, action: "agentSpend", state: "CHAIN_VERIFIED", txId: d.txId });
const pendingEntryOf = (q) => ({ requestId: q.requestId, action: "ownerPause", state: "PREFLIGHT_VERIFIED", txId: q.txId, signerRole: "owner" });
/* The existing fields of the step-3 answer, exactly as today, and the write it reports. */
async function assertClosedAnswerAndWrite(x, s, answer, label) {
  assert.equal(answer.status, "REQUEST_RECOVERY_REQUIRED", `${label}: Q is still PENDING on the closed vault (got ${JSON.stringify(answer).slice(0, 400)})`);
  assert.equal(answer.vaultId, V.cv.vaultId); assert.equal(answer.requestId, s.q.requestId);
  assert.deepEqual(answer.pending, [pendingEntryOf(s.q)], `${label}: pending[] names Q`);
  assert.equal(answer.vaultStatus, "RECOVERED"); assert.equal(answer.recordedVaultClosed, true); assert.equal(answer.reason, CLOSED_REASON);
  assert.equal((await x.rawRequest(s.d.requestId)).state, "CHAIN_VERIFIED", `${label}: this Verify completed the executed D from its own receipt (finishRecordedV4)`);
  assert.deepEqual(await x.receipt(s.d.txId), s.dReceipt, `${label}: D's receipt is kept byte-identical`);
  assert.deepEqual(await x.rawRequest(s.q.requestId), s.qRaw, `${label}: the PENDING Q is byte-identical`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r113 = (name, fn) => test(`RC45 R1-13 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- RED ---------------- */
  r113("SDK Verify, step 3 on the closed RECOVERED vault: finishRecordedV4 completes the executed D (CHAIN_VERIFIED from its own receipt, no node call) while the owner's Q stays PENDING; the answer is REQUEST_RECOVERY_REQUIRED with every existing field as today AND settled[] naming exactly D (CHAIN_VERIFIED), no other new field [RED on ecb9928]", async (x) => {
    const s = await closedWithStrandedRecord(x);
    const calls = x.model.calls.length;
    const out = await settle(x.verify(V.cv));
    assert.equal(out.error, null, `the step-3 Verify answers (${said(out)})`);
    assert.equal(x.model.calls.length, calls, "step 3 makes no node call");
    await assertClosedAnswerAndWrite(x, s, out.value, "SDK");
    assert.deepEqual(out.value.settled, [completedEntry(s.d)], `the answer reports what this Verify settled: settled[] names D CHAIN_VERIFIED (PA-R1-02 R1-13; got ${JSON.stringify(out.value).slice(0, 400)})`);
    assert.deepEqual(Object.keys(out.value).sort(), [...ANSWER_KEYS, "settled"].sort(), "no field other than the existing settled[] is added");
  });

  r113("hosted Verify route (self-hosted POST /vaults/:id/reconcile): the same step-3 Verify answers 200 with body.reconcile REQUEST_RECOVERY_REQUIRED, every existing field as today, AND settled[] naming exactly D (CHAIN_VERIFIED) [RED on ecb9928]", async (x) => {
    const s = await closedWithStrandedRecord(x);
    const r = await x.verifyRoute(V.cv);
    assert.equal(r.status, 200, `the route answers (${r.status} ${r.code ?? ""} ${r.message ?? ""})`);
    const answer = K.jsonSafe(r.body.reconcile);
    await assertClosedAnswerAndWrite(x, s, answer, "route");
    assert.equal(r.body.vault.status, "RECOVERED");
    assert.deepEqual(answer.settled, [completedEntry(s.d)], `the route body reports what this Verify settled: settled[] names D CHAIN_VERIFIED (got ${JSON.stringify(answer).slice(0, 400)})`);
  });

  r113("the real route body told by the closed Verify map (web/refusal-explain.js verifyStatus / renderVerifyHtml): the executed D is listed under \"Completed by this Verify\" and no line says \"nothing was written\"; the closed-vault notice and the pending Q stay [RED on ecb9928]", async (x) => {
    const s = await closedWithStrandedRecord(x);
    const r = await x.verifyRoute(V.cv);
    assert.equal(r.status, 200, `the route answers (${r.status} ${r.code ?? ""} ${r.message ?? ""})`);
    const answer = K.jsonSafe(r.body.reconcile);
    await assertClosedAnswerAndWrite(x, s, answer, "map");
    const v = RX.verifyStatus(answer), text = v.lines.join(" ");
    assert.equal(v.level, "warn", "REQUEST_RECOVERY_REQUIRED stays warn");
    assert.ok(text.includes("closed vault, history only"), `the closed-vault notice stays; it says: ${text}`);
    assert.ok(v.lines.some((l) => l.startsWith("Pending:") && l.includes(s.q.requestId.slice(0, 8))), `the pending Q stays listed; it says: ${text}`);
    assert.ok(v.lines.every((l) => !NOTHING_WRITTEN.test(l)), `a Verify that completed D is never told "nothing was written" (C1); it says: ${text}`);
    assert.ok(v.lines.some((l) => l.startsWith("Completed by this Verify:") && l.includes(s.d.requestId.slice(0, 8))), `D is listed under "Completed by this Verify"; it says: ${text}`);
    assert.doesNotMatch(RX.renderVerifyHtml(answer).replace(/<[^>]+>/g, " ").replace(/the recorded vault is closed;[^<]*/i, ""), NOTHING_WRITTEN, "the rendered Verify block never says nothing was written");
  });

  /* ---------------- HOLDS ---------------- */
  r113("holds: after the completing Verify, a further step-3 Verify writes nothing, makes no node call and answers REQUEST_RECOVERY_REQUIRED for Q with every existing field as today and NO settled[] (nothing was settled); the closed map then still says \"nothing was written\" with the closed-vault notice", async (x) => {
    const s = await closedWithStrandedRecord(x);
    await settle(x.verify(V.cv));
    assert.equal((await x.rawRequest(s.d.requestId)).state, "CHAIN_VERIFIED", "the completing Verify finished D");
    const before = await x.snap(), calls = x.model.calls.length;
    const out = await settle(x.verify(V.cv));
    assert.equal(out.error, null, `the further Verify answers (${said(out)})`);
    assert.deepEqual(await x.snap(), before, "the further Verify writes nothing");
    assert.equal(x.model.calls.length, calls, "no node call");
    assert.equal(out.value.status, "REQUEST_RECOVERY_REQUIRED"); assert.equal(out.value.requestId, s.q.requestId);
    assert.deepEqual(out.value.pending, [pendingEntryOf(s.q)]);
    assert.equal(out.value.vaultStatus, "RECOVERED"); assert.equal(out.value.recordedVaultClosed, true); assert.equal(out.value.reason, CLOSED_REASON);
    assert.deepEqual(Object.keys(out.value).sort(), [...ANSWER_KEYS], "no settled[] when nothing was settled; no new field");
    const v = RX.verifyStatus(K.jsonSafe(out.value)), text = v.lines.join(" ");
    assert.ok(text.includes("closed vault, history only"), `the closed-vault notice; it says: ${text}`);
    assert.ok(v.lines.some((l) => NOTHING_WRITTEN.test(l)), `nothing was written and the map says so; it says: ${text}`);
    assert.ok(v.lines.every((l) => !l.startsWith("Completed by this Verify:")), `nothing is listed as completed; it says: ${text}`);
  });
}
