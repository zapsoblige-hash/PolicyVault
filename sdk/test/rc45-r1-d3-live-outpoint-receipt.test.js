"use strict";
/*
 * RC45 R1 D3 — A RECORD ON THE RECORDED LIVE OUTPOINT IS NEVER FINISHED FROM ITS
 * RECEIPT (writer disposition D3 of DELTA-DISPOSITIONS-01, "the missing
 * fail-closed test"; design amendment PA-R1-02 "D2-D4", independent design
 * check condition C6). Internal regression material for the RC45 successor
 * candidate; not an audit.
 *
 * The R1-06 implementer's fail-closed reading (sdk/src/reconcile-v4.js
 * receiptFinishable): a SIGNED_OR_REJECTED record with a receipt that matches
 * it, whose recorded predecessor is still the recorded LIVE outpoint, is not
 * yet a recorded hop. It is the receipt-first crash window of R1-06 C3 (the
 * receipt written, the manifest not advanced), or, with that outpoint live
 * again, a reorganization deeper than D (L-1). Its signed bytes could still
 * spend the live outpoint, so finishRecorded and settleOneHop leave it
 * unwritten and the next pass's step 7 advances it (ADVANCED, then
 * CHAIN_VERIFIED). Sabotage row: remove the live-outpoint exclusion
 * (`(live && recovery().onOutpoint(r, live))`).
 *
 * C6: each leg reaches receiptFinishable while the record is on
 * m.live.outpoint, and names the caller it exercises:
 *   (a) finishRecordedV4, reached through request-scoped recovery of an
 *       earlier record P1 stranded right after its own manifest advance
 *       (settleJournalFree's advanced branch, no node call);
 *   (b) settleOneHop, reached by a Verify in which L is observed live at
 *       depth >= D and lastTransition.newOutpoint equals L (the chain model
 *       removes the window record's outputs and restores L: add/remove).
 * A Verify with L spent goes straight to step 7 and never calls
 * receiptFinishable, so it could not detect the sabotage row.
 *
 * HOLDS on ecb9928 (and must keep holding).
 *
 * Population (CANDIDATE-WRITTEN; TEST keys 0x11 owner / 0x21 agent; F5 kit
 * vaults): (a) the delegate's ordinary spend P1 submitted, accepted and
 * observed at zero depth, the submit stopped right after its manifest advance
 * (SUBMITTED, manifest recorded, no receipt, claims kept: the T6 "fin"
 * shape); (b) the delegate's ordinary spend P1 completed at zero depth by its
 * submit (L-2). Then, on P1's successor L1, the owner's Pause Q built and
 * finalized (Q holds the claim on L1); Q lands and deepens to D; Verify's
 * completion of Q (step 7) is stopped by an in-process store fault AT its
 * manifest advance, so exactly Q's own receipt is written (the window).
 * Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures and the pinned
 * pv_vm_preflight for every consensus byte. Node observations come only from
 * the explicit chain model of sdk/testutil/rc45-f5-kit.js; every config names
 * ws://127.0.0.1:1, so nothing can dial a node.
 *
 * Layer: SDK (reconcileVaultV4, reconcileTransitionWalletRequestV4). Both
 * stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}
 * (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a FAIL).
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const recovery4 = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ a: K.vault("r1d3-finish-recorded"), b: K.vault("r1d3-settle-one-hop") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (o) => (o.error ? `${o.error.code ?? "no code"}: ${String(o.error.message).slice(0, 240)}` : JSON.stringify(o.value).slice(0, 300));
const same = (p, o) => p && o && p.transactionId === o.transactionId && Number(p.index) === Number(o.index);

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r1d3-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), s = cand.store.getStore(template);
  B = {};
  { // (a) P1 stranded right after its manifest advance (the T6 "fin" shape), then the owner's Q on L1.
    const v = V.a; await K.seedVault(cand, template, v, w);
    const p1 = await k.finalize(await k.agentSpend(v, 4), w.agent);
    assert.equal(p1.state, "PREFLIGHT_VERIFIED");
    const model = K.chainModel(template); model.know(p1); model.seedInputs(frozenOf(p1), p1.covenantId); model.confirmOnSubmit = true;
    const write = s.write.bind(s); let crashed = false;
    s.write = async (c, key, value) => {
      const out = await write(c, key, value);
      if (!crashed && c === Categories.VAULT && key === v.vaultId) { crashed = true; throw new Error("TEST crash right after the manifest advance"); }
      return out;
    };
    try {
      await assert.rejects(cand.submit4.submitWalletRequestV4({ config: template, requestId: p1.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }), /TEST crash right after the manifest advance/);
    } finally { s.write = write; }
    assert.equal(crashed, true, "the submit reached its manifest advance");
    assert.equal((await cand.wr4.loadRequest(template, p1.requestId)).state, "SUBMITTED");
    assert.equal((await s.read(Categories.VAULT, v.vaultId)).latestTransitionTxId, p1.txId);
    assert.equal(await s.read(Categories.RECEIPT, p1.txId), null, "no receipt yet");
    const q = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner);
    assert.equal(q.state, "PREFLIGHT_VERIFIED", "the owner's Pause finalizes on P1's successor");
    B.a = { p1: p1.requestId, q: q.requestId, model: model.serialize() };
  }
  { // (b) P1 completed at zero depth by its own submit (L-2), then the owner's Q on L1.
    const v = V.b; await K.seedVault(cand, template, v, w);
    const p1 = await k.finalize(await k.agentSpend(v, 4), w.agent);
    const model = K.chainModel(template); model.know(p1); model.seedInputs(frozenOf(p1), p1.covenantId); model.confirmOnSubmit = true;
    const done = await cand.submit4.submitWalletRequestV4({ config: template, requestId: p1.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 });
    assert.equal(done.request.state, "CHAIN_VERIFIED", "the ordinary spend completes at zero depth (L-2)");
    const m = await s.read(Categories.VAULT, v.vaultId);
    assert.equal(m.latestTransitionTxId, p1.txId); assert.equal(m.lastTransition.newOutpoint.transactionId, p1.txId);
    const q = await k.finalize(await k.ownerOp(v, "ownerPause"), w.owner);
    assert.equal(q.state, "PREFLIGHT_VERIFIED", "the owner's Pause finalizes on P1's successor");
    B.b = { p1: p1.requestId, q: q.requestId, model: model.serialize() };
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const st of stores) { try { await st.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend, tag) {
  const dataRoot = mk("pv-rc45-r1d3-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1d3_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config, B[tag].model);
  return {
    config, store, model, pgDatabase,
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    recover: (requestId) => recovery4.reconcileTransitionWalletRequestV4({ config, requestId, rpc: model.rpc })
  };
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
function canonicalWithout(snap, drops) {
  const records = {};
  for (const [c, entries] of Object.entries(snap.records)) records[c] = entries.filter(([k]) => !drops.some(([dc, dk]) => dc === c && dk === k));
  return K.canonicalState({ records, audit: snap.audit });
}
/* Q's own durable rows (its record, its receipt, its transition claim on L1 and its submission claim), read raw. */
async function qRows(x, q) {
  return {
    record: await x.rawRequest(q.requestId),
    receipt: await x.receipt(q.txId),
    transitionClaim: await x.store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(q.predecessorOutpoint)),
    submissionClaim: await x.store.read(Categories.SUBMISSION_CLAIM, q.txId)
  };
}

/*
 * The receipt-first crash window (R1-06 C3): Q lands and deepens to D; Verify (step 7: L1 spent) completes Q and is
 * stopped AT its manifest advance, so exactly Q's own receipt is written. Returns L1's UTXO entry as the chain held it.
 */
async function crashWindow(x, v, tag) {
  const q = await x.req(B[tag].q), p1 = await x.req(B[tag].p1);
  const m0 = await x.rawManifest(v);
  assert.ok(same(m0.live.outpoint, q.predecessorOutpoint), "Q is on the recorded live outpoint L1 (P1's successor)");
  assert.equal(m0.latestTransitionTxId, p1.txId);
  assert.equal((await x.store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(q.predecessorOutpoint)))?.txId, q.txId, "Q holds the claim on L1");
  const l1 = x.model.serialize().utxos.find((u) => same(u.outpoint, q.predecessorOutpoint));
  assert.ok(l1, "L1 is live on the chain model (P1 landed)");
  frozenOf(q).inputs.forEach((i, index) => { if (index > 0) x.model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 5000n); }); // the owner's fuel
  x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const base = await x.snap();
  const f = storeFault(x.store, (name, args) => name === "write" && args[0] === Categories.VAULT && args[1] === v.vaultId);
  let run;
  try { run = await settle(x.verify(v)); } finally { f.restore(); }
  assert.equal(f.fired, true, `Verify's completion of Q reached its manifest advance (${said(run)})`);
  assert.ok(run.error && /TEST store fault/.test(String(run.error.message)), `the fault stopped it (${said(run)})`);
  const atWindow = await x.snap();
  assert.equal((await x.receipt(q.txId))?.proof?.requestId, q.requestId, "Q's own receipt is the first durable write of its completion (R1-06 C3)");
  assert.equal(canonicalWithout(atWindow, [[Categories.RECEIPT, q.txId]]), canonicalWithout(base, [[Categories.RECEIPT, q.txId]]), "nothing but Q's receipt is written; the manifest is not advanced");
  const qr = await qRows(x, q);
  assert.equal(qr.record.state, "PREFLIGHT_VERIFIED");
  assert.equal(recovery4.ownReceiptMatches(qr.receipt, qr.record, recovery4.validateIdentity(x.config, qr.record).expected), true, "Q's receipt matches Q exactly: only the live-outpoint exclusion keeps Q out of the receipt-matching finish");
  return { q, p1, l1, atWindow, qr };
}
/* The next pass's step 7 advances Q (ADVANCED, then CHAIN_VERIFIED), Q's receipt byte-identical; a further Verify writes nothing. */
async function stepSevenAdvances(x, v, q, receipt) {
  const out = await settle(x.verify(v));
  assert.equal(out.error, null, `the next Verify answers (${said(out)})`);
  assert.equal(out.value.status, "ADVANCED", `step 7 advances Q (got ${said(out)})`);
  assert.equal(out.value.txId, q.txId); assert.equal(out.value.requestId, q.requestId); assert.equal(out.value.to, "ownerPause");
  assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal((await x.rawManifest(v)).latestTransitionTxId, q.txId, "the manifest is advanced by Q");
  assert.deepEqual(await x.receipt(q.txId), receipt, "Q's receipt is kept byte-identical (H-40)");
  const settled = await x.snap();
  await settle(x.verify(v));
  assert.deepEqual(await x.snap(), settled, "a further Verify writes nothing");
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const d3 = (name, tag, fn) => test(`RC45 R1 D3 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend, tag); try { await fn(x); } finally { await release(x); } });

  d3("caller finishRecordedV4 (request-scoped recovery, settleJournalFree's advanced branch; holds): in the receipt-first crash window of the owner's Pause Q (its own receipt written, the manifest not advanced, Q on the recorded live outpoint L1), request-scoped recovery of the earlier P1 (stranded right after its own manifest advance) finishes P1 with no node call and leaves Q, its receipt and its claims byte-identical; the next Verify's step 7 advances Q (ADVANCED, then CHAIN_VERIFIED) with its receipt byte-identical", "a", async (x) => {
    const { q, p1, atWindow, qr } = await crashWindow(x, V.a, "a");
    const m = await x.rawManifest(V.a);
    assert.equal(m.latestTransitionTxId, p1.txId, "the manifest still records P1's advance (Q's manifest advance never happened)");
    assert.equal((await x.rawRequest(p1.requestId)).state, "SUBMITTED", "P1 is stranded after its own manifest advance");
    const calls = x.model.calls.length;
    const out = await settle(x.recover(p1.requestId));
    assert.equal(out.error, null, `request-scoped recovery of P1 answers (${said(out)})`);
    assert.equal(out.value.outcome, "CHAIN_VERIFIED", `P1's recorded advancement is finished (got ${out.value.outcome}: ${out.value.detail})`);
    assert.equal(x.model.calls.length, calls, "finishRecordedV4 makes no node call");
    assert.deepEqual(await qRows(x, q), qr, "Q (on the recorded live outpoint) is never finished from its receipt: its record, receipt and claims are byte-identical (D3)");
    assert.deepEqual(await x.rawManifest(V.a), m, "finishRecorded never rewrites the manifest");
    const after = await x.snap(), changed = after.records[Categories.REQUEST].filter(([k, r]) => JSON.stringify(r) !== JSON.stringify((atWindow.records[Categories.REQUEST].find(([b]) => b === k) ?? [])[1]));
    assert.deepEqual(changed.map(([k]) => k), [p1.requestId], "the only request record written is P1");
    await stepSevenAdvances(x, V.a, q, qr.receipt);
  });

  d3("caller settleOneHop (a Verify with L live at depth D and lastTransition.newOutpoint = L; holds): in the receipt-first crash window of the owner's Pause Q, the chain model then holds L1 live again (Q's outputs removed, L1 restored at its original score: a reorganization deeper than D); a Verify answers REQUEST_RECOVERY_REQUIRED for Q with nothing written (Q, its receipt and its claims byte-identical); once Q lands again at D, the next Verify's step 7 advances Q (ADVANCED, then CHAIN_VERIFIED) with its receipt byte-identical", "b", async (x) => {
    const { q, p1, l1, qr } = await crashWindow(x, V.b, "b");
    const m = await x.rawManifest(V.b);
    assert.ok(same(m.lastTransition.newOutpoint, q.predecessorOutpoint), "lastTransition.newOutpoint is L1 (P1's successor)");
    assert.equal(m.lastTransition.txId, p1.txId);
    // The chain model: Q's outputs removed and L1 restored exactly as it was (add/remove).
    frozenOf(q).outputs.forEach((_o, index) => x.model.remove({ transactionId: q.txId, index }));
    x.model.add(l1.outpoint, l1.amount, { version: l1.scriptPublicKey.version, scriptHex: l1.scriptPublicKey.script }, l1.covenantId, BigInt(l1.blockDaaScore));
    assert.ok(x.model.virtualDaaScore - BigInt(l1.blockDaaScore) >= SETTLE_DEPTH_DAA, "L1 is observed at depth >= D");
    const before = await x.snap(), reads = x.model.reads.length;
    const out = await settle(x.verify(V.b));
    assert.equal(out.error, null, `Verify answers (${said(out)})`);
    assert.ok(x.model.readAddresses(reads).includes(l1.address), "the Verify read L1 first and found it live (step 6, settleLive: settleOneHop runs)");
    assert.equal(out.value.status, "REQUEST_RECOVERY_REQUIRED", `Q's signed work on the live L1 is still pending (got ${said(out)})`);
    assert.equal(out.value.requestId, q.requestId); assert.equal(out.value.recordedVaultClosed, false);
    assert.equal(out.value.settled, undefined, "nothing was settled");
    assert.deepEqual(await qRows(x, q), qr, "Q (on the recorded live outpoint) is never finished from its receipt: its record, receipt and claims are byte-identical (D3)");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
    await stepSevenAdvances(x, V.b, q, qr.receipt);
  });
}
