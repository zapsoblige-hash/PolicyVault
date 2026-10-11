"use strict";
/*
 * RC45 R1 D2 — A JOURNALED RECORD IS NEVER FINISHED FROM ITS RECEIPT, EVEN WITH
 * ITS CLAIMS AND RESERVATION STILL HELD (writer disposition D2 of
 * DELTA-DISPOSITIONS-01 for the R1 delta review; design amendment PA-R1-02
 * "D2-D4", independent design check condition C5). Internal regression
 * material for the RC45 successor candidate; not an audit.
 *
 * Why this file exists: the R1-06 sabotage row S6 (journaled records admitted
 * to the receipt-matching finish, i.e. `!r.transitionRecovery` dropped from
 * reconcile-v4.js receiptFinishable's predicate) was not detected by R1-06's
 * own journaled-exclusion leg: that record held no claim or reservation any
 * more and its audit row already existed, so completeRecord's writes were
 * no-ops and relabel's own refusal hid the rest. Here the journaled record
 * keeps everything completeRecord would touch:
 *   - its own transition claim on its predecessor and its submission claim,
 *   - its budget reservation,
 *   - a receipt that names it and matches it exactly (requestId, expected
 *     outpoint and value, and its immutable binding: the R1-06 C2 predicate
 *     holds for everything except the journal),
 *   - no reconciled_advanced {via: "reconcile"} row for its txid.
 * Under S6, completeRecord would append that row, release both claims and the
 * reservation, and finishByReceipt would push a CHAIN_VERIFIED entry for it
 * into settled[] whatever relabel decides (C5). Each leg asserts (i) the
 * journaled record's claims, reservation, record, receipt and audit rows are
 * byte-identical and (ii) the answer's settled[] names no journaled record;
 * the population keeps every other write out of the pass, so the whole
 * durable state is also byte-identical.
 *
 * HOLDS on ecb9928 (and must keep holding; L-15: journaled RC42/RC44 history
 * is never written). Callers of receiptFinishable exercised:
 *   - settleOneHop, the journaled record in the LAST hop (L live at depth D;
 *     lastHop leaves it out because it is journaled, so only the receipt
 *     predicate could take it);
 *   - settleOneHop, the journaled record TWO hops back (after an ordinary SDK
 *     hop P2 that completed at zero depth; no loser candidate exists);
 *   - finishRecordedV4 (step 3) on the closed vault after the owner's Close &
 *     recover: REQUEST_RECOVERY_REQUIRED for the journaled record with nothing
 *     written.
 *
 * Population: a TEST vault seeded by the F5 kit; the delegate's agentSpend W
 * (4 KAS) built and finalized by the candidate (real v0.4.1 compiler,
 * pv_call_encoder, TEST-key signature, pinned pv_vm_preflight): claims on L0
 * and its held budget reservation (taken ACTIVE at build, CONSUMED at
 * finalize; it counts until released, and releaseReservationForRequest removes
 * it in either status). The candidate's ordinary submit broadcasts W and does
 * not observe its effect yet (RECONCILIATION_REQUIRED, journal-free, claims
 * and reservation kept; RC44's request-scoped recovery admits only
 * SUBMITTING/SUBMITTED/RECONCILIATION_REQUIRED/... records, not
 * PREFLIGHT_VERIFIED). RC44-written journal: the pinned df5b8de writer
 * (sdk/testutil/rc45-f7-rc44-history.js scenario "journal": RC44 request-scoped
 * recovery with L0 live -> RECONCILIATION_REQUIRED with a PROTECTED journal;
 * a missing or mismatched POLICYVAULT_TEST_RC44_TREE FAILS). CANDIDATE-written
 * strand: W lands at depth D; the candidate's journal path (request-scoped
 * recovery) proves the effect, writes EFFECT_PROVEN, advances the manifest and
 * writes W's receipt, and is stopped by an in-process store fault at its
 * transition_recovery_completed row (the next durable step), so W's claims
 * and reservation stay held. Node observations come only from the explicit
 * chain model of sdk/testutil/rc45-f5-kit.js; every config names
 * ws://127.0.0.1:1, so nothing can dial a node.
 *
 * Layer: SDK (reconcileVaultV4, reconcileTransitionWalletRequestV4). Both
 * stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}
 * (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a FAIL). TEST
 * keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const H7 = require("../testutil/rc45-f7-rc44-history");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const recovery4 = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ j: K.vault("r1d2-journaled") });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, journaled = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (o) => (o.error ? `${o.error.code ?? "no code"}: ${String(o.error.message).slice(0, 240)}` : JSON.stringify(o.value).slice(0, 300));

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r1d2-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w);
  await K.seedVault(cand, template, V.j, w);
  const W = await k.finalize(await k.agentSpend(V.j, 4), w.agent);
  assert.equal(W.state, "PREFLIGHT_VERIFIED", "the delegate's spend W finalizes (claims on L0, its reservation held)");
  const s = cand.store.getStore(template);
  assert.equal((await s.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(W.predecessorOutpoint)))?.txId, W.txId);
  // The reservation is taken ACTIVE at build and is CONSUMED at finalize; it keeps counting until it is released
  // (sdk/src/budget-reservation.js LIFECYCLE), and releaseReservationForRequest removes it in either status.
  const held = await s.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(W));
  assert.ok(held && ["ACTIVE", "CONSUMED"].includes(held.status) && held.requestId === W.requestId, `W holds its reservation (${JSON.stringify(held)})`);
  { // The ordinary submit broadcasts W; its effect is not observed yet (RECONCILIATION_REQUIRED, journal-free, claims kept).
    const model = K.chainModel(template); model.seedInputs(frozenOf(W), W.covenantId); model.know(W);
    await assert.rejects(cand.submit4.submitWalletRequestV4({ config: template, requestId: W.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e && e.code === "RECONCILIATION_REQUIRED", "the broadcast is accepted but not yet observed");
    assert.deepEqual(model.broadcasts, [W.txId], "W's signed bytes reached the node");
    const r = await cand.wr4.loadRequest(template, W.requestId);
    assert.equal(r.state, "RECONCILIATION_REQUIRED"); assert.equal(r.transitionRecovery, undefined, "journal-free");
    assert.equal((await s.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(W.predecessorOutpoint)))?.txId, W.txId, "its claim on L0 is kept");
    assert.ok(await s.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(W)), "its reservation is kept");
  }
  // RC44-written protection journal over the candidate-written W (the pinned df5b8de writer only).
  const rc44 = H7.runF7Rc44Scenario("journal", { snapshot: await K.snapshot(cand, template), requestId: W.requestId, track });
  assert.equal(rc44.result.phase, "PROTECTED", "the RC44 writer's protection journal");
  journaled = await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK }));
  B = { W: W.requestId };
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const st of stores) { try { await st.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r1d2-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1d2_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  await K.install(cand, config, journaled);
  const store = cand.store.getStore(config), model = K.chainModel(config);
  const x = {
    config, store, model, pgDatabase, k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => K.snapshot(cand, config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc }),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    recover: (requestId) => recovery4.reconcileTransitionWalletRequestV4({ config, requestId, rpc: model.rpc })
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

/* Everything the receipt-matching finish could write for the journaled record `r`, read raw. */
async function journaledRows(x, r) {
  const s = x.store, audit = (await s.readAudit({ limit: 5000 })).filter((row) => row.txId === r.txId || row.requestId === r.requestId);
  return {
    record: await s.read(Categories.REQUEST, r.requestId),
    transitionClaim: await s.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(r.predecessorOutpoint)),
    submissionClaim: await s.read(Categories.SUBMISSION_CLAIM, r.txId),
    reservation: await s.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: await s.read(Categories.RECEIPT, r.txId),
    audit
  };
}

/*
 * The strand: W lands and deepens to D; the candidate's journal path proves the effect (EFFECT_PROVEN), advances the
 * manifest and writes W's receipt, then stops at its transition_recovery_completed row. W stays journaled
 * (RECONCILIATION_REQUIRED) with its claims, its reservation and a receipt that matches it exactly.
 */
async function strand(x) {
  const W0 = await x.rawRequest(B.W);
  assert.equal(W0.state, "RECONCILIATION_REQUIRED"); assert.equal(W0.transitionRecovery?.phase, "PROTECTED", "RC44-written journaled history");
  x.model.seedInputs(frozenOf(W0), W0.covenantId); x.model.confirm(frozenOf(W0), W0.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const f = storeFault(x.store, (name, args) => name === "appendAudit" && args[0] && args[0].action === "transition_recovery_completed");
  let run;
  try { run = await settle(x.recover(B.W)); } finally { f.restore(); }
  assert.equal(f.fired, true, `the candidate's journal path reached its completion row (${said(run)})`);
  assert.ok(run.error && /TEST store fault/.test(String(run.error.message)), `the store fault stopped it (${said(run)})`);
  const W = await x.rawRequest(B.W);
  assert.equal(W.state, "RECONCILIATION_REQUIRED", "W is still journaled history");
  assert.equal(W.transitionRecovery?.phase, "EFFECT_PROVEN");
  const m = await x.rawManifest(V.j);
  assert.equal(m.latestTransitionTxId, W.txId, "the manifest is advanced by W");
  const rows = await journaledRows(x, W);
  assert.equal(rows.transitionClaim?.txId, W.txId, "W's own transition claim on L0 is still held");
  assert.equal(rows.submissionClaim?.txId, W.txId, "W's own submission claim is still held");
  assert.ok(rows.reservation, "W's budget reservation is still held");
  assert.equal(rows.receipt?.proof?.requestId, W.requestId, "W's receipt names W");
  // Every part of the R1-06 C2 finishing predicate holds except the journal: only the exclusion of journaled records
  // keeps W out of the receipt-matching finish (so a leg that writes nothing here detects sabotage S6).
  assert.equal(recovery4.ownReceiptMatches(rows.receipt, W, recovery4.validateIdentity(x.config, W).expected), true, "the receipt matches W exactly (requestId, expected outpoint and value, immutable binding)");
  assert.equal(rows.audit.some((row) => row.action === "reconciled_advanced" && row.via === "reconcile"), false, "no completion row for W's txid yet");
  assert.equal(rows.audit.some((row) => row.action === "transition_recovery_completed"), false, "the journal path stopped before its completion row");
  assert.equal(await recovery4.isPendingTransitionV4(x.config, W), true, "the journaled W is PENDING");
  return W;
}
/* A Verify (or another caller) that must leave the journaled W and everything it holds byte-identical. */
async function assertJournaledUntouched(x, W, beforeRows, beforeSnap, answer, label) {
  const rows = await journaledRows(x, W);
  assert.deepEqual(rows.record, beforeRows.record, `${label}: the journaled record is byte-identical (L-15)`);
  assert.deepEqual(rows.transitionClaim, beforeRows.transitionClaim, `${label}: its transition claim is byte-identical (never released)`);
  assert.deepEqual(rows.submissionClaim, beforeRows.submissionClaim, `${label}: its submission claim is byte-identical (never released)`);
  assert.deepEqual(rows.reservation, beforeRows.reservation, `${label}: its reservation is byte-identical (never released)`);
  assert.deepEqual(rows.receipt, beforeRows.receipt, `${label}: its receipt is byte-identical`);
  assert.deepEqual(rows.audit, beforeRows.audit, `${label}: no audit row is added for it (no reconciled_advanced via reconcile)`);
  const settled = Array.isArray(answer?.settled) ? answer.settled : [];
  assert.deepEqual(settled.filter((e) => e && e.requestId === W.requestId), [], `${label}: the answer's settled[] names no journaled record (got ${JSON.stringify(answer?.settled)})`);
  assert.deepEqual(await x.snap(), beforeSnap, `${label}: nothing at all is written`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const d2 = (name, fn) => test(`RC45 R1 D2 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  d2("settleOneHop, the journaled record in the LAST hop (holds): W (RC44 PROTECTED journal, then the candidate's journal path stopped after its receipt) holds its claims, its reservation and a receipt that matches it exactly; a Verify with W's successor live at depth D answers CONSISTENT, settled[] names no journaled record, and W, its claims, reservation, receipt and audit rows are byte-identical (nothing written)", async (x) => {
    const W = await strand(x);
    const m = await x.rawManifest(V.j);
    assert.equal(m.lastTransition?.txId, W.txId, "W is the recorded last hop");
    const beforeRows = await journaledRows(x, W), beforeSnap = await x.snap();
    const out = await settle(x.verify(V.j));
    assert.equal(out.error, null, `Verify answers (${said(out)})`);
    assert.equal(out.value.status, "CONSISTENT", `the live successor at depth D is consistent (got ${said(out)})`);
    await assertJournaledUntouched(x, W, beforeRows, beforeSnap, out.value, "last hop");
  });

  d2("settleOneHop, the journaled record TWO hops back (holds): after the strand, the delegate's ordinary spend P2 completes on W's successor at zero depth (SDK path; no loser candidate exists); a Verify at depth D answers CONSISTENT, settled[] names no journaled record, and W, its claims, reservation, receipt and audit rows are byte-identical (nothing written)", async (x) => {
    const W = await strand(x);
    const p2 = await x.k.finalize(await x.k.agentSpend(V.j, 2), w.agent);
    assert.equal(p2.state, "PREFLIGHT_VERIFIED", "P2 finalizes on W's successor (the journaled W on L0 blocks nothing)");
    x.model.know(p2); x.model.confirmOnSubmit = true;
    let run;
    try { run = await settle(x.submit(p2.requestId)); } finally { x.model.confirmOnSubmit = false; }
    assert.equal(run.error, null, `P2's ordinary submit completes (${said(run)})`);
    assert.equal(run.value.request.state, "CHAIN_VERIFIED");
    assert.equal((await x.rawManifest(V.j)).latestTransitionTxId, p2.txId, "the manifest moved past W's successor");
    x.model.advance(SETTLE_DEPTH_DAA);
    const beforeRows = await journaledRows(x, W), beforeSnap = await x.snap();
    const out = await settle(x.verify(V.j));
    assert.equal(out.error, null, `Verify answers (${said(out)})`);
    assert.equal(out.value.status, "CONSISTENT", `got ${said(out)}`);
    await assertJournaledUntouched(x, W, beforeRows, beforeSnap, out.value, "two hops back");
  });

  d2("finishRecordedV4 on the closed vault (holds): after the strand, the owner's Close & recover R on W's successor is submitted (contested: SUBMITTED), lands and is completed by Verify at D (RECOVERED); the next Verify (step 3, no node call) answers REQUEST_RECOVERY_REQUIRED for the journaled W, settled[] names no journaled record, and W, its claims, reservation, receipt and audit rows are byte-identical (nothing written)", async (x) => {
    const W = await strand(x);
    const R = await x.k.finalize(await x.k.ownerOp(V.j, "ownerRecover", "fuel2"), w.owner);
    assert.equal(R.state, "PREFLIGHT_VERIFIED", "the owner's Close & recover finalizes (break-glass)");
    frozenOf(R).inputs.forEach((i, index) => { if (index > 0) x.model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 5000n); }); // the owner's fuel
    x.model.know(R); x.model.confirmOnSubmit = true;
    let run;
    try { run = await settle(x.submit(R.requestId)); } finally { x.model.confirmOnSubmit = false; }
    assert.equal(run.error, null, `the recover is submitted (${said(run)})`);
    x.model.advance(SETTLE_DEPTH_DAA);
    const closed = await settle(x.verify(V.j));
    assert.equal(closed.error, null, `Verify at D answers (${said(closed)})`);
    assert.equal(closed.value.status, "ADVANCED"); assert.equal(closed.value.to, "RECOVERED");
    assert.equal((await x.rawManifest(V.j)).status, "RECOVERED");
    const beforeRows = await journaledRows(x, W), beforeSnap = await x.snap(), calls = x.model.calls.length;
    const out = await settle(x.verify(V.j));
    assert.equal(out.error, null, `the step-3 Verify answers (${said(out)})`);
    assert.equal(out.value.status, "REQUEST_RECOVERY_REQUIRED", `the journaled W stays unresolved history (got ${said(out)})`);
    assert.equal(out.value.requestId, W.requestId); assert.equal(out.value.recordedVaultClosed, true);
    assert.equal(x.model.calls.length, calls, "step 3 makes no node call");
    await assertJournaledUntouched(x, W, beforeRows, beforeSnap, out.value, "closed vault");
  });
}
