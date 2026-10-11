"use strict";
/*
 * RC45 T3 — THE VERIFY SETTLEMENT PASS (fix item F5 RC45-L5-VERIFY-SETTLEMENT;
 * plan rc45-simplified-plan-r2 §1 O1/O3, §2.0 SEEN / CONFIRMED / D, the
 * validateIdentity error rule and R, §2.2 steps 0-11 with completePositive,
 * twinComplete, settleLoser, settleOneHop, releaseEstablishedLeftover and the
 * reorg rule (CR-H2), §4, L-2, L-13, §8 T3 (the Verify-pass legs), §8.2
 * sabotage c/k/v; m is in rc45-t3-verify-cap.test.js, l in
 * rc45-t7-verify-crash.test.js). Internal RED-first regression material for the
 * RC45 candidate; not an audit.
 *
 * RED on C1 e62b1973 (Verify refuses on any vault-wide PENDING record before
 * reading the chain; case A advances at zero depth and relabels no request;
 * case E writes TERMINATED_UNKNOWN; an uncontested owner recover completes at
 * zero depth in submit; no loser, twin, one-hop, leftover or contradiction
 * handling). GREEN after F5:
 *   - below D = 1,000 DAA a SEEN spender of the recorded outpoint L answers
 *     CLAIM_PENDING{txId, depth, required} with zero writes;
 *   - at D: the primary member (earliest valid, preferring signed states)
 *     completes (manifest, receipt, audit reconciled_advanced, own claims
 *     R-released, reservation, CHAIN_VERIFIED last); signed same-txid twins
 *     complete, BUILT twins stay BUILT; journal-free PENDING records exactly on
 *     L with another txid become STALE with one transition_superseded row and
 *     their claims and reservation released (losers first for a terminal
 *     winner);
 *   - every Close & recover is two-step: submit returns at SUBMITTED with no
 *     manifest write; Verify writes RECOVERED at D (CR-H2);
 *   - settleOneHop settles the ancestor of a recorded advancement at D;
 *     releaseEstablishedLeftover releases an established rejection's leftover
 *     claims (>= 1 matching record) and reports it; an orphan claim stays
 *     byte-identical;
 *   - absence answers UNKNOWN{reason, unchecked} with NO write (never
 *     TERMINATED_UNKNOWN); two SEEN spenders, or the recorded ancestor live
 *     again / spent by another recorded txid, answer CHAIN_CONTRADICTION with
 *     no write; a failed read with nothing seen, or a harness spawn failure in
 *     validateIdentity, is a 422 (the SDK call rejects) with no write;
 *   - validateIdentity runs only for SEEN groups (the candidate grouping cap
 *     and dedupe legs are in sdk/test/rc45-t3-verify-cap.test.js).
 * The owner-side legs of T3 that belong to F3 (quota full, agent reject 403,
 * the contested submit returning at SUBMITTED, the mempool wire text at the
 * owner's submit) are not repeated here; the owner's contested Pause below
 * lands out of band (the owner holds the signed transaction).
 *
 * Layers: SDK. Real v0.4.1 compiler, pv_call_encoder, TEST-key signatures
 * (deterministic dev signer) and pv_vm_preflight for every consensus byte.
 * Node observations come ONLY from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js passed as `rpc`; every config names
 * ws://127.0.0.1:1, so nothing can dial a node. The harness-failure legs run
 * the candidate Verify in a fresh child process with POLICYVAULT_PV_VM_PREFLIGHT_PATH
 * pointing to a failing TEST harness (vm-preflight.js reads it at load).
 *
 * RC44-written shapes (CR-M13): the one-hop vault (an age-released PREFLIGHT_VERIFIED
 * ancestor, a signed W1 twin) comes from the pinned df5b8de writers in
 * POLICYVAULT_TEST_RC44_TREE (sdk/testutil/rc45-f5-rc44-history.js; a missing
 * or mismatched tree FAILS, never skips). Candidate-written bases are
 * labelled; contested pairs are finalized apart and merged
 * (sdk/testutil/rc45-f5-kit.js finalizeApart). SYNTHETIC: the orphan claim
 * (claim writer on a request never stored) and the leftover's crash point
 * (the store throws at the claim release after the durable SUBMISSION_REJECTED write).
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const H5 = require("../testutil/rc45-f5-rc44-history");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const { recordedNegativeIsEstablished } = require("../src/submission-classification");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({
  cp: K.vault("t3-cp"), cr: K.vault("t3-cr"), tw: K.vault("t3-tw"), ur: K.vault("t3-ur"), oc: K.vault("t3-oc"), lo: K.vault("t3-lo"),
  un: K.vault("t3-un"), cc: K.vault("t3-cc"), rf: K.vault("t3-rf"), vs: K.vault("t3-vs"), hop: H5.F5_RC44_VAULTS.hop
});
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const sansState = (r) => { const { state, ...rest } = r; void state; return rest; };
const mentions = (list, r) => Array.isArray(list) && (JSON.stringify(list).includes(r.requestId) || JSON.stringify(list).includes(r.txId));

async function rejection(promise, message) {
  let caught = null;
  await assert.rejects(promise, (e) => { caught = e; return true; }, message);
  return caught;
}
async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));

before(async () => {
 
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  // (1) RC44-written history (hop), by the pinned df5b8de writers only.
  const rc44 = H5.runF5Rc44Scenario("t3", { track });
  H = rc44.result.hist;
  // (2) One template root: the RC44 records plus the candidate-written bases.
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t3-template-"), rpcUrl: LOOPBACK });
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  B = {};
  for (const [tag, action] of [["cp", "ownerPause"], ["cr", "ownerRecover"]]) {
    // A delegate spend D and the owner's break-glass Q on L0, finalized apart: D holds the only claim (contested).
    // cp also carries BUILT and rejected delegate noise on L0 (optional groups; never losers).
    const v = V[tag]; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const q = await k.ownerOp(v, action); await K.sleep(3);
    const noise = [];
    if (tag === "cp") {
      noise.push(id(await k.agentSpend(v, 1)), id(await k.agentSpend(v, 2)));
      const rj = await k.agentSpend(v, 3); await cand.wr4.markWalletRejected(template, rj.requestId); noise.push(id(rj));
    }
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B[tag] = { d: id(d), q: id(q), noise };
  }
  { // tw: three owner Pauses with the same fuel on L0 (same txid): T1 BUILT (earliest), Q and T2 finalized apart (Q holds the claim).
    const v = V.tw; await K.seedVault(cand, template, v, w);
    const t1 = await k.ownerOp(v, "ownerPause"); await K.sleep(3);
    const q = await k.ownerOp(v, "ownerPause"); await K.sleep(3);
    const t2 = await k.ownerOp(v, "ownerPause");
    assert.equal(q.txId, t1.txId); assert.equal(t2.txId, t1.txId);
    await K.finalizeApart(cand, template, [{ requestId: q.requestId, signer: w.owner }, { requestId: t2.requestId, signer: w.owner }], { claimHolder: q.requestId, track });
    B.tw = { t1: id(t1), q: id(q), t2: id(t2) };
  }
  { // ur: the owner's recover alone, finalized (own claim).
    const v = V.ur; await K.seedVault(cand, template, v, w);
    const q = await k.finalize(await k.ownerOp(v, "ownerRecover"), w.owner); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    B.ur = { q: id(q) };
  }
  { // oc: SYNTHETIC orphan claim on L0 — the finalize's claim for a spend built in a scratch copy and never stored here.
    const v = V.oc; await K.seedVault(cand, template, v, w);
    const scratch = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f5-t3-orphan-"), rpcUrl: LOOPBACK });
    await K.install(cand, scratch, await K.snapshot(cand, template));
    const r = await K.kitFor(cand, scratch, w).agentSpend(v, 4);
    await cand.claims.claimTransition(template, K.claimArgsFor(r));
    B.oc = { claimTxId: r.txId, L: r.predecessorOutpoint, input0: frozenOf(r).inputs[0] };
  }
  { const v = V.lo; await K.seedVault(cand, template, v, w); B.lo = { d: id(await k.finalize(await k.agentSpend(v, 4), w.agent)) }; }
  { const v = V.un; await K.seedVault(cand, template, v, w); B.un = { k: id(await k.agentSpend(v, 2)) }; }
  { const v = V.cc; await K.seedVault(cand, template, v, w); B.cc = { k1: id(await k.agentSpend(v, 1)), k2: id(await k.agentSpend(v, 2)) }; }
  { const v = V.rf; await K.seedVault(cand, template, v, w); B.rf = { d: id(await k.finalize(await k.agentSpend(v, 4), w.agent)) }; }
  { // vs: W BUILT (never signed here; it lands out of band), U finalized (PENDING, signed bytes).
    const v = V.vs; await K.seedVault(cand, template, v, w);
    const wr = await k.agentSpend(v, 2); await K.sleep(3);
    const u = await k.finalize(await k.agentSpend(v, 3), w.agent);
    B.vs = { w: id(wr), u: id(u) };
  }
  // Compile the RC44-written states with the candidate compiler once, so fresh cases reuse the template's cache.
  for (const r of [H.hop.a, H.hop.b]) {
    const q = await cand.wr4.loadRequest(template, r.requestId);
    for (const s of [q.build.stateJson, q.build.successorState]) cand.submit4.successorAddressAndScript(template, q.build.template, s, q.contractVersion);
  }
 
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
  const dataRoot = mk("pv-rc45-f5-t3-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f5_t3_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), model = K.chainModel(config);
  return {
    config, store, model, pgDatabase, k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    submissionClaim: (txId) => store.read(Categories.SUBMISSION_CLAIM, txId),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: model.rpc })
  };
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
const auditOf = async (x, action) => (await x.audit()).filter((e) => e.action === action);
/* The harness-failure environment for a Verify child: a TEST pv_vm_preflight that cannot run the engine. */
function failingHarness() {
  const dir = mk("pv-rc45-f5-t3-harness-"), harness = path.join(dir, "pv_vm_preflight_failing");
  fs.writeFileSync(harness, "#!/bin/sh\necho 'TEST harness: engine unavailable' 1>&2\nexit 3\n", { mode: 0o755 });
  return { POLICYVAULT_PV_VM_PREFLIGHT_PATH: harness };
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t3 = (name, fn) => test(`RC45 T3 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- contested break-glass, depth gating, completePositive, settleLoser ---------------- */
  t3("contested Pause, owner wins: below D Verify answers CLAIM_PENDING{txId, depth, required} with zero writes; at D the Pause completes (PAUSED, CHAIN_VERIFIED + receipt + reconciled_advanced), the delegate PREFLIGHT_VERIFIED becomes STALE with its claims and reservation released and one transition_superseded row; BUILT/rejected noise untouched; a second Verify writes nothing [RED on C1]", async (x) => {
    const d = await x.req(B.cp.d), q = await x.req(B.cp.q), dBefore = await x.rawRequest(d.requestId), qBefore = await x.rawRequest(q.requestId);
    const noiseBefore = await Promise.all(B.cp.noise.map((r) => x.rawRequest(r)));
    assert.equal(d.state, "PREFLIGHT_VERIFIED"); assert.equal(q.state, "PREFLIGHT_VERIFIED");
    const claim = await x.claimOn(d.predecessorOutpoint);
    assert.equal(claim.txId, d.txId, "the delegate holds the only claim on L (the owner's break-glass took none)");
    x.model.seedInputs(frozenOf(q), q.covenantId); // L and the owner's fuel, live and deep
    x.model.confirm(frozenOf(q), q.txId); // the owner's signed Pause lands (depth 0)
    x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.cp), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING", "depth 999 < D: the SEEN spender is not yet CONFIRMED");
    assert.equal(pending.txId, q.txId); assert.equal(String(pending.depth), "999"); assert.equal(String(pending.required), "1000");
    assert.deepEqual(await x.snap(), below, "below D nothing is written (sabotage c, k)");
    assert.deepEqual(await x.claimOn(d.predecessorOutpoint), claim, "the delegate's claim is byte-identical");
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.cp), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId); assert.equal(done.requestId, q.requestId);
    assert.ok(mentions(done.settled, d), "settled[] reports the superseded delegate request");
    const m = await x.rawManifest(V.cp);
    assert.equal(m.status, "PAUSED"); assert.equal(m.latestTransitionTxId, q.txId);
    assert.deepEqual(m.live.outpoint, { transactionId: q.txId, index: 0 }); assert.equal(m.live.stateId, q.successorStateId);
    assert.equal(m.lastTransition.txId, q.txId); assert.deepEqual(m.lastTransition.oldOutpoint, q.predecessorOutpoint);
    const qa = await x.rawRequest(q.requestId), da = await x.rawRequest(d.requestId);
    assert.equal(qa.state, "CHAIN_VERIFIED"); assert.deepEqual(sansState(qa), sansState(qBefore), "the winner's relabel changes only its state (H-44)");
    assert.equal(da.state, "STALE"); assert.deepEqual(sansState(da), sansState(dBefore), "the loser's relabel changes only its state (H-44)");
    const receipt = await x.receipt(q.txId);
    assert.equal(receipt.proof.requestId, q.requestId); assert.equal(receipt.proof.successorOutpoint, `${q.txId}:0`); assert.equal(receipt.proof.reconciled, true);
    assert.equal(await x.claimOn(d.predecessorOutpoint), null, "the loser's claim on L is released (R: read its own txid first)");
    assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.submissionClaim(q.txId), null);
    assert.equal(await x.reservationOf(d), null, "the loser's reservation is released");
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1, "one transition_superseded row");
    assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].txId, d.txId); assert.equal(superseded[0].winnerTxId, q.txId);
    const advanced = (await auditOf(x, "reconciled_advanced")).filter((e) => e.txId === q.txId);
    assert.equal(advanced.length, 1); assert.equal(advanced[0].requestId, q.requestId); assert.equal(advanced[0].via, "reconcile"); assert.equal(advanced[0].result, "CHAIN_VERIFIED");
    assert.equal(advanced[0].oldStateId, q.predecessorStateId); assert.equal(advanced[0].newStateId, q.successorStateId);
    assert.deepEqual(await Promise.all(B.cp.noise.map((r) => x.rawRequest(r))), noiseBefore, "BUILT and rejected records on L are neither losers nor twins");
    const settled = await x.snap();
    const again = await resolved(() => x.verify(V.cp), "a second Verify answers");
    assert.equal(again.status, "CONSISTENT"); assert.deepEqual(await x.snap(), settled, "a second Verify writes nothing");
  });
  t3("contested Close & recover, owner wins: below D CLAIM_PENDING with zero writes; at D the vault is RECOVERED (receipt successorOutpoint null), the delegate record STALE with one transition_superseded row; the next Verify answers TERMINAL with no write and no node call [RED on C1]", async (x) => {
    const d = await x.req(B.cr.d), q = await x.req(B.cr.q);
    assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId, "the delegate holds the only claim");
    x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.cr), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, q.txId); assert.equal(String(pending.required), "1000");
    assert.deepEqual(await x.snap(), below, "no terminal status is written below D (CR-H2)");
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.cr), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId); assert.equal(done.requestId, q.requestId);
    const m = await x.rawManifest(V.cr);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, q.txId); assert.equal(m.lastTransition.txId, q.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    const receipt = await x.receipt(q.txId);
    assert.equal(receipt.proof.requestId, q.requestId); assert.equal(receipt.proof.successorOutpoint, null); assert.equal(receipt.proof.value, q.build.accounting.terminalPayout);
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    assert.equal(await x.claimOn(d.predecessorOutpoint), null); assert.equal(await x.reservationOf(d), null); assert.equal(await x.submissionClaim(d.txId), null);
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].winnerTxId, q.txId);
    const closed = await x.snap(), calls = x.model.calls.length;
    const again = await resolved(() => x.verify(V.cr), "a second Verify answers");
    assert.equal(again.status, "TERMINAL"); assert.deepEqual(await x.snap(), closed); assert.equal(x.model.calls.length, calls, "a closed vault answers without a node call");
  });
  t3("delegate wins over the owner's contested Pause: at D the delegate spend completes, the owner's PREFLIGHT_VERIFIED Pause becomes STALE (transition_superseded names the delegate as winner); a second Pause then completes [RED on C1]", async (x) => {
    const d = await x.req(B.cp.d), q = await x.req(B.cp.q);
    x.model.seedInputs(frozenOf(q), q.covenantId); // L and the owner's fuel
    x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.cp), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, d.txId); assert.equal(done.requestId, d.requestId);
    assert.ok(mentions(done.settled, q), "settled[] reports the owner's superseded Pause");
    const m = await x.rawManifest(V.cp), index = frozenOf(d).outputs.findIndex((o) => o.covenant !== null);
    assert.equal(m.status, "ACTIVE"); assert.deepEqual(m.live.outpoint, { transactionId: d.txId, index });
    assert.equal(m.agentRegistry[0].periodSpent, (4n * KAS).toString());
    assert.equal((await x.rawRequest(d.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.receipt(d.txId)).proof.requestId, d.requestId);
    assert.equal((await x.rawRequest(q.requestId)).state, "STALE", "the owner's Pause never executed: STALE");
    assert.equal(await x.claimOn(d.predecessorOutpoint), null, "the winner releases its own claim");
    assert.equal(await x.reservationOf(d), null); assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.submissionClaim(q.txId), null);
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, q.requestId); assert.equal(superseded[0].txId, q.txId); assert.equal(superseded[0].winnerTxId, d.txId);
    const again = await resolved(() => x.k.ownerOp(V.cp, "ownerPause"), "the owner can Pause the new live state");
    const signed = await resolved(() => x.k.finalize(again, w.owner), "and finalize it");
    x.model.know(signed); x.model.confirmOnSubmit = true;
    const submitted = await resolved(() => x.submit(signed.requestId), "an uncontested non-terminal submit completes (L-2)");
    assert.equal(submitted.request.state, "CHAIN_VERIFIED");
    assert.equal((await x.rawManifest(V.cp)).status, "PAUSED");
  });
  t3("same-txid owner twins (CR-M10): at D the primary is the earliest SIGNED member, its signed twin completes too, and the BUILT twin stays BUILT byte-identical (never STALE) [RED on C1]", async (x) => {
    const t1 = await x.req(B.tw.t1), q = await x.req(B.tw.q), t2 = await x.req(B.tw.t2), t1Before = await x.rawRequest(t1.requestId);
    assert.equal(t1.state, "BUILT"); assert.equal(q.state, "PREFLIGHT_VERIFIED"); assert.equal(t2.state, "PREFLIGHT_VERIFIED");
    x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.tw), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId);
    assert.equal(done.requestId, q.requestId, "the primary is the earliest valid member preferring signed states (not the earlier BUILT twin)");
    assert.equal((await x.receipt(q.txId)).proof.requestId, q.requestId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.rawRequest(t2.requestId)).state, "CHAIN_VERIFIED", "a signed same-txid twin completes (twinComplete)");
    assert.deepEqual(await x.rawRequest(t1.requestId), t1Before, "the BUILT twin stays BUILT and byte-identical (S5)");
    assert.equal((await auditOf(x, "transition_superseded")).length, 0, "twins are never superseded");
    assert.equal(await x.claimOn(q.predecessorOutpoint), null); assert.equal((await x.rawManifest(V.tw)).status, "PAUSED");
  });
  t3("uncontested Close & recover is two-step (CR-H2): submit returns at SUBMITTED with no manifest write although the recover landed at depth 0; below D Verify answers CLAIM_PENDING with zero writes; at D the vault is RECOVERED with a receipt and the owner's claims are released [RED on C1]", async (x) => {
    const q = await x.req(B.ur.q);
    const manifestBefore = await x.rawManifest(V.ur);
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true;
    const submitted = await resolved(() => x.submit(q.requestId), "the recover submit returns without error");
    void submitted;
    assert.equal((await x.rawRequest(q.requestId)).state, "SUBMITTED", "every ownerRecover is contested: submit stops at SUBMITTED (no poll, sabotage v)");
    assert.deepEqual(await x.rawManifest(V.ur), manifestBefore, "no terminal status is written at zero depth");
    assert.equal(await x.receipt(q.txId), null, "no receipt at zero depth");
    assert.deepEqual(x.model.broadcasts, [q.txId]);
    assert.equal((await x.claimOn(q.predecessorOutpoint)).txId, q.txId, "the owner's own claim is kept");
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.ur), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, q.txId); assert.equal(String(pending.depth), "999");
    assert.deepEqual(await x.snap(), below);
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.ur), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId);
    const m = await x.rawManifest(V.ur);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.receipt(q.txId)).proof.requestId, q.requestId);
    assert.equal(await x.claimOn(q.predecessorOutpoint), null); assert.equal(await x.submissionClaim(q.txId), null);
  });

  /* ---------------- claims without a spender: orphan and established leftover (CR-M4, CR-I1, H-06) ---------------- */
  t3("orphan claim (CR-M4): with L live Verify answers CLAIM_PENDING{claimTxId} and the claim stays byte-identical; once L is spent by an unknown transaction Verify answers UNKNOWN and writes nothing (no TERMINATED_UNKNOWN) [RED on C1]", async (x) => {
    const L = B.oc.L, claim = await x.claimOn(L);
    assert.equal(claim.txId, B.oc.claimTxId);
    x.model.add(L, B.oc.input0.utxo.amount, B.oc.input0.utxo.scriptPublicKey, V.oc.cov, x.model.virtualDaaScore - 5000n);
    const live = await x.snap();
    const pending = await resolved(() => x.verify(V.oc), "Verify with L live");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.claimTxId, B.oc.claimTxId);
    assert.deepEqual(await x.snap(), live, "a lone claim on L is never released or changed");
    x.model.remove(L); // L spent by a transaction nothing records
    const out = await resolved(() => x.verify(V.oc), "Verify with L gone");
    assert.equal(out.status, "UNKNOWN");
    assert.deepEqual(await x.snap(), live, "UNKNOWN writes nothing: the orphan claim stays byte-identical and the manifest is not TERMINATED_UNKNOWN");
  });
  t3("releaseEstablishedLeftover: an established SUBMISSION_REJECTED whose claim release was interrupted leaves its claims and reservation; with L live Verify releases them, audits submission_rejected_claims_released, answers CONSISTENT and reports it in settled[] [RED on C1]", async (x) => {
    const d = await x.req(B.lo.d), L = d.predecessorOutpoint, key = cand.claims.transitionClaimKey(L);
    x.model.know(d); x.model.seedInputs(frozenOf(d), d.covenantId);
    x.model.mempoolAdd(K.hex("rc45-f5-t3-lo-out-of-app-spend"), [L]); // an out-of-app spend of L waits in the mempool
    const s = x.store, remove = s.remove.bind(s); let crashed = false;
    s.remove = async (c, k) => { if (!crashed && c === Categories.TRANSITION_CLAIM && k === key) { crashed = true; throw new Error("TEST crash after the durable SUBMISSION_REJECTED write (before the claim release)"); } return remove(c, k); };
    let error;
    try { error = await rejection(x.submit(d.requestId), "the rejected submit is interrupted"); } finally { s.remove = remove; }
    assert.equal(crashed, true, `the REJECTED branch reached its claim release (${error && error.message})`);
    const rejected = await x.rawRequest(d.requestId);
    assert.equal(rejected.state, "SUBMISSION_REJECTED"); assert.equal(recordedNegativeIsEstablished(rejected), true, "the rejection is an established negative");
    assert.equal((await x.claimOn(L)).txId, d.txId, "leftover transition claim"); assert.ok(await x.submissionClaim(d.txId), "leftover submission claim");
    assert.ok(await x.reservationOf(d), "leftover reservation");
    const out = await resolved(() => x.verify(V.lo), "Verify with L live");
    assert.equal(out.status, "CONSISTENT", "the established rejection's leftover is released (>= 1 matching record)");
    assert.ok(mentions(out.settled, d), "settled[] reports the released leftover (CR-I1)");
    assert.equal(await x.claimOn(L), null); assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.reservationOf(d), null);
    assert.deepEqual(await x.rawRequest(d.requestId), rejected, "the rejected record itself is unchanged");
    const released = (await auditOf(x, "submission_rejected_claims_released")).filter((e) => e.txId === undefined || e.txId === d.txId);
    assert.equal(released.length, 1, "one submission_rejected_claims_released row (any txId it carries names the rejected transaction)");
  });

  /* ---------------- settleOneHop on RC44-written history (H-25) ---------------- */
  t3("settleOneHop (RC44-written): below D nothing is written; at D the age-released ancestor A becomes STALE (winner B) and B's signed twin T completes; CONSISTENT [RED on C1]", async (x) => {
    const a = await x.req(H.hop.a.requestId), b = await x.req(H.hop.b.requestId), t = await x.req(H.hop.t.requestId);
    assert.equal(a.state, "PREFLIGHT_VERIFIED"); assert.equal(b.state, "CHAIN_VERIFIED"); assert.equal(t.state, "PREFLIGHT_VERIFIED");
    const m0 = await x.rawManifest(V.hop);
    assert.equal(m0.lastTransition.txId, b.txId, "RC44 advanced L0 -> L1 by B");
    x.model.confirm(frozenOf(b), b.txId); // L1 (and B's payment) indexed at depth 0
    x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const early = await resolved(() => x.verify(V.hop), "Verify below depth D");
    assert.equal(early.status, "CONSISTENT", "ancestor records never block the live L1");
    assert.deepEqual(await x.snap(), below, "no settlement below D");
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.hop), "Verify at depth D");
    assert.equal(done.status, "CONSISTENT");
    assert.ok(mentions(done.settled, a), "settled[] reports the superseded ancestor");
    assert.equal((await x.rawRequest(a.requestId)).state, "STALE");
    assert.equal((await x.rawRequest(t.requestId)).state, "CHAIN_VERIFIED", "the signed W1-txid twin completes");
    assert.equal(await x.claimOn(t.predecessorOutpoint), null, "the twin's own claim on L0 is released");
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, a.requestId); assert.equal(superseded[0].winnerTxId, b.txId);
    assert.deepEqual(await x.rawManifest(V.hop), m0, "the manifest is not rewritten");
  });
  for (const variant of ["the recorded ancestor L0 is live again", "the ancestor A (another recorded txid) is SEEN spending L0"]) {
    t3(`step 10 on RC44-written history: L1 gone and ${variant} -> CHAIN_CONTRADICTION, nothing written [RED on C1]`, async (x) => {
      const a = await x.req(H.hop.a.requestId), b = await x.req(H.hop.b.requestId);
      if (variant.startsWith("the recorded")) {
        const input0 = frozenOf(b).inputs[0];
        x.model.add(input0.previousOutpoint, input0.utxo.amount, input0.utxo.scriptPublicKey, b.covenantId, x.model.virtualDaaScore - 5000n);
      } else x.model.confirm(frozenOf(a), a.txId, x.model.virtualDaaScore - 5000n);
      const before = await x.snap();
      const out = await resolved(() => x.verify(V.hop), "Verify answers");
      assert.equal(out.status, "CHAIN_CONTRADICTION");
      assert.deepEqual(await x.snap(), before, "a contradiction writes nothing");
    });
  }

  /* ---------------- absence, contradiction and unavailability stay distinct (-05; H-49) ---------------- */
  t3("absence: L gone and nothing recorded is SEEN -> UNKNOWN with no write (never TERMINATED_UNKNOWN; UNKNOWN has no durable marker) [RED on C1]", async (x) => {
    const before = await x.snap();
    const out = await resolved(() => x.verify(V.un), "Verify answers");
    assert.equal(out.status, "UNKNOWN"); assert.ok(out.reason, "UNKNOWN names its reason");
    assert.deepEqual(await x.snap(), before, "UNKNOWN writes nothing");
    assert.equal((await x.rawManifest(V.un)).status, "ACTIVE");
  });
  t3("two recorded spenders of L are both SEEN at depth -> CHAIN_CONTRADICTION with no write [RED on C1]", async (x) => {
    const k1 = await x.req(B.cc.k1), k2 = await x.req(B.cc.k2);
    x.model.confirm(frozenOf(k1), k1.txId); x.model.confirm(frozenOf(k2), k2.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const out = await resolved(() => x.verify(V.cc), "Verify answers");
    assert.equal(out.status, "CHAIN_CONTRADICTION");
    assert.deepEqual(await x.snap(), before);
  });
  t3("unavailability: L gone and the candidate reads fail with nothing SEEN -> 422 (the SDK call rejects) with no write [RED on C1]", async (x) => {
    const d = await x.req(B.rf.d), address = x.model.addressOf(frozenOf(d).inputs[0].utxo.scriptPublicKey);
    x.model.failRead = (a) => a !== address; // the recorded outpoint's address answers (L absent); every other read fails
    const before = await x.snap();
    await rejection(x.verify(V.rf), "nothing seen and a read failed: RECONCILE_FAILED, never UNKNOWN");
    assert.deepEqual(await x.snap(), before);
  });
  t3("unavailability of the recorded outpoint read itself -> the SDK call rejects with no write [holds on C1]", async (x) => {
    x.model.failRead = () => true;
    const before = await x.snap();
    await rejection(x.verify(V.un), "the node cannot answer");
    assert.deepEqual(await x.snap(), before);
  });

  /* ---------------- validate only SEEN groups; environment errors are 422 (CR-M2, CR2-L3) ---------------- */
  t3("validateIdentity runs only for SEEN groups: with a failing VM harness, the byte-less landed W below D answers CLAIM_PENDING with zero writes although the unseen signed U would fail its harness spawn [RED on C1]", async (x) => {
    const wr = await x.req(B.vs.w), u = await x.req(B.vs.u);
    assert.equal(wr.state, "BUILT"); assert.equal(u.state, "PREFLIGHT_VERIFIED");
    x.model.confirm(frozenOf(wr), wr.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const before = await x.snap();
    const run = K.verifyInChild(x, V.vs, { env: failingHarness(), pg: PG });
    assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
    assert.ok(run.result.ok, `Verify answers (${run.result.message})`);
    assert.equal(run.result.value.status, "CLAIM_PENDING"); assert.equal(run.result.value.txId, wr.txId);
    assert.deepEqual(await x.snap(), before);
  });
  t3("an environment error in validateIdentity (VM harness spawn) is a 422 with no write; once the harness runs, the same Verify completes W and supersedes U [RED on C1]", async (x) => {
    const wr = await x.req(B.vs.w), u = await x.req(B.vs.u);
    x.model.confirm(frozenOf(wr), wr.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const run = K.verifyInChild(x, V.vs, { env: failingHarness(), pg: PG });
    assert.equal(run.signal, null); assert.equal(run.status, 0, run.stderr);
    assert.equal(run.result.ok, false, `the harness failure aborts the settlement (${JSON.stringify(run.result.value)})`);
    assert.match(run.result.message, /harness/i, "the refusal is the harness spawn failure");
    assert.deepEqual(await x.snap(), before, "an environment error writes nothing");
    const done = await resolved(() => x.verify(V.vs), "Verify with a working harness");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, wr.txId);
    assert.equal((await x.rawRequest(wr.requestId)).state, "CHAIN_VERIFIED", "a byte-less BUILT record completes by its txid");
    assert.equal((await x.rawRequest(u.requestId)).state, "STALE");
    void settle;
  });
}
