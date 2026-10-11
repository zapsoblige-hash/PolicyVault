"use strict";
/*
 * RC45 T3 — OWNER BREAK-GLASS (fix item F3 RC45-L5-OWNER-BREAKGLASS; plan
 * rc45-simplified-plan-r2 §1 O1, §2.0 BREAK_GLASS_V4 and R (read-then-release),
 * §2.3 touch points (A1 quota exemption and count, B3, the contested
 * break-glass finalize and submit, CR-H2 every ownerRecover contested, the
 * REJECTED branch's read-then-release J1-ALL-01, A4 request.confirmed only for
 * CHAIN_VERIFIED, A2 reject narrowing), §4 submit rows, §5 S1/S2/S5, §8 T3 owner
 * legs and the F3 part of T8 (quota check and count), §8.2 sabotage b, i, j, o,
 * v). Internal RED-first regression material for the RC45 candidate; not an
 * audit.
 *
 * RED on C1 e62b1973: the hosted quota counts and refuses the owner's
 * break-glass (429 at a full per-vault quota; break-glass BUILT rows are
 * counted); any vault-wide pending record refuses the owner's build
 * (REQUEST_RECOVERY_REQUIRED); a break-glass finalize or submit without the
 * transition claim is refused (CLAIM_CONFLICT); an uncontested Close & recover
 * completes at zero depth and emits request.confirmed; an agent may reject the
 * owner's request. GREEN after F3 (on top of F2, F4 and F5):
 *   - A1: POST /wallet/v4/requests skips the open-request quota for ownerPause
 *     and ownerRecover, and the count excludes v4 break-glass rows; ordinary
 *     owner actions stay counted and refused;
 *   - O1: on a live vault the owner's Pause / Close & recover builds (201),
 *     finalizes without touching the delegate's transition claim (no claim is
 *     taken when the delegate holds it; absent -> the owner's own claim), and
 *     its contested submit returns 200 at SUBMITTED right after the broadcast:
 *     no poll, no manifest write, no receipt, no request.confirmed, the
 *     delegate's records byte-identical;
 *   - CR-H2: every ownerRecover is contested, the uncontested one included;
 *   - Verify (F5) then completes the accepted spend at D = 1,000 DAA (the
 *     owner's, or the delegate's when it wins; the loser STALE); a second
 *     Pause after the delegate wins is uncontested and completes at zero
 *     depth (L-2) with request.confirmed;
 *   - the real mempool wire text "... already spent by transaction <d> in the
 *     mempool" labels the owner's request SUBMISSION_REJECTED (an established
 *     negative) with its audit row, releases the owner's submission claim and
 *     reads the transition claim before any release: the delegate's claim stays
 *     byte-identical (J1-ALL-01, sabotage o);
 *   - an RC44-written claimless byte-less FINALIZED delegate spend on L: the
 *     owner's finalize takes its own claim and the submit is contested
 *     (SUBMITTED) by the PENDING delegate record;
 *   - same-txid owner twins: the abandoned BUILT twin never refuses the signed
 *     one and stays BUILT byte-identical (S5, CR-M10);
 *   - A2: an agent principal rejecting an owner-signed request gets 403
 *     REQUEST_FORBIDDEN with nothing changed; the signer and the owner still
 *     reject (hosted).
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, wallet
 * sessions signed in with TEST keys) plus SDK. Real v0.4.1 compiler,
 * pv_call_encoder, TEST-key signatures (deterministic dev signer) and
 * pv_vm_preflight for every consensus byte. Node observations come ONLY from
 * the explicit chain model of sdk/testutil/rc45-f5-kit.js (UTXOs with
 * blockDaaScore, a virtualDaaScore, a mempool with conflict detection and the
 * rusty-kaspa v2.0.1 wire texts): Verify gets it as `rpc`; the route-level
 * submit reaches it through a module-cache wrapper of the REAL
 * submitWalletRequestV4 (sdk/testutil/rc45-f3-kit.js submitThroughModel; never
 * a stub). Every config names ws://127.0.0.1:1, so nothing can dial a node.
 *
 * Bases (template, installed into a fresh store per test):
 *   s1 — CANDIDATE-WRITTEN: an agent policy naming 33 TEST recipients; 300
 *        agent spends built then rejected (10 amounts x 30 recipients) and 32
 *        agent spends left BUILT (the per-vault quota, 32 by default, is full),
 *        built apart in parallel candidate processes and merged
 *        (rc45-f3-kit.js buildApart); then the delegate spend d built and
 *        finalized (PREFLIGHT_VERIFIED, holding the claim on L).
 *   s2 — CANDIDATE-WRITTEN: one BUILT and one rejected agent spend, then d
 *        finalized (PREFLIGHT_VERIFIED, holding the claim on L).
 *   ur, rj, qc, qd — CANDIDATE-WRITTEN clean vaults (rj: two BUILT agent spends).
 *   fz — RC44-WRITTEN (CR-M13): a byte-less FINALIZED agent spend on the live L
 *        with no claim, by the pinned df5b8de writers in POLICYVAULT_TEST_RC44_TREE
 *        (sdk/testutil/rc45-rc44-history.js scenario t4; the five writer sha256
 *        pins and the sdk/src tree are verified; a missing or mismatched tree
 *        FAILS, never skips).
 *
 * Both stores: JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE} (the rc45 runner's pg mode; a skipped PostgreSQL leg there is a
 * FAIL). TEST keys only; no production data, credentials or endpoints.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const H44 = require("../testutil/rc45-rc44-history");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const { recordedNegativeIsEstablished } = require("../src/submission-classification");
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({
  s1: K.vault("f3-s1"), s2: K.vault("f3-s2"), ur: K.vault("f3-ur"), rj: K.vault("f3-rj"), qc: K.vault("f3-qc"), qd: K.vault("f3-qd"),
  fz: H44.T4_VAULTS.fz
});
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const OPEN = new Set(["BUILT", "AWAITING_APPROVALS"]);

async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f3-t3-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  B = {};
  { // s1 first (buildApart copies the whole template into each child root).
    const v = V.s1, spam = K.spamRecipients(template, 32);
    await K.seedVault(cand, template, v, w, { recipients: [w.recipient, ...spam] });
    const jobs = [];
    for (let a = 1n; a <= 10n; a++) for (let i = 0; i < 30; i++) jobs.push({ sompi: String(KAS + a * (KAS / 10n)), recipient: spam[i].xonly, reject: true });
    for (let i = 0; i < 32; i++) jobs.push({ sompi: String(KAS), recipient: spam[i].xonly, reject: false });
    const noise = await F3.buildApart(cand, template, v, jobs, { children: 24, track });
    const built = noise.filter((n) => !n.reject), rejected = noise.filter((n) => n.reject);
    assert.equal(built.length, 32); assert.equal(rejected.length, 300);
    assert.equal(new Set(noise.map((n) => n.txId)).size, 332, "332 distinct delegate transactions on L");
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent);
    assert.equal(d.state, "PREFLIGHT_VERIFIED");
    B.s1 = { d: id(d), built: built.map(id), rejected: rejected.map(id) };
  }
  { const v = V.s2; await K.seedVault(cand, template, v, w);
    const n1 = await k.agentSpend(v, 1); await K.sleep(3);
    const n2 = await k.agentSpend(v, 2); await cand.wr4.markWalletRejected(template, n2.requestId); await K.sleep(3);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    B.s2 = { d: id(d), noise: [id(n1), id(n2)] };
  }
  { await K.seedVault(cand, template, V.ur, w); }
  { const v = V.rj; await K.seedVault(cand, template, v, w);
    const a = await k.agentSpend(v, 2); await K.sleep(3); const a2 = await k.agentSpend(v, 3);
    B.rj = { a: id(a), a2: id(a2) };
  }
  { await K.seedVault(cand, template, V.qc, w); await K.seedVault(cand, template, V.qd, w); }
  // fz: RC44-written history, by the pinned df5b8de writers only.
  const rc44 = H44.runRc44Scenario("t4", { track });
  H = rc44.result.hist;
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  { const r = await cand.wr4.loadRequest(template, H.fz.r.requestId);
    assert.equal(r.state, "FINALIZED"); assert.equal(r.finalTransaction, undefined);
    // Compile the RC44-written states with the candidate compiler once, so fresh cases reuse the template's cache.
    for (const s of [r.build.stateJson, r.build.successorState]) cand.submit4.successorAddressAndScript(template, r.build.template, s, r.contractVersion);
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

/* A fresh hosted case (authMode enabled; owner and agent signed in with TEST keys) holding the template's records. */
async function fresh(backend, quota = {}) {
  const dataRoot = mk("pv-rc45-f3-t3-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK, ...quota };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f3_t3_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig(hosted);
  assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), api = F3.apiFor(config);
  const x = {
    config, store, api, pgDatabase, model: K.chainModel(config), k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawMany: (ids) => Promise.all(ids.map((requestId) => store.read(Categories.REQUEST, requestId))),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    submissionClaim: (txId) => store.read(Categories.SUBMISSION_CLAIM, txId),
    reservationOf: (r) => store.read(Categories.TRANSITION_CLAIM, cand.budget.reservationKey(r)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    requestCount: async () => (await store.listKeys(Categories.REQUEST)).length,
    openOn: async (v) => (await store.listValues(Categories.REQUEST)).filter((r) => r && r.vaultId === v.vaultId && OPEN.has(r.state)).length,
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: x.model.rpc }),
    confirmed: (requestId) => F3.eventsOf(config, "request.confirmed", requestId)
  };
  x.cookie = { owner: await api.signIn(w.owner), agent: await api.signIn(w.agent) };
  /* The owner's hosted click path: build (owner session), attach the owner's TEST-key signature, submit. */
  x.ownerBuild = (v, action, which = "fuel") => api.build(x.cookie.owner, { vaultId: v.vaultId, action, params: { fuel: x.k.fuelOf(v, which) }, signerAddress: w.owner.address });
  x.topUp = (v, which = "fuel") => api.build(x.cookie.owner, { vaultId: v.vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel: x.k.fuelOf(v, which) }, signerAddress: w.owner.address });
  x.ownerSign = async (requestId) => api.signature(x.cookie.owner, requestId, x.k.sign(await x.req(requestId), w.owner));
  x.ownerSubmit = (requestId) => F3.submitThroughModel(() => x.model, () => api.submit(x.cookie.owner, requestId));
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
const auditOf = async (x, action) => (await x.audit()).filter((e) => e.action === action);
/* Build + sign the owner's break-glass through the hosted API; returns the stored PREFLIGHT_VERIFIED record. */
async function ownerSigned(x, v, action, which = "fuel") {
  const built = await x.ownerBuild(v, action, which);
  assert.equal(built.status, 201, `the owner's ${action} builds on the live vault (${said(built)})`);
  const signed = await x.ownerSign(built.body.request.requestId);
  assert.equal(signed.status, 200, `the owner's ${action} finalizes (${said(signed)})`);
  assert.equal(signed.body.request.state, "PREFLIGHT_VERIFIED");
  return x.req(built.body.request.requestId);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t3 = (name, fn, quota) => test(`RC45 T3 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend, quota); try { await fn(x); } finally { await release(x); } });

  /* ---------------- S1: contested break-glass with the quota full (A1, O1, A4; sabotage b, j) ---------------- */
  t3("S1 contested Pause through the hosted API: with 32 delegate BUILT requests (per-vault quota full) and 300 built/rejected, an ordinary owner action is refused 429 but the owner's Pause builds 201; its finalize takes no claim (the delegate's claim byte-identical); its submit returns 200 at SUBMITTED although the Pause landed at depth 0 (no poll, no manifest write, no receipt, no request.confirmed); Verify completes it at D and supersedes the delegate [RED on C1]", async (x) => {
    const d = await x.req(B.s1.d), L = d.predecessorOutpoint, noise = [...B.s1.built, ...B.s1.rejected];
    const claim = await x.claimOn(L), manifest0 = await x.rawManifest(V.s1);
    const dBefore = await x.rawRequest(d.requestId), dSubmission = await x.submissionClaim(d.txId), dReservation = await x.reservationOf(d);
    const noiseBefore = await x.rawMany(noise);
    assert.equal(d.state, "PREFLIGHT_VERIFIED"); assert.equal(claim.txId, d.txId, "the delegate's signed spend holds the claim on L");
    assert.ok(dSubmission && dReservation);
    assert.equal(await x.openOn(V.s1), 32, "32 open delegate requests: the per-vault quota (32) is full");
    const ordinary = await x.topUp(V.s1);
    assert.equal(ordinary.status, 429, `an ordinary owner action stays counted and refused (${said(ordinary)})`); assert.equal(ordinary.code, "QUOTA_EXCEEDED");
    const built = await x.ownerBuild(V.s1, "ownerPause");
    assert.equal(built.status, 201, `the owner's break-glass Pause is exempt from the full quota and never refused by pending delegate work (${said(built)})`);
    const q0 = await x.req(built.body.request.requestId);
    assert.equal(q0.state, "BUILT"); assert.deepEqual(q0.predecessorOutpoint, L);
    assert.deepEqual(await x.claimOn(L), claim, "building touches no claim");
    const signed = await x.ownerSign(q0.requestId);
    assert.equal(signed.status, 200, `the contested Pause finalizes (${said(signed)})`); assert.equal(signed.body.request.state, "PREFLIGHT_VERIFIED");
    const q = await x.req(q0.requestId);
    assert.ok(q.finalTransaction, "the owner's record carries its signed bytes");
    assert.deepEqual(await x.claimOn(L), claim, "the contested finalize takes no claim: the delegate's claim is byte-identical");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore, "the delegate's record is untouched");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true; // L and the owner's fuel live; the Pause lands on broadcast
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the contested submit answers (${said(submitted)})`);
    assert.equal(submitted.body.request.state, "SUBMITTED", "contested: the submit returns right after the SUBMITTED save");
    assert.deepEqual(x.model.broadcasts, [q.txId], "the signed Pause reached the node once");
    assert.equal((await x.rawRequest(q.requestId)).state, "SUBMITTED");
    assert.deepEqual(await x.rawManifest(V.s1), manifest0, "no manifest write although the Pause landed at depth 0 (no poll)");
    assert.equal(await x.receipt(q.txId), null, "no receipt at zero depth");
    assert.deepEqual(await x.claimOn(L), claim, "the delegate's claim is still byte-identical");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore);
    assert.deepEqual(await x.submissionClaim(d.txId), dSubmission); assert.deepEqual(await x.reservationOf(d), dReservation);
    assert.equal((await x.confirmed(q.requestId)).length, 0, "no request.confirmed for a contested submit (A4)");
    assert.deepEqual(await x.rawMany(noise), noiseBefore, "the BUILT and rejected delegate records are untouched");
    // Verify (F5) completes the accepted Pause at depth D and supersedes the delegate.
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.s1), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, q.txId); assert.equal(String(pending.required), "1000");
    assert.deepEqual(await x.snap(), below, "below D nothing is written");
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.s1), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId); assert.equal(done.requestId, q.requestId);
    const m = await x.rawManifest(V.s1);
    assert.equal(m.status, "PAUSED"); assert.equal(m.latestTransitionTxId, q.txId); assert.deepEqual(m.live.outpoint, { transactionId: q.txId, index: 0 });
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.receipt(q.txId)).proof.requestId, q.requestId);
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE", "the delegate's spend lost to the confirmed Pause");
    assert.equal(await x.claimOn(L), null); assert.equal(await x.submissionClaim(d.txId), null); assert.equal(await x.reservationOf(d), null);
    assert.equal(await x.submissionClaim(q.txId), null);
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, d.requestId); assert.equal(superseded[0].winnerTxId, q.txId);
    assert.deepEqual(await x.rawMany(noise), noiseBefore, "BUILT and rejected records are neither losers nor twins");
  });

  t3("S1 contested Close & recover through the hosted API (CR-H2): 201 at the full quota; finalize leaves the delegate's claim byte-identical; submit returns 200 at SUBMITTED although the recover landed at depth 0 (no RECOVERED at zero depth, no receipt, no request.confirmed); Verify writes RECOVERED only at D; the next Verify answers TERMINAL [RED on C1]", async (x) => {
    const d = await x.req(B.s1.d), L = d.predecessorOutpoint;
    const claim = await x.claimOn(L), manifest0 = await x.rawManifest(V.s1), dBefore = await x.rawRequest(d.requestId);
    const built = await x.ownerBuild(V.s1, "ownerRecover");
    assert.equal(built.status, 201, `the owner's Close & recover is exempt from the full quota (${said(built)})`);
    const signed = await x.ownerSign(built.body.request.requestId);
    assert.equal(signed.status, 200, `the contested recover finalizes (${said(signed)})`); assert.equal(signed.body.request.state, "PREFLIGHT_VERIFIED");
    const q = await x.req(built.body.request.requestId);
    assert.deepEqual(await x.claimOn(L), claim, "the delegate's claim is byte-identical after the owner's finalize");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true;
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the recover submit answers (${said(submitted)})`);
    assert.equal(submitted.body.request.state, "SUBMITTED", "every ownerRecover is contested: submit stops at SUBMITTED");
    assert.deepEqual(await x.rawManifest(V.s1), manifest0, "no terminal status is written at zero depth");
    assert.equal(await x.receipt(q.txId), null);
    assert.deepEqual(await x.claimOn(L), claim); assert.deepEqual(await x.rawRequest(d.requestId), dBefore);
    assert.equal((await x.confirmed(q.requestId)).length, 0, "no request.confirmed for a recover at SUBMITTED (A4)");
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.s1), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, q.txId);
    assert.deepEqual(await x.snap(), below, "no terminal status below D");
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.s1), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId);
    const m = await x.rawManifest(V.s1);
    assert.equal(m.status, "RECOVERED"); assert.equal(m.live, null); assert.equal(m.latestTransitionTxId, q.txId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    const receipt = await x.receipt(q.txId);
    assert.equal(receipt.proof.requestId, q.requestId); assert.equal(receipt.proof.successorOutpoint, null);
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    assert.equal(await x.claimOn(L), null); assert.equal(await x.reservationOf(d), null);
    const closed = await x.snap();
    const again = await resolved(() => x.verify(V.s1), "a second Verify answers");
    assert.equal(again.status, "TERMINAL"); assert.deepEqual(await x.snap(), closed);
  });

  /* ---------------- CR-H2: the uncontested recover is two-step too (sabotage v) ---------------- */
  t3("uncontested Close & recover through the hosted API (CR-H2): nothing pending, the owner takes its own claim, yet the submit returns 200 at SUBMITTED although the recover landed at depth 0 (no manifest write, no receipt, no request.confirmed, the own claim kept); Verify writes RECOVERED at D [RED on C1]", async (x) => {
    const manifest0 = await x.rawManifest(V.ur);
    const q = await ownerSigned(x, V.ur, "ownerRecover");
    const own = await x.claimOn(q.predecessorOutpoint);
    assert.equal(own.txId, q.txId, "with no foreign claim the owner's finalize takes its own claim");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true;
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the recover submit answers (${said(submitted)})`);
    assert.equal(submitted.body.request.state, "SUBMITTED", "every ownerRecover is contested, the uncontested one included (sabotage v): SUBMITTED, no poll");
    assert.deepEqual(x.model.broadcasts, [q.txId]);
    assert.equal((await x.rawRequest(q.requestId)).state, "SUBMITTED");
    assert.deepEqual(await x.rawManifest(V.ur), manifest0, "no RECOVERED at zero depth");
    assert.equal(await x.receipt(q.txId), null);
    assert.deepEqual(await x.claimOn(q.predecessorOutpoint), own, "the owner's own claim is kept until Verify completes");
    assert.equal((await x.confirmed(q.requestId)).length, 0, "no request.confirmed at SUBMITTED (A4)");
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await resolved(() => x.verify(V.ur), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, q.txId);
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

  /* ---------------- delegate wins over a submitted Pause; a second Pause completes (S1) ---------------- */
  t3("delegate wins: the owner's contested Pause reaches SUBMITTED, but consensus accepts the delegate's spend of L; Verify at D completes the delegate, labels the owner's SUBMITTED Pause STALE (transition_superseded names the delegate as winner); a second Pause is uncontested and completes at zero depth with request.confirmed [RED on C1]", async (x) => {
    const d = await x.req(B.s2.d), L = d.predecessorOutpoint, claim = await x.claimOn(L), manifest0 = await x.rawManifest(V.s2);
    assert.equal(claim.txId, d.txId);
    const q = await ownerSigned(x, V.s2, "ownerPause");
    assert.deepEqual(await x.claimOn(L), claim, "the delegate's claim is byte-identical after the owner's finalize");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId);
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the contested submit answers (${said(submitted)})`); assert.equal(submitted.body.request.state, "SUBMITTED");
    assert.deepEqual(await x.rawManifest(V.s2), manifest0);
    // The delegate had broadcast its signed spend through another node; consensus accepts it (the owner's Pause, a double spend of L, never executes).
    x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const pending = await resolved(() => x.verify(V.s2), "Verify answers below depth D");
    assert.equal(pending.status, "CLAIM_PENDING"); assert.equal(pending.txId, d.txId);
    x.model.advance(1n);
    const done = await resolved(() => x.verify(V.s2), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, d.txId); assert.equal(done.requestId, d.requestId);
    const m = await x.rawManifest(V.s2), index = frozenOf(d).outputs.findIndex((o) => o.covenant !== null);
    assert.equal(m.status, "ACTIVE"); assert.deepEqual(m.live.outpoint, { transactionId: d.txId, index });
    assert.equal((await x.rawRequest(d.requestId)).state, "CHAIN_VERIFIED");
    const qa = await x.rawRequest(q.requestId);
    assert.equal(qa.state, "STALE", "the owner's submitted Pause never executed: STALE");
    assert.equal(await x.submissionClaim(q.txId), null, "the loser's submission claim is released");
    const superseded = await auditOf(x, "transition_superseded");
    assert.equal(superseded.length, 1); assert.equal(superseded[0].requestId, q.requestId); assert.equal(superseded[0].txId, q.txId); assert.equal(superseded[0].winnerTxId, d.txId);
    assert.equal((await x.confirmed(q.requestId)).length, 0, "the superseded Pause never emitted request.confirmed");
    // A second Pause on the delegate's successor (another fuel UTXO) is uncontested: zero-depth completion (L-2).
    const q2 = await ownerSigned(x, V.s2, "ownerPause", "fuel2");
    assert.deepEqual(q2.predecessorOutpoint, m.live.outpoint);
    assert.equal((await x.claimOn(q2.predecessorOutpoint)).txId, q2.txId, "uncontested: the owner holds its own claim");
    x.model.know(q2); x.model.seedInputs(frozenOf(q2), q2.covenantId); x.model.confirmOnSubmit = true;
    const second = await x.ownerSubmit(q2.requestId);
    assert.equal(second.status, 200, `the second Pause submits (${said(second)})`); assert.equal(second.body.request.state, "CHAIN_VERIFIED", "an uncontested non-terminal submit completes at zero depth (L-2)");
    assert.equal((await x.rawManifest(V.s2)).status, "PAUSED");
    assert.equal((await x.confirmed(q2.requestId)).length, 1, "request.confirmed is emitted for CHAIN_VERIFIED (A4)");
  });

  /* ---------------- the real mempool wire text; read-then-release (J1-ALL-01, sabotage o) ---------------- */
  t3("mempool wire text (CR2-L8): the delegate's signed spend waits in the node mempool; the owner's contested Pause is rejected with the real 'already spent by transaction <d> in the mempool' text -> SUBMISSION_REJECTED (established) with its audit row and its submission claim released, while the delegate's claim is read first and stays byte-identical (J1-ALL-01) [RED on C1]", async (x) => {
    const d = await x.req(B.s2.d), L = d.predecessorOutpoint, claim = await x.claimOn(L), manifest0 = await x.rawManifest(V.s2);
    const dBefore = await x.rawRequest(d.requestId), dSubmission = await x.submissionClaim(d.txId), dReservation = await x.reservationOf(d);
    x.model.seedInputs(frozenOf(d), d.covenantId); // L live and deep
    x.model.mempoolAdd(d.txId, [L]); // the delegate broadcast its signed spend outside PolicyVault; it waits in the mempool
    const q = await ownerSigned(x, V.s2, "ownerPause");
    assert.deepEqual(await x.claimOn(L), claim);
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId);
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.code, "SUBMISSION_REJECTED", `the node's mempool rejection is a definitive rejection (${said(submitted)})`);
    assert.deepEqual(x.model.broadcasts, [q.txId]);
    const stored = await x.rawRequest(q.requestId);
    assert.equal(stored.state, "SUBMISSION_REJECTED");
    assert.equal(recordedNegativeIsEstablished(stored), true, "an established negative");
    assert.match(String(stored.submissionOutcome && stored.submissionOutcome.reason), new RegExp(`already spent by transaction ${d.txId} in the mempool`), "the real rusty-kaspa wire text is recorded");
    const released = (await auditOf(x, "submission_rejected_claims_released")).filter((e) => e.txId === q.txId);
    assert.equal(released.length, 1, "the REJECTED branch completes: one submission_rejected_claims_released row");
    assert.equal(await x.submissionClaim(q.txId), null, "the owner's submission claim is released");
    assert.deepEqual(await x.claimOn(L), claim, "read-then-release: the delegate's transition claim is never released by the owner's rejection");
    assert.deepEqual(await x.rawRequest(d.requestId), dBefore);
    assert.deepEqual(await x.submissionClaim(d.txId), dSubmission); assert.deepEqual(await x.reservationOf(d), dReservation);
    assert.deepEqual(await x.rawManifest(V.s2), manifest0);
    assert.equal((await x.confirmed(q.requestId)).length, 0);
  });

  /* ---------------- S2: an RC44-written claimless byte-less FINALIZED on L ---------------- */
  t3("claimless FINALIZED (RC44-written): with a byte-less FINALIZED delegate spend on L and no claim, the owner's Pause builds 201, its finalize takes the owner's own claim, and its submit is contested by the PENDING delegate record: 200 at SUBMITTED, no manifest write, no request.confirmed, the FINALIZED record byte-identical; Verify at D completes the Pause and supersedes it [RED on C1]", async (x) => {
    const r = await x.req(H.fz.r.requestId), L = r.predecessorOutpoint, rBefore = await x.rawRequest(r.requestId), manifest0 = await x.rawManifest(V.fz);
    assert.equal(r.state, "FINALIZED"); assert.equal(r.finalTransaction, undefined); assert.equal(await x.claimOn(L), null, "RC44 wrote FINALIZED before any claim");
    const q = await ownerSigned(x, V.fz, "ownerPause");
    assert.equal((await x.claimOn(L)).txId, q.txId, "absent claim: the owner's finalize takes its own claim");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true;
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the contested submit answers (${said(submitted)})`);
    assert.equal(submitted.body.request.state, "SUBMITTED", "contested by the PENDING FINALIZED delegate record on L: no poll");
    assert.deepEqual(await x.rawManifest(V.fz), manifest0, "no manifest write at zero depth");
    assert.equal(await x.receipt(q.txId), null);
    assert.deepEqual(await x.rawRequest(r.requestId), rBefore, "the FINALIZED record is untouched");
    assert.equal((await x.confirmed(q.requestId)).length, 0);
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.fz), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId);
    assert.equal((await x.rawManifest(V.fz)).status, "PAUSED");
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    const loser = await x.rawRequest(r.requestId);
    assert.equal(loser.state, "STALE"); assert.equal(loser.finalTransaction, undefined);
  });

  /* ---------------- S5: same-txid owner twins (CR-M10) ---------------- */
  t3("owner twin (S5): two owner Pauses built with the same fuel are one transaction; the abandoned BUILT twin never refuses the signed one; the contested submit returns at SUBMITTED; at D the signed twin completes and the BUILT twin stays BUILT byte-identical (never STALE) [RED on C1]", async (x) => {
    const d = await x.req(B.s2.d), L = d.predecessorOutpoint, claim = await x.claimOn(L);
    const t1 = await x.ownerBuild(V.s2, "ownerPause");
    assert.equal(t1.status, 201, `the first (abandoned) Pause builds (${said(t1)})`);
    const q0 = await x.ownerBuild(V.s2, "ownerPause");
    assert.equal(q0.status, 201, `the second Pause builds; its BUILT twin never refuses it (${said(q0)})`);
    assert.equal(q0.body.request.txId, t1.body.request.txId, "same fuel, same live state: the same transaction (twins)");
    const t1Before = await x.rawRequest(t1.body.request.requestId);
    const signed = await x.ownerSign(q0.body.request.requestId);
    assert.equal(signed.status, 200, `the signed twin finalizes (${said(signed)})`); assert.equal(signed.body.request.state, "PREFLIGHT_VERIFIED");
    const q = await x.req(q0.body.request.requestId);
    assert.deepEqual(await x.claimOn(L), claim, "the delegate still holds the only claim");
    assert.deepEqual(await x.rawRequest(t1.body.request.requestId), t1Before, "the BUILT twin is untouched");
    x.model.know(q); x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirmOnSubmit = true;
    const submitted = await x.ownerSubmit(q.requestId);
    assert.equal(submitted.status, 200, `the contested submit answers (${said(submitted)})`); assert.equal(submitted.body.request.state, "SUBMITTED");
    assert.deepEqual(await x.rawRequest(t1.body.request.requestId), t1Before);
    x.model.confirmOnSubmit = false; x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.s2), "Verify at depth D");
    assert.equal(done.status, "ADVANCED"); assert.equal(done.txId, q.txId); assert.equal(done.requestId, q.requestId, "the primary is the signed twin");
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.deepEqual(await x.rawRequest(t1.body.request.requestId), t1Before, "the BUILT twin stays BUILT byte-identical (CR-M10)");
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    assert.equal((await x.rawManifest(V.s2)).status, "PAUSED");
  });

  /* ---------------- A2: only the signer or the owner may reject (H-11; sabotage i) ---------------- */
  t3("reject narrowing (A2): an agent principal rejecting the owner-signed Pause gets 403 REQUEST_FORBIDDEN and nothing changes (no request.rejected); the agent still rejects its own request and the owner rejects the agent's and its own [RED on C1]", async (x) => {
    const built = await x.ownerBuild(V.rj, "ownerPause");
    assert.equal(built.status, 201, said(built));
    const qid = built.body.request.requestId, qBefore = await x.rawRequest(qid);
    const attempt = await x.api.reject(x.cookie.agent, qid);
    assert.equal(attempt.status, 403, `an agent may not reject the owner's request (${said(attempt)})`);
    assert.equal(attempt.code, "REQUEST_FORBIDDEN");
    assert.deepEqual(await x.rawRequest(qid), qBefore, "the owner's request is unchanged");
    assert.equal((await F3.eventsOf(x.config, "request.rejected", qid)).length, 0, "no request.rejected for a refused rejection");
    const own = await x.api.reject(x.cookie.agent, B.rj.a);
    assert.equal(own.status, 200, `the agent rejects its own request (${said(own)})`); assert.equal(own.body.request.state, "WALLET_REJECTED");
    const byOwner = await x.api.reject(x.cookie.owner, B.rj.a2);
    assert.equal(byOwner.status, 200, `the owner rejects its agent's request (${said(byOwner)})`); assert.equal(byOwner.body.request.state, "WALLET_REJECTED");
    const ownerOwn = await x.api.reject(x.cookie.owner, qid);
    assert.equal(ownerOwn.status, 200, `the owner rejects its own request (${said(ownerOwn)})`); assert.equal(ownerOwn.body.request.state, "WALLET_REJECTED");
  });

  /* ---------------- A1: the quota count excludes break-glass rows (T8 j) ---------------- */
  t3("quota count (T8 j, perVault 2 / perWallet 3): BUILT ownerPause and ownerRecover rows are not counted, so two ordinary owner builds still fit on the vault and a third is refused; break-glass stays exempt at the full per-vault and per-wallet quota; an agent sending ownerPause is never built [RED on C1]", async (x) => {
    const p1 = await x.ownerBuild(V.qc, "ownerPause");
    assert.equal(p1.status, 201, said(p1));
    const r1 = await x.ownerBuild(V.qc, "ownerRecover");
    assert.equal(r1.status, 201, said(r1));
    const t1 = await x.topUp(V.qc);
    assert.equal(t1.status, 201, `the two BUILT break-glass rows are not counted: the first ordinary build fits (${said(t1)})`);
    const t2 = await x.topUp(V.qc);
    assert.equal(t2.status, 201, `the second ordinary build fits (${said(t2)})`);
    const t3x = await x.topUp(V.qc);
    assert.equal(t3x.status, 429, `the third ordinary build is refused (${said(t3x)})`); assert.equal(t3x.code, "QUOTA_EXCEEDED");
    const p2 = await x.ownerBuild(V.qc, "ownerPause", "fuel2");
    assert.equal(p2.status, 201, `break-glass is exempt at the full per-vault quota (${said(p2)})`);
    const u1 = await x.topUp(V.qd);
    assert.equal(u1.status, 201, `the wallet holds two counted rows (${said(u1)})`);
    const u2 = await x.topUp(V.qd, "fuel2");
    assert.equal(u2.status, 429, `the per-wallet quota (3) is full (${said(u2)})`); assert.equal(u2.code, "QUOTA_EXCEEDED");
    const r2 = await x.ownerBuild(V.qd, "ownerRecover");
    assert.equal(r2.status, 201, `break-glass is exempt at the full per-wallet quota (${said(r2)})`);
    const before = await x.requestCount();
    const agent = await x.api.build(x.cookie.agent, { vaultId: V.qc.vaultId, action: "ownerPause", params: { fuel: x.k.fuelOf(V.qc, "fuel3") }, signerAddress: w.agent.address });
    assert.ok(agent.status === 403 || agent.status === 429, `an agent sending ownerPause is refused (${said(agent)})`);
    assert.ok(agent.code === "NOT_OWNER" || agent.code === "QUOTA_EXCEEDED", `refused as NOT_OWNER (B3) or by the quota, never built (${said(agent)})`);
    assert.equal(await x.requestCount(), before, "nothing durable is created for the agent's attempt");
  }, { maxOpenRequestsPerVault: 2, maxOpenRequestsPerWallet: 3 });

  /* ---------------- B3 (holds on C1): an agent sending ownerPause gets NOT_OWNER ---------------- */
  t3("B3: an agent sending ownerPause to the SDK builder on a live vault with pending delegate work gets NOT_OWNER and nothing is written [HOLDS on C1]", async (x) => {
    const before = await x.snap();
    await assert.rejects(cand.wr4.buildWalletRequestV4({ config: x.config, vaultId: V.s2.vaultId, action: "ownerPause", params: { fuel: x.k.fuelOf(V.s2, "fuel3") }, signerAddress: w.agent.address }), { code: "NOT_OWNER" });
    assert.deepEqual(await x.snap(), before);
  });
}
