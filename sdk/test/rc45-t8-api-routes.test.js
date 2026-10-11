"use strict";
/*
 * RC45 T8 — THE HOSTED API SURFACE OF THE COMPLETED L5 (fix item F8
 * RC45-L5-API-WEB; plan rc45-simplified-plan-r2 §2.1(2) error.extra, §2.3
 * touch points (reject narrowing A2, request.confirmed A4), §5 A3 / A5
 * (vault.reconciled correlation.requestId) / A6 (the badge), §6 H-50/H-51,
 * §8 rules (CR-M14, CR2-L12) and T8 "reject narrowing; extra; requestId
 * correlation; A6; attestation mapping", §A F8 -> T8). Internal RED-first
 * regression material for the RC45 candidate; not an audit.
 *
 * Already pinned by earlier RED commits of this phase and not repeated here:
 * the quota check and count and the hosted-quota re-base (F3 c271241), the
 * agent-on-owner-request reject 403 and the no-request.confirmed legs of
 * contested and recover submits (F3), the Verify-route paste legs A5 body
 * limits, v2 + field -> 422 and GATE 1 foreign evidence -> 404 (F6 0b1f0ff).
 *
 * RED on C1 e62b1973:
 *   - A3: the route's v4Error drops error.extra (and the SDK error carries
 *     none): a refusal names neither the blocking record nor the claim, and
 *     the finalize/submit routes REPLACE extra with { request };
 *   - A5: vault.reconciled carries correlation { txId } only;
 *   - A2: every covenant agent of the vault may reject another agent's
 *     request (the narrowing is signer or template.owner only);
 *   - A6: the badge reads only the transition claim, so a PENDING record on
 *     the live outpoint without a claim (RC44-written shapes) badges ACTIVE;
 *   - attestation mapping: C1's Verify cannot produce the RC45 settlement
 *     shapes (it answers REQUEST_RECOVERY_REQUIRED for any vault-wide
 *     pending record), so the STALE loser / late CHAIN_VERIFIED / BUILT
 *     twin ladders are unreachable.
 * GREEN after F8 on top of F2..F7:
 *   - the build/finalize/submit routes pass the SDK's error.extra
 *     {requestId, action, state, signerRole, claimTxId}; finalize and submit
 *     merge it with { request };
 *   - vault.reconciled carries correlation.requestId whenever the outcome
 *     names one (ADVANCED, REQUEST_RECOVERY_REQUIRED);
 *   - reject: signer or owner only, else 403 REQUEST_FORBIDDEN with nothing
 *     changed; a foreign principal still gets 404 (GATE 1);
 *   - A6: operationalForV4 passes the first PENDING record on the live
 *     outpoint as a held claim: ACTION_REQUIRED_VERIFY naming its txid; an
 *     ancestor record changes nothing;
 *   - the export maps a Verify-settled vault truthfully: the winner SETTLED,
 *     the STALE loser AUTHORIZED/FAILED(STALE), a BUILT same-txid twin
 *     AUTHORIZED/IN_PROGRESS with no broadcast rung.
 * HOLDS on C1 (and must keep holding): an uncontested ordinary route submit
 * that completes CHAIN_VERIFIED emits exactly one request.confirmed; the
 * owner rejects an agent's BUILT request; a foreign principal's reject is a
 * 404 with nothing changed; an ancestor PENDING record leaves the badge
 * ACTIVE.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, wallet
 * sessions signed in with TEST keys through /auth/challenge + /auth/verify;
 * sdk/testutil/rc45-f3-kit.js apiFor) plus SDK. Real v0.4.1 compiler,
 * pv_call_encoder, TEST-key signatures (deterministic dev signer) and
 * pv_vm_preflight for every consensus byte. Node observations come ONLY from
 * the explicit chain model of sdk/testutil/rc45-f5-kit.js (UTXOs with
 * blockDaaScore, a virtualDaaScore, a mempool with the rusty-kaspa v2.0.1
 * wire texts). Route-level Verify and submit cannot pass `rpc` and the default
 * rpcUrl is the operator's testnet-10 node, so, as plan §8 rules allow
 * (CR-M14, CR2-L12), the module-cache exports of the REAL reconcileVaultV4 /
 * reconcileVaultV2 / submitWalletRequestV4 are wrapped to call themselves with
 * the model's rpc (never a stub) and restored afterwards; every config names
 * ws://127.0.0.1:1, so nothing can dial a node.
 *
 * Bases (template, installed into a fresh store per test):
 *   xb — d (agent spend) finalized, PREFLIGHT_VERIFIED holding the claim on L;
 *        o, the owner's ordinary ownerTopUp, BUILT before d was finalized.
 *   xc — e (agent spend) BUILT plus e's own transition claim on L and no
 *        bytes (the L-16 shape: an ordinary finalize that took W2 and stopped
 *        before W1; SYNTHETIC stop, written with the finalize's claim writer).
 *   xs — d and the owner's ordinary ownerTopUp o2 finalized apart
 *        (PREFLIGHT_VERIFIED both; d holds the only claim on L).
 *   ra — d finalized (PREFLIGHT_VERIFIED + claim on L); it lands at depth D.
 *   rc — d finalized, then a SYNTHETIC RECOVERED manifest (live null,
 *        lastTransition an ownerRecover with another txid): a closed vault
 *        with a PENDING record.
 *   cv — clean (an uncontested ordinary ownerTopUp through the routes).
 *   rj — a vault with TWO covenant agents (0x21, and 0x32 as the second
 *        agent's key); a1, a2 the first agent's BUILT spends.
 *   at — t, the owner's Pause BUILT first; q, a second owner Pause with the
 *        same fuel (the same txid); d an agent spend; all built through the
 *        hosted build route (intent-manifest records exist); d and q
 *        finalized apart (d holds the only claim on L).
 *   an — d finalized on L0, then a SYNTHETIC manifest whose live outpoint is
 *        P1 (same state): d is PENDING on an ancestor.
 *   fz, ag — RC44-WRITTEN (CR-M13) by the pinned df5b8de writers
 *        (sdk/testutil/rc45-rc44-history.js scenario t4, reused unchanged; the
 *        five writer sha256 pins and the sdk/src tree are verified; a missing
 *        or mismatched POLICYVAULT_TEST_RC44_TREE FAILS, never skips): fz a
 *        byte-less FINALIZED agent spend on the live L with no claim; ag a
 *        PREFLIGHT_VERIFIED agent spend on the live L whose claims RC44
 *        released by age (case C).
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

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({
  xb: K.vault("f8-xb"), xc: K.vault("f8-xc"), xs: K.vault("f8-xs"), ra: K.vault("f8-ra"), rc: K.vault("f8-rc"), cv: K.vault("f8-cv"),
  rj: K.vault("f8-rj"), at: K.vault("f8-at"), an: K.vault("f8-an"), fz: H44.T4_VAULTS.fz, ag: H44.T4_VAULTS.ag
});
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, H = null, B = null, w = null, templateRoot = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();
const extraOf = (r) => (r && r.extra ? { requestId: r.extra.requestId, action: r.extra.action, state: r.extra.state, signerRole: r.extra.signerRole } : null);

/* The five durable categories of the F5 kit plus the intent-manifest records the hosted build route writes (the
 * attestation export reads them); audit rows as the F5 kit keeps them. */
async function snapshotAll(config) {
  const snap = await K.snapshot(cand, config), s = cand.store.getStore(config);
  snap.records[Categories.INTENT_MANIFEST] = await Promise.all((await s.listKeys(Categories.INTENT_MANIFEST)).sort().map(async (k) => [k, await s.read(Categories.INTENT_MANIFEST, k)]));
  return snap;
}

/* A v0.4.1 vault whose registry holds TWO covenant agents: the TEST agent (0x21) and 0x32 (w.recipient2's key). */
async function seedTwoAgentVault(config, v) {
  const m = cand, entry = (agentPk) => ({ agentPk, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [w.recipient.xonly] });
  const entries = [entry(w.agent.xonly), entry(w.recipient2.xonly)];
  const template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policies = entries.map((e) => m.agents.normalizeAgentPolicyV4({ ...e, agentRecipientRoot: m.recipients.buildRecipientTree(e.recipients).root }));
  const state = m.vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `RC45 F8 TEST ${v.tag}`, status: "ACTIVE", template, agentRegistry: entries,
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}
/* Rewrite a stored v4 manifest (SYNTHETIC history; the normalizer still validates the result). */
async function rewriteManifest(config, v, patch) {
  const m = await cand.manifest4.loadManifestV4(config, v.vaultId);
  await cand.manifest4.persistManifestV4(config, { ...cand.submit4.manifestToJson(m), ...patch(m) });
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-f8-t8-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off); every case is hosted");
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  const topUp = (v, which) => cand.wr4.buildWalletRequestV4({ config: template, vaultId: v.vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel: k.fuelOf(v, which) }, signerAddress: w.owner.address });
  const { handle } = require("../../server/src/api");
  const routeBuild = async (body) => {
    const r = await handle(template, "POST", ["wallet", "v4", "requests"], {}, body);
    assert.equal(r.status, 201, `hosted build route (${JSON.stringify(r.body).slice(0, 200)})`);
    return cand.wr4.loadRequest(template, r.body.request.requestId);
  };
  B = {};
  { const v = V.xb; await K.seedVault(cand, template, v, w);
    const o = await topUp(v, "fuel"); assert.equal(o.state, "BUILT"); await K.sleep(3);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    B.xb = { d: id(d), o: id(o) };
  }
  { const v = V.xc; await K.seedVault(cand, template, v, w);
    const e = await k.agentSpend(v, 4);
    await cand.claims.claimTransition(template, K.claimArgsFor(e));
    B.xc = { e: id(e) };
  }
  { const v = V.xs; await K.seedVault(cand, template, v, w);
    const d = await k.agentSpend(v, 4); await K.sleep(3);
    const o2 = await topUp(v, "fuel");
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: o2.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B.xs = { d: id(d), o2: id(o2) };
  }
  { const v = V.ra; await K.seedVault(cand, template, v, w); B.ra = { d: id(await k.finalize(await k.agentSpend(v, 4), w.agent)) }; }
  { const v = V.rc; await K.seedVault(cand, template, v, w);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent);
    const recoverTxId = K.hex("rc45-f8-rc-synthetic-recover");
    await rewriteManifest(template, v, (m) => ({ status: "RECOVERED", live: null, latestTransitionTxId: recoverTxId,
      lastTransition: { action: "ownerRecover", txId: recoverTxId, oldStateId: m.live.stateId, newStateId: null, oldOutpoint: m.live.outpoint, newOutpoint: null } }));
    B.rc = { d: id(d), recoverTxId };
  }
  { await K.seedVault(cand, template, V.cv, w); }
  { const v = V.rj; await seedTwoAgentVault(template, v);
    const a1 = await k.agentSpend(v, 1); await K.sleep(3); const a2 = await k.agentSpend(v, 2);
    B.rj = { a1: id(a1), a2: id(a2) };
  }
  { const v = V.at; await K.seedVault(cand, template, v, w);
    const body = (action, params, signer) => ({ vaultId: v.vaultId, action, params, signerAddress: signer.address });
    const t = await routeBuild(body("ownerPause", { fuel: k.fuelOf(v) }, w.owner)); await K.sleep(3);
    const q = await routeBuild(body("ownerPause", { fuel: k.fuelOf(v) }, w.owner)); await K.sleep(3);
    const d = await routeBuild(body("agentSpend", k.spend(4n * KAS), w.agent));
    assert.equal(q.txId, t.txId, "the two owner Pauses with the same fuel are one transaction (same-txid twins)");
    assert.equal(typeof q.manifestHash, "string"); assert.equal(typeof d.manifestHash, "string");
    await K.finalizeApart(cand, template, [{ requestId: d.requestId, signer: w.agent }, { requestId: q.requestId, signer: w.owner }], { claimHolder: d.requestId, track });
    B.at = { t: id(t), q: id(q), d: id(d) };
  }
  { const v = V.an; await K.seedVault(cand, template, v, w);
    const d = await k.finalize(await k.agentSpend(v, 4), w.agent);
    const P1 = { transactionId: K.hex("rc45-f8-an-P1"), index: 0 };
    await rewriteManifest(template, v, (m) => ({ live: { ...cand.submit4.manifestToJson(m).live, outpoint: P1 } }));
    B.an = { d: id(d), P1 };
  }
  // fz, ag: RC44-written history, by the pinned df5b8de writers only.
  const rc44 = H44.runRc44Scenario("t4", { track });
  H = rc44.result.hist;
  await K.install(cand, template, await K.snapshot(cand, cand.config.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: LOOPBACK })));
  for (const r of [H.fz.r, H.ag.a]) {
    const q = await cand.wr4.loadRequest(template, r.requestId);
    for (const s of [q.build.stateJson, q.build.successorState]) cand.submit4.successorAddressAndScript(template, q.build.template, s, q.contractVersion);
  }
  history = await snapshotAll(template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh hosted case (authMode enabled; owner, agent, second agent and a foreign wallet signed in with TEST keys). */
async function fresh(backend) {
  const dataRoot = mk("pv-rc45-f8-t8-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_f8_t8_${process.pid}_${++serial}`;
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
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    audit: () => store.readAudit({ limit: 5000 }),
    snap: () => K.snapshot(cand, config),
    events: (type, requestId) => F3.eventsOf(config, type, requestId),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: x.model.rpc })
  };
  x.cookie = { owner: await api.signIn(w.owner), agent: await api.signIn(w.agent), agent2: await api.signIn(w.recipient2), foreign: await api.signIn(w.recipient3) };
  x.topUp = (v, which = "fuel") => api.build(x.cookie.owner, { vaultId: v.vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel: x.k.fuelOf(v, which) }, signerAddress: w.owner.address });
  x.agentBuild = (v, kas) => api.build(x.cookie.agent, { vaultId: v.vaultId, action: "agentSpend", params: x.k.spend(BigInt(kas) * KAS), signerAddress: w.agent.address });
  x.ownerSign = async (requestId) => api.signature(x.cookie.owner, requestId, x.k.sign(await x.req(requestId), w.owner));
  x.ownerSubmit = (requestId) => F3.submitThroughModel(() => x.model, () => api.submit(x.cookie.owner, requestId));
  /* POST /vaults/:id/reconcile through the REAL reconcilers wrapped with the explicit chain model's rpc. */
  x.verifyRoute = async (vaultId, body, cookie) => {
    const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), m2 = require(path.join(SDK_SRC, "reconcile-v2.js"));
    const real4 = m4.reconcileVaultV4, real2 = m2.reconcileVaultV2, seen = { v4: [], v2: [] };
    m4.reconcileVaultV4 = (c, vid, options = {}) => { seen.v4.push({ vaultId: vid, options: { ...options } }); return real4(c, vid, { ...options, rpc: x.model.rpc }); };
    m2.reconcileVaultV2 = (c, vid, options = {}) => { seen.v2.push({ vaultId: vid, options: { ...options } }); return real2(c, vid, { ...options, rpc: x.model.rpc }); };
    try { return { r: await api.call("POST", ["vaults", vaultId, "reconcile"], body, cookie), seen }; } finally { m4.reconcileVaultV4 = real4; m2.reconcileVaultV2 = real2; }
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}
async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}
/* The attestation ladder, exactly as sdk/test/governance-attestation-ladder.test.js reads it. */
function ladderOf(attestation) {
  const o = attestation.outcome;
  return { decision: attestation.authorization.decision, refusalCode: attestation.authorization.refusalCode, failureCode: o.failureCode, txId: o.txId,
    outputs: o.chain.outputs.length, successorOutpoint: o.chain.successorOutpoint, state: o.state, disposition: o.disposition, reached: o.reached.map((r) => r.state) };
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const t8 = (name, fn) => test(`RC45 T8 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- A3: error.extra reaches the hosted caller (§2.1(2), §5 A3) ---------------- */
  t8("A3 build: a hosted build refused 422 REQUEST_RECOVERY_REQUIRED carries the SDK's error.extra naming the PENDING record on the live outpoint {requestId, action, state, signerRole}, for the owner's ordinary build and the agent's build; nothing is written [RED on C1]", async (x) => {
    const d = await x.req(B.xb.d), want = { requestId: d.requestId, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent" };
    assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId, "the delegate's signed spend holds the claim on L");
    const before = await x.snap();
    const owner = await x.topUp(V.xb, "fuel2");
    assert.equal(owner.status, 422, `the owner's ordinary build is refused (${said(owner)})`);
    assert.equal(owner.code, "REQUEST_RECOVERY_REQUIRED");
    assert.deepEqual(extraOf(owner), want, "the route passes error.extra = {requestId, action, state, signerRole, claimTxId} (A3)");
    const agent = await x.agentBuild(V.xb, 1);
    assert.equal(agent.status, 422, `the agent's build is refused (${said(agent)})`);
    assert.equal(agent.code, "REQUEST_RECOVERY_REQUIRED");
    assert.deepEqual(extraOf(agent), want, "the agent's refusal names the same record");
    assert.deepEqual(await x.snap(), before, "a refused build writes nothing");
  });
  t8("A3 build: a claim on the live outpoint refuses an ordinary hosted build pre-sign with 409 CLAIM_CONFLICT whose error.extra names the claim's txid (claimTxId); nothing is written [RED on C1]", async (x) => {
    const e = await x.req(B.xc.e), claim = await x.claimOn(e.predecessorOutpoint), before = await x.snap();
    assert.equal(e.state, "BUILT"); assert.equal(claim.txId, e.txId, "e's own claim sits on L without bytes (L-16)");
    const owner = await x.topUp(V.xc, "fuel2");
    assert.equal(owner.status, 409, `the owner's ordinary build is refused pre-sign (${said(owner)})`);
    assert.equal(owner.code, "CLAIM_CONFLICT");
    assert.equal(owner.extra?.claimTxId, e.txId, "error.extra.claimTxId names the claim on L (A3)");
    const agent = await x.agentBuild(V.xc, 1);
    assert.equal(agent.status, 409, `the agent's build is refused pre-sign (${said(agent)})`);
    assert.equal(agent.code, "CLAIM_CONFLICT"); assert.equal(agent.extra?.claimTxId, e.txId);
    assert.deepEqual(await x.snap(), before, "a refused build writes nothing; the claim is byte-identical");
  });
  t8("A3 finalize: the hosted finalize refusal merges the SDK's error.extra with { request }: 422 REQUEST_RECOVERY_REQUIRED names the blocking PENDING record and still presents the caller's own BUILT request; nothing is written [RED on C1]", async (x) => {
    const d = await x.req(B.xb.d), o = await x.req(B.xb.o), before = await x.snap();
    assert.equal(o.state, "BUILT");
    const r = await x.ownerSign(o.requestId);
    assert.equal(r.status, 422, `the owner's ordinary finalize is refused (${said(r)})`);
    assert.equal(r.code, "REQUEST_RECOVERY_REQUIRED");
    assert.deepEqual(extraOf(r), { requestId: d.requestId, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent" }, "{...error.extra, request}: the blocking record (A3)");
    assert.equal(r.extra?.request?.requestId, o.requestId, "{...error.extra, request}: the caller's own request is still presented");
    assert.equal(r.extra.request.state, "BUILT");
    assert.equal(r.extra.request.build, undefined, "the presented request stays the public presentation");
    assert.deepEqual(await x.snap(), before, "a refused finalize writes nothing");
  });
  t8("A3 submit: the hosted submit refusal merges the SDK's error.extra with { request }: the owner's ordinary PREFLIGHT_VERIFIED request is refused 422 REQUEST_RECOVERY_REQUIRED naming the delegate's PENDING record on L; nothing is broadcast or written [RED on C1]", async (x) => {
    const d = await x.req(B.xs.d), o2 = await x.req(B.xs.o2), before = await x.snap();
    assert.equal(o2.state, "PREFLIGHT_VERIFIED"); assert.equal((await x.claimOn(d.predecessorOutpoint)).txId, d.txId);
    x.model.know(o2); x.model.seedInputs(frozenOf(o2), o2.covenantId);
    const r = await x.ownerSubmit(o2.requestId);
    assert.equal(r.status, 422, `the owner's ordinary submit is refused (${said(r)})`);
    assert.equal(r.code, "REQUEST_RECOVERY_REQUIRED");
    assert.deepEqual(extraOf(r), { requestId: d.requestId, action: "agentSpend", state: "PREFLIGHT_VERIFIED", signerRole: "agent" }, "{...error.extra, request}: the blocking record (A3)");
    assert.equal(r.extra?.request?.requestId, o2.requestId, "{...error.extra, request}: the caller's own request is still presented");
    assert.deepEqual(x.model.broadcasts, [], "nothing reached the node");
    assert.deepEqual(await x.snap(), before, "a refused submit writes nothing");
  });

  /* ---------------- A5: vault.reconciled carries correlation.requestId ---------------- */
  t8("A5 vault.reconciled: a route Verify that settles the delegate's spend at depth D answers ADVANCED {txId, requestId} and emits one vault.reconciled whose correlation carries requestId beside txId (data {outcome, to} only) [RED on C1]", async (x) => {
    const d = await x.req(B.ra.d);
    x.model.confirm(frozenOf(d), d.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const { r, seen } = await x.verifyRoute(V.ra.vaultId, {}, x.cookie.owner);
    assert.equal(seen.v4.length, 1, `the real v0.4 reconciler runs once through the model (${said(r)})`);
    assert.equal(r.status, 200, said(r));
    const out = r.body.reconcile;
    assert.equal(out.status, "ADVANCED", `Verify settles the landed spend at depth D (got ${JSON.stringify(out).slice(0, 300)})`);
    assert.equal(out.txId, d.txId); assert.equal(out.requestId, d.requestId);
    const events = await x.events("vault.reconciled");
    assert.equal(events.length, 1, "one vault.reconciled");
    assert.equal(events[0].vaultId, V.ra.vaultId);
    assert.deepEqual(events[0].correlation, { requestId: d.requestId, txId: d.txId }, "correlation.requestId beside txId (A5, events spec)");
    assert.deepEqual(events[0].data, out.to === undefined ? { outcome: "ADVANCED" } : { outcome: "ADVANCED", to: out.to }, "data stays {outcome, to}: settled[] is unpublished (CR-L18)");
  });
  t8("A5 vault.reconciled: a route Verify on a closed vault with a PENDING record answers REQUEST_RECOVERY_REQUIRED {recordedVaultClosed, requestId} with no node call and no write, and its vault.reconciled carries correlation.requestId [RED on C1]", async (x) => {
    const d = await x.req(B.rc.d), before = await x.snap(), calls = x.model.calls.length;
    const { r, seen } = await x.verifyRoute(V.rc.vaultId, {}, x.cookie.owner);
    assert.equal(r.status, 200, said(r)); assert.equal(seen.v4.length, 1);
    const out = r.body.reconcile;
    assert.equal(out.status, "REQUEST_RECOVERY_REQUIRED"); assert.equal(out.recordedVaultClosed, true); assert.equal(out.requestId, d.requestId);
    assert.equal(x.model.calls.length, calls, "a closed vault answers without a node call");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    const events = await x.events("vault.reconciled");
    assert.equal(events.length, 1, "one vault.reconciled");
    assert.equal(events[0].correlation.requestId, d.requestId, "vault.reconciled carries correlation.requestId (A5)");
    assert.equal(events[0].data.outcome, "REQUEST_RECOVERY_REQUIRED");
  });

  /* ---------------- A4: request.confirmed stays on CHAIN_VERIFIED ---------------- */
  t8("A4 holds: an uncontested ordinary ownerTopUp through the hosted routes that completes CHAIN_VERIFIED at zero depth (L-2) emits exactly one request.confirmed {state CHAIN_VERIFIED, terminal false} [holds on C1]", async (x) => {
    const built = await x.topUp(V.cv);
    assert.equal(built.status, 201, said(built));
    const requestId = built.body.request.requestId;
    const signed = await x.ownerSign(requestId);
    assert.equal(signed.status, 200, said(signed)); assert.equal(signed.body.request.state, "PREFLIGHT_VERIFIED");
    const r = await x.req(requestId);
    x.model.know(r); x.model.seedInputs(frozenOf(r), r.covenantId); x.model.confirmOnSubmit = true;
    const sub = await x.ownerSubmit(requestId);
    assert.equal(sub.status, 200, said(sub)); assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
    const confirmed = await x.events("request.confirmed", requestId);
    assert.equal(confirmed.length, 1, "exactly one request.confirmed for the CHAIN_VERIFIED submit");
    assert.equal(confirmed[0].data.state, "CHAIN_VERIFIED"); assert.equal(confirmed[0].data.terminal, false);
    assert.equal(confirmed[0].correlation.txId, r.txId);
  });

  /* ---------------- A2: reject narrowing (H-11) with GATE 1 ---------------- */
  t8("A2 reject narrowing: another covenant agent of the same vault rejecting the first agent's BUILT request gets 403 REQUEST_FORBIDDEN; the request, its reservation and every record are unchanged and no request.rejected is emitted [RED on C1]", async (x) => {
    const a1 = await x.rawRequest(B.rj.a1), before = await x.snap();
    assert.equal(a1.state, "BUILT"); assert.equal(a1.signerXOnly, w.agent.xonly);
    const r = await x.api.reject(x.cookie.agent2, a1.requestId);
    assert.equal(r.status, 403, `a covenant agent that is neither the signer nor the owner may not reject (${said(r)})`);
    assert.equal(r.code, "REQUEST_FORBIDDEN");
    assert.deepEqual(await x.rawRequest(a1.requestId), a1, "the request is byte-identical");
    assert.deepEqual(await x.snap(), before, "nothing is written");
    assert.deepEqual(await x.events("request.rejected", a1.requestId), [], "no request.rejected");
  });
  t8("A2 GATE 1 holds: a foreign principal rejecting the agent's request gets 404 REQUEST_NOT_FOUND with nothing changed; the vault owner rejects the agent's BUILT request (200 WALLET_REJECTED, one request.rejected) [holds on C1]", async (x) => {
    const a1 = await x.rawRequest(B.rj.a1), a2 = await x.rawRequest(B.rj.a2), before = await x.snap();
    const foreign = await x.api.reject(x.cookie.foreign, a1.requestId);
    assert.equal(foreign.status, 404, said(foreign)); assert.equal(foreign.code, "REQUEST_NOT_FOUND");
    assert.deepEqual(await x.snap(), before, "a foreign reject writes nothing");
    const owner = await x.api.reject(x.cookie.owner, a2.requestId);
    assert.equal(owner.status, 200, said(owner)); assert.equal(owner.body.request.state, "WALLET_REJECTED");
    assert.equal((await x.events("request.rejected", a2.requestId)).length, 1);
    assert.deepEqual(await x.rawRequest(a1.requestId), a1, "the other request is untouched");
  });

  /* ---------------- A6: the badge (§5 A6) ---------------- */
  t8("A6 badge: a PENDING record on the live outpoint without a transition claim is presented as a held claim — the RC44-written claimless byte-less FINALIZED (fz) and the PREFLIGHT_VERIFIED whose claims RC44 released by age (ag) badge ACTION_REQUIRED_VERIFY naming the record's txid and request, on GET /vaults/:id and GET /vaults; nothing is written [RED on C1]", async (x) => {
    const before = await x.snap();
    const list = await x.api.call("GET", ["vaults"], null, x.cookie.owner);
    assert.equal(list.status, 200, said(list));
    for (const [v, h, state] of [[V.fz, H.fz.r, "FINALIZED"], [V.ag, H.ag.a, "PREFLIGHT_VERIFIED"]]) {
      const rec = await x.req(h.requestId), manifest = await x.rawManifest(v);
      assert.equal(rec.state, state, `${v.tag}: the RC44-written record`);
      assert.deepEqual(manifest.live.outpoint, rec.predecessorOutpoint, `${v.tag}: the record spends the live outpoint`);
      assert.equal(await x.claimOn(rec.predecessorOutpoint), null, `${v.tag}: no transition claim on L`);
      const one = await x.api.call("GET", ["vaults", v.vaultId], null, x.cookie.owner);
      assert.equal(one.status, 200, said(one));
      const op = one.body.operational;
      assert.equal(op.status, "ACTION_REQUIRED_VERIFY", `${v.tag}: the PENDING record on L is a held claim (A6), got ${JSON.stringify(op).slice(0, 200)}`);
      assert.equal(op.claim?.txId, rec.txId, `${v.tag}: the badge names the record's txid`);
      assert.equal(op.request?.requestId, rec.requestId, `${v.tag}: and its request`);
      const listed = list.body.vaults.find((p) => p && p.vaultId === v.vaultId);
      assert.ok(listed, `${v.tag}: the owner's listing presents the vault`);
      assert.equal(listed.operational.status, "ACTION_REQUIRED_VERIFY", `${v.tag}: the listing badges the same`);
    }
    assert.deepEqual(await x.snap(), before, "presentation writes nothing");
  });
  t8("A6 holds: a PENDING record on an ancestor outpoint (the vault's live outpoint moved on) leaves the badge ACTIVE — the held claim is taken only from the live outpoint [holds on C1]", async (x) => {
    const d = await x.req(B.an.d), manifest = await x.rawManifest(V.an);
    assert.equal(d.state, "PREFLIGHT_VERIFIED");
    assert.deepEqual(manifest.live.outpoint, B.an.P1); assert.notDeepEqual(d.predecessorOutpoint, B.an.P1);
    const one = await x.api.call("GET", ["vaults", V.an.vaultId], null, x.cookie.owner);
    assert.equal(one.status, 200, said(one));
    assert.equal(one.body.operational.status, "ACTIVE", JSON.stringify(one.body.operational).slice(0, 200));
  });

  /* ---------------- attestation mapping of Verify-settled records (T8; F12 spec terms) ---------------- */
  t8("attestation mapping: after Verify settles the owner's contested Pause at D, the export presents the winner SETTLED (CHAIN_VERIFIED rung, successor outpoint), the superseded delegate AUTHORIZED/FAILED with failureCode STALE and no broadcast rung, and the owner's abandoned BUILT same-txid twin AUTHORIZED/IN_PROGRESS with no broadcast rung although a receipt exists for its txid (signed-state-only twins, CR-M10); store path and request route agree [RED on C1]", async (x) => {
    const t = await x.req(B.at.t), q = await x.req(B.at.q), d = await x.req(B.at.d);
    assert.equal(t.state, "BUILT"); assert.equal(q.state, "PREFLIGHT_VERIFIED"); assert.equal(d.state, "PREFLIGHT_VERIFIED");
    x.model.seedInputs(frozenOf(q), q.covenantId); x.model.confirm(frozenOf(q), q.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const done = await resolved(() => x.verify(V.at), "Verify at depth D");
    assert.equal(done.status, "ADVANCED", `Verify settles the owner's Pause (got ${JSON.stringify(done).slice(0, 300)})`);
    assert.equal(done.txId, q.txId); assert.equal(done.requestId, q.requestId);
    assert.equal((await x.rawRequest(q.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.rawRequest(d.requestId)).state, "STALE");
    assert.equal((await x.rawRequest(t.requestId)).state, "BUILT", "the BUILT twin stays BUILT (CR-M10)");
    const index = frozenOf(q).outputs.findIndex((o) => o.covenant !== null);
    const expected = {
      [q.requestId]: { decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId: q.txId, outputs: 1, successorOutpoint: { transactionId: q.txId, index }, state: "CHAIN_VERIFIED", disposition: "SETTLED", reached: ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"] },
      [d.requestId]: { decision: "AUTHORIZED", refusalCode: null, failureCode: "STALE", txId: null, outputs: 0, successorOutpoint: null, state: "AUTHORIZED", disposition: "FAILED", reached: ["AUTHORIZED"] },
      [t.requestId]: { decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "AUTHORIZED", disposition: "IN_PROGRESS", reached: ["AUTHORIZED"] }
    };
    assert.ok(await x.receipt(t.txId), "a receipt exists for the twin's (shared) txid");
    const { buildAttestationForRequest } = require("../../server/src/attestations");
    for (const [requestId, want] of Object.entries(expected)) {
      const { attestation } = await buildAttestationForRequest(x.config, await x.req(requestId));
      assert.deepEqual(ladderOf(attestation), want, `store path ${requestId}`);
      const route = await x.api.call("GET", ["attestations", "requests", requestId], null, x.cookie.owner);
      assert.equal(route.status, 200, said(route));
      assert.deepEqual(ladderOf(route.body.attestation), want, `request route ${requestId}`);
    }
  });
}
