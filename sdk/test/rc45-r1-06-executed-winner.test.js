"use strict";
/*
 * RC45 R1-06 — AN EXECUTED WINNER IS NEVER LABELLED STALE (finding ST-03 of the
 * independent candidate review rc45-patch-independent-01; remediation plan R1
 * revision 2, R1-06 with conditions C2, C3, K4 and K5). Internal RED-first
 * regression material for the RC45 successor candidate; not an audit.
 * Adapted from the review-only probes review-settlement-c-strand (settlement)
 * and review-lead-closeout-strand (lead). The T7 crash-point re-pins, probe C
 * on the SDK path and the receipt-first crash window are in
 * sdk/test/rc45-t7-verify-crash.test.js; this file holds the hosted-route
 * legs, the staleness-verdict legs, the exact C2 finishing predicate and the
 * RC42 governed creator.
 *
 * The rules (plan R1-06):
 *   - K4 receipt guard: in submit and finalize, BEFORE predecessorDispositionV4,
 *     a receipt for request.txId that receiptMatches THIS request
 *     (proof.requestId === r.requestId, the expected outpoint and value)
 *     answers 422 RECONCILIATION_REQUIRED with nothing written, whatever the
 *     staleness verdict (stale, own-txid or not stale);
 *   - C2 finishing predicate (finishRecorded / settleOneHop), exactly:
 *     journal-free, state in SIGNED_OR_REJECTED and not CHAIN_VERIFIED,
 *     receiptMatches with proof.requestId === r.requestId and the expected
 *     outpoint and value, identity valid -> complete CHAIN_VERIFIED from the
 *     recorded proof, no node call, in any hop position; same-txid twins only
 *     through twinComplete (CR-M10); journaled records are never written
 *     (L-15);
 *   - K5 residual: an unsigned (BUILT) winner whose completion stopped after
 *     the manifest write keeps its receipt and its unsigned label; C2 never
 *     finishes it and its finalize answers 422 by the receipt guard.
 *
 * RED on dc7552e: a hosted or SDK submit / finalize of an executed winner
 * after a further hop labels it STALE (and the attestation exports it
 * FAILED/STALE); Verify never finishes a winner stranded more than one hop
 * back, so a closed vault keeps it unresolved (REQUEST_RECOVERY_REQUIRED).
 * HOLDS on dc7552e (and must keep holding): the own-txid verdict's 422; every
 * C2 exclusion (a receipt naming another request, another outpoint or value,
 * a journaled record, an identity-invalid record, an unsigned winner, a BUILT
 * same-txid twin); the RC42 governed creator stays REFUSED on every export
 * path after its retry executed and after a further hop.
 *
 * Population (candidate-written): TEST vaults seeded by the F5 kit; the
 * delegate's spend W and the unsigned spend U built through the self-hosted
 * v0.4 build route (intent-manifest records, so the attestation export can
 * name their outputs), W finalized with the agent's TEST key (deterministic
 * dev signer, pinned pv_vm_preflight); a same-txid pair W2 / T2 built
 * SDK-direct (W2 finalized, T2 BUILT). RC42-written: the EXISTING ladder
 * writer (sdk/testutil/rc45-f8-rc42.js, a84e2a9 modules, pins verified;
 * POLICYVAULT_TEST_RC42_TREE; a missing tree is a FAIL, never a skip) for
 * TWIN_DEF_CREATOR_BUILT / TWIN_SHARER_CV. SYNTHETIC (labelled where used):
 * the completion receipt written create-only by the test when the runtime
 * has not written it (exactly completeRecord's shape), and the C2 exclusion
 * mutations of a receipt or a record.
 *
 * Layers: SDK + API (the real server/src/api.js handle; hosted cases sign in
 * with TEST keys through /auth/challenge + /auth/verify; route-level submit
 * and Verify wrap the module-cache exports of the REAL
 * submitWalletRequestV4 / reconcileVaultV4 to pass the explicit chain model's
 * rpc, plan r2 §8 rules CR-M14, CR2-L12). Real v0.4/v0.4.1 compiler,
 * pv_call_encoder, TEST-key signatures and pv_vm_preflight for every consensus
 * byte. Node observations come only from the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js; every config names ws://127.0.0.1:1, so
 * nothing can dial a node. "No write" for a route leg covers every durable
 * record category the kit snapshots plus the intent-manifest records and the
 * audit; the route's pre-existing request.failed platform event is not
 * counted (the plan's "no write" is the SDK guard's). Both stores: JSON
 * always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45
 * runner's pg mode; a skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const R42 = require("../testutil/rc45-f8-rc42");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const recovery4 = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const RC42_TREE = process.env.POLICYVAULT_TEST_RC42_TREE || "";
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V = Object.freeze({ hw: K.vault("r106-hw"), hu: K.vault("r106-hu"), tw: K.vault("r106-tw") });
const FULL_LADDER = Object.freeze(["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"]);
const REFUSED_TERMINAL_LADDER = Object.freeze({ decision: "REFUSED", refusalCode: "GOVERNANCE_PROPOSAL_TERMINAL", failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "REFUSED", disposition: "REFUSED", reached: [] });
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, history = null, B = null, w = null, templateRoot = null, overlay = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const track = (root) => roots.push(root);
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (outcome) => (outcome.error ? `${outcome.error.code ?? "no code"}: ${String(outcome.error.message).slice(0, 240)}` : `success (${JSON.stringify(outcome.value && outcome.value.request ? { state: outcome.value.request.state } : outcome.value && outcome.value.state ? { state: outcome.value.state } : null)})`);
const routeSaid = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();
async function resolved(fn, message) {
  let value;
  await assert.doesNotReject(async () => { value = await fn(); }, message);
  return value;
}

/* The five durable categories of the F5 kit plus the intent-manifest records the build route writes; the audit. */
async function snapshotAll(config) {
  const snap = await K.snapshot(cand, config), s = cand.store.getStore(config);
  snap.records[Categories.INTENT_MANIFEST] = await Promise.all((await s.listKeys(Categories.INTENT_MANIFEST)).sort().map(async (k) => [k, await s.read(Categories.INTENT_MANIFEST, k)]));
  return snap;
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r106-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off); the cases are hosted");
  w = K.walletsFor(template);
  const k = K.kitFor(cand, template, w), id = (r) => r.requestId;
  const { handle } = require("../../server/src/api");
  const routeBuild = async (v, kas) => {
    const r = await handle(template, "POST", ["wallet", "v4", "requests"], {}, { vaultId: v.vaultId, action: "agentSpend", params: k.spend(BigInt(kas) * KAS), signerAddress: w.agent.address });
    assert.equal(r.status, 201, `self-hosted build route (${JSON.stringify(r.body).slice(0, 200)})`);
    const built = await cand.wr4.loadRequest(template, r.body.request.requestId);
    assert.equal(built.state, "BUILT"); assert.equal(typeof built.manifestHash, "string", "the build route recorded an intent manifest");
    return built;
  };
  B = {};
  { await K.seedVault(cand, template, V.hw, w);
    const W = await k.finalize(await routeBuild(V.hw, 4), w.agent);
    assert.equal(W.state, "PREFLIGHT_VERIFIED", "the delegate's spend W finalizes (real TEST-key signature, pinned pv_vm_preflight)");
    B.hw = { W: id(W) }; }
  { await K.seedVault(cand, template, V.hu, w); B.hu = { U: id(await routeBuild(V.hu, 3)) }; }
  { await K.seedVault(cand, template, V.tw, w);
    const w2 = await k.agentSpend(V.tw, 4), t2 = await k.agentSpend(V.tw, 4);
    assert.equal(t2.txId, w2.txId, "the same spend on the same live state freezes the same transaction (same-txid twin)");
    const W2 = await k.finalize(w2, w.agent); assert.equal(W2.state, "PREFLIGHT_VERIFIED");
    B.tw = { W2: id(W2), T2: id(t2) }; }
  history = await snapshotAll(template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh hosted case (authMode enabled); wallets sign in on first use. */
async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r106-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r106_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig(hosted);
  assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), api = F3.apiFor(config), cookies = {};
  const x = {
    config, store, api, pgDatabase, model: K.chainModel(config), k: K.kitFor(cand, config, w),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    rawRequest: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (v) => store.read(Categories.VAULT, v.vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    snap: () => snapshotAll(config),
    verify: (v) => cand.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc: x.model.rpc }),
    submit: (requestId) => cand.submit4.submitWalletRequestV4({ config, requestId, rpc: x.model.rpc, pollAttempts: 1, pollDelayMs: 0 }),
    cookie: async (who) => { if (!cookies[who]) cookies[who] = await api.signIn(w[who]); return cookies[who]; }
  };
  /* POST /vaults/:id/reconcile through the REAL reconcileVaultV4 wrapped with the explicit chain model's rpc. */
  x.verifyRoute = async (v, cookie) => {
    const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
    m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: x.model.rpc });
    try { return await api.call("POST", ["vaults", v.vaultId, "reconcile"], {}, cookie); } finally { m4.reconcileVaultV4 = real4; }
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

/* ---------------- faults, receipts, hops ---------------- */
/* One in-process store fault (the next matching durable step throws instead of being performed), as the review probes inject it. */
function storeFault(store, when) {
  const names = ["write", "createExclusive", "remove", "appendAudit"], own = {}, performed = [];
  let fired = false;
  for (const name of names) {
    own[name] = Object.prototype.hasOwnProperty.call(store, name) ? store[name] : undefined;
    const original = store[name].bind(store);
    store[name] = async (...args) => {
      if (!fired && when(name, args, performed)) {
        fired = true;
        throw Object.assign(new Error(`TEST store fault at ${name} ${String(args[0])}/${String(args[1])}`), { code: "ECONNRESET" });
      }
      const out = await original(...args);
      performed.push([name, args[0], args[1]]);
      return out;
    };
  }
  return { get fired() { return fired; }, restore() { for (const name of names) { if (own[name] === undefined) delete store[name]; else store[name] = own[name]; } } };
}
const atRelabel = (r) => (name, args) => name === "write" && args[0] === Categories.REQUEST && args[1] === r.requestId && args[2] && args[2].state === "CHAIN_VERIFIED";
const afterManifest = (v) => (_name, _args, performed) => performed.some(([n, c, k]) => n === "write" && c === Categories.VAULT && k === v.vaultId);
/* The executed winner `r` lands at depth D; Verify's completion of it stops at `when`; the manifest is advanced by r. */
async function strand(x, v, r, when, label) {
  x.model.confirm(frozenOf(r), r.txId); x.model.advance(SETTLE_DEPTH_DAA);
  const f = storeFault(x.store, when);
  let outcome;
  try { outcome = await settle(x.verify(v)); } finally { f.restore(); }
  assert.equal(f.fired, true, `${label}: the injected fault fired`);
  assert.ok(outcome.error && /TEST store fault/.test(String(outcome.error.message)), `${label}: the faulted Verify stopped at the fault (${said(outcome)})`);
  assert.equal((await x.rawManifest(v)).latestTransitionTxId, r.txId, `${label}: the manifest is advanced by the executed winner`);
  assert.equal((await x.rawRequest(r.requestId)).state, r.state, `${label}: the winner keeps its label (${r.state})`);
}
/* The receipt exactly as the completion writes it (sdk/src/reconcile-v4.js completeRecord: create-only, keyed by txid). */
async function completionReceipt(x, r) {
  const e = recovery4.validateIdentity(x.config, r).expected;
  return { schema: "policyvault-receipt/v1", txId: r.txId, vaultId: r.vaultId, action: r.action,
    proof: { requestId: r.requestId, successorOutpoint: e.kind === "recover" ? null : `${r.txId}:${e.index}`, value: e.valueSompi, reconciled: true }, verifiedAt: new Date().toISOString() };
}
/* After a stop right after the manifest write, R1-06 C3 has already written the winner's receipt (the receipt precedes
 * the manifest). dc7552e writes it after the manifest, so there the test writes the identical receipt create-only
 * (SYNTHETIC at dc7552e; a no-op after R1-06), which isolates the K4 guard from the C3 order (pinned in T7). */
async function ensureCompletionReceipt(x, r) {
  if (!(await x.receipt(r.txId))) assert.equal(await x.store.createExclusive(Categories.RECEIPT, r.txId, await completionReceipt(x, r)), true);
  const receipt = await x.receipt(r.txId);
  assert.equal(receipt?.proof?.requestId, r.requestId, "the winner's own receipt");
  return receipt;
}
/* The delegate's ordinary spend P2 on the advanced vault, SDK path: completes uncontested at zero depth (L-2). */
async function sdkHop(x, v) {
  const p2 = await x.k.finalize(await x.k.agentSpend(v, 2), w.agent);
  assert.equal(p2.state, "PREFLIGHT_VERIFIED", "P2 finalizes (the stranded winner on the ancestor outpoint blocks nothing)");
  x.model.know(p2); x.model.confirmOnSubmit = true;
  let run;
  try { run = await settle(x.submit(p2.requestId)); } finally { x.model.confirmOnSubmit = false; }
  assert.equal(run.error, null, `P2's ordinary submit completes (${said(run)})`);
  assert.equal(run.value.request.state, "CHAIN_VERIFIED");
  assert.equal((await x.rawManifest(v)).latestTransitionTxId, p2.txId, "the manifest moved past the winner's successor");
  return p2;
}
/* The same hop through the agent's hosted build, signature and submit routes. */
async function hostedHop(x, v) {
  const agent = await x.cookie("agent");
  const built = await x.api.build(agent, { vaultId: v.vaultId, action: "agentSpend", params: x.k.spend(2n * KAS), signerAddress: w.agent.address });
  assert.equal(built.status, 201, `the agent's hosted build of P2 (${routeSaid(built)})`);
  const p2 = await x.req(built.body.request.requestId);
  const fin = await x.api.signature(agent, p2.requestId, x.k.sign(p2, w.agent));
  assert.equal(fin.status, 200, `the agent's hosted finalize of P2 (${routeSaid(fin)})`);
  const signed = await x.req(p2.requestId);
  x.model.know(signed); x.model.confirmOnSubmit = true;
  let sub;
  try { sub = await F3.submitThroughModel(() => x.model, () => x.api.submit(agent, p2.requestId)); } finally { x.model.confirmOnSubmit = false; }
  assert.equal(sub.status, 200, `the agent's hosted submit of P2 completes (${routeSaid(sub)})`);
  assert.equal(sub.body.request.state, "CHAIN_VERIFIED");
  assert.equal((await x.rawManifest(v)).latestTransitionTxId, p2.txId, "the manifest moved past the winner's successor");
  return signed;
}

/* ---------------- the attestation export, every path ---------------- */
function ladderOf(attestation) {
  const o = attestation.outcome;
  return { decision: attestation.authorization.decision, refusalCode: attestation.authorization.refusalCode, failureCode: o.failureCode, txId: o.txId,
    outputs: o.chain.outputs.length, successorOutpoint: o.chain.successorOutpoint, state: o.state, disposition: o.disposition, reached: o.reached.map((r) => r.state) };
}
const ndjsonRecords = (raw) => String(raw).split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
/* The store path, GET /attestations/requests/:id (json, ndjson), GET /attestations/export?vaultId (json, ndjson). */
async function exportsOf(config, api, request, vaultId, cookie = null) {
  const { buildAttestationForRequest } = require("../../server/src/attestations");
  const { handle } = require("../../server/src/api");
  const opts = cookie ? { headers: { cookie } } : {};
  const out = { store: ladderOf((await buildAttestationForRequest(config, request)).attestation) };
  const one = await api.call("GET", ["attestations", "requests", request.requestId], null, cookie);
  assert.equal(one.status, 200, `request route (${routeSaid(one)})`);
  out.route = ladderOf(one.body.attestation);
  const ndOne = ndjsonRecords((await handle(config, "GET", ["attestations", "requests", request.requestId], { format: "ndjson" }, null, opts)).rawBody);
  assert.equal(ndOne.length, 1);
  out.routeNdjson = ladderOf(ndOne[0]);
  const batch = await api.call("GET", ["attestations", "export"], null, cookie, { vaultId });
  assert.equal(batch.status, 200, `vault export (${routeSaid(batch)})`);
  const rec = batch.body.records.find((r) => r.attestation.subject.requestId === request.requestId);
  assert.ok(rec, "the vault export lists the request");
  out.export = ladderOf(rec.attestation);
  const ndRec = ndjsonRecords((await handle(config, "GET", ["attestations", "export"], { vaultId, format: "ndjson" }, null, opts)).rawBody).find((a) => a.subject.requestId === request.requestId);
  assert.ok(ndRec, "the ndjson vault export lists the request");
  out.exportNdjson = ladderOf(ndRec);
  return out;
}
function assertEveryPath(paths, expected, label) {
  for (const [name, ladder] of Object.entries(paths)) assert.deepEqual(ladder, expected, `${label}: ${name}`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r106 = (name, fn) => test(`RC45 R1-06 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- RED: K4 at the hosted routes, C2 in any hop position ---------------- */
  r106("hosted probe C: the delegate's executed spend W (built through the build route, CONFIRMED at D) is stranded by a fault at its CHAIN_VERIFIED relabel (own receipt written, manifest advanced); the agent's ordinary spend P2 completes through the hosted build/signature/submit routes at zero depth; the agent's hosted submit of W then answers 422 RECONCILIATION_REQUIRED with nothing written (never 409 STALE); the owner's hosted Verify route at D finishes W CHAIN_VERIFIED with its receipt byte-identical, and W exports AUTHORIZED / CHAIN_VERIFIED / SETTLED with the full ladder on every export path (never FAILED/STALE) [RED on dc7552e]", async (x) => {
    const W = await x.req(B.hw.W);
    await strand(x, V.hw, W, atRelabel(W), "hosted probe C");
    const receipt = await x.receipt(W.txId);
    assert.equal(receipt?.proof?.requestId, W.requestId, "W's own receipt is written before the faulted relabel");
    await hostedHop(x, V.hw);
    const before = await x.snap(), agent = await x.cookie("agent");
    const sub = await F3.submitThroughModel(() => x.model, () => x.api.submit(agent, W.requestId));
    assert.equal(`${sub.status} ${sub.code}`, "422 RECONCILIATION_REQUIRED", `the agent's hosted submit of the executed W answers 422 RECONCILIATION_REQUIRED from the receipt guard (got ${routeSaid(sub)})`);
    assert.deepEqual(await x.snap(), before, "the refused hosted submit writes nothing (W is never labelled STALE)");
    x.model.advance(SETTLE_DEPTH_DAA);
    const v = await x.verifyRoute(V.hw, await x.cookie("owner"));
    assert.equal(v.status, 200, `the owner's hosted Verify route answers (${routeSaid(v)})`);
    const after = await x.req(W.requestId);
    assert.equal(after.state, "CHAIN_VERIFIED", "the owner's Verify finishes the executed W from its recorded proof (C2, any hop position)");
    assert.deepEqual(await x.receipt(W.txId), receipt, "W's own receipt is kept byte-identical");
    for (const [name, l] of Object.entries(await exportsOf(x.config, x.api, after, V.hw.vaultId, await x.cookie("owner")))) {
      assert.deepEqual({ decision: l.decision, failureCode: l.failureCode, state: l.state, disposition: l.disposition, txId: l.txId, reached: l.reached },
        { decision: "AUTHORIZED", failureCode: null, state: "CHAIN_VERIFIED", disposition: "SETTLED", txId: W.txId, reached: [...FULL_LADDER] }, `W's export (${name}) is the executed payment, never FAILED/STALE`);
    }
  });

  r106("hosted finalize, stale verdict (K4, K5 residual): an ordinary unsigned spend U (built through the build route, signed outside PolicyVault, landed at D) is completed by Verify up to its manifest write and stops right after it, keeping its own receipt (R1-06 C3; the identical receipt written create-only at dc7552e) and its BUILT label; the agent's ordinary spend P2 then completes through the hosted routes on U's successor; the agent's hosted finalize of U (its real TEST-key signature) answers 422 RECONCILIATION_REQUIRED with nothing written (never 409 STALE) [RED on dc7552e]", async (x) => {
    const U = await x.req(B.hu.U);
    await strand(x, V.hu, U, afterManifest(V.hu), "unsigned winner, stop after the manifest write");
    await ensureCompletionReceipt(x, U);
    await hostedHop(x, V.hu);
    const before = await x.snap();
    const fin = await x.api.signature(await x.cookie("agent"), U.requestId, x.k.sign(U, w.agent));
    assert.equal(`${fin.status} ${fin.code}`, "422 RECONCILIATION_REQUIRED", `the agent's hosted finalize of the executed unsigned U answers 422 RECONCILIATION_REQUIRED from the receipt guard (got ${routeSaid(fin)})`);
    assert.deepEqual(await x.snap(), before, "the refused hosted finalize writes nothing (U is never labelled STALE)");
  });

  r106("SDK finalize, stale verdict (K4, K5 residual): the same stranded unsigned U with its own receipt after the agent's ordinary spend P2 completed on U's successor (SDK path): finalizeWalletRequestV4 answers 422 RECONCILIATION_REQUIRED with nothing written, before predecessorDispositionV4 (never STALE) [RED on dc7552e]", async (x) => {
    const U = await x.req(B.hu.U);
    await strand(x, V.hu, U, afterManifest(V.hu), "unsigned winner, stop after the manifest write");
    await ensureCompletionReceipt(x, U);
    await sdkHop(x, V.hu);
    const before = await x.snap();
    const fin = await settle(x.k.finalize(U, w.agent));
    assert.equal(fin.error?.code, "RECONCILIATION_REQUIRED", `finalize of the executed unsigned U answers 422 RECONCILIATION_REQUIRED from the receipt guard (got ${said(fin)})`);
    assert.deepEqual(await x.snap(), before, "the refused finalize writes nothing (U is never labelled STALE)");
  });

  r106("SDK submit, stale verdict (K4): the delegate's executed W stranded with its own receipt after the stop right after its manifest write (R1-06 C3; the identical receipt written create-only at dc7552e), then the agent's ordinary spend P2 completed on W's successor: submitWalletRequestV4 of W answers 422 RECONCILIATION_REQUIRED with nothing written and no node call (never STALE) [RED on dc7552e]", async (x) => {
    const W = await x.req(B.hw.W);
    await strand(x, V.hw, W, afterManifest(V.hw), "signed winner, stop after the manifest write");
    await ensureCompletionReceipt(x, W);
    await sdkHop(x, V.hw);
    const before = await x.snap(), calls = x.model.calls.length;
    const sub = await settle(x.submit(W.requestId));
    assert.equal(sub.error?.code, "RECONCILIATION_REQUIRED", `submit of the executed W answers 422 RECONCILIATION_REQUIRED from the receipt guard (got ${said(sub)})`);
    assert.deepEqual(await x.snap(), before, "the refused submit writes nothing (W is never labelled STALE)");
    assert.equal(x.model.calls.length, calls, "no node call");
  });

  r106("C2 in any hop position on a closed vault, no node call: the executed W is stranded by a fault at its CHAIN_VERIFIED relabel; the owner then closes the vault (Close & recover R on W's successor, submitted, landed, completed by Verify at D); a further Verify finishes W CHAIN_VERIFIED from its recorded proof with no node call (receipt byte-identical) and answers TERMINAL [RED on dc7552e]", async (x) => {
    const W = await x.req(B.hw.W);
    await strand(x, V.hw, W, atRelabel(W), "closed-vault strand");
    const receipt = await x.receipt(W.txId);
    assert.equal(receipt?.proof?.requestId, W.requestId);
    const R = await x.k.finalize(await x.k.ownerOp(V.hw, "ownerRecover"), w.owner);
    assert.equal(R.state, "PREFLIGHT_VERIFIED", "the owner's Close & recover finalizes (break-glass)");
    const fr = frozenOf(R);
    fr.inputs.forEach((i, index) => { if (index > 0) x.model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, x.model.virtualDaaScore - 5000n); }); // the owner's fuel
    x.model.know(R); x.model.confirmOnSubmit = true;
    let run;
    try { run = await settle(x.submit(R.requestId)); } finally { x.model.confirmOnSubmit = false; }
    assert.equal(run.error, null, `the recover is submitted (${said(run)})`);
    x.model.advance(SETTLE_DEPTH_DAA);
    const closed = await resolved(() => x.verify(V.hw), "Verify at D answers");
    assert.equal(closed.status, "ADVANCED", `Verify completes the recover at D (got ${JSON.stringify(closed).slice(0, 300)})`);
    assert.equal((await x.rawManifest(V.hw)).status, "RECOVERED");
    const calls = x.model.calls.length;
    const last = await resolved(() => x.verify(V.hw), "the further Verify answers");
    assert.equal((await x.rawRequest(W.requestId)).state, "CHAIN_VERIFIED", "W is finished CHAIN_VERIFIED from its recorded proof (C2, any hop position; no longer an unresolved record of the closed vault)");
    assert.equal(x.model.calls.length, calls, "finishing from the recorded proof needs no node call");
    assert.deepEqual(await x.receipt(W.txId), receipt, "W's own receipt is kept byte-identical");
    assert.equal(last.status, "TERMINAL", `nothing unresolved remains (got ${JSON.stringify(last).slice(0, 300)})`);
  });

  r106("C2 for a winner in another SIGNED_OR_REJECTED state, any hop position: the delegate's W is submitted through the ordinary SDK submit and its effect is not yet observed (RECONCILIATION_REQUIRED, journal-free, claims kept); it lands at D and Verify's completion of it faults at its CHAIN_VERIFIED relabel (own receipt written); after the agent's ordinary spend P2 completed on W's successor, the next Verify at D finishes the RECONCILIATION_REQUIRED W CHAIN_VERIFIED from its recorded proof, its receipt byte-identical [RED on dc7552e]", async (x) => {
    const W0 = await x.req(B.hw.W);
    x.model.seedInputs(frozenOf(W0), W0.covenantId); x.model.know(W0);
    const sub = await settle(x.submit(W0.requestId));
    assert.equal(sub.error?.code, "RECONCILIATION_REQUIRED", `the ordinary submit broadcasts but does not observe the effect yet (${said(sub)})`);
    const W = await x.req(B.hw.W);
    assert.equal(W.state, "RECONCILIATION_REQUIRED"); assert.equal(W.transitionRecovery, undefined, "journal-free");
    await strand(x, V.hw, W, atRelabel(W), "RECONCILIATION_REQUIRED winner (relabel fault)");
    const receipt = await x.receipt(W.txId);
    assert.equal(receipt?.proof?.requestId, W.requestId);
    await sdkHop(x, V.hw);
    x.model.advance(SETTLE_DEPTH_DAA);
    await resolved(() => x.verify(V.hw), "the next Verify at D answers");
    assert.equal((await x.rawRequest(W.requestId)).state, "CHAIN_VERIFIED", "Verify finishes the executed RECONCILIATION_REQUIRED W from its recorded proof (C2: any SIGNED_OR_REJECTED state, any hop position)");
    assert.deepEqual(await x.receipt(W.txId), receipt, "W's own receipt is kept byte-identical");
  });

  /* ---------------- HOLDS: the own-txid verdict ---------------- */
  r106("own-txid verdict (K4; holds): a winner whose completion stopped right after its own manifest write (its own receipt present), with no further hop: submit of the executed W and finalize of the executed unsigned U each answer 422 RECONCILIATION_REQUIRED with nothing written", async (x) => {
    const W = await x.req(B.hw.W), U = await x.req(B.hu.U);
    await strand(x, V.hw, W, afterManifest(V.hw), "signed winner, stop after the manifest write");
    await ensureCompletionReceipt(x, W);
    await strand(x, V.hu, U, afterManifest(V.hu), "unsigned winner, stop after the manifest write");
    await ensureCompletionReceipt(x, U);
    let before = await x.snap();
    const sub = await settle(x.submit(W.requestId));
    assert.equal(sub.error?.code, "RECONCILIATION_REQUIRED", `submit of W (got ${said(sub)})`);
    assert.deepEqual(await x.snap(), before, "the refused submit writes nothing");
    before = await x.snap();
    const fin = await settle(x.k.finalize(U, w.agent));
    assert.equal(fin.error?.code, "RECONCILIATION_REQUIRED", `finalize of U (got ${said(fin)})`);
    assert.deepEqual(await x.snap(), before, "the refused finalize writes nothing");
  });

  /* ---------------- HOLDS: the exact C2 finishing predicate (exclusions) ---------------- */
  /* Each starts from probe C's stranded W (relabel fault: own receipt, PREFLIGHT_VERIFIED), one SDK hop (P2 at zero depth)
   * and depth D, then applies one SYNTHETIC change that takes the record out of the predicate; Verify (which may answer or
   * refuse) then writes nothing at all. */
  const exclusions = [
    ["a receipt whose proof.requestId names another request (twins finish only through twinComplete, CR-M10)",
      async (x, W, receipt) => x.store.write(Categories.RECEIPT, W.txId, { ...receipt, proof: { ...receipt.proof, requestId: K.hex("rc45-r106-another-request") } })],
    ["a receipt naming another output of the transaction (expected outpoint)",
      async (x, W, receipt) => x.store.write(Categories.RECEIPT, W.txId, { ...receipt, proof: { ...receipt.proof, successorOutpoint: `${W.txId}:${Number(receipt.proof.successorOutpoint.split(":")[1]) + 1}` } })],
    ["a receipt with another value (expected value)",
      async (x, W, receipt) => x.store.write(Categories.RECEIPT, W.txId, { ...receipt, proof: { ...receipt.proof, value: String(BigInt(receipt.proof.value) + 1n) } })],
    ["a journaled record (a PROTECTED transition-recovery journal, RECONCILIATION_REQUIRED; L-15: journaled history is never written)",
      async (x, W) => {
        const raw = await x.rawRequest(W.requestId), copy = JSON.parse(JSON.stringify(raw));
        delete copy.state; delete copy.transitionRecovery;
        await x.store.write(Categories.REQUEST, W.requestId, { ...raw, state: "RECONCILIATION_REQUIRED",
          transitionRecovery: { schema: recovery4.RECOVERY_SCHEMA, phase: "PROTECTED", requestBinding: recovery4.canonicalRecordFingerprint(copy), originalState: "PREFLIGHT_VERIFIED",
            claimFingerprints: [null, null], reservationFingerprint: null, protectedAt: new Date(0).toISOString() } });
      }],
    ["an identity-invalid record (its recorded signer x-only key no longer binds its build)",
      async (x, W) => { const raw = await x.rawRequest(W.requestId); await x.store.write(Categories.REQUEST, W.requestId, { ...raw, signerXOnly: "ab".repeat(32) }); }]
  ];
  for (const [what, change] of exclusions) {
    r106(`C2 exclusion (holds): a stranded executed W with ${what} is not finished; Verify writes nothing`, async (x) => {
      const W = await x.req(B.hw.W);
      await strand(x, V.hw, W, atRelabel(W), "C2 exclusion strand");
      const receipt = await x.receipt(W.txId);
      assert.equal(receipt?.proof?.requestId, W.requestId);
      await sdkHop(x, V.hw);
      x.model.advance(SETTLE_DEPTH_DAA);
      await change(x, W, receipt); // SYNTHETIC
      const before = await x.snap();
      const out = await settle(x.verify(V.hw));
      assert.deepEqual(await x.snap(), before, `Verify writes nothing (answered ${out.error ? said(out) : JSON.stringify(out.value).slice(0, 200)})`);
    });
  }
  r106("C2 exclusion (holds; K5 residual): an executed UNSIGNED winner U whose completion stopped right after its manifest write keeps its own receipt and its BUILT label; after the agent's ordinary spend P2 completed on U's successor, Verify at D never finishes U and writes nothing", async (x) => {
    const U = await x.req(B.hu.U);
    await strand(x, V.hu, U, afterManifest(V.hu), "unsigned winner, stop after the manifest write");
    await ensureCompletionReceipt(x, U);
    await sdkHop(x, V.hu);
    x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const out = await settle(x.verify(V.hu));
    assert.deepEqual(await x.snap(), before, `Verify writes nothing (answered ${out.error ? said(out) : JSON.stringify(out.value).slice(0, 200)})`);
    assert.equal((await x.rawRequest(U.requestId)).state, "BUILT", "U keeps its unsigned label");
  });
  r106("C2 twins (holds; CR-M10): the executed W2 is stranded by a fault at its CHAIN_VERIFIED relabel while its same-txid twin T2 is BUILT; after the agent's ordinary spend P2 completed on W2's successor, Verify at D never completes the BUILT twin T2 (byte-identical) and keeps W2's receipt byte-identical", async (x) => {
    const W2 = await x.req(B.tw.W2), T2raw = await x.rawRequest(B.tw.T2);
    assert.equal(T2raw.state, "BUILT"); assert.equal(T2raw.txId, W2.txId);
    await strand(x, V.tw, W2, atRelabel(W2), "twin strand");
    const receipt = await x.receipt(W2.txId);
    assert.equal(receipt?.proof?.requestId, W2.requestId, "the shared txid's receipt names W2");
    await sdkHop(x, V.tw);
    x.model.advance(SETTLE_DEPTH_DAA);
    await settle(x.verify(V.tw));
    assert.deepEqual(await x.rawRequest(B.tw.T2), T2raw, "the BUILT same-txid twin is never completed (twins only through twinComplete, which keeps BUILT twins)");
    assert.deepEqual(await x.receipt(W2.txId), receipt, "the shared receipt is kept byte-identical");
  });

  /* ---------------- HOLDS: the RC42 governed creator ---------------- */
  test(`RC45 R1-06 ${backend}: RC42 governed creator (holds): after the content-identical retry W of the RC42 TWIN_DEF_CREATOR_BUILT executed (CONFIRMED at D), Verify settles the vault by W and the never-signed creator stays byte-identical and REFUSED_TERMINAL_LADDER on every export path; after a further hop (the RC42 owner's ordinary top-up completing at zero depth on W's successor) a Verify at D still leaves the creator byte-identical and REFUSED on every export path, and the retry keeps its SETTLED ladder`, { skip }, async () => {
    if (!overlay) { R42.verifyRc42Tree(RC42_TREE); overlay = R42.rc42Overlay(RC42_TREE, mk("pv-rc45-r106-rc42-overlay-")); }
    const dataRoot = mk("pv-rc45-r106-rc42-data-");
    let pg = null, config, pgStore = null;
    if (backend === "PostgreSQL") {
      const database = `pv_rc45_r106_rc42_${process.pid}_${++serial}`;
      await admin.query(`CREATE DATABASE ${database}`); databases.push(database);
      pg = { host: PG.host, port: PG.port, user: PG.user, database };
    }
    const result = R42.runRc42LadderWriter({ overlay, backend: pg ? "postgres" : "json", dataRoot, pg });
    try {
      if (pg) {
        config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: pg.host, pgPort: pg.port, pgUser: pg.user, pgDatabase: pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
        pgStore = await cand.store.openPgStore(config); stores.push(pgStore);
        assert.equal(cand.store.getStore(config).kind, "postgres");
      } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
      const store = cand.store.getStore(config), api = F3.apiFor(config), model = K.chainModel(config);
      assert.deepEqual(result.twin, { sameTx: true, sameManifest: true }, "the RC42 writer produced a content-identical pair");
      const cc = result.cases.TWIN_DEF_CREATOR_BUILT, sc = result.cases.TWIN_SHARER_CV;
      assert.ok(cc && sc && cc.vaultId === sc.vaultId, "the RC42 writer wrote both twin cases on one vault");
      const creatorRaw = await store.read(Categories.REQUEST, cc.requestId), retry = await cand.wr4.loadRequest(config, sc.requestId);
      assert.equal(creatorRaw.state, "BUILT"); assert.equal(retry.state, "CHAIN_VERIFIED"); assert.equal(creatorRaw.txId, retry.txId);
      const creatorExports = async (label) => assertEveryPath(await exportsOf(config, api, await cand.wr4.loadRequest(config, cc.requestId), cc.vaultId), REFUSED_TERMINAL_LADDER, label);
      await creatorExports("before Verify");
      model.confirm(frozenOf(retry), retry.txId); model.advance(SETTLE_DEPTH_DAA);
      const done = await resolved(() => cand.reconcile4.reconcileVaultV4(config, cc.vaultId, { rpc: model.rpc }), "Verify at D answers");
      assert.equal(done.status, "ADVANCED", `Verify settles the vault by the executed retry (got ${JSON.stringify(done).slice(0, 300)})`);
      assert.deepEqual(await store.read(Categories.REQUEST, cc.requestId), creatorRaw, "the never-signed creator is byte-identical");
      await creatorExports("after the retry executed and Verify settled the vault");
      // A further hop: the RC42 owner (TEST key 0x01) tops up through the candidate; it completes uncontested at zero depth.
      const kaspa = require(config.rustyKaspaModule), priv = new kaspa.PrivateKey("01".repeat(32));
      const owner = { secretHex: "01".repeat(32), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
      const fuel = { outpoint: { transactionId: "d6".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${owner.xonly}ac` };
      // Built through the self-hosted build route, so the vault export can name its outputs (intent-manifest record).
      const routed = await api.call("POST", ["wallet", "v4", "requests"], { vaultId: cc.vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel }, signerAddress: owner.address });
      assert.equal(routed.status, 201, `the owner's top-up through the self-hosted build route (${routeSaid(routed)})`);
      const built = await cand.wr4.loadRequest(config, routed.body.request.requestId);
      const signedSafeJson = cand.signer.makeDevSigner(config, { secretHex: owner.secretHex, expectedAddress: owner.address }).signInputs(built.transaction.unsignedSafeJson, built.transaction.signInputs);
      const topUp = await cand.wr4.finalizeWalletRequestV4({ config, requestId: built.requestId, signedSafeJson });
      assert.equal(topUp.state, "PREFLIGHT_VERIFIED");
      const ft = frozenOf(topUp);
      ft.inputs.forEach((i, index) => { if (index > 0) model.add(i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, null, model.virtualDaaScore - 5000n); });
      model.know(topUp); model.confirmOnSubmit = true;
      let run;
      try { run = await settle(cand.submit4.submitWalletRequestV4({ config, requestId: topUp.requestId, rpc: model.rpc, pollAttempts: 1, pollDelayMs: 0 })); } finally { model.confirmOnSubmit = false; }
      assert.equal(run.error, null, `the owner's top-up completes (${said(run)})`);
      assert.equal(run.value.request.state, "CHAIN_VERIFIED");
      model.advance(SETTLE_DEPTH_DAA);
      await resolved(() => cand.reconcile4.reconcileVaultV4(config, cc.vaultId, { rpc: model.rpc }), "the Verify after the hop answers");
      assert.deepEqual(await store.read(Categories.REQUEST, cc.requestId), creatorRaw, "the never-signed creator is still byte-identical (never finished by the C2 predicate: BUILT, and the shared receipt names the retry)");
      await creatorExports("after a further hop and Verify at D");
      for (const [name, l] of Object.entries(await exportsOf(config, api, await cand.wr4.loadRequest(config, sc.requestId), sc.vaultId))) {
        assert.equal(l.decision, "AUTHORIZED", name); assert.equal(l.disposition, "SETTLED", name); assert.deepEqual(l.reached, [...FULL_LADDER], name); assert.equal(l.txId, retry.txId, name);
      }
    } finally {
      if (pgStore) { const i = stores.indexOf(pgStore); if (i >= 0) { stores.splice(i, 1); await pgStore.close(); } }
    }
  });
}
