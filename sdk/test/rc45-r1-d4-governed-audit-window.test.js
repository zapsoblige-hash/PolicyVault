"use strict";
/*
 * RC45 R1 D4 — THE GOVERNED MANIFEST-TO-AUDIT CRASH WINDOW IS A RECORDED
 * RESIDUAL (writer disposition D4 of DELTA-DISPOSITIONS-01; design amendment
 * PA-R1-02 "D2-D4", independent design check condition C7). Internal
 * regression material for the RC45 successor candidate; not an audit.
 *
 * The window (R1-03): a governance-refused, never-signed primary CONFIRMED at
 * depth D gets no receipt; completePositive advances the manifest by its txid
 * (advanceManifestAndRegistryV4: one VAULT write, then only reads), and the
 * next durable step is the governed history row reconciled_advanced {via:
 * "governance-refused-request-txid"}. A crash between the two loses that row.
 * Disposition: a recorded residual (LOW, audit-only), the same write order as
 * the pre-existing adoption path. What stays correct, and what each leg pins
 * after the crash: the manifest is advanced by the txid (lastTransition:
 * action, txid, outpoints); the request record is byte-identical (BUILT); no
 * receipt is at its txid and none names it; every export path answers
 * REFUSED_TERMINAL_LADDER. A second Verify (L is the recorded successor, live
 * at depth D; settleOneHop sees the BUILT row as W1 and has nothing to do)
 * writes nothing and answers CONSISTENT; the lost row is not written by any
 * later pass (the alternative "write the idempotent row on re-entry" is not
 * proposed now; the delta review may require it).
 *
 * C7: the population has NO PENDING loser on L (TWIN_PU_DEF_CREATOR_BUILT is
 * alone on its vault). With a loser on L the non-terminal order (manifest,
 * governed row, losers) would leave the loser unsettled and the second Verify
 * would supersede it through settleOneHop (a write, named in settled[]); that
 * case is not covered here. Injection, both as C7 allows: an in-process store
 * fault at the first durable step after the manifest write (afterManifest),
 * and a real SIGKILL of a fresh Verify child before its second durable step
 * (sdk/testutil/rc45-f5-kit.js verifyInChild killBefore: 1).
 *
 * HOLDS on ecb9928 (and must keep holding).
 *
 * Population: the EXISTING RC42 ladder writer (sdk/testutil/rc45-f8-rc42.js,
 * a84e2a9 modules only, unchanged), run ONCE per store backend; every test
 * works on its own copy (JSON: a copy of the data root; PostgreSQL: CREATE
 * DATABASE ... TEMPLATE plus a copy of the data root). Case used:
 * TWIN_PU_DEF_CREATOR_BUILT (governed ownerUnpause, BUILT, proposal CANCELLED,
 * alone on its PAUSED vault). The owner (TEST key 0x01) signs its unsigned
 * transaction outside PolicyVault; it lands on the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js and deepens to D. Nothing dials a node: every
 * config names ws://127.0.0.1:1. POLICYVAULT_TEST_RC42_TREE must name the
 * a84e2a9 extraction (a missing tree is a FAIL in before(), never a skip).
 *
 * Layers: SDK + CRASH-RECOVERY + API (the export reads through the
 * self-hosted server/src/api.js handle). Both stores: JSON always; PostgreSQL
 * with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const R42 = require("../testutil/rc45-f8-rc42");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const RC42_TREE = process.env.POLICYVAULT_TEST_RC42_TREE || "";
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const GOVERNED_VIA = "governance-refused-request-txid";
const REFUSED_TERMINAL_LADDER = Object.freeze({ decision: "REFUSED", refusalCode: "GOVERNANCE_PROPOSAL_TERMINAL", failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "REFUSED", disposition: "REFUSED", reached: [] });
const SNAP_CATEGORIES = [Categories.VAULT, Categories.REQUEST, Categories.TRANSITION_CLAIM, Categories.SUBMISSION_CLAIM, Categories.RECEIPT,
  Categories.INTENT_MANIFEST, Categories.GOVERNANCE_PROPOSAL, Categories.GOVERNANCE_APPROVAL];

const roots = [], stores = [], databases = [];
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
let admin = null, overlay = null, serial = 0;
const bases = {};
const settle = (promise) => promise.then((value) => ({ value, error: null }), (error) => ({ value: null, error }));
const said = (o) => (o.error ? `${o.error.code ?? "no code"}: ${String(o.error.message).slice(0, 240)}` : JSON.stringify(o.value).slice(0, 300));

before(() => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  R42.verifyRc42Tree(RC42_TREE);
  overlay = R42.rc42Overlay(RC42_TREE, mk("pv-rc45-r1d4-rc42-overlay-"));
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of [...databases].reverse()) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* The RC42 writer's population, written ONCE per backend (lazily), then copied per test. */
function baseFor(backend) {
  if (!bases[backend]) {
    bases[backend] = (async () => {
      const dataRoot = mk("pv-rc45-r1d4-base-");
      let pg = null;
      if (backend === "PostgreSQL") {
        const database = `pv_rc45_r1d4_base_${process.pid}`;
        await admin.query(`CREATE DATABASE ${database}`); databases.push(database);
        pg = { host: PG.host, port: PG.port, user: PG.user, database };
      }
      const result = R42.runRc42LadderWriter({ overlay, backend: pg ? "postgres" : "json", dataRoot, pg });
      return { dataRoot, database: pg ? pg.database : null, result };
    })();
  }
  return bases[backend];
}
async function cloneDatabase(from, to) {
  for (let attempt = 0; ; attempt++) {
    try { await admin.query(`CREATE DATABASE ${to} TEMPLATE ${from}`); return; } catch (error) {
      if (attempt >= 40 || !/being accessed by other users/.test(String(error && error.message))) throw error;
      await K.sleep(250);
    }
  }
}
/* A fresh self-hosted copy of the RC42 population. */
async function fresh(backend) {
  const base = await baseFor(backend);
  const dataRoot = mk("pv-rc45-r1d4-case-");
  fs.cpSync(base.dataRoot, dataRoot, { recursive: true });
  let config, pgDatabase = null, pgStore = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1d4_${process.pid}_${++serial}`;
    await cloneDatabase(base.database, pgDatabase); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    pgStore = await cand.store.openPgStore(config); stores.push(pgStore);
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  assert.equal(config.tenancyEnforced, false, "self-hosted case");
  const store = cand.store.getStore(config), api = F3.apiFor(config);
  const x = {
    config, store, api, pgStore, pgDatabase, result: base.result, model: K.chainModel(config),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    raw: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (vaultId) => store.read(Categories.VAULT, vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    receiptsNaming: async (requestId) => (await store.listValues(Categories.RECEIPT)).filter((r) => r && r.proof && r.proof.requestId === requestId),
    audit: async (vaultId) => (await store.readAudit({ limit: 5000 })).filter((a) => a.vaultId === vaultId),
    verify: (vaultId) => cand.reconcile4.reconcileVaultV4(config, vaultId, { rpc: x.model.rpc })
  };
  /* Every durable category the pass, the routes or the governance gate could write, and the audit. */
  x.snap = async () => {
    const records = {};
    for (const c of SNAP_CATEGORIES) records[c] = await Promise.all((await store.listKeys(c)).sort().map(async (k) => [k, await store.read(c, k)]));
    return { records, audit: await store.readAudit({ limit: 5000 }) };
  };
  return x;
}
async function release(x) {
  if (!x.pgStore) return;
  const i = stores.indexOf(x.pgStore);
  if (i >= 0) { stores.splice(i, 1); await x.pgStore.close(); }
}

/* The attestation ladder, exactly as sdk/test/governance-attestation-ladder.test.js reads it. */
function ladderOf(attestation) {
  const o = attestation.outcome;
  return { decision: attestation.authorization.decision, refusalCode: attestation.authorization.refusalCode, failureCode: o.failureCode, txId: o.txId,
    outputs: o.chain.outputs.length, successorOutpoint: o.chain.successorOutpoint, state: o.state, disposition: o.disposition, reached: o.reached.map((r) => r.state) };
}
const ndjsonRecords = (raw) => String(raw).split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
/* Every export path: the store path, GET /attestations/requests/:id (json, ndjson), GET /attestations/export?vaultId (json, ndjson). */
async function exportsOf(x, request, vaultId) {
  const { buildAttestationForRequest } = require("../../server/src/attestations");
  const { handle } = require("../../server/src/api");
  const out = { store: ladderOf((await buildAttestationForRequest(x.config, request)).attestation) };
  const one = await x.api.call("GET", ["attestations", "requests", request.requestId]);
  assert.equal(one.status, 200, `request route (${one.code} ${one.message})`);
  out.route = ladderOf(one.body.attestation);
  const ndOne = ndjsonRecords((await handle(x.config, "GET", ["attestations", "requests", request.requestId], { format: "ndjson" }, null, {})).rawBody);
  assert.equal(ndOne.length, 1);
  out.routeNdjson = ladderOf(ndOne[0]);
  const batch = await x.api.call("GET", ["attestations", "export"], null, null, { vaultId });
  assert.equal(batch.status, 200, `vault export (${batch.code} ${batch.message})`);
  const rec = batch.body.records.find((r) => r.attestation.subject.requestId === request.requestId);
  assert.ok(rec, "the vault export lists the request");
  out.export = ladderOf(rec.attestation);
  const ndRec = ndjsonRecords((await handle(x.config, "GET", ["attestations", "export"], { vaultId, format: "ndjson" }, null, {})).rawBody).find((a) => a.subject.requestId === request.requestId);
  assert.ok(ndRec, "the ndjson vault export lists the request");
  out.exportNdjson = ladderOf(ndRec);
  return out;
}
function assertEveryPath(paths, expected, label) {
  for (const [name, ladder] of Object.entries(paths)) assert.deepEqual(ladder, expected, `${label}: ${name}`);
}
const covenantIndex = (request) => frozenOf(request).outputs.findIndex((o) => o.covenant !== null && o.covenant !== undefined);

/* The governed unsigned primary (TWIN_PU_DEF_CREATOR_BUILT), alone on its PAUSED vault, refused by the candidate's governance truth. */
async function governedRow(x) {
  const c = x.result.cases.TWIN_PU_DEF_CREATOR_BUILT;
  assert.ok(c, "the RC42 writer wrote TWIN_PU_DEF_CREATOR_BUILT");
  const row = await x.req(c.requestId);
  assert.equal(row.state, "BUILT"); assert.equal(row.finalTransaction, undefined, "never signed through PolicyVault");
  const ir = require("../../server/src/intent-records");
  assert.equal((await ir.governanceRefusalFor(x.config, row, await ir.loadManifestRecord(x.config, row.manifestHash)))?.code, "GOVERNANCE_PROPOSAL_TERMINAL", "the candidate's governance truth refuses the row");
  assert.deepEqual((await cand.wr4.listVaultRequests(x.config, c.vaultId)).map((r) => r.requestId), [row.requestId], "the governed row is alone on its vault (no PENDING loser on L; C7)");
  const m0 = await x.rawManifest(c.vaultId);
  assert.equal(m0.status, "PAUSED"); assert.deepEqual(m0.live.outpoint, row.predecessorOutpoint);
  return { c, row, index: covenantIndex(row), rawBefore: await x.raw(row.requestId) };
}
/* The manifest advanced by the governed row's txid exactly as a completion advances it (lastTransition: action, txid, outpoints). */
function assertAdvancedBy(m, row, index) {
  assert.equal(m.status, "ACTIVE", "the governed ownerUnpause unpaused the vault");
  assert.deepEqual(m.live.outpoint, { transactionId: row.txId, index });
  assert.equal(m.live.stateId, row.successorStateId);
  assert.equal(m.latestTransitionTxId, row.txId);
  assert.deepEqual({ action: m.lastTransition.action, txId: m.lastTransition.txId, oldStateId: m.lastTransition.oldStateId, newStateId: m.lastTransition.newStateId,
    oldOutpoint: { transactionId: m.lastTransition.oldOutpoint.transactionId, index: Number(m.lastTransition.oldOutpoint.index) }, newOutpoint: m.lastTransition.newOutpoint },
  { action: row.action, txId: row.txId, oldStateId: row.predecessorStateId, newStateId: row.successorStateId,
    oldOutpoint: { transactionId: row.predecessorOutpoint.transactionId, index: Number(row.predecessorOutpoint.index) }, newOutpoint: { transactionId: row.txId, index } });
}
/* What stays correct after the window, and the residual itself (the governed history row is lost). */
async function assertAfterWindow(x, g, label) {
  const { c, row, index, rawBefore } = g;
  assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
  assert.deepEqual(await x.raw(row.requestId), rawBefore, `${label}: the governed row is byte-identical (BUILT, never relabelled)`);
  assert.equal(await x.receipt(row.txId), null, `${label}: no receipt at its txid`);
  assert.deepEqual(await x.receiptsNaming(row.requestId), [], `${label}: no receipt names it`);
  const rows = (await x.audit(c.vaultId)).filter((a) => a.txId === row.txId && a.action === "reconciled_advanced");
  assert.deepEqual(rows, [], `${label}: the governed history row reconciled_advanced {via: "${GOVERNED_VIA}"} is lost in the window (the D4 residual), and no completion row exists`);
  assertEveryPath(await exportsOf(x, await x.req(row.requestId), c.vaultId), REFUSED_TERMINAL_LADDER, `${label}: the export`);
}
/* A second Verify writes nothing and answers CONSISTENT; a third still writes nothing (the lost row is not re-written). */
async function assertSecondVerifyQuiet(x, g, label) {
  const { c } = g;
  const before = await x.snap();
  const again = await settle(x.verify(c.vaultId));
  assert.equal(again.error, null, `${label}: the second Verify answers (${said(again)})`);
  assert.equal(again.value.status, "CONSISTENT", `${label}: the second Verify (got ${said(again)})`);
  assert.deepEqual(again.value.settled, [], `${label}: it settles nothing`);
  assert.deepEqual(await x.snap(), before, `${label}: the second Verify writes nothing`);
  await settle(x.verify(c.vaultId));
  assert.deepEqual(await x.snap(), before, `${label}: a third Verify writes nothing either (the lost row is not written on re-entry)`);
  await assertAfterWindow(x, g, `${label}, after the second and third Verify`);
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const d4 = (name, fn) => test(`RC45 R1 D4 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  d4("in-process store fault right after the governed manifest advance (holds): the governance-refused, never-signed RC42 row (alone on its vault) is CONFIRMED at D; the first durable step after the manifest write is the governed history row, and the fault stops the pass there; the manifest is advanced by the txid, the row is byte-identical (BUILT), no receipt names it, every export path is REFUSED_TERMINAL_LADDER and the governed row is lost; a second Verify writes nothing and answers CONSISTENT", async (x) => {
    const g = await governedRow(x);
    x.model.confirm(frozenOf(g.row), g.row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const performed = [];
    let faulted = null;
    const s = x.store, names = ["write", "createExclusive", "remove", "appendAudit"], own = {};
    for (const name of names) {
      own[name] = Object.prototype.hasOwnProperty.call(s, name) ? s[name] : undefined;
      const original = s[name].bind(s);
      s[name] = async (...args) => {
        if (faulted === null && performed.some(([n, cat, key]) => n === "write" && cat === Categories.VAULT && key === g.c.vaultId)) {
          faulted = { name, args };
          throw Object.assign(new Error(`TEST store fault at ${name}`), { code: "ECONNRESET" });
        }
        const out = await original(...args);
        performed.push([name, args[0], args[1]]);
        return out;
      };
    }
    let run;
    try { run = await settle(x.verify(g.c.vaultId)); } finally { for (const name of names) { if (own[name] === undefined) delete s[name]; else s[name] = own[name]; } }
    assert.ok(run.error && /TEST store fault/.test(String(run.error.message)), `the fault stopped the pass (${said(run)})`);
    assert.deepEqual(performed.map(([n, cat]) => `${n} ${cat}`), [`write ${Categories.VAULT}`], "the manifest advance is the only durable step before the fault (no receipt for a governance-refused unsigned primary)");
    assert.equal(faulted.name, "appendAudit", "the next durable step after the manifest write is an audit append");
    assert.equal(faulted.args[0]?.action, "reconciled_advanced"); assert.equal(faulted.args[0]?.via, GOVERNED_VIA, "it is the governed history row");
    assert.equal(faulted.args[0]?.txId, g.row.txId);
    await assertAfterWindow(x, g, "after the in-process fault");
    await assertSecondVerifyQuiet(x, g, "after the in-process fault");
  });

  d4("SIGKILL of a fresh Verify child before its second durable step (holds): the governance-refused, never-signed RC42 row (alone on its vault) is CONFIRMED at D; the child is killed right after the governed manifest advance; the manifest is advanced by the txid, the row is byte-identical (BUILT), no receipt names it, every export path is REFUSED_TERMINAL_LADDER and the governed row is lost; a second Verify writes nothing and answers CONSISTENT", async (x) => {
    const g = await governedRow(x);
    x.model.confirm(frozenOf(g.row), g.row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    const run = K.verifyInChild(x, { vaultId: g.c.vaultId }, { killBefore: 1, pg: PG });
    assert.equal(run.signal, "SIGKILL", `the child was killed before its second durable step (child answered ${JSON.stringify(run.result)}; ${run.stderr})`);
    const atKill = await x.snap();
    const changed = Object.keys(atKill.records).filter((cat) => JSON.stringify(atKill.records[cat]) !== JSON.stringify(before.records[cat]));
    assert.deepEqual(changed, [Categories.VAULT], "exactly one durable step happened: the manifest advance");
    assert.deepEqual(atKill.audit, before.audit, "no audit row was written before the kill");
    await assertAfterWindow(x, g, "after the SIGKILL");
    await assertSecondVerifyQuiet(x, g, "after the SIGKILL");
  });
}
