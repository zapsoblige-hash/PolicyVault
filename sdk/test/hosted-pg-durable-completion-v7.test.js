"use strict";

/*
 * HOSTED PG / CRASH-RECOVERY (real builds; mocked chain readback; the REAL
 * PostgreSQL driver with deterministic fault injection on ONE store
 * instance, then a FRESH store over the same database for the retry):
 * Codex checkpoint 12 (R7-02) — "the production JSON and PostgreSQL
 * abstractions persist these records separately; the inspected PG tests do
 * not exercise this new fault-recovery matrix; the generic PG pass does not
 * close it."
 *
 * Covered here on live PostgreSQL: a failure AFTER root advancement (the
 * root predecessor claim release), a finalization write failure (the final
 * CHAIN_VERIFIED request write) and a receipt write failure — each followed
 * by a fresh read through a NEW pool/store and a public retry (submit or
 * reconcile). Injected failures are confined to the test's own database;
 * the chain is a mocked observation (never chain evidence).
 *
 * SKIPPED cleanly without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the gate
 * every hosted-pg-*.test.js uses); REQUIREMENT_NOT_AVAILABLE without the
 * real toolchain. Each test gets its own database (created + dropped here).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const fx = require("../testutil/org-root-durable-fixture");
const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { wr7, Categories } = fx;

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const TOOLCHAIN_AVAILABLE = fx.toolchainAvailable();
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL integration" : !TOOLCHAIN_AVAILABLE ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" : undefined;

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

function pgConfigFor(dbName) {
  return loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-pg-durable-")) });
}
async function freshPgConfig() {
  const dbName = `pv_durable12_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = pgConfigFor(dbName);
  openStores.push(await openPgStore(config, { migrate: true }));
  return { config, dbName };
}
/* a FRESH store (new pool, new config object) over the SAME database — "after reload" for the hosted backend */
async function reopen(dbName) {
  const config = pgConfigFor(dbName);
  openStores.push(await openPgStore(config));
  return config;
}
const sql = (cfg, text, params) => fx.getStore(cfg).pool().query(text, params);

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
});
after(async () => {
  if (!PG_AVAILABLE) return;
  for (const store of openStores) { try { await store.close(); } catch { /* already closed */ } }
  for (const db of createdDbs) { try { await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } catch { /* best effort */ } }
  await adminPool.end();
});

async function settledOrganization(config, seed) {
  const rpc = fx.mockRpc();
  const o = await fx.organization(config, rpc, { seed });
  const fin = await fx.signedSetAgentRoot(config, o);
  const pred = await fx.spendPredecessors(config, rpc, o);
  fx.settle(config, rpc, fin);
  const genesisBroadcasts = rpc.submits(); // the two genesis broadcasts went through this same mock node
  return { rpc, o, fin, pred, genesisBroadcasts };
}
async function assertPgRecordsComplete(cfg, o, fin, pred, label) {
  await fx.assertFullyCompleted(cfg, o, fin, label, { predecessors: pred });
  const claims = await sql(cfg, "SELECT key FROM transition_claims WHERE network_id = $1", [cfg.networkId]);
  assert.ok(!claims.rows.some((r) => r.key === fx.transitionClaimKey(pred.rootOutpoint)), `${label}: the root predecessor claim row is gone`);
  const sub = await sql(cfg, "SELECT 1 FROM submission_claims WHERE network_id = $1 AND key = $2", [cfg.networkId, fin.txId]);
  assert.equal(sub.rowCount, 0, `${label}: the submission claim row is gone`);
  const receipt = await sql(cfg, "SELECT 1 FROM receipts WHERE network_id = $1 AND key = $2", [cfg.networkId, fin.txId]);
  assert.equal(receipt.rowCount, 1, `${label}: exactly one receipt row`);
  const audit = await sql(cfg, "SELECT value FROM audit_events WHERE network_id = $1 AND tx_id = $2", [cfg.networkId, fin.txId]);
  assert.equal(audit.rows.filter((r) => r.value.result === "CHAIN_VERIFIED").length, 1, `${label}: exactly one CHAIN_VERIFIED audit row (jsonb)`);
  const root = await sql(cfg, "SELECT value FROM org_roots WHERE network_id = $1 AND key = $2", [cfg.networkId, o.rootCovenantId]);
  assert.equal(root.rows[0].value.pendingRequestId, null, `${label}: pointer cleared in the jsonb row`);
}

test("PG durable recovery: a failure AFTER root advancement (root predecessor claim release) → RECONCILIATION_REQUIRED + guard held in the database; a FRESH store discovers it through public reconcile and completes everything exactly once", { skip }, async () => {
  const { config, dbName } = await freshPgConfig();
  const { rpc, o, fin, pred, genesisBroadcasts } = await settledOrganization(config, 0x70);
  const inj = fx.inject(config, "remove", (cat, key) => cat === Categories.TRANSITION_CLAIM && key === fx.transitionClaimKey(pred.rootOutpoint), { message: "injected pg remove failure (transition_claims)" });
  await assert.rejects(() => wr7.submitOrgRootRequest({ config, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(inj.count(), 1); inj.restore();
  const fresh = await reopen(dbName);
  const req = await wr7.loadOrgRootRequest(fresh, fin.id);
  assert.equal(req.state, "RECONCILIATION_REQUIRED", req.error);
  const root = await wr7.loadOrgRoot(fresh, o.rootCovenantId);
  assert.equal(root.live.outpoint.transactionId, fin.txId, "root advanced before the failure (jsonb round trip)");
  assert.equal(root.pendingRequestId, fin.id, "guard held in the database");
  assert.equal((await wr7.verifyRootActionCompletion(fresh, req)).complete, false);
  await assert.rejects(() => wr7.buildRootActionRequest({ config: fresh, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(fresh, o.fuelKey) }, signerAddress: fx.ADDR(fresh, o.owner1) }), (e) => e.code === "ROOT_PENDING_REQUEST");
  const r = await reconcileOrgRootV7(fresh, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
  assert.ok(r.root.completion.some((c) => c.replayed && c.requestId === fin.id));
  await assertPgRecordsComplete(await reopen(dbName), o, fin, pred, "after public reconcile");
  assert.equal((await wr7.submitOrgRootRequest({ config: await reopen(dbName), requestId: fin.id, rpc })).state, "CHAIN_VERIFIED", "retried submit is idempotent");
  assert.equal(rpc.submits(), genesisBroadcasts + 1, "exactly one broadcast of the action; never rebroadcast");
});

test("PG durable recovery: the FINAL request write (CHAIN_VERIFIED) fails after every other record → a fresh read shows RECONCILIATION_REQUIRED beside complete vault/root/claims; public retry via submit finishes it without duplicating receipt or audit", { skip }, async () => {
  const { config, dbName } = await freshPgConfig();
  const { rpc, o, fin, pred, genesisBroadcasts } = await settledOrganization(config, 0x80);
  const inj = fx.inject(config, "write", (cat, key, value) => cat === Categories.ORG_ROOT_REQUEST && key === fin.id && value.state === "CHAIN_VERIFIED", { message: "injected pg write failure (org_root_requests)" });
  await assert.rejects(() => wr7.submitOrgRootRequest({ config, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(inj.count(), 1); inj.restore();
  const fresh = await reopen(dbName);
  const req = await wr7.loadOrgRootRequest(fresh, fin.id);
  assert.equal(req.state, "RECONCILIATION_REQUIRED");
  assert.equal((await sql(fresh, "SELECT 1 FROM receipts WHERE network_id = $1 AND key = $2", [fresh.networkId, fin.txId])).rowCount, 1, "the receipt row was written before the failing step");
  assert.equal((await wr7.loadOrgRoot(fresh, o.rootCovenantId)).pendingRequestId, fin.id, "guard held");
  const v = await wr7.verifyRootActionCompletion(fresh, req);
  assert.deepEqual(v.missing, [`root pending pointer still names this request`, `request state RECONCILIATION_REQUIRED`], `only the request + pointer remain: ${v.missing.join("; ")}`);
  const s = await wr7.submitOrgRootRequest({ config: fresh, requestId: fin.id, rpc });
  assert.equal(s.state, "CHAIN_VERIFIED");
  assert.equal(s.chain.completion.receipt, "ALREADY_PRESENT");
  assert.equal(s.chain.completion.audit, "ALREADY_PRESENT");
  await assertPgRecordsComplete(await reopen(dbName), o, fin, pred, "after public submit");
  assert.equal((await reconcileOrgRootV7(await reopen(dbName), o.rootCovenantId, { rpc })).root.status, "CONSISTENT");
  assert.equal(rpc.submits(), genesisBroadcasts + 1, "exactly one broadcast of the action; never rebroadcast");
});

test("PG durable recovery: a claim/finalization write failure at the RECEIPT → fresh read, guard held, then public reconcile completes; a second reconcile is CONSISTENT with no new rows", { skip }, async () => {
  const { config, dbName } = await freshPgConfig();
  const { rpc, o, fin, pred, genesisBroadcasts } = await settledOrganization(config, 0x90);
  const inj = fx.inject(config, "write", (cat, key) => cat === Categories.RECEIPT && key === fin.txId, { message: "injected pg write failure (receipts)" });
  await assert.rejects(() => wr7.submitOrgRootRequest({ config, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(inj.count(), 1); inj.restore();
  const fresh = await reopen(dbName);
  assert.equal((await wr7.loadOrgRootRequest(fresh, fin.id)).state, "RECONCILIATION_REQUIRED");
  assert.equal((await wr7.loadOrgRoot(fresh, o.rootCovenantId)).pendingRequestId, fin.id, "guard held");
  const r = await reconcileOrgRootV7(fresh, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
  const done = await reopen(dbName);
  await assertPgRecordsComplete(done, o, fin, pred, "after public reconcile");
  const rows = async () => (await sql(done, "SELECT (SELECT count(*) FROM receipts) AS r, (SELECT count(*) FROM audit_events) AS a, (SELECT count(*) FROM transition_claims) AS c", [])).rows[0];
  const before = await rows();
  assert.equal((await reconcileOrgRootV7(done, o.rootCovenantId, { rpc })).root.status, "CONSISTENT");
  assert.deepEqual(await rows(), before, "a repeated reconcile writes no new rows");
  assert.equal(rpc.submits(), genesisBroadcasts + 1, "exactly one broadcast of the action; never rebroadcast");
});


test("PG CP13: overlapping public recovery, rejection cleanup, and historical receipt repair across independent pools", { skip }, async () => {
  const { config, dbName } = await freshPgConfig();
  const { rpc, o, fin, pred, genesisBroadcasts } = await settledOrganization(config, 0xa0);
  const failReceipt = fx.inject(config, "write", (cat, key) => cat === Categories.RECEIPT && key === fin.txId);
  await assert.rejects(wr7.submitOrgRootRequest({ config, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  failReceipt.restore();
  const other = await reopen(dbName);
  await Promise.all([
    wr7.submitOrgRootRequest({ config, requestId: fin.id, rpc }),
    wr7.submitOrgRootRequest({ config: other, requestId: fin.id, rpc }),
    reconcileOrgRootV7(other, o.rootCovenantId, { rpc })
  ]);
  await assertPgRecordsComplete(other, o, fin, pred, "overlapping recovery");
  assert.equal(rpc.submits(), genesisBroadcasts + 1);
  const second = await fx.signedRootAction(config, o, { vaultOperations: [{ vaultId: o.vaultId, action: "ownerPause", params: {} }] });
  await fx.spendPredecessors(config, rpc, o); fx.settle(config, rpc, second);
  await wr7.submitOrgRootRequest({ config, requestId: second.id, rpc });
  const latest = fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId));
  for (const mode of ["correct", "absent", "foreign"]) {
    const receipt = await fx.loadReceipt(config, fin.txId);
    if (mode === "absent") await fx.getStore(config).remove(Categories.RECEIPT, fin.txId);
    if (mode === "foreign") await fx.getStore(config).write(Categories.RECEIPT, fin.txId, { ...receipt, vaultId: fx.H(0xb1) });
    const fresh = await reopen(dbName);
    await Promise.all([
      wr7.submitOrgRootRequest({ config: fresh, requestId: fin.id, rpc }),
      reconcileOrgRootV7(other, o.rootCovenantId, { rpc })
    ]);
    assert.equal((await wr7.loadOrgRootRequest(fresh, fin.id)).state, "CHAIN_VERIFIED", mode);
    assert.equal((await fx.loadReceipt(fresh, fin.txId)).vaultId, o.rootCovenantId, mode);
    assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(fresh, o.vaultId)), latest, mode);
    const audits = await sql(fresh, "SELECT value FROM audit_events WHERE network_id = $1 AND tx_id = $2", [fresh.networkId, fin.txId]);
    assert.equal(audits.rows.filter((r) => r.value.result === "CHAIN_VERIFIED").length, 1, mode);
  }
  assert.equal((await wr7.loadOrgRoot(other, o.rootCovenantId)).generation, 2);
  assert.equal(latest.generation, 2);
  assert.equal(rpc.submits(), genesisBroadcasts + 2, "one broadcast per new action, none for recovery");
});
