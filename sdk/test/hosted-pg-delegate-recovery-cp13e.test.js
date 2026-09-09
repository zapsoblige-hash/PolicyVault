"use strict";
// Real PostgreSQL persistence and fresh pools; actual SDK/VM-built requests;
// chain observations are stubs. Only databases created by this file are torn down.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { fx, baseFixture, caseFor, assertComplete, boundaries } = require("../testutil/cp13e-delegate-fixture");
const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { reconcileVault } = require("../src/reconcile-v7");
const { wr7, Categories } = fx;
const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
const skip = !(PG.port && PG.user && PG.database) ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !fx.toolchainAvailable() ? "REQUIREMENT_NOT_AVAILABLE: real v7 compiler/VM" : undefined;
let admin, base, serial = 0;
const databases = [], stores = [];
before(async () => { if (!skip) { admin = new (require("pg").Pool)(PG); base = await baseFixture(); } });
after(async () => {
  for (const store of stores) await store.close();
  for (const db of databases) await admin.query(`DROP DATABASE ${db} WITH (FORCE)`);
  if (admin) await admin.end();
});
async function reopen(db, migrate = false) {
  const config = loadConfig({ ...fx.freshJsonConfig("pv-cp13e-pg-files-"), persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: db, pgNoTls: true, authMode: "enabled", authCookieInsecure: true });
  stores.push(await openPgStore(config, { migrate })); return config;
}
async function freshCase() {
  const db = `pv_cp13e_${process.pid}_${++serial}`; await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
  const config = await reopen(db, true), target = fx.getStore(config), source = fx.getStore(base.config);
  for (const category of [Categories.ORG_ROOT, Categories.ORG_ROOT_REQUEST, Categories.VAULT, Categories.REQUEST, Categories.RECEIPT, Categories.SUBMISSION_CLAIM, Categories.TRANSITION_CLAIM]) {
    for (const key of await source.listKeys(category)) await target.write(category, key, await source.read(category, key));
  }
  for (const entry of await source.readAudit({ limit: 1000 })) await target.appendAudit(entry);
  return Object.assign(caseFor(base, config), { db });
}
async function assertRows(x) {
  await assertComplete(x);
  const pool = fx.getStore(x.config).pool();
  const query = (sql) => pool.query(sql, [x.config.networkId, x.q.txId]);
  assert.equal((await query("SELECT key FROM receipts WHERE network_id=$1 AND key=$2")).rowCount, 1);
  assert.equal((await query("SELECT key FROM submission_claims WHERE network_id=$1 AND key=$2")).rowCount, 0);
  const audits = await query("SELECT value FROM audit_events WHERE network_id=$1 AND tx_id=$2");
  assert.equal(audits.rows.filter((r) => r.value.result === "CHAIN_VERIFIED").length, 1);
}
for (const [stage, [method, predicate]] of Object.entries(boundaries)) test(`CP13E live PG persistent ${stage}: fresh pools retain failure/guard then repair every record once`, { skip }, async () => {
  const x = await freshCase(); await x.timeout(); x.settle();
  for (let attempt = 0; attempt < 2; attempt++) {
    x.config = await reopen(x.db);
    const fault = fx.inject(x.config, method, (...args) => predicate(x, ...args), { times: Infinity, message: "PERSISTENT_PG_CP13E_" + stage });
    const r = await x.reconcile(); assert.equal(r.status, "UNKNOWN", JSON.stringify(r)); assert.ok(fault.count() > 0);
    const independent = await reopen(x.db);
    assert.equal((await wr7.loadV7WalletRequest(independent, x.q.requestId)).state, "RECONCILIATION_REQUIRED");
    const v = fx.manifestToJsonV7(await fx.loadManifestV7(independent, x.o.vaultId));
    assert.equal(v.live.tokenPosition.state.amount, v.generation === base.before.generation ? "100000" : "99950");
    await assert.rejects(wr7.buildV7WalletRequest({ config: independent, vaultId: x.o.vaultId, action: "tokenDeposit", signerAddress: fx.ADDR(independent, x.o.agentKey) }), (e) => e.code === "VAULT_PENDING_REQUEST");
    assert.deepEqual(await wr7.loadOrgRoot(independent, x.o.rootCovenantId), x.root);
    fault.restore();
  }
  x.config = await reopen(x.db); const other = await reopen(x.db);
  await Promise.all([x.submit(), reconcileVault(other, x.rpc, x.o.vaultId), wr7.submitV7WalletRequest({ config: other, requestId: x.q.requestId, rpc: x.rpc })]);
  x.config = await reopen(x.db); await assertRows(x);
});
test("CP13E live PG: missing-pointer legacy recovery and same-request history after actual ownerPause", { skip }, async () => {
  const x = await freshCase(); await x.timeout();
  const q = await x.request(); delete q.predecessorVault; await wr7.saveV7WalletRequest(x.config, q);
  // The pre-snapshot format also predates request-bound submission fingerprints.
  const submission = await fx.loadSubmissionClaim(x.config, q.txId);
  delete submission.expected;
  await fx.getStore(x.config).write(Categories.SUBMISSION_CLAIM, q.txId, submission);
  const claim = await require("../src/submission-claim").loadTransitionClaim(x.config, q.predecessorOutpoint);
  claim.expected = { kind: "v7Successor", txId: q.txId };
  await fx.getStore(x.config).write(Categories.TRANSITION_CLAIM, fx.transitionClaimKey(q.predecessorOutpoint), claim);
  x.config = await reopen(x.db); assert.equal((await x.reconcile()).status, "UNKNOWN"); x.settle();
  assert.equal((await x.reconcile()).status, "ADVANCED"); await assertRows(x);
  const second = await fx.signedRootAction(x.config, x.o, { vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, second);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: second.id, rpc: x.rpc });
  const vault = await x.vault(), root = await wr7.loadOrgRoot(x.config, x.o.rootCovenantId);
  const old = await x.request(); old.state = "RECONCILIATION_REQUIRED"; await wr7.saveV7WalletRequest(x.config, old);
  await fx.getStore(x.config).remove(Categories.RECEIPT, old.txId);
  x.config = await reopen(x.db); assert.equal((await x.reconcile()).status, "ADVANCED");
  assert.equal((await x.submit()).state, "CHAIN_VERIFIED");
  assert.deepEqual(await x.vault(), vault); assert.deepEqual(await wr7.loadOrgRoot(x.config, x.o.rootCovenantId), root);
  assert.equal((await fx.auditLinesFor(x.config, old.txId)).length, 1); assert.equal(x.rpc.submits(), 2);
});
test("CP13E live PG: same root/request keys in different databases stay isolated; failed first call releases the process queue", { skip }, async () => {
  const a = await freshCase(), b = await freshCase(); await a.timeout(); await b.timeout(); b.settle();
  await Promise.all([assert.rejects(a.submit()), b.submit(), b.reconcile()]);
  a.config = await reopen(a.db); b.config = await reopen(b.db);
  assert.equal((await a.request()).state, "RECONCILIATION_REQUIRED"); await assertRows(b);
  a.settle(); await a.submit(); await assertRows(a);
  for (const id of ["../alias", ".", "x/y", "x\\y"]) await assert.rejects(wr7.submitV7WalletRequest({ config: a.config, requestId: id, rpc: a.rpc }));
  assert.equal(a.rpc.submits(), 1);
});
test("CP13E live PG: independent finalizer pools cannot rewind completion; a saved SIGNED rewind repairs through fresh-pool reconcile", { skip }, async () => {
  const x = await freshCase(), other = await reopen(x.db), q = await x.request();
  q.state = "BUILT"; await wr7.saveV7WalletRequest(x.config, q);
  const signedSafeJson = fx.signAll(x.config, q.transaction.unsignedSafeJson, [[0, x.o.agentKey], [q.build.frozen.inputs.length - 1, x.o.fuelKey]]);
  const results = await Promise.allSettled([wr7.finalizeV7WalletRequest({ config: x.config, requestId: q.requestId, signedSafeJson }), wr7.finalizeV7WalletRequest({ config: other, requestId: q.requestId, signedSafeJson })]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(results.find((r) => r.status === "rejected").reason.code, "SIGNED");
  const oldSigned = await x.request(); x.settle(); await x.submit(); await assertRows(x);
  await wr7.saveV7WalletRequest(other, oldSigned);
  x.config = await reopen(x.db); assert.equal((await x.reconcile()).status, "ADVANCED"); await assertRows(x);
  const next = await fx.signedRootAction(x.config, x.o, { vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause" }] });
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, next);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: next.id, rpc: x.rpc });
  const current = await x.vault(); await wr7.saveV7WalletRequest(other, oldSigned);
  x.config = await reopen(x.db); assert.equal((await x.reconcile()).status, "ADVANCED");
  assert.equal((await x.request()).state, "CHAIN_VERIFIED"); assert.deepEqual(await x.vault(), current);
  assert.equal((await fx.auditLinesFor(x.config, q.txId)).length, 1); assert.equal(x.rpc.submits(), 2);
});
