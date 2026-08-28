"use strict";

/*
 * POSTGRESQL INTEGRATION + JSON<->PG EQUIVALENCE (Phase C).
 *
 * Runs against a REAL local PostgreSQL (directive §7) — SKIPPED cleanly
 * when POLICYVAULT_TEST_PG_* is not set (so the suite stays green on
 * machines without a database, while the checkpoint gate runs it against
 * the live instance). Proves: migrations, per-category CRUD, the UNIQUE
 * claim arbiter, network-composite isolation, transaction rollback,
 * restart durability, and that the JSON and PG backends produce
 * EQUIVALENT observable durable behavior for the same operations.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { getStore, openPgStore, Categories } = require("../src/store");
const { runMigrations, assertSchemaCurrent } = require("../../server/src/migrate");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL integration";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = []; // every store opened, closed in after()

/* Each test gets its own fresh migrated database (real isolation). */
async function freshPgConfig(networkId = "testnet-10") {
  const dbName = `pv_it_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const overrides = {
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: dbName,
    pgNoTls: true,
    authMode: "enabled",
    authCookieInsecure: true,
    networkId,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-it-json-")),
    ...(networkId === "mainnet" ? { allowMainnet: true, appOrigin: "https://app.policy-vault.org", authCookieInsecure: false, rpcUrl: "ws://127.0.0.1:18110" } : {})
  };
  const config = loadConfig(overrides);
  const store = await openPgStore(config, { migrate: true });
  openStores.push(store);
  return { config, store, dbName };
}

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
});

after(async () => {
  if (!PG_AVAILABLE) return;
  for (const store of openStores) { try { await store.close(); } catch { /* already closed */ } }
  for (const db of createdDbs) {
    try { await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } catch { /* best effort */ }
  }
  await adminPool.end();
});

test("§C migrations: fresh DB migrates, re-run is a no-op, schema asserts current", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const r1 = await runMigrations(pool); // already migrated in openPgStore
  assert.ok(r1.applied >= 1);
  await assertSchemaCurrent(pool); // no throw
  const rows = await pool.query("SELECT version FROM schema_migrations ORDER BY version");
  assert.ok(rows.rowCount >= 1);
});

test("§C migrations: a database at a FUTURE schema version fails closed", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  await pool.query("INSERT INTO schema_migrations (version, name, checksum) VALUES (999, '999_future.sql', 'x')");
  await assert.rejects(() => assertSchemaCurrent(pool), /newer than this build/);
});

test("§C CRUD: every category round-trips through the PG store", { skip }, async () => {
  const { store } = await freshPgConfig();
  for (const [cat, key] of [
    [Categories.VAULT, "aa".repeat(32)],
    [Categories.REQUEST, "req-1"],
    [Categories.RECEIPT, "tx-1"],
    [Categories.ORG, "org-1"],
    [Categories.ORG_ASSIGNMENTS, "assignments"]
  ]) {
    await store.write(cat, key, { hello: key, n: 5n });
    const got = await store.read(cat, key);
    assert.equal(got.hello, key);
    assert.equal(got.n, "5"); // BigInt serialized as string, exactly like durable-json
  }
  await store.appendAudit({ vaultId: "aa".repeat(32), type: "T", at: new Date().toISOString() });
  assert.equal((await store.readAudit({ vaultId: "aa".repeat(32) })).length, 1);
});

test("§C constraint: the transition-claim UNIQUE key is the race arbiter (createExclusive)", { skip }, async () => {
  const { store } = await freshPgConfig();
  const first = await store.createExclusive(Categories.TRANSITION_CLAIM, "pred-0", { txId: "t1" });
  const second = await store.createExclusive(Categories.TRANSITION_CLAIM, "pred-0", { txId: "t2" });
  assert.equal(first, true);
  assert.equal(second, false);
  assert.equal((await store.read(Categories.TRANSITION_CLAIM, "pred-0")).txId, "t1");
});

test("§C network isolation: same key under two networks is two distinct rows (composite PK, directive §11)", { skip }, async () => {
  // The (network_id, key) composite primary key keeps same-id objects on
  // different networks apart. The testnet-configured store reads ONLY its
  // own network's row even when a mainnet row shares the key. (The
  // process-level mainnet network-stamp refusal is proven separately in
  // the store smoke; here we prove ROW isolation.)
  const { store } = await freshPgConfig();
  await store.write(Categories.VAULT, "shared-id", { net: "testnet-10" });
  await store.pool().query(`INSERT INTO vaults (network_id, key, value) VALUES ('mainnet', 'shared-id', '{"net":"mainnet"}'::jsonb)`);
  assert.equal((await store.read(Categories.VAULT, "shared-id")).net, "testnet-10");
  // Both rows coexist; the testnet store never lists or reads the mainnet one.
  const two = await store.pool().query(`SELECT network_id FROM vaults WHERE key = 'shared-id' ORDER BY network_id`);
  assert.deepEqual(two.rows.map((r) => r.network_id), ["mainnet", "testnet-10"]);
  assert.deepEqual(await store.listKeys(Categories.VAULT), ["shared-id"]); // testnet store: one key only
});

test("§C transaction: a forced mid-operation failure rolls back ALL rows (no half-commit)", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`INSERT INTO wallet_requests (network_id, key, value) VALUES ('testnet-10', 'r1', '{"a":1}'::jsonb)`);
    await client.query(`INSERT INTO audit_events (network_id, vault_id, value) VALUES ('testnet-10', 'v1', '{"e":1}'::jsonb)`);
    // Force a failure (duplicate PK) before commit.
    await client.query(`INSERT INTO wallet_requests (network_id, key, value) VALUES ('testnet-10', 'r1', '{"a":2}'::jsonb)`).catch(async (e) => {
      await client.query("ROLLBACK");
      throw e;
    });
    await client.query("COMMIT");
    assert.fail("expected the duplicate insert to fail");
  } catch {
    // rolled back
  } finally {
    client.release();
  }
  // Nothing half-applied: neither the request nor the audit row survived.
  assert.equal(await store.read(Categories.REQUEST, "r1"), null);
  assert.equal((await store.readAudit({ vaultId: "v1" })).length, 0);
});

test("§C restart durability: state, claims, and receipts survive a fresh store/pool on the same DB", { skip }, async () => {
  const { config, store, dbName } = await freshPgConfig();
  await store.write(Categories.VAULT, "v-keep", { alive: true });
  await store.createExclusive(Categories.TRANSITION_CLAIM, "pred-keep", { txId: "t-keep" });
  await store.write(Categories.RECEIPT, "tx-keep", { verified: true });
  await store.close(); // simulate process exit

  // A NEW process/pool on the same database.
  const config2 = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName,
    pgNoTls: true, authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-it-r-"))
  });
  const store2 = await openPgStore(config2);
  openStores.push(store2);
  assert.equal((await store2.read(Categories.VAULT, "v-keep")).alive, true);
  assert.equal((await store2.read(Categories.TRANSITION_CLAIM, "pred-keep")).txId, "t-keep");
  assert.equal((await store2.read(Categories.RECEIPT, "tx-keep")).verified, true);
  // A re-claim on the surviving predecessor still conflicts (durable claim).
  assert.equal(await store2.createExclusive(Categories.TRANSITION_CLAIM, "pred-keep", { txId: "other" }), false);
  void config;
});

/* ---------- JSON <-> PG EQUIVALENCE (directive §25/§52) ---------- */

async function bothBackends() {
  const jsonConfig = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-eq-json-")) });
  const { store: pgStore } = await freshPgConfig();
  return { json: getStore(jsonConfig), pg: pgStore };
}

test("§C equivalence: claim acquire/conflict is identical across JSON and PG", { skip }, async () => {
  const { json, pg } = await bothBackends();
  for (const store of [json, pg]) {
    const first = await store.createExclusive(Categories.TRANSITION_CLAIM, "eq-pred", { txId: "A" });
    const second = await store.createExclusive(Categories.TRANSITION_CLAIM, "eq-pred", { txId: "B" });
    const owner = (await store.read(Categories.TRANSITION_CLAIM, "eq-pred")).txId;
    const released = await store.remove(Categories.TRANSITION_CLAIM, "eq-pred");
    const afterRelease = await store.createExclusive(Categories.TRANSITION_CLAIM, "eq-pred", { txId: "C" });
    assert.deepEqual(
      { first, second, owner, released, afterRelease },
      { first: true, second: false, owner: "A", released: true, afterRelease: true },
      `backend ${store.kind} claim semantics`
    );
  }
});

test("§C equivalence: idempotent submission claim + overwrite write + list shape match", { skip }, async () => {
  const { json, pg } = await bothBackends();
  for (const store of [json, pg]) {
    assert.equal(await store.createExclusive(Categories.SUBMISSION_CLAIM, "tx", { a: 1 }), true);
    assert.equal(await store.createExclusive(Categories.SUBMISSION_CLAIM, "tx", { a: 2 }), false); // idempotent: first wins
    await store.write(Categories.REQUEST, "r1", { v: 1 });
    await store.write(Categories.REQUEST, "r1", { v: 2 }); // overwrite
    assert.equal((await store.read(Categories.REQUEST, "r1")).v, 2, `backend ${store.kind} overwrite`);
    await store.write(Categories.REQUEST, "r2", { v: 9 });
    const keys = (await store.listKeys(Categories.REQUEST)).sort();
    assert.deepEqual(keys, ["r1", "r2"], `backend ${store.kind} listKeys`);
  }
});

test("§C equivalence: missing read is null; remove of absent is false — both backends", { skip }, async () => {
  const { json, pg } = await bothBackends();
  for (const store of [json, pg]) {
    assert.equal(await store.read(Categories.VAULT, "nope"), null);
    assert.equal(await store.remove(Categories.RECEIPT, "nope"), false);
  }
});
