"use strict";

/*
 * PLATFORM-AGENT-API POSTGRESQL BACKEND (migration 005; server/src/
 * platform-store.js). Runs against a REAL local PostgreSQL — SKIPPED
 * cleanly without POLICYVAULT_TEST_PG_*. Each test gets its own fresh,
 * uniquely-named database on the shared cluster (created + dropped here;
 * the shared cluster's own databases are never touched), matching the
 * pattern in sdk/test/postlaunch-migrations-pg.test.js.
 *
 * Proves: migration 005 applies (machine_identities, machine_credentials,
 * idempotency_records tables, in order, after 001-004); the PG driver's
 * create-only claim arbiter (INSERT ... ON CONFLICT DO NOTHING) really
 * is atomic under genuine concurrency — TWO real, independently-issued
 * pool queries racing on the SAME key resolve to exactly one winner, the
 * property the whole idempotency/credential-uniqueness design rests on;
 * and the full machine-identity + Bearer-auth + idempotency pipeline
 * works end-to-end through the REAL server against Postgres (not just
 * the JSON backend the other new test files exercise).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { listMigrationFiles } = require("../../server/src/migrate");
const { Categories, getPlatformStore } = require("../../server/src/platform-store");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the platform-store PG suite";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

async function freshPgConfig(overrides = {}) {
  const dbName = `pv_plat_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-platpg-")),
    ...overrides
  });
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
  for (const store of openStores) {
    try {
      await store.close();
    } catch {
      /* closed */
    }
  }
  for (const db of createdDbs) {
    try {
      await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    } catch {
      /* best effort */
    }
  }
  await adminPool.end();
});

test("migration 005 applies after 001-004, in order, exactly once; the three new tables exist with the (network_id, key) jsonb shape", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const files = listMigrationFiles();
  assert.deepEqual(files.map((m) => m.version), [1, 2, 3, 4, 5, 6, 7, 8, 9], "this build ships migrations 001..009 (008 = audit chain, 009 = notifications)");

  const applied = await pool.query("SELECT version, name FROM schema_migrations ORDER BY version");
  assert.deepEqual(applied.rows.map((r) => r.version), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(applied.rows[4].name, "005_platform_agent_api.sql");
  assert.equal(applied.rows[5].name, "006_events_webhooks.sql");

  for (const table of ["machine_identities", "machine_credentials", "idempotency_records"]) {
    const cols = await pool.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name`,
      [table]
    );
    const names = cols.rows.map((r) => r.column_name).sort();
    assert.deepEqual(names, ["key", "network_id", "updated_at", "value"], `${table} must have the standard category-table shape`);
  }

  // Idempotent re-migration is a no-op (mirrors postlaunch-migrations-pg.test.js).
  const { runMigrations, assertSchemaCurrent } = require("../../server/src/migrate");
  await runMigrations(pool);
  const again = await pool.query("SELECT count(*)::int AS n FROM schema_migrations");
  assert.equal(again.rows[0].n, 9);
  await assertSchemaCurrent(pool);
});

test("PgPlatformStore.createExclusive is a REAL atomic claim arbiter: two genuinely concurrent pool queries racing on the same key resolve to exactly one winner", { skip }, async () => {
  const { config } = await freshPgConfig();
  const platformStore = getPlatformStore(config);
  const key = "race-key-1";

  // Fire both createExclusive calls without awaiting the first — this is
  // TWO independent connections/queries from the pool racing for real
  // (unlike the JSON backend, PostgreSQL genuinely parallelizes these).
  const [a, b] = await Promise.all([
    platformStore.createExclusive(Categories.MACHINE_IDENTITY, key, { n: "a" }),
    platformStore.createExclusive(Categories.MACHINE_IDENTITY, key, { n: "b" })
  ]);
  const wins = [a, b].filter(Boolean).length;
  assert.equal(wins, 1, "exactly one of two concurrent create-only claims on the same key must win");

  const stored = await platformStore.read(Categories.MACHINE_IDENTITY, key);
  assert.ok(stored.n === "a" || stored.n === "b");
  // The loser's value never overwrote the winner's.
  if (a) assert.equal(stored.n, "a");
  if (b) assert.equal(stored.n, "b");
});

test("read/write/remove/listValues round-trip correctly through jsonb for all three platform categories", { skip }, async () => {
  const { config } = await freshPgConfig();
  const platformStore = getPlatformStore(config);

  for (const cat of Object.values(Categories)) {
    const key = `rt-${cat}`;
    assert.equal(await platformStore.read(cat, key), null);
    const created = await platformStore.createExclusive(cat, key, { hello: "world", n: 1, nested: { a: [1, 2, 3] } });
    assert.equal(created, true);
    const again = await platformStore.createExclusive(cat, key, { hello: "different" });
    assert.equal(again, false, "createExclusive must refuse an already-claimed key");
    const read = await platformStore.read(cat, key);
    assert.deepEqual(read, { hello: "world", n: 1, nested: { a: [1, 2, 3] } });
    await platformStore.write(cat, key, { hello: "overwritten" });
    assert.deepEqual(await platformStore.read(cat, key), { hello: "overwritten" });
    const listed = await platformStore.listValues(cat);
    assert.ok(listed.some((v) => v.hello === "overwritten"));
    const removed = await platformStore.remove(cat, key);
    assert.equal(removed, true);
    assert.equal(await platformStore.read(cat, key), null);
  }
});

test("end-to-end against REAL Postgres: machine identity creation, Bearer authentication, and an idempotent build all work through the real server", { skip }, async () => {
  const { config } = await freshPgConfig();
  const { handle } = require("../../server/src/api");
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const KAS = 100000000n;
  const A = KEY(0x31);
  const AGENT = KEY(0x32);
  const RECIP = KEY(0x33);
  const VAULT_ID = "8a".repeat(32);

  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const stateObj = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state: stateObj });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state: stateObj });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "pg platform e2e", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(stateObj), stateId, outpoint: { transactionId: "8b".repeat(32), index: 0 }, outpointValue: (stateObj.protectedValue + stateObj.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "8c".repeat(32) },
    creationTxId: "8d".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const POST = (segs, body, headers) => handle(config, "POST", segs, {}, body, { headers: headers ?? {} });
  const GET = (segs, query, headers) => handle(config, "GET", segs, query ?? {}, null, { headers: headers ?? {} });

  const ch = await POST(["auth", "challenge"], { walletAddress: ADDR(A) });
  const sig = kaspa.signMessage({ message: ch.body.challenge.message, privateKey: A.toString() });
  const v = await POST(["auth", "verify"], { nonce: ch.body.challenge.nonce, signature: sig, publicKey: A.toPublicKey().toString().toLowerCase() });
  const cookie = v.headers["Set-Cookie"].split(";")[0];

  const created = await POST(["identities"], { scopes: ["read:vaults", "request:build"] }, { cookie });
  assert.equal(created.status, 201);
  const token = created.body.credential.token;

  const vaults = await GET(["vaults"], {}, { authorization: `Bearer ${token}` });
  assert.equal(vaults.status, 200);
  assert.equal(vaults.body.vaults[0].vaultId, VAULT_ID);

  // Idempotent build, twice, same key: exactly one durable request row.
  const body = { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (2n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) };
  const headers = { authorization: `Bearer ${token}`, idempotencyKey: "pg-e2e-key" };
  const first = await POST(["wallet", "v4", "requests"], body, headers);
  assert.equal(first.status, 201);
  const replay = await POST(["wallet", "v4", "requests"], body, headers);
  assert.equal(replay.status, 201);
  assert.equal(replay.body.idempotency.replayed, true);
  assert.equal(replay.body.request.requestId, first.body.request.requestId);

  const rows = await config ? await require("../src/store").getStore(config).listValues(require("../src/store").Categories.REQUEST) : [];
  assert.equal(rows.length, 1, "exactly one durable wallet-request row in Postgres");

  // Revoking the credential immediately invalidates it — proven against
  // the real PG-backed store, not just JSON.
  const revoked = await POST(["identities", created.body.identity.identityId, "revoke"], {}, { cookie });
  assert.equal(revoked.body.identity.status, "REVOKED");
  await assert.rejects(
    GET(["vaults"], {}, { authorization: `Bearer ${token}` }),
    (e) => e.status === 401 && e.code === "MACHINE_TOKEN_INVALID"
  );
});
