"use strict";

/*
 * AUDIT HASH CHAIN — POSTGRESQL BACKEND (migration 008;
 * server/src/audit-chain.js over the PG audit_events store). Runs against
 * a REAL local PostgreSQL — SKIPPED cleanly without POLICYVAULT_TEST_PG_*.
 * Each test gets its own fresh, uniquely-named database (the
 * postlaunch-platform-store-pg pattern).
 *
 * Proves the G-2 CLASS DEFECT CANNOT RECUR HERE: chained records written
 * through the REAL server audit module survive a PostgreSQL jsonb round
 * trip — which demonstrably REORDERS object keys — and re-verify exactly
 * (recordHash recomputed from the RELOADED representation matches).
 * Also: migration 008 shapes (audit_chain_state + the partial chain-seq
 * index); SQL tamper via jsonb_set -> BROKEN RECORD_TAMPERED at the
 * right seq; row DELETE -> SEQ_GAP; the verification endpoint over a PG
 * config via real api.handle(); head-anchor recovery from PG records
 * after a process-cache reset; and PG/JSON behavior parity of reason
 * codes.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const sdkEntry = require("../src/index");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the audit-chain PG suite";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

async function freshPgConfig(overrides = {}) {
  const dbName = `pv_chain_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    hostedDevOpen: true, // single-operator open dev instance; hosted gating is the JSON suite's subject
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-chainpg-")),
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

/* Appends N chained records through the REAL server audit module, with
 * deliberately non-canonical key insertion order (the jsonb reorder
 * demonstration relies on it). */
async function appendProbes(config, n) {
  const { appendAudit } = require("../../server/src/audit");
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push(
      await appendAudit(config, {
        kind: "metadata",
        action: "pg_probe",
        result: "OK",
        zulu: `z${i}`, // longer/later keys inserted BEFORE shorter ones:
        alpha: `a${i}`, // jsonb reorders (length-then-bytewise), proving
        nested: { bbbb: i, a: `v${i}` }, // representation independence below
        detail: `probe ${i}`
      })
    );
  }
  return out;
}

test("migration 008 applies after 001-007: audit_chain_state has the category shape; the partial chain-seq index exists on audit_events", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const applied = await pool.query("SELECT version, name FROM schema_migrations ORDER BY version");
  assert.deepEqual(applied.rows.map((r) => r.version), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(applied.rows[7].name, "008_audit_chain.sql");
  const cols = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_chain_state' ORDER BY column_name`);
  assert.deepEqual(cols.rows.map((r) => r.column_name).sort(), ["key", "network_id", "updated_at", "value"]);
  const idx = await pool.query(`SELECT indexdef FROM pg_indexes WHERE tablename = 'audit_events' AND indexname = 'audit_events_chain_seq_idx'`);
  assert.equal(idx.rowCount, 1);
  assert.ok(idx.rows[0].indexdef.includes("chain"), "partial expression index over the embedded chain seq");
});

test("G-2 CLASS PROOF: chained records survive the jsonb ROUND TRIP — keys demonstrably reordered, chain VALID, recordHash recomputes from the RELOADED representation", { skip }, async () => {
  const { config, store } = await freshPgConfig();
  const written = await appendProbes(config, 5);
  // The reloaded records come back from jsonb with REORDERED keys.
  const { readAudit } = require("../../server/src/audit");
  const reloaded = (await readAudit(config, { limit: 100 })).reverse();
  assert.equal(reloaded.length, 5);
  const insertionKeys = Object.keys(written[0].nested);
  const reloadedKeys = Object.keys(reloaded[0].nested);
  assert.deepEqual(insertionKeys, ["bbbb", "a"], "insertion order was non-canonical");
  assert.deepEqual(reloadedKeys, ["a", "bbbb"], "jsonb reordered the keys (the G-2 defect vector is REAL on this backend)");

  // The chain re-verifies from the reloaded representation.
  const chain = require("../../server/src/audit-chain");
  const v = await chain.verifyChain(config, {});
  assert.equal(v.status, "VALID");
  assert.equal(v.checked.count, 5);
  assert.equal(v.complete, true);

  // Belt-and-suspenders: recompute one recordHash BY HAND from the
  // reloaded record using the SDK PUBLIC ENTRY serializer.
  const r = reloaded[2];
  const { chain: env, ...content } = r;
  const preimage = sdkEntry.canonicalJsonStringify({ content, nonce: env.nonce, prevHash: env.prevHash, seq: env.seq });
  assert.equal(crypto.createHash("sha256").update(preimage, "utf8").digest("hex"), env.recordHash, "hand recomputation from the PG representation matches");

  // The durable head anchor round-tripped through PG too.
  const head = await store.pool().query(`SELECT value FROM audit_chain_state WHERE network_id = $1 AND key = 'head'`, [config.networkId]);
  assert.equal(head.rowCount, 1);
  assert.equal(head.rows[0].value.seq, 5);
});

test("SQL TAMPER: jsonb_set of one persisted field -> BROKEN RECORD_TAMPERED at the right seq (same reason code as the JSON backend)", { skip }, async () => {
  const { config, store } = await freshPgConfig();
  await appendProbes(config, 4);
  const pool = store.pool();
  const r = await pool.query(
    `UPDATE audit_events SET value = jsonb_set(value, '{detail}', '"tampered by SQL"')
     WHERE network_id = $1 AND (((value -> 'chain') ->> 'seq')::bigint) = 3`,
    [config.networkId]
  );
  assert.equal(r.rowCount, 1);
  const chain = require("../../server/src/audit-chain");
  const v = await chain.verifyChain(config, {});
  assert.equal(v.status, "BROKEN");
  assert.deepEqual(v.broken, { atSeq: 3, reason: "RECORD_TAMPERED" });
});

test("SQL DELETION: removing an interior row -> SEQ_GAP; removing the newest rows -> TAIL_TRUNCATED via the durable anchor", { skip }, async () => {
  const { config, store } = await freshPgConfig();
  await appendProbes(config, 5);
  const pool = store.pool();
  await pool.query(`DELETE FROM audit_events WHERE network_id = $1 AND (((value -> 'chain') ->> 'seq')::bigint) = 2`, [config.networkId]);
  const chain = require("../../server/src/audit-chain");
  let v = await chain.verifyChain(config, {});
  assert.equal(v.status, "BROKEN");
  assert.deepEqual(v.broken, { atSeq: 2, reason: "SEQ_GAP" });

  const { config: config2, store: store2 } = await freshPgConfig();
  await appendProbes(config2, 5);
  await store2.pool().query(`DELETE FROM audit_events WHERE network_id = $1 AND (((value -> 'chain') ->> 'seq')::bigint) >= 4`, [config2.networkId]);
  v = await chain.verifyChain(config2, {});
  assert.equal(v.status, "BROKEN");
  assert.deepEqual(v.broken, { atSeq: 4, reason: "TAIL_TRUNCATED" });
});

test("ENDPOINT over PG via real api.handle(): status + verify + bounded continuation; head recovers from PG records after a process-cache reset", { skip }, async () => {
  const { config } = await freshPgConfig();
  const { handle } = require("../../server/src/api");
  await appendProbes(config, 6);

  const status = await handle(config, "GET", ["audit", "chain"], {}, null, {});
  assert.equal(status.status, 200);
  assert.equal(status.body.head.seq, 6);
  assert.deepEqual(status.body.records, { total: 6, chained: 6, unchained: 0 });

  let from = 1;
  let total = 0;
  for (let i = 0; i < 10; i++) {
    const v = await handle(config, "GET", ["audit", "chain", "verify"], { fromSeq: String(from), limit: "2" }, null, {});
    assert.equal(v.body.status, "VALID");
    total += v.body.checked.count;
    if (v.body.complete) break;
    from = v.body.nextFromSeq;
  }
  assert.equal(total, 6, "bounded continuation walked the whole chain on PG");

  // Fresh-process simulation: the head cache is rebuilt from PG.
  const chain = require("../../server/src/audit-chain");
  chain.resetProcessCache();
  await appendProbes(config, 1);
  const v2 = await handle(config, "GET", ["audit", "chain", "verify"], {}, null, {});
  assert.equal(v2.body.status, "VALID");
  assert.equal(v2.body.head.seq, 7, "chain continued from PG records, not from genesis");
});
