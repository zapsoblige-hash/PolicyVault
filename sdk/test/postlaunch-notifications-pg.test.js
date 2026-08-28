"use strict";

/*
 * HUMAN NOTIFICATIONS — POSTGRESQL BACKEND (migration 009; server/src/
 * notifications.js + notify-delivery.js over the PG events store). Runs
 * against a REAL local PostgreSQL — SKIPPED cleanly without
 * POLICYVAULT_TEST_PG_*. Fresh uniquely-named database per test.
 *
 * Proves PG/JSON parity for the new categories: migration 009 shapes
 * (notification_rules + notification_delivery_state + creator index);
 * rule CRUD through real api.handle() persisting to PG; the delivery
 * worker consuming the REAL PG outbox with its per-rule cursor/counters
 * durably round-tripped through jsonb; refusal-code parity (unregistered
 * smtp, unknown/self-referential event types); rule-mutation audit rows
 * landing CHAINED in PG audit_events; and rule+state removal.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the notifications PG suite";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

async function freshPgConfig(overrides = {}) {
  const dbName = `pv_notif_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    hostedDevOpen: true, // store parity is the subject; hosted tenancy/scopes are proven in postlaunch-notifications.test.js
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-notifpg-")),
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

async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

test("migration 009 applies: notification tables carry the standard category shape and the creator index", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const applied = await pool.query("SELECT version, name FROM schema_migrations ORDER BY version");
  assert.deepEqual(applied.rows.map((r) => r.version), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(applied.rows[8].name, "009_notifications.sql");
  for (const table of ["notification_rules", "notification_delivery_state"]) {
    const c = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name`, [table]);
    assert.deepEqual(c.rows.map((r) => r.column_name).sort(), ["key", "network_id", "updated_at", "value"], `${table} has the standard category shape`);
  }
  const idx = await pool.query(`SELECT indexname FROM pg_indexes WHERE tablename = 'notification_rules'`);
  assert.ok(idx.rows.some((r) => r.indexname === "notification_rules_creator_idx"), "creator index exists");
});

test("rule CRUD via real api.handle() persists to PG; refusal parity; the rule-mutation audit row lands CHAINED in PG audit_events", { skip }, async () => {
  const { config, store } = await freshPgConfig();
  const { handle } = require("../../server/src/api");
  const pool = store.pool();

  const created = await handle(config, "POST", ["notifications", "rules"], {}, { label: "pg rule", eventTypes: ["request.built"], channel: { type: "console" } }, {});
  assert.equal(created.status, 201);
  const ruleId = created.body.rule.ruleId;
  const row = await pool.query(`SELECT value FROM notification_rules WHERE network_id = $1 AND key = $2`, [config.networkId, ruleId]);
  assert.equal(row.rowCount, 1);
  assert.equal(row.rows[0].value.label, "pg rule");

  // Refusal parity with the JSON backend (same closed codes).
  await expectThrow(handle(config, "POST", ["notifications", "rules"], {}, { eventTypes: ["notification.rule.disabled"], channel: { type: "console" } }, {}), 422, "NOTIFY_EVENT_TYPE_SELF_REFERENTIAL");
  await expectThrow(handle(config, "POST", ["notifications", "rules"], {}, { eventTypes: ["nope"], channel: { type: "console" } }, {}), 422, "NOTIFY_EVENT_TYPE_UNKNOWN");
  await expectThrow(handle(config, "POST", ["notifications", "rules"], {}, { channel: { type: "smtp", to: "a@b.co" } }, {}), 422, "NOTIFY_CHANNEL_UNAVAILABLE");

  // The rule-creation audit line is CHAINED in PG.
  const audit = await pool.query(`SELECT value FROM audit_events WHERE network_id = $1 AND value ? 'chain' ORDER BY id`, [config.networkId]);
  assert.equal(audit.rowCount, 1);
  assert.equal(audit.rows[0].value.kind, "notification");
  assert.equal(audit.rows[0].value.action, "notification_rule_created");
  assert.equal(audit.rows[0].value.chain.seq, 1);

  // disable -> enable -> delete round trip on PG.
  const off = await handle(config, "POST", ["notifications", "rules", ruleId, "disable"], {}, {}, {});
  assert.equal(off.body.rule.status, "DISABLED");
  const on = await handle(config, "POST", ["notifications", "rules", ruleId, "enable"], {}, {}, {});
  assert.equal(on.body.rule.status, "ACTIVE");
  const del = await handle(config, "POST", ["notifications", "rules", ruleId, "delete"], {}, {}, {});
  assert.equal(del.body.deleted, true);
  assert.equal((await pool.query(`SELECT 1 FROM notification_rules WHERE network_id = $1 AND key = $2`, [config.networkId, ruleId])).rowCount, 0);
});

test("the worker consumes the REAL PG outbox: delivery via console provider; per-rule cursor + counters durably round-trip through jsonb", { skip }, async () => {
  const { config, store } = await freshPgConfig();
  const { handle } = require("../../server/src/api");
  const { emitPlatformEvent } = require("../../server/src/events");
  const { NotificationWorker } = require("../../server/src/notify-delivery");
  const pool = store.pool();

  const created = await handle(config, "POST", ["notifications", "rules"], {}, { label: "pg deliver", eventTypes: ["vault.created"], channel: { type: "console" } }, {});
  const ruleId = created.body.rule.ruleId;
  for (let i = 0; i < 3; i++) {
    await emitPlatformEvent(config, { type: "vault.created", vaultId: "cd".repeat(32), data: { contractVersion: "v0.4", label: `pg ${i}` } });
  }
  const lines = [];
  const worker = new NotificationWorker(config, { consoleSink: (l) => lines.push(l) });
  await worker.tick();
  assert.equal(lines.filter((l) => l.includes(ruleId)).length, 3, "all three outbox events delivered");

  // Durable state row in PG, cursor at the stream head.
  const st = await pool.query(`SELECT value FROM notification_delivery_state WHERE network_id = $1 AND key = $2`, [config.networkId, ruleId]);
  assert.equal(st.rowCount, 1);
  assert.equal(st.rows[0].value.counters.delivered, 3);
  const head = await pool.query(`SELECT COALESCE(MAX(id), 0) AS m FROM platform_events WHERE network_id = $1`, [config.networkId]);
  assert.equal(st.rows[0].value.cursor, String(head.rows[0].m), "per-rule cursor persisted at the PG outbox head");

  // A SECOND worker instance (fresh process shape) resumes from the
  // durable cursor: nothing is redelivered.
  const lines2 = [];
  const worker2 = new NotificationWorker(config, { consoleSink: (l) => lines2.push(l) });
  await worker2.tick();
  assert.equal(lines2.length, 0, "durable cursor prevents redelivery across worker restarts");
});
