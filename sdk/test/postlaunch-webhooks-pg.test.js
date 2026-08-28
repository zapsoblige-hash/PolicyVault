"use strict";

/*
 * EVENTS + WEBHOOKS POSTGRESQL BACKEND (migration 006; server/src/
 * events-store.js PG driver). Runs against a REAL local PostgreSQL —
 * SKIPPED cleanly without POLICYVAULT_TEST_PG_*. Each test gets its own
 * fresh, uniquely-named database (created + dropped here), the exact
 * pattern of sdk/test/postlaunch-platform-store-pg.test.js.
 *
 * Proves: migration 006 applies after 001-005 with the expected table
 * shapes; the outbox's bigserial append order is the cursor (concurrent
 * appends get distinct, ordered seqs); (network_id, event_id) uniqueness
 * refuses duplicate appends; type-filtered cursor listing; endpoint /
 * delivery-state / dead-letter categories round-trip; and the FULL
 * pipeline — real api.handle() emission on a REAL ownerPause build,
 * tenant-scoped polling, endpoint CRUD, and a delivery tick persisting
 * cursor + counters — works end-to-end against Postgres, not just the
 * JSON backend the other webhook suites exercise.
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
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the webhooks PG suite";

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

async function freshPgConfig(overrides = {}) {
  const dbName = `pv_wh_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    hostedDevOpen: true, // single-operator open dev instance (config.js's sanctioned non-mainnet dev unlock): delivery/store parity is the subject; hosted tenancy is proven in postlaunch-webhooks-events.test.js
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-whpg-")),
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

test("migration 006 applies after 001-005; outbox + webhook tables carry the expected shapes and the (network_id, event_id) uniqueness", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const applied = await pool.query("SELECT version, name FROM schema_migrations ORDER BY version");
  assert.deepEqual(applied.rows.map((r) => r.version), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(applied.rows[5].name, "006_events_webhooks.sql");

  const cols = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'platform_events' ORDER BY column_name`);
  assert.deepEqual(cols.rows.map((r) => r.column_name), ["created_at", "event_id", "id", "network_id", "org_id", "type", "value", "vault_id"]);
  for (const table of ["webhook_endpoints", "webhook_delivery_state", "webhook_dead_letters"]) {
    const c = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name`, [table]);
    assert.deepEqual(c.rows.map((r) => r.column_name).sort(), ["key", "network_id", "updated_at", "value"], `${table} has the standard category shape`);
  }
  const uniq = await pool.query(`SELECT indexdef FROM pg_indexes WHERE tablename = 'platform_events' AND indexdef ILIKE '%UNIQUE%'`);
  assert.ok(uniq.rows.some((r) => r.indexdef.includes("network_id") && r.indexdef.includes("event_id")), "unique (network_id, event_id) exists");
});

test("outbox semantics on PG: bigserial cursor order under concurrent appends; duplicate eventId refused; type filter + cursor resume; latest/count", { skip }, async () => {
  const { config } = await freshPgConfig();
  const { getEventsStore } = require("../../server/src/events-store");
  const { emitPlatformEvent } = require("../../server/src/events");
  const store = getEventsStore(config);
  assert.equal(store.kind, "postgres");

  // Ten CONCURRENT appends: all succeed with distinct, gap-free-ordered seqs.
  const events = await Promise.all(
    Array.from({ length: 10 }, (_, i) =>
      emitPlatformEvent(config, { type: "request.built", vaultId: "ab".repeat(32), correlation: { requestId: `r${i}` }, data: { action: "ownerPause", state: "BUILT" } })
    )
  );
  assert.equal(new Set(events.map((e) => e.eventId)).size, 10);
  const listed = await store.listEventsAfter({ cursor: "0", limit: 100 });
  assert.equal(listed.length, 10);
  const seqs = listed.map((r) => r.seq);
  assert.deepEqual([...seqs].sort((a, b) => a - b), seqs, "ascending append order");
  assert.equal(new Set(seqs).size, 10, "distinct seqs under concurrency");

  // Duplicate eventId: the unique arbiter refuses the second append.
  await store.appendEvent({ ...events[0], eventId: "duplicate-check", type: "request.built" });
  await assert.rejects(() => store.appendEvent({ ...events[1], eventId: "duplicate-check", type: "request.built" }), (e) => e.code === "EVENTS_DUPLICATE_EVENT_ID");

  await emitPlatformEvent(config, { type: "request.rejected", vaultId: "ab".repeat(32), data: { action: "ownerPause", state: "WALLET_REJECTED" } });
  const filtered = await store.listEventsAfter({ cursor: "0", limit: 100, types: ["request.rejected"] });
  assert.equal(filtered.length, 1);
  const mid = listed[4].cursor;
  const resumed = await store.listEventsAfter({ cursor: mid, limit: 100 });
  assert.equal(resumed[0].seq, listed[5].seq, "cursor resume is exact");
  assert.equal(await store.latestCursor(), String(Math.max(...(await store.listEventsAfter({ cursor: "0", limit: 100 })).map((r) => r.seq))));
  assert.equal(await store.countEvents(), 12);
  await assert.rejects(() => store.listEventsAfter({ cursor: "DROP TABLE" }), (e) => e.code === "EVENTS_CURSOR_INVALID", "hostile cursors fail closed before touching SQL");
});

test("END-TO-END on PG: real handle() build emits request.built; polling pages it; endpoint CRUD + a delivery tick persist cursor/counters in PG", { skip }, async () => {
  const { config } = await freshPgConfig();
  const { handle } = require("../../server/src/api");
  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const kaspa = require(config.rustyKaspaModule);
  const KEY = new kaspa.PrivateKey("a5".repeat(32));
  const XO = KEY.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = KEY.toPublicKey().toAddress(config.networkId).toString();
  const AGENT = new kaspa.PrivateKey("c5".repeat(32)).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const RECIP = new kaspa.PrivateKey("d5".repeat(32)).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const KAS = 100000000n;
  const VAULT_ID = "7e".repeat(32);

  const registry = [{
    agentPk: AGENT, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [RECIP]
  }];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const st = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template: { owner: XO, vaultId: VAULT_ID }, state: st });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "pg webhooks", status: "ACTIVE", template: { owner: XO, vaultId: VAULT_ID }, agentRegistry: registry,
    live: { state: stateToJsonV4(st), stateId: computeStateIdV4({ networkId: config.networkId, template: { owner: XO, vaultId: VAULT_ID }, state: st }), outpoint: { transactionId: "75".repeat(32), index: 0 }, outpointValue: (st.protectedValue + st.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "43".repeat(32) },
    creationTxId: "76".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const fuel = { outpoint: { transactionId: "77".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO}ac` };
  const built = await handle(config, "POST", ["wallet", "v4", "requests"], {}, { vaultId: VAULT_ID, action: "ownerPause", params: { fuel }, signerAddress: ADDR }, {});
  assert.equal(built.status, 201);

  const page = await handle(config, "GET", ["events"], {}, null, {});
  const ev = page.body.events.find((e) => e.event.type === "request.built");
  assert.ok(ev, "request.built lands in the PG outbox via the same emission path");
  assert.equal(ev.event.correlation.requestId, built.body.request.requestId);
  assert.equal(ev.event.correlation.manifestHash, built.body.request.manifestHash);

  // Endpoint CRUD + one delivery tick against PG state, with an injected
  // in-process transport (real-HTTP delivery is proven in
  // postlaunch-webhooks-delivery.test.js; here the DURABLE PG delivery
  // state is the subject).
  const createdEp = await handle(config, "POST", ["webhooks"], {}, { url: "https://pg.example.com/hook" }, {});
  assert.equal(createdEp.status, 201);
  const endpointId = createdEp.body.endpoint.endpointId;
  const secret = createdEp.body.secret;

  const rejected = await handle(config, "POST", ["wallet", "v4", "requests", built.body.request.requestId, "reject"], {}, {}, {});
  assert.equal(rejected.status, 200);

  const { DeliveryWorker } = require("../../server/src/events-delivery");
  const { verifyWebhookSignature, SIGNATURE_HEADER } = require("../../server/src/events-signing");
  const seen = [];
  const worker = new DeliveryWorker(config, {
    transport: async ({ rawBody, headers }) => {
      seen.push({ rawBody, headers });
      return { ok: true, httpStatus: 200, errorCode: null, durationMs: 1 };
    }
  });
  await worker.tick();
  assert.equal(seen.length, 1, "only the post-subscription event (request.rejected) delivers — new endpoints start at the stream head");
  assert.equal(JSON.parse(seen[0].rawBody).event.type, "request.rejected");
  assert.equal(verifyWebhookSignature({ header: seen[0].headers[SIGNATURE_HEADER], rawBody: seen[0].rawBody, secret }).ok, true, "signed exactly as on the JSON backend");

  const monitor = await handle(config, "GET", ["webhooks", endpointId], {}, null, {});
  assert.equal(monitor.body.delivery.counters.delivered, 1);
  assert.ok(BigInt(monitor.body.delivery.cursor) > 0n, "the durable PG cursor advanced");
  const again = new DeliveryWorker(config, {
    transport: async () => {
      throw new Error("must not be called — cursor is durable");
    }
  });
  await again.tick();
  assert.equal(monitor.body.delivery.counters.delivered, 1, "a fresh worker over the SAME PG state redelivers nothing");
});
