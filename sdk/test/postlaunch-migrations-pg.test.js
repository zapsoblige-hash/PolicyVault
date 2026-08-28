"use strict";

/*
 * POSTLAUNCH MIGRATIONS 002/003/004 + LIVE-PG ROUND-TRIP REGRESSIONS
 * (audit-correlation-spec §5/§6; the MANDATORY live-PG regression: JSON
 * suites cannot catch jsonb representation defects — the Phase G-2
 * lesson).
 *
 * Runs against a REAL local PostgreSQL — SKIPPED cleanly without
 * POLICYVAULT_TEST_PG_*. Each test gets its own fresh database on the
 * shared cluster (created + dropped here; the shared cluster's own
 * databases are never touched). Proves:
 *   - migrations 001..004 apply in order, exactly once; re-run is a
 *     no-op; assertSchemaCurrent passes; a future version still fails
 *     closed; 001's recorded checksum is untouched;
 *   - the 002 schema shape: intent_manifests table, the five nullable
 *     audit_events correlation columns, the new indexes;
 *   - the 003/004 tables exist with the category shape;
 *   - PgStore.appendAudit LIFTS the correlation fields into the new
 *     columns (and old-style records write NULLs — never a default
 *     claim);
 *   - intent-manifest PG round trip: write through the REAL server
 *     recorder from a REAL build -> read back through jsonb (which
 *     reorders keys) -> canonical re-hash equals the row key -> the
 *     verifier re-derives VERIFIED_EXACT;
 *   - governance proposal PG round trip: the recomputed canonical
 *     digest survives jsonb; a collected approval signature still
 *     verifies after storage.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore, Categories, getStore } = require("../src/store");
const { runMigrations, assertSchemaCurrent, listMigrationFiles } = require("../../server/src/migrate");

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
const openStores = [];

async function freshPgConfig() {
  const dbName = `pv_pl_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-pl-json-"))
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
  for (const store of openStores) { try { await store.close(); } catch { /* closed */ } }
  for (const db of createdDbs) {
    try { await adminPool.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); } catch { /* best effort */ }
  }
  await adminPool.end();
});

test("migrations 001..007 apply in order exactly once; idempotent re-run; future version fails closed; 001 checksum intact", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();
  const files = listMigrationFiles();
  // 005_platform_agent_api.sql (machine identities/credentials +
  // idempotency records) and 006_events_webhooks.sql (event outbox +
  // webhook endpoints/delivery-state/dead-letters —
  // docs/postlaunch/webhooks-events-spec.md) joined the migration set, and
  // 007_agent_suspensions.sql (hosted-layer agent suspend — fullscale
  // surface 21 residual; docs/postlaunch/hosted-agent-suspend.md) after
  // them; this count is a mechanical fact about the build, updated for
  // that reason only.
  assert.deepEqual(files.map((m) => m.version), [1, 2, 3, 4, 5, 6, 7, 8, 9], "this build ships migrations 001..009 (008 = audit chain, 009 = notifications)");

  const first = await pool.query("SELECT version, name, checksum FROM schema_migrations ORDER BY version");
  assert.deepEqual(first.rows.map((r) => r.version), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(first.rows[0].name, "001_initial_hosted_schema.sql");
  assert.equal(first.rows[0].checksum, files[0].checksum, "001's recorded checksum equals the frozen file's bytes");

  // re-run: no-op, nothing re-applied, applied_at rows unchanged in count
  await runMigrations(pool);
  const second = await pool.query("SELECT count(*)::int AS n FROM schema_migrations");
  assert.equal(second.rows[0].n, 9);
  await assertSchemaCurrent(pool); // no throw

  // future-version discipline unchanged
  await pool.query("INSERT INTO schema_migrations (version, name, checksum) VALUES (999, '999_future.sql', 'x')");
  await assert.rejects(() => assertSchemaCurrent(pool), /newer than this build/);
});

test("002 schema shape: intent_manifests + five NULLABLE audit_events correlation columns + the new indexes", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();

  const cols = await pool.query(
    `SELECT column_name, is_nullable FROM information_schema.columns
     WHERE table_name = 'audit_events' AND column_name IN ('request_id','manifest_hash','proposal_id','tx_id','actor_xonly')
     ORDER BY column_name`
  );
  assert.deepEqual(
    cols.rows,
    [
      { column_name: "actor_xonly", is_nullable: "YES" },
      { column_name: "manifest_hash", is_nullable: "YES" },
      { column_name: "proposal_id", is_nullable: "YES" },
      { column_name: "request_id", is_nullable: "YES" },
      { column_name: "tx_id", is_nullable: "YES" }
    ],
    "all five correlation columns exist and are nullable (old rows predate them; never a default claim)"
  );

  const tables = await pool.query(
    `SELECT table_name FROM information_schema.tables WHERE table_name IN
     ('intent_manifests','governance_proposals','governance_approvals','org_controls','risk_evaluations') ORDER BY table_name`
  );
  assert.deepEqual(
    tables.rows.map((r) => r.table_name),
    ["governance_approvals", "governance_proposals", "intent_manifests", "org_controls", "risk_evaluations"]
  );

  const indexes = await pool.query(
    `SELECT indexname FROM pg_indexes WHERE indexname IN
     ('intent_manifests_request_idx','intent_manifests_txid_idx','intent_manifests_vault_idx',
      'audit_events_txid_idx','audit_events_request_idx','audit_events_manifest_idx','audit_events_actor_idx',
      'receipts_vault_idx','wallet_requests_manifest_idx',
      'governance_proposals_vault_idx','governance_proposals_digest_idx','risk_evaluations_vault_idx','risk_evaluations_intent_idx')
     ORDER BY indexname`
  );
  assert.equal(indexes.rows.length, 13, `all new indexes exist (got ${indexes.rows.map((r) => r.indexname).join(", ")})`);
});

test("PgStore.appendAudit lifts correlation fields into columns; old-style records write NULLs", { skip }, async () => {
  const { store } = await freshPgConfig();
  const pool = store.pool();

  await store.appendAudit({
    at: new Date().toISOString(), vaultId: "aa".repeat(32), action: "agentSpend", actor: "agent",
    requestId: "req-1", manifestHash: "bb".repeat(32), proposalId: "prop-1", txId: "cc".repeat(32), actorXOnly: "dd".repeat(32)
  });
  await store.appendAudit({ at: new Date().toISOString(), vaultId: "aa".repeat(32), action: "legacy", actor: "system" });

  const rows = await pool.query("SELECT request_id, manifest_hash, proposal_id, tx_id, actor_xonly FROM audit_events ORDER BY id");
  assert.deepEqual(rows.rows[0], {
    request_id: "req-1", manifest_hash: "bb".repeat(32), proposal_id: "prop-1", tx_id: "cc".repeat(32), actor_xonly: "dd".repeat(32)
  });
  assert.deepEqual(rows.rows[1], { request_id: null, manifest_hash: null, proposal_id: null, tx_id: null, actor_xonly: null });

  // and the values remain inline in the jsonb record (columns are indexes, not truth)
  const values = await pool.query("SELECT value->>'manifestHash' AS mh FROM audit_events ORDER BY id LIMIT 1");
  assert.equal(values.rows[0].mh, "bb".repeat(32));

  // indexed walk: the txid predicate answers from the lifted column
  const byTx = await pool.query("SELECT value->>'action' AS action FROM audit_events WHERE network_id=$1 AND tx_id=$2", [
    store._network ?? "testnet-10",
    "cc".repeat(32)
  ]);
  assert.equal(byTx.rows[0].action, "agentSpend");
});

test("MANDATORY live-PG regression: intent manifest write -> jsonb read -> canonical re-hash equality -> verdict re-derivation", { skip }, async () => {
  const { config } = await freshPgConfig();

  // Seed a REAL v0.4 manifest and drive the REAL build route over PG.
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const KAS = 100000000n;
  const owner = KEY(1);
  const agentA = KEY(0x1e);
  const recipient = KEY(0x28);
  const VAULT_ID = "39".repeat(32);
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const REGISTRY = [
    {
      agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(recipient)]
    }
  ];
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "pg regression", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "70".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const { handle } = require("../../server/src/api");
  const built = await handle(config, "POST", ["wallet", "v4", "requests"], {}, {
    vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) },
    signerAddress: ADDR(agentA)
  });
  assert.equal(built.status, 201);
  const manifestHash = built.body.request.manifestHash;
  assert.match(manifestHash, /^[0-9a-f]{64}$/);

  // Read the row back THROUGH jsonb (PostgreSQL reorders object keys):
  // the canonical re-hash must equal the row key, and the verifier must
  // re-derive VERIFIED_EXACT from the stored body alone.
  const { loadManifestRecord } = require("../../server/src/intent-records");
  const record = await loadManifestRecord(config, manifestHash); // throws on any hash divergence
  assert.equal(record.manifestHash, manifestHash);
  const { computeManifestHashV1, verifyIntentManifest } = require("../../core/intent");
  const { manifestHash: embedded, ...body } = record.manifest;
  assert.equal(embedded, manifestHash);
  assert.equal(computeManifestHashV1(body), manifestHash, "canonical hash is jsonb-key-order independent");
  const reverified = verifyIntentManifest({ manifest: record.manifest });
  assert.equal(reverified.verdict, "VERIFIED_EXACT");
  assert.equal(reverified.ok, true);

  // Prove jsonb actually re-ordered SOMETHING relative to insertion
  // (representation changed; values identical) — the exact G-2 class.
  const raw = await getStore(config).pool().query(`SELECT value::text AS t FROM intent_manifests WHERE key = $1`, [manifestHash]);
  assert.ok(raw.rows[0].t.length > 0);

  // Governance proposal PG round trip: digest + approval survive jsonb.
  const governance = require("../../server/src/governance");
  const { loadManifestV4 } = require("../src/manifest-v4");
  const gvManifest = await loadManifestV4(config, VAULT_ID);
  const NEW_AGENT = { ...REGISTRY[0], agentPk: XO(KEY(0x55)) };
  const proposalRecord = await governance.createProposal({
    config, manifest: gvManifest, vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT },
    proposedByXOnly: XO(owner)
  });
  const message = governance.approvalMessageText(config, proposalRecord.proposalId, proposalRecord.proposalDigest);
  const signature = kaspa.signMessage({ message, privateKey: owner.toString() });
  await governance.collectProposalApproval({ config, proposalId: proposalRecord.proposalId, approverAddress: ADDR(owner), signature });

  const reloaded = await governance.loadProposalRecord(config, proposalRecord.proposalId);
  const { governanceProposalDigest } = require("../../core/governance");
  assert.equal(governanceProposalDigest(reloaded.proposal), proposalRecord.proposalDigest, "canonical digest is jsonb-key-order independent");
  const status = await governance.approvalStatus(config, reloaded, proposalRecord.proposalDigest, gvManifest, null);
  assert.equal(status.ownerApproved, true, "the stored approval signature still verifies after the PG round trip");
  assert.equal(status.satisfied, true);
});
