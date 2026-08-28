"use strict";

/*
 * PG PARITY — pre-build period-budget reservations (surface 15) against a
 * REAL PostgreSQL backend. SKIPPED cleanly without POLICYVAULT_TEST_PG_*
 * (same pattern as postlaunch-platform-store-pg.test.js: a fresh,
 * uniquely-named database on the shared cluster, created + dropped here).
 *
 * Proves the claim-idiom parity the design rests on: reservation records
 * and the admission lock live in the EXISTING transition_claims table
 * (INSERT ... ON CONFLICT DO NOTHING is the arbiter — no migration, no
 * new table), transition claims themselves are untouched, and the full
 * build -> refuse -> reject -> rebuild -> finalize(consume) lifecycle
 * behaves IDENTICALLY to the JSON backend under real concurrency.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { openPgStore, getStore, Categories } = require("../src/store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { claimTransition, loadTransitionClaim } = require("../src/submission-claim");
const { buildWalletRequestV4, finalizeWalletRequestV4, markWalletRejected, RequestState } = require("../src/wallet-requests-v4");
const { RESERVATION_SCHEMA, listReservationsV4 } = require("../src/budget-reservation");
const { makeDevSigner } = require("../src/signer-dev");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the reservation PG suite";

let adminPool;
let config;
let store;
let kaspa;
const dbName = `pv_resv_${process.pid}_${Date.now() % 100000}`;

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-resvpg-"))
  });
  store = await openPgStore(config, { migrate: true });
  kaspa = require(config.rustyKaspaModule);
});

after(async () => {
  if (!PG_AVAILABLE) return;
  try {
    await store.close();
  } catch {
    /* closed */
  }
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.end();
});

/* ---- fixture (mirrors budget-reservation.test.js) ---- */
const KAS = 100000000n;
const KEYOF = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const VAULT_ID = "5f".repeat(32);

function tightEntry(agent, recipientKp) {
  return {
    agentPk: XO(agent), maxPerSpend: (20n * KAS).toString(), periodBudget: (30n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (25n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipientKp)]
  };
}

let seedCounter = 0;
async function seedManifest(owner, registry) {
  seedCounter += 1;
  const outTxId = (0xb0 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId,
    vaultId: VAULT_ID, label: "resv-pg", status: "ACTIVE", template, agentRegistry: registry,
    live: {
      state: stateToJsonV4(state), stateId,
      outpoint: { transactionId: outTxId, index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256, covenantId: "4d".repeat(32)
    },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

test("PG: reservation rows live in transition_claims under resv- keys; transition claims themselves are untouched", { skip }, async () => {
  const owner = KEYOF(1);
  const agent = KEYOF(0x1e);
  const rec = KEYOF(0x28);
  await seedManifest(owner, [tightEntry(agent, rec)]);
  assert.equal(getStore(config).kind, "postgres", "the run really is on the PG backend");

  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: { payAmountSompi: (20n * KAS).toString(), agentPk: XO(agent), recipient: XO(rec) },
    signerAddress: ADDR(agent)
  });
  assert.equal(req.state, RequestState.BUILT);

  // The row is IN the transition_claims table, resv- keyed, v1 schema.
  const rows = await store.pool().query(`SELECT key, value->>'schema' AS schema FROM transition_claims WHERE key LIKE 'resv-%'`);
  assert.equal(rows.rowCount, 1);
  assert.equal(rows.rows[0].schema, RESERVATION_SCHEMA);
  assert.ok(rows.rows[0].key.endsWith(req.requestId));

  // A REAL transition claim on an unrelated outpoint coexists untouched.
  const outpoint = { transactionId: "cc".repeat(32), index: 0 };
  await claimTransition(config, { outpoint, action: "test", txId: "dd".repeat(32), vaultId: VAULT_ID, stateId: "ee".repeat(32) });
  const claim = await loadTransitionClaim(config, outpoint);
  assert.equal(claim.txId, "dd".repeat(32));
  const resv = await listReservationsV4(config, { vaultId: VAULT_ID, agentPk: XO(agent) });
  assert.equal(resv.length, 1, "the claim record does not leak into the reservation scope");

  await markWalletRejected(config, req.requestId);
  const after = await store.pool().query(`SELECT key FROM transition_claims WHERE key LIKE 'resv-%'`);
  assert.equal(after.rowCount, 0, "rejection deleted the reservation row");
});

test("PG: two CONCURRENT over-budget builds — exactly one durable, one BUDGET_RESERVED_EXCEEDED (real PG arbitration)", { skip }, async () => {
  const owner = KEYOF(1);
  const agent = KEYOF(0x1e);
  const rec = KEYOF(0x28);
  await seedManifest(owner, [tightEntry(agent, rec)]); // fresh outpoint sweeps prior state
  const build = () =>
    buildWalletRequestV4({
      config, vaultId: VAULT_ID, action: "agentSpend",
      params: { payAmountSompi: (20n * KAS).toString(), agentPk: XO(agent), recipient: XO(rec) },
      signerAddress: ADDR(agent)
    });
  const results = await Promise.allSettled([build(), build()]);
  const ok = results.filter((r) => r.status === "fulfilled");
  const failed = results.filter((r) => r.status === "rejected");
  assert.equal(ok.length, 1, `exactly one wins (${JSON.stringify(results.map((r) => (r.status === "rejected" ? r.reason.code : "ok")))})`);
  assert.equal(failed[0].reason.code, "BUDGET_RESERVED_EXCEEDED");
  assert.ok(failed[0].reason.message.includes(ok[0].value.requestId));
  const rows = await store.pool().query(`SELECT key FROM transition_claims WHERE key LIKE 'resv-%'`);
  assert.equal(rows.rowCount, 1, "exactly one reservation row");
  await markWalletRejected(config, ok[0].value.requestId);
});

test("PG: build -> refuse -> reject -> rebuild -> finalize consumes (full lifecycle parity)", { skip }, async () => {
  const owner = KEYOF(1);
  const agent = KEYOF(0x1e);
  const rec = KEYOF(0x28);
  await seedManifest(owner, [tightEntry(agent, rec)]);
  const build = (kas) =>
    buildWalletRequestV4({
      config, vaultId: VAULT_ID, action: "agentSpend",
      params: { payAmountSompi: (kas * KAS).toString(), agentPk: XO(agent), recipient: XO(rec) },
      signerAddress: ADDR(agent)
    });
  const first = await build(20n);
  await assert.rejects(() => build(20n), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  await markWalletRejected(config, first.requestId);
  const second = await build(20n);
  assert.equal(second.state, RequestState.BUILT);

  const signer = makeDevSigner(config, { secretHex: SEC(0x1e), expectedAddress: ADDR(agent) });
  const signed = signer.signInputs(second.transaction.unsignedSafeJson, second.transaction.signInputs);
  const done = await finalizeWalletRequestV4({ config, requestId: second.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);

  const rows = await store.pool().query(`SELECT value->>'status' AS status, value->>'txId' AS txid FROM transition_claims WHERE key LIKE 'resv-%'`);
  assert.equal(rows.rowCount, 1);
  assert.equal(rows.rows[0].status, "CONSUMED");
  assert.equal(rows.rows[0].txid, done.txId);
  // consumed keeps counting: 20 consumed + 20 > 30
  await assert.rejects(() => build(20n), (e) => e.code === "BUDGET_RESERVED_EXCEEDED");
  // and the finalize transition claim EXISTS alongside (unchanged arbiter)
  const claims = await store.pool().query(`SELECT key FROM transition_claims WHERE key NOT LIKE 'resv%'`);
  assert.ok(claims.rowCount >= 1, "the finalize-time transition claim is present and untouched");
});
