"use strict";

/*
 * RC-LC-1 — PostgreSQL PARITY (owner remediation requirement 10).
 *
 * The JSON suite (rc-lc1-manifest-rebind.test.js) proves the full HTTP
 * lifecycle; THIS suite proves the STORE-DEPENDENT semantics of the fix
 * behave identically over a REAL PostgreSQL backend, where
 * createExclusive is INSERT ... ON CONFLICT (network_id, key) DO
 * NOTHING (rowCount 0 = refused) and the rebind's remove+createExclusive
 * re-arbitration is DELETE + a second INSERT. Driven at the module level
 * exactly like sdk/test/budget-reservation-pg.test.js (real builders,
 * real dev signer, real encoder + VM preflight at finalize; offline).
 *
 * SKIPPED cleanly without POLICYVAULT_TEST_PG_* (fresh uniquely-named
 * database on the shared cluster, created + dropped here).
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
const { makeDevSigner } = require("../src/signer-dev");
const wr4 = require("../src/wallet-requests-v4");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the RC-LC-1 PG parity suite";

let adminPool;
let config;
let store;
let kaspa;
let recordManifestForRequest;
let assertRequestManifestVerified;
const dbName = `pv_rclc1_${process.pid}_${Date.now() % 100000}`;

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rclc1pg-"))
  });
  store = await openPgStore(config, { migrate: true });
  kaspa = require(config.rustyKaspaModule);
  ({ recordManifestForRequest, assertRequestManifestVerified } = require("../../server/src/intent-records"));
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

const KAS = 100000000n;
const KEYOF = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();

function entry(agent, recipientKp) {
  return {
    agentPk: XO(agent), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (30n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipientKp)]
  };
}

let seedCounter = 0;
async function seedVault(owner, agent, recipientKp, vaultId) {
  seedCounter += 1;
  const outTxId = (0xc0 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const registry = [entry(agent, recipientKp)];
  const template = { owner: XO(owner), vaultId };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(),
    paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "rc-lc1-pg", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

/* Build + record + stamp, exactly the api finishBuilt order. */
async function buildSpend({ vaultId, owner, agent, recipientKp, paySompi }) {
  const request = await wr4.buildWalletRequestV4({
    config, vaultId, action: "agentSpend",
    params: { payAmountSompi: paySompi.toString(), agentPk: XO(agent), recipient: XO(recipientKp) },
    signerAddress: ADDR(agent)
  });
  const rec = await recordManifestForRequest(config, request, { proposalId: null });
  request.manifestHash = rec.manifestHash;
  await wr4.saveRequest(config, request);
  return request;
}

async function signAndFinalize(request, agent, agentSecret) {
  const signer = makeDevSigner(config, { secretHex: SEC(agentSecret), expectedAddress: ADDR(agent) });
  const signedSafeJson = signer.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  const durable = await wr4.loadRequest(config, request.requestId);
  await assertRequestManifestVerified(config, durable); // the route's pre-finalize gate
  return wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson });
}

test("PG parity: reject -> identical rebuild SHARES the content-addressed record (INSERT..ON CONFLICT false) and finalizes to preflight", { skip }, async () => {
  const owner = KEYOF(1), agent = KEYOF(0x1e), recipientKp = KEYOF(0x28);
  const vaultId = "b1".repeat(32);
  await seedVault(owner, agent, recipientKp, vaultId);
  const r1 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  await wr4.markWalletRejected(config, r1.requestId);

  const r2 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  assert.equal(r2.manifestHash, r1.manifestHash, "identical intent, identical hash");
  assert.notEqual(r2.requestId, r1.requestId);
  const rec = await getStore(config).read(Categories.INTENT_MANIFEST, r2.manifestHash);
  assert.equal(rec.requestId, r1.requestId, "PG record keeps creator provenance (content-addressed, shared)");

  const fin = await signAndFinalize(r2, agent, 0x1e);
  assert.equal(fin.state, "PREFLIGHT_VERIFIED", "finalize binds by CONTENT over PG");
});

test("PG parity: two LIVE identical builds share one record; content gate passes, claim arbiter keeps finalize exclusivity", { skip }, async () => {
  const owner = KEYOF(1), agent = KEYOF(0x1e), recipientKp = KEYOF(0x28);
  const vaultId = "b2".repeat(32);
  await seedVault(owner, agent, recipientKp, vaultId);
  const r1 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  // free r1's reservation so the identical second build reaches the
  // recorder (reservation accounting is its own, separately-tested gate)
  const { releaseReservationForRequest } = require("../src/budget-reservation");
  await releaseReservationForRequest(config, r1);
  const r2 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  assert.notEqual(r2.requestId, r1.requestId, "distinct durable requests (C05 contract)");
  assert.equal(r2.txId, r1.txId);
  const rec = await getStore(config).read(Categories.INTENT_MANIFEST, r1.manifestHash);
  assert.equal(rec.requestId, r1.requestId, "creator provenance intact over PG");
  const f2 = await signAndFinalize(r2, agent, 0x1e);
  assert.equal(f2.state, "PREFLIGHT_VERIFIED", "the sharing request finalizes on CONTENT over PG");
  // broadcast exclusivity stays with the transition-claim arbiter:
  // the duplicate's finalize refuses fail-closed (designed layer,
  // untouched by this remediation)
  await assert.rejects(signAndFinalize(r1, agent, 0x1e), (e) => e.code === "CLAIM_CONFLICT");
});

test("PG parity: idempotent replay of the same request reuses its own record", { skip }, async () => {
  const owner = KEYOF(1), agent = KEYOF(0x1e), recipientKp = KEYOF(0x28);
  const vaultId = "b3".repeat(32);
  await seedVault(owner, agent, recipientKp, vaultId);
  const r1 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  const durable = await wr4.loadRequest(config, r1.requestId);
  const replay = await recordManifestForRequest(config, durable, { proposalId: null });
  assert.equal(replay.ok, true);
  const rec = await getStore(config).read(Categories.INTENT_MANIFEST, r1.manifestHash);
  assert.equal(rec.requestId, r1.requestId, "binding unchanged on PG replay");
});

test("PG parity: an ORPHAN record (creator request missing) is shared safely — content is the gate, and jsonb round-trip re-hashes intact", { skip }, async () => {
  const owner = KEYOF(1), agent = KEYOF(0x1e), recipientKp = KEYOF(0x28);
  const vaultId = "b4".repeat(32);
  await seedVault(owner, agent, recipientKp, vaultId);
  const r1 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  await wr4.markWalletRejected(config, r1.requestId);
  // orphan: creator points at a request that no longer exists — content
  // addressing makes this harmless (the record IS the manifest evidence)
  const rec = await getStore(config).read(Categories.INTENT_MANIFEST, r1.manifestHash);
  rec.requestId = "00000000-0000-4000-8000-000000000000";
  await getStore(config).write(Categories.INTENT_MANIFEST, r1.manifestHash, rec);
  const r2 = await buildSpend({ vaultId, owner, agent, recipientKp, paySompi: 4n * KAS });
  assert.equal(r2.manifestHash, r1.manifestHash);
  const f2 = await signAndFinalize(r2, agent, 0x1e);
  assert.equal(f2.state, "PREFLIGHT_VERIFIED", "orphan-creator record shared + finalized on content over PG (jsonb G-2 re-hash intact)");
});
