"use strict";

/*
 * POSTGRESQL INTEGRATION — above-threshold approval lifecycle THROUGH the
 * postgres store (Phase G defect G-2 regression, production-shaped).
 *
 * The real Phase G human run proved the JSON-backend approval lifecycle
 * tests could not catch a postgres-only defect: jsonb re-orders object
 * keys, so the key-order-sensitive package commitment "mutated" across the
 * store round trip and finalize failed PACKAGE_MUTATED with every value
 * intact. This test runs the FULL collect→finalize lifecycle with the
 * durable request/package persisted in a REAL PostgreSQL database:
 *   build (AWAITING_APPROVALS) → approval #1 (package frozen + stored via
 *   jsonb) → approval #2 (package RELOADED from jsonb — the pre-fix code
 *   failed exactly here) → finalize (agent signature) → VM preflight PASS.
 *
 * SKIPPED cleanly when POLICYVAULT_TEST_PG_* is not set (project
 * convention — the checkpoint gate runs it against the live instance).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { buildWalletRequestV4, finalizeWalletRequestV4, collectApprovalV4, RequestState } = require("../src/wallet-requests-v4");
const { makeDevSigner } = require("../src/signer-dev");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL integration";

let adminPool = null;
let pgStore = null;
let config = null;
const DB_NAME = `pv_pgapproval_${process.pid}`;

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  await adminPool.query(`DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE)`).catch(() => {});
  await adminPool.query(`CREATE DATABASE ${DB_NAME}`);
  config = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: DB_NAME,
    pgNoTls: true,
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-pgapproval-"))
  });
  pgStore = await openPgStore(config, { migrate: true });
});

after(async () => {
  if (!PG_AVAILABLE) return;
  if (pgStore) { try { await pgStore.close(); } catch { /* already closed */ } }
  if (adminPool) {
    await adminPool.query(`DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE)`).catch(() => {});
    await adminPool.end();
  }
});

test("PG: above-threshold approvals collect + finalize survive the jsonb round trip (G-2)", { skip }, async () => {
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const KAS = 100000000n;

  const owner = KEY(1);
  const agent = KEY(0x1e);
  const recipient = KEY(0x28);
  const approver1 = KEY(20);
  const approver2 = KEY(21);
  const VAULT_ID = "77".repeat(32);
  const template = { owner: XO(owner), vaultId: VAULT_ID };

  const entry = {
    agentPk: XO(agent), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipient)]
  };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root,
    approvers: [XO(approver1), XO(approver2)], approvalM: "2", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: config.networkId,
    vaultId: VAULT_ID,
    label: "pg approval regression",
    status: "ACTIVE",
    template,
    agentRegistry: [entry],
    live: {
      state: stateToJsonV4(state),
      stateId: computeStateIdV4({ networkId: config.networkId, template, state }),
      outpoint: { transactionId: "78".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "41".repeat(32)
    },
    creationTxId: "42".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });

  // Above-threshold spend: 6 KAS > 5 KAS threshold, agent-owned fuel.
  const req = await buildWalletRequestV4({
    config, vaultId: VAULT_ID, action: "agentSpend",
    params: {
      payAmountSompi: (6n * KAS).toString(), agentPk: XO(agent), recipient: XO(recipient),
      fuel: { outpoint: { transactionId: "79".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agent)}ac` }
    },
    signerAddress: ADDR(agent)
  });
  assert.equal(req.state, RequestState.AWAITING_APPROVALS);

  const approverSignedJson = (kp, secret) => {
    const signer = makeDevSigner(config, { secretHex: SEC(secret), expectedAddress: ADDR(kp) });
    return signer.signInputs(req.transaction.unsignedSafeJson, [{ index: 0 }]);
  };

  // Approval #1 creates + freezes the package and stores it through jsonb.
  const r1 = await collectApprovalV4({ config, requestId: req.requestId, approverAddress: ADDR(approver1), signedSafeJson: approverSignedJson(approver1, 20) });
  assert.equal(r1.approvals.collected, 1);

  // Approval #2 RELOADS the jsonb-round-tripped package — the pre-fix code
  // failed here with PACKAGE_MUTATED despite every value being intact.
  const r2 = await collectApprovalV4({ config, requestId: req.requestId, approverAddress: ADDR(approver2), signedSafeJson: approverSignedJson(approver2, 21) });
  assert.equal(r2.approvals.complete, true);
  assert.equal(r2.request.state, RequestState.BUILT);

  // Agent signs the frozen bytes; finalize must accept the stored package.
  const agentSigner = makeDevSigner(config, { secretHex: SEC(0x1e), expectedAddress: ADDR(agent) });
  const signed = agentSigner.signInputs(req.transaction.unsignedSafeJson, req.transaction.signInputs);
  const done = await finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(done.state, RequestState.PREFLIGHT_VERIFIED);
  assert.equal(done.txId, req.txId, "the finalized transaction is the exact frozen transaction the approvers signed");
});
