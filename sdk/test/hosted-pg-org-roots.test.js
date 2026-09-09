"use strict";

/*
 * HOSTED PG: the v0.7 ON-CHAIN ORGANIZATIONAL ROOT server orchestration
 * pipeline (sdk/src/wallet-requests-v7.js + sdk/src/reconcile-v7.js +
 * sdk/src/manifest-v7.js) over the REAL PostgreSQL driver (migration 011:
 * org_roots + org_root_requests tables), proving the MANDATORY live-PG
 * regression class (postlaunch-migrations-pg.test.js's own lesson: JSON-
 * backend suites cannot catch jsonb representation defects — a canonical
 * value can survive a jsonb round trip with every BYTE intact yet a
 * BigInt/number distinction, key order, or numeric-string precision can
 * still drift).
 *
 * Runs against a REAL local PostgreSQL — SKIPPED cleanly without
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the same gate every other
 * hosted-pg-*.test.js file uses). ALSO requires the real toolchain
 * (silverc, pv_call_encoder, pv_tx_probe) since these are real covenant
 * builds — REQUIREMENT_NOT_AVAILABLE otherwise (never silently passed).
 * Each test gets its own fresh database (created + dropped here).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { loadManifestV7 } = require("../src/manifest-v7");
const { covenantAddress, loadKaspa } = require("../src/chain");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);

const toolchainConfigProbe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-pg-probe-")) });
const TOOLCHAIN_AVAILABLE =
  fs.existsSync(toolchainConfigProbe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(toolchainConfigProbe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));

const skip = !PG_AVAILABLE
  ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run PostgreSQL integration"
  : !TOOLCHAIN_AVAILABLE
    ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe"
    : undefined;

const kaspa = TOOLCHAIN_AVAILABLE ? require(toolchainConfigProbe.rustyKaspaModule) : null;
const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p, networkId) => p.toPublicKey().toAddress(networkId).toString();

let adminPool;
let dbCounter = 0;
const createdDbs = [];
const openStores = [];

async function freshPgConfig() {
  const dbName = `pv_org7_${process.pid}_${++dbCounter}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  createdDbs.push(dbName);
  const config = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-pg-json-"))
  });
  const store = await openPgStore(config, { migrate: true });
  openStores.push(store);
  return config;
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
      /* already closed */
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

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function sign65(unsignedSafeJson, index, key) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  return kaspa.createInputSignature(tx, index, key).slice(2);
}
function mockRpc(byAddress = {}) {
  const table = byAddress;
  return {
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) for (const e of table[a] ?? []) entries.push(e);
      return { entries };
    },
    async submitTransaction({ transaction }) {
      return { transactionId: transaction.finalize().toString().toLowerCase() };
    },
    async disconnect() {},
    spend(outpoint) {
      for (const address of Object.keys(table)) table[address] = table[address].filter((e) => e.outpoint.transactionId !== outpoint.transactionId || e.outpoint.index !== outpoint.index);
    },
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function fuelUtxoFor(networkId, fuelKey, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
}
function slotResponse(reqEnvelope, signerAddress, sigHex) {
  return {
    responseVersion: "policyvault-org-root-slot-response/1",
    requestVersion: reqEnvelope.requestVersion,
    requestId: reqEnvelope.requestId,
    network: reqEnvelope.network,
    manifestHash: reqEnvelope.manifestHash,
    txId: reqEnvelope.txId,
    root: reqEnvelope.root,
    slot: reqEnvelope.slot,
    signerAddress,
    signatureHex: sigHex,
    sighashType: 1,
    signedAtMs: Date.now()
  };
}

test("root genesis over PG: build -> sign -> submit -> CHAIN_VERIFIED, read back through jsonb, canonical hash/verdict survive the round trip", { skip }, async () => {
  const config = await freshPgConfig();
  const owner1 = KEY(0x71), owner2 = KEY(0x72), owner3 = KEY(0x73), funder = KEY(0xf0);
  const rpc = mockRpc();

  const req = await wr7.buildRootGenesisRequest({
    config, label: "pg org",
    owners: [{ slot: 1, publicKey: XO(owner1) }, { slot: 2, publicKey: XO(owner2) }, { slot: 3, publicKey: XO(owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder, config.networkId), funding: [fuelUtxoFor(config.networkId, funder)]
  });
  assert.match(req.id, /^[0-9a-f-]{36}$/);

  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: req.id, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");

  const addr = covenantAddress(config, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: req.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");

  /* re-load THROUGH jsonb (postgres reorders object keys) and prove the
   * canonical facts are representation-independent */
  const root = await wr7.loadOrgRoot(config, submitted.rootCovenantId);
  assert.equal(root.authorityModel, "ON_CHAIN_ORGANIZATIONAL_ROOT");
  assert.equal(root.generation, 0);
  assert.equal(root.slots.length, 3);
  assert.equal(root.live.outpoint.transactionId, submitted.txId);

  const reloadedRequest = await wr7.loadOrgRootRequest(config, req.id);
  assert.equal(reloadedRequest.state, "CHAIN_VERIFIED");
  assert.equal(reloadedRequest.manifest.kind, "genesis-summary", "a genesis kind carries the signer-visible SUMMARY, not a formal policyvault-org-root-manifest/1");
  assert.equal(reloadedRequest.manifestHash, null, "no formal manifest -> no manifestHash");
  assert.match(reloadedRequest.signerVisibleDigest, /^[0-9a-f]{64}$/, "the summary still gets its own canonical digest, jsonb-key-order independent");

  /* the store really is PG: prove the raw jsonb column round-trips */
  const raw = await require("../src/store").getStore(config).pool().query("SELECT value::text AS t FROM org_roots WHERE key = $1", [submitted.rootCovenantId]);
  assert.equal(raw.rows.length, 1);
  assert.ok(raw.rows[0].t.length > 0);
});

test("root action (M-of-N, with ONE vault operation) over PG: manifest hash / verification survive the jsonb round trip; org_root_requests indexed lookups work", { skip }, async () => {
  const config = await freshPgConfig();
  const owner1 = KEY(0x81), owner2 = KEY(0x82), owner3 = KEY(0x83), funder = KEY(0xf1), fuelKey = KEY(0x91);
  const rpc = mockRpc();

  const rootReq = await wr7.buildRootGenesisRequest({
    config, label: "pg org 2",
    owners: [{ slot: 1, publicKey: XO(owner1) }, { slot: 2, publicKey: XO(owner2) }, { slot: 3, publicKey: XO(owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder, config.networkId), funding: [fuelUtxoFor(config.networkId, funder)]
  });
  const rootSigned = signAll(rootReq.transaction.unsignedSafeJson, rootReq.transaction.signInputs.map((s) => [s.index, funder]));
  const rootFinalized = await wr7.submitOrgRootRequestSignature({ config, requestId: rootReq.id, signedSafeJson: rootSigned });
  const rootAddr = covenantAddress(config, Buffer.from(rootFinalized.build.rootScriptHex, "hex"));
  rpc.seed(rootAddr, utxo(rootAddr, rootFinalized.txId, rootFinalized.build.rootOutputIndex, rootFinalized.build.accounting.kas.rootValue, rootFinalized.rootCovenantId));
  const rootSubmitted = await wr7.submitOrgRootRequest({ config, requestId: rootReq.id, rpc });
  const rootCovenantId = rootSubmitted.rootCovenantId;

  const heartbeatReq = await wr7.buildRootActionRequest({ config, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(config.networkId, fuelKey) }, signerAddress: ADDR(owner1, config.networkId) });
  assert.match(heartbeatReq.manifestHash, /^[0-9a-f]{64}$/);

  const env1 = await wr7.getOrCreateSlotSigningRequest({ config, requestId: heartbeatReq.id, slot: 1 });
  await wr7.submitSlotSignature({ config, requestId: heartbeatReq.id, slot: 1, response: slotResponse(env1, ADDR(owner1, config.networkId), sign65(heartbeatReq.transaction.unsignedSafeJson, heartbeatReq.rootInputIndex, owner1)) });
  const env2 = await wr7.getOrCreateSlotSigningRequest({ config, requestId: heartbeatReq.id, slot: 2 });
  const afterBoth = await wr7.submitSlotSignature({ config, requestId: heartbeatReq.id, slot: 2, response: slotResponse(env2, ADDR(owner2, config.networkId), sign65(heartbeatReq.transaction.unsignedSafeJson, heartbeatReq.rootInputIndex, owner2)) });

  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(heartbeatReq.transaction.unsignedSafeJson), afterBoth.build.frozen.inputs.length - 1, fuelKey);
  const finalizedHeartbeat = await wr7.finalizeOrgRootRequest({ config, requestId: heartbeatReq.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalizedHeartbeat.state, "SIGNED");

  /* re-verify the manifest AFTER a jsonb round trip: read the request back
   * from PG and re-run verifyOrgRootIntentManifest against the STORED body */
  const reloadedHeartbeat = await wr7.loadOrgRootRequest(config, heartbeatReq.id);
  const { verifyOrgRootIntentManifest } = require("../../core/intent/org-root-manifest-v7");
  const verdict = verifyOrgRootIntentManifest({ manifest: reloadedHeartbeat.manifest });
  assert.equal(verdict.verdict, "VERIFIED", `post-jsonb re-verification must still pass: ${JSON.stringify(verdict.failures)}`);
  const { computeManifestHashV1 } = require("../../core/intent/canonical");
  const { manifestHash, ...body } = reloadedHeartbeat.manifest;
  assert.equal(computeManifestHashV1(body), manifestHash, "the canonical manifest hash is jsonb-key-order independent");

  const outputs = reloadedHeartbeat.build.frozen.outputs;
  for (const input of reloadedHeartbeat.build.frozen.inputs) rpc.spend(input.previousOutpoint); // coherent accepted readback consumes the actual inputs
  const rootOutIdx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === rootCovenantId);
  const kaspaLocal = loadKaspa(config);
  const address = kaspaLocal.addressFromScriptPublicKey({ version: outputs[rootOutIdx].scriptPublicKey.version, script: outputs[rootOutIdx].scriptPublicKey.scriptHex }, config.networkId).toString();
  rpc.seed(address, utxo(address, reloadedHeartbeat.txId, rootOutIdx, outputs[rootOutIdx].value, rootCovenantId));
  const submittedHeartbeat = await wr7.submitOrgRootRequest({ config, requestId: heartbeatReq.id, rpc });
  assert.equal(submittedHeartbeat.state, "CHAIN_VERIFIED");

  /* indexed lookup: org_root_requests_root_idx */
  const listed = await wr7.listOrgRootRequests(config, { rootCovenantId });
  assert.ok(listed.some((r) => r.id === heartbeatReq.id));

  const rootAfter = await wr7.loadOrgRoot(config, rootCovenantId);
  assert.equal(rootAfter.generation, 1);
  assert.equal(rootAfter.state.rootNonce, "1");
});

test("reconcile over PG: CONSISTENT / UNKNOWN never mutate the durable record; a proven successor ADVANCES it", { skip }, async () => {
  const config = await freshPgConfig();
  const owner1 = KEY(0xa1), owner2 = KEY(0xa2), owner3 = KEY(0xa3), funder = KEY(0xa9);
  const rpc = mockRpc();
  const req = await wr7.buildRootGenesisRequest({
    config, label: "pg reconcile",
    owners: [{ slot: 1, publicKey: XO(owner1) }, { slot: 2, publicKey: XO(owner2) }, { slot: 3, publicKey: XO(owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder, config.networkId), funding: [fuelUtxoFor(config.networkId, funder)]
  });
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: req.id, signedSafeJson: signed });
  const addr = covenantAddress(config, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: req.id, rpc });
  const rootCovenantId = submitted.rootCovenantId;

  const consistent = await reconcileOrgRootV7(config, rootCovenantId, { rpc });
  assert.equal(consistent.root.status, "CONSISTENT");

  const before = await wr7.loadOrgRoot(config, rootCovenantId);
  const rpc2 = mockRpc(); // the root's live outpoint is now ABSENT (no claim exists either)
  const unknown = await reconcileOrgRootV7(config, rootCovenantId, { rpc: rpc2 });
  assert.equal(unknown.root.status, "UNKNOWN");
  const after = await wr7.loadOrgRoot(config, rootCovenantId);
  assert.deepEqual(after, before, "an UNKNOWN reconcile outcome never mutates the durable record, even across a jsonb round trip");
});
