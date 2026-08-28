"use strict";

/*
 * SDK layer — v0.2 reconcile-only proof standard + durable-claim adversarial
 * cases. Offline: a mock RPC returns controlled UTXO sets so every branch of
 * the exact proof-of-effect logic is exercised without a node. silverc is
 * used for real address derivation.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { normalizeTemplateV2, normalizeStateV2, computeStateIdV2, spendSuccessorV2, stateToJson } = require("../src/vault-state-v2");
const { compileExactStateV2 } = require("../src/contract-compiler-v2");
const { covenantAddress } = require("../src/chain");
const { MANIFEST_SCHEMA_V2, persistManifestV2, loadManifestV2 } = require("../src/manifest-v2");
const { claimTransition, loadTransitionClaim } = require("../src/submission-claim");
const { reconcileVaultV2, proveExpectedEffect } = require("../src/reconcile-v2");
const { VaultStatus } = require("../src/manifest");

const PK = (n) => n.toString(16).padStart(2, "0").repeat(32);

function tempConfig() {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv2-recon-"));
  return loadConfig({ dataRoot });
}

/* Build an ACTIVE v0.2 vault on disk and return everything the tests need. */
async function setupVault(config) {
  const vaultId = crypto.randomBytes(32).toString("hex");
  const template = normalizeTemplateV2({ owner: PK(1), vaultId });
  const state = normalizeStateV2({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: PK(2),
    maxPerSpend: "10000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "600",
    recipients: [PK(3), PK(4), PK(5)],
    delegateActive: "1",
    policyNonce: "0"
  });
  const stateId = computeStateIdV2({ networkId: config.networkId, template, state });
  const compiled = compileExactStateV2({ config, template, state });
  const address = covenantAddress(config, compiled.scriptBytes);
  const covenantId = crypto.randomBytes(32).toString("hex");
  const creationTxId = crypto.randomBytes(32).toString("hex");
  const predecessorOutpoint = { transactionId: creationTxId, index: 0 };

  await persistManifestV2(config, {
    schema: MANIFEST_SCHEMA_V2,
    contractVersion: "policyvault-0.2",
    networkId: config.networkId,
    vaultId,
    label: "recon",
    status: VaultStatus.ACTIVE,
    template: { owner: template.owner, vaultId: template.vaultId },
    live: {
      state: stateToJson(state),
      stateId,
      outpoint: predecessorOutpoint,
      outpointValue: state.protectedValue.toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId
    },
    creationTxId,
    latestTransitionTxId: null,
    lastTransition: null
  });

  return { vaultId, template, state, stateId, address, covenantId, predecessorOutpoint };
}

/* Mock RPC whose getUtxosByAddresses returns entries from `byAddress`. */
function mockRpc(byAddress) {
  return {
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) {
        for (const e of byAddress[a] ?? []) {
          entries.push(e);
        }
      }
      return { entries };
    },
    async disconnect() {}
  };
}

function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: amountSompi, covenantId };
}

test("CONSISTENT: predecessor live, no claim", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const rpc = mockRpc({ [v.address]: [utxo(v.address, v.predecessorOutpoint.transactionId, 0, "100000000000", v.covenantId)] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "CONSISTENT");
});

test("ADVANCED: predecessor gone, successor proven exactly", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const successor = spendSuccessorV2(v.state, 4_000_000_000n);
  const successorCompiled = compileExactStateV2({ config, template: v.template, state: successor });
  const successorAddress = covenantAddress(config, successorCompiled.scriptBytes);
  const successorStateId = computeStateIdV2({ networkId: config.networkId, template: v.template, state: successor });
  const txId = crypto.randomBytes(32).toString("hex");

  await claimTransition(config, {
    outpoint: v.predecessorOutpoint,
    action: "delegateSpend",
    txId,
    vaultId: v.vaultId,
    stateId: v.stateId,
    expected: {
      kind: "successor",
      txId,
      index: 1,
      valueSompi: successor.protectedValue.toString(),
      covenantId: v.covenantId,
      scriptSha256: successorCompiled.scriptSha256,
      stateId: successorStateId,
      address: successorAddress,
      state: stateToJson(successor),
      action: "delegateSpend",
      contractVersion: "policyvault-0.2"
    }
  });

  // Predecessor gone; successor present at exact address/value/covenantId.
  const rpc = mockRpc({
    [v.address]: [],
    [successorAddress]: [utxo(successorAddress, txId, 1, successor.protectedValue.toString(), v.covenantId)]
  });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "ADVANCED");
  assert.equal(r.stateId, successorStateId);
  const m = await loadManifestV2(config, v.vaultId);
  assert.equal(m.live.outpoint.transactionId, txId);
  assert.equal(m.live.outpoint.index, 1);
  assert.equal(m.live.state.protectedValue, successor.protectedValue);
});

test("UNKNOWN: predecessor gone, successor absent (fail closed)", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const successor = spendSuccessorV2(v.state, 4_000_000_000n);
  const successorCompiled = compileExactStateV2({ config, template: v.template, state: successor });
  const successorAddress = covenantAddress(config, successorCompiled.scriptBytes);
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, {
    outpoint: v.predecessorOutpoint,
    action: "delegateSpend",
    txId,
    vaultId: v.vaultId,
    stateId: v.stateId,
    expected: {
      kind: "successor",
      txId,
      index: 1,
      valueSompi: successor.protectedValue.toString(),
      covenantId: v.covenantId,
      scriptSha256: successorCompiled.scriptSha256,
      stateId: computeStateIdV2({ networkId: config.networkId, template: v.template, state: successor }),
      address: successorAddress,
      state: stateToJson(successor),
      action: "delegateSpend",
      contractVersion: "policyvault-0.2"
    }
  });
  const rpc = mockRpc({ [v.address]: [], [successorAddress]: [] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "UNKNOWN");
  assert.equal((await loadManifestV2(config, v.vaultId)).status, VaultStatus.TERMINATED_UNKNOWN);
});

test("UNKNOWN: successor present but WRONG value is not proof", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const successor = spendSuccessorV2(v.state, 4_000_000_000n);
  const successorCompiled = compileExactStateV2({ config, template: v.template, state: successor });
  const successorAddress = covenantAddress(config, successorCompiled.scriptBytes);
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, {
    outpoint: v.predecessorOutpoint,
    action: "delegateSpend",
    txId,
    vaultId: v.vaultId,
    stateId: v.stateId,
    expected: {
      kind: "successor",
      txId,
      index: 1,
      valueSompi: successor.protectedValue.toString(),
      covenantId: v.covenantId,
      scriptSha256: successorCompiled.scriptSha256,
      stateId: computeStateIdV2({ networkId: config.networkId, template: v.template, state: successor }),
      address: successorAddress,
      state: stateToJson(successor),
      action: "delegateSpend",
      contractVersion: "policyvault-0.2"
    }
  });
  // Off by one sompi.
  const rpc = mockRpc({ [v.address]: [], [successorAddress]: [utxo(successorAddress, txId, 1, (successor.protectedValue - 1n).toString(), v.covenantId)] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "UNKNOWN");
});

test("UNKNOWN: predecessor gone, no claim (fail closed)", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const rpc = mockRpc({ [v.address]: [] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "UNKNOWN");
  assert.equal((await loadManifestV2(config, v.vaultId)).status, VaultStatus.TERMINATED_UNKNOWN);
});

test("CLAIM_PENDING: predecessor live, claim too fresh to release", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, { outpoint: v.predecessorOutpoint, action: "delegateSpend", txId, vaultId: v.vaultId, stateId: v.stateId, expected: null });
  const rpc = mockRpc({ [v.address]: [utxo(v.address, v.predecessorOutpoint.transactionId, 0, "100000000000", v.covenantId)] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc, stalePendingMinimumMs: 60_000 });
  assert.equal(r.status, "CLAIM_PENDING");
  assert.ok(await loadTransitionClaim(config, v.predecessorOutpoint), "claim must be preserved");
});

test("CLAIM_RELEASED: predecessor live, stale never-confirmed claim removed", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, { outpoint: v.predecessorOutpoint, action: "delegateSpend", txId, vaultId: v.vaultId, stateId: v.stateId, expected: null });
  const rpc = mockRpc({ [v.address]: [utxo(v.address, v.predecessorOutpoint.transactionId, 0, "100000000000", v.covenantId)] });
  // minimum 0 => immediately releasable; predecessor live, no effect.
  const r = await reconcileVaultV2(config, v.vaultId, { rpc, stalePendingMinimumMs: 0 });
  assert.equal(r.status, "CLAIM_RELEASED");
  assert.equal(await loadTransitionClaim(config, v.predecessorOutpoint), null, "claim must be removed");
});

test("CLAIM_PENDING when release disabled even if stale", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, { outpoint: v.predecessorOutpoint, action: "delegateSpend", txId, vaultId: v.vaultId, stateId: v.stateId, expected: null });
  const rpc = mockRpc({ [v.address]: [utxo(v.address, v.predecessorOutpoint.transactionId, 0, "100000000000", v.covenantId)] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc, stalePendingMinimumMs: 0, allowClaimRelease: false });
  assert.equal(r.status, "CLAIM_PENDING");
  assert.ok(await loadTransitionClaim(config, v.predecessorOutpoint));
});

test("ADVANCED recover: predecessor gone, owner payout proven", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const ownerAddress = "kaspatest:qtestowneraddressplaceholder000000000000000000000000000000";
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, {
    outpoint: v.predecessorOutpoint,
    action: "ownerRecover",
    txId,
    vaultId: v.vaultId,
    stateId: v.stateId,
    expected: { kind: "recover", txId, index: 0, valueSompi: v.state.protectedValue.toString(), ownerAddress, contractVersion: "policyvault-0.2" }
  });
  const rpc = mockRpc({ [v.address]: [], [ownerAddress]: [utxo(ownerAddress, txId, 0, v.state.protectedValue.toString(), undefined)] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "ADVANCED");
  assert.equal(r.to, "RECOVERED");
  assert.equal((await loadManifestV2(config, v.vaultId)).status, VaultStatus.RECOVERED);
});

test("UNKNOWN recover: owner payout absent is not proof", async () => {
  const config = tempConfig();
  const v = await setupVault(config);
  const ownerAddress = "kaspatest:qtestowneraddressplaceholder000000000000000000000000000000";
  const txId = crypto.randomBytes(32).toString("hex");
  await claimTransition(config, {
    outpoint: v.predecessorOutpoint,
    action: "ownerRecover",
    txId,
    vaultId: v.vaultId,
    stateId: v.stateId,
    expected: { kind: "recover", txId, index: 0, valueSompi: v.state.protectedValue.toString(), ownerAddress, contractVersion: "policyvault-0.2" }
  });
  const rpc = mockRpc({ [v.address]: [], [ownerAddress]: [] });
  const r = await reconcileVaultV2(config, v.vaultId, { rpc });
  assert.equal(r.status, "UNKNOWN");
});

test("proveExpectedEffect rejects wrong covenantId and unknown kinds", async () => {
  const addr = "kaspatest:qexample";
  const txId = "aa".repeat(32);
  const okRpc = mockRpc({ [addr]: [utxo(addr, txId, 1, "5", "cc".repeat(32))] });
  // wrong covenantId
  assert.equal(
    await proveExpectedEffect(okRpc, { expected: { kind: "successor", txId, index: 1, valueSompi: "5", covenantId: "dd".repeat(32), address: addr } }),
    null
  );
  // correct
  assert.ok(
    await proveExpectedEffect(okRpc, { expected: { kind: "successor", txId, index: 1, valueSompi: "5", covenantId: "cc".repeat(32), address: addr } })
  );
  // unknown kind
  assert.equal(await proveExpectedEffect(okRpc, { expected: { kind: "wat" } }), null);
  // no expected
  assert.equal(await proveExpectedEffect(okRpc, {}), null);
});
