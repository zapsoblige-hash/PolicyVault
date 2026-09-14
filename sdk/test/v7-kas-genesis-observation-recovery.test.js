"use strict";
/*
 * SDK / CRASH-RECOVERY — RC32-03 replacement (fullscale-rc33, 2026-09-10): a KAS treasury genesis whose broadcast
 * outcome is UNCERTAIN is recovered by OBSERVATION ONLY through the SAME durable request. A repeated submit never
 * re-broadcasts, never asks for a new signature and never creates a replacement; the request id, the frozen txid and
 * the signed bytes are preserved; a request that carried a broadcast is never withdrawn; the recovery path belongs to
 * the OPERABLE set (it keeps working after the creation kill switch removed the KAS profile from the CREATABLE set),
 * while a signed-but-never-broadcast genesis is refused by the same switch (RC32-02 parity for the KAS profile).
 * Mainnet-LABELLED test config, in-process mock node, TEST keys; nothing leaves the process.
 * REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) without silverc / the encoder.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../src/config");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const wr7kas = require("../src/wallet-requests-v7-kas");
const { loadManifestV7Kas } = require("../src/manifest-v7-kas");
const { covenantAddress } = require("../src/chain");
const { getStore, Categories } = require("../src/store");
const { createHarness } = require("./helpers/v7-kas-mock-harness");

const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-obs-probe-")) });
const available = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const KAS_V = "policyvault-0.7-kas";

function mainnetConfig(over = {}) {
  const saved = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    return loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", ...over });
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = saved;
  }
}
const spy = (rpc) => { const s = { calls: 0, rpc: { ...rpc, async submitTransaction(a) { s.calls += 1; return rpc.submitTransaction(a); } } }; return s; };

test("KAS genesis with an UNCERTAIN broadcast outcome: repeated submits observe only (no rebroadcast, no new signature, no replacement); withdrawal refused; recovery survives the creation kill switch; the original request settles by chain proof", { skip: SKIP }, async () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-observation-"));
  const cfgOn = mainnetConfig({ dataRoot });
  const H = createHarness(cfgOn);
  const c = H.ctx();
  const rpc = H.mockRpc();
  const rootCovenantId = await H.rootGenesis(cfgOn, c, rpc);

  /* build + sign (the funder's wallet signs ONCE) */
  const built = await wr7kas.buildKasVaultGenesisRequest({ config: cfgOn, rootCovenantId, label: "observation-only recovery", agents: [c.policy], approvers: [H.XO(c.approver1)], approvalM: 1, recoveryAddress: H.ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder, 200n * H.KAS)] });
  assert.equal(built.state, "BUILT");
  const signedJson = H.signAll(built.transaction.unsignedSafeJson, built.transaction.signInputs.map((s) => [s.index, c.funder]));
  const finalized = await wr7kas.finalizeKasWalletRequest({ config: cfgOn, requestId: built.requestId, signedSafeJson: signedJson });
  assert.equal(finalized.state, "SIGNED");
  const signedRecord = await wr7kas.loadKasWalletRequest(cfgOn, built.requestId);
  assert.equal(typeof signedRecord.signedSafeJson, "string");
  const outIndex = Number(built.build.vaultOutputIndex);
  const vaultAddress = covenantAddress(cfgOn, Buffer.from(built.build.vaultScriptHex, "hex"));

  /* 1. the broadcast is accepted by the node but the vault output is NOT observed: RECONCILIATION_REQUIRED, claim held */
  const s1 = spy(rpc);
  await assert.rejects(() => wr7kas.submitKasWalletRequest({ config: cfgOn, requestId: built.requestId, rpc: s1.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s1.calls, 1, "exactly one broadcast");
  const afterFirst = await wr7kas.loadKasWalletRequest(cfgOn, built.requestId);
  assert.equal(afterFirst.state, "RECONCILIATION_REQUIRED");
  assert.equal(afterFirst.txId, built.txId, "the frozen txid is the durable identity");
  assert.ok(await getStore(cfgOn).read(Categories.SUBMISSION_CLAIM, built.txId), "the submission claim is held while the outcome is uncertain");
  assert.equal(await loadManifestV7Kas(cfgOn, built.vaultId), null, "no treasury record before chain proof");

  /* 2. a request that carried a broadcast is NEVER withdrawn */
  const rejected = await wr7kas.markKasWalletRejected(cfgOn, built.requestId);
  assert.equal(rejected.state, "RECONCILIATION_REQUIRED", "withdrawal of an uncertain genesis is refused (state unchanged)");

  /* 3. repeated submits are observation-only — also on the SAME data after the creation kill switch */
  const cfgOff = mainnetConfig({ dataRoot, mainnetCreationDisabled: [KAS_V] });
  assert.ok(cfgOff.mainnetCreationDisabled.has(KAS_V));
  const Hoff = createHarness(cfgOff);
  for (const cfg of [cfgOn, cfgOff]) {
    const s = spy(rpc);
    await assert.rejects(() => wr7kas.submitKasWalletRequest({ config: cfg, requestId: built.requestId, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
    assert.equal(s.calls, 0, "a repeated submit of an uncertain genesis never rebroadcasts");
    const again = await wr7kas.loadKasWalletRequest(cfg, built.requestId);
    assert.equal(again.state, "RECONCILIATION_REQUIRED");
    assert.equal(again.txId, built.txId);
    assert.equal(again.signedSafeJson, signedRecord.signedSafeJson, "the signed bytes are preserved — no new signature is ever requested");
    assert.equal(again.requestId, built.requestId);
  }
  /* control: with creation disabled a NEW genesis is refused before any durable write, while the recovery above kept working */
  const rowsBefore = (await getStore(cfgOff).listValues(Categories.REQUEST, { strict: true })).length;
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ config: cfgOff, rootCovenantId, label: "refused", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: Hoff.ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: Hoff.ADDR(c.funder), funding: [Hoff.fuelUtxoFor(c.funder, 200n * Hoff.KAS)] }), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  assert.equal((await getStore(cfgOff).listValues(Categories.REQUEST, { strict: true })).length, rowsBefore, "a refused creation writes nothing");
  /* control: a SIGNED genesis that was never broadcast cannot be submitted after the switch (KAS parity with RC32-02) */
  const late = await wr7kas.buildKasVaultGenesisRequest({ config: cfgOn, rootCovenantId, label: "signed before the switch", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: H.ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder, 200n * H.KAS)] });
  const lateFinalized = await wr7kas.finalizeKasWalletRequest({ config: cfgOn, requestId: late.requestId, signedSafeJson: H.signAll(late.transaction.unsignedSafeJson, late.transaction.signInputs.map((s) => [s.index, c.funder])) });
  assert.equal(lateFinalized.state, "SIGNED");
  const sLate = spy(rpc);
  await assert.rejects(() => wr7kas.submitKasWalletRequest({ config: cfgOff, requestId: late.requestId, rpc: sLate.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  assert.equal(sLate.calls, 0, "the node is never asked to broadcast a refused pre-switch genesis");
  assert.equal((await wr7kas.loadKasWalletRequest(cfgOff, late.requestId)).state, "SIGNED", "the refused genesis keeps its durable state (never SUBMITTED)");

  /* 4. the chain settles: the SAME request completes by observation on the disabled image — still one broadcast in total */
  rpc.seed(vaultAddress, H.utxo(vaultAddress, built.txId, outIndex, built.build.frozen.outputs[outIndex].value, built.build.covenantId));
  const s4 = spy(rpc);
  const settled = await wr7kas.submitKasWalletRequest({ config: cfgOff, requestId: built.requestId, rpc: s4.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(s4.calls, 0, "settlement is observed, never rebroadcast");
  assert.equal(settled.state, "CHAIN_VERIFIED");
  assert.equal(settled.requestId, built.requestId);
  assert.equal(settled.txId, built.txId);
  assert.equal(settled.chain.successorOutpoint, `${built.txId}:${outIndex}`);
  const manifest = await loadManifestV7Kas(cfgOff, built.vaultId);
  assert.equal(manifest.status, "ACTIVE");
  assert.equal(manifest.creationTxId, built.txId);
  assert.equal(manifest.orgRootCovenantId, rootCovenantId);
  assert.ok((await wr7.loadOrgRoot(cfgOff, rootCovenantId)).vaults.includes(built.vaultId), "the root lists the settled treasury");
  assert.equal(await getStore(cfgOff).read(Categories.SUBMISSION_CLAIM, built.txId), null, "the submission claim is released by chain proof");
  /* 5. a further submit of a CHAIN_VERIFIED genesis is idempotent (no broadcast, no state change) */
  const s5 = spy(rpc);
  const again = await wr7kas.submitKasWalletRequest({ config: cfgOff, requestId: built.requestId, rpc: s5.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(s5.calls, 0);
  assert.equal(again.state, "CHAIN_VERIFIED");
  assert.equal((await wr7kas.listKasWalletRequests(cfgOff, {})).filter((r) => r.kind === "kasGenesis" && r.state === "CHAIN_VERIFIED").length, 1, "exactly one settled genesis — no replacement was ever created");
  fs.rmSync(dataRoot, { recursive: true, force: true });
});
