"use strict";
/*
 * SDK / CRASH-RECOVERY — v0.7 mainnet enablement (2026-09-10): the VERIFIED ROLLBACK ROUTE.
 *
 * Rollback of the v0.7 enablement is NOT "restore an old database snapshot" and NOT "return to
 * the rc31 gate" (either would strand on-chain v0.7 organizations / KAS treasuries that exist
 * by then). Rollback is the SAME software image with NEW creation switched off
 * (POLICYVAULT_MAINNET_CREATION_DISABLED) while every EXISTING root / treasury stays fully
 * manageable — delegates keep paying, approvers keep approving, owners keep governing, the
 * reconciler keeps proving. This test drives the REAL v0.7 builders / finalizers / submitters /
 * reconciler on a MAINNET-LABELLED test config against a mock node (test keys only, nothing
 * leaves the process) and proves both halves of that claim, plus that a genesis built BEFORE the
 * switch cannot be submitted AFTER it (genesis submit is a creation entry).
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
const { loadManifestV7Kas, listRootedKasVaultsV7 } = require("../src/manifest-v7-kas");
const { reconcileOrgRootV7, reconcileVault } = require("../src/reconcile-v7");
const { getStore, Categories } = require("../src/store");
const { createHarness } = require("./helpers/v7-kas-mock-harness");

const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-rb-probe-")) });
const available = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const KAS_V = "policyvault-0.7-kas";
const ROOT_V = "policyvault-0.7-root";

function mainnetConfig(over = {}) {
  const saved = process.env.POLICYVAULT_ALLOW_MAINNET;
  process.env.POLICYVAULT_ALLOW_MAINNET = "true";
  try {
    return loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", ...over });
  } finally {
    if (saved === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = saved;
  }
}
const requestCount = async (cfg) => (await getStore(cfg).listValues(Categories.REQUEST, { strict: true })).length;
const KILL_SENTENCE = (v) => `mainnet: creation of covenant generation "${v}" is DISABLED by operator configuration (POLICYVAULT_MAINNET_CREATION_DISABLED) — refusing this new genesis (fail closed).`;

test("ROLLBACK ROUTE: creation disabled for the KAS profile on the same image — every NEW treasury refuses before any durable write, a pre-switch genesis cannot be submitted, and EXISTING treasuries stay fully manageable (payments, approvals, owner operations, reconcile, listing)", { skip: SKIP }, async () => {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-rollback-"));
  /* ---- BEFORE the switch: the enabled image creates a root and a treasury (mainnet-labelled, mock node) ---- */
  const cfgOn = mainnetConfig({ dataRoot });
  assert.equal(cfgOn.networkId, "mainnet");
  const H = createHarness(cfgOn);
  const c = H.ctx();
  const rpc = H.mockRpc();
  const rootCovenantId = await H.rootGenesis(cfgOn, c, rpc);
  const { vaultId } = await H.kasGenesis(cfgOn, c, rpc, rootCovenantId);
  assert.equal((await loadManifestV7Kas(cfgOn, vaultId)).status, "ACTIVE");
  /* a second treasury BUILT (funder not yet signed) before the switch — the durable request exists */
  const pending = await wr7kas.buildKasVaultGenesisRequest({ config: cfgOn, rootCovenantId, label: "built before the switch", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: H.ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: H.ADDR(c.funder), funding: [H.fuelUtxoFor(c.funder, 200n * H.KAS)] });
  assert.equal(pending.state, "BUILT");
  const countBefore = await requestCount(cfgOn);

  /* ---- AFTER the switch: SAME data, SAME software, creation of the KAS profile DISABLED ---- */
  const cfgOff = mainnetConfig({ dataRoot, mainnetCreationDisabled: [KAS_V] });
  assert.ok(cfgOff.mainnetCreationDisabled.has(KAS_V));
  const Hoff = createHarness(cfgOff);
  /* 1. NEW treasury: refused with the kill-switch sentence, before any durable write */
  await assert.rejects(
    () => wr7kas.buildKasVaultGenesisRequest({ config: cfgOff, rootCovenantId, label: "after the switch", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: Hoff.ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: Hoff.ADDR(c.funder), funding: [Hoff.fuelUtxoFor(c.funder, 200n * Hoff.KAS)] }),
    (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED" && e.message.includes(KILL_SENTENCE(KAS_V))
  );
  assert.equal(await requestCount(cfgOff), countBefore, "a refused creation writes nothing");
  /* 2. the genesis BUILT before the switch: its signature is still accepted (no broadcast) but SUBMIT — a creation entry — refuses; the request never reaches the network */
  const signedPending = Hoff.signAll(pending.transaction.unsignedSafeJson, pending.transaction.signInputs.map((s) => [s.index, c.funder]));
  const finalizedPending = await wr7kas.finalizeKasWalletRequest({ config: cfgOff, requestId: pending.requestId, signedSafeJson: signedPending }).catch((e) => e);
  if (!(finalizedPending instanceof Error)) assert.equal(finalizedPending.state, "SIGNED");
  else assert.equal(finalizedPending.code, "GENERATION_NOT_MAINNET_AUTHORIZED");
  let submitCalls = 0;
  const spyRpc = { ...rpc, async submitTransaction(a) { submitCalls += 1; return rpc.submitTransaction(a); } };
  await assert.rejects(() => wr7kas.submitKasWalletRequest({ config: cfgOff, requestId: pending.requestId, rpc: spyRpc }), (e) => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED" && e.message.includes(KILL_SENTENCE(KAS_V)));
  assert.equal(submitCalls, 0, "the node is never asked to broadcast a refused genesis");
  const stillPending = await wr7kas.loadKasWalletRequest(cfgOff, pending.requestId);
  assert.ok(["BUILT", "SIGNED"].includes(stillPending.state), `the pre-switch genesis stays ${stillPending.state}, never SUBMITTED`);
  assert.equal(await loadManifestV7Kas(cfgOff, pending.vaultId), null, "no treasury record was created for the refused genesis");
  /* 3. the EXISTING treasury: delegate payment below the threshold (delegate key only) */
  const below = await Hoff.driveSpend(cfgOff, rpc, c, vaultId, { amountSompi: 1n * Hoff.KAS });
  assert.equal(below.state, "CHAIN_VERIFIED", below.error ?? "");
  /* 4. above the threshold with the vault-level approver tier */
  const above = await Hoff.driveSpend(cfgOff, rpc, c, vaultId, { amountSompi: 3n * Hoff.KAS, approvers: [c.approver1] });
  assert.equal(above.state, "CHAIN_VERIFIED", above.error ?? "");
  /* 5. owner operations through the root's M-of-N (top-up, pause, unpause) */
  const topUp = await Hoff.driveRootOp(cfgOff, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (1n * Hoff.KAS).toString() } }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  assert.equal(topUp.state, "CHAIN_VERIFIED");
  const paused = await Hoff.driveRootOp(cfgOff, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerPause", params: {} }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  assert.equal(paused.state, "CHAIN_VERIFIED");
  assert.equal(String((await loadManifestV7Kas(cfgOff, vaultId)).live.state.paused), "1", "the pause landed (live state is BigInt-normalized)");
  const unpaused = await Hoff.driveRootOp(cfgOff, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerUnpause", params: {} }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  assert.equal(unpaused.state, "CHAIN_VERIFIED");
  /* 6. reconcile + listing keep working on the disabled image */
  const rv = await reconcileVault(cfgOff, rpc, vaultId);
  assert.ok(rv && typeof rv.status === "string", "the vault reconciler answers");
  const rr = await reconcileOrgRootV7(cfgOff, rootCovenantId, { rpc });
  assert.ok(rr && typeof rr === "object", "the root reconciler answers");
  const listed = await listRootedKasVaultsV7(cfgOff, {});
  assert.ok(listed.some((m) => m.vaultId === vaultId), "the existing treasury is still listed");
  const vault = await loadManifestV7Kas(cfgOff, vaultId);
  assert.equal(vault.status, "ACTIVE");
  assert.equal(BigInt(vault.live.state.feeReserve) > 0n, true);

  /* ---- ROOT creation disabled too: no new organization, existing organizations keep governing ---- */
  const cfgOffAll = mainnetConfig({ dataRoot, mainnetCreationDisabled: [KAS_V, ROOT_V] });
  const Hall = createHarness(cfgOffAll);
  await assert.rejects(() => Hall.rootGenesis(cfgOffAll, Hall.ctx(), rpc), (e) => /DISABLED by operator configuration/.test(e.message));
  const again = await Hall.driveRootOp(cfgOffAll, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (1n * Hall.KAS).toString() } }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  assert.equal(again.state, "CHAIN_VERIFIED", "an existing organization keeps governing its treasury with root creation disabled");
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

test("ROLLBACK ROUTE: an unknown or non-creatable name in POLICYVAULT_MAINNET_CREATION_DISABLED refuses to START (a typo can never silently leave creation enabled); the switch has no effect on testnet", () => {
  assert.throws(() => mainnetConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-rb-bad-")), mainnetCreationDisabled: ["policyvault-0.7-kaz"] }), (e) => /POLICYVAULT_MAINNET_CREATION_DISABLED|unknown|not creatable|refus/i.test(e.message));
  const t = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-rb-t-")), mainnetCreationDisabled: [KAS_V] });
  const { assertGenerationMainnetCreatable } = require("../src/config");
  assert.equal(assertGenerationMainnetCreatable(t, KAS_V), KAS_V, "testnet creation is unaffected by the mainnet kill switch");
});
