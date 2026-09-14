"use strict";

/*
 * SDK/API (JSON store): the v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT (CANDIDATE —
 * NOT covenant-byte-frozen) server-orchestrated request pipeline
 * (sdk/src/wallet-requests-v7-kas.js + sdk/src/manifest-v7-kas.js +
 * sdk/src/rooted-kas-profile-v7.js riding sdk/src/wallet-requests-v7.js),
 * driven end to end with the REAL toolchain and REAL secp256k1 Schnorr
 * signatures over deterministic TEST-ONLY keys. Broadcast is exercised
 * against a MOCK RPC (the org-roots-api / wallet-v7-hd-api precedent).
 *
 * v0.7 mainnet-enablement directive (2026-09-10) — the complete root-plus-KAS
 * lifecycle at the SDK boundary:
 *   root genesis -> KAS vault genesis (delegate policy set, vault-level
 *   approvers, pinned recovery key, protected principal + fee reserve) ->
 *   owner operation riding the root's M-of-N (ownerTopUpReserve) ->
 *   delegate spend BELOW the agent's approval threshold -> delegate spend
 *   ABOVE it (vault-level approval collection, the frozen v0.4.1 tier) ->
 *   deferred completion (submit without chain proof, then reconcile) ->
 *   pause / spend refused / unpause -> terminal recovery to the pinned key;
 *   plus the emergency (FREEZE, K=1) path and every fail-closed refusal
 *   (unregistered agent, over cap, stranger approver, under-approved
 *   finalize, paused vault, terminal vault, pending request).
 *
 * Classified REQUIREMENT_NOT_AVAILABLE when silverc / pv_call_encoder /
 * pv_tx_probe are absent.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const wr7kas = require("../src/wallet-requests-v7-kas");
const { loadManifestV7Kas, listRootedKasVaultsV7 } = require("../src/manifest-v7-kas");
const { reconcileOrgRootV7, reconcileVault } = require("../src/reconcile-v7");
const { covenantAddress, loadKaspa } = require("../src/chain");
const { getStore, Categories } = require("../src/store");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-api-")) });
}
const config = freshConfig();
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function sign65(unsignedSafeJson, index, key) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  return kaspa.createInputSignature(tx, index, key).slice(2); // drop the 0x41 push prefix -> raw 65 bytes
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
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; },
    clear(address) { table[address] = []; }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function spkAddress(cfg, spk) {
  return loadKaspa(cfg).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString();
}
function fuelUtxoFor(key, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(key)}ac` };
}
/* seed EXACTLY the outputs a finalized request's frozen transaction declares; consume its inputs */
function seedOutputs(cfg, rpc, frozen, txId, covenantIdOf) {
  for (const input of frozen.inputs) rpc.clear(spkAddress(cfg, input.utxo.scriptPublicKey));
  frozen.outputs.forEach((o, i) => {
    const addr = spkAddress(cfg, o.scriptPublicKey);
    rpc.seed(addr, utxo(addr, txId, i, o.value, covenantIdOf(o)));
  });
}
function seedRootAction(cfg, rpc, finalized) {
  seedOutputs(cfg, rpc, finalized.build.frozen, finalized.txId, (o) => (o.covenant ? o.covenant.covenantId : null));
}
async function driveGenesis(cfg, request, funderKey, rpc) {
  const signed = signAll(request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funderKey]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: request.id, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const addr = covenantAddress(cfg, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}
async function slotSign(cfg, req, slot, key) {
  const envelope = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot });
  const sig = sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, key);
  const response = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: envelope.requestVersion, requestId: envelope.requestId, network: envelope.network, manifestHash: envelope.manifestHash, txId: envelope.txId, root: envelope.root, slot: envelope.slot, signerAddress: ADDR(key), signatureHex: sig, sighashType: 1, signedAtMs: Date.now() };
  return wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot, response });
}
/* ONE owner operation on the KAS vault riding a root action: build -> slot signatures -> finalize (fuel) -> seed -> submit */
async function driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { action = "authorize", op, signers, initiator }) {
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action, params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [op], signerAddress: ADDR(initiator ?? signers[0].key) });
  assert.equal(req.kind, "rootAction");
  assert.equal(req.vaultOperations[0].profile, "policyvault-0.7-kas", "the request records the vault's profile");
  assert.equal(req.manifest.manifestVersion, "policyvault-org-root-kas-manifest/1", "the org-root-KAS manifest family describes the transition");
  assert.ok(typeof req.redeemScripts[req.build.covenantId] === "string", "the predecessor redeem travels with the request (R7-04)");
  let after = req;
  for (const { slot, key } of signers) after = await slotSign(cfg, req, slot, key);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), after.build.frozen.inputs.length - 1, c.fuelKey);
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalized.state, "SIGNED");
  seedRootAction(cfg, rpc, finalized);
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED", `${op.action}: ${submitted.error ?? ""}`);
  return submitted;
}

function ctx() {
  const owner1 = KEY(0x71), owner2 = KEY(0x72), owner3 = KEY(0x73);
  const funder = KEY(0xf0), fuelKey = KEY(0x64), agentKey = KEY(0x62), otherAgent = KEY(0x66), recipientKey = KEY(0x63), recoveryKey = KEY(0x51);
  const approver1 = KEY(0x91), approver2 = KEY(0x92), stranger = KEY(0x99);
  const policy = { agentPk: XO(agentKey), maxPerSpend: (5n * KAS).toString(), periodBudget: (20n * KAS).toString(), periodLengthDaa: "1000", periodStartDaa: "5000", periodSpent: "0", approvalThreshold: (2n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), recipients: [XO(recipientKey)] };
  return { owner1, owner2, owner3, funder, fuelKey, agentKey, otherAgent, recipientKey, recoveryKey, approver1, approver2, stranger, policy };
}
async function rootGenesis(cfg, c, rpc) {
  const req = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  await driveGenesis(cfg, req, c.funder, rpc);
  return req.rootCovenantId;
}
async function kasGenesis(cfg, c, rpc, rootCovenantId, over = {}) {
  const req = await wr7kas.buildKasVaultGenesisRequest({
    config: cfg, rootCovenantId, label: "kas treasury", agents: [c.policy], approvers: [XO(c.approver1), XO(c.approver2)], approvalM: 1,
    recoveryAddress: ADDR(c.recoveryKey), depositKas: "100", feeReserveKas: "5", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder, 200n * KAS)], ...over
  });
  assert.equal(req.kind, "kasGenesis");
  assert.equal(req.state, "BUILT");
  assert.equal(req.authorityModel, "ON_CHAIN_ORGANIZATIONAL_ROOT");
  assert.equal(req.candidateStatus, "CANDIDATE");
  assert.equal(req.summary.depositKas, "100");
  assert.equal(req.summary.approvalM, "1");
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, c.funder]));
  const finalized = await wr7kas.finalizeKasWalletRequest({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const addr = covenantAddress(cfg, Buffer.from(req.build.vaultScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, req.txId, 0, req.build.frozen.outputs[0].value, req.build.covenantId));
  const submitted = await wr7kas.submitKasWalletRequest({ config: cfg, requestId: req.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return { request: submitted, vaultId: req.vaultId };
}
async function driveSpend(cfg, rpc, c, vaultId, { amountSompi, signer = c.agentKey, approvers = [], seed = true, pollAttempts = 30 }) {
  let req = await wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: amountSompi.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(signer) });
  for (const key of approvers) {
    const r = await wr7kas.collectApprovalKas({ config: cfg, requestId: req.requestId, approverAddress: ADDR(key), signatureHex: sign65(req.transaction.unsignedSafeJson, 0, key) });
    req = r.request;
  }
  const signed = signAll(req.transaction.unsignedSafeJson, [[0, signer]]);
  const finalized = await wr7kas.finalizeKasWalletRequest({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  if (seed) seedOutputs(cfg, rpc, finalized.build.frozen, finalized.txId, (o) => (o.covenant ? o.covenant.covenantId : null));
  return wr7kas.submitKasWalletRequest({ config: cfg, requestId: req.requestId, rpc, pollAttempts, pollDelayMs: 0 });
}

test("KAS lifecycle: root genesis -> KAS vault genesis -> owner top-up via the root M-of-N -> delegate spends below/above threshold with vault-level approvals -> deferred completion by reconcile -> pause / refused / unpause -> terminal recovery", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await rootGenesis(cfg, c, rpc);

  /* ---- genesis ---- */
  const { request: genesis, vaultId } = await kasGenesis(cfg, c, rpc, rootCovenantId);
  let vault = await loadManifestV7Kas(cfg, vaultId);
  assert.ok(vault, "the KAS vault record exists");
  assert.equal(vault.status, "ACTIVE");
  assert.equal(vault.contractVersion, "policyvault-0.7-kas");
  assert.equal(vault.live.state.protectedValue, 100n * KAS);
  assert.equal(vault.live.state.feeReserve, 5n * KAS);
  assert.equal(vault.live.outpointValue, 105n * KAS);
  assert.equal(vault.agentRegistryRoot, vault.live.state.agentRoot, "the durable registry reproduces the covenant agentRoot");
  assert.equal(vault.live.state.approvalM, 1n);
  assert.equal(vault.template.recoveryPk, XO(c.recoveryKey));
  assert.deepEqual((await wr7.loadOrgRoot(cfg, rootCovenantId)).vaults, [vaultId]);
  assert.equal((await listRootedKasVaultsV7(cfg, { orgRootCovenantId: rootCovenantId })).length, 1);
  assert.equal((await wr7kas.submitKasWalletRequest({ config: cfg, requestId: genesis.requestId, rpc })).state, "CHAIN_VERIFIED", "re-submitting a CHAIN_VERIFIED genesis is idempotent");
  const genesisReceipt = await getStore(cfg).read(Categories.RECEIPT, genesis.txId);
  assert.equal(genesisReceipt.action, "createRootedKasVault");

  /* ---- owner operation riding the root: ownerTopUpReserve under AUTHORIZE (2 of 3) ---- */
  const topUp = await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (2n * KAS).toString() } }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.live.state.feeReserve, 7n * KAS);
  assert.equal(vault.live.state.protectedValue, 100n * KAS);
  assert.equal(vault.generation, 1);
  assert.equal(vault.live.outpoint.transactionId, topUp.txId);
  assert.equal(vault.latestTransitionTxId, topUp.txId);
  assert.equal((await wr7.loadOrgRoot(cfg, rootCovenantId)).pendingRequestId, null);
  assert.equal((await wr7.loadOrgRoot(cfg, rootCovenantId)).generation, 1);

  /* ---- delegate spend BELOW the approval threshold (2 KAS): agent signature only, fee from the reserve ---- */
  const spend1 = await driveSpend(cfg, rpc, c, vaultId, { amountSompi: 1n * KAS });
  assert.equal(spend1.state, "CHAIN_VERIFIED");
  assert.equal(spend1.aboveThreshold, false);
  assert.equal(spend1.approvalProgress.required, 0);
  assert.equal(spend1.review.amountKas, "1");
  assert.equal(spend1.review.fuelFunded, false);
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.live.state.protectedValue, 99n * KAS);
  assert.equal(vault.live.state.feeReserve, 7n * KAS - BigInt(spend1.build.accounting.kas.reserveConsumed));
  assert.equal(vault.generation, 2);
  assert.equal(vault.agentRegistry[0].policy.periodSpent, 1n * KAS, "the spending agent's period accounting advanced");
  assert.equal(vault.agentRegistryRoot, vault.live.state.agentRoot);
  assert.equal(spend1.chain.successorOutpoint, `${spend1.txId}:1`);
  assert.equal((await getStore(cfg).read(Categories.RECEIPT, spend1.txId)).proof.successorOutpoint, `${spend1.txId}:1`);

  /* ---- delegate spend ABOVE the threshold: the vault-level M-of-N tier (approvalM 1 of 2) ---- */
  let above = await wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: (3n * KAS).toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) });
  assert.equal(above.state, "AWAITING_APPROVALS");
  assert.equal(above.aboveThreshold, true);
  assert.deepEqual({ collected: above.approvalProgress.collected, required: above.approvalProgress.required, complete: above.approvalProgress.complete }, { collected: 0, required: 1, complete: false });
  assert.ok(above.manifest.approverTier.aboveThreshold, "the manifest shows the vault-level tier honestly");
  await assert.rejects(() => wr7kas.finalizeKasWalletRequest({ config: cfg, requestId: above.requestId, signedSafeJson: signAll(above.transaction.unsignedSafeJson, [[0, c.agentKey]]) }), (e) => e.code === "INSUFFICIENT_APPROVALS");
  await assert.rejects(() => wr7kas.collectApprovalKas({ config: cfg, requestId: above.requestId, approverAddress: ADDR(c.stranger), signatureHex: sign65(above.transaction.unsignedSafeJson, 0, c.stranger) }), (e) => e.code === "UNKNOWN_APPROVER");
  const collected = await wr7kas.collectApprovalKas({ config: cfg, requestId: above.requestId, approverAddress: ADDR(c.approver1), signatureHex: sign65(above.transaction.unsignedSafeJson, 0, c.approver1) });
  assert.equal(collected.approvals.complete, true);
  assert.equal(collected.request.state, "BUILT");
  await assert.rejects(() => wr7kas.collectApprovalKas({ config: cfg, requestId: above.requestId, approverAddress: ADDR(c.approver2), signatureHex: sign65(above.transaction.unsignedSafeJson, 0, c.approver2) }), (e) => e.code === "BUILT", "no further approvals are collected once complete");
  const signedAbove = signAll(above.transaction.unsignedSafeJson, [[0, c.agentKey]]);
  const finalizedAbove = await wr7kas.finalizeKasWalletRequest({ config: cfg, requestId: above.requestId, signedSafeJson: signedAbove });
  assert.equal(finalizedAbove.state, "SIGNED");
  seedOutputs(cfg, rpc, finalizedAbove.build.frozen, finalizedAbove.txId, (o) => (o.covenant ? o.covenant.covenantId : null));
  const submittedAbove = await wr7kas.submitKasWalletRequest({ config: cfg, requestId: above.requestId, rpc });
  assert.equal(submittedAbove.state, "CHAIN_VERIFIED");
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.live.state.protectedValue, 96n * KAS);
  assert.equal(vault.agentRegistry[0].policy.periodSpent, 4n * KAS);
  assert.equal(vault.generation, 3);

  /* ---- refusals at the build boundary ---- */
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.otherAgent) }), (e) => e.code === "AGENT_NOT_REGISTERED");
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: (6n * KAS).toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "OVER_CAP");
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.stranger) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "RECIPIENT_NOT_ALLOWLISTED" || /recipient/i.test(e.message));
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "ownerPause", params: {}, signerAddress: ADDR(c.owner1) }), (e) => e.code === "UNKNOWN_ACTION");
  assert.equal((await wr7kas.listKasWalletRequests(cfg, { vaultId })).length, 3, "refused builds leave no durable record");

  /* ---- deferred completion: broadcast accepted, successor NOT observed -> RECONCILIATION_REQUIRED; the vault is guarded; reconcile completes it ---- */
  await assert.rejects(() => driveSpend(cfg, rpc, c, vaultId, { amountSompi: 1n * KAS, seed: false, pollAttempts: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  const pending = (await wr7kas.listKasWalletRequests(cfg, { vaultId })).find((q) => q.state === "RECONCILIATION_REQUIRED");
  assert.ok(pending, "the unproven request is truthfully RECONCILIATION_REQUIRED");
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "VAULT_PENDING_REQUEST");
  await assert.rejects(() => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerPause", params: {} }], signerAddress: ADDR(c.owner1) }), (e) => e.code === "VAULT_PENDING_REQUEST", "an owner op is refused while a delegate request is unfinished");
  const unresolved = await reconcileVault(cfg, rpc, vaultId);
  assert.equal(unresolved.status, "UNKNOWN", `without the successor on chain nothing advances: ${JSON.stringify(unresolved)}`);
  seedOutputs(cfg, rpc, pending.build.frozen, pending.txId, (o) => (o.covenant ? o.covenant.covenantId : null));
  const reconciled = await reconcileVault(cfg, rpc, vaultId);
  assert.equal(reconciled.status, "ADVANCED", JSON.stringify(reconciled));
  assert.equal((await wr7kas.loadKasWalletRequest(cfg, pending.requestId)).state, "CHAIN_VERIFIED");
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.live.state.protectedValue, 95n * KAS);
  assert.equal(vault.generation, 4);
  const orgReconcile = await reconcileOrgRootV7(cfg, rootCovenantId, { rpc });
  assert.equal(orgReconcile.root.status, "CONSISTENT");
  assert.equal(orgReconcile.vaults[0].status, "CONSISTENT", JSON.stringify(orgReconcile.vaults));

  /* ---- pause (full quorum) -> spend refused -> unpause ---- */
  await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerPause", params: {} }, signers: [{ slot: 1, key: c.owner1 }, { slot: 3, key: c.owner3 }] });
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.status, "PAUSED");
  assert.equal(vault.live.state.paused, 1n);
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "VAULT_PAUSED");
  await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerUnpause", params: {} }, signers: [{ slot: 2, key: c.owner2 }, { slot: 3, key: c.owner3 }] });
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.status, "ACTIVE");

  /* ---- ownerSetApprovers + ownerSetAgentRoot (registry replaced, derived root) ---- */
  await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerSetApprovers", params: { approvers: [XO(c.approver2)], approvalM: "1" } }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.live.state.activeApproverCount, 1);
  const newPolicy = { ...c.policy, agentPk: XO(c.otherAgent), maxPerSpend: (2n * KAS).toString() };
  await assert.rejects(() => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerSetAgentRoot", params: { newAgentRoot: "11".repeat(32) } }], signerAddress: ADDR(c.owner1) }), (e) => e.code === "AGENT_SET_REQUIRED", "a bare root is never accepted");
  const setRoot = await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerSetAgentRoot", params: { agents: [newPolicy] } }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  assert.equal(setRoot.newRegistry.length, 1);
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.agentRegistry.length, 1);
  assert.equal(vault.agentRegistry[0].policy.agentPk, XO(c.otherAgent));
  assert.equal(vault.agentRegistryRoot, vault.live.state.agentRoot);
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "AGENT_NOT_REGISTERED", "the replaced agent is gone");
  const spendNew = await driveSpend(cfg, rpc, c, vaultId, { amountSompi: 1n * KAS, signer: c.otherAgent });
  assert.equal(spendNew.state, "CHAIN_VERIFIED");

  /* ---- terminal recovery to the GENESIS-PINNED key (full quorum) ---- */
  const recover = await driveRootOp(cfg, rpc, c, rootCovenantId, vaultId, { op: { vaultId, action: "ownerRecover", params: {} }, signers: [{ slot: 1, key: c.owner1 }, { slot: 2, key: c.owner2 }] });
  const payout = recover.build.frozen.outputs[0];
  assert.equal(payout.scriptPublicKey.scriptHex, `20${XO(c.recoveryKey)}ac`, "output 0 pays the pinned recovery key");
  vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.status, "RECOVERED");
  assert.equal(vault.live, null);
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.otherAgent) }), (e) => e.code === "VAULT_TERMINAL");
  assert.equal((await reconcileVault(cfg, rpc, vaultId)).status, "TERMINAL");
  console.log(`KAS lifecycle: genesis + ${["ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerSetApprovers", "ownerSetAgentRoot", "ownerRecover"].length} owner ops via the root M-of-N + 4 delegate spends (1 above threshold with a vault-level approval, 1 completed by reconcile) CHAIN_VERIFIED against the mock chain`);
});

test("KAS emergency path: ownerEmergencyPause under FREEZE needs ONE owner (K=1) and lands the root frozen + the vault paused; a full-quorum op is refused on the frozen root", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await rootGenesis(cfg, c, rpc);
  const { vaultId } = await kasGenesis(cfg, c, rpc, rootCovenantId);
  const freeze = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "freeze", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerEmergencyPause", params: {} }], signerAddress: ADDR(c.owner3) });
  assert.equal(freeze.requiredApprovals, "1");
  assert.equal(freeze.actionClass, "AUTHORITY-REDUCING");
  assert.equal(freeze.manifest.manifestVersion, "policyvault-org-root-kas-manifest/1");
  const after = await slotSign(cfg, freeze, 3, c.owner3);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(freeze.transaction.unsignedSafeJson), after.build.frozen.inputs.length - 1, c.fuelKey);
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: freeze.id, fuelSignatureScriptHex: fuelSig });
  seedRootAction(cfg, rpc, finalized);
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: freeze.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  const root = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.equal(root.state.frozen, "1");
  const vault = await loadManifestV7Kas(cfg, vaultId);
  assert.equal(vault.status, "PAUSED");
  assert.equal(vault.live.state.paused, 1n);
  await assert.rejects(() => wr7kas.buildKasWalletRequest({ config: cfg, vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), recipient: XO(c.recipientKey) }, signerAddress: ADDR(c.agentKey) }), (e) => e.code === "VAULT_PAUSED");
  await assert.rejects(() => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerUnpause", params: {} }], signerAddress: ADDR(c.owner1) }), (e) => /frozen|FROZEN/.test(e.message) || e.code === "ROOT_FROZEN", "a frozen root refuses an AUTHORIZE-path vault op until unfrozen");
});

test("KAS genesis refusals: no principal, malformed policy set, root not live; nothing durable is written", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await rootGenesis(cfg, c, rpc);
  const base = { config: cfg, rootCovenantId, label: "x", agents: [c.policy], approvers: [], approvalM: 0, recoveryAddress: ADDR(c.recoveryKey), depositKas: "10", feeReserveKas: "1", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder, 200n * KAS)] };
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ ...base, depositKas: "0" }), (e) => e.code === "BUILD_FAILED");
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ ...base, agents: [{ ...c.policy, recipients: [] }] }), (e) => e.code === "AGENT_SET_INVALID" || e.code === "BUILD_FAILED");
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ ...base, approvers: [XO(c.approver1)], approvalM: 2 }), (e) => e.code === "BUILD_FAILED");
  await assert.rejects(() => wr7kas.buildKasVaultGenesisRequest({ ...base, rootCovenantId: "ab".repeat(32) }), (e) => e.code === "ROOT_NOT_FOUND");
  assert.equal((await wr7kas.listKasWalletRequests(cfg)).length, 0);
});
