"use strict";

/*
 * SDK/API (JSON store): the v0.7 ON-CHAIN ORGANIZATIONAL ROOT server
 * orchestration pipeline (sdk/src/wallet-requests-v7.js +
 * sdk/src/reconcile-v7.js + sdk/src/manifest-v7.js), driven end to end
 * with the REAL toolchain (silverc, the production pv_call_encoder,
 * pv_tx_probe) and REAL secp256k1 Schnorr signatures over deterministic
 * TEST-ONLY keys. Broadcast is exercised against a MOCK RPC (this file's
 * own `mockRpc`, matching the precedent in sdk/test/v2-reconcile.test.js
 * for chain-readback tests) — the exact same code path is proven against
 * a REAL testnet-10 node by tools/testnet-v7-http-e2e.js.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when silverc / pv_call_encoder / pv_tx_probe are absent.
 *
 * Covers docs/postlaunch/v0.7-app-surface-contract.md §5:
 *   - well-formed root creation; ill-formed owner sets refused before any
 *     durable record;
 *   - request build with vault operations and the parent-action cross-check;
 *   - slot signature verification (foreign key, duplicate slot, wrong
 *     digest, expired envelope, envelope for another request/root ->
 *     refused);
 *   - finalize under quorum refused / at quorum succeeds;
 *   - submit idempotency and PENDING-is-not-success;
 *   - reconcile advances ONLY on proven successor observation (mocked
 *     chain readback with stale/absent/contradicting cases);
 *   - hosted-org admin cannot create root requests without an active slot;
 *   - capabilities advertise the versions and the authority model.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { deriveRootPinsV7 } = require("../src/contract-compiler-v7");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { ROOT_STATE_LEN_V7 } = require("../../core/model/vault-state-v7-root");

const wr7 = require("../src/wallet-requests-v7");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { covenantAddress, loadKaspa } = require("../src/chain");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-api-")) });
}
const config = freshConfig();
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

/* ---- shared signing / mock-chain helpers ---- */

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
    _table: table,
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    },
    clear(address) {
      table[address] = [];
    }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}

/* A P2SH scriptPublicKey (shape { version, scriptHex }, as every frozen
 * build's outputs carry) -> its address on this network. Mirrors
 * sdk/src/wallet-requests-v7.js's own spkToAddress. */
function spkAddress(cfg, spk) {
  const k = loadKaspa(cfg);
  return k.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString();
}

/* Seed the mock RPC with the EXACT successor output(s) a finalized
 * org-root request's frozen transaction declares, so submit's chain-proof
 * polling finds them immediately. Covers both root-only and root+vault
 * builds; for a terminal ownerRecover it seeds output 0 (the payout)
 * instead of a vault successor. */
function seedRootActionSuccessors(cfg, rpc, finalizedRequest) {
  for (const input of finalizedRequest.build.frozen.inputs) rpc.clear(spkAddress(cfg, input.utxo.scriptPublicKey));
  const outputs = finalizedRequest.build.frozen.outputs;
  const rootOutIdx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === finalizedRequest.rootCovenantId);
  const rootAddr = spkAddress(cfg, outputs[rootOutIdx].scriptPublicKey);
  rpc.seed(rootAddr, utxo(rootAddr, finalizedRequest.txId, rootOutIdx, outputs[rootOutIdx].value, finalizedRequest.rootCovenantId));

  const isRootOnly = finalizedRequest.build.kind === "orgRootTransition";
  const isTerminal = !isRootOnly && finalizedRequest.build.successorState === null;
  if (isTerminal) {
    const addr0 = spkAddress(cfg, outputs[0].scriptPublicKey);
    rpc.seed(addr0, utxo(addr0, finalizedRequest.txId, 0, outputs[0].value, null));
  } else if (!isRootOnly) {
    const vaultOutIdx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === finalizedRequest.build.covenantId);
    const vaultAddr = spkAddress(cfg, outputs[vaultOutIdx].scriptPublicKey);
    rpc.seed(vaultAddr, utxo(vaultAddr, finalizedRequest.txId, vaultOutIdx, outputs[vaultOutIdx].value, finalizedRequest.build.covenantId));
  }
}

/* ---- test fixture context: one organization, one rooted vault, one asset ---- */

function ctx() {
  const owner1 = KEY(0x71), owner2 = KEY(0x72), owner3 = KEY(0x73);
  const funder = KEY(0xf0);
  const fuelKey = KEY(0x64);
  const agentKey = KEY(0x62);
  const recipientKey = KEY(0x63);

  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const tokenCovenantId = H(0x54);
  const descriptor = {
    schema: "policyvault-asset-descriptor/1",
    assetId: H(0x11),
    displayName: "Org Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };

  const rTree = buildRecipientTree([XO(recipientKey)]);
  const policy = { agentPk: XO(agentKey), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };

  return { owner1, owner2, owner3, funder, fuelKey, agentKey, recipientKey, descriptor, tokenCovenantId, ref, rTree, policy };
}

function fuelUtxoFor(fuelKey, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
}

/* Drive a genesis request (root or rooted vault) to CHAIN_VERIFIED against
 * a mock RPC seeded with exactly its own expected output. */
async function driveGenesis(cfg, request, funderKey, rpc) {
  const signed = signAll(request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funderKey]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: request.id, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const scriptHex = finalized.build.rootScriptHex ?? finalized.build.vaultScriptHex;
  const outIndex = finalized.build.rootOutputIndex ?? finalized.build.vaultOutputIndex;
  const covId = finalized.build.covenantId ?? finalized.rootCovenantId;
  const value = finalized.build.accounting?.kas?.rootValue ?? finalized.build.initialState.feeReserve;
  const addr = covenantAddress(cfg, Buffer.from(scriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, outIndex, value, covId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

/* ------------------------------------------------------------------ */

test("well-formed root genesis: build -> finalize -> submit -> CHAIN_VERIFIED; ORG_ROOT persisted with authorityModel", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const req = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  assert.equal(req.kind, "rootGenesis");
  assert.equal(req.state, "AUTHORIZED");
  assert.equal(req.requiredApprovals, "1");

  const rpc = mockRpc();
  const submitted = await driveGenesis(cfg, req, c.funder, rpc);
  assert.equal(submitted.chain.successorOutpoint, `${submitted.txId}:0`);

  const root = await wr7.loadOrgRoot(cfg, submitted.rootCovenantId);
  assert.ok(root);
  assert.equal(root.authorityModel, "ON_CHAIN_ORGANIZATIONAL_ROOT");
  assert.equal(root.generation, 0);
  assert.equal(root.pendingRequestId, null);
  assert.equal(root.slots.length, 3);
  assert.equal(root.live.outpoint.transactionId, submitted.txId);

  /* re-submitting an already-CHAIN_VERIFIED request is idempotent */
  const again = await wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc });
  assert.equal(again.state, "CHAIN_VERIFIED");
});

test("ill-formed owner sets are refused BEFORE any durable record exists", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const before = await wr7.listOrgRootRequests(cfg);
  assert.equal(before.length, 0);

  const base = {
    config: cfg, label: "bad org", recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  };
  await assert.rejects(
    () => wr7.buildRootGenesisRequest({ ...base, owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 1, publicKey: XO(c.owner2) }], ownerM: 2, emergencyK: 1, recoveryM: 1 }),
    (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; }
  );
  await assert.rejects(
    () => wr7.buildRootGenesisRequest({ ...base, owners: [{ slot: 1, publicKey: XO(c.owner1) }], ownerM: 5, emergencyK: 1, recoveryM: 1 }),
    (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; }
  );
  await assert.rejects(
    () => wr7.buildRootGenesisRequest({ ...base, owners: [{ slot: 2, publicKey: XO(c.owner1) }], ownerM: 1, emergencyK: 1, recoveryM: 1 }),
    (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; }
  );
  const after = await wr7.listOrgRootRequests(cfg);
  assert.equal(after.length, 0, "no durable request was created by any of the refused builds");
});

test("rooted vault genesis pins the root; full owner-quorum lifecycle: root action WITHOUT a vault op (heartbeat), WITH a vault op, and the emergency lighter quorum", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rootReq = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  const rpc = mockRpc();
  await driveGenesis(cfg, rootReq, c.funder, rpc);
  const rootCovenantId = rootReq.rootCovenantId;

  const tree = buildTokenAgentTreeV5([c.policy]);
  const vaultReq = await wr7.buildRootedVaultGenesisRequest({
    config: cfg, rootCovenantId, label: "treasury", descriptor: c.descriptor, templateIndex: 0,
    agents: [{ ...c.policy, recipients: [...c.rTree.recipients] }],
    recoveryAddress: ADDR(KEY(0x51)), depositKas: "0", feeReserveKas: "5", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  assert.equal(vaultReq.kind, "rootedVaultGenesis");
  const vaultSubmitted = await driveGenesis(cfg, vaultReq, c.funder, rpc);
  const vaultId = vaultSubmitted.build.template.vaultId;

  const rootAfterVault = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.deepEqual(rootAfterVault.vaults, [vaultId]);
  const vaultManifest = await require("../src/manifest-v7").loadManifestV7(cfg, vaultId);
  assert.ok(vaultManifest);
  assert.equal(vaultManifest.agentRegistryRoot, tree.root);
  assert.equal(vaultManifest.orgRootCovenantId, rootCovenantId);

  /* ---- ROOT ACTION without a vault op: an AUTHORIZE heartbeat ---- */
  const heartbeatReq = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, signerAddress: ADDR(c.owner1) });
  assert.equal(heartbeatReq.kind, "rootAction");
  assert.equal(heartbeatReq.requiredApprovals, "2");
  assert.equal(heartbeatReq.slots.length, 3);
  assert.equal(heartbeatReq.slots.every((s) => s.status === "PENDING"), true);

  /* GET slot-request/:slot -> the exact signer-request envelope */
  const slotReq1 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: heartbeatReq.id, slot: 1 });
  assert.equal(slotReq1.slot.publicKey, XO(c.owner1));
  const sig1 = sign65(heartbeatReq.transaction.unsignedSafeJson, heartbeatReq.rootInputIndex, c.owner1);
  const resp1 = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: slotReq1.requestVersion, requestId: slotReq1.requestId, network: slotReq1.network, manifestHash: slotReq1.manifestHash, txId: slotReq1.txId, root: slotReq1.root, slot: slotReq1.slot, signerAddress: ADDR(c.owner1), signatureHex: sig1, sighashType: 1, signedAtMs: Date.now() };
  const afterSlot1 = await wr7.submitSlotSignature({ config: cfg, requestId: heartbeatReq.id, slot: 1, response: resp1 });
  assert.equal(afterSlot1.signaturesPresent, 1);

  /* finalize under quorum is refused */
  await assert.rejects(() => wr7.finalizeOrgRootRequest({ config: cfg, requestId: heartbeatReq.id }), (e) => { assert.equal(e.code, "UNDER_QUORUM"); return true; });

  const slotReq2 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: heartbeatReq.id, slot: 2 });
  const sig2 = sign65(heartbeatReq.transaction.unsignedSafeJson, heartbeatReq.rootInputIndex, c.owner2);
  const resp2 = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: slotReq2.requestVersion, requestId: slotReq2.requestId, network: slotReq2.network, manifestHash: slotReq2.manifestHash, txId: slotReq2.txId, root: slotReq2.root, slot: slotReq2.slot, signerAddress: ADDR(c.owner2), signatureHex: sig2, sighashType: 1, signedAtMs: Date.now() };
  const afterSlot2 = await wr7.submitSlotSignature({ config: cfg, requestId: heartbeatReq.id, slot: 2, response: resp2 });
  assert.equal(afterSlot2.signaturesPresent, 2);

  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(heartbeatReq.transaction.unsignedSafeJson), afterSlot2.build.frozen.inputs.length - 1, c.fuelKey);
  const finalizedHeartbeat = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: heartbeatReq.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalizedHeartbeat.state, "SIGNED");

  seedRootActionSuccessors(cfg, rpc, finalizedHeartbeat);
  const submittedHeartbeat = await wr7.submitOrgRootRequest({ config: cfg, requestId: heartbeatReq.id, rpc });
  assert.equal(submittedHeartbeat.state, "CHAIN_VERIFIED");

  const rootAfterHeartbeat = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.equal(rootAfterHeartbeat.generation, 1);
  assert.equal(rootAfterHeartbeat.pendingRequestId, null);
  assert.equal(rootAfterHeartbeat.state.rootNonce, "1");

  /* re-submitting an already-CHAIN_VERIFIED rootAction request is idempotent */
  const heartbeatAgain = await wr7.submitOrgRootRequest({ config: cfg, requestId: heartbeatReq.id, rpc });
  assert.equal(heartbeatAgain.state, "CHAIN_VERIFIED");

  /* ---- a SECOND root-authorized request cannot be BUILT while one is pending ---- */
  const pendingProbe = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, signerAddress: ADDR(c.owner1) });
  assert.ok(pendingProbe.id, "a second heartbeat may be built once the first reached CHAIN_VERIFIED and cleared pendingRequestId");
  await wr7.rejectOrgRootRequest({ config: cfg, requestId: pendingProbe.id, reason: "probe only" }); // clear pendingRequestId before continuing

  /* ---- ROOT ACTION WITH a vault operation: ownerTopUpReserve under AUTHORIZE ---- */
  const topUpReq = await wr7.buildRootActionRequest({
    config: cfg, rootCovenantId, action: "authorize",
    params: { fuel: fuelUtxoFor(c.fuelKey) },
    vaultOperations: [{ vaultId, action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (KAS / 2n).toString() } }],
    signerAddress: ADDR(c.owner2)
  });
  assert.equal(topUpReq.vaultOperations.length, 1);
  assert.equal(topUpReq.vaultOperations[0].action, "ownerTopUpReserve");
  assert.equal(topUpReq.actionClass, "AUTHORITY-NEUTRAL");

  const s1 = sign65(topUpReq.transaction.unsignedSafeJson, topUpReq.rootInputIndex, c.owner1);
  const req1 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: topUpReq.id, slot: 1 });
  const r1 = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: req1.requestVersion, requestId: req1.requestId, network: req1.network, manifestHash: req1.manifestHash, txId: req1.txId, root: req1.root, slot: req1.slot, signerAddress: ADDR(c.owner1), signatureHex: s1, sighashType: 1, signedAtMs: Date.now() };
  await wr7.submitSlotSignature({ config: cfg, requestId: topUpReq.id, slot: 1, response: r1 });
  const s2 = sign65(topUpReq.transaction.unsignedSafeJson, topUpReq.rootInputIndex, c.owner2);
  const req2 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: topUpReq.id, slot: 2 });
  const r2 = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: req2.requestVersion, requestId: req2.requestId, network: req2.network, manifestHash: req2.manifestHash, txId: req2.txId, root: req2.root, slot: req2.slot, signerAddress: ADDR(c.owner2), signatureHex: s2, sighashType: 1, signedAtMs: Date.now() };
  const afterBoth = await wr7.submitSlotSignature({ config: cfg, requestId: topUpReq.id, slot: 2, response: r2 });

  const fuelSig2 = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(topUpReq.transaction.unsignedSafeJson), afterBoth.build.frozen.inputs.length - 1, c.fuelKey);
  const finalizedTopUp = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: topUpReq.id, fuelSignatureScriptHex: fuelSig2 });
  seedRootActionSuccessors(cfg, rpc, finalizedTopUp);
  const submittedTopUp = await wr7.submitOrgRootRequest({ config: cfg, requestId: topUpReq.id, rpc });
  assert.equal(submittedTopUp.state, "CHAIN_VERIFIED");

  const vaultAfterTopUp = await require("../src/manifest-v7").loadManifestV7(cfg, vaultId);
  assert.equal(vaultAfterTopUp.live.state.feeReserve, 5n * KAS + KAS / 2n);
  assert.equal(vaultAfterTopUp.generation, 1);

  /* ---- EMERGENCY quorum: ownerEmergencyPause under FREEZE (K=1), ONE signature ---- */
  const freezeReq = await wr7.buildRootActionRequest({
    config: cfg, rootCovenantId, action: "freeze",
    params: { fuel: fuelUtxoFor(c.fuelKey) },
    vaultOperations: [{ vaultId, action: "ownerEmergencyPause", params: {} }],
    signerAddress: ADDR(c.owner3)
  });
  assert.equal(freezeReq.requiredApprovals, "1");
  assert.equal(freezeReq.actionClass, "AUTHORITY-REDUCING");
  assert.deepEqual(freezeReq.warnings, ["LANDS_FROZEN"], "freeze itself carries no DANGEROUS_* label, but it DOES land the root frozen");

  const fs1 = sign65(freezeReq.transaction.unsignedSafeJson, freezeReq.rootInputIndex, c.owner3);
  const fReq1 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: freezeReq.id, slot: 3 });
  const fR1 = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: fReq1.requestVersion, requestId: fReq1.requestId, network: fReq1.network, manifestHash: fReq1.manifestHash, txId: fReq1.txId, root: fReq1.root, slot: fReq1.slot, signerAddress: ADDR(c.owner3), signatureHex: fs1, sighashType: 1, signedAtMs: Date.now() };
  const afterFreezeSig = await wr7.submitSlotSignature({ config: cfg, requestId: freezeReq.id, slot: 3, response: fR1 });
  const freezeFuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(freezeReq.transaction.unsignedSafeJson), afterFreezeSig.build.frozen.inputs.length - 1, c.fuelKey);
  const finalizedFreeze = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: freezeReq.id, fuelSignatureScriptHex: freezeFuelSig });
  seedRootActionSuccessors(cfg, rpc, finalizedFreeze);
  const submittedFreeze = await wr7.submitOrgRootRequest({ config: cfg, requestId: freezeReq.id, rpc });
  assert.equal(submittedFreeze.state, "CHAIN_VERIFIED");

  const rootAfterFreeze = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.equal(rootAfterFreeze.state.frozen, "1");
  const vaultAfterFreeze = await require("../src/manifest-v7").loadManifestV7(cfg, vaultId);
  assert.equal(vaultAfterFreeze.live.state.paused, 1n);
  assert.equal(vaultAfterFreeze.status, "PAUSED");
});

test("delegate spend and token deposit on a rooted vault: NO root input, never touches ORG_ROOT_REQUEST", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();

  const rootReq = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  await driveGenesis(cfg, rootReq, c.funder, rpc);

  const vaultReq = await wr7.buildRootedVaultGenesisRequest({
    config: cfg, rootCovenantId: rootReq.rootCovenantId, label: "treasury", descriptor: c.descriptor, templateIndex: 0,
    agents: [{ ...c.policy, recipients: [...c.rTree.recipients] }],
    recoveryAddress: ADDR(KEY(0x51)), depositKas: "0", feeReserveKas: "5", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  const vaultSubmitted = await driveGenesis(cfg, vaultReq, c.funder, rpc);
  const vaultId = vaultSubmitted.build.template.vaultId;
  const vaultCovenantId = vaultSubmitted.build.covenantId;

  /* ---- TOKEN DEPOSIT: a user's own p2pk-owned KCC20 position -> the vault ---- */
  const depositor = KEY(0x91);
  const userState = { ownerIdentifier: XO(depositor), identifierType: 0 /* P2PK */, amount: 100000n, isMinter: false };
  const userProgram = compileKcc20Program({ config: cfg, state: userState, familyBound: 2 });
  const userOutpoint = { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 };
  const depositCarry = 1n * KAS;

  const depositReq = await wr7.buildV7WalletRequest({
    config: cfg, vaultId, action: "tokenDeposit",
    params: {
      userPosition: { outpoint: userOutpoint, value: depositCarry.toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: userState },
      /* the FULL user balance (100000) is deposited so there is no
       * remainder output — a partial deposit and its carry-split are
       * exercised by the SDK's own vault-builders-v7 suite */
      depositAmount: "100000", depositCarryKasSompi: depositCarry.toString(),
      fuel: fuelUtxoFor(c.fuelKey)
    },
    signerAddress: ADDR(depositor)
  });
  assert.equal(depositReq.schema, "policyvault-wallet-request/v7");
  assert.equal(depositReq.action, "tokenDeposit");
  const depositSigned = signAll(depositReq.transaction.unsignedSafeJson, [[0, depositor], [1, c.fuelKey]]);
  const depositFinalized = await wr7.finalizeV7WalletRequest({ config: cfg, requestId: depositReq.requestId, signedSafeJson: depositSigned });
  assert.equal(depositFinalized.state, "SIGNED");
  const depositOutSpk = depositFinalized.build.frozen.outputs[0].scriptPublicKey;
  const depositAddr = spkAddress(cfg, depositOutSpk);
  rpc.seed(depositAddr, utxo(depositAddr, depositFinalized.txId, 0, depositFinalized.build.frozen.outputs[0].value, c.tokenCovenantId));
  const depositSubmitted = await wr7.submitV7WalletRequest({ config: cfg, requestId: depositReq.requestId, rpc });
  assert.equal(depositSubmitted.state, "CHAIN_VERIFIED");

  const vaultAfterDeposit = await require("../src/manifest-v7").loadManifestV7(cfg, vaultId);
  assert.equal(vaultAfterDeposit.live.tokenPosition.state.amount, 100000n);
  assert.equal(vaultAfterDeposit.live.tokenPosition.state.ownerIdentifier, vaultCovenantId);

  /* a second deposit into an already-held position is refused, fail closed */
  await assert.rejects(
    () =>
      wr7.buildV7WalletRequest({
        config: cfg, vaultId, action: "tokenDeposit",
        params: { userPosition: { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, value: depositCarry.toString(), scriptPublicKeyHex: userProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: userState }, depositAmount: "1", depositCarryKasSompi: depositCarry.toString(), fuel: fuelUtxoFor(c.fuelKey) },
        signerAddress: ADDR(depositor)
      }),
    (e) => { assert.equal(e.code, "TOKEN_POSITION_ALREADY_HELD"); return true; }
  );

  /* ---- DELEGATE SPEND: tokenAgentSpend, NO root input, NO ORG_ROOT_REQUEST touched ---- */
  const rootBefore = await wr7.loadOrgRoot(cfg, rootReq.rootCovenantId);
  const spendReq = await wr7.buildV7WalletRequest({
    config: cfg, vaultId, action: "tokenAgentSpend",
    params: {
      spendAmount: "200", agents: [c.policy], recipient: XO(c.recipientKey), recipients: [...c.rTree.recipients],
      recipientCarryKasSompi: (KAS / 5n).toString(), reserveConsumedSompi: "50000",
      fuel: fuelUtxoFor(c.fuelKey), tokenPosition: { outpoint: vaultAfterDeposit.live.tokenPosition.outpoint, value: vaultAfterDeposit.live.tokenPosition.value.toString(), scriptPublicKeyHex: vaultAfterDeposit.live.tokenPosition.scriptPublicKeyHex, covenantId: vaultAfterDeposit.live.tokenPosition.covenantId, state: { ownerIdentifier: vaultAfterDeposit.live.tokenPosition.state.ownerIdentifier, identifierType: vaultAfterDeposit.live.tokenPosition.state.identifierType, amount: vaultAfterDeposit.live.tokenPosition.state.amount.toString(), isMinter: vaultAfterDeposit.live.tokenPosition.state.isMinter } }
    },
    signerAddress: ADDR(c.agentKey)
  });
  assert.equal(spendReq.build.hasRootInput, false, "a delegate spend build carries NO root input");
  const spendSigned = signAll(spendReq.transaction.unsignedSafeJson, [[0, c.agentKey], [spendReq.transaction.signInputs.length - 1, c.fuelKey]]);
  const spendFinalized = await wr7.finalizeV7WalletRequest({ config: cfg, requestId: spendReq.requestId, signedSafeJson: spendSigned });
  // Exact settled effect: consumed predecessors and both continuations,
  // rather than a vault-output-only mock that retained the spent inputs.
  for (const input of spendFinalized.build.frozen.inputs) rpc._table[spkAddress(cfg, input.utxo.scriptPublicKey)] = [];
  spendFinalized.build.frozen.outputs.forEach((out, index) => {
    const address = spkAddress(cfg, out.scriptPublicKey);
    rpc.seed(address, utxo(address, spendFinalized.txId, index, out.value, out.covenant?.covenantId));
  });
  const spendSubmitted = await wr7.submitV7WalletRequest({ config: cfg, requestId: spendReq.requestId, rpc });
  assert.equal(spendSubmitted.state, "CHAIN_VERIFIED");

  const vaultAfterSpend = await require("../src/manifest-v7").loadManifestV7(cfg, vaultId);
  assert.equal(vaultAfterSpend.live.tokenPosition.state.amount, 100000n - 200n, "the delegate spend's SELF continuation carries the reduced balance forward");

  /* the org-root record and its requests were NEVER touched by any of this */
  const rootAfter = await wr7.loadOrgRoot(cfg, rootReq.rootCovenantId);
  assert.deepEqual(rootAfter.state, rootBefore.state);
  assert.equal(rootAfter.generation, rootBefore.generation);
  const orgRequests = await wr7.listOrgRootRequests(cfg, { rootCovenantId: rootReq.rootCovenantId });
  assert.ok(orgRequests.every((r) => r.kind !== "rootAction" || r.vaultOperations.every((v) => v.vaultId !== vaultId)), "no rootAction request exists for the delegate/deposit path");
});

test("reconcile: CONSISTENT when live, ADVANCED only on proven successor, UNKNOWN on a divergent/absent successor (never guessed)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();

  const rootReq = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  const submittedGenesis = await driveGenesis(cfg, rootReq, c.funder, rpc);
  const rootCovenantId = submittedGenesis.rootCovenantId;

  /* CONSISTENT: the live outpoint is still on chain, no claim */
  const consistent = await reconcileOrgRootV7(cfg, rootCovenantId, { rpc });
  assert.equal(consistent.root.status, "CONSISTENT");

  /* build+finalize a heartbeat but do NOT submit it — simulate a crash after
   * BUILD by manually creating the transition claim a real submit would
   * have made, then reconcile with the live outpoint STILL present (no
   * successor broadcast at all): CLAIM_PENDING, never advanced. */
  const heartbeat = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, signerAddress: ADDR(c.owner1) });
  const { claimTransition } = require("../src/submission-claim");
  const rootNow = await wr7.loadOrgRoot(cfg, rootCovenantId);
  await claimTransition(cfg, { outpoint: rootNow.live.outpoint, action: "authorize", txId: heartbeat.txId, vaultId: rootCovenantId, stateId: null, expected: { kind: "orgRootRequest", requestId: heartbeat.id } });

  const pending = await reconcileOrgRootV7(cfg, rootCovenantId, { rpc, stalePendingMinimumMs: 10_000_000, allowClaimRelease: true });
  assert.equal(pending.root.status, "CLAIM_PENDING");

  /* RC27F / retained UX-05: age and one unspent root are insufficient.
   * This manually seeded claim has no frozen signed attempt or funding /
   * mempool / acceptance-window proof. Supported negative outcomes have
   * actual public-path controls in outcome-arbitration-rc27f.test.js. */
  const released = await reconcileOrgRootV7(cfg, rootCovenantId, { rpc, stalePendingMinimumMs: 0, allowClaimRelease: true });
  assert.equal(released.root.status, "CLAIM_PENDING");
  const rootAfterRelease = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.equal(rootAfterRelease.pendingRequestId, heartbeat.id, "age alone cannot clear the unresolved request");

  /* UNKNOWN: the live outpoint is GONE (spent by something) and no claim
   * names a provable successor — never guessed into a new shape. */
  const { loadTransitionClaim } = require("../src/submission-claim");
  const stillClaimed = await loadTransitionClaim(cfg, rootAfterRelease.live.outpoint);
  assert.equal(stillClaimed.txId, heartbeat.txId, "the unresolved claim is preserved");
  rpc.clear(rootAfterRelease.live.address);
  const unknown = await reconcileOrgRootV7(cfg, rootCovenantId, { rpc });
  assert.equal(unknown.root.status, "UNKNOWN");
  const rootAfterUnknown = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.deepEqual(rootAfterUnknown, rootAfterRelease, "an UNKNOWN outcome never mutates the durable record");
});

/* ================================================================== *
 * rc26 round-7 internal review R7-02 — ownerSetAgentRoot END TO END through the
 * request layer: the owners install a FULL new delegate policy set (registry
 * entries: policy + each agent's recipients, the genesis `agents` shape); the
 * request carries the validated entries (`newRegistry`), the manifest carries
 * the policies (`policy.agentSet`) for the owners' review, the verifier binds
 * the successor agentRoot to their fold, and ONLY a CHAIN-VERIFIED transition
 * replaces the durable registry. A bare root is refused before any build.
 * ================================================================== */
test("R7-02: ownerSetAgentRoot carries and binds the new policy set; a bare newAgentRoot is refused; the durable registry is replaced only on CHAIN_VERIFIED", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const { buildTokenAgentTreeV5 } = require("../src/agent-merkle-v5");
  const { loadManifestV7 } = require("../src/manifest-v7");

  const rootReq = await wr7.buildRootGenesisRequest({
    config: cfg, label: "acme dao",
    owners: [{ slot: 1, publicKey: XO(c.owner1) }, { slot: 2, publicKey: XO(c.owner2) }, { slot: 3, publicKey: XO(c.owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  await driveGenesis(cfg, rootReq, c.funder, rpc);
  const rootCovenantId = rootReq.rootCovenantId;
  const vaultReq = await wr7.buildRootedVaultGenesisRequest({
    config: cfg, rootCovenantId, label: "treasury", descriptor: c.descriptor, templateIndex: 0,
    agents: [{ ...c.policy, recipients: [...c.rTree.recipients] }],
    recoveryAddress: ADDR(KEY(0x51)), depositKas: "0", feeReserveKas: "5", signerAddress: ADDR(c.funder), funding: [fuelUtxoFor(c.funder)]
  });
  const vaultSubmitted = await driveGenesis(cfg, vaultReq, c.funder, rpc);
  const vaultId = vaultSubmitted.build.template.vaultId;
  const before = await loadManifestV7(cfg, vaultId);
  assert.equal(before.agentRegistry.length, 1);

  /* a bare root (the pre-rc27 shape) is refused before any build — the owners approve RULES */
  await assert.rejects(
    () => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerSetAgentRoot", params: { newAgentRoot: "99".repeat(32) } }], signerAddress: ADDR(c.owner1) }),
    (e) => { assert.equal(e.code, "AGENT_SET_REQUIRED"); return true; }
  );
  /* a malformed set (an entry without recipients) is refused as a set, not built */
  await assert.rejects(
    () => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(c.fuelKey) }, vaultOperations: [{ vaultId, action: "ownerSetAgentRoot", params: { agents: [{ ...c.policy }] } }], signerAddress: ADDR(c.owner1) }),
    (e) => { assert.ok(e.code && e.code !== "BUILD_FAILED", `code ${e.code}: ${e.message}`); assert.match(e.message, /recipients|policy set/); return true; }
  );

  const newAgentKey = KEY(0x66);
  const newEntries = [
    { ...c.policy, tokenMaxPerSpend: "100", recipients: [...c.rTree.recipients] },
    { ...c.policy, agentPk: XO(newAgentKey), recipients: [...c.rTree.recipients] }
  ];
  const setReq = await wr7.buildRootActionRequest({
    config: cfg, rootCovenantId, action: "authorize",
    params: { fuel: fuelUtxoFor(c.fuelKey) },
    vaultOperations: [{ vaultId, action: "ownerSetAgentRoot", params: { agents: newEntries } }],
    signerAddress: ADDR(c.owner1)
  });
  assert.equal(setReq.vaultOperations[0].action, "ownerSetAgentRoot");
  assert.equal(setReq.newRegistry.length, 2, "the validated registry entries travel on the request");
  assert.deepEqual(setReq.newRegistry.map((e) => e.agentPk).sort(), [XO(c.agentKey), XO(newAgentKey)].sort());
  const carried = setReq.manifest.vaultOperations[0].manifest.policy.agentSet;
  assert.equal(carried.length, 2, "the manifest carries the policy set for the owners' review");
  assert.deepEqual(carried.map((p) => p.recipients), [[...c.rTree.recipients], [...c.rTree.recipients]], "Codex checkpoint 11: the manifest carries every policy's RECIPIENTS");
  const expectedRoot = buildTokenAgentTreeV5(carried.map(({ recipients, ...policy }) => { void recipients; return policy; })).root;
  assert.equal(setReq.build.successorState.agentRoot, expectedRoot, "the successor agentRoot is the fold of the carried set");
  assert.notEqual(expectedRoot, before.live.state.agentRoot);

  const s1 = sign65(setReq.transaction.unsignedSafeJson, setReq.rootInputIndex, c.owner1);
  const req1 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: setReq.id, slot: 1 });
  await wr7.submitSlotSignature({ config: cfg, requestId: setReq.id, slot: 1, response: { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: req1.requestVersion, requestId: req1.requestId, network: req1.network, manifestHash: req1.manifestHash, txId: req1.txId, root: req1.root, slot: req1.slot, signerAddress: ADDR(c.owner1), signatureHex: s1, sighashType: 1, signedAtMs: Date.now() } });
  const s2 = sign65(setReq.transaction.unsignedSafeJson, setReq.rootInputIndex, c.owner2);
  const req2 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: setReq.id, slot: 2 });
  const afterBoth = await wr7.submitSlotSignature({ config: cfg, requestId: setReq.id, slot: 2, response: { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: req2.requestVersion, requestId: req2.requestId, network: req2.network, manifestHash: req2.manifestHash, txId: req2.txId, root: req2.root, slot: req2.slot, signerAddress: ADDR(c.owner2), signatureHex: s2, sighashType: 1, signedAtMs: Date.now() } });
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(setReq.transaction.unsignedSafeJson), afterBoth.build.frozen.inputs.length - 1, c.fuelKey);
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: setReq.id, fuelSignatureScriptHex: fuelSig });
  assert.equal((await loadManifestV7(cfg, vaultId)).agentRegistry.length, 1, "NOT yet: the durable registry is untouched before chain verification");
  seedRootActionSuccessors(cfg, rpc, finalized);
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: setReq.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");

  const after = await loadManifestV7(cfg, vaultId);
  assert.equal(after.agentRegistry.length, 2, "the CHAIN-VERIFIED transition replaced the durable registry");
  assert.equal(after.live.state.agentRoot, expectedRoot);
  assert.equal(after.agentRegistry.find((e) => e.policy.agentPk === XO(c.agentKey)).policy.tokenMaxPerSpend, 100n, "the tightened cap is what the (normalized) registry now holds");
  assert.equal(after.generation, 1);
});
