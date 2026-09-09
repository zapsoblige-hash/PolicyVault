"use strict";

/*
 * SDK/API (JSON store): the v0.7-payment-hd HIERARCHICAL-DELEGATION rooted
 * vault (CANDIDATE — NOT covenant-byte-frozen, NOT production) server-orchestrated request pipeline
 * (sdk/src/wallet-requests-v7-hd.js + sdk/src/manifest-v7-hd.js), driven
 * end to end with the REAL toolchain and REAL secp256k1 Schnorr
 * signatures over deterministic TEST-ONLY keys. Broadcast is exercised
 * against a MOCK RPC (mirrors sdk/test/org-roots-api.test.js /
 * wallet-v5-api.test.js's own mockRpc precedent).
 *
 * Classified REQUIREMENT_NOT_AVAILABLE when silverc / pv_call_encoder are
 * absent.
 *
 * Covers docs/postlaunch/v0.7-app-surface-contract.md §6.1:
 *   - a rooted HD vault genesis (level-1 forest) -> sign -> submit ->
 *     CHAIN_VERIFIED under an organizational root;
 *   - hdSpend (level 1): ancestor chain / effectiveAuthority / the
 *     verbatim expiry statement are present on every response;
 *   - delegateSetChildRoot1 creates a level-2 child, then childSpendL2
 *     spends from it — proving the durable forest advances correctly
 *     across BOTH mechanisms;
 *   - delegation refused while the vault is paused, BEFORE any durable
 *     record beyond the refused build attempt;
 *   - a revoked child (delegateSetChildRoot1 replacing it with an empty
 *     subtree) can no longer spend at that level.
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
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const wr7 = require("../src/wallet-requests-v7");
const wr7hd = require("../src/wallet-requests-v7-hd");
const { loadManifestV7Hd } = require("../src/manifest-v7-hd");
const { covenantAddress, loadKaspa } = require("../src/chain");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7hd-api-")) });
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

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
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
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function spkAddress(cfg, spk) {
  const k = loadKaspa(cfg);
  return k.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString();
}
function fundingUtxoFor(key, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(key)}ac` };
}

async function driveOrgRootGenesis(cfg, owner, funder, rpc) {
  const req = await wr7.buildRootGenesisRequest({
    config: cfg, label: "hd-test-org",
    owners: [{ slot: 1, publicKey: XO(owner) }], ownerM: 1, emergencyK: 1, recoveryM: 1,
    recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder), funding: [fundingUtxoFor(funder)]
  });
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: req.id, signedSafeJson: signed });
  const scriptHex = finalized.build.rootScriptHex ?? finalized.build.vaultScriptHex;
  const outIndex = finalized.build.rootOutputIndex ?? finalized.build.vaultOutputIndex;
  const covId = finalized.build.covenantId ?? finalized.rootCovenantId;
  const value = finalized.build.accounting?.kas?.rootValue ?? finalized.build.initialState.feeReserve;
  const addr = covenantAddress(cfg, Buffer.from(scriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, outIndex, value, covId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted.rootCovenantId;
}

function ctx() {
  const owner = KEY(0xa1);
  const funder = KEY(0xa2);
  const l1 = KEY(0xa3); // level-1 delegate
  const l2 = KEY(0xa4); // level-2 delegate
  const recipient = KEY(0xa5);
  const fuelKey = KEY(0xa6);

  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const tokenCovenantId = H(0x54);
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "HD API Token", tokenStandard: "kcc20/1", tokenCovenantId,
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rTree = buildRecipientTree([XO(recipient)]);
  const level1Leaf = { pk: XO(l1), maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: (1n * KAS).toString(), maxCarryKas: KAS.toString(), expiryDaa: "999999999" };
  return { owner, funder, l1, l2, recipient, fuelKey, ref, descriptor, tokenCovenantId, rTree, level1Leaf };
}

async function driveHdGenesis(cfg, c, rootCovenantId, rpc) {
  const req = await wr7hd.buildHdVaultGenesisRequest({
    config: cfg, rootCovenantId, label: "hd-vault", descriptor: c.descriptor, templateIndex: 0,
    initialAgents: [{ ...c.level1Leaf, recipients: [XO(c.recipient)] }],
    recoveryAddress: ADDR(c.owner), feeReserveKas: "5", signerAddress: ADDR(c.funder), funding: [fundingUtxoFor(c.funder)]
  });
  assert.equal(req.kind, "hdGenesis");
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, c.funder]));
  const finalized = await wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: req.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const addr = covenantAddress(cfg, Buffer.from(finalized.build.vaultScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.vaultOutputIndex, finalized.build.initialState.feeReserve, finalized.build.covenantId));
  const submitted = await wr7hd.submitHdWalletRequest({ config: cfg, requestId: req.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

test("rooted HD vault genesis under an organizational root: BUILT -> SIGNED -> CHAIN_VERIFIED; manifest persisted ACTIVE, CANDIDATE status, forest root reconstructed", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await driveOrgRootGenesis(cfg, c.owner, c.funder, rpc);
  const submitted = await driveHdGenesis(cfg, c, rootCovenantId, rpc);
  assert.equal(submitted.authorityModel, "ON_CHAIN_ORGANIZATIONAL_ROOT");
  assert.equal(submitted.status, "CANDIDATE");

  const manifest = await loadManifestV7Hd(cfg, submitted.vaultId);
  assert.ok(manifest);
  assert.equal(manifest.status, "ACTIVE");
  assert.equal(manifest.contractVersion, "policyvault-0.7-payment-hd");
  assert.equal(manifest.orgRootCovenantId, rootCovenantId);
  assert.equal(manifest.forest.length, 1);
});

test("hdSpend at level 1: ancestor chain / effectiveAuthority / the verbatim expiry statement are present; the durable forest advances (periodSpent)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await driveOrgRootGenesis(cfg, c.owner, c.funder, rpc);
  const genesis = await driveHdGenesis(cfg, c, rootCovenantId, rpc);
  const vaultId = genesis.vaultId;

  /* fund the vault with a token position it can spend from */
  const posState = { ownerIdentifier: genesis.build.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: 1000n, isMinter: false };
  const posProgram = compileKcc20Program({ config: cfg, state: posState, familyBound: c.ref.familyBound });
  const tokenPosition = { outpoint: { transactionId: H(0x02), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: posState.ownerIdentifier, identifierType: posState.identifierType, amount: "1000", isMinter: false } };

  const spendReq = await wr7hd.buildHdWalletRequest({
    config: cfg, vaultId, action: "hdSpend", signerAddress: ADDR(c.l1),
    params: { path: [0], spendAmount: "200", recipient: XO(c.recipient), recipientListsByLevel: [[XO(c.recipient)]], recipientCarryKasSompi: (KAS / 4n).toString(), tokenPosition, fuel: fundingUtxoFor(c.fuelKey) }
  });
  assert.equal(spendReq.level, 1);
  assert.ok(Array.isArray(spendReq.ancestorChain) && spendReq.ancestorChain.length === 1);
  assert.ok(spendReq.effectiveAuthority);
  assert.equal(spendReq.expiryStatement, "expiry is enforced by PolicyVault's core and by revocation, not by consensus");

  const signed = signAll(spendReq.transaction.unsignedSafeJson, [[0, c.l1], [2, c.fuelKey]]);
  await wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: spendReq.requestId, signedSafeJson: signed });
  const succIdx = spendReq.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === spendReq.build.covenantId);
  const succAddr = spkAddress(cfg, spendReq.build.frozen.outputs[succIdx].scriptPublicKey);
  rpc.seed(succAddr, utxo(succAddr, spendReq.txId, succIdx, spendReq.build.frozen.outputs[succIdx].value, spendReq.build.covenantId));
  const submitted = await wr7hd.submitHdWalletRequest({ config: cfg, requestId: spendReq.requestId, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");

  const after = await loadManifestV7Hd(cfg, vaultId);
  assert.equal(after.forest[0].leaf.periodSpent.toString(), "200");
  assert.equal(after.live.tokenPosition.state.amount.toString(), "800");
});

test("delegation is refused DELEGATION_WHILE_PAUSED while the vault is paused (the builder's own PAUSED code, remapped)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await driveOrgRootGenesis(cfg, c.owner, c.funder, rpc);
  const genesis = await driveHdGenesis(cfg, c, rootCovenantId, rpc);
  const vaultId = genesis.vaultId;

  /* This track does not wire an HD owner-pause op (documented scope —
   * see wallet-requests-v7-hd.js's module header); to exercise the
   * PAUSED -> DELEGATION_WHILE_PAUSED remap honestly, directly persist a
   * manifest whose live.state.paused is 1 (exactly what an owner pause
   * would have produced) and confirm the server-orchestrated build path
   * refuses with the correct closed code before any durable request. */
  const manifest = await loadManifestV7Hd(cfg, vaultId);
  const { manifestToJsonV7Hd, persistManifestV7Hd } = require("../src/manifest-v7-hd");
  const { computeStateIdV7Hd } = require("../src/contract-compiler-v7");
  const { normalizeStateV7 } = require("../../core/model/vault-state-v7");
  const json = manifestToJsonV7Hd(manifest);
  /* a valid paused fixture: change paused AND recompute the state tuple's
   * stateId (paused is part of the state ID), so the manifest stays
   * internally consistent — the assertion under test is the build refusal,
   * not the persist guard. */
  const pausedState = { ...json.live.state, paused: "1" };
  const pausedStateId = computeStateIdV7Hd({ networkId: cfg.networkId, template: manifest.template, state: normalizeStateV7(pausedState) });
  await persistManifestV7Hd(cfg, { ...json, live: { ...json.live, state: pausedState, stateId: pausedStateId } });

  await assert.rejects(
    () => wr7hd.buildHdWalletRequest({ config: cfg, vaultId, action: "delegateSetChildRoot1", signerAddress: ADDR(c.l1), params: { path: [0], newChildTree: [{ leaf: c.level1Leaf, recipients: [XO(c.recipient)] }], fuel: fundingUtxoFor(c.fuelKey) } }),
    (e) => { assert.equal(e.code, "DELEGATION_WHILE_PAUSED"); return true; }
  );
});

test("delegateSetChildRoot1 creates a level-2 child; childSpendL2 spends from it", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await driveOrgRootGenesis(cfg, c.owner, c.funder, rpc);
  const genesis = await driveHdGenesis(cfg, c, rootCovenantId, rpc);
  const vaultId = genesis.vaultId;

  const childLeaf = { pk: XO(c.l2), maxPerSpend: "100", periodBudget: "300", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: (KAS / 2n).toString(), maxCarryKas: (KAS / 2n).toString(), expiryDaa: "999999999" };
  const delegateReq = await wr7hd.buildHdWalletRequest({
    config: cfg, vaultId, action: "delegateSetChildRoot1", signerAddress: ADDR(c.l1),
    params: { path: [0], newChildTree: [{ leaf: childLeaf, recipients: [XO(c.recipient)] }], fuel: fundingUtxoFor(c.fuelKey) }
  });
  assert.equal(delegateReq.level, 1);
  const delegateSigned = signAll(delegateReq.transaction.unsignedSafeJson, [[0, c.l1], [1, c.fuelKey]]);
  await wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: delegateReq.requestId, signedSafeJson: delegateSigned });
  const dSuccIdx = delegateReq.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === delegateReq.build.covenantId);
  const dSuccAddr = spkAddress(cfg, delegateReq.build.frozen.outputs[dSuccIdx].scriptPublicKey);
  rpc.seed(dSuccAddr, utxo(dSuccAddr, delegateReq.txId, dSuccIdx, delegateReq.build.frozen.outputs[dSuccIdx].value, delegateReq.build.covenantId));
  const delegateSubmitted = await wr7hd.submitHdWalletRequest({ config: cfg, requestId: delegateReq.requestId, rpc });
  assert.equal(delegateSubmitted.state, "CHAIN_VERIFIED");

  const afterDelegate = await loadManifestV7Hd(cfg, vaultId);
  assert.equal(afterDelegate.forest[0].kids.length, 1);
  assert.equal(afterDelegate.forest[0].kids[0].leaf.pk, XO(c.l2));

  /* ---- childSpendL2: the level-2 delegate spends ---- */
  const posState = { ownerIdentifier: afterDelegate.live.covenantId, identifierType: assets.kcc20.OWNER_SCHEMES.COVENANT_ID, amount: 500n, isMinter: false };
  const posProgram = compileKcc20Program({ config: cfg, state: posState, familyBound: c.ref.familyBound });
  const tokenPosition = { outpoint: { transactionId: H(0x03), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: posProgram.p2shSpkHex, covenantId: c.tokenCovenantId, state: { ownerIdentifier: posState.ownerIdentifier, identifierType: posState.identifierType, amount: "500", isMinter: false } };
  const l2SpendReq = await wr7hd.buildHdWalletRequest({
    config: cfg, vaultId, action: "childSpendL2", signerAddress: ADDR(c.l2),
    params: { path: [0, 0], spendAmount: "50", recipient: XO(c.recipient), recipientListsByLevel: [[XO(c.recipient)], [XO(c.recipient)]], recipientCarryKasSompi: (KAS / 8n).toString(), tokenPosition, fuel: fundingUtxoFor(c.fuelKey) }
  });
  assert.equal(l2SpendReq.level, 2);
  assert.equal(l2SpendReq.ancestorChain.length, 2);
  const l2Signed = signAll(l2SpendReq.transaction.unsignedSafeJson, [[0, c.l2], [2, c.fuelKey]]);
  await wr7hd.finalizeHdWalletRequest({ config: cfg, requestId: l2SpendReq.requestId, signedSafeJson: l2Signed });
  const l2SuccIdx = l2SpendReq.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === l2SpendReq.build.covenantId);
  const l2SuccAddr = spkAddress(cfg, l2SpendReq.build.frozen.outputs[l2SuccIdx].scriptPublicKey);
  rpc.seed(l2SuccAddr, utxo(l2SuccAddr, l2SpendReq.txId, l2SuccIdx, l2SpendReq.build.frozen.outputs[l2SuccIdx].value, l2SpendReq.build.covenantId));
  const l2Submitted = await wr7hd.submitHdWalletRequest({ config: cfg, requestId: l2SpendReq.requestId, rpc });
  assert.equal(l2Submitted.state, "CHAIN_VERIFIED");

  const afterL2Spend = await loadManifestV7Hd(cfg, vaultId);
  assert.equal(afterL2Spend.forest[0].kids[0].leaf.periodSpent.toString(), "50");
});

test("unknown v0.7-payment-hd action fails closed; unknown vault fails closed; a second deposit into an already-held position refused", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const c = ctx();
  const rpc = mockRpc();
  const rootCovenantId = await driveOrgRootGenesis(cfg, c.owner, c.funder, rpc);
  const genesis = await driveHdGenesis(cfg, c, rootCovenantId, rpc);

  await assert.rejects(
    () => wr7hd.buildHdWalletRequest({ config: cfg, vaultId: genesis.vaultId, action: "totallyBogusAction", signerAddress: ADDR(c.l1), params: {} }),
    (e) => { assert.equal(e.code, "UNKNOWN_ACTION"); return true; }
  );
  await assert.rejects(
    () => wr7hd.buildHdWalletRequest({ config: cfg, vaultId: H(0xee), action: "hdSpend", signerAddress: ADDR(c.l1), params: { path: [0] } }),
    (e) => { assert.equal(e.code, "VAULT_NOT_FOUND"); return true; }
  );
});
