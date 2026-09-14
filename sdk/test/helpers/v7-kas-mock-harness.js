"use strict";
/* Shared MOCK-RPC harness for the v0.7-kas SDK lifecycle tests (extracted verbatim from
 * sdk/test/wallet-v7-kas-api.test.js so the kill-switch recovery-route test can drive the SAME
 * real builders / finalizers / submitters / reconciler against a mock node). The harness is
 * parameterized by the config it is given: every helper takes `cfg` explicitly, and the network
 * (testnet-10 or a mainnet-LABELLED test config) comes from that config alone. TEST KEYS ONLY. */
const assert = require("node:assert/strict");
const crypto = require("crypto");
const wr7 = require("../../src/wallet-requests-v7");
const wr7kas = require("../../src/wallet-requests-v7-kas");
const { covenantAddress, loadKaspa } = require("../../src/chain");

function createHarness(config) {
  const kaspa = require(config.rustyKaspaModule);
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


  return { KAS, KEY, XO, ADDR, signAll, sign65, mockRpc, utxo, spkAddress, fuelUtxoFor, seedOutputs, seedRootAction, driveGenesis, slotSign, driveRootOp, ctx, rootGenesis, kasGenesis, driveSpend, kaspa };
}
module.exports = { createHarness };
