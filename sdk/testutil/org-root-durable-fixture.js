"use strict";

/*
 * TEST FIXTURE (not a test file — sdk/test/ is the test-runner root): the
 * v0.7 organizational-root + rooted-vault fixture shared by the durable-
 * completion RECOVERY matrices of Codex checkpoint 12 (R7-02):
 *   sdk/test/org-root-durable-recovery-cp12.test.js   (JSON store, fault injection + reload)
 *   sdk/test/hosted-pg-durable-completion-v7.test.js  (live PostgreSQL, fault injection + fresh store)
 * Real builds through the real compiler; the chain is a mocked readback
 * (seeded UTXO table) — DURABLE ORDERING / REPLAY evidence, never settled-
 * chain timing evidence. Every key is a TEST key.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const { loadManifestV7, manifestToJsonV7 } = require("../src/manifest-v7");
const { loadTransitionClaim, transitionClaimKey } = require("../src/submission-claim");
const { getStore, Categories } = require("../src/store");
const { readAudit } = require("../src/audit");
const { loadKaspa, covenantAddress } = require("../src/chain");

const KAS = 100_000_000n;

function toolchainAvailable() {
  const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-durable-probe-")) });
  return fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
}
function freshJsonConfig(prefix = "pv-durable12-") {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), prefix)) });
}
/* "after reload": a fresh config + store instance over the SAME durable state (no injected hooks survive it) */
function reloadJsonConfig(cfg) {
  return loadConfig({ dataRoot: cfg.dataRoot });
}
/* an independent copy of a JSON data root (one organization built once, exercised by many boundaries) */
function cloneJsonConfig(cfg, prefix = "pv-durable12-clone-") {
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.cpSync(cfg.dataRoot, dst, { recursive: true });
  return loadConfig({ dataRoot: dst });
}

const kaspaOf = (cfg) => loadKaspa(cfg);
const KEY = (cfg, v) => new (kaspaOf(cfg).PrivateKey)(v.toString(16).padStart(2, "0").repeat(32));
const XO = (cfg, k) => k.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (cfg, k) => k.toPublicKey().toAddress(cfg.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

/* a seeded UTXO table standing in for the node; counts broadcasts so "never rebroadcast" is assertable */
function mockRpc() {
  const table = {};
  let submits = 0;
  return {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { submits += 1; return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; },
    clear(address) { table[address] = []; },
    submits: () => submits
  };
}
const utxo = (address, txId, index, amount, covenantId) => ({ address, outpoint: { transactionId: txId, index }, amount: BigInt(amount), covenantId: covenantId ?? null });
function spkAddress(cfg, spk) { return kaspaOf(cfg).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString(); }
function fuelUtxoFor(cfg, key, amount = 50n * KAS) { return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(cfg, key)}ac` }; }
function signAll(cfg, unsignedSafeJson, entries) {
  const kaspa = kaspaOf(cfg);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const safe = JSON.parse(unsignedSafeJson);
  for (const [index, key] of entries) safe.inputs[index].signatureScript = kaspa.createInputSignature(tx, index, key);
  return JSON.stringify(safe);
}
function sign65(cfg, unsignedSafeJson, index, key) {
  const kaspa = kaspaOf(cfg);
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  return kaspa.createInputSignature(tx, index, key).slice(2, 2 + 130);
}

async function driveGenesis(cfg, request, funderKey, rpc) {
  const signed = signAll(cfg, request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funderKey]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: request.id, signedSafeJson: signed });
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

/* one organization (2-of-3) + one rooted vault with ONE agent */
async function organization(cfg, rpc, { seed = 0x70 } = {}) {
  const owner1 = KEY(cfg, seed + 1), owner2 = KEY(cfg, seed + 2), owner3 = KEY(cfg, seed + 3), funder = KEY(cfg, 0xf0), fuelKey = KEY(cfg, 0x64), agentKey = KEY(cfg, 0x62), recipientKey = KEY(cfg, 0x63);
  const ref = compileKcc20Program({ config: cfg, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = { schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "Org Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54), acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }], decimalsDisplay: 2, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false } };
  const rTree = buildRecipientTree([XO(cfg, recipientKey)]);
  const policy = { agentPk: XO(cfg, agentKey), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const rootReq = await wr7.buildRootGenesisRequest({ config: cfg, label: "acme dao", owners: [{ slot: 1, publicKey: XO(cfg, owner1) }, { slot: 2, publicKey: XO(cfg, owner2) }, { slot: 3, publicKey: XO(cfg, owner3) }], ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(cfg, funder), funding: [fuelUtxoFor(cfg, funder)] });
  await driveGenesis(cfg, rootReq, funder, rpc);
  const vaultReq = await wr7.buildRootedVaultGenesisRequest({ config: cfg, rootCovenantId: rootReq.rootCovenantId, label: "treasury", descriptor, templateIndex: 0, agents: [{ ...policy, recipients: [...rTree.recipients] }], recoveryAddress: ADDR(cfg, KEY(cfg, 0x51)), depositKas: "0", feeReserveKas: "5", signerAddress: ADDR(cfg, funder), funding: [fuelUtxoFor(cfg, funder)] });
  const vaultSubmitted = await driveGenesis(cfg, vaultReq, funder, rpc);
  return { owner1, owner2, owner3, funder, fuelKey, agentKey, recipientKey, policy, rTree, descriptor, rootCovenantId: rootReq.rootCovenantId, vaultId: vaultSubmitted.build.template.vaultId, vaultCovenantId: vaultSubmitted.build.covenantId };
}

/* build + 2 owner-slot signatures + the fee signature for ONE root action — NOT submitted */
async function signedRootAction(cfg, o, { action = "authorize", vaultOperations = [] } = {}) {
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action, params: { fuel: fuelUtxoFor(cfg, o.fuelKey) }, vaultOperations, signerAddress: ADDR(cfg, o.owner1) });
  for (const [slot, key] of [[1, o.owner1], [2, o.owner2]]) {
    const s = sign65(cfg, req.transaction.unsignedSafeJson, req.rootInputIndex, key);
    const r = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot });
    await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot, response: { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: r.requestVersion, requestId: r.requestId, network: r.network, manifestHash: r.manifestHash, txId: r.txId, root: r.root, slot: r.slot, signerAddress: ADDR(cfg, key), signatureHex: s, sighashType: 1, signedAtMs: Date.now() } });
  }
  const after = await wr7.loadOrgRootRequest(cfg, req.id);
  const kaspa = kaspaOf(cfg);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), after.build.frozen.inputs.length - 1, o.fuelKey);
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalized.state, "SIGNED");
  return finalized;
}
function setAgentRootEntries(cfg, o) {
  const newAgentKey = KEY(cfg, 0x66);
  return [{ ...o.policy, tokenMaxPerSpend: "100", recipients: [...o.rTree.recipients] }, { ...o.policy, agentPk: XO(cfg, newAgentKey), recipients: [...o.rTree.recipients] }];
}
const signedSetAgentRoot = (cfg, o) => signedRootAction(cfg, o, { vaultOperations: [{ vaultId: o.vaultId, action: "ownerSetAgentRoot", params: { agents: setAgentRootEntries(cfg, o) } }] });
const signedRootOnly = (cfg, o) => signedRootAction(cfg, o, {});
/* TERMINAL: ownerRecover on the rooted vault rides the ordinary `authorize` root action (OWNER_OP_ROOT_AUTHORITY_V7) */
const signedTerminalRecover = (cfg, o) => signedRootAction(cfg, o, { vaultOperations: [{ vaultId: o.vaultId, action: "ownerRecover", params: {} }] });

/* seed the chain with the finalized transaction's successor outputs (root; vault continuation or the terminal payout) */
function settle(cfg, rpc, finalized) {
  const outputs = finalized.build.frozen.outputs;
  const rootOutIdx = outputs.findIndex((x) => x.covenant && x.covenant.covenantId === finalized.rootCovenantId);
  const rootAddr = spkAddress(cfg, outputs[rootOutIdx].scriptPublicKey);
  rpc.seed(rootAddr, utxo(rootAddr, finalized.txId, rootOutIdx, outputs[rootOutIdx].value, finalized.rootCovenantId));
  const isRootOnly = finalized.build.kind === "orgRootTransition";
  const isTerminal = !isRootOnly && finalized.build.successorState === null;
  let vaultOutIdx = null;
  if (isTerminal) {
    const addr0 = spkAddress(cfg, outputs[0].scriptPublicKey);
    rpc.seed(addr0, utxo(addr0, finalized.txId, 0, outputs[0].value, null));
  } else if (!isRootOnly) {
    vaultOutIdx = outputs.findIndex((x) => x.covenant && x.covenant.covenantId === finalized.build.covenantId);
    const vaultAddr = spkAddress(cfg, outputs[vaultOutIdx].scriptPublicKey);
    rpc.seed(vaultAddr, utxo(vaultAddr, finalized.txId, vaultOutIdx, outputs[vaultOutIdx].value, finalized.build.covenantId));
  }
  return { rootOutIdx, vaultOutIdx };
}
/* the predecessor outpoints are SPENT once the transaction settles; returns them (the immutable claim keys) */
async function spendPredecessors(cfg, rpc, o) {
  const root = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  rpc.clear(root.live.address);
  const m = await loadManifestV7(cfg, o.vaultId);
  const { compileExactStateV7 } = require("../src/contract-compiler-v7");
  const { stateToJsonV7 } = require("../../core/model/vault-state-v7");
  const compiled = compileExactStateV7({ config: cfg, template: m.template, state: stateToJsonV7(m.live.state), contractVersion: m.contractVersion });
  rpc.clear(covenantAddress(cfg, Buffer.from(compiled.scriptHex, "hex")));
  return { rootOutpoint: root.live.outpoint, vaultOutpoint: m.live.outpoint };
}

const auditLinesFor = async (cfg, txId) => (await readAudit(cfg, { limit: 1000 })).filter((e) => e && e.txId === txId && e.result === "CHAIN_VERIFIED");
const loadSubmissionClaim = (cfg, txId) => getStore(cfg).read(Categories.SUBMISSION_CLAIM, txId);
const loadReceipt = (cfg, txId) => getStore(cfg).read(Categories.RECEIPT, txId);

/* every durable record of ONE completed root action, exactly once — kind: "setAgentRoot" | "rootOnly" | "terminal" */
async function assertFullyCompleted(cfg, o, finalized, label, { kind = "setAgentRoot", predecessors = null, rootGeneration = 1 } = {}) {
  const req = await wr7.loadOrgRootRequest(cfg, finalized.id);
  assert.equal(req.state, "CHAIN_VERIFIED", `${label}: request`);
  assert.ok(req.chain && req.chain.completion && typeof req.chain.completion.via === "string", `${label}: the completion record is on the request`);
  const root = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  assert.equal(root.live.outpoint.transactionId, finalized.txId, `${label}: root advanced`);
  assert.equal(root.pendingRequestId, null, `${label}: pending pointer cleared`);
  assert.equal(root.generation, rootGeneration, `${label}: exactly ${rootGeneration} root advancement(s) after genesis (genesis records generation 0)`);
  const m = await loadManifestV7(cfg, o.vaultId);
  if (kind === "setAgentRoot") {
    assert.equal(m.live.outpoint.transactionId, finalized.txId, `${label}: VAULT advanced to the same transaction`);
    assert.equal(m.agentRegistry.length, 2, `${label}: registry replaced (2 policies)`);
    assert.equal(m.live.state.agentRoot, finalized.build.successorState.agentRoot, `${label}: registry root == live agentRoot`);
    assert.equal(m.latestTransitionTxId, finalized.txId, `${label}: latestTransitionTxId`);
    assert.equal(m.generation, 1, `${label}: exactly ONE vault advancement`);
  } else if (kind === "terminal") {
    assert.equal(m.status, "RECOVERED", `${label}: vault RECOVERED`);
    assert.equal(m.live, null, `${label}: no live outpoint after a terminal recovery`);
    assert.equal(m.latestTransitionTxId, finalized.txId, `${label}: latestTransitionTxId`);
    assert.equal(m.generation, 1, `${label}: exactly ONE vault advancement`);
  } else {
    assert.equal(m.generation, 0, `${label}: a root-only action never touches the vault`);
  }
  const verified = await wr7.verifyRootActionCompletion(cfg, req);
  assert.equal(verified.complete, true, `${label}: verifyRootActionCompletion → complete (missing: ${verified.missing.join("; ")})`);
  if (predecessors) {
    assert.equal(await loadTransitionClaim(cfg, predecessors.rootOutpoint), null, `${label}: the ROOT predecessor claim is released`);
    if (kind !== "rootOnly" && predecessors.vaultOutpoint) {
      const vc = await loadTransitionClaim(cfg, predecessors.vaultOutpoint);
      assert.ok(vc === null || vc.txId !== finalized.txId, `${label}: no same-request claim remains on the VAULT predecessor`);
    }
  }
  assert.equal(await loadSubmissionClaim(cfg, finalized.txId), null, `${label}: submission claim released`);
  assert.ok(await loadReceipt(cfg, finalized.txId), `${label}: receipt present`);
  assert.equal((await auditLinesFor(cfg, finalized.txId)).length, 1, `${label}: exactly ONE CHAIN_VERIFIED audit line for the transaction`);
  return { req, root, m };
}

/* deterministic fault injection on the store method (write / remove / appendAudit) behind ONE config object */
function inject(cfg, method, predicate, { times = 1, message } = {}) {
  const store = getStore(cfg);
  const real = store[method].bind(store);
  let fired = 0;
  store[method] = async (...args) => {
    if ((times === Infinity || fired < times) && predicate(...args)) {
      fired += 1;
      throw new Error(message ?? `injected ${method} failure #${fired}`);
    }
    return real(...args);
  };
  return { count: () => fired, restore: () => { store[method] = real; } };
}

module.exports = {
  KAS, H, KEY, XO, ADDR, kaspaOf,
  toolchainAvailable, freshJsonConfig, reloadJsonConfig, cloneJsonConfig,
  mockRpc, utxo, spkAddress, fuelUtxoFor, signAll, sign65,
  driveGenesis, organization, signedRootAction, signedSetAgentRoot, signedRootOnly, signedTerminalRecover, setAgentRootEntries,
  settle, spendPredecessors, assertFullyCompleted, inject,
  auditLinesFor, loadSubmissionClaim, loadReceipt, transitionClaimKey, manifestToJsonV7, loadManifestV7, wr7, Categories, getStore
};
