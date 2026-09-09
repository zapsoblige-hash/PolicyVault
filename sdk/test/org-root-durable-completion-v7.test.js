"use strict";

/*
 * SDK (real builds through the real compiler; mocked chain readback with an
 * in-process JSON data root): rc26 round-7 review R7-02, second defect —
 * DURABLE COMPLETION of a root action that carries a vault operation.
 *
 * Codex checkpoint 11 reproduced, on the WIP `109c5b9`:
 *   (a) deferred settlement (the outcome is unobserved at submit; the
 *       transaction settles later; reconciliation runs): the request became
 *       CHAIN_VERIFIED and the ROOT advanced, but the VAULT kept its old
 *       outpoint and the OLD (one-agent) registry, vault reconciliation
 *       returned UNKNOWN, and the PREDECESSOR claim stayed held (the claim was
 *       released against the already-replaced successor outpoint);
 *   (b) a retried submission afterwards returned early on the terminal state
 *       and left the stale registry unchanged;
 *   (c) a vault-persistence failure AFTER the root was persisted (inline path)
 *       left the request BROADCAST, the root advanced with its pending pointer
 *       cleared, and a later reconciliation reporting root CONSISTENT / vault
 *       UNKNOWN without repair.
 *
 * Required now: ONE replayable completion of ALL affected durable records
 * (vault + registry, then root, then claims/receipt/request), truthful
 * incomplete status until it finishes, release of the ACTUAL predecessor
 * claim, no duplicate advancement on repeated reconciliation.
 * RED on 109c5b9.
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
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { loadManifestV7 } = require("../src/manifest-v7");
const { loadTransitionClaim } = require("../src/submission-claim");
const { getStore, Categories } = require("../src/store");
const loadSubmissionClaim = (cfg, txId) => getStore(cfg).read(Categories.SUBMISSION_CLAIM, txId);
const { loadKaspa } = require("../src/chain");

const config0 = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-durable-")) });
const available = fs.existsSync(config0.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config0.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder";
const KAS = 100_000_000n;

function freshConfig() { return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-durable-")) }); }
const kaspaOf = (cfg) => loadKaspa(cfg);
const KEY = (cfg, v) => new (kaspaOf(cfg).PrivateKey)(v.toString(16).padStart(2, "0").repeat(32));
const XO = (cfg, k) => k.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (cfg, k) => k.toPublicKey().toAddress(cfg.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

function mockRpc() {
  const table = {};
  return {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; },
    clear(address) { table[address] = []; }
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
  const sig = kaspa.createInputSignature(tx, index, key);
  return sig.slice(2, 2 + 130);
}

async function driveGenesis(cfg, request, funderKey, rpc) {
  const signed = signAll(cfg, request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funderKey]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: request.id, signedSafeJson: signed });
  const scriptHex = finalized.build.rootScriptHex ?? finalized.build.vaultScriptHex;
  const outIndex = finalized.build.rootOutputIndex ?? finalized.build.vaultOutputIndex;
  const covId = finalized.build.covenantId ?? finalized.rootCovenantId;
  const value = finalized.build.accounting?.kas?.rootValue ?? finalized.build.initialState.feeReserve;
  const { covenantAddress } = require("../src/chain");
  const addr = covenantAddress(cfg, Buffer.from(scriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, outIndex, value, covId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

/* one organization + one rooted vault with ONE agent; returns everything a setAgentRoot needs */
async function organization(cfg, rpc) {
  const owner1 = KEY(cfg, 0x71), owner2 = KEY(cfg, 0x72), owner3 = KEY(cfg, 0x73), funder = KEY(cfg, 0xf0), fuelKey = KEY(cfg, 0x64), agentKey = KEY(cfg, 0x62), recipientKey = KEY(cfg, 0x63);
  const ref = compileKcc20Program({ config: cfg, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = { schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "Org Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54), acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }], decimalsDisplay: 2, issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false } };
  const rTree = buildRecipientTree([XO(cfg, recipientKey)]);
  const policy = { agentPk: XO(cfg, agentKey), tokenMaxPerSpend: "250", tokenPeriodBudget: "400", periodLengthDaa: "1000", periodStartDaa: "5000", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: (KAS / 4n).toString(), agentRecipientRoot: rTree.root };
  const rootReq = await wr7.buildRootGenesisRequest({ config: cfg, label: "acme dao", owners: [{ slot: 1, publicKey: XO(cfg, owner1) }, { slot: 2, publicKey: XO(cfg, owner2) }, { slot: 3, publicKey: XO(cfg, owner3) }], ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(cfg, funder), funding: [fuelUtxoFor(cfg, funder)] });
  await driveGenesis(cfg, rootReq, funder, rpc);
  const vaultReq = await wr7.buildRootedVaultGenesisRequest({ config: cfg, rootCovenantId: rootReq.rootCovenantId, label: "treasury", descriptor, templateIndex: 0, agents: [{ ...policy, recipients: [...rTree.recipients] }], recoveryAddress: ADDR(cfg, KEY(cfg, 0x51)), depositKas: "0", feeReserveKas: "5", signerAddress: ADDR(cfg, funder), funding: [fuelUtxoFor(cfg, funder)] });
  const vaultSubmitted = await driveGenesis(cfg, vaultReq, funder, rpc);
  return { owner1, owner2, owner3, fuelKey, agentKey, recipientKey, policy, rTree, rootCovenantId: rootReq.rootCovenantId, vaultId: vaultSubmitted.build.template.vaultId, vaultCovenantId: vaultSubmitted.build.covenantId };
}

/* build + 2 slot signatures + fee signature for a setAgentRoot (two-policy set) — NOT submitted */
async function signedSetAgentRoot(cfg, o) {
  const newAgentKey = KEY(cfg, 0x66);
  const entries = [{ ...o.policy, tokenMaxPerSpend: "100", recipients: [...o.rTree.recipients] }, { ...o.policy, agentPk: XO(cfg, newAgentKey), recipients: [...o.rTree.recipients] }];
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(cfg, o.fuelKey) }, vaultOperations: [{ vaultId: o.vaultId, action: "ownerSetAgentRoot", params: { agents: entries } }], signerAddress: ADDR(cfg, o.owner1) });
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

/* seed the chain with the finalized transaction's successor outputs (root + vault) */
function settle(cfg, rpc, finalized) {
  const outputs = finalized.build.frozen.outputs;
  const rootOutIdx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === finalized.rootCovenantId);
  const rootAddr = spkAddress(cfg, outputs[rootOutIdx].scriptPublicKey);
  rpc.seed(rootAddr, utxo(rootAddr, finalized.txId, rootOutIdx, outputs[rootOutIdx].value, finalized.rootCovenantId));
  const vaultOutIdx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === finalized.build.covenantId);
  const vaultAddr = spkAddress(cfg, outputs[vaultOutIdx].scriptPublicKey);
  rpc.seed(vaultAddr, utxo(vaultAddr, finalized.txId, vaultOutIdx, outputs[vaultOutIdx].value, finalized.build.covenantId));
  return { rootOutIdx, vaultOutIdx };
}
/* the predecessor outpoints are SPENT once the transaction settles */
async function spendPredecessors(cfg, rpc, o) {
  const root = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  rpc.clear(root.live.address);
  const m = await loadManifestV7(cfg, o.vaultId);
  const { compileExactStateV7 } = require("../src/contract-compiler-v7");
  const { stateToJsonV7 } = require("../../core/model/vault-state-v7");
  const { covenantAddress } = require("../src/chain");
  const compiled = compileExactStateV7({ config: cfg, template: m.template, state: stateToJsonV7(m.live.state), contractVersion: m.contractVersion });
  rpc.clear(covenantAddress(cfg, Buffer.from(compiled.scriptHex, "hex")));
  return { rootOutpoint: root.live.outpoint, vaultOutpoint: m.live.outpoint };
}

async function assertFullyCompleted(cfg, o, finalized, label) {
  const req = await wr7.loadOrgRootRequest(cfg, finalized.id);
  assert.equal(req.state, "CHAIN_VERIFIED", `${label}: request`);
  const root = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  assert.equal(root.live.outpoint.transactionId, finalized.txId, `${label}: root advanced`);
  assert.equal(root.pendingRequestId, null, `${label}: pending pointer cleared`);
  const m = await loadManifestV7(cfg, o.vaultId);
  assert.equal(m.live.outpoint.transactionId, finalized.txId, `${label}: VAULT advanced to the same transaction`);
  assert.equal(m.agentRegistry.length, 2, `${label}: registry replaced (2 policies)`);
  assert.equal(m.live.state.agentRoot, finalized.build.successorState.agentRoot, `${label}: registry root == live agentRoot`);
  assert.equal(m.generation, 1, `${label}: exactly ONE vault advancement`);
  assert.equal(root.generation, 1, `${label}: exactly ONE root advancement after genesis (genesis records generation 0)`);
  return { req, root, m };
}

test("R7-02 durable completion (a): DEFERRED settlement — reconciliation completes the VAULT + REGISTRY, releases the ACTUAL predecessor claims, and the request is CHAIN_VERIFIED only when everything is done; repeated reconciliation never advances twice", { skip: SKIP }, async () => {
  const cfg = freshConfig(); const rpc = mockRpc();
  const o = await organization(cfg, rpc);
  const fin = await signedSetAgentRoot(cfg, o);
  const pred = await spendPredecessors(cfg, rpc, o);
  /* submit: the successor is NOT observable yet (nothing seeded) -> RECONCILIATION_REQUIRED, nothing advanced */
  await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await wr7.loadOrgRootRequest(cfg, fin.id)).state, "RECONCILIATION_REQUIRED");
  assert.equal((await loadManifestV7(cfg, o.vaultId)).agentRegistry.length, 1, "old registry retained while uncertain");
  assert.ok(await loadTransitionClaim(cfg, pred.rootOutpoint), "predecessor root claim held while uncertain");
  /* the transaction settles later */
  settle(cfg, rpc, fin);
  const r1 = await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc });
  assert.equal(r1.root.status, "ADVANCED", JSON.stringify(r1));
  await assertFullyCompleted(cfg, o, fin, "after reconcile");
  assert.equal(await loadTransitionClaim(cfg, pred.rootOutpoint), null, "the PREDECESSOR root claim is released (not the successor's)");
  assert.equal(await loadSubmissionClaim(cfg, fin.txId), null, "submission claim released");
  const vaultStatuses = r1.vaults.map((v) => v.status);
  assert.deepEqual(vaultStatuses, ["CONSISTENT"], `vault side reconciles CONSISTENT, not UNKNOWN: ${JSON.stringify(r1.vaults)}`);
  /* repeated reconciliation and a retried submit: idempotent, no duplicate advancement */
  const r2 = await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc });
  assert.equal(r2.root.status, "CONSISTENT");
  const again = await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc });
  assert.equal(again.state, "CHAIN_VERIFIED");
  await assertFullyCompleted(cfg, o, fin, "after repeat");
});

test("R7-02 durable completion (c): a VAULT persistence failure after chain proof leaves NO advanced root / cleared pointer / BROADCAST request behind; the next reconciliation completes everything", { skip: SKIP }, async () => {
  const cfg = freshConfig(); const rpc = mockRpc();
  const o = await organization(cfg, rpc);
  const fin = await signedSetAgentRoot(cfg, o);
  await spendPredecessors(cfg, rpc, o);
  settle(cfg, rpc, fin);
  /* inject ONE failure into the vault manifest write */
  const store = require("../src/store").getStore(cfg);
  const realWrite = store.write.bind(store);
  let failed = 0;
  store.write = async (category, key, value) => { if (category === require("../src/store").Categories.VAULT && failed === 0) { failed += 1; throw new Error("disk full (injected)"); } return realWrite(category, key, value); };
  let err = null;
  try { await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }); } catch (e) { err = e; }
  store.write = realWrite;
  assert.ok(err && failed === 1, "the injected failure fired");
  const req = await wr7.loadOrgRootRequest(cfg, fin.id);
  assert.equal(req.state, "RECONCILIATION_REQUIRED", `truthful incomplete status, got ${req.state}`);
  const rootMid = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  assert.notEqual(rootMid.live.outpoint.transactionId, fin.txId, "the root is NOT advanced before the vault write succeeded");
  assert.equal(rootMid.pendingRequestId, fin.id, "the pending pointer is NOT cleared while incomplete");
  assert.equal((await loadManifestV7(cfg, o.vaultId)).agentRegistry.length, 1, "registry unchanged after the failed write");
  const r = await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r));
  await assertFullyCompleted(cfg, o, fin, "after repair");
});

test("R7-02 durable completion (b): a root-only action (no vault operation) still completes on the deferred path with the actual predecessor claim released", { skip: SKIP }, async () => {
  const cfg = freshConfig(); const rpc = mockRpc();
  const o = await organization(cfg, rpc);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(cfg, o.fuelKey) }, signerAddress: ADDR(cfg, o.owner1) });
  for (const [slot, key] of [[1, o.owner1], [2, o.owner2]]) {
    const s = sign65(cfg, req.transaction.unsignedSafeJson, req.rootInputIndex, key);
    const r = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot });
    await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot, response: { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: r.requestVersion, requestId: r.requestId, network: r.network, manifestHash: r.manifestHash, txId: r.txId, root: r.root, slot: r.slot, signerAddress: ADDR(cfg, key), signatureHex: s, sighashType: 1, signedAtMs: Date.now() } });
  }
  const after = await wr7.loadOrgRootRequest(cfg, req.id);
  const kaspa = kaspaOf(cfg);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), after.build.frozen.inputs.length - 1, o.fuelKey);
  const fin = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id, fuelSignatureScriptHex: fuelSig });
  const root0 = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  const predOutpoint = root0.live.outpoint;
  rpc.clear(root0.live.address);
  await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  const outputs = fin.build.frozen.outputs;
  const rootOutIdx = outputs.findIndex((x) => x.covenant && x.covenant.covenantId === o.rootCovenantId);
  const rootAddr = spkAddress(cfg, outputs[rootOutIdx].scriptPublicKey);
  rpc.seed(rootAddr, utxo(rootAddr, fin.txId, rootOutIdx, outputs[rootOutIdx].value, o.rootCovenantId));
  const r1 = await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc });
  assert.equal(r1.root.status, "ADVANCED");
  assert.equal((await wr7.loadOrgRootRequest(cfg, fin.id)).state, "CHAIN_VERIFIED");
  assert.equal(await loadTransitionClaim(cfg, predOutpoint), null, "the PREDECESSOR claim is released");
  assert.equal((await wr7.loadOrgRoot(cfg, o.rootCovenantId)).generation, 1, "exactly ONE root advancement after genesis (generation 0)");
  assert.equal((await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc })).root.status, "CONSISTENT");
});
