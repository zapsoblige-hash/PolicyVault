"use strict";
// Actual public SDK builders, designated deterministic test keys and real VM
// finalization, with an explicitly stubbed UTXO table (never a live chain).
const assert = require("node:assert/strict");
const fx = require("./org-root-durable-fixture");
const { wr7 } = fx;
const { reconcileVault } = require("../src/reconcile-v7");
function settle(config, rpc, q) {
  for (const input of q.build.frozen.inputs) rpc.clear(fx.spkAddress(config, input.utxo.scriptPublicKey));
  q.build.frozen.outputs.forEach((out, index) => {
    const address = fx.spkAddress(config, out.scriptPublicKey);
    rpc.seed(address, { ...fx.utxo(address, q.txId, index, out.value, out.covenant?.covenantId), scriptPublicKey: out.scriptPublicKey.scriptHex });
  });
}
async function signedSpend(config, o, { fuel = true, periodsElapsed = "0", spendAmount = "50" } = {}) {
  const before = fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId));
  const q = await wr7.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenAgentSpend", signerAddress: fx.ADDR(config, o.agentKey),
    params: { spendAmount, periodsElapsed, agents: before.agentRegistry.map(({ recipients, ...policy }) => policy), recipient: fx.XO(config, o.recipientKey), recipients: [...o.rTree.recipients], recipientCarryKasSompi: (fx.KAS / 5n).toString(), tokenPosition: before.live.tokenPosition,
      ...(fuel ? { reserveConsumedSompi: "50000", fuel: fx.fuelUtxoFor(config, o.fuelKey) } : {}) } });
  const keys = [[0, o.agentKey]];
  if (fuel) keys.push([q.build.frozen.inputs.length - 1, o.fuelKey]);
  return wr7.finalizeV7WalletRequest({ config, requestId: q.requestId, signedSafeJson: fx.signAll(config, q.transaction.unsignedSafeJson, keys) });
}
async function baseFixture() {
  const config = fx.freshJsonConfig("pv-cp13e-base-"), rpc = fx.mockRpc(), o = await fx.organization(config, rpc);
  const first = await fx.signedSetAgentRoot(config, o);
  await fx.spendPredecessors(config, rpc, o); fx.settle(config, rpc, first);
  await wr7.submitOrgRootRequest({ config, requestId: first.id, rpc });
  const depositor = fx.KEY(config, 0x91);
  const state = { ownerIdentifier: fx.XO(config, depositor), identifierType: 0, amount: 100000n, isMinter: false };
  const program = require("../src/token-program-kcc20").compileKcc20Program({ config, state, familyBound: 2 });
  const deposit = await wr7.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenDeposit", signerAddress: fx.ADDR(config, depositor),
    params: { userPosition: { outpoint: { transactionId: fx.H(0x92), index: 0 }, value: fx.KAS.toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: o.descriptor.tokenCovenantId, state }, depositAmount: "100000", depositCarryKasSompi: fx.KAS.toString(), fuel: fx.fuelUtxoFor(config, o.fuelKey) } });
  const df = await wr7.finalizeV7WalletRequest({ config, requestId: deposit.requestId, signedSafeJson: fx.signAll(config, deposit.transaction.unsignedSafeJson, [[0, depositor], [1, o.fuelKey]]) });
  settle(config, rpc, df); await wr7.submitV7WalletRequest({ config, requestId: df.requestId, rpc });
  const q = await signedSpend(config, o);
  return { config, o, first, deposit: df, q, before: fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId)), root: await wr7.loadOrgRoot(config, o.rootCovenantId) };
}
function caseFor(base, config = fx.cloneJsonConfig(base.config, "pv-cp13e-case-")) {
  const rpc = fx.mockRpc();
  const x = { ...base, config, rpc };
  rpc.seed(base.root.live.address, fx.utxo(base.root.live.address, base.root.live.outpoint.transactionId, base.root.live.outpoint.index, base.root.live.value, base.root.rootCovenantId));
  x.settle = (q = x.q) => settle(x.config, rpc, q);
  x.submit = () => wr7.submitV7WalletRequest({ config: x.config, requestId: x.q.requestId, rpc, pollAttempts: 1, pollDelayMs: 0 });
  x.reconcile = () => reconcileVault(x.config, rpc, x.o.vaultId, { allowClaimRelease: true, stalePendingMinimumMs: 0 });
  x.request = () => wr7.loadV7WalletRequest(x.config, x.q.requestId);
  x.vault = async () => fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId));
  x.timeout = async () => {
    const submit = rpc.submitTransaction.bind(rpc);
    rpc.submitTransaction = async (args) => { await submit(args); throw Error("STUB accepted RPC timeout"); };
    await assert.rejects(x.submit(), (e) => e.code === "RECONCILIATION_REQUIRED");
    rpc.submitTransaction = submit;
  };
  return x;
}
async function assertComplete(x, { broadcasts = 1, generation = x.before.generation + 1, tokenAmount = "99950", spent = "50" } = {}) {
  const q = await x.request(), v = await x.vault();
  assert.equal(q.state, "CHAIN_VERIFIED", q.error);
  assert.equal(v.generation, generation);
  assert.equal(v.live.tokenPosition.state.amount, tokenAmount);
  assert.equal(v.live.stateId, q.build.successorStateId);
  assert.equal(v.live.state.agentRoot, q.build.successorState.agentRoot);
  assert.equal(v.agentRegistry.find((a) => a.agentPk === q.build.callExtra.agentPk).tokenPeriodSpent, spent);
  assert.deepEqual(await wr7.loadOrgRoot(x.config, x.o.rootCovenantId), x.root, "delegate never changes root record");
  assert.equal(await require("../src/submission-claim").loadTransitionClaim(x.config, q.predecessorOutpoint), null);
  assert.equal(await fx.loadSubmissionClaim(x.config, q.txId), null);
  const receipt = await fx.loadReceipt(x.config, q.txId);
  assert.equal(receipt.proof.requestId, q.requestId);
  assert.equal(receipt.proof.requestFingerprint, wr7.completionReceiptPointer(q).requestFingerprint);
  assert.equal((await fx.auditLinesFor(x.config, q.txId)).length, 1);
  assert.equal(x.rpc.submits(), broadcasts);
}
const boundaries = {
  replayRequest: ["write", (x, cat, key, v) => cat === fx.Categories.REQUEST && key === x.q.requestId && v.state === "RECONCILIATION_REQUIRED"],
  vault: ["write", (x, cat, key) => cat === fx.Categories.VAULT && key === x.o.vaultId],
  receipt: ["write", (x, cat, key) => cat === fx.Categories.RECEIPT && key === x.q.txId],
  audit: ["appendAudit", (x, e) => e.txId === x.q.txId],
  predecessorRelease: ["remove", (x, cat, key) => cat === fx.Categories.TRANSITION_CLAIM && key === fx.transitionClaimKey(x.q.predecessorOutpoint)],
  submissionRelease: ["remove", (x, cat, key) => cat === fx.Categories.SUBMISSION_CLAIM && key === x.q.txId],
  finalRequest: ["write", (x, cat, key, v) => cat === fx.Categories.REQUEST && key === x.q.requestId && v.state === "CHAIN_VERIFIED"]
};
module.exports = { fx, baseFixture, caseFor, signedSpend, settle, assertComplete, boundaries };
