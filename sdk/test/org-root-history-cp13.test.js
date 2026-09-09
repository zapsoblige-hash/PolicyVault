"use strict";
const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const fx = require("../testutil/org-root-durable-fixture");
const { persistManifestV7 } = require("../src/manifest-v7");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { claimTransition } = require("../src/submission-claim");
const { wr7, Categories } = fx;
const skip = fx.toolchainAvailable() ? undefined : "REQUIREMENT_NOT_AVAILABLE: real v7 compiler/VM";
let base;
before(async () => {
  if (skip) return;
  const config = fx.freshJsonConfig("pv-cp13-history-");
  const rpc = fx.mockRpc(), o = await fx.organization(config, rpc);
  const first = await fx.signedSetAgentRoot(config, o);
  await fx.spendPredecessors(config, rpc, o); fx.settle(config, rpc, first);
  await wr7.submitOrgRootRequest({ config, requestId: first.id, rpc });
  base = { config, o, first };
});
async function copy() {
  const config = fx.cloneJsonConfig(base.config, "pv-cp13-history-case-");
  const rpc = fx.mockRpc(); fx.settle(config, rpc, base.first);
  return { config, rpc, o: base.o, first: base.first };
}
async function next(x, vaultOp) {
  const second = await fx.signedRootAction(x.config, x.o, { vaultOperations: vaultOp ? [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] : [] });
  if (vaultOp) await fx.spendPredecessors(x.config, x.rpc, x.o);
  else x.rpc.clear((await wr7.loadOrgRoot(x.config, x.o.rootCovenantId)).live.address);
  fx.settle(x.config, x.rpc, second);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: second.id, rpc: x.rpc });
  return second;
}

test("CP13 real SDK/VM builds: later ownerPause proves BEYOND; historical submit/reconcile preserve both records", { skip }, async () => {
  const x = await copy(), second = await next(x, true);
  const before = fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId));
  const config = fx.reloadJsonConfig(x.config);
  assert.equal((await wr7.submitOrgRootRequest({ config, requestId: x.first.id, rpc: x.rpc })).state, "CHAIN_VERIFIED");
  assert.equal((await wr7.submitOrgRootRequest({ config, requestId: second.id, rpc: x.rpc })).state, "CHAIN_VERIFIED");
  await reconcileOrgRootV7(config, x.o.rootCovenantId, { rpc: x.rpc });
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(config, x.o.vaultId)), before);
  assert.equal(before.generation, 2); assert.equal(before.status, "PAUSED");
  assert.equal((await wr7.loadOrgRoot(config, x.o.rootCovenantId)).generation, 2);
  for (const q of [x.first,second]) assert.equal((await fx.auditLinesFor(config, q.txId)).length, 1);
  assert.equal(x.rpc.submits(), 1, "only the second action was broadcast by this case");
});

test("CP13 real later transition: receipt repair and downgraded history are discoverable after reload", { skip }, async () => {
  const x = await copy(), second = await next(x, true);
  const store = fx.getStore(x.config), q = await wr7.loadOrgRootRequest(x.config, x.first.id);
  const receipt = await fx.loadReceipt(x.config, x.first.txId);
  await store.write(Categories.RECEIPT, q.txId, { ...receipt, vaultId: fx.H(0x89) });
  q.state = "RECONCILIATION_REQUIRED"; await wr7.saveOrgRootRequest(x.config, q);
  const config = fx.reloadJsonConfig(x.config);
  const result = await reconcileOrgRootV7(config, x.o.rootCovenantId, { rpc: x.rpc });
  assert.ok(result.root.completion.some((c) => c.requestId === q.id && c.replayed));
  assert.equal((await wr7.loadOrgRootRequest(config, q.id)).state, "CHAIN_VERIFIED");
  assert.equal((await fx.loadReceipt(config, q.txId)).vaultId, x.o.rootCovenantId);
  assert.equal((await wr7.loadOrgRoot(config, x.o.rootCovenantId)).live.outpoint.transactionId, second.txId);
  assert.equal((await fx.auditLinesFor(config, q.txId)).length, 1);
});

test("CP13 real history: inconsistent later state/registry cannot be justified by its genuine transition receipt", { skip }, async () => {
  const x = await copy(); await next(x, true);
  const vault = fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId));
  const validVault = structuredClone(vault);
  const prior = fx.manifestToJsonV7(await fx.loadManifestV7(base.config, x.o.vaultId));
  // Keep a real later txid, receipt and generation, but substitute the old state.
  vault.live.state = prior.live.state; vault.live.stateId = prior.live.stateId;
  vault.live.scriptSha256 = prior.live.scriptSha256; vault.live.outpointValue = prior.live.outpointValue;
  vault.agentRegistry = prior.agentRegistry; vault.status = "ACTIVE";
  await persistManifestV7(x.config, vault);
  const installedVault = fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId));
  const priorRequest = await wr7.loadOrgRootRequest(x.config, x.first.id), priorRoot = await wr7.loadOrgRoot(x.config, x.o.rootCovenantId);
  await assert.rejects(wr7.submitOrgRootRequest({ config: x.config, requestId: x.first.id, rpc: x.rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.deepEqual(await wr7.loadOrgRootRequest(x.config, x.first.id), priorRequest, "failed inspection preserves established completion");
  assert.deepEqual(await wr7.loadOrgRoot(x.config, x.o.rootCovenantId), priorRoot, "failed inspection never restores a historical pending pointer");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId)), installedVault);
  const requestCount = (await wr7.listOrgRootRequests(x.config)).length;
  await assert.rejects(wr7.buildRootActionRequest({ config: fx.reloadJsonConfig(x.config), rootCovenantId: x.o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(x.config, x.o.owner1), params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] }), (e) => e.code === "VAULT_PENDING_REQUEST", "contradictory current state is refused before a new owner operation is persisted");
  assert.equal((await wr7.listOrgRootRequests(x.config)).length, requestCount);
  assert.deepEqual(await wr7.loadOrgRoot(x.config, x.o.rootCovenantId), priorRoot);
  await persistManifestV7(x.config, validVault);
  await reconcileOrgRootV7(fx.reloadJsonConfig(x.config), x.o.rootCovenantId, { rpc: x.rpc });
  assert.equal((await wr7.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(x.config, x.o.owner1), params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerUnpause", params: {} }] })).state, "AUTHORIZED");
});

test("RC27F admission: a vault's current owner effect does not require tracing later root-only history", { skip }, async () => {
  const x = await copy(), later = await next(x, false);
  const fault = fx.inject(x.config, "readAudit", (query) => query.txId === later.txId, { times: Infinity });
  try {
    const q = await wr7.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(x.config, x.o.owner1), params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
    assert.equal(q.state, "AUTHORIZED");
    assert.equal(fault.count(), 0, "unrelated later root-only completion history is outside the vault admission proof");
  } finally { fault.restore(); }
});

test("CP13 real history: legacy stale vault repairs only with its continuation observed; false terminal labels do not bypass it", { skip }, async () => {
  const x = await copy(); await next(x, false);
  const first = await wr7.loadOrgRootRequest(x.config, x.first.id);
  const original = fx.manifestToJsonV7(await fx.loadManifestV7(x.config, x.o.vaultId));
  const stale = { ...original, live: { ...original.live, state: first.build.stateJson, stateId: first.build.predecessorStateId, outpoint: first.build.predecessorOutpoint, outpointValue: first.build.stateJson.feeReserve }, agentRegistry: [{ ...x.o.policy, recipients: [...x.o.rTree.recipients] }], generation: 0, latestTransitionTxId: null };
  const compiled = require("../src/contract-compiler-v7").compileExactStateV7({ config: x.config, template: stale.template, state: stale.live.state, contractVersion: stale.contractVersion });
  stale.live.scriptSha256 = compiled.scriptSha256;
  await persistManifestV7(x.config, stale);
  await claimTransition(x.config, { outpoint: first.build.predecessorOutpoint, txId: first.txId, action: first.action, vaultId: x.o.vaultId });
  const output = first.build.frozen.outputs.find((o) => o.covenant?.covenantId === first.build.covenantId);
  const address = fx.spkAddress(x.config, output.scriptPublicKey);
  x.rpc.clear(address);
  await assert.rejects(wr7.submitOrgRootRequest({ config: x.config, requestId: first.id, rpc: x.rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await fx.loadManifestV7(x.config, x.o.vaultId)).generation, 0);
  const idx = first.build.frozen.outputs.indexOf(output);
  x.rpc.seed(address, fx.utxo(address, first.txId, idx, output.value, first.build.covenantId));
  assert.equal((await wr7.submitOrgRootRequest({ config: fx.reloadJsonConfig(x.config), requestId: first.id, rpc: x.rpc })).state, "CHAIN_VERIFIED");
  assert.equal((await fx.loadManifestV7(x.config, x.o.vaultId)).generation, 1);
  assert.equal(await require("../src/submission-claim").loadTransitionClaim(x.config, first.build.predecessorOutpoint), null);
});


test("CP13 real deposit and delegate spend: later token metadata and policy remain intact during historical root retry", { skip }, async () => {
  const x = await copy(), { config, o, rpc } = x;
  const depositor = fx.KEY(config, 0x91);
  const userState = { ownerIdentifier: fx.XO(config, depositor), identifierType: 0, amount: 100000n, isMinter: false };
  const program = require("../src/token-program-kcc20").compileKcc20Program({ config, state: userState, familyBound: 2 });
  const deposit = await wr7.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenDeposit",
    params: { userPosition: { outpoint: { transactionId: fx.H(0x92), index: 0 }, value: fx.KAS.toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: o.descriptor.tokenCovenantId, state: userState }, depositAmount: "100000", depositCarryKasSompi: fx.KAS.toString(), fuel: fx.fuelUtxoFor(config, o.fuelKey) }, signerAddress: fx.ADDR(config, depositor) });
  async function finalizeAndSubmit(q, keys) {
    const fin = await wr7.finalizeV7WalletRequest({ config, requestId: q.requestId, signedSafeJson: fx.signAll(config, q.transaction.unsignedSafeJson, keys) });
    // A settled transaction consumes its inputs. CP13E also checks those
    // predecessor queries instead of accepting contradictory mock UTXOs.
    for (const input of fin.build.frozen.inputs) rpc.clear(fx.spkAddress(config, input.utxo.scriptPublicKey));
    for (let i = 0; i < fin.build.frozen.outputs.length; i++) {
      const out = fin.build.frozen.outputs[i], address = fx.spkAddress(config, out.scriptPublicKey);
      rpc.seed(address, fx.utxo(address, fin.txId, i, out.value, out.covenant?.covenantId));
    }
    return wr7.submitV7WalletRequest({ config, requestId: q.requestId, rpc });
  }
  await finalizeAndSubmit(deposit, [[0, depositor], [1, o.fuelKey]]);
  const afterDeposit = fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId));
  assert.equal((await wr7.submitOrgRootRequest({ config, requestId: x.first.id, rpc })).state, "CHAIN_VERIFIED");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId)), afterDeposit);
  const spend = await wr7.buildV7WalletRequest({ config, vaultId: o.vaultId, action: "tokenAgentSpend",
    params: { spendAmount: "50", agents: afterDeposit.agentRegistry.map(({ recipients, ...policy }) => policy), recipient: fx.XO(config, o.recipientKey), recipients: [...o.rTree.recipients], recipientCarryKasSompi: (fx.KAS / 5n).toString(), reserveConsumedSompi: "50000", fuel: fx.fuelUtxoFor(config, o.fuelKey), tokenPosition: afterDeposit.live.tokenPosition }, signerAddress: fx.ADDR(config, o.agentKey) });
  const fin = await finalizeAndSubmit(spend, [[0, o.agentKey], [spend.transaction.signInputs.length - 1, o.fuelKey]]);
  const afterSpend = fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId));
  assert.equal(afterSpend.live.tokenPosition.state.amount, "99950");
  assert.equal(afterSpend.generation, 3);
  assert.equal((await wr7.submitOrgRootRequest({ config: fx.reloadJsonConfig(config), requestId: x.first.id, rpc })).state, "CHAIN_VERIFIED");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId)), afterSpend);
  assert.equal((await fx.auditLinesFor(config, x.first.txId)).length, 1);
  assert.equal((await fx.loadReceipt(config, fin.txId)).proof.requestId, spend.requestId);
  const stale = structuredClone(afterSpend);
  stale.live.tokenPosition = afterDeposit.live.tokenPosition;
  await persistManifestV7(config, stale);
  const installedStale = fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId));
  const priorRequest = await wr7.loadOrgRootRequest(config, x.first.id), priorRoot = await wr7.loadOrgRoot(config, o.rootCovenantId);
  await assert.rejects(wr7.submitOrgRootRequest({ config, requestId: x.first.id, rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(config, o.vaultId)), installedStale);
  assert.deepEqual(await wr7.loadOrgRootRequest(config, x.first.id), priorRequest);
  assert.deepEqual(await wr7.loadOrgRoot(config, o.rootCovenantId), priorRoot);
  await assert.rejects(wr7.buildRootActionRequest({ config: fx.reloadJsonConfig(config), rootCovenantId: o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(config, o.owner1), params: { fuel: fx.fuelUtxoFor(config, o.fuelKey) }, vaultOperations: [{ vaultId: o.vaultId, action: "ownerPause", params: {} }] }), (e) => e.code === "VAULT_PENDING_REQUEST", "contradictory token lineage still blocks the next operation");

});
