"use strict";
const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const { fx, baseFixture, caseFor, signedSpend, assertComplete, boundaries } = require("../testutil/cp13e-delegate-fixture");
const { wr7, Categories } = fx;
const { persistManifestV7 } = require("../src/manifest-v7");
const skip = fx.toolchainAvailable() ? undefined : "REQUIREMENT_NOT_AVAILABLE: real v7 compiler/VM";
let base;
before(async () => { if (!skip) base = await baseFixture(); });

test("CP13E real SDK/VM + JSON: honest inline and accepted-timeout reload recover the same request exactly once", { skip }, async () => {
  for (const deferred of [false, true]) {
    const x = caseFor(base);
    if (deferred) { await x.timeout(); x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "UNKNOWN"); }
    x.settle();
    if (deferred) assert.equal((await x.reconcile()).status, "ADVANCED"); else await x.submit();
    x.config = fx.reloadJsonConfig(x.config);
    await Promise.all([x.submit(), x.reconcile(), x.submit()]); await assertComplete(x);
  }
});
for (const [stage, [method, predicate]] of Object.entries(boundaries)) test(`CP13E real SDK/VM + JSON persistent ${stage}: every reload still fails until the fault is removed`, { skip }, async () => {
  const x = caseFor(base); await x.timeout(); x.settle();
  for (let attempt = 0; attempt < 2; attempt++) {
    x.config = fx.reloadJsonConfig(x.config);
    const fault = fx.inject(x.config, method, (...args) => predicate(x, ...args), { times: Infinity, message: "PERSISTENT_CP13E_" + stage });
    const r = await x.reconcile(); assert.equal(r.status, "UNKNOWN", JSON.stringify(r)); assert.ok(fault.count() > 0);
    assert.equal((await x.request()).state, "RECONCILIATION_REQUIRED");
    const v = await x.vault();
    assert.ok(v.generation === base.before.generation || v.generation === base.before.generation + 1);
    assert.equal(v.live.tokenPosition.state.amount, v.generation === base.before.generation ? "100000" : "99950");
    await assert.rejects(wr7.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(x.config, x.o.owner1), vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause" }], params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) } }), (e) => e.code === "VAULT_PENDING_REQUEST");
    fault.restore();
  }
  x.config = fx.reloadJsonConfig(x.config); await Promise.all([x.submit(), x.reconcile(), x.submit()]); await assertComplete(x);
});
test("CP13E real SDK/VM + JSON: legacy missing pointer, pointer-only and completed-vault partials are publicly discoverable", { skip }, async () => {
  for (const kind of ["missing-pointer", "pointer-only", "advanced-vault"]) {
    const x = caseFor(base); x.settle();
    if (kind === "advanced-vault") await x.submit(); else await x.timeout();
    const q = await x.request(); q.state = "SUBMITTED"; delete q.predecessorVault;
    await wr7.saveV7WalletRequest(x.config, q);
    // Actual pre-snapshot records predate the request-bound submission field.
    // Preserve their claims, but do not retain a fingerprint of deleted data.
    const submission = await fx.getStore(x.config).read(Categories.SUBMISSION_CLAIM, q.txId);
    if (submission) { delete submission.expected; await fx.getStore(x.config).write(Categories.SUBMISSION_CLAIM, q.txId, submission); }
    if (kind !== "advanced-vault") {
      const claim = await require("../src/submission-claim").loadTransitionClaim(x.config, q.predecessorOutpoint);
      claim.expected = { kind: "v7Successor", txId: q.txId, ...(kind === "pointer-only" ? { requestId: q.requestId } : {}) };
      await fx.getStore(x.config).write(Categories.TRANSITION_CLAIM, fx.transitionClaimKey(q.predecessorOutpoint), claim);
    } else await fx.getStore(x.config).remove(Categories.RECEIPT, q.txId);
    x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "ADVANCED", kind); await assertComplete(x);
  }
});
test("CP13E real SDK/VM: reserve-funded and rollover delegate forms use the same replayable completion", { skip }, async () => {
  for (const options of [{ fuel: false }, { periodsElapsed: "2" }]) {
    const x = caseFor(base); x.q = await signedSpend(x.config, x.o, options);
    await x.timeout(); x.settle(); x.config = fx.reloadJsonConfig(x.config);
    const r = await x.reconcile(); assert.equal(r.status, "ADVANCED", JSON.stringify(r)); await assertComplete(x);
    assert.equal((await x.vault()).agentRegistry.find((e) => e.agentPk === x.q.build.callExtra.agentPk).periodStartDaa, options.periodsElapsed ? "7000" : "5000");
  }
});
test("CP13E real SDK/VM history: later ownerPause preserves truthful delegate retry and repairs receipt without rollback", { skip }, async () => {
  const x = caseFor(base); x.settle(); await x.submit();
  const second = await fx.signedRootAction(x.config, x.o, { vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, second);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: second.id, rpc: x.rpc });
  const current = await x.vault(), root = await wr7.loadOrgRoot(x.config, x.o.rootCovenantId);
  await fx.getStore(x.config).remove(Categories.RECEIPT, x.q.txId);
  const q = await x.request(); q.state = "RECONCILIATION_REQUIRED"; await wr7.saveV7WalletRequest(x.config, q);
  x.config = fx.reloadJsonConfig(x.config);
  assert.equal((await x.reconcile()).status, "ADVANCED"); assert.equal((await x.submit()).state, "CHAIN_VERIFIED");
  assert.deepEqual(await x.vault(), current); assert.deepEqual(await wr7.loadOrgRoot(x.config, x.o.rootCovenantId), root);
  assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1); assert.equal(x.rpc.submits(), 2);
  const substituted = structuredClone(current); substituted.live.tokenPosition = base.before.live.tokenPosition;
  await persistManifestV7(x.config, substituted); const installed = await x.vault();
  await assert.rejects(x.submit()); assert.deepEqual(await x.vault(), installed);
});
test("CP13E real SDK/VM history: a later actual delegate spend connects both vault and token predecessors", { skip }, async () => {
  const x = caseFor(base); x.settle(); await x.submit();
  const second = await signedSpend(x.config, x.o, { spendAmount: "25" });
  x.settle(second); await wr7.submitV7WalletRequest({ config: x.config, requestId: second.requestId, rpc: x.rpc, pollAttempts: 1 });
  const current = await x.vault(); assert.equal(current.live.tokenPosition.state.amount, "99925");
  assert.equal((await x.submit()).state, "CHAIN_VERIFIED"); assert.deepEqual(await x.vault(), current);
  const q = await x.request(); q.state = "RECONCILIATION_REQUIRED"; await wr7.saveV7WalletRequest(x.config, q);
  x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "ADVANCED");
  assert.deepEqual(await x.vault(), current); assert.equal(x.rpc.submits(), 2);
});
test("CP13E real SDK/VM history: legacy completed delegate without a snapshot remains truthful after an actual ownerPause", { skip }, async () => {
  const x = caseFor(base); x.settle(); await x.submit();
  const q = await x.request(); delete q.predecessorVault; await wr7.saveV7WalletRequest(x.config, q);
  const receipt = await fx.loadReceipt(x.config, q.txId);
  await fx.getStore(x.config).write(Categories.RECEIPT, q.txId, { ...receipt, proof: { ...receipt.proof, ...wr7.completionReceiptPointer(q) } });
  const next = await fx.signedRootAction(x.config, x.o, { vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause" }] });
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, next);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: next.id, rpc: x.rpc });
  const current = await x.vault(); q.state = "RECONCILIATION_REQUIRED"; await wr7.saveV7WalletRequest(x.config, q);
  x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "ADVANCED");
  assert.deepEqual(await x.vault(), current); assert.equal((await x.request()).predecessorVault.generation, base.before.generation);
});
test("CP13E real SDK/VM history: a later installed registry does not roll back during delegate repair", { skip }, async () => {
  const x = caseFor(base); x.settle(); await x.submit();
  const next = await fx.signedSetAgentRoot(x.config, x.o);
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, next);
  await wr7.submitOrgRootRequest({ config: x.config, requestId: next.id, rpc: x.rpc });
  const current = await x.vault(); const q = await x.request(); q.state = "RECONCILIATION_REQUIRED"; await wr7.saveV7WalletRequest(x.config, q);
  x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "ADVANCED");
  assert.deepEqual(await x.vault(), current); assert.equal((await fx.auditLinesFor(x.config, q.txId)).length, 1);
});
test("CP13E JSON: canonical request key refusal occurs before lookup/broadcast, including a mismatched embedded ID", { skip }, async () => {
  const x = caseFor(base);
  for (const id of ["../alias", ".", "x/y", "x\\y"]) await assert.rejects(wr7.submitV7WalletRequest({ config: x.config, requestId: id, rpc: x.rpc }));
  const q = await x.request(); await fx.getStore(x.config).write(Categories.REQUEST, q.requestId, { ...q, requestId: "substituted-id" });
  await assert.rejects(x.submit(), (e) => e.code === "REQUEST_ID_MISMATCH"); assert.equal(x.rpc.submits(), 0);
});
test("CP13E JSON: concurrent finalization/withdrawal cannot rewind a completed delegate request", { skip }, async () => {
  for (const other of ["finalize", "withdraw"]) {
    const x = caseFor(base), q = await x.request(); q.state = "BUILT"; await wr7.saveV7WalletRequest(x.config, q);
    const args = { config: x.config, requestId: q.requestId, signedSafeJson: fx.signAll(x.config, q.transaction.unsignedSafeJson, [[0, x.o.agentKey], [q.build.frozen.inputs.length - 1, x.o.fuelKey]]) };
    const first = wr7.finalizeV7WalletRequest(args);
    const second = other === "finalize" ? wr7.finalizeV7WalletRequest(args) : wr7.markV7WalletRejected(x.config, q.requestId);
    const results = await Promise.allSettled([first, second]);
    assert.equal(results[0].status, "fulfilled");
    if (other === "finalize") { assert.equal(results[1].status, "rejected"); assert.equal(results[1].reason.code, "SIGNED"); }
    else assert.equal(results[1].value.state, "SIGNED");
    x.settle(); await x.submit(); await assertComplete(x);
    assert.equal((await wr7.markV7WalletRejected(x.config, q.requestId)).state, "CHAIN_VERIFIED");
    await assert.rejects(wr7.finalizeV7WalletRequest(args), (e) => e.code === "CHAIN_VERIFIED");
    await assertComplete(x);
  }
});
test("CP13E JSON: bound legacy SIGNED rewind is discovered after reload; a same-tx prebuilt request cannot steal its receipt", { skip }, async () => {
  const x = caseFor(base), oldSigned = await x.request(); x.settle(); await x.submit();
  await wr7.saveV7WalletRequest(x.config, oldSigned); // saved late-finalizer shape from the reproduced race
  const duplicate = { ...oldSigned, requestId: "another-signed-request" };
  await wr7.saveV7WalletRequest(x.config, duplicate);
  x.config = fx.reloadJsonConfig(x.config); assert.equal((await x.reconcile()).status, "ADVANCED"); await assertComplete(x);
  await assert.rejects(wr7.submitV7WalletRequest({ config: x.config, requestId: duplicate.requestId, rpc: x.rpc, pollAttempts: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  await assertComplete(x);
});
