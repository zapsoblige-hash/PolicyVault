"use strict";
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const { dep, fx, d, wr } = require("../testutil/rc27f-fixtures");
const { outcomeRpc } = require("../testutil/rc27f-outcome-fixture");
const rec = dep("sdk/src/reconcile-v7"), claims = dep("sdk/src/submission-claim");
let base; before(async () => { base = await d.baseFixture(); });
for (const defect of [null, "body", "header", "confirmation", "trailing", "incomplete", "unaccepted"]) test(`RC27F F-1: delegate conflict ${defect ?? "valid body/header/confirmation"} preserves exact outcome and claims`, async () => {
  const x = d.caseFor(base), { conflictId } = outcomeRpc(x, { conflict: true, defect });
  await assert.rejects(x.submit()); x.config = fx.reloadJsonConfig(x.config);
  const result = await x.reconcile(), q = await x.request();
  if (!defect) {
    assert.equal(result.status, "CLAIM_RELEASED", JSON.stringify(result));
    assert.equal(q.state, "SUPERSEDED"); assert.equal(q.submissionOutcome.proof.acceptedConflictingTxId, conflictId);
    assert.equal(await fx.loadSubmissionClaim(x.config, q.txId), null);
    assert.equal(await claims.loadTransitionClaim(x.config, q.predecessorOutpoint), null);
    await d.signedSpend(x.config, x.o);
  } else {
    assert.equal(result.status, "UNKNOWN", JSON.stringify(result));
    assert.equal(q.state, "RECONCILIATION_REQUIRED");
    assert.ok(await fx.loadSubmissionClaim(x.config, q.txId));
    assert.ok(await claims.loadTransitionClaim(x.config, q.predecessorOutpoint));
    await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
  }
  assert.deepEqual(await x.vault(), x.before); assert.equal(x.rpc.submits(), 1);
});
async function rootCase() {
  const x = d.caseFor(base); x.q = await fx.signedRootOnly(x.config, x.o);
  x.submit = () => wr.submitOrgRootRequest({ config: x.config, requestId: x.q.id, rpc: x.rpc });
  x.request = () => wr.loadOrgRootRequest(x.config, x.q.id);
  x.org = (options = {}) => rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc, stalePendingMinimumMs: 0, ...options });
  return x;
}
for (const mode of ["covenant", "script", "duplicate"]) for (const path of ["submit", "reconcile"]) test(`RC27F F-5: ${path} refuses substituted root ${mode} metadata before completion writes`, async () => {
  const x = await rootCase(), root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  d.settle(x.config, x.rpc, x.q);
  const index = x.q.build.frozen.outputs.findIndex((o) => o.covenant?.covenantId === x.q.rootCovenantId);
  const out = x.q.build.frozen.outputs[index], address = fx.spkAddress(x.config, out.scriptPublicKey);
  const honest = { ...fx.utxo(address, x.q.txId, index, out.value, out.covenant.covenantId), scriptPublicKey: out.scriptPublicKey.scriptHex };
  x.rpc.clear(address);
  x.rpc.seed(address, { ...honest, ...(mode === "covenant" ? { covenantId: fx.H(0xee) } : mode === "script" ? { scriptPublicKey: "51" } : {}) });
  if (mode === "duplicate") x.rpc.seed(address, honest);
  if (path === "submit") await assert.rejects(x.submit(), { code: "RECONCILIATION_REQUIRED" });
  else {
    const submit = x.rpc.submitTransaction.bind(x.rpc);
    x.rpc.submitTransaction = async (args) => { await submit(args); throw Error("STUB accepted/lost response"); };
    await assert.rejects(x.submit());
    await assert.rejects(x.org(), { code: "RECONCILIATION_REQUIRED" });
  }
  assert.deepEqual(await wr.loadOrgRoot(x.config, x.o.rootCovenantId), root);
  assert.notEqual((await x.request()).state, "CHAIN_VERIFIED");
  assert.equal(await fx.loadReceipt(x.config, x.q.txId), null);
  assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 0);
  assert.ok(await fx.loadSubmissionClaim(x.config, x.q.txId));
  x.rpc.clear(address); x.rpc.seed(address, honest); x.config = fx.reloadJsonConfig(x.config);
  await x.org(); await x.submit(); assert.equal((await x.request()).state, "CHAIN_VERIFIED");
  assert.equal(x.rpc.submits(), 1);
});
for (const path of ["submit", "reconcile"]) test(`RC27F F-5: historical ${path} refuses a still-live input of the later proving root`, async () => {
  const x = await rootCase(); d.settle(x.config, x.rpc, x.q); await x.submit();
  const later = await fx.signedRootOnly(x.config, x.o); d.settle(x.config, x.rpc, later);
  await wr.submitOrgRootRequest({ config: x.config, requestId: later.id, rpc: x.rpc });
  const store = fx.getStore(x.config), root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId), request = await x.request();
  await store.remove(fx.Categories.RECEIPT, x.q.txId);
  const spent = later.build.frozen.inputs[later.rootInputIndex], address = fx.spkAddress(x.config, spent.utxo.scriptPublicKey);
  x.rpc.seed(address, fx.utxo(address, spent.previousOutpoint.transactionId, spent.previousOutpoint.index, spent.utxo.amount, spent.utxo.covenantId));
  await assert.rejects(path === "submit" ? x.submit() : x.org(), { code: "RECONCILIATION_REQUIRED" });
  assert.deepEqual(await wr.loadOrgRoot(x.config, x.o.rootCovenantId), root);
  assert.deepEqual(await x.request(), request); assert.equal(await fx.loadReceipt(x.config, x.q.txId), null);
  x.rpc.clear(address); x.config = fx.reloadJsonConfig(x.config);
  await x.org(); await x.submit(); assert.equal((await x.request()).state, "CHAIN_VERIFIED");
  assert.equal(x.rpc.submits(), 2); assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1);
});
for (const mode of ["lost-response", "bound-rejection", "query-unavailable", "mempool-present", "contradictory-output", "disabled-release", "claim-write-failure"]) test(`RC27F F-1/F-7: root ${mode} has durable attempt boundaries and replayable arbitration`, async () => {
  const x = await rootCase(); outcomeRpc(x, { rejection: mode === "bound-rejection" });
  const fault = mode === "claim-write-failure" && fx.inject(x.config, "createExclusive", (c) => c === fx.Categories.SUBMISSION_CLAIM);
  await assert.rejects(x.submit()); if (fault) fault.restore();
  assert.equal((await x.request()).submissionAttempt.phase, mode === "claim-write-failure" ? "PREPARING" : mode === "bound-rejection" ? "REJECTED_RESPONSE" : "BROADCAST_STARTED");
  if (mode === "query-unavailable") x.rpc.getMempoolEntry = async () => { throw Error("missing RPC service"); };
  if (mode === "contradictory-output") fx.settle(x.config, x.rpc, x.q); // predecessor is still reported live too
  if (mode === "mempool-present") {
    const tx = x.q.finalTransaction;
    const transaction = { ...tx, outputs: tx.outputs.map((o) => ({ ...o, scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex } })) };
    x.rpc.getMempoolEntry = async () => ({ mempoolEntry: { transaction, is_orphan: false } });
  }
  x.config = fx.reloadJsonConfig(x.config);
  const r = await x.org({ allowClaimRelease: mode !== "disabled-release" });
  const unresolved = ["query-unavailable", "mempool-present", "contradictory-output", "disabled-release"].includes(mode);
  assert.equal(r.root.status, unresolved ? "CLAIM_PENDING" : "CLAIM_RELEASED", JSON.stringify(r));
  if (unresolved) {
    assert.ok(await fx.loadSubmissionClaim(x.config, x.q.txId));
    assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, x.q.id);
    await assert.rejects(x.submit()); assert.equal(x.rpc.submits(), 1);
    // The very same attempted transaction subsequently lands. Resume, never rebroadcast.
    for (const out of x.q.build.frozen.outputs) x.rpc.clear(fx.spkAddress(x.config, out.scriptPublicKey)); // replace the prior contradictory observation, not append duplicate rows
    d.settle(x.config, x.rpc, x.q); // every frozen input, including fuel, is now spent
    await x.org(); assert.equal((await x.request()).state, "CHAIN_VERIFIED");
  } else {
    assert.equal((await x.request()).state, mode === "bound-rejection" ? "SUBMISSION_REJECTED" : "NOT_BROADCAST");
    assert.equal(await fx.loadSubmissionClaim(x.config, x.q.txId), null);
    assert.equal(await claims.loadTransitionClaim(x.config, x.q.manifest.root.outpoint), null);
    assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, null);
    await fx.signedRootOnly(x.config, x.o);
  }
  assert.equal(x.rpc.submits(), fault ? 0 : 1);
});
test("RC27F F-1: an old orphan vault claim cannot be released by one unspent read and age", async () => {
  const x = d.caseFor(base), outpoint = x.before.live.outpoint;
  await claims.claimTransition(x.config, { outpoint, vaultId: x.o.vaultId, txId: fx.H(0x77), action: "orphan", stateId: x.before.live.stateId });
  const claim = await claims.loadTransitionClaim(x.config, outpoint);
  outcomeRpc(x); await rec.reconcileVault(x.config, x.rpc, x.o.vaultId, { stalePendingMinimumMs: 0 });
  assert.deepEqual(await claims.loadTransitionClaim(x.config, outpoint), claim);
  assert.equal(x.rpc.submits(), 0);
});
test("RC27F F-1/F-7: a same-transaction root request cannot reuse another request's pending claim", async () => {
  const x = await rootCase(); outcomeRpc(x); const stranger = { ...structuredClone(x.q), id: "same-tx-pending-stranger" };
  await assert.rejects(x.submit()); const claim = await claims.loadTransitionClaim(x.config, x.q.manifest.root.outpoint);
  await wr.saveOrgRootRequest(x.config, stranger);
  await assert.rejects(wr.submitOrgRootRequest({ config: x.config, requestId: stranger.id, rpc: x.rpc }), { code: "CLAIM_CONFLICT" });
  assert.equal(x.rpc.submits(), 1); assert.deepEqual(await claims.loadTransitionClaim(x.config, x.q.manifest.root.outpoint), claim);
  assert.equal((await wr.loadOrgRootRequest(x.config, stranger.id)).submissionAttempt, undefined);
});
