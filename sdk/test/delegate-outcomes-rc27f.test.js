"use strict";
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const { dep, fx, d, wr } = require("../testutil/rc27f-fixtures");
let base; before(async () => { base = await d.baseFixture(); });
function caseWithNegativeProof() {
  const x = d.caseFor(base); let attempted = false;
  for (const i of x.q.build.frozen.inputs) {
    const a = fx.spkAddress(x.config, i.utxo.scriptPublicKey);
    x.rpc.seed(a, { ...fx.utxo(a, i.previousOutpoint.transactionId, i.previousOutpoint.index, i.utxo.amount, i.utxo.covenantId), scriptPublicKey: i.utxo.scriptPublicKey.scriptHex });
  }
  const real = x.rpc.submitTransaction.bind(x.rpc);
  x.rpc.submitTransaction = async (args) => { attempted = true; await real(args); throw Error("STUB response lost; acceptance unknown"); };
  x.rpc.getBlockDagInfo = async () => ({ sink: attempted ? fx.H(0x12) : fx.H(0x11) });
  x.rpc.getVirtualChainFromBlock = async () => ({ removedChainBlockHashes: [], addedChainBlockHashes: [fx.H(0x12)], acceptedTransactionIds: [{ acceptingBlockHash: fx.H(0x12), acceptedTransactionIds: [] }] });
  x.rpc.getMempoolEntry = async ({ transactionId }) => { throw Error(`Transaction ${transactionId} not found`); };
  return x;
}
async function uncertain(x) { await assert.rejects(x.submit()); }
async function assertSettledNegative(x, state, broadcasts = 1) {
  assert.equal((await x.request()).state, state);
  assert.equal(await dep("sdk/src/submission-claim").loadTransitionClaim(x.config, x.q.predecessorOutpoint), null);
  assert.equal(await fx.loadSubmissionClaim(x.config, x.q.txId), null);
  assert.deepEqual(await x.vault(), x.before);
  assert.equal(x.rpc.submits(), broadcasts);
  await d.signedSpend(x.config, x.o);
}
for (const rejected of [false, true]) test(`RC27F F-1: ${rejected ? "bound initial rejection" : "transient uncertainty"} settles only with complete negative proof`, async () => {
  const x = caseWithNegativeProof();
  if (rejected) {
    const submit = x.rpc.submitTransaction;
    x.rpc.submitTransaction = async (args) => { try { await submit(args); } catch { throw Error(`Rejected transaction ${x.q.txId}: test consensus refusal`); } };
  }
  await uncertain(x); x.config = fx.reloadJsonConfig(x.config);
  const result = await x.reconcile(); assert.equal(result.status, "CLAIM_RELEASED");
  await assertSettledNegative(x, rejected ? "SUBMISSION_REJECTED" : "NOT_BROADCAST");
  await x.submit(); assert.equal(x.rpc.submits(), 1, "negative result cannot resubmit the old transaction");
});
test("RC27F F-1: unknown/missing RPC errors, malformed mempool and incomplete history never release uncertainty", async () => {
  for (const defect of ["unknown", "missing", "suffix", "shape", "history", "inputs"]) {
    const x = caseWithNegativeProof(); await uncertain(x);
    if (defect === "shape") x.rpc.getMempoolEntry = async () => ({});
    else if (defect === "history") x.rpc.getVirtualChainFromBlock = async () => ({ addedChainBlockHashes: [fx.H(0x12)], acceptedTransactionIds: [] });
    else if (defect === "inputs") x.rpc.getUtxosByAddresses = async () => { throw Error("STUB node unavailable"); };
    else x.rpc.getMempoolEntry = async () => { throw Error(defect === "suffix" ? `Transaction ${x.q.txId} not found: response truncated` : `${defect} RPC resource`); };
    x.config = fx.reloadJsonConfig(x.config);
    assert.equal((await x.reconcile()).status, "UNKNOWN", defect);
    assert.ok(await fx.loadSubmissionClaim(x.config, x.q.txId));
    await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
    assert.equal(x.rpc.submits(), 1);
  }
});
test("RC27F F-1: original transaction landing between output and funding queries is completed, never superseded", async () => {
  const x = caseWithNegativeProof(); await uncertain(x);
  const query = x.rpc.getUtxosByAddresses.bind(x.rpc), a = fx.spkAddress(x.config, x.q.build.frozen.inputs[0].utxo.scriptPublicKey);
  let injected = false;
  x.rpc.getUtxosByAddresses = async (args) => { if (!injected && args.addresses.includes(a)) { injected = true; x.settle(); } return query(args); };
  assert.equal((await x.reconcile()).status, "ADVANCED"); assert.ok(injected);
  await d.assertComplete(x);
});
test("RC27F F-1: failed submission-claim persistence before broadcast has replayable negative settlement", async () => {
  for (const failRelease of [false, true]) {
    const x = caseWithNegativeProof();
    const claim = fx.inject(x.config, "createExclusive", (c) => c === fx.Categories.SUBMISSION_CLAIM);
    const release = failRelease && fx.inject(x.config, "remove", (c) => c === fx.Categories.TRANSITION_CLAIM, { times: Infinity });
    await uncertain(x); claim.restore(); if (release) release.restore();
    assert.equal(x.rpc.submits(), 0);
    x.config = fx.reloadJsonConfig(x.config); await x.reconcile();
    await assertSettledNegative(x, "NOT_BROADCAST", 0);
  }
});
test("RC27F F-1: proven negative settlement releases only its own claims after a failed final write", async () => {
  const x = caseWithNegativeProof(); await uncertain(x);
  const fail = fx.inject(x.config, "write", (c, k, v) => c === fx.Categories.REQUEST && k === x.q.requestId && v.state === "NOT_BROADCAST");
  assert.equal((await x.reconcile()).status, "UNKNOWN"); assert.equal(fail.count(), 1); fail.restore();
  const foreign = { outpoint: x.q.predecessorOutpoint, txId: fx.H(0x99), vaultId: x.o.vaultId, action: "foreign", stateId: x.q.predecessorStateId };
  await dep("sdk/src/submission-claim").claimTransition(x.config, foreign);
  x.config = fx.reloadJsonConfig(x.config); await x.reconcile();
  assert.equal((await x.request()).state, "NOT_BROADCAST");
  assert.equal((await dep("sdk/src/submission-claim").loadTransitionClaim(x.config, foreign.outpoint)).txId, foreign.txId);
  assert.equal(x.rpc.submits(), 1);
});
