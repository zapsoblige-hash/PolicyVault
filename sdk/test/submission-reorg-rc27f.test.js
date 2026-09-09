"use strict";
// Public recovery regression for the naturally removed starting tip observed
// by the RC27F signed-browser run. Real SDK/VM + isolated JSON, stubbed RPC.
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const { dep, fx, d, wr } = require("../testutil/rc27f-fixtures");
const { outcomeRpc } = require("../testutil/rc27f-outcome-fixture");
const rec = dep("sdk/src/reconcile-v7"), claims = dep("sdk/src/submission-claim");
let base; before(async () => { base = await d.baseFixture(); });
async function prepared(kind, variant) {
  const x = d.caseFor(base);
  if (kind === "root") {
    x.q = await fx.signedRootOnly(x.config, x.o);
    x.submit = () => wr.submitOrgRootRequest({ config: x.config, requestId: x.q.id, rpc: x.rpc });
    x.request = () => wr.loadOrgRootRequest(x.config, x.q.id);
  }
  x.recover = () => rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc, stalePendingMinimumMs: 0 });
  const { hashes } = outcomeRpc(x, { rejection: !["ambiguous", "missing-removals", "null-removals"].includes(variant) });
  x.rpc.getVirtualChainFromBlock = async () => { throw Error("STUB first query unavailable; preserve original attempt"); };
  await assert.rejects(x.submit());
  assert.equal((await x.request()).state, "RECONCILIATION_REQUIRED");
  const request = await x.request();
  if (variant === "accepted-phase") request.submissionAttempt.phase = "ACCEPTED_RESPONSE";
  if (variant === "missing-fingerprint") delete request.submissionAttempt.requestFingerprint;
  if (variant === "wrong-fingerprint") request.submissionAttempt.requestFingerprint = fx.H(0xe1);
  if (variant === "wrong-rejection-id") request.submissionAttempt.error = `Rejected transaction ${fx.H(0xe2)}: test consensus refusal`;
  if (kind === "root") await wr.saveOrgRootRequest(x.config, request);
  else await fx.getStore(x.config).write(fx.Categories.REQUEST, request.requestId, request);
  const [start, sink] = hashes, mid = fx.H(0xd1), ancestor = fx.H(0xd2);
  let mempoolReads = 0;
  x.rpc.getVirtualChainFromBlock = async ({ startHash }) => {
    const initial = startHash === start;
    let removed = initial ? [start] : [], added = [sink], ids = [];
    if (variant === "multi-page" || variant === "later-removal" || variant === "sink-missing") {
      if (initial) { removed = [start, ancestor]; added = [mid]; }
      else { assert.equal(startHash, mid); added = variant === "sink-missing" ? [] : [sink]; }
    }
    if (variant === "own-accepted") ids = [x.q.txId];
    if (variant === "malformed-removals") removed = "not-an-array";
    if (variant.startsWith("missing-removals")) removed = undefined;
    if (variant.startsWith("null-removals")) removed = null;
    if (variant === "duplicate-removals") removed = [start, start];
    if (variant === "wrong-anchor") removed = [ancestor];
    if (variant === "overlap") removed = [start, sink];
    if (variant === "later-removal" && !initial) removed = [mid];
    if (variant === "spending-input" || variant === "changing-input") x.rpc.clear(fx.spkAddress(x.config, x.q.build.frozen.inputs.at(-1).utxo.scriptPublicKey));
    if (variant === "late-output") {
      const out = x.q.build.frozen.outputs[0], address = fx.spkAddress(x.config, out.scriptPublicKey);
      x.rpc.seed(address, fx.utxo(address, x.q.txId, 0, out.value, out.covenant?.covenantId ?? null));
    }
    return { removedChainBlockHashes: removed, addedChainBlockHashes: added,
      acceptedTransactionIds: variant === "entries-missing" ? [] : added.map((h) => ({ acceptingBlockHash: h, acceptedTransactionIds: ids })) };
  };
  if (variant === "spending-input") x.rpc.clear(fx.spkAddress(x.config, x.q.build.frozen.inputs.at(-1).utxo.scriptPublicKey));
  if (variant === "mempool-late") x.rpc.getMempoolEntry = async ({ transactionId }) => {
    if (++mempoolReads > 1) return {}; // later unavailable/contradictory answer cannot release
    throw Error(`Transaction ${transactionId} not found`);
  };
  x.config = fx.reloadJsonConfig(x.config);
  x.originalStart = request.submitStartHash; x.kind = kind;
  return x;
}
for (const kind of ["root", "delegate"]) for (const variant of ["single", "multi-page"]) test(`RC27F F-1 reorg: ${kind} bound first rejection recovers original ${variant} removed-anchor window after reload`, async () => {
  const x = await prepared(kind, variant), priorRoot = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  await x.recover(); const q = await x.request();
  assert.equal(q.state, "SUBMISSION_REJECTED", JSON.stringify(q.submissionOutcome ?? q.error));
  assert.equal(q.submitStartHash, x.originalStart, "never re-anchor the durable request");
  assert.equal(q.submissionOutcome.proof.initialAnchorReorg, true);
  assert.equal(q.submissionOutcome.proof.completeAcceptanceWindow, true);
  assert.equal(await fx.loadSubmissionClaim(x.config, q.txId), null);
  const predecessor = kind === "root" ? q.manifest.root.outpoint : q.predecessorOutpoint;
  assert.equal(await claims.loadTransitionClaim(x.config, predecessor), null);
  const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  assert.equal(root.pendingRequestId, null); assert.deepEqual(root.live, priorRoot.live);
  assert.deepEqual(await x.vault(), x.before); assert.equal(x.rpc.submits(), 1);
  await x.recover();
  if (kind === "root") await assert.rejects(x.submit(), { code: "SUBMISSION_REJECTED" }); else await x.submit();
  assert.equal(x.rpc.submits(), 1);
  if (kind === "root") await fx.signedRootOnly(x.config, x.o); else await d.signedSpend(x.config, x.o);
});
for (const kind of ["root", "delegate"]) test(`RC27F F-1 reorg: ${kind} missing removal evidence cannot settle an ambiguous or rejected attempt`, async () => {
  for (const variant of ["missing-removals", "null-removals", "missing-removals-rejected", "null-removals-rejected"]) {
    const x = await prepared(kind, variant);
    await x.recover();
    const q = await x.request();
    assert.equal(q.state, "RECONCILIATION_REQUIRED", variant);
    assert.ok(await fx.loadSubmissionClaim(x.config, q.txId), variant);
    assert.ok(await claims.loadTransitionClaim(x.config, kind === "root" ? q.manifest.root.outpoint : q.predecessorOutpoint), variant);
    assert.equal(x.rpc.submits(), 1, variant);
    if (kind === "root") await assert.rejects(fx.signedRootOnly(x.config, x.o), { code: "ROOT_PENDING_REQUEST" });
    else await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
  }
});
for (const kind of ["root", "delegate"]) test(`RC27F F-1 reorg: ${kind} uncertainty and contradictory windows retain original claims and guards`, async () => {
  for (const variant of ["ambiguous", "accepted-phase", "missing-fingerprint", "wrong-fingerprint", "wrong-rejection-id", "own-accepted", "entries-missing", "sink-missing", "malformed-removals", "duplicate-removals", "wrong-anchor", "overlap", "later-removal", "spending-input", "changing-input", "late-output", "mempool-late"]) {
    const x = await prepared(kind, variant);
    try { await x.recover(); } catch (e) { assert.equal(e.code, "RECONCILIATION_REQUIRED", variant); }
    const q = await x.request(); assert.equal(q.state, "RECONCILIATION_REQUIRED", variant);
    assert.equal(q.submitStartHash, x.originalStart, variant);
    assert.ok(await fx.loadSubmissionClaim(x.config, q.txId), variant);
    assert.ok(await claims.loadTransitionClaim(x.config, kind === "root" ? q.manifest.root.outpoint : q.predecessorOutpoint), variant);
    if (kind === "root") {
      assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, q.id, variant);
      await assert.rejects(fx.signedRootOnly(x.config, x.o), { code: "ROOT_PENDING_REQUEST" });
    } else await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
    assert.equal(x.rpc.submits(), 1, variant);
  }
});
