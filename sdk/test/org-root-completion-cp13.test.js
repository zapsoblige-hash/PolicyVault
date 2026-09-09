"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const memoryRoot = require("../testutil/cp13-memory");

// Models a later root-only transaction at the RPC boundary. The separate
// real-build integration controls construct/sign the same operation through
// supported SDK builders; this fast layer exercises persistence semantics.
async function laterRoot(x) {
  const q = x.clone(x.req), root = await x.readRoot();
  q.id = "second-request"; q.txId = x.H("88"); q.state = "RECONCILIATION_REQUIRED";
  q.manifest = x.clone(q.manifest);
  q.manifest.root.outpoint = root.live.outpoint;
  q.manifest.rootState.before.state = root.state;
  const next = { ...root.state, rootNonce: String(BigInt(root.state.rootNonce) + 1n) };
  q.manifest.rootState.after.state = next;
  q.manifest.transaction.txId = q.txId;
  const out = x.clone(x.fr.outputs.find((o) => o.covenant?.covenantId === x.rootId));
  out.scriptPublicKey.scriptHex = "aa88";
  const frozen = { ...x.clone(x.fr), outputs: [out] };
  const rootInput = frozen.inputs.find((input) => input.utxo.covenantId === x.rootId);
  assert.ok(rootInput, "modeled transaction includes the actual current root predecessor");
  rootInput.previousOutpoint = x.clone(root.live.outpoint);
  rootInput.utxo.scriptPublicKey = x.clone(x.fr.outputs.find((o) => o.covenant?.covenantId === x.rootId).scriptPublicKey);
  rootInput.utxo.amount = root.live.value;
  x.registerTransaction(frozen, q.txId);
  q.build = { kind: "orgRootTransition", frozen, successorState: next };
  q.finalTransaction = frozen; q.vaultOperations = []; q.newRegistry = null;
  const vaultOut = x.fr.outputs.find((o) => o.covenant?.covenantId !== x.rootId && o.covenant);
  x.rpc.query = async (address) => {
    if (address === "spk:aa88") return [{ outpoint: { transactionId: q.txId, index: 0 }, amount: BigInt(out.value), covenantId: x.rootId }];
    if (address === "spk:" + vaultOut.scriptPublicKey.scriptHex) return [{ outpoint: { transactionId: x.txid, index: x.fr.outputs.indexOf(vaultOut) }, amount: BigInt(vaultOut.value), covenantId: vaultOut.covenant.covenantId }];
    return [];
  };
  await x.wr.saveOrgRootRequest(x.cfg, q);
  await x.wr.submitOrgRootRequest({ config: x.cfg, requestId: q.id, rpc: x.rpc });
  return q;
}

test("CP13 honest public recovery and retry remain complete without rebroadcast", async () => {
  const x = memoryRoot(); await x.reset();
  assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED");
  x.reload(); assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED");
  assert.equal((await x.status()).auditCount, 1);
  assert.ok(!x.getEvents().includes("STUB_SUBMIT"));
});

test("CP13 R7-02/A: unrelated outpoint + generation 2 + stale policy cannot complete", async () => {
  for (const latest of ["98", "99"]) {
    const x = memoryRoot(); await x.reset();
    const vault = x.clone(x.doc);
    vault.live.outpoint = { transactionId: x.H("99"), index: 7 };
    vault.latestTransitionTxId = x.H(latest); vault.generation = 2;
    await x.manifestModule.persistManifestV7(x.cfg, vault); x.reload();
    assert.equal((await x.invoke("submit")).error, "RECONCILIATION_REQUIRED");
    const state = await x.status();
    assert.equal(state.requestState, "RECONCILIATION_REQUIRED");
    assert.equal(state.pending, x.req.id); assert.equal(state.oldRootClaim, true);
    assert.equal(state.auditCount, 0); assert.equal(state.vaultGeneration, 2);
  }
});

test("CP13 R7-02/B: completed historical request survives a later root through submit/reconcile", async () => {
  const x = memoryRoot(); await x.reset(); await x.invoke("submit");
  const q = await laterRoot(x); x.reload();
  assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED");
  await x.invoke("reconcile");
  assert.equal((await x.readRequest()).state, "CHAIN_VERIFIED");
  assert.equal((await x.readRoot()).live.outpoint.transactionId, q.txId);
  assert.equal((await x.readRoot()).generation, 2);
  assert.equal(x.getAudits().filter((e) => e.txId === x.txid).length, 1);
  assert.equal((await x.wr.submitOrgRootRequest({ config: x.cfg, requestId: q.id, rpc: x.rpc })).state, "CHAIN_VERIFIED");
});

test("CP13 R7-02/C: concurrent public submit/submit and submit/reconcile emit once", async () => {
  for (const other of ["submit", "reconcile"]) {
    const x = memoryRoot(); await x.reset();
    const results = await Promise.all([x.invoke("submit"), x.invoke(other)]);
    assert.ok(results.every((r) => !r.error), JSON.stringify(results));
    const state = await x.status();
    assert.equal(state.auditCount, 1); assert.equal(state.rootGeneration, 1);
    assert.equal(state.vaultGeneration, 1); assert.equal(state.pending, null);
    assert.ok(!x.getEvents().includes("STUB_SUBMIT"));
  }
});

test("CP13 R7-02/C: failed queued completion releases exclusion and retry succeeds", async () => {
  const x = memoryRoot(); await x.reset(); x.setFault("receipt");
  const a = await Promise.all([x.invoke("submit"), x.invoke("reconcile")]);
  assert.ok(a.every((r) => r.error === "RECONCILIATION_REQUIRED"));
  x.setFault(null); x.reload();
  assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED");
  assert.equal((await x.status()).auditCount, 1);
});

test("CP13 R7-02/D: correct/absent/foreign-root receipts repair across historical retry", async () => {
  for (const historical of [false, true]) for (const mode of ["correct", "absent", "foreign"]) {
    const x = memoryRoot(); await x.reset(); await x.invoke("submit");
    if (historical) await laterRoot(x);
    const receipt = await x.store.read(x.Categories.RECEIPT, x.txid);
    if (mode === "absent") await x.store.remove(x.Categories.RECEIPT, x.txid);
    if (mode === "foreign") await x.store.write(x.Categories.RECEIPT, x.txid, { ...receipt, vaultId: x.H("89") });
    x.reload();
    assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED", `${historical}/${mode}`);
    assert.equal((await x.store.read(x.Categories.RECEIPT, x.txid)).vaultId, x.rootId);
    assert.equal(x.getAudits().filter((e) => e.txId === x.txid).length, 1);
    assert.equal((await x.readRoot()).generation, historical ? 2 : 1);
  }
});

test("CP13 persistent faults survive reload/public retries then complete exactly once", async () => {
  for (const stage of ["vaultWrite", "rootWrite", "rootRelease", "vaultRelease", "submissionRelease", "receipt", "audit", "finalRequest", "pointerClear"]) {
    const x = memoryRoot(); await x.reset(); x.setFault(stage);
    for (const path of ["submit", "submit", "reconcile"]) {
      assert.equal((await x.invoke(path)).error, "RECONCILIATION_REQUIRED", stage + "/" + path);
      x.reload(); assert.equal((await x.readRoot()).pendingRequestId, x.req.id);
    }
    x.setFault(null); await x.invoke("reconcile");
    const state = await x.status();
    assert.equal(state.complete, true, stage); assert.equal(state.auditCount, 1, stage);
    assert.equal(state.rootGeneration, 1, stage); assert.equal(state.vaultGeneration, 1, stage);
    assert.ok(!x.getEvents().includes("STUB_SUBMIT"), stage);
  }
});


test("CP13 root queue: distinct stores with the same root/request identity keep their own failure and completion", async () => {
  const left = memoryRoot(), right = memoryRoot();
  await left.reset(); await right.reset(); left.setFault("receipt");
  const [a, b] = await Promise.all([left.invoke("submit"), right.invoke("submit")]);
  assert.equal(a.error, "RECONCILIATION_REQUIRED");
  assert.equal(b.result, "CHAIN_VERIFIED");
  assert.equal((await left.status()).pending, left.req.id);
  assert.equal((await right.status()).pending, null);
  left.setFault(null); left.reload();
  assert.equal((await left.invoke("submit")).result, "CHAIN_VERIFIED");
  assert.equal((await left.status()).auditCount, 1);
  assert.equal((await right.status()).auditCount, 1);
});

test("CP13 historical evidence: a mismatched later receipt fingerprint is refused; a verified retry repairs it", async () => {
  const x = memoryRoot(); await x.reset(); await x.invoke("submit");
  const later = await laterRoot(x);
  const receipt = await x.store.read(x.Categories.RECEIPT, later.txId);
  await x.store.write(x.Categories.RECEIPT, later.txId, { ...receipt, proof: { ...receipt.proof, requestFingerprint: x.H("00") } });
  x.reload();
  const priorRequest = await x.readRequest(), priorRoot = await x.readRoot();
  assert.equal((await x.invoke("submit")).error, "RECONCILIATION_REQUIRED");
  assert.deepEqual(await x.readRequest(), priorRequest, "failed historical inspection preserves established completion");
  assert.deepEqual(await x.readRoot(), priorRoot, "failed inspection never restores a historical pending pointer");
  await x.wr.submitOrgRootRequest({ config: x.cfg, requestId: later.id, rpc: x.rpc });
  assert.equal((await x.invoke("submit")).result, "CHAIN_VERIFIED");
  assert.equal((await x.readRoot()).live.outpoint.transactionId, later.txId);
  for (const txId of [later.txId, x.txid]) assert.equal(x.getAudits().filter((e) => e.txId === txId).length, 1);
});
