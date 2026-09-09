"use strict";
// Public SDK + real compiler/VM; isolated JSON stores and a stubbed node.
// The same assertions can run against the immutable pre-correction source.
const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path"), fs = require("node:fs");
const source = process.env.POLICYVAULT_RC27F_SOURCE || path.resolve(__dirname, "../..");
const dep = (p) => require(path.join(source, p));
const d = dep("sdk/testutil/cp13e-delegate-fixture");
const { fx, caseFor, boundaries, assertComplete } = d;
const { wr7: wr, Categories: C, getStore } = fx;
const { reconcileOrgRootV7 } = dep("sdk/src/reconcile-v7");
let base;
before(async () => { base = await d.baseFixture(); });
const org = (x) => reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc });

for (const stage of ["vault", "receipt", "audit", "predecessorRelease", "submissionRelease", "finalRequest"]) {
  test(`RC27F F-4: organization-only recovery after delegate ${stage} failure preserves earlier history`, async () => {
    const x = caseFor(base), first = await wr.loadOrgRootRequest(x.config, x.first.id);
    const [method, predicate] = boundaries[stage];
    const fault = fx.inject(x.config, method, (...args) => predicate(x, ...args));
    x.settle(); await assert.rejects(x.submit(), { code: "RECONCILIATION_REQUIRED" });
    assert.equal(fault.count(), 1); fault.restore();
    x.config = fx.reloadJsonConfig(x.config);
    await org(x); await org(x); await x.reconcile();
    await assertComplete(x);
    assert.deepEqual(await wr.loadOrgRootRequest(x.config, x.first.id), first, "earlier proven request is never rewritten");
    await d.signedSpend(x.config, x.o);
  });
}

for (const area of ["delegate-audit", "delegate-receipt", "root-audit"]) {
  test(`RC27F F-5: completed ${area} inspection failure preserves durable proof byte for byte`, async () => {
    const x = caseFor(base); x.settle(); await x.submit();
    const before = await records(x.config);
    const fault = area.endsWith("audit")
      ? fx.inject(x.config, "readAudit", (o) => o.txId === (area.startsWith("root") ? x.first.txId : x.q.txId), { times: Infinity })
      : fx.inject(x.config, "read", (c, k) => c === C.RECEIPT && k === x.q.txId, { times: Infinity });
    const result = await org(x).catch((e) => ({ error: e.code || e.message }));
    assert.ok(fault.count() > 0, "the intended inspection actually failed");
    assert.ok(result.error || result.root?.status === "UNKNOWN" || result.vaults?.some((v) => v.status === "UNKNOWN"), "fresh verification is unavailable, never claimed successful");
    fault.restore();
    assert.deepEqual(await records(x.config), before);
    await org(x); await assertComplete(x);
  });
}

test("RC27F F-6: signed owner requests cannot be withdrawn or release their reservation", async () => {
  const x = caseFor(base), q = await fx.signedRootOnly(x.config, x.o);
  const before = await records(x.config);
  await assert.rejects(wr.rejectOrgRootRequest({ config: x.config, requestId: q.id }), { code: "CANNOT_REJECT" });
  assert.deepEqual(await records(x.config), before);
});
test("RC27F F-6: unsigned cancellation replays a failed pointer clear; another request's pointer survives", async () => {
  const x = caseFor(base);
  const q = await wr.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, signerAddress: fx.ADDR(x.config, x.o.owner1), vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
  await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
  const fault = fx.inject(x.config, "write", (c, k, v) => c === C.ORG_ROOT && v.pendingRequestId == null);
  await assert.rejects(wr.rejectOrgRootRequest({ config: x.config, requestId: q.id })); fault.restore();
  assert.equal((await wr.loadOrgRootRequest(x.config, q.id)).state, "REFUSED");
  x.config = fx.reloadJsonConfig(x.config);
  await wr.rejectOrgRootRequest({ config: x.config, requestId: q.id });
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, null);
  await d.signedSpend(x.config, x.o);
  const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId); root.pendingRequestId = "other-request"; await wr.saveOrgRoot(x.config, root);
  await wr.rejectOrgRootRequest({ config: x.config, requestId: q.id });
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, "other-request");
});

test("RC27F F-7: finalize, queued submit and late finalize serialize without terminal rewind or rebroadcast", async () => {
  const x = caseFor(base), q = await fx.signedRootOnly(x.config, x.o);
  q.state = "AUTHORIZED"; delete q.finalTransaction; delete q.finalizedTxHex; await wr.saveOrgRootRequest(x.config, q);
  const fuelSignatureScriptHex = fx.kaspaOf(x.config).createInputSignature(fx.kaspaOf(x.config).Transaction.deserializeFromSafeJSON(q.transaction.unsignedSafeJson), q.build.frozen.inputs.length - 1, x.o.fuelKey);
  let entered, release; const enteredP = new Promise((r) => { entered = r; }), held = new Promise((r) => { release = r; });
  const store = getStore(x.config), write = store.write.bind(store); let paused = false;
  store.write = async (c, k, v) => { if (!paused && c === C.ORG_ROOT_REQUEST && k === q.id && v.state === "SIGNED") { paused = true; entered(); await held; } return write(c, k, v); };
  const finalize = () => wr.finalizeOrgRootRequest({ config: x.config, requestId: q.id, fuelSignatureScriptHex });
  const a = finalize(); await enteredP;
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, q);
  const b = wr.submitOrgRootRequest({ config: x.config, requestId: q.id, rpc: x.rpc }).then((v) => ({ value: v }), (error) => ({ error }));
  const c = finalize().then((value) => ({ value }), (error) => ({ error }));
  await new Promise((r) => setImmediate(r)); release();
  await a; const submitted = await b, late = await c; store.write = write;
  assert.equal(submitted.value?.state, "CHAIN_VERIFIED", submitted.error?.message);
  assert.ok(late.error, "late finalizer refuses after fresh durable-state check");
  assert.equal((await wr.loadOrgRootRequest(x.config, q.id)).state, "CHAIN_VERIFIED");
  await wr.submitOrgRootRequest({ config: x.config, requestId: q.id, rpc: x.rpc });
  assert.equal(x.rpc.submits(), 1);
});

test("RC27F F-8: simulated case-folding filesystem never exposes a request under a spelling alias", async () => {
  const config = fx.freshJsonConfig("pv-rc27f-alias-"), store = getStore(config);
  for (const [category, key, value] of [[C.ORG_ROOT_REQUEST, "MixedRoot", { id: "MixedRoot", rootCovenantId: "11".repeat(32) }], [C.REQUEST, "MixedV4", { requestId: "MixedV4" }]]) await store.write(category, key, value);
  const exists = fs.existsSync, read = fs.readFileSync;
  const map = (p) => typeof p === "string" && p.startsWith(config.dataRoot) ? p.replace("MIXEDROOT.json", "MixedRoot.json").replace("MIXEDV4.json", "MixedV4.json") : p;
  fs.existsSync = (p) => exists(map(p)); fs.readFileSync = (p, ...args) => read(map(p), ...args);
  try {
    assert.equal((await wr.loadOrgRootRequest(config, "MixedRoot")).id, "MixedRoot");
    await assert.rejects(wr.loadOrgRootRequest(config, "MIXEDROOT"), /identity|storage key/i);
    await assert.rejects(dep("sdk/src/wallet-requests-v4").loadRequest(config, "MIXEDV4"), /identity|storage key/i);
  } finally { fs.existsSync = exists; fs.readFileSync = read; }
  // Case-sensitive backends may legitimately contain two distinct logical keys.
  await store.write(C.REQUEST, "MIXEDV4", { requestId: "MIXEDV4" });
  assert.equal((await store.read(C.REQUEST, "MixedV4")).requestId, "MixedV4");
  assert.equal((await store.read(C.REQUEST, "MIXEDV4")).requestId, "MIXEDV4");
});

test("RC27F F-7: an actual saved SIGNED/SUBMISSION_REJECTED root rewind recovers; a same-tx stranger cannot take the receipt", async () => {
  for (const state of ["SIGNED", "SUBMISSION_REJECTED"]) {
    const x = caseFor(base), q = await fx.signedRootOnly(x.config, x.o), old = structuredClone(q);
    await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, q);
    await wr.submitOrgRootRequest({ config: x.config, requestId: q.id, rpc: x.rpc });
    old.state = state; await wr.saveOrgRootRequest(x.config, old);
    const stranger = { ...old, id: "same-tx-stranger", state: "SIGNED" }; await wr.saveOrgRootRequest(x.config, stranger);
    x.config = fx.reloadJsonConfig(x.config); await org(x);
    assert.equal((await wr.loadOrgRootRequest(x.config, q.id)).state, "CHAIN_VERIFIED");
    assert.equal((await wr.loadOrgRootRequest(x.config, stranger.id)).state, "SIGNED");
    const next = await wr.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, signerAddress: fx.ADDR(x.config, x.o.owner1) });
    assert.equal(next.state, "AUTHORIZED", "another request's bound receipt does not make the historical same-tx draft a reservation");
    await wr.rejectOrgRootRequest({ config: x.config, requestId: next.id });
    await assert.rejects(wr.submitOrgRootRequest({ config: x.config, requestId: stranger.id, rpc: x.rpc }));
    assert.equal((await wr.loadOrgRootRequest(x.config, stranger.id)).state, "SIGNED", "refusing an unsubmitted stranger must not invent an unresolved submission");
    const afterRefusal = await wr.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, signerAddress: fx.ADDR(x.config, x.o.owner1) });
    assert.equal(afterRefusal.state, "AUTHORIZED");
    await wr.rejectOrgRootRequest({ config: x.config, requestId: afterRefusal.id });
    assert.equal((await fx.loadReceipt(x.config, q.txId)).proof.requestId, q.id);
    assert.equal(x.rpc.submits(), 1);
    assert.equal((await wr.submitOrgRootRequest({ config: x.config, requestId: x.first.id, rpc: x.rpc })).state, "CHAIN_VERIFIED");
  }
});
test("RC27F F-6: request persistence followed by failed reservation-pointer write cannot create an orphan bypass", async () => {
  const x = caseFor(base), fault = fx.inject(x.config, "write", (c, k, v) => c === C.ORG_ROOT && v.pendingRequestId != null);
  const build = () => wr.buildRootActionRequest({ config: x.config, rootCovenantId: x.o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) }, signerAddress: fx.ADDR(x.config, x.o.owner1), vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
  await assert.rejects(build()); fault.restore(); x.config = fx.reloadJsonConfig(x.config);
  await assert.rejects(build(), { code: "ROOT_PENDING_REQUEST" });
  await assert.rejects(d.signedSpend(x.config, x.o), { code: "VAULT_PENDING_REQUEST" });
  const q = (await wr.listOrgRootRequests(x.config, { rootCovenantId: x.o.rootCovenantId })).find((q) => q.state === "AUTHORIZED");
  await wr.rejectOrgRootRequest({ config: x.config, requestId: q.id });
  await d.signedSpend(x.config, x.o);
});

async function records(config) {
  const store = getStore(config), out = {};
  for (const c of [C.ORG_ROOT, C.ORG_ROOT_REQUEST, C.VAULT, C.REQUEST, C.RECEIPT, C.TRANSITION_CLAIM, C.SUBMISSION_CLAIM]) {
    out[c] = {};
    for (const k of (await store.listKeys(c)).sort()) out[c][k] = await store.read(c, k);
  }
  out.audit = await store.readAudit({ limit: 1000 }); return out;
}
