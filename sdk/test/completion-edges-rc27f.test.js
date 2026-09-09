"use strict";
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const f = require("../testutil/rc27f-fixtures"), { dep, fx, d, wr } = f;
const rec = dep("sdk/src/reconcile-v7"), C = fx.Categories;
let spendBase, depositBase;
test("RC27F F-8: JSON reservations retain their exact composite identities and refuse substitutions", async () => {
  await require("../testutil/rc27f-store-controls")(fx.getStore(fx.freshJsonConfig("pv-rc27f-resv-")), C);
});
before(async () => { spendBase = await d.baseFixture(); depositBase = await f.depositBase(); });
for (const kind of ["delegate", "deposit"]) test(`RC27F F-5: completed ${kind} survives a failed verification plus failed diagnostic request reread`, async () => {
  const x = kind === "delegate" ? d.caseFor(spendBase) : f.depositCase(depositBase);
  x.settle(); await x.submit(); const before = await x.request(), vault = await x.vault();
  let armed = false;
  const audit = fx.inject(x.config, "readAudit", (args) => { if (args.txId === x.q.txId) { armed = true; return true; } return false; }, { times: Infinity });
  const read = fx.inject(x.config, "read", (c, k) => armed && c === C.REQUEST && k === x.q.requestId, { times: Infinity });
  await assert.rejects(x.submit()); assert.ok(audit.count() && read.count()); audit.restore(); read.restore();
  assert.deepEqual(await x.request(), before); assert.deepEqual(await x.vault(), vault);
  await x.submit(); assert.equal(x.rpc.submits(), 1);
});
for (const kind of ["delegate", "deposit"]) test(`RC27F F-2/F-3: ${kind} receipt outer identities must agree with its bound pointer`, async () => {
  const x = kind === "delegate" ? d.caseFor(spendBase) : f.depositCase(depositBase);
  x.settle(); await x.submit(); const receipt = await fx.loadReceipt(x.config, x.q.txId);
  for (const field of ["txId", "vaultId", "action"]) {
    await fx.getStore(x.config).write(C.RECEIPT, x.q.txId, { ...receipt, [field]: field === "action" ? "unrelated-action" : fx.H(0x88) });
    await assert.rejects(d.signedSpend(x.config, x.o), { code: field === "txId" ? "STORE_IDENTITY_MISMATCH" : "VAULT_PENDING_REQUEST" });
    assert.equal((await x.request()).state, "CHAIN_VERIFIED");
    await fx.getStore(x.config).write(C.RECEIPT, x.q.txId, receipt);
  }
  await d.signedSpend(x.config, x.o); assert.equal(x.rpc.submits(), 1);
});
test("RC27F F-3: unchanged signed deposit remains valid after a completed owner policy operation", async () => {
  const x = f.depositCase(depositBase), bytes = JSON.stringify(x.q.finalTransaction);
  const owner = await fx.signedSetAgentRoot(x.config, x.o);
  await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, owner);
  await wr.submitOrgRootRequest({ config: x.config, requestId: owner.id, rpc: x.rpc });
  const current = await x.vault(); x.before = current; x.root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  x.settle(); await x.submit(); await f.assertDepositComplete(x, 2);
  assert.equal(JSON.stringify((await x.request()).finalTransaction), bytes);
  assert.deepEqual((await x.vault()).agentRegistry, current.agentRegistry);
  await d.signedSpend(x.config, x.o);
});
test("RC27F F-2/F-3: deposit, two delegates and public token-bearing terminal recovery retain verifiable history", async () => {
  const x = d.caseFor(spendBase); x.settle(); await x.submit();
  const second = await d.signedSpend(x.config, x.o); x.settle(second);
  await wr.submitV7WalletRequest({ config: x.config, requestId: second.requestId, rpc: x.rpc, pollAttempts: 1 });
  const position = (await x.vault()).live.tokenPosition;
  const terminal = await fx.signedTerminalRecover(x.config, x.o);
  assert.equal(terminal.build.hasTokenInput, true);
  assert.deepEqual(terminal.build.frozen.inputs[terminal.build.tokenInputIndex].previousOutpoint, position.outpoint);
  assert.equal(terminal.build.accounting.token.recoveredToRecoveryPk, "99900");
  d.settle(x.config, x.rpc, terminal);
  await wr.submitOrgRootRequest({ config: x.config, requestId: terminal.id, rpc: x.rpc });
  x.config = fx.reloadJsonConfig(x.config); const vault = await x.vault();
  for (const requestId of [x.deposit.requestId, x.q.requestId, second.requestId]) assert.equal((await wr.submitV7WalletRequest({ config: x.config, requestId, rpc: x.rpc })).state, "CHAIN_VERIFIED");
  await rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc });
  assert.deepEqual(await x.vault(), vault); assert.equal(vault.status, "RECOVERED");
  assert.equal(x.rpc.submits(), 3);
});
for (const complete of [false, true]) test(`RC27F F-6/F-7: a saved pre-sign cache snapshot cannot cancel or sign an ${complete ? "accepted" : "uncertain"} root request`, async () => {
  const x = d.caseFor(spendBase), store = fx.getStore(x.config), write = store.write.bind(store);
  let saved;
  store.write = async (c, k, v) => { if (!saved && c === C.ORG_ROOT_REQUEST && v.state === "AUTHORIZED") saved = structuredClone(v); return write(c, k, v); };
  const q = await fx.signedRootOnly(x.config, x.o); store.write = write;
  if (complete) {
    await fx.spendPredecessors(x.config, x.rpc, x.o); fx.settle(x.config, x.rpc, q);
    await wr.submitOrgRootRequest({ config: x.config, requestId: q.id, rpc: x.rpc });
  } else {
    const submit = x.rpc.submitTransaction.bind(x.rpc);
    x.rpc.submitTransaction = async (args) => { await submit(args); throw Error("STUB lost response"); };
    await assert.rejects(wr.submitOrgRootRequest({ config: x.config, requestId: q.id, rpc: x.rpc }));
  }
  await wr.saveOrgRootRequest(x.config, saved); const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  await assert.rejects(wr.rejectOrgRootRequest({ config: x.config, requestId: q.id }), { code: "CANNOT_REJECT" });
  for (const call of [() => wr.getOrCreateSlotSigningRequest({ config: x.config, requestId: q.id, slot: 1 }), () => wr.submitSlotSignature({ config: x.config, requestId: q.id, slot: 1, response: {} }), () => wr.finalizeOrgRootRequest({ config: x.config, requestId: q.id }), () => wr.submitOrgRootRequestSignature({ config: x.config, requestId: q.id })]) await assert.rejects(call(), { code: "RECONCILIATION_REQUIRED" });
  assert.deepEqual(await wr.loadOrgRoot(x.config, x.o.rootCovenantId), root); assert.equal(x.rpc.submits(), 1);
});
test("RC27F F-8: strict identity listings reject typed missing/misbound IDs while retaining generic records", async () => {
  const config = fx.freshJsonConfig("pv-rc27f-typed-"), store = fx.getStore(config);
  for (const id of [null, "other-id"]) {
    await store.write(C.ORG_ROOT_REQUEST, "expected-id", { schemaVersion: wr.ORG_ROOT_REQUEST_SCHEMA, id });
    await assert.rejects(wr.loadOrgRootRequest(config, "expected-id"), { code: "REQUEST_ID_MISMATCH" });
    await assert.rejects(wr.listOrgRootRequests(config), { code: "REQUEST_ID_MISMATCH" });
  }
  await store.write(C.ORG_ROOT_REQUEST, "expected-id", { generic: true });
  assert.deepEqual(await store.read(C.ORG_ROOT_REQUEST, "expected-id"), { generic: true });
});
for (const stage of ["root", "receipt"]) test(`RC27F F-4: a later owner ${stage} interruption and earlier delegate history converge in public org reconcile`, async () => {
  const x = d.caseFor(spendBase); x.settle(); await x.submit(); const completed = await x.request();
  const owner = await fx.signedRootAction(x.config, x.o, { vaultOperations: [{ vaultId: x.o.vaultId, action: "ownerPause", params: {} }] });
  const fault = fx.inject(x.config, "write", (c, k, v) => stage === "root" ? c === C.ORG_ROOT && v.live?.outpoint?.transactionId === owner.txId : c === C.RECEIPT && k === owner.txId);
  d.settle(x.config, x.rpc, owner);
  await assert.rejects(wr.submitOrgRootRequest({ config: x.config, requestId: owner.id, rpc: x.rpc })); assert.equal(fault.count(), 1); fault.restore();
  x.config = fx.reloadJsonConfig(x.config);
  await rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc }); await x.reconcile();
  await rec.reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc });
  assert.deepEqual(await x.request(), completed);
  assert.equal((await wr.loadOrgRootRequest(x.config, owner.id)).state, "CHAIN_VERIFIED");
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).pendingRequestId, null);
  assert.equal((await x.vault()).live.state.paused, "1"); assert.equal(x.rpc.submits(), 2);
});
