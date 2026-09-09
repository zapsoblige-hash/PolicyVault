"use strict";
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const f = require("../testutil/rc27f-fixtures"), { fx, wr, d } = f;
let base; before(async () => { base = await f.depositBase(); });
test("RC27F F-3: accepted deposit timeout guards prebuilt signing/submission, reloads, reconciles and permits a spend", async () => {
  const x = f.depositCase(base); x.settle(); await x.timeout();
  await assert.rejects(x.build(), { code: "VAULT_PENDING_REQUEST" });
  await assert.rejects(wr.finalizeV7WalletRequest({ config: x.config, requestId: x.prebuilt.requestId, signedSafeJson: x.signed }), { code: "VAULT_PENDING_REQUEST" });
  // An already signed competing request also cannot bypass the submit guard.
  await wr.saveV7WalletRequest(x.config, { ...base.q, requestId: x.prebuilt.requestId });
  await assert.rejects(wr.submitV7WalletRequest({ config: x.config, requestId: x.prebuilt.requestId, rpc: x.rpc }), (e) => ["VAULT_PENDING_REQUEST", "RECONCILIATION_REQUIRED"].includes(e.code));
  x.config = fx.reloadJsonConfig(x.config);
  await f.dep("sdk/src/reconcile-v7").reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc });
  await x.submit(); await x.reconcile(); await f.assertDepositComplete(x);
  await assert.rejects(x.build(), { code: "TOKEN_POSITION_ALREADY_HELD" });
  await d.signedSpend(x.config, x.o);
});
for (const stage of ["vault", "receipt", "audit", "submissionRelease", "finalRequest"]) {
  test(`RC27F F-3: deposit ${stage} write failure replays once after reload`, async () => {
    const x = f.depositCase(base); x.settle();
    const [method, predicate] = d.boundaries[stage];
    const fault = fx.inject(x.config, method, (...args) => predicate(x, ...args));
    await assert.rejects(x.submit()); assert.equal(fault.count(), 1); fault.restore();
    x.config = fx.reloadJsonConfig(x.config);
    await f.dep("sdk/src/reconcile-v7").reconcileOrgRootV7(x.config, x.o.rootCovenantId, { rpc: x.rpc });
    await Promise.all([x.reconcile(), x.submit()]); await f.assertDepositComplete(x);
  });
}
test("RC27F F-3: missing/substituted deposit token output and failed query keep the same protected request", async () => {
  for (const mode of ["absent", "wrong-covenant", "wrong-value", "query-fails"]) {
    const x = f.depositCase(base); await x.timeout(); x.settle();
    const query = x.rpc.getUtxosByAddresses.bind(x.rpc);
    x.rpc.getUtxosByAddresses = async (args) => {
      if (mode === "query-fails") throw Error("STUB unavailable");
      const r = await query(args); r.entries = r.entries.flatMap((u) => u.outpoint.transactionId !== x.q.txId ? [u] : mode === "absent" ? [] : [{ ...u, ...(mode === "wrong-value" ? { amount: 1n } : { covenantId: "ff".repeat(32) }) }]); return r;
    };
    const result = await x.reconcile(); assert.equal(result.status, "UNKNOWN", mode);
    assert.ok(await fx.loadSubmissionClaim(x.config, x.q.txId)); assert.equal((await x.vault()).live.tokenPosition, null);
    x.rpc.getUtxosByAddresses = query; await x.reconcile(); await f.assertDepositComplete(x);
  }
});
