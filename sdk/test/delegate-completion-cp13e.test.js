"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const memory = require("../testutil/cp13e-memory");

async function assertComplete(x, broadcasts = 1) {
  const q = await x.request(), vault = await x.vault();
  assert.equal(q.state, "CHAIN_VERIFIED", q.error);
  assert.equal(vault.generation, x.doc.generation + 1);
  assert.equal(vault.live.stateId, q.build.successorStateId);
  assert.equal(vault.live.state.agentRoot, q.build.successorState.agentRoot);
  assert.equal(vault.live.tokenPosition.state.amount, "99950");
  assert.equal(vault.agentRegistry.find((e) => e.agentPk === q.build.callExtra.agentPk).tokenPeriodSpent, "50");
  assert.equal(await x.claimModule.loadTransitionClaim(x.config, q.predecessorOutpoint), null);
  assert.equal(await x.store.read(x.Categories.SUBMISSION_CLAIM, q.txId), null);
  const receipt = await x.store.read(x.Categories.RECEIPT, q.txId);
  assert.equal(receipt.proof.requestId, q.requestId);
  assert.equal(receipt.proof.requestFingerprint, x.wr.completionReceiptPointer(q).requestFingerprint);
  assert.equal(x.getAudits().filter((e) => e.txId === q.txId && e.result === "CHAIN_VERIFIED").length, 1);
  assert.equal(x.submits(), broadcasts);
}
async function timeout(x) {
  x.setMode("timeout");
  await assert.rejects(x.submit(), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await x.request()).state, "RECONCILIATION_REQUIRED");
  x.setMode("honest");
}
async function legacy(x, pointer) {
  await timeout(x);
  const q = await x.request(); delete q.predecessorVault;
  await x.wr.saveV7WalletRequest(x.config, q);
  // Pre-snapshot records also predate request-bound submission claims.
  // Keeping that modern fingerprint would deliberately contradict q.
  const submission = await x.store.read(x.Categories.SUBMISSION_CLAIM, q.txId);
  if (submission) { delete submission.expected; await x.store.write(x.Categories.SUBMISSION_CLAIM, q.txId, submission); }
  const c = await x.claimModule.loadTransitionClaim(x.config, q.predecessorOutpoint);
  c.expected = { kind: "v7Successor", txId: q.txId, ...(pointer ? { requestId: q.requestId } : {}) };
  await x.store.write(x.Categories.TRANSITION_CLAIM, q.predecessorOutpoint.transactionId + "-" + q.predecessorOutpoint.index, c);
}

test("CP13E memory: honest inline + repeated public submit/reconcile complete once and preserve every root byte", async () => {
  const x = await memory(), root = await x.readRoot();
  await x.submit(); await assertComplete(x);
  x.reload(); await x.submit(); assert.equal((await x.reconcile()).status, "CONSISTENT");
  await assertComplete(x); assert.deepEqual(await x.readRoot(), root);
});
test("CP13E memory: accepted timeout, no observation, RPC errors, reload and later exact effect preserve one request", async () => {
  const x = await memory(); await timeout(x);
  const claim = await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint);
  assert.equal(claim.expected.requestId, x.q.requestId); assert.equal(claim.expected.requestFingerprint, x.wr.completionReceiptPointer(await x.request()).requestFingerprint);
  for (const mode of ["honest", "query-error"]) {
    x.setLanded(false); x.setMode(mode); x.reload();
    assert.equal((await x.reconcile()).status, "UNKNOWN");
    assert.equal((await x.vault()).generation, x.doc.generation);
    assert.ok(await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint));
    await assert.rejects(x.wr.buildV7WalletRequest({ config: x.config, vaultId: x.q.vaultId, action: "tokenDeposit" }), (e) => e.code === "VAULT_PENDING_REQUEST");
  }
  x.setLanded(true); x.setMode("honest"); x.reload();
  assert.equal((await x.reconcile()).status, "ADVANCED"); await assertComplete(x);
});
for (const pointer of [false, true]) test(`CP13E memory: saved legacy ${pointer ? "pointer-only" : "missing-pointer"} shape recovers through public reconcile after reload`, async () => {
  const x = await memory(); await legacy(x, pointer); x.reload();
  assert.equal((await x.reconcile()).status, "ADVANCED"); await assertComplete(x);
});
test("CP13E memory: wrong/ambiguous legacy claim association stays protected", async () => {
  for (const mode of ["wrong-pointer", "ambiguous", "wrong-state-id", "wrong-fingerprint"]) {
    const x = await memory(); await legacy(x, false);
    const c = await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint);
    if (mode === "wrong-pointer") c.expected.requestId = "another-request";
    if (mode === "wrong-state-id") c.stateId = "99".repeat(32);
    if (mode === "wrong-fingerprint") c.expected.requestFingerprint = "99".repeat(32);
    if (mode === "ambiguous") await x.wr.saveV7WalletRequest(x.config, { ...await x.request(), requestId: "duplicate-request" });
    await x.store.write(x.Categories.TRANSITION_CLAIM, x.q.predecessorOutpoint.transactionId + "-" + x.q.predecessorOutpoint.index, c);
    x.reload(); assert.equal((await x.reconcile()).status, "UNKNOWN", mode);
    assert.equal((await x.vault()).generation, x.doc.generation, mode);
    assert.deepEqual(await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint), c, mode);
  }
});

const boundaries = {
  replayRequest: ["write", (x, cat, key, v) => cat === x.Categories.REQUEST && key === x.q.requestId && v.state === "RECONCILIATION_REQUIRED"],
  vault: ["write", (x, cat) => cat === x.Categories.VAULT],
  receipt: ["write", (x, cat, key) => cat === x.Categories.RECEIPT && key === x.q.txId],
  audit: ["appendAudit", (x, e) => e.txId === x.q.txId],
  predecessorRelease: ["remove", (x, cat, key) => cat === x.Categories.TRANSITION_CLAIM && key === x.q.predecessorOutpoint.transactionId + "-" + x.q.predecessorOutpoint.index],
  submissionRelease: ["remove", (x, cat, key) => cat === x.Categories.SUBMISSION_CLAIM && key === x.q.txId],
  finalRequest: ["write", (x, cat, key, v) => cat === x.Categories.REQUEST && key === x.q.requestId && v.state === "CHAIN_VERIFIED"]
};
for (const [stage, [method, predicate]] of Object.entries(boundaries)) test(`CP13E memory persistent ${stage}: failure, reload, still failing, guarded prebuilt submit, repair and overlap`, async () => {
  const x = await memory(), root = await x.readRoot(); await timeout(x);
  const real = x.store[method].bind(x.store); let failures = 0;
  x.store[method] = async (...args) => { if (predicate(x, ...args)) { failures++; throw Error("STUB_PERSISTENT_" + stage); } return real(...args); };
  for (let attempt = 0; attempt < 2; attempt++) {
    x.reload(); assert.equal((await x.reconcile()).status, "UNKNOWN", stage);
    assert.notEqual((await x.request()).state, "CHAIN_VERIFIED", stage);
    assert.ok([x.doc.generation, x.doc.generation + 1].includes((await x.vault()).generation));
    const q = structuredClone(x.q); q.requestId = "prebuilt-replacement";
    await x.wr.saveV7WalletRequest(x.config, q);
    await assert.rejects(x.wr.submitV7WalletRequest({ config: x.config, requestId: q.requestId, rpc: x.rpc, pollAttempts: 1 }), (e) => ["RECONCILIATION_REQUIRED", "VAULT_PENDING_REQUEST"].includes(e.code));
    assert.equal(x.submits(), 1, "no replacement or replay broadcast");
  }
  assert.ok(failures >= 2); x.store[method] = real; x.reload();
  await Promise.all([x.submit(), x.reconcile(), x.submit()]);
  await assertComplete(x); assert.deepEqual(await x.readRoot(), root);
});
test("CP13E memory: an older inline partial (vault written, request unfinished, receipt missing) is discoverable without current-outpoint claim", async () => {
  const x = await memory(); await x.submit();
  const q = await x.request(); q.state = "SUBMITTED"; delete q.predecessorVault;
  await x.wr.saveV7WalletRequest(x.config, q); await x.store.remove(x.Categories.RECEIPT, q.txId);
  x.reload(); assert.equal((await x.reconcile()).status, "ADVANCED"); await assertComplete(x);
});
test("CP13E memory: absent claims do not prove completion; foreign predecessor claims survive proven completion", async () => {
  for (const foreign of [false, true]) {
    const x = await memory(); await timeout(x);
    await x.claimModule.releaseTransitionClaim(x.config, { outpoint: x.q.predecessorOutpoint, txId: x.q.txId });
    if (foreign) await x.claimModule.claimTransition(x.config, { outpoint: x.q.predecessorOutpoint, txId: "ef".repeat(32), vaultId: x.q.vaultId, action: "authorize", expected: { kind: "orgRootRequest", requestId: "foreign" } });
    const claim = await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint);
    x.setLanded(false); assert.equal((await x.reconcile()).status, "UNKNOWN"); assert.equal((await x.vault()).generation, x.doc.generation);
    x.setLanded(true); await x.submit();
    assert.equal((await x.request()).state, "CHAIN_VERIFIED");
    assert.deepEqual(await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint), claim);
  }
});
test("CP13E memory: source bytes, funding, covenant, policy and predecessor substitutions refuse before broadcast", async () => {
  const mutations = [
    (q) => q.finalTransaction.inputs[0].computeBudget++,
    (q) => { q.build.frozen.inputs[2].computeBudget++; q.finalTransaction.inputs[2].computeBudget++; },
    (q) => { q.build.frozen.lockTime = "1"; q.finalTransaction.lockTime = "1"; },
    (q) => { q.build.frozen.outputs[0].covenant.authorizingInput = 1; q.finalTransaction.outputs[0].covenant.authorizingInput = 1; },
    (q) => { q.build.frozen.outputs[2].scriptPublicKey.scriptHex = q.build.frozen.outputs[1].scriptPublicKey.scriptHex; q.finalTransaction.outputs[2].scriptPublicKey.scriptHex = q.build.frozen.outputs[1].scriptPublicKey.scriptHex; },
    (q) => { q.build.frozen.outputs[3].scriptPublicKey.scriptHex = "20" + "99".repeat(32) + "ac"; q.finalTransaction.outputs[3].scriptPublicKey.scriptHex = q.build.frozen.outputs[3].scriptPublicKey.scriptHex; },
    (q) => q.predecessorStateId = "99".repeat(32),
    (q) => q.build.callExtra.tokenPeriodBudget = "1",
    (q) => { q.build.frozen.subnetworkId = "01".repeat(20); q.finalTransaction.subnetworkId = q.build.frozen.subnetworkId; },
    (q) => { q.build.frozen.gas = "1"; q.finalTransaction.gas = "1"; },
    (q) => q.build.networkId = "mainnet"
  ];
  for (const mutate of mutations) {
    const x = await memory(), q = await x.request(); mutate(q); await x.wr.saveV7WalletRequest(x.config, q);
    await assert.rejects(x.submit()); assert.equal(x.submits(), 0);
    assert.equal((await x.vault()).generation, x.doc.generation);
  }
});
test("CP13E memory: contradictory output/input queries, missing token continuation and substituted covenant cannot release uncertainty", async () => {
  for (const kind of ["live-predecessor", "missing-token", "wrong-covenant", "query-race"]) {
    const x = await memory(); await timeout(x); let reads = 0;
    const query = x.rpc.query.bind(x.rpc);
    x.rpc.query = async (a) => {
      const refs = await query(a);
      if (kind === "live-predecessor" && a === "spk:" + x.q.build.frozen.inputs[0].utxo.scriptPublicKey.scriptHex) return [{ outpoint: x.q.predecessorOutpoint, amount: 1n }];
      if (kind === "missing-token") return refs.filter((r) => r.outpoint.index !== 1);
      if (kind === "wrong-covenant") return refs.map((r) => ({ ...r, covenantId: "99".repeat(32) }));
      if (kind === "query-race" && ++reads > 5) return [];
      return refs;
    };
    assert.equal((await x.reconcile()).status, "UNKNOWN", kind);
    assert.ok(await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint), kind);
    assert.equal((await x.vault()).generation, x.doc.generation, kind);
  }
});
test("CP13E memory: unexplained successor token/state/generation refused; terminal request label does not hide incompleteness", async () => {
  for (const kind of ["token", "state", "generation", "marker"]) {
    const x = await memory(); await x.submit(); const v = await x.vault();
    if (kind === "token") v.live.tokenPosition = x.doc.live.tokenPosition;
    if (kind === "generation") v.generation++;
    if (kind === "marker") v.latestTransitionTxId = "99".repeat(32);
    if (kind === "state") { v.live.state = x.doc.live.state; v.live.stateId = x.doc.live.stateId; v.agentRegistry = x.doc.agentRegistry; v.live.outpointValue = x.doc.live.outpointValue; v.live.scriptSha256 = x.doc.live.scriptSha256; }
    await x.manifestModule.persistManifestV7(x.config, v); x.reload();
    const installed = await x.vault(); await assert.rejects(x.submit());
    assert.deepEqual(await x.vault(), installed); assert.equal(x.submits(), 1);
  }
});
test("CP13E memory: a substituted submission claim refuses before any completion write", async () => {
  const x = await memory(); await timeout(x);
  const sub = await x.store.read(x.Categories.SUBMISSION_CLAIM, x.q.txId);
  await x.store.write(x.Categories.SUBMISSION_CLAIM, x.q.txId, { ...sub, vaultId: "99".repeat(32) });
  assert.equal((await x.reconcile()).status, "UNKNOWN");
  assert.equal((await x.vault()).generation, x.doc.generation);
  assert.equal(await x.store.read(x.Categories.RECEIPT, x.q.txId), null);
  assert.ok(await x.claimModule.loadTransitionClaim(x.config, x.q.predecessorOutpoint));
});
test("CP13E memory: concurrent recovery in separate stores with the same keys stays isolated", async () => {
  const a = await memory(), b = await memory(); await timeout(a); await timeout(b);
  a.setLanded(false);
  await Promise.all([assert.rejects(a.submit()), b.submit(), b.reconcile()]);
  assert.equal((await a.request()).state, "RECONCILIATION_REQUIRED"); await assertComplete(b);
  a.setLanded(true); await a.submit(); await assertComplete(a);
});
