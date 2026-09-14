"use strict";
const { test, before } = require("node:test"), assert = require("node:assert/strict");
const { dep, fx, wr } = require("../testutil/rc27f-fixtures");
const hd = dep("sdk/src/wallet-requests-v7-hd");
let base;
before(async () => {
  const config = fx.freshJsonConfig("pv-rc27f-hd-base-"), rpc = fx.mockRpc(), o = await fx.organization(config, rpc);
  const owner = await fx.signedRootOnly(config, o);
  const genesisArgs = { config, vaultId: fx.H(0x93), rootCovenantId: o.rootCovenantId, descriptor: o.descriptor, initialAgents: [{ pk: fx.XO(config, o.agentKey), maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: fx.KAS.toString(), maxCarryKas: fx.KAS.toString(), expiryDaa: "999999999", recipients: [fx.XO(config, o.recipientKey)] }], recoveryAddress: fx.ADDR(config, o.owner1), feeReserveKas: "5", signerAddress: fx.ADDR(config, o.funder), funding: [fx.fuelUtxoFor(config, o.funder)] };
  const q = await hd.buildHdVaultGenesisRequest(genesisArgs);
  const signed = fx.signAll(config, q.transaction.unsignedSafeJson, q.transaction.signInputs.map((i) => [i.index, o.funder]));
  const ready = await hd.finalizeHdWalletRequest({ config, requestId: q.requestId, signedSafeJson: signed });
  base = { config, o, owner, q: ready, genesisArgs };
});
function fixture() {
  const x = { ...base, config: fx.cloneJsonConfig(base.config, "pv-rc27f-hd-"), rpc: fx.mockRpc() };
  const out = x.q.build.frozen.outputs[x.q.build.vaultOutputIndex], a = fx.spkAddress(x.config, out.scriptPublicKey);
  x.rpc.seed(a, fx.utxo(a, x.q.txId, x.q.build.vaultOutputIndex, out.value, x.q.build.covenantId));
  x.submit = () => hd.submitHdWalletRequest({ config: x.config, requestId: x.q.requestId, rpc: x.rpc }); return x;
}
test("RC27F F-9: HD membership append and ordinary root completion mutually exclude stale root writes", async () => {
  const x = fixture(), store = fx.getStore(x.config), read = store.read.bind(store), write = store.write.bind(store);
  let afterVault = false, paused = false, entered, release;
  const enteredP = new Promise((r) => { entered = r; }), held = new Promise((r) => { release = r; });
  store.write = async (c, k, v) => { await write(c, k, v); if (c === fx.Categories.VAULT && k === x.q.vaultId) afterVault = true; };
  /* RC33-ID-01 (2026-09-11): the genesis vault record is now written CREATE-ONLY (sdk/src/vault-identity.js), so the
   * 'vault record written' probe observes the create-only primitive as well — the property under test is unchanged */
  const createExclusive = store.createExclusive.bind(store);
  store.createExclusive = async (c, k, v) => { const created = await createExclusive(c, k, v); if (c === fx.Categories.VAULT && k === x.q.vaultId) afterVault = true; return created; };
  store.read = async (c, k) => { const value = await read(c, k); if (afterVault && !paused && c === fx.Categories.ORG_ROOT && k === x.o.rootCovenantId) { paused = true; entered(); await held; } return value; };
  const a = x.submit(); await enteredP;
  fx.settle(x.config, x.rpc, x.owner);
  const b = wr.submitOrgRootRequest({ config: x.config, requestId: x.owner.id, rpc: x.rpc });
  await new Promise((r) => setImmediate(r)); release();
  await Promise.all([a, b]); store.read = read; store.write = write;
  const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId);
  assert.equal(root.generation, 1); assert.equal(root.live.outpoint.transactionId, x.owner.txId);
  assert.equal(root.pendingRequestId, null); assert.ok(root.vaults.includes(x.q.vaultId));
  assert.equal(root.vaults.filter((id) => id === x.q.vaultId).length, 1);
  assert.equal((await hd.loadHdWalletRequest(x.config, x.q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal(x.rpc.submits(), 2);
});
for (const stage of ["root", "receipt", "audit", "submissionRelease", "finalRequest"]) test(`RC27F F-9: HD genesis ${stage} failure completes after reload without rebroadcast or duplicate effects`, async () => {
  const x = fixture();
  const conditions = {
    root: ["write", (c, k, v) => c === fx.Categories.ORG_ROOT && v.vaults.includes(x.q.vaultId)],
    receipt: ["write", (c, k) => c === fx.Categories.RECEIPT && k === x.q.txId],
    audit: ["appendAudit", (v) => v.txId === x.q.txId],
    submissionRelease: ["remove", (c, k) => c === fx.Categories.SUBMISSION_CLAIM && k === x.q.txId],
    finalRequest: ["write", (c, k, v) => c === fx.Categories.REQUEST && k === x.q.requestId && v.state === "CHAIN_VERIFIED"]
  };
  const [method, predicate] = conditions[stage], fault = fx.inject(x.config, method, predicate);
  await assert.rejects(x.submit()); assert.equal(fault.count(), 1); fault.restore();
  x.config = fx.reloadJsonConfig(x.config);
  await x.submit(); await x.submit();
  assert.equal((await hd.loadHdWalletRequest(x.config, x.q.requestId)).state, "CHAIN_VERIFIED");
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).vaults.filter((id) => id === x.q.vaultId).length, 1);
  assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1);
  assert.equal(await fx.loadSubmissionClaim(x.config, x.q.txId), null);
  assert.equal(x.rpc.submits(), 1);
});
async function signedDeposit(x) {
  const key = fx.KEY(x.config, 0x91), state = { ownerIdentifier: fx.XO(x.config, key), identifierType: 0, amount: 100000n, isMinter: false };
  const program = dep("sdk/src/token-program-kcc20").compileKcc20Program({ config: x.config, state, familyBound: 2 });
  const q = await hd.buildHdWalletRequest({ config: x.config, vaultId: x.q.vaultId, action: "tokenDeposit", signerAddress: fx.ADDR(x.config, key), params: { userPosition: { outpoint: { transactionId: fx.H(0x92), index: 0 }, value: fx.KAS.toString(), scriptPublicKeyHex: program.p2shSpkHex, covenantId: x.o.descriptor.tokenCovenantId, state }, depositAmount: "100000", depositCarryKasSompi: fx.KAS.toString(), fuel: fx.fuelUtxoFor(x.config, x.o.fuelKey) } });
  return hd.finalizeHdWalletRequest({ config: x.config, requestId: q.requestId, signedSafeJson: fx.signAll(x.config, q.transaction.unsignedSafeJson, [[0, key], [1, x.o.fuelKey]]) });
}
test("RC27F F-9: an unsigned identical genesis draft never reserves the completed vault", async () => {
  const x = fixture();
  /* RC33-ID-01 (2026-09-11, sdk/src/vault-identity.js): a second build with the SAME vault identity is now refused before
   * anything is written (VAULT_ID_IN_USE — identities are never recycled), so an identical duplicate draft can only exist
   * as a PRE-CORRECTION record. The F-9 property (such a stale unsigned draft never reserves the completed vault) is kept
   * by writing that legacy duplicate directly, exactly as the pre-correction builder left it (STALE ASSUMPTION in this
   * test asset; the property under test is unchanged). */
  await assert.rejects(hd.buildHdVaultGenesisRequest({ ...x.genesisArgs, config: x.config }), (e) => e.code === "VAULT_ID_IN_USE");
  const stored = await hd.loadHdWalletRequest(x.config, x.q.requestId);
  const duplicate = { ...stored, requestId: require("crypto").randomUUID(), state: "BUILT", createdAt: new Date().toISOString() };
  delete duplicate.signedSafeJson;
  await hd.saveHdWalletRequest(x.config, duplicate);
  assert.notEqual(duplicate.requestId, x.q.requestId); assert.equal(duplicate.txId, x.q.txId);
  await x.submit(); await hd.markHdWalletRejected(x.config, duplicate.requestId);
  await signedDeposit(x);
  assert.equal(x.rpc.submits(), 1); assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1);
});
test("RC27F F-9: a lost legacy root membership repairs while preserving a later HD deposit", async () => {
  const x = fixture(); await x.submit();
  const deposit = await signedDeposit(x); require("../testutil/cp13e-delegate-fixture").settle(x.config, x.rpc, deposit);
  await hd.submitHdWalletRequest({ config: x.config, requestId: deposit.requestId, rpc: x.rpc });
  const store = fx.getStore(x.config), before = await store.read(fx.Categories.VAULT, x.q.vaultId);
  const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId); root.vaults = root.vaults.filter((id) => id !== x.q.vaultId); await wr.saveOrgRoot(x.config, root);
  x.config = fx.reloadJsonConfig(x.config); await x.submit();
  assert.deepEqual(await fx.getStore(x.config).read(fx.Categories.VAULT, x.q.vaultId), before);
  assert.ok((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).vaults.includes(x.q.vaultId));
  assert.equal(x.rpc.submits(), 2); assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1);
});
test("RC27F F-9: membership repair refuses unavailable/contradictory evidence and retries only the root append", async () => {
  const x = fixture(); await x.submit();
  const deposit = await signedDeposit(x); require("../testutil/cp13e-delegate-fixture").settle(x.config, x.rpc, deposit);
  await hd.submitHdWalletRequest({ config: x.config, requestId: deposit.requestId, rpc: x.rpc });
  const store = fx.getStore(x.config), C = fx.Categories, vault = await store.read(C.VAULT, x.q.vaultId);
  const request = await hd.loadHdWalletRequest(x.config, x.q.requestId), receipt = await store.read(C.RECEIPT, x.q.txId);
  const root = await wr.loadOrgRoot(x.config, x.o.rootCovenantId); root.vaults = root.vaults.filter((id) => id !== x.q.vaultId); await wr.saveOrgRoot(x.config, root);
  const read = x.rpc.getUtxosByAddresses.bind(x.rpc);
  for (const mode of ["receipt-missing", "receipt-wrong", "audit-unavailable", "amount", "covenant", "script", "duplicate", "root-write"]) {
    let fault;
    if (mode === "receipt-missing") await store.remove(C.RECEIPT, x.q.txId);
    if (mode === "receipt-wrong") await store.write(C.RECEIPT, x.q.txId, { ...receipt, vaultId: fx.H(0xee) });
    if (mode === "audit-unavailable") fault = fx.inject(x.config, "readAudit", (a) => a.txId === x.q.txId);
    if (mode === "root-write") fault = fx.inject(x.config, "write", (c, k) => c === C.ORG_ROOT && k === x.o.rootCovenantId);
    if (["amount", "covenant", "script", "duplicate"].includes(mode)) x.rpc.getUtxosByAddresses = async (args) => {
      const result = await read(args);
      const entries = result.entries.map((e) => e.outpoint.transactionId !== vault.live.outpoint.transactionId || e.outpoint.index !== vault.live.outpoint.index ? e : { ...e, ...(mode === "amount" ? { amount: BigInt(e.amount) + 1n } : mode === "covenant" ? { covenantId: fx.H(0xee) } : mode === "script" ? { scriptPublicKey: "51" } : {}) });
      return { entries: mode === "duplicate" ? [...entries, ...entries] : entries };
    };
    await assert.rejects(x.submit(), undefined, mode); fault?.restore(); x.rpc.getUtxosByAddresses = read;
    if (mode.startsWith("receipt-")) await store.write(C.RECEIPT, x.q.txId, receipt);
    assert.deepEqual(await hd.loadHdWalletRequest(x.config, x.q.requestId), request, mode);
    assert.deepEqual(await store.read(C.VAULT, x.q.vaultId), vault, mode);
    assert.deepEqual(await wr.loadOrgRoot(x.config, x.o.rootCovenantId), root, mode);
  }
  x.config = fx.reloadJsonConfig(x.config); await x.submit(); await x.submit();
  assert.deepEqual(await fx.getStore(x.config).read(C.VAULT, x.q.vaultId), vault);
  assert.deepEqual(await hd.loadHdWalletRequest(x.config, x.q.requestId), request);
  assert.equal((await wr.loadOrgRoot(x.config, x.o.rootCovenantId)).vaults.filter((id) => id === x.q.vaultId).length, 1);
  assert.equal((await fx.auditLinesFor(x.config, x.q.txId)).length, 1); assert.equal(x.rpc.submits(), 2);
});
