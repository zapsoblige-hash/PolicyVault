"use strict";
/* L5-01 actual legacy ABI and finalization interruption regressions: actual signed v0.4.1 encoder/VM pipeline, deterministic
 * TEST keys, mocked node only. Claude S1/S3/S4/S7 are prevention regressions;
 * S2/S5 retain the existing post-broadcast controls. Legacy version rewrites
 * and missing request records are synthetic historical shapes, not evidence
 * of production occurrence. PostgreSQL uses owned disposable databases. */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const fx = require("../testutil/v4-transition-recovery-fixture");
const { wr4, submit4, vs4, getStore, Categories, transitionClaimKey, KAS, wallet, clone, install, snapshot } = fx;
const { makeDevSigner } = require("../src/signer-dev");
const { reconcileVaultV4 } = require("../src/reconcile-v4");
const { findProtectedTransitionV4, reconcileTransitionWalletRequestV4 } = require("../src/wallet-recovery-v4");
const { persistManifestV4 } = require("../src/manifest-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { reservationKey } = require("../src/budget-reservation");
const { openPgStore } = require("../src/store");
const VAULT = "a8".repeat(32), ANCHOR = "31".repeat(32);
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = { host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1", port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0), user: process.env.POLICYVAULT_TEST_PG_USER, database: process.env.POLICYVAULT_TEST_PG_DATABASE };
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = TOOLCHAIN ? undefined : "REQUIREMENT_NOT_AVAILABLE: real compiler and VM";
const pgSkip = skip || (PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}");
const roots = [], stores = [], databases = [];
let base, admin, serial = 0;
function freshConfig(overrides = {}) {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-lead5-test-")); roots.push(dataRoot);
  return fx.loadConfig({ ...overrides, dataRoot });
}
async function signedBase(version = "policyvault-0.4", action = "agentSpend", interruptFinalized = false) {
  const config = freshConfig(); assert.equal(config.networkId, "testnet-10");
  const owner = wallet(config, 0x11), agent = wallet(config, 0x21), recipient = wallet(config, 0x31);
  const entry = { agentPk: agent.xonly, maxPerSpend: (20n*KAS).toString(), periodBudget: (50n*KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n*KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [recipient.xonly] };
  const template = { owner: owner.xonly, vaultId: VAULT };
  const policy = normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root });
  const state = vs4.normalizeStateV4({ protectedValue: (1000n*KAS).toString(), feeReserve: (5n*KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: version });
  await persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion: version, networkId: config.networkId, vaultId: VAULT, label: "LEAD5 TEST", status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: vs4.stateToJsonV4(state), stateId: vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: version }), outpoint: { transactionId: "42".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) }, creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null });
  const fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n*KAS).toString(), scriptPublicKeyHex: `20${owner.xonly}ac` };
  const params = action === "agentSpend" ? { payAmountSompi: (4n*KAS).toString(), agentPk: agent.xonly, recipient: recipient.xonly } : { fuel };
  const signer = action === "agentSpend" ? agent : owner;
  const request = await wr4.buildWalletRequestV4({ config, vaultId: VAULT, action, params, signerAddress: signer.address });
  const signed = makeDevSigner(config, { secretHex: signer.secretHex, expectedAddress: signer.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  if (interruptFinalized) {
    // RC45 F4 (plan r2 §8.1 ":111-119: setup :48-53 intercepts the deleted FINALIZED write (:51 fails)"; §2.4(1) "the only
    // FINALIZED writer is deleted"): the same interceptor now finds NO FINALIZED write — the candidate finalize completes
    // (was :51 `assert.rejects(..., /TEST crash after FINALIZED/); assert.equal(hit, true)`). The historical byte-less
    // FINALIZED shape therefore comes from the pinned RC44 writer (see the test below).
    const store = getStore(config), write = store.write.bind(store); let hit = false, finalized;
    store.write = async (...args) => { const out = await write(...args); if (!hit && args[0] === Categories.REQUEST && args[2]?.state === "FINALIZED") { hit = true; throw Error("TEST crash after FINALIZED"); } return out; };
    try { await assert.doesNotReject(async () => { finalized = await wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: signed }); }, "the candidate finalize never persists FINALIZED, so the interceptor never fires"); assert.equal(hit, false, "no FINALIZED write"); } finally { store.write = write; }
    assert.equal(finalized.state, "PREFLIGHT_VERIFIED"); assert.ok(finalized.finalTransaction, "its first request write carries the signed bytes");
    return { config, request: await wr4.loadRequest(config, request.requestId), signed };
  }
  const finalized = await wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: signed });
  assert.equal(finalized.state, "PREFLIGHT_VERIFIED");
  return { config, owner, agent, recipient, request: finalized, params, snap: await snapshot(config) };
}
function node(config, request) {
  const kaspa = require(config.rustyKaspaModule), table = new Map(), calls = [];
  const address = (s) => kaspa.addressFromScriptPublicKey({ version: s.version, script: s.scriptHex }, config.networkId).toString();
  const seed = (a, outpoint, amount, s, covenantId = null) => table.set(a, [...(table.get(a) ?? []), { address: a, outpoint: clone(outpoint), amount: String(amount), scriptPublicKey: { version: s.version, script: s.scriptHex }, covenantId, blockDaaScore: "1", isCoinbase: false }]);
  const funding = () => { table.clear(); request.finalTransaction.inputs.forEach((i, idx) => seed(address(i.utxo.scriptPublicKey), i.previousOutpoint, i.utxo.amount, i.utxo.scriptPublicKey, idx === 0 ? request.covenantId : i.utxo.covenantId ?? null)); };
  const settle = () => { table.clear(); request.finalTransaction.outputs.forEach((o, idx) => seed(address(o.scriptPublicKey), { transactionId: request.txId, index: idx }, o.value, o.scriptPublicKey, o.covenant?.covenantId ?? null)); };
  const rpc = {
    async getUtxosByAddresses({ addresses }) { calls.push("getUtxosByAddresses"); return { entries: addresses.flatMap((a) => clone(table.get(a) ?? [])) }; },
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { sink: ANCHOR, virtualDaaScore: "90000000" }; }, // RC45 F5 (§8.1 mock :66): + virtualDaaScore
    async getMempoolEntry() { calls.push("getMempoolEntry"); return { entry: { transaction: { verboseData: { transactionId: request.txId } } } }; },
    async getVirtualChainFromBlock() { calls.push("getVirtualChainFromBlock"); throw Error("TEST unavailable historical acceptance"); },
    async submitTransaction() { calls.push("submitTransaction"); throw Error("TEST connection lost after signed transition submission"); },
    async disconnect() { calls.push("disconnect"); }
  };
  funding(); return { rpc, funding, settle, calls };
}

const legacyBases = {};
before(async () => {
  if (!TOOLCHAIN) return;
  for (const action of ["agentSpend", "ownerPause", "ownerRecover"]) legacyBases[action] = await signedBase("policyvault-0.4", action);
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) await s.close();
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
});
for (const [backend, pg, skipped] of [["JSON", false, skip], ["PostgreSQL", true, pgSkip]]) {
  for (const action of ["agentSpend", "ownerPause", "ownerRecover"]) test(`L5 actual legacy ${backend}: ${action} retains exact compiled/signed positive recovery`, { skip: skipped }, async () => {
    const b = legacyBases[action]; let config;
    if (pg) {
      const db = `pv_lead5_legacy_${process.pid}_${++serial}`; await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
      config = freshConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: db, pgNoTls: true, authMode: "enabled", authCookieInsecure: true });
      stores.push(await openPgStore(config, { migrate: true }));
    } else config = freshConfig();
    await install(config, b.snap);
    const n = node(config, b.request), s = getStore(config), before = await snapshot(config);
    assert.equal(b.request.contractVersion, "policyvault-0.4"); assert.equal(b.request.build.contractVersion, "policyvault-0.4");
    assert.equal((await reconcileVaultV4(config, VAULT, { rpc: n.rpc })).status, "REQUEST_RECOVERY_REQUIRED");
    // RC45 F5 (plan r2 §8.1 v4-recovery-legacy-lead5 :98, was `assert.deepEqual(n.calls, [])`; §2.2 "every Verify re-reads the
    // recorded outpoint first"): Verify reads the recorded outpoint before it answers; it writes nothing and never submits.
    assert.deepEqual(await snapshot(config), before); assert.ok(n.calls.includes("getUtxosByAddresses"), "Verify re-reads the recorded outpoint first"); assert.equal(n.calls.includes("submitTransaction"), false);
    n.settle(); const recover = () => reconcileTransitionWalletRequestV4({ config, requestId: b.request.requestId, rpc: n.rpc });
    assert.equal((await recover()).outcome, "CHAIN_VERIFIED");
    const q = await wr4.loadRequest(config, b.request.requestId), m = await s.read(Categories.VAULT, VAULT);
    assert.deepEqual(q.finalTransaction, b.request.finalTransaction); assert.deepEqual(q.build, b.request.build);
    assert.equal(m.contractVersion, "policyvault-0.4"); assert.equal(m.latestTransitionTxId, b.request.txId);
    assert.equal(m.status, action === "ownerRecover" ? "RECOVERED" : action === "ownerPause" ? "PAUSED" : "ACTIVE");
    assert.equal(await s.read(Categories.SUBMISSION_CLAIM, q.txId), null); assert.equal(await s.read(Categories.TRANSITION_CLAIM, transitionClaimKey(q.predecessorOutpoint)), null);
    const complete = await snapshot(config), reads = n.calls.length;
    assert.equal((await recover()).outcome, "CHAIN_VERIFIED"); assert.deepEqual(await snapshot(config), complete); assert.equal(n.calls.length, reads);
    assert.equal(n.calls.includes("submitTransaction"), false);
  });
}
/* RC45 F4 (plan r2 §8.1 v4-recovery-legacy-lead5 :111-119, CR-M13): the candidate no longer writes FINALIZED (signedBase's
 * interrupt leg now pins that), so the byte-less FINALIZED of this historical interruption is written by the pinned df5b8de
 * writers in POLICYVAULT_TEST_RC44_TREE (sdk/testutil/rc45-rc44-history.js "lead5Finalized": the same vault, keys, spend and
 * :48-53 interceptor, run against RC44; a missing or mismatched tree FAILS, never skips). :115 reads an explicit chain model
 * (the recorded outpoint live, a virtualDaaScore) instead of a throwing stub; :113, :116-118 hold unchanged. */
const rc44Roots = [];
after(() => { for (const root of rc44Roots) require("../testutil/rc45-rc44-history").removeOwnedRoot(root); });
test("L5 finalization crash: FINALIZED without retained signed bytes stays protected and never infers rejection", { skip }, async () => {
  const H44 = require("../testutil/rc45-rc44-history");
  const rc44 = H44.runRc44Scenario("lead5Finalized", { track: (root) => rc44Roots.push(root) });
  const config = freshConfig({ rpcUrl: H44.LOOPBACK });
  await install(config, await snapshot(fx.loadConfig({ dataRoot: rc44.dataRoot, rpcUrl: H44.LOOPBACK })));
  const b = { request: await wr4.loadRequest(config, rc44.result.requestId), signed: rc44.result.signed };
  assert.equal(b.request.state, "FINALIZED"); assert.equal(b.request.finalTransaction, undefined);
  assert.equal(b.request.contractVersion, "policyvault-0.4.1"); assert.equal(b.request.vaultId, VAULT);
  const before = await snapshot(config);
  const kaspa = require(config.rustyKaspaModule), input = JSON.parse(b.request.build.frozenCanonicalJson).inputs[0], s = input.utxo.scriptPublicKey;
  const address = kaspa.addressFromScriptPublicKey({ version: s.version, script: s.scriptHex }, config.networkId).toString();
  const live = { address, outpoint: clone(input.previousOutpoint), amount: String(input.utxo.amount), scriptPublicKey: { version: s.version, script: s.scriptHex }, covenantId: b.request.covenantId, blockDaaScore: String(90_000_000n - 5000n), isCoinbase: false };
  const model = { // the recorded outpoint L is live and deep; nothing else is indexed; never submits
    async getUtxosByAddresses({ addresses }) { return { entries: addresses.includes(address) ? [clone(live)] : [] }; },
    async getBlockDagInfo() { return { sink: ANCHOR, virtualDaaScore: "90000000" }; },
    async getMempoolEntry({ transactionId }) { throw Error(`Transaction ${transactionId} not found`); },
    async getVirtualChainFromBlock() { throw Error("TEST unavailable historical acceptance"); },
    async submitTransaction() { throw Error("TEST must not submit"); },
    async disconnect() {}
  };
  assert.equal((await reconcileVaultV4(config, VAULT, { rpc: model })).status, "REQUEST_RECOVERY_REQUIRED");
  await assert.rejects(wr4.finalizeWalletRequestV4({ config, requestId: b.request.requestId, signedSafeJson: b.signed }), { code: "FINALIZED" });
  await assert.rejects(reconcileTransitionWalletRequestV4({ config, requestId: b.request.requestId }), { code: "TRANSITION_RECOVERY_REFUSED" });
  assert.deepEqual(await snapshot(config), before);
  // The candidate side of the same interruption (was :51): no FINALIZED write exists to intercept (asserted in signedBase).
  const candidate = await signedBase("policyvault-0.4.1", "agentSpend", true);
  assert.equal(candidate.request.state, "PREFLIGHT_VERIFIED", "the candidate's interrupted finalize is not FINALIZED");
});
