"use strict";
/* L5-01 regressions: actual signed v0.4.1 encoder/VM pipeline, deterministic
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
async function signedBase() {
  const config = freshConfig(); assert.equal(config.networkId, "testnet-10");
  const owner = wallet(config, 0x11), agent = wallet(config, 0x21), recipient = wallet(config, 0x31);
  const entry = { agentPk: agent.xonly, maxPerSpend: (20n*KAS).toString(), periodBudget: (50n*KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n*KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [recipient.xonly] };
  const template = { owner: owner.xonly, vaultId: VAULT };
  const policy = normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root });
  const state = vs4.normalizeStateV4({ protectedValue: (1000n*KAS).toString(), feeReserve: (5n*KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 });
  await persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion: vs4.CONTRACT_VERSION_V4_1, networkId: config.networkId, vaultId: VAULT, label: "LEAD5 TEST", status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: vs4.stateToJsonV4(state), stateId: vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 }), outpoint: { transactionId: "42".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) }, creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null });
  const params = { payAmountSompi: (4n*KAS).toString(), agentPk: agent.xonly, recipient: recipient.xonly };
  const request = await wr4.buildWalletRequestV4({ config, vaultId: VAULT, action: "agentSpend", params, signerAddress: agent.address });
  const signed = makeDevSigner(config, { secretHex: agent.secretHex, expectedAddress: agent.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
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
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { sink: ANCHOR, virtualDaaScore: "90000000" }; }, // RC45 F5 (§8.1 :58): + virtualDaaScore (depth = virtual - blockDaaScore)
    async getMempoolEntry() { calls.push("getMempoolEntry"); return { entry: { transaction: { verboseData: { transactionId: request.txId } } } }; },
    async getVirtualChainFromBlock() { calls.push("getVirtualChainFromBlock"); throw Error("TEST unavailable historical acceptance"); },
    async submitTransaction() { calls.push("submitTransaction"); throw Error("TEST connection lost after signed transition submission"); },
    async disconnect() { calls.push("disconnect"); }
  };
  funding(); return { rpc, funding, settle, calls };
}
before(async () => { if (TOOLCHAIN) base = await signedBase(); if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG); });
after(async () => {
  for (const s of stores) await s.close();
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
});
async function fresh(pg) {
  let config;
  if (pg) {
    const db = `pv_lead5_${process.pid}_${++serial}`; await admin.query(`CREATE DATABASE ${db}`); databases.push(db);
    config = freshConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: db, pgNoTls: true, authMode: "enabled", authCookieInsecure: true });
    stores.push(await openPgStore(config, { migrate: true }));
  } else config = freshConfig();
  await install(config, base.snap);
  const x = { config, q: base.request, ...node(config, base.request) };
  x.generic = (options = {}) => reconcileVaultV4(config, VAULT, { rpc: x.rpc, ...options });
  x.recover = () => reconcileTransitionWalletRequestV4({ config, requestId: x.q.requestId, rpc: x.rpc });
  x.request = () => wr4.loadRequest(config, x.q.requestId);
  x.manifest = () => getStore(config).read(Categories.VAULT, VAULT);
  x.raw = () => snapshot(config);
  x.age = async () => { const s = getStore(config), k = transitionClaimKey(x.q.predecessorOutpoint), c = await s.read(Categories.TRANSITION_CLAIM, k); await s.write(Categories.TRANSITION_CLAIM, k, { ...c, createdAt: "2000-01-01T00:00:00.000Z" }); };
  return x;
}
async function postBroadcast(x) {
  await assert.rejects(submit4.submitWalletRequestV4({ config: x.config, requestId: x.q.requestId, rpc: x.rpc, pollAttempts: 1, pollDelayMs: 0 }), { code: "RECONCILIATION_REQUIRED" });
  assert.equal((await x.request()).state, "RECONCILIATION_REQUIRED");
  assert.equal(x.calls.filter((c) => c === "submitTransaction").length, 1);
}
/* RC45 F5 (plan r2 §8.1 v4-reconcile-lead5 zero-call pins S1 :111, S2 :142, S3 :123; §2.2 reorg rule "every Verify
 * re-reads the recorded outpoint first"): Verify now reads the node before it answers; it still never submits. */
function assertOutpointRead(x) {
  assert.ok(x.calls.includes("getUtxosByAddresses"), "Verify re-reads the recorded outpoint first (was: no node call)");
  assert.equal(x.calls.includes("submitTransaction"), false, "Verify never submits");
}
/* RC45 F7 (plan r2 §8.1 v4-reconcile-lead5 assertComplete :94-106 — :96 journal phase, :103 transition_recovery_completed;
 * §2.2 completePositive (4), §2.6 step 5, CR-M9): completion writes no journal, and its audit row is the pass's
 * reconciled_advanced carrying the txId (was: journal phase COMPLETE and one transition_recovery_completed row). */
async function assertComplete(x) {
  const r = await x.request(), s = getStore(x.config), m = await x.manifest();
  assert.equal(r.state, "CHAIN_VERIFIED"); assert.equal(r.transitionRecovery, undefined, "no journal (was: phase COMPLETE)");
  assert.deepEqual(r.finalTransaction, base.request.finalTransaction); assert.deepEqual(r.build, base.request.build);
  assert.equal(m.live.outpoint.transactionId, r.txId); assert.equal(m.agentRegistry[0].periodSpent, (4n*KAS).toString());
  assert.equal(await s.read(Categories.TRANSITION_CLAIM, transitionClaimKey(r.predecessorOutpoint)), null);
  assert.equal(await s.read(Categories.SUBMISSION_CLAIM, r.txId), null);
  assert.equal(await s.read(Categories.TRANSITION_CLAIM, reservationKey(r)), null);
  const receipt = await s.read(Categories.RECEIPT, r.txId); assert.equal(receipt.proof.requestId, r.requestId);
  const audit = await s.readAudit({ vaultId: VAULT, limit: 1000 });
  assert.equal(audit.filter((e) => e.action === "reconciled_advanced" && e.txId === r.txId).length, 1, "one reconciled_advanced row with the txId (was: one transition_recovery_completed)");
  assert.equal(audit.filter((e) => e.action === "transition_recovery_completed").length, 0, "the journal-era completion row is never written");
  const snap = await x.raw(), calls = x.calls.length;
  assert.equal((await x.recover()).outcome, "CHAIN_VERIFIED"); assert.deepEqual(await x.raw(), snap); assert.equal(x.calls.length, calls);
}
for (const [backend, pg, skipped] of [["JSON", false, skip], ["PostgreSQL", true, pgSkip]]) {
  const scenario = (name, fn) => test(`L5 ${backend}: ${name}`, { skip: skipped }, async () => fn(await fresh(pg)));
  scenario("S1 aged signed preflight request stays protected byte-for-byte", async (x) => {
    await x.age(); const before = await x.raw(); assert.equal((await x.generic()).status, "REQUEST_RECOVERY_REQUIRED");
    assert.deepEqual(await x.raw(), before); assertOutpointRead(x); // RC45 F5 §8.1 S1 :111 (was: assert.deepEqual(x.calls, []))
    assert.equal((await findProtectedTransitionV4(x.config, VAULT)).requestId, x.q.requestId);
  });
  scenario("own finalized request may still submit normally after generic observation", async (x) => {
    await x.age(); await x.generic(); await postBroadcast(x);
    const s = getStore(x.config); assert.equal((await s.read(Categories.TRANSITION_CLAIM, transitionClaimKey(x.q.predecessorOutpoint))).txId, x.q.txId);
    assert.equal((await s.read(Categories.TRANSITION_CLAIM, reservationKey(x.q))).status, "CONSUMED");
  });
  scenario("S3 synthetic legacy v0.4 record remains protected before and after landing", async (x) => {
    await postBroadcast(x); const r = await x.request(); r.contractVersion = "policyvault-0.4"; await wr4.saveRequest(x.config, r); await x.age();
    const before = await x.raw(); x.calls.length = 0;
    assert.equal((await x.generic()).status, "REQUEST_RECOVERY_REQUIRED"); x.settle();
    // RC45 F5 §8.1 S3 :123 (was: REQUEST_RECOVERY_REQUIRED and no node call): after the landing the record's identity fails
    // (build.contractVersion != r.contractVersion), so it is excluded; nothing else explains L -> UNKNOWN, no write.
    assert.equal((await x.generic()).status, "UNKNOWN"); assert.deepEqual(await x.raw(), before); assertOutpointRead(x);
    await assert.rejects(x.recover(), { code: "TRANSITION_RECOVERY_REFUSED" }); assert.deepEqual(await x.raw(), before);
  });
  scenario("S4 orphan claim is never released by age or caller override", async (x) => {
    await getStore(x.config).remove(Categories.REQUEST, x.q.requestId); await x.age(); const before = await x.raw();
    for (const options of [{}, { allowClaimRelease: true, stalePendingMinimumMs: 0 }, { allowClaimRelease: false }, { stalePendingMinimumMs: -1 }]) {
      assert.equal((await x.generic(options)).status, "CLAIM_PENDING"); assert.deepEqual(await x.raw(), before);
    }
    // RC45 F5 §8.1 S4 :131 (was: rejects /no durable request found/): no recorded request explains L -> UNKNOWN, no write;
    // the orphan claim stays byte-identical.
    x.settle(); let unknown; await assert.doesNotReject(async () => { unknown = await x.generic(); }, "Verify answers");
    assert.equal(unknown.status, "UNKNOWN"); assert.deepEqual(await x.raw(), before);
  });
  scenario("S7 competing build refused and original late signed effect remains recoverable", async (x) => {
    await x.age(); assert.equal((await x.generic()).status, "REQUEST_RECOVERY_REQUIRED");
    const before = await x.raw();
    await assert.rejects(wr4.buildWalletRequestV4({ config: x.config, vaultId: VAULT, action: "agentSpend", params: { ...base.params, payAmountSompi: (3n*KAS).toString() }, signerAddress: base.agent.address }), { code: "REQUEST_RECOVERY_REQUIRED" });
    // RC45 F5 §8.1 S7 :137 (was: REQUEST_RECOVERY_REQUIRED): the landed own txid is SEEN at depth >= D -> Verify completes it.
    assert.deepEqual(await x.raw(), before); x.settle(); assert.equal((await x.generic()).status, "ADVANCED");
    assert.equal((await x.recover()).outcome, "CHAIN_VERIFIED"); await assertComplete(x);
  });
  scenario("S2 modern post-broadcast guard control", async (x) => {
    await postBroadcast(x); await x.age(); const before = await x.raw(); x.calls.length = 0;
    assert.equal((await x.generic()).status, "REQUEST_RECOVERY_REQUIRED"); assert.deepEqual(await x.raw(), before); assertOutpointRead(x); // RC45 F5 §8.1 S2 :142
  });
  scenario("S5 modern request recovery control", async (x) => {
    await postBroadcast(x); await x.age(); x.settle(); assert.equal((await x.generic()).status, "ADVANCED"); // RC45 F5 §8.1 S5 :145 (was REQUEST_RECOVERY_REQUIRED)
    assert.equal((await x.recover()).outcome, "CHAIN_VERIFIED"); await assertComplete(x);
  });
  for (const unavailable of [false, true]) scenario(`preflight observation ${unavailable ? "unavailable" : "absent"} preserves claims and reservation`, async (x) => {
    const before = await x.raw(); if (unavailable) x.rpc.getUtxosByAddresses = async () => { throw Error("TEST unavailable"); };
    assert.equal((await x.recover()).outcome, "PROTECTED_UNRESOLVED"); const after = await x.raw();
    for (const category of [Categories.VAULT, Categories.SUBMISSION_CLAIM, Categories.TRANSITION_CLAIM, Categories.RECEIPT]) assert.deepEqual(after.records[category], before.records[category]);
    // RC45 F7 (plan r2 §8.1 v4-reconcile-lead5 :148-155 "-> zero writes", :152 journal; :150 holds; §2.6 step 4): the request
    // record and the audit log are untouched too — no journal, no relabel; a read failure in the pass (its 422) is
    // PROTECTED_UNRESOLVED with no write (was: RECONCILIATION_REQUIRED with a journal whose originalState is PREFLIGHT_VERIFIED).
    assert.deepEqual(after, before, "zero writes: every record and the audit log are byte-identical");
    const r = await x.request(); assert.equal(r.transitionRecovery, undefined, "no journal"); assert.equal(r.state, "PREFLIGHT_VERIFIED"); assert.equal(r.submitStartHash, undefined);
    assert.deepEqual(r.finalTransaction, base.request.finalTransaction); assert.deepEqual(r.build, base.request.build);
    assert.equal(x.calls.includes("submitTransaction"), false);
  });
  for (const corrupt of ["missing", "invalid-signature"]) scenario(`preflight ${corrupt} signed bytes refuse before any write`, async (x) => {
    const r = await x.request(); if (corrupt === "missing") delete r.finalTransaction; else r.finalTransaction.inputs[0].signatureScript = "00";
    await wr4.saveRequest(x.config, r); const before = await x.raw();
    await assert.rejects(x.recover(), { code: "TRANSITION_RECOVERY_REFUSED" }); assert.deepEqual(await x.raw(), before);
  });
  scenario("wrong observed output script cannot advance", async (x) => {
    x.settle(); const get = x.rpc.getUtxosByAddresses;
    x.rpc.getUtxosByAddresses = async (args) => { const out = await get(args); for (const e of out.entries) e.scriptPublicKey.script = "51"; return out; };
    const before = await x.manifest(); assert.equal((await x.recover()).outcome, "PROTECTED_UNRESOLVED"); assert.deepEqual(await x.manifest(), before);
  });
  scenario("foreign attempt claim is never changed or released", async (x) => {
    const s = getStore(x.config), k = transitionClaimKey(x.q.predecessorOutpoint), claim = await s.read(Categories.TRANSITION_CLAIM, k);
    await s.write(Categories.TRANSITION_CLAIM, k, { ...claim, txId: "fa".repeat(32) }); x.settle(); const before = await x.raw();
    await assert.rejects(x.recover(), { code: "CLAIM_CONFLICT" }); assert.deepEqual(await x.raw(), before);
  });
  scenario("duplicate unresolved signed transaction identity refuses before writes", async (x) => {
    await wr4.saveRequest(x.config, { ...clone(x.q), requestId: "second-signed-request" }); x.settle(); const before = await x.raw();
    await assert.rejects(x.recover(), { code: "CLAIM_CONFLICT" }); assert.deepEqual(await x.raw(), before);
  });
  for (const boundary of ["manifest", "receipt", "audit", "claim", "request"]) scenario(`positive preflight completion recovers interruption after ${boundary}`, async (x) => {
    x.settle(); const failure = fx.injectAfter(x.config, boundary);
    try { await assert.rejects(x.recover(), /TEST interruption/); assert.equal(failure.hit(), true); } finally { failure.restore(); }
    assert.equal((await x.recover()).outcome, "CHAIN_VERIFIED"); await assertComplete(x);
  });
}
