"use strict";
// Ordinary persistence/restart regressions for v0.2 REQUEST genesis and signatureless legacy headless recovery.
// Isolated JSON roots, deterministic TEST keys, real WASM builders, in-process node fixtures; no network or funds.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { loadConfig } = require("../src/config");
const { getStore, Categories } = require("../src/store");
const { findVaultIdentityReservation, assertVaultIdentityFree } = require("../src/vault-identity");
const { createVault } = require("../src/create-vault");
const { createVaultV2 } = require("../src/vault-ops-v2");
const headless = require("../src/headless-creation");
const { claimSubmission } = require("../src/submission-claim");
const { toolchainSkip, answers } = require("./helpers/rc35-recovery-fixtures");

const SKIP = toolchainSkip("pv-res01-probe-");
const KAS = 100000000n;
const hex32 = () => crypto.randomBytes(32).toString("hex");

/* a mock node in the shape the WASM transaction generator and the SDK's UTXO reader both accept */
function nodeMock(cfg) {
  const kaspa = require(cfg.rustyKaspaModule);
  const table = {};
  const rpc = {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    fund(address, xonly, amount) { table[address] = [...(table[address] ?? []), { address, outpoint: { transactionId: hex32(), index: 0 }, amount, scriptPublicKey: { version: 0, script: `20${xonly}ac` }, blockDaaScore: 1n, isCoinbase: false }]; },
    seedVault(address, txId, index, amount, covenantId) { table[address] = [...(table[address] ?? []), { address, outpoint: { transactionId: txId, index }, amount, scriptPublicKey: { version: 0, script: "" }, blockDaaScore: 2n, isCoinbase: false, covenantId }]; },
    clear(address) { table[address] = []; }
  };
  return { kaspa, rpc, connection: { rpc, kaspa, serverInfo: { networkId: cfg.networkId } } };
}
function keyOf(kaspa, byte, networkId) {
  const secret = byte.toString(16).padStart(2, "0").repeat(32);
  const priv = new kaspa.PrivateKey(secret);
  return { secret, address: priv.toPublicKey().toAddress(networkId).toString(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase() };
}
function setup(t) {
  const cfg = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-res01-")) });
  t.after(() => fs.rmSync(cfg.dataRoot, { recursive: true, force: true }));
  const { kaspa, rpc, connection } = nodeMock(cfg);
  const funder = keyOf(kaspa, 0xf0, cfg.networkId), owner = keyOf(kaspa, 0x21, cfg.networkId), delegate = keyOf(kaspa, 0x62, cfg.networkId), r1 = keyOf(kaspa, 0x63, cfg.networkId);
  rpc.fund(funder.address, funder.xonly, 5000n * KAS);
  const store = getStore(cfg);
  const policyFor = (vaultId) => ({ label: "headless v1", owner: owner.xonly, delegate: delegate.xonly, vaultId, maxPerSpend: (10n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "600", recipients: [r1.xonly], initValue: (100n * KAS).toString(), initPeriodStartDaa: "1000" });
  const v2For = (vaultId) => ({ templateInput: { owner: owner.xonly, vaultId }, initialStateInput: { protectedValue: (100n * KAS).toString(), periodStartDaa: "1000", periodSpent: "0", paused: "0", delegate: delegate.xonly, maxPerSpend: (10n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "600", recipients: [r1.xonly], delegateActive: "1", policyNonce: "0" } });
  const drivers = {
    v1: (vaultId, over = {}) => createVault({ config: cfg, policyInput: policyFor(vaultId), fundingKey: { secret: funder.secret, address: funder.address }, delegateAddress: delegate.address, delegateFuelSompi: 0n, connection: over.connection ?? connection, pollAttempts: 1, pollDelayMs: 0 }),
    v2: (vaultId, over = {}) => createVaultV2({ config: cfg, ...v2For(vaultId), fundingKey: { secret: funder.secret, address: funder.address }, delegateFuelSompi: 0n, label: "headless v2", connection: over.connection ?? connection, pollAttempts: 1, pollDelayMs: 0 })
  };
  /* a node view whose broadcast answers follow a script and which lands the vault output when told to */
  function scripted(answerFor) {
    const s = { calls: 0 };
    s.rpc = { ...rpc, async submitTransaction({ transaction }) { s.calls += 1; const txId = transaction.finalize().toString().toLowerCase(); const a = answerFor(txId, transaction); if (a && a.land) landOutput(transaction, txId); if (a && a.throw) throw new Error(a.throw); return { transactionId: txId }; } };
    s.connection = { rpc: s.rpc, kaspa, serverInfo: { networkId: cfg.networkId } };
    return s;
  }
  /* land the vault output of a signed transaction exactly as the node would index it */
  function landOutput(transaction, txId) {
    const outs = transaction.outputs;
    for (let i = 0; i < outs.length; i++) {
      const o = outs[i];
      if (!o.covenant) continue;
      const addr = kaspa.addressFromScriptPublicKey(o.scriptPublicKey, cfg.networkId).toString();
      rpc.seedVault(addr, txId, i, BigInt(o.value), String(o.covenant.covenantId).toLowerCase());
    }
  }
  return { cfg, kaspa, rpc, connection, store, funder, owner, delegate, r1, policyFor, v2For, drivers, scripted, landOutput };
}


async function prepareWalletGenesis(x) {
  x.rpc.fund(x.owner.address, x.owner.xonly, 5000n * KAS);
  const connection = { ...x.connection };
  const chain = require("../src/chain"), original = chain.connectVerified;
  chain.connectVerified = async () => connection;
  const location = require.resolve("../src/wallet-requests-v2");
  delete require.cache[location];
  let wr2;
  try { wr2 = require("../src/wallet-requests-v2"); } finally { chain.connectVerified = original; }
  const request = await wr2.buildCreateWalletRequestV2({ config: x.cfg, ...x.v2For(hex32()), signerAddress: x.owner.address });
  const transaction = x.kaspa.Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
  const inputs = transaction.inputs;
  for (let i = 0; i < inputs.length; i++) inputs[i].signatureScript = x.kaspa.createInputSignature(transaction, i, new x.kaspa.PrivateKey(x.owner.secret));
  transaction.inputs = inputs;
  const signedSafeJson = transaction.serializeToSafeJSON();
  let calls = 0, durableBeforeBroadcast = false;
  const anchor = "ab".repeat(32);
  connection.rpc = { ...x.rpc, getBlockDagInfo: async () => ({ sink: anchor }), async submitTransaction({ transaction: signed }) {
    calls++;
    const stored = await wr2.loadRequest(x.cfg, request.requestId);
    assert.equal(stored.state, "SUBMITTING");
    assert.equal(stored.submitStartHash, anchor);
    assert.equal(typeof stored.signedSafeJson, "string");
    assert.equal(x.kaspa.Transaction.deserializeFromSafeJSON(stored.signedSafeJson).finalize().toString().toLowerCase(), stored.txId);
    durableBeforeBroadcast = true;
    x.landOutput(signed, stored.txId);
    throw Error("connection closed before response (isolated fixture)");
  } };
  return { wr2, request, signedSafeJson, connection, calls: () => calls, durable: () => durableBeforeBroadcast,
    attempt: () => wr2.attachWalletSignatureV2({ config: x.cfg, requestId: request.requestId, signedSafeJson }),
    load: () => wr2.loadRequest(x.cfg, request.requestId),
    recover: () => wr2.reconcileCreateWalletRequestV2({ config: x.cfg, requestId: request.requestId, rpc: connection.rpc }) };
}

function interruptOnce(store, boundary) {
  const methods = ["createExclusive", "write", "remove", "appendAudit"];
  const originals = Object.fromEntries(methods.map((name) => [name, store[name].bind(store)]));
  let hit = false;
  const should = (name, category, value) => boundary === "VAULT" ? name === "createExclusive" && category === Categories.VAULT
    : boundary === "RECEIPT" ? name === "write" && category === Categories.RECEIPT
    : boundary === "AUDIT" ? name === "appendAudit"
    : boundary === "CLAIM_RELEASE" ? name === "remove" && category === Categories.SUBMISSION_CLAIM
    : name === "write" && category === Categories.REQUEST && value?.state === "CHAIN_VERIFIED";
  for (const name of methods) store[name] = async (...args) => {
    if (!hit && should(name, args[0], args[2])) { hit = true; throw Error(`TEST interrupted ${boundary}`); }
    return originals[name](...args);
  };
  return { restore: () => { for (const name of methods) store[name] = originals[name]; }, hit: () => hit };
}

async function legacyHeadless(x, generation) {
  const vaultId = hex32(), txId = hex32();
  const definition = generation === "v1" ? { policyInput: x.policyFor(vaultId) } : x.v2For(vaultId);
  await claimSubmission(x.cfg, { txId, vaultId, action: generation === "v1" ? "createVault" : "createVaultV2" });
  let compiled, value;
  if (generation === "v1") {
    const { normalizePolicy, normalizeState } = require("../src/vault-state");
    const policy = normalizePolicy(definition.policyInput);value = policy.initValue;
    compiled = require("../src/contract-compiler").compileExactState({ config: x.cfg, policy, state: normalizeState({ protectedValue: value, periodStartDaa: policy.initPeriodStartDaa, periodSpent: "0", paused: "0" }) });
  } else {
    const { normalizeTemplateV2, normalizeStateV2 } = require("../src/vault-state-v2");
    const template = normalizeTemplateV2(definition.templateInput), state = normalizeStateV2(definition.initialStateInput); value = state.protectedValue;
    compiled = require("../src/contract-compiler-v2").compileExactStateV2({ config: x.cfg, template, state });
  }
  const address = require("../src/chain").covenantAddress(x.cfg, compiled.scriptBytes);
  x.rpc.seedVault(address, txId, 1, value, hex32());
  const args = { txId, ...definition, rpc: x.rpc };
  return { vaultId, txId, definition, args, recover: () => headless.recoverLegacyHeadlessClaim(x.cfg, args) };
}

test("RC36 v2 REQUEST: signed bytes and anchor are durable before broadcast; an accepted lost response recovers through the same request and attach replay without another signature or broadcast", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);
  const originalCreate = x.store.createExclusive.bind(x.store);let durableBeforeClaim = false;
  x.store.createExclusive = async (category, key, value) => {
    if (category === Categories.SUBMISSION_CLAIM) { const r = await q.load();assert.equal(r.txId, key);assert.ok(r.signedSafeJson);durableBeforeClaim = true; }
    return originalCreate(category, key, value);
  };
  await assert.rejects(q.attempt, (e) => e.code === "RECONCILIATION_REQUIRED");
  x.store.createExclusive = originalCreate;
  const retained = await q.load();assert.ok(durableBeforeClaim);assert.ok(q.durable());assert.equal(q.calls(), 1);
  const done = await q.wr2.attachWalletSignatureV2({ config: x.cfg, requestId: q.request.requestId, signedSafeJson: "not used in observation recovery" });
  assert.equal(done.state, "CHAIN_VERIFIED");assert.equal(done.requestId, retained.requestId);assert.equal(done.txId, retained.txId);assert.equal(done.signedSafeJson, retained.signedSafeJson);
  assert.equal((await q.recover()).state, "CHAIN_VERIFIED");assert.equal(q.calls(), 1);
  assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), null);
  assert.equal((await x.store.read(Categories.RECEIPT, retained.txId)).proof.requestId, retained.requestId);
});

test("RC36 v2 REQUEST: legacy missing signatures recover only from complete original transaction/definition and matching txid; malformed originals and another operation's claim stay untouched", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);await assert.rejects(q.attempt);
  const retained = await q.load();delete retained.signedSafeJson;await x.store.write(Categories.REQUEST, retained.requestId, retained);
  for (const change of [r => { delete r.transaction; }, r => { r.txId = hex32(); }, r => { r.template.owner = x.delegate.xonly; }, r => { r.initialState.protectedValue = "1"; }]) {
    const bad = structuredClone(retained);change(bad);await x.store.write(Categories.REQUEST, bad.requestId, bad);const before = JSON.stringify(await q.load());
    await assert.rejects(q.recover);assert.equal(JSON.stringify(await q.load()), before);assert.equal(await x.store.read(Categories.VAULT, retained.vaultId), null);
  }
  await x.store.write(Categories.REQUEST, retained.requestId, retained);
  const ownClaim = await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), foreign = { ...ownClaim, vaultId: hex32() };
  await x.store.write(Categories.SUBMISSION_CLAIM, retained.txId, foreign);await assert.rejects(q.recover, e => e.code === "CLAIM_CONFLICT");
  assert.deepEqual(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), foreign);assert.equal(await x.store.read(Categories.VAULT, retained.vaultId), null);
  await x.store.write(Categories.SUBMISSION_CLAIM, retained.txId, ownClaim);
  const done = await q.recover();assert.equal(done.state, "CHAIN_VERIFIED");assert.equal(done.signedSafeJson, undefined);assert.equal(done.transaction.unsignedSafeJson, retained.transaction.unsignedSafeJson);assert.equal(q.calls(), 1);
});

for (const boundary of ["VAULT", "RECEIPT", "AUDIT", "CLAIM_RELEASE", "REQUEST_FINAL"]) {
  test(`RC36 v2 REQUEST: observation completion retries after ${boundary} interruption without changing the genesis or overwriting records`, { skip: SKIP }, async (t) => {
    const x = setup(t), q = await prepareWalletGenesis(x);await assert.rejects(q.attempt);const retained = await q.load();
    const interrupted = interruptOnce(x.store, boundary);await assert.rejects(q.recover);interrupted.restore();assert.ok(interrupted.hit());
    const existing = await x.store.read(Categories.VAULT, retained.vaultId);const done = await q.recover();assert.equal(done.state, "CHAIN_VERIFIED");assert.equal(done.signedSafeJson, retained.signedSafeJson);assert.equal(done.txId, retained.txId);assert.equal(q.calls(), 1);
    if (existing) assert.deepEqual(await x.store.read(Categories.VAULT, retained.vaultId), existing);
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), null);assert.equal((await q.recover()).state, "CHAIN_VERIFIED");
  });
}

for (const generation of ["v1", "v2"]) for (const boundary of ["VAULT", "RECEIPT", "AUDIT", "CLAIM_RELEASE", "REQUEST_FINAL"]) {
  test(`RC36 legacy headless ${generation}: original-definition recovery resumes through both APIs after ${boundary} interruption with no fabricated signed bytes`, { skip: SKIP }, async (t) => {
    const x = setup(t), q = await legacyHeadless(x, generation);
    const interrupted = interruptOnce(x.store, boundary);await assert.rejects(q.recover);interrupted.restore();assert.ok(interrupted.hit());
    const records = await headless.listHeadlessCreations(x.cfg, { vaultId: q.vaultId });assert.equal(records.length, 1);const retained = records[0];assert.equal(retained.signedSafeJson, null);
    const existing = await x.store.read(Categories.VAULT, q.vaultId);
    const done = await headless.recoverHeadlessCreation(x.cfg, { requestId: retained.requestId, rpc: x.rpc });assert.equal(done.outcome, "CHAIN_VERIFIED");assert.equal(done.record.txId, q.txId);assert.equal(done.record.signedSafeJson, null);
    if (existing) assert.deepEqual(await x.store.read(Categories.VAULT, q.vaultId), existing);
    assert.equal((await q.recover()).outcome, "CHAIN_VERIFIED");assert.equal((await headless.listHeadlessCreations(x.cfg, { vaultId: q.vaultId })).length, 1);assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, q.txId), null);
  });
}

test("RC36 legacy headless: an interrupted record refuses a changed definition, missing original metadata and another operation's claim; uncertainty keeps its original reservation", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await legacyHeadless(x, "v1");const interrupted = interruptOnce(x.store, "VAULT");await assert.rejects(q.recover);interrupted.restore();
  const record = (await headless.listHeadlessCreations(x.cfg, { vaultId: q.vaultId }))[0], ownClaim = await x.store.read(Categories.SUBMISSION_CLAIM, q.txId);
  await assert.rejects(() => headless.recoverLegacyHeadlessClaim(x.cfg, { ...q.args, policyInput: { ...q.definition.policyInput, initValue: "1" } }), e => e.code === "DEFINITION_MISMATCH");
  await x.store.write(Categories.REQUEST, record.requestId, { ...record, definition: {} });await assert.rejects(() => headless.recoverHeadlessCreation(x.cfg, { requestId: record.requestId, rpc: x.rpc }));
  await x.store.write(Categories.REQUEST, record.requestId, record);const foreign = { ...ownClaim, action: "anotherOperation" };await x.store.write(Categories.SUBMISSION_CLAIM, q.txId, foreign);
  await assert.rejects(() => headless.recoverHeadlessCreation(x.cfg, { requestId: record.requestId, rpc: x.rpc }), e => e.code === "CLAIM_CONFLICT");assert.deepEqual(await x.store.read(Categories.SUBMISSION_CLAIM, q.txId), foreign);assert.equal(await x.store.read(Categories.VAULT, q.vaultId), null);
  await x.store.write(Categories.SUBMISSION_CLAIM, q.txId, ownClaim);x.rpc.clear(record.expected.address);assert.equal((await q.recover()).outcome, "PENDING");assert.deepEqual(await x.store.read(Categories.SUBMISSION_CLAIM, q.txId), ownClaim);
});

test("RC36 v2 REQUEST observation recovery never authorizes the legacy generation on mainnet", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);await assert.rejects(q.attempt);const before = JSON.stringify(await q.load());
  await assert.rejects(() => q.wr2.reconcileCreateWalletRequestV2({ config: { ...x.cfg, networkId: "mainnet", allowMainnet: true }, requestId: q.request.requestId, rpc: q.connection.rpc }), e => e.code === "GENERATION_NOT_MAINNET_AUTHORIZED");
  assert.equal(JSON.stringify(await q.load()), before);assert.equal(q.calls(), 1);
});

function recoverInFreshProcess(x, requestId, generation) {
  const data = JSON.stringify(x.cfg.dataRoot), sdk = JSON.stringify(path.resolve(__dirname, "../src"));
  return JSON.parse(execFileSync(process.execPath, ["-e", `
    const root=${sdk};const {loadConfig}=require(root+'/config');const {getStore,Categories}=require(root+'/store');
    (async()=>{const config=loadConfig({dataRoot:${data}});const request=await getStore(config).read(Categories.REQUEST,${JSON.stringify(requestId)});
      const e=${generation === "request" ? "{address:request.vaultAddress,index:request.vaultOutputIndex,value:request.initialState.protectedValue,covenantId:request.covenantId}" : "request.expected"};
      const rpc={getUtxosByAddresses:async({addresses})=>({entries:addresses.includes(e.address)?[{address:e.address,outpoint:{transactionId:request.txId,index:e.index},amount:e.value,covenantId:e.covenantId,scriptPublicKey:{version:0,script:''},blockDaaScore:'1',isCoinbase:false}]:[]}),submitTransaction:async()=>{throw Error('TEST recovery must never submit')}};
      const out=${generation === "request" ? "await require(root+'/wallet-requests-v2').reconcileCreateWalletRequestV2({config,requestId:request.requestId,rpc})" : "await require(root+'/headless-creation').recoverHeadlessCreation(config,{requestId:request.requestId,rpc})"};
      console.log(JSON.stringify({state:out.state??out.record.state,claim:!!await getStore(config).read(Categories.SUBMISSION_CLAIM,request.txId),manifest:!!await getStore(config).read(Categories.VAULT,request.vaultId)}));
    })().catch(e=>{console.error(e.stack);process.exit(1)});
  `], { encoding: "utf8" }).trim().split("\n").pop());
}

test("RC36 v2 REQUEST: a fresh process observes a retained legacy unsigned definition without signing or resubmitting", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);await assert.rejects(q.attempt);const retained = await q.load();delete retained.signedSafeJson;await x.store.write(Categories.REQUEST, retained.requestId, retained);
  assert.deepEqual(recoverInFreshProcess(x, retained.requestId, "request"), { state: "CHAIN_VERIFIED", claim: false, manifest: true });
  const after = await q.load();assert.equal(after.txId, retained.txId);assert.equal(after.signedSafeJson, undefined);assert.equal(after.transaction.unsignedSafeJson, retained.transaction.unsignedSafeJson);assert.equal(q.calls(), 1);
});

test("RC36 legacy headless: a fresh process finishes signatureless original-definition bookkeeping after interrupted final write and a repeated interruption", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await legacyHeadless(x, "v1");let interrupted = interruptOnce(x.store, "REQUEST_FINAL");await assert.rejects(q.recover);interrupted.restore();assert.ok(interrupted.hit());
  const retained = (await headless.listHeadlessCreations(x.cfg, { vaultId: q.vaultId }))[0];assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, q.txId), null);
  // Receipt bookkeeping must remain replayable even if its final request write is interrupted a second time.
  interrupted = interruptOnce(x.store, "REQUEST_FINAL");await assert.rejects(q.recover);interrupted.restore();assert.ok(interrupted.hit());
  assert.deepEqual(recoverInFreshProcess(x, retained.requestId, "headless"), { state: "CHAIN_VERIFIED", claim: false, manifest: true });
  assert.equal((await headless.loadHeadlessCreation(x.cfg, retained.requestId)).signedSafeJson, null);
});

test("RC36 v2 REQUEST: exact original receipt repairs retained genesis claim bookkeeping after its output is spent; a changed immutable owner is never accepted", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);await assert.rejects(q.attempt);await q.recover();const retained = await q.load();
  const original = await x.store.read(Categories.VAULT, retained.vaultId);x.rpc.clear(retained.vaultAddress);
  // Older v2 completion left the genesis submission claim behind despite a complete exact receipt.
  await claimSubmission(x.cfg, { txId: retained.txId, vaultId: retained.vaultId, action: "createVault" });
  assert.equal((await q.recover()).state, "CHAIN_VERIFIED");assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), null);assert.deepEqual(await x.store.read(Categories.VAULT, retained.vaultId), original);
  const foreign = structuredClone(original);foreign.template.owner = x.delegate.xonly;
  foreign.live.stateId = require("../src/vault-state-v2").computeStateIdV2({ networkId: x.cfg.networkId, template: foreign.template, state: foreign.live.state });
  await x.store.write(Categories.VAULT, retained.vaultId, foreign);await claimSubmission(x.cfg, { txId: retained.txId, vaultId: retained.vaultId, action: "createVault" });
  assert.equal((await q.recover()).state, "RECONCILIATION_REQUIRED");assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId));assert.deepEqual(await x.store.read(Categories.VAULT, retained.vaultId), foreign);assert.equal(q.calls(), 1);
});

test("RC36 v2 REQUEST: a proven negative is durable before an interrupted claim release and the same request retries only bookkeeping", { skip: SKIP }, async (t) => {
  const x = setup(t), q = await prepareWalletGenesis(x);let calls = 0;
  const baseRpc = { ...x.rpc, async submitTransaction({ transaction }) { calls++;throw Error(`Rejected transaction ${transaction.finalize().toString().toLowerCase()}: transaction is not standard: TEST policy rejection`); } };
  q.connection.rpc = require("./helpers/negative-proof-fixtures").negativeRpc(x.cfg, null, { baseRpc, captureAtSubmission: true }).rpc;
  const interrupted = interruptOnce(x.store, "CLAIM_RELEASE");await assert.rejects(q.attempt);interrupted.restore();assert.ok(interrupted.hit());
  const retained = await q.load();assert.equal(retained.state, "SUBMISSION_REJECTED");assert.ok(retained.submissionOutcome.proof);assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId));
  assert.equal((await q.recover()).state, "SUBMISSION_REJECTED");assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, retained.txId), null);assert.equal((await q.load()).signedSafeJson, retained.signedSafeJson);assert.equal(calls, 1);
});

test("RC36 headless: a proven negative is durable before interrupted claim release and observation retry releases only its own original claim", { skip: SKIP }, async (t) => {
  const x = setup(t), vaultId = hex32();let calls = 0;
  const baseRpc = { ...x.rpc, async submitTransaction({ transaction }) { calls++;throw Error(`Rejected transaction ${transaction.finalize().toString().toLowerCase()}: transaction is not standard: TEST policy rejection`); } };
  const rpc = require("./helpers/negative-proof-fixtures").negativeRpc(x.cfg, null, { baseRpc, captureAtSubmission: true }).rpc;
  const interrupted = interruptOnce(x.store, "CLAIM_RELEASE");await assert.rejects(() => x.drivers.v1(vaultId, { connection: { ...x.connection, rpc } }));interrupted.restore();assert.ok(interrupted.hit());
  const record = (await headless.listHeadlessCreations(x.cfg, { vaultId }))[0];assert.equal(record.state, "SUBMISSION_REJECTED");assert.ok(record.submissionOutcome.proof);assert.ok(await x.store.read(Categories.SUBMISSION_CLAIM, record.txId));
  const done = await headless.recoverHeadlessCreation(x.cfg, { requestId: record.requestId, rpc });assert.equal(done.outcome, "SUBMISSION_REJECTED");assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, record.txId), null);assert.equal(done.record.signedSafeJson, record.signedSafeJson);assert.equal(calls, 1);
});
