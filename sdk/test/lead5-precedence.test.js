"use strict";
/*
 * LEAD5-PRECEDENCE-01 — ordering of the LEAD-5 protected-transition guard.
 *
 * LEAD-5 (RC38; widened at lane checkpoint 6ff4539) refuses ANOTHER build /
 * finalize / reconcile-advance while a vault has an unresolved PROTECTED
 * transition (REQUEST_RECOVERY_REQUIRED). This suite pins WHERE that refusal
 * sits relative to the other read-only refusals:
 *   1. build: an unauthorized signer is refused on its own terms (403 NOT_AGENT
 *      / NOT_OWNER) and an unknown action fails closed (BUILD_FAILED) — neither
 *      learns that the vault has an unresolved transition; the authorized
 *      caller is still refused REQUEST_RECOVERY_REQUIRED; nothing is persisted;
 *   2. reconcile: the Gate-R network posture (operational network; manifest
 *      network == configured network) is refused BEFORE the protected-transition
 *      status is emitted — a foreign-network process never receives a recovery
 *      status for a vault it must not touch; on the matching network the
 *      protected status still takes priority and no node is contacted.
 * RED on the pre-correction bytes (guard first / status first), GREEN after.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const wr4 = require("../src/wallet-requests-v4");
const { reconcileVaultV4 } = require("../src/reconcile-v4");
const { makeDevSigner } = require("../src/signer-dev");
const { handle } = require("../../server/src/api");

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-lead5-prec-test-"));
const mainRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-lead5-prec-main-"));
const config = loadConfig({ dataRoot: testRoot });
function withEnv(pairs, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(pairs)) { saved[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
}
// Offline mainnet posture exactly as mainnet-gate-r.test.js: any node contact would fail on ws://127.0.0.1:1.
const mainnetConfig = withEnv({ POLICYVAULT_ALLOW_MAINNET: "true" }, () => loadConfig({ networkId: "mainnet", allowMainnet: true, rpcUrl: "ws://127.0.0.1:1", dataRoot: mainRoot }));
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const SEC = (v) => v.toString(16).padStart(2, "0").repeat(32);
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p, net = config.networkId) => p.toPublicKey().toAddress(net).toString();
const KAS = 100000000n;
const owner = KEY(1);
const agentA = KEY(0x1e);
const agentB = KEY(0x1f);
const recipient = KEY(0x28);
const other = KEY(0x29);
const unrelated = KEY(0x77);
// One FRESH vault per test (LEAD-5 protects a vault across tests otherwise).
let VAULT_ID = "6b".repeat(32);
let template = { owner: XO(owner), vaultId: VAULT_ID };
let vaultCounter = 0;
function rotateVault() {
  VAULT_ID = "6b".repeat(31) + (0x6b + vaultCounter).toString(16).padStart(2, "0");
  vaultCounter += 1;
  template = { owner: XO(owner), vaultId: VAULT_ID };
}
function agentEntry(kp, recipients) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  };
}
const REGISTRY = [agentEntry(agentA, [recipient, other]), agentEntry(agentB, [other])];
let seedCounter = 0;
async function seed(cfg) {
  rotateVault();
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config: cfg, template, state });
  const stateId = computeStateIdV4({ networkId: cfg.networkId, template, state });
  return await persistManifestV4(cfg, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: cfg.networkId, vaultId: VAULT_ID,
    label: "lead5-precedence", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const spendParams = (kp = agentA, to = recipient) => ({ payAmountSompi: (4n * KAS).toString(), agentPk: XO(kp), recipient: XO(to) });
const secretOf = (kp) => ({ [XO(owner)]: SEC(1), [XO(agentA)]: SEC(0x1e), [XO(agentB)]: SEC(0x1f), [XO(unrelated)]: SEC(0x77) })[XO(kp)];
const devSign = (req, kp) => makeDevSigner(config, { secretHex: secretOf(kp), expectedAddress: ADDR(kp) }).signInputs(req.transaction.unsignedSafeJson, req.transaction.signInputs);
const requestFiles = (root) => (fs.existsSync(path.join(root, "requests")) ? fs.readdirSync(path.join(root, "requests")).length : 0);
async function expectThrow(promise, status, code) {
  try { await promise; assert.fail("expected an API error"); } catch (e) {
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}
const POST = (cfg, segs, body) => handle(cfg, "POST", segs, {}, body);

/* Protect the testnet vault: build + finalize one request (PREFLIGHT_VERIFIED). */
async function protectTestnetVault() {
  await seed(config);
  const a = await wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(agentA) });
  const done = await wr4.finalizeWalletRequestV4({ config, requestId: a.requestId, signedSafeJson: devSign(a, agentA) });
  assert.equal(done.state, "PREFLIGHT_VERIFIED");
  return a;
}

test("LEAD-5 stands: with a PROTECTED transition the AUTHORIZED agent is refused REQUEST_RECOVERY_REQUIRED (SDK and HTTP), nothing persisted", async () => {
  await protectTestnetVault();
  const before = requestFiles(testRoot);
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(agentA) }), (e) => e.code === "REQUEST_RECOVERY_REQUIRED");
  await expectThrow(POST(config, ["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(agentA) }), 422, "REQUEST_RECOVERY_REQUIRED");
  assert.equal(requestFiles(testRoot), before, "a refused build persists nothing");
});

test("precedence: with a PROTECTED transition an UNAUTHORIZED signer is refused on its own terms (403 NOT_AGENT / NOT_OWNER), never told about the transition; nothing persisted", async () => {
  await protectTestnetVault();
  const before = requestFiles(testRoot);
  // SDK
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(owner) }), (e) => e.code === "NOT_AGENT" && !/unresolved transition/.test(e.message));
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(unrelated) }), (e) => e.code === "NOT_AGENT");
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(agentB, other), signerAddress: ADDR(agentA) }), (e) => e.code === "NOT_AGENT");
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "ownerPause", params: { fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agentA)}ac` } }, signerAddress: ADDR(agentA) }), (e) => e.code === "NOT_OWNER");
  // HTTP (authorization maps to 403; the transition state is not disclosed)
  await expectThrow(POST(config, ["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(owner) }), 403, "NOT_AGENT");
  await expectThrow(POST(config, ["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(unrelated) }), 403, "NOT_AGENT");
  await expectThrow(POST(config, ["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agentA)}ac` } }, signerAddress: ADDR(agentA) }), 403, "NOT_OWNER");
  assert.equal(requestFiles(testRoot), before, "unauthorized attempts persist nothing");
});

test("precedence: with a PROTECTED transition an UNKNOWN action still fails closed as BUILD_FAILED (no legacy fallback, no transition disclosure)", async () => {
  await protectTestnetVault();
  await assert.rejects(() => wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "delegateSpend", params: {}, signerAddress: ADDR(agentA) }), (e) => e.code === "BUILD_FAILED" && /unknown action/.test(e.message));
  await expectThrow(POST(config, ["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "delegateSpend", params: {}, signerAddress: ADDR(agentA) }), 422, "BUILD_FAILED");
});

/* Protect the mainnet-stamped vault WITHOUT a mainnet signer: build offline, then
 * label the durable request PREFLIGHT_VERIFIED exactly as a crash after
 * finalize would leave it (LEAD-5 protects the label, not the bytes). */
async function protectMainnetVault() {
  await seed(mainnetConfig);
  const a = await wr4.buildWalletRequestV4({ config: mainnetConfig, vaultId: VAULT_ID, action: "agentSpend", params: spendParams(), signerAddress: ADDR(agentA, "mainnet") });
  await wr4.saveRequest(mainnetConfig, { ...(await wr4.loadRequest(mainnetConfig, a.requestId)), state: "PREFLIGHT_VERIFIED" });
  return a;
}

test("precedence: reconcile refuses a FOREIGN-network manifest before emitting the protected-transition status", async () => {
  await protectMainnetVault();
  const foreign = loadConfig({ dataRoot: mainRoot }); // testnet-10 process pointed at the mainnet data root
  await assert.rejects(() => reconcileVaultV4(foreign, VAULT_ID), /manifest network mainnet != configured testnet-10/);
});

test("precedence: reconcile refuses a NON-OPERATIONAL network before emitting the protected-transition status", async () => {
  await protectMainnetVault();
  await assert.rejects(() => reconcileVaultV4({ ...mainnetConfig, allowMainnet: false }, VAULT_ID), /dual-flag unlock/);
  await assert.rejects(() => reconcileVaultV4({ ...mainnetConfig, networkId: "devnet" }, VAULT_ID), /not an operational/);
});

/* RC45 F5 (plan r2 §8.1 lead5-precedence :167-171, :169 dialled ws://127.0.0.1:1; §2.2 reorg rule "every Verify re-reads
 * the recorded outpoint first"): the Verify pass reads the node before it answers, so this control passes an explicit
 * chain model (the recorded outpoint live and deep, a virtualDaaScore; it never submits) instead of relying on "no node
 * contact". The protected record on the live outpoint still takes priority and nothing is written. */
test("control: on the MATCHING network the protected transition still takes priority; Verify reads the recorded outpoint through the explicit rpc and writes nothing (RC45 F5)", async () => {
  const a = await protectMainnetVault();
  const built = await wr4.loadRequest(mainnetConfig, a.requestId), input0 = JSON.parse(built.build.frozenCanonicalJson).inputs[0], spk = input0.utxo.scriptPublicKey;
  const address = kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, "mainnet").toString();
  const live = { address, outpoint: { ...input0.previousOutpoint }, amount: String(input0.utxo.amount), scriptPublicKey: { version: spk.version, script: spk.scriptHex }, covenantId: "41".repeat(32), blockDaaScore: String(90_000_000n - 5000n), isCoinbase: false };
  const calls = [];
  const rpc = {
    async getUtxosByAddresses({ addresses }) { calls.push("getUtxosByAddresses"); return { entries: addresses.includes(address) ? [JSON.parse(JSON.stringify(live))] : [] }; },
    async getBlockDagInfo() { calls.push("getBlockDagInfo"); return { sink: "31".repeat(32), virtualDaaScore: "90000000" }; },
    async getMempoolEntry({ transactionId }) { calls.push("getMempoolEntry"); throw new Error(`Transaction ${transactionId} not found`); },
    async getVirtualChainFromBlock() { calls.push("getVirtualChainFromBlock"); throw new Error("TEST chain model: acceptance history is not modelled (unavailable)"); },
    async submitTransaction() { calls.push("submitTransaction"); throw new Error("TEST chain model: Verify must never submit"); },
    async disconnect() { calls.push("disconnect"); }
  };
  const before = requestFiles(mainRoot);
  const r = await reconcileVaultV4(mainnetConfig, VAULT_ID, { rpc });
  assert.equal(r.status, "REQUEST_RECOVERY_REQUIRED");
  assert.equal(r.requestId, a.requestId);
  assert.ok(calls.includes("getUtxosByAddresses"), "Verify re-reads the recorded outpoint first (through the explicit rpc)");
  assert.equal(calls.includes("submitTransaction"), false);
  assert.equal(requestFiles(mainRoot), before, "nothing is written");
});
