"use strict";
/*
 * RC45 R1-01 test kit (remediation plan rc45-r1-plan-01 PLAN-R1 revision 2,
 * item R1-01 / review finding S-01; conditions C6, C7, K2, K3). Internal
 * RED-first regression material for the RC45 successor candidate; not an
 * audit.
 *
 * Used by sdk/test/rc45-r1-01-legacy-request-routes.test.js. It adds, on top
 * of the F5 kit (sdk/testutil/rc45-f5-kit.js: vaults, wallets, snapshots,
 * install) and the F3 kit (sdk/testutil/rc45-f3-kit.js: the hosted route
 * handler with TEST-key wallet sessions):
 *
 *   - buildV2Records: REAL v0.2 (policyvault-0.2) wallet requests, built by
 *     the candidate's own wallet-requests-v2 buildWalletRequestV2 (real v0.2
 *     compiler and pv_call_encoder, real fee computation) in a CHILD process
 *     whose chain.connectVerified is replaced, BEFORE wallet-requests-v2 is
 *     first loaded, by an EXPLICIT mocked chain model (the v0.2 live covenant
 *     UTXO at its real P2SH address and ordinary TEST fuel for the two
 *     signers). The child writes the v0.2 manifest and the two BUILT requests
 *     into the template's JSON root; the parent never loads the substituted
 *     module, so the hosted route under test keeps the real connectVerified.
 *   - nodeSentinel: replaces the WASM module's RpcClient (the only node
 *     client sdk/src/chain.js connectVerified constructs) by a recorder whose
 *     connect() refuses, for the duration of one call: "no node call" is
 *     "no RpcClient was constructed", and no node can ever be dialled.
 *   - eventRows: the durable platform event stream, for "nothing written".
 *
 * Nothing dials a node: every config names ws://127.0.0.1:1, the sentinel
 * refuses every connect, and the v0.2 builds see only the explicit model.
 * TEST keys only (0x11 owner, 0x21 agent / v0.2 delegate, 0x31 recipient).
 */
const path = require("node:path"), cp = require("node:child_process");
const assert = require("node:assert/strict");
const K = require("./rc45-f5-kit");

const CHILD_MODE = "rc45-r1-v2-build-child", CHILD_TAG = "RC45-R1-V2-BUILD-RESULT ";
const SDK_SRC = path.join(__dirname, "..", "src");
const V2_REQUEST_SCHEMA = "policyvault-wallet-request/v2";

/* ---------------- REAL v0.2 records, built in a child against an explicit chain model ---------------- */
async function v2BuildChild(input) {
  const r = (name) => path.join(SDK_SRC, name);
  const wr2Path = require.resolve(r("wallet-requests-v2.js"));
  const { loadConfig } = require(r("config.js"));
  const config = loadConfig({ dataRoot: input.dataRoot, rpcUrl: K.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const kaspa = require(config.rustyKaspaModule);
  const chain = require(r("chain.js"));
  const V2 = require(r("vault-state-v2.js"));
  const { compileExactStateV2 } = require(r("contract-compiler-v2.js"));
  const { persistManifestV2, MANIFEST_SCHEMA_V2 } = require(r("manifest-v2.js"));
  const wallets = K.walletsFor(config), owner = wallets.owner, delegate = wallets.agent;
  const KAS = K.KAS;
  const template = V2.normalizeTemplateV2({ owner: owner.xonly, vaultId: input.vaultId });
  const state = V2.normalizeStateV2({ protectedValue: (195n * KAS).toString(), periodStartDaa: "545127882", periodSpent: (5n * KAS).toString(), paused: "0", delegate: delegate.xonly,
    maxPerSpend: (10n * KAS).toString(), periodBudget: (100n * KAS).toString(), periodLengthDaa: "600", recipients: [wallets.recipient.xonly], delegateActive: "1", policyNonce: "0" });
  const compiled = compileExactStateV2({ config, template, state });
  const covenantAddress = chain.covenantAddress(config, compiled.scriptBytes);
  const liveOutpoint = { transactionId: input.liveTxId, index: 0 };
  await persistManifestV2(config, { schema: MANIFEST_SCHEMA_V2, contractVersion: V2.CONTRACT_VERSION_V2, networkId: config.networkId, vaultId: template.vaultId, label: "RC45 R1-01 TEST v0.2", status: "ACTIVE", template,
    live: { state, stateId: V2.computeStateIdV2({ networkId: config.networkId, template, state }), outpoint: liveOutpoint, outpointValue: state.protectedValue.toString(), scriptSha256: compiled.scriptSha256, covenantId: input.covenantId },
    creationTxId: input.liveTxId, latestTransitionTxId: null, lastTransition: null });
  /* THE EXPLICIT CHAIN MODEL (TEST): the live covenant UTXO at its real P2SH address, ordinary fuel for each signer. */
  const p2sh = kaspa.payToScriptHashScript(Buffer.from(compiled.scriptBytes).toString("hex"));
  const entries = [
    { address: covenantAddress, outpoint: liveOutpoint, amount: state.protectedValue, scriptPublicKey: { version: Number(p2sh.version), script: String(p2sh.script) }, blockDaaScore: 545127000n, isCoinbase: false, covenantId: input.covenantId },
    { address: owner.address, outpoint: { transactionId: input.ownerFuelTxId, index: 0 }, amount: 100n * KAS, scriptPublicKey: { version: 0, script: `20${owner.xonly}ac` }, blockDaaScore: 545127000n, isCoinbase: false },
    { address: delegate.address, outpoint: { transactionId: input.delegateFuelTxId, index: 0 }, amount: 100n * KAS, scriptPublicKey: { version: 0, script: `20${delegate.xonly}ac` }, blockDaaScore: 545127000n, isCoinbase: false }
  ];
  const reads = [];
  const rpc = {
    async getUtxosByAddresses({ addresses }) { reads.push(addresses.map(String)); const want = new Set(addresses.map(String)); return { entries: entries.filter((e) => want.has(e.address)).map((e) => ({ ...e, outpoint: { ...e.outpoint }, scriptPublicKey: { ...e.scriptPublicKey } })) }; },
    async disconnect() {}
  };
  assert.equal(require.cache[wr2Path], undefined, "wallet-requests-v2 was not loaded before the explicit chain model was bound");
  chain.connectVerified = async () => ({ rpc, kaspa, serverInfo: { networkId: config.networkId, isSynced: true, hasUtxoIndex: true } });
  const wr2 = require(wr2Path);
  const pause = await wr2.buildWalletRequestV2({ config, vaultId: template.vaultId, action: "ownerPause", params: {}, signerAddress: owner.address });
  await K.sleep(3);
  const spend = await wr2.buildWalletRequestV2({ config, vaultId: template.vaultId, action: "delegateSpend", params: { payAmountSompi: (2n * KAS).toString(), recipientIndex: 1 }, signerAddress: delegate.address });
  for (const q of [pause, spend]) {
    assert.equal(q.schema, V2_REQUEST_SCHEMA);
    assert.equal(q.state, "BUILT");
  }
  return { vaultId: template.vaultId, pause: pause.requestId, spend: spend.requestId, reads: reads.length };
}
/* Build the two REAL v0.2 records into `template` (a JSON-backed config) in a fresh child process. */
function buildV2Records(template, tag) {
  const input = { dataRoot: template.dataRoot, vaultId: K.hex(`rc45-r1-v2-${tag}-vault`), liveTxId: K.hex(`rc45-r1-v2-${tag}-live`), covenantId: K.hex(`rc45-r1-v2-${tag}-covenant`),
    ownerFuelTxId: K.hex(`rc45-r1-v2-${tag}-owner-fuel`), delegateFuelTxId: K.hex(`rc45-r1-v2-${tag}-delegate-fuel`) };
  const child = cp.spawnSync(process.execPath, [__filename, CHILD_MODE, JSON.stringify(input)], { encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env } });
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(CHILD_TAG));
  assert.ok(line && child.status === 0, `RC45 R1-01 v0.2 build child failed (status ${child.status}, signal ${child.signal}): ${(child.stderr || "").slice(-4000)}`);
  return JSON.parse(line.slice(CHILD_TAG.length));
}

/* ---------------- the node sentinel ---------------- */
function nodeSentinel(config) {
  const kaspa = require(config.rustyKaspaModule);
  const real = kaspa.RpcClient, constructed = [];
  class SentinelRpcClient {
    constructor(options) { constructed.push({ url: options && options.url }); }
    async connect() { throw new Error("TEST node sentinel: node contact refused (R1-01; no node is ever dialled)"); }
    async disconnect() {}
  }
  kaspa.RpcClient = SentinelRpcClient;
  assert.equal(kaspa.RpcClient, SentinelRpcClient, "the node sentinel is installed");
  return { constructed, restore() { kaspa.RpcClient = real; } };
}
/* Run `fn` with the sentinel installed; returns { value, nodeCalls }. */
async function withNodeSentinel(config, fn) {
  const s = nodeSentinel(config);
  try { return { value: await fn(), nodeCalls: s.constructed.length }; } finally { s.restore(); }
}

/* The durable platform event stream (every type), for "nothing written". */
async function eventRows(config) {
  const { getEventsStore } = require("../../server/src/events-store");
  return (await getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 })).map((row) => row.event);
}

if (require.main === module && process.argv[2] === CHILD_MODE) {
  v2BuildChild(JSON.parse(process.argv[3])).then(
    (result) => { process.stdout.write(`${CHILD_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = { V2_REQUEST_SCHEMA, buildV2Records, nodeSentinel, withNodeSentinel, eventRows };
