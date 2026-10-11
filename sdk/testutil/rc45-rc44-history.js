"use strict";
/*
 * RC45 test support: RC44-written record shapes from the pinned df5b8de
 * writers (plan rc45-simplified-plan-r2 §8 rules, CR-M13). Internal RED-first
 * regression material for the RC45 candidate; not an audit.
 *
 * The parent (a candidate test) never loads an RC44 module. It verifies the
 * read-only extraction named by POLICYVAULT_TEST_RC44_TREE against the plan's
 * five writer sha256 pins and the df5b8de sdk/src git tree (a missing or
 * mismatched tree FAILS, never skips), builds a test-local overlay that can
 * run those writers (byte copies of the RC44 sdk/src, core and contracts, the
 * pins re-verified on the copy, links to the remaining RC44 directories and
 * dependencies, links to this tree's pv_tx_probe / pv_call_encoder /
 * pv_vm_preflight because the extraction ships no VM binaries and its
 * modules resolve them tree-relatively), and runs THIS file as a child
 * process that loads ONLY the overlay's RC44 modules. The child writes a JSON
 * data root; the parent reads it through the candidate store.
 *
 * TEST keys only (deterministic dev signer); every config names
 * ws://127.0.0.1:1, so nothing can dial a node; no production data.
 */
const path = require("node:path"), fs = require("node:fs"), os = require("node:os"), crypto = require("node:crypto");
const assert = require("node:assert/strict");

const KAS = 100000000n, LOOPBACK = "ws://127.0.0.1:1";
const RESULT_TAG = "RC45-RC44-WRITER-RESULT ";
/* Plan r2 §8 (CR-M13): the df5b8de writer files and the df5b8de sdk/src tree. */
const RC44_WRITER_PINS = Object.freeze({
  "sdk/src/wallet-requests-v4.js": "267ea76b5f580cdf10495d83721b862748f416b7c5b1dea570047dd4d3178dfe",
  "sdk/src/wallet-submit-v4.js": "a2b98ccfa696d927a61e8fb4727ccd4988aad959ffcb3b0c994001b34099c0b6",
  "sdk/src/wallet-recovery-v4.js": "b4c18259d905e1785a29a882d5ca89c1f143d54d99240fd7064dd3e38537ac68",
  "sdk/src/reconcile-v4.js": "56b45432e0092196e645aa91518cdbf0c207d2c11fecb660feac5775ea1454e0",
  "sdk/src/store.js": "239b3c8418b63e4112385c9a8198ee821eac52432b6bdb9e8d8202e822b3f426"
});
const RC44_SDK_SRC_TREE = "af22dfb2238a7e271ffd65eea5dba3b773c9bd6c";
const VM_BIN = path.join(__dirname, "..", "..", "tests", "vm", "target", "debug");
const OWNED_PREFIX = "pv-rc45-";

const clone = (value) => JSON.parse(JSON.stringify(value));
const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
/* git tree id of a flat directory of regular 100644 files (the pinned df5b8de sdk/src tree has no subtree). */
function gitTreeOfFlatDir(dir) {
  const names = fs.readdirSync(dir).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const parts = [];
  for (const name of names) {
    const file = path.join(dir, name);
    assert.ok(fs.lstatSync(file).isFile(), `${file} must be a regular file`);
    const body = fs.readFileSync(file);
    parts.push(Buffer.from(`100644 ${name}\0`), crypto.createHash("sha1").update(Buffer.concat([Buffer.from(`blob ${body.length}\0`), body])).digest());
  }
  const content = Buffer.concat(parts);
  return crypto.createHash("sha1").update(Buffer.concat([Buffer.from(`tree ${content.length}\0`), content])).digest("hex");
}
function verifyRc44Tree(tree) {
  assert.ok(typeof tree === "string" && path.isAbsolute(tree), "POLICYVAULT_TEST_RC44_TREE must name the absolute df5b8de extraction (a missing tree is a FAIL, never a SKIP)");
  for (const [rel, pin] of Object.entries(RC44_WRITER_PINS)) assert.equal(sha256File(path.join(tree, rel)), pin, `RC44 writer ${rel} is not the pinned df5b8de byte sequence`);
  assert.equal(gitTreeOfFlatDir(path.join(tree, "sdk", "src")), RC44_SDK_SRC_TREE, "RC44 sdk/src is not the pinned df5b8de tree");
  assert.ok(fs.existsSync(path.join(tree, "sdk", "node_modules")), "the RC44 tree carries its exact offline dependencies");
}
function ownedTempRoot(prefix) {
  assert.ok(prefix.startsWith(OWNED_PREFIX), `temporary roots must be named ${OWNED_PREFIX}*`);
  return fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
}
/* A test-local copy of the df5b8de extraction that can run its writers. */
function rc44Overlay(tree, root) {
  fs.mkdirSync(path.join(root, "sdk"));
  for (const entry of fs.readdirSync(tree)) {
    if (entry === "sdk") continue;
    if (entry === "core" || entry === "contracts") fs.cpSync(path.join(tree, entry), path.join(root, entry), { recursive: true });
    else fs.symlinkSync(path.join(tree, entry), path.join(root, entry));
  }
  for (const entry of fs.readdirSync(path.join(tree, "sdk"))) {
    if (entry === "src") fs.cpSync(path.join(tree, "sdk", "src"), path.join(root, "sdk", "src"), { recursive: true });
    else fs.symlinkSync(path.join(tree, "sdk", entry), path.join(root, "sdk", entry));
  }
  fs.mkdirSync(path.join(root, "tests", "vm", "target", "debug"), { recursive: true });
  for (const bin of ["pv_tx_probe", "pv_call_encoder", "pv_vm_preflight"]) fs.symlinkSync(path.join(VM_BIN, bin), path.join(root, "tests", "vm", "target", "debug", bin));
  // The extraction is read-only; make the COPIED directories removable (links are never followed).
  (function writable(dir) {
    fs.chmodSync(dir, 0o755);
    for (const entry of fs.readdirSync(dir)) { const p = path.join(dir, entry); if (fs.lstatSync(p).isDirectory()) writable(p); }
  })(root);
  verifyRc44Tree(root);
  return root;
}
/* Remove a test-owned temporary root without ever following a link (the
 * overlay links into the read-only extraction and this tree's VM bins). */
function removeOwnedRoot(root) {
  const tmp = fs.realpathSync(os.tmpdir());
  assert.ok(typeof root === "string" && root.length > tmp.length + 1 && path.dirname(root) === tmp && path.basename(root).startsWith(OWNED_PREFIX), `refusing to remove ${root}`);
  (function remove(p) {
    const st = fs.lstatSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isDirectory()) { for (const entry of fs.readdirSync(p)) remove(path.join(p, entry)); fs.rmdirSync(p); }
    else fs.unlinkSync(p); // a regular file, or the link itself
  })(root);
}

function modulesOf(sdkSrc) {
  const r = (name) => require(path.join(sdkSrc, name));
  return { config: r("config.js"), store: r("store.js"), wr4: r("wallet-requests-v4.js"), submit4: r("wallet-submit-v4.js"), reconcile4: r("reconcile-v4.js"),
    manifest4: r("manifest-v4.js"), vs4: r("vault-state-v4.js"), compiler4: r("contract-compiler-v4.js"), agents: r("agent-merkle-v4.js"),
    recipients: r("recipient-merkle-v3.js"), signer: r("signer-dev.js"), claims: r("submission-claim.js"), budget: r("budget-reservation.js") };
}
function walletsFor(config) {
  const kaspa = require(config.rustyKaspaModule);
  const one = (byte) => {
    const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
    return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
  };
  return { owner: one(0x11), agent: one(0x21), recipient: one(0x31) };
}
/* One vault per history: its id, genesis outpoint L0, covenant id and owner fuel (all TEST values). */
function vault(tag) { const d = tag[1]; return Object.freeze({ tag, vaultId: tag.repeat(32), out: `b${d}`.repeat(32), cov: `c${d}`.repeat(32), fuel: `d${d}`.repeat(32) }); }
/* RC45 T4 vaults: candidate-written (ord, race, bg, bgc, twin) and RC44-written (fz, ag). */
const T4_VAULTS = Object.freeze({
  ord: vault("a1"), race: vault("a2"), bg: vault("a3"), bgc: vault("a4"), twin: vault("a5"), fz: vault("a6"), ag: vault("a7")
});
async function seedVault(m, config, v, w, label = "RC45 T4 TEST") {
  const entry = { agentPk: w.agent.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [w.recipient.xonly] };
  const template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policy = m.agents.normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: m.recipients.buildRecipientTree(entry.recipients).root });
  const state = m.vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `${label} ${v.tag}`, status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}
function kitFor(m, config, w) {
  const spend = (kas) => ({ payAmountSompi: (BigInt(kas) * KAS).toString(), agentPk: w.agent.xonly, recipient: w.recipient.xonly });
  const fuel = (v) => ({ outpoint: { transactionId: v.fuel, index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` });
  const build = (v, action, params, signer) => m.wr4.buildWalletRequestV4({ config, vaultId: v.vaultId, action, params, signerAddress: signer.address });
  const sign = (request, signer) => m.signer.makeDevSigner(config, { secretHex: signer.secretHex, expectedAddress: signer.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
  return {
    spend, fuel, sign,
    agentSpend: (v, kas) => build(v, "agentSpend", spend(kas), w.agent),
    ownerOp: (v, action, extra = {}) => build(v, action, { fuel: fuel(v), ...extra }, w.owner),
    finalize: (request, signer, signedSafeJson) => m.wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson: signedSafeJson ?? sign(request, signer) })
  };
}

/* The RC44 FINALIZED interruption of v4-recovery-legacy-lead5 :48-53, run
 * against the RC44 writer: the store write that persists FINALIZED completes,
 * then the process "crashes" (SYNTHETIC crash point: the interceptor throws
 * immediately after that durable write, so nothing later in RC44 finalize
 * runs — the same durable state as a kill right after the write). */
async function rc44FinalizeCrashAfterFinalized(m, config, request, signedSafeJson) {
  const store = m.store.getStore(config), write = store.write.bind(store); let hit = false;
  store.write = async (...args) => { const out = await write(...args); if (!hit && args[0] === m.store.Categories.REQUEST && args[2]?.state === "FINALIZED") { hit = true; throw Error("TEST crash after FINALIZED"); } return out; };
  try {
    await assert.rejects(m.wr4.finalizeWalletRequestV4({ config, requestId: request.requestId, signedSafeJson }), /TEST crash after FINALIZED/);
    assert.equal(hit, true, "the RC44 writer persisted FINALIZED before its claim");
  } finally { store.write = write; }
  return m.wr4.loadRequest(config, request.requestId);
}

/* ---------------------------------------------------------------------------
 * RC44 SCENARIOS (child process only; `m` is the RC44 overlay's modules).
 * ------------------------------------------------------------------------- */
const SCENARIOS = {
  /* RC45 T4: fz = an RC44 byte-less FINALIZED agent spend on the live L0 (no
   * claims, ACTIVE reservation); ag = an RC44 PREFLIGHT_VERIFIED agent spend on
   * the live L0 whose claims and reservation RC44 released by age (case C). */
  async t4(m, config) {
    const w = walletsFor(config), k = kitFor(m, config, w), hist = {};
    const pick = (r) => ({ requestId: r.requestId, txId: r.txId, state: r.state, action: r.action, predecessorOutpoint: r.predecessorOutpoint, covenantId: r.covenantId });
    { const v = T4_VAULTS.fz; await seedVault(m, config, v, w);
      const r = await k.agentSpend(v, 4); assert.equal(r.state, "BUILT");
      const f = await rc44FinalizeCrashAfterFinalized(m, config, r, k.sign(r, w.agent));
      assert.equal(f.state, "FINALIZED"); assert.equal(f.finalTransaction, undefined);
      hist.fz = { r: pick(f) };
    }
    { const v = T4_VAULTS.ag; await seedVault(m, config, v, w);
      const a = await k.finalize(await k.agentSpend(v, 4), w.agent); assert.equal(a.state, "PREFLIGHT_VERIFIED");
      // RC44 case C: live predecessor + effect absent + claim age >= minimum -> releases the claims and reservation.
      const kaspa = require(config.rustyKaspaModule), frozen = JSON.parse(a.build.frozenCanonicalJson), spk = frozen.inputs[0].utxo.scriptPublicKey;
      const address = kaspa.addressFromScriptPublicKey({ version: Number(spk.version), script: spk.scriptHex }, config.networkId).toString();
      const entry = { address, outpoint: clone(frozen.inputs[0].previousOutpoint), amount: String(frozen.inputs[0].utxo.amount), scriptPublicKey: { version: Number(spk.version), script: spk.scriptHex }, covenantId: a.covenantId, blockDaaScore: String(90_000_000n - 5000n), isCoinbase: false };
      const rpc = {
        async getUtxosByAddresses({ addresses }) { return { entries: addresses.includes(address) ? [clone(entry)] : [] }; },
        async getBlockDagInfo() { return { sink: "31".repeat(32), virtualDaaScore: "90000000" }; },
        async getMempoolEntry({ transactionId }) { throw new Error(`Transaction ${transactionId} not found`); },
        async getVirtualChainFromBlock() { throw new Error("TEST chain model: virtual-chain acceptance history is not modelled (unavailable)"); },
        async submitTransaction() { throw new Error("TEST chain model: the RC44 age release never submits"); },
        async disconnect() {}
      };
      const status = await m.reconcile4.reconcileVaultV4(config, v.vaultId, { rpc, stalePendingMinimumMs: 0 });
      assert.equal(status.status, "CLAIM_RELEASED"); assert.equal(status.claimTxId, a.txId);
      hist.ag = { a: pick(await m.wr4.loadRequest(config, a.requestId)) };
    }
    return { hist };
  },
  /* v4-recovery-legacy-lead5 :111-119 (plan r2 §8.1): the byte-less FINALIZED
   * of signedBase("policyvault-0.4.1", "agentSpend", interrupt) written by RC44. */
  async lead5Finalized(m, config) {
    const VAULT = "a8".repeat(32), version = "policyvault-0.4.1", w = walletsFor(config);
    const owner = w.owner, agent = w.agent, recipient = w.recipient;
    const entry = { agentPk: agent.xonly, maxPerSpend: (20n*KAS).toString(), periodBudget: (50n*KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n*KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [recipient.xonly] };
    const template = { owner: owner.xonly, vaultId: VAULT };
    const policy = m.agents.normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: m.recipients.buildRecipientTree(entry.recipients).root });
    const state = m.vs4.normalizeStateV4({ protectedValue: (1000n*KAS).toString(), feeReserve: (5n*KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4([policy]).root, approvers: [], approvalM: "0", policyNonce: "0" });
    const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion: version });
    await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion: version, networkId: config.networkId, vaultId: VAULT, label: "LEAD5 TEST", status: "ACTIVE", template, agentRegistry: [entry],
      live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: version }), outpoint: { transactionId: "42".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) }, creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null });
    const request = await m.wr4.buildWalletRequestV4({ config, vaultId: VAULT, action: "agentSpend", params: { payAmountSompi: (4n*KAS).toString(), agentPk: agent.xonly, recipient: recipient.xonly }, signerAddress: agent.address });
    const signed = m.signer.makeDevSigner(config, { secretHex: agent.secretHex, expectedAddress: agent.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs);
    const f = await rc44FinalizeCrashAfterFinalized(m, config, request, signed);
    return { requestId: f.requestId, txId: f.txId, state: f.state, signed };
  }
};

async function rc44Child(input) {
  verifyRc44Tree(input.tree);
  const m = modulesOf(path.join(input.tree, "sdk", "src"));
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const scenario = SCENARIOS[input.scenario];
  assert.equal(typeof scenario, "function", `unknown RC44 scenario ${input.scenario}`);
  return scenario(m, config);
}

/*
 * Parent side: verify POLICYVAULT_TEST_RC44_TREE, build the overlay, run one
 * scenario in a child that loads only the overlay's RC44 modules, and return
 * { dataRoot, overlay, result }. Both roots are test-owned (remove them with
 * removeOwnedRoot); `track` receives every root created.
 */
function runRc44Scenario(scenario, { tree = process.env.POLICYVAULT_TEST_RC44_TREE || "", track = () => {} } = {}) {
  verifyRc44Tree(tree);
  const dataRoot = ownedTempRoot(`${OWNED_PREFIX}rc44-data-`); track(dataRoot);
  const overlayRoot = ownedTempRoot(`${OWNED_PREFIX}rc44-overlay-`); track(overlayRoot);
  const overlay = rc44Overlay(tree, overlayRoot);
  const env = { ...process.env }; delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
  const child = require("node:child_process").spawnSync(process.execPath, [__filename, JSON.stringify({ tree: overlay, dataRoot, scenario })], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024, env });
  assert.equal(child.status, 0, `RC44 writer (${scenario}) failed: ${(child.stderr || "").slice(-4000)}`);
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
  assert.ok(line, `the RC44 writer (${scenario}) reported its result`);
  return { dataRoot, overlay, result: JSON.parse(line.slice(RESULT_TAG.length)) };
}

if (require.main === module) {
  rc44Child(JSON.parse(process.argv[2])).then(
    (result) => { process.stdout.write(`${RESULT_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = {
  KAS, LOOPBACK, RC44_WRITER_PINS, RC44_SDK_SRC_TREE, T4_VAULTS, OWNED_PREFIX,
  verifyRc44Tree, rc44Overlay, removeOwnedRoot, ownedTempRoot, modulesOf, walletsFor, vault, seedVault, kitFor, runRc44Scenario, clone
};
