"use strict";
/*
 * RC45 R2 test support: records written by the pinned RC44 (df5b8de) writers
 * for the delegate period-start legs. Internal RED-first regression material;
 * not an audit.
 *
 * RC44 commits a delegate's period start exactly as requested (a "0", a stale
 * snapshot or an inherited start) and never re-checks it before signing or
 * broadcasting. The R2 suites need such records exactly as RC44 wrote them:
 *   - proposal: a governance proposal (the vault-owner act of POST
 *     /governance/proposals) for an addAgent whose new delegate starts at 0,
 *     written by RC44's server/src/governance.js createProposal;
 *   - records: on three vaults, an addAgent whose new delegate starts at 0 left
 *     BUILT, the same addAgent finalized by RC44 (PREFLIGHT_VERIFIED with its
 *     transition and submission claims), and a v0.4.1 genesis whose delegate
 *     starts at 0 left BUILT.
 *
 * The parent (a candidate test) never loads an RC44 module. It verifies the
 * read-only extraction named by POLICYVAULT_TEST_RC44_TREE (the five writer
 * sha256 pins and the df5b8de sdk/src git tree of rc45-rc44-history.js, plus
 * the df5b8de server/src/governance.js pin below; a missing or mismatched
 * tree FAILS, never skips), builds a test-local overlay (byte copies of the
 * RC44 sdk/src, server, core and contracts, links to the remaining RC44
 * directories and dependencies and to this tree's pv_* VM binaries) and runs
 * THIS file as a child process that loads ONLY the overlay's RC44 modules and
 * writes a JSON data root. The parent reads it through the candidate store.
 *
 * TEST keys only (deterministic dev signer); every config names
 * ws://127.0.0.1:1, so nothing can dial a node; no production data.
 */
const path = require("node:path"), fs = require("node:fs"), crypto = require("node:crypto");
const assert = require("node:assert/strict");
const H44 = require("./rc45-rc44-history");

const RESULT_TAG = "RC45-R2-RC44-WRITER-RESULT ";
const RC44_GOVERNANCE_SHA256 = "3bc5863df253cc39aa948aa32d4b1cebbf7a384052eac709d68aedba65eaec2e"; // df5b8de server/src/governance.js
const VM_BIN = path.join(__dirname, "..", "..", "tests", "vm", "target", "debug");
const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

/* The rc45-rc44-history overlay, with server/ copied too (so the RC44 governance writer and the RC44 sdk modules it
 * requires are one module set). */
function overlayWithServer(tree, root) {
  fs.mkdirSync(path.join(root, "sdk"));
  for (const entry of fs.readdirSync(tree)) {
    if (entry === "sdk") continue;
    if (["core", "contracts", "server"].includes(entry)) fs.cpSync(path.join(tree, entry), path.join(root, entry), { recursive: true });
    else fs.symlinkSync(path.join(tree, entry), path.join(root, entry));
  }
  for (const entry of fs.readdirSync(path.join(tree, "sdk"))) {
    if (entry === "src") fs.cpSync(path.join(tree, "sdk", "src"), path.join(root, "sdk", "src"), { recursive: true });
    else fs.symlinkSync(path.join(tree, "sdk", entry), path.join(root, "sdk", entry));
  }
  fs.mkdirSync(path.join(root, "tests", "vm", "target", "debug"), { recursive: true });
  for (const bin of ["pv_tx_probe", "pv_call_encoder", "pv_vm_preflight"]) fs.symlinkSync(path.join(VM_BIN, bin), path.join(root, "tests", "vm", "target", "debug", bin));
  (function writable(dir) {
    fs.chmodSync(dir, 0o755);
    for (const entry of fs.readdirSync(dir)) { const p = path.join(dir, entry); if (fs.lstatSync(p).isDirectory()) writable(p); }
  })(root);
  H44.verifyRc44Tree(root);
  assert.equal(sha256File(path.join(root, "server", "src", "governance.js")), RC44_GOVERNANCE_SHA256, "RC44 server/src/governance.js is not the pinned df5b8de byte sequence");
  return root;
}

/* ---------------- child side (RC44 modules only) ---------------- */
async function seedVault(m, config, { vaultId, out, cov, owner, registry, label }) {
  const template = { owner, vaultId };
  const policies = registry.map((e) => m.agents.normalizeAgentPolicyV4({ ...e, agentRecipientRoot: m.recipients.buildRecipientTree(e.recipients).root }));
  const state = m.vs4.normalizeStateV4({ protectedValue: (1000n * H44.KAS).toString(), feeReserve: (5n * H44.KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId, label, status: "ACTIVE", template, agentRegistry: registry,
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: cov },
    creationTxId: out, latestTransitionTxId: null, lastTransition: null });
}
const SCENARIOS = {
  /* An RC44 addAgent proposal (new delegate start "0") on the base vault, written by RC44's createProposal. */
  async proposal(m, config, input, overlay) {
    await seedVault(m, config, input.base);
    const governance = require(path.join(overlay, "server", "src", "governance.js"));
    const manifest = await m.manifest4.loadManifestV4(config, input.base.vaultId);
    const record = await governance.createProposal({ config, manifest, vaultId: input.base.vaultId, action: "addAgent", params: input.params, proposedByXOnly: input.base.owner });
    assert.equal(record.status, "OPEN");
    return { record };
  },
  /* RC44-written BUILT and PREFLIGHT_VERIFIED addAgent requests (new delegate start "0") and a BUILT genesis (start "0"). */
  async records(m, config, input) {
    const w = H44.walletsFor(config);
    const owner = w.owner;
    assert.equal(owner.xonly, input.built.owner, "the RC44 TEST owner key (0x11) matches the parent's");
    const fuel = (v) => ({ outpoint: { transactionId: v.fuel, index: 1 }, amount: (100n * H44.KAS).toString(), scriptPublicKeyHex: `20${input.built.owner}ac` });
    const out = {};
    await seedVault(m, config, input.built);
    const built = await m.wr4.buildWalletRequestV4({ config, vaultId: input.built.vaultId, action: "addAgent", params: { fuel: fuel(input.built), agent: input.agent }, signerAddress: owner.address });
    assert.equal(built.state, "BUILT");
    out.built = { requestId: built.requestId, txId: built.txId };
    await seedVault(m, config, input.signed);
    const toSign = await m.wr4.buildWalletRequestV4({ config, vaultId: input.signed.vaultId, action: "addAgent", params: { fuel: fuel(input.signed), agent: input.agent }, signerAddress: owner.address });
    const signedSafeJson = m.signer.makeDevSigner(config, { secretHex: owner.secretHex, expectedAddress: owner.address }).signInputs(toSign.transaction.unsignedSafeJson, toSign.transaction.signInputs);
    const signed = await m.wr4.finalizeWalletRequestV4({ config, requestId: toSign.requestId, signedSafeJson });
    assert.equal(signed.state, "PREFLIGHT_VERIFIED");
    out.signed = { requestId: signed.requestId, txId: signed.txId };
    const genesis = await m.wr4.buildCreateWalletRequestV4({ config, contractVersion: m.vs4.CONTRACT_VERSION_V4_1, templateInput: { owner: input.built.owner, vaultId: input.genesis.vaultId },
      initialAgents: [input.agent], initialState: { protectedValue: (1000n * H44.KAS).toString(), feeReserve: (5n * H44.KAS).toString(), approvers: [], approvalM: "0" },
      signerAddress: owner.address, funding: [input.genesis.funding], label: "RC45 R2 TEST rc44 genesis" });
    assert.equal(genesis.state, "BUILT");
    out.genesis = { requestId: genesis.requestId, txId: genesis.txId };
    return out;
  }
};
async function child(input) {
  H44.verifyRc44Tree(input.overlay);
  const m = H44.modulesOf(path.join(input.overlay, "sdk", "src"));
  const config = m.config.loadConfig({ dataRoot: input.dataRoot, rpcUrl: H44.LOOPBACK });
  assert.equal(config.networkId, "testnet-10");
  const scenario = SCENARIOS[input.scenario];
  assert.equal(typeof scenario, "function", `unknown RC44 scenario ${input.scenario}`);
  return scenario(m, config, input.input, input.overlay);
}

/* ---------------- parent side ---------------- */
/* Run one scenario in a child that loads only the overlay's RC44 modules; returns { dataRoot, result }. */
function runRc44R2(scenario, input, { tree = process.env.POLICYVAULT_TEST_RC44_TREE || "", track = () => {} } = {}) {
  H44.verifyRc44Tree(tree);
  const dataRoot = H44.ownedTempRoot(`${H44.OWNED_PREFIX}r2-rc44-data-`); track(dataRoot);
  const overlayRoot = H44.ownedTempRoot(`${H44.OWNED_PREFIX}r2-rc44-overlay-`); track(overlayRoot);
  const overlay = overlayWithServer(tree, overlayRoot);
  const env = { ...process.env }; delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
  const payload = JSON.stringify({ overlay, dataRoot, scenario, input });
  const r = require("node:child_process").spawnSync(process.execPath, [__filename, payload], { encoding: "utf8", timeout: 600000, maxBuffer: 64 * 1024 * 1024, env });
  assert.equal(r.status, 0, `RC44 writer (${scenario}) failed: ${(r.stderr || "").slice(-4000)}`);
  const line = (r.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
  assert.ok(line, `the RC44 writer (${scenario}) reported its result`);
  return { dataRoot, result: JSON.parse(line.slice(RESULT_TAG.length)) };
}

if (require.main === module) {
  child(JSON.parse(process.argv[2])).then(
    (result) => { process.stdout.write(`${RESULT_TAG}${JSON.stringify(result)}\n`); },
    (error) => { process.stderr.write(`${error && error.stack ? error.stack : error}\n`); process.exitCode = 1; }
  );
}

module.exports = { RC44_GOVERNANCE_SHA256, runRc44R2 };
