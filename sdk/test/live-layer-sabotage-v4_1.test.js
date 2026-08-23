"use strict";

/*
 * SDK — H2 §35 LIVE-LAYER sabotage sensitivity (v0.4.1). For the version /
 * authority / integrity VALIDATION guards that are deterministically testable
 * offline, this NEUTRALIZES the guard IN THE PRODUCTION SOURCE (real string
 * mutation), busts the module cache, proves the protecting assertion turns RED,
 * then restores the file BYTE-IDENTICALLY (SHA re-checked). The remaining
 * submit/reconcile guards are proven load-bearing by the LIVE crash + reconcile
 * (docs/v041-crash-reconcile-live-evidence.json) and concurrency
 * (docs/v041-concurrency-live-evidence.json) matrices — see
 * docs/v041-live-layer-sabotage.md for the full 14/14 mapping.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SRC = path.join(__dirname, "..", "src");
const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function bustCache() {
  for (const k of Object.keys(require.cache)) {
    if (k.includes(`${path.sep}sdk${path.sep}src${path.sep}`)) delete require.cache[k];
  }
}

/*
 * Run `scenario` with `file` mutated (from -> to). Guarantees the file is
 * restored byte-identically even if the scenario throws. Returns nothing;
 * `scenario` does its own assertions against the sabotaged module.
 */
function withSabotage(file, from, to, scenario) {
  const abs = path.join(SRC, file);
  const original = fs.readFileSync(abs);
  const originalSha = sha(original);
  const text = original.toString("utf8");
  assert.ok(text.includes(from), `[${file}] sabotage anchor must be present: ${from}`);
  const mutated = text.replace(from, to);
  assert.notEqual(mutated, text, `[${file}] mutation must change the source`);
  try {
    fs.writeFileSync(abs, mutated);
    bustCache();
    scenario();
  } finally {
    fs.writeFileSync(abs, original);
    bustCache();
    assert.equal(sha(fs.readFileSync(abs)), originalSha, `[${file}] must be restored byte-identically`);
  }
}

// ---- Guard 13: selector / version dispatch (resolveV4Abi fails closed) ----
test("§35 G13 version dispatch: unknown version fails closed", () => {
  // Real guard: unknown version throws with no cross-version fallback.
  const { resolveV4Abi } = require("../src/vault-state-v4");
  assert.throws(() => resolveV4Abi("policyvault-9.9"), /no cross-version fallback/, "REAL guard must reject unknown version");
  // Neutralized: the fail-closed branch is bypassed -> unknown version resolves
  // to undefined (no longer fails closed). Protecting assertion turns red.
  withSabotage("vault-state-v4.js", "  if (!abi) {", "  if (!abi && false) {", () => {
    const { resolveV4Abi: sabotaged } = require("../src/vault-state-v4");
    const abi = sabotaged("policyvault-9.9");
    assert.equal(abi, undefined, "SABOTAGED resolveV4Abi no longer fails closed (guard was load-bearing)");
  });
});

// ---- Guard 8: definitive-rejection classification (conservative ambiguity) ----
test("§35 G8 rejection classification: transport errors stay AMBIGUOUS", () => {
  const { isDefinitiveSubmitRejection } = require("../src/wallet-submit-v4");
  // Real guard: a transport error is AMBIGUOUS (keeps claims); a node rejection
  // is DEFINITIVE.
  assert.equal(isDefinitiveSubmitRejection("WebSocket is not connected"), false, "REAL guard: transport error ambiguous");
  assert.equal(isDefinitiveSubmitRejection("Rejected transaction abc: too many sig ops"), true, "REAL guard: node rejection definitive");
  // Neutralized: classify EVERYTHING as definitive -> a transport error would be
  // treated as a definitive node rejection (unsafe: could release claims on a
  // still-pending tx). Protecting assertion turns red.
  withSabotage("wallet-submit-v4.js", 'return /\\bRejected transaction /i.test(String(message ?? ""));', "return true;", () => {
    const { isDefinitiveSubmitRejection: sabotaged } = require("../src/wallet-submit-v4");
    assert.equal(sabotaged("WebSocket is not connected"), true, "SABOTAGED classifier calls a transport error DEFINITIVE (guard was load-bearing)");
  });
});

// ---- Guard 1: contract-version predecessor derivation ----
test("§35 G1 version predecessor derivation: v0.4.1 state derives the v0.4.1 covenant", () => {
  const { loadConfig } = require("../src/config");
  const { successorAddressAndScript } = require("../src/wallet-submit-v4");
  const os = require("os");
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv41-sab-"));
  const config = loadConfig({ dataRoot });
  const kaspa = require(config.rustyKaspaModule);
  const XO = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32)).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const rroot = buildRecipientTree([XO(40)]).root;
  const agent = { agentPk: XO(30), maxPerSpend: "1000000000", periodBudget: "1000000000", periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: "100000000000", agentMaxFeePerTx: "100000000", agentRecipientRoot: rroot };
  const template = { owner: XO(1), vaultId: "22".repeat(32) };
  const state = { protectedValue: "2000000000", feeReserve: "500000000", paused: "0", agentRoot: buildAgentTreeV4([agent]).root, approverSlots: Array(10).fill("00".repeat(32)), approvalM: "0", policyNonce: "0" };
  // v0.4.1 derivation (16,980-byte covenant) vs v0.4 derivation (18,839) differ.
  const at41 = successorAddressAndScript(config, template, state, "policyvault-0.4.1");
  const at40 = successorAddressAndScript(config, template, state, "policyvault-0.4");
  assert.notEqual(at41.scriptSha256, at40.scriptSha256, "the two versions compile to different covenants");
  // Neutralized: force v0.4 regardless of the requested version -> a v0.4.1
  // vault's predecessor is derived at the WRONG (v0.4) address (the exact class
  // of bug the live gate caught in H2-C, line 170).
  withSabotage("wallet-submit-v4.js", "const compiled = compileExactStateV4({ config, template, state, contractVersion });", 'const compiled = compileExactStateV4({ config, template, state, contractVersion: "policyvault-0.4" });', () => {
    const { successorAddressAndScript: sabotaged } = require("../src/wallet-submit-v4");
    const bad = sabotaged(config, template, state, "policyvault-0.4.1");
    assert.equal(bad.scriptSha256, at40.scriptSha256, "SABOTAGED derivation ignores the version and yields the v0.4 address (guard was load-bearing)");
    assert.notEqual(bad.scriptSha256, at41.scriptSha256, "SABOTAGED derivation no longer matches the v0.4.1 covenant");
  });
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

// ---- Guard 5: registry-root equality (durable metadata must reproduce root) ----
test("§35 G5 registry-root equality: a manifest whose registry ≠ covenant agentRoot is refused", () => {
  const { CONTRACT_VERSION_V4_1, computeStateIdV4 } = require("../src/vault-state-v4");
  const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const kaspa = require(require("../src/config").loadConfig().rustyKaspaModule);
  const XO = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32)).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const networkId = "testnet-10";
  const rec = [XO(40)];
  const entry = { agentPk: XO(30), maxPerSpend: "1000000000", periodBudget: "1000000000", periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: "100000000000", agentMaxFeePerTx: "100000000", recipients: rec };
  const policy = { ...entry, agentRecipientRoot: buildRecipientTree(rec).root };
  const realRoot = buildAgentTreeV4([policy]).root;
  const template = { owner: XO(1), vaultId: "22".repeat(32) };
  // Manifest whose covenant agentRoot is a DIFFERENT value than the registry
  // reconstructs -> the local metadata cannot reproduce the on-chain tree.
  const state = { protectedValue: "2000000000", feeReserve: "500000000", paused: "0", agentRoot: "ff".repeat(32), approverSlots: Array(10).fill("00".repeat(32)), approvalM: "0", policyNonce: "0" };
  const stateId = computeStateIdV4({ networkId, template, state: normalizeForId(state), contractVersion: CONTRACT_VERSION_V4_1 });
  const badManifest = {
    schema: "policyvault-vault-manifest/v4", contractVersion: CONTRACT_VERSION_V4_1, networkId, template,
    status: "ACTIVE", agentRegistry: [entry],
    live: { state, stateId, outpoint: { transactionId: "11".repeat(32), index: 0 }, outpointValue: "2500000000", scriptSha256: "33".repeat(32), covenantId: "44".repeat(32) },
    creationTxId: "11".repeat(32), latestTransitionTxId: null, lastTransition: null
  };
  function normalizeForId(s) {
    // computeStateIdV4 wants BigInt fields + approvers[]; mirror stateToJson shape.
    return { protectedValue: BigInt(s.protectedValue), feeReserve: BigInt(s.feeReserve), paused: BigInt(s.paused), agentRoot: s.agentRoot, approvers: s.approverSlots, approvalM: BigInt(s.approvalM), policyNonce: BigInt(s.policyNonce) };
  }
  const { normalizeManifestV4 } = require("../src/manifest-v4");
  // Real guard: refuses to load a manifest whose registry can't reproduce the
  // covenant agentRoot.
  assert.throws(() => normalizeManifestV4(badManifest), /does not match the covenant agentRoot|REGISTRY_ROOT_MISMATCH/, "REAL guard rejects registry/root mismatch");
  void realRoot;
  // Neutralized: the equality check is bypassed -> a manifest whose registry
  // does NOT reproduce the covenant root loads anyway (the covenant identity is
  // no longer authoritative). Protecting assertion turns red.
  withSabotage("manifest-v4.js", "if (tree.root !== state.agentRoot) {", "if (false) {", () => {
    const { normalizeManifestV4: sabotaged } = require("../src/manifest-v4");
    const m = sabotaged(badManifest);
    assert.equal(m.agentRegistryRoot !== m.live.state.agentRoot, true, "SABOTAGED loader accepts a registry that does not reproduce the covenant root (guard was load-bearing)");
  });
});
