"use strict";

/*
 * BRIDGE — REAL BUILDER integration (UNIT/INTEGRATION).
 *
 * Drives the ACTUAL sdk/src/vault-builders-v4.js builders (real silverc
 * compiles + the real pv_call_encoder + real pv_tx_probe + kaspa-wasm,
 * fully OFFLINE) to construct genuine v0.4 transactions, feeds each build
 * through core/intent/bridge, and asserts:
 *   (a) faithful derivation of a real build -> VERIFIED_EXACT;
 *   (b) tampered variants -> the correct fail-closed detector code;
 *   (c) G-2-class storage-representation stability of the derived manifest.
 *
 * The compiled Rust toolchain is a build artifact (gitignored) that is NOT
 * present in an isolated git worktree. The test resolves an sdk base that
 * HAS the toolchain (the worktree first, then the main checkout — sdk/src
 * is byte-identical between them, verified); if none is found every case
 * SKIPS with a message rather than failing. TEST KEYS ONLY (byte-repeated).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { deriveManifestFromV4Build, deriveRequestedIntent, deriveAndVerify } = require("../derive");
const { computeManifestHashV1 } = require("../../canonical");
const { VERDICTS } = require("../../verify");

/* ---- locate an sdk base whose compiled toolchain binaries exist ---- */
const WORKTREE_SDK = path.resolve(__dirname, "../../../../sdk");
const MAIN_SDK = path.join(os.homedir(), "policyvault", "sdk");
function hasToolchain(base) {
  return (
    fs.existsSync(path.join(base, "..", "tests/vm/target/debug/pv_call_encoder")) &&
    fs.existsSync(path.join(base, "..", "tests/vm/target/debug/pv_tx_probe"))
  );
}
const SDK_BASE = [WORKTREE_SDK, MAIN_SDK].find(hasToolchain) || null;
const SKIP = SDK_BASE === null;
const skipMsg = "no compiled sdk toolchain (pv_call_encoder/pv_tx_probe) found — real-builder cases skipped (offline gap; see core-v1-falsification-review.md)";

/* Build every real transaction ONCE (each ~seconds); reuse across cases. */
let FX = null;
if (!SKIP) {
  const { loadConfig } = require(path.join(SDK_BASE, "src/config"));
  const { buildAgentTreeV4 } = require(path.join(SDK_BASE, "src/agent-merkle-v4"));
  const { buildRecipientTree } = require(path.join(SDK_BASE, "src/recipient-merkle-v3"));
  const { buildV4Transaction, buildCreateV4, createApprovalPackageForBuildV4 } = require(path.join(SDK_BASE, "src/vault-builders-v4"));

  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-bridge-real-"));
  const config = loadConfig({ dataRoot });
  const kaspa = require(config.rustyKaspaModule);
  const KAS = 100000000n;
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

  const owner = KEY(1);
  const agentA = KEY(0x1e);
  const fuelKey = KEY(3);
  const recipient = KEY(0x28);
  const otherRecipient = KEY(0x29);
  const approvers3 = [KEY(20), KEY(21), KEY(22)];

  const rTree = buildRecipientTree([XO(recipient), XO(otherRecipient)]);
  const policyA = (over = {}) => ({
    agentPk: XO(agentA), maxPerSpend: "20000000000", periodBudget: "50000000000",
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: "5000000000", agentMaxFeePerTx: "100000000", agentRecipientRoot: rTree.root, ...over
  });
  const agents = [policyA()];
  const aTree = buildAgentTreeV4(agents);
  const template = { owner: XO(owner), vaultId: "22".repeat(32) };
  const st = (over = {}) => ({
    protectedValue: "1000000000000", feeReserve: "500000000", paused: "0",
    agentRoot: aTree.root, approvers: [], approvalM: "0", policyNonce: "0", ...over
  });
  const chain = (fuel) => {
    const c = { predecessorOutpoint: { transactionId: "42".repeat(32), index: 0 }, predecessorValue: "1000500000000", covenantId: "41".repeat(32) };
    if (fuel) c.fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
    return c;
  };
  const commonSpendParams = { agentPk: XO(agentA), agents, recipient: XO(recipient), recipients: [XO(recipient), XO(otherRecipient)] };

  /* Production request path sets changeXOnly = signerXOnly (the agent for
   * an agent spend) — sdk/src/wallet-requests-v4.js:415. Fee change returns
   * to the signer, which the manifest's change→signer rule mirrors. (The
   * agent signs the covenant input; the reserve-funded case omits fuel.) */
  const spendReserve = buildV4Transaction({ config, templateInput: template, stateInput: st(), action: "agentSpend", params: { payAmountSompi: (40n * KAS).toString(), ...commonSpendParams }, chain: chain(false), changeXOnly: XO(agentA) });
  const spendFuel = buildV4Transaction({ config, templateInput: template, stateInput: st(), action: "agentSpend", params: { payAmountSompi: (40n * KAS).toString(), ...commonSpendParams }, chain: chain(true), changeXOnly: XO(agentA) });
  const stApprovers = st({ approvers: approvers3.map(XO), approvalM: "2" });
  const spendAbove = buildV4Transaction({ config, templateInput: template, stateInput: stApprovers, action: "agentSpend", params: { payAmountSompi: (60n * KAS).toString(), ...commonSpendParams }, chain: chain(true), changeXOnly: XO(agentA) });
  const rollover = buildV4Transaction({ config, templateInput: template, stateInput: st({ agentRoot: buildAgentTreeV4([policyA({ periodSpent: (49900n * 1000000n).toString() })]).root }), action: "agentSpend", params: { payAmountSompi: (40n * KAS).toString(), agentPk: XO(agentA), agents: [policyA({ periodSpent: (49900n * 1000000n).toString() })], recipient: XO(recipient), recipients: [XO(recipient), XO(otherRecipient)], periodsElapsed: "1" }, chain: chain(false), changeXOnly: XO(owner) });
  const setRoot = buildV4Transaction({ config, templateInput: template, stateInput: stApprovers, action: "ownerSetAgentRoot", params: { newAgentRoot: "cd".repeat(32) }, chain: chain(true), changeXOnly: XO(owner) });
  const topUp = buildV4Transaction({ config, templateInput: template, stateInput: st(), action: "ownerTopUp", params: { topUpAmountSompi: (10n * KAS).toString() }, chain: chain(true), changeXOnly: XO(owner) });
  const pause = buildV4Transaction({ config, templateInput: template, stateInput: st(), action: "ownerPause", params: {}, chain: chain(true), changeXOnly: XO(owner) });
  const recover = buildV4Transaction({ config, templateInput: template, stateInput: st(), action: "ownerRecover", params: {}, chain: chain(true), changeXOnly: XO(owner) });
  const genesis = buildCreateV4({ config, templateInput: template, initialStateInput: st(), funding: [{ outpoint: { transactionId: "45".repeat(32), index: 0 }, amount: (20000n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` }], changeXOnly: XO(owner) });

  FX = { spendReserve, spendFuel, spendAbove, rollover, setRoot, topUp, pause, recover, genesis, ATTACKER: XO(KEY(0x99)), dataRoot };
  fs.rmSync(dataRoot, { recursive: true, force: true });
}

/* rehash a tampered manifest body (models an author who controls the hash
 * field — the hash proves integrity, the detectors prove honesty). */
function rehash(m) {
  const body = { ...m };
  delete body.manifestHash;
  return { ...body, manifestHash: computeManifestHashV1(body) };
}
const clone = (v) => JSON.parse(JSON.stringify(v));

function assertFullPass(build, label, extra = {}) {
  const requestedIntent = deriveRequestedIntent(build, { maxFeeSompi: null });
  const decodedTransaction = clone(JSON.parse(build.frozenCanonicalJson));
  decodedTransaction.txId = build.txId;
  const { manifest, verification } = deriveAndVerify({ build, requestedIntent, decodedTransaction, ...extra });
  assert.equal(verification.verdict, VERDICTS.VERIFIED_EXACT, `${label}: ${JSON.stringify(verification.failures)}`);
  assert.equal(verification.statement, "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.");
  return manifest;
}

test("faithful derivation of every REAL builder output verifies EXACT", { skip: SKIP && skipMsg }, () => {
  assertFullPass(FX.spendReserve, "agentSpend reserve-funded");
  assertFullPass(FX.spendFuel, "agentSpend fuel-funded (change output)");
  assertFullPass(FX.spendAbove, "agentSpend above-threshold");
  assertFullPass(FX.rollover, "agentSpend rollover (CLTV lockTime)");
  assertFullPass(FX.setRoot, "ownerSetAgentRoot (nonce increment)");
  assertFullPass(FX.topUp, "ownerTopUp (value into covenant)");
  assertFullPass(FX.pause, "ownerPause");
  assertFullPass(FX.recover, "ownerRecover (terminal)");
  assertFullPass(FX.genesis, "createVault (genesis)");
});

test("real agentSpend output order is [payment, successor, change] (mirrors the SDK builder)", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.spendFuel });
  assert.deepEqual(m.effects.outputs.map((e) => e.kind), ["payment", "successor", "change"]);
  assert.equal(m.payment.outputIndex, 0, "payment is output 0 in a real agent spend");
  assert.equal(m.stateAfter.expectedOutpoint.index, 1, "successor is output 1 in a real agent spend");
});

test("deriveRequestedIntent reconstructs the intent each real build realizes", { skip: SKIP && skipMsg }, () => {
  const i = deriveRequestedIntent(FX.spendReserve);
  assert.equal(i.action, "agentSpend");
  assert.equal(i.params.recipient, FX.spendReserve.payment.recipient);
  assert.equal(i.params.payAmountSompi, String(FX.spendReserve.payment.value));
  const t = deriveRequestedIntent(FX.setRoot);
  assert.equal(t.params.newAgentRoot, "cd".repeat(32));
  const g = deriveRequestedIntent(FX.genesis);
  assert.equal(g.action, "createVault");
  assert.equal(g.params.owner, FX.genesis.template.owner);
});

/* ---- tampered variants: correct fail-closed detector code ---- */

test("tamper: fee inflation past the requested cap -> EXCESSIVE_FEE", { skip: SKIP && skipMsg }, () => {
  const requestedIntent = deriveRequestedIntent(FX.spendReserve, { maxFeeSompi: "1000" }); // real fee is millions
  const { verification } = deriveAndVerify({ build: FX.spendReserve, requestedIntent });
  assert.equal(verification.verdict, VERDICTS.REFUSED);
  assert.ok(verification.failures.some((f) => f.code === "EXCESSIVE_FEE"), JSON.stringify(verification.failures));
});

test("tamper: recipient substitution -> HIDDEN_RECIPIENT", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.spendReserve });
  const t = clone(m);
  const pi = t.payment.outputIndex;
  t.transaction.outputs[pi].scriptPublicKey.scriptHex = `20${FX.ATTACKER}ac`;
  const { verifyIntentManifest } = require("../../verify");
  const r = verifyIntentManifest({ manifest: rehash(t) });
  assert.ok(r.failures.some((f) => f.code === "HIDDEN_RECIPIENT"), JSON.stringify(r.failures));
});

test("tamper: extra unexplained output -> UNEXPECTED_OUTPUT", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.spendFuel });
  const t = clone(m);
  t.transaction.outputs.push({ value: "5000", scriptPublicKey: { version: 0, scriptHex: `20${FX.ATTACKER}ac` }, covenant: null });
  t.effects.outputs.push({ index: t.effects.outputs.length, kind: "change" });
  const { verifyIntentManifest } = require("../../verify");
  const r = verifyIntentManifest({ manifest: rehash(t) });
  assert.equal(r.verdict, VERDICTS.REFUSED);
  assert.ok(r.failures.some((f) => f.code === "UNEXPECTED_OUTPUT" || f.code === "ACTION_TX_SHAPE_MISMATCH"), JSON.stringify(r.failures));
});

test("tamper: wrong successor covenant binding -> WRONG_SUCCESSOR", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.topUp });
  const t = clone(m);
  const si = t.effects.outputs.findIndex((e) => e.kind === "successor");
  t.transaction.outputs[si].covenant.covenantId = FX.ATTACKER;
  const { verifyIntentManifest } = require("../../verify");
  const r = verifyIntentManifest({ manifest: rehash(t) });
  assert.ok(r.failures.some((f) => f.code === "WRONG_SUCCESSOR"), JSON.stringify(r.failures));
});

test("tamper: unauthorized policy mutation on a spend -> HIDDEN_POLICY_MUTATION", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.spendReserve });
  const t = clone(m);
  t.stateAfter.state.paused = "1"; // agentSpend may not change paused
  const { verifyIntentManifest } = require("../../verify");
  const r = verifyIntentManifest({ manifest: rehash(t) });
  assert.ok(r.failures.some((f) => f.code === "HIDDEN_POLICY_MUTATION"), JSON.stringify(r.failures));
});

test("tamper: action relabelled away from the realized transaction -> refuse", { skip: SKIP && skipMsg }, () => {
  const m = deriveManifestFromV4Build({ build: FX.spendReserve });
  const t = clone(m);
  t.requested.action = "ownerPause";
  t.requested.params = {};
  const { verifyIntentManifest } = require("../../verify");
  const r = verifyIntentManifest({ manifest: rehash(t) });
  assert.equal(r.verdict, VERDICTS.REFUSED);
});

/* ---- G-2 storage-representation regression on a real manifest ---- */

function deepReorderKeys(value) {
  if (Array.isArray(value)) return value.map(deepReorderKeys); // array order is meaningful — preserved
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).reverse()) out[k] = deepReorderKeys(value[k]); // reverse insertion order
    return out;
  }
  return value;
}

test("G-2: derived manifest hash is stable under JSON round-trip and deep key reorder", { skip: SKIP && skipMsg }, () => {
  const { verifyIntentManifest } = require("../../verify");
  for (const [name, build] of [["spend", FX.spendFuel], ["owner", FX.setRoot], ["genesis", FX.genesis], ["recover", FX.recover]]) {
    const m = deriveManifestFromV4Build({ build });
    const body = { ...m };
    delete body.manifestHash;
    const jsonRoundTrip = JSON.parse(JSON.stringify(body));
    const reordered = deepReorderKeys(body);
    assert.equal(computeManifestHashV1(jsonRoundTrip), m.manifestHash, `${name}: JSON round-trip hash drift`);
    assert.equal(computeManifestHashV1(reordered), m.manifestHash, `${name}: key-reorder hash drift (jsonb-class)`);
    /* both representations still verify EXACT */
    assert.equal(verifyIntentManifest({ manifest: rehash(JSON.parse(JSON.stringify(m))) }).verdict, VERDICTS.VERIFIED_EXACT, name);
  }
});
