"use strict";

/* SDK — offline v0.4.1 builders (Checkpoint H-R). Proves the version-ABI
 * parametrization: the SAME builder architecture, driven with contractVersion
 * "policyvault-0.4.1", produces the STANDARDNESS-reduced covenant (16,980-byte
 * redeem script, 13 static sig-ops) and routes the six owner operations through
 * ONE ownerControl entrypoint + opSelector, while v0.4 is byte-for-byte
 * unchanged. Uses real silverc compiles + the real pv_call_encoder. The
 * consensus/standardness proof itself lives in tests/vm/v4_1_production.rs. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const { buildV4Transaction, buildCreateV4, finalizeV4Transaction } = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");

const V4 = "policyvault-0.4";
const V4_1 = "policyvault-0.4.1";
const REDEEM_V4_BYTES = 18839;
const REDEEM_V4_1_BYTES = 16980;

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv41-builders-test-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);

const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const agentA = KEY(0x1e);
const fuelKey = KEY(3);
const recipient = KEY(0x28);
const otherRecipient = KEY(0x29);
const approvers = [KEY(20), KEY(21), KEY(22)];
const rTree = buildRecipientTree([XO(recipient), XO(otherRecipient)]);

function policyA(over = {}) {
  return {
    agentPk: XO(agentA),
    maxPerSpend: "20000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: "5000000000",
    agentMaxFeePerTx: "100000000",
    agentRecipientRoot: rTree.root,
    ...over
  };
}
const AGENTS = [policyA()];
const TREE = buildAgentTreeV4(AGENTS);
const template = { owner: XO(owner), vaultId: "22".repeat(32) };

function state(over = {}) {
  return {
    protectedValue: "1000000000000",
    feeReserve: "500000000",
    paused: "0",
    agentRoot: TREE.root,
    approvers: approvers.map(XO),
    approvalM: "2",
    policyNonce: "0",
    ...over
  };
}
function chainCtx({ value = "1000500000000", fuel = true, outpointByte = "42" } = {}) {
  const ctx = {
    predecessorOutpoint: { transactionId: outpointByte.repeat(32), index: 0 },
    predecessorValue: value,
    covenantId: "41".repeat(32)
  };
  if (fuel) {
    ctx.fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: "1000000000", scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  }
  return ctx;
}
function spendParams(over = {}) {
  return { payAmountSompi: "4000000000", agentPk: XO(agentA), agents: AGENTS, recipient: XO(recipient), recipients: [XO(recipient), XO(otherRecipient)], ...over };
}
function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
}

test("HR-SDK: v0.4.1 genesis produces the standardness-reduced 16,980-byte covenant", () => {
  const funding = [{ outpoint: { transactionId: "51".repeat(32), index: 0 }, amount: "2000000000000", scriptPublicKeyHex: `20${XO(fuelKey)}ac` }];
  const g41 = buildCreateV4({ config, templateInput: template, initialStateInput: state(), funding, changeXOnly: XO(owner), contractVersion: V4_1 });
  assert.equal(g41.contractVersion, V4_1);
  assert.equal(g41.vaultScriptHex.length / 2, REDEEM_V4_1_BYTES, "v0.4.1 vault redeem script must be 16,980 bytes");

  // Same inputs at v0.4 (default) still produce the frozen 18,839-byte script,
  // and a DIFFERENT stateId (version is part of identity) so they never collide.
  const g4 = buildCreateV4({ config, templateInput: template, initialStateInput: state(), funding, changeXOnly: XO(owner) });
  assert.equal(g4.contractVersion, V4);
  assert.equal(g4.vaultScriptHex.length / 2, REDEEM_V4_BYTES);
  assert.notEqual(g41.stateId, g4.stateId, "v0.4 and v0.4.1 vaults must have distinct state identities");
  assert.notEqual(g41.scriptSha256, g4.scriptSha256);
});

test("HR-SDK: v0.4.1 agentSpend finalizes on the 16,980-byte covenant (length-stable)", () => {
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams(), chain: chainCtx({ fuel: false }), changeXOnly: XO(owner), contractVersion: V4_1
  });
  assert.equal(build.contractVersion, V4_1);
  assert.equal(build.encoderFunction, "agentSpend", "agentSpend keeps its entrypoint name in v0.4.1");
  const fin = finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, agentA) });
  assert.equal(fin.txId, build.txId);
  assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength, "FEE_DRIFT gate: final call length == planned");
  const artifact = JSON.parse(fs.readFileSync(path.join(build.encoderBuildDir, "artifact.json")));
  assert.equal(artifact.script.length, REDEEM_V4_1_BYTES, "the finalized covenant is the 16,980-byte v0.4.1 script");
});

test("HR-SDK: v0.4.1 routes all six owner ops through ownerControl + opSelector", () => {
  const chain = chainCtx({ fuel: true });
  const cases = [
    ["ownerSetAgentRoot", { newAgents: AGENTS }, 0],
    ["ownerSetApprovers", { newApprovers: { approvers: approvers.map(XO), approvalM: "2" } }, 1],
    ["ownerTopUp", { topUpAmountSompi: "100000000" }, 2],
    ["ownerTopUpReserve", { topUpReserveAmountSompi: "100000000" }, 3],
    ["ownerPause", {}, 4]
  ];
  for (const [action, params, selector] of cases) {
    const build = buildV4Transaction({ config, templateInput: template, stateInput: state(), action, params, chain, changeXOnly: XO(owner), contractVersion: V4_1 });
    assert.equal(build.encoderFunction, "ownerControl", `${action} must route through ownerControl`);
    assert.equal(build.encoderExtra.opSelector, selector, `${action} must map to opSelector ${selector}`);
    // finalize drives the REAL encoder (ownerControl + opSelector) through to bytes.
    const fin = finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, owner), fuelSignatureScriptHex: signFuel(build) });
    assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength, `${action}: final length == planned`);
  }
  // unpause from a paused predecessor -> selector 5.
  const up = buildV4Transaction({ config, templateInput: template, stateInput: state({ paused: "1" }), action: "ownerUnpause", params: {}, chain, changeXOnly: XO(owner), contractVersion: V4_1 });
  assert.equal(up.encoderExtra.opSelector, 5);
});

test("HR-SDK: the SAME owner op under v0.4 keeps its own entrypoint (no consolidation)", () => {
  const build = buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerPause", params: {}, chain: chainCtx({ fuel: true }), changeXOnly: XO(owner) });
  assert.equal(build.contractVersion, V4);
  assert.equal(build.encoderFunction, "ownerPause");
  assert.deepEqual(build.encoderExtra, {});
});

test("HR-SDK: unknown contractVersion fails closed (no default, no fallback)", () => {
  assert.throws(
    () => buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams(), chain: chainCtx({ fuel: false }), changeXOnly: XO(owner), contractVersion: "policyvault-9.9" }),
    /no cross-version fallback/
  );
});
