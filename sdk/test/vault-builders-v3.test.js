"use strict";

/* SDK — offline v0.3 builders (20A/20B/20I/20J/20K at the SDK layer;
 * production-covenant execution proof lives in tests/vm
 * v3_sdk_integration.rs). Uses real silverc compiles, the real
 * pv_call_encoder, the real pv_tx_probe, and the real WASM — offline. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildV3Transaction, buildCreateV3, finalizeV3Transaction, createApprovalPackageForBuild } = require("../src/vault-builders-v3");
const { frozenToWasmTransaction, frozenTxCommitment } = require("../src/frozen-tx-v3");
const { submitApprovalV3 } = require("../src/approval-package-v3");
const { calculateRequiredFee } = require("../src/fee-mass");
const { feeDescriptorFromFrozen } = require("../src/frozen-tx-v3");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv3-builders-test-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);

const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const delegate = KEY(2);
const fuelKey = KEY(3);
const recipient = KEY(40);
const approvers = [KEY(20), KEY(21), KEY(22)];

const tree = buildRecipientTree([XO(recipient), XO(KEY(41)), XO(KEY(42))]);
const template = { owner: XO(owner), vaultId: "22".repeat(32) };

function state(over = {}) {
  return {
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: XO(delegate),
    delegateActive: "1",
    maxPerSpend: "20000000000",
    periodBudget: "80000000000",
    periodLengthDaa: "864000",
    recipientRoot: tree.root,
    approvers: approvers.map(XO),
    approvalM: "2",
    approvalThresholdAmount: "5000000000",
    policyNonce: "0",
    ...over
  };
}

function chainCtx(predecessorValue = "100000000000") {
  return {
    predecessorOutpoint: { transactionId: "42".repeat(32), index: 0 },
    predecessorValue,
    covenantId: "41".repeat(32),
    fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: "1000000000", scriptPublicKeyHex: `20${XO(fuelKey)}ac` }
  };
}

function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
}

test("below-threshold spend: shape, budget 31, exact fee, freeze, finalize (length-stable)", () => {
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "delegateSpend",
    params: { payAmountSompi: "4000000000", recipient: XO(recipient), recipients: [...tree.recipients] },
    chain: chainCtx(),
    changeXOnly: XO(fuelKey)
  });
  assert.equal(build.aboveThreshold, false);
  assert.equal(build.computeBudget, 31);
  assert.equal(build.frozen.outputs.length, 3);
  assert.equal(build.frozen.outputs[0].value, 4000000000n); // exact payment
  assert.equal(build.frozen.outputs[1].value, 96000000000n); // exact successor
  assert.equal(build.frozen.outputs[1].covenant.covenantId, "41".repeat(32));
  assert.equal(build.successorState.periodSpent, "4000000000");
  assert.equal(build.successorState.policyNonce, "0");

  // the fee equals an independent recomputation over the same exact shape
  const recomputed = calculateRequiredFee(
    feeDescriptorFromFrozen(build.frozen, [
      // planned covenant sig-script length: call bytes + 3-byte push + 28,483-byte redeem
      build.plannedCallHexLength / 2 + 3 + 28483,
      66
    ])
  ).minimumRequiredFee;
  assert.equal(build.requiredFeeSompi, recomputed.toString());
  // principal/fee separation: fee is funded ONLY by fuel
  const fuel = build.frozen.inputs[1].utxo.amount;
  assert.equal(fuel - build.frozen.outputs[2].value, BigInt(build.requiredFeeSompi));

  const fin = finalizeV3Transaction({ build, covenantSignatureHex: signCov(build, delegate), fuelSignatureScriptHex: signFuel(build) });
  assert.equal(fin.txId, build.txId, "v1 txId is stable across signing");
  assert.equal(fin.finalTransaction.inputs[0].signatureScript.length, build.plannedCallHexLength + 6 + 28483 * 2);
});

test("above-threshold spend requires a complete package bound to THIS build", () => {
  const mk = (pay) =>
    buildV3Transaction({
      config,
      templateInput: template,
      stateInput: state(),
      action: "delegateSpend",
      params: { payAmountSompi: pay, recipient: XO(recipient), recipients: [...tree.recipients] },
      chain: chainCtx(),
      changeXOnly: XO(fuelKey)
    });
  const build = mk("15000000000");
  assert.equal(build.aboveThreshold, true);
  assert.equal(build.computeBudget, 135);

  // finalize without a package fails closed
  assert.throws(
    () => finalizeV3Transaction({ build, covenantSignatureHex: signCov(build, delegate), fuelSignatureScriptHex: signFuel(build) }),
    /requires a complete approval package/
  );
  // an incomplete package fails closed
  let pkg = createApprovalPackageForBuild(build);
  pkg = submitApprovalV3(pkg, { signatureHex: signCov(build, approvers[0]), approverXOnly: XO(approvers[0]) });
  assert.throws(
    () => finalizeV3Transaction({ build, covenantSignatureHex: signCov(build, delegate), fuelSignatureScriptHex: signFuel(build), approvalPackage: pkg }),
    /insufficient approvals/i
  );
  // a package from a DIFFERENT build is rejected (txId binding)
  const other = mk("15000001000");
  let otherPkg = createApprovalPackageForBuild(other);
  otherPkg = submitApprovalV3(otherPkg, { signatureHex: signCov(other, approvers[0]), approverXOnly: XO(approvers[0]) });
  otherPkg = submitApprovalV3(otherPkg, { signatureHex: signCov(other, approvers[1]), approverXOnly: XO(approvers[1]) });
  assert.throws(
    () =>
      finalizeV3Transaction({ build, covenantSignatureHex: signCov(build, delegate), fuelSignatureScriptHex: signFuel(build), approvalPackage: otherPkg }),
    /bound to one exact frozen transaction/
  );
  // the complete correct package finalizes
  pkg = submitApprovalV3(pkg, { signatureHex: signCov(build, approvers[1]), approverXOnly: XO(approvers[1]) });
  const fin = finalizeV3Transaction({
    build,
    covenantSignatureHex: signCov(build, delegate),
    fuelSignatureScriptHex: signFuel(build),
    approvalPackage: pkg
  });
  assert.equal(fin.txId, build.txId);

  // below/equal threshold must NOT accept a package (no fake approvals)
  const below = mk("5000000000");
  assert.equal(below.aboveThreshold, false);
  assert.throws(() => createApprovalPackageForBuild(below), /delegate authorization is sufficient/);
});

test("caller cannot force a successor: builders take intent only (20B)", () => {
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state({ periodSpent: "500000000" }),
    action: "ownerPause",
    params: { successor: { periodSpent: "0" } }, // ignored: unknown params carry no authority
    chain: chainCtx(),
    changeXOnly: XO(owner)
  });
  assert.equal(build.successorState.periodSpent, "500000000", "accounting preserved regardless of caller-supplied successor data");
  assert.equal(build.successorState.paused, "1");
});

test("version dispatch fails closed: no silent fallback (20K)", () => {
  const args = {
    config,
    templateInput: template,
    stateInput: state(),
    action: "ownerPause",
    params: {},
    chain: chainCtx(),
    changeXOnly: XO(owner)
  };
  assert.throws(() => buildV3Transaction({ ...args, contractVersion: "policyvault-0.2" }), /unsupported contractVersion/);
  assert.throws(() => buildV3Transaction({ ...args, contractVersion: "policyvault-0.4" }), /unsupported contractVersion/);
  assert.throws(() => buildV3Transaction({ ...args, action: "delegateSpendWithProof" }), /unknown v0.3 action/);
});

test("stale predecessor value fails closed before any construction", () => {
  assert.throws(
    () =>
      buildV3Transaction({
        config,
        templateInput: template,
        stateInput: state(),
        action: "ownerPause",
        params: {},
        chain: chainCtx("99000000000"),
        changeXOnly: XO(owner)
      }),
    /STALE|stale or inconsistent/
  );
});

test("recovery-mode predecessor is accepted ONLY by ownerRecover", () => {
  const malformed = state({
    approvers: undefined,
    approverSlots: [XO(approvers[0]), XO(approvers[0]), ...Array.from({ length: 8 }, () => "00".repeat(32))],
    approvalM: "0",
    approvalThresholdAmount: "1",
    paused: "1",
    delegateActive: "0"
  });
  // ordinary op refuses the malformed state outright (strict normalize)
  assert.throws(
    () =>
      buildV3Transaction({
        config,
        templateInput: template,
        stateInput: malformed,
        action: "ownerPause",
        params: { allowMalformedState: true },
        chain: chainCtx(),
        changeXOnly: XO(owner)
      }),
    /duplicates/
  );
  // ownerRecover with allowMalformedState builds the exact malformed state
  const rec = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: malformed,
    action: "ownerRecover",
    params: { allowMalformedState: true },
    chain: chainCtx(),
    changeXOnly: XO(owner)
  });
  assert.equal(rec.computeBudget, 16);
  assert.equal(rec.frozen.outputs[0].value, 100000000000n, "full protected value to the owner");
  assert.equal(rec.frozen.outputs[0].scriptPublicKey.scriptHex, `20${XO(owner)}ac`);
});

test("finalize enforces SIG_HASH_ALL covenant signatures and exact fuel sig-script width", () => {
  const build = buildV3Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "ownerPause",
    params: {},
    chain: chainCtx(),
    changeXOnly: XO(owner)
  });
  const good = signCov(build, owner);
  assert.throws(
    () => finalizeV3Transaction({ build, covenantSignatureHex: good.slice(0, -2) + "02", fuelSignatureScriptHex: signFuel(build) }),
    /SIG_HASH_ALL/
  );
  assert.throws(() => finalizeV3Transaction({ build, covenantSignatureHex: good.slice(0, 128), fuelSignatureScriptHex: signFuel(build) }), /length/);
  assert.throws(() => finalizeV3Transaction({ build, covenantSignatureHex: good, fuelSignatureScriptHex: "aa" }), /fuel signature script/);
  assert.throws(() => finalizeV3Transaction({ build, covenantSignatureHex: good, fuelSignatureScriptHex: signFuel(build), approvalPackage: {} }), /does not take approvals/);
});

test("genesis: deterministic offline construction with real covenantId (20A)", () => {
  const genesis = buildCreateV3({
    config,
    templateInput: template,
    initialStateInput: state(),
    funding: [{ outpoint: { transactionId: "ef".repeat(32), index: 0 }, amount: "150000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
    changeXOnly: XO(owner),
    delegateFuelSompi: "500000000"
  });
  assert.equal(genesis.kind, "genesis");
  assert.match(genesis.covenantId, /^[0-9a-f]{64}$/);
  assert.equal(genesis.vaultOutputIndex, 0);
  assert.equal(genesis.frozen.outputs[0].value, 100000000000n);
  assert.equal(genesis.frozen.outputs[0].covenant.covenantId, genesis.covenantId);
  assert.equal(genesis.frozen.outputs[1].value, 500000000n); // delegate fuel
  // deterministic: rebuilding produces the identical frozen transaction
  const again = buildCreateV3({
    config,
    templateInput: template,
    initialStateInput: state(),
    funding: [{ outpoint: { transactionId: "ef".repeat(32), index: 0 }, amount: "150000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
    changeXOnly: XO(owner),
    delegateFuelSompi: "500000000"
  });
  assert.equal(frozenTxCommitment(again.frozen), frozenTxCommitment(genesis.frozen));
  assert.equal(again.txId, genesis.txId);
  assert.equal(again.covenantId, genesis.covenantId);

  // genesis prerequisites fail closed
  assert.throws(() => buildCreateV3({ config, templateInput: template, initialStateInput: state({ policyNonce: "1" }), funding: [], changeXOnly: XO(owner) }), /policyNonce 0/);
  assert.throws(() => buildCreateV3({ config, templateInput: template, initialStateInput: state({ periodSpent: "1" }), funding: [], changeXOnly: XO(owner) }), /periodSpent 0/);
  assert.throws(() => buildCreateV3({ config, templateInput: template, initialStateInput: state({ paused: "1" }), funding: [], changeXOnly: XO(owner) }), /unpaused/);
});

test("v0.2 -> v0.3 upgrade primitives exist without fake lineage: recover (v0.2 side) + create (v0.3 side) are separate transactions", () => {
  // 4H exposes only the primitives: a v0.3 genesis whose funding COULD be
  // a v0.2 recovery payout. The two are distinct transactions with a new
  // covenantId/lineage — no in-lineage migration path exists in the SDK.
  const genesis = buildCreateV3({
    config,
    templateInput: { owner: XO(owner), vaultId: "77".repeat(32) },
    initialStateInput: state(),
    funding: [{ outpoint: { transactionId: "99".repeat(32), index: 0 }, amount: "150000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
    changeXOnly: XO(owner)
  });
  assert.notEqual(genesis.covenantId, "41".repeat(32), "a recreated vault gets a NEW covenantId (new lineage)");
  assert.equal(genesis.initialState.periodSpent, "0", "fresh accounting at the new genesis — never migrated");
});
