"use strict";

/* SDK — offline v0.4 builders (Checkpoint E §E4/§E6/§E7/§E8/§E9 at the
 * SDK layer; production-covenant execution proof lives in tests/vm
 * v4_sdk_integration.rs). Uses real silverc compiles, the real
 * pv_call_encoder, the real pv_tx_probe, and the real WASM — offline. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildAgentTreeV4 } = require("../src/agent-merkle-v4");
const {
  buildV4Transaction,
  buildCreateV4,
  finalizeV4Transaction,
  createApprovalPackageForBuildV4
} = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const {
  submitApprovalV4,
  isCompleteV4,
  missingSlotsV4,
  loadApprovalPackageV4,
  approvalPackageToJsonV4,
  PLACEHOLDER_APPROVAL
} = require("../src/approval-package-v4");
const { V4_BUDGET } = require("../src/compute-budget-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-builders-test-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);

const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const agentA = KEY(0x1e); // 30
const agentB = KEY(0x1f); // 31
const fuelKey = KEY(3);
const recipient = KEY(0x28); // 40
const otherRecipient = KEY(0x29); // 41
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
function policyB(over = {}) {
  return {
    agentPk: XO(agentB),
    maxPerSpend: "90000000000",
    periodBudget: "90000000000",
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: "5000000000",
    agentMaxFeePerTx: "500000000",
    agentRecipientRoot: rTree.root,
    ...over
  };
}

const AGENTS = [policyA(), policyB()];
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
  return {
    payAmountSompi: "4000000000",
    agentPk: XO(agentA),
    agents: AGENTS,
    recipient: XO(recipient),
    recipients: [XO(recipient), XO(otherRecipient)],
    ...over
  };
}

function signCov(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}
function signFuel(build) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
}
function approverSig(build, kp) {
  return kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
}

test("E4/E6: reserve-funded below-threshold spend — 1in/2out, fee == reserveConsumed, exact conservation, finalize length-stable", () => {
  const build = buildV4Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "agentSpend",
    params: spendParams(),
    chain: chainCtx({ fuel: false }),
    changeXOnly: XO(owner)
  });
  assert.equal(build.computeBudget, V4_BUDGET.SPEND_NO_APPROVALS);
  assert.equal(build.frozen.inputs.length, 1);
  assert.equal(build.frozen.outputs.length, 2);
  const acc = build.accounting;
  assert.equal(acc.fee, acc.reserveConsumed, "reserve mode consumes exactly the network fee");
  assert.equal(acc.externalIn, "0");
  assert.equal(acc.externalOut, "0");
  assert.equal(BigInt(acc.successorProtected), BigInt(acc.predecessorProtected) - BigInt(acc.payAmount));
  assert.equal(BigInt(acc.successorFeeReserve), BigInt(acc.predecessorFeeReserve) - BigInt(acc.reserveConsumed));
  assert.equal(BigInt(acc.successorTotal), build.frozen.outputs[1].value);
  // conservation theorem: fee = reserveConsumed + (extIn - extOut)
  assert.equal(BigInt(acc.fee), BigInt(acc.reserveConsumed) + BigInt(acc.externalIn) - BigInt(acc.externalOut));
  // nonce preserved by spends
  assert.equal(build.successorState.policyNonce, "0");
  const fin = finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, agentA) });
  assert.equal(fin.txId, build.txId, "v1 txId excludes signature scripts");
  assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength, "FEE_DRIFT gate: final call length == planned");
});

test("E4/E6: fuel-funded spend with zero reserve consumption — change exact, principal untouched by fee", () => {
  const build = buildV4Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "agentSpend",
    params: spendParams(),
    chain: chainCtx(),
    changeXOnly: XO(fuelKey)
  });
  assert.equal(build.frozen.inputs.length, 2);
  assert.equal(build.frozen.outputs.length, 3);
  const acc = build.accounting;
  assert.equal(acc.reserveConsumed, "0");
  assert.equal(acc.successorFeeReserve, acc.predecessorFeeReserve, "no reserve movement");
  assert.equal(BigInt(acc.externalIn) - BigInt(acc.externalOut), BigInt(acc.fee));
  const fin = finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, agentA), fuelSignatureScriptHex: signFuel(build) });
  assert.equal(fin.txId, build.txId);
});

test("E4: fuel-funded spend with partial reserve consumption", () => {
  const build = buildV4Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "agentSpend",
    params: spendParams({ reserveConsumedSompi: "1000000" }),
    chain: chainCtx(),
    changeXOnly: XO(fuelKey)
  });
  const acc = build.accounting;
  assert.equal(acc.reserveConsumed, "1000000");
  assert.equal(BigInt(acc.fee), 1000000n + BigInt(acc.externalIn) - BigInt(acc.externalOut));
});

test("E4: fee-reserve fail-closed matrix (specific errors, no policy mutation)", () => {
  // reserveConsumed above the exact fee
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: spendParams({ reserveConsumedSompi: "90000000" }),
        chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    (e) => e.code === "RESERVE_OVER_FEE"
  );
  // reserve mode refuses a caller-supplied reserveConsumed
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: spendParams({ reserveConsumedSompi: "1" }),
        chain: chainCtx({ fuel: false }), changeXOnly: XO(owner)
      }),
    /derived by the builder/
  );
  // reserve mode with an empty reserve fails with a clear code
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state({ feeReserve: "0" }), action: "agentSpend",
        params: spendParams(),
        chain: chainCtx({ value: "1000000000000", fuel: false }), changeXOnly: XO(owner)
      }),
    (e) => e.code === "INSUFFICIENT_RESERVE"
  );
  // reserve mode with a fee cap below the exact fee fails with the cap code
  const cappedAgents = [policyA({ agentMaxFeePerTx: "1000" }), policyB()];
  const cappedTree = buildAgentTreeV4(cappedAgents);
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state({ agentRoot: cappedTree.root }), action: "agentSpend",
        params: spendParams({ agents: cappedAgents }),
        chain: chainCtx({ fuel: false }), changeXOnly: XO(owner)
      }),
    (e) => e.code === "OVER_AGENT_FEE_CAP"
  );
  // predecessor value must equal protected + reserve
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: spendParams(), chain: chainCtx({ value: "1000000000000" }), changeXOnly: XO(fuelKey)
      }),
    (e) => e.code === "STALE"
  );
});

test("E6: proof-mismatch fail-closed — foreign agent set, foreign recipient set", () => {
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state({ agentRoot: "cd".repeat(32) }), action: "agentSpend",
        params: spendParams(), chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    (e) => e.code === "AGENT_ROOT_MISMATCH"
  );
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: spendParams({ recipients: [XO(recipient)] }), chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    (e) => e.code === "RECIPIENT_ROOT_MISMATCH"
  );
  // recipient not in the agent's tree
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: spendParams({ recipient: XO(KEY(0x55)) }), chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    /not in this tree/
  );
});

test("E7/E8/E9: above-threshold spend — freeze before approval, collect 2-of-3, finalize", () => {
  const build = buildV4Transaction({
    config,
    templateInput: template,
    stateInput: state(),
    action: "agentSpend",
    params: spendParams({ payAmountSompi: "6000000000" }), // threshold 50 KAS < 60 KAS
    chain: chainCtx(),
    changeXOnly: XO(fuelKey)
  });
  assert.equal(build.aboveThreshold, true);
  assert.equal(build.computeBudget, V4_BUDGET.SPEND_WITH_APPROVALS);

  // finalize without approvals fails closed
  assert.throws(
    () => finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, agentA), fuelSignatureScriptHex: signFuel(build) }),
    (e) => e.code === "INSUFFICIENT_APPROVALS"
  );

  let pkg = createApprovalPackageForBuildV4(build);
  assert.equal(isCompleteV4(pkg), false);
  assert.equal(missingSlotsV4(pkg).length, 3);

  // placeholder never counts
  assert.throws(
    () => submitApprovalV4(pkg, { signatureHex: PLACEHOLDER_APPROVAL, approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGNATURE_INVALID"
  );
  // unknown signer rejected
  assert.throws(
    () => submitApprovalV4(pkg, { signatureHex: approverSig(build, KEY(0x66)), approverXOnly: XO(KEY(0x66)) }),
    (e) => e.code === "UNKNOWN_APPROVER"
  );
  // approver key A with approver B's signature fails Schnorr verification
  assert.throws(
    () => submitApprovalV4(pkg, { signatureHex: approverSig(build, approvers[1]), approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGNATURE_INVALID"
  );
  // non-ALL trailing byte rejected at the shape gate
  const sig0 = approverSig(build, approvers[0]);
  assert.throws(
    () => submitApprovalV4(pkg, { signatureHex: sig0.slice(0, -2) + "02", approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGHASH_NOT_ALL"
  );

  pkg = submitApprovalV4(pkg, { signatureHex: sig0, approverXOnly: XO(approvers[0]) });
  // duplicate submission into the same slot rejected
  assert.throws(
    () => submitApprovalV4(pkg, { signatureHex: sig0, approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "DUPLICATE_APPROVAL"
  );
  assert.equal(isCompleteV4(pkg), false, "1 of 2 required");
  pkg = submitApprovalV4(pkg, { signatureHex: approverSig(build, approvers[1]), approverXOnly: XO(approvers[1]) });
  assert.equal(isCompleteV4(pkg), true);

  // durable round-trip preserves integrity
  const reloaded = loadApprovalPackageV4(approvalPackageToJsonV4(pkg));
  assert.equal(reloaded.commitment, pkg.commitment);

  const fin = finalizeV4Transaction({
    build,
    covenantSignatureHex: signCov(build, agentA),
    fuelSignatureScriptHex: signFuel(build),
    approvalPackage: reloaded
  });
  assert.equal(fin.txId, build.txId);
  assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength);
});

test("E7: any protected mutation after freeze voids the package (commitment + probe)", () => {
  const build = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams({ payAmountSompi: "6000000000" }),
    chain: chainCtx(), changeXOnly: XO(fuelKey)
  });
  const pkg = createApprovalPackageForBuildV4(build);
  for (const mutate of [
    (p) => { p.payAmountSompi = "6000000001"; },
    (p) => { p.recipient = XO(otherRecipient); },
    (p) => { p.predecessorOutpoint = { ...p.predecessorOutpoint, index: 1 }; },
    (p) => { p.approvalM = "1"; },
    (p) => { p.approverSlots = [...p.approverSlots.slice(1), p.approverSlots[0]]; },
    (p) => { p.computeBudget = 1; },
    (p) => { p.reserveConsumedSompi = "1"; },
    (p) => { p.agentPolicy = { ...p.agentPolicy, maxPerSpend: "999999999999" }; },
    (p) => { p.agentProof = { ...p.agentProof, pathBits: "1" }; },
    (p) => { p.successorAgentRoot = "cd".repeat(32); },
    (p) => { p.frozenTransaction = { ...p.frozenTransaction, lockTime: "5" }; },
    (p) => { p.requiredFeeSompi = "1"; }
  ]) {
    const copy = JSON.parse(JSON.stringify(pkg));
    mutate(copy);
    assert.throws(
      () => submitApprovalV4(copy, { signatureHex: approverSig(build, approvers[0]), approverXOnly: XO(approvers[0]) }),
      (e) => e.code === "PACKAGE_MUTATED" || /approval-package-v4/.test(e.message),
      "mutated package must fail integrity"
    );
  }
});

test("E1/E8: staleness — B's frozen package cannot be rebased after A finalizes; approvals do not transfer", () => {
  // A and B: two builds against the SAME predecessor outpoint.
  const buildA = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams({ payAmountSompi: "6000000000" }),
    chain: chainCtx(), changeXOnly: XO(fuelKey)
  });
  const buildB = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams({ payAmountSompi: "7000000000", agentPk: XO(agentB), reserveConsumedSompi: "0" }),
    chain: chainCtx(), changeXOnly: XO(fuelKey)
  });
  assert.notEqual(buildA.txId, buildB.txId);
  let pkgB = createApprovalPackageForBuildV4(buildB);
  pkgB = submitApprovalV4(pkgB, { signatureHex: approverSig(buildB, approvers[0]), approverXOnly: XO(approvers[0]) });

  // A finalizes (conceptually consumes the predecessor). B is now stale:
  // its frozen tx still spends the OLD outpoint — consensus will reject it
  // once A confirms, and the SDK provides NO rebase: a new predecessor
  // means a NEW build. Prove the two intended rebase paths fail closed:
  // 1) mutating B's package predecessor to the successor outpoint voids it;
  const rebased = JSON.parse(JSON.stringify(pkgB));
  rebased.predecessorOutpoint = { transactionId: buildA.txId, index: 1 };
  rebased.frozenTransaction.inputs[0].previousOutpoint = { transactionId: buildA.txId, index: 1 };
  assert.throws(
    () => submitApprovalV4(rebased, { signatureHex: approverSig(buildB, approvers[1]), approverXOnly: XO(approvers[1]) }),
    (e) => e.code === "PACKAGE_MUTATED",
    "package rebase must void the package"
  );
  // 2) a REBUILT B' against the successor outpoint is a different frozen
  //    tx; B's collected approval fails Schnorr verification on it.
  const successorValue = (BigInt(buildA.successorState.protectedValue) + BigInt(buildA.successorState.feeReserve)).toString();
  // The successor tree carries A's advanced accounting; B's leaf is unchanged.
  const successorAgents = [policyA({ periodSpent: "6000000000" }), policyB()];
  const buildB2 = buildV4Transaction({
    config, templateInput: template, stateInput: buildA.successorState, action: "agentSpend",
    params: spendParams({ payAmountSompi: "7000000000", agentPk: XO(agentB), reserveConsumedSompi: "0", agents: successorAgents }),
    chain: { ...chainCtx(), predecessorOutpoint: { transactionId: buildA.txId, index: 1 }, predecessorValue: successorValue },
    changeXOnly: XO(fuelKey)
  });
  const pkgB2 = createApprovalPackageForBuildV4(buildB2);
  const staleSig = pkgB.approvals.find((s) => s !== null);
  assert.throws(
    () => submitApprovalV4(pkgB2, { signatureHex: staleSig, approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGNATURE_INVALID",
    "an approval collected for the stale build must not verify on the rebuilt transaction"
  );
});

test("E6: owner operations — successor derivation, fuel required, budgets", () => {
  const chain = chainCtx();
  const run = (action, params) =>
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action, params, chain, changeXOnly: XO(owner) });

  const setRoot = run("ownerSetAgentRoot", { newAgentRoot: "cd".repeat(32) });
  assert.equal(setRoot.successorState.agentRoot, "cd".repeat(32));
  assert.equal(setRoot.successorState.policyNonce, "1");
  assert.equal(setRoot.computeBudget, V4_BUDGET.OWNER_OP);
  const finRoot = finalizeV4Transaction({ build: setRoot, covenantSignatureHex: signCov(setRoot, owner), fuelSignatureScriptHex: signFuel(setRoot) });
  assert.equal(finRoot.txId, setRoot.txId);

  // ownerSetAgentRoot from a canonical agent set
  const withNew = run("ownerSetAgentRoot", { newAgents: [...AGENTS, policyA({ agentPk: XO(KEY(0x77)) })] });
  assert.equal(withNew.successorState.agentRoot, buildAgentTreeV4([...AGENTS, policyA({ agentPk: XO(KEY(0x77)) })]).root);

  const setApp = run("ownerSetApprovers", { newApprovers: { approvers: [XO(KEY(25)), XO(KEY(26))], approvalM: "2" } });
  assert.equal(setApp.successorState.approvalM, "2");
  assert.equal(setApp.successorState.policyNonce, "1");

  const topUp = run("ownerTopUp", { topUpAmountSompi: "500000000" });
  assert.equal(topUp.successorState.protectedValue, "1000500000000");
  assert.equal(topUp.successorState.feeReserve, "500000000");
  assert.equal(BigInt(topUp.accounting.externalIn) - BigInt(topUp.accounting.externalOut) - BigInt(topUp.accounting.fee), 500000000n);

  const topUpR = run("ownerTopUpReserve", { topUpReserveAmountSompi: "200000000" });
  assert.equal(topUpR.successorState.feeReserve, "700000000");
  assert.equal(topUpR.successorState.protectedValue, "1000000000000");

  const pause = run("ownerPause", {});
  assert.equal(pause.successorState.paused, "1");
  assert.equal(pause.successorState.policyNonce, "0", "pause preserves the nonce");

  // owner ops REQUIRE fuel (their covenant values are pinned exactly)
  assert.throws(
    () => buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerPause", params: {}, chain: chainCtx({ fuel: false }), changeXOnly: XO(owner) }),
    (e) => e.code === "FUEL_REQUIRED"
  );
});

test("E6: ownerRecover — terminal payout incl. reserve; malformed-state break-glass; zero-reserve recovery", () => {
  const chain = chainCtx();
  const rec = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "ownerRecover", params: {}, chain, changeXOnly: XO(owner)
  });
  assert.equal(rec.successorState, null, "terminal: no successor is fabricated");
  assert.equal(rec.frozen.outputs[0].value, 1000500000000n, "payout = protected + reserve");
  assert.equal(rec.computeBudget, V4_BUDGET.RECOVER);
  const finRec = finalizeV4Transaction({ build: rec, covenantSignatureHex: signCov(rec, owner), fuelSignatureScriptHex: signFuel(rec) });
  assert.equal(finRec.txId, rec.txId);

  // malformed predecessor (duplicate approvers, inconsistent M, paused,
  // garbage agentRoot, EMPTY reserve) — the break-glass parse
  const malformed = {
    protectedValue: "77000000000",
    feeReserve: "0",
    paused: "1",
    agentRoot: "ef".repeat(32),
    approverSlots: [XO(KEY(20)), XO(KEY(20)), ...Array.from({ length: 8 }, () => "00".repeat(32))],
    approvalM: "9",
    policyNonce: "12"
  };
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: malformed, action: "ownerRecover", params: {},
        chain: { ...chain, predecessorValue: "77000000000" }, changeXOnly: XO(owner)
      }),
    /duplicates/,
    "the strict parse must reject the malformed state"
  );
  const recM = buildV4Transaction({
    config, templateInput: template, stateInput: malformed, action: "ownerRecover", params: { allowMalformedState: true },
    chain: { ...chain, predecessorValue: "77000000000" }, changeXOnly: XO(owner)
  });
  assert.equal(recM.frozen.outputs[0].value, 77000000000n, "zero-reserve recovery pays out the full principal");
  // the recovery parse is quarantined: ordinary actions refuse it
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: malformed, action: "ownerPause", params: { allowMalformedState: true },
        chain: { ...chain, predecessorValue: "77000000000" }, changeXOnly: XO(owner)
      }),
    /duplicates/,
    "allowMalformedState must have no effect outside ownerRecover"
  );
});

test("E6: genesis — vault output holds protected + reserve; covenantId from real wasm; genesis-only invariants", () => {
  const build = buildCreateV4({
    config,
    templateInput: template,
    initialStateInput: state(),
    funding: [{ outpoint: { transactionId: "45".repeat(32), index: 0 }, amount: "2000000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
    changeXOnly: XO(owner),
    agentFuel: { xOnly: XO(agentA), amountSompi: "1000000000" }
  });
  assert.equal(build.frozen.outputs[0].value, 1000500000000n, "vault UTXO = protected + reserve");
  assert.equal(build.frozen.outputs[0].covenant.covenantId, build.covenantId);
  assert.equal(build.accounting.vaultValue, "1000500000000");
  assert.match(build.covenantId, /^[0-9a-f]{64}$/);
  assert.throws(
    () => buildCreateV4({
      config, templateInput: template, initialStateInput: state({ policyNonce: "1" }),
      funding: [{ outpoint: { transactionId: "45".repeat(32), index: 0 }, amount: "2000000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
      changeXOnly: XO(owner)
    }),
    /policyNonce 0/
  );
  assert.throws(
    () => buildCreateV4({
      config, templateInput: template, initialStateInput: state({ paused: "1" }),
      funding: [{ outpoint: { transactionId: "45".repeat(32), index: 0 }, amount: "2000000000000", scriptPublicKeyHex: `20${XO(owner)}ac` }],
      changeXOnly: XO(owner)
    }),
    /unpaused/
  );
});

test("E6: version + action dispatch fails closed", () => {
  assert.throws(
    () => buildV4Transaction({ config, contractVersion: "policyvault-0.3", templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams(), chain: chainCtx(), changeXOnly: XO(owner) }),
    /no cross-version fallback/
  );
  assert.throws(
    () => buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "delegateSpend", params: spendParams(), chain: chainCtx(), changeXOnly: XO(owner) }),
    /unknown v0.4 action/
  );
});
