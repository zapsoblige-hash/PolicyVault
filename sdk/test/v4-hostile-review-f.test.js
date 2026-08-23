"use strict";

/* SDK — Checkpoint F MAX hostile review of the v0.4 construction layer.
 * These are NEW adversarial angles beyond the Checkpoint-E suites:
 * interleaved accounting (F2), recipient-reuse boundary (F3),
 * caller-injection into transitions/builders (F4), independent
 * conservation verification (F5), cross-package approval migration (F9),
 * build-object immutability / aliasing (F10), and malformed-state
 * fail-closed (F11). Production-covenant execution proof for these shapes
 * lives in tests/vm (v4_production f_* + v4_sdk_integration). Offline. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { loadConfig } = require("../src/config");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { buildAgentTreeV4, generateAgentProofV4, applyAgentSpendV4, foldAgentPolicyV4, agentLeafHash } = require("../src/agent-merkle-v4");
const { agentSpendSuccessorV4 } = require("../src/vault-transitions-v4");
const { normalizeStateV4 } = require("../src/vault-state-v4");
const {
  buildV4Transaction,
  finalizeV4Transaction,
  createApprovalPackageForBuildV4
} = require("../src/vault-builders-v4");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { submitApprovalV4 } = require("../src/approval-package-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv4-hostile-f-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();

const owner = KEY(1);
const agentA = KEY(0x1e);
const agentB = KEY(0x1f);
const fuelKey = KEY(3);
const recipient = KEY(0x28);
const other = KEY(0x29);
const approvers = [KEY(20), KEY(21), KEY(22)];

const rTreeA = buildRecipientTree([XO(recipient), XO(other)]);
const rTreeB = buildRecipientTree([XO(other)]);

function policyA(over = {}) {
  return {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    agentRecipientRoot: rTreeA.root, ...over
  };
}
function policyB(over = {}) {
  return {
    agentPk: XO(agentB), maxPerSpend: (30n * KAS).toString(), periodBudget: (30n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    agentRecipientRoot: rTreeB.root, ...over
  };
}
const AGENTS = [policyA(), policyB()];
const TREE = buildAgentTreeV4(AGENTS);
const template = { owner: XO(owner), vaultId: "22".repeat(32) };

function state(over = {}) {
  return {
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: TREE.root, approvers: approvers.map(XO), approvalM: "2", policyNonce: "0", ...over
  };
}
function chainCtx({ value = (1005n * KAS).toString(), fuel = true, outpoint = "42" } = {}) {
  const ctx = { predecessorOutpoint: { transactionId: outpoint.repeat(32), index: 0 }, predecessorValue: value, covenantId: "41".repeat(32) };
  if (fuel) ctx.fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
  return ctx;
}
function spendParams(over = {}) {
  return { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentA), agents: AGENTS, recipient: XO(recipient), recipients: [...rTreeA.recipients], ...over };
}
const signCov = (build, kp) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);
const signFuel = (build) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
const approverSig = (build, kp) => kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 0, kp).slice(2);

/* ------------------------------------------------------------- F5 helper */
/* Independent conservation checker over a build, derived from the FROZEN tx
 * alone — never trusting builder bookkeeping. Verifies, per action, that
 * (a) fee = inputs - outputs, (b) the covenant input holds exactly protected
 * + reserve, (c) the covenant successor holds exactly new protected + new
 * reserve, (d) principal/reserve moved exactly as the op authorizes, and
 * (e) no covenant value escapes to a non-pinned output (external change <=
 * external inputs). For agentSpend it additionally proves the strict
 * conservation theorem fee = reserveConsumed + (externalIn - externalOut). */
function assertConservation(build) {
  const f = build.frozen;
  const totalIn = f.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = f.outputs.reduce((s, o) => s + o.value, 0n);
  const fee = totalIn - totalOut;
  assert.equal(fee, BigInt(build.requiredFeeSompi), "fee = inputs - outputs");

  const covP = BigInt(build.stateJson.protectedValue);
  const covR = BigInt(build.stateJson.feeReserve);
  assert.equal(f.inputs[0].utxo.amount, covP + covR, "covenant input = protected + reserve");
  const externalIn = totalIn - f.inputs[0].utxo.amount;

  if (build.action === "ownerRecover") {
    assert.equal(f.outputs[0].value, covP + covR, "recover pays out protected + reserve");
    const change = totalOut - (covP + covR);
    assert.ok(change <= externalIn, "recover change <= external inputs");
    assert.equal(fee, externalIn - change, "recover fee comes only from fuel");
    return;
  }

  const succ = f.outputs.find((o) => o.covenant !== null);
  assert.ok(succ, "a covenant successor exists");
  const succP = BigInt(build.successorState.protectedValue);
  const succR = BigInt(build.successorState.feeReserve);
  assert.equal(succ.value, succP + succR, "successor value = new protected + new reserve");

  const pay = build.payment ? BigInt(build.payment.value) : 0n;
  // change = every P2PK output that is neither the successor nor the payment
  const change = totalOut - succ.value - pay;
  assert.ok(change >= 0n && change <= externalIn, "external change is between 0 and external inputs (no covenant escape)");

  switch (build.action) {
    case "agentSpend": {
      assert.equal(succP, covP - pay, "principal moves only by the exact payment");
      const reserveConsumed = covR - succR;
      assert.equal(reserveConsumed, BigInt(build.accounting.reserveConsumed), "reserveConsumed = covR - succR");
      assert.ok(reserveConsumed >= 0n && reserveConsumed <= fee, "0 <= reserveConsumed <= fee");
      // strict conservation theorem for the spend path
      assert.equal(fee, reserveConsumed + (externalIn - change), "fee = reserveConsumed + (externalIn - externalOut)");
      break;
    }
    case "ownerTopUp":
      assert.equal(succR, covR, "topUp preserves reserve");
      assert.equal(succP, covP + (externalIn - change - fee), "topUp adds exactly the fuel-funded top-up to principal");
      break;
    case "ownerTopUpReserve":
      assert.equal(succP, covP, "topUpReserve preserves principal");
      assert.equal(succR, covR + (externalIn - change - fee), "topUpReserve adds exactly the fuel-funded amount to reserve");
      break;
    default: // pause/unpause/setAgentRoot/setApprovers
      assert.equal(succP, covP, "value-neutral owner op preserves principal");
      assert.equal(succR, covR, "value-neutral owner op preserves reserve");
      assert.equal(fee, externalIn - change, "fee comes only from fuel");
  }
}

/* =============================================================== F2 */

test("F2: interleaved A->B->A requires the live tree each step; a stale tree is rejected", () => {
  // Spend A: advance A's leaf, get successor root RA.
  const proofA0 = generateAgentProofV4(TREE, XO(agentA));
  const rA = agentSpendSuccessorV4(normalizeStateV4(state()), {
    agentPolicy: proofA0.policy, agentProof: { siblingsHex: proofA0.siblingsHex, pathBits: proofA0.pathBits },
    payAmount: (4n * KAS).toString(), reserveConsumed: "0"
  });
  const treeAfterA = applyAgentSpendV4(TREE, XO(agentA), { newPeriodStartDaa: proofA0.policy.periodStartDaa, newPeriodSpent: (4n * KAS).toString() }).tree;
  assert.equal(rA.successor.agentRoot, treeAfterA.root, "successor root == canonical rebuild after A");
  // B's leaf is byte-identical after A's spend (single-leaf update).
  assert.equal(
    agentLeafHash(treeAfterA.agents.find((a) => a.agentPk === XO(agentB))).toString("hex"),
    agentLeafHash(TREE.agents.find((a) => a.agentPk === XO(agentB))).toString("hex"),
    "B preserved through A's update"
  );

  // Spend B against A's successor state: must use the CURRENT tree (treeAfterA).
  const stateAfterA = { ...state(), agentRoot: rA.successor.agentRoot, protectedValue: rA.successor.protectedValue.toString(), feeReserve: rA.successor.feeReserve.toString() };
  const proofB = generateAgentProofV4(treeAfterA, XO(agentB));
  const rB = agentSpendSuccessorV4(normalizeStateV4(stateAfterA), {
    agentPolicy: proofB.policy, agentProof: { siblingsHex: proofB.siblingsHex, pathBits: proofB.pathBits },
    payAmount: (4n * KAS).toString(), reserveConsumed: "0"
  });
  const treeAfterB = applyAgentSpendV4(treeAfterA, XO(agentB), { newPeriodStartDaa: proofB.policy.periodStartDaa, newPeriodSpent: (4n * KAS).toString() }).tree;
  assert.equal(rB.successor.agentRoot, treeAfterB.root);

  // Spend A again: A's CURRENT periodSpent is 4 KAS. Using the STALE original
  // TREE proof (periodSpent 0) against stateAfterB must fail membership.
  const stateAfterB = { ...stateAfterA, agentRoot: rB.successor.agentRoot };
  assert.throws(
    () => agentSpendSuccessorV4(normalizeStateV4(stateAfterB), { agentPolicy: proofA0.policy, agentProof: { siblingsHex: proofA0.siblingsHex, pathBits: proofA0.pathBits }, payAmount: (4n * KAS).toString(), reserveConsumed: "0" }),
    /does not verify/,
    "A's stale (pre-interleave) proof must not verify against the current root"
  );
  // The correct A' proof (periodSpent 4 KAS, from treeAfterB) verifies.
  const proofA1 = generateAgentProofV4(treeAfterB, XO(agentA));
  assert.equal(proofA1.policy.periodSpent, 4n * KAS, "A's live leaf reflects its first spend");
  const rA2 = agentSpendSuccessorV4(normalizeStateV4(stateAfterB), {
    agentPolicy: proofA1.policy, agentProof: { siblingsHex: proofA1.siblingsHex, pathBits: proofA1.pathBits },
    payAmount: (4n * KAS).toString(), reserveConsumed: "0"
  });
  assert.equal(rA2.newSpent, 8n * KAS, "A's period accounting accumulates across interleaved spends (no reset)");
});

test("F2: no periodSpent decrease / start rewind — accounting only moves forward within a period", () => {
  const proof = generateAgentProofV4(TREE, XO(agentA));
  const r = agentSpendSuccessorV4(normalizeStateV4(state()), { agentPolicy: proof.policy, agentProof: { siblingsHex: proof.siblingsHex, pathBits: proof.pathBits }, payAmount: (4n * KAS).toString(), reserveConsumed: "0" });
  assert.equal(r.newSpent, 4n * KAS);
  assert.equal(r.newStart, 541000000n, "no rollover: start unchanged");
  // the successor leaf carries the ADVANCED accounting; folding the OLD leaf
  // up the same path would give the OLD root (can't rewind under the new root)
  assert.notEqual(foldAgentPolicyV4(r.newPolicy, proof.siblingsHex, proof.pathBits), TREE.root);
});

/* =============================================================== F3 */

test("F3: recipient proof from agent A's tree cannot authorize a spend by agent B", () => {
  // B's agentRecipientRoot is rTreeB (only `other`); A's is rTreeA.
  // Supplying A's recipient list for a B spend must mismatch B's leaf root.
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentB), agents: AGENTS, recipient: XO(other), recipients: [...rTreeA.recipients] },
        chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    (e) => e.code === "RECIPIENT_ROOT_MISMATCH"
  );
  // B paying a recipient that is only in A's tree is impossible (not in B's tree).
  assert.throws(
    () =>
      buildV4Transaction({
        config, templateInput: template, stateInput: state(), action: "agentSpend",
        params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agentB), agents: AGENTS, recipient: XO(recipient), recipients: [...rTreeB.recipients] },
        chain: chainCtx(), changeXOnly: XO(fuelKey)
      }),
    /not in this tree/
  );
});

test("F3: recipient tree malleability (duplicate-last) stays confined to encoding, not authority", () => {
  // A one-recipient tree is depth 0 (root == leaf); a two-identical-recipient
  // input dedups to one recipient — same root, no phantom recipient.
  const single = buildRecipientTree([XO(recipient)]);
  const dupInput = buildRecipientTree([XO(recipient), XO(recipient)]);
  assert.equal(single.root, dupInput.root, "duplicate recipient entries dedup to the same root");
  assert.equal(dupInput.recipients.length, 1, "no phantom recipient is introduced");
  // Reordering recipients yields the same root (sorted canonical set).
  const ab = buildRecipientTree([XO(recipient), XO(other)]);
  const ba = buildRecipientTree([XO(other), XO(recipient)]);
  assert.equal(ab.root, ba.root);
});

/* =============================================================== F4 */

test("F4: builders derive successor state; caller-injected successor fields are ignored", () => {
  // The builder has NO successor parameter. Injecting junk (successor,
  // protectedValue, feeReserve, agentRoot, policyNonce) must not change the
  // derived successor.
  const clean = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams(), chain: chainCtx({ fuel: false }), changeXOnly: XO(owner)
  });
  const injected = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: {
      ...spendParams(),
      successor: { protectedValue: "1", feeReserve: "1", agentRoot: "cd".repeat(32), policyNonce: "99" },
      protectedValue: "1", feeReserve: "1", agentRoot: "cd".repeat(32), policyNonce: "99", reserveConsumedSompi: undefined
    },
    chain: chainCtx({ fuel: false }), changeXOnly: XO(owner)
  });
  assert.deepEqual(injected.successorState, clean.successorState, "successor is derived, not caller-supplied");
  assert.equal(injected.txId, clean.txId, "identical frozen transaction");
});

test("F4: owner ops derive successor; injected owner successor is ignored", () => {
  const clean = buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerPause", params: {}, chain: chainCtx(), changeXOnly: XO(owner) });
  const injected = buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "ownerPause",
    params: { successor: { paused: "0" }, paused: "0", policyNonce: "42", protectedValue: "1" }, chain: chainCtx(), changeXOnly: XO(owner)
  });
  assert.deepEqual(injected.successorState, clean.successorState);
  assert.equal(injected.successorState.paused, "1");
  assert.equal(injected.successorState.policyNonce, "0", "pause preserves nonce regardless of injection");
});

/* =============================================================== F5 */

test("F5: conservation holds independently for every funding mode + owner op + recover", () => {
  const builds = [
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams(), chain: chainCtx({ fuel: false }), changeXOnly: XO(owner) }),
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams({ reserveConsumedSompi: "1000000" }), chain: chainCtx(), changeXOnly: XO(fuelKey) }),
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams(), chain: chainCtx(), changeXOnly: XO(fuelKey) }),
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerTopUp", params: { topUpAmountSompi: (10n * KAS).toString() }, chain: chainCtx(), changeXOnly: XO(owner) }),
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: (2n * KAS).toString() }, chain: chainCtx(), changeXOnly: XO(owner) }),
    buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "ownerRecover", params: {}, chain: chainCtx(), changeXOnly: XO(owner) })
  ];
  for (const b of builds) {
    assertConservation(b);
  }
});

/* =============================================================== F9 */

test("F9: an approval collected for one vault/tx cannot migrate to another", () => {
  // Two DISTINCT above-threshold spends (different recipients => different tx).
  const mk = (target) => buildV4Transaction({
    config, templateInput: template, stateInput: state(), action: "agentSpend",
    params: spendParams({ payAmountSompi: (6n * KAS).toString(), recipient: target }),
    chain: chainCtx(), changeXOnly: XO(fuelKey)
  });
  const bTarget = mk(XO(recipient));
  const bOther = mk(XO(other));
  assert.notEqual(bTarget.txId, bOther.txId);
  const pkgOther = createApprovalPackageForBuildV4(bOther);
  // A valid approval for bTarget spliced into bOther's package must fail
  // Schnorr verification (different sighash).
  const sigForTarget = approverSig(bTarget, approvers[0]);
  assert.throws(
    () => submitApprovalV4(pkgOther, { signatureHex: sigForTarget, approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGNATURE_INVALID",
    "approval bound to tx A cannot authorize tx B"
  );
});

test("F9: approval from a different policyNonce/successor does not verify", () => {
  const b0 = buildV4Transaction({ config, templateInput: template, stateInput: state({ policyNonce: "0" }), action: "agentSpend", params: spendParams({ payAmountSompi: (6n * KAS).toString() }), chain: chainCtx(), changeXOnly: XO(fuelKey) });
  const b1 = buildV4Transaction({ config, templateInput: template, stateInput: state({ policyNonce: "7" }), action: "agentSpend", params: spendParams({ payAmountSompi: (6n * KAS).toString() }), chain: chainCtx(), changeXOnly: XO(fuelKey) });
  // policyNonce is part of the predecessor state script (input UTXO) => different sighash.
  assert.notEqual(b0.txId, b1.txId, "different policyNonce => different predecessor script => different tx");
  const pkg1 = createApprovalPackageForBuildV4(b1);
  assert.throws(
    () => submitApprovalV4(pkg1, { signatureHex: approverSig(b0, approvers[0]), approverXOnly: XO(approvers[0]) }),
    (e) => e.code === "SIGNATURE_INVALID"
  );
});

/* =============================================================== F10 */

test("F10: the build object is deeply immutable (no aliasing surface for finalize)", () => {
  "use strict";
  const build = buildV4Transaction({ config, templateInput: template, stateInput: state(), action: "agentSpend", params: spendParams(), chain: chainCtx({ fuel: false }), changeXOnly: XO(owner) });
  assert.ok(Object.isFrozen(build));
  assert.ok(Object.isFrozen(build.callExtra), "callExtra frozen");
  assert.ok(Object.isFrozen(build.accounting), "accounting frozen");
  assert.ok(Object.isFrozen(build.agentProof), "agentProof frozen");
  assert.ok(Object.isFrozen(build.recipientProof), "recipientProof frozen");
  assert.ok(Object.isFrozen(build.payment), "payment frozen");
  assert.ok(Object.isFrozen(build.frozen.inputs[0]), "frozen input frozen");
  // Attempting to mutate a nested field throws in strict mode.
  assert.throws(() => { build.callExtra.payAmount = "999999999"; }, TypeError);
  assert.throws(() => { build.accounting.reserveConsumed = "0"; }, TypeError);
  // Finalize still succeeds from the untouched build.
  const fin = finalizeV4Transaction({ build, covenantSignatureHex: signCov(build, agentA) });
  assert.equal(fin.txId, build.txId);
});

/* =============================================================== F11 */

test("F11: malformed predecessor states fail closed for ordinary ops; recovery still works", () => {
  const malformed = [
    { over: { approvalM: "11" }, why: "M out of range" },
    { over: { approverSlots: [XO(approvers[0]), XO(approvers[0]), ...Array.from({ length: 8 }, () => "00".repeat(32))], approvers: undefined, approvalM: "1" }, why: "duplicate approver" },
    { over: { protectedValue: "0" }, why: "zero principal" },
    { over: { agentRoot: "zz".repeat(32) }, why: "malformed root hex" },
    { over: { paused: "2" }, why: "invalid pause value" }
  ];
  for (const { over, why } of malformed) {
    assert.throws(
      () => buildV4Transaction({ config, templateInput: template, stateInput: state(over), action: "ownerPause", params: {}, chain: chainCtx(), changeXOnly: XO(owner) }),
      new RegExp("."),
      `ordinary op must fail closed on: ${why}`
    );
  }
  // ownerRecover from a malformed state (duplicate approvers, garbage root,
  // extreme nonce, zero reserve) succeeds via the break-glass parse.
  const recoverBuild = buildV4Transaction({
    config, templateInput: template, action: "ownerRecover",
    stateInput: { protectedValue: (50n * KAS).toString(), feeReserve: "0", paused: "1", agentRoot: "ef".repeat(32), approverSlots: [XO(approvers[0]), XO(approvers[0]), ...Array.from({ length: 8 }, () => "00".repeat(32))], approvalM: "9", policyNonce: "999999999" },
    params: { allowMalformedState: true },
    chain: chainCtx({ value: (50n * KAS).toString() }), changeXOnly: XO(owner)
  });
  assert.equal(recoverBuild.frozen.outputs[0].value, 50n * KAS, "recovery pays out the full principal with zero reserve");
  // allowMalformedState must NOT leak into non-recovery paths.
  assert.throws(
    () => buildV4Transaction({
      config, templateInput: template, action: "ownerPause",
      stateInput: { protectedValue: (50n * KAS).toString(), feeReserve: "0", paused: "0", agentRoot: "ef".repeat(32), approverSlots: [XO(approvers[0]), XO(approvers[0]), ...Array.from({ length: 8 }, () => "00".repeat(32))], approvalM: "9", policyNonce: "5" },
      params: { allowMalformedState: true }, chain: chainCtx({ value: (50n * KAS).toString() }), changeXOnly: XO(owner)
    }),
    /duplicates/,
    "allowMalformedState is quarantined to ownerRecover"
  );
});
