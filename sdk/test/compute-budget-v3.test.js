"use strict";

/* UNIT — centralized v0.3 compute-budget selection (20I at the SDK layer;
 * VM sufficiency proofs live in tests/vm v3_sdk_integration.rs). */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { V3_BUDGET, selectComputeBudgetV3, assertBudgetSufficient } = require("../src/compute-budget-v3");
const { calculateRequiredFee } = require("../src/fee-mass");

test("proven-safe tiers: spends by threshold side, owner ops, recover", () => {
  assert.equal(selectComputeBudgetV3({ operation: "delegateSpend", aboveThreshold: false }), 31);
  assert.equal(selectComputeBudgetV3({ operation: "delegateSpend", aboveThreshold: true }), 135);
  assert.equal(selectComputeBudgetV3({ operation: "rolloverAndSpend", aboveThreshold: false }), 31);
  assert.equal(selectComputeBudgetV3({ operation: "rolloverAndSpend", aboveThreshold: true }), 135);
  for (const op of ["ownerPause", "ownerUnpause", "revokeDelegate", "rotateDelegate", "ownerTopUp", "migratePolicy", "ownerSetRecipientRoot", "ownerSetApprovers"]) {
    assert.equal(selectComputeBudgetV3({ operation: op }), 29, op);
  }
  assert.equal(selectComputeBudgetV3({ operation: "ownerRecover" }), 16);
});

test("v0.2 budget 20 is NOT inherited anywhere in the v0.3 tiers", () => {
  for (const value of Object.values(V3_BUDGET)) {
    assert.notEqual(value, 20);
  }
});

test("unknown operations and missing threshold flags fail closed", () => {
  assert.throws(() => selectComputeBudgetV3({ operation: "createVault" }), /unknown v0.3 operation/);
  assert.throws(() => selectComputeBudgetV3({ operation: "delegateSpendWithProof" }), /unknown v0.3 operation/);
  assert.throws(() => selectComputeBudgetV3({ operation: "delegateSpend" }), /aboveThreshold/);
});

test("callers can never lower the committed budget below the proven tier", () => {
  assert.throws(() => assertBudgetSufficient({ operation: "delegateSpend", aboveThreshold: true, committed: 134 }), /below the proven-safe minimum/);
  assert.throws(() => assertBudgetSufficient({ operation: "delegateSpend", aboveThreshold: false, committed: 29 }), /below the proven-safe minimum/);
  assert.throws(() => assertBudgetSufficient({ operation: "ownerRecover", committed: 15 }), /below the proven-safe minimum/);
  assert.equal(assertBudgetSufficient({ operation: "delegateSpend", aboveThreshold: true, committed: 135 }), 135);
});

test("tier over-commitment is FEE-NEUTRAL for v0.3 shapes (transient-dominated)", () => {
  // The approved-spend shape from the golden vectors: sig-script 29,977 B.
  const shape = (budget) => ({
    version: 1,
    payloadHex: "",
    inputs: [
      { signatureScriptHex: "00".repeat(29977), computeBudget: budget },
      { signatureScriptHex: "00".repeat(66), computeBudget: 10 }
    ],
    outputs: [
      { scriptHex: "00".repeat(34), hasCovenant: false },
      { scriptHex: "00".repeat(35), hasCovenant: true },
      { scriptHex: "00".repeat(34), hasCovenant: false }
    ]
  });
  const exact2of3 = calculateRequiredFee(shape(61)).minimumRequiredFee;
  const tier = calculateRequiredFee(shape(135)).minimumRequiredFee;
  assert.equal(tier, exact2of3, "committing the 135 tier must not change the fee for an approved spend");
});
