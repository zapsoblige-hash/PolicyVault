"use strict";

/* SDK — v0.4 compute-budget tiers (Checkpoint E §E5). The tier VALUES are
 * proven sufficient per exact shape by the production-byte VM gate
 * (v4_sdk_integration.rs); this suite pins selection + floor semantics. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { V4_BUDGET, selectComputeBudgetV4, assertBudgetSufficientV4 } = require("../src/compute-budget-v4");

test("E5: tier selection per operation", () => {
  assert.equal(selectComputeBudgetV4({ operation: "agentSpend", aboveThreshold: false }), V4_BUDGET.SPEND_NO_APPROVALS);
  assert.equal(selectComputeBudgetV4({ operation: "agentSpend", aboveThreshold: true }), V4_BUDGET.SPEND_WITH_APPROVALS);
  for (const op of ["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause"]) {
    assert.equal(selectComputeBudgetV4({ operation: op }), V4_BUDGET.OWNER_OP);
  }
  assert.equal(selectComputeBudgetV4({ operation: "ownerRecover" }), V4_BUDGET.RECOVER);
});

test("E5: tiers dominate the measured production floors (23/26/25/132/22/14)", () => {
  assert.ok(V4_BUDGET.SPEND_NO_APPROVALS >= 26, "must cover measured agent12/recip0 = 26 and agent0/recip16 = 25");
  assert.ok(V4_BUDGET.SPEND_WITH_APPROVALS >= 132, "must cover the measured worst case 132");
  assert.ok(V4_BUDGET.OWNER_OP >= 22, "must cover measured ownerSetAgentRoot = 22");
  assert.ok(V4_BUDGET.RECOVER >= 14, "must cover measured ownerRecover = 14");
});

test("E5: fail closed — unknown operation, missing tier input, under-commit", () => {
  assert.throws(() => selectComputeBudgetV4({ operation: "delegateSpend" }), /unknown v0.4 operation/);
  assert.throws(() => selectComputeBudgetV4({ operation: "agentSpend" }), /aboveThreshold/);
  assert.throws(
    () => assertBudgetSufficientV4({ operation: "agentSpend", aboveThreshold: true, committed: V4_BUDGET.SPEND_WITH_APPROVALS - 1 }),
    /below the proven-safe minimum/
  );
  assert.equal(
    assertBudgetSufficientV4({ operation: "agentSpend", aboveThreshold: true, committed: V4_BUDGET.SPEND_WITH_APPROVALS }),
    V4_BUDGET.SPEND_WITH_APPROVALS
  );
});
