"use strict";

/*
 * UNIT — v0.7 compute budgets. Every committed budget must COVER the
 * engine-measured requirement of docs/postlaunch/v0.7-organizational-root-design.md
 * §12.3, computed with rusty-kaspa's own charging rule
 * (ComputeBudget::checked_covering_script_units). Sufficiency on real bytes is
 * proven separately by tests/vm/tests/v7_sdk_integration.rs; this suite pins
 * the MODEL so an accidental constant change fails here first.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  V7_BUDGET,
  UNITS_PER_BUDGET,
  SIGOP_UNITS,
  ROOT_TEMPLATE_REFERENCE_BYTES,
  requiredBudgetForUnits,
  rootScriptUnits,
  selectRootComputeBudgetV7,
  selectComputeBudgetV7,
  selectTokenInputBudgetV7,
  assertBudgetSufficientV7,
  assertRootBudgetSufficientV7
} = require("../compute-budget-v7");

/* Measured PRICED units -> the budget rusty-kaspa would require (§12.3). */
const MEASURED_ROOT = [
  { label: "ROTATE 12-of-12", actionName: "rotate", activeOwnerSlots: 12, priced: 1_339_272, required: 133 },
  { label: "AUTHORIZE 2-of-3", actionName: "authorize", activeOwnerSlots: 3, priced: 397_182, required: 39 },
  { label: "FREEZE K=1 (3 active)", actionName: "freeze", activeOwnerSlots: 3, priced: 397_184, required: 39 },
  { label: "OWNER-RECOVER (4 active)", actionName: "ownerRecover", activeOwnerSlots: 4, priced: 502_295, required: 50 },
  { label: "SUCCESSION", actionName: "succession", activeOwnerSlots: 3, priced: 177_665, required: 17 },
  { label: "root input inside a vault op (3 active)", actionName: "authorize", activeOwnerSlots: 3, priced: 97_192 + 3 * SIGOP_UNITS, required: 39 }
];

/* The measured AUTHORIZE threshold sweep: UNPRICED script units by active slots. */
const SWEEP_SCRIPT_UNITS = [87_532, 92_421, 97_182, 101_813, 106_314, 110_685, 114_943, 119_058, 123_043, 126_898, 130_623, 134_217];

const ROOT_GEOMETRY = { rootPrefixLen: 1, rootSuffixLen: 11_077 };
const TOKEN_GEOMETRY = { templatePrefixLen: 1, templateSuffixLen: 1_521 };

test("the charging rule matches rusty-kaspa's ComputeBudget::checked_covering_script_units", () => {
  assert.equal(UNITS_PER_BUDGET, 10_000);
  assert.equal(requiredBudgetForUnits(0), 0);
  assert.equal(requiredBudgetForUnits(9_999), 0);
  assert.equal(requiredBudgetForUnits(10_000), 1);
  assert.equal(requiredBudgetForUnits(19_999), 1);
  assert.equal(requiredBudgetForUnits(20_000), 2);
  for (const row of MEASURED_ROOT) {
    assert.equal(requiredBudgetForUnits(row.priced), row.required, `${row.label}: the design's measured budget must be reproducible from its priced units`);
  }
});

test("the root script-unit model is an UPPER BOUND at every measured threshold", () => {
  SWEEP_SCRIPT_UNITS.forEach((measured, i) => {
    const modelled = rootScriptUnits({ activeOwnerSlots: i + 1, wfNew: false });
    assert.ok(modelled >= measured, `${i + 1} active slots: model ${modelled} must cover the measured ${measured}`);
    assert.ok(modelled - measured < 8_000, `${i + 1} active slots: model ${modelled} is wastefully above ${measured}`);
  });
  /* WF(new) paths measured at +5,055 (rotate, 12 active) and +5,113 (recover, 4 active) */
  assert.ok(rootScriptUnits({ activeOwnerSlots: 12, wfNew: true }) >= 139_272);
  assert.ok(rootScriptUnits({ activeOwnerSlots: 4, wfNew: true }) >= 102_295);
});

test("every committed root budget covers the engine-measured requirement", () => {
  for (const row of MEASURED_ROOT) {
    const committed = selectRootComputeBudgetV7({ actionName: row.actionName, activeOwnerSlots: row.activeOwnerSlots });
    assert.ok(committed >= row.required, `${row.label}: committed ${committed} < required ${row.required}`);
    assert.ok(committed <= row.required + 20, `${row.label}: committed ${committed} is far above the required ${row.required}`);
    assertRootBudgetSufficientV7({ actionName: row.actionName, activeOwnerSlots: row.activeOwnerSlots, committed });
  }
  /* the priced cost scales with ACTIVE slots, not with the threshold */
  assert.ok(selectRootComputeBudgetV7({ actionName: "authorize", activeOwnerSlots: 12 }) > selectRootComputeBudgetV7({ actionName: "authorize", activeOwnerSlots: 3 }));
});

test("every committed rooted-vault budget covers the engine-measured requirement", () => {
  const measured = [
    { operation: "ownerSetAgentRoot", units: 299_534 },
    { operation: "ownerTopUpReserve", units: 299_601 },
    { operation: "ownerPause", units: 299_606 },
    { operation: "ownerUnpause", units: 299_604 },
    { operation: "ownerEmergencyPause", units: 299_607 },
    { operation: "ownerRecover", units: 284_373 }
  ];
  for (const row of measured) {
    const committed = selectComputeBudgetV7({ operation: row.operation, ...ROOT_GEOMETRY, ...TOKEN_GEOMETRY });
    const required = requiredBudgetForUnits(row.units);
    assert.ok(committed >= required, `${row.operation}: committed ${committed} < required ${required}`);
    assertBudgetSufficientV7({ operation: row.operation, ...ROOT_GEOMETRY, ...TOKEN_GEOMETRY, committed });
  }
  /* delegate spend: 100,390 script units + one sig-op; deep proofs 152,713 + one */
  const spend = selectComputeBudgetV7({ operation: "tokenAgentSpend", ...TOKEN_GEOMETRY });
  assert.ok(spend >= requiredBudgetForUnits(100_390 + SIGOP_UNITS));
  assert.ok(spend >= requiredBudgetForUnits(152_713 + SIGOP_UNITS), "the committed budget must cover the production proof depths 12/16");
});

test("budgets scale with the pinned root template size and fail closed on unknowns", () => {
  const base = selectComputeBudgetV7({ operation: "ownerPause", ...ROOT_GEOMETRY, ...TOKEN_GEOMETRY });
  const bigger = selectComputeBudgetV7({ operation: "ownerPause", rootPrefixLen: 1, rootSuffixLen: ROOT_TEMPLATE_REFERENCE_BYTES + 4_000, ...TOKEN_GEOMETRY });
  assert.ok(bigger > base, "a larger pinned root template costs more to slice and rebuild");
  assert.equal(V7_BUDGET.ORDINARY_INPUT, 10);
  assert.ok(selectTokenInputBudgetV7({ ...TOKEN_GEOMETRY }) >= 4);
  assert.ok(selectTokenInputBudgetV7({ ...TOKEN_GEOMETRY, signerOwned: true }) > selectTokenInputBudgetV7({ ...TOKEN_GEOMETRY }));

  assert.throws(() => selectRootComputeBudgetV7({ actionName: "dissolve", activeOwnerSlots: 3 }), /unknown v0.7 root action/);
  assert.throws(() => selectRootComputeBudgetV7({ actionName: "authorize", activeOwnerSlots: 13 }), /activeOwnerSlots/);
  assert.throws(() => selectRootComputeBudgetV7({ actionName: "authorize", activeOwnerSlots: 0 }), /activeOwnerSlots/);
  assert.throws(() => selectComputeBudgetV7({ operation: "delegateSpend", ...TOKEN_GEOMETRY }), /unknown v0.7 rooted-vault operation/);
  assert.throws(() => selectComputeBudgetV7({ operation: "ownerPause", ...TOKEN_GEOMETRY }), /root template geometry/);
  assert.throws(() => assertBudgetSufficientV7({ operation: "ownerPause", ...ROOT_GEOMETRY, ...TOKEN_GEOMETRY, committed: 1 }), /below the proven-safe minimum/);
  assert.throws(() => assertRootBudgetSufficientV7({ actionName: "authorize", activeOwnerSlots: 3, committed: 1 }), /below the proven-safe minimum/);
});
