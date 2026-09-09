"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const m = require("../compute-budget-v7-hd");

/* The exact required budgets tests/vm/tests/v7_hd_production.rs measured
 * under production sig-op pricing (2026-09-03 run). This module's output
 * must always be >= these, for both the shallow and deep shapes actually
 * measured. */
const MEASURED_REQUIRED = Object.freeze({
  hdSpend: { shallow: 40 },
  childSpendL2: { shallow: 41 },
  childSpendL3: { shallow: 41, deep: 54 },
  delegateSetChildRoot1: { shallow: 36 },
  delegateSetChildRoot2: { shallow: 36, deep: 41 }
});

test("selectHdComputeBudgetV7 is sufficient for every engine-measured shallow shape", () => {
  for (const [operation, required] of Object.entries(MEASURED_REQUIRED)) {
    const committed = m.selectHdComputeBudgetV7({ operation, atMaxDepth: false });
    assert.ok(committed >= required.shallow, `${operation} shallow: committed ${committed} must be >= measured-required ${required.shallow}`);
  }
});

test("selectHdComputeBudgetV7 (atMaxDepth) is sufficient for every engine-measured deep shape", () => {
  for (const [operation, required] of Object.entries(MEASURED_REQUIRED)) {
    if (required.deep === undefined) continue;
    const committed = m.selectHdComputeBudgetV7({ operation, atMaxDepth: true });
    assert.ok(committed >= required.deep, `${operation} deep: committed ${committed} must be >= measured-required ${required.deep}`);
  }
});

test("atMaxDepth defaults to true (the safe default for an unknown proof depth)", () => {
  const shallowExplicit = m.selectHdComputeBudgetV7({ operation: "childSpendL3", atMaxDepth: false });
  const deepDefault = m.selectHdComputeBudgetV7({ operation: "childSpendL3" });
  assert.ok(deepDefault >= shallowExplicit);
});

test("unknown operation fails closed", () => {
  assert.throws(() => m.selectHdComputeBudgetV7({ operation: "tokenAgentSpend" }), (e) => e.code === "UNKNOWN_OPERATION");
});

test("assertHdBudgetSufficientV7 accepts a covering budget and rejects an under-committed one", () => {
  const required = m.selectHdComputeBudgetV7({ operation: "hdSpend", atMaxDepth: true });
  assert.equal(m.assertHdBudgetSufficientV7({ operation: "hdSpend", atMaxDepth: true, committed: required }), required);
  assert.throws(() => m.assertHdBudgetSufficientV7({ operation: "hdSpend", atMaxDepth: true, committed: required - 1 }), /below the proven-safe minimum/);
});

test("every SPEND_OPS / DELEGATION_OPS entry has a shallow-units constant and the two sets are disjoint", () => {
  for (const op of [...m.SPEND_OPS, ...m.DELEGATION_OPS]) {
    assert.ok(m.SHALLOW_UNITS[op] !== undefined, `${op} missing from SHALLOW_UNITS`);
  }
  const overlap = m.SPEND_OPS.filter((op) => m.DELEGATION_OPS.includes(op));
  assert.deepEqual(overlap, []);
});
