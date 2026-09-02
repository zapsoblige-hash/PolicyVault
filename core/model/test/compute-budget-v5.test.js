"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { selectComputeBudgetV5, assertBudgetSufficientV5, V5_BUDGET } = require("../compute-budget-v5");

/* Measured covering budgets (tests/vm/tests/v5_production.rs, 2026-09-01). */
const MEASURED = [
  { operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 1521, covering: 19 },
  { operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 1521, covering: 25 }, // depths 12/16
  { operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 2737, covering: 22 },
  { operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 5169, covering: 28 },
  { operation: "ownerPause", covering: 15 },
  { operation: "ownerRecover", templatePrefixLen: 1, templateSuffixLen: 1521, covering: 14 }
];

test("the model covers every measured production shape with headroom and scales with template size", () => {
  for (const m of MEASURED) {
    const b = selectComputeBudgetV5(m);
    assert.ok(b >= m.covering + 1, `${m.operation} suffix ${m.templateSuffixLen}: model ${b} must exceed measured ${m.covering}`);
  }
  assert.equal(selectComputeBudgetV5({ operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 1521 }), 28);
  assert.equal(selectComputeBudgetV5({ operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 9425 }), 47); // bound 15, the standardness limit
  assert.equal(selectComputeBudgetV5({ operation: "ownerSetAgentRoot" }), V5_BUDGET.OWNER_OP);
  assert.equal(selectComputeBudgetV5({ operation: "ownerRecover", templatePrefixLen: 1, templateSuffixLen: 1521 }), 17);
});

test("fail closed: unknown operation, missing geometry, under-commit", () => {
  assert.throws(() => selectComputeBudgetV5({ operation: "agentSpend" }), /unknown v0.5 operation/);
  assert.throws(() => selectComputeBudgetV5({ operation: "tokenAgentSpend" }), /geometry/);
  assert.throws(() => assertBudgetSufficientV5({ operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 1521, committed: 27 }), /below/);
  assert.equal(assertBudgetSufficientV5({ operation: "tokenAgentSpend", templatePrefixLen: 1, templateSuffixLen: 1521, committed: 28 }), 28);
});
