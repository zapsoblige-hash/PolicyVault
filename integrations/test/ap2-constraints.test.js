"use strict";

/*
 * UNIT / ADVERSARIAL — restrictive-only constraint evaluation (spec §3.5
 * + A-30): every constraint type's DENY path, unknown/unparseable ⇒
 * DENY (never ALLOW), deny-wins composition, budget/recurrence
 * accounting semantics, line-items REVIEW.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { evaluateConstraints } = require("../ap2/constraints");

const CTX = Object.freeze({
  payAmountSompi: "250000000",
  payeeId: "merchant-1",
  instrumentHandle: "instr-1",
  transactionId: "T".repeat(43),
  currencyLiteral: "KAS",
  nowSeconds: 1_000_000,
  accounting: { consumedSompi: "0", occurrenceCount: 0 }
});

function evaluate(constraints, ctxOverrides = {}) {
  return evaluateConstraints(
    constraints.map((c) => ({ type: typeof c.type === "string" ? c.type : null, value: c })),
    { ...CTX, ...ctxOverrides }
  );
}

test("A-30 headline: unknown constraint types DENY; unparseable values DENY; an evaluator can never resolve permissive", () => {
  assert.equal(evaluate([{ type: "payment.future_thing", x: 1 }]).decision, "DENY");
  assert.equal(evaluate([{ type: "payment.future_thing", x: 1 }]).codes[0], "AP2_CONSTRAINT_UNKNOWN");
  assert.equal(evaluate([{ type: "payment.amount_range", min: "not-a-number" }]).codes[0], "AP2_CONSTRAINT_UNREADABLE");
  assert.equal(evaluate([{ type: "payment.amount_range" }]).codes[0], "AP2_CONSTRAINT_UNREADABLE"); // no bounds at all
  assert.equal(evaluate([{ no_type: true }]).codes[0], "AP2_CONSTRAINT_UNREADABLE");
  assert.equal(evaluate([{ type: "payment.amount_range", min: 1, max: 10, extra_knob: 1 }]).codes[0], "AP2_CONSTRAINT_UNREADABLE");
});

test("amount_range: inside passes, outside DENYs (both bounds)", () => {
  assert.equal(evaluate([{ type: "payment.amount_range", min: 1, max: 250000000 }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "payment.amount_range", max: 249999999 }]).codes[0], "AP2_AMOUNT_OUT_OF_RANGE");
  assert.equal(evaluate([{ type: "payment.amount_range", min: 250000001 }]).codes[0], "AP2_AMOUNT_OUT_OF_RANGE");
});

test("budget: cumulative accounting DENYs the payment that would cross the limit; a foreign-currency budget never allows", () => {
  const budget = { type: "payment.budget", amount: 500000000, currency: "KAS" };
  assert.equal(evaluate([budget]).decision, "ALLOW");
  assert.equal(evaluate([budget], { accounting: { consumedSompi: "250000001", occurrenceCount: 1 } }).codes[0], "AP2_MANDATE_BUDGET_EXCEEDED");
  assert.equal(evaluate([budget], { accounting: { consumedSompi: "250000000", occurrenceCount: 1 } }).decision, "ALLOW"); // exactly at the limit
  assert.equal(evaluate([{ type: "payment.budget", amount: 10 ** 15, currency: "USD" }]).codes[0], "AP2_CONSTRAINT_UNREADABLE");
});

test("allowed_payees / allowed_payment_instruments / allowed_merchants: membership by exact id; absence from the set DENYs", () => {
  assert.equal(evaluate([{ type: "payment.allowed_payees", allowed: ["merchant-1", { id: "merchant-2" }] }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "payment.allowed_payees", allowed: ["merchant-2"] }]).codes[0], "AP2_PAYEE_NOT_IN_MANDATE");
  assert.equal(evaluate([{ type: "payment.allowed_payees", allowed: [] }]).codes[0], "AP2_CONSTRAINT_UNREADABLE"); // empty set: unreadable, not permissive
  assert.equal(evaluate([{ type: "payment.allowed_payment_instruments", allowed: ["instr-1"] }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "payment.allowed_payment_instruments", allowed: ["other"] }]).codes[0], "AP2_INSTRUMENT_NOT_IN_MANDATE");
  assert.equal(evaluate([{ type: "checkout.allowed_merchants", allowed: [{ id: "merchant-1", name: "M1" }] }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "checkout.allowed_merchants", allowed: [{ id: "other" }] }]).codes[0], "AP2_MERCHANT_NOT_ALLOWED");
});

test("allowed_pisps always DENYs — PolicyVault is never a PISP", () => {
  assert.equal(evaluate([{ type: "payment.allowed_pisps", allowed: ["some-pisp"] }]).codes[0], "AP2_PISP_UNSUPPORTED");
});

test("agent_recurrence: occurrence limit enforced from adapter-side accounting", () => {
  const rec = { type: "payment.agent_recurrence", max_occurrences: 2 };
  assert.equal(evaluate([rec], { accounting: { consumedSompi: "0", occurrenceCount: 1 } }).decision, "ALLOW");
  assert.equal(evaluate([rec], { accounting: { consumedSompi: "0", occurrenceCount: 2 } }).codes[0], "AP2_RECURRENCE_EXCEEDED");
});

test("execution_date: outside the window DENYs (both directions)", () => {
  assert.equal(evaluate([{ type: "payment.execution_date", not_before: 999999, not_after: 1000001 }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "payment.execution_date", not_before: 1000001 }]).codes[0], "AP2_EXECUTION_WINDOW");
  assert.equal(evaluate([{ type: "payment.execution_date", not_after: 999999 }]).codes[0], "AP2_EXECUTION_WINDOW");
});

test("A-17: reference linkage mismatch DENYs (superseded open mandate cannot bless a different checkout)", () => {
  assert.equal(evaluate([{ type: "payment.reference", conditional_transaction_id: "T".repeat(43) }]).decision, "ALLOW");
  assert.equal(evaluate([{ type: "payment.reference", conditional_transaction_id: "X".repeat(43) }]).codes[0], "AP2_REFERENCE_MISMATCH");
});

test("A-11: line items disagreeing with payment_amount are REVIEW — never a different paid amount; unreadable items DENY", () => {
  const match = evaluate([{ type: "checkout.line_items", items: [{ id: "i1", title: "t", price: 250000000, currency: "KAS" }] }]);
  assert.equal(match.decision, "ALLOW");
  const mismatch = evaluate([{ type: "checkout.line_items", items: [{ price: 100, currency: "KAS" }] }]);
  assert.equal(mismatch.decision, "REVIEW");
  assert.equal(mismatch.codes[0], "AP2_LINE_ITEMS_MISMATCH");
  const foreign = evaluate([{ type: "checkout.line_items", items: [{ price: 199, currency: "USD" }] }]);
  assert.equal(foreign.decision, "REVIEW"); // not comparable: a human question, never a conversion
  const unreadable = evaluate([{ type: "checkout.line_items", items: [{ price: "1.99", currency: "USD" }] }]);
  assert.equal(unreadable.decision, "DENY");
});

test("deny-wins composition: DENY beats REVIEW beats ALLOW regardless of order; all codes are surfaced", () => {
  const out = evaluate([
    { type: "checkout.line_items", items: [{ price: 1, currency: "KAS" }] }, // REVIEW
    { type: "payment.amount_range", min: 1, max: 250000000 }, // ALLOW
    { type: "payment.allowed_payees", allowed: ["someone-else"] } // DENY
  ]);
  assert.equal(out.decision, "DENY");
  assert.deepEqual(out.codes.sort(), ["AP2_LINE_ITEMS_MISMATCH", "AP2_PAYEE_NOT_IN_MANDATE"].sort());
  assert.equal(out.evaluated.length, 3);
});

test("the floor never moves: a mandate LOOSER than the covenant grants nothing (no permissive output exists to grant it)", () => {
  // amount_range up to 500 KAS while the covenant cap may be far lower:
  // the evaluator's only possible verdicts are ALLOW (no objection),
  // REVIEW, DENY — there is no output that could widen anything.
  const out = evaluate([{ type: "payment.amount_range", min: 1, max: 50000000000 }]);
  assert.equal(out.decision, "ALLOW");
  assert.ok(["ALLOW", "REVIEW", "DENY"].includes(out.decision));
});
