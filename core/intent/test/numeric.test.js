"use strict";

/*
 * UNIT — numeric + hex safety guards (core/intent/manifest.js).
 *
 * All consensus/accounting values are integer sompi: canonical base-10
 * digit strings in manifest JSON, BigInt in logic. Everything else —
 * floats, negatives, signs, exponents, decimals, non-canonical encodings
 * (leading zeros), unsafe integers, NaN/Infinity, BigInt-in-JSON,
 * malformed strings — is refused with VALUE_INVALID.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  MAX_SOMPI,
  parseAmount,
  parsePositiveAmount,
  requireInt,
  requireHex,
  validateStateShape,
  validateAgentPolicyShape
} = require("../manifest");
const { STATE_BEFORE, POLICY_BEFORE, clone } = require("../testutil/fixtures");

const refusesValue = (fn, label) => assert.throws(fn, (e) => e.code === "VALUE_INVALID", `${label} must refuse with VALUE_INVALID`);

test("parseAmount: canonical digit strings parse to exact BigInt", () => {
  assert.equal(parseAmount("0", "x"), 0n);
  assert.equal(parseAmount("1", "x"), 1n);
  assert.equal(parseAmount("50000000000", "x"), 50000000000n);
  assert.equal(parseAmount(MAX_SOMPI.toString(), "x"), MAX_SOMPI);
});

test("parseAmount: refuses every non-canonical / non-integer / non-string form", () => {
  const bad = [
    ["number", 5],
    ["float", 5.5],
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["-Infinity", -Infinity],
    ["negative number", -1],
    ["BigInt", 5n],
    ["null", null],
    ["undefined", undefined],
    ["object", { amount: "5" }],
    ["array", ["5"]],
    ["boolean", true],
    ["empty string", ""],
    ["leading space", " 5"],
    ["trailing space", "5 "],
    ["plus sign", "+5"],
    ["minus sign", "-5"],
    ["decimal point", "1.5"],
    ["exponent", "1e3"],
    ["hex prefix", "0x10"],
    ["leading zero", "05"],
    ["double zero", "00"],
    ["thousands separator", "1_000"],
    ["comma", "1,000"],
    ["arabic-indic digits", "٥٥"],
    ["devanagari digits", "५५"],
    ["whitespace only", "  "]
  ];
  for (const [label, value] of bad) {
    refusesValue(() => parseAmount(value, "x"), label);
  }
});

test("parseAmount: overflow beyond MAX_SOMPI is refused", () => {
  refusesValue(() => parseAmount((MAX_SOMPI + 1n).toString(), "x"), "MAX_SOMPI + 1");
  refusesValue(() => parseAmount("9".repeat(30), "x"), "30-digit overflow");
});

test("parsePositiveAmount: zero is refused, one is accepted", () => {
  assert.equal(parsePositiveAmount("1", "x"), 1n);
  refusesValue(() => parsePositiveAmount("0", "x"), "zero");
});

test("requireInt: structural integers only (indexes, budgets, versions)", () => {
  assert.equal(requireInt(0, "x"), 0);
  assert.equal(requireInt(65535, "x", { max: 0xffff }), 65535);
  const bad = [
    ["float", 1.5],
    ["negative", -1],
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["unsafe integer", 2 ** 53],
    ["digit string", "5"],
    ["null", null],
    ["BigInt", 5n]
  ];
  for (const [label, value] of bad) {
    refusesValue(() => requireInt(value, "x"), label);
  }
  refusesValue(() => requireInt(0x10000, "x", { max: 0xffff }), "computeBudget above u16");
});

test("requireHex: exact-width lowercase hex only", () => {
  const ok = "ab".repeat(32);
  assert.equal(requireHex(ok, 32, "x"), ok);
  const bad = [
    ["uppercase", "AB".repeat(32)],
    ["mixed case", "Ab" + "ab".repeat(31)],
    ["too short", "ab".repeat(31)],
    ["too long", "ab".repeat(33)],
    ["non-hex chars", "zz".repeat(32)],
    ["0x prefix", "0x" + "ab".repeat(31)],
    ["number", 171],
    ["null", null]
  ];
  for (const [label, value] of bad) {
    refusesValue(() => requireHex(value, 32, "x"), label);
  }
});

test("state shape: domain guards on every quantity", () => {
  assert.ok(validateStateShape(clone(STATE_BEFORE), "state"));
  const mutations = [
    ["zero protectedValue", (s) => { s.protectedValue = "0"; }],
    ["negative-form protectedValue", (s) => { s.protectedValue = "-1"; }],
    ["float feeReserve", (s) => { s.feeReserve = "1.5"; }],
    ["paused out of range", (s) => { s.paused = "2"; }],
    ["approvalM above 10", (s) => { s.approvalM = "11"; }],
    ["policyNonce above bound", (s) => { s.policyNonce = "1000000001"; }],
    ["non-canonical nonce", (s) => { s.policyNonce = "07" }]
  ];
  for (const [label, mutate] of mutations) {
    const s = clone(STATE_BEFORE);
    mutate(s);
    assert.throws(() => validateStateShape(s, "state"), (e) => e.code === "VALUE_INVALID" || e.code === "SCHEMA_INVALID", `${label} must refuse`);
  }
});

test("agent policy shape: positive-domain guards mirror the v0.4 leaf", () => {
  assert.ok(validateAgentPolicyShape(clone(POLICY_BEFORE), "policy"));
  const mutations = [
    ["zero maxPerSpend", (p) => { p.maxPerSpend = "0"; }],
    ["zero periodBudget", (p) => { p.periodBudget = "0"; }],
    ["zero periodLengthDaa", (p) => { p.periodLengthDaa = "0"; }],
    ["float periodSpent", (p) => { p.periodSpent = "1.0"; }],
    ["numeric approvalThreshold", (p) => { p.approvalThreshold = 1500000000; }],
    ["short agentPk", (p) => { p.agentPk = "22".repeat(31); }]
  ];
  for (const [label, mutate] of mutations) {
    const p = clone(POLICY_BEFORE);
    mutate(p);
    assert.throws(() => validateAgentPolicyShape(p, "policy"), (e) => e.code === "VALUE_INVALID", `${label} must refuse`);
  }
});
