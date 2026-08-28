"use strict";

/*
 * UNIT tests — risk adapter contract validation (Program D core).
 * Layer: UNIT (pure validation, no I/O).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  RISK_ADAPTER_CONTRACT_VERSION,
  RISK_VERDICTS,
  VERDICT_ALLOW,
  VERDICT_DENY,
  RiskRefusal,
  requireJsonSafe,
  validateAdapterDefinition,
  validateVerdictResult,
  createAdapterRegistry
} = require("../interface");

function refusalCode(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof RiskRefusal, `expected RiskRefusal, got ${err && err.name}: ${err && err.message}`);
    assert.equal(err.failClosed, true);
    return err.code;
  }
  assert.fail("expected a fail-closed refusal");
}

function validDef(overrides = {}) {
  return {
    name: "test-adapter",
    adapterVersion: "1.0.0",
    contractVersion: RISK_ADAPTER_CONTRACT_VERSION,
    capabilities: ["sanctions"],
    evaluate: async () => ({ verdict: VERDICT_ALLOW, reasons: [] }),
    ...overrides
  };
}

test("verdict vocabulary is exactly ALLOW | REVIEW | DENY", () => {
  assert.deepEqual([...RISK_VERDICTS], ["ALLOW", "REVIEW", "DENY"]);
  assert.ok(Object.isFrozen(RISK_VERDICTS));
});

test("a valid adapter definition normalizes and freezes", () => {
  const def = validateAdapterDefinition(validDef());
  assert.equal(def.name, "test-adapter");
  assert.equal(def.contractVersion, RISK_ADAPTER_CONTRACT_VERSION);
  assert.ok(Object.isFrozen(def));
  assert.ok(Object.isFrozen(def.capabilities));
});

test("unknown adapter contract versions refuse at registration", () => {
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ contractVersion: "policyvault-risk-adapter/2" }))), "ADAPTER_CONTRACT_UNKNOWN");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ contractVersion: undefined }))), "ADAPTER_CONTRACT_UNKNOWN");
});

test("malformed adapter definitions refuse", () => {
  assert.equal(refusalCode(() => validateAdapterDefinition(null)), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ name: "Bad Name" }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ adapterVersion: "" }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ capabilities: [] }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ evaluate: "not-a-function" }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ extraField: true }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ timeoutMs: 0 }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ timeoutMs: 1.5 }))), "ADAPTER_DEFINITION_INVALID");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ timeoutMs: 10_000_000 }))), "ADAPTER_DEFINITION_INVALID");
});

test("unknown capabilities refuse; x- extensions are permitted", () => {
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ capabilities: ["telepathy"] }))), "ADAPTER_CAPABILITY_UNKNOWN");
  assert.equal(refusalCode(() => validateAdapterDefinition(validDef({ capabilities: [42] }))), "ADAPTER_CAPABILITY_UNKNOWN");
  const def = validateAdapterDefinition(validDef({ capabilities: ["x-internal-screening", "erp"] }));
  assert.deepEqual([...def.capabilities], ["x-internal-screening", "erp"]);
});

test("verdict results validate strictly; unknown verdicts refuse", () => {
  const ok = validateVerdictResult({ verdict: VERDICT_ALLOW, reasons: [] }, "a");
  assert.equal(ok.verdict, VERDICT_ALLOW);
  assert.ok(Object.isFrozen(ok));

  const deny = validateVerdictResult({ verdict: VERDICT_DENY, reasons: [{ code: "SANCTIONS_HIT", message: "listed address", evidence: { list: "x" } }] }, "a");
  assert.equal(deny.reasons[0].code, "SANCTIONS_HIT");

  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "PERMIT", reasons: [] }, "a")), "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "allow", reasons: [] }, "a")), "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: undefined, reasons: [] }, "a")), "ADAPTER_VERDICT_UNKNOWN");
  assert.equal(refusalCode(() => validateVerdictResult("ALLOW", "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: VERDICT_ALLOW }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: VERDICT_ALLOW, reasons: "none" }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: VERDICT_ALLOW, reasons: [], extra: 1 }, "a")), "ADAPTER_VERDICT_INVALID");
});

test("a restrictive verdict without a structured reason refuses", () => {
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [] }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "REVIEW", reasons: [] }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [{ code: "bad code!", message: "x" }] }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [{ code: "X", message: "" }] }, "a")), "ADAPTER_VERDICT_INVALID");
  assert.equal(refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [{ code: "X", message: "m", surprise: 1 }] }, "a")), "ADAPTER_VERDICT_INVALID");
});

test("verdict evidence must be JSON-safe (BigInt refuses — amounts travel as decimal strings)", () => {
  assert.equal(
    refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [{ code: "X", message: "m", evidence: { amount: 5n } }] }, "a")),
    "JSON_UNSAFE"
  );
  assert.equal(
    refusalCode(() => validateVerdictResult({ verdict: "DENY", reasons: [{ code: "X", message: "m", evidence: { score: NaN } }] }, "a")),
    "JSON_UNSAFE"
  );
  const ok = validateVerdictResult({ verdict: "DENY", reasons: [{ code: "X", message: "m", evidence: { amountSompi: "5", score: 0.93 } }] }, "a");
  assert.equal(ok.reasons[0].evidence.amountSompi, "5");
});

test("requireJsonSafe walks nested structures and fails closed", () => {
  requireJsonSafe({ a: [{ b: "1", c: null, d: true }] }, "x");
  assert.equal(refusalCode(() => requireJsonSafe({ a: [1n] }, "x")), "JSON_UNSAFE");
  assert.equal(refusalCode(() => requireJsonSafe({ a: undefined }, "x")), "JSON_UNSAFE");
  assert.equal(refusalCode(() => requireJsonSafe({ a: new Date(0) }, "x")), "JSON_UNSAFE");
  assert.equal(refusalCode(() => requireJsonSafe({ a: () => {} }, "x")), "JSON_UNSAFE");
});

test("adapter registry keeps order, refuses duplicates", () => {
  const reg = createAdapterRegistry();
  reg.register(validDef({ name: "first" }));
  reg.register(validDef({ name: "second" }));
  assert.equal(reg.size(), 2);
  assert.deepEqual(reg.list().map((d) => d.name), ["first", "second"]);
  assert.ok(Object.isFrozen(reg.list()));
  assert.equal(reg.get("first").name, "first");
  assert.equal(refusalCode(() => reg.register(validDef({ name: "first" }))), "ADAPTER_DUPLICATE");
});
