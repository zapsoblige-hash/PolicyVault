"use strict";

/* UNIT layer — canonical amount parsing. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { parseSompi, parsePositiveSompi, kasToSompi, sompiToKas, SOMPI_PER_KAS } = require("../src/amounts");

test("parseSompi accepts digit strings and BigInt", () => {
  assert.equal(parseSompi("0"), 0n);
  assert.equal(parseSompi("12345678901234567"), 12345678901234567n);
  assert.equal(parseSompi(5n), 5n);
});

test("parseSompi rejects unsafe inputs", () => {
  for (const bad of [1.5, -1, "1.5", "-1", "1e8", "0x10", "", " 1", "NaN", "Infinity", null, undefined, {}, []]) {
    assert.throws(() => parseSompi(bad), /amounts:/, `should reject ${JSON.stringify(bad)}`);
  }
  assert.throws(() => parseSompi(-1n), /negative/);
  assert.throws(() => parseSompi(29_000_000_001n * SOMPI_PER_KAS), /maximum/);
});

test("parsePositiveSompi rejects zero", () => {
  assert.throws(() => parsePositiveSompi("0"), /greater than zero/);
  assert.equal(parsePositiveSompi("1"), 1n);
});

test("kasToSompi exact decimal handling", () => {
  assert.equal(kasToSompi("1"), 100_000_000n);
  assert.equal(kasToSompi("0.00000001"), 1n);
  assert.equal(kasToSompi("1.23456789"), 123_456_789n);
  assert.equal(kasToSompi("1000000"), 100_000_000_000_000n);
  assert.equal(kasToSompi("0.5"), 50_000_000n);
});

test("kasToSompi rejects malformed values", () => {
  for (const bad of ["1.234567891", "-1", "1e3", ".5", "1.", "1,5", "0x1", "", "one", "1.5.5"]) {
    assert.throws(() => kasToSompi(bad), /amounts:/, `should reject ${JSON.stringify(bad)}`);
  }
  assert.throws(() => kasToSompi(1.5), /string/);
});

test("sompiToKas canonical rendering", () => {
  assert.equal(sompiToKas(100_000_000n), "1");
  assert.equal(sompiToKas(1n), "0.00000001");
  assert.equal(sompiToKas(150_000_000n), "1.5");
  assert.equal(sompiToKas(0n), "0");
});

test("round trip", () => {
  for (const value of ["0.00000001", "1", "1.5", "123.45678901".slice(0, 10), "9999999.99999999"]) {
    assert.equal(sompiToKas(kasToSompi(value)), value);
  }
});
