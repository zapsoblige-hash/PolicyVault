"use strict";

/*
 * UNIT — exact sompi -> KAS rendering (core/explain/kas.js).
 *
 * The renderer mirrors sdk/src/amounts.js sompiToKas semantics (integer
 * division, 8-decimal zero-padded fraction, trailing zeros trimmed)
 * with strict canonical input and the i64 domain. Golden vectors are
 * hand-computed integer arithmetic; adversarial display cases prove the
 * integer path (never floating point) and the refusal of every
 * malformed encoding.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { sompiToKasString, kasAmount, parseCanonicalSompi, I64_MAX, SOMPI_PER_KAS } = require("../kas");

test("kas: adversarial display case — 1000000000 sompi renders as exactly '10' KAS (integer path)", () => {
  assert.equal(sompiToKasString("1000000000"), "10");
  assert.equal(sompiToKasString(1000000000n), "10");
});

test("kas: golden rendering vectors (exact, trailing zeros trimmed, never rounded)", () => {
  const vectors = [
    ["0", "0"],
    ["1", "0.00000001"],
    ["10", "0.0000001"],
    ["100000000", "1"],
    ["125000000", "1.25"],
    ["150000000", "1.5"],
    ["100000001", "1.00000001"],
    ["5000", "0.00005"],
    ["99999999", "0.99999999"],
    ["49099995000", "490.99995"],
    ["2000000000", "20"],
    ["2900000000000000000", "29000000000"], // the SDK MAX_SOMPI supply ceiling
    [I64_MAX.toString(), "92233720368.54775807"] // i64 num8 bound (governance domain)
  ];
  for (const [sompi, kas] of vectors) {
    assert.equal(sompiToKasString(sompi), kas, `sompi ${sompi}`);
  }
});

test("kas: kasAmount returns the exact {sompi, kas} pair", () => {
  assert.deepEqual(kasAmount("125000000"), { sompi: "125000000", kas: "1.25" });
  assert.deepEqual(kasAmount(0n), { sompi: "0", kas: "0" });
});

test("kas: precision floats would corrupt is preserved exactly", () => {
  // 2^53-scale values where Number arithmetic loses integer precision.
  const sompi = "9007199254740993"; // 2^53 + 1 — not representable as a JS number
  assert.equal(sompiToKasString(sompi), "90071992.54740993");
  const roundTrip = parseCanonicalSompi(sompi);
  assert.equal(roundTrip.toString(), sompi);
});

test("kas: malformed inputs refuse (fail closed, VALUE_INVALID)", () => {
  const bad = [
    "", // empty
    "01", // leading zero — one value, one encoding
    "00", // non-canonical zero
    "1.5", // decimals are KAS-form, not sompi
    "-1", // sign
    "+1",
    " 1", // whitespace
    "1 ",
    "1e8", // exponent
    "0x10", // hex
    "١٢٣", // non-ASCII digits
    "10n"
  ];
  for (const value of bad) {
    assert.throws(() => sompiToKasString(value), (e) => e.code === "VALUE_INVALID", `must refuse ${JSON.stringify(value)}`);
  }
});

test("kas: JS numbers, negatives, and non-string types refuse (floating-point risk)", () => {
  for (const value of [10, 1.5, NaN, Infinity, -1, null, undefined, {}, [], true]) {
    assert.throws(() => sompiToKasString(value), (e) => e.code === "VALUE_INVALID", `must refuse ${typeof value} ${String(value)}`);
  }
  assert.throws(() => sompiToKasString(-1n), (e) => e.code === "VALUE_INVALID", "negative BigInt refuses");
});

test("kas: values above the i64 encoding domain refuse", () => {
  assert.throws(() => sompiToKasString(I64_MAX + 1n), (e) => e.code === "VALUE_INVALID");
  assert.throws(() => sompiToKasString((I64_MAX + 1n).toString()), (e) => e.code === "VALUE_INVALID");
  assert.equal(sompiToKasString(I64_MAX), "92233720368.54775807"); // the bound itself renders
});

test("kas: SOMPI_PER_KAS is the canonical 1e8 BigInt", () => {
  assert.equal(SOMPI_PER_KAS, 100000000n);
});
