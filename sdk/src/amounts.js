"use strict";

/*
 * Canonical KAS <-> sompi conversion.
 *
 * All consensus/accounting values are BigInt sompi. Floating point is
 * forbidden on every funds path. Parsers fail closed on anything that is
 * not an exact, in-range, well-formed amount.
 */

const SOMPI_PER_KAS = 100_000_000n;

/* Kaspa max supply ~28.7B KAS; use a generous hard ceiling for sanity. */
const MAX_SOMPI = 29_000_000_000n * SOMPI_PER_KAS;

function fail(message) {
  throw new Error(`amounts: ${message}`);
}

/*
 * Parse a decimal-string sompi amount into BigInt.
 * Accepts BigInt directly. Rejects numbers (floating-point risk).
 */
function parseSompi(value, field = "amount") {
  let amount;

  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!/^\d+$/.test(value)) {
      fail(`${field} must be a base-10 digit string, got ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    fail(`${field} must be a BigInt or decimal string, got ${typeof value}`);
  }

  if (amount < 0n) {
    fail(`${field} must not be negative`);
  }
  if (amount > MAX_SOMPI) {
    fail(`${field} exceeds maximum representable sompi`);
  }

  return amount;
}

function parsePositiveSompi(value, field = "amount") {
  const amount = parseSompi(value, field);
  if (amount === 0n) {
    fail(`${field} must be greater than zero`);
  }
  return amount;
}

/*
 * Parse a human KAS decimal string ("12", "0.5", "1.23456789") into
 * BigInt sompi. Max 8 fractional digits, no exponents, no signs, no
 * floats.
 */
function kasToSompi(value, field = "amount") {
  if (typeof value !== "string") {
    fail(`${field} must be a string KAS amount, got ${typeof value}`);
  }
  const match = /^(\d+)(?:\.(\d{1,8}))?$/.exec(value.trim());
  if (!match) {
    fail(`${field} is not a valid KAS decimal string: ${JSON.stringify(value)}`);
  }
  const whole = BigInt(match[1]);
  const fracDigits = match[2] ?? "";
  const frac = BigInt(fracDigits.padEnd(8, "0") || "0");
  const amount = whole * SOMPI_PER_KAS + frac;
  if (amount > MAX_SOMPI) {
    fail(`${field} exceeds maximum representable sompi`);
  }
  return amount;
}

/*
 * Render BigInt sompi as a canonical KAS decimal string with trailing
 * zeros trimmed ("1.5", "0.00000001", "12").
 */
function sompiToKas(value, field = "amount") {
  const amount = parseSompi(value, field);
  const whole = amount / SOMPI_PER_KAS;
  const frac = amount % SOMPI_PER_KAS;
  if (frac === 0n) {
    return whole.toString();
  }
  const fracStr = frac.toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

module.exports = {
  SOMPI_PER_KAS,
  MAX_SOMPI,
  parseSompi,
  parsePositiveSompi,
  kasToSompi,
  sompiToKas
};
