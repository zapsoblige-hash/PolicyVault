"use strict";

/*
 * Amount gates for protocol-inbound values (x402 §3.3 / AP2 §3.3).
 *
 * MAX_SOMPI comes from the canonical numeric-safety module (re-exported
 * unchanged by `sdk/src/amounts.js`); the adapters never define their own
 * supply constant and never touch floating point. The x402 canonical
 * digit-string grammar is DELIBERATELY stricter than parseSompi (which
 * tolerates leading zeros): one value must have exactly one encoding,
 * because digests are functions of encodings.
 */

const { MAX_SOMPI, sompiToKas } = require("../../sdk/src/amounts");

/* ^(0|[1-9][0-9]*)$ — ASCII digits, no sign, no decimal point, no
 * exponent, no whitespace, no leading zeros (intent-manifest canonical
 * amount encoding). */
const CANONICAL_SOMPI_RE = /^(0|[1-9][0-9]*)$/;

class AmountError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AmountError";
    this.code = code;
  }
}

/*
 * x402 amount: the inbound value MUST already be a JSON string in the
 * canonical sompi encoding. Atomic unit == sompi, identity mapping — the
 * adapter performs no unit conversion, no decimal parsing, no rounding,
 * and no currency conversion, ever. Returns the canonical digit string.
 */
function requireCanonicalSompiString(value, { code = "AMOUNT_INVALID", field = "amount" } = {}) {
  if (typeof value !== "string") {
    throw new AmountError(code, `${field} must be a JSON string of canonical sompi digits — got ${value === null ? "null" : typeof value}`);
  }
  if (!CANONICAL_SOMPI_RE.test(value)) {
    throw new AmountError(code, `${field} is not canonical sompi digits (^(0|[1-9][0-9]*)$) — refusing`);
  }
  const amount = BigInt(value);
  if (amount <= 0n) throw new AmountError(code, `${field} must be > 0 — an agentSpend pays a positive amount`);
  if (amount > MAX_SOMPI) throw new AmountError(code, `${field} exceeds MAX_SOMPI — refusing`);
  return value;
}

/*
 * AP2 amount: `payment_amount.amount` is a JSON integer in MINOR UNITS;
 * minor unit == sompi by declaration of the pinned Kaspa payment
 * instrument. The LEXICAL token (from the strict parser) must be a plain
 * integer — `1.0`, `1e8`, `-0`, `007` are refusals even where their
 * numeric value would be representable. Returns the canonical digit
 * string (the identity re-encoding of the integer).
 */
function requireSafeMinorUnitsInteger(value, lexicalToken, { code = "AMOUNT_INVALID", field = "payment_amount.amount" } = {}) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new AmountError(code, `${field} must be a JSON integer (safe range) — refusing`);
  }
  if (typeof lexicalToken !== "string" || !/^(0|[1-9][0-9]*)$/.test(lexicalToken)) {
    throw new AmountError(code, `${field} numeric token ${JSON.stringify(lexicalToken ?? null)} is not a plain unsigned integer — refusing`);
  }
  if (value <= 0) throw new AmountError(code, `${field} must be >= 1`);
  const canonical = String(value);
  if (canonical !== lexicalToken) {
    throw new AmountError(code, `${field} token is not canonical (${lexicalToken} != ${canonical}) — refusing`);
  }
  const amount = BigInt(canonical);
  if (amount > MAX_SOMPI) throw new AmountError(code, `${field} exceeds MAX_SOMPI — refusing`);
  return canonical;
}

module.exports = { AmountError, CANONICAL_SOMPI_RE, MAX_SOMPI, sompiToKas, requireCanonicalSompiString, requireSafeMinorUnitsInteger };
