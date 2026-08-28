"use strict";

/*
 * Exact integer sompi -> KAS decimal rendering for the explanation layer.
 *
 * MIRRORS the semantics of sdk/src/amounts.js `sompiToKas` (whole =
 * amount / 1e8; fraction = amount % 1e8 zero-padded to 8 digits with
 * trailing zeros trimmed; no fraction part when it is zero) WITHOUT
 * importing it: core/explain is a portable shared-core module with zero
 * SDK/server imports. sdk/src/amounts.js is itself pure (BigInt-only
 * integer math, no I/O), so the coordinator MAY later wire the SDK
 * implementation in its place inside SDK-resident code paths; the
 * rendered strings are identical over the shared domain by construction
 * (asserted by golden vectors in core/explain/test/kas.test.js).
 *
 * Differences from the SDK helper, both deliberate and both STRICTER or
 * WIDER in a fail-closed-compatible way:
 *   - INPUT is canonical only: a BigInt, or a base-10 digit string with
 *     no leading zeros ("0" or [1-9][0-9]*). The SDK parser tolerates
 *     leading zeros; explanation inputs come from manifests/delta
 *     results where one value has exactly one encoding, so a
 *     non-canonical encoding here is evidence of tampering or a wrong
 *     pipeline and REFUSES.
 *   - DOMAIN is 0..I64_MAX (2^63-1), the num8 consensus encoding bound
 *     used by core/governance, which is a superset of the SDK's
 *     MAX_SOMPI supply ceiling (2.9e18 < 2^63-1). Intent-manifest
 *     amounts are already bounded to MAX_SOMPI upstream by
 *     core/intent validateManifest; governance delta values may
 *     legitimately reach the i64 bound.
 *
 * NUMERIC SAFETY: BigInt integer math only. JS numbers are refused on
 * every path (floating point can silently corrupt a funds display —
 * a display defect on a signing screen is a funds-safety defect).
 */

const SOMPI_PER_KAS = 100000000n;
const I64_MAX = 2n ** 63n - 1n; // num8 encoding domain (core/governance)

const CANONICAL_DIGITS_RE = /^(0|[1-9][0-9]*)$/;

function refuse(code, message) {
  const e = new Error(`explain-kas: ${message}`);
  e.code = code;
  throw e;
}

/*
 * Parse a canonical sompi quantity (BigInt or canonical base-10 digit
 * string) into BigInt. Refuses JS numbers, signs, decimals, exponents,
 * whitespace, leading zeros, empty strings, negatives, and values above
 * I64_MAX. Fail closed: an unrenderable amount is never approximated.
 */
function parseCanonicalSompi(value, field = "amount") {
  let amount;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_DIGITS_RE.test(value)) {
      refuse("VALUE_INVALID", `${field} is not a canonical base-10 digit string: ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    refuse(
      "VALUE_INVALID",
      `${field} must be a BigInt or canonical digit string (JS numbers are refused: floating point is unsafe for funds display), got ${typeof value}`
    );
  }
  if (amount < 0n) refuse("VALUE_INVALID", `${field} must not be negative`);
  if (amount > I64_MAX) refuse("VALUE_INVALID", `${field} exceeds the i64 encoding domain`);
  return amount;
}

/*
 * Render sompi as an exact KAS decimal string. Pure integer/string math;
 * exact 8-decimal handling; trailing fraction zeros trimmed; NEVER
 * rounded, truncated, or approximated ("1000000000" -> "10",
 * "125000000" -> "1.25", "1" -> "0.00000001").
 */
function sompiToKasString(value, field = "amount") {
  const amount = parseCanonicalSompi(value, field);
  const whole = amount / SOMPI_PER_KAS;
  const frac = amount % SOMPI_PER_KAS;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

/* The {sompi, kas} display pair used throughout structured explanations:
 * the exact integer AND its exact KAS rendering, so no consumer ever
 * needs to re-derive one from the other. */
function kasAmount(value, field = "amount") {
  const amount = parseCanonicalSompi(value, field);
  return { sompi: amount.toString(), kas: sompiToKasString(amount, field) };
}

module.exports = {
  SOMPI_PER_KAS,
  I64_MAX,
  parseCanonicalSompi,
  sompiToKasString,
  kasAmount
};
