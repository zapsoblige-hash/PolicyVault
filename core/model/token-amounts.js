"use strict";

/*
 * TOKEN-domain numeric primitives for the portable core (v0.5). Token
 * amounts are atomic units — NEVER KAS/sompi (separate accounting domain,
 * docs/postlaunch/v0.5-design-freeze.md §I.5). Same rejection discipline as
 * the sompi parsers (no signs, leading zeros, floats, exponents, NaN,
 * Infinity), bounded to the i64 domain the Kaspa VM decodes token amounts
 * in. Also carries the frozen kcc20-state/1 byte facts the model layer
 * needs without depending on core/assets (core/model purity rule:
 * builtins + siblings only; core/assets depends on core/model, never the
 * reverse).
 */

const MAX_I64 = 0x7fffffffffffffffn;
const KCC20_STATE_LEN = 46;
const OWNER_SCHEMES = Object.freeze({ P2PK: 0x00, P2SH: 0x01, COVENANT_ID: 0x02 });

class TokenAmountError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TokenAmountError";
    this.code = code;
  }
}

function parseAtomicAmount(value, label = "amount") {
  let n;
  if (typeof value === "bigint") {
    n = value;
  } else if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    n = BigInt(value);
  } else {
    throw new TokenAmountError(
      "KCC20_MALFORMED",
      `${label} must be a non-negative atomic-unit decimal string or BigInt (no signs, leading zeros, floats, exponents)`
    );
  }
  if (n < 0n || n > MAX_I64) {
    throw new TokenAmountError("KCC20_MALFORMED", `${label} must be within 0..2^63-1 (the VM decodes token amounts as i64)`);
  }
  return n;
}

module.exports = { MAX_I64, KCC20_STATE_LEN, OWNER_SCHEMES, TokenAmountError, parseAtomicAmount };
