"use strict";

/*
 * Canonical KCC20 token adapter — shared deterministic core (v0.5).
 *
 * Status: IMPLEMENTED + UNIT-TESTED, pinned byte-for-byte to the real
 * silverscript compiler / rusty-kaspa v2.0.1 engine through the fixture
 * core/assets/test/fixtures/kcc20-template-v1.json (captured by
 * tests/vm/tests/v5_fixture_capture.rs — production-byte rule).
 *
 * What this module KNOWS (all consensus-visible byte facts):
 *   - the `kcc20-state/1` state layout and its exact 46-byte encoding
 *     inside a KCC20 redeem script:
 *       0x20 || ownerIdentifier(32)      (OpData32 push)
 *       0x01 || identifierType(1)        (OpData1 push)
 *       0x08 || amount LE64(8)           (OpData8 push, fixed width)
 *       0x01 || isMinter(0x00|0x01)      (OpData1 push)
 *   - redeem = prefix || state || suffix; prefix/suffix = the TEMPLATE;
 *   - the in-VM template identity blake2b-256(prefix || suffix);
 *   - the version-0 P2SH envelope OpBlake2b OpData32 <blake2b-256(redeem)>
 *     OpEqual;
 *   - the post-Toccata STATIC P2SH sig-op scan (mempool standardness),
 *     mirrored from rusty-kaspa get_sig_op_count_by_opcodes.
 *
 * What it does NOT do: trust anything. Every input is bytes from a
 * transaction or a validated descriptor; every mismatch throws (fail
 * closed). Token amounts are atomic units (NEVER KAS/sompi).
 */

const { blake2b, blake2bHex } = require("./blake2b");
const { MAX_I64, KCC20_STATE_LEN, OWNER_SCHEMES, parseAtomicAmount: parseAtomicAmountCore } = require("../model/token-amounts");

const STATE_LAYOUT_ID = "kcc20-state/1";
const STATE_LEN = KCC20_STATE_LEN;
const MAX_STANDARD_P2SH_SIG_OPS = 15; // rusty-kaspa mining/src/mempool/check_transaction_standard.rs
const MAX_PUB_KEYS_PER_MULTISIG = 20; // rusty-kaspa crypto/txscript/src/lib.rs

/* opcode values (rusty-kaspa crypto/txscript/src/opcodes/mod.rs) */
const OP = Object.freeze({
  FALSE: 0x00,
  DATA1: 0x01,
  DATA75: 0x4b,
  PUSHDATA1: 0x4c,
  PUSHDATA2: 0x4d,
  PUSHDATA4: 0x4e,
  ONE: 0x51,
  SIXTEEN: 0x60,
  EQUAL: 0x87,
  CHECKMULTISIG_ECDSA: 0xa9,
  BLAKE2B: 0xaa,
  CHECKSIG_ECDSA: 0xab,
  CHECKSIG: 0xac,
  CHECKSIG_VERIFY: 0xad,
  CHECKMULTISIG: 0xae,
  CHECKMULTISIG_VERIFY: 0xaf,
  CHECKSIG_FROM_STACK: 0xd7,
  CHECKSIG_FROM_STACK_ECDSA: 0xd8
});

class Kcc20Error extends Error {
  constructor(code, message) {
    super(message);
    this.name = "Kcc20Error";
    this.code = code;
  }
}
function fail(code, message) {
  throw new Kcc20Error(code, message);
}

/* ---- portable byte helpers ---- */
function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}
function hexToBytes(hex, label) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    fail("KCC20_MALFORMED", `${label ?? "value"} must be lowercase even-length hex`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function asBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  return hexToBytes(value, label);
}
function concat(chunks) {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* ---- atomic amounts (token domain; NEVER sompi) — core/model primitive ---- */
function parseAtomicAmount(value, label = "amount") {
  try {
    return parseAtomicAmountCore(value, label);
  } catch (e) {
    fail(e.code ?? "KCC20_MALFORMED", e.message);
  }
}

/* ---- kcc20-state/1 codec ---- */
function normalizeState(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    fail("KCC20_MALFORMED", "token state must be a plain object");
  }
  for (const key of Object.keys(input)) {
    if (!["ownerIdentifier", "identifierType", "amount", "isMinter"].includes(key)) {
      fail("KCC20_MALFORMED", `token state carries unknown field ${JSON.stringify(key)} — closed layout, failing closed`);
    }
  }
  if (typeof input.ownerIdentifier !== "string" || !/^[0-9a-f]{64}$/.test(input.ownerIdentifier)) {
    fail("KCC20_MALFORMED", "ownerIdentifier must be 64 lowercase hex characters");
  }
  const type = input.identifierType;
  if (!Number.isInteger(type) || !Object.values(OWNER_SCHEMES).includes(type)) {
    fail("KCC20_UNKNOWN_OWNER_SCHEME", `identifierType ${JSON.stringify(type)} is not a known owner scheme (0x00 p2pk, 0x01 p2sh, 0x02 covenant-id) — failing closed`);
  }
  if (typeof input.isMinter !== "boolean") {
    fail("KCC20_MALFORMED", "isMinter must be an explicit boolean");
  }
  return Object.freeze({
    ownerIdentifier: input.ownerIdentifier,
    identifierType: type,
    amount: parseAtomicAmount(input.amount),
    isMinter: input.isMinter
  });
}

function encodeState(input) {
  const s = normalizeState(input);
  const out = new Uint8Array(STATE_LEN);
  out[0] = 0x20;
  out.set(hexToBytes(s.ownerIdentifier), 1);
  out[33] = 0x01;
  out[34] = s.identifierType;
  out[35] = 0x08;
  let v = s.amount;
  for (let i = 0; i < 8; i++) {
    out[36 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  out[44] = 0x01;
  out[45] = s.isMinter ? 0x01 : 0x00;
  return out;
}

function decodeState(bytesIn) {
  const b = asBytes(bytesIn, "state");
  if (b.length !== STATE_LEN) {
    fail("KCC20_MALFORMED_STATE", `kcc20-state/1 must be exactly ${STATE_LEN} bytes (got ${b.length}) — failing closed`);
  }
  if (b[0] !== 0x20 || b[33] !== 0x01 || b[35] !== 0x08 || b[44] !== 0x01) {
    fail("KCC20_MALFORMED_STATE", "kcc20-state/1 push framing is not canonical (expected 0x20/0x01/0x08/0x01 push opcodes) — failing closed");
  }
  const type = b[34];
  if (!Object.values(OWNER_SCHEMES).includes(type)) {
    fail("KCC20_UNKNOWN_OWNER_SCHEME", `identifierType 0x${type.toString(16)} is not a known owner scheme — failing closed`);
  }
  if (b[45] !== 0x00 && b[45] !== 0x01) {
    fail("KCC20_MALFORMED_STATE", "isMinter byte must be 0x00 or 0x01 — failing closed");
  }
  let amount = 0n;
  for (let i = 7; i >= 0; i--) amount = (amount << 8n) | BigInt(b[36 + i]);
  if (amount > MAX_I64) {
    fail("KCC20_MALFORMED_STATE", "amount has the i64 sign bit set (negative in-VM) — failing closed");
  }
  return Object.freeze({
    ownerIdentifier: bytesToHex(b.subarray(1, 33)),
    identifierType: type,
    amount,
    isMinter: b[45] === 0x01
  });
}

/* ---- template geometry / identity ---- */
function normalizeGeometry(g) {
  if (!g || typeof g !== "object") fail("KCC20_MALFORMED", "geometry object is required");
  for (const k of ["prefixLen", "stateLen", "suffixLen"]) {
    if (!Number.isInteger(g[k]) || g[k] < 0 || g[k] > 1_000_000) fail("KCC20_MALFORMED", `geometry.${k} must be an integer 0..1000000`);
  }
  if (g.stateLen !== STATE_LEN) fail("KCC20_MALFORMED", `geometry.stateLen must be ${STATE_LEN} for ${STATE_LAYOUT_ID}`);
  return Object.freeze({ prefixLen: g.prefixLen, stateLen: g.stateLen, suffixLen: g.suffixLen });
}

function splitRedeem(redeemIn, geometryIn) {
  const redeem = asBytes(redeemIn, "redeem");
  const g = normalizeGeometry(geometryIn);
  if (redeem.length !== g.prefixLen + g.stateLen + g.suffixLen) {
    fail("KCC20_GEOMETRY_MISMATCH", `redeem length ${redeem.length} != pinned geometry ${g.prefixLen}+${g.stateLen}+${g.suffixLen} — failing closed`);
  }
  return Object.freeze({
    prefix: redeem.subarray(0, g.prefixLen),
    state: redeem.subarray(g.prefixLen, g.prefixLen + g.stateLen),
    suffix: redeem.subarray(g.prefixLen + g.stateLen)
  });
}

function reconstructRedeem(prefix, state, suffix) {
  return concat([asBytes(prefix, "prefix"), asBytes(state, "state"), asBytes(suffix, "suffix")]);
}

/* The in-VM identity the *WithTemplate builtins verify. */
function templateVmHashHex(prefix, suffix) {
  return blake2bHex([asBytes(prefix, "prefix"), asBytes(suffix, "suffix")], 32);
}

/* Version-0 P2SH envelope for a redeem script. */
function p2shSpkHex(redeem) {
  return "aa20" + bytesToHex(blake2b(asBytes(redeem, "redeem"), 32)) + "87";
}

/* ---- script parsing (push-aware), mirrors rusty-kaspa parse_script ---- */
function parseOpcodes(scriptIn) {
  const s = asBytes(scriptIn, "script");
  const ops = [];
  let i = 0;
  while (i < s.length) {
    const op = s[i];
    let dataLen = 0;
    let header = 1;
    if (op >= OP.DATA1 && op <= OP.DATA75) {
      dataLen = op;
    } else if (op === OP.PUSHDATA1) {
      if (i + 1 >= s.length) return { ops, malformed: true };
      dataLen = s[i + 1];
      header = 2;
    } else if (op === OP.PUSHDATA2) {
      if (i + 2 >= s.length) return { ops, malformed: true };
      dataLen = s[i + 1] | (s[i + 2] << 8);
      header = 3;
    } else if (op === OP.PUSHDATA4) {
      if (i + 4 >= s.length) return { ops, malformed: true };
      dataLen = (s[i + 1] | (s[i + 2] << 8) | (s[i + 3] << 16) | (s[i + 4] << 24)) >>> 0;
      header = 5;
    }
    if (i + header + dataLen > s.length) return { ops, malformed: true };
    ops.push({ op, data: s.subarray(i + header, i + header + dataLen) });
    i += header + dataLen;
  }
  return { ops, malformed: false };
}

/* The redeem script of a P2SH spend is the LAST push of the signature script. */
function lastPushData(sigscriptIn) {
  const { ops, malformed } = parseOpcodes(sigscriptIn);
  if (malformed || ops.length === 0) fail("KCC20_MALFORMED", "signature script is malformed or empty — cannot locate a redeem script");
  const last = ops[ops.length - 1];
  if (last.op > OP.PUSHDATA4) fail("KCC20_MALFORMED", "signature script does not end with a data push — cannot locate a redeem script");
  return last.data;
}

/* rusty-kaspa deserialize_i64 (enforce_minimal = false): <= 8 bytes, LE, sign-magnitude top bit. */
function deserializeI64(data) {
  if (data.length > 8) return null;
  if (data.length === 0) return 0n;
  const msb = data[data.length - 1];
  const sign = msb & 0x80 ? -1n : 1n;
  let acc = BigInt(msb & 0x7f);
  for (let i = data.length - 2; i >= 0; i--) acc = (acc << 8n) + BigInt(data[i]);
  return acc * sign;
}

/*
 * Static P2SH sig-op scan of a REDEEM script — exactly rusty-kaspa's
 * get_sig_op_count_by_opcodes semantics (post-Toccata: from-stack variants
 * count; non-minimal pushes before multisig are honoured; unknown multisig
 * count = 20). A malformed script is reported (the node's scanner returns 0
 * for it; PolicyVault fails CLOSED instead).
 */
function countStaticSigOps(redeemIn) {
  const { ops, malformed } = parseOpcodes(redeemIn);
  if (malformed) return { sigOps: 0, malformed: true };
  let sigOps = 0;
  let prevMultisigCount = null;
  for (const { op, data } of ops) {
    const count = prevMultisigCount;
    prevMultisigCount = null;
    if (op === OP.CHECKSIG || op === OP.CHECKSIG_VERIFY || op === OP.CHECKSIG_ECDSA || op === OP.CHECKSIG_FROM_STACK || op === OP.CHECKSIG_FROM_STACK_ECDSA) {
      sigOps += 1;
    } else if (op === OP.CHECKMULTISIG || op === OP.CHECKMULTISIG_VERIFY || op === OP.CHECKMULTISIG_ECDSA) {
      sigOps += count ?? MAX_PUB_KEYS_PER_MULTISIG;
    } else if (op >= OP.ONE && op <= OP.SIXTEEN) {
      prevMultisigCount = op - OP.ONE + 1;
    } else if (op <= OP.PUSHDATA4) {
      const n = deserializeI64(data);
      prevMultisigCount = n !== null && n >= 1n && n <= BigInt(MAX_PUB_KEYS_PER_MULTISIG) ? Number(n) : null;
    }
  }
  return { sigOps, malformed: false };
}

/* Canonical representative state used to scan a template's redeem. */
const ZERO_STATE = Object.freeze({ ownerIdentifier: "00".repeat(32), identifierType: OWNER_SCHEMES.COVENANT_ID, amount: "0", isMinter: false });

/*
 * Standardness envelope for an accepted template (frozen v0.5 rule): the
 * static sig-op count of prefix || state || suffix must be <= 15, the
 * script must parse, or the template MUST NOT become spend-enabled.
 */
function templateStandardness(prefix, suffix) {
  const redeem = reconstructRedeem(asBytes(prefix, "prefix"), encodeState(ZERO_STATE), asBytes(suffix, "suffix"));
  const scan = countStaticSigOps(redeem);
  if (scan.malformed) {
    return Object.freeze({ standard: false, reason: "TEMPLATE_MALFORMED", staticSigOps: null, limit: MAX_STANDARD_P2SH_SIG_OPS });
  }
  if (scan.sigOps > MAX_STANDARD_P2SH_SIG_OPS) {
    return Object.freeze({ standard: false, reason: "TEMPLATE_NONSTANDARD_FAMILY_BOUND", staticSigOps: scan.sigOps, limit: MAX_STANDARD_P2SH_SIG_OPS });
  }
  return Object.freeze({ standard: true, reason: null, staticSigOps: scan.sigOps, limit: MAX_STANDARD_P2SH_SIG_OPS });
}

module.exports = {
  STATE_LAYOUT_ID,
  STATE_LEN,
  OWNER_SCHEMES,
  MAX_I64,
  MAX_STANDARD_P2SH_SIG_OPS,
  Kcc20Error,
  bytesToHex,
  hexToBytes,
  bytesEqual,
  parseAtomicAmount,
  normalizeState,
  encodeState,
  decodeState,
  normalizeGeometry,
  splitRedeem,
  reconstructRedeem,
  templateVmHashHex,
  p2shSpkHex,
  parseOpcodes,
  lastPushData,
  countStaticSigOps,
  templateStandardness,
  ZERO_STATE
};
