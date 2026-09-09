"use strict";

/*
 * Versioned settlement policy (spec §6; decisions A + B). Exactly one
 * policy id is implemented: pv-x402-settlement/1. Unknown ids fail
 * closed. A future consensus change (DAGKNIGHT finality, changed DAA
 * semantics) ships as pv-x402-settlement/2 with its own rules — this
 * module never reinterprets /1.
 */

const { SETTLEMENT_POLICY_ID, MIN_DEPTH_DAA_DEFAULT, MIN_DEPTH_DAA_FLOOR, MAX_WINDOW_DAA } = require("./constants");
const { refuse } = require("./codes");

const DAA_RE = /^(0|[1-9][0-9]*)$/;
const MAX_DAA = 0xffffffffffffffffn;

/* Decimal DAA-score string (node values and requirement fields) → BigInt. */
function parseDaaString(value, label, code = "SCHEMA_INVALID") {
  if (typeof value !== "string" || !DAA_RE.test(value)) refuse(code, `${label} must be a canonical decimal integer string`);
  const n = BigInt(value);
  if (n > MAX_DAA) refuse(code, `${label} exceeds u64`);
  return n;
}

/* Deployment configuration of MIN_DEPTH_DAA: default 100; the floor is 20
 * and is a HARD floor (a lower configuration is refused at boot). */
function resolveMinDepth(configured) {
  if (configured === undefined || configured === null) return MIN_DEPTH_DAA_DEFAULT;
  let n;
  if (typeof configured === "bigint") n = configured;
  else if (typeof configured === "string" && DAA_RE.test(configured)) n = BigInt(configured);
  else if (typeof configured === "number" && Number.isSafeInteger(configured) && configured >= 0) n = BigInt(configured);
  else throw new Error("x402-facilitator: MIN_DEPTH_DAA must be a non-negative integer — fail closed");
  if (n < MIN_DEPTH_DAA_FLOOR) {
    throw new Error(`x402-facilitator: MIN_DEPTH_DAA ${n} is below the hard floor ${MIN_DEPTH_DAA_FLOOR} of ${SETTLEMENT_POLICY_ID} — refused (the floor is not the target; the default is ${MIN_DEPTH_DAA_DEFAULT})`);
  }
  if (n > 1_000_000n) throw new Error("x402-facilitator: MIN_DEPTH_DAA above 1,000,000 is not a sane configuration — refused");
  return n;
}

/* The only implemented policy. */
function resolveSettlementPolicy(policyId, { minDepthDaa } = {}) {
  if (policyId !== SETTLEMENT_POLICY_ID) refuse("POLICY_UNSUPPORTED", `settlementPolicy ${JSON.stringify(typeof policyId === "string" ? policyId.slice(0, 64) : policyId)}`);
  return Object.freeze({ id: SETTLEMENT_POLICY_ID, minDepthDaa: minDepthDaa ?? MIN_DEPTH_DAA_DEFAULT, maxWindowDaa: MAX_WINDOW_DAA });
}

/* Window sanity (§2.2 / §6): strictly increasing, length ≤ MAX_WINDOW_DAA. */
function validateWindow(validFrom, validUntil) {
  if (validUntil <= validFrom) refuse("REQUIREMENT_WINDOW_INVALID", "validUntilDaaScore must be greater than validFromDaaScore");
  if (validUntil - validFrom > MAX_WINDOW_DAA) refuse("REQUIREMENT_WINDOW_INVALID", `window length ${validUntil - validFrom} exceeds MAX_WINDOW_DAA ${MAX_WINDOW_DAA}`);
  return Object.freeze({ validFrom, validUntil });
}

/* PENDING vs final refusal for an unobserved payment (§7.1 step 4). */
function unobservedDisposition({ virtualDaaScore, validUntil, minDepthDaa }) {
  return virtualDaaScore > validUntil + minDepthDaa ? "REQUIREMENT_EXPIRED" : "PAYMENT_NOT_OBSERVED";
}

/* Depth classification (§6): CHAIN_SEEN below the minimum, CHAIN_VERIFIED at or above. */
function classifyDepth({ virtualDaaScore, blockDaaScore, minDepthDaa }) {
  if (blockDaaScore > virtualDaaScore) refuse("RPC_MALFORMED", "entry blockDaaScore is above the virtual DAA score");
  const depth = virtualDaaScore - blockDaaScore;
  return Object.freeze({ depth, status: depth >= minDepthDaa ? "CHAIN_VERIFIED" : "CHAIN_SEEN" });
}

module.exports = { parseDaaString, resolveMinDepth, resolveSettlementPolicy, validateWindow, unobservedDisposition, classifyDepth, DAA_RE };
