"use strict";

/*
 * Centralized v0.6 controller compute-budget selection.
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. Like v0.5 the controller's cost scales with the
 * accepted token template (two template reads + two output reconstructions
 * on a swap; one + two on a spend) AND, on a swap, with the APPROVED POOL
 * TEMPLATE (one hash-verified read of the pool's revealed redeem).
 *
 * Measured on the CANDIDATE PolicyVault.v0.6.sil under production sig-op
 * pricing (tests/vm/tests/v6_production.rs v6_measurement_units_mass_standardness,
 * 2026-09-03; token template = upstream kcc20.sil bound 2, suffix 2,686 B;
 * pool fixture redeem 10,566 B; priced units INCLUDE the 100,000-unit
 * Schnorr sig-op):
 *
 *   tokenAgentSpend, agent depth 1 / recipient depth 0:      294,894 -> 29
 *   tokenAgentSpend, agent depth 12 / recipient depth 16:    346,027 -> 34
 *   tokenAtomicSell A, agent depth 1 / swap depth 2:         385,481 -> 38
 *   tokenAtomicSell A, agent depth 12 / swap depth 12:       426,614 -> 42
 *   tokenAtomicSell B (P2PK proceeds):                        385,652 -> 38
 *   tokenAtomicBuy,   agent depth 1 / swap depth 2:          385,481 -> 38
 *   tokenAtomicBuy,   agent depth 12 / swap depth 12:        426,614 -> 42
 *   ownerControl (fundSwapPrincipal):                         251,097 -> 25
 *   ownerRecover (with position):                             174,206 -> 17
 *
 * Model = base (max-depth measurement) + 24 units per token-template byte
 * above the reference + 24 units per pool-template byte above the
 * reference (the v0.5 measured slope; the pool read hashes the pool redeem
 * once) + 20,000 headroom, in 10,000-unit budget units, ceiling-rounded.
 * Callers may NEVER lower the committed budget below the model value; the
 * production-byte suite executes SDK-built shapes with the SDK's own
 * committed budget and asserts sufficiency.
 */

const UNITS_PER_BUDGET = 10_000;
const SIGOP_UNITS = 100_000;
const SLOPE_PER_TEMPLATE_BYTE = 24;
const REFERENCE_TEMPLATE_BYTES = 2_687; // prefix 1 + suffix 2,686 (bound 2)
const REFERENCE_POOL_BYTES = 10_566;
const HEADROOM = 20_000;
const SPEND_BASE = 346_027; // depths 12/16, incl. sig-op
const SWAP_BASE = 426_614; // depths 12/12, incl. sig-op (sell A/B and buy measured equal within 171 units)
const OWNER_BASE = 251_097;
const RECOVER_BASE = 174_206;

const V6_BUDGET = Object.freeze({
  ORDINARY_INPUT: 10,
  /* the pool fixture input executes its own family scan (measured 90,000 units -> 9 at one reserve note) */
  POOL_INPUT_MIN: 12
});

function fail(message) {
  throw new Error(`compute-budget-v6: ${message}`);
}
function templateBytes({ templatePrefixLen, templateSuffixLen }) {
  if (!Number.isInteger(templatePrefixLen) || !Number.isInteger(templateSuffixLen) || templatePrefixLen < 0 || templateSuffixLen < 0) fail("template geometry (templatePrefixLen/templateSuffixLen) is required to size a template-scaled budget");
  return templatePrefixLen + templateSuffixLen;
}
function poolBytes({ poolPrefixLen, poolSuffixLen }) {
  const p = Number(poolPrefixLen);
  const s = Number(poolSuffixLen);
  if (!Number.isInteger(p) || !Number.isInteger(s) || p < 0 || s < 0) fail("pool geometry (poolPrefixLen/poolSuffixLen) is required to size a swap budget");
  return p + s;
}
function ceilBudget(units) {
  return Math.ceil(units / UNITS_PER_BUDGET);
}

function selectComputeBudgetV6({ operation, templatePrefixLen, templateSuffixLen, poolPrefixLen, poolSuffixLen }) {
  const tplExtra = () => Math.max(0, templateBytes({ templatePrefixLen, templateSuffixLen }) - REFERENCE_TEMPLATE_BYTES) * SLOPE_PER_TEMPLATE_BYTE;
  switch (operation) {
    case "tokenAgentSpend":
      return ceilBudget(SPEND_BASE + tplExtra() + HEADROOM);
    case "tokenAtomicSell":
    case "tokenAtomicBuy": {
      const poolExtra = Math.max(0, poolBytes({ poolPrefixLen, poolSuffixLen }) - REFERENCE_POOL_BYTES) * SLOPE_PER_TEMPLATE_BYTE;
      return ceilBudget(SWAP_BASE + tplExtra() + poolExtra + HEADROOM);
    }
    case "ownerSetAgentRoot":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
    case "ownerSetSwapRoot":
    case "ownerFundSwapPrincipal":
      return ceilBudget(OWNER_BASE + HEADROOM);
    case "ownerRecover":
      return ceilBudget(RECOVER_BASE + tplExtra() + HEADROOM);
    default:
      fail(`unknown v0.6 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/* Token-family input executing the reference KCC20 program (v0.5 model: 20,000 + 24/byte; +sig-op when signer-owned). */
function selectTokenInputBudgetV6({ templatePrefixLen, templateSuffixLen, signerOwned = false }) {
  const base = 20_000 + SLOPE_PER_TEMPLATE_BYTE * templateBytes({ templatePrefixLen, templateSuffixLen });
  return Math.max(4, ceilBudget(base + (signerOwned ? SIGOP_UNITS : 0)));
}

/* Pool fixture input: family scan of up to 4 notes (each a template read) + one output reconstruction. */
function selectPoolInputBudgetV6({ templatePrefixLen, templateSuffixLen, poolPrefixLen, poolSuffixLen }) {
  const base = 40_000 + 4 * SLOPE_PER_TEMPLATE_BYTE * templateBytes({ templatePrefixLen, templateSuffixLen }) + 2 * poolBytes({ poolPrefixLen, poolSuffixLen });
  return Math.max(V6_BUDGET.POOL_INPUT_MIN, ceilBudget(base + HEADROOM));
}

function assertBudgetSufficientV6(args) {
  const required = selectComputeBudgetV6(args);
  if (!Number.isInteger(args.committed) || args.committed < required) fail(`committed compute budget ${args.committed} is below the proven-safe minimum ${required} for ${args.operation}`);
  return args.committed;
}

module.exports = { V6_BUDGET, UNITS_PER_BUDGET, SIGOP_UNITS, selectComputeBudgetV6, selectTokenInputBudgetV6, selectPoolInputBudgetV6, assertBudgetSufficientV6 };
