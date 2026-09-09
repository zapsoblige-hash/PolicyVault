"use strict";

/*
 * Centralized v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT compute-budget
 * selection. Sibling of core/model/compute-budget-v7.js (the payment
 * profile); the ROOT side of a rooted-vault transaction is UNCHANGED (same
 * root covenant), so this module reuses selectRootComputeBudgetV7 from
 * compute-budget-v7.js unmodified and adds ONLY the vault-side model.
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. Every constant below is an ENGINE MEASUREMENT
 * from tests/vm/tests/v7_kas_production.rs (2026-09-03, release build,
 * rusty-kaspa 2.0.1); nothing here is estimated without a labeled safety
 * margin on top of a real measurement.
 *
 * BUDGET ARITHMETIC. Identical to compute-budget-v7.js:
 *   required_budget = ceil((units - (10_000 - 1)) / 10_000)
 * so every model below over-approximates with ceil(units / 10_000) after
 * adding headroom, so the committed budget is ALWAYS >= the required one.
 * tests/vm/tests/v7_kas_sdk_integration.rs asserts exactly that on SDK-built
 * bytes for every input of every accept vector.
 *
 * MEASURED (v7_kas_production.rs, priced units for the VAULT input, sig-op
 * pricing 100,000 units/executed checkSig — ownerControl/ownerRecover
 * EXECUTE ZERO checkSigs, so their priced and unpriced numbers are equal).
 *
 * RE-MEASURED 2026-09-03 (Wave 2, Track C2) after candidate hardening E6
 * (tools/gen_v7_kas.js: requireAgentAuthorization SIGHASH_ALL gate on
 * agentSig + requireOnlyPlainInputsOnDelegatePath). SilverScript inlines
 * every function into the ONE shared redeem script regardless of which
 * entrypoint calls it, so the two new functions shifted priced/unpriced
 * units for EVERY entrypoint, not only agentSpend (by a different, non-
 * uniform amount per entrypoint — empirically +1,740 for every ownerControl
 * selector, +580 for ownerRecover, +2,096 for agentSpend; deltas BETWEEN two
 * agentSpend shapes, e.g. depth vs base or approvals vs base, are unaffected
 * since the E6 overhead is a constant offset on that entrypoint's own base).
 * Values below are the CURRENT measurement; the constants derived from them
 * carry their own margin on top:
 *   ownerControl(0 setAgentRoot)   priced 361,088
 *   ownerControl(1 setApprovers)   priced 366,214  <- max of 0..6
 *   ownerControl(2 topUp)          priced 361,156
 *   ownerControl(3 topUpReserve)   priced 361,157
 *   ownerControl(4 pause)          priced 361,162
 *   ownerControl(5 unpause)        priced 361,160
 *   ownerControl(6 EMERGENCY pause) priced 361,163
 *   ownerRecover                   priced 278,768
 *   delegate spend depth 0/0, 0 approvals    unpriced 123,730 (1 sig-op)
 *   delegate spend depth 12/16, 0 approvals  unpriced 175,925 (1 sig-op)
 *   delegate spend depth 12/16, 10-of-10     unpriced 219,103, priced 1,319,103 (11 sig-ops)
 * The depth allowance (52,195) and per-approval delta (~4,318/approval) are
 * UNCHANGED from the pre-E6 measurement (both are differences between two
 * agentSpend shapes, so the constant E6 offset cancels out).
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/compute-budget-v7-kas.test.js);
 * sufficiency is PROVEN on real engine execution by the SDK integration suite.
 */

const { selectRootComputeBudgetV7, ROOT_TEMPLATE_REFERENCE_BYTES } = require("./compute-budget-v7");

const UNITS_PER_BUDGET = 10_000;
const SIGOP_UNITS = 100_000;
const HEADROOM = 20_000;

/* ---- rooted KAS vault: ownerControl / ownerRecover ---- */

/* The vault's owner path slices the root's revealed redeem exactly as the
 * payment profile's does (byte-for-byte the same requireRootAuthorization),
 * so it scales with the SAME root-template reference and slope. */
const ROOT_TEMPLATE_SLOPE = 26;
const VAULT_OWNER_CONTROL_UNITS = 367_000; /* post-E6 max measured selector 0..6 (366,214) + margin */
const VAULT_OWNER_RECOVER_UNITS = 279_500; /* post-E6 measured 278,768 + margin */

/* ---- rooted KAS vault: agentSpend (delegate) ---- */

const SPEND_BASE = 124_500; /* post-E6 measured depth0/0, 0 approvals: 123,730 + margin */
const SPEND_ROLLOVER_MARGIN = 200; /* measured rollover delta over base: 44 */
/* Measured: depth12/16 adds 52,195 unpriced units over the depth0/0 base
 * (agent Merkle depth <= 12, recipient Merkle depth <= 16, both linear
 * unrolled walks in the covenant — a linear model in the DEEPER-normalized
 * fraction is the right functional form, not a heuristic). Rounded up. */
const DEPTH_ALLOWANCE_MAX = 53_000;
const AGENT_MAX_DEPTH = 12;
const RECIPIENT_MAX_DEPTH = 16;
/* Measured: 10-of-10 approvals at depth12/16 add 43,178 unpriced units over
 * the depth12/16-only measurement (217,007 - 173,829), i.e. ~4,318/approval
 * for the slot-extraction + gate loop (BEFORE sig-op pricing, which is added
 * separately below). Rounded up per approval. */
const PER_APPROVAL_UNPRICED = 4_400;

const V7_KAS_BUDGET = Object.freeze({
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v7-kas: ${message}`);
}

function ceilBudget(units) {
  const n = Math.ceil(units / UNITS_PER_BUDGET);
  if (!Number.isInteger(n) || n < 1 || n > 65_535) fail(`computed compute budget ${n} is outside the u16 domain`);
  return n;
}

function requiredBudgetForUnits(units) {
  if (!Number.isInteger(units) || units < 0) fail("units must be a non-negative integer");
  const charged = Math.max(0, units - (UNITS_PER_BUDGET - 1));
  return Math.ceil(charged / UNITS_PER_BUDGET);
}

function rootTemplateBytes({ rootPrefixLen, rootSuffixLen }) {
  if (!Number.isInteger(rootPrefixLen) || !Number.isInteger(rootSuffixLen) || rootPrefixLen < 0 || rootSuffixLen < 0) {
    fail("root template geometry (rootPrefixLen/rootSuffixLen) is required to size a rooted-vault owner budget");
  }
  return rootPrefixLen + rootSuffixLen;
}

function rootExtraUnits({ rootPrefixLen, rootSuffixLen }) {
  return Math.max(0, rootTemplateBytes({ rootPrefixLen, rootSuffixLen }) - ROOT_TEMPLATE_REFERENCE_BYTES) * ROOT_TEMPLATE_SLOPE;
}

function smallNonNegInt(value, field, max) {
  const n = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isInteger(n) || n < 0 || n > max) fail(`${field} must be an integer 0..${max}`);
  return n;
}

/* The committed budget for the ROOTED KAS VAULT covenant input. */
function selectComputeBudgetV7Kas({ operation, rootPrefixLen, rootSuffixLen, agentTreeDepth = 0, recipientDepth = 0, approvalsChecked = 0, rollover = false }) {
  switch (operation) {
    case "agentSpend": {
      const depth = smallNonNegInt(agentTreeDepth, "agentTreeDepth", AGENT_MAX_DEPTH);
      const recip = smallNonNegInt(recipientDepth, "recipientDepth", RECIPIENT_MAX_DEPTH);
      const approvals = smallNonNegInt(approvalsChecked, "approvalsChecked", 10);
      const depthFraction = Math.max(depth / AGENT_MAX_DEPTH, recip / RECIPIENT_MAX_DEPTH);
      const depthUnits = Math.ceil(depthFraction * DEPTH_ALLOWANCE_MAX);
      const approvalUnits = approvals * PER_APPROVAL_UNPRICED;
      const sigOpUnits = (1 + approvals) * SIGOP_UNITS; /* the agent's own sig-op + every executed approval */
      const rolloverMargin = rollover ? SPEND_ROLLOVER_MARGIN : 0;
      return ceilBudget(SPEND_BASE + depthUnits + approvalUnits + sigOpUnits + rolloverMargin + HEADROOM);
    }
    case "ownerSetAgentRoot":
    case "ownerSetApprovers":
    case "ownerTopUp":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
    case "ownerEmergencyPause": {
      const extra = rootExtraUnits({ rootPrefixLen, rootSuffixLen });
      return ceilBudget(VAULT_OWNER_CONTROL_UNITS + extra + HEADROOM);
    }
    case "ownerRecover": {
      const extra = rootExtraUnits({ rootPrefixLen, rootSuffixLen });
      return ceilBudget(VAULT_OWNER_RECOVER_UNITS + extra + HEADROOM);
    }
    default:
      return fail(`unknown v0.7-kas rooted-vault operation ${JSON.stringify(operation)} — failing closed`);
  }
}

function assertBudgetSufficientV7Kas({ operation, committed, ...geometry }) {
  const required = selectComputeBudgetV7Kas({ operation, ...geometry });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = {
  V7_KAS_BUDGET,
  UNITS_PER_BUDGET,
  SIGOP_UNITS,
  AGENT_MAX_DEPTH,
  RECIPIENT_MAX_DEPTH,
  requiredBudgetForUnits,
  selectComputeBudgetV7Kas,
  assertBudgetSufficientV7Kas,
  /* re-exported so a caller never has to import compute-budget-v7.js just to
   * budget the root input of a v0.7-kas owner operation */
  selectRootComputeBudgetV7
};
