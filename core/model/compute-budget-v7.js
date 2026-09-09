"use strict";

/*
 * Centralized v0.7 ORGANIZATIONAL ROOT / ROOTED VAULT compute-budget
 * selection.
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node, and a builder can never lower it after the fact
 * because the exact-fee freeze depends on it. Every constant below is an
 * ENGINE MEASUREMENT from the production candidates
 * (docs/postlaunch/v0.7-organizational-root-design.md §12.3,
 * tests/vm/tests/v7_root_production.rs + v7_payment_production.rs,
 * 2026-09-03); nothing here is estimated.
 *
 * BUDGET ARITHMETIC. rusty-kaspa charges
 *   required_budget = ceil((units - (10_000 - 1)) / 10_000)
 * (ComputeBudget::checked_covering_script_units, consensus/core/src/mass/
 * units.rs), i.e. ordinary floor division for the current constants. Every
 * model below therefore over-approximates with ceil(units / 10_000) after
 * adding headroom, so the committed budget is ALWAYS >= the required one.
 * tests/vm/tests/v7_sdk_integration.rs asserts exactly that on SDK-built
 * bytes for every input of every accept vector.
 *
 * SIG-OP PRICING. Priced units include 100,000 units per EXECUTED Schnorr
 * sig-op. The root runs `checkSig` once per ACTIVE owner slot (inactive
 * sentinel slots are never inspected), so the root's priced cost scales with
 * activeCount, NOT with the threshold — which is also why the sweep's
 * sigscript length is constant at 12,776 B for every threshold.
 *
 * MEASURED (priced units -> required budget):
 *   root ROTATE 12-of-12          1,339,272 -> 133   (script 139,272, 12 sig-ops)
 *   root AUTHORIZE 2-of-3           397,182 ->  39   (script  97,182,  3 sig-ops)
 *   root FREEZE (K = 1)             397,184 ->  39   (script  97,184,  3 sig-ops)
 *   root OWNER-RECOVER (4 active)   502,295 ->  50   (script 102,295,  4 sig-ops)
 *   root SUCCESSION                 177,665 ->  17   (script  77,665,  1 sig-op)
 *   threshold sweep script units     87,532 (1-of-1) .. 134,217 (12-of-12)
 *   rooted vault ownerControl 0..4   299,534 .. 299,607 script units, 0 sig-ops
 *   rooted vault ownerRecover        284,373 script units, 0 sig-ops
 *   root input inside a vault op      97,192 script units, active-slot sig-ops
 *   delegate spend (depths 0/0)      100,390 script units + 1 sig-op
 *   delegate spend (depths 12/16)    152,713 script units + 1 sig-op
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/compute-budget-v7.test.js);
 * sufficiency is PROVEN on real engine execution by the SDK integration suite.
 */

const { OWNER_SLOTS_V7 } = require("./owner-set-v7");

const UNITS_PER_BUDGET = 10_000;
const SIGOP_UNITS = 100_000;
const HEADROOM = 20_000;

/* ---- root covenant ---- */

/*
 * Root script units as a function of ACTIVE owner slots. The measured sweep
 * is concave (deltas 4,889 down to 3,594), so a straight line through the
 * FIRST measured point with the LARGEST measured delta is a strict upper
 * bound at every n in [1, 12]:
 *     87,532 + 4,889 * (n - 1)   >=   measured(n)
 * (checked at n = 1, 3 and 12 in core/model/test/compute-budget-v7.test.js).
 */
const ROOT_BASE_1_ACTIVE = 87_532;
const ROOT_PER_ACTIVE_SLOT = 4_889;
/* WF(new) (+ the age check on recovery) measured at +5,113 (recover, 4 active)
 * and +5,055 (rotate, 12 active); 5,300 covers both with margin. */
const ROOT_WF_NEW_ALLOWANCE = 5_300;
/* rootSuccession runs WF(prev) + WF(new) and exactly one checkSig. */
const ROOT_SUCCESSION_SCRIPT_UNITS = 78_400;

/* ---- rooted payment vault ---- */

/*
 * A rooted vault's owner path slices the root's revealed redeem, hashes its
 * template identity, rebuilds the successor redeem and P2SH-compares it, so
 * its cost scales with the ROOT TEMPLATE SIZE. The reference is the measured
 * production root (prefix 1 B + suffix 11,077 B = 11,078 B); the slope is the
 * v0.5-measured template slope of 24 units/byte rounded up to 26.
 */
const ROOT_TEMPLATE_REFERENCE_BYTES = 11_078;
const ROOT_TEMPLATE_SLOPE = 26;
const VAULT_OWNER_CONTROL_UNITS = 299_700; /* max measured selector 0..4 */
const VAULT_OWNER_RECOVER_UNITS = 284_500;

/*
 * Delegate spend: the frozen v0.5 model plus the measured v0.7 delta of
 * +2,182 script units (the generalised family closure), with the v0.5
 * token-template slope, depth allowance and headroom carried unchanged.
 */
const SPEND_BASE = 199_252 + 2_182; /* v0.5 measured base + the v0.7 delta */
const RECOVER_TOKEN_TEMPLATE_SLOPE = 24;
const TOKEN_TEMPLATE_REFERENCE_BYTES = 1_522; /* prefix 1 + suffix 1,521 (bound 2) */
const DEPTH_ALLOWANCE = 51_261; /* agent depth 12 + recipient depth 16, measured */

const V7_BUDGET = Object.freeze({
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v7: ${message}`);
}

function ceilBudget(units) {
  const n = Math.ceil(units / UNITS_PER_BUDGET);
  if (!Number.isInteger(n) || n < 1 || n > 65_535) fail(`computed compute budget ${n} is outside the u16 domain`);
  return n;
}

/* The budget rusty-kaspa would actually REQUIRE for `units` priced units. */
function requiredBudgetForUnits(units) {
  if (!Number.isInteger(units) || units < 0) fail("units must be a non-negative integer");
  const charged = Math.max(0, units - (UNITS_PER_BUDGET - 1));
  return Math.ceil(charged / UNITS_PER_BUDGET);
}

function activeSlots(value) {
  const n = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isInteger(n) || n < 1 || n > OWNER_SLOTS_V7) {
    fail(`activeOwnerSlots must be an integer 1..${OWNER_SLOTS_V7} — the root's priced cost scales with the ACTIVE slots it inspects`);
  }
  return n;
}

function rootScriptUnits({ activeOwnerSlots, wfNew }) {
  const n = activeSlots(activeOwnerSlots);
  return ROOT_BASE_1_ACTIVE + ROOT_PER_ACTIVE_SLOT * (n - 1) + (wfNew ? ROOT_WF_NEW_ALLOWANCE : 0);
}

/*
 * The committed budget for a ROOT covenant input, for either a root-only
 * transaction or the root input that authorizes a rooted vault operation.
 */
function selectRootComputeBudgetV7({ actionName, activeOwnerSlots }) {
  switch (actionName) {
    case "authorize":
    case "freeze":
    case "unfreeze": {
      const n = activeSlots(activeOwnerSlots);
      return ceilBudget(rootScriptUnits({ activeOwnerSlots: n, wfNew: false }) + SIGOP_UNITS * n + HEADROOM);
    }
    case "rotate":
    case "ownerRecover": {
      const n = activeSlots(activeOwnerSlots);
      return ceilBudget(rootScriptUnits({ activeOwnerSlots: n, wfNew: true }) + SIGOP_UNITS * n + HEADROOM);
    }
    case "succession":
      return ceilBudget(ROOT_SUCCESSION_SCRIPT_UNITS + SIGOP_UNITS + HEADROOM);
    default:
      return fail(`unknown v0.7 root action ${JSON.stringify(actionName)} — failing closed`);
  }
}

function rootTemplateBytes({ rootPrefixLen, rootSuffixLen }) {
  if (!Number.isInteger(rootPrefixLen) || !Number.isInteger(rootSuffixLen) || rootPrefixLen < 0 || rootSuffixLen < 0) {
    fail("root template geometry (rootPrefixLen/rootSuffixLen) is required to size a rooted-vault owner budget");
  }
  return rootPrefixLen + rootSuffixLen;
}

function tokenTemplateBytes({ templatePrefixLen, templateSuffixLen }) {
  if (!Number.isInteger(templatePrefixLen) || !Number.isInteger(templateSuffixLen) || templatePrefixLen < 0 || templateSuffixLen < 0) {
    fail("token template geometry (templatePrefixLen/templateSuffixLen) is required to size a template-scaled budget");
  }
  return templatePrefixLen + templateSuffixLen;
}

/* The committed budget for the ROOTED VAULT covenant input. */
function selectComputeBudgetV7({ operation, templatePrefixLen, templateSuffixLen, rootPrefixLen, rootSuffixLen }) {
  switch (operation) {
    case "tokenAgentSpend": {
      const extra = Math.max(0, tokenTemplateBytes({ templatePrefixLen, templateSuffixLen }) - TOKEN_TEMPLATE_REFERENCE_BYTES) * RECOVER_TOKEN_TEMPLATE_SLOPE;
      return ceilBudget(SPEND_BASE + extra + DEPTH_ALLOWANCE + HEADROOM);
    }
    case "ownerSetAgentRoot":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
    case "ownerEmergencyPause": {
      const rootExtra = Math.max(0, rootTemplateBytes({ rootPrefixLen, rootSuffixLen }) - ROOT_TEMPLATE_REFERENCE_BYTES) * ROOT_TEMPLATE_SLOPE;
      return ceilBudget(VAULT_OWNER_CONTROL_UNITS + rootExtra + HEADROOM);
    }
    case "ownerRecover": {
      const rootExtra = Math.max(0, rootTemplateBytes({ rootPrefixLen, rootSuffixLen }) - ROOT_TEMPLATE_REFERENCE_BYTES) * ROOT_TEMPLATE_SLOPE;
      const tokenExtra = Math.max(0, tokenTemplateBytes({ templatePrefixLen, templateSuffixLen }) - TOKEN_TEMPLATE_REFERENCE_BYTES) * RECOVER_TOKEN_TEMPLATE_SLOPE;
      return ceilBudget(VAULT_OWNER_RECOVER_UNITS + rootExtra + tokenExtra + HEADROOM);
    }
    default:
      return fail(`unknown v0.7 rooted-vault operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/*
 * Committed budget for a TOKEN-FAMILY input executing the reference KCC20
 * program — identical arithmetic to the frozen v0.5 model (the agent path is
 * byte-for-byte v0.5 and the token family never sees the root).
 */
function selectTokenInputBudgetV7({ templatePrefixLen, templateSuffixLen, signerOwned = false }) {
  const base = 20_000 + RECOVER_TOKEN_TEMPLATE_SLOPE * tokenTemplateBytes({ templatePrefixLen, templateSuffixLen });
  return Math.max(4, ceilBudget(base + (signerOwned ? SIGOP_UNITS : 0)));
}

function assertBudgetSufficientV7({ operation, committed, ...geometry }) {
  const required = selectComputeBudgetV7({ operation, ...geometry });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

function assertRootBudgetSufficientV7({ actionName, activeOwnerSlots, committed }) {
  const required = selectRootComputeBudgetV7({ actionName, activeOwnerSlots });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for root ${actionName}`);
  }
  return committed;
}

module.exports = {
  V7_BUDGET,
  UNITS_PER_BUDGET,
  SIGOP_UNITS,
  ROOT_TEMPLATE_REFERENCE_BYTES,
  requiredBudgetForUnits,
  rootScriptUnits,
  selectRootComputeBudgetV7,
  selectComputeBudgetV7,
  selectTokenInputBudgetV7,
  assertBudgetSufficientV7,
  assertRootBudgetSufficientV7
};
