"use strict";

/*
 * v0.7 ROOTED KAS VAULT transition planner
 * (contracts/PolicyVault.v0.7-kas.sil, derived from the FROZEN v0.4.1).
 *
 * The vault's STATE MATH is the frozen v0.4.1 math, so this module DELEGATES
 * to core/model/vault-transitions-v4.js rather than restating rules that are
 * already VM-proven and byte-frozen. What v0.7-kas adds is the AUTHORITY:
 *
 *   - there is no owner key and no owner signature; an owner operation is
 *     valid only when the same transaction ALSO spends the pinned
 *     organizational root, and the vault pins that root's EXACT successor
 *     bytes so it can tell WHICH root path ran;
 *   - `ownerControl` merges v0.4.1's six selectors (0..5, all requiring the
 *     root's AUTHORIZE/full quorum) with a new EMERGENCY pause (selector 6,
 *     the ONLY vault effect reachable from the root's LIGHTER emergency
 *     quorum — a FREEZE root successor);
 *   - `ownerRecover` pays protectedValue + feeReserve to the GENESIS-PINNED
 *     cold destination `recoveryPk` — never to an address a quorum-signing
 *     session can choose — under the root's FULL quorum (AUTHORIZE);
 *   - the DELEGATE path (`agentSpend`) never touches the root at all and is
 *     byte-for-byte the frozen v0.4.1 logic (including D2:
 *     require(periodLengthDaa > 0), which the FROZEN v0.4.1 base itself does
 *     NOT have — v0.7-kas adds it, so this module rejects a zero-length
 *     period at the SAME boundary the covenant does).
 *
 * Every plan therefore carries `rootAuthority` — the root action the
 * transaction MUST also run, and the frozen byte the vault will pin — so a
 * builder can never assemble a vault operation without the matching root
 * path, and a manifest can state the required organizational authority.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-transitions-v7-kas.test.js).
 */

const { parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey } = require("./vault-state");
const { resolveOwnerOpAuthorityV7Kas, OWNER_OP_SELECTOR_V7_KAS } = require("./vault-state-v7-kas");
const {
  agentSpendSuccessorV4,
  setAgentRootSuccessorV4,
  setApproversSuccessorV4,
  topUpSuccessorV4,
  topUpReserveSuccessorV4,
  pauseSuccessorV4,
  MAX_PERIODS_ELAPSED
} = require("./vault-transitions-v4");

function fail(message, code) {
  const e = new Error(`vault-transitions-v7-kas: ${message}`);
  if (code) e.code = code;
  throw e;
}

function authority(action) {
  const info = resolveOwnerOpAuthorityV7Kas(action);
  return Object.freeze({
    action,
    opSelector: info.opSelector,
    rootActionName: info.rootActionName,
    expectFrozenAfter: info.expectFrozenAfter,
    quorum: info.rootActionName === "freeze" ? "emergencyK" : "ownerM"
  });
}

/*
 * DELEGATE spend — the frozen v0.4.1 rules PLUS DEVIATION D2: a zero-length
 * period makes the period budget vacuous (the v0.6 adversarial-review
 * finding F1, carried into every v0.7 generation). The FROZEN v0.4.1
 * covenant itself lacks this check (its leaves are owner-committed, so it is
 * an owner-misconfiguration hazard there, not a delegate escalation), so
 * vault-transitions-v4.js is NEVER changed; this wrapper adds the same
 * boundary the v0.7-kas covenant enforces, so a builder can never derive a
 * plan the covenant would reject on that ground. NO root input exists.
 */
function agentSpendSuccessorV7Kas(state, params) {
  const policy = params && params.agentPolicy;
  if (policy && policy.periodLengthDaa !== undefined) {
    const periodLengthDaa = typeof policy.periodLengthDaa === "bigint" ? policy.periodLengthDaa : BigInt(policy.periodLengthDaa);
    if (periodLengthDaa <= 0n) {
      fail("agentSpend: D2 — periodLengthDaa must be > 0 (a zero-length period makes the period budget vacuous)", "D2_ZERO_LENGTH_PERIOD");
    }
  }
  const plan = agentSpendSuccessorV4(state, params);
  return Object.freeze({ ...plan, rootAuthority: null, requiresRootInput: false });
}

function setAgentRootSuccessorV7Kas(state, newAgentRoot) {
  const successor = setAgentRootSuccessorV4(state, newAgentRoot);
  return Object.freeze({ successor, opSelector: OWNER_OP_SELECTOR_V7_KAS.ownerSetAgentRoot, rootAuthority: authority("ownerSetAgentRoot"), requiresRootInput: true });
}

function setApproversSuccessorV7Kas(state, params) {
  const successor = setApproversSuccessorV4(state, params);
  return Object.freeze({ successor, opSelector: OWNER_OP_SELECTOR_V7_KAS.ownerSetApprovers, rootAuthority: authority("ownerSetApprovers"), requiresRootInput: true });
}

function topUpSuccessorV7Kas(state, topUpAmount) {
  const successor = topUpSuccessorV4(state, topUpAmount);
  return Object.freeze({ successor, opSelector: OWNER_OP_SELECTOR_V7_KAS.ownerTopUp, rootAuthority: authority("ownerTopUp"), requiresRootInput: true });
}

function topUpReserveSuccessorV7Kas(state, topUpAmount) {
  const successor = topUpReserveSuccessorV4(state, topUpAmount);
  return Object.freeze({ successor, opSelector: OWNER_OP_SELECTOR_V7_KAS.ownerTopUpReserve, rootAuthority: authority("ownerTopUpReserve"), requiresRootInput: true });
}

function pauseSuccessorV7Kas(state, pause) {
  const successor = pauseSuccessorV4(state, pause);
  const action = pause ? "ownerPause" : "ownerUnpause";
  return Object.freeze({
    successor,
    opSelector: pause ? OWNER_OP_SELECTOR_V7_KAS.ownerPause : OWNER_OP_SELECTOR_V7_KAS.ownerUnpause,
    rootAuthority: authority(action),
    requiresRootInput: true
  });
}

/*
 * EMERGENCY pause (selector 6): the identical state effect to selector 4 but
 * a strictly LIGHTER root authority (the root runs FREEZE under emergencyK).
 * AUTHORITY-REDUCING and monotone — paused 0 -> 1, every other field
 * preserved, policyNonce included, no value movement. Unpausing is selector 5
 * and needs the FULL quorum.
 */
function emergencyPauseSuccessorV7Kas(state) {
  const successor = pauseSuccessorV4(state, true);
  return Object.freeze({ successor, opSelector: OWNER_OP_SELECTOR_V7_KAS.ownerEmergencyPause, rootAuthority: authority("ownerEmergencyPause"), requiresRootInput: true });
}

/*
 * ownerRecover (TERMINAL): protectedValue + feeReserve pay out to the
 * GENESIS-PINNED recoveryPk. The destination is a template constant, NOT a
 * parameter of the signing session — unlike v0.4.1's plain recoverPlanV4,
 * which pays the removed owner key.
 */
function recoverPlanV7Kas(state, template) {
  if (!state || typeof state !== "object" || typeof state.protectedValue !== "bigint" || typeof state.feeReserve !== "bigint") {
    fail("recover: normalized predecessor state is required");
  }
  if (!template || typeof template !== "object") fail("recover: the vault template is required (recoveryPk is pinned at genesis)");
  const recoveryPk = normalizeXOnlyPubkey(template.recoveryPk, "template.recoveryPk");
  return Object.freeze({
    terminal: true,
    payoutXOnly: recoveryPk,
    payoutValue: state.protectedValue + state.feeReserve,
    opSelector: null,
    rootAuthority: authority("ownerRecover"),
    requiresRootInput: true
  });
}

/*
 * Dispatch by SDK action; unknown actions fail closed. `state` MUST already
 * be normalized (typeof state.policyNonce === "bigint") — callers normalize
 * once via normalizeStateV7Kas before dispatch (matching vault-builders-v7.js
 * for the payment profile). Re-normalizing here would be UNSAFE for v0.4's
 * approvers/approverSlots field-name overlap: a normalized state's own
 * `approvers` field is the padded 10-slot array, which normalizeStateV4
 * would otherwise misinterpret as the "active keys only" input form and
 * reject on the first sentinel slot. Each underlying v4 transition function
 * already enforces normalization via requireContinuingState.
 */
function ownerOpSuccessorV7Kas(action, state, params = {}) {
  if (!state || typeof state !== "object" || typeof state.policyNonce !== "bigint") {
    fail("ownerOpSuccessorV7Kas: state must already be normalized via normalizeStateV7Kas (BigInt fields) — refusing to guess the approvers/approverSlots shape");
  }
  const s = state;
  switch (action) {
    case "ownerSetAgentRoot": {
      if (params.newAgentRoot === undefined) fail("ownerSetAgentRoot requires params.newAgentRoot");
      return { ...setAgentRootSuccessorV7Kas(s, params.newAgentRoot), externalFunding: 0n };
    }
    case "ownerSetApprovers":
      return { ...setApproversSuccessorV7Kas(s, params), externalFunding: 0n };
    case "ownerTopUp": {
      const amount = parsePositiveSompi(params.topUpAmountSompi, "topUpAmountSompi");
      return { ...topUpSuccessorV7Kas(s, amount), externalFunding: amount };
    }
    case "ownerTopUpReserve": {
      const amount = parsePositiveSompi(params.topUpReserveAmountSompi, "topUpReserveAmountSompi");
      return { ...topUpReserveSuccessorV7Kas(s, amount), externalFunding: amount };
    }
    case "ownerPause":
      return { ...pauseSuccessorV7Kas(s, true), externalFunding: 0n };
    case "ownerUnpause":
      return { ...pauseSuccessorV7Kas(s, false), externalFunding: 0n };
    case "ownerEmergencyPause":
      return { ...emergencyPauseSuccessorV7Kas(s), externalFunding: 0n };
    default:
      return fail(`unknown v0.7-kas rooted-vault owner action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  }
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  agentSpendSuccessorV7Kas,
  setAgentRootSuccessorV7Kas,
  setApproversSuccessorV7Kas,
  topUpSuccessorV7Kas,
  topUpReserveSuccessorV7Kas,
  pauseSuccessorV7Kas,
  emergencyPauseSuccessorV7Kas,
  recoverPlanV7Kas,
  ownerOpSuccessorV7Kas
};
