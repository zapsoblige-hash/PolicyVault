"use strict";

/*
 * Exact live-state model for a PolicyVault vault.
 *
 * A vault's full identity = immutable policy (constructor params, part of
 * the compiled template) + mutable state fields + contract version +
 * network. There is exactly one current live state; its deterministic
 * state ID names build artifacts and binds requests.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { CONTRACT_VERSION } = require("./config");

function fail(message) {
  throw new Error(`vault-state: ${message}`);
}

function normalizeHex(value, bytes, field) {
  if (typeof value !== "string") {
    fail(`${field} must be a hex string`);
  }
  const normalized = value.trim().toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(normalized)) {
    fail(`${field} must be ${bytes}-byte lowercase hex`);
  }
  return normalized;
}

function normalizeXOnlyPubkey(value, field) {
  return normalizeHex(value, 32, field);
}

function normalizeDaa(value, field) {
  const daa = parseSompi(value, field); // same digit-string/BigInt rules
  /*
   * DAA-score locks must stay below LOCK_TIME_THRESHOLD (5e11) so
   * tx.time comparisons keep DAA semantics (rusty-kaspa constants.rs).
   */
  if (daa >= 500_000_000_000n) {
    fail(`${field} must be below the DAA lock-time threshold`);
  }
  return daa;
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

/*
 * Immutable policy. recipients: array of 1..3 x-only pubkey hex strings;
 * unused slots repeat the first recipient so the compiled template stays
 * shaped for exactly 3.
 */
function normalizePolicy(input) {
  if (!input || typeof input !== "object") {
    fail("policy object is required");
  }

  const recipientsIn = input.recipients;
  if (!Array.isArray(recipientsIn) || recipientsIn.length < 1 || recipientsIn.length > 3) {
    fail("policy.recipients must contain 1 to 3 recipients");
  }
  const recipients = recipientsIn.map((r, i) => normalizeXOnlyPubkey(r, `policy.recipients[${i}]`));
  const padded = [recipients[0], recipients[1] ?? recipients[0], recipients[2] ?? recipients[1] ?? recipients[0]];

  const maxPerSpend = parsePositiveSompi(input.maxPerSpend, "policy.maxPerSpend");
  const periodBudget = parsePositiveSompi(input.periodBudget, "policy.periodBudget");
  if (periodBudget < maxPerSpend) {
    fail("policy.periodBudget must be >= policy.maxPerSpend");
  }

  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "policy.owner"),
    delegate: normalizeXOnlyPubkey(input.delegate, "policy.delegate"),
    vaultId: normalizeHex(input.vaultId, 32, "policy.vaultId"),
    maxPerSpend,
    periodBudget,
    periodLengthDaa: normalizeSmallInt(input.periodLengthDaa, "policy.periodLengthDaa", {
      min: 1n,
      max: 500_000_000_000n
    }),
    recipients: Object.freeze(padded),
    declaredRecipientCount: recipients.length,
    initValue: parsePositiveSompi(input.initValue, "policy.initValue"),
    initPeriodStartDaa: normalizeDaa(input.initPeriodStartDaa, "policy.initPeriodStartDaa")
  });
}

/* Mutable state fields. */
function normalizeState(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const protectedValue = parsePositiveSompi(input.protectedValue, "state.protectedValue");
  const periodSpent = parseSompi(input.periodSpent, "state.periodSpent");
  const paused = normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n });
  return Object.freeze({
    protectedValue,
    periodStartDaa: normalizeDaa(input.periodStartDaa, "state.periodStartDaa"),
    periodSpent,
    paused
  });
}

/*
 * Deterministic application-level state ID: sha256 over a canonical,
 * versioned, field-tagged encoding. (Application identity only — never a
 * consensus value.)
 */
function computeStateId({ networkId, policy, state }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  const canonical = [
    "policyvault-state/v1",
    `network:${networkId}`,
    `contract:${CONTRACT_VERSION}`,
    `owner:${policy.owner}`,
    `delegate:${policy.delegate}`,
    `vaultId:${policy.vaultId}`,
    `maxPerSpend:${policy.maxPerSpend}`,
    `periodBudget:${policy.periodBudget}`,
    `periodLengthDaa:${policy.periodLengthDaa}`,
    `recipients:${policy.recipients.join(",")}`,
    `initValue:${policy.initValue}`,
    `initPeriodStartDaa:${policy.initPeriodStartDaa}`,
    `protectedValue:${state.protectedValue}`,
    `periodStartDaa:${state.periodStartDaa}`,
    `periodSpent:${state.periodSpent}`,
    `paused:${state.paused}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/* The exact successor state for a within-period delegate spend. */
function spendSuccessor(state, payAmount) {
  const pay = parsePositiveSompi(payAmount, "payAmount");
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return Object.freeze({
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa,
    periodSpent: state.periodSpent + pay,
    paused: 0n
  });
}

/* The exact successor state for a rollover-and-spend. */
function rolloverSuccessor(policy, state, payAmount, periodsElapsed) {
  const pay = parsePositiveSompi(payAmount, "payAmount");
  const periods = normalizeSmallInt(periodsElapsed, "periodsElapsed", { min: 1n, max: 1000n });
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return Object.freeze({
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa + periods * policy.periodLengthDaa,
    periodSpent: pay,
    paused: 0n
  });
}

module.exports = {
  normalizePolicy,
  normalizeState,
  computeStateId,
  spendSuccessor,
  rolloverSuccessor,
  normalizeHex,
  normalizeXOnlyPubkey
};
