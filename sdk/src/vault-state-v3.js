"use strict";

/*
 * Exact live-state model for a PolicyVault v0.3 vault.
 *
 * v0.3 identity = immutable template constants (owner, vaultId) + mutable
 * state. Over v0.2 it adds a Merkle recipient allowlist (recipientRoot)
 * and a covenant-enforced M-of-N approval policy over up to 10 fixed
 * distinct approver slots (sentinel = the all-zero pubkey).
 *
 * Strict, fail-closed normalization ONLY — no transaction building here
 * (that is later SDK work). Enforces the funds-critical set-time rules the
 * covenant relies on:
 *   - approver x-only keys are distinct among ACTIVE slots (Phase 3.5 A2);
 *   - 1 <= approvalM <= activeApproverCount when there is an approval tier;
 *   - the "no approval tier" config (0 approvers) requires approvalM == 0
 *     AND approvalThresholdAmount >= maxPerSpend, so a spend can never
 *     exceed the threshold and approvals can never be required on-chain.
 * All quantities are BigInt sompi / integers — never JS Number.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");

const CONTRACT_VERSION_V3 = "policyvault-0.3";
const MAX_APPROVERS = 10;
const APPROVER_SENTINEL = "00".repeat(32);
const DAA_LOCK_THRESHOLD = 500_000_000_000n;

function fail(message) {
  throw new Error(`vault-state-v3: ${message}`);
}

function normalizeDaa(value, field) {
  const daa = parseSompi(value, field);
  if (daa >= DAA_LOCK_THRESHOLD) {
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

/* v0.3 immutable template constants. */
function normalizeTemplateV3(input) {
  if (!input || typeof input !== "object") {
    fail("template object is required");
  }
  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "template.owner"),
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId")
  });
}

/*
 * Recipient root: exactly 32-byte lowercase hex (the SHA-256 Merkle
 * commitment). The tree/proof builder is separate SDK work; here we only
 * validate the on-chain commitment value.
 */
function normalizeRecipientRoot(value) {
  return normalizeHex(value, 32, "state.recipientRoot");
}

/*
 * Approver set. Two accepted input forms:
 *
 *  - `input.approvers`: an array of 0..10 x-only hex strings for the
 *    ACTIVE approvers (the creation form). The SDK canonicalizes: sorts
 *    ascending and pads with sentinels, so one approver set has exactly
 *    one layout. NOTE: the PRODUCTION covenant does NOT require sorted
 *    order — it enforces distinctness via 45 pairwise `!=` checks (byte
 *    ordering aborts on 32-byte keys, Phase 4.5) — sorting is purely the
 *    SDK's deterministic canonical convention.
 *
 *  - `input.approverSlots`: an EXACT 10-slot layout (sentinels allowed in
 *    any position). Used when reloading persisted/observed state: the slot
 *    layout is consensus-visible (it is baked into the compiled script),
 *    so it must be preserved EXACTLY, never re-sorted.
 *
 * Fails closed on: too many, malformed key, the sentinel passed as an
 * active key (creation form), or a duplicate active key.
 */
function normalizeApprovers(input) {
  if (input.approverSlots !== undefined) {
    const slots = input.approverSlots;
    if (!Array.isArray(slots) || slots.length !== MAX_APPROVERS) {
      fail(`state.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
    }
    const seen = new Set();
    let activeCount = 0;
    const normalized = slots.map((k, i) => {
      const key = normalizeHex(k, 32, `state.approverSlots[${i}]`);
      if (key !== APPROVER_SENTINEL) {
        if (seen.has(key)) {
          fail(`state.approverSlots[${i}] duplicates an earlier active approver key — active approver keys must be distinct`);
        }
        seen.add(key);
        activeCount += 1;
      }
      return key;
    });
    return { approvers: Object.freeze(normalized), activeCount };
  }

  const raw = input.approvers;
  if (!Array.isArray(raw)) {
    fail("state.approvers must be an array (0..10 x-only pubkeys) or state.approverSlots an exact 10-slot layout");
  }
  if (raw.length > MAX_APPROVERS) {
    fail(`state.approvers has ${raw.length} entries; max is ${MAX_APPROVERS}`);
  }
  const active = [];
  const seen = new Set();
  raw.forEach((k, i) => {
    const key = normalizeXOnlyPubkey(k, `state.approvers[${i}]`);
    if (key === APPROVER_SENTINEL) {
      fail(`state.approvers[${i}] is the all-zero sentinel; pass only active approver keys`);
    }
    if (seen.has(key)) {
      fail(`state.approvers[${i}] duplicates an earlier approver key — active approver keys must be distinct`);
    }
    seen.add(key);
    active.push(key);
  });
  active.sort();
  const padded = active.slice();
  while (padded.length < MAX_APPROVERS) {
    padded.push(APPROVER_SENTINEL);
  }
  return { approvers: Object.freeze(padded), activeCount: active.length };
}

/*
 * v0.3 mutable state. Every field strictly validated; approval policy
 * cross-checked against the active approver count.
 */
function normalizeStateV3(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const maxPerSpend = parsePositiveSompi(input.maxPerSpend, "state.maxPerSpend");
  const periodBudget = parsePositiveSompi(input.periodBudget, "state.periodBudget");
  if (periodBudget < maxPerSpend) {
    fail("state.periodBudget must be >= state.maxPerSpend");
  }

  const { approvers, activeCount } = normalizeApprovers(input);
  const approvalM = normalizeSmallInt(input.approvalM, "state.approvalM", { min: 0n, max: BigInt(MAX_APPROVERS) });
  const approvalThresholdAmount = parseSompi(input.approvalThresholdAmount, "state.approvalThresholdAmount");
  if (approvalThresholdAmount < 0n) {
    fail("state.approvalThresholdAmount must be >= 0");
  }

  if (activeCount === 0) {
    // No approval tier: approvals must be unreachable on-chain.
    if (approvalM !== 0n) {
      fail("state.approvalM must be 0 when there are no active approvers");
    }
    if (approvalThresholdAmount < maxPerSpend) {
      fail(
        "a vault with no approvers must set approvalThresholdAmount >= maxPerSpend " +
          "so a spend can never require approvals"
      );
    }
  } else {
    if (approvalM < 1n) {
      fail("state.approvalM must be >= 1 when approvers are configured");
    }
    if (approvalM > BigInt(activeCount)) {
      fail(`state.approvalM (${approvalM}) exceeds the active approver count (${activeCount})`);
    }
  }

  return Object.freeze({
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    periodStartDaa: normalizeDaa(input.periodStartDaa, "state.periodStartDaa"),
    periodSpent: parseSompi(input.periodSpent, "state.periodSpent"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    delegate: normalizeXOnlyPubkey(input.delegate, "state.delegate"),
    delegateActive: normalizeSmallInt(input.delegateActive, "state.delegateActive", { min: 0n, max: 1n }),
    maxPerSpend,
    periodBudget,
    periodLengthDaa: normalizeSmallInt(input.periodLengthDaa, "state.periodLengthDaa", { min: 1n, max: DAA_LOCK_THRESHOLD }),
    recipientRoot: normalizeRecipientRoot(input.recipientRoot),
    approvers,
    activeApproverCount: activeCount,
    approvalM,
    approvalThresholdAmount,
    /* Consensus-visible; REQUIRED — no implicit default (fail closed). */
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/*
 * RECOVERY-MODE normalization (break-glass parse; Phase 4H §13).
 *
 * Consensus does NOT validate v0.3 genesis state, so a hand-baked UTXO can
 * carry an approver set the strict normalizer rejects (duplicate active
 * keys, approvalM = 0 with active approvers, M > activeCount, budget <
 * cap, …). The production covenant still allows ownerRecover from such a
 * state, and the SDK must be able to CONSTRUCT that recovery — which
 * requires compiling the EXACT malformed state, not a sanitized one.
 *
 * This parser validates only the field SHAPES needed for exact-state
 * compilation (hex widths, integer domains) and preserves the approver
 * slot layout exactly, INCLUDING duplicates. It performs NO approval-
 * policy validation. The result is marked `recoveryParse: true` and MUST
 * only be used for ownerRecover construction — every ordinary transition
 * builder rejects it.
 */
function normalizeStateV3ForRecovery(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const slotsIn = input.approverSlots ?? input.approvers;
  if (!Array.isArray(slotsIn) || slotsIn.length > MAX_APPROVERS) {
    fail(`recovery parse requires an approver slot array of at most ${MAX_APPROVERS} entries`);
  }
  const slots = slotsIn.map((k, i) => normalizeHex(k, 32, `state.approverSlots[${i}]`));
  while (slots.length < MAX_APPROVERS) {
    slots.push(APPROVER_SENTINEL);
  }
  let activeCount = 0;
  for (const s of slots) {
    if (s !== APPROVER_SENTINEL) activeCount += 1;
  }
  /* Shape-only integer domains: recovery ignores policy semantics, so a
   * paused=1/delegateActive=0/duplicate-approver/M=0/budget<cap state all
   * parse — only widths and the representable integer range are enforced
   * (the compiled template substitutes the exact values). */
  return Object.freeze({
    recoveryParse: true,
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    periodStartDaa: parseSompi(input.periodStartDaa, "state.periodStartDaa"),
    periodSpent: parseSompi(input.periodSpent, "state.periodSpent"),
    paused: parseSompi(input.paused, "state.paused"),
    delegate: normalizeXOnlyPubkey(input.delegate, "state.delegate"),
    delegateActive: parseSompi(input.delegateActive, "state.delegateActive"),
    maxPerSpend: parseSompi(input.maxPerSpend, "state.maxPerSpend"),
    periodBudget: parseSompi(input.periodBudget, "state.periodBudget"),
    periodLengthDaa: parseSompi(input.periodLengthDaa, "state.periodLengthDaa"),
    recipientRoot: normalizeRecipientRoot(input.recipientRoot),
    approvers: Object.freeze(slots),
    activeApproverCount: activeCount,
    approvalM: parseSompi(input.approvalM, "state.approvalM"),
    approvalThresholdAmount: parseSompi(input.approvalThresholdAmount, "state.approvalThresholdAmount"),
    policyNonce: parseSompi(input.policyNonce, "state.policyNonce")
  });
}

/* Deterministic v0.3 state ID (application identity, versioned encoding). */
function computeStateIdV3({ networkId, template, state }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  const canonical = [
    "policyvault-state/v3",
    `network:${networkId}`,
    `contract:${CONTRACT_VERSION_V3}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `protectedValue:${state.protectedValue}`,
    `periodStartDaa:${state.periodStartDaa}`,
    `periodSpent:${state.periodSpent}`,
    `paused:${state.paused}`,
    `delegate:${state.delegate}`,
    `delegateActive:${state.delegateActive}`,
    `maxPerSpend:${state.maxPerSpend}`,
    `periodBudget:${state.periodBudget}`,
    `periodLengthDaa:${state.periodLengthDaa}`,
    `recipientRoot:${state.recipientRoot}`,
    `approvers:${state.approvers.join(",")}`,
    `approvalM:${state.approvalM}`,
    `approvalThresholdAmount:${state.approvalThresholdAmount}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/* policyNonce is consensus-visible: never default it implicitly. */
function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

/* JSON-safe encoding (BigInt -> digit strings) for manifests/receipts. */
function stateToJsonV3(state) {
  return {
    protectedValue: state.protectedValue.toString(),
    periodStartDaa: state.periodStartDaa.toString(),
    periodSpent: state.periodSpent.toString(),
    paused: state.paused.toString(),
    delegate: state.delegate,
    delegateActive: state.delegateActive.toString(),
    maxPerSpend: state.maxPerSpend.toString(),
    periodBudget: state.periodBudget.toString(),
    periodLengthDaa: state.periodLengthDaa.toString(),
    recipientRoot: state.recipientRoot,
    approverSlots: [...state.approvers],
    approvalM: state.approvalM.toString(),
    approvalThresholdAmount: state.approvalThresholdAmount.toString(),
    policyNonce: requireNonce(state).toString()
  };
}

module.exports = {
  CONTRACT_VERSION_V3,
  MAX_APPROVERS,
  APPROVER_SENTINEL,
  normalizeTemplateV3,
  normalizeStateV3,
  normalizeStateV3ForRecovery,
  normalizeApprovers,
  normalizeRecipientRoot,
  computeStateIdV3,
  stateToJsonV3
};
