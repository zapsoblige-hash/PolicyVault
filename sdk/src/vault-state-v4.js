"use strict";

/*
 * Exact live-state model for a PolicyVault v0.4 vault (FROZEN ABI,
 * docs/covenant-spec-v0.4.md). Low-level normalization + exact serialization
 * only — NO transaction builders (that is a later phase, deliberately not
 * implemented in Checkpoint C).
 *
 * v0.4 identity = immutable template (owner, vaultId) + 17 mutable state
 * fields. The single v0.3 delegate and its per-delegate policy move INTO the
 * per-agent authenticated leaf (agentRoot commitment), so fixed state holds
 * only: boundVaultId, protectedValue, feeReserve, paused, agentRoot,
 * approver1..10, approvalM, policyNonce. The covenant UTXO holds
 * protectedValue + feeReserve. All quantities are BigInt sompi / integers.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");

const CONTRACT_VERSION_V4 = "policyvault-0.4";
// v0.4.1 STANDARDNESS REDESIGN: byte-identical state ABI to v0.4, but the six
// owner operations are consolidated behind ownerControl + opSelector so the
// redeem script carries 13 (<=15) static sig-ops and relays on a default node.
const CONTRACT_VERSION_V4_1 = "policyvault-0.4.1";
const MAX_APPROVERS = 10;

/*
 * Version-ABI descriptors. Everything about v0.4 and v0.4.1 is identical EXCEPT
 * the version tag, the on-disk covenant path, the artifact build subdir (kept
 * separate so identical state never reads the wrong version's cached script),
 * and — for owner operations only — the encoder call shape. Unknown versions
 * FAIL CLOSED; there is no cross-version fallback.
 */
const V4_ABIS = Object.freeze({
  [CONTRACT_VERSION_V4]: Object.freeze({
    version: CONTRACT_VERSION_V4,
    contractRelPath: "contracts/PolicyVault.v0.4.sil",
    buildSubdir: "build-v4",
    // v0.4: each owner op is its own covenant entrypoint (no opSelector).
    consolidatedOwner: false
  }),
  [CONTRACT_VERSION_V4_1]: Object.freeze({
    version: CONTRACT_VERSION_V4_1,
    contractRelPath: "contracts/PolicyVault.v0.4.1.sil",
    buildSubdir: "build-v4_1",
    // v0.4.1: owner ops are ONE ownerControl entrypoint + opSelector.
    consolidatedOwner: true
  })
});

// v0.4.1 owner sdkAction -> ownerControl opSelector (mutually exclusive branches).
const OWNER_OP_SELECTOR_V4_1 = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerSetApprovers: 1,
  ownerTopUp: 2,
  ownerTopUpReserve: 3,
  ownerPause: 4,
  ownerUnpause: 5
});

function resolveV4Abi(contractVersion) {
  const abi = V4_ABIS[contractVersion ?? CONTRACT_VERSION_V4];
  if (!abi) {
    fail(`unknown contract version ${JSON.stringify(contractVersion)} for the v0.4 family — failing closed (no cross-version fallback)`);
  }
  return abi;
}
const APPROVER_SENTINEL = "00".repeat(32);

function fail(message) {
  throw new Error(`vault-state-v4: ${message}`);
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

/* v0.4 immutable template constants. */
function normalizeTemplateV4(input) {
  if (!input || typeof input !== "object") {
    fail("template object is required");
  }
  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "template.owner"),
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId")
  });
}

/*
 * Approver slots. Two accepted input forms (mirrors v0.3): `approvers`
 * (0..10 active x-only keys, canonicalized: sorted + padded) or
 * `approverSlots` (exact 10-slot layout, preserved verbatim). Fails closed
 * on: too many, malformed key, sentinel as an active key, or duplicate
 * active key.
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
 * v0.4 mutable state. Every field strictly validated; approver policy
 * cross-checked against the active approver count (a vault MAY have zero
 * approvers and approvalM 0 — an all-agent-below-their-own-threshold vault;
 * when approvers are configured, 1 <= approvalM <= activeCount).
 */
function normalizeStateV4(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const { approvers, activeCount } = normalizeApprovers(input);
  const approvalM = normalizeSmallInt(input.approvalM, "state.approvalM", { min: 0n, max: BigInt(MAX_APPROVERS) });
  if (activeCount === 0) {
    if (approvalM !== 0n) {
      fail("state.approvalM must be 0 when there are no active approvers");
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
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    approvers,
    activeApproverCount: activeCount,
    approvalM,
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/*
 * BREAK-GLASS shape-only parse for ownerRecover (Checkpoint E; mirrors
 * v0.3's normalizeStateV3ForRecovery). Consensus does not validate genesis
 * state, so a manually-baked v0.4 UTXO can carry duplicate approver keys,
 * an inconsistent approvalM, paused=1, or a garbage agentRoot — and the
 * covenant still allows ownerRecover from it. This parse enforces ONLY
 * widths and representable integer domains (the compiled template
 * substitutes the exact values); it is quarantined to ownerRecover by the
 * `recoveryParse: true` marker, which every ordinary transition rejects.
 */
function normalizeStateV4ForRecovery(input) {
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
  return Object.freeze({
    recoveryParse: true,
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: parseSompi(input.paused, "state.paused"),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    approvers: Object.freeze(slots),
    activeApproverCount: activeCount,
    approvalM: parseSompi(input.approvalM, "state.approvalM"),
    policyNonce: parseSompi(input.policyNonce, "state.policyNonce")
  });
}

/* Deterministic v0.4 state ID (application identity; never a consensus value). */
function computeStateIdV4({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  // The version is part of the identity so a v0.4 and a v0.4.1 vault with the
  // same owner/vaultId/state never collide (distinct stateId -> distinct build
  // dir and manifest). Default preserves every existing v0.4 stateId exactly.
  const version = contractVersion ?? CONTRACT_VERSION_V4;
  const canonical = [
    "policyvault-state/v4",
    `network:${networkId}`,
    `contract:${version}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `protectedValue:${state.protectedValue}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `approvers:${state.approvers.join(",")}`,
    `approvalM:${state.approvalM}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

/* JSON-safe encoding (BigInt -> digit strings) for manifests/receipts. */
function stateToJsonV4(state) {
  return {
    protectedValue: state.protectedValue.toString(),
    feeReserve: state.feeReserve.toString(),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    approverSlots: [...state.approvers],
    approvalM: state.approvalM.toString(),
    policyNonce: requireNonce(state).toString()
  };
}

module.exports = {
  CONTRACT_VERSION_V4,
  CONTRACT_VERSION_V4_1,
  V4_ABIS,
  OWNER_OP_SELECTOR_V4_1,
  resolveV4Abi,
  MAX_APPROVERS,
  APPROVER_SENTINEL,
  normalizeTemplateV4,
  normalizeStateV4,
  normalizeStateV4ForRecovery,
  normalizeApprovers,
  computeStateIdV4,
  stateToJsonV4
};
