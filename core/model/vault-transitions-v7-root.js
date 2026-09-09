"use strict";

/*
 * v0.7 ORGANIZATIONAL ROOT transition planner — the deterministic successor
 * for EVERY root path, mirroring `contracts/PolicyVault.v0.7-root.sil`
 * exactly so the core refuses locally what consensus would refuse.
 * LOCAL PRE-CHECK ONLY: the covenant remains the authority.
 *
 * Rules carried verbatim from the covenant (design §2.4 as amended by
 * coordinator decision D6, §11):
 *
 *   common       WF(prev); new.boundOrgId == prev.boundOrgId;
 *                new.rootNonce == prev.rootNonce + 1 (as the exact 8-byte
 *                little-endian bytes OpNum2Bin(prev + 1, 8) produces);
 *                successorValue >= inputValue - rootMaxFeePerTx.
 *   0 AUTHORIZE  prev.frozen == 0; new == prev except the nonce.  NEUTRAL.
 *   1 ROTATE     new set as supplied; WF(new); frozen preserved (allowed
 *                while frozen, so a compromised key can be rotated out
 *                before unfreezing).                        EXPANDING.
 *   2 FREEZE     prev.frozen == 0; new.frozen == 1; set preserved. The ONLY
 *                effect the lighter emergency quorum can reach.  REDUCING.
 *   3 UNFREEZE   prev.frozen == 1; new.frozen == 0; set preserved. EXPANDING.
 *   4 OWNER-REC  recoveryM >= 1; this.age >= recoveryDelayDaa; WF(new);
 *                D6: the recovered set MUST LAND FROZEN.       EXPANDING.
 *   SUCCESSION   successorPk != 0; this.age >= successionDelayDaa; WF(prev);
 *                WF(new); lands frozen; D1: new.owner1 != prev.owner1 so a
 *                succession is never byte-identical to a FREEZE.
 *                EXPANDING for the successor, TERMINAL for the old set.
 *
 * FRESHNESS is outpoint binding + SIGHASH_ALL + a strictly increasing nonce,
 * NEVER an expiry: Kaspa lockTime is a lower bound only, so a "valid until"
 * field would be security theatre. Spending the root's outpoint is the kill
 * switch that invalidates every collected approval at once.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-transitions-v7-root.test.js).
 */

const { parseSompi } = require("./amounts");
const {
  normalizeRootStateV7,
  normalizeRootTemplateV7,
  rootStateTailHexV7,
  computeRootStateDigestV7,
  MAX_ROOT_NONCE_V7
} = require("./vault-state-v7-root");
const { normalizeOwnerSetV7, resolveRootActionV7, requiredApprovalsV7, activeOwnerSlotsV7, INACTIVE_SLOT_KEY } = require("./owner-set-v7");

function fail(message, code) {
  const e = new Error(`vault-transitions-v7-root: ${message}`);
  if (code) e.code = code;
  throw e;
}

function advanceNonce(prev) {
  if (prev.rootNonce >= MAX_ROOT_NONCE_V7) {
    fail("the root nonce has reached its 8-byte domain limit — a further transition could not encode; failing closed", "NONCE_EXHAUSTED");
  }
  return prev.rootNonce + 1n;
}

function sameSet(a, b) {
  for (let i = 0; i < a.owners.length; i += 1) if (a.owners[i] !== b.owners[i]) return false;
  return a.ownerM === b.ownerM && a.emergencyK === b.emergencyK && a.recoveryM === b.recoveryM;
}

/*
 * Plan shape shared by every root path. `nonceBytesHex` and `tailHex` are the
 * EXACT consensus-visible bytes the covenant will compare, so a caller (and a
 * manifest verifier) can check the successor byte-for-byte rather than by
 * field equality.
 */
function plan({ prev, successor, actionName, template, minSequence = 0n }) {
  const info = resolveRootActionV7(actionName);
  const required = requiredApprovalsV7(prev, actionName);
  return Object.freeze({
    actionName,
    action: info.action,
    entrypoint: info.entrypoint,
    class: info.class,
    classForPreviousSet: info.classForPreviousSet ?? null,
    quorumSource: info.quorumSource,
    requiredApprovals: required,
    expectedSignerSlots: actionName === "succession" ? Object.freeze([]) : activeOwnerSlotsV7(prev),
    setMayChange: info.setMayChange,
    requiresAge: info.requiresAge,
    minSequence,
    prev,
    successor,
    prevStateDigest: computeRootStateDigestV7(prev),
    newStateDigest: computeRootStateDigestV7(successor),
    tailHex: rootStateTailHexV7({ frozen: successor.frozen, rootNonce: successor.rootNonce }),
    rootMaxFeePerTx: template ? normalizeRootTemplateV7(template).rootMaxFeePerTx : null
  });
}

function withSet(prev, ownerSetInput, { frozen }) {
  const set = normalizeOwnerSetV7(ownerSetInput);
  return normalizeRootStateV7({
    boundOrgId: prev.boundOrgId,
    owners: [...set.owners],
    ownerM: set.ownerM,
    emergencyK: set.emergencyK,
    recoveryM: set.recoveryM,
    frozen,
    rootNonce: advanceNonce(prev)
  });
}

function preserved(prev, { frozen }) {
  return normalizeRootStateV7({
    boundOrgId: prev.boundOrgId,
    owners: [...prev.owners],
    ownerM: prev.ownerM,
    emergencyK: prev.emergencyK,
    recoveryM: prev.recoveryM,
    frozen,
    rootNonce: advanceNonce(prev)
  });
}

/* action 0 AUTHORIZE — the ONLY root shape a rooted vault accepts for a
 * GENERAL owner operation, and the organization's cheap heartbeat (it also
 * refreshes the freshness of every stale approval by consuming the outpoint). */
function authorizeSuccessorV7Root(prevInput, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  if (prev.frozen !== 0n) fail("authorize: the root is FROZEN — unfreeze under the full quorum first", "ROOT_FROZEN");
  return plan({ prev, successor: preserved(prev, { frozen: 0n }), actionName: "authorize", template });
}

/* action 1 ROTATE — install a new owner set / thresholds; allowed while frozen. */
function rotateSuccessorV7Root(prevInput, newOwnerSet, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  const successor = withSet(prev, newOwnerSet, { frozen: prev.frozen });
  if (sameSet(prev, successor)) {
    fail("rotate: the supplied set is identical to the live set — a rotation that changes nothing burns a fee and hides its intent; failing closed", "ROTATE_NO_CHANGE");
  }
  return plan({ prev, successor, actionName: "rotate", template });
}

/* action 2 FREEZE — the lighter emergency quorum's ONLY reachable effect. */
function freezeSuccessorV7Root(prevInput, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  if (prev.frozen !== 0n) fail("freeze: the root is already frozen", "ALREADY_FROZEN");
  return plan({ prev, successor: preserved(prev, { frozen: 1n }), actionName: "freeze", template });
}

/* action 3 UNFREEZE — full quorum. */
function unfreezeSuccessorV7Root(prevInput, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  if (prev.frozen !== 1n) fail("unfreeze: the root is not frozen", "NOT_FROZEN");
  return plan({ prev, successor: preserved(prev, { frozen: 0n }), actionName: "unfreeze", template });
}

/*
 * action 4 OWNER-RECOVER — a recovery-quorum subset installs a new set after
 * the root has been idle for recoveryDelayDaa. D6: it LANDS FROZEN, so a
 * recovery transition is never byte-identical to an AUTHORIZE one and can
 * never satisfy a rooted vault's GENERAL owner path.
 */
function ownerRecoverSuccessorV7Root(prevInput, newOwnerSet, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  if (prev.recoveryM < 1n) {
    fail("ownerRecover: this root opted OUT of owner recovery (recoveryM = 0) — the path is permanently unavailable; failing closed", "RECOVERY_DISABLED");
  }
  const t = normalizeRootTemplateV7(template ?? fail("ownerRecover: the root template is required (recoveryDelayDaa is the idle gate)"));
  const successor = withSet(prev, newOwnerSet, { frozen: 1n });
  return plan({ prev, successor, actionName: "ownerRecover", template: t, minSequence: t.recoveryDelayDaa });
}

/*
 * SUCCESSION — the genesis-pinned successor key installs a new (frozen) set
 * after successionDelayDaa of idleness. D1: the primary key MUST change, so a
 * succession's successor bytes can never be mistaken for a FREEZE's.
 */
function successionSuccessorV7Root(prevInput, newOwnerSet, { template } = {}) {
  const prev = normalizeRootStateV7(prevInput);
  const t = normalizeRootTemplateV7(template ?? fail("succession: the root template is required (successorPk and successionDelayDaa)"));
  if (!t.successionEnabled || t.successorPk === INACTIVE_SLOT_KEY) {
    fail("succession: this root opted OUT of succession (successorPk = 0) — the path is permanently unavailable; failing closed", "SUCCESSION_DISABLED");
  }
  const successor = withSet(prev, newOwnerSet, { frozen: 1n });
  if (successor.owners[0] === prev.owners[0]) {
    fail("succession: the installed set must change owner slot 1 (deviation D1) — otherwise the successor bytes are indistinguishable from a FREEZE and a rooted vault could not tell the two root paths apart", "D1_PRIMARY_KEY_UNCHANGED");
  }
  return plan({ prev, successor, actionName: "succession", template: t, minSequence: t.successionDelayDaa });
}

/* Dispatch by action name; unknown names fail closed (never a default route). */
function rootTransitionV7(actionName, prev, params = {}) {
  switch (actionName) {
    case "authorize":
      return authorizeSuccessorV7Root(prev, params);
    case "rotate":
      return rotateSuccessorV7Root(prev, params.newOwnerSet, params);
    case "freeze":
      return freezeSuccessorV7Root(prev, params);
    case "unfreeze":
      return unfreezeSuccessorV7Root(prev, params);
    case "ownerRecover":
      return ownerRecoverSuccessorV7Root(prev, params.newOwnerSet, params);
    case "succession":
      return successionSuccessorV7Root(prev, params.newOwnerSet, params);
    default:
      return fail(`unknown v0.7 root action ${JSON.stringify(actionName)} — failing closed`, "UNKNOWN_ROOT_ACTION");
  }
}

/*
 * The covenant's value rule: the root may lose at most rootMaxFeePerTx per
 * transition and can never pay anyone (its single authorized continuation
 * output carries the value). Checked here so a build refuses before bytes
 * exist rather than after a node rejects.
 */
function assertRootValueRuleV7({ inputValue, successorValue, rootMaxFeePerTx }) {
  const inV = parseSompi(inputValue, "inputValue");
  const outV = parseSompi(successorValue, "successorValue");
  const maxFee = parseSompi(rootMaxFeePerTx, "rootMaxFeePerTx");
  const floor = inV > maxFee ? inV - maxFee : 0n;
  if (outV < floor) {
    fail(`the root successor would carry ${outV} sompi but the covenant requires >= ${floor} (input ${inV} - rootMaxFeePerTx ${maxFee})`, "ROOT_VALUE_RULE");
  }
  return Object.freeze({ inputValue: inV, successorValue: outV, rootMaxFeePerTx: maxFee, maxLoss: inV - outV });
}

module.exports = {
  authorizeSuccessorV7Root,
  rotateSuccessorV7Root,
  freezeSuccessorV7Root,
  unfreezeSuccessorV7Root,
  ownerRecoverSuccessorV7Root,
  successionSuccessorV7Root,
  rootTransitionV7,
  assertRootValueRuleV7
};
