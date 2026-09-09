"use strict";

/*
 * UNIT — v0.7 organizational ROOT transitions: the deterministic successor
 * for every root path, the nonce increment AS BYTES, the D6 (recovery lands
 * frozen) and D1 (succession changes the primary key) rules, the quorum each
 * path requires, the relative-age gates, and the value rule.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  authorizeSuccessorV7Root,
  rotateSuccessorV7Root,
  freezeSuccessorV7Root,
  unfreezeSuccessorV7Root,
  ownerRecoverSuccessorV7Root,
  successionSuccessorV7Root,
  rootTransitionV7,
  assertRootValueRuleV7
} = require("../vault-transitions-v7-root");
const { normalizeRootStateV7, rootStateTailHexV7, serializeRootStateHexV7, MAX_ROOT_NONCE_V7 } = require("../vault-state-v7-root");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, AUTHORITY_CLASSES_V7 } = require("../owner-set-v7");

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = "a7".repeat(32);
function owners(n, base = 0x71) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < n ? K(base + i) : INACTIVE_SLOT_KEY);
  return out;
}
const TEMPLATE = { orgId: ORG_ID, recoveryDelayDaa: 1000n, successorPk: K(0x7f), successionDelayDaa: 2000n, rootMaxFeePerTx: 200000n };
const state = (over = {}) => normalizeRootStateV7({ boundOrgId: ORG_ID, owners: owners(3), ownerM: 2, emergencyK: 1, recoveryM: 2, frozen: 0, rootNonce: 0, ...over });
const SET = (n, m, k, r, base = 0x71) => ({ owners: owners(n, base), ownerM: m, emergencyK: k, recoveryM: r });

function refuses(fn, code) {
  assert.throws(fn, (e) => {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

test("AUTHORIZE: neutral, full quorum, everything preserved but the nonce", () => {
  const prev = state({ rootNonce: 41 });
  const p = authorizeSuccessorV7Root(prev, { template: TEMPLATE });
  assert.equal(p.action, 0);
  assert.equal(p.class, AUTHORITY_CLASSES_V7.NEUTRAL);
  assert.equal(p.quorumSource, "ownerM");
  assert.equal(p.requiredApprovals, 2n);
  assert.equal(p.requiresAge, false);
  assert.equal(p.minSequence, 0n);
  assert.equal(p.successor.rootNonce, 42n);
  assert.equal(p.successor.frozen, 0n);
  assert.deepEqual([...p.successor.owners], [...prev.owners]);
  /* the nonce increment AS BYTES — what the covenant actually compares */
  assert.equal(p.tailHex, rootStateTailHexV7({ frozen: 0n, rootNonce: 42n }));
  assert.equal(p.tailHex.slice(4), "08" + "2a00000000000000");
  assert.deepEqual(p.expectedSignerSlots.map((s) => s.slot), [1, 2, 3]);
  assert.notEqual(p.prevStateDigest, p.newStateDigest);
  refuses(() => authorizeSuccessorV7Root(state({ frozen: 1 }), { template: TEMPLATE }), "ROOT_FROZEN");
});

test("ROTATE: expanding, full quorum, allowed while frozen, frozen preserved", () => {
  const p = rotateSuccessorV7Root(state(), SET(4, 3, 2, 2), { template: TEMPLATE });
  assert.equal(p.action, 1);
  assert.equal(p.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(p.requiredApprovals, 2n, "the PREDECESSOR's ownerM gates the rotation");
  assert.equal(p.successor.ownerM, 3n);
  assert.equal(p.successor.activeCount, 4);
  assert.equal(p.successor.frozen, 0n);
  /* rotating a compromised key out is allowed WHILE frozen */
  const frozen = rotateSuccessorV7Root(state({ frozen: 1 }), SET(3, 2, 1, 2, 0x81), { template: TEMPLATE });
  assert.equal(frozen.successor.frozen, 1n, "ROTATE preserves the frozen flag");
  refuses(() => rotateSuccessorV7Root(state(), SET(3, 2, 1, 2), { template: TEMPLATE }), "ROTATE_NO_CHANGE");
  /* WF(new) is enforced on the installed set */
  refuses(() => rotateSuccessorV7Root(state(), SET(3, 4, 1, 2), { template: TEMPLATE }), "M_ABOVE_ACTIVE");
  refuses(() => rotateSuccessorV7Root(state(), SET(3, 2, 3, 2), { template: TEMPLATE }), "K_ABOVE_M");
});

test("FREEZE / UNFREEZE: the monotone emergency lever and its full-quorum reversal", () => {
  const f = freezeSuccessorV7Root(state(), { template: TEMPLATE });
  assert.equal(f.action, 2);
  assert.equal(f.class, AUTHORITY_CLASSES_V7.REDUCING);
  assert.equal(f.quorumSource, "emergencyK");
  assert.equal(f.requiredApprovals, 1n, "the LIGHTER quorum");
  assert.equal(f.successor.frozen, 1n);
  assert.deepEqual([...f.successor.owners], [...state().owners], "FREEZE moves nothing but the flag and the nonce");
  refuses(() => freezeSuccessorV7Root(state({ frozen: 1 }), { template: TEMPLATE }), "ALREADY_FROZEN");

  const u = unfreezeSuccessorV7Root(state({ frozen: 1 }), { template: TEMPLATE });
  assert.equal(u.action, 3);
  assert.equal(u.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(u.requiredApprovals, 2n, "unfreezing needs the FULL quorum");
  assert.equal(u.successor.frozen, 0n);
  refuses(() => unfreezeSuccessorV7Root(state(), { template: TEMPLATE }), "NOT_FROZEN");
});

test("OWNER-RECOVER: D6 lands FROZEN, needs the recovery quorum and the idle delay", () => {
  const prev = state({ owners: owners(4), ownerM: 4, emergencyK: 1, recoveryM: 2 });
  const p = ownerRecoverSuccessorV7Root(prev, SET(2, 2, 1, 2), { template: TEMPLATE });
  assert.equal(p.action, 4);
  assert.equal(p.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(p.quorumSource, "recoveryM");
  assert.equal(p.requiredApprovals, 2n);
  assert.equal(p.requiresAge, true);
  assert.equal(p.minSequence, TEMPLATE.recoveryDelayDaa, "the relative input age is the dead-man's switch");
  assert.equal(p.successor.frozen, 1n, "decision D6: a recovery MUST land frozen");
  /* a recovery successor is therefore NEVER byte-identical to an AUTHORIZE one */
  const authorize = authorizeSuccessorV7Root(prev, { template: TEMPLATE });
  assert.notEqual(serializeRootStateHexV7(p.successor), serializeRootStateHexV7(authorize.successor));

  refuses(() => ownerRecoverSuccessorV7Root(state({ recoveryM: 0 }), SET(2, 2, 1, 0), { template: TEMPLATE }), "RECOVERY_DISABLED");
  assert.throws(() => ownerRecoverSuccessorV7Root(prev, SET(2, 2, 1, 2)), /root template is required/);
});

test("SUCCESSION: opt-in, idle-gated, lands FROZEN, and D1 forces a new primary key", () => {
  const prev = state();
  const p = successionSuccessorV7Root(prev, SET(2, 2, 1, 1, 0x91), { template: TEMPLATE });
  assert.equal(p.action, null, "succession is its own entrypoint");
  assert.equal(p.entrypoint, "rootSuccession");
  assert.equal(p.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(p.classForPreviousSet, AUTHORITY_CLASSES_V7.TERMINAL);
  assert.equal(p.requiredApprovals, 1n);
  assert.equal(p.minSequence, TEMPLATE.successionDelayDaa);
  assert.equal(p.successor.frozen, 1n);
  assert.deepEqual(p.expectedSignerSlots, [], "no owner slot signs a succession");

  refuses(() => successionSuccessorV7Root(prev, SET(3, 2, 1, 2), { template: TEMPLATE }), "D1_PRIMARY_KEY_UNCHANGED");
  refuses(() => successionSuccessorV7Root(prev, SET(2, 2, 1, 1, 0x91), { template: { ...TEMPLATE, successorPk: INACTIVE_SLOT_KEY } }), "SUCCESSION_DISABLED");
});

test("dispatch fails closed and the nonce domain is bounded", () => {
  refuses(() => rootTransitionV7("dissolve", state(), { template: TEMPLATE }), "UNKNOWN_ROOT_ACTION");
  assert.equal(rootTransitionV7("authorize", state(), { template: TEMPLATE }).action, 0);
  assert.equal(rootTransitionV7("rotate", state(), { template: TEMPLATE, newOwnerSet: SET(4, 3, 2, 2) }).action, 1);
  refuses(() => authorizeSuccessorV7Root(state({ rootNonce: MAX_ROOT_NONCE_V7 }), { template: TEMPLATE }), "NONCE_EXHAUSTED");
});

test("the value rule: the root may lose at most rootMaxFeePerTx and can never pay anyone", () => {
  const ok = assertRootValueRuleV7({ inputValue: 300000000n, successorValue: 299950000n, rootMaxFeePerTx: 200000n });
  assert.equal(ok.maxLoss, 50000n);
  assertRootValueRuleV7({ inputValue: 300000000n, successorValue: 300000000n, rootMaxFeePerTx: 0n });
  refuses(() => assertRootValueRuleV7({ inputValue: 300000000n, successorValue: 299799999n, rootMaxFeePerTx: 200000n }), "ROOT_VALUE_RULE");
});
