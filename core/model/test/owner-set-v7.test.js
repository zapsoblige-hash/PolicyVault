"use strict";

/*
 * UNIT — v0.7 organizational owner set: WF(S) exactly as
 * contracts/PolicyVault.v0.7-root.sil enforces it, the 780-byte signature
 * blob assembly with canonical placeholders and the 65-byte/0x01 gate, and
 * the action vocabulary + authority classes.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  OWNER_SLOTS_V7,
  SIG_SLOT_LEN_V7,
  SIG_BLOB_LEN_V7,
  INACTIVE_SLOT_KEY,
  PLACEHOLDER_SLOT_HEX_V7,
  AUTHORITY_CLASSES_V7,
  ROOT_ACTIONS_V7,
  resolveRootActionV7,
  resolveRootActionCodeV7,
  normalizeOwnerSetV7,
  activeOwnerSlotsV7,
  requiredApprovalsV7,
  assembleOwnerSigsBlobV7,
  placeholderOwnerSigsBlobV7,
  inspectOwnerSigsBlobV7
} = require("../owner-set-v7");

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const SIG = (b) => b.toString(16).padStart(2, "0").repeat(64) + "01";

function owners(n) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < n ? K(0x71 + i) : INACTIVE_SLOT_KEY);
  return out;
}
const set = (n, m, k, r) => normalizeOwnerSetV7({ owners: owners(n), ownerM: m, emergencyK: k, recoveryM: r });

function refuses(fn, code) {
  assert.throws(fn, (e) => {
    assert.equal(e.code, code, `expected code ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

test("constants match the covenant's fixed geometry", () => {
  assert.equal(OWNER_SLOTS_V7, 12);
  assert.equal(SIG_SLOT_LEN_V7, 65);
  assert.equal(SIG_BLOB_LEN_V7, 780);
  assert.equal(PLACEHOLDER_SLOT_HEX_V7.length, 130);
  assert.ok(PLACEHOLDER_SLOT_HEX_V7.endsWith("01"), "the placeholder passes the SIGHASH_ALL gate and fails verification");
  assert.equal(placeholderOwnerSigsBlobV7().length, SIG_BLOB_LEN_V7 * 2);
});

test("WF(S): a well-formed set normalizes with its active count and thresholds", () => {
  const s = set(3, 2, 1, 2);
  assert.equal(s.activeCount, 3);
  assert.equal(s.ownerM, 2n);
  assert.equal(s.emergencyK, 1n);
  assert.equal(s.recoveryM, 2n);
  assert.deepEqual(
    activeOwnerSlotsV7(s).map((x) => x.slot),
    [1, 2, 3]
  );
  /* the covenant's own boundary cases */
  assert.equal(set(1, 1, 1, 0).activeCount, 1);
  assert.equal(set(12, 12, 1, 6).activeCount, 12);
});

test("WF(S) refusals mirror the covenant rule for rule", () => {
  refuses(() => normalizeOwnerSetV7({ owners: owners(3).slice(0, 5), ownerM: 2, emergencyK: 1, recoveryM: 0 }), "SLOT_COUNT");
  /* an active slot after an inactive one */
  const gap = owners(3);
  gap[1] = INACTIVE_SLOT_KEY;
  refuses(() => normalizeOwnerSetV7({ owners: gap, ownerM: 1, emergencyK: 1, recoveryM: 0 }), "NOT_CONTIGUOUS");
  /* a duplicate key across two active slots */
  const dup = owners(3);
  dup[2] = dup[0];
  refuses(() => normalizeOwnerSetV7({ owners: dup, ownerM: 2, emergencyK: 1, recoveryM: 0 }), "DUPLICATE_OWNER_KEY");
  refuses(() => normalizeOwnerSetV7({ owners: owners(0), ownerM: 1, emergencyK: 1, recoveryM: 0 }), "NO_ACTIVE_SLOTS");
  refuses(() => normalizeOwnerSetV7({ owners: owners(3), ownerM: 4, emergencyK: 1, recoveryM: 0 }), "M_ABOVE_ACTIVE");
  refuses(() => normalizeOwnerSetV7({ owners: owners(3), ownerM: 2, emergencyK: 3, recoveryM: 0 }), "K_ABOVE_M");
  refuses(() => normalizeOwnerSetV7({ owners: owners(3), ownerM: 2, emergencyK: 1, recoveryM: 3 }), "R_ABOVE_M");
  assert.throws(() => normalizeOwnerSetV7({ owners: owners(3), ownerM: 0, emergencyK: 1, recoveryM: 0 }), /ownerM out of range/);
  assert.throws(() => normalizeOwnerSetV7({ owners: owners(3), ownerM: 2, emergencyK: 0, recoveryM: 0 }), /emergencyK out of range/);
});

test("action vocabulary carries all four authority classes and fails closed on unknowns", () => {
  assert.equal(ROOT_ACTIONS_V7.authorize.class, AUTHORITY_CLASSES_V7.NEUTRAL);
  assert.equal(ROOT_ACTIONS_V7.freeze.class, AUTHORITY_CLASSES_V7.REDUCING);
  assert.equal(ROOT_ACTIONS_V7.rotate.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(ROOT_ACTIONS_V7.unfreeze.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(ROOT_ACTIONS_V7.ownerRecover.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(ROOT_ACTIONS_V7.succession.class, AUTHORITY_CLASSES_V7.EXPANDING);
  assert.equal(ROOT_ACTIONS_V7.succession.classForPreviousSet, AUTHORITY_CLASSES_V7.TERMINAL);
  assert.equal(ROOT_ACTIONS_V7.succession.action, null, "succession is a separate entrypoint, not an action code");
  assert.equal(ROOT_ACTIONS_V7.ownerRecover.landsFrozen, 1n, "decision D6: a recovery MUST land frozen");
  for (const [code, name] of [[0, "authorize"], [1, "rotate"], [2, "freeze"], [3, "unfreeze"], [4, "ownerRecover"]]) {
    assert.equal(resolveRootActionCodeV7(code).name, name);
  }
  refuses(() => resolveRootActionV7("dissolve"), "UNKNOWN_ROOT_ACTION");
  refuses(() => resolveRootActionCodeV7(5), "UNKNOWN_ROOT_ACTION");
});

test("required approvals come from the PREDECESSOR set, per action", () => {
  const s = set(4, 3, 1, 2);
  assert.equal(requiredApprovalsV7(s, "authorize"), 3n);
  assert.equal(requiredApprovalsV7(s, "rotate"), 3n);
  assert.equal(requiredApprovalsV7(s, "unfreeze"), 3n);
  assert.equal(requiredApprovalsV7(s, "freeze"), 1n, "the emergency quorum is the lighter one");
  assert.equal(requiredApprovalsV7(s, "ownerRecover"), 2n);
  assert.equal(requiredApprovalsV7(s, "succession"), 1n);
  refuses(() => requiredApprovalsV7(set(3, 2, 1, 0), "ownerRecover"), "RECOVERY_DISABLED");
});

test("blob assembly places each signature in its own slot and pads the rest", () => {
  const s = set(3, 2, 1, 2);
  const blob = assembleOwnerSigsBlobV7({
    ownerSet: s,
    actionName: "authorize",
    approvals: [
      { slot: 1, signatureHex: SIG(0xa1) },
      { publicKey: s.owners[2], signatureHex: SIG(0xa3) }
    ]
  });
  assert.equal(blob.blobHex.length, SIG_BLOB_LEN_V7 * 2);
  assert.deepEqual(blob.signedSlots, [1, 3]);
  assert.equal(blob.requiredApprovals, 2n);
  assert.equal(blob.satisfiedApprovals, 2n);
  const seen = inspectOwnerSigsBlobV7(blob.blobHex);
  assert.deepEqual(seen.signedSlots, [1, 3]);
  assert.equal(seen.slots[1].hex, PLACEHOLDER_SLOT_HEX_V7, "an abstaining slot carries the canonical placeholder");
  assert.ok(seen.slots.every((x) => x.sighashAll), "every slot ends in the 0x01 gate byte");
  /* the blob LENGTH is constant regardless of the threshold — this is what
   * keeps the exact-fee freeze valid across signature collection */
  const one = assembleOwnerSigsBlobV7({ ownerSet: set(12, 1, 1, 0), actionName: "authorize", approvals: [{ slot: 1, signatureHex: SIG(0xb1) }] });
  assert.equal(one.blobHex.length, blob.blobHex.length);
});

test("blob assembly refusal matrix", () => {
  const s = set(3, 2, 1, 2);
  const ok = [{ slot: 1, signatureHex: SIG(0xa1) }, { slot: 2, signatureHex: SIG(0xa2) }];
  const build = (approvals, actionName = "authorize", requireQuorum = true) => () => assembleOwnerSigsBlobV7({ ownerSet: s, actionName, approvals, requireQuorum });

  refuses(build([ok[0], { slot: 1, signatureHex: SIG(0xa9) }]), "DUPLICATE_SLOT");
  refuses(build([ok[0], { slot: 2, signatureHex: SIG(0xa1) }]), "SIGNATURE_REUSED");
  refuses(build([{ slot: 4, signatureHex: SIG(0xa4) }]), "SLOT_INACTIVE");
  refuses(build([{ slot: 13, signatureHex: SIG(0xa4) }]), "SLOT_OUT_OF_RANGE");
  refuses(build([{ publicKey: K(0xee), signatureHex: SIG(0xa1) }]), "OWNER_NOT_IN_SET");
  refuses(build([{ slot: 1, publicKey: s.owners[1], signatureHex: SIG(0xa1) }]), "SLOT_KEY_MISMATCH");
  refuses(build([{ slot: 1, signatureHex: SIG(0xa1).slice(0, -2) + "02" }, ok[1]]), "SIGHASH_NOT_ALL");
  refuses(build([{ slot: 1, signatureHex: "ab".repeat(30) }]), "SIGNATURE_INVALID");
  refuses(build([{ slot: 1, signatureHex: PLACEHOLDER_SLOT_HEX_V7 }]), "PLACEHOLDER_AS_SIGNATURE");
  refuses(build([ok[0]]), "UNDER_QUORUM");
  /* an emergency FREEZE needs only K = 1, so the same single approval passes */
  assert.equal(assembleOwnerSigsBlobV7({ ownerSet: s, actionName: "freeze", approvals: [ok[0]] }).satisfiedApprovals, 1n);
  /* requireQuorum:false is the BUILD-time (pre-signature) shape only */
  assert.equal(build([], "authorize", false)().signedSlots.length, 0);
});
