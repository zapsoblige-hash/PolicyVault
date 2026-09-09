"use strict";
const { ownGet, describeKey } = require("./own-get");

/*
 * PolicyVault v0.7 ORGANIZATIONAL OWNER SET — the deterministic core's
 * single source of truth for what an organization's M-of-N owner set IS,
 * what makes it WELL-FORMED, how the 780-byte owner signature blob is
 * assembled, and which authority CLASS each root action carries.
 *
 * Every rule below mirrors `contracts/PolicyVault.v0.7-root.sil`
 * (contract `PolicyVaultOrgRoot`) EXACTLY, so the core refuses locally what
 * consensus would refuse. The covenant remains the authority: nothing here
 * is a security boundary, and nothing here may ever be relaxed to "help" a
 * caller.
 *
 * WELL-FORMEDNESS WF(S) — checked by the covenant on the PREDECESSOR of
 * every root spend and on every NEW set:
 *   - ownerM >= 1
 *   - ownerM <= active(S)
 *   - active slots are CONTIGUOUS from slot 1 (no active slot after an
 *     inactive one)
 *   - all active keys are pairwise distinct (the covenant's 11 guards
 *     imply all C(12,2) = 66 inequalities under contiguity)
 *   - 1 <= emergencyK <= ownerM
 *   - 0 <= recoveryM <= ownerM   (0 = the owner-recovery path is DISABLED)
 *   - frozen in {0, 1}
 *
 * SIGNATURE BLOB — exactly 12 x 65 = 780 bytes. Slot i (0-based) is bytes
 * [65i, 65i+65). An ACTIVE slot carries a 64-byte Schnorr signature plus the
 * trailing 0x01 SIGHASH_ALL gate byte; the canonical abstention placeholder
 * is 64 zero bytes + 0x01 (it passes the gate, fails verification, counts 0).
 * Inactive slots are never inspected by the covenant and always carry the
 * placeholder here so the blob length — and therefore the exact transaction
 * byte shape and fee — is CONSTANT for every threshold.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/owner-set-v7.test.js).
 */

const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");

const OWNER_SLOTS_V7 = 12;
const SIG_SLOT_LEN_V7 = 65;
const SIG_BLOB_LEN_V7 = OWNER_SLOTS_V7 * SIG_SLOT_LEN_V7; // 780
const SIGHASH_ALL_GATE_BYTE = "01";
const INACTIVE_SLOT_KEY = "00".repeat(32);
const PLACEHOLDER_SLOT_HEX_V7 = "00".repeat(64) + SIGHASH_ALL_GATE_BYTE;

/* The four governance classes the design records for manifests (§2.4). */
const AUTHORITY_CLASSES_V7 = Object.freeze({
  REDUCING: "AUTHORITY-REDUCING",
  NEUTRAL: "AUTHORITY-NEUTRAL",
  EXPANDING: "AUTHORITY-EXPANDING",
  TERMINAL: "TERMINAL"
});

/*
 * Root action vocabulary. `quorumSource` names the state field the covenant
 * reads for `required`; `setMayChange` mirrors the covenant's own branch;
 * `requiresAge` marks the two relative-input-age (dead-man's switch) paths.
 *
 * SUCCESSION has no numeric action code — it is a separate covenant
 * entrypoint (`rootSuccession`) — and it is TERMINAL for the outgoing owner
 * set while being AUTHORITY-EXPANDING for the successor, so both labels are
 * carried explicitly rather than collapsed.
 */
const ROOT_ACTIONS_V7 = Object.freeze({
  authorize: Object.freeze({
    name: "authorize",
    action: 0,
    entrypoint: "rootAction",
    class: AUTHORITY_CLASSES_V7.NEUTRAL,
    quorumSource: "ownerM",
    setMayChange: false,
    requiresAge: false,
    requiresUnfrozen: true,
    landsFrozen: null /* preserved */
  }),
  rotate: Object.freeze({
    name: "rotate",
    action: 1,
    entrypoint: "rootAction",
    class: AUTHORITY_CLASSES_V7.EXPANDING,
    quorumSource: "ownerM",
    setMayChange: true,
    requiresAge: false,
    requiresUnfrozen: false,
    landsFrozen: null /* preserved — rotation is allowed while frozen */
  }),
  freeze: Object.freeze({
    name: "freeze",
    action: 2,
    entrypoint: "rootAction",
    class: AUTHORITY_CLASSES_V7.REDUCING,
    quorumSource: "emergencyK",
    setMayChange: false,
    requiresAge: false,
    requiresUnfrozen: true,
    landsFrozen: 1n
  }),
  unfreeze: Object.freeze({
    name: "unfreeze",
    action: 3,
    entrypoint: "rootAction",
    class: AUTHORITY_CLASSES_V7.EXPANDING,
    quorumSource: "ownerM",
    setMayChange: false,
    requiresAge: false,
    requiresUnfrozen: false,
    landsFrozen: 0n
  }),
  ownerRecover: Object.freeze({
    name: "ownerRecover",
    action: 4,
    entrypoint: "rootAction",
    class: AUTHORITY_CLASSES_V7.EXPANDING,
    quorumSource: "recoveryM",
    setMayChange: true,
    requiresAge: true,
    /* coordinator decision D6: a recovery MUST land frozen */
    requiresUnfrozen: false,
    landsFrozen: 1n
  }),
  succession: Object.freeze({
    name: "succession",
    action: null,
    entrypoint: "rootSuccession",
    class: AUTHORITY_CLASSES_V7.EXPANDING,
    classForPreviousSet: AUTHORITY_CLASSES_V7.TERMINAL,
    quorumSource: "successorPk",
    setMayChange: true,
    requiresAge: true,
    requiresUnfrozen: false,
    landsFrozen: 1n
  })
});

const ROOT_ACTION_BY_CODE = Object.freeze(
  Object.fromEntries(
    Object.values(ROOT_ACTIONS_V7)
      .filter((a) => a.action !== null)
      .map((a) => [a.action, a])
  )
);

function fail(message, code) {
  const e = new Error(`owner-set-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveRootActionV7(name) {
  const info = ownGet(ROOT_ACTIONS_V7, name); // own-property only (F-05)
  if (!info) {
    fail(`unknown v0.7 root action ${describeKey(name)} — failing closed (no default route)`, "UNKNOWN_ROOT_ACTION");
  }
  return info;
}

function resolveRootActionCodeV7(code) {
  const info = ROOT_ACTION_BY_CODE[typeof code === "bigint" ? Number(code) : code];
  if (!info) {
    fail(`unknown v0.7 root action code ${JSON.stringify(code)} — failing closed`, "UNKNOWN_ROOT_ACTION");
  }
  return info;
}

function smallInt(value, field, { min, max }) {
  let n;
  if (typeof value === "bigint") n = value;
  else if (typeof value === "number") {
    if (!Number.isInteger(value)) fail(`${field} must be an integer`);
    n = BigInt(value);
  } else if (typeof value === "string") {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) fail(`${field} must be a non-negative digit string`);
    n = BigInt(value);
  } else {
    fail(`${field} is required (BigInt, integer or digit string)`);
  }
  if (n < min || n > max) fail(`${field} out of range [${min}, ${max}]`);
  return n;
}

/*
 * Normalize + WF-check an owner set. `owners` is exactly 12 entries; an
 * inactive slot is the 32-byte sentinel zero. Every failure carries a code
 * so callers (and tamper tests) can attribute a refusal to its rule.
 */
function normalizeOwnerSetV7(input) {
  if (!input || typeof input !== "object") fail("owner set object is required");
  const raw = input.owners;
  if (!Array.isArray(raw) || raw.length !== OWNER_SLOTS_V7) {
    fail(`owners must be an array of exactly ${OWNER_SLOTS_V7} slots (the sentinel zero marks an inactive slot)`, "SLOT_COUNT");
  }
  const owners = raw.map((k, i) => normalizeXOnlyPubkey(k, `owners[${i}]`));

  /* active(S) + CONTIGUITY: no active slot may follow an inactive one. */
  let active = 0;
  let seenInactive = false;
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) {
    const isActive = owners[i] !== INACTIVE_SLOT_KEY;
    if (isActive) {
      if (seenInactive) {
        fail(`owner slot ${i + 1} is active after an inactive slot — active slots must be contiguous from slot 1`, "NOT_CONTIGUOUS");
      }
      active += 1;
    } else {
      seenInactive = true;
    }
  }
  if (active === 0) fail("an owner set must have at least one active slot", "NO_ACTIVE_SLOTS");

  /* pairwise distinctness over the ACTIVE slots (the covenant's 11 guards) */
  const seen = new Set();
  for (let i = 0; i < active; i += 1) {
    if (seen.has(owners[i])) {
      fail(`owner slot ${i + 1} repeats a key already held by an earlier slot — active keys must be pairwise distinct`, "DUPLICATE_OWNER_KEY");
    }
    seen.add(owners[i]);
  }

  const ownerM = smallInt(input.ownerM, "ownerM", { min: 1n, max: BigInt(OWNER_SLOTS_V7) });
  if (ownerM > BigInt(active)) fail(`ownerM ${ownerM} exceeds the ${active} active owner slots — the set could never reach quorum`, "M_ABOVE_ACTIVE");
  const emergencyK = smallInt(input.emergencyK, "emergencyK", { min: 1n, max: BigInt(OWNER_SLOTS_V7) });
  if (emergencyK > ownerM) fail(`emergencyK ${emergencyK} exceeds ownerM ${ownerM} — the emergency quorum may never be heavier than the full quorum`, "K_ABOVE_M");
  const recoveryM = smallInt(input.recoveryM, "recoveryM", { min: 0n, max: BigInt(OWNER_SLOTS_V7) });
  if (recoveryM > ownerM) fail(`recoveryM ${recoveryM} exceeds ownerM ${ownerM}`, "R_ABOVE_M");

  return Object.freeze({
    owners: Object.freeze(owners),
    activeCount: active,
    ownerM,
    emergencyK,
    recoveryM
  });
}

/* The active slots as { slot (1-based), index (0-based), publicKey }. */
function activeOwnerSlotsV7(ownerSet) {
  const out = [];
  for (let i = 0; i < ownerSet.activeCount; i += 1) {
    out.push(Object.freeze({ slot: i + 1, index: i, publicKey: ownerSet.owners[i] }));
  }
  return Object.freeze(out);
}

/* The quorum the covenant will require for one action, from the PREDECESSOR set. */
function requiredApprovalsV7(ownerSet, actionName) {
  const info = resolveRootActionV7(actionName);
  switch (info.quorumSource) {
    case "ownerM":
      return ownerSet.ownerM;
    case "emergencyK":
      return ownerSet.emergencyK;
    case "recoveryM":
      if (ownerSet.recoveryM < 1n) {
        fail("the owner-recovery path is DISABLED for this root (recoveryM = 0) — failing closed", "RECOVERY_DISABLED");
      }
      return ownerSet.recoveryM;
    case "successorPk":
      return 1n;
    default:
      fail(`internal: unknown quorum source ${info.quorumSource}`);
  }
  return 0n;
}

function normalizeSlotSignatureHex(value, label) {
  if (typeof value !== "string") fail(`${label} must be lowercase hex`, "SIGNATURE_INVALID");
  let sig = value.trim().toLowerCase();
  /* tolerate the wallet convention of a leading 0x41 push opcode */
  if (sig.length === (SIG_SLOT_LEN_V7 + 1) * 2 && sig.startsWith("41")) sig = sig.slice(2);
  if (!/^[0-9a-f]+$/.test(sig) || sig.length !== SIG_SLOT_LEN_V7 * 2) {
    fail(`${label} must be exactly ${SIG_SLOT_LEN_V7} bytes (64-byte Schnorr signature + the sighash-type byte)`, "SIGNATURE_INVALID");
  }
  if (!sig.endsWith(SIGHASH_ALL_GATE_BYTE)) {
    fail(`${label} sighash byte 0x${sig.slice(-2)} != 0x01 — the root covenant gates every counted slot on SIGHASH_ALL`, "SIGHASH_NOT_ALL");
  }
  if (sig === PLACEHOLDER_SLOT_HEX_V7) {
    fail(`${label} is the canonical abstention placeholder, not a signature — it can never count toward a quorum`, "PLACEHOLDER_AS_SIGNATURE");
  }
  return sig;
}

/*
 * Assemble the 780-byte owner signature blob from OUT-OF-BAND signatures.
 *
 * `approvals` is a list of { slot | publicKey, signatureHex }. Every entry
 * must name an ACTIVE slot of THIS set; absent slots carry the canonical
 * placeholder. Refusals (all pre-consensus, all fail-closed):
 *   DUPLICATE_SLOT           the same slot supplied twice
 *   SIGNATURE_REUSED         one signature offered for two different slots
 *   SLOT_INACTIVE            an approval aimed at a sentinel-zero slot
 *   OWNER_NOT_IN_SET         a public key that is not an active owner
 *   SIGHASH_NOT_ALL          a slot whose trailing byte is not 0x01
 *   SIGNATURE_INVALID        wrong length / not hex
 *   UNDER_QUORUM             fewer approvals than the action requires
 *
 * The blob's LENGTH is constant (780 B) regardless of how many slots signed,
 * which is exactly why the exact-fee freeze survives signature collection.
 */
function assembleOwnerSigsBlobV7({ ownerSet, actionName, approvals, requireQuorum = true }) {
  const set = ownerSet && ownerSet.activeCount !== undefined ? ownerSet : normalizeOwnerSetV7(ownerSet);
  if (!Array.isArray(approvals)) fail("approvals must be an array of { slot | publicKey, signatureHex }");
  const slots = new Array(OWNER_SLOTS_V7).fill(PLACEHOLDER_SLOT_HEX_V7);
  const usedSlots = new Set();
  const usedSignatures = new Set();
  const signedSlots = [];

  for (const [i, approval] of approvals.entries()) {
    if (!approval || typeof approval !== "object") fail(`approvals[${i}] must be an object`);
    let index;
    if (approval.slot !== undefined && approval.slot !== null) {
      const slot = Number(approval.slot);
      if (!Number.isInteger(slot) || slot < 1 || slot > OWNER_SLOTS_V7) fail(`approvals[${i}].slot must be 1..${OWNER_SLOTS_V7}`, "SLOT_OUT_OF_RANGE");
      index = slot - 1;
      if (approval.publicKey !== undefined && approval.publicKey !== null) {
        const pk = normalizeXOnlyPubkey(approval.publicKey, `approvals[${i}].publicKey`);
        if (pk !== set.owners[index]) fail(`approvals[${i}] names slot ${slot} but carries a different public key — refusing to place a signature under a key the covenant will not check it against`, "SLOT_KEY_MISMATCH");
      }
    } else if (approval.publicKey !== undefined && approval.publicKey !== null) {
      const pk = normalizeXOnlyPubkey(approval.publicKey, `approvals[${i}].publicKey`);
      index = set.owners.indexOf(pk);
      if (index < 0 || index >= set.activeCount) {
        fail(`approvals[${i}].publicKey is not an active owner of this root — a signature under a key outside the set can never count`, "OWNER_NOT_IN_SET");
      }
    } else {
      fail(`approvals[${i}] must carry a slot or a publicKey`);
    }
    if (index >= set.activeCount) fail(`approvals[${i}] targets inactive slot ${index + 1} — inactive slots are never inspected by the covenant`, "SLOT_INACTIVE");
    if (usedSlots.has(index)) fail(`approvals[${i}] repeats slot ${index + 1} — one slot, one signature`, "DUPLICATE_SLOT");
    const sig = normalizeSlotSignatureHex(approval.signatureHex, `approvals[${i}].signatureHex`);
    if (usedSignatures.has(sig)) {
      fail(`approvals[${i}] reuses a signature already placed in another slot — a single approval can never satisfy two slots`, "SIGNATURE_REUSED");
    }
    usedSlots.add(index);
    usedSignatures.add(sig);
    slots[index] = sig;
    signedSlots.push(index + 1);
  }

  signedSlots.sort((a, b) => a - b);
  const required = requiredApprovalsV7(set, actionName);
  const satisfied = BigInt(signedSlots.length);
  if (requireQuorum && satisfied < required) {
    fail(`the blob carries ${satisfied} owner approval(s) but ${actionName} requires ${required} — refusing to finalize an under-quorum root transaction`, "UNDER_QUORUM");
  }
  const blobHex = slots.join("");
  if (blobHex.length !== SIG_BLOB_LEN_V7 * 2) fail("internal: assembled blob is not 780 bytes");
  return Object.freeze({
    blobHex,
    signedSlots: Object.freeze(signedSlots),
    requiredApprovals: required,
    satisfiedApprovals: satisfied,
    actionName
  });
}

/* The all-placeholder blob: the exact byte shape a build freezes against. */
function placeholderOwnerSigsBlobV7() {
  return PLACEHOLDER_SLOT_HEX_V7.repeat(OWNER_SLOTS_V7);
}

/* Read a blob back: which slots carry a non-placeholder 65-byte slot. */
function inspectOwnerSigsBlobV7(blobHex) {
  const hex = normalizeHex(blobHex, SIG_BLOB_LEN_V7, "ownerSigs");
  const slots = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) {
    const slot = hex.slice(i * SIG_SLOT_LEN_V7 * 2, (i + 1) * SIG_SLOT_LEN_V7 * 2);
    slots.push(Object.freeze({ slot: i + 1, index: i, hex: slot, placeholder: slot === PLACEHOLDER_SLOT_HEX_V7, sighashAll: slot.endsWith(SIGHASH_ALL_GATE_BYTE) }));
  }
  return Object.freeze({
    slots: Object.freeze(slots),
    signedSlots: Object.freeze(slots.filter((s) => !s.placeholder).map((s) => s.slot))
  });
}

module.exports = {
  OWNER_SLOTS_V7,
  SIG_SLOT_LEN_V7,
  SIG_BLOB_LEN_V7,
  INACTIVE_SLOT_KEY,
  PLACEHOLDER_SLOT_HEX_V7,
  AUTHORITY_CLASSES_V7,
  ROOT_ACTIONS_V7,
  ROOT_ACTION_BY_CODE,
  resolveRootActionV7,
  resolveRootActionCodeV7,
  normalizeOwnerSetV7,
  activeOwnerSlotsV7,
  requiredApprovalsV7,
  assembleOwnerSigsBlobV7,
  placeholderOwnerSigsBlobV7,
  inspectOwnerSigsBlobV7,
  normalizeSlotSignatureHex
};
