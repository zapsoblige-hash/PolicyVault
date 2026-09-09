"use strict";
const { ownGet, describeKey } = require("./own-get");

/*
 * Exact live-state model for a PolicyVault v0.7 ORGANIZATIONAL ROOT
 * instance (docs/postlaunch/v0.7-organizational-root-design.md §2, §9.1;
 * contracts/PolicyVault.v0.7-root.sil, contract `PolicyVaultOrgRoot`).
 *
 * A root instance is:
 *   TEMPLATE (immutable; changing any of it is a ROOT MIGRATION, i.e. a new
 *   covenant id): orgId, recoveryDelayDaa, successorPk (zero = succession
 *   DISABLED), successionDelayDaa, rootMaxFeePerTx.
 *   STATE (18 fields): boundOrgId (= orgId), owner1..owner12, ownerM,
 *   emergencyK, recoveryM, frozen, rootNonce.
 *
 * BYTE LAYOUT — the state region length is a CONSTANT (467 B) precisely so a
 * ROOTED VAULT can slice HEAD and TAIL by fixed offsets instead of decoding
 * 18 fields (§9.1). Each field is `data_prefix(fixed_type_size) || payload`
 * (~/silverscript/silverscript-lang/src/compiler/compile.rs `data_prefix`):
 *
 *   boundOrgId   0x20 || 32 B                         33 B   ┐
 *   owner1..12   0x20 || 32 B  each                  396 B   │ HEAD 456 B
 *   ownerM       0x08 || serialize_i64(n, 8)           9 B   │
 *   emergencyK   0x08 || serialize_i64(n, 8)           9 B   │
 *   recoveryM    0x08 || serialize_i64(n, 8)           9 B   ┘
 *   frozen       0x01 || <0x00|0x01>                   2 B   ┐ TAIL 11 B
 *   rootNonce    0x08 || 8 unsigned little-endian B    9 B   ┘
 *                                                     ---
 *                                       rootStateLen  467 B
 *
 * `serialize_i64(n, Some(8))` (rusty-kaspa crypto/txscript/src/data_stack.rs)
 * is a fixed 8-byte SIGN-MAGNITUDE little-endian encoding, zero-padded and
 * never minimal, so for the non-negative values this state can hold it is
 * exactly the 8-byte unsigned little-endian encoding — which is also what the
 * covenant's `OpNum2Bin(prev + 1, 8)` produces for the nonce.
 *
 * NOTHING here is a security boundary: Kaspa consensus is. These bytes exist
 * so the SDK, the signer-visible manifest and the tests can rebuild — and
 * therefore CHECK — exactly what the covenant will see.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/model/test/vault-state-v7-root.test.js);
 * the byte layout is pinned against the real compiler/engine by
 * tests/vm/tests/v7_root_production.rs and tests/vm/tests/v7_sdk_integration.rs.
 */

const crypto = require("crypto");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY, normalizeOwnerSetV7 } = require("./owner-set-v7");

const CONTRACT_VERSION_V7_ROOT = "policyvault-0.7-root";

/* Measured on the production candidate (design §12.3) and asserted by the
 * SDK compiler against the compiler's OWN state_layout on every compile. */
const ROOT_STATE_LEN_V7 = 467;
const ROOT_TAIL_LEN_V7 = 11;
const ROOT_HEAD_LEN_V7 = ROOT_STATE_LEN_V7 - ROOT_TAIL_LEN_V7; // 456
const ROOT_FROZEN_PUSH_LEN_V7 = 2;
const ROOT_NONCE_PUSH_LEN_V7 = 9;

/* The nonce is `byte[8]`; `int(bytes)` reads it as a sign-magnitude i64, so a
 * value with bit 63 set would read back NEGATIVE. The predecessor is bounded
 * one below the maximum so `prev + 1` always round-trips as positive. */
const MAX_ROOT_NONCE_V7 = (1n << 63n) - 2n;

const V7_ROOT_ABIS = Object.freeze({
  [CONTRACT_VERSION_V7_ROOT]: Object.freeze({
    version: CONTRACT_VERSION_V7_ROOT,
    contractName: "PolicyVaultOrgRoot",
    contractRelPath: "contracts/PolicyVault.v0.7-root.sil",
    buildSubdir: "build-v7-root",
    ownerSlots: OWNER_SLOTS_V7
  })
});

function fail(message, code) {
  const e = new Error(`vault-state-v7-root: ${message}`);
  if (code) e.code = code;
  throw e;
}

function resolveV7RootAbi(contractVersion) {
  const abi = ownGet(V7_ROOT_ABIS, contractVersion); // own-property only (F-05)
  if (!abi) {
    fail(`unknown contract version ${describeKey(contractVersion)} for the v0.7 root lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return abi;
}

function bigIntField(value, field, { min, max }) {
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
 * The immutable root template. `successorPk` zero means the succession path
 * is DISABLED; `recoveryDelayDaa`/`successionDelayDaa` are RELATIVE input
 * ages (the covenant's `this.age >= D`, compiled to OpCheckSequenceVerify)
 * and must be >= 1 so a dead-man's-switch path can never be taken instantly.
 */
function normalizeRootTemplateV7(input) {
  if (!input || typeof input !== "object") fail("root template object is required");
  const successorPk = normalizeXOnlyPubkey(input.successorPk, "template.successorPk");
  const successionEnabled = successorPk !== INACTIVE_SLOT_KEY;
  return Object.freeze({
    orgId: normalizeHex(input.orgId, 32, "template.orgId"),
    recoveryDelayDaa: bigIntField(input.recoveryDelayDaa, "template.recoveryDelayDaa", { min: 1n, max: 0xffffffffn }),
    successorPk,
    successionEnabled,
    successionDelayDaa: bigIntField(input.successionDelayDaa, "template.successionDelayDaa", { min: 1n, max: 0xffffffffn }),
    rootMaxFeePerTx: bigIntField(input.rootMaxFeePerTx, "template.rootMaxFeePerTx", { min: 0n, max: 100_000_000_000n })
  });
}

/*
 * The 18-field mutable root state. WF(S) is enforced here through
 * normalizeOwnerSetV7 exactly as the covenant enforces it on the predecessor
 * of every spend and on every new set.
 */
function normalizeRootStateV7(input) {
  if (!input || typeof input !== "object") fail("root state object is required");
  const ownerSet = normalizeOwnerSetV7(input);
  const frozen = bigIntField(input.frozen, "state.frozen", { min: 0n, max: 1n });
  const rootNonce = bigIntField(input.rootNonce, "state.rootNonce", { min: 0n, max: MAX_ROOT_NONCE_V7 });
  return Object.freeze({
    boundOrgId: normalizeHex(input.boundOrgId, 32, "state.boundOrgId"),
    owners: ownerSet.owners,
    activeCount: ownerSet.activeCount,
    ownerM: ownerSet.ownerM,
    emergencyK: ownerSet.emergencyK,
    recoveryM: ownerSet.recoveryM,
    frozen,
    rootNonce
  });
}

/* The genesis state a template implies, given an owner set. */
function genesisRootStateV7({ template, ownerSet, frozen = 0n, rootNonce = 0n }) {
  const t = normalizeRootTemplateV7(template);
  const set = normalizeOwnerSetV7(ownerSet);
  return normalizeRootStateV7({
    boundOrgId: t.orgId,
    owners: [...set.owners],
    ownerM: set.ownerM,
    emergencyK: set.emergencyK,
    recoveryM: set.recoveryM,
    frozen,
    rootNonce
  });
}

/* ------------------------------------------------------------------ */
/* exact byte layout                                                    */
/* ------------------------------------------------------------------ */

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/* `serialize_i64(n, Some(8))` for the non-negative values this state holds. */
function encodeInt8LE(value, field) {
  if (typeof value !== "bigint" || value < 0n || value > MAX_ROOT_NONCE_V7 + 1n) {
    fail(`${field} must be a non-negative BigInt below 2^63 to encode as a fixed 8-byte silverscript int`);
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function decodeInt8LE(bytes, field) {
  if (bytes.length !== 8) fail(`${field} must be 8 bytes`);
  if ((bytes[7] & 0x80) !== 0) fail(`${field} has the sign bit set — a v0.7 root state never holds a negative field`, "NEGATIVE_FIELD");
  let v = 0n;
  for (let i = 7; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/*
 * The EXACT state-region bytes the compiler bakes into the root's redeem
 * script. Rebuilding them here is what lets the SDK and the manifest verify
 * a root successor byte-for-byte (which is precisely what the rooted vault's
 * covenant does in-VM).
 */
function serializeRootStateV7(state) {
  const s = state && state.activeCount !== undefined ? state : normalizeRootStateV7(state);
  const parts = [];
  const pushBytes32 = (hex) => {
    parts.push(new Uint8Array([0x20]));
    parts.push(hexToBytes(hex));
  };
  const pushInt = (value, field) => {
    parts.push(new Uint8Array([0x08]));
    parts.push(encodeInt8LE(value, field));
  };
  pushBytes32(s.boundOrgId);
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) pushBytes32(s.owners[i]);
  pushInt(s.ownerM, "ownerM");
  pushInt(s.emergencyK, "emergencyK");
  pushInt(s.recoveryM, "recoveryM");
  /* TAIL */
  parts.push(new Uint8Array([0x01, Number(s.frozen)]));
  parts.push(new Uint8Array([0x08]));
  parts.push(encodeInt8LE(s.rootNonce, "rootNonce"));

  let total = 0;
  for (const p of parts) total += p.length;
  if (total !== ROOT_STATE_LEN_V7) fail(`internal: serialized root state is ${total} B, expected ${ROOT_STATE_LEN_V7}`);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function serializeRootStateHexV7(state) {
  return bytesToHex(serializeRootStateV7(state));
}

/* The 11-byte fixed-width TAIL: 0x01 || frozen || 0x08 || nonce(8 LE). */
function rootStateTailV7({ frozen, rootNonce }) {
  const f = bigIntField(frozen, "frozen", { min: 0n, max: 1n });
  const n = bigIntField(rootNonce, "rootNonce", { min: 0n, max: MAX_ROOT_NONCE_V7 + 1n });
  const out = new Uint8Array(ROOT_TAIL_LEN_V7);
  out[0] = 0x01;
  out[1] = Number(f);
  out[2] = 0x08;
  out.set(encodeInt8LE(n, "rootNonce"), 3);
  return out;
}
function rootStateTailHexV7(input) {
  return bytesToHex(rootStateTailV7(input));
}

/* The exact successor tail a rooted vault's covenant rebuilds and pins. */
function expectedRootSuccessorTailHexV7({ prevRootNonce, expectFrozenAfter }) {
  const prev = bigIntField(prevRootNonce, "prevRootNonce", { min: 0n, max: MAX_ROOT_NONCE_V7 });
  return rootStateTailHexV7({ frozen: expectFrozenAfter, rootNonce: prev + 1n });
}

/* Inverse of serializeRootStateV7 — used to READ a root successor's bytes. */
function parseRootStateV7(bytes) {
  let b = bytes;
  if (typeof b === "string") {
    const hex = b.trim().toLowerCase();
    if (!/^[0-9a-f]*$/.test(hex) || hex.length !== ROOT_STATE_LEN_V7 * 2) {
      fail(`a v0.7 root state region is exactly ${ROOT_STATE_LEN_V7} bytes of lowercase hex — refusing to parse ${hex.length / 2} bytes`, "BAD_STATE_LENGTH");
    }
    b = hexToBytes(normalizeHex(hex, ROOT_STATE_LEN_V7, "rootState"));
  }
  if (!(b instanceof Uint8Array) || b.length !== ROOT_STATE_LEN_V7) {
    fail(`a v0.7 root state region is exactly ${ROOT_STATE_LEN_V7} bytes — refusing to parse ${b && b.length} bytes`, "BAD_STATE_LENGTH");
  }
  let at = 0;
  const take32 = (field) => {
    if (b[at] !== 0x20) fail(`${field}: expected a 32-byte data prefix 0x20 at offset ${at}, found 0x${b[at].toString(16)}`, "BAD_STATE_ENCODING");
    const hex = bytesToHex(b.subarray(at + 1, at + 33));
    at += 33;
    return hex;
  };
  const takeInt = (field) => {
    if (b[at] !== 0x08) fail(`${field}: expected an 8-byte int prefix 0x08 at offset ${at}, found 0x${b[at].toString(16)}`, "BAD_STATE_ENCODING");
    const v = decodeInt8LE(b.subarray(at + 1, at + 9), field);
    at += 9;
    return v;
  };
  const boundOrgId = take32("boundOrgId");
  const owners = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) owners.push(take32(`owner${i + 1}`));
  const ownerM = takeInt("ownerM");
  const emergencyK = takeInt("emergencyK");
  const recoveryM = takeInt("recoveryM");
  if (b[at] !== 0x01) fail(`frozen: expected a 1-byte data prefix 0x01 at offset ${at}`, "BAD_STATE_ENCODING");
  const frozenByte = b[at + 1];
  if (frozenByte !== 0x00 && frozenByte !== 0x01) fail(`frozen byte 0x${frozenByte.toString(16)} is outside {0x00, 0x01}`, "BAD_FROZEN_DOMAIN");
  at += 2;
  const rootNonce = takeInt("rootNonce");
  if (at !== ROOT_STATE_LEN_V7) fail("internal: root state parse did not consume the whole region");
  return normalizeRootStateV7({ boundOrgId, owners, ownerM, emergencyK, recoveryM, frozen: BigInt(frozenByte), rootNonce });
}

/* ------------------------------------------------------------------ */
/* identity                                                            */
/* ------------------------------------------------------------------ */

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/*
 * Deterministic root state DIGEST — a representation-independent hash of the
 * EXACT consensus-visible state bytes. It is what the signer-visible
 * manifest carries for "prev root state" and "new root state": two parties
 * comparing digests are comparing the bytes consensus will compare.
 */
function computeRootStateDigestV7(state) {
  /* BYTE-NATIVE on purpose: `update(<Uint8Array>)` is exactly the surface the
   * browser crypto shim supports (the F1 browser-portability wave), so this
   * digest is computable in a browser or a mobile signer, not only in Node.
   * An ambient `Buffer` here would have made the module Node-only — which is
   * precisely what core/crossruntime/test/v7-org-root-portability.test.js
   * catches. */
  return crypto.createHash("sha256").update(serializeRootStateV7(state)).digest("hex");
}

/* Deterministic root state ID (application identity; never a consensus value). */
function computeRootStateIdV7({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) fail("networkId is required for the root state ID");
  const abi = resolveV7RootAbi(contractVersion ?? CONTRACT_VERSION_V7_ROOT);
  const t = normalizeRootTemplateV7(template);
  const s = normalizeRootStateV7(state);
  const canonical = [
    "policyvault-root-state/v7",
    `network:${networkId}`,
    `contract:${abi.version}`,
    `orgId:${t.orgId}`,
    `recoveryDelayDaa:${t.recoveryDelayDaa}`,
    `successorPk:${t.successorPk}`,
    `successionDelayDaa:${t.successionDelayDaa}`,
    `rootMaxFeePerTx:${t.rootMaxFeePerTx}`,
    `stateDigest:${computeRootStateDigestV7(s)}`
  ].join("\n");
  return sha256Hex(canonical);
}

function rootStateToJsonV7(state) {
  const s = state && state.activeCount !== undefined ? state : normalizeRootStateV7(state);
  return {
    boundOrgId: s.boundOrgId,
    owners: [...s.owners],
    ownerM: s.ownerM.toString(),
    emergencyK: s.emergencyK.toString(),
    recoveryM: s.recoveryM.toString(),
    frozen: s.frozen.toString(),
    rootNonce: s.rootNonce.toString()
  };
}

function rootTemplateToJsonV7(template) {
  const t = normalizeRootTemplateV7(template);
  return {
    orgId: t.orgId,
    recoveryDelayDaa: t.recoveryDelayDaa.toString(),
    successorPk: t.successorPk,
    successionEnabled: t.successionEnabled,
    successionDelayDaa: t.successionDelayDaa.toString(),
    rootMaxFeePerTx: t.rootMaxFeePerTx.toString()
  };
}

module.exports = {
  CONTRACT_VERSION_V7_ROOT,
  V7_ROOT_ABIS,
  ROOT_STATE_LEN_V7,
  ROOT_TAIL_LEN_V7,
  ROOT_HEAD_LEN_V7,
  ROOT_FROZEN_PUSH_LEN_V7,
  ROOT_NONCE_PUSH_LEN_V7,
  MAX_ROOT_NONCE_V7,
  resolveV7RootAbi,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  genesisRootStateV7,
  serializeRootStateV7,
  serializeRootStateHexV7,
  parseRootStateV7,
  rootStateTailV7,
  rootStateTailHexV7,
  expectedRootSuccessorTailHexV7,
  computeRootStateDigestV7,
  computeRootStateIdV7,
  rootStateToJsonV7,
  rootTemplateToJsonV7
};
