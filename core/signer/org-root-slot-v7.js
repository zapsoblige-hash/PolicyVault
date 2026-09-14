"use strict";

/*
 * PolicyVault v0.7 ORGANIZATIONAL ROOT — the EXTERNAL-SIGNER SLOT PATH.
 *
 * One owner, one slot, one signature. A v0.7 root spend is authorized by an
 * M-of-N blob of 12 x 65 bytes in which slot i is a SIGHASH_ALL signature
 * under owner key i (core/model/owner-set-v7). Each owner therefore signs
 * INDEPENDENTLY, out of band, over the SAME frozen transaction — a browser
 * extension, a hardware device, an air-gapped machine, an HSM or a policy
 * engine, each behind the Universal Signer Interface (core/signer/interface).
 * This module is the request/response envelope that makes that collection
 * round safe:
 *
 *   createRootSlotSigningRequest()   one owner's request, bound to the
 *                                    manifest hash, the slot, the root
 *                                    outpoint, the network, the expected
 *                                    signer identity and a deadline;
 *   requestRootSlotSignature()       drive that request through ANY
 *                                    validated USI v1 adapter (CLI /
 *                                    air-gapped / hardware / extension);
 *   buildRootSlotSignatureResponse() the response envelope a signer (or an
 *                                    air-gap shuttle) returns;
 *   verifyRootSlotSignatureResponse()every binding re-checked, fail closed;
 *   collectRootSlotApprovals()       fold verified responses into the
 *                                    780-byte blob through the PINNED core
 *                                    assembler (quorum, duplicate-slot,
 *                                    signature-reuse and sighash rules are
 *                                    the covenant's own, not new ones).
 *
 * WHAT THIS PATH REFUSES (each with a named reason; the interface's CLOSED
 * v1 error vocabulary is never extended):
 *   WRONG_NETWORK          the request's network is not the signer's
 *   REQUEST_EXPIRED        the collection round's deadline elapsed
 *   RESPONSE_REPLAYED      a response reused against a different request
 *   MANIFEST_HASH_MISMATCH the response describes a different manifest
 *   TXID_DRIFT             the signer returned different transaction bytes
 *   FOREIGN_INPUT_SIGNED   the signer touched an input it was not asked to
 *   SLOT_NOT_HELD          the signer claims a slot it does not hold (or is
 *                          asked for one whose key it does not report)
 *   SLOT_KEY_MISMATCH      the declared slot key is not the set's slot key
 *   SLOT_INACTIVE          a sentinel-zero slot (never inspected in-VM)
 *   DUPLICATE_SLOT         two responses for one slot
 *   SIGHASH_NOT_ALL        a slot signature whose gate byte is not 0x01
 *   PLACEHOLDER_AS_SIGNATURE / SIGNATURE_INVALID  malformed slot material
 *   UNDER_QUORUM           fewer verified slots than the action requires
 *
 * FRESHNESS — READ THIS BEFORE TRUSTING `expiresAtMs`. The request deadline
 * is a COORDINATION deadline for the collection round only. It is NOT a
 * consensus expiry and it is NOT what makes a stale approval unusable: the
 * ONE kill switch is the root OUTPOINT. Every counted slot signature is
 * SIGHASH_ALL over the whole transaction, which commits to the root's
 * outpoint (single-use by consensus) and to the successor state whose nonce
 * strictly increases — so spending the root invalidates every collected
 * approval at once. Kaspa lockTime is a lower bound only, which is exactly
 * why the manifest deliberately carries no expiry field.
 *
 * IDENTITY BOUNDARY (standing project rule, inherited from
 * core/signer/interface.js): everything an adapter reports about identity is
 * a CLAIM, and this module contains NO cryptography and NO address codec. It
 * binds the transport identity (`expectedSignerAddress`) and the covenant
 * identity (`slot.publicKey`) into one envelope and refuses any mismatch it
 * can see structurally; the address <-> key correspondence is established by
 * the caller that owns the codec. The CRYPTOGRAPHIC slot <-> key binding is
 * the covenant's own per-slot `checkSig` under consensus — an optional
 * `verifySlotSignature` hook may be injected by a caller that holds a
 * verifier, and when it is supplied a failure REFUSES.
 *
 * TRANSPORTABLE: a request and a response are both plain JSON-safe objects
 * with no functions and no ambient state, so an air-gapped flow can write the
 * request to a file, carry it across, and bring the response back — and every
 * binding is re-checked on the way in. The OPTIONAL local signature verifier
 * is a verification-time argument, never a field of the transported request.
 *
 * NON-CUSTODY: no field of any request or response can carry a seed phrase,
 * a private key or a wallet backup. Requests carry frozen public bytes;
 * responses carry a 65-byte signature. Keys never leave the signer.
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from server/ or
 * sdk/ (node:crypto only, for request-id entropy, through the interface).
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/signer/test/org-root-slot-v7.test.js)
 * + SDK-TESTED end to end with REAL Schnorr signatures through two independent
 * offline CLI keyfile signers (sdk/test/org-root-slot-signer-v7.test.js).
 */

const crypto = require("crypto");
const { SIGNER_INTERFACE_VERSION, SignerErrorCodes, signerError } = require("./errors");
const { SIGHASH_ALL, SIGNER_NETWORKS, createTransactionSigningRequest, executeSigning, normalizePublicKeyToXOnly } = require("./interface");
const {
  OWNER_SLOTS_V7,
  SIG_SLOT_LEN_V7,
  INACTIVE_SLOT_KEY,
  normalizeOwnerSetV7,
  assembleOwnerSigsBlobV7,
  normalizeSlotSignatureHex
} = require("../model/owner-set-v7");
const { ORG_ROOT_MANIFEST_VERSION_1, verifyOrgRootIntentManifest } = require("../intent/org-root-manifest-v7");
/* v0.7 enablement (2026-09-10): the org-root-KAS manifest family (owner operations on a ROOTED KAS SAFE-PAYMENT VAULT riding
 * the same root transition) is a second accepted family. Dispatch is by manifestVersion, each family through ITS OWN
 * verifier; anything else fails closed (no default route). */
const { ORG_ROOT_KAS_MANIFEST_VERSION_1, verifyOrgRootIntentManifestV7Kas } = require("../intent/org-root-manifest-v7-kas");
const ACCEPTED_ROOT_MANIFEST_FAMILIES = Object.freeze([ORG_ROOT_MANIFEST_VERSION_1, ORG_ROOT_KAS_MANIFEST_VERSION_1]);
function verifyRootManifestByFamily({ manifest, descriptors, redeemScripts }) {
  if (manifest.manifestVersion === ORG_ROOT_MANIFEST_VERSION_1) return verifyOrgRootIntentManifest({ manifest, descriptors, redeemScripts });
  if (manifest.manifestVersion === ORG_ROOT_KAS_MANIFEST_VERSION_1) return verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts });
  return { verdict: "REFUSED", failures: [{ name: "manifestVersion", detail: `unknown org-root manifest family ${String(manifest.manifestVersion)}` }] };
}
/*
 * v2 addition (Wave 2, Track G): the SAME Universal Signer Interface v2
 * core (core/signer/v2) every other v2 consumer uses. Imported ADDITIVELY —
 * nothing above this line, and nothing in the v1 functions below, changes.
 */
/* PORTABILITY: require the two portable v2 leaves directly, NOT the v2 index —
 * the index also pulls the mock adapter and the transport adapters, which are
 * deliberately not part of the closed browser/mobile bundle. Same names. */
const v2 = Object.freeze({ ...require("./v2/errors"), ...require("./v2/interface") });

const ORG_ROOT_SLOT_REQUEST_VERSION_1 = "policyvault-org-root-slot-request/1";
const ORG_ROOT_SLOT_RESPONSE_VERSION_1 = "policyvault-org-root-slot-response/1";

/*
 * policyvault-org-root-slot-request/2 — the SAME slot-collection round,
 * carried over the Universal Signer Interface v2 (docs/postlaunch/
 * signer-interface-v2-spec.md) instead of v1. Additive and parallel: the
 * v1 request/response versions, and every v1 function above, are
 * byte-identical and untouched. A v2 collection round differs from v1 in
 * exactly the ways v2 differs from v1 generally (§2 of the v2 spec):
 *
 *   - CAPABILITY PROBING: `requestRootSlotSignatureV2` always drives the
 *     request through `executeSigningV2`, whose gate 3 cross-checks the
 *     adapter's DECLARED descriptor against what `probeCapabilities()`
 *     actually observes — SIGHASH_ALL and the transaction format included
 *     — and refuses `CAPABILITY_MISMATCH` before any prompt opens. By
 *     default a signer that cannot be probed at all (`probed: false`) is
 *     ALSO refused (`requireProbedCapabilities`, overridable for adapters
 *     — e.g. the air-gap shuttle — whose whole point is that they cannot
 *     be interrogated before the shuttle).
 *   - USER PRESENCE: `requestRootSlotSignatureV2` defaults
 *     `requireUserPresence: true` — an organizational owner's counted
 *     signature is expected to come from a human at the signer. The
 *     override exists, and is used, for adapters that are legitimately
 *     unattended by deliberate operator choice (the CLI keyfile adapter
 *     declares `userPresence: "not-required"` because running the process
 *     IS the approval — spec §8); it is never silently defaulted away.
 *   - BOUND REQUEST + RESPONSE ENVELOPE: the request carries a CSPRNG
 *     nonce and a `payloadSha256` that commits to the exact unsigned
 *     transaction bytes AND the manifest hash AND the slot AND the root
 *     outpoint AND the nonce itself (`computeSlotRequestDigestV2`) — a
 *     strictly WIDER binding than v1's per-field checks, folded into one
 *     digest a caller can compare in one step. The response is a bound
 *     envelope that echoes `requestVersion`/`requestId`/`nonce`; a v1
 *     envelope presented on this path (or vice versa) is refused with
 *     `INTERFACE_VERSION_UNSUPPORTED` before any other field is read.
 *   - EXPIRY + CANCELLATION: `expiresAtMs` is still a COORDINATION
 *     deadline only (see the header above — the root OUTPOINT remains the
 *     one freshness kill switch), but v2's own request expiry and
 *     cancellation-token plumbing are available to
 *     `requestRootSlotSignatureV2` through `executeSigningV2`.
 *   - REPLAY GUARD keyed on (root id, root STATE nonce, request id, slot):
 *     `createOrgRootSlotReplayGuardV2()` is a SEPARATE, coarser guard than
 *     v2's own session-scoped requestId/nonce guard (which
 *     `executeSigningV2` already runs internally per signer call) — it
 *     exists to catch a caller issuing TWO overlapping requests for the
 *     SAME (root, root-state-nonce, slot), which the per-request guard
 *     cannot see because each request legitimately gets its own fresh
 *     requestId/nonce.
 *
 * WHAT DID NOT CHANGE: the 65-byte/0x01 SIGHASH_ALL gate is still checked
 * IN-CORE before a signature is ever stored
 * (`extractSlotSignatureFromSignedTransaction` / `normalizeSlotSignatureHex`
 * — REUSED verbatim, not reimplemented); the frozen-byte structural proof
 * (`extractSlotSignatureFromSignedTransaction`'s TXID-drift / foreign-input
 * checks) is the SAME function the v1 path calls; `collectRootSlotApprovalsV2`
 * folds into the SAME pinned `assembleOwnerSigsBlobV7` the v1 path uses —
 * the covenant's own quorum/duplicate-slot/signature-reuse/sighash rules
 * are not re-implemented, and a v2-collected blob is byte-identical to a
 * v1-collected one for the same approvals.
 *
 * COMPATIBILITY CLAIMS (stated precisely, not implied): this module is
 * UNIT-TESTED and ADVERSARIAL-TESTED against the mock v2 adapter, the CLI
 * keyfile v2 adapter (REAL kaspa-wasm BIP-340 Schnorr — see
 * sdk/test/org-root-slot-signer-v2.test.js), and the air-gap v2 shuttle's
 * serialization round trip. It is NOT tested against, and makes NO claim
 * of compatibility with, any live browser wallet: the KasWare v2 lift is
 * itself only UNIT-TESTED against the documented provider API (v2 spec
 * §1/§8), never against a running extension, and that limitation is
 * inherited unchanged here.
 */
const ORG_ROOT_SLOT_REQUEST_VERSION_2 = "policyvault-org-root-slot-request/2";
const ORG_ROOT_SLOT_RESPONSE_VERSION_2 = "policyvault-org-root-slot-response/2";

const SLOT_REQUEST_DIGEST_DOMAIN_V2 = "policyvault-org-root-slot-request-digest/2";

/* Closed key sets — bounded envelopes, never an open bag of fields. */
const SLOT_REQUEST_V2_KEYS = Object.freeze([
  "requestVersion",
  "interfaceVersion",
  "requestId",
  "nonce",
  "createdAtMs",
  "expiresAtMs",
  "expiryIsCoordinationOnly",
  "network",
  "manifestHash",
  "txId",
  "root",
  "slot",
  "action",
  "expectedSignerAddress",
  "unsignedSafeJson",
  "payloadSha256",
  "requiredCapabilities",
  "signerRequest"
]);
const SLOT_RESPONSE_V2_KEYS = Object.freeze([
  "responseVersion",
  "requestVersion",
  "requestId",
  "nonce",
  "network",
  "manifestHash",
  "txId",
  "root",
  "slot",
  "signerAddress",
  "signatureHex",
  "sighashType",
  "signedAtMs",
  "capabilitiesProbed",
  "txIdVerified",
  "provider",
  "transport"
]);
const MAX_ROOT_NONCE_DIGITS = 20; /* u64 decimal never exceeds 20 digits */
const DECIMAL_STRING_RE = /^(0|[1-9][0-9]{0,19})$/;

function assertDecimalString(value, field) {
  if (typeof value !== "string" || !DECIMAL_STRING_RE.test(value) || value.length > MAX_ROOT_NONCE_DIGITS) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `${field} must be a canonical non-negative decimal string`);
  }
  return value;
}

/*
 * The v2 slot-request digest: sha256 over a domain tag and the EXACT
 * unsigned transaction bytes, the manifest hash, the slot number, the
 * root outpoint, and the request's own nonce — joined unambiguously
 * (newline-separated, each field already a closed hex/decimal/JSON
 * string so no field can absorb a neighbour's bytes). This is a STRICTER,
 * wider binding than v1 ever expressed: v1 checks each of these fields
 * independently at verification time; v2 additionally lets a caller
 * confirm all of them at once by recomputing one digest.
 */
function computeSlotRequestDigestV2({ unsignedSafeJson, manifestHash, slotNumber, rootOutpoint, nonce }) {
  const material = [
    SLOT_REQUEST_DIGEST_DOMAIN_V2,
    unsignedSafeJson,
    manifestHash,
    String(slotNumber),
    `${rootOutpoint.transactionId}:${rootOutpoint.index}`,
    nonce
  ].join("\n");
  return crypto.createHash("sha256").update(material, "utf8").digest("hex");
}

/* The named reasons this path can refuse for. They are DETAIL, never a
 * substitute for the interface's closed error-code vocabulary: every throw
 * below still carries one of SignerErrorCodes. */
const SLOT_REFUSALS = Object.freeze({
  REQUEST_INVALID: "REQUEST_INVALID",
  REQUEST_EXPIRED: "REQUEST_EXPIRED",
  MANIFEST_NOT_VERIFIED: "MANIFEST_NOT_VERIFIED",
  MANIFEST_HASH_MISMATCH: "MANIFEST_HASH_MISMATCH",
  WRONG_NETWORK: "WRONG_NETWORK",
  ROOT_OUTPOINT_MISMATCH: "ROOT_OUTPOINT_MISMATCH",
  ROOT_INPUT_MISMATCH: "ROOT_INPUT_MISMATCH",
  SLOT_OUT_OF_RANGE: "SLOT_OUT_OF_RANGE",
  SLOT_INACTIVE: "SLOT_INACTIVE",
  SLOT_KEY_MISMATCH: "SLOT_KEY_MISMATCH",
  SLOT_NOT_HELD: "SLOT_NOT_HELD",
  DUPLICATE_SLOT: "DUPLICATE_SLOT",
  RESPONSE_REPLAYED: "RESPONSE_REPLAYED",
  RESPONSE_INVALID: "RESPONSE_INVALID",
  TXID_DRIFT: "TXID_DRIFT",
  FOREIGN_INPUT_SIGNED: "FOREIGN_INPUT_SIGNED",
  SIGNER_IDENTITY_MISMATCH: "SIGNER_IDENTITY_MISMATCH",
  SIGHASH_NOT_ALL: "SIGHASH_NOT_ALL",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  SIGNATURE_NOT_VERIFIED: "SIGNATURE_NOT_VERIFIED",
  SUCCESSION_TAKES_NO_SLOTS: "SUCCESSION_TAKES_NO_SLOTS",
  /* v2 additions ONLY (Wave 2, Track G) — the v1 reasons above are
   * unchanged and every v1 refusal still carries exactly the same one. */
  SLOT_REQUEST_DIGEST_MISMATCH: "SLOT_REQUEST_DIGEST_MISMATCH",
  NONCE_MISMATCH: "NONCE_MISMATCH",
  DUPLICATE_SLOT_REQUEST: "DUPLICATE_SLOT_REQUEST"
});

const MAX_REQUEST_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000; /* 7 days: a collection round, not a security window */
const HEX64_RE = /^[0-9a-f]{64}$/;

function refuse(code, reason, message, details = {}) {
  return signerError(code, `org-root-slot-v7 ${reason}: ${message}`, { details: { reason, ...details } });
}

/*
 * v2 counterpart of `refuse()`. The v1 helper above constructs its error
 * through v1's `signerError`, which validates the code against v1's
 * CLOSED (block-1-only) vocabulary — a v2-ONLY code (PAYLOAD_MUTATED,
 * RESPONSE_BINDING_MISMATCH, REPLAY_DETECTED, DUPLICATE_SETTLEMENT,
 * CAPABILITY_MISMATCH, ...) would be silently reclassified to
 * PROTOCOL_VIOLATION by that constructor. Every v2 function below that
 * needs to throw one of those codes uses THIS helper instead, which goes
 * through `v2.signerErrorV2` (the wider v2 vocabulary). Codes v1 and v2
 * share (e.g. WRONG_NETWORK, ACCOUNT_CHANGED, INTERFACE_VERSION_UNSUPPORTED)
 * work identically through either helper — same string value, same result.
 */
function refuseV2(code, reason, message, details = {}) {
  return v2.signerErrorV2(code, `org-root-slot-v7 ${reason}: ${message}`, { details: { reason, ...details } });
}

function invalidRequest(reason, message, details) {
  return refuse(SignerErrorCodes.REQUEST_INVALID, reason, message, details);
}

function invalidResponse(reason, message, details) {
  return refuse(SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, reason, message, details);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function newRequestId() {
  return crypto.randomBytes(16).toString("hex");
}

function assertHex64(value, field) {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `${field} must be 32-byte lowercase hex`);
  }
  return value;
}

function assertIntegerMs(value, field) {
  if (!Number.isInteger(value) || value <= 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `${field} must be a positive integer epoch-millisecond value`);
  return value;
}

function sameOutpoint(a, b) {
  return isPlainObject(a) && isPlainObject(b) && a.transactionId === b.transactionId && Number(a.index) === Number(b.index);
}

/* ------------------------------------------------------------------ */
/* request construction                                                */
/* ------------------------------------------------------------------ */

/*
 * Build ONE owner's slot signing request from a VERIFIED org-root manifest.
 *
 * The manifest is re-verified here (never trusted by marker), so a request
 * can never be issued for a description that does not match the transaction
 * it asks an owner to sign. The request carries, and the response envelope
 * binds, all of: manifest hash, slot index, root outpoint, network, expected
 * signer address, and the deadline.
 *
 *   manifest              policyvault-org-root-manifest/1
 *   slot                  1..12 (1-based, as the manifest names slots)
 *   expectedSignerAddress the address the adapter must report as active
 *   unsignedSafeJson      the FROZEN transaction serialization to sign
 *   rootInputIndex        the index of the root covenant input
 *   expiresAtMs           coordination deadline (see the header: NOT a
 *                         consensus expiry)
 */
function createRootSlotSigningRequest({
  manifest,
  descriptors = {},
  redeemScripts = {}, // Codex checkpoint 6 (UX-02 / UX-13): the vault's predecessor redeem script(s) the verifier rebuilds the successor from
  slot,
  expectedSignerAddress,
  unsignedSafeJson,
  rootInputIndex,
  expiresAtMs,
  nowMs = Date.now()
} = {}) {
  if (!isPlainObject(manifest) || !ACCEPTED_ROOT_MANIFEST_FAMILIES.includes(manifest.manifestVersion)) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `a ${ACCEPTED_ROOT_MANIFEST_FAMILIES.join(" or ")} manifest is required — failing closed (no default route)`);
  }
  const verification = verifyRootManifestByFamily({ manifest, descriptors, redeemScripts });
  if (verification.verdict !== "VERIFIED") {
    throw invalidRequest(
      SLOT_REFUSALS.MANIFEST_NOT_VERIFIED,
      `the manifest does not verify against the transaction it describes — refusing to ask an owner to sign it (failing checks: ${verification.failures.map((f) => f.name).join(", ")})`
    );
  }
  if (manifest.action.name === "succession") {
    throw invalidRequest(
      SLOT_REFUSALS.SUCCESSION_TAKES_NO_SLOTS,
      "a succession is authorized by the pinned successor key through its own entrypoint, not by an owner slot blob — there is no slot to request"
    );
  }

  const network = manifest.network.networkId;
  if (!SIGNER_NETWORKS.includes(network)) {
    throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `the manifest names network ${JSON.stringify(network)}, which this signer interface version does not express — failing closed`);
  }

  const slotNumber = Number(slot);
  if (!Number.isInteger(slotNumber) || slotNumber < 1 || slotNumber > OWNER_SLOTS_V7) {
    throw invalidRequest(SLOT_REFUSALS.SLOT_OUT_OF_RANGE, `slot must be an integer 1..${OWNER_SLOTS_V7}`);
  }
  const expected = manifest.action.expectedSignerSlots.find((s) => Number(s.slot) === slotNumber);
  if (!expected) {
    throw invalidRequest(
      SLOT_REFUSALS.SLOT_INACTIVE,
      `slot ${slotNumber} is not one of the ${manifest.action.expectedSignerSlots.length} active owner slot(s) this action expects — an inactive slot is never inspected by the covenant and can never count`
    );
  }
  if (expected.publicKey === INACTIVE_SLOT_KEY) {
    throw invalidRequest(SLOT_REFUSALS.SLOT_INACTIVE, `slot ${slotNumber} holds the sentinel-zero key`);
  }

  if (typeof expectedSignerAddress !== "string" || !expectedSignerAddress.trim()) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expectedSignerAddress is required — a slot signature is only accepted from the identity it was requested from");
  }
  if (typeof unsignedSafeJson !== "string" || !unsignedSafeJson) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "unsignedSafeJson (the FROZEN transaction serialization) is required");
  }
  if (!Number.isInteger(rootInputIndex) || rootInputIndex < 0) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "rootInputIndex (the index of the root covenant input) is required");
  }

  assertIntegerMs(nowMs, "nowMs");
  const deadline = assertIntegerMs(expiresAtMs, "expiresAtMs");
  if (deadline <= nowMs) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expiresAtMs must be in the future");
  if (deadline - nowMs > MAX_REQUEST_LIFETIME_MS) {
    throw invalidRequest(
      SLOT_REFUSALS.REQUEST_INVALID,
      `expiresAtMs is more than ${MAX_REQUEST_LIFETIME_MS} ms ahead — a collection round that long should be re-issued against a fresh root state rather than left open`
    );
  }

  /* the underlying USI v1 request: exactly ONE input, SIGHASH_ALL only */
  const signerRequest = createTransactionSigningRequest({
    unsignedSafeJson,
    signInputs: [{ index: rootInputIndex, sighashType: SIGHASH_ALL }],
    network,
    expectedSignerAddress,
    scheme: "schnorr"
  });

  return deepFreeze({
    requestVersion: ORG_ROOT_SLOT_REQUEST_VERSION_1,
    interfaceVersion: SIGNER_INTERFACE_VERSION,
    requestId: newRequestId(),
    createdAtMs: nowMs,
    expiresAtMs: deadline,
    expiryIsCoordinationOnly: true,
    network,
    manifestHash: assertHex64(manifest.manifestHash, "manifest.manifestHash"),
    txId: assertHex64(manifest.transaction.txId, "manifest.transaction.txId"),
    root: {
      covenantId: assertHex64(manifest.root.covenantId, "manifest.root.covenantId"),
      outpoint: { transactionId: manifest.root.outpoint.transactionId, index: Number(manifest.root.outpoint.index) },
      inputIndex: rootInputIndex
    },
    slot: { number: slotNumber, index: slotNumber - 1, publicKey: expected.publicKey },
    action: {
      name: manifest.action.name,
      authorityClass: manifest.action.authorityClass,
      requiredApprovals: manifest.action.requiredApprovals,
      quorumSource: manifest.action.quorumSource
    },
    expectedSignerAddress: expectedSignerAddress.trim(),
    unsignedSafeJson,
    signerRequest
  });
}

/* Structural re-validation of a slot request (defense in depth — a request
 * is re-checked, never trusted by marker). */
function assertRootSlotSigningRequest(request) {
  if (!isPlainObject(request)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "a slot signing request object is required");
  if (request.requestVersion !== ORG_ROOT_SLOT_REQUEST_VERSION_1) {
    throw refuse(
      SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.REQUEST_INVALID,
      `slot request declares version ${JSON.stringify(request.requestVersion)}; this core implements exactly ${JSON.stringify(ORG_ROOT_SLOT_REQUEST_VERSION_1)} — failing closed`
    );
  }
  if (typeof request.requestId !== "string" || !/^[0-9a-f]{32}$/.test(request.requestId)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "requestId must be 32-hex");
  assertHex64(request.manifestHash, "manifestHash");
  assertHex64(request.txId, "txId");
  assertHex64(request.slot.publicKey, "slot.publicKey");
  if (!SIGNER_NETWORKS.includes(request.network)) throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `unknown network ${JSON.stringify(request.network)}`);
  if (!Number.isInteger(request.slot.number) || request.slot.number < 1 || request.slot.number > OWNER_SLOTS_V7) throw invalidRequest(SLOT_REFUSALS.SLOT_OUT_OF_RANGE, "slot.number out of range");
  if (request.slot.index !== request.slot.number - 1) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "slot.index must be slot.number - 1");
  assertIntegerMs(request.expiresAtMs, "expiresAtMs");
  if (typeof request.unsignedSafeJson !== "string" || !request.unsignedSafeJson) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "unsignedSafeJson is required");
  if (!isPlainObject(request.signerRequest) || request.signerRequest.kind !== "sign-transaction") throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "signerRequest must be the USI sign-transaction request");
  return request;
}

function assertNotExpired(request, nowMs) {
  assertIntegerMs(nowMs, "nowMs");
  if (nowMs >= request.expiresAtMs) {
    throw refuse(
      SignerErrorCodes.SIGNER_TIMEOUT,
      SLOT_REFUSALS.REQUEST_EXPIRED,
      `the collection round for slot ${request.slot.number} closed at ${request.expiresAtMs}; re-issue the request against the live root state (the security freshness is the root OUTPOINT, not this deadline)`
    );
  }
}

/* ------------------------------------------------------------------ */
/* signed-transaction -> ONE slot signature                            */
/* ------------------------------------------------------------------ */

/*
 * Extract the slot signature a signer produced, and prove structurally that
 * it signed EXACTLY the transaction it was handed and EXACTLY the one input
 * it was asked for.
 *
 * A USI v1 adapter returns the signed Safe JSON serialization. The frozen
 * bytes must be otherwise IDENTICAL: any other difference — an output value,
 * a recipient script, another input's signature script, the lock time — is
 * TXID DRIFT and refuses. (A different transaction is exactly what "a slot
 * signature over a different transaction" means, and this catches it without
 * needing a txid implementation in portable core.)
 */
function extractSlotSignatureFromSignedTransaction({ request, signedSafeJson }) {
  assertRootSlotSigningRequest(request);
  if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "the signer returned no signed transaction serialization");
  }
  let signed;
  let unsigned;
  try {
    signed = JSON.parse(signedSafeJson);
    unsigned = JSON.parse(request.unsignedSafeJson);
  } catch (e) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, `the signed serialization is not JSON: ${e.message}`);
  }
  if (!isPlainObject(signed) || !Array.isArray(signed.inputs) || signed.inputs.length !== unsigned.inputs.length) {
    throw invalidResponse(SLOT_REFUSALS.TXID_DRIFT, "the signed serialization does not have the same input set as the frozen transaction");
  }
  const idx = request.root.inputIndex;
  if (idx >= signed.inputs.length) throw invalidResponse(SLOT_REFUSALS.ROOT_INPUT_MISMATCH, `root input index ${idx} is out of range for a transaction with ${signed.inputs.length} input(s)`);

  /* Every field EXCEPT the one signature script must be byte-identical. The
   * frozen serialization may carry no `signatureScript` key at all for an
   * unsigned input, so the comparison restores the ORIGINAL presence/absence
   * rather than normalizing it — normalizing would hide a real difference. */
  const strippedSigned = JSON.parse(signedSafeJson);
  const strippedUnsigned = JSON.parse(request.unsignedSafeJson);
  const returnedScript = String(strippedSigned.inputs[idx].signatureScript ?? "");
  if (Object.prototype.hasOwnProperty.call(strippedUnsigned.inputs[idx], "signatureScript")) {
    strippedSigned.inputs[idx].signatureScript = strippedUnsigned.inputs[idx].signatureScript;
  } else {
    delete strippedSigned.inputs[idx].signatureScript;
  }
  if (JSON.stringify(strippedSigned) !== JSON.stringify(strippedUnsigned)) {
    /* attribute the drift: a foreign input touched vs. anything else */
    for (let i = 0; i < signed.inputs.length; i += 1) {
      if (i === idx) continue;
      if (String(signed.inputs[i].signatureScript ?? "") !== String(unsigned.inputs[i].signatureScript ?? "")) {
        throw invalidResponse(
          SLOT_REFUSALS.FOREIGN_INPUT_SIGNED,
          `the signer altered input ${i}, which this request did not ask it to sign — refusing the whole response`
        );
      }
    }
    throw invalidResponse(
      SLOT_REFUSALS.TXID_DRIFT,
      "the signer returned different transaction bytes than the frozen ones it was handed — a slot signature over a different transaction can never be accepted"
    );
  }

  /* the returned script is the raw createInputSignature output: a 0x41 push
   * of 64-byte Schnorr + the sighash-type byte. normalizeSlotSignatureHex
   * tolerates the push opcode and enforces the 0x01 SIGHASH_ALL gate the
   * covenant checks on every counted slot. */
  let signatureHex;
  try {
    signatureHex = normalizeSlotSignatureHex(returnedScript, `slot ${request.slot.number} signature`);
  } catch (e) {
    const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : e.code === "PLACEHOLDER_AS_SIGNATURE" ? SLOT_REFUSALS.SIGNATURE_INVALID : SLOT_REFUSALS.SIGNATURE_INVALID;
    throw invalidResponse(reason, e.message, { code: e.code ?? null });
  }
  return signatureHex;
}

/* ------------------------------------------------------------------ */
/* response envelope                                                   */
/* ------------------------------------------------------------------ */

/*
 * Build the response envelope for ONE slot. It re-states every binding the
 * request carried, so a response can be shuttled across an air gap as a
 * standalone file and still be checked against the request it belongs to.
 *
 * Exactly one of `signedSafeJson` (an adapter's signed serialization) or
 * `signatureHex` (a raw 65-byte slot signature, e.g. from a device that
 * returns only the signature) is supplied.
 */
function buildRootSlotSignatureResponse({ request, signedSafeJson, signatureHex, signerAddress, signedAtMs = Date.now() }) {
  assertRootSlotSigningRequest(request);
  const haveSigned = signedSafeJson !== undefined && signedSafeJson !== null;
  const haveRaw = signatureHex !== undefined && signatureHex !== null;
  if (haveSigned === haveRaw) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "exactly one of signedSafeJson or signatureHex must be supplied");
  }
  let sig;
  if (haveSigned) {
    sig = extractSlotSignatureFromSignedTransaction({ request, signedSafeJson });
  } else {
    try {
      sig = normalizeSlotSignatureHex(signatureHex, `slot ${request.slot.number} signature`);
    } catch (e) {
      const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : SLOT_REFUSALS.SIGNATURE_INVALID;
      throw invalidResponse(reason, e.message, { code: e.code ?? null });
    }
  }
  assertIntegerMs(signedAtMs, "signedAtMs");
  return deepFreeze({
    responseVersion: ORG_ROOT_SLOT_RESPONSE_VERSION_1,
    requestVersion: request.requestVersion,
    requestId: request.requestId,
    network: request.network,
    manifestHash: request.manifestHash,
    txId: request.txId,
    root: { covenantId: request.root.covenantId, outpoint: { ...request.root.outpoint }, inputIndex: request.root.inputIndex },
    slot: { number: request.slot.number, index: request.slot.index, publicKey: request.slot.publicKey },
    signerAddress: typeof signerAddress === "string" && signerAddress.trim() ? signerAddress.trim() : request.expectedSignerAddress,
    signatureHex: sig,
    sighashType: SIGHASH_ALL,
    signedAtMs
  });
}

/*
 * Verify ONE response against the request it claims to answer. EVERY binding
 * is re-checked: version, requestId (a response replayed into another
 * request refuses here), network, manifest hash, txid, root covenant id and
 * outpoint, slot number and key, signer identity, the SIGHASH_ALL gate byte,
 * and the deadline.
 *
 * `ownerSet`, when supplied, is the PREDECESSOR owner set the covenant will
 * check against: the slot must be ACTIVE in it and hold exactly the declared
 * key, so a signer claiming a slot it does not hold is refused before the
 * blob is ever assembled.
 */
function verifyRootSlotSignatureResponse({ request, response, ownerSet = null, nowMs = Date.now(), verifySlotSignature = null }) {
  assertRootSlotSigningRequest(request);
  if (!isPlainObject(response)) throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "a slot response object is required");
  if (response.responseVersion !== ORG_ROOT_SLOT_RESPONSE_VERSION_1) {
    throw refuse(
      SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.RESPONSE_INVALID,
      `slot response declares version ${JSON.stringify(response.responseVersion)}; this core implements exactly ${JSON.stringify(ORG_ROOT_SLOT_RESPONSE_VERSION_1)} — failing closed`
    );
  }
  assertNotExpired(request, nowMs);

  if (response.requestId !== request.requestId) {
    throw invalidResponse(
      SLOT_REFUSALS.RESPONSE_REPLAYED,
      `this response answers request ${response.requestId}, not ${request.requestId} — a signature collected for one request is never accepted for another`
    );
  }
  if (response.network !== request.network) throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `response network ${JSON.stringify(response.network)} != request network ${JSON.stringify(request.network)}`);
  if (response.manifestHash !== request.manifestHash) throw invalidResponse(SLOT_REFUSALS.MANIFEST_HASH_MISMATCH, "the response describes a different manifest than the one this request was issued for");
  if (response.txId !== request.txId) throw invalidResponse(SLOT_REFUSALS.TXID_DRIFT, "the response names a different transaction id than the frozen one");
  if (!isPlainObject(response.root) || response.root.covenantId !== request.root.covenantId) throw invalidResponse(SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH, "the response names a different root covenant");
  if (!sameOutpoint(response.root.outpoint, request.root.outpoint)) {
    throw invalidResponse(
      SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH,
      "the response names a different root outpoint — the root outpoint IS the freshness kill switch and is never allowed to drift"
    );
  }
  if (!isPlainObject(response.slot) || Number(response.slot.number) !== request.slot.number) throw invalidResponse(SLOT_REFUSALS.SLOT_NOT_HELD, `the response claims slot ${response.slot && response.slot.number}, but this request is for slot ${request.slot.number}`);
  if (response.slot.publicKey !== request.slot.publicKey) throw invalidResponse(SLOT_REFUSALS.SLOT_KEY_MISMATCH, "the response declares a different key for this slot than the manifest's owner set does");
  if (response.signerAddress !== request.expectedSignerAddress) {
    throw refuse(SignerErrorCodes.ACCOUNT_CHANGED, SLOT_REFUSALS.SIGNER_IDENTITY_MISMATCH, "the response was produced by a different signer identity than the request was issued to");
  }
  if (response.sighashType !== SIGHASH_ALL) throw invalidResponse(SLOT_REFUSALS.SIGHASH_NOT_ALL, `the response declares sighash type ${JSON.stringify(response.sighashType)}; the root covenant gates every counted slot on SIGHASH_ALL (0x01)`);

  let signatureHex;
  try {
    signatureHex = normalizeSlotSignatureHex(response.signatureHex, `slot ${request.slot.number} signature`);
  } catch (e) {
    const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : SLOT_REFUSALS.SIGNATURE_INVALID;
    throw invalidResponse(reason, e.message, { code: e.code ?? null });
  }
  if (signatureHex.length !== SIG_SLOT_LEN_V7 * 2) throw invalidResponse(SLOT_REFUSALS.SIGNATURE_INVALID, `a slot signature must be exactly ${SIG_SLOT_LEN_V7} bytes`);

  /* the slot must be ACTIVE in the predecessor set and hold this exact key */
  if (ownerSet !== null) {
    const set = ownerSet.activeCount !== undefined ? ownerSet : normalizeOwnerSetV7(ownerSet);
    if (request.slot.index >= set.activeCount) {
      throw invalidResponse(SLOT_REFUSALS.SLOT_INACTIVE, `slot ${request.slot.number} is inactive in the predecessor owner set — inactive slots are never inspected by the covenant`);
    }
    if (set.owners[request.slot.index] !== request.slot.publicKey) {
      throw invalidResponse(
        SLOT_REFUSALS.SLOT_NOT_HELD,
        `slot ${request.slot.number} of the predecessor set holds a different key — refusing to place this signature under a key the covenant will not check it against`
      );
    }
  }

  /* OPTIONAL cryptographic binding. When a caller injects a verifier (it
   * owns the crypto; portable core deliberately does not), a failure REFUSES
   * here instead of at consensus. When none is injected the binding remains
   * the covenant's own per-slot checkSig — recorded honestly. */
  let signatureVerified = false;
  if (verifySlotSignature !== null) {
    if (typeof verifySlotSignature !== "function") throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "verifySlotSignature, when supplied, must be a function");
    let ok;
    try {
      ok = verifySlotSignature({ publicKey: request.slot.publicKey, signatureHex, unsignedSafeJson: request.unsignedSafeJson, inputIndex: request.root.inputIndex });
    } catch (e) {
      throw invalidResponse(SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED, `the injected slot-signature verifier failed: ${e.message}`);
    }
    if (ok !== true) {
      throw invalidResponse(SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED, `the slot signature does not verify under the slot's public key ${request.slot.publicKey}`);
    }
    signatureVerified = true;
  }

  return deepFreeze({
    slot: request.slot.number,
    index: request.slot.index,
    publicKey: request.slot.publicKey,
    signatureHex,
    signerAddress: response.signerAddress,
    signatureVerified,
    cryptographicBinding: signatureVerified
      ? "verified locally by the injected verifier AND enforced in-VM by the root covenant's per-slot checkSig"
      : "enforced in-VM by the root covenant's per-slot checkSig (no local verifier was injected)"
  });
}

/* ------------------------------------------------------------------ */
/* collection -> the 780-byte blob                                     */
/* ------------------------------------------------------------------ */

/*
 * Fold verified slot responses into the approvals list the PINNED core
 * assembler consumes, and assemble the blob.
 *
 * `pairs` is [{ request, response }] — one per owner who signed. The quorum,
 * duplicate-slot, signature-reuse, inactive-slot and SIGHASH_ALL rules are
 * NOT re-implemented here: assembleOwnerSigsBlobV7 owns them, because it is
 * the module the production-byte suites and the covenant agree with.
 */
function collectRootSlotApprovals({ ownerSet, actionName, pairs, nowMs = Date.now(), requireQuorum = true, verifySlotSignature = null }) {
  if (!Array.isArray(pairs) || pairs.length === 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "pairs must be a non-empty array of { request, response }");
  const set = ownerSet && ownerSet.activeCount !== undefined ? ownerSet : normalizeOwnerSetV7(ownerSet);
  const seenSlots = new Set();
  const seenRequestIds = new Set();
  const approvals = [];
  const verified = [];
  for (const [i, pair] of pairs.entries()) {
    if (!isPlainObject(pair) || !isPlainObject(pair.request) || !isPlainObject(pair.response)) {
      throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `pairs[${i}] must be { request, response }`);
    }
    if (pair.request.manifestHash !== pairs[0].request.manifestHash) {
      throw invalidResponse(SLOT_REFUSALS.MANIFEST_HASH_MISMATCH, `pairs[${i}] was collected for a different manifest — one collection round covers exactly one transaction`);
    }
    if (seenRequestIds.has(pair.request.requestId)) {
      throw invalidResponse(SLOT_REFUSALS.RESPONSE_REPLAYED, `pairs[${i}] reuses request ${pair.request.requestId}`);
    }
    seenRequestIds.add(pair.request.requestId);
    const v = verifyRootSlotSignatureResponse({ request: pair.request, response: pair.response, ownerSet: set, nowMs, verifySlotSignature });
    if (seenSlots.has(v.slot)) {
      throw invalidResponse(SLOT_REFUSALS.DUPLICATE_SLOT, `slot ${v.slot} was collected twice — one slot, one signature`);
    }
    seenSlots.add(v.slot);
    approvals.push({ slot: v.slot, publicKey: v.publicKey, signatureHex: v.signatureHex });
    verified.push(v);
  }

  let blob;
  try {
    blob = assembleOwnerSigsBlobV7({ ownerSet: set, actionName, approvals, requireQuorum });
  } catch (e) {
    /* the assembler's codes are the covenant's own rules; surface them
     * verbatim behind the interface's closed error vocabulary */
    throw invalidResponse(e.code === "UNDER_QUORUM" ? "UNDER_QUORUM" : e.code || SLOT_REFUSALS.RESPONSE_INVALID, e.message, { code: e.code ?? null });
  }
  return deepFreeze({
    approvals,
    verified,
    blobHex: blob.blobHex,
    signedSlots: blob.signedSlots,
    requiredApprovals: blob.requiredApprovals.toString(),
    satisfiedApprovals: blob.satisfiedApprovals.toString(),
    actionName: blob.actionName
  });
}

/* ------------------------------------------------------------------ */
/* driving an external signer                                          */
/* ------------------------------------------------------------------ */

/*
 * Drive ONE slot request through a validated USI v1 adapter — a CLI keyfile
 * signer, an air-gapped shuttle, a hardware device, a browser extension, an
 * HSM. Every fail-closed gate of executeSigning applies first (capability,
 * scheme, declared AND live network, identity before and after approval,
 * bounded asynchronous approval), then this module re-checks the frozen-byte
 * structure and builds the bound response envelope.
 */
async function requestRootSlotSignature({ adapter, request, timeoutMs, onTransition, nowMs = Date.now(), signerAddress }) {
  assertRootSlotSigningRequest(request);
  assertNotExpired(request, nowMs);

  /*
   * THE SLOT-KEY GATE. executeSigning binds the transport identity (the
   * ADDRESS the adapter reports as active, before and after approval); the
   * covenant binds the KEY. Those are two different identities, and this
   * module owns no address codec to relate them — so when the adapter offers
   * getPublicKey(), its CLAIMED key is compared to the slot's key and a
   * mismatch refuses BEFORE the signer is ever asked to sign. This is what
   * stops a request that was (wrongly) issued to a non-owner's address from
   * producing a real signature that then has to be caught downstream.
   *
   * An adapter that offers no key claim (getPublicKey absent, or returning
   * null) cannot be gated here: the binding then rests entirely on the
   * covenant's own per-slot checkSig, and the returned response records
   * `slotKeyClaimChecked: false` so nothing downstream can mistake an
   * unchecked claim for a checked one.
   *
   * TRUST BOUNDARY of that flag: it is LOCAL PROVENANCE recorded by the
   * runtime that actually drove the adapter, not a verified claim about the
   * response. A response that crossed an air gap could carry any value, so
   * `verifyRootSlotSignatureResponse` deliberately NEVER reads it and never
   * lets it influence a decision — it computes its own `signatureVerified`
   * from the optional injected verifier instead. Display it as provenance;
   * never treat it as proof.
   */
  let slotKeyClaimChecked = false;
  if (typeof adapter === "object" && adapter !== null && typeof adapter.getPublicKey === "function") {
    let claimed = null;
    try {
      claimed = await adapter.getPublicKey();
    } catch {
      claimed = null; /* a provider that cannot report a key is not gated here */
    }
    if (claimed !== null && claimed !== undefined) {
      const xOnly = normalizePublicKeyToXOnly(claimed, "signer getPublicKey()");
      if (xOnly !== request.slot.publicKey) {
        throw refuse(
          SignerErrorCodes.ACCOUNT_CHANGED,
          SLOT_REFUSALS.SLOT_NOT_HELD,
          `the signer reports public key ${xOnly}, but slot ${request.slot.number} of this organization's owner set is ${request.slot.publicKey} — refusing to ask it for a signature that could never count`
        );
      }
      slotKeyClaimChecked = true;
    }
  }

  const options = {};
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  if (onTransition !== undefined) options.onTransition = onTransition;
  const outcome = await executeSigning(adapter, request.signerRequest, options);
  const response = buildRootSlotSignatureResponse({
    request,
    signedSafeJson: outcome.result.signedSafeJson,
    signerAddress: signerAddress ?? request.expectedSignerAddress,
    signedAtMs: Date.now()
  });
  return deepFreeze({ ...response, slotKeyClaimChecked });
}

/* ==================================================================== */
/* policyvault-org-root-slot-request/2 — additive, parallel to v1 above  */
/* ==================================================================== */

/* Structural re-validation of a v2 slot request (defense in depth — never
 * trusted by marker). Recomputes the outer payloadSha256 AND delegates to
 * the embedded USI v2 request's OWN validator, which recomputes ITS
 * payloadSha256 independently from the SAME unsignedSafeJson. */
function assertRootSlotSigningRequestV2(request) {
  if (!isPlainObject(request)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "a v2 slot signing request object is required");
  if (request.requestVersion !== ORG_ROOT_SLOT_REQUEST_VERSION_2) {
    throw refuse(
      v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.REQUEST_INVALID,
      `slot request declares version ${JSON.stringify(request.requestVersion)}; this v2 path implements exactly ${JSON.stringify(ORG_ROOT_SLOT_REQUEST_VERSION_2)} — failing closed`
    );
  }
  const extraKeys = Object.keys(request).filter((k) => !SLOT_REQUEST_V2_KEYS.includes(k));
  if (extraKeys.length > 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `slot request carries unknown key(s) ${JSON.stringify(extraKeys)} — refusing (closed envelope)`);
  for (const key of SLOT_REQUEST_V2_KEYS) {
    if (!(key in request)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `slot request is missing required key ${JSON.stringify(key)}`);
  }
  if (request.interfaceVersion !== v2.SIGNER_INTERFACE_VERSION_V2) {
    throw refuse(
      v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.REQUEST_INVALID,
      `slot request declares interface version ${JSON.stringify(request.interfaceVersion)}; expected exactly ${JSON.stringify(v2.SIGNER_INTERFACE_VERSION_V2)}`
    );
  }
  if (typeof request.requestId !== "string" || !/^[0-9a-f]{32}$/.test(request.requestId)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "requestId must be 32-hex");
  if (typeof request.nonce !== "string" || !/^[0-9a-f]{64}$/.test(request.nonce)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "nonce must be 64-hex (32 CSPRNG bytes)");
  assertHex64(request.manifestHash, "manifestHash");
  assertHex64(request.txId, "txId");
  if (!isPlainObject(request.slot)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "slot is required");
  assertHex64(request.slot.publicKey, "slot.publicKey");
  if (!SIGNER_NETWORKS.includes(request.network)) throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `unknown network ${JSON.stringify(request.network)}`);
  if (!Number.isInteger(request.slot.number) || request.slot.number < 1 || request.slot.number > OWNER_SLOTS_V7) throw invalidRequest(SLOT_REFUSALS.SLOT_OUT_OF_RANGE, "slot.number out of range");
  if (request.slot.index !== request.slot.number - 1) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "slot.index must be slot.number - 1");
  assertIntegerMs(request.createdAtMs, "createdAtMs");
  assertIntegerMs(request.expiresAtMs, "expiresAtMs");
  if (request.expiresAtMs <= request.createdAtMs) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expiresAtMs must be after createdAtMs");
  if (request.expiryIsCoordinationOnly !== true) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expiryIsCoordinationOnly must be true — the deadline is a collection-round deadline, never a consensus expiry");
  }
  if (typeof request.unsignedSafeJson !== "string" || !request.unsignedSafeJson) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "unsignedSafeJson is required");
  if (!isPlainObject(request.root) || !isPlainObject(request.root.outpoint)) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "root.outpoint is required");
  assertHex64(request.root.covenantId, "root.covenantId");
  assertHex64(request.root.outpoint.transactionId, "root.outpoint.transactionId");
  if (!Number.isInteger(request.root.outpoint.index) || request.root.outpoint.index < 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "root.outpoint.index must be a non-negative integer");
  if (!Number.isInteger(request.root.inputIndex) || request.root.inputIndex < 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "root.inputIndex is required");
  assertDecimalString(request.root.stateNonce, "root.stateNonce");

  /* the outer digest re-binds unsignedSafeJson + manifestHash + slot +
   * root outpoint + nonce — a request whose digest no longer matches its
   * own fields was altered after creation and is refused BEFORE any
   * signer is invoked. */
  const expectedDigest = computeSlotRequestDigestV2({
    unsignedSafeJson: request.unsignedSafeJson,
    manifestHash: request.manifestHash,
    slotNumber: request.slot.number,
    rootOutpoint: request.root.outpoint,
    nonce: request.nonce
  });
  if (request.payloadSha256 !== expectedDigest) {
    throw refuseV2(
      v2.SignerErrorCodesV2.PAYLOAD_MUTATED,
      SLOT_REFUSALS.SLOT_REQUEST_DIGEST_MISMATCH,
      "the slot request's payloadSha256 does not match its own fields (unsigned transaction + manifest hash + slot + root outpoint + nonce) — the request was altered after creation; refusing before the signer is invoked"
    );
  }

  if (!isPlainObject(request.signerRequest) || request.signerRequest.kind !== "sign-transaction") {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "signerRequest must be the USI v2 sign-transaction request");
  }
  /* defense in depth: the embedded v2 USI request re-validates ITSELF
   * (interface version, requestId/nonce shape, expiry ordering, its own
   * payloadSha256 recomputed from the SAME unsignedSafeJson, canonical
   * sign-inputs, transaction format, sighash.all) through the shared v2
   * core — never re-implemented here. */
  v2.assertSigningRequestV2(request.signerRequest);
  if (request.signerRequest.requestId !== request.requestId || request.signerRequest.nonce !== request.nonce) {
    throw refuseV2(
      v2.SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH,
      SLOT_REFUSALS.NONCE_MISMATCH,
      "the org-root-slot request envelope is not bound to its own embedded USI request — refusing"
    );
  }
  if (request.signerRequest.unsignedSafeJson !== request.unsignedSafeJson) {
    throw refuseV2(
      v2.SignerErrorCodesV2.PAYLOAD_MUTATED,
      SLOT_REFUSALS.SLOT_REQUEST_DIGEST_MISMATCH,
      "the embedded USI request carries different transaction bytes than the org-root-slot envelope — refusing"
    );
  }
  if (request.signerRequest.expectedSignerAddress !== request.expectedSignerAddress) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "the embedded USI request names a different expected signer than the envelope");
  }
  return request;
}

/*
 * Build ONE owner's v2 slot signing request from a VERIFIED org-root
 * manifest. Same contract as v1's `createRootSlotSigningRequest` (the
 * manifest is re-verified here, never trusted by marker; every binding
 * fact the v1 request carries is carried here too), PLUS the v2-only
 * additions documented at the top of this section: a CSPRNG nonce, an
 * explicit v2 USI request (`signerRequest`, pinned to SIGHASH_ALL and
 * kaspa-safe-json/1), the wide `payloadSha256` digest, the predecessor
 * root STATE nonce (for the domain-level replay guard), and the frozen
 * `requiredCapabilities` a caller can show a human before issuing the
 * request.
 */
function createRootSlotSigningRequestV2({
  manifest,
  descriptors = {},
  redeemScripts = {}, // Codex checkpoint 6 (UX-02 / UX-13): the vault's predecessor redeem script(s) the verifier rebuilds the successor from
  slot,
  expectedSignerAddress,
  unsignedSafeJson,
  rootInputIndex,
  expiresAtMs,
  nowMs = Date.now()
} = {}) {
  if (!isPlainObject(manifest) || !ACCEPTED_ROOT_MANIFEST_FAMILIES.includes(manifest.manifestVersion)) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `a ${ACCEPTED_ROOT_MANIFEST_FAMILIES.join(" or ")} manifest is required — failing closed (no default route)`);
  }
  const verification = verifyRootManifestByFamily({ manifest, descriptors, redeemScripts });
  if (verification.verdict !== "VERIFIED") {
    throw invalidRequest(
      SLOT_REFUSALS.MANIFEST_NOT_VERIFIED,
      `the manifest does not verify against the transaction it describes — refusing to ask an owner to sign it (failing checks: ${verification.failures.map((f) => f.name).join(", ")})`
    );
  }
  if (manifest.action.name === "succession") {
    throw invalidRequest(
      SLOT_REFUSALS.SUCCESSION_TAKES_NO_SLOTS,
      "a succession is authorized by the pinned successor key through its own entrypoint, not by an owner slot blob — there is no slot to request"
    );
  }

  const network = manifest.network.networkId;
  if (!SIGNER_NETWORKS.includes(network)) {
    throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `the manifest names network ${JSON.stringify(network)}, which this signer interface version does not express — failing closed`);
  }

  const slotNumber = Number(slot);
  if (!Number.isInteger(slotNumber) || slotNumber < 1 || slotNumber > OWNER_SLOTS_V7) {
    throw invalidRequest(SLOT_REFUSALS.SLOT_OUT_OF_RANGE, `slot must be an integer 1..${OWNER_SLOTS_V7}`);
  }
  const expected = manifest.action.expectedSignerSlots.find((s) => Number(s.slot) === slotNumber);
  if (!expected) {
    throw invalidRequest(
      SLOT_REFUSALS.SLOT_INACTIVE,
      `slot ${slotNumber} is not one of the ${manifest.action.expectedSignerSlots.length} active owner slot(s) this action expects — an inactive slot is never inspected by the covenant and can never count`
    );
  }
  if (expected.publicKey === INACTIVE_SLOT_KEY) {
    throw invalidRequest(SLOT_REFUSALS.SLOT_INACTIVE, `slot ${slotNumber} holds the sentinel-zero key`);
  }

  if (typeof expectedSignerAddress !== "string" || !expectedSignerAddress.trim()) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expectedSignerAddress is required — a slot signature is only accepted from the identity it was requested from");
  }
  if (typeof unsignedSafeJson !== "string" || !unsignedSafeJson) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "unsignedSafeJson (the FROZEN transaction serialization) is required");
  }
  if (!Number.isInteger(rootInputIndex) || rootInputIndex < 0) {
    throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "rootInputIndex (the index of the root covenant input) is required");
  }

  assertIntegerMs(nowMs, "nowMs");
  const deadline = assertIntegerMs(expiresAtMs, "expiresAtMs");
  if (deadline <= nowMs) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "expiresAtMs must be in the future");
  if (deadline - nowMs > MAX_REQUEST_LIFETIME_MS) {
    throw invalidRequest(
      SLOT_REFUSALS.REQUEST_INVALID,
      `expiresAtMs is more than ${MAX_REQUEST_LIFETIME_MS} ms ahead — a collection round that long should be re-issued against a fresh root state rather than left open`
    );
  }

  /* the underlying USI v2 request: exactly ONE input, SIGHASH_ALL only,
   * pinned to kaspa-safe-json/1, with its own CSPRNG nonce and an
   * explicit ttlMs (every v2 request expires). */
  const signerRequest = v2.createTransactionSigningRequestV2({
    unsignedSafeJson,
    signInputs: [{ index: rootInputIndex, sighashType: SIGHASH_ALL }],
    network,
    expectedSignerAddress,
    scheme: "schnorr",
    transactionFormat: v2.TRANSACTION_FORMATS[0],
    ttlMs: deadline - nowMs,
    nowMs
  });

  const rootOutpoint = { transactionId: manifest.root.outpoint.transactionId, index: Number(manifest.root.outpoint.index) };
  const rootStateNonce = assertDecimalString(manifest.rootState.before.state.rootNonce, "manifest.rootState.before.state.rootNonce");
  const payloadSha256 = computeSlotRequestDigestV2({
    unsignedSafeJson,
    manifestHash: manifest.manifestHash,
    slotNumber,
    rootOutpoint,
    nonce: signerRequest.nonce
  });

  return deepFreeze({
    requestVersion: ORG_ROOT_SLOT_REQUEST_VERSION_2,
    interfaceVersion: v2.SIGNER_INTERFACE_VERSION_V2,
    requestId: signerRequest.requestId,
    nonce: signerRequest.nonce,
    createdAtMs: nowMs,
    expiresAtMs: deadline,
    expiryIsCoordinationOnly: true,
    network,
    manifestHash: assertHex64(manifest.manifestHash, "manifest.manifestHash"),
    txId: assertHex64(manifest.transaction.txId, "manifest.transaction.txId"),
    root: {
      covenantId: assertHex64(manifest.root.covenantId, "manifest.root.covenantId"),
      outpoint: rootOutpoint,
      inputIndex: rootInputIndex,
      stateNonce: rootStateNonce
    },
    slot: { number: slotNumber, index: slotNumber - 1, publicKey: expected.publicKey },
    action: {
      name: manifest.action.name,
      authorityClass: manifest.action.authorityClass,
      requiredApprovals: manifest.action.requiredApprovals,
      quorumSource: manifest.action.quorumSource
    },
    expectedSignerAddress: expectedSignerAddress.trim(),
    unsignedSafeJson,
    payloadSha256,
    requiredCapabilities: {
      schemes: [...v2.POLICYVAULT_TRANSACTION_REQUIREMENTS.schemes],
      features: [...v2.POLICYVAULT_TRANSACTION_REQUIREMENTS.features],
      sighash: [...v2.POLICYVAULT_TRANSACTION_REQUIREMENTS.sighash],
      transactionFormat: v2.POLICYVAULT_TRANSACTION_REQUIREMENTS.transactionFormat
    },
    signerRequest
  });
}

/*
 * v2 counterpart of `extractSlotSignatureFromSignedTransaction`. The
 * frozen-byte structural proof (TXID drift / foreign-input attribution /
 * the 0x01 SIGHASH_ALL gate) is IDENTICAL logic to the v1 function; it is
 * a separate function only because the v1 function hard-validates its
 * input through `assertRootSlotSigningRequest` (the v1 assert), and the
 * v1 path must stay byte-identical and untouched — this is the same body
 * validated through `assertRootSlotSigningRequestV2` instead.
 */
function extractSlotSignatureFromSignedTransactionV2({ request, signedSafeJson }) {
  assertRootSlotSigningRequestV2(request);
  if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "the signer returned no signed transaction serialization");
  }
  let signed;
  let unsigned;
  try {
    signed = JSON.parse(signedSafeJson);
    unsigned = JSON.parse(request.unsignedSafeJson);
  } catch (e) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, `the signed serialization is not JSON: ${e.message}`);
  }
  if (!isPlainObject(signed) || !Array.isArray(signed.inputs) || signed.inputs.length !== unsigned.inputs.length) {
    throw invalidResponse(SLOT_REFUSALS.TXID_DRIFT, "the signed serialization does not have the same input set as the frozen transaction");
  }
  const idx = request.root.inputIndex;
  if (idx >= signed.inputs.length) throw invalidResponse(SLOT_REFUSALS.ROOT_INPUT_MISMATCH, `root input index ${idx} is out of range for a transaction with ${signed.inputs.length} input(s)`);

  const strippedSigned = JSON.parse(signedSafeJson);
  const strippedUnsigned = JSON.parse(request.unsignedSafeJson);
  const returnedScript = String(strippedSigned.inputs[idx].signatureScript ?? "");
  if (Object.prototype.hasOwnProperty.call(strippedUnsigned.inputs[idx], "signatureScript")) {
    strippedSigned.inputs[idx].signatureScript = strippedUnsigned.inputs[idx].signatureScript;
  } else {
    delete strippedSigned.inputs[idx].signatureScript;
  }
  if (JSON.stringify(strippedSigned) !== JSON.stringify(strippedUnsigned)) {
    for (let i = 0; i < signed.inputs.length; i += 1) {
      if (i === idx) continue;
      if (String(signed.inputs[i].signatureScript ?? "") !== String(unsigned.inputs[i].signatureScript ?? "")) {
        throw invalidResponse(
          SLOT_REFUSALS.FOREIGN_INPUT_SIGNED,
          `the signer altered input ${i}, which this request did not ask it to sign — refusing the whole response`
        );
      }
    }
    throw invalidResponse(
      SLOT_REFUSALS.TXID_DRIFT,
      "the signer returned different transaction bytes than the frozen ones it was handed — a slot signature over a different transaction can never be accepted"
    );
  }

  let signatureHex;
  try {
    signatureHex = normalizeSlotSignatureHex(returnedScript, `slot ${request.slot.number} signature`);
  } catch (e) {
    const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : e.code === "PLACEHOLDER_AS_SIGNATURE" ? SLOT_REFUSALS.SIGNATURE_INVALID : SLOT_REFUSALS.SIGNATURE_INVALID;
    throw invalidResponse(reason, e.message, { code: e.code ?? null });
  }
  return signatureHex;
}

/*
 * Build the v2 response envelope for ONE slot. Bound like the v1 response
 * (every fact the request carried is re-stated) PLUS the v2-only nonce
 * echo and the PROVENANCE fields `capabilitiesProbed` / `txIdVerified` /
 * `provider` / `transport`, copied verbatim from the `executeSigningV2`
 * outcome that produced this response (never re-derived here — this
 * module holds no cryptography and no capability logic of its own).
 */
function buildRootSlotSignatureResponseV2({
  request,
  signedSafeJson,
  signatureHex,
  signerAddress,
  signedAtMs = Date.now(),
  capabilitiesProbed = false,
  txIdVerified = false,
  provider = null,
  transport = null
}) {
  assertRootSlotSigningRequestV2(request);
  const haveSigned = signedSafeJson !== undefined && signedSafeJson !== null;
  const haveRaw = signatureHex !== undefined && signatureHex !== null;
  if (haveSigned === haveRaw) {
    throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "exactly one of signedSafeJson or signatureHex must be supplied");
  }
  let sig;
  if (haveSigned) {
    sig = extractSlotSignatureFromSignedTransactionV2({ request, signedSafeJson });
  } else {
    try {
      sig = normalizeSlotSignatureHex(signatureHex, `slot ${request.slot.number} signature`);
    } catch (e) {
      const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : SLOT_REFUSALS.SIGNATURE_INVALID;
      throw invalidResponse(reason, e.message, { code: e.code ?? null });
    }
  }
  assertIntegerMs(signedAtMs, "signedAtMs");
  if (typeof capabilitiesProbed !== "boolean") throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "capabilitiesProbed must be a boolean");
  if (typeof txIdVerified !== "boolean") throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "txIdVerified must be a boolean");
  return deepFreeze({
    responseVersion: ORG_ROOT_SLOT_RESPONSE_VERSION_2,
    requestVersion: request.requestVersion,
    requestId: request.requestId,
    nonce: request.nonce,
    network: request.network,
    manifestHash: request.manifestHash,
    txId: request.txId,
    root: { covenantId: request.root.covenantId, outpoint: { ...request.root.outpoint }, inputIndex: request.root.inputIndex },
    slot: { number: request.slot.number, index: request.slot.index, publicKey: request.slot.publicKey },
    signerAddress: typeof signerAddress === "string" && signerAddress.trim() ? signerAddress.trim() : request.expectedSignerAddress,
    signatureHex: sig,
    sighashType: SIGHASH_ALL,
    signedAtMs,
    capabilitiesProbed,
    txIdVerified,
    provider: provider === null || provider === undefined ? null : String(provider),
    transport: transport === null || transport === undefined ? null : String(transport)
  });
}

/*
 * Verify ONE v2 response against the request it claims to answer. Every
 * binding the v1 verifier checks is checked here too, PLUS: the response's
 * OWN requestVersion (a v1 envelope presented on this path is refused with
 * INTERFACE_VERSION_UNSUPPORTED, not silently accepted) and its nonce
 * (RESPONSE_BINDING_MISMATCH otherwise — v1 responses were bare of a
 * nonce, so this is a strictly wider check than v1 could express).
 */
function verifyRootSlotSignatureResponseV2({ request, response, ownerSet = null, nowMs = Date.now(), verifySlotSignature = null }) {
  assertRootSlotSigningRequestV2(request);
  if (!isPlainObject(response)) throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, "a slot response object is required");
  if (response.responseVersion !== ORG_ROOT_SLOT_RESPONSE_VERSION_2) {
    throw refuse(
      v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.RESPONSE_INVALID,
      `slot response declares version ${JSON.stringify(response.responseVersion)}; this v2 path implements exactly ${JSON.stringify(ORG_ROOT_SLOT_RESPONSE_VERSION_2)} — failing closed`
    );
  }
  const extraKeys = Object.keys(response).filter((k) => !SLOT_RESPONSE_V2_KEYS.includes(k));
  if (extraKeys.length > 0) throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, `slot response carries unknown key(s) ${JSON.stringify(extraKeys)} — refusing (closed envelope)`);
  for (const key of SLOT_RESPONSE_V2_KEYS) {
    if (!(key in response)) throw invalidResponse(SLOT_REFUSALS.RESPONSE_INVALID, `slot response is missing required key ${JSON.stringify(key)}`);
  }
  assertNotExpired(request, nowMs);

  if (response.requestVersion !== request.requestVersion) {
    throw refuse(
      v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.RESPONSE_INVALID,
      `the response answers a ${JSON.stringify(response.requestVersion)} request; this request is ${JSON.stringify(request.requestVersion)} — refusing`
    );
  }
  if (response.requestId !== request.requestId) {
    throw invalidResponse(
      SLOT_REFUSALS.RESPONSE_REPLAYED,
      `this response answers request ${response.requestId}, not ${request.requestId} — a signature collected for one request is never accepted for another`
    );
  }
  if (response.nonce !== request.nonce) {
    throw refuseV2(
      v2.SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH,
      SLOT_REFUSALS.NONCE_MISMATCH,
      "the response's nonce does not match the request it claims to answer — v2 responses are bound envelopes; refusing"
    );
  }
  if (response.network !== request.network) throw refuse(SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK, `response network ${JSON.stringify(response.network)} != request network ${JSON.stringify(request.network)}`);
  if (response.manifestHash !== request.manifestHash) throw invalidResponse(SLOT_REFUSALS.MANIFEST_HASH_MISMATCH, "the response describes a different manifest than the one this request was issued for");
  if (response.txId !== request.txId) throw invalidResponse(SLOT_REFUSALS.TXID_DRIFT, "the response names a different transaction id than the frozen one");
  if (!isPlainObject(response.root) || response.root.covenantId !== request.root.covenantId) throw invalidResponse(SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH, "the response names a different root covenant");
  if (!sameOutpoint(response.root.outpoint, request.root.outpoint)) {
    throw invalidResponse(
      SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH,
      "the response names a different root outpoint — the root outpoint IS the freshness kill switch and is never allowed to drift"
    );
  }
  if (!isPlainObject(response.slot) || Number(response.slot.number) !== request.slot.number) throw invalidResponse(SLOT_REFUSALS.SLOT_NOT_HELD, `the response claims slot ${response.slot && response.slot.number}, but this request is for slot ${request.slot.number}`);
  if (response.slot.publicKey !== request.slot.publicKey) throw invalidResponse(SLOT_REFUSALS.SLOT_KEY_MISMATCH, "the response declares a different key for this slot than the manifest's owner set does");
  if (response.signerAddress !== request.expectedSignerAddress) {
    throw refuse(SignerErrorCodes.ACCOUNT_CHANGED, SLOT_REFUSALS.SIGNER_IDENTITY_MISMATCH, "the response was produced by a different signer identity than the request was issued to");
  }
  if (response.sighashType !== SIGHASH_ALL) throw invalidResponse(SLOT_REFUSALS.SIGHASH_NOT_ALL, `the response declares sighash type ${JSON.stringify(response.sighashType)}; the root covenant gates every counted slot on SIGHASH_ALL (0x01)`);

  let signatureHex;
  try {
    signatureHex = normalizeSlotSignatureHex(response.signatureHex, `slot ${request.slot.number} signature`);
  } catch (e) {
    const reason = e.code === "SIGHASH_NOT_ALL" ? SLOT_REFUSALS.SIGHASH_NOT_ALL : SLOT_REFUSALS.SIGNATURE_INVALID;
    throw invalidResponse(reason, e.message, { code: e.code ?? null });
  }
  if (signatureHex.length !== SIG_SLOT_LEN_V7 * 2) throw invalidResponse(SLOT_REFUSALS.SIGNATURE_INVALID, `a slot signature must be exactly ${SIG_SLOT_LEN_V7} bytes`);

  if (ownerSet !== null) {
    const set = ownerSet.activeCount !== undefined ? ownerSet : normalizeOwnerSetV7(ownerSet);
    if (request.slot.index >= set.activeCount) {
      throw invalidResponse(SLOT_REFUSALS.SLOT_INACTIVE, `slot ${request.slot.number} is inactive in the predecessor owner set — inactive slots are never inspected by the covenant`);
    }
    if (set.owners[request.slot.index] !== request.slot.publicKey) {
      throw invalidResponse(
        SLOT_REFUSALS.SLOT_NOT_HELD,
        `slot ${request.slot.number} of the predecessor set holds a different key — refusing to place this signature under a key the covenant will not check it against`
      );
    }
  }

  let signatureVerified = false;
  if (verifySlotSignature !== null) {
    if (typeof verifySlotSignature !== "function") throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "verifySlotSignature, when supplied, must be a function");
    let ok;
    try {
      ok = verifySlotSignature({ publicKey: request.slot.publicKey, signatureHex, unsignedSafeJson: request.unsignedSafeJson, inputIndex: request.root.inputIndex });
    } catch (e) {
      throw invalidResponse(SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED, `the injected slot-signature verifier failed: ${e.message}`);
    }
    if (ok !== true) {
      throw invalidResponse(SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED, `the slot signature does not verify under the slot's public key ${request.slot.publicKey}`);
    }
    signatureVerified = true;
  }

  return deepFreeze({
    slot: request.slot.number,
    index: request.slot.index,
    publicKey: request.slot.publicKey,
    signatureHex,
    signerAddress: response.signerAddress,
    signatureVerified,
    capabilitiesProbed: response.capabilitiesProbed === true,
    txIdVerified: response.txIdVerified === true,
    cryptographicBinding: signatureVerified
      ? "verified locally by the injected verifier AND enforced in-VM by the root covenant's per-slot checkSig"
      : "enforced in-VM by the root covenant's per-slot checkSig (no local verifier was injected)"
  });
}

/*
 * Fold verified v2 slot responses into the 780-byte blob. Identical
 * contract to v1's `collectRootSlotApprovals`; the quorum, duplicate-slot,
 * signature-reuse, inactive-slot and SIGHASH_ALL rules are NOT
 * re-implemented — `assembleOwnerSigsBlobV7` is the SAME pinned assembler
 * the v1 path and the covenant agree with, so a v2-collected blob is
 * byte-identical to a v1-collected one for the same approvals.
 */
function collectRootSlotApprovalsV2({ ownerSet, actionName, pairs, nowMs = Date.now(), requireQuorum = true, verifySlotSignature = null }) {
  if (!Array.isArray(pairs) || pairs.length === 0) throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, "pairs must be a non-empty array of { request, response }");
  const set = ownerSet && ownerSet.activeCount !== undefined ? ownerSet : normalizeOwnerSetV7(ownerSet);
  const seenSlots = new Set();
  const seenRequestIds = new Set();
  const approvals = [];
  const verified = [];
  for (const [i, pair] of pairs.entries()) {
    if (!isPlainObject(pair) || !isPlainObject(pair.request) || !isPlainObject(pair.response)) {
      throw invalidRequest(SLOT_REFUSALS.REQUEST_INVALID, `pairs[${i}] must be { request, response }`);
    }
    if (pair.request.manifestHash !== pairs[0].request.manifestHash) {
      throw invalidResponse(SLOT_REFUSALS.MANIFEST_HASH_MISMATCH, `pairs[${i}] was collected for a different manifest — one collection round covers exactly one transaction`);
    }
    if (seenRequestIds.has(pair.request.requestId)) {
      throw invalidResponse(SLOT_REFUSALS.RESPONSE_REPLAYED, `pairs[${i}] reuses request ${pair.request.requestId}`);
    }
    seenRequestIds.add(pair.request.requestId);
    const v = verifyRootSlotSignatureResponseV2({ request: pair.request, response: pair.response, ownerSet: set, nowMs, verifySlotSignature });
    if (seenSlots.has(v.slot)) {
      throw invalidResponse(SLOT_REFUSALS.DUPLICATE_SLOT, `slot ${v.slot} was collected twice — one slot, one signature`);
    }
    seenSlots.add(v.slot);
    approvals.push({ slot: v.slot, publicKey: v.publicKey, signatureHex: v.signatureHex });
    verified.push(v);
  }

  let blob;
  try {
    blob = assembleOwnerSigsBlobV7({ ownerSet: set, actionName, approvals, requireQuorum });
  } catch (e) {
    throw invalidResponse(e.code === "UNDER_QUORUM" ? "UNDER_QUORUM" : e.code || SLOT_REFUSALS.RESPONSE_INVALID, e.message, { code: e.code ?? null });
  }
  return deepFreeze({
    approvals,
    verified,
    blobHex: blob.blobHex,
    signedSlots: blob.signedSlots,
    requiredApprovals: blob.requiredApprovals.toString(),
    satisfiedApprovals: blob.satisfiedApprovals.toString(),
    actionName: blob.actionName
  });
}

/*
 * A SEPARATE, coarser replay guard than v2's own per-call requestId/nonce
 * guard (which `executeSigningV2` already runs internally on every
 * invocation — see `core/signer/v2/interface.js`'s `createReplayGuard`).
 * This one is keyed on (root covenant id, root STATE nonce, request id,
 * slot): it exists to catch a CALLER issuing two overlapping requests for
 * the SAME slot of the SAME root generation, which the per-call guard
 * cannot see because each request legitimately mints its own fresh
 * requestId/nonce. Session-scoped, in-memory, single-use per (root,
 * stateNonce, slot) — a caller that wants this protection across process
 * restarts persists it durably itself (this module holds no storage).
 */
function createOrgRootSlotReplayGuardV2() {
  const openKeys = new Map(); /* "covenantId|stateNonce|slot" -> requestId */
  const settled = new Set(); /* requestIds already consumed */
  const keyOf = (request) => `${request.root.covenantId}|${request.root.stateNonce}|${request.slot.number}`;

  return Object.freeze({
    open(request) {
      if (settled.has(request.requestId)) {
        throw refuseV2(v2.SignerErrorCodesV2.DUPLICATE_SETTLEMENT, SLOT_REFUSALS.DUPLICATE_SLOT_REQUEST, `slot request ${request.requestId} already reached a terminal state — refusing to re-open it`);
      }
      const key = keyOf(request);
      const holder = openKeys.get(key);
      if (holder !== undefined && holder !== request.requestId) {
        throw refuseV2(
          v2.SignerErrorCodesV2.REPLAY_DETECTED,
          SLOT_REFUSALS.DUPLICATE_SLOT_REQUEST,
          `a signing request is already open for slot ${request.slot.number} of root ${request.root.covenantId} at root state nonce ${request.root.stateNonce} — one open request per (root, state nonce, slot)`
        );
      }
      openKeys.set(key, request.requestId);
      return true;
    },
    consume(request) {
      if (settled.has(request.requestId)) {
        throw refuseV2(v2.SignerErrorCodesV2.DUPLICATE_SETTLEMENT, SLOT_REFUSALS.DUPLICATE_SLOT_REQUEST, `a settlement for slot request ${request.requestId} was already accepted — refusing the duplicate`);
      }
      settled.add(request.requestId);
      openKeys.delete(keyOf(request));
      return true;
    },
    isSettled(requestId) {
      return settled.has(requestId);
    }
  });
}

/*
 * Drive ONE v2 slot request through a validated USI v2 adapter — a mock
 * signer, the CLI keyfile signer (real kaspa-wasm BIP-340 Schnorr), an
 * air-gap shuttle, or a browser extension lifted onto v2. Every fail-closed
 * gate of `executeSigningV2` applies first (capability PROBE vs
 * declaration, scheme, sighash, transaction format, transport, user
 * presence, bounded async deadline, declared AND live network, identity
 * before and after approval), then this module re-checks the frozen-byte
 * structure and builds the bound v2 response envelope.
 *
 * `requireUserPresence` defaults to `true`: an organizational owner's
 * counted signature is expected to come from a human at the signer. The
 * override is real and tested (the CLI keyfile adapter declares
 * `userPresence: "not-required"` because running the process IS the
 * approval — v2 spec §8), never silently defaulted away.
 *
 * `requireProbedCapabilities` defaults to `true` for the same reason: a
 * signer this module cannot interrogate before the shuttle is refused
 * unless the caller explicitly accepts an honest `probed: false` (the
 * air-gap shuttle's documented limitation).
 */
async function requestRootSlotSignatureV2({
  adapter,
  request,
  timeoutMs,
  onTransition,
  nowMs = Date.now(),
  signerAddress,
  deriveTransactionId,
  requireUserPresence = true,
  requireProbedCapabilities = true,
  allowedTransports,
  cancellation,
  replayGuard
} = {}) {
  assertRootSlotSigningRequestV2(request);
  assertNotExpired(request, nowMs);

  /* THE SLOT-KEY GATE — identical rationale to the v1 path's own comment
   * above: executeSigningV2 binds the transport ADDRESS the adapter
   * reports as active; the covenant binds the KEY. When the adapter offers
   * getPublicKey(), its CLAIMED key is compared to the slot's key BEFORE
   * the signer is ever asked to sign. */
  let slotKeyClaimChecked = false;
  if (typeof adapter === "object" && adapter !== null && typeof adapter.getPublicKey === "function") {
    let claimed = null;
    try {
      claimed = await adapter.getPublicKey();
    } catch {
      claimed = null; /* a provider that cannot report a key is not gated here */
    }
    if (claimed !== null && claimed !== undefined) {
      const xOnly = normalizePublicKeyToXOnly(claimed, "signer getPublicKey()");
      if (xOnly !== request.slot.publicKey) {
        throw refuse(
          SignerErrorCodes.ACCOUNT_CHANGED,
          SLOT_REFUSALS.SLOT_NOT_HELD,
          `the signer reports public key ${xOnly}, but slot ${request.slot.number} of this organization's owner set is ${request.slot.publicKey} — refusing to ask it for a signature that could never count`
        );
      }
      slotKeyClaimChecked = true;
    }
  }

  const options = { requireUserPresence, requireProbedCapabilities };
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  if (onTransition !== undefined) options.onTransition = onTransition;
  if (deriveTransactionId !== undefined) options.deriveTransactionId = deriveTransactionId;
  if (allowedTransports !== undefined) options.allowedTransports = allowedTransports;
  if (cancellation !== undefined) options.cancellation = cancellation;
  if (replayGuard !== undefined) options.replayGuard = replayGuard;
  if (Number.isInteger(nowMs)) options.nowMs = nowMs;

  const outcome = await v2.executeSigningV2(adapter, request.signerRequest, options);
  const response = buildRootSlotSignatureResponseV2({
    request,
    signedSafeJson: outcome.result.signedSafeJson,
    signerAddress: signerAddress ?? request.expectedSignerAddress,
    signedAtMs: Date.now(),
    capabilitiesProbed: outcome.capabilitiesProbed === true,
    txIdVerified: outcome.txIdVerified === true,
    provider: outcome.provider ?? null,
    transport: outcome.transport ?? null
  });
  return deepFreeze({ ...response, slotKeyClaimChecked });
}

module.exports = {
  ORG_ROOT_SLOT_REQUEST_VERSION_1,
  ORG_ROOT_SLOT_RESPONSE_VERSION_1,
  SLOT_REFUSALS,
  MAX_REQUEST_LIFETIME_MS,
  createRootSlotSigningRequest,
  assertRootSlotSigningRequest,
  assertNotExpired,
  extractSlotSignatureFromSignedTransaction,
  buildRootSlotSignatureResponse,
  verifyRootSlotSignatureResponse,
  collectRootSlotApprovals,
  requestRootSlotSignature,

  /* v2 (additive; the v1 exports above are byte-identical and untouched) */
  ORG_ROOT_SLOT_REQUEST_VERSION_2,
  ORG_ROOT_SLOT_RESPONSE_VERSION_2,
  SLOT_REQUEST_V2_KEYS,
  SLOT_RESPONSE_V2_KEYS,
  computeSlotRequestDigestV2,
  createRootSlotSigningRequestV2,
  assertRootSlotSigningRequestV2,
  extractSlotSignatureFromSignedTransactionV2,
  buildRootSlotSignatureResponseV2,
  verifyRootSlotSignatureResponseV2,
  collectRootSlotApprovalsV2,
  createOrgRootSlotReplayGuardV2,
  requestRootSlotSignatureV2
};
