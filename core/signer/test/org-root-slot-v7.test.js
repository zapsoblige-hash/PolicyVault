"use strict";

/*
 * UNIT + ADVERSARIAL: the v0.7 ORGANIZATIONAL ROOT external-signer SLOT path
 * (core/signer/org-root-slot-v7.js).
 *
 * The fixtures are REAL v0.7 org-root builds captured from the production SDK
 * (sdk/tools/capture-v7-manifests.js, deterministic TEST-ONLY keys), so the
 * request envelopes below are bound to real frozen transactions.
 *
 * The HOSTILE MATRIX this file exists for — each row must REFUSE with the
 * named reason BEFORE any signature reaches the covenant:
 *   wrong network (declared and live) · wrong slot key · a slot the signer
 *   does not hold · an inactive slot · duplicate slot · a slot signature over
 *   a DIFFERENT transaction (txid drift) · a signer that touched a foreign
 *   input · a non-ALL sighash gate byte · a stale request (deadline elapsed) ·
 *   a response replayed into another request · a response from a different
 *   signer identity · the abstention placeholder offered as a signature ·
 *   under-quorum finalize · a manifest that does not verify · succession
 *   (which takes no owner slots at all).
 *
 * The cryptographic slot<->key binding is the covenant's per-slot checkSig
 * (proven on the real engine by tests/vm/tests/v7_sdk_integration.rs and, with
 * REAL Schnorr signatures through the offline CLI keyfile signer, by
 * core/signer/adapters/cli/test/org-root-slot.test.js). This suite proves the
 * ENVELOPE: every binding a collection round can get wrong, refused by name.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const slotPath = require("../org-root-slot-v7");
const {
  ORG_ROOT_SLOT_REQUEST_VERSION_1,
  ORG_ROOT_SLOT_RESPONSE_VERSION_1,
  SLOT_REFUSALS,
  MAX_REQUEST_LIFETIME_MS,
  createRootSlotSigningRequest,
  extractSlotSignatureFromSignedTransaction,
  buildRootSlotSignatureResponse,
  verifyRootSlotSignatureResponse,
  collectRootSlotApprovals,
  requestRootSlotSignature
} = slotPath;
const { SignerErrorCodes } = require("../errors");
const { SIG_BLOB_LEN_V7, PLACEHOLDER_SLOT_HEX_V7 } = require("../../model/owner-set-v7");
const { computeManifestHashV1 } = require("../../intent/canonical");

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "v7-org-root-slot.json"), "utf8"));
const OWNER_SET = fixture.ownerSet;
const ADDRESSES = fixture.ownerAddresses;
const ROOT_INPUT = fixture.rootInputIndex;
const NOW = 1_700_000_000_000;
const SOON = NOW + 60 * 60 * 1000;

/* A 65-byte slot: 64 signature bytes + the 0x01 SIGHASH_ALL gate byte. These
 * are STRUCTURAL fixtures, not cryptographic signatures — the covenant's own
 * checkSig is what makes a slot count, and the real-Schnorr proof lives in the
 * CLI adapter suite and the production-byte vectors. */
const slotSig = (b) => b.toString(16).padStart(2, "0").repeat(64) + "01";

function makeRequest(slot, over = {}) {
  return createRootSlotSigningRequest({
    manifest: fixture.primary.manifest,
    slot,
    expectedSignerAddress: ADDRESSES[slot - 1],
    unsignedSafeJson: fixture.primary.unsignedSafeJson,
    rootInputIndex: ROOT_INPUT,
    expiresAtMs: SOON,
    nowMs: NOW,
    ...over
  });
}

/* A signer that behaves EXACTLY like the offline CLI adapter: it writes the
 * raw createInputSignature output (a 0x41 push of the 65-byte slot) into the
 * one input it was asked to sign and returns the whole serialization. */
function signOneInput(unsignedSafeJson, index, sigHex, extra = null) {
  const j = JSON.parse(unsignedSafeJson);
  j.inputs[index].signatureScript = `41${sigHex}`;
  if (typeof extra === "function") extra(j);
  return JSON.stringify(j);
}

function respond(request, sigHex, over = {}) {
  return {
    ...buildRootSlotSignatureResponse({
      request,
      signedSafeJson: signOneInput(request.unsignedSafeJson, request.root.inputIndex, sigHex),
      signedAtMs: NOW + 1000
    }),
    ...over
  };
}

function refusal(fn) {
  try {
    fn();
  } catch (e) {
    return e;
  }
  return null;
}

async function asyncRefusal(fn) {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  return null;
}

/* A minimal fully-conformant USI v1 adapter that really signs one input. */
function createSlotTestAdapter({ address, network = "testnet-10", sigHex = slotSig(0xab), mutate = null } = {}) {
  return {
    describe() {
      return {
        interfaceVersion: "policyvault-signer/1",
        provider: "slot-test",
        label: "Slot test signer",
        kind: "cli",
        schemes: ["schnorr"],
        networks: [network],
        features: {
          messageSigning: false,
          transactionSigning: true,
          specificInputSigning: true,
          multiAccount: false,
          networkSwitching: false,
          accountEvents: false,
          asynchronousApproval: false,
          airGapped: false,
          hardwareDisplay: false
        }
      };
    },
    async detect() {
      return true;
    },
    async connect() {
      return { address };
    },
    async disconnect() {
      return undefined;
    },
    async getActiveAccount() {
      return { address };
    },
    async getPublicKey() {
      return null;
    },
    async getNetwork() {
      return network;
    },
    async signTransaction(request) {
      return signOneInput(request.unsignedSafeJson, request.signInputs[0].index, sigHex, mutate);
    }
  };
}

/* ------------------------------------------------------------------ */

test("slot path: a request binds the manifest hash, slot, root outpoint, network, signer and deadline", () => {
  const req = makeRequest(1);
  assert.equal(req.requestVersion, ORG_ROOT_SLOT_REQUEST_VERSION_1);
  assert.equal(req.interfaceVersion, "policyvault-signer/1");
  assert.equal(req.manifestHash, fixture.primary.manifest.manifestHash);
  assert.equal(req.txId, fixture.primary.manifest.transaction.txId);
  assert.equal(req.network, fixture.primary.manifest.network.networkId);
  assert.deepEqual(req.root.outpoint, { transactionId: fixture.primary.manifest.root.outpoint.transactionId, index: Number(fixture.primary.manifest.root.outpoint.index) });
  assert.equal(req.root.covenantId, fixture.primary.manifest.root.covenantId);
  assert.equal(req.slot.number, 1);
  assert.equal(req.slot.index, 0);
  assert.equal(req.slot.publicKey, OWNER_SET.owners[0]);
  assert.equal(req.expectedSignerAddress, ADDRESSES[0]);
  assert.equal(req.expiresAtMs, SOON);
  assert.equal(req.expiryIsCoordinationOnly, true, "the deadline is a collection-round deadline, NEVER a consensus expiry");
  assert.equal(req.action.name, "authorize");
  assert.equal(req.action.requiredApprovals, "2");

  /* the underlying USI v1 request signs EXACTLY one input, SIGHASH_ALL only */
  assert.equal(req.signerRequest.kind, "sign-transaction");
  assert.deepEqual(req.signerRequest.signInputs, [{ index: ROOT_INPUT, sighashType: 1 }]);
  assert.equal(req.signerRequest.network, req.network);
  assert.equal(req.signerRequest.expectedSignerAddress, ADDRESSES[0]);
  assert.equal(req.signerRequest.scheme, "schnorr");
});

test("slot path: HAPPY PATH — one signature per owner folds into the 780-byte blob", () => {
  const r1 = makeRequest(1);
  const r2 = makeRequest(2);
  const p1 = { request: r1, response: respond(r1, slotSig(0x11)) };
  const p2 = { request: r2, response: respond(r2, slotSig(0x22)) };

  const one = verifyRootSlotSignatureResponse({ request: r1, response: p1.response, ownerSet: OWNER_SET, nowMs: NOW + 2000 });
  assert.equal(one.slot, 1);
  assert.equal(one.publicKey, OWNER_SET.owners[0]);
  assert.equal(one.signatureHex, slotSig(0x11));
  assert.equal(one.signatureVerified, false);
  assert.match(one.cryptographicBinding, /enforced in-VM by the root covenant's per-slot checkSig/);

  const collected = collectRootSlotApprovals({ ownerSet: OWNER_SET, actionName: "authorize", pairs: [p1, p2], nowMs: NOW + 2000 });
  assert.equal(collected.blobHex.length, SIG_BLOB_LEN_V7 * 2, "the blob is always exactly 780 bytes");
  assert.deepEqual([...collected.signedSlots], [1, 2]);
  assert.equal(collected.requiredApprovals, "2");
  assert.equal(collected.satisfiedApprovals, "2");
  /* abstaining slots carry the canonical placeholder, so the byte shape — and
   * therefore the exact-fee freeze — is constant for every threshold */
  assert.equal(collected.blobHex.slice(2 * 65 * 2, 3 * 65 * 2), PLACEHOLDER_SLOT_HEX_V7);
  assert.equal(collected.blobHex.slice(0, 130), slotSig(0x11));
});

test("slot path: an OPTIONAL injected verifier binds the signature to the slot key, and its refusal is fatal", () => {
  const r1 = makeRequest(1);
  const response = respond(r1, slotSig(0x11));
  const seen = [];
  const ok = verifyRootSlotSignatureResponse({
    request: r1,
    response,
    ownerSet: OWNER_SET,
    nowMs: NOW + 1,
    verifySlotSignature: (args) => {
      seen.push(args);
      return true;
    }
  });
  assert.equal(ok.signatureVerified, true);
  assert.match(ok.cryptographicBinding, /verified locally by the injected verifier AND enforced in-VM/);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].publicKey, OWNER_SET.owners[0]);
  assert.equal(seen[0].inputIndex, ROOT_INPUT);
  assert.equal(seen[0].signatureHex, slotSig(0x11));

  const bad = refusal(() => verifyRootSlotSignatureResponse({ request: r1, response, ownerSet: OWNER_SET, nowMs: NOW + 1, verifySlotSignature: () => false }));
  assert.equal(bad.signerCode, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  assert.equal(bad.details.reason, SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED);

  const threw = refusal(() =>
    verifyRootSlotSignatureResponse({
      request: r1,
      response,
      ownerSet: OWNER_SET,
      nowMs: NOW + 1,
      verifySlotSignature: () => {
        throw new Error("verifier exploded");
      }
    })
  );
  assert.equal(threw.details.reason, SLOT_REFUSALS.SIGNATURE_NOT_VERIFIED, "a verifier that throws is never treated as a pass");
});

test("slot path HOSTILE: every binding a collection round can get wrong is REFUSED by name", () => {
  const r1 = makeRequest(1);
  const r2 = makeRequest(2);
  const good = respond(r1, slotSig(0x11));

  const rows = [
    [
      "WRONG NETWORK — the response names a different network",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, network: "mainnet" }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.WRONG_NETWORK,
      SLOT_REFUSALS.WRONG_NETWORK
    ],
    [
      "WRONG SLOT KEY — the response declares a key the manifest's set does not hold in that slot",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, slot: { ...good.slot, publicKey: "ee".repeat(32) } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SLOT_KEY_MISMATCH
    ],
    [
      "A SIGNER CLAIMING A SLOT IT DOES NOT HOLD — the response answers with another slot number",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, slot: { number: 2, index: 1, publicKey: OWNER_SET.owners[1] } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SLOT_NOT_HELD
    ],
    [
      "A SIGNER CLAIMING A SLOT IT DOES NOT HOLD — the predecessor set holds a different key in that slot",
      () =>
        verifyRootSlotSignatureResponse({
          request: r1,
          response: good,
          ownerSet: { ...OWNER_SET, owners: OWNER_SET.owners.map((k, i) => (i === 0 ? "9a".repeat(32) : k)) },
          nowMs: NOW + 1
        }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SLOT_NOT_HELD
    ],
    [
      "AN INACTIVE SLOT — slot 3 answered against a set whose third slot was removed",
      () => {
        const r3 = makeRequest(3);
        return verifyRootSlotSignatureResponse({
          request: r3,
          response: respond(r3, slotSig(0x33)),
          ownerSet: { ...OWNER_SET, owners: OWNER_SET.owners.map((k, i) => (i < 2 ? k : "00".repeat(32))), ownerM: 2, emergencyK: 1, recoveryM: 2 },
          nowMs: NOW + 1
        });
      },
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SLOT_INACTIVE
    ],
    [
      "TXID DRIFT — the response names a different transaction id",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, txId: "cc".repeat(32) }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.TXID_DRIFT
    ],
    [
      "A DIFFERENT MANIFEST",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, manifestHash: "dd".repeat(32) }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.MANIFEST_HASH_MISMATCH
    ],
    [
      "A DIFFERENT ROOT OUTPOINT — the freshness kill switch is never allowed to drift",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, root: { ...good.root, outpoint: { transactionId: "0e".repeat(32), index: 0 } } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH
    ],
    [
      "A RESPONSE REPLAYED INTO ANOTHER REQUEST",
      () => verifyRootSlotSignatureResponse({ request: r2, response: good, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.RESPONSE_REPLAYED
    ],
    [
      "A DIFFERENT SIGNER IDENTITY",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, signerAddress: ADDRESSES[2] }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.ACCOUNT_CHANGED,
      SLOT_REFUSALS.SIGNER_IDENTITY_MISMATCH
    ],
    [
      "A NON-ALL SIGHASH TYPE DECLARED",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, sighashType: 2 }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SIGHASH_NOT_ALL
    ],
    [
      "A NON-ALL SIGHASH GATE BYTE IN THE SIGNATURE ITSELF",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, signatureHex: `${slotSig(0x11).slice(0, -2)}02` }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SIGHASH_NOT_ALL
    ],
    [
      "THE ABSTENTION PLACEHOLDER OFFERED AS A SIGNATURE",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, signatureHex: PLACEHOLDER_SLOT_HEX_V7 }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INVALID_SIGNATURE_RESPONSE,
      SLOT_REFUSALS.SIGNATURE_INVALID
    ],
    [
      "A STALE REQUEST — the collection round's deadline elapsed",
      () => verifyRootSlotSignatureResponse({ request: r1, response: good, ownerSet: OWNER_SET, nowMs: SOON }),
      SignerErrorCodes.SIGNER_TIMEOUT,
      SLOT_REFUSALS.REQUEST_EXPIRED
    ],
    [
      "AN UNKNOWN RESPONSE VERSION",
      () => verifyRootSlotSignatureResponse({ request: r1, response: { ...good, responseVersion: "policyvault-org-root-slot-response/2" }, ownerSet: OWNER_SET, nowMs: NOW + 1 }),
      SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
      SLOT_REFUSALS.RESPONSE_INVALID
    ]
  ];

  let refused = 0;
  for (const [label, fn, expectedCode, expectedReason] of rows) {
    const e = refusal(fn);
    assert.ok(e, `${label}: must refuse`);
    if (expectedCode !== null) assert.equal(e.signerCode, expectedCode, `${label}: error code`);
    if (expectedReason !== null) assert.equal(e.details.reason, expectedReason, `${label}: got ${e.details && e.details.reason} — ${e.message}`);
    refused += 1;
  }
  assert.equal(refused, rows.length);
  console.log(`ORG-ROOT SLOT hostile rows refused: ${refused}`);
});

test("slot path HOSTILE: a slot signature over a DIFFERENT transaction, and a signer that touched a foreign input", () => {
  const r1 = makeRequest(1);

  /* the signer signed the OTHER organization transaction's bytes */
  const otherTxSigned = signOneInput(fixture.other.unsignedSafeJson, ROOT_INPUT, slotSig(0x11));
  const drift = refusal(() => extractSlotSignatureFromSignedTransaction({ request: r1, signedSafeJson: otherTxSigned }));
  assert.equal(drift.signerCode, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  assert.equal(drift.details.reason, SLOT_REFUSALS.TXID_DRIFT);

  /* the signer changed an output value while signing */
  const mutatedOutputs = signOneInput(r1.unsignedSafeJson, ROOT_INPUT, slotSig(0x11), (j) => {
    j.outputs[j.outputs.length - 1].value = (BigInt(j.outputs[j.outputs.length - 1].value) - 1n).toString();
  });
  const mutated = refusal(() => extractSlotSignatureFromSignedTransaction({ request: r1, signedSafeJson: mutatedOutputs }));
  assert.equal(mutated.details.reason, SLOT_REFUSALS.TXID_DRIFT);

  /* the signer also filled an input it was never asked to sign */
  const foreign = signOneInput(r1.unsignedSafeJson, ROOT_INPUT, slotSig(0x11), (j) => {
    j.inputs[1].signatureScript = `41${slotSig(0x99)}`;
  });
  const foreignErr = refusal(() => extractSlotSignatureFromSignedTransaction({ request: r1, signedSafeJson: foreign }));
  assert.equal(foreignErr.details.reason, SLOT_REFUSALS.FOREIGN_INPUT_SIGNED);
  assert.match(foreignErr.message, /altered input 1/);

  /* nothing signed at all */
  const empty = refusal(() => extractSlotSignatureFromSignedTransaction({ request: r1, signedSafeJson: r1.unsignedSafeJson }));
  assert.equal(empty.details.reason, SLOT_REFUSALS.SIGNATURE_INVALID);

  /* not JSON */
  const garbage = refusal(() => extractSlotSignatureFromSignedTransaction({ request: r1, signedSafeJson: "not json" }));
  assert.equal(garbage.details.reason, SLOT_REFUSALS.RESPONSE_INVALID);
});

test("slot path HOSTILE: a duplicate slot, a cross-manifest pair and an UNDER-QUORUM finalize are all refused", () => {
  const r1 = makeRequest(1);
  const r1b = makeRequest(1);
  const r2 = makeRequest(2);

  const dup = refusal(() =>
    collectRootSlotApprovals({
      ownerSet: OWNER_SET,
      actionName: "authorize",
      pairs: [
        { request: r1, response: respond(r1, slotSig(0x11)) },
        { request: r1b, response: respond(r1b, slotSig(0x33)) }
      ],
      nowMs: NOW + 1
    })
  );
  assert.equal(dup.details.reason, SLOT_REFUSALS.DUPLICATE_SLOT);

  const replayed = refusal(() =>
    collectRootSlotApprovals({
      ownerSet: OWNER_SET,
      actionName: "authorize",
      pairs: [
        { request: r1, response: respond(r1, slotSig(0x11)) },
        { request: r1, response: respond(r1, slotSig(0x11)) }
      ],
      nowMs: NOW + 1
    })
  );
  assert.equal(replayed.details.reason, SLOT_REFUSALS.RESPONSE_REPLAYED);

  /* one signature short of the 2-of-3 quorum: the PINNED core assembler
   * refuses, so no under-quorum transaction is ever finalized */
  const under = refusal(() => collectRootSlotApprovals({ ownerSet: OWNER_SET, actionName: "authorize", pairs: [{ request: r1, response: respond(r1, slotSig(0x11)) }], nowMs: NOW + 1 }));
  assert.equal(under.signerCode, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  assert.equal(under.details.reason, "UNDER_QUORUM");
  assert.equal(under.details.code, "UNDER_QUORUM");

  /* the EMERGENCY quorum needs only 1 — the same single approval succeeds for
   * the lighter action and fails for the full one, which is the whole point */
  const emergency = collectRootSlotApprovals({ ownerSet: OWNER_SET, actionName: "freeze", pairs: [{ request: r1, response: respond(r1, slotSig(0x11)) }], nowMs: NOW + 1 });
  assert.equal(emergency.requiredApprovals, "1");
  assert.equal(emergency.satisfiedApprovals, "1");

  /* two owners who signed DIFFERENT transactions cannot be folded together */
  const otherReq = createRootSlotSigningRequest({
    manifest: fixture.other.manifest,
    slot: 2,
    expectedSignerAddress: ADDRESSES[1],
    unsignedSafeJson: fixture.other.unsignedSafeJson,
    rootInputIndex: ROOT_INPUT,
    expiresAtMs: SOON,
    nowMs: NOW
  });
  const cross = refusal(() =>
    collectRootSlotApprovals({
      ownerSet: OWNER_SET,
      actionName: "authorize",
      pairs: [
        { request: r1, response: respond(r1, slotSig(0x11)) },
        { request: otherReq, response: respond(otherReq, slotSig(0x22)) }
      ],
      nowMs: NOW + 1
    })
  );
  assert.equal(cross.details.reason, SLOT_REFUSALS.MANIFEST_HASH_MISMATCH);
  void r2;
});

test("slot path HOSTILE: a request is never issued for a manifest that does not verify, an unknown version, or a succession", () => {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(fixture.primary.manifest));
  void manifestHash;
  body.action.requiredApprovals = "1";
  const tampered = { ...body, manifestHash: computeManifestHashV1(body) };
  const bad = refusal(() => createRootSlotSigningRequest({ manifest: tampered, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.primary.unsignedSafeJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(bad.signerCode, SignerErrorCodes.REQUEST_INVALID);
  assert.equal(bad.details.reason, SLOT_REFUSALS.MANIFEST_NOT_VERIFIED);
  assert.match(bad.message, /requiredApprovals/);

  const unknown = refusal(() => createRootSlotSigningRequest({ manifest: { ...fixture.primary.manifest, manifestVersion: "policyvault-org-root-manifest/2" }, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.primary.unsignedSafeJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(unknown.details.reason, SLOT_REFUSALS.REQUEST_INVALID);

  const succession = refusal(() => createRootSlotSigningRequest({ manifest: fixture.succession.manifest, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.succession.manifest.transaction.frozenCanonicalJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(succession.details.reason, SLOT_REFUSALS.SUCCESSION_TAKES_NO_SLOTS);

  const inactive = refusal(() => makeRequest(5));
  assert.equal(inactive.details.reason, SLOT_REFUSALS.SLOT_INACTIVE);
  const outOfRange = refusal(() => makeRequest(13));
  assert.equal(outOfRange.details.reason, SLOT_REFUSALS.SLOT_OUT_OF_RANGE);

  const expired = refusal(() => makeRequest(1, { expiresAtMs: NOW - 1 }));
  assert.equal(expired.signerCode, SignerErrorCodes.REQUEST_INVALID);
  const tooLong = refusal(() => makeRequest(1, { expiresAtMs: NOW + MAX_REQUEST_LIFETIME_MS + 1 }));
  assert.match(tooLong.message, /re-issued against a fresh root state/);

  const noAddress = refusal(() => makeRequest(1, { expectedSignerAddress: "" }));
  assert.match(noAddress.message, /expectedSignerAddress is required/);
});

test("slot path: an AIR-GAP round trip through JSON preserves every binding", () => {
  const req = makeRequest(1);
  /* the request carries no functions and no ambient state */
  const shuttledRequest = JSON.parse(JSON.stringify(req));
  assert.deepEqual(shuttledRequest, JSON.parse(JSON.stringify(req)));

  const signedOffline = signOneInput(shuttledRequest.unsignedSafeJson, shuttledRequest.root.inputIndex, slotSig(0x11));
  const response = buildRootSlotSignatureResponse({ request: shuttledRequest, signedSafeJson: signedOffline, signedAtMs: NOW + 5000 });
  const shuttledResponse = JSON.parse(JSON.stringify(response));

  const verified = verifyRootSlotSignatureResponse({ request: req, response: shuttledResponse, ownerSet: OWNER_SET, nowMs: NOW + 6000 });
  assert.equal(verified.slot, 1);
  assert.equal(verified.signatureHex, slotSig(0x11));
  assert.equal(shuttledResponse.responseVersion, ORG_ROOT_SLOT_RESPONSE_VERSION_1);

  /* a device that returns ONLY the 65-byte signature is equally supported */
  const rawOnly = buildRootSlotSignatureResponse({ request: req, signatureHex: slotSig(0x11), signedAtMs: NOW + 5000 });
  assert.equal(rawOnly.signatureHex, slotSig(0x11));
  const both = refusal(() => buildRootSlotSignatureResponse({ request: req, signatureHex: slotSig(0x11), signedSafeJson: signedOffline }));
  assert.match(both.message, /exactly one of signedSafeJson or signatureHex/);
  const neither = refusal(() => buildRootSlotSignatureResponse({ request: req }));
  assert.match(neither.message, /exactly one of signedSafeJson or signatureHex/);
});

test("slot path: driving a real USI v1 adapter — approval, and the LIVE network + identity gates", async () => {
  const req = makeRequest(1);
  const adapter = createSlotTestAdapter({ address: ADDRESSES[0], sigHex: slotSig(0x11) });
  const states = [];
  const response = await requestRootSlotSignature({ adapter, request: req, nowMs: NOW, onTransition: (t) => states.push(t.state) });
  assert.deepEqual(states, ["SUBMITTED", "APPROVED"]);
  const verified = verifyRootSlotSignatureResponse({ request: req, response, ownerSet: OWNER_SET, nowMs: NOW + 1 });
  assert.equal(verified.signatureHex, slotSig(0x11));
  assert.equal(verified.signerAddress, ADDRESSES[0]);

  /* WRONG NETWORK at the LIVE adapter: the signer is on mainnet, the request
   * is for the manifest's network — refused before any prompt */
  const wrongNetwork = await asyncRefusal(() => requestRootSlotSignature({ adapter: createSlotTestAdapter({ address: ADDRESSES[0], network: "mainnet" }), request: req, nowMs: NOW }));
  assert.equal(wrongNetwork.signerCode, SignerErrorCodes.WRONG_NETWORK);

  /* the WRONG OWNER's signer answering another owner's request */
  const wrongIdentity = await asyncRefusal(() => requestRootSlotSignature({ adapter: createSlotTestAdapter({ address: ADDRESSES[2] }), request: req, nowMs: NOW }));
  assert.equal(wrongIdentity.signerCode, SignerErrorCodes.ACCOUNT_CHANGED);

  /* a signer that quietly edits the transaction while signing */
  const drifting = createSlotTestAdapter({
    address: ADDRESSES[0],
    mutate: (j) => {
      j.outputs[0].value = (BigInt(j.outputs[0].value) - 1n).toString();
    }
  });
  const drift = await asyncRefusal(() => requestRootSlotSignature({ adapter: drifting, request: req, nowMs: NOW }));
  assert.equal(drift.details.reason, SLOT_REFUSALS.TXID_DRIFT);

  /* a stale request never reaches the signer at all */
  const stale = await asyncRefusal(() => requestRootSlotSignature({ adapter, request: req, nowMs: SOON + 1 }));
  assert.equal(stale.signerCode, SignerErrorCodes.SIGNER_TIMEOUT);
  assert.equal(stale.details.reason, SLOT_REFUSALS.REQUEST_EXPIRED);
});

test("slot path: STRUCTURAL NON-CUSTODY — no request or response field can carry key material", () => {
  const req = makeRequest(1);
  const res = respond(req, slotSig(0x11));
  const forbidden = /(privateKey|secret|seed|mnemonic|passphrase|wallet ?backup)/i;
  for (const key of Object.keys(req)) assert.doesNotMatch(key, forbidden, `request field ${key}`);
  for (const key of Object.keys(res)) assert.doesNotMatch(key, forbidden, `response field ${key}`);
  assert.doesNotMatch(JSON.stringify(req), forbidden);
  assert.doesNotMatch(JSON.stringify(res), forbidden);

  /* the module itself never names key material either */
  /* comments are stripped first so the module's own prose about NOT touching
   * key material cannot trip (or hide) the scan */
  const source = fs.readFileSync(path.join(__dirname, "..", "org-root-slot-v7.js"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  assert.doesNotMatch(code, /privateKey|mnemonic|seedPhrase|walletBackup/i, "the slot path never touches key material");

  /* every refusal code this module can emit is in the CLOSED v1 vocabulary */
  const used = [...source.matchAll(/SignerErrorCodes\.([A-Z_]+)/g)].map((m) => m[1]);
  assert.ok(used.length > 0);
  for (const code of used) assert.ok(Object.prototype.hasOwnProperty.call(SignerErrorCodes, code), `${code} must be part of the closed v1 error vocabulary`);
});
