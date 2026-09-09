"use strict";

/*
 * ADVERSARIAL: the v0.7 ORGANIZATIONAL ROOT external-signer SLOT path,
 * carried over Universal Signer Interface v2
 * (`core/signer/org-root-slot-v7.js`'s `policyvault-org-root-slot-request/2`
 * additions). Mirrors the coverage discipline of
 * `core/signer/test/org-root-slot-v7.test.js` (the v1 hostile suite, left
 * byte-identical and unexercised by this file's imports) but adds every
 * binding v2 introduces: the wide request digest, the response nonce echo,
 * capability PROBING before a request is issued, user presence, transport,
 * and the closed request/response envelopes.
 *
 * Fixtures are the SAME real v0.7 org-root captures the v1 suite uses
 * (`core/signer/test/fixtures/v7-org-root-slot.json`, captured from the
 * production SDK with deterministic TEST-ONLY keys) — the request/response
 * envelopes below are bound to real frozen transactions.
 *
 * In every pre-invocation adapter-level case this suite additionally
 * asserts `control.invocations === 0`: no prompt may open for a request
 * that cannot be accepted (mirrors hostile-v2.test.js's own discipline).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const slotPath = require("../org-root-slot-v7");
const {
  ORG_ROOT_SLOT_REQUEST_VERSION_1,
  ORG_ROOT_SLOT_RESPONSE_VERSION_1,
  ORG_ROOT_SLOT_REQUEST_VERSION_2,
  ORG_ROOT_SLOT_RESPONSE_VERSION_2,
  SLOT_REFUSALS,
  MAX_REQUEST_LIFETIME_MS,
  createRootSlotSigningRequest,
  buildRootSlotSignatureResponse,
  verifyRootSlotSignatureResponse,
  createRootSlotSigningRequestV2,
  assertRootSlotSigningRequestV2,
  extractSlotSignatureFromSignedTransactionV2,
  buildRootSlotSignatureResponseV2,
  verifyRootSlotSignatureResponseV2,
  collectRootSlotApprovalsV2,
  createOrgRootSlotReplayGuardV2,
  requestRootSlotSignatureV2
} = slotPath;
const { SignerErrorCodes } = require("../errors");
const v2 = require("../v2");
const { SIG_BLOB_LEN_V7, PLACEHOLDER_SLOT_HEX_V7 } = require("../../model/owner-set-v7");
const { computeManifestHashV1 } = require("../../intent/canonical");

const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "v7-org-root-slot.json"), "utf8"));
const OWNER_SET = fixture.ownerSet;
const ADDRESSES = fixture.ownerAddresses;
const ROOT_INPUT = fixture.rootInputIndex;
const NOW = 1_700_000_000_000;
const SOON = NOW + 60 * 60 * 1000;

const slotSig = (b) => b.toString(16).padStart(2, "0").repeat(64) + "01";

function makeRequestV2(slot, over = {}) {
  return createRootSlotSigningRequestV2({
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

function signOneInput(unsignedSafeJson, index, sigHex, extra = null) {
  const j = JSON.parse(unsignedSafeJson);
  j.inputs[index].signatureScript = `41${sigHex}`;
  if (typeof extra === "function") extra(j);
  return JSON.stringify(j);
}

function respondV2(request, sigHex, over = {}) {
  return {
    ...buildRootSlotSignatureResponseV2({
      request,
      signedSafeJson: signOneInput(request.unsignedSafeJson, request.root.inputIndex, sigHex),
      signedAtMs: NOW + 1000,
      capabilitiesProbed: true,
      txIdVerified: false,
      provider: "test-fixture",
      transport: "in-page"
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

/* A fully-conformant mock v2 adapter that really "signs" one input by
 * writing the requested slot signature into the frozen transaction's
 * signature-script slot, with every descriptor/probe/behaviour knob a
 * hostile row needs to flip. */
function createMockV2({
  address = ADDRESSES[0],
  publicKey = null,
  network = fixture.primary.manifest.network.networkId,
  sigHex = slotSig(0x11),
  mutate = null,
  probe = undefined,
  sighash = undefined,
  userPresence = "required",
  transport = "in-page",
  cancellation = "unsupported",
  maxTimeoutMs = 600000,
  mutateEnvelope = null,
  asyncApproval = false
} = {}) {
  const adapter = v2.createMockSignerAdapterV2({
    provider: "mockv2test",
    accounts: [{ address, publicKey: publicKey ?? `02${OWNER_SET.owners[0]}` }],
    networks: [network],
    userPresence,
    transport,
    cancellation,
    maxTimeoutMs,
    asyncApproval,
    ...(sighash ? { sighash } : {}),
    probe
  });
  adapter.control.signedPayloadFor = (request) => signOneInput(request.unsignedSafeJson, request.signInputs[0].index, sigHex, mutate);
  if (mutateEnvelope) adapter.control.mutateEnvelope = mutateEnvelope;
  return adapter;
}

/* ------------------------------------------------------------------ */

test("v2 slot path: a request binds the manifest hash, slot, root outpoint, network, signer, deadline AND a wide payload digest", () => {
  const req = makeRequestV2(1);
  assert.equal(req.requestVersion, ORG_ROOT_SLOT_REQUEST_VERSION_2);
  assert.equal(req.interfaceVersion, "policyvault-signer/2");
  assert.equal(req.manifestHash, fixture.primary.manifest.manifestHash);
  assert.equal(req.txId, fixture.primary.manifest.transaction.txId);
  assert.equal(req.network, fixture.primary.manifest.network.networkId);
  assert.equal(req.slot.number, 1);
  assert.equal(req.slot.publicKey, OWNER_SET.owners[0]);
  assert.equal(req.root.stateNonce, fixture.primary.manifest.rootState.before.state.rootNonce);
  assert.match(req.nonce, /^[0-9a-f]{64}$/);
  assert.match(req.requestId, /^[0-9a-f]{32}$/);
  assert.equal(req.payloadSha256.length, 64);
  assert.deepEqual(req.requiredCapabilities.sighash, ["all"]);
  assert.equal(req.requiredCapabilities.transactionFormat, "kaspa-safe-json/1");
  assert.equal(req.signerRequest.kind, "sign-transaction");
  assert.equal(req.signerRequest.requestId, req.requestId, "the outer envelope and the embedded USI request share ONE requestId");
  assert.equal(req.signerRequest.nonce, req.nonce);
});

test("v2 slot path: HAPPY PATH through a mock v2 adapter — probed, presence-checked, and folded into the 780-byte blob", async () => {
  const req = makeRequestV2(1);
  const adapter = createMockV2({ address: ADDRESSES[0], sigHex: slotSig(0x11) });
  const states = [];
  const full = await requestRootSlotSignatureV2({ adapter, request: req, nowMs: NOW, onTransition: (t) => states.push(t.state) });
  assert.deepEqual(states, ["SUBMITTED", "APPROVED"]);
  assert.equal(full.slotKeyClaimChecked, true);
  const { slotKeyClaimChecked, ...response } = full;
  void slotKeyClaimChecked;
  assert.equal(response.responseVersion, ORG_ROOT_SLOT_RESPONSE_VERSION_2);
  assert.equal(response.capabilitiesProbed, true);
  assert.equal(response.provider, "mockv2test");
  assert.equal(response.transport, "in-page");

  const shuttled = JSON.parse(JSON.stringify(response));
  const verified = verifyRootSlotSignatureResponseV2({ request: req, response: shuttled, ownerSet: OWNER_SET, nowMs: NOW + 1000 });
  assert.equal(verified.slot, 1);
  assert.equal(verified.signatureHex, slotSig(0x11));
  assert.equal(verified.capabilitiesProbed, true);

  const req2 = makeRequestV2(2);
  const adapter2 = createMockV2({ address: ADDRESSES[1], publicKey: `02${OWNER_SET.owners[1]}`, sigHex: slotSig(0x22) });
  const { slotKeyClaimChecked: c2, ...response2 } = await requestRootSlotSignatureV2({ adapter: adapter2, request: req2, nowMs: NOW });
  void c2;

  const collected = collectRootSlotApprovalsV2({
    ownerSet: OWNER_SET,
    actionName: "authorize",
    pairs: [
      { request: req, response },
      { request: req2, response: response2 }
    ],
    nowMs: NOW + 2000
  });
  assert.equal(collected.blobHex.length, SIG_BLOB_LEN_V7 * 2);
  assert.deepEqual([...collected.signedSlots], [1, 2]);
  assert.equal(collected.satisfiedApprovals, "2");
  assert.equal(collected.blobHex.slice(2 * 65 * 2, 3 * 65 * 2), PLACEHOLDER_SLOT_HEX_V7, "abstaining slots still carry the canonical placeholder — the exact byte shape is constant");
});

test("v2 slot path: driving the CLI-shaped adapter declaring userPresence not-required is honoured, not silently overridden", async () => {
  const req = makeRequestV2(1);
  const adapter = createMockV2({ address: ADDRESSES[0], sigHex: slotSig(0x11), userPresence: "not-required", cancellation: "unsupported" });
  const refusedByDefault = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter, request: req, nowMs: NOW }));
  assert.equal(refusedByDefault.signerCode, v2.SignerErrorCodesV2.USER_PRESENCE_REQUIRED, "the SAFE DEFAULT refuses an unattended signer for a counted owner slot");
  assert.equal(adapter.control.invocations, 0, "no prompt may open for a request the presence gate refuses");

  const { slotKeyClaimChecked, ...response } = await requestRootSlotSignatureV2({ adapter, request: req, nowMs: NOW, requireUserPresence: false });
  void slotKeyClaimChecked;
  assert.equal(response.signatureHex, slotSig(0x11), "an explicit, deliberate override is honoured — never a silent bypass");
});

test("v2 slot path: capability PROBE vs DECLARATION mismatches are refused before any signer invocation", async () => {
  const req = makeRequestV2(1);

  const sighashLies = createMockV2({
    address: ADDRESSES[0],
    probe: { interfaceVersion: "policyvault-signer/2", probed: true, methods: ["signTransaction", "getNetwork", "getActiveAccount", "getPublicKey"], sighash: { all: false, none: true, single: false, anyoneCanPay: false }, transactionFormats: ["kaspa-safe-json/1"], network: req.network }
  });
  const mismatch = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: sighashLies, request: req, nowMs: NOW }));
  assert.equal(mismatch.signerCode, v2.SignerErrorCodesV2.CAPABILITY_MISMATCH, "PROBE SAYS SIGHASH_NONE ONLY — the declared SIGHASH_ALL is refused as an over-declaration");
  assert.equal(sighashLies.control.invocations, 0);

  const formatLies = createMockV2({
    address: ADDRESSES[0],
    probe: { interfaceVersion: "policyvault-signer/2", probed: true, methods: ["signTransaction", "getNetwork", "getActiveAccount", "getPublicKey"], sighash: { all: true, none: false, single: false, anyoneCanPay: false }, transactionFormats: [], network: req.network }
  });
  const formatMismatch = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: formatLies, request: req, nowMs: NOW }));
  assert.equal(formatMismatch.signerCode, v2.SignerErrorCodesV2.CAPABILITY_MISMATCH, "the declared transaction format is refused when the probe shows none");

  /* an honestly UNPROBEABLE signer (the air-gap shuttle's own limitation)
   * is refused by the SAFE DEFAULT, and accepted only on an explicit
   * override */
  const unprobeable = createMockV2({ address: ADDRESSES[0], probe: null });
  const refusedUnprobed = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: unprobeable, request: req, nowMs: NOW }));
  assert.equal(refusedUnprobed.signerCode, v2.SignerErrorCodesV2.CAPABILITY_MISMATCH);
  const { slotKeyClaimChecked, ...accepted } = await requestRootSlotSignatureV2({ adapter: unprobeable, request: req, nowMs: NOW, requireProbedCapabilities: false });
  void slotKeyClaimChecked;
  assert.equal(accepted.capabilitiesProbed, false, "an honest probed:false is recorded, never fabricated as true");
});

test("v2 slot path: a mutated payload digest and a mutated envelope nonce are both caught by the USI v2 core BEFORE this module ever sees a signature", async () => {
  const req = makeRequestV2(1);

  const digestLiar = createMockV2({
    address: ADDRESSES[0],
    mutateEnvelope: (env) => ({ ...env, payloadSha256: "ee".repeat(32) })
  });
  const digestErr = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: digestLiar, request: req, nowMs: NOW }));
  assert.equal(digestErr.signerCode, v2.SignerErrorCodesV2.PAYLOAD_MUTATED, "MUTATED PAYLOAD AFTER PRESENCE — the signer's returned envelope digest does not match the verified bytes");

  const nonceLiar = createMockV2({
    address: ADDRESSES[0],
    mutateEnvelope: (env) => ({ ...env, nonce: "ab".repeat(32) })
  });
  const nonceErr = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: nonceLiar, request: req, nowMs: NOW }));
  assert.equal(nonceErr.signerCode, v2.SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, "REPLAYED ENVELOPE shape — a stale/foreign nonce in the returned envelope is refused, not silently accepted");
});

test("v2 slot path: TRANSPORT_UNSUPPORTED and the async deadline gate refuse before invocation", async () => {
  const req = makeRequestV2(1);
  const adapter = createMockV2({ address: ADDRESSES[0] });
  const transportRefused = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter, request: req, nowMs: NOW, allowedTransports: ["cli", "qr-airgap"] }));
  assert.equal(transportRefused.signerCode, v2.SignerErrorCodesV2.TRANSPORT_UNSUPPORTED);
  assert.equal(adapter.control.invocations, 0);

  const tinyMaxTimeout = createMockV2({ address: ADDRESSES[0], maxTimeoutMs: 5000 });
  const timeoutRefused = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: tinyMaxTimeout, request: req, nowMs: NOW, timeoutMs: 6000 }));
  assert.equal(timeoutRefused.signerCode, v2.SignerErrorCodesV2.REQUEST_INVALID, "a deadline above the signer's declared maxTimeoutMs is refused rather than waited out");
});

test("v2 slot path: CONSUMER CANCELLATION and REQUEST EXPIRY both fail closed and discard a late settlement", async () => {
  const req = makeRequestV2(1);
  const asyncAdapter = createMockV2({ address: ADDRESSES[0], cancellation: "supported", asyncApproval: true });
  const token = v2.createCancellationToken();
  const cancelPromise = requestRootSlotSignatureV2({ adapter: asyncAdapter, request: req, nowMs: NOW, timeoutMs: 60000, cancellation: token });
  token.cancel("owner withdrew");
  const cancelled = await asyncRefusal(() => cancelPromise);
  assert.equal(cancelled.signerCode, v2.SignerErrorCodesV2.REQUEST_CANCELLED);

  const stale = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: createMockV2({ address: ADDRESSES[0] }), request: req, nowMs: SOON + 1 }));
  assert.equal(stale.signerCode, SignerErrorCodes.SIGNER_TIMEOUT, "EXPIRED — the collection round's own deadline elapsed before the signer was ever invoked (this module's own pre-gate reuses v1's assertNotExpired verbatim)");
  assert.equal(stale.details.reason, SLOT_REFUSALS.REQUEST_EXPIRED);
});

test("v2 slot path: an OVERSIZED unsigned transaction and an oversized signer address are refused at request-creation time", () => {
  const huge = "x".repeat(1048577);
  const err = refusal(() =>
    createRootSlotSigningRequestV2({
      manifest: fixture.primary.manifest,
      slot: 1,
      expectedSignerAddress: ADDRESSES[0],
      unsignedSafeJson: huge,
      rootInputIndex: ROOT_INPUT,
      expiresAtMs: SOON,
      nowMs: NOW
    })
  );
  assert.equal(err.signerCode, v2.SignerErrorCodesV2.REQUEST_INVALID);

  const longAddress = `kaspatest:${"a".repeat(300)}`;
  const addrErr = refusal(() => makeRequestV2(1, { expectedSignerAddress: longAddress }));
  assert.equal(addrErr.signerCode, v2.SignerErrorCodesV2.REQUEST_INVALID);
});

test("v2 slot path: v1 envelopes are refused on the v2 path and v2 envelopes are refused on the v1 path (never silently accepted)", () => {
  const reqV1 = createRootSlotSigningRequest({
    manifest: fixture.primary.manifest,
    slot: 1,
    expectedSignerAddress: ADDRESSES[0],
    unsignedSafeJson: fixture.primary.unsignedSafeJson,
    rootInputIndex: ROOT_INPUT,
    expiresAtMs: SOON,
    nowMs: NOW
  });
  const responseV1 = buildRootSlotSignatureResponse({ request: reqV1, signedSafeJson: signOneInput(reqV1.unsignedSafeJson, reqV1.root.inputIndex, slotSig(0x11)), signedAtMs: NOW + 1000 });
  assert.equal(responseV1.responseVersion, ORG_ROOT_SLOT_RESPONSE_VERSION_1);

  const reqV2 = makeRequestV2(1);
  /* a v1 response fed to the v2 verifier: refused on responseVersion, not
   * silently treated as v2 */
  const v1OnV2 = refusal(() => verifyRootSlotSignatureResponseV2({ request: reqV2, response: responseV1, ownerSet: OWNER_SET, nowMs: NOW + 1 }));
  assert.equal(v1OnV2.signerCode, v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED);
  assert.equal(v1OnV2.details.reason, SLOT_REFUSALS.RESPONSE_INVALID);

  /* a v1 REQUEST fed to the v2 request validator */
  const v1ReqOnV2 = refusal(() => assertRootSlotSigningRequestV2(reqV1));
  assert.equal(v1ReqOnV2.signerCode, v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED);

  /* the mirror image: a v2 response fed to the v1 verifier */
  const responseV2 = { ...buildRootSlotSignatureResponseV2({ request: reqV2, signedSafeJson: signOneInput(reqV2.unsignedSafeJson, reqV2.root.inputIndex, slotSig(0x11)), signedAtMs: NOW + 1000 }) };
  const v2OnV1 = refusal(() => verifyRootSlotSignatureResponse({ request: reqV1, response: responseV2, ownerSet: OWNER_SET, nowMs: NOW + 1 }));
  assert.equal(v2OnV1.signerCode, SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED);
});

test("v2 slot path HOSTILE MATRIX: every binding a v2 collection round can get wrong is refused by name", () => {
  const r1 = makeRequestV2(1);
  const r2 = makeRequestV2(2);
  const good = respondV2(r1, slotSig(0x11));

  const rows = [
    ["FOREIGN SLOT KEY — the response declares a key the manifest's set does not hold in that slot", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, slot: { ...good.slot, publicKey: "ee".repeat(32) } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SLOT_KEY_MISMATCH],
    ["A SIGNER CLAIMING A SLOT IT DOES NOT HOLD — answers with another slot number", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, slot: { number: 2, index: 1, publicKey: OWNER_SET.owners[1] } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SLOT_NOT_HELD],
    ["A SIGNER CLAIMING A SLOT IT DOES NOT HOLD — predecessor set holds a different key", () => verifyRootSlotSignatureResponseV2({ request: r1, response: good, ownerSet: { ...OWNER_SET, owners: OWNER_SET.owners.map((k, i) => (i === 0 ? "9a".repeat(32) : k)) }, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SLOT_NOT_HELD],
    ["AN INACTIVE SLOT — slot 3 answered against a set whose third slot was removed", () => { const r3 = makeRequestV2(3); return verifyRootSlotSignatureResponseV2({ request: r3, response: respondV2(r3, slotSig(0x33)), ownerSet: { ...OWNER_SET, owners: OWNER_SET.owners.map((k, i) => (i < 2 ? k : "00".repeat(32))), ownerM: 2, emergencyK: 1, recoveryM: 2 }, nowMs: NOW + 1 }); }, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SLOT_INACTIVE],
    ["SIGNATURE FOR ANOTHER REQUEST — a valid response replayed against a different request", () => verifyRootSlotSignatureResponseV2({ request: r2, response: good, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.RESPONSE_REPLAYED],
    ["SIGNATURE FOR ANOTHER ROOT — a different root outpoint, the freshness kill switch, is never allowed to drift", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, root: { ...good.root, outpoint: { transactionId: "0e".repeat(32), index: 0 } } }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.ROOT_OUTPOINT_MISMATCH],
    ["SIGNATURE FOR ANOTHER ROOT (different manifest)", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, manifestHash: "dd".repeat(32) }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.MANIFEST_HASH_MISMATCH],
    ["SIGNATURE FOR ANOTHER NONCE — v2's own binding, undetectable in v1", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, nonce: "ab".repeat(32) }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), v2.SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, SLOT_REFUSALS.NONCE_MISMATCH],
    ["SIGNATURE FOR ANOTHER NETWORK — the response names a different network", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, network: "mainnet" }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.WRONG_NETWORK, SLOT_REFUSALS.WRONG_NETWORK],
    ["A DIFFERENT SIGNER IDENTITY", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, signerAddress: ADDRESSES[2] }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.ACCOUNT_CHANGED, SLOT_REFUSALS.SIGNER_IDENTITY_MISMATCH],
    ["A NON-ALL SIGHASH TYPE DECLARED", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, sighashType: 2 }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SIGHASH_NOT_ALL],
    ["HASH-TYPE BYTE != 0x01 IN THE SIGNATURE ITSELF", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, signatureHex: `${slotSig(0x11).slice(0, -2)}02` }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SIGHASH_NOT_ALL],
    ["A 64-BYTE (128-hex) SIGNATURE — missing the gate byte entirely", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, signatureHex: "11".repeat(64) }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SIGNATURE_INVALID],
    ["A 66-BYTE (132-hex) SIGNATURE — one byte too many", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, signatureHex: `${slotSig(0x11)}00` }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SIGNATURE_INVALID],
    ["THE ABSTENTION PLACEHOLDER OFFERED AS A SIGNATURE", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, signatureHex: PLACEHOLDER_SLOT_HEX_V7 }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.SIGNATURE_INVALID],
    ["A STALE REQUEST — the collection round's deadline elapsed", () => verifyRootSlotSignatureResponseV2({ request: r1, response: good, ownerSet: OWNER_SET, nowMs: SOON }), SignerErrorCodes.SIGNER_TIMEOUT, SLOT_REFUSALS.REQUEST_EXPIRED],
    ["AN UNKNOWN RESPONSE VERSION", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, responseVersion: "policyvault-org-root-slot-response/3" }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED, SLOT_REFUSALS.RESPONSE_INVALID],
    ["A RESPONSE ANSWERING A DIFFERENT requestVersion (a downgrade smuggled into the v2 shape)", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, requestVersion: ORG_ROOT_SLOT_REQUEST_VERSION_1 }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), v2.SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED, SLOT_REFUSALS.RESPONSE_INVALID],
    ["ENVELOPE KEY-SET ADDITION — an extra unknown key on the response", () => verifyRootSlotSignatureResponseV2({ request: r1, response: { ...good, extraField: "smuggled" }, ownerSet: OWNER_SET, nowMs: NOW + 1 }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.RESPONSE_INVALID],
    ["ENVELOPE KEY REMOVAL — a required key missing from the response", () => { const { txId, ...missing } = good; void txId; return verifyRootSlotSignatureResponseV2({ request: r1, response: missing, ownerSet: OWNER_SET, nowMs: NOW + 1 }); }, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.RESPONSE_INVALID],
    ["A FORGED capabilitiesProbed/txIdVerified TYPE — non-boolean provenance is refused at build time", () => buildRootSlotSignatureResponseV2({ request: r1, signedSafeJson: signOneInput(r1.unsignedSafeJson, r1.root.inputIndex, slotSig(0x11)), capabilitiesProbed: "yes" }), SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, SLOT_REFUSALS.RESPONSE_INVALID],
    ["A REQUEST DIGEST MISMATCH — the outer payloadSha256 no longer matches its own fields (tampered after creation)", () => assertRootSlotSigningRequestV2({ ...r1, root: { ...r1.root, outpoint: { ...r1.root.outpoint, index: r1.root.outpoint.index + 1 } } }), v2.SignerErrorCodesV2.PAYLOAD_MUTATED, SLOT_REFUSALS.SLOT_REQUEST_DIGEST_MISMATCH],
    ["A REQUEST ENVELOPE KEY-SET ADDITION", () => assertRootSlotSigningRequestV2({ ...r1, extraField: 1 }), SignerErrorCodes.REQUEST_INVALID, SLOT_REFUSALS.REQUEST_INVALID],
    ["A REQUEST WITH expiryIsCoordinationOnly FORGED false", () => assertRootSlotSigningRequestV2({ ...r1, expiryIsCoordinationOnly: false }), SignerErrorCodes.REQUEST_INVALID, SLOT_REFUSALS.REQUEST_INVALID]
  ];

  let refused = 0;
  for (const [label, fn, expectedCode, expectedReason] of rows) {
    const e = refusal(fn);
    assert.ok(e, `${label}: must refuse`);
    if (expectedCode !== null) assert.equal(e.signerCode, expectedCode, `${label}: error code (got ${e.signerCode})`);
    if (expectedReason !== null) assert.equal(e.details && e.details.reason, expectedReason, `${label}: got ${e.details && e.details.reason} — ${e.message}`);
    refused += 1;
  }
  assert.equal(refused, rows.length);
  console.log(`ORG-ROOT SLOT v2 hostile matrix rows refused: ${refused}`);
});

test("v2 slot path HOSTILE: TXID DRIFT, a FOREIGN INPUT SIGNED, DUPLICATE SLOT, UNDER-QUORUM, and a CROSS-MANIFEST pair", () => {
  const r1 = makeRequestV2(1);

  const otherTxSigned = signOneInput(fixture.other.unsignedSafeJson, ROOT_INPUT, slotSig(0x11));
  const drift = refusal(() => extractSlotSignatureFromSignedTransactionV2({ request: r1, signedSafeJson: otherTxSigned }));
  assert.equal(drift.signerCode, SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  assert.equal(drift.details.reason, SLOT_REFUSALS.TXID_DRIFT);

  const foreign = signOneInput(r1.unsignedSafeJson, ROOT_INPUT, slotSig(0x11), (j) => {
    j.inputs[1].signatureScript = `41${slotSig(0x99)}`;
  });
  const foreignErr = refusal(() => extractSlotSignatureFromSignedTransactionV2({ request: r1, signedSafeJson: foreign }));
  assert.equal(foreignErr.details.reason, SLOT_REFUSALS.FOREIGN_INPUT_SIGNED);

  const r1b = makeRequestV2(1);
  const dup = refusal(() =>
    collectRootSlotApprovalsV2({
      ownerSet: OWNER_SET,
      actionName: "authorize",
      pairs: [
        { request: r1, response: respondV2(r1, slotSig(0x11)) },
        { request: r1b, response: respondV2(r1b, slotSig(0x33)) }
      ],
      nowMs: NOW + 1
    })
  );
  assert.equal(dup.details.reason, SLOT_REFUSALS.DUPLICATE_SLOT);

  const under = refusal(() => collectRootSlotApprovalsV2({ ownerSet: OWNER_SET, actionName: "authorize", pairs: [{ request: r1, response: respondV2(r1, slotSig(0x11)) }], nowMs: NOW + 1 }));
  assert.equal(under.details.reason, "UNDER_QUORUM");

  const otherReq = createRootSlotSigningRequestV2({ manifest: fixture.other.manifest, slot: 2, expectedSignerAddress: ADDRESSES[1], unsignedSafeJson: fixture.other.unsignedSafeJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW });
  const cross = refusal(() =>
    collectRootSlotApprovalsV2({
      ownerSet: OWNER_SET,
      actionName: "authorize",
      pairs: [
        { request: r1, response: respondV2(r1, slotSig(0x11)) },
        { request: otherReq, response: respondV2(otherReq, slotSig(0x22)) }
      ],
      nowMs: NOW + 1
    })
  );
  assert.equal(cross.details.reason, SLOT_REFUSALS.MANIFEST_HASH_MISMATCH);
});

test("v2 slot path HOSTILE: a request is never issued for a manifest that does not verify, an unknown version, succession, an inactive/out-of-range slot, or a stale deadline", () => {
  const { manifestHash, ...body } = JSON.parse(JSON.stringify(fixture.primary.manifest));
  void manifestHash;
  body.action.requiredApprovals = "1";
  const tampered = { ...body, manifestHash: computeManifestHashV1(body) };
  const bad = refusal(() => createRootSlotSigningRequestV2({ manifest: tampered, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.primary.unsignedSafeJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(bad.details.reason, SLOT_REFUSALS.MANIFEST_NOT_VERIFIED);

  const unknown = refusal(() => createRootSlotSigningRequestV2({ manifest: { ...fixture.primary.manifest, manifestVersion: "policyvault-org-root-manifest/2" }, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.primary.unsignedSafeJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(unknown.details.reason, SLOT_REFUSALS.REQUEST_INVALID);

  const succession = refusal(() => createRootSlotSigningRequestV2({ manifest: fixture.succession.manifest, slot: 1, expectedSignerAddress: ADDRESSES[0], unsignedSafeJson: fixture.succession.manifest.transaction.frozenCanonicalJson, rootInputIndex: ROOT_INPUT, expiresAtMs: SOON, nowMs: NOW }));
  assert.equal(succession.details.reason, SLOT_REFUSALS.SUCCESSION_TAKES_NO_SLOTS);

  const inactive = refusal(() => makeRequestV2(5));
  assert.equal(inactive.details.reason, SLOT_REFUSALS.SLOT_INACTIVE);
  const outOfRange = refusal(() => makeRequestV2(13));
  assert.equal(outOfRange.details.reason, SLOT_REFUSALS.SLOT_OUT_OF_RANGE);

  const expired = refusal(() => makeRequestV2(1, { expiresAtMs: NOW - 1 }));
  assert.equal(expired.signerCode, SignerErrorCodes.REQUEST_INVALID);
  const tooLong = refusal(() => makeRequestV2(1, { expiresAtMs: NOW + MAX_REQUEST_LIFETIME_MS + 1 }));
  assert.match(tooLong.message, /re-issued against a fresh root state/);
});

test("v2 slot path HOSTILE: WRONG NETWORK, WRONG IDENTITY, and an owner outside the set are all refused BEFORE any prompt opens", async () => {
  const req = makeRequestV2(1);

  const wrongNetwork = createMockV2({ address: ADDRESSES[0], network: "mainnet" });
  const wn = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: wrongNetwork, request: req, nowMs: NOW }));
  assert.equal(wn.signerCode, v2.SignerErrorCodesV2.WRONG_NETWORK);
  assert.equal(wrongNetwork.control.invocations, 0);

  const wrongIdentity = createMockV2({ address: ADDRESSES[2], publicKey: `02${OWNER_SET.owners[2]}` });
  const wi = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: wrongIdentity, request: req, nowMs: NOW }));
  assert.equal(wi.signerCode, SignerErrorCodes.ACCOUNT_CHANGED, "the SLOT-KEY gate refuses an owner outside the set before the identity gate is even reached");
  assert.equal(wrongIdentity.control.invocations, 0);

  const drifting = createMockV2({
    address: ADDRESSES[0],
    mutate: (j) => {
      j.outputs[0].value = (BigInt(j.outputs[0].value) - 1n).toString();
    }
  });
  const drift = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: drifting, request: req, nowMs: NOW }));
  assert.equal(drift.details.reason, SLOT_REFUSALS.TXID_DRIFT);
});

test("v2 slot path: the org-root-level replay guard is keyed on (root, root-state-nonce, slot), independent of the per-call USI guard", () => {
  const guard = createOrgRootSlotReplayGuardV2();
  const r1 = makeRequestV2(1);
  assert.equal(guard.open(r1), true);
  /* the SAME request re-opened is fine (idempotent open) */
  assert.equal(guard.open(r1), true);
  /* a DIFFERENT request for the SAME (root, state nonce, slot) is refused */
  const r1AnotherRound = { ...r1, requestId: "ab".repeat(16) };
  const dup = refusal(() => guard.open(r1AnotherRound));
  assert.equal(dup.signerCode, v2.SignerErrorCodesV2.REPLAY_DETECTED);
  assert.equal(dup.details.reason, SLOT_REFUSALS.DUPLICATE_SLOT_REQUEST);

  assert.equal(guard.consume(r1), true);
  assert.equal(guard.isSettled(r1.requestId), true);
  const doubleConsume = refusal(() => guard.consume(r1));
  assert.equal(doubleConsume.signerCode, v2.SignerErrorCodesV2.DUPLICATE_SETTLEMENT);

  /* a DIFFERENT slot of the SAME round is independent */
  const r2 = makeRequestV2(2);
  assert.equal(guard.open(r2), true);
});

test("v2 slot path: STRUCTURAL NON-CUSTODY — no v2 request or response field can carry key material, and every v2 refusal code is in the closed v2 vocabulary", () => {
  const req = makeRequestV2(1);
  const res = respondV2(req, slotSig(0x11));
  const forbidden = /(privateKey|secret|seed|mnemonic|passphrase|wallet ?backup)/i;
  for (const key of Object.keys(req)) assert.doesNotMatch(key, forbidden, `request field ${key}`);
  for (const key of Object.keys(res)) assert.doesNotMatch(key, forbidden, `response field ${key}`);
  assert.doesNotMatch(JSON.stringify(req), forbidden);
  assert.doesNotMatch(JSON.stringify(res), forbidden);

  const source = fs.readFileSync(path.join(__dirname, "..", "org-root-slot-v7.js"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  assert.doesNotMatch(code, /privateKey|mnemonic|seedPhrase|walletBackup/i, "the slot path never touches key material");

  const usedV1 = [...source.matchAll(/SignerErrorCodes\.([A-Z_]+)/g)].map((m) => m[1]);
  for (const c of usedV1) assert.ok(Object.prototype.hasOwnProperty.call(SignerErrorCodes, c), `${c} must be part of the closed v1 error vocabulary`);
  const usedV2 = [...source.matchAll(/v2\.SignerErrorCodesV2\.([A-Z_]+)/g)].map((m) => m[1]);
  assert.ok(usedV2.length > 0, "the v2 path must actually use v2-only codes somewhere");
  for (const c of usedV2) assert.ok(Object.prototype.hasOwnProperty.call(v2.SignerErrorCodesV2, c), `${c} must be part of the closed v2 error vocabulary`);
});
