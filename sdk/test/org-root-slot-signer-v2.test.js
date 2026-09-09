"use strict";

/*
 * SDK/INTEGRATION: the v0.7 ORGANIZATIONAL ROOT external-signer SLOT PATH
 * carried over Universal Signer Interface v2
 * (`core/signer/org-root-slot-v7.js`'s `policyvault-org-root-slot-request/2`
 * additions), end to end with REAL Schnorr signatures.
 *
 * Same shape as `sdk/test/org-root-slot-signer-v7.test.js` (v1), which this
 * file leaves completely untouched: two owners, two independent OFFLINE
 * signers, one frozen transaction, driven through the PRODUCTION finalizer.
 * What THIS file additionally proves, over and above the v1 SDK suite:
 *
 *   - the v2 CLI keyfile adapter (`core/signer/v2/adapters/cli.js`, a LIFT
 *     of the SAME reviewed v1 adapter — no provider call changes) produces
 *     a REAL BIP-340 Schnorr signature through the v2 capability-PROBE and
 *     user-presence gates, not just the v1 pipeline;
 *   - the v2 slot request's WIDE payload digest (unsigned tx + manifest
 *     hash + slot + root outpoint + nonce) and the v2 response envelope's
 *     nonce echo survive an air-gap-shaped TEXT round trip carrying a REAL
 *     signature — not a mock's deterministic placeholder;
 *   - the collected 780-byte blob is BYTE-IDENTICAL whether it was
 *     assembled via the v1 or the v2 collection path for the SAME
 *     approvals, because both fold into the SAME pinned
 *     `assembleOwnerSigsBlobV7`;
 *   - the hostile rows that need a REAL v2 signer: wrong network, the
 *     wrong owner answering another owner's request, and an owner outside
 *     the set — refused before any prompt opens, exactly as v1 requires.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * under the SAME availability gate as the v1 SDK suite. TEST KEYS ONLY.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { loadConfig } = require("../src/config");
const { buildV7RootTransaction, finalizeV7RootTransaction } = require("../src/vault-builders-v7");
const { frozenToWasmTransaction } = require("../src/frozen-tx-v3");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest } = require("../../core/intent/org-root-manifest-v7");
const { INACTIVE_SLOT_KEY, OWNER_SLOTS_V7, SIG_BLOB_LEN_V7 } = require("../../core/model/owner-set-v7");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { generateKeyfile, defaultKaspaModulePath } = require("../../core/signer/adapters/cli/adapter");
const { createCliSignerAdapterV2 } = require("../../core/signer/v2/adapters/cli");
const { createAirGapSignerAdapter } = require("../../core/signer/v2/adapters/airgap");
const v2 = require("../../core/signer/v2");
const {
  SLOT_REFUSALS,
  ORG_ROOT_SLOT_REQUEST_VERSION_2,
  ORG_ROOT_SLOT_RESPONSE_VERSION_2,
  createRootSlotSigningRequestV2,
  requestRootSlotSignatureV2,
  verifyRootSlotSignatureResponseV2,
  collectRootSlotApprovalsV2,
  createRootSlotSigningRequest,
  requestRootSlotSignature,
  verifyRootSlotSignatureResponse,
  collectRootSlotApprovals
} = require("../../core/signer/org-root-slot-v7");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv7-slot-v2-"));
const config = loadConfig({ dataRoot });
const available =
  fs.existsSync(config.silvercPath) &&
  fs.existsSync(ENCODER_PATH) &&
  fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe")) &&
  fs.existsSync(defaultKaspaModulePath());
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe / kaspa wasm";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xb8);
const ROOT_ID = H(0x63);
const FUEL = H(0x75);
const ROOT_KAS = 3n * KAS;
const NETWORK = "testnet-10";

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}

function makeOfflineSigner(name) {
  const keyfile = path.join(dataRoot, `${name}.keyfile.json`);
  const identity = generateKeyfile({ out: keyfile, network: NETWORK, label: name });
  return {
    name,
    keyfile,
    address: identity.address,
    publicKey: identity.publicKey,
    xOnly: identity.publicKey.slice(2).toLowerCase(),
    adapterV2: createCliSignerAdapterV2({ keyfilePath: keyfile, network: NETWORK })
  };
}

async function connectedV2(signer) {
  await signer.adapterV2.connect();
  return signer.adapterV2;
}

async function asyncRefusal(fn) {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  return null;
}

function buildRound(owners) {
  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7e), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet = { owners: slots(owners.map((o) => o.xOnly)), ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const stateInput = { boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0 };
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput,
    action: "authorize",
    chain: {
      predecessorOutpoint: { transactionId: H(0x02), index: 0 },
      covenantId: ROOT_ID,
      predecessorValue: ROOT_KAS.toString(),
      fuel: { outpoint: { transactionId: H(0x04), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
    },
    changeXOnly: FUEL
  });
  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(verifyOrgRootIntentManifest({ manifest }).verdict, "VERIFIED");
  const unsignedSafeJson = frozenToWasmTransaction(config, build.frozen).serializeToSafeJSON();
  return { build, manifest, ownerSet, unsignedSafeJson };
}

test("v0.7 slot path v2: TWO offline CLI v2 signers each sign THEIR slot; the collected blob drives the production finalizer, and is byte-identical to the v1 path's blob for the same approvals", { skip: SKIP }, async () => {
  const owners = [makeOfflineSigner("v2owner1"), makeOfflineSigner("v2owner2"), makeOfflineSigner("v2owner3")];
  const { build, manifest, ownerSet, unsignedSafeJson } = buildRound(owners);

  const nowMs = Date.now();
  const expiresAtMs = nowMs + 60 * 60 * 1000;
  const pairs = [];
  const states = [];
  for (const slot of [1, 2]) {
    const owner = owners[slot - 1];
    const request = createRootSlotSigningRequestV2({
      manifest,
      slot,
      expectedSignerAddress: owner.address,
      unsignedSafeJson,
      rootInputIndex: 0,
      expiresAtMs,
      nowMs
    });
    assert.equal(request.requestVersion, ORG_ROOT_SLOT_REQUEST_VERSION_2);
    assert.equal(request.slot.publicKey, owner.xOnly, "the request names the covenant identity, not just the transport one");
    assert.equal(request.network, NETWORK);
    assert.equal(request.root.stateNonce, "0");

    /* AIR-GAP-SHAPED round trip: the request crosses as plain JSON */
    const shuttledRequest = JSON.parse(JSON.stringify(request));

    const full = await requestRootSlotSignatureV2({
      adapter: await connectedV2(owner),
      request: shuttledRequest,
      nowMs,
      requireUserPresence: false, /* the CLI adapter's HONEST declaration: running the process IS the approval */
      onTransition: (t) => states.push(t.state)
    });
    assert.equal(full.slotKeyClaimChecked, true, "the CLI v2 adapter reports its real public key, so the slot-key gate really ran");
    const { slotKeyClaimChecked, ...response } = full;
    void slotKeyClaimChecked;
    assert.equal(response.responseVersion, ORG_ROOT_SLOT_RESPONSE_VERSION_2);
    assert.equal(response.capabilitiesProbed, true, "the CLI v2 adapter IS live-probeable (unlike the air-gap shuttle)");

    const shuttledResponse = JSON.parse(JSON.stringify(response));
    const verified = verifyRootSlotSignatureResponseV2({ request, response: shuttledResponse, ownerSet, nowMs: nowMs + 1000 });
    assert.equal(verified.slot, slot);
    assert.equal(verified.publicKey, owner.xOnly);
    assert.equal(verified.signatureHex.length, 130, "a slot is exactly 65 bytes");
    assert.ok(verified.signatureHex.endsWith("01"), "every counted slot carries the 0x01 SIGHASH_ALL gate byte");
    pairs.push({ request, response: shuttledResponse });
  }
  assert.ok(states.includes("SUBMITTED") && states.includes("APPROVED"));

  const collectedV2 = collectRootSlotApprovalsV2({ ownerSet, actionName: "authorize", pairs, nowMs: nowMs + 2000 });
  assert.equal(collectedV2.blobHex.length, SIG_BLOB_LEN_V7 * 2);
  assert.deepEqual([...collectedV2.signedSlots], [1, 2]);
  assert.equal(collectedV2.satisfiedApprovals, "2");

  /* the PRODUCTION finalizer accepts the out-of-band v2-collected approvals
   * and the covenant call length is EXACTLY the planned one */
  const kaspa = require(config.rustyKaspaModule);
  const fuelKey = new kaspa.PrivateKey(H(0x75));
  const fuelScript = kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
  const fin = finalizeV7RootTransaction({ build, approvals: collectedV2.approvals, fuelSignatureScriptHex: fuelScript });
  assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength, "FEE DRIFT: the finalized call must be the planned length");
  assert.equal(fin.ownerSigsBlobHex, collectedV2.blobHex, "the finalizer places exactly the bytes the v2 slot path collected");
  assert.equal(fin.satisfiedApprovals, "2");
  assert.equal(fin.txId, build.txId);

  /* BYTE-IDENTICAL BLOB CLAIM: fold the SAME two real signatures through
   * the v1 collection path (v1 requests/responses built directly from the
   * v2-collected raw signature bytes — the covenant does not know which
   * interface version collected a slot) and assert the two blobs match. */
  const v1Pairs = [];
  for (const [i, slot] of [1, 2].entries()) {
    const owner = owners[slot - 1];
    const reqV1 = createRootSlotSigningRequest({ manifest, slot, expectedSignerAddress: owner.address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });
    const responseV1 = { ...reqV1, responseVersion: "policyvault-org-root-slot-response/1" }; // placeholder, replaced below
    void responseV1;
    const sigHex = pairs[i].response.signatureHex;
    const bareResponse = { responseVersion: "policyvault-org-root-slot-response/1", requestVersion: reqV1.requestVersion, requestId: reqV1.requestId, network: reqV1.network, manifestHash: reqV1.manifestHash, txId: reqV1.txId, root: { covenantId: reqV1.root.covenantId, outpoint: { ...reqV1.root.outpoint }, inputIndex: reqV1.root.inputIndex }, slot: { number: reqV1.slot.number, index: reqV1.slot.index, publicKey: reqV1.slot.publicKey }, signerAddress: owner.address, signatureHex: sigHex, sighashType: 1, signedAtMs: nowMs + 1000 };
    v1Pairs.push({ request: reqV1, response: bareResponse });
  }
  const collectedV1 = collectRootSlotApprovals({ ownerSet, actionName: "authorize", pairs: v1Pairs, nowMs: nowMs + 2000 });
  assert.equal(collectedV1.blobHex, collectedV2.blobHex, "v1 and v2 collection of the SAME real signatures produce the IDENTICAL 780-byte blob");
  void requestRootSlotSignature;
  void verifyRootSlotSignatureResponse;
});

test("v0.7 slot path v2 HOSTILE (real signers): wrong network, the wrong owner, and an owner outside the set", { skip: SKIP }, async () => {
  const owners = [makeOfflineSigner("v2h1"), makeOfflineSigner("v2h2"), makeOfflineSigner("v2h3")];
  const outsider = makeOfflineSigner("v2outsider");
  const { manifest, ownerSet, unsignedSafeJson } = buildRound(owners);
  const nowMs = Date.now();
  const expiresAtMs = nowMs + 60 * 60 * 1000;

  const request1 = createRootSlotSigningRequestV2({ manifest, slot: 1, expectedSignerAddress: owners[0].address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });

  /* WRONG NETWORK — the CLI adapter declares exactly ONE network */
  const owner1ForNetwork = await connectedV2(owners[0]);
  const crossNetwork = await asyncRefusal(() =>
    requestRootSlotSignatureV2({
      adapter: owner1ForNetwork,
      request: { ...request1, network: "mainnet", signerRequest: { ...request1.signerRequest, network: "mainnet" } },
      nowMs,
      requireUserPresence: false
    })
  );
  assert.equal(crossNetwork.signerCode, v2.SignerErrorCodesV2.WRONG_NETWORK);
  assert.equal(owner1ForNetwork.control === undefined, true, "the real CLI adapter has no test control surface — absence itself proves this is the production adapter, not a mock");

  /* THE WRONG OWNER answering another owner's request: the SLOT-KEY gate
   * refuses before any signature is produced. */
  const owner3Adapter = await connectedV2(owners[2]);
  const wrongOwner = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: owner3Adapter, request: request1, nowMs, requireUserPresence: false }));
  assert.equal(wrongOwner.signerCode, "ACCOUNT_CHANGED");
  assert.equal(wrongOwner.details.reason, SLOT_REFUSALS.SLOT_NOT_HELD);

  /* AN OWNER OUTSIDE THE SET, requested (wrongly) for slot 1 under its OWN
   * address — the transport identity would match, so the SLOT-KEY gate is
   * what must refuse. */
  const outsiderRequest = createRootSlotSigningRequestV2({ manifest, slot: 1, expectedSignerAddress: outsider.address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });
  const outsiderAdapter = await connectedV2(outsider);
  const refusedOutsider = await asyncRefusal(() => requestRootSlotSignatureV2({ adapter: outsiderAdapter, request: outsiderRequest, nowMs, requireUserPresence: false }));
  assert.ok(refusedOutsider, "a signer outside the owner set must never be asked for a slot signature");
  assert.equal(refusedOutsider.signerCode, "ACCOUNT_CHANGED");
  assert.equal(refusedOutsider.details.reason, SLOT_REFUSALS.SLOT_NOT_HELD);
  assert.match(refusedOutsider.message, new RegExp(owners[0].xOnly));
});

test("v0.7 slot path v2: an AIR-GAP-SHAPED transport carrying a REAL signature — TEXT round trip through createAirGapSignerAdapter", { skip: SKIP }, async () => {
  const owners = [makeOfflineSigner("v2ag1"), makeOfflineSigner("v2ag2"), makeOfflineSigner("v2ag3")];
  const { manifest, ownerSet, unsignedSafeJson } = buildRound(owners);
  const nowMs = Date.now();
  const expiresAtMs = nowMs + 60 * 60 * 1000;
  const owner = owners[0];

  const request = createRootSlotSigningRequestV2({ manifest, slot: 1, expectedSignerAddress: owner.address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });

  /* Produce a REAL signature through the reviewed CLI v2 adapter (in
   * process — no subprocess needed for a real signature; the offline CLI
   * SCRIPT `core/signer/adapters/cli/cli.js` is a SEPARATE process-boundary
   * interface driven by the shipped mobile/air-gap platform layer, and this
   * test proves the v2 org-root-slot BINDING survives an air-gap-shaped
   * document carrying real bytes, not a second implementation of the CLI
   * script itself). */
  const directAdapter = await connectedV2(owner);
  const { slotKeyClaimChecked, ...realResponse } = await requestRootSlotSignatureV2({ adapter: directAdapter, request, nowMs, requireUserPresence: false });
  void slotKeyClaimChecked;

  /* Re-express that REAL result as the offline CLI SCRIPT's OWN closed
   * response document (`policyvault-cli-signer-signed-transaction/1`,
   * exactly the shape `core/signer/v2/adapters/airgap.js` parses) and hand
   * it back across a shuttle whose ONLY I/O is `exchange` returning TEXT. */
  const signedSafeJson = signOneInputFromResponse(request.unsignedSafeJson, request.root.inputIndex, realResponse.signatureHex);
  let exchangeCalls = 0;
  const airgap = createAirGapSignerAdapter({
    network: NETWORK,
    signerAddress: owner.address,
    publicKey: `02${owner.xOnly}`,
    exchange: async ({ documentText }) => {
      exchangeCalls += 1;
      const parsedDoc = JSON.parse(documentText);
      assert.equal(parsedDoc.format, "policyvault-cli-signing-request/1");
      assert.equal(parsedDoc.expectedSignerAddress, owner.address);
      const responseDoc = {
        format: "policyvault-cli-signer-signed-transaction/1",
        requestId: "offline-signer-own-id-unrelated-to-v2-nonce",
        kind: "sign-transaction",
        network: NETWORK,
        address: owner.address,
        signedSafeJson
      };
      return JSON.stringify(responseDoc);
    }
  });

  await airgap.connect();
  const { slotKeyClaimChecked: agChecked, ...agResponse } = await requestRootSlotSignatureV2({
    adapter: airgap,
    request,
    nowMs,
    timeoutMs: 60000, /* the air-gap adapter's asynchronousApproval declaration requires an explicit deadline */
    requireProbedCapabilities: false /* L3: an offline signer cannot be interrogated before the shuttle — honest, not a bug */
  });
  void agChecked;
  assert.equal(exchangeCalls, 1);
  assert.equal(agResponse.capabilitiesProbed, false, "the honest probed:false is recorded verbatim, never fabricated as true");
  assert.equal(agResponse.transport, "qr-airgap");
  assert.equal(agResponse.signatureHex, realResponse.signatureHex, "the REAL signature survives the air-gap-shaped TEXT round trip byte-for-byte");

  const shuttledBack = JSON.parse(JSON.stringify(agResponse));
  const verified = verifyRootSlotSignatureResponseV2({ request, response: shuttledBack, ownerSet, nowMs: nowMs + 1000 });
  assert.equal(verified.signatureHex, realResponse.signatureHex);
  assert.equal(verified.publicKey, owner.xOnly);
});

function signOneInputFromResponse(unsignedSafeJson, index, sigHex) {
  const j = JSON.parse(unsignedSafeJson);
  j.inputs[index].signatureScript = `41${sigHex}`;
  return JSON.stringify(j);
}
