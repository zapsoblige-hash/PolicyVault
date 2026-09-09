"use strict";

/*
 * SDK/INTEGRATION: the v0.7 ORGANIZATIONAL ROOT external-signer SLOT PATH,
 * end to end with REAL Schnorr signatures.
 *
 * Two owners, two independent OFFLINE signers, one frozen transaction. Each
 * owner runs the production CLI keyfile adapter (core/signer/adapters/cli —
 * a genuinely different signer class from a browser wallet: headless,
 * offline, local keyfile, no prompt) behind the Universal Signer Interface,
 * and the slot path (core/signer/org-root-slot-v7) issues each of them a
 * request bound to the manifest hash, the slot, the root outpoint, the
 * network, their expected identity and a deadline.
 *
 * What this proves that the portable core suite cannot:
 *   - a REAL `createInputSignature` SIGHASH_ALL signature over the REAL
 *     frozen transaction, produced inside a signer that never exposes its
 *     key, is accepted by the slot path and lands in the correct slot;
 *   - the collected 780-byte blob drives the PRODUCTION finalizer
 *     (finalizeV7RootTransaction) to a covenant call of exactly the planned
 *     length — i.e. the exact-fee freeze survives out-of-band collection;
 *   - the air-gap shuttle (request JSON out, response JSON back) preserves
 *     every binding;
 *   - the hostile rows that need a REAL signer: a signer on the wrong
 *     network, the wrong owner answering another owner's request, and an
 *     owner outside the set whose real signature still cannot be placed.
 *
 * The cryptographic slot<->key binding itself is the covenant's per-slot
 * `checkSig`, proven on the real engine by tests/vm/tests/v7_sdk_integration.rs
 * over the same finalizer and the same signing primitive.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed) when
 * silverc / pv_call_encoder / pv_tx_probe / the vendored kaspa WASM are
 * absent. TEST KEYS ONLY: every key here is generated fresh into a temp dir.
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
const { SignerErrorCodes } = require("../../core/signer/errors");
const { generateKeyfile, createCliSignerAdapter, defaultKaspaModulePath } = require("../../core/signer/adapters/cli/adapter");
const {
  SLOT_REFUSALS,
  createRootSlotSigningRequest,
  requestRootSlotSignature,
  verifyRootSlotSignatureResponse,
  collectRootSlotApprovals
} = require("../../core/signer/org-root-slot-v7");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv7-slot-"));
const config = loadConfig({ dataRoot });
const available =
  fs.existsSync(config.silvercPath) &&
  fs.existsSync(ENCODER_PATH) &&
  fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe")) &&
  fs.existsSync(defaultKaspaModulePath());
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe / kaspa wasm";

const KAS = 100000000n;
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const ORG_ID = H(0xa7);
const ROOT_ID = H(0x52);
const FUEL = H(0x64);
const ROOT_KAS = 3n * KAS;
const NETWORK = "testnet-10";

function slots(keys) {
  const out = [];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY);
  return out;
}

/* Generate ONE offline CLI signer with a fresh TEST key and return its
 * adapter plus the identity the root will pin. The x-only key the covenant
 * checks is the compressed key without its parity byte. */
function makeOfflineSigner(name) {
  const keyfile = path.join(dataRoot, `${name}.keyfile.json`);
  const identity = generateKeyfile({ out: keyfile, network: NETWORK, label: name });
  return {
    name,
    keyfile,
    address: identity.address,
    publicKey: identity.publicKey,
    xOnly: identity.publicKey.slice(2).toLowerCase(),
    adapter: createCliSignerAdapter({ keyfilePath: keyfile, network: NETWORK })
  };
}

async function connected(signer) {
  await signer.adapter.connect();
  return signer.adapter;
}

async function asyncRefusal(fn) {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  return null;
}

/* One real 2-of-3 organizational root AUTHORIZE, frozen. */
function buildRound(owners) {
  const rootTemplate = { orgId: ORG_ID, recoveryDelayDaa: "1000", successorPk: H(0x7f), successionDelayDaa: "2000", rootMaxFeePerTx: "200000" };
  const ownerSet = { owners: slots(owners.map((o) => o.xOnly)), ownerM: 2, emergencyK: 1, recoveryM: 2 };
  const stateInput = { boundOrgId: ORG_ID, ...ownerSet, frozen: 0, rootNonce: 0 };
  const build = buildV7RootTransaction({
    config,
    templateInput: rootTemplate,
    stateInput,
    action: "authorize",
    chain: {
      predecessorOutpoint: { transactionId: H(0x01), index: 0 },
      covenantId: ROOT_ID,
      predecessorValue: ROOT_KAS.toString(),
      fuel: { outpoint: { transactionId: H(0x03), index: 0 }, amount: (1n * KAS).toString(), scriptPublicKeyHex: `20${FUEL}ac` }
    },
    changeXOnly: FUEL
  });
  const manifest = buildOrgRootIntentManifest({ build, vaultOperations: [], satisfiedApprovals: 2 });
  assert.equal(verifyOrgRootIntentManifest({ manifest }).verdict, "VERIFIED");
  const unsignedSafeJson = frozenToWasmTransaction(config, build.frozen).serializeToSafeJSON();
  return { build, manifest, ownerSet, unsignedSafeJson };
}

test("v0.7 slot path: TWO offline CLI signers each sign THEIR slot; the collected blob drives the production finalizer", { skip: SKIP }, async () => {
  const owners = [makeOfflineSigner("owner1"), makeOfflineSigner("owner2"), makeOfflineSigner("owner3")];
  const { build, manifest, ownerSet, unsignedSafeJson } = buildRound(owners);

  const nowMs = Date.now();
  const expiresAtMs = nowMs + 60 * 60 * 1000;
  const pairs = [];
  for (const slot of [1, 2]) {
    const owner = owners[slot - 1];
    const request = createRootSlotSigningRequest({
      manifest,
      slot,
      expectedSignerAddress: owner.address,
      unsignedSafeJson,
      rootInputIndex: 0,
      expiresAtMs,
      nowMs
    });
    assert.equal(request.slot.publicKey, owner.xOnly, "the request names the covenant identity, not just the transport one");
    assert.equal(request.network, NETWORK);

    /* AIR GAP: the request crosses as plain JSON and comes back as plain JSON */
    const shuttledRequest = JSON.parse(JSON.stringify(request));
    const response = await requestRootSlotSignature({ adapter: await connected(owner), request: shuttledRequest, nowMs });
    const shuttledResponse = JSON.parse(JSON.stringify(response));

    const verified = verifyRootSlotSignatureResponse({ request, response: shuttledResponse, ownerSet, nowMs: nowMs + 1000 });
    assert.equal(verified.slot, slot);
    assert.equal(verified.publicKey, owner.xOnly);
    assert.equal(verified.signatureHex.length, 130, "a slot is exactly 65 bytes");
    assert.ok(verified.signatureHex.endsWith("01"), "every counted slot carries the 0x01 SIGHASH_ALL gate byte");
    assert.equal(response.slotKeyClaimChecked, true, "the signer's own reported key was compared to the slot's key before signing");
    pairs.push({ request, response: shuttledResponse });
  }

  const collected = collectRootSlotApprovals({ ownerSet, actionName: "authorize", pairs, nowMs: nowMs + 2000 });
  assert.equal(collected.blobHex.length, SIG_BLOB_LEN_V7 * 2);
  assert.deepEqual([...collected.signedSlots], [1, 2]);
  assert.equal(collected.satisfiedApprovals, "2");

  /* the PRODUCTION finalizer accepts the out-of-band-collected approvals and
   * the covenant call length is EXACTLY the planned one — the exact-fee
   * freeze survives an M-of-N collection round across two signers */
  const kaspa = require(config.rustyKaspaModule);
  const fuelKey = new kaspa.PrivateKey(H(0x64));
  const fuelScript = kaspa.createInputSignature(frozenToWasmTransaction(config, build.frozen), 1, fuelKey);
  const fin = finalizeV7RootTransaction({ build, approvals: collected.approvals, fuelSignatureScriptHex: fuelScript });
  assert.equal(fin.covenantCallHex.length, build.plannedCallHexLength, "FEE DRIFT: the finalized call must be the planned length");
  assert.equal(fin.ownerSigsBlobHex, collected.blobHex, "the finalizer places exactly the bytes the slot path collected");
  assert.equal(fin.satisfiedApprovals, "2");
  assert.equal(fin.txId, build.txId);
});

test("v0.7 slot path HOSTILE (real signers): wrong network, the wrong owner, and an owner outside the set", { skip: SKIP }, async () => {
  const owners = [makeOfflineSigner("h1"), makeOfflineSigner("h2"), makeOfflineSigner("h3")];
  const outsider = makeOfflineSigner("outsider");
  const { manifest, ownerSet, unsignedSafeJson } = buildRound(owners);
  const nowMs = Date.now();
  const expiresAtMs = nowMs + 60 * 60 * 1000;

  const request1 = createRootSlotSigningRequest({ manifest, slot: 1, expectedSignerAddress: owners[0].address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });

  /* WRONG NETWORK: slot 1's own owner, on the right key, but the request
   * names a different network than the signer operates on. The CLI adapter
   * declares exactly one network, so the gate refuses before any prompt.
   * (The adapter's mainnet dual-unlock is separately proven by
   * core/signer/adapters/cli/test/network-unlock.test.js.) */
  const owner1ForNetwork = await connected(owners[0]);
  const crossNetwork = await asyncRefusal(() =>
    requestRootSlotSignature({
      adapter: owner1ForNetwork,
      request: { ...request1, signerRequest: { ...request1.signerRequest, network: "mainnet" } },
      nowMs
    })
  );
  assert.equal(crossNetwork.signerCode, SignerErrorCodes.WRONG_NETWORK);

  /* THE WRONG OWNER answering another owner's request: the identity gate
   * refuses before any signature is produced. */
  const owner3Adapter = await connected(owners[2]);
  const wrongOwner = await asyncRefusal(() => requestRootSlotSignature({ adapter: owner3Adapter, request: request1, nowMs }));
  assert.equal(wrongOwner.signerCode, SignerErrorCodes.ACCOUNT_CHANGED);

  /* AN OWNER OUTSIDE THE SET. The request was (wrongly) issued to the
   * outsider's own address for slot 1, so the ADDRESS gate alone would let it
   * through — the transport identity matches. The SLOT-KEY gate refuses
   * instead: the signer's own reported public key is not slot 1's key, so no
   * signature is ever requested. */
  const outsiderRequest = createRootSlotSigningRequest({ manifest, slot: 1, expectedSignerAddress: outsider.address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });
  const outsiderAdapter = await connected(outsider);
  const refusedOutsider = await asyncRefusal(() => requestRootSlotSignature({ adapter: outsiderAdapter, request: outsiderRequest, nowMs }));
  assert.ok(refusedOutsider, "a signer outside the owner set must never be asked for a slot signature");
  assert.equal(refusedOutsider.signerCode, SignerErrorCodes.ACCOUNT_CHANGED);
  assert.equal(refusedOutsider.details.reason, SLOT_REFUSALS.SLOT_NOT_HELD);
  assert.match(refusedOutsider.message, new RegExp(owners[0].xOnly));

  /* the same gate refuses an OWNER asked for ANOTHER owner's slot, even
   * though both are legitimate members of the set */
  const slot2Request = createRootSlotSigningRequest({ manifest, slot: 2, expectedSignerAddress: owners[1].address, unsignedSafeJson, rootInputIndex: 0, expiresAtMs, nowMs });
  const owner1Adapter = await connected(owners[0]);
  const wrongSlot = await asyncRefusal(() => requestRootSlotSignature({ adapter: owner1Adapter, request: { ...slot2Request, expectedSignerAddress: owners[0].address, signerRequest: { ...slot2Request.signerRequest, expectedSignerAddress: owners[0].address } }, nowMs }));
  assert.equal(wrongSlot.details.reason, SLOT_REFUSALS.SLOT_NOT_HELD);

  /* and a REAL signature relabelled into another slot is refused on the key
   * binding at verification time, not merely on the address */
  const genuine = await requestRootSlotSignature({ adapter: await connected(owners[1]), request: slot2Request, nowMs });
  assert.equal(genuine.slotKeyClaimChecked, true, "the CLI signer reports its key, so the slot-key gate really ran");
  const relabelled = { ...genuine, slot: { number: 1, index: 0, publicKey: owners[0].xOnly }, signerAddress: owners[0].address };
  const refusedRelabel = (() => {
    try {
      verifyRootSlotSignatureResponse({ request: slot2Request, response: relabelled, ownerSet, nowMs: nowMs + 1 });
      return null;
    } catch (e) {
      return e;
    }
  })();
  assert.equal(refusedRelabel.details.reason, SLOT_REFUSALS.SLOT_NOT_HELD);
});
