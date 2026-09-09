"use strict";

/*
 * HOSTILE matrix for the v0.7 ON-CHAIN ORGANIZATIONAL ROOT server
 * orchestration pipeline (docs/postlaunch/v0.7-app-surface-contract.md §5):
 * sub-quorum finalize, duplicate slot signature, foreign key, stale root
 * outpoint, action-class mislabel in the body ignored/refused, hosted-org
 * admin without a slot, envelope replay across requests/roots, tampered
 * manifest hash, PENDING presented as success = failure.
 *
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped, never silently passed)
 * when silverc / pv_call_encoder / pv_tx_probe are absent.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const wr7 = require("../src/wallet-requests-v7");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-hostile-")) });
}
const config = freshConfig();
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function sign65(unsignedSafeJson, index, key) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  return kaspa.createInputSignature(tx, index, key).slice(2);
}
function mockRpc(byAddress = {}) {
  const table = byAddress;
  return {
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) for (const e of table[a] ?? []) entries.push(e);
      return { entries };
    },
    async submitTransaction({ transaction }) {
      return { transactionId: transaction.finalize().toString().toLowerCase() };
    },
    async disconnect() {},
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function spkAddress(cfg, spk) {
  const { loadKaspa } = require("../src/chain");
  const k = loadKaspa(cfg);
  return k.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, cfg.networkId).toString();
}
function fuelUtxoFor(fuelKey, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
}

function slotResponse(reqEnvelope, signerAddress, sigHex) {
  return {
    responseVersion: "policyvault-org-root-slot-response/1",
    requestVersion: reqEnvelope.requestVersion,
    requestId: reqEnvelope.requestId,
    network: reqEnvelope.network,
    manifestHash: reqEnvelope.manifestHash,
    txId: reqEnvelope.txId,
    root: reqEnvelope.root,
    slot: reqEnvelope.slot,
    signerAddress,
    signatureHex: sigHex,
    sighashType: 1,
    signedAtMs: Date.now()
  };
}

/* Build+submit a live 2-of-3 organizational root, ready for owner-op tests. */
async function setupRoot(cfg) {
  const owner1 = KEY(0x71), owner2 = KEY(0x72), owner3 = KEY(0x73), outsider = KEY(0x99);
  const funder = KEY(0xf0);
  const rpc = mockRpc();

  const req = await wr7.buildRootGenesisRequest({
    config: cfg, label: "hostile org",
    owners: [{ slot: 1, publicKey: XO(owner1) }, { slot: 2, publicKey: XO(owner2) }, { slot: 3, publicKey: XO(owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder), funding: [fuelUtxoFor(funder)]
  });
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: req.id, signedSafeJson: signed });
  const { covenantAddress } = require("../src/chain");
  const addr = covenantAddress(cfg, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc });
  return { rootCovenantId: submitted.rootCovenantId, owner1, owner2, owner3, outsider, funder, rpc };
}

test("finalize below quorum is refused with UNDER_QUORUM; at quorum it succeeds", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1, owner2 } = await setupRoot(cfg);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });

  await assert.rejects(() => wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id }), (e) => { assert.equal(e.code, "UNDER_QUORUM"); return true; });

  const envelope = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 1 });
  const sig = sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, owner1);
  await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 1, response: slotResponse(envelope, ADDR(owner1), sig) });
  await assert.rejects(() => wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id }), (e) => { assert.equal(e.code, "UNDER_QUORUM"); return true; });

  const envelope2 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 2 });
  const sig2 = sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, owner2);
  await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 2, response: slotResponse(envelope2, ADDR(owner2), sig2) });
  const reqNow = await wr7.loadOrgRootRequest(cfg, req.id);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), reqNow.build.frozen.inputs.length - 1, KEY(0x64));
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalized.state, "SIGNED");
});

test("duplicate slot signature is refused (DUPLICATE_SLOT_SIGNATURE)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1 } = await setupRoot(cfg);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });
  const envelope = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 1 });
  const sig = sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, owner1);
  await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 1, response: slotResponse(envelope, ADDR(owner1), sig) });
  await assert.rejects(
    () => wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 1, response: slotResponse(envelope, ADDR(owner1), sig) }),
    (e) => { assert.equal(e.code, "DUPLICATE_SLOT_SIGNATURE"); return true; }
  );
});

test("a signature from a real key OUTSIDE the owner set is refused (foreign key)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1, outsider } = await setupRoot(cfg);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });
  const envelope = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 1 });
  const outsiderSig = sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, outsider);
  /* the outsider's REAL signature is placed under slot 1's response, but the
   * signer identity/address claimed does not hold slot 1's covenant key */
  await assert.rejects(
    () => wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 1, response: slotResponse(envelope, ADDR(outsider), outsiderSig) }),
    (e) => { assert.ok(["SIGNER_IDENTITY_MISMATCH", "SLOT_KEY_MISMATCH", "ACCOUNT_CHANGED"].includes(e.code) || /signer|slot/i.test(e.message)); return true; }
  );
});

test("wrong manifest digest / envelope for another request is refused (RESPONSE binding)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1, owner2 } = await setupRoot(cfg);
  const reqA = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });
  /* STALE ASSUMPTION corrected (rc16 review N-02 server guard): a slot signing
   * request is only issued while the request is AUTHORIZED, so the attacker's
   * envelope for A is obtained BEFORE A is withdrawn — the replay property
   * under test (A's response presented against B) is unchanged. */
  const envelopeA = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: reqA.id, slot: 1 });
  await wr7.rejectOrgRootRequest({ config: cfg, requestId: reqA.id, reason: "clear pending" });
  const reqB = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner2) });

  const sigA = sign65(reqA.transaction.unsignedSafeJson, reqA.rootInputIndex, owner1);
  const responseForA = slotResponse(envelopeA, ADDR(owner1), sigA);

  /* the response envelope answers reqA's request/manifest — presenting it
   * against reqB must be refused, never silently accepted */
  await assert.rejects(
    () => wr7.submitSlotSignature({ config: cfg, requestId: reqB.id, slot: 1, response: responseForA }),
    (e) => { assert.ok(["RESPONSE_REPLAYED", "MANIFEST_HASH_MISMATCH", "TXID_DRIFT"].includes(e.code)); return true; }
  );
});

test("a stale/absent root outpoint refuses a new root-action build (ROOT_STALE_OUTPOINT)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const owner1 = KEY(0x71);
  const funder = KEY(0xf0);
  /* a root record with NO live outpoint at all (as if genesis were built but never chain-verified) */
  await wr7.saveOrgRoot(cfg, {
    schemaVersion: "policyvault-org-root-record/1",
    rootCovenantId: H(0x77),
    orgId: H(0x01),
    label: "unconfirmed",
    networkId: cfg.networkId,
    contractVersion: "policyvault-0.7-root",
    authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT",
    template: { orgId: H(0x01), recoveryDelayDaa: "600", successorPk: "00".repeat(32), successionDelayDaa: "600", rootMaxFeePerTx: "1000000" },
    state: { boundOrgId: H(0x01), owners: [XO(owner1), ...new Array(11).fill("00".repeat(32))], ownerM: "1", emergencyK: "1", recoveryM: "0", frozen: "0", rootNonce: "0" },
    slots: [{ slot: 1, publicKey: XO(owner1), address: ADDR(owner1), label: "" }],
    rootPins: null,
    live: null,
    generation: 0,
    pendingRequestId: null,
    vaults: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  await assert.rejects(
    () => wr7.buildRootActionRequest({ config: cfg, rootCovenantId: H(0x77), action: "authorize", params: { fuel: fuelUtxoFor(funder) }, signerAddress: ADDR(owner1) }),
    (e) => { assert.equal(e.code, "ROOT_STALE_OUTPOINT"); return true; }
  );
});

test("a hosted-org admin (real address, NOT an active slot) cannot create a root request", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId } = await setupRoot(cfg);
  const hostedAdmin = KEY(0x42); // a real wallet identity, but never placed in any owner slot
  await assert.rejects(
    () => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(hostedAdmin) }),
    (e) => { assert.equal(e.code, "NOT_AN_ACTIVE_SLOT"); return true; }
  );
});

test("owner set ill-formed at genesis is refused with the closed OWNER_SET_ILL_FORMED code, before any durable record", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const funder = KEY(0xf0);
  const before = await wr7.listOrgRootRequests(cfg);
  assert.equal(before.length, 0);
  await assert.rejects(
    () => wr7.buildRootGenesisRequest({
      config: cfg, label: "", owners: [{ slot: 1, publicKey: XO(KEY(0x11)) }], ownerM: 1, emergencyK: 2 /* K > M */, recoveryM: 0,
      recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01",
      signerAddress: ADDR(funder), funding: [fuelUtxoFor(funder)]
    }),
    (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; }
  );
  assert.equal((await wr7.listOrgRootRequests(cfg)).length, 0);
});

test("at most ONE vault operation per root transition (covenant refuses a second rooted vault as a foreign rider)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1 } = await setupRoot(cfg);
  await assert.rejects(
    () => wr7.buildRootActionRequest({
      config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) },
      vaultOperations: [{ vaultId: H(0x01), action: "ownerPause", params: {} }, { vaultId: H(0x02), action: "ownerPause", params: {} }],
      signerAddress: ADDR(owner1)
    }),
    (e) => { assert.equal(e.code, "ONE_VAULT_OPERATION_PER_ROOT_TRANSITION"); return true; }
  );
});

test("PENDING is never presented as success: BROADCAST/SIGNED are not CHAIN_VERIFIED, and re-submitting after a definitive rejection never advances the record", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1, owner2 } = await setupRoot(cfg);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });
  const e1 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 1 });
  await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 1, response: slotResponse(e1, ADDR(owner1), sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, owner1)) });
  const e2 = await wr7.getOrCreateSlotSigningRequest({ config: cfg, requestId: req.id, slot: 2 });
  await wr7.submitSlotSignature({ config: cfg, requestId: req.id, slot: 2, response: slotResponse(e2, ADDR(owner2), sign65(req.transaction.unsignedSafeJson, req.rootInputIndex, owner2)) });
  const reqSigned = await wr7.loadOrgRootRequest(cfg, req.id);
  const fuelSig = kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), reqSigned.build.frozen.inputs.length - 1, KEY(0x64));
  const finalized = await wr7.finalizeOrgRootRequest({ config: cfg, requestId: req.id, fuelSignatureScriptHex: fuelSig });
  assert.equal(finalized.state, "SIGNED", "SIGNED is not success");
  assert.notEqual(finalized.state, "CHAIN_VERIFIED");

  /* a node that DEFINITIVELY rejects the transaction must never advance
   * the root record, and the request must record the refusal honestly */
  const rejectingRpc = {
    async getUtxosByAddresses() {
      return { entries: [] }; // the root's own live outpoint is reported ABSENT: definitive-rejection path re-checks it
    },
    async submitTransaction() {
      const err = new Error(`Rejected transaction ${finalized.txId}: mempool policy violation`);
      throw err;
    },
    async disconnect() {}
  };
  await assert.rejects(
    () => wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc: rejectingRpc }),
    (e) => { assert.ok(["SUBMISSION_REJECTED", "RECONCILIATION_REQUIRED"].includes(e.code)); return true; }
  );
  const rootAfter = await wr7.loadOrgRoot(cfg, rootCovenantId);
  assert.equal(rootAfter.generation, 0, "a rejected/ambiguous submit never advances the root's generation");
  const reqAfter = await wr7.loadOrgRootRequest(cfg, req.id);
  assert.notEqual(reqAfter.state, "CHAIN_VERIFIED");
});

test("a manifest with a tampered field fails local re-verification (manifest hash / structural checks)", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1 } = await setupRoot(cfg);
  const req = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "authorize", params: { fuel: fuelUtxoFor(KEY(0x64)) }, signerAddress: ADDR(owner1) });
  const { verifyOrgRootIntentManifest } = require("../../core/intent/org-root-manifest-v7");
  const tampered = { ...req.manifest, action: { ...req.manifest.action, requiredApprovals: "1" } }; // claim a lower threshold than the real one
  const verdict = verifyOrgRootIntentManifest({ manifest: tampered });
  assert.equal(verdict.verdict, "REFUSED");
  assert.ok(verdict.failures.some((f) => f.name === "manifestHash"), "the recomputed hash no longer matches — the tamper is caught at the hash, before any semantic check even matters");
});
