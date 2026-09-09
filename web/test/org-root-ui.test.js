"use strict";

/*
 * web/org-root-ui.js — the v0.7 ON-CHAIN ORGANIZATIONAL ROOT web surface
 * (Wave 2, Track B-web; contract docs/postlaunch/v0.7-app-surface-contract.md).
 *
 * The server lane (Track B-server) builds the /org-roots routes in a
 * separate worktree, so this suite runs against FIXTURE responses shaped
 * exactly per the contract's ORG_ROOT / ORG_ROOT_REQUEST records — never
 * a live server. Everything funds-relevant this module touches (owner-set
 * well-formedness, the org-root intent manifest and its LOCAL
 * VERIFICATION, the signer-visible explanation, and the slot-signature
 * extraction/response envelope) is exercised through the REAL
 * web/core-bundle.js, using the REAL production-byte manifest fixtures
 * captured by sdk/tools/capture-v7-manifests.js
 * (core/explain/test/fixtures/v7-org-root-manifests.json) — the same
 * fixtures core/explain/test/org-root-explain.test.js pins.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const WEB_DIR = path.join(__dirname, "..");
const REPO = path.join(WEB_DIR, "..");
const core = require("../core-bundle.js");
const orgRootUiMod = require("../org-root-ui.js");
const ORG_ROOT_UI_SRC = fs.readFileSync(path.join(WEB_DIR, "org-root-ui.js"), "utf8");
const APP_V4 = fs.readFileSync(path.join(WEB_DIR, "app-v4.js"), "utf8");
const ONBOARDING = fs.readFileSync(path.join(WEB_DIR, "onboarding.js"), "utf8");

const FIXTURES = JSON.parse(fs.readFileSync(path.join(REPO, "core/explain/test/fixtures/v7-org-root-manifests.json"), "utf8"));
function manifestFixture(name) {
  const item = FIXTURES.manifests.find((m) => m.name === name);
  assert.ok(item, `fixture ${name} exists`);
  return item;
}

/* ==================== test doubles ==================== */

function fakeApi(overrides = {}) {
  const calls = [];
  const responses = new Map(Object.entries(overrides));
  return {
    calls,
    on(key, value) { responses.set(key, value); return this; },
    async getJSON(p) {
      calls.push({ method: "GET", path: p });
      const r = responses.get(`GET ${p}`);
      if (typeof r === "function") return r();
      if (r === undefined) throw Object.assign(new Error(`no fake response for GET ${p}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async postJSON(p, body) {
      calls.push({ method: "POST", path: p, body });
      const r = responses.get(`POST ${p}`);
      if (typeof r === "function") return r(body);
      if (r === undefined) throw Object.assign(new Error(`no fake response for POST ${p}`), { code: "FAKE_UNMAPPED" });
      return r;
    },
    async resolveXOnly(address) {
      calls.push({ method: "resolveXOnly", address });
      const map = overrides.__resolve || {};
      if (Object.prototype.hasOwnProperty.call(map, address)) return map[address];
      throw Object.assign(new Error(`address rejected: ${address}`), { code: "ADDRESS_INVALID" });
    }
  };
}

const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const OWNERS = { "kaspa:qown1": K(0x71), "kaspa:qown2": K(0x72), "kaspa:qown3": K(0x73), "kaspa:qfunder": K(0xf1) };

function mod(apiOverrides) {
  const api = fakeApi({ __resolve: OWNERS, ...apiOverrides });
  return { api, m: orgRootUiMod.createModule({ api, core }) };
}

function genesisForm(overrides = {}) {
  return {
    owners: [{ address: "kaspa:qown1", label: "Alice" }, { address: "kaspa:qown2", label: "Bob" }, { address: "kaspa:qown3", label: "Carol" }],
    ownerM: 2, emergencyK: 1, recoveryM: 1,
    recoveryDelayDaa: 1000, successionDelayDaa: 2000,
    successorAddress: "",
    rootValueKas: "10", rootMaxFeePerTxKas: "0.001",
    signerAddress: "kaspa:qfunder",
    ...overrides
  };
}

/* A fake unsigned/signed Safe JSON pair whose ONLY difference is input[0]'s
 * signatureScript — exactly the shape a real wallet round trip produces,
 * and exactly what core.orgRootSlotV7's extraction diffs against (the same
 * technique sdk/src/wallet-requests-v4.js collectApprovalV4 uses). */
/* The wallet payload (kaspa Safe JSON) derived from the manifest's FROZEN
 * transaction — since the UX-02 signing boundary, a payload that is not the
 * reviewed transaction is refused before the wallet, so the fixtures carry
 * the real bytes (STALE ASSUMPTION corrected: the old placeholder payload
 * was never the reviewed transaction). */
function safeJsonFromManifest(manifest, tamper) {
  const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
  const wire = (spk) => `${Number(spk.version || 0).toString(16).padStart(4, "0")}${spk.scriptHex}`;
  const safe = {
    id: manifest.transaction.txId, version: frozen.version,
    inputs: frozen.inputs.map((i) => ({ transactionId: i.previousOutpoint.transactionId, index: i.previousOutpoint.index, sequence: String(i.sequence ?? "0"), sigOpCount: 0, computeBudget: i.computeBudget ?? 0, signatureScript: "", utxo: { address: null, amount: String(i.utxo.amount), scriptPublicKey: wire(i.utxo.scriptPublicKey), blockDaaScore: String(i.utxo.blockDaaScore ?? "0"), isCoinbase: false, covenantId: i.utxo.covenantId ? String(i.utxo.covenantId) : null } })),
    outputs: frozen.outputs.map((o) => ({ value: String(o.value), scriptPublicKey: wire(o.scriptPublicKey), covenant: o.covenant ? { authorizingInput: Number(o.covenant.authorizingInput), covenantId: String(o.covenant.covenantId) } : null })),
    subnetworkId: frozen.subnetworkId, lockTime: String(frozen.lockTime ?? "0"), gas: "0", storageMass: "0", payload: ""
  };
  if (tamper) tamper(safe);
  return JSON.stringify(safe);
}
function fakeTxPair(manifest, sigByte) {
  const unsignedSafeJson = safeJsonFromManifest(manifest);
  const signed = JSON.parse(unsignedSafeJson);
  signed.inputs[0].signatureScript = `41${sigByte.toString(16).padStart(2, "0").repeat(64)}01`;
  return { unsignedSafeJson, signedSafeJson: JSON.stringify(signed) };
}
module.exports = { safeJsonFromManifest };

function slotEnvelopeFor(manifest, slotEntry, unsignedSafeJson, rootInputIndex = 0) {
  return {
    requestVersion: core.orgRootSlotV7.ORG_ROOT_SLOT_REQUEST_VERSION_1,
    requestId: "d".repeat(32),
    manifestHash: manifest.manifestHash,
    txId: manifest.transaction.txId,
    network: manifest.network.networkId,
    root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootInputIndex },
    slot: { number: slotEntry.slot, index: slotEntry.slot - 1, publicKey: slotEntry.publicKey },
    unsignedSafeJson,
    signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootInputIndex, sighashType: 1 }] },
    expiresAtMs: Date.now() + 100000
  };
}

/* ==================================================================
 * createModule guards
 * ================================================================== */

test("createModule: requires api.{getJSON,postJSON,resolveXOnly}", () => {
  assert.throws(() => orgRootUiMod.createModule({ api: { getJSON: async () => {}, postJSON: async () => {} }, core }), /requires api/);
  assert.throws(() => orgRootUiMod.createModule({ core }), /requires api/);
});

test("createModule: requires the v0.7 core bundle closure", () => {
  const { api } = mod();
  assert.throws(() => orgRootUiMod.createModule({ api, core: {} }), /requires the v0\.7 core bundle/);
  assert.throws(() => orgRootUiMod.createModule({ api }), /requires the v0\.7 core bundle/);
});

/* ==================================================================
 * (a)/(b) WIZARD normalization + "EXACT ROOT POLICY BEFORE SIGNING"
 * ================================================================== */

test("normalizeWizardGenesis: well-formed owner set resolves addresses and normalizes through the real core", async () => {
  const { m } = mod();
  const norm = await m.normalizeWizardGenesis(genesisForm());
  assert.equal(norm.ownerSet.activeCount, 3);
  assert.equal(norm.ownerSet.ownerM, 2n);
  assert.equal(norm.ownerSet.emergencyK, 1n);
  assert.equal(norm.ownerSet.recoveryM, 1n);
  assert.equal(norm.body.owners.length, 3);
  assert.deepEqual(norm.body.owners.map((o) => o.slot), [1, 2, 3]);
});

test("normalizeWizardGenesis: a duplicate owner key is refused OWNER_SET_ILL_FORMED, BEFORE any POST", async () => {
  const { api, m } = mod({ __resolve: { ...OWNERS, "kaspa:qown2": OWNERS["kaspa:qown1"] } });
  await assert.rejects(
    () => m.normalizeWizardGenesis(genesisForm()),
    (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); assert.match(e.message, /distinct|DUPLICATE_OWNER_KEY/); return true; }
  );
  assert.ok(!api.calls.some((c) => c.method === "POST"), "no network write happened before the local refusal");
});

test("normalizeWizardGenesis: M above the active owner count is refused locally", async () => {
  const { m } = mod();
  await assert.rejects(() => m.normalizeWizardGenesis(genesisForm({ ownerM: 5 })), (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; });
});

test("normalizeWizardGenesis: an empty owner list is refused before any address resolution", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.normalizeWizardGenesis(genesisForm({ owners: [] })), (e) => { assert.equal(e.code, "OWNER_SET_ILL_FORMED"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "resolveXOnly").length, 0);
});

test("normalizeWizardGenesis: a floating-point-looking KAS amount never reaches Number() arithmetic — the canonical parser rejects garbage", async () => {
  const { m } = mod();
  await assert.rejects(() => m.normalizeWizardGenesis(genesisForm({ rootValueKas: "1e10" })));
  await assert.rejects(() => m.normalizeWizardGenesis(genesisForm({ rootValueKas: "NaN" })));
  await assert.rejects(() => m.normalizeWizardGenesis(genesisForm({ rootValueKas: "-1" })));
});

test('renderGenesisPolicyPanelHtml: "EXACT ROOT POLICY BEFORE SIGNING", full untruncated keys, real thresholds', async () => {
  const { m } = mod();
  const norm = await m.normalizeWizardGenesis(genesisForm());
  const html = m.renderGenesisPolicyPanelHtml(norm);
  assert.match(html, /EXACT ROOT POLICY BEFORE SIGNING/);
  for (const k of Object.values(OWNERS).slice(0, 3)) assert.ok(html.includes(k), `full key ${k} appears untruncated`);
  assert.match(html, /Required for AUTHORIZE.*: 2 of 3/);
  assert.match(html, /Required for emergency FREEZE.*: 1 of 3/);
  assert.match(html, /Recovery delay: 1000 DAA score/);
  assert.match(html, /Succession delay: 2000 DAA score/);
  assert.match(html, /succession DISABLED/);
  assert.match(html, /Root value: 10 KAS/);
});

test("createGenesisRequest: POSTs the exact contract §2 body shape to /org-roots", async () => {
  const { api, m } = mod({ "POST /org-roots": (body) => ({ request: { id: "req1", rootCovenantId: "r".repeat(64), kind: "rootGenesis", ...body } }) });
  const created = await m.createGenesisRequest(genesisForm());
  const call = api.calls.find((c) => c.path === "/org-roots");
  assert.ok(call, "POST /org-roots was called");
  assert.equal(call.body.ownerM, 2);
  assert.equal(call.body.signerAddress, "kaspa:qfunder");
  assert.equal(created.request.kind, "rootGenesis");
});

/* ==================================================================
 * (d) SLOT SIGNING — own slot only, through the pinned core
 * ================================================================== */

test("signOwnSlot: a real production-byte manifest, own slot, mock adapter -> a valid response envelope", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xbb);
  const envelope = slotEnvelopeFor(manifest, slots[0], unsignedSafeJson);
  const { m } = mod();
  let adapterCalledWith = null;
  const adapter = { signInputs: async (u, list, opts) => { adapterCalledWith = { u, list, opts }; return signedSafeJson; } };

  const response = await m.signOwnSlot({
    request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter,
    connectedXOnly: slots[0].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner1"
  });

  assert.equal(response.slot.number, slots[0].slot);
  assert.equal(response.signatureHex.length, 130);
  assert.ok(response.signatureHex.endsWith("01"));
  assert.ok(adapterCalledWith, "the adapter was invoked exactly once");
  assert.deepEqual(adapterCalledWith.list, [{ index: 0, sighashType: 1 }]);
  assert.equal(adapterCalledWith.opts.expectedSignerAddress, "kaspa:qowner1");
});

test("signOwnSlot: FOREIGN-SLOT attempt is refused BEFORE the wallet is ever invoked", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xbb);
  const envelope = slotEnvelopeFor(manifest, slots[0], unsignedSafeJson);
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return signedSafeJson; } };

  await assert.rejects(
    () => m.signOwnSlot({
      request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter,
      connectedXOnly: slots[1].publicKey /* a DIFFERENT owner's key */, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner2"
    }),
    (e) => { assert.equal(e.code, "NOT_AN_ACTIVE_SLOT"); assert.match(e.message, /ONLY their own slot/); return true; }
  );
  assert.equal(adapterInvoked, false, "the wallet must never be invoked for a slot this identity does not hold");
});

test("signOwnSlot: a TAMPERED manifest fails local re-verification and the wallet is never invoked", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const tampered = { ...fx.manifest, manifestHash: "0".repeat(64) }; // hash no longer matches the content
  const slots = fx.manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(fx.manifest, 0xbb);
  const envelope = slotEnvelopeFor(fx.manifest, slots[0], unsignedSafeJson);
  const { m } = mod();
  let adapterInvoked = false;
  const adapter = { signInputs: async () => { adapterInvoked = true; return signedSafeJson; } };

  await assert.rejects(
    () => m.signOwnSlot({ request: { manifest: tampered, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter, connectedXOnly: slots[0].publicKey, network: fx.manifest.network.networkId, expectedSignerAddress: "kaspa:qowner1" }),
    (e) => { assert.equal(e.code, "RESPONSE_BINDING_MISMATCH"); return true; }
  );
  assert.equal(adapterInvoked, false);
});

test("signOwnSlot: succession takes no owner slot — refuses closed rather than fabricating one", async () => {
  const fx = manifestFixture("root_succession");
  assert.equal(fx.manifest.action.expectedSignerSlots.length, 0);
});

/* ==================================================================
 * envelope import validation
 * ================================================================== */

function requestRecordFor(manifest, slotStates) {
  return {
    manifestHash: manifest.manifestHash,
    slots: slotStates.map((status, i) => ({ slot: i + 1, publicKey: manifest.action.expectedSignerSlots[i].publicKey, status }))
  };
}

test("validateImportedEnvelope: a genuinely signed envelope round-trips as valid", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xcc);
  const envelope = slotEnvelopeFor(manifest, slots[1], unsignedSafeJson);
  const { m } = mod();
  const adapter = { signInputs: async () => signedSafeJson };
  const response = await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter, connectedXOnly: slots[1].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner2" });

  const request = requestRecordFor(manifest, ["PENDING", "PENDING", "PENDING"]);
  const v = m.validateImportedEnvelope(request, JSON.stringify(response));
  assert.equal(v.ok, true);
  assert.equal(v.slot, 2);
});

test("validateImportedEnvelope: malformed JSON is refused, closed", () => {
  const { m } = mod();
  const v = m.validateImportedEnvelope({ manifestHash: "a".repeat(64), slots: [] }, "{not json");
  assert.equal(v.ok, false);
  assert.equal(v.code, "RESPONSE_BINDING_MISMATCH");
});

test("validateImportedEnvelope: an envelope for a DIFFERENT manifest is refused", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xdd);
  const envelope = slotEnvelopeFor(manifest, slots[0], unsignedSafeJson);
  const { m } = mod();
  const adapter = { signInputs: async () => signedSafeJson };
  const response = await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter, connectedXOnly: slots[0].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner1" });

  const otherRequest = requestRecordFor(manifest, ["PENDING", "PENDING", "PENDING"]);
  otherRequest.manifestHash = "f".repeat(64); // a different request
  const v = m.validateImportedEnvelope(otherRequest, JSON.stringify(response));
  assert.equal(v.ok, false);
  assert.equal(v.code, "RESPONSE_BINDING_MISMATCH");
});

test("validateImportedEnvelope: a slot that already signed refuses a second import (DUPLICATE_SLOT_SIGNATURE)", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xee);
  const envelope = slotEnvelopeFor(manifest, slots[0], unsignedSafeJson);
  const { m } = mod();
  const adapter = { signInputs: async () => signedSafeJson };
  const response = await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter, connectedXOnly: slots[0].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner1" });

  const request = requestRecordFor(manifest, ["SIGNED", "PENDING", "PENDING"]);
  const v = m.validateImportedEnvelope(request, JSON.stringify(response));
  assert.equal(v.ok, false);
  assert.equal(v.code, "DUPLICATE_SLOT_SIGNATURE");
});

/* ==================================================================
 * finalize gating — a UI convenience, never the security boundary
 * ================================================================== */

test("finalizeGate: present < required -> disabled, with a reason naming both numbers", () => {
  const { m } = mod();
  const g = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 1, requiredApprovals: 2, manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "PENDING" }] });
  assert.equal(g.enabled, false);
  assert.match(g.reason, /1 of 2/);
});

test("finalizeGate: present >= required -> enabled", () => {
  const { m } = mod();
  assert.equal(m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: 2, manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "SIGNED" }] }).enabled, true);
  // STALE ASSUMPTION corrected after the rc15 internal review (F-01): a SIGNED
  // request is ALREADY finalized — offering Finalize again consumed a wallet
  // signature on a pre-detectable conflict. The gate is now stricter, never looser.
  const signed = m.finalizeGate({ state: "SIGNED", signaturesPresent: 3, requiredApprovals: 2, manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "SIGNED" }, { slot: 3, status: "SIGNED" }] });
  assert.equal(signed.enabled, false);
  assert.match(signed.reason, /already finalized/);
});

test("rc19 review R4-08: the quorum comes from the VERIFIED manifest — a server record claiming a lower or zero quorum never enables finalize; no manifest, no finalize", () => {
  const { m } = mod();
  const slots2 = [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "SIGNED" }];
  const lied = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: "0", manifest: { action: { requiredApprovals: "2" } }, slots: slots2 });
  assert.equal(lied.enabled, false, "a server record that disagrees with the verified manifest never enables, even at quorum"); assert.match(lied.reason, /disagrees with the verified manifest/);
  const dis = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 1, requiredApprovals: "0", manifest: { action: { requiredApprovals: "2" } }, slots: [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "PENDING" }] });
  assert.equal(dis.enabled, false); assert.match(dis.reason, /disagrees with the verified manifest/);
  const zero = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 0, requiredApprovals: "0", manifest: { action: { requiredApprovals: "0" } }, slots: [{ slot: 1, status: "PENDING" }] });
  assert.equal(zero.enabled, false); assert.match(zero.reason, /zero-approval quorum/);
  const none = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: 2, slots: slots2 });
  assert.equal(none.enabled, false); assert.match(none.reason, /no verified quorum/);
  // rc21 review R6-07: coerced array / number quorums never enable
  for (const q of [["2"], 2, { toString: () => "2" }]) assert.equal(m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: "2", manifest: { action: { requiredApprovals: q } }, slots: slots2 }).enabled, false, JSON.stringify(q));
  assert.equal(m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: ["2"], manifest: { action: { requiredApprovals: "2" } }, slots: slots2 }).enabled, false, "server array quorum");
});

test("finalizeGate: a request not in AUTHORIZED/SIGNED state is never offered finalize regardless of counts", () => {
  const { m } = mod();
  assert.equal(m.finalizeGate({ state: "BROADCAST", signaturesPresent: 5, requiredApprovals: 2 }).enabled, false);
  assert.equal(m.finalizeGate(null).enabled, false);
});

test("finalizeRequest: refuses to POST when the gate is not met (never trusts a caller to have checked)", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.finalizeRequest("root1", "req1", { state: "AUTHORIZED", signaturesPresent: 0, requiredApprovals: 2 }));
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

test("submitRequest: refuses to POST unless the request is SIGNED", async () => {
  const { api, m } = mod();
  await assert.rejects(() => m.submitRequest("root1", "req1", { state: "AUTHORIZED" }));
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

/* ==================================================================
 * (d) PENDING IS NOT SUCCESS — the v0.7 request outcome ladder
 * ================================================================== */

test("requestOutcome: EXACTLY CHAIN_VERIFIED and VERIFIED_OUTCOME are verified — every other named state is pending or failed", () => {
  const { m } = mod();
  const verified = ["CHAIN_VERIFIED", "VERIFIED_OUTCOME"];
  const notVerified = ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "REFUSED", "FAILED"];
  for (const s of verified) assert.equal(m.isVerifiedRequestOutcome(s), true, s);
  for (const s of notVerified) assert.equal(m.isVerifiedRequestOutcome(s), false, s);
});

test("requestOutcome: an UNKNOWN state fails closed to pending, never success", () => {
  const { m } = mod();
  assert.equal(m.isVerifiedRequestOutcome("SOME_FUTURE_STATE_NOBODY_WROTE_YET"), false);
  assert.equal(m.requestOutcome(undefined).level, "pending");
  assert.equal(m.requestOutcome(null).level, "pending");
});

test("requestOutcome: REFUSED and FAILED are level failed, never pending or verified", () => {
  const { m } = mod();
  assert.equal(m.requestOutcome("REFUSED").level, "failed");
  assert.equal(m.requestOutcome("FAILED").level, "failed");
});

test("requestOutcome: v0.7 SIGNED (quorum met, not finalized) is NOT the v0.4 SIGNED meaning — kept as a separate closed table", () => {
  const { m } = mod();
  const RX = require("../refusal-explain.js");
  const v7 = m.requestOutcome("SIGNED");
  const v4 = RX.outcome("SIGNED");
  assert.equal(v7.level, "pending");
  assert.equal(v4.level, "pending");
  assert.notEqual(v7.meaning, v4.meaning, "the two SIGNED meanings must not silently collide in one shared table");
});

test("renderRequestDetailHtml: every rendered state is described as NOT proof unless it is CHAIN_VERIFIED/VERIFIED_OUTCOME", () => {
  const { m } = mod();
  for (const state of ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN"]) {
    const html = m.renderRequestDetailHtml({ id: "r1", kind: "rootAction", action: "authorize", slots: [], state, signaturesPresent: 0, requiredApprovals: 1 });
    assert.ok(!/level: "verified"/.test(html));
  }
  const okHtml = m.renderRequestDetailHtml({ id: "r1", kind: "rootAction", action: "authorize", slots: [], state: "CHAIN_VERIFIED", signaturesPresent: 2, requiredApprovals: 2 });
  assert.match(okHtml, /Chain-verified/);
});

/* ==================================================================
 * (f) DANGEROUS ACTIONS — typed confirmation
 * ================================================================== */

test("isDangerousAction: exactly ownerRecover, succession, rotate, unfreeze — never authorize/freeze", () => {
  const { m } = mod();
  for (const a of ["ownerRecover", "succession", "rotate", "unfreeze"]) assert.equal(m.isDangerousAction(a), true, a);
  for (const a of ["authorize", "freeze"]) assert.equal(m.isDangerousAction(a), false, a);
});

test("typedConfirmationMatches: requires the EXACT phrase — no partial, no case-insensitive shortcut beyond exact trim", () => {
  const { m } = mod();
  assert.equal(m.typedConfirmationMatches("rotate", "CONFIRM ROTATE"), true);
  assert.equal(m.typedConfirmationMatches("rotate", " CONFIRM ROTATE "), true, "surrounding whitespace is trimmed");
  assert.equal(m.typedConfirmationMatches("rotate", "confirm rotate"), false);
  assert.equal(m.typedConfirmationMatches("rotate", "CONFIRM"), false);
  assert.equal(m.typedConfirmationMatches("rotate", ""), false);
});

test("renderDangerousConfirmHtml: ownerRecover/succession state LANDS FROZEN, the relative delay, and the heartbeat AUTHORIZE mitigation", () => {
  const { m } = mod();
  for (const action of ["ownerRecover", "succession"]) {
    const html = m.renderDangerousConfirmHtml({ action, rootLabel: "Acme Treasury", delayDaa: 5000 });
    assert.match(html, /LANDS FROZEN|lands the root FROZEN/i, action);
    assert.match(html, /RELATIVE|relative input age/i, action);
    assert.match(html, /heartbeat AUTHORIZE/i, action);
    assert.match(html, new RegExp(m.dangerousConfirmPhrase(action)), action);
  }
});

test("renderDangerousConfirmHtml: rotate/unfreeze also demand the typed phrase and state what changes", () => {
  const { m } = mod();
  const rotate = m.renderDangerousConfirmHtml({ action: "rotate", rootLabel: "Acme" });
  assert.match(rotate, /owner set of this organization CHANGES|installs a new set/i);
  assert.match(rotate, new RegExp(m.dangerousConfirmPhrase("rotate")));
  const unfreeze = m.renderDangerousConfirmHtml({ action: "unfreeze", rootLabel: "Acme" });
  assert.match(unfreeze, new RegExp(m.dangerousConfirmPhrase("unfreeze")));
});

test("createRootRequest: ROOT_FROZEN refuses locally BEFORE any network call for an action that requires unfrozen", async () => {
  const { api, m } = mod();
  const frozenRoot = { rootCovenantId: "r".repeat(64), state: { frozen: 1 }, pendingRequestId: null };
  await assert.rejects(() => m.createRootRequest(frozenRoot, { action: "authorize", params: {}, signerAddress: "kaspa:qown1" }), (e) => { assert.equal(e.code, "ROOT_FROZEN"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

test("createRootRequest: rotate is still permitted while frozen (key rotation must remain possible before unfreezing)", async () => {
  const { m } = mod({ "POST /org-roots/r/requests": (b) => ({ request: { id: "req1", ...b } }) });
  const frozenRoot = { rootCovenantId: "r", state: { frozen: 1 }, pendingRequestId: null };
  const req = await m.createRootRequest(frozenRoot, { action: "rotate", params: {}, signerAddress: "kaspa:qown1" });
  assert.equal(req.id, "req1");
});

test("createRootRequest: ROOT_PENDING_REQUEST refuses locally when a request is already pending", async () => {
  const { api, m } = mod();
  const root = { rootCovenantId: "r".repeat(64), state: { frozen: 0 }, pendingRequestId: "already-open" };
  await assert.rejects(() => m.createRootRequest(root, { action: "authorize", params: {}, signerAddress: "kaspa:qown1" }), (e) => { assert.equal(e.code, "ROOT_PENDING_REQUEST"); return true; });
  assert.equal(api.calls.filter((c) => c.method === "POST").length, 0);
});

/* ==================================================================
 * (c) request review, rendered from the REAL org-root-explain lines
 * ================================================================== */

test("renderRequestReviewHtml: a VERIFIED manifest renders the core's own fixed explanation lines verbatim", () => {
  const { m } = mod();
  const fx = manifestFixture("root_authorize_2of3");
  const html = m.renderRequestReviewHtml({ manifest: fx.manifest });
  assert.match(html, /VERIFIED — EXACT ROOT POLICY BEFORE SIGNING/);
  assert.match(html, new RegExp(fx.manifest.manifestHash));
  // every fixed line from the real core renderer appears verbatim
  const lines = core.orgRootExplain.humanReadable({ manifest: fx.manifest });
  for (const line of lines) assert.ok(html.includes(escapeForHtmlCheck(line)), `line present: ${line.slice(0, 60)}`);
});

function escapeForHtmlCheck(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

test("renderRequestReviewHtml: no manifest -> DO NOT SIGN, never a normal review", () => {
  const { m } = mod();
  const html = m.renderRequestReviewHtml({});
  assert.match(html, /Do not sign|DO NOT SIGN/i);
});

/* ==================================================================
 * ARIA live regions on the new status surfaces
 * ================================================================== */

test("ARIA: renderRootDetailHtml/renderRequestReviewHtml/renderRequestDetailHtml/renderDangerousConfirmHtml each carry a live-region status surface", async () => {
  const { m } = mod();
  const rootDetailHtml = m.renderRootDetailHtml({ rootCovenantId: "r".repeat(64), label: "Acme", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1", rootNonce: "0" }, slots: [], generation: 0, pendingRequestId: null, live: null });
  const fx = manifestFixture("root_authorize_2of3");
  const reviewHtml = m.renderRequestReviewHtml({ manifest: fx.manifest });
  const detailHtml = m.renderRequestDetailHtml({ id: "r1", kind: "rootAction", action: "authorize", slots: [], state: "AUTHORIZED", signaturesPresent: 0, requiredApprovals: 2 });
  const dangerHtml = m.renderDangerousConfirmHtml({ action: "rotate", rootLabel: "Acme" });
  for (const [name, html] of [["renderRootDetailHtml", rootDetailHtml], ["renderRequestReviewHtml", reviewHtml], ["renderRequestDetailHtml", detailHtml], ["renderDangerousConfirmHtml", dangerHtml]]) {
    assert.match(html, /role="status"/, name);
    assert.match(html, /aria-live="polite"/, name);
    assert.match(html, /aria-atomic="true"/, name);
  }
});

/* ==================================================================
 * 375px layout — reuses the app's EXISTING global responsive rules
 * (web/index.html's @media block + .mtable), never introduces new
 * ad-hoc wide/fixed-width markup.
 * ================================================================== */

test("375px: every table this module renders uses the app's existing .mtable scroll container, never a bare <table>", () => {
  const { m } = mod();
  const rootDetailHtml = m.renderRootDetailHtml({
    rootCovenantId: "r".repeat(64), label: "Acme",
    state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1", rootNonce: "0" },
    slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1", label: "Alice" }],
    generation: 0, pendingRequestId: null, live: null
  });
  const detailHtml = m.renderRequestDetailHtml({ id: "r1", kind: "rootAction", action: "authorize", slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1", status: "PENDING" }], state: "AUTHORIZED", signaturesPresent: 0, requiredApprovals: 2 });
  for (const html of [rootDetailHtml, detailHtml]) {
    const tables = [...html.matchAll(/<table[^>]*>/g)];
    assert.ok(tables.length > 0, "at least one table rendered");
    for (const t of tables) assert.match(t[0], /class="mtable"/, `every <table> carries class="mtable": ${t[0]}`);
  }
});

test("375px: no fixed pixel width over 375 is hardcoded in this module's own markup", () => {
  // widths this module sets are max-width style hints on modal cards
  // (wired in app-v4.js, not here) — org-root-ui.js itself sets no
  // fixed pixel width at all.
  assert.ok(!/width:\s*\d{3,}px/.test(ORG_ROOT_UI_SRC), "no hardcoded 3+-digit pixel width in web/org-root-ui.js");
});

/* ==================================================================
 * keyboard focus order — only native focusable elements, no custom
 * tabindex traps; relies on index.html's existing global :focus-visible
 * rule (pinned by web/test/flagship-ux-responsive.test.js), never a
 * bespoke one.
 * ================================================================== */

test("keyboard focus: this module renders only native interactive elements (button/input/textarea), never a tabindex trap", () => {
  const { m } = mod();
  const rootDetailHtml = m.renderRootDetailHtml({ rootCovenantId: "r".repeat(64), label: "Acme", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1", rootNonce: "0" }, slots: [], generation: 0, pendingRequestId: null, live: null });
  const dangerHtml = m.renderDangerousConfirmHtml({ action: "rotate", rootLabel: "Acme" });
  for (const html of [rootDetailHtml, dangerHtml]) {
    assert.ok(!/tabindex="-1"/.test(html), "no interactive element is pulled out of tab order");
    assert.ok(!/<div[^>]*onclick=/.test(html), "no click-only div masquerading as a control");
  }
});

/* ==================================================================
 * reduced motion — this module carries no CSS/animation of its own
 * ================================================================== */

test("reduced motion: web/org-root-ui.js defines no <style>, @keyframes, or inline CSS animation/transition of its own", () => {
  assert.ok(!/<style/i.test(ORG_ROOT_UI_SRC));
  assert.ok(!/@keyframes/.test(ORG_ROOT_UI_SRC));
  // scoped to actual inline style="" attribute values (not prose like
  // "per transition:" in a KAS-fee sentence)
  assert.ok(!/style="[^"]*\b(animation|transition)\s*:/.test(ORG_ROOT_UI_SRC));
});

/* ==================================================================
 * truthfulness — claim discipline (owner's standing rules) + the
 * hosted-org / on-chain-root distinction (contract §0)
 * ================================================================== */

const FORBIDDEN_CLAIMS = [
  /\baudited\b/i, /\bcertified\b/i, /\bcompliant\b/i, /\bindependently reviewed\b/i,
  /\bindustry standard\b/i, /\binstitutional[- ]grade\b/i, /\bfully decentrali[sz]ed\b/i,
  /\btrustless stablecoin\b/i, /\bproduction verified\b/i, /\bno alternative\b/i
];

test("truthfulness: web/org-root-ui.js never claims audited/certified/compliant/institutional-grade/etc.", () => {
  for (const re of FORBIDDEN_CLAIMS) assert.ok(!re.test(ORG_ROOT_UI_SRC), `must not match ${re}`);
});

test("truthfulness: hosted-organization language in this module always denies on-chain authority", () => {
  const html = orgRootUiMod.createModule({ api: fakeApi({ __resolve: OWNERS }), core }).renderOnChainRootSummaryHtml([]);
  assert.match(html, /On-chain organizational root \(covenant-enforced M-of-N\)/);
  assert.match(html, /Legacy vaults keep exactly ONE on-chain owner key and are never presented as M-of-N/);
});

test("truthfulness: the ownerOp / root-detail rendering never implies the ROOT is a legacy single-owner vault", () => {
  const { m } = mod();
  const html = m.renderRootDetailHtml({ rootCovenantId: "r".repeat(64), label: "Acme", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1", rootNonce: "0" }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1" }], generation: 0, pendingRequestId: null, live: null });
  assert.match(html, /ON_CHAIN_ORGANIZATIONAL_ROOT/);
  assert.ok(!/single[- ]owner/i.test(html));
});

test("truthfulness: rootedVaultOwnerOps rendering never offers a single-owner-signature button on a rooted vault", () => {
  const { m } = mod();
  const html = m.renderRootedVaultOwnerOpsHtml({ vaultId: "v1" }, { rootCovenantId: "r1" });
  assert.match(html, /ROOT REQUESTS, never a single-owner signature/);
  assert.ok(!/data-ownersign/i.test(html), "no legacy v0.4-style single-owner signing hook");
});

/* ---------------- app-v4.js / onboarding.js integration ---------------- */

test("app-v4.js: the Organizations view carries both required section headers verbatim", () => {
  assert.match(APP_V4, /Hosted organization \(grouping &amp;? ?roles.*no on-chain authority\)/);
  assert.match(APP_V4, /orgRootUI\(\)/);
  assert.match(APP_V4, /renderOnChainRootSummaryHtml/);
});

test("app-v4.js: orgRootUI() degrades to null when window.PolicyVaultOrgRootUI or the v0.7 core closure is absent (never throws)", () => {
  assert.match(APP_V4, /window\.PolicyVaultOrgRootUI\s*&&\s*window\.PolicyVaultCore\s*&&\s*window\.PolicyVaultCore\.ownerSetV7/);
});

test("onboarding.js: explains the on-chain organizational root truthfully and distinguishes it from a hosted organization", () => {
  assert.match(ONBOARDING, /ON-CHAIN ORGANIZATIONAL ROOT/);
  assert.match(ONBOARDING, /real M-of-N owner quorum/);
  assert.match(ONBOARDING, /application metadata only and is NOT that/);
});

/* ---------------- refusal-explain.js closed table for v0.7 ---------------- */

test("refusal-explain.js: every contract-closed v0.7 code has a title/meaning/next with no override offered", () => {
  const RX = require("../refusal-explain.js");
  const V7_CODES = orgRootUiMod.createModule({ api: fakeApi({ __resolve: OWNERS }), core }).V7_REFUSAL_CODES;
  for (const code of V7_CODES) {
    const e = RX.explain(code);
    assert.ok(e, `refusal-explain.js explains ${code}`);
    assert.ok(e.title && e.meaning && e.next.length, code);
  }
});

test("displayCodeFor: maps the pinned core's granular reasons onto the contract's closed vocabulary", () => {
  const { m } = mod();
  assert.equal(m.displayCodeFor({ code: "DUPLICATE_OWNER_KEY" }), "OWNER_SET_ILL_FORMED");
  assert.equal(m.displayCodeFor({ code: "SLOT_INACTIVE" }), "NOT_AN_ACTIVE_SLOT");
  assert.equal(m.displayCodeFor({ code: "DUPLICATE_SLOT" }), "DUPLICATE_SLOT_SIGNATURE");
  assert.equal(m.displayCodeFor({ code: "UNDER_QUORUM" }), "UNDER_QUORUM");
  assert.equal(m.displayCodeFor({ code: "ROOT_FROZEN" }), "ROOT_FROZEN");
  assert.equal(m.displayCodeFor({}), "UNKNOWN");
  assert.equal(m.displayCodeFor(null), "UNKNOWN");
});

test("rc16 review N-02: a still-PENDING owner slot on a request that is no longer AUTHORIZED is NEVER asked to sign — signOwnSlot refuses before the wallet, the detail text says no further approval is collected; AUTHORIZED still works", async () => {
  const fx = manifestFixture("root_authorize_2of3");
  const manifest = fx.manifest;
  const slots = manifest.action.expectedSignerSlots;
  const { unsignedSafeJson, signedSafeJson } = fakeTxPair(manifest, 0xbb);
  const envelope = slotEnvelopeFor(manifest, slots[2], unsignedSafeJson);
  const { m } = mod();
  for (const st of ["SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "REFUSED", "FAILED", undefined]) {
    let invoked = 0;
    const adapter = { signInputs: async () => { invoked++; return signedSafeJson; } };
    await assert.rejects(
      () => m.signOwnSlot({ request: { manifest, state: st }, slotEnvelope: envelope, adapter, connectedXOnly: slots[2].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner3" }),
      (e) => e.code === "REQUEST_NOT_SIGNABLE" && /only collected while it is AUTHORIZED/.test(e.message),
      `state ${st}`
    );
    assert.equal(invoked, 0, `wallet not invoked on ${st}`);
  }
  const req = { id: "q1", kind: "rootAction", action: "authorize", state: "SIGNED", signaturesPresent: 2, requiredApprovals: 2, createdBy: "kaspa:qowner1", rootInputIndex: 0, manifest,
    slots: [{ slot: 1, publicKey: slots[0].publicKey, status: "SIGNED" }, { slot: 2, publicKey: slots[1].publicKey, status: "SIGNED" }, { slot: 3, publicKey: slots[2].publicKey, status: "PENDING" }] };
  const html = m.renderRequestDetailHtml(req, { viewerXOnly: slots[2].publicKey, viewerAddress: "kaspa:qowner3" });
  const role = (html.match(/Your role<\/div><div class="rv-v">([^<]*)/) || [])[1] || "";
  assert.doesNotMatch(role, /your approval is needed/);
  assert.match(role, /no further approval is collected — the request is already finalized/);
  const roleOpen = (m.renderRequestDetailHtml({ ...req, state: "AUTHORIZED", signaturesPresent: 1 }, { viewerXOnly: slots[2].publicKey, viewerAddress: "kaspa:qowner3" }).match(/Your role<\/div><div class="rv-v">([^<]*)/) || [])[1] || "";
  assert.match(roleOpen, /your approval is needed/);
  let invokedA = 0;
  const adapterA = { signInputs: async () => { invokedA++; return signedSafeJson; } };
  const response = await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelope, adapter: adapterA, connectedXOnly: slots[2].publicKey, network: manifest.network.networkId, expectedSignerAddress: "kaspa:qowner3" });
  assert.equal(invokedA, 1);
  assert.equal(response.slot.number, slots[2].slot);
});


/* ---------------- Codex checkpoint 6 (UX-09): SUCCESSION requests are described by their own action ---------------- */
test("Codex checkpoint 6 (UX-09): a succession request (no owner slots, required 1, 0 owner signatures) is rendered by its SUCCESSOR-signature role and state — the successor is never read-only or told to collect owner approvals; other viewers get no owner-approval guidance; no Finalize control; SIGNED offers Submit", () => {
  const fx = manifestFixture("root_succession");
  const manifest = fx.manifest;
  const successor = manifest.root.template.successorPk;
  const orgRoot = { rootCovenantId: manifest.root.covenantId, template: { ...manifest.root.template }, slots: [], live: { outpoint: manifest.root.outpoint, blockDaaScore: "1000000" } };
  const { m } = mod();
  const base = { id: "sx1", rootCovenantId: manifest.root.covenantId, kind: "rootAction", action: "succession", actionClass: "AUTHORITY-EXPANDING", state: "AUTHORIZED", signaturesPresent: 0, requiredApprovals: "1", manifest, slots: [], createdBy: "kaspatest:qsucc", rootInputIndex: 0, transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }] } };
  const other = K(0x72);
  for (const [label, state] of [["authorized (fresh)", "AUTHORIZED"], ["authorized (reopened after a wallet rejection)", "AUTHORIZED"]]) {
    const html = m.renderRequestDetailHtml({ ...base, state }, { orgRoot, viewerXOnly: successor, viewerAddress: "kaspatest:qsucc", currentDaa: "1000500" });
    assert.doesNotMatch(html, /read-only/, `${label}: the successor is never read-only`);
    assert.doesNotMatch(html, /Collect \d+ more owner approval/, `${label}: no owner-approval collection`);
    assert.doesNotMatch(html, /0 of 1 collected/, `${label}: no slot count`);
    assert.match(html, /You are the designated successor: this succession is authorized by YOUR signature alone/, label);
    assert.match(html, /not yet signed by the designated successor — no owner approvals are collected for a succession/, label);
    assert.match(html, /Authorized — awaiting the designated successor's signature/, label);
    assert.match(html, /Approve in wallet \(designated successor\): your wallet signs the root input and your own fee input/, label);
    assert.match(html, /succession waiting period/, label);
    assert.doesNotMatch(html, /data-rootfinalize/, `${label}: a succession is never "finalized" by a fee payer`);
    assert.match(html, /<button disabled data-rootsubmit="sx1"/, `${label}: submit waits for the signature`);
    assert.match(html, /data-rootreject="sx1"/, `${label}: withdraw offered while unsigned`);
    assert.match(html, /Waiting condition[^]*Succession/, `${label}: the age gate is stated`);
    const viewer = m.renderRequestDetailHtml({ ...base, state }, { orgRoot, viewerXOnly: other, viewerAddress: "kaspatest:qown2", currentDaa: "1000500" });
    assert.doesNotMatch(viewer, /Collect \d+ more owner approval/, `${label}: another viewer gets no owner-approval guidance`);
    assert.doesNotMatch(viewer, /your approval is needed/, label);
    assert.match(viewer, /authorized by the designated successor's signature alone \(key 7f7f/, label);
    assert.match(viewer, /Waiting for the designated successor to sign in their wallet — no owner approval is needed or collected/, label);
    assert.doesNotMatch(viewer, /data-rootfinalize/, label);
    const nobody = m.renderRequestDetailHtml({ ...base, state }, { orgRoot, viewerXOnly: null, currentDaa: null });
    assert.doesNotMatch(nobody, /Collect \d+ more owner approval/, `${label}: no identity => still no owner-approval guidance`);
  }
  const signed = m.renderRequestDetailHtml({ ...base, state: "SIGNED", signaturesPresent: 0 }, { orgRoot, viewerXOnly: successor, viewerAddress: "kaspatest:qsucc" });
  assert.match(signed, /Signed by the successor — NOT yet broadcast/);
  assert.match(signed, /You are the designated successor and have signed this succession/);
  assert.match(signed, /signed by the designated successor \(one signature: the root input and the successor's fee input\)/);
  assert.match(signed, /Signed by the designated successor and assembled — submit it to the network/);
  assert.doesNotMatch(signed, /0 of 1 collected|read-only|Collect \d+ more/);
  assert.match(signed, /<button data-rootsubmit="sx1" class="primary">/, "SIGNED offers Submit");
  assert.doesNotMatch(signed, /data-rootfinalize/);
  const signedOther = m.renderRequestDetailHtml({ ...base, state: "SIGNED" }, { orgRoot, viewerXOnly: other });
  assert.match(signedOther, /this wallet is not the successor and only reads it/);
  assert.match(signedOther, /<button data-rootsubmit="sx1"/, "anyone may submit a signed succession");
  const verified = m.renderRequestDetailHtml({ ...base, state: "CHAIN_VERIFIED", chain: { predecessorOutpoint: "p:0", successorOutpoint: "s:0" } }, { orgRoot, viewerXOnly: successor });
  assert.match(verified, /Chain-verified/); assert.match(verified, /Complete — verified on the chain/); assert.doesNotMatch(verified, /data-rootreject/);
  /* the closed tables */
  assert.equal(m.successionOutcome("AUTHORIZED").title, "Authorized — awaiting the designated successor's signature");
  assert.equal(m.successionOutcome("SIGNED").level, "pending");
  assert.equal(m.successionOutcome("CHAIN_VERIFIED").level, "verified");
  assert.equal(m.successionOutcome("NONSENSE").level, "pending", "unknown states fail closed");
  assert.equal(m.successionSignatureState("AUTHORIZED"), "unsigned"); assert.equal(m.successionSignatureState("SIGNED"), "signed"); assert.equal(m.successionSignatureState("REFUSED"), "unknown");
  assert.equal(m.successionSignerOf(base, orgRoot), successor);
  assert.equal(m.successionSignerOf(base, { template: { successorPk: K(0x11) } }), null, "the request and the root disagree => offer nothing");
  /* an OWNER action is untouched by the succession rendering (regression guard for the M-of-N wording) */
  const own = manifestFixture("root_authorize_2of3").manifest;
  const ownHtml = m.renderRequestDetailHtml({ id: "o1", kind: "rootAction", action: "authorize", state: "AUTHORIZED", signaturesPresent: 1, requiredApprovals: "2", manifest: own, slots: own.action.expectedSignerSlots.map((s, i) => ({ slot: s.slot, publicKey: s.publicKey, address: `kaspatest:qown${s.slot}`, status: i === 0 ? "SIGNED" : "PENDING" })) }, { viewerXOnly: own.action.expectedSignerSlots[1].publicKey });
  assert.match(ownHtml, /1 of 2 collected/); assert.match(ownHtml, /Collect 1 more owner approval, then finalize/); assert.match(ownHtml, /data-rootfinalize="o1"/);
});

/* ================================================================== *
 * rc26 round-7 internal review (independent falsification of cf4e644):
 * R7-05 (dead controls) and R7-06 (non-canonical quorum digits).
 * ================================================================== */

test("rc26 round-7 R7-06: finalizeGate refuses a NON-CANONICAL digit string ('02') as the quorum — the verifier refuses it, so the gate must never enable on it", () => {
  const { m } = mod();
  const slots2 = [{ slot: 1, status: "SIGNED" }, { slot: 2, status: "SIGNED" }];
  const g = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: "02", manifest: { action: { requiredApprovals: "02" } }, slots: slots2 });
  assert.equal(g.enabled, false, "'02' is not a canonical base-10 digit string (the verifier refuses requiredApprovals '02')");
  assert.ok(typeof g.reason === "string" && g.reason.length > 0);
  const g2 = m.finalizeGate({ state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: 2, manifest: { action: { requiredApprovals: "2" } }, slots: slots2 });
  assert.equal(g2.enabled, true, "control: the canonical '2' still enables at quorum");
});

/* rc26 round-7 R7-05 — CLOSED by browser initiation (owner-approved; launch scope 2026-09-08). The former "dead controls"
 * finding is now the opposite requirement: every `[data-rootvaultop]` control the panel renders HAS a handler in
 * app-v4.js (openRootedVaultOpFlow), is offered only for the supported profile, and is enabled only when
 * vaultOpAvailability() allows it. A vault whose summary was not loaded renders NO control. */
test("R7-05: the rooted-vault owner-operations panel renders one WIRED control per supported operation (never a single-owner signature) and states the ROOT-REQUEST path; an unloaded vault renders no control", () => {
  const { m } = mod();
  const unloaded = m.renderRootedVaultOwnerOpsHtml({ vaultId: "v1" }, { rootCovenantId: "r1" }, { loaded: false });
  assert.ok(!/<button/i.test(unloaded), `an unloaded vault offers nothing: ${unloaded.slice(0, 200)}`);
  assert.match(unloaded, /could not be loaded/);
  assert.match(unloaded, /ROOT REQUESTS, never a single-owner signature/);
  const orgRoot = { rootCovenantId: "r1", networkId: "testnet-10", state: { ownerM: "2", emergencyK: "1", recoveryM: "1", frozen: 0 }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1" }, { slot: 2, publicKey: K(0x72) }], template: {}, live: { outpoint: { transactionId: "bb".repeat(32), index: 0 } } };
  const vault = { vaultId: "v1", label: "Ops", status: "ACTIVE", contractVersion: "policyvault-0.7-payment", generation: 2, recoveryPk: K(0x99), live: { outpoint: { transactionId: "cc".repeat(32), index: 0 }, feeReserveKas: "1", paused: false, tokenPosition: null }, agents: [] };
  const html = m.renderRootedVaultOwnerOpsHtml(vault, orgRoot, { viewerXOnly: K(0x71) });
  const ops = (html.match(/data-rootvaultop="([A-Za-z]+)"/g) || []).map((s) => s.replace(/.*="|"$/g, ""));
  assert.deepEqual(ops, ["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"], "exactly the six supported owner operations, in order");
  assert.match(html, /<button type="button" disabled class="" data-rootvaultop="ownerUnpause"[^>]*title="this vault is not paused"/, "Unpause is offered but disabled with its reason while the vault is not paused");
  assert.match(html, /data-rootvaultop="ownerRecover"[^>]*title="CLOSES this vault permanently/);
  assert.match(html, /Pinned recovery key/);
  assert.match(html, new RegExp(K(0x99)));
  assert.match(html, /no delegate rules installed — no agent can pay from this vault/);
  assert.ok(!/data-ownersign/i.test(html), "no legacy v0.4-style single-owner signing hook");
  assert.ok(!/SDK or API today/.test(html), "the old 'created through the SDK or API today' statement is gone — the browser path exists");
  assert.match(APP_V4, /querySelectorAll\("\[data-rootvaultop\]"\)/, "app-v4.js wires every [data-rootvaultop] control");
  assert.match(APP_V4, /async function openRootedVaultOpFlow\(rootUI, orgRoot, vault, op/, "the handler exists in app-v4.js");
  assert.match(APP_V4, /rootUI\.validateVaultOpDraft\(/, "the handler validates through the module's own validator before any network call");
  assert.match(APP_V4, /vaultOperations: \[v\.vaultOperation\]/, "the request is created with exactly ONE vaultOperations entry");
});

test("R7-05: the root detail renders one panel per linked vault from the PRESENTED summaries (controls only for the supported profile; HD candidate and unloaded vaults get statements), and no section without vaults", () => {
  const { m } = mod();
  const base = { rootCovenantId: "r1", label: "acme", networkId: "testnet-10", state: { ownerM: 2, emergencyK: 1, recoveryM: 1, frozen: 0, rootNonce: 0 }, template: { successorPk: "", recoveryDelayDaa: "600", successionDelayDaa: "600", rootMaxFeePerTx: "1000000" }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspatest:q1" }], live: { outpoint: { transactionId: "bb".repeat(32), index: 0 } } };
  const live = { outpoint: { transactionId: "cc".repeat(32), index: 0 }, feeReserveKas: "1", paused: false, tokenPosition: null };
  const summaries = [
    { vaultId: "v-one", label: "One", status: "ACTIVE", contractVersion: "policyvault-0.7-payment", live, agents: [] },
    { vaultId: "v-two", label: "Two", status: "ACTIVE", contractVersion: "policyvault-0.7-payment-hd", live, agents: [] }
  ];
  const withVaults = m.renderRootDetailHtml({ ...base, vaults: ["v-one", "v-two", "v-three"] }, { viewerXOnly: K(0x71), rootedVaults: summaries });
  assert.match(withVaults, /Rooted vaults \(3\)/);
  assert.equal((withVaults.match(/data-rooted-vault-owner-ops=/g) || []).length, 3, "one panel per linked vault");
  assert.equal((withVaults.match(/data-rootvaultop=/g) || []).length, 6, "controls ONLY for the supported policyvault-0.7-payment vault");
  assert.match(withVaults, /Hierarchical-delegation vaults are a CANDIDATE profile — owner operations are not offered/);
  assert.match(withVaults, /could not be loaded — reload before starting an owner operation/, "a vault without a loaded summary offers nothing and says so");
  const readOnly = m.renderRootDetailHtml({ ...base, vaults: ["v-one"] }, { viewerXOnly: K(0x55), rootedVaults: summaries });
  assert.ok(/data-rootvaultop="ownerPause"[^>]*title="Only an owner of this root can start this"/.test(readOnly) && !/<button type="button" class="" data-rootvaultop="ownerPause"/.test(readOnly), "a non-owner sees every control disabled with the reason");
  const noSummaries = m.renderRootDetailHtml({ ...base, vaults: ["v-one"] }, { viewerXOnly: K(0x71), rootedVaults: null });
  assert.ok(!/data-rootvaultop=/.test(noSummaries), "summaries not loaded → no control at all");
  const without = m.renderRootDetailHtml({ ...base, vaults: [] }, {});
  assert.ok(!/Rooted vaults \(/.test(without));
});

/* ================================================================== *
 * R7-05 browser initiation + F-6 reservation / authorized withdrawal
 * (owner-approved; launch scope 2026-09-08). Real core bundle, real v7
 * manifest fixtures, fake api; DOM-free.
 * ================================================================== */

const setupModForOps = require("../setup-ui.js");
function opsMod(apiOverrides) {
  const api = fakeApi({ __resolve: { ...OWNERS, "kaspa:qagent": K(0x22), "kaspa:qrec": K(0x33), "kaspa:qrec2": K(0x34) }, ...apiOverrides });
  return { api, m: orgRootUiMod.createModule({ api, core, setup: setupModForOps.createModule({ core }) }) };
}
const OPS_ROOT = { rootCovenantId: "r".repeat(64), networkId: "testnet-10", state: { frozen: 0, ownerM: "2", emergencyK: "1", recoveryM: "1" }, slots: [{ slot: 1, publicKey: K(0x71), address: "kaspa:qown1" }, { slot: 2, publicKey: K(0x72), address: "kaspa:qown2" }], template: {}, vaults: ["v1"], pendingRequestId: null, live: { outpoint: { transactionId: "bb".repeat(32), index: 0 } } };
const OPS_VAULT = { vaultId: "v1", label: "Ops", status: "ACTIVE", contractVersion: "policyvault-0.7-payment", generation: 2, recoveryPk: K(0x99), live: { outpoint: { transactionId: "cc".repeat(32), index: 0 }, feeReserveKas: "1", paused: false, tokenPosition: null }, agents: [{ agentPk: K(0x22), tokenMaxPerSpend: "250", tokenPeriodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "12345", tokenPeriodSpent: "7", agentMaxFeePerTx: "100000000", agentMaxCarryKas: "25000000", agentRecipientRoot: "00".repeat(32), recipients: [K(0x33)] }] };

test("R7-05: the vault-operation table agrees with the SHARED CORE's owner-op authority map (root action per operation) — an operation the core does not know is never offered", () => {
  const { m } = opsMod();
  const table = core.vaultStateV7.OWNER_OP_ROOT_AUTHORITY_V7;
  for (const op of m.VAULT_OP_ORDER) {
    const info = m.vaultOpInfo(op);
    assert.ok(info, `${op} is known`);
    assert.equal(info.rootAction, table[op].rootActionName, `${op} requires the core's root action`);
  }
  assert.equal(m.vaultOpInfo("tokenAgentSpend"), null, "a delegate action is not an owner operation");
  assert.equal(m.vaultOpInfo("constructor"), null, "own-property lookup only (prototype keys are unknown operations)");
  assert.equal(m.vaultOpInfo("__proto__"), null);
  assert.equal(m.vaultOpAvailability({ op: "ownerTopUp", vault: OPS_VAULT, orgRoot: OPS_ROOT, viewerXOnly: K(0x71) }).offered, false, "a v0.4-only owner action is not a rooted-vault operation");
});

test("R7-05: availability matrix — owner + live + unreserved + unfrozen enables; non-owner / pending reservation / frozen root / mainnet / terminal vault / wrong paused state / HD candidate refuse with the exact reason", () => {
  const { m } = opsMod();
  const ok = (op, over = {}) => m.vaultOpAvailability({ op, vault: OPS_VAULT, orgRoot: OPS_ROOT, viewerXOnly: K(0x71), ...over });
  for (const op of ["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerEmergencyPause", "ownerRecover"]) assert.equal(ok(op).enabled, true, op);
  assert.match(ok("ownerUnpause").reason, /not paused/);
  assert.equal(ok("ownerUnpause", { vault: { ...OPS_VAULT, live: { ...OPS_VAULT.live, paused: true } } }).enabled, true, "unpause enables on a paused vault");
  assert.match(ok("ownerPause", { vault: { ...OPS_VAULT, live: { ...OPS_VAULT.live, paused: true } } }).reason, /already paused/);
  assert.match(ok("ownerEmergencyPause", { vault: { ...OPS_VAULT, live: { ...OPS_VAULT.live, paused: true } } }).reason, /already paused/);
  assert.match(ok("ownerPause", { viewerXOnly: K(0x55) }).reason, /Only an owner of this root/);
  assert.match(ok("ownerPause", { viewerXOnly: null }).reason, /Only an owner of this root/);
  assert.match(ok("ownerPause", { orgRoot: { ...OPS_ROOT, pendingRequestId: "some-request" } }).reason, /already pending on this root/);
  assert.match(ok("ownerPause", { pendingRequestId: "explicit" }).reason, /already pending/);
  assert.match(ok("ownerPause", { orgRoot: { ...OPS_ROOT, state: { ...OPS_ROOT.state, frozen: 1 } } }).reason, /root is FROZEN/);
  assert.match(ok("ownerEmergencyPause", { orgRoot: { ...OPS_ROOT, state: { ...OPS_ROOT.state, frozen: 1 } } }).reason, /already FROZEN/);
  assert.match(ok("ownerPause", { orgRoot: { ...OPS_ROOT, networkId: "mainnet" } }).reason, /not mainnet-authorized/);
  assert.match(ok("ownerPause", { networkId: "mainnet" }).reason, /not mainnet-authorized/);
  assert.match(ok("ownerPause", { vault: { ...OPS_VAULT, live: null } }).reason, /no confirmed on-chain outpoint/);
  assert.match(ok("ownerPause", { vault: { ...OPS_VAULT, status: "RECOVERED", live: null } }).reason, /RECOVERED — no further owner operation/);
  const hd = ok("ownerPause", { vault: { ...OPS_VAULT, contractVersion: "policyvault-0.7-payment-hd" } });
  assert.equal(hd.offered, false); assert.equal(hd.enabled, false);
  const legacy = ok("ownerPause", { vault: { ...OPS_VAULT, contractVersion: "policyvault-0.4.1" } });
  assert.equal(legacy.offered, false, "a legacy single-owner vault is never presented as a rooted vault");
});

test("R7-05: drafts are prefilled EXACTLY from the presented vault (agent rules carried value for value; a new agent's period starts at the current DAA) and validated through the SAME core normalizers the SDK runs", async () => {
  const { m } = opsMod();
  const top = m.vaultOpDraftFrom({ op: "ownerTopUpReserve", vault: OPS_VAULT });
  assert.deepEqual(top, { op: "ownerTopUpReserve", amountKas: "" });
  for (const bad of ["", "0", "-1", "abc", "1.123456789", "1e3", "NaN"]) {
    const r = await m.validateVaultOpDraft({ op: "ownerTopUpReserve", draft: { amountKas: bad }, vault: OPS_VAULT });
    assert.equal(r.ok, false, `top-up ${JSON.stringify(bad)} refused`); assert.ok(r.errors.get("amount"));
  }
  const good = await m.validateVaultOpDraft({ op: "ownerTopUpReserve", draft: { amountKas: "0.5" }, vault: OPS_VAULT });
  assert.deepEqual(good.vaultOperation, { vaultId: "v1", action: "ownerTopUpReserve", params: { topUpReserveAmountSompi: "50000000" } }, "an exact positive sompi digit string, from the canonical parser");
  const ag = m.vaultOpDraftFrom({ op: "ownerSetAgentRoot", vault: OPS_VAULT, currentDaa: "777" });
  assert.equal(ag.agents.length, 1);
  assert.deepEqual(ag.agents[0], { existing: true, agentKey: K(0x22), tokenMaxPerSpend: "250", tokenPeriodBudget: "2000", periodLengthDaa: "100000000", periodStartDaa: "12345", tokenPeriodSpent: "7", agentMaxFeePerTxKas: "1", agentMaxCarryKas: "0.25", recipients: K(0x33) });
  const unchanged = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: ag, vault: OPS_VAULT, currentDaa: "777" });
  assert.equal(unchanged.ok, true, JSON.stringify([...unchanged.errors]));
  const entry = unchanged.vaultOperation.params.agents[0];
  assert.equal(unchanged.vaultOperation.action, "ownerSetAgentRoot");
  assert.deepEqual(Object.keys(entry).sort(), ["agentMaxCarryKas", "agentMaxFeePerTx", "agentPk", "agentRecipientRoot", "periodLengthDaa", "periodStartDaa", "tokenMaxPerSpend", "tokenPeriodBudget", "tokenPeriodSpent", "recipients"].sort(), "the SDK registry-entry shape: the policy's closed fields + recipients");
  assert.equal(entry.agentPk, K(0x22)); assert.equal(entry.periodStartDaa, "12345"); assert.equal(entry.tokenPeriodSpent, "7"); assert.equal(entry.agentMaxFeePerTx, "100000000"); assert.equal(entry.agentMaxCarryKas, "25000000");
  assert.equal(entry.agentRecipientRoot, core.recipientMerkle.buildRecipientTree([K(0x33)]).root, "the recipient commitment is recomputed from the listed recipients");
  assert.deepEqual(entry.recipients, [K(0x33)]);
  /* edit: raise the cap, add a recipient by ADDRESS, add a NEW agent by address */
  ag.agents[0].tokenMaxPerSpend = "300"; ag.agents[0].recipients = `${K(0x33)}\nkaspa:qrec2`;
  ag.agents.push({ ...m.vaultOpDraftFrom({ op: "ownerSetAgentRoot", vault: { agents: [] }, currentDaa: "777" }).agents[0], agentKey: "kaspa:qagent", tokenMaxPerSpend: "10", tokenPeriodBudget: "100", periodLengthDaa: "864000", agentMaxFeePerTxKas: "0.01", agentMaxCarryKas: "0", recipients: "kaspa:qrec" });
  assert.equal(ag.agents[1].agentKey, "kaspa:qagent");
  assert.match(ag.agents[1].agentKey, /agent/);
  ag.agents[1].agentKey = "kaspa:qown2"; // a distinct key (0x72) so the set has two different agents
  const edited = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: ag, vault: OPS_VAULT, currentDaa: "777" });
  assert.equal(edited.ok, true, JSON.stringify([...edited.errors]));
  assert.equal(edited.vaultOperation.params.agents[0].tokenMaxPerSpend, "300");
  assert.deepEqual(edited.vaultOperation.params.agents[0].recipients, [K(0x33), K(0x34)]);
  assert.equal(edited.vaultOperation.params.agents[1].agentPk, K(0x72));
  assert.equal(edited.vaultOperation.params.agents[1].periodStartDaa, "777", "a NEW agent's period starts at the current network DAA");
  assert.equal(edited.vaultOperation.params.agents[1].tokenPeriodSpent, "0");
  assert.equal(edited.vaultOperation.params.agents[1].agentMaxFeePerTx, "1000000");
  /* refusals: duplicate agent, duplicate recipient, missing recipients, malformed / non-positive amounts, zero period, bad address */
  const dup = JSON.parse(JSON.stringify(ag)); dup.agents[1].agentKey = K(0x22);
  const rDup = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: dup, vault: OPS_VAULT });
  assert.equal(rDup.ok, false); assert.match(rDup.errors.get("agentRows")[1].agentKey, /already listed/);
  const bad = { op: "ownerSetAgentRoot", agents: [{ existing: false, agentKey: "kaspa:qnobody", tokenMaxPerSpend: "0", tokenPeriodBudget: "x", periodLengthDaa: "0", periodStartDaa: "1", tokenPeriodSpent: "0", agentMaxFeePerTxKas: "abc", agentMaxCarryKas: "", recipients: "" }] };
  const rBad = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: bad, vault: OPS_VAULT });
  assert.equal(rBad.ok, false);
  const e = rBad.errors.get("agentRows")[0];
  assert.match(e.agentKey, /address rejected/); assert.match(e.tokenMaxPerSpend, /greater than 0/); assert.match(e.tokenPeriodBudget, /whole number/); assert.match(e.periodLengthDaa, /greater than 0/); assert.match(e.agentMaxFeePerTxKas, /./); assert.match(e.recipients, /At least one allowed recipient/);
  const dupRec = JSON.parse(JSON.stringify(ag)); dupRec.agents[0].recipients = `${K(0x33)}\nkaspa:qrec`;
  const rDupRec = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: dupRec, vault: OPS_VAULT });
  assert.equal(rDupRec.ok, false); assert.match(rDupRec.errors.get("agentRows")[0].recipients, /listed twice/);
  /* the closed-layout normalizer refuses an unknown field even if a caller smuggles one in */
  assert.throws(() => core.agentMerkleV5.normalizeTokenAgentPolicyV5({ ...entry, recipients: undefined, extra: 1 }), /unknown token agent policy field/);
  /* the empty set is allowed (the review says no agent can pay) */
  const empty = await m.validateVaultOpDraft({ op: "ownerSetAgentRoot", draft: { op: "ownerSetAgentRoot", agents: [] }, vault: OPS_VAULT });
  assert.equal(empty.ok, true); assert.deepEqual(empty.vaultOperation.params.agents, []);
  /* no-parameter operations; the terminal one needs its typed phrase */
  for (const op of ["ownerPause", "ownerUnpause", "ownerEmergencyPause"]) assert.deepEqual((await m.validateVaultOpDraft({ op, draft: {}, vault: OPS_VAULT })).vaultOperation, { vaultId: "v1", action: op, params: {} });
  assert.equal(m.vaultOpConfirmPhrase("ownerRecover"), "CONFIRM CLOSE VAULT");
  assert.equal(m.vaultOpConfirmPhrase("ownerPause"), "");
  const rec = await m.validateVaultOpDraft({ op: "ownerRecover", draft: { typed: "confirm close vault" }, vault: OPS_VAULT });
  assert.equal(rec.ok, false); assert.match(rec.errors.get("typed"), /CONFIRM CLOSE VAULT/);
  assert.deepEqual((await m.validateVaultOpDraft({ op: "ownerRecover", draft: { typed: " CONFIRM CLOSE VAULT " }, vault: OPS_VAULT })).vaultOperation, { vaultId: "v1", action: "ownerRecover", params: {} });
  const unknown = await m.validateVaultOpDraft({ op: "ownerTopUp", draft: { amountKas: "1" }, vault: OPS_VAULT });
  assert.equal(unknown.ok, false); assert.match(unknown.errors.get("op"), /failing closed/);
  assert.throws(() => m.vaultOpDraftFrom({ op: "nope", vault: OPS_VAULT }), /failing closed/);
});

test("R7-05: the parameter forms are labelled, name every field, carry the exact hidden period fields, and the terminal form shows the pinned recovery key and demands the typed phrase", () => {
  const { m } = opsMod();
  const top = m.renderVaultOpFormHtml({ op: "ownerTopUpReserve", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: { amountKas: "0.5" }, errors: new Map(), connectedAddress: "kaspa:qown1" });
  assert.match(top, /<form class="setup-form" data-vaultop-form="ownerTopUpReserve" data-vault="v1"/);
  assert.match(top, /<label class="f-label" for="f-amount">Amount to add to the fee reserve<\/label>/);
  assert.match(top, /name="amount" value="0\.5"/);
  assert.match(top, /Authorized by 2 of 2 owners through the root's <b>authorize<\/b> action/);
  assert.match(top, /data-vaultop-cancel="1"/);
  const withErr = m.renderVaultOpFormHtml({ op: "ownerTopUpReserve", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: { amountKas: "0" }, errors: new Map([["amount", "Enter a KAS amount greater than 0."]]), connectedAddress: "kaspa:qown1" });
  assert.match(withErr, /class="ferr" data-err="amount" style="display:block">Enter a KAS amount greater than 0\./);
  const ag = m.vaultOpDraftFrom({ op: "ownerSetAgentRoot", vault: OPS_VAULT, currentDaa: "777" });
  const agents = m.renderVaultOpFormHtml({ op: "ownerSetAgentRoot", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: ag, errors: new Map(), connectedAddress: "kaspa:qown1", currentDaa: "777" });
  assert.equal((agents.match(/data-agent-row="/g) || []).length, 1);
  for (const f of ["agentKey", "tokenMaxPerSpend", "tokenPeriodBudget", "periodLengthDaa", "agentMaxFeePerTxKas", "agentMaxCarryKas"]) assert.match(agents, new RegExp(`<label class="f-label" for="f-agent-0-${f}">`), `${f} is labelled`);
  assert.match(agents, /<textarea id="f-agent-0-recipients" name="agent-0-recipients"/);
  assert.match(agents, /name="agent-0-periodStartDaa" value="12345"/); assert.match(agents, /name="agent-0-tokenPeriodSpent" value="7"/); assert.match(agents, /name="agent-0-existing" value="1"/);
  assert.match(agents, /the installed values, carried unchanged/);
  assert.match(agents, /id="v4-add-agent"/); assert.match(agents, /data-remove-agent="0"/);
  assert.match(agents, /These rules REPLACE the installed set completely/);
  const emergency = m.renderVaultOpFormHtml({ op: "ownerEmergencyPause", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: {}, errors: new Map(), connectedAddress: "kaspa:qown1" });
  assert.match(emergency, /Authorized by 1 of 2 owners \(emergency quorum\) through the root's <b>freeze<\/b> action/);
  assert.match(emergency, /the organizational root is FROZEN/); assert.match(emergency, /Only this one vault is paused/);
  assert.doesNotMatch(emergency, /v4-vaultop-typed/, "an emergency pause is confirmed, not typed");
  const rec = m.renderVaultOpFormHtml({ op: "ownerRecover", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: { typed: "" }, errors: new Map(), connectedAddress: "kaspa:qown1" });
  assert.match(rec, /IRREVERSIBLE/); assert.match(rec, new RegExp(K(0x99))); assert.match(rec, /1 KAS of fee reserve/);
  assert.match(rec, /<label class="f-label" for="v4-vaultop-typed">Type the confirmation phrase<\/label>/); assert.match(rec, /CONFIRM CLOSE VAULT/);
  assert.match(m.renderVaultOpFormHtml({ op: "bogus", vault: OPS_VAULT, orgRoot: OPS_ROOT, draft: {}, errors: new Map() }), /refusing to render a form/);
});

test("R7-05: the request detail describes the vault operation from the VERIFIED manifest (fee reserve before/after, installed rules with recipients, terminal payout to the pinned recovery key) for every vault-operation fixture", () => {
  const { m } = opsMod();
  const cases = {
    vault_owner_pause_under_authorize: [/Pause vault on vault 4444/, /Fee reserve: 5 KAS → 5 KAS/, /requires the root to run authorize/],
    vault_set_agent_root_under_authorize: [/Change agent rules on vault/, /New delegate rules: 2 agent policies/, /agent 6262[0-9a-f]+: up to 100 per payment, 400 per 1000 DAA/, /may pay ONLY \d+ recipient/],
    vault_emergency_pause_under_freeze: [/Emergency-pause vault on vault/, /requires the root to run freeze/],
    vault_recover_terminal_with_position: [/Close & recover vault on vault/, /TERMINAL: this vault is CLOSED; 5 KAS is paid to the pinned recovery key 5151/, /entire token position of 300 atomic units goes to the same recovery key/, /Fee reserve: 5 KAS → 0 KAS/]
  };
  for (const [name, expectations] of Object.entries(cases)) {
    const item = manifestFixture(name);
    const request = { id: `req-${name}`, kind: "rootAction", action: item.manifest.action.name, state: "AUTHORIZED", manifest: item.manifest, descriptors: item.descriptors || {}, redeemScripts: item.redeemScripts || {}, vaultOperations: item.manifest.vaultOperations.map((op) => ({ vaultId: op.manifest.vault.vaultId, action: op.manifest.action.sdkAction })), slots: [], rootCovenantId: item.manifest.root.covenantId, requiredApprovals: item.manifest.action.requiredApprovals, signaturesPresent: 0 };
    const s = m.vaultOperationSummary(request);
    assert.equal(s.ok, true, name);
    assert.equal(s.terminal, name === "vault_recover_terminal_with_position");
    const text = s.lines.join("\n");
    for (const re of expectations) assert.match(text, re, `${name}: ${re}`);
    const html = m.renderRequestDetailHtml(request, { orgRoot: { rootCovenantId: request.rootCovenantId, slots: [], template: {}, state: {} } });
    assert.match(html, /data-vault-operation-summary="verified"/, name);
    assert.match(html, /data-rootreject=/, `${name}: unsigned + never attempted → withdrawal offered`);
    assert.match(html, /data-reservation-next="withdraw"/, name);
  }
  const refused = m.vaultOperationSummary({ manifest: { vaultOperations: [{}] }, vaultOperations: [{ vaultId: "x", action: "ownerPause" }] });
  assert.equal(refused.ok, false); assert.match(refused.lines[0], /do not sign/);
  assert.equal(m.vaultOperationSummary({ manifest: { vaultOperations: [] } }), null);
});

test("F-6: withdrawEligibility follows the owner-approved reservation table — unsigned & unattempted → withdraw; signature attached → collect; finalized → resume the ORIGINAL submission; attempted / uncertain → outcome recovery; terminal → nothing", () => {
  const { m } = opsMod();
  const e = (r) => m.withdrawEligibility(r).kind;
  assert.equal(e({ state: "AUTHORIZED", slots: [{ status: "PENDING" }, { status: "PENDING" }] }), "withdraw");
  assert.equal(e({ state: "AUTHORIZED", slots: [] }), "withdraw");
  assert.equal(e({ state: "AUTHORIZED", slots: [{ status: "SIGNED" }, { status: "PENDING" }] }), "collect");
  assert.equal(e({ state: "SIGNED", slots: [{ status: "SIGNED" }, { status: "SIGNED" }] }), "resume");
  for (const st of ["BROADCAST", "CHAIN_SEEN", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"]) assert.equal(e({ state: st, slots: [] }), "recover", st);
  assert.equal(e({ state: "AUTHORIZED", slots: [], submissionAttempt: { txId: "x" } }), "recover", "durable attempt evidence outranks the state");
  assert.equal(e({ state: "SIGNED", slots: [], submissionOutcome: { kind: "x" } }), "recover");
  for (const st of ["REFUSED", "CHAIN_VERIFIED", "VERIFIED_OUTCOME", "SUBMISSION_REJECTED", "STALE", "FAILED"]) assert.equal(e({ state: st, slots: [] }), "none", st);
  assert.equal(e({ state: "WEIRD", slots: [] }), "none", "an unknown state offers no withdrawal path (fail closed)");
  assert.equal(e(null), "none");
});

test("F-6: the request detail offers exactly the authorized next action — Withdraw only when eligible, 'Verify state (recover outcome)' for an attempted request, Submit for a finalized one; the reservation row explains that a dismissed wallet prompt releases nothing", () => {
  const { m } = opsMod();
  const item = manifestFixture("vault_owner_pause_under_authorize");
  const base = { id: "q9", kind: "rootAction", action: "authorize", state: "AUTHORIZED", manifest: item.manifest, descriptors: item.descriptors || {}, redeemScripts: item.redeemScripts || {}, vaultOperations: [{ vaultId: item.manifest.vaultOperations[0].manifest.vault.vaultId, action: "ownerPause" }], slots: [{ slot: 1, publicKey: K(0x71), status: "PENDING" }, { slot: 2, publicKey: K(0x72), status: "PENDING" }], rootCovenantId: item.manifest.root.covenantId, requiredApprovals: "2", signaturesPresent: 0 };
  const orgRoot = { rootCovenantId: base.rootCovenantId, slots: base.slots, template: {}, state: { ownerM: "2" } };
  const fresh = m.renderRequestDetailHtml(base, { orgRoot, viewerXOnly: K(0x71) });
  assert.match(fresh, /<button class="warn" data-rootreject="q9" title="unsigned and never attempted/);
  assert.match(fresh, /data-reservation-next="withdraw"/);
  assert.match(fresh, /guards the named vault/);
  assert.match(fresh, /dismissing a wallet prompt, closing this window or disconnecting the wallet does not release it/);
  assert.match(fresh, /not an on-chain freeze/);
  assert.doesNotMatch(fresh, /data-rootreconcile-request/);
  const partial = m.renderRequestDetailHtml({ ...base, signaturesPresent: 1, slots: [{ ...base.slots[0], status: "SIGNED" }, base.slots[1]] }, { orgRoot, viewerXOnly: K(0x72) });
  assert.doesNotMatch(partial, /data-rootreject=/); assert.match(partial, /data-reservation-next="collect"/);
  const finalized = m.renderRequestDetailHtml({ ...base, state: "SIGNED", signaturesPresent: 2, slots: base.slots.map((s) => ({ ...s, status: "SIGNED" })) }, { orgRoot, viewerXOnly: K(0x71) });
  assert.doesNotMatch(finalized, /data-rootreject=/); assert.match(finalized, /<button data-rootsubmit="q9" class="primary">/); assert.match(finalized, /data-reservation-next="resume"/); assert.match(finalized, /a finalized request is never withdrawn/);
  const attempted = m.renderRequestDetailHtml({ ...base, state: "RECONCILIATION_REQUIRED", signaturesPresent: 2, slots: base.slots.map((s) => ({ ...s, status: "SIGNED" })), submissionAttempt: { txId: "ab".repeat(32) } }, { orgRoot, viewerXOnly: K(0x71) });
  assert.doesNotMatch(attempted, /data-rootreject=/);
  assert.match(attempted, new RegExp(`<button data-rootreconcile="${base.rootCovenantId}" data-rootreconcile-request="q9">Verify state \\(recover outcome\\)</button>`));
  assert.match(attempted, /data-reservation-next="recover"/); assert.match(attempted, /cannot be withdrawn or replaced until its outcome is proven/);
  const done = m.renderRequestDetailHtml({ ...base, state: "CHAIN_VERIFIED", chain: { predecessorOutpoint: "p:0", successorOutpoint: "s:0" } }, { orgRoot, viewerXOnly: K(0x71) });
  assert.doesNotMatch(done, /data-rootreject=|data-rootreconcile-request|Reservation/);
  assert.match(APP_V4, /noteRootRefusal\("Withdraw did not complete — the request and its reservation are kept", err, rootUI\); repaint\(\); return;/, "app-v4.js keeps the request open and reports the real error when withdrawal fails");
  assert.match(APP_V4, /if \(st === "REFUSED"\) \{ note\("Request withdrawn/, "success is claimed only from the server's own REFUSED answer");
  assert.match(APP_V4, /treated as NOT withdrawn/);
  assert.match(APP_V4, /m\.querySelector\("\[data-rootreconcile-request\]"\)/, "the outcome-recovery control is wired in the request modal");
});

test("F-6: the root detail names the request that holds the reservation, the vault it guards and the authorized next step; the guarded vault's panel points at it and offers no operation", () => {
  const { m } = opsMod();
  const pending = { id: "p1", kind: "rootAction", action: "authorize", state: "AUTHORIZED", slots: [{ slot: 1, status: "PENDING" }], vaultOperations: [{ vaultId: "v1", action: "ownerTopUpReserve" }] };
  const g = m.reservationGuidance({ request: pending, orgRoot: OPS_ROOT });
  assert.equal(g.requestId, "p1"); assert.deepEqual(g.guardedVaultIds, ["v1"]); assert.equal(g.eligibility.kind, "withdraw");
  assert.match(g.text, /Top up fee reserve on vault v1 \(p1, AUTHORIZED\) holds this root's transition reservation and guards vault v1/);
  assert.match(g.text, /Dismissing a wallet prompt, closing this window or disconnecting the wallet does NOT release it/);
  assert.match(g.text, /not an on-chain freeze: agent payments continue/);
  assert.match(g.text, /Next: Withdraw it \(safe/);
  const resume = m.reservationGuidance({ request: { ...pending, state: "SIGNED" }, orgRoot: OPS_ROOT });
  assert.match(resume.text, /ORIGINAL finalized transaction is resumed, never rebuilt or replaced/);
  const recover = m.reservationGuidance({ request: { ...pending, state: "BROADCAST" }, orgRoot: OPS_ROOT });
  assert.match(recover.text, /Use Verify state \(outcome recovery\)/);
  assert.equal(m.reservationGuidance({ request: null }), null);
  const html = m.renderRootDetailHtml({ ...OPS_ROOT, pendingRequestId: "p1" }, { viewerXOnly: K(0x71), rootedVaults: [OPS_VAULT], pendingRequest: pending });
  assert.match(html, /data-root-reservation="p1" data-reservation-next="withdraw"/);
  assert.match(html, /holds this root&#39;s transition reservation|holds this root's transition reservation/);
  assert.match(html, /data-vault-guarded-by="p1"/);
  assert.match(html, /<button type="button" data-vieworequest="p1">Open that request<\/button>/);
  assert.ok(!/<button type="button" class="" data-rootvaultop=/.test(html), "every operation control is disabled while the root is reserved");
  assert.match(html, /data-rootvaultop="ownerPause"[^>]*title="A request is already pending on this root/);
  const unknownPending = m.renderRootDetailHtml({ ...OPS_ROOT, pendingRequestId: "p1" }, { viewerXOnly: K(0x71), rootedVaults: [OPS_VAULT], pendingRequest: null });
  assert.match(unknownPending, /data-root-reservation="p1">A request is already pending on this root/, "when the pending record could not be loaded the banner still states the reservation");
  assert.match(APP_V4, /rootUI\.fetchRequest\(rootId, orgRoot\.pendingRequestId\)/, "app-v4.js loads the pending request for the guidance");
  assert.match(APP_V4, /rootUI\.fetchRootedVaults\(rootId\)/, "app-v4.js loads the vault summaries for the panels");
  assert.match(APP_V4, /querySelectorAll\("\[data-vieworequest\]"\)/, "every 'open that request' control is wired");
});
