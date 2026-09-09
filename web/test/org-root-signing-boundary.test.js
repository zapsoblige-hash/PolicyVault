"use strict";
/*
 * Codex checkpoint 2 — UX-02 / UX-13: THE root signing boundary.
 *
 * Every root signing entry point (genesis funder, owner slot, successor,
 * fee input at finalize) must refuse — with ZERO wallet calls — any hostile
 * substitution of the transaction/envelope, network, funding, destinations,
 * fees or authority, and must hand the wallet EXACTLY the payload that was
 * bound to the review. Fixtures are the real production-byte manifests
 * (core/explain/test/fixtures); payloads are derived from their frozen
 * transactions, then tampered one field at a time.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const core = require("../core-bundle.js");
const orgRootUiMod = require("../org-root-ui.js");
const setupMod = require("../setup-ui.js");
const { safeJsonFromManifest } = require("./org-root-ui.test.js");

const FIXTURES = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "core", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));
const manifestOf = (name) => structuredClone(FIXTURES.manifests.find((x) => x.name === name).manifest);
const descriptorsOf = (name) => structuredClone(FIXTURES.manifests.find((x) => x.name === name).descriptors || {}); // rc21 review R6-02: the request carries the vault descriptors
const redeemScriptsOf = (name) => structuredClone(FIXTURES.manifests.find((x) => x.name === name).redeemScripts || {}); // Codex checkpoint 6 (UX-02 / UX-13): the request carries the vault's predecessor redeem script
const NET = "testnet-10";
const FUEL_OWNER = "64".repeat(32); // the fixture's fuel input key (input 1)

function mod() {
  const calls = [];
  const api = { calls, getJSON: async () => ({}), postJSON: async (p, body) => { calls.push({ p, body }); return { request: { state: "SIGNED" } }; }, resolveXOnly: async (a) => a };
  return { api, m: orgRootUiMod.createModule({ api, core, setup: setupMod.createModule({ core }) }) };
}
function envelopeFor(manifest, slotEntry, unsignedSafeJson, over = {}) {
  return { requestVersion: core.orgRootSlotV7.ORG_ROOT_SLOT_REQUEST_VERSION_1, requestId: "d".repeat(32), manifestHash: manifest.manifestHash, txId: manifest.transaction.txId, network: manifest.network.networkId,
    root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: 0 }, slot: { number: slotEntry.slot, index: slotEntry.slot - 1, publicKey: slotEntry.publicKey },
    unsignedSafeJson, signerRequest: { kind: "sign-transaction", signInputs: [{ index: 0, sighashType: 1 }] }, expiresAtMs: Date.now() + 100000, ...over };
}
function countingAdapter(signedFor) {
  const a = { calls: 0, seen: null, signInputs: async (u, list, opts) => { a.calls++; a.seen = { u, list, opts }; return signedFor(u); } };
  return a;
}
const slotSigned = (u) => { const s = JSON.parse(u); s.inputs[0].signatureScript = `41${"bb".repeat(64)}01`; return JSON.stringify(s); };
const fuelSigned = (u) => { const s = JSON.parse(u); s.inputs[1] = { ...s.inputs[1], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(s); };

async function expectRefused(label, fn, adapter, codes) {
  let err = null;
  try { await fn(); } catch (e) { err = e; }
  assert.ok(err, `${label}: refused`);
  assert.ok(codes.includes(err.code), `${label}: code ${err.code} (${err.message}) expected one of ${codes.join("|")}`);
  assert.equal(adapter.calls, 0, `${label}: ZERO wallet calls`);
}

/* ---------------- owner slot ---------------- */
test("slot: the happy path signs EXACTLY the bound payload once; every hostile substitution refuses with zero wallet calls", async () => {
  const manifest = manifestOf("root_authorize_2of3");
  const slots = manifest.action.expectedSignerSlots;
  const payload = safeJsonFromManifest(manifest);
  const { m } = mod();
  const ok = countingAdapter(slotSigned);
  const env = envelopeFor(manifest, slots[0], payload);
  const res = await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: env, adapter: ok, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" });
  assert.equal(ok.calls, 1);
  assert.equal(ok.seen.u, payload, "the payload verified is the payload signed");
  assert.equal(res.slot.number, 1);
  // the SDK's REAL Safe JSON shape: the covenant (root) input carries `utxo.covenantId: null`
  // (kaspa WASM UtxoEntry) — accepted; the outpoint/amount/script binding above stays exact
  const realShape = safeJsonFromManifest(manifest, (s) => { s.inputs[0].utxo.covenantId = null; });
  const ok2 = countingAdapter(slotSigned);
  await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED" }, slotEnvelope: envelopeFor(manifest, slots[0], realShape), adapter: ok2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" });
  assert.equal(ok2.calls, 1, "SDK-shaped payload (null input covenant id) signs");

  const cases = [
    ["root input DECLARES a different covenant id", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].utxo.covenantId = "0d".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["fee input declares a covenant id the review did not have", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].utxo.covenantId = manifest.root.covenantId; }) }, ["PAYLOAD_MISMATCH"]],
    ["transaction id substituted", { payload: safeJsonFromManifest(manifest, (s) => { s.id = "0f".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["root input spends another outpoint", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].transactionId = "0e".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["destination (root output script) substituted", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[0].scriptPublicKey = `0000aa20${"0d".repeat(32)}87`; }) }, ["PAYLOAD_MISMATCH"]],
    ["root output value drained (fee up)", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[0].value = String(BigInt(s.outputs[0].value) - 1n); }) }, ["PAYLOAD_MISMATCH", "FEE_MISMATCH"]],
    ["change output redirected", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[1].scriptPublicKey = `000020${"0c".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH"]],
    ["extra input smuggled in", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs.push({ ...s.inputs[1], transactionId: "0b".repeat(32) }); }) }, ["PAYLOAD_MISMATCH"]],
    ["payload already carries a signature", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].signatureScript = "41" + "ee".repeat(64) + "01"; }) }, ["PAYLOAD_INVALID"]],
    ["wrong network session", { network: "mainnet" }, ["NETWORK_MISMATCH"]],
    ["envelope for another review (manifest hash)", { envOver: { manifestHash: "0a".repeat(32) } }, ["PAYLOAD_MISMATCH"]],
    ["envelope for another transaction (txId)", { envOver: { txId: "09".repeat(32) } }, ["PAYLOAD_MISMATCH"]],
    ["envelope asks the owner to sign the FEE input", { envOver: { signerRequest: { kind: "sign-transaction", signInputs: [{ index: 1, sighashType: 1 }] } } }, ["PAYLOAD_MISMATCH"]],
    ["envelope names a different root outpoint", { envOver: { root: { covenantId: manifest.root.covenantId, outpoint: { transactionId: "08".repeat(32), index: 0 }, inputIndex: 0 } } }, ["PAYLOAD_MISMATCH"]],
    ["connected key is not an expected signer slot", { connected: "07".repeat(32), envSlot: { slot: 9, publicKey: "07".repeat(32) } }, ["NOT_AN_ACTIVE_SLOT"]],
    ["manifest tampered (ownerM) -> DO NOT SIGN review", { manifestTamper: (mf) => { mf.ownerSet.after.ownerM = "1"; } }, ["RESPONSE_BINDING_MISMATCH", "REVIEW_REFUSED"]],
    ["manifest missing", { noManifest: true }, ["OWNER_PATH_TAKES_NO_SIGNATURE", "REVIEW_MISSING"]],
    ["request already finalized", { state: "SIGNED" }, ["REQUEST_NOT_SIGNABLE"]],
    ["computeBudget changed (consensus field)", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].computeBudget = 1; }) }, ["PAYLOAD_MISMATCH"]],
    ["subnetworkId changed", { payload: safeJsonFromManifest(manifest, (s) => { s.subnetworkId = "01" + "00".repeat(19); }) }, ["PAYLOAD_INVALID", "PAYLOAD_MISMATCH"]],
    ["root output covenant metadata changed", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[0].covenant.authorizingInput = 1; }) }, ["PAYLOAD_MISMATCH"]],
    ["unknown field in an output", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[1].memo = "x"; }) }, ["PAYLOAD_INVALID"]],
    ["change redirected away from the fee payer (frozen tx re-authored to match)", { manifestTamper: (mf) => { const f = JSON.parse(mf.transaction.frozenCanonicalJson); f.outputs[1].scriptPublicKey = { version: 0, scriptHex: `20${"0c".repeat(32)}ac` }; mf.transaction.frozenCanonicalJson = JSON.stringify(f); }, payload: safeJsonFromManifest(manifest, (s) => { s.outputs[1].scriptPublicKey = `000020${"0c".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]]
  ];
  for (const [label, c, codes] of cases) {
    const mf = c.manifestTamper ? (() => { const x = manifestOf("root_authorize_2of3"); c.manifestTamper(x); return x; })() : manifest;
    const pl = c.payload || payload;
    const slotEntry = c.envSlot || slots[0];
    const e = envelopeFor(manifest, slotEntry, pl, c.envOver || {});
    const adapter = countingAdapter(slotSigned);
    await expectRefused(label, () => m.signOwnSlot({ request: c.noManifest ? { state: "AUTHORIZED" } : { manifest: mf, state: c.state || "AUTHORIZED" }, slotEnvelope: e, adapter, connectedXOnly: c.connected || slots[0].publicKey, network: c.network || NET, expectedSignerAddress: "kaspa:qowner1" }), adapter, codes);
  }
});

/* ---------------- fee input at finalize (UX-13) ---------------- */
test("finalize (fee input): a DO-NOT-SIGN review, a missing manifest, a substituted payload, a foreign fee input, a wrong network or a non-owner are all refused BEFORE the wallet; the honest path signs exactly the bound payload", async () => {
  const manifest = manifestOf("root_authorize_2of3");
  const payload = safeJsonFromManifest(manifest);
  const { m, api } = mod();
  const base = { id: "q1", kind: "rootAction", action: "authorize", state: "AUTHORIZED", signaturesPresent: 2, requiredApprovals: "2", createdBy: "kaspatest:qown1", rootInputIndex: 0, manifest, slots: [{ slot: 1, publicKey: manifest.action.expectedSignerSlots[0].publicKey, status: "SIGNED" }, { slot: 2, publicKey: manifest.action.expectedSignerSlots[1].publicKey, status: "SIGNED" }, { slot: 3, publicKey: manifest.action.expectedSignerSlots[2].publicKey, status: "PENDING" }], transaction: { unsignedSafeJson: payload, signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }] } };
  const ok = countingAdapter(fuelSigned);
  await m.finalizeRequest("r", "q1", base, { adapter: ok, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
  assert.equal(ok.calls, 1);
  assert.equal(ok.seen.u, payload);
  assert.deepEqual(ok.seen.list, [{ index: 1, sighashType: 1 }]);
  assert.equal(api.calls.length, 1);
  const cases = [
    ["DO-NOT-SIGN review (manifest tampered: rootValueLoss claim)", { manifestTamper: (mf) => { mf.fee.rootValueLoss = "1"; } }, ["REVIEW_REFUSED"]],
    ["manifest missing", { req: (r) => { delete r.manifest; } }, ["REVIEW_MISSING", "UNDER_QUORUM"]], // rc19 review R4-08: the gate refuses first (no verified quorum) — earlier, never looser
    ["payload is a different transaction (id)", { payload: safeJsonFromManifest(manifest, (s) => { s.id = "0f".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["fee input replaced by someone else's UTXO", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].utxo.scriptPublicKey = `000020${"0c".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH", "NOT_THE_SIGNER"]], // Codex checkpoint 6 (UX-03): the fee-owner gate (from the payload's own fee input) refuses first
    ["fee input amount changed", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].utxo.amount = String(BigInt(s.inputs[1].utxo.amount) + 1n); }) }, ["PAYLOAD_MISMATCH", "FEE_MISMATCH"]],
    ["connected wallet is not the fee-input owner", { connected: manifest.action.expectedSignerSlots[0].publicKey }, ["NOT_THE_SIGNER"]],
    ["wrong network session", { network: "mainnet" }, ["NETWORK_MISMATCH"]],
    ["signInputs points at the ROOT input", { req: (r) => { r.transaction.signInputs = [{ index: 1, sighashType: 1 }, { index: 0, sighashType: 1 }]; } }, ["REQUEST_NOT_SIGNABLE", "PAYLOAD_MISMATCH", "NOT_THE_SIGNER"]], // Codex checkpoint 6 (UX-03): no verifiable fee input => the fee-owner gate refuses first
    ["already finalized", { req: (r) => { r.state = "SIGNED"; } }, ["UNDER_QUORUM"]],
    /* Codex checkpoint 3 — the consensus fields the comparison previously dropped */
    ["computeBudget of the root input changed", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].computeBudget = s.inputs[0].computeBudget + 1; }) }, ["PAYLOAD_MISMATCH"]],
    ["computeBudget of the fee input changed", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].computeBudget = 7; }) }, ["PAYLOAD_MISMATCH"]],
    ["subnetworkId changed", { payload: safeJsonFromManifest(manifest, (s) => { s.subnetworkId = "01" + "00".repeat(19); }) }, ["PAYLOAD_INVALID", "PAYLOAD_MISMATCH"]],
    ["gas set", { payload: safeJsonFromManifest(manifest, (s) => { s.gas = "1"; }) }, ["PAYLOAD_INVALID", "PAYLOAD_MISMATCH"]],
    ["payload set", { payload: safeJsonFromManifest(manifest, (s) => { s.payload = "aa"; }) }, ["PAYLOAD_INVALID", "PAYLOAD_MISMATCH"]],
    ["lockTime changed", { payload: safeJsonFromManifest(manifest, (s) => { s.lockTime = "5"; }) }, ["PAYLOAD_MISMATCH"]],
    ["root output covenant metadata changed (covenant id)", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[0].covenant.covenantId = "0e".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["root output covenant metadata dropped", { payload: safeJsonFromManifest(manifest, (s) => { s.outputs[0].covenant = null; }) }, ["PAYLOAD_MISMATCH"]],
    ["root input utxo covenant id changed", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[0].utxo.covenantId = "0e".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["an unknown field smuggled into the payload", { payload: safeJsonFromManifest(manifest, (s) => { s.extra = 1; }) }, ["PAYLOAD_INVALID"]],
    ["an unknown field smuggled into an input", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].sighash = 2; }) }, ["PAYLOAD_INVALID"]],
    ["storageMass set", { payload: safeJsonFromManifest(manifest, (s) => { s.storageMass = "1"; }) }, ["PAYLOAD_INVALID"]],
    ["fee input already signed", { payload: safeJsonFromManifest(manifest, (s) => { s.inputs[1].signatureScript = "41" + "ee".repeat(64) + "01"; }) }, ["PAYLOAD_INVALID"]],
    /* rc18 review R3-01 — the fee payer's change destination */
    ["change output redirected to another key (manifest re-hashed to match)", { req: (r) => { const s = JSON.parse(r.transaction.unsignedSafeJson); s.outputs[1].scriptPublicKey = `000020${"0c".repeat(32)}ac`; r.transaction.unsignedSafeJson = JSON.stringify(s); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson); f.outputs[1].scriptPublicKey = { version: 0, scriptHex: `20${"0c".repeat(32)}ac` }; r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f); } }, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]],
    ["fee input replaced by another key's UTXO with matching change (manifest consistent)", { req: (r) => { const s = JSON.parse(r.transaction.unsignedSafeJson); s.inputs[1].utxo.scriptPublicKey = `000020${"0c".repeat(32)}ac`; s.outputs[1].scriptPublicKey = `000020${"0c".repeat(32)}ac`; r.transaction.unsignedSafeJson = JSON.stringify(s); } }, ["PAYLOAD_MISMATCH", "NOT_THE_SIGNER"]]
  ];
  for (const [label, c, codes] of cases) {
    const r = structuredClone(base);
    if (c.manifestTamper) c.manifestTamper(r.manifest);
    if (c.payload) r.transaction.unsignedSafeJson = c.payload;
    if (c.req) c.req(r);
    const adapter = countingAdapter(fuelSigned);
    await expectRefused(label, () => m.finalizeRequest("r", "q1", r, { adapter, network: c.network || NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: c.connected || FUEL_OWNER }), adapter, codes);
  }
});

/* ---------------- successor ---------------- */
test("succession: only the installed successor may sign, only the root input plus its own funds; substitutions refuse before the wallet", async () => {
  const manifest = manifestOf("root_succession");
  const successor = manifest.ownerSet.after.slots[0].publicKey;
  const payload = safeJsonFromManifest(manifest);
  const { m } = mod();
  const request = { id: "s1", rootCovenantId: manifest.root.covenantId, kind: "rootAction", action: "succession", state: "AUTHORIZED", rootInputIndex: 0, manifest, transaction: { unsignedSafeJson: payload, signInputs: [{ index: 0, sighashType: 1 }] } };
  const ok = countingAdapter(slotSigned);
  await m.signSingleSignerRequest({ request, adapter: ok, network: NET, expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor });
  assert.equal(ok.calls, 1);
  assert.equal(ok.seen.u, payload);
  const cases = [
    ["connected wallet is not the PINNED successor", { connected: FUEL_OWNER }, ["NOT_THE_SIGNER"]],
    ["root has no designated successor (pinned key zero)", { req: (r) => { r.manifest.root.template.successorPk = "00".repeat(32); } }, ["REQUEST_NOT_SIGNABLE", "REVIEW_REFUSED"]],
    ["pinned successor differs from the connected wallet even though it installs the connected wallet as sole owner", { req: (r) => { r.manifest.root.template.successorPk = "0d".repeat(32); } }, ["NOT_THE_SIGNER", "REVIEW_REFUSED"]],
    ["asked to also sign a fee input that is not the successor's", { req: (r) => { r.transaction.signInputs = [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }]; } }, ["PAYLOAD_MISMATCH"]],
    ["an authorize request presented as a succession", { req: (r) => { r.manifest = manifestOf("root_authorize_2of3"); r.transaction.unsignedSafeJson = safeJsonFromManifest(r.manifest); } }, ["REQUEST_NOT_SIGNABLE", "NOT_THE_SIGNER"]],
    ["payload substituted", { req: (r) => { r.transaction.unsignedSafeJson = safeJsonFromManifest(manifest, (s) => { s.outputs[0].scriptPublicKey = `0000aa20${"0d".repeat(32)}87`; }); } }, ["PAYLOAD_MISMATCH"]],
    ["wrong network", { network: "mainnet" }, ["NETWORK_MISMATCH"]],
    ["a multi-owner action is never a single-signer request", { req: (r) => { r.action = "authorize"; r.manifest = manifestOf("root_authorize_2of3"); } }, ["REQUEST_NOT_SIGNABLE"]]
  ];
  for (const [label, c, codes] of cases) {
    const r = structuredClone(request);
    if (c.req) c.req(r);
    const adapter = countingAdapter(slotSigned);
    await expectRefused(label, () => m.signSingleSignerRequest({ request: r, adapter, network: c.network || NET, expectedSignerAddress: "kaspa:qsucc", connectedXOnly: c.connected || successor }), adapter, codes);
  }
});

/* ---------------- root genesis (funder) ---------------- */
test("genesis: the review verdict, the network, the root value, the destinations, the funding identity and the fee are bound to the exact payload before the funder's wallet", async () => {
  const { m } = mod();
  const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
  const OWNERS = { "kaspatest:qown1": K(0x71), "kaspatest:qown2": K(0x72), "kaspatest:qown3": K(0x73), "kaspatest:qfunder": K(0xf1) };
  const api2 = { getJSON: async () => ({}), postJSON: async () => ({ request: { state: "SIGNED" } }), resolveXOnly: async (a) => { if (OWNERS[a]) return OWNERS[a]; throw Object.assign(new Error("bad"), { code: "ADDRESS_INVALID" }); } };
  const m2 = orgRootUiMod.createModule({ api: api2, core, setup: setupMod.createModule({ core }) });
  const draft = { label: "Acme", owners: [{ address: "kaspatest:qown1" }, { address: "kaspatest:qown2" }, { address: "kaspatest:qown3" }], ownerM: "2", emergencyK: "1", recoveryEnabled: true, recoveryM: "1", recoveryDelay: { preset: "30d" }, successionEnabled: false, successorAddress: "", successionDelay: { preset: "90d" }, rootValueKas: "1", rootMaxFeePerTxKas: "0.001", signerAddress: "kaspatest:qfunder" };
  const { norm } = await m2.validateGenesisDraft(draft, { connectedAddress: "kaspatest:qfunder" });
  const slots = core.ownerSetV7.activeOwnerSlotsV7(norm.ownerSet).map((s) => ({ slot: s.slot, publicKey: s.publicKey, address: `kaspatest:qown${s.slot}`, label: "" }));
  const ORG = "0a".repeat(32), COV = "0c".repeat(32);
  const summary = { kind: "genesis-summary", contractVersion: "policyvault-0.7-root", networkId: NET, orgId: ORG, covenantId: COV, template: { orgId: ORG, recoveryDelayDaa: String(norm.recoveryDelayDaa), successorPk: norm.successorPk, successionEnabled: false, successionDelayDaa: String(norm.successionDelayDaa), rootMaxFeePerTx: norm.rootMaxFeePerTxSompi.toString() }, slots, initialState: { ownerM: "2", emergencyK: "1", recoveryM: "1", frozen: "0", rootNonce: "0" }, rootValueKas: "1", txId: "7e".repeat(32), requiredFeeSompi: "208300" };
  const FUNDER = K(0xf1);
  const rootValue = 100000000n, fee = 208300n;
  /* the ONLY acceptable root destination: the P2SH of the exact script the reviewed rules compile to (shared core) */
  const ROOT_SPK = "0000" + core.rootScriptV7.genesisRootSpkHexV7({ template: { orgId: ORG, recoveryDelayDaa: String(norm.recoveryDelayDaa), successorPk: norm.successorPk, successionDelayDaa: String(norm.successionDelayDaa), rootMaxFeePerTx: norm.rootMaxFeePerTxSompi.toString() }, ownerSet: { owners: [...norm.ownerSet.owners], ownerM: "2", emergencyK: "1", recoveryM: "1" } });
  const mk = (t) => { const s = { id: summary.txId, version: 1, inputs: [{ transactionId: "5e".repeat(32), index: 0, sequence: "0", sigOpCount: 0, computeBudget: 10, signatureScript: "", utxo: { address: null, amount: (rootValue + fee + 50000000n).toString(), scriptPublicKey: `000020${FUNDER}ac`, blockDaaScore: "0", isCoinbase: false, covenantId: null } }], outputs: [{ value: rootValue.toString(), scriptPublicKey: ROOT_SPK, covenant: { authorizingInput: 0, covenantId: COV } }, { value: "50000000", scriptPublicKey: `000020${FUNDER}ac`, covenant: null }], subnetworkId: "00".repeat(20), lockTime: "0", gas: "0", storageMass: "0", payload: "" }; if (t) t(s); return JSON.stringify(s); };
  const payload = mk();
  const crossCheck = m2.genesisCrossCheck({ summary, norm });
  assert.equal(crossCheck.ok, true, crossCheck.mismatches.join(";"));
  const request = { id: "g1", kind: "rootGenesis", rootCovenantId: COV, manifest: summary, transaction: { unsignedSafeJson: payload, signInputs: [{ index: 0, sighashType: 1 }] } };
  const ok = countingAdapter(() => "{}");
  await m2.signGenesisRequest({ request, adapter: ok, network: NET, expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: FUNDER, crossCheck, norm });
  assert.equal(ok.calls, 1);
  assert.equal(ok.seen.u, payload, "the payload verified is the payload signed");
  const cases = [
    ["review did not check out (DO NOT SIGN)", { crossCheck: { ok: false, mismatches: ["owners needed to approve changes: server 1, reviewed 2"] } }, ["REVIEW_REFUSED"]],
    ["no review recorded", { crossCheck: null }, ["REVIEW_REFUSED"]],
    ["summary missing", { req: (r) => { delete r.manifest; } }, ["REVIEW_MISSING"]],
    ["transaction id differs from the summary", { payload: mk((s) => { s.id = "0f".repeat(32); }) }, ["PAYLOAD_MISMATCH"]],
    ["root output carries less than the reviewed funding", { payload: mk((s) => { s.outputs[0].value = (rootValue - 1n).toString(); s.outputs[1].value = "50000001"; }) }, ["PAYLOAD_MISMATCH"]],
    ["root output is not a covenant output", { payload: mk((s) => { s.outputs[0].scriptPublicKey = `000020${"0d".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH"]],
    ["change redirected to another wallet", { payload: mk((s) => { s.outputs[1].scriptPublicKey = `000020${"0c".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH"]],
    ["funding input belongs to someone else", { payload: mk((s) => { s.inputs[0].utxo.scriptPublicKey = `000020${"0c".repeat(32)}ac`; }) }, ["PAYLOAD_MISMATCH"]],
    ["fee differs from the reviewed fee", { payload: mk((s) => { s.outputs[1].value = "49999999"; }) }, ["FEE_MISMATCH"]],
    ["wrong network", { network: "mainnet" }, ["NETWORK_MISMATCH"]],
    ["connected wallet is not the funder", { connected: K(0x71) }, ["PAYLOAD_MISMATCH"]],
    ["not every funding input is signed", { req: (r) => { r.transaction.unsignedSafeJson = mk((s) => { s.inputs.push({ ...s.inputs[0], transactionId: "5f".repeat(32) }); s.outputs[1].value = (BigInt(s.outputs[1].value) + rootValue + fee + 50000000n).toString(); }); } }, ["PAYLOAD_MISMATCH"]],
    /* Codex checkpoint 3 (UX-02): the root destination is bound to the reviewed RULES through the exact script */
    ["root output P2SH substituted (a different locking script, review otherwise consistent)", { payload: mk((s) => { s.outputs[0].scriptPublicKey = `0000aa20${"5c".repeat(32)}87`; }) }, ["PAYLOAD_MISMATCH"]],
    ["root output P2SH of DIFFERENT rules (M 1 of 3 instead of 2 of 3)", { payload: mk((s) => { s.outputs[0].scriptPublicKey = "0000" + core.rootScriptV7.genesisRootSpkHexV7({ template: summary.template, ownerSet: { owners: [...norm.ownerSet.owners], ownerM: "1", emergencyK: "1", recoveryM: "1" } }); }) }, ["PAYLOAD_MISMATCH"]],
    ["root output P2SH of a different recovery waiting period", { payload: mk((s) => { s.outputs[0].scriptPublicKey = "0000" + core.rootScriptV7.genesisRootSpkHexV7({ template: { ...summary.template, recoveryDelayDaa: "1" }, ownerSet: { owners: [...norm.ownerSet.owners], ownerM: "2", emergencyK: "1", recoveryM: "1" } }); }) }, ["PAYLOAD_MISMATCH"]],
    ["root output covenant metadata differs from the review", { payload: mk((s) => { s.outputs[0].covenant = { authorizingInput: 0, covenantId: "0e".repeat(32) }; }) }, ["PAYLOAD_MISMATCH"]],
    ["summary without the exact fee (rc18 review R3-04)", { req: (r) => { delete r.manifest.requiredFeeSompi; } }, ["REVIEW_MISSING"]],
    ["summary with a garbage fee", { req: (r) => { r.manifest.requiredFeeSompi = "lots"; } }, ["REVIEW_MISSING"]],
    ["summary with an inconsistent organization id", { req: (r) => { r.manifest.orgId = "0b".repeat(32); } }, ["REVIEW_MISSING"]],
    ["reviewed rules not supplied (no norm)", { norm: null }, ["REVIEW_MISSING"]],
    ["a second change output smuggled in", { payload: mk((s) => { s.outputs[1].value = "40000000"; s.outputs.push({ value: "10000000", scriptPublicKey: `000020${FUNDER}ac`, covenant: null }); }) }, ["PAYLOAD_MISMATCH"]],
    ["computeBudget / subnetwork changed on a genesis", { payload: mk((s) => { s.subnetworkId = "01" + "00".repeat(19); }) }, ["PAYLOAD_INVALID"]],
    /* rc19 review R4-07 */
    ["genesis with a lock time (a delayed replayable creation)", { payload: mk((s) => { s.lockTime = "4102444800"; }) }, ["PAYLOAD_MISMATCH"]],
    ["summary without the root covenant id", { req: (r) => { delete r.manifest.covenantId; } }, ["REVIEW_MISSING"]]
  ];
  for (const [label, c, codes] of cases) {
    const r = structuredClone(request);
    if (c.payload) r.transaction.unsignedSafeJson = c.payload;
    if (c.req) c.req(r);
    const adapter = countingAdapter(() => "{}");
    await expectRefused(label, () => m2.signGenesisRequest({ request: r, adapter, network: c.network || NET, expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: c.connected || FUNDER, crossCheck: "crossCheck" in c ? c.crossCheck : crossCheck, norm: "norm" in c ? c.norm : norm }), adapter, codes);
  }
});

/* ---------------- rc19 review R4-01 / R4-02: destinations + input closure on MULTI-covenant root transactions ---------------- */
test("R4-02: honest multi-covenant root transactions (a rooted-vault operation under authorize / freeze; a terminal recover with a token position and a payout to the pinned recovery key) SIGN in the owner-slot and fee roles; R4-01: a bare P2SH output, an undeclared covenant, covenant metadata on a P2PK output, a foreign payout or a lock time refuse with zero wallet calls", async () => {
  const { m } = mod();
  const fixtures = ["vault_owner_pause_under_authorize", "vault_emergency_pause_under_freeze", "vault_recover_terminal_with_position"];
  for (const name of fixtures) {
    const manifest = manifestOf(name);
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const rootIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.root.covenantId);
    assert.ok(rootIdx >= 0, `${name}: the fixture carries a root input`);
    const fuelIdx = frozen.inputs.length - 1;
    assert.ok(frozen.inputs.length >= 3, `${name}: a multi-covenant transaction (${frozen.inputs.length} inputs)`);
    const payload = safeJsonFromManifest(manifest);
    const slots = manifest.action.expectedSignerSlots;
    // owner slot
    const okSlot = countingAdapter((u) => { const sj = JSON.parse(u); sj.inputs[rootIdx].signatureScript = `41${"bb".repeat(64)}01`; return JSON.stringify(sj); });
    const env = envelopeFor(manifest, slots[0], payload, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
    await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name) }, slotEnvelope: env, adapter: okSlot, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" });
    assert.equal(okSlot.calls, 1, `${name}: the owner slot signs the honest multi-covenant transaction`);
    assert.equal(okSlot.seen.u, payload);
    // fee input
    const req = () => ({ id: "m1", kind: "rootAction", action: manifest.action.name, state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: rootIdx, manifest: structuredClone(manifest), descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name), slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: payload, signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } }); // the server presents every frozen input (server/src/org-roots.js)
    const fuelSign = (u) => { const sj = JSON.parse(u); sj.inputs[fuelIdx] = { ...sj.inputs[fuelIdx], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(sj); };
    const okFuel = countingAdapter(fuelSign);
    await m.finalizeRequest("r", "m1", req(), { adapter: okFuel, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
    assert.equal(okFuel.calls, 1, `${name}: the fee payer signs the honest multi-covenant transaction`);
    assert.deepEqual(okFuel.seen.list, [{ index: fuelIdx, sighashType: 1 }]);
    // hostile: the manifest's frozen transaction AND the payload are changed CONSISTENTLY (a hostile server authors both)
    // a hostile server authors the manifest too: the frozen transaction is changed consistently AND the manifest is RE-HASHED,
    // so only the destination / input-closure rules can refuse (the hash and the pinned verifier do not)
    const rehash = (r) => { const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; };
    const both = (fn) => (r) => { const sj = JSON.parse(r.transaction.unsignedSafeJson); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson); fn(sj, f); r.transaction.unsignedSafeJson = JSON.stringify(sj); r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f); rehash(r); };
    const changeIdx = frozen.outputs.length - 1; // the fee payer's P2PK change (last output in every fixture)
    assert.equal(frozen.outputs[changeIdx].scriptPublicKey.scriptHex, `20${FUEL_OWNER}ac`, `${name}: the last output is the fee payer's change`);
    const bareP2sh = `aa20${"0d".repeat(32)}87`;
    const cases = [ // [label, mutate, expected codes] — the bare-P2SH cases MUST come from the destination rule itself (PAYLOAD_MISMATCH)
      ["change redirected to a BARE P2SH (no covenant metadata) — rc19 review R4-01", both((sj, f) => { sj.outputs[changeIdx].scriptPublicKey = `0000${bareP2sh}`; f.outputs[changeIdx].scriptPublicKey = { version: 0, scriptHex: bareP2sh }; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]], // rc21 review R6-06: the shared verifier now refuses it first (feePayerChangeBound)
      ["an extra bare P2SH output carrying part of the change", both((sj, f) => { const v = BigInt(sj.outputs[changeIdx].value); sj.outputs[changeIdx].value = (v - 1000n).toString(); f.outputs[changeIdx].value = (v - 1000n).toString(); sj.outputs.push({ value: "1000", scriptPublicKey: `0000${bareP2sh}`, covenant: null }); f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: bareP2sh }, covenant: null }); }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]],
      ["an extra output continuing an UNDECLARED covenant", both((sj, f) => { const v = BigInt(sj.outputs[changeIdx].value); sj.outputs[changeIdx].value = (v - 1000n).toString(); f.outputs[changeIdx].value = (v - 1000n).toString(); const cov = { authorizingInput: 0, covenantId: "0e".repeat(32) }; sj.outputs.push({ value: "1000", scriptPublicKey: `0000${bareP2sh}`, covenant: cov }); f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: bareP2sh }, covenant: cov }); }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]],
      ["covenant metadata attached to the P2PK change", both((sj, f) => { const cov = { authorizingInput: 0, covenantId: manifest.root.covenantId }; sj.outputs[changeIdx].covenant = cov; f.outputs[changeIdx].covenant = cov; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]],
      ["change redirected to another key", both((sj, f) => { sj.outputs[changeIdx].scriptPublicKey = `000020${"0c".repeat(32)}ac`; f.outputs[changeIdx].scriptPublicKey = { version: 0, scriptHex: `20${"0c".repeat(32)}ac` }; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]],
      ["an extra input that is neither the root, a declared covenant nor the fee payer's", both((sj, f) => { sj.inputs.splice(fuelIdx, 0, { ...sj.inputs[fuelIdx], transactionId: "0b".repeat(32), utxo: { ...sj.inputs[fuelIdx].utxo, scriptPublicKey: `000020${"0c".repeat(32)}ac` } }); f.inputs.splice(fuelIdx, 0, { ...f.inputs[fuelIdx], previousOutpoint: { transactionId: "0b".repeat(32), index: 0 }, utxo: { ...f.inputs[fuelIdx].utxo, scriptPublicKey: { version: 0, scriptHex: `20${"0c".repeat(32)}ac` } } }); }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH", "NOT_THE_SIGNER"]], // Codex checkpoint 6 (UX-03): the fee-owner gate (reading the declared fee input) may refuse first
      ["lock time set on a root transaction", both((sj, f) => { sj.lockTime = "5"; f.lockTime = "5"; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]] // rc26 round-7 R7-01: the SHARED verifier now refuses the lockTime FIRST (lockTimeZero) — refused EARLIER, never looser
    ];
    if (name === "vault_recover_terminal_with_position") {
      cases.push(["the vault descriptor withheld from the request (rc21 review R6-02 — the token-side checks can no longer be skipped)", both(() => {}), ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"], (r) => { r.descriptors = {}; }]);
      cases.push(["the token continuation carrying the fee payer's change (rc21 review R6-01)", both((sj, f) => { const ti = sj.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === manifest.vaultOperations[0].tokenCovenantId); const v = BigInt(sj.outputs[changeIdx].value); sj.outputs[changeIdx].value = (v - 1000n).toString(); f.outputs[changeIdx].value = (v - 1000n).toString(); sj.outputs[ti].value = (BigInt(sj.outputs[ti].value) + 1000n).toString(); f.outputs[ti].value = (BigInt(f.outputs[ti].value) + 1000n).toString(); }), ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH", "PAYLOAD_MISMATCH"]]);
      cases.push(["terminal payout redirected away from the pinned recovery key", both((sj, f) => { sj.outputs[0].scriptPublicKey = `000020${"0f".repeat(32)}ac`; f.outputs[0].scriptPublicKey = { version: 0, scriptHex: `20${"0f".repeat(32)}ac` }; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]]);
      /* rc20 review R5-03: the payout is ONE output, at index 0, exactly the predecessor fee reserve — the change can never masquerade as a second payout */
      const recoverySpk = `000020${manifest.vaultOperations[0].manifest.vault.recoveryPk}ac`;
      cases.push(["the fee payer's change redirected to the vault's pinned recovery key as a SECOND payout", both((sj, f) => { sj.outputs[changeIdx].scriptPublicKey = recoverySpk; f.outputs[changeIdx].scriptPublicKey = { version: 0, scriptHex: recoverySpk.slice(4) }; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]]);
      cases.push(["a terminal recover that still CONTINUES its own vault covenant", both((sj, f) => { const v = BigInt(sj.outputs[changeIdx].value); sj.outputs[changeIdx].value = (v - 1000n).toString(); f.outputs[changeIdx].value = (v - 1000n).toString(); const cov = { authorizingInput: 0, covenantId: manifest.vaultOperations[0].covenantId }; sj.outputs.push({ value: "1000", scriptPublicKey: `0000${bareP2sh}`, covenant: cov }); f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: bareP2sh }, covenant: cov }); }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]]);
    }
    /* rc20 review R5-01: the declared families are the INNER manifests' — an outer id cannot license a foreign output, and a
     * covenant output whose authorizing input carries no covenant would CREATE one (a valid genesis under the upstream rule) */
    const FOREIGN = "0e".repeat(32);
    cases.push(["outer tokenCovenantId set to a FOREIGN family and the change tagged with it (genesis-shaped attacker covenant)", both((sj, f) => { const cov = { authorizingInput: fuelIdx, covenantId: FOREIGN }; sj.outputs[changeIdx] = { value: sj.outputs[changeIdx].value, scriptPublicKey: `0000${bareP2sh}`, covenant: cov }; f.outputs[changeIdx] = { value: f.outputs[changeIdx].value, scriptPublicKey: { version: 0, scriptHex: bareP2sh }, covenant: cov }; }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"], (r) => { r.manifest.vaultOperations[0].tokenCovenantId = FOREIGN; }]);
    cases.push(["outer covenantId set to a FOREIGN family (inner manifest untouched)", both(() => {}), ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"], (r) => { r.manifest.vaultOperations[0].covenantId = FOREIGN; }]);
    cases.push(["a genesis-shaped output tagged with the REAL token family but authorized by the plain fee input", both((sj, f) => { const fam = manifest.vaultOperations[0].tokenCovenantId; const cov = { authorizingInput: fuelIdx, covenantId: fam }; const v = BigInt(sj.outputs[changeIdx].value); sj.outputs[changeIdx].value = (v - 1000n).toString(); f.outputs[changeIdx].value = (v - 1000n).toString(); sj.outputs.push({ value: "1000", scriptPublicKey: `0000${bareP2sh}`, covenant: cov }); f.outputs.push({ value: "1000", scriptPublicKey: { version: 0, scriptHex: bareP2sh }, covenant: cov }); }), ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]]);
    /* rc20 review R5-04: the root continuation SCRIPT is rebuilt from the reviewed template + state — a substituted script (metadata kept) refuses */
    const rootOutIdx = frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === manifest.root.covenantId);
    cases.push(["root continuation script substituted (covenant metadata kept)", both((sj, f) => { sj.outputs[rootOutIdx].scriptPublicKey = `0000${bareP2sh}`; f.outputs[rootOutIdx].scriptPublicKey = { version: 0, scriptHex: bareP2sh }; }), ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH", "PAYLOAD_MISMATCH"]]);
    for (const [label, mutate, codes, pre] of cases) {
      const r = req(); if (pre) pre(r); mutate(r);
      const adapter = countingAdapter(fuelSign);
      await expectRefused(`${name}: ${label} (fee role)`, () => m.finalizeRequest("r", "m1", r, { adapter, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), adapter, codes);
      const r2 = req(); if (pre) pre(r2); mutate(r2);
      const adapter2 = countingAdapter((u) => u);
      const env2 = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
      await expectRefused(`${name}: ${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: r2.descriptors, redeemScripts: r2.redeemScripts }, slotEnvelope: env2, adapter: adapter2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), adapter2, codes);
    }
  }
  // succession: the same bare-P2SH change refuses for the successor too
  const sm = manifestOf("root_succession");
  const successor = sm.root.template.successorPk;
  const sreq = { id: "s1", rootCovenantId: sm.root.covenantId, kind: "rootAction", action: "succession", state: "AUTHORIZED", rootInputIndex: 0, manifest: sm, transaction: { unsignedSafeJson: safeJsonFromManifest(sm), signInputs: [{ index: 0, sighashType: 1 }] } };
  const sj = JSON.parse(sreq.transaction.unsignedSafeJson); const f = JSON.parse(sm.transaction.frozenCanonicalJson);
  const last = sj.outputs.length - 1;
  sj.outputs[last].scriptPublicKey = `0000aa20${"0d".repeat(32)}87`; f.outputs[last].scriptPublicKey = { version: 0, scriptHex: `aa20${"0d".repeat(32)}87` };
  sreq.transaction.unsignedSafeJson = JSON.stringify(sj); sm.transaction.frozenCanonicalJson = JSON.stringify(f);
  { const { manifestHash, ...body } = sm; void manifestHash; sreq.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; }
  const sad = countingAdapter(slotSigned);
  await expectRefused("succession: change redirected to a bare P2SH (manifest re-hashed)", () => m.signSingleSignerRequest({ request: sreq, adapter: sad, network: NET, expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor }), sad, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED"]);
});

/* ---------------- Codex checkpoint 6 (UX-02 / UX-13): DERIVED budgets + the rebuilt VAULT successor script ---------------- */
test("Codex checkpoint 6 (UX-02 / UX-13): CONSISTENT substitutions (frozen transaction + payload changed together, manifest re-hashed) of the root, fee, succession and genesis compute budgets and of a rooted vault's successor script are refused BEFORE the wallet in every role; the honest fixtures still sign", async () => {
  const { m } = mod();
  const rehash = (r) => { const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; };
  const both = (fn) => (r) => { const sj = JSON.parse(r.transaction.unsignedSafeJson); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson); fn(sj, f, r.manifest); r.transaction.unsignedSafeJson = JSON.stringify(sj); r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f); rehash(r); };
  const codes = ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH", "PAYLOAD_MISMATCH"];
  /* ROOT-ONLY action: root input 42 -> 0 / 41 / 43 and fee input 10 -> 0 / 11, consistently, with the manifest's declared budget moved too */
  {
    const manifest = manifestOf("root_authorize_2of3");
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    assert.equal(frozen.inputs[0].computeBudget, 42, "fixture sanity: the SDK committed the derived root budget for authorize with 3 active slots");
    assert.equal(frozen.inputs[1].computeBudget, 10, "fixture sanity: the SDK committed the ordinary budget on the fee input");
    const slots = manifest.action.expectedSignerSlots;
    const req = () => ({ id: "b1", kind: "rootAction", action: "authorize", state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: 0, manifest: structuredClone(manifest), descriptors: {}, redeemScripts: {}, slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } });
    const honest = countingAdapter(fuelSigned);
    await m.finalizeRequest("r", "b1", req(), { adapter: honest, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
    assert.equal(honest.calls, 1, "honest control: the fee payer signs");
    for (const [label, v] of [["root input computeBudget 42 -> 0", 0], ["root input computeBudget 42 -> 41 (one below the derived minimum)", 41], ["root input computeBudget 42 -> 43 (declared and frozen moved together)", 43], ["root input computeBudget 42 -> 100", 100]]) {
      const mutate = both((sj, f, mf) => { sj.inputs[0].computeBudget = v; f.inputs[0].computeBudget = v; mf.root.computeBudget = v; });
      const r = req(); mutate(r);
      const a = countingAdapter(fuelSigned);
      await expectRefused(`${label} (fee role)`, () => m.finalizeRequest("r", "b1", r, { adapter: a, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), a, codes);
      const r2 = req(); mutate(r2);
      const a2 = countingAdapter(slotSigned);
      const env = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson);
      await expectRefused(`${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: 0, descriptors: {}, redeemScripts: {} }, slotEnvelope: env, adapter: a2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), a2, codes);
    }
    for (const [label, v] of [["fee input computeBudget 10 -> 0", 0], ["fee input computeBudget 10 -> 11", 11]]) {
      const r = req(); both((sj, f) => { sj.inputs[1].computeBudget = v; f.inputs[1].computeBudget = v; })(r);
      const a = countingAdapter(fuelSigned);
      await expectRefused(`${label} (fee role)`, () => m.finalizeRequest("r", "b1", r, { adapter: a, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), a, codes);
    }
  }
  /* SUCCESSION: root input 20 -> 0, consistently */
  {
    const sm = manifestOf("root_succession");
    const successor = sm.root.template.successorPk;
    const sreq = () => ({ id: "s1", rootCovenantId: sm.root.covenantId, kind: "rootAction", action: "succession", state: "AUTHORIZED", rootInputIndex: 0, manifest: structuredClone(sm), transaction: { unsignedSafeJson: safeJsonFromManifest(sm), signInputs: [{ index: 0, sighashType: 1 }] } });
    const honest = countingAdapter(slotSigned);
    await m.signSingleSignerRequest({ request: sreq(), adapter: honest, network: NET, expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor });
    assert.equal(honest.calls, 1, "honest control: the successor signs");
    for (const v of [0, 19, 21]) {
      const r = sreq(); both((sj, f, mf) => { sj.inputs[0].computeBudget = v; f.inputs[0].computeBudget = v; mf.root.computeBudget = v; })(r);
      const a = countingAdapter(slotSigned);
      await expectRefused(`succession input computeBudget 20 -> ${v}`, () => m.signSingleSignerRequest({ request: r, adapter: a, network: NET, expectedSignerAddress: "kaspa:qsucc", connectedXOnly: successor }), a, ["REVIEW_REFUSED", "PAYLOAD_MISMATCH"]);
    }
  }
  /* ROOTED VAULT operations: the vault input's budget (32 / 31) and the token input's (6), and the vault SUCCESSOR script */
  for (const name of ["vault_owner_pause_under_authorize", "vault_emergency_pause_under_freeze", "vault_recover_terminal_with_position"]) {
    const manifest = manifestOf(name);
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const rootIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.root.covenantId);
    const vaultIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.vaultOperations[0].covenantId);
    const tokenIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.vaultOperations[0].tokenCovenantId);
    const fuelIdx = frozen.inputs.length - 1;
    const slots = manifest.action.expectedSignerSlots;
    const req = () => ({ id: "v1", kind: "rootAction", action: manifest.action.name, state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: rootIdx, manifest: structuredClone(manifest), descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name), slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } });
    const fuelSign = (u) => { const sj = JSON.parse(u); sj.inputs[fuelIdx] = { ...sj.inputs[fuelIdx], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(sj); };
    const honest = countingAdapter(fuelSign);
    await m.finalizeRequest("r", "v1", req(), { adapter: honest, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
    assert.equal(honest.calls, 1, `${name}: honest control signs with the carried redeem script`);
    const cases = [
      [`vault input computeBudget ${frozen.inputs[vaultIdx].computeBudget} -> 0 (declared moved too)`, both((sj, f, mf) => { sj.inputs[vaultIdx].computeBudget = 0; f.inputs[vaultIdx].computeBudget = 0; mf.vaultOperations[0].manifest.transaction.computeBudget = 0; const { manifestHash, ...b } = mf.vaultOperations[0].manifest; void manifestHash; mf.vaultOperations[0].manifest = { ...b, manifestHash: core.intent.computeManifestHashV1(b) }; })],
      [`vault input computeBudget ${frozen.inputs[vaultIdx].computeBudget} -> +1 (declared moved too)`, both((sj, f, mf) => { const v = frozen.inputs[vaultIdx].computeBudget + 1; sj.inputs[vaultIdx].computeBudget = v; f.inputs[vaultIdx].computeBudget = v; mf.vaultOperations[0].manifest.transaction.computeBudget = v; const { manifestHash, ...b } = mf.vaultOperations[0].manifest; void manifestHash; mf.vaultOperations[0].manifest = { ...b, manifestHash: core.intent.computeManifestHashV1(b) }; })],
      ["root input computeBudget 42 -> 0 inside a vault operation", both((sj, f, mf) => { sj.inputs[rootIdx].computeBudget = 0; f.inputs[rootIdx].computeBudget = 0; mf.root.computeBudget = 0; })],
      ["fee input computeBudget 10 -> 0", both((sj, f) => { sj.inputs[fuelIdx].computeBudget = 0; f.inputs[fuelIdx].computeBudget = 0; })],
      ["the vault's predecessor redeem script substituted (another vault's template)", both(() => {}), (r) => { const h = r.redeemScripts[manifest.vaultOperations[0].covenantId]; r.redeemScripts[manifest.vaultOperations[0].covenantId] = h.slice(0, -2) + (h.slice(-2) === "00" ? "01" : "00"); }]
    ];
    if (!manifest.vaultOperations[0].terminal) cases.push(["the vault's predecessor redeem script withheld from the request (a continuation cannot be rebuilt => fail closed)", both(() => {}), (r) => { r.redeemScripts = {}; }]);
    if (tokenIdx >= 0) cases.push(["token input computeBudget 6 -> 0", both((sj, f) => { sj.inputs[tokenIdx].computeBudget = 0; f.inputs[tokenIdx].computeBudget = 0; })]);
    const succIdx = frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === manifest.vaultOperations[0].covenantId);
    if (succIdx >= 0) {
      const bare = `aa20${"5c".repeat(32)}87`;
      cases.push(["vault SUCCESSOR P2SH replaced (covenant metadata preserved, manifest re-hashed) — the pre-sign gap recorded at rc20 review R5-04", both((sj, f) => { sj.outputs[succIdx].scriptPublicKey = `0000${bare}`; f.outputs[succIdx].scriptPublicKey = { version: 0, scriptHex: bare }; })]);
      /* the successor of a DIFFERENT reviewed state (the pause not applied) under the SAME template: consistent everywhere except the reviewed state */
      const redeem = redeemScriptsOf(name)[manifest.vaultOperations[0].covenantId];
      const wrongState = core.vaultScriptV7.reconstructVaultSuccessorSpkHexV7({ redeemHex: redeem, vaultId: manifest.vaultOperations[0].manifest.vault.vaultId, state: manifest.vaultOperations[0].manifest.stateBefore.state });
      cases.push(["vault successor script of the PREDECESSOR state (operation not applied) under the same template", both((sj, f) => { sj.outputs[succIdx].scriptPublicKey = `0000${wrongState}`; f.outputs[succIdx].scriptPublicKey = { version: 0, scriptHex: wrongState }; })]);
    } else {
      /* the redeem is optional on a terminal op but a carried one must still be the vault input's (never a foreign script riding along) */
      cases.push(["a foreign redeem script carried on a terminal operation", both(() => {}), (r) => { r.redeemScripts[manifest.vaultOperations[0].covenantId] = "6b" + "20".concat("44".repeat(32)) + "08" + "00".repeat(8) + "08" + "00".repeat(8) + "20" + "00".repeat(32) + "08" + "00".repeat(8) + "aa"; }]);
    }
    for (const [label, mutate, pre] of cases) {
      const r = req(); if (pre) pre(r); mutate(r);
      const a = countingAdapter(fuelSign);
      await expectRefused(`${name}: ${label} (fee role)`, () => m.finalizeRequest("r", "v1", r, { adapter: a, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), a, codes);
      const r2 = req(); if (pre) pre(r2); mutate(r2);
      const a2 = countingAdapter((u) => u);
      const env2 = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
      await expectRefused(`${name}: ${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: r2.descriptors, redeemScripts: r2.redeemScripts }, slotEnvelope: env2, adapter: a2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), a2, codes);
    }
  }
  /* GENESIS: funding input computeBudget 10 -> 0 / 100 */
  {
    const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
    const OWNERS = { "kaspatest:qown1": K(0x71), "kaspatest:qown2": K(0x72), "kaspatest:qown3": K(0x73), "kaspatest:qfunder": K(0xf1) };
    const api2 = { getJSON: async () => ({}), postJSON: async () => ({ request: { state: "SIGNED" } }), resolveXOnly: async (a) => { if (OWNERS[a]) return OWNERS[a]; throw Object.assign(new Error("bad"), { code: "ADDRESS_INVALID" }); } };
    const m2 = orgRootUiMod.createModule({ api: api2, core, setup: setupMod.createModule({ core }) });
    const draft = { label: "Acme", owners: [{ address: "kaspatest:qown1" }, { address: "kaspatest:qown2" }, { address: "kaspatest:qown3" }], ownerM: "2", emergencyK: "1", recoveryEnabled: true, recoveryM: "1", recoveryDelay: { preset: "30d" }, successionEnabled: false, successorAddress: "", successionDelay: { preset: "90d" }, rootValueKas: "1", rootMaxFeePerTxKas: "0.001", signerAddress: "kaspatest:qfunder" };
    const { norm } = await m2.validateGenesisDraft(draft, { connectedAddress: "kaspatest:qfunder" });
    const slots = core.ownerSetV7.activeOwnerSlotsV7(norm.ownerSet).map((s) => ({ slot: s.slot, publicKey: s.publicKey, address: `kaspatest:qown${s.slot}`, label: "" }));
    const ORG = "0a".repeat(32), COV = "0c".repeat(32);
    const summary = { kind: "genesis-summary", contractVersion: "policyvault-0.7-root", networkId: NET, orgId: ORG, covenantId: COV, template: { orgId: ORG, recoveryDelayDaa: String(norm.recoveryDelayDaa), successorPk: norm.successorPk, successionEnabled: false, successionDelayDaa: String(norm.successionDelayDaa), rootMaxFeePerTx: norm.rootMaxFeePerTxSompi.toString() }, slots, initialState: { ownerM: "2", emergencyK: "1", recoveryM: "1", frozen: "0", rootNonce: "0" }, rootValueKas: "1", txId: "7e".repeat(32), requiredFeeSompi: "208300" };
    const FUNDER = K(0xf1);
    const rootValue = 100000000n, fee = 208300n;
    const ROOT_SPK = "0000" + core.rootScriptV7.genesisRootSpkHexV7({ template: summary.template, ownerSet: { owners: [...norm.ownerSet.owners], ownerM: "2", emergencyK: "1", recoveryM: "1" } });
    const mk = (budget) => JSON.stringify({ id: summary.txId, version: 1, inputs: [{ transactionId: "5e".repeat(32), index: 0, sequence: "0", sigOpCount: 0, computeBudget: budget, signatureScript: "", utxo: { address: null, amount: (rootValue + fee + 50000000n).toString(), scriptPublicKey: `000020${FUNDER}ac`, blockDaaScore: "0", isCoinbase: false, covenantId: null } }], outputs: [{ value: rootValue.toString(), scriptPublicKey: ROOT_SPK, covenant: { authorizingInput: 0, covenantId: COV } }, { value: "50000000", scriptPublicKey: `000020${FUNDER}ac`, covenant: null }], subnetworkId: "00".repeat(20), lockTime: "0", gas: "0", storageMass: "0", payload: "" });
    const crossCheck = m2.genesisCrossCheck({ summary, norm });
    assert.equal(crossCheck.ok, true, crossCheck.mismatches.join(";"));
    const request = (budget) => ({ id: "g1", kind: "rootGenesis", rootCovenantId: COV, manifest: summary, transaction: { unsignedSafeJson: mk(budget), signInputs: [{ index: 0, sighashType: 1 }] } });
    const honest = countingAdapter(() => "{}");
    await m2.signGenesisRequest({ request: request(10), adapter: honest, network: NET, expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: FUNDER, crossCheck, norm });
    assert.equal(honest.calls, 1, "honest genesis control signs with the ordinary budget");
    for (const budget of [0, 9, 11, 100]) {
      const a = countingAdapter(() => "{}");
      await expectRefused(`genesis funding input computeBudget 10 -> ${budget}`, () => m2.signGenesisRequest({ request: request(budget), adapter: a, network: NET, expectedSignerAddress: "kaspatest:qfunder", connectedXOnly: FUNDER, crossCheck, norm }), a, ["PAYLOAD_MISMATCH"]);
    }
  }
});

test("Codex checkpoint 7 (UX-02 / UX-13): CONSISTENT pin / predecessor-state substitutions — root suffix +1000 with the vault budget re-derived, token suffix 1 with the token budget re-derived, recoveryPk replaced with both payouts redirected, the terminal predecessor paused byte falsified (predecessor inputs and both redeems unchanged, manifests re-hashed) — are refused BEFORE the wallet in the fee and slot roles with ZERO wallet calls; the terminal op without its redeem is refused; the honest fixtures (UX-14's three vault operations) still sign exactly once", async () => {
  const { m } = mod();
  const codes = ["REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH", "PAYLOAD_MISMATCH"];
  const rehashInner = (mf) => { const { manifestHash, ...b } = mf.vaultOperations[0].manifest; void manifestHash; mf.vaultOperations[0].manifest = { ...b, manifestHash: core.intent.computeManifestHashV1(b) }; };
  const rehash = (r) => { const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; };
  const both = (fn) => (r) => { const sj = JSON.parse(r.transaction.unsignedSafeJson); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson); fn(sj, f, r.manifest); r.transaction.unsignedSafeJson = JSON.stringify(sj); r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f); rehashInner(r.manifest); rehash(r); };
  const NEW_PK = "9b".repeat(32);
  for (const name of ["vault_owner_pause_under_authorize", "vault_emergency_pause_under_freeze", "vault_recover_terminal_with_position"]) {
    const manifest = manifestOf(name);
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const op = manifest.vaultOperations[0];
    const rootIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.root.covenantId);
    const vaultIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === op.covenantId);
    const tokenIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === op.tokenCovenantId);
    const fuelIdx = frozen.inputs.length - 1;
    const slots = manifest.action.expectedSignerSlots;
    const req = () => ({ id: "v7", kind: "rootAction", action: manifest.action.name, state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: rootIdx, manifest: structuredClone(manifest), descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name), slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: safeJsonFromManifest(manifest), signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } });
    const fuelSign = (u) => { const sj = JSON.parse(u); sj.inputs[fuelIdx] = { ...sj.inputs[fuelIdx], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(sj); };
    const honest = countingAdapter(fuelSign);
    await m.finalizeRequest("r", "v7", req(), { adapter: honest, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
    assert.equal(honest.calls, 1, `${name}: honest control signs once (UX-14)`);
    const honestSlot = countingAdapter((u) => { const sj = JSON.parse(u); sj.inputs[rootIdx].signatureScript = `41${"bb".repeat(64)}01`; return JSON.stringify(sj); });
    const envH = envelopeFor(manifest, slots[0], safeJsonFromManifest(manifest), { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
    await m.signOwnSlot({ request: { manifest: structuredClone(manifest), state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name) }, slotEnvelope: envH, adapter: honestSlot, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" });
    assert.equal(honestSlot.calls, 1, `${name}: honest owner-slot control signs once (UX-14)`);
    const vaultBudgetFor = (mf) => { const v = mf.vaultOperations[0].manifest.vault; return core.computeBudgetV7.selectComputeBudgetV7({ operation: mf.vaultOperations[0].manifest.action.sdkAction, templatePrefixLen: v.templateGeometry.prefixLen, templateSuffixLen: v.templateGeometry.suffixLen, rootPrefixLen: v.rootGeometry.prefixLen, rootSuffixLen: v.rootGeometry.suffixLen }); };
    const cases = [
      ["root suffix length +1000, vault budget re-derived (frozen + payload + declared)", both((sj, f, mf) => { const v = mf.vaultOperations[0].manifest.vault; v.rootGeometry.suffixLen += 1000; const b = vaultBudgetFor(mf); mf.vaultOperations[0].manifest.transaction.computeBudget = b; sj.inputs[vaultIdx].computeBudget = b; f.inputs[vaultIdx].computeBudget = b; })],
      ["root template hash substituted", both((sj, f, mf) => { mf.vaultOperations[0].manifest.vault.rootTemplateVmHash = "9c".repeat(32); })],
      ["descriptor hash substituted", both((sj, f, mf) => { mf.vaultOperations[0].manifest.vault.descriptorHash = "9e".repeat(32); })],
      ["declared predecessor policyNonce +1 (redeem kept)", both((sj, f, mf) => { const st = mf.vaultOperations[0].manifest.stateBefore.state; st.policyNonce = String(BigInt(st.policyNonce) + 1n); })]
    ];
    if (op.terminal) {
      cases.push(["token suffix length 1, token budget re-derived 6 -> 4 (frozen + payload)", both((sj, f, mf) => { const v = mf.vaultOperations[0].manifest.vault; v.templateGeometry.suffixLen = 1; const tb = core.computeBudgetV7.selectTokenInputBudgetV7({ templatePrefixLen: v.templateGeometry.prefixLen, templateSuffixLen: 1 }); assert.equal(tb, 4); sj.inputs[tokenIdx].computeBudget = tb; f.inputs[tokenIdx].computeBudget = tb; const vb = vaultBudgetFor(mf); mf.vaultOperations[0].manifest.transaction.computeBudget = vb; sj.inputs[vaultIdx].computeBudget = vb; f.inputs[vaultIdx].computeBudget = vb; })]);
      cases.push(["recoveryPk substituted, reserve payout redirected and token payout reconstructed to the replacement key", both((sj, f, mf) => {
        const inner = mf.vaultOperations[0].manifest; inner.vault.recoveryPk = NEW_PK; inner.policy.recoveryPk = NEW_PK;
        const descriptor = descriptorsOf(name)[op.covenantId];
        const redeemHex = core.assets.redeemFromSignatureScript(inner.tokenSignatureScriptHex);
        const verified = core.assets.verifyTokenInputRedeem({ descriptor, redeemHex });
        const recoveryState = core.assets.kcc20.encodeState({ ownerIdentifier: NEW_PK, identifierType: core.assets.kcc20.OWNER_SCHEMES.P2PK, amount: verified.state.amount, isMinter: false });
        const tokenOut = core.assets.kcc20.p2shSpkHex(core.assets.kcc20.reconstructRedeem(verified.prefixHex, recoveryState, verified.suffixHex));
        const t = f.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === op.tokenCovenantId);
        f.outputs[0].scriptPublicKey = { version: 0, scriptHex: `20${NEW_PK}ac` }; sj.outputs[0].scriptPublicKey = `000020${NEW_PK}ac`;
        f.outputs[t].scriptPublicKey = { version: 0, scriptHex: tokenOut }; sj.outputs[t].scriptPublicKey = `0000${tokenOut}`;
      })]);
      cases.push(["declared predecessor paused 0 -> 1 while the actual redeem is kept", both((sj, f, mf) => { mf.vaultOperations[0].manifest.stateBefore.state.paused = "1"; })]);
      cases.push(["the terminal operation's redeem withheld (Codex checkpoint 6 left it optional)", both(() => {}), (r) => { r.redeemScripts = {}; }]);
    } else {
      cases.push(["token suffix length 1, vault budget re-derived", both((sj, f, mf) => { const v = mf.vaultOperations[0].manifest.vault; v.templateGeometry.suffixLen = 1; const b = vaultBudgetFor(mf); mf.vaultOperations[0].manifest.transaction.computeBudget = b; sj.inputs[vaultIdx].computeBudget = b; f.inputs[vaultIdx].computeBudget = b; })]);
      cases.push(["contract version relabelled to the HD candidate with root suffix +1000 and budget re-derived", both((sj, f, mf) => { const v = mf.vaultOperations[0].manifest.vault; v.contractVersion = "policyvault-0.7-payment-hd"; v.rootGeometry.suffixLen += 1000; const b = vaultBudgetFor(mf); mf.vaultOperations[0].manifest.transaction.computeBudget = b; sj.inputs[vaultIdx].computeBudget = b; f.inputs[vaultIdx].computeBudget = b; })]);
    }
    for (const [label, mutate, pre] of cases) {
      const r = req(); if (pre) pre(r); mutate(r);
      const a = countingAdapter(fuelSign);
      await expectRefused(`${name}: ${label} (fee role)`, () => m.finalizeRequest("r", "v7", r, { adapter: a, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), a, codes);
      const r2 = req(); if (pre) pre(r2); mutate(r2);
      const a2 = countingAdapter((u) => u);
      const env2 = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
      await expectRefused(`${name}: ${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: r2.descriptors, redeemScripts: r2.redeemScripts }, slotEnvelope: env2, adapter: a2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), a2, codes);
    }
  }
});

/* ================================================================== *
 * rc26 round-7 internal review R7-01 (browser boundary): a hidden RELATIVE
 * LOCK — a non-zero input `sequence` authored CONSISTENTLY into the frozen
 * transaction and the signing payload (a hostile server authors both, and
 * re-hashes the manifest) — is refused in every role with ZERO wallet calls.
 * Only the age-gated root input may carry its covenant delay (the manifest's
 * own `action.minSequence`); every other input must be spendable now. A
 * genesis funding input may never carry a sequence either.
 * ================================================================== */
test("rc26 round-7 R7-01 (browser): non-zero input sequences authored consistently into frozen tx + payload are refused in the slot and fee roles; genesis funding inputs too", async () => {
  const { m } = mod();
  for (const name of ["root_authorize_2of3", "vault_owner_pause_under_authorize"]) {
    const manifest = manifestOf(name);
    const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
    const rootIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.root.covenantId);
    const fuelIdx = frozen.inputs.length - 1;
    const slots = manifest.action.expectedSignerSlots;
    const payload = safeJsonFromManifest(manifest);
    const req = () => ({ id: "m1", kind: "rootAction", action: manifest.action.name, state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: rootIdx, manifest: structuredClone(manifest), descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name), slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: payload, signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } });
    const both = (fn) => (r) => { const sj = JSON.parse(r.transaction.unsignedSafeJson); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson); fn(sj, f); r.transaction.unsignedSafeJson = JSON.stringify(sj); r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f); const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; };
    const fuelSign = (u) => { const sj = JSON.parse(u); sj.inputs[fuelIdx] = { ...sj.inputs[fuelIdx], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(sj); };
    const cases = [
      ["root input sequence 1,000,000 on a NON-age-gated action (hidden relative lock on the root)", both((sj, f) => { sj.inputs[rootIdx].sequence = "1000000"; f.inputs[rootIdx].sequence = "1000000"; })],
      ["fee input sequence 2^32-1 (unminable for 2^32 DAA)", both((sj, f) => { sj.inputs[fuelIdx].sequence = "4294967295"; f.inputs[fuelIdx].sequence = "4294967295"; })],
      ["root input sequence with the DISABLE flag (2^63)", both((sj, f) => { sj.inputs[rootIdx].sequence = "9223372036854775808"; f.inputs[rootIdx].sequence = "9223372036854775808"; })]
    ];
    if (name === "vault_owner_pause_under_authorize") {
      const vi = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.vaultOperations[0].covenantId);
      assert.ok(vi >= 0);
      cases.push(["vault input sequence 1,000,000 (an approved pause that never lands)", both((sj, f) => { sj.inputs[vi].sequence = "1000000"; f.inputs[vi].sequence = "1000000"; })]);
    }
    for (const [label, mutate] of cases) {
      const r = req(); mutate(r);
      const adapter = countingAdapter(fuelSign);
      await expectRefused(`${name}: ${label} (fee role)`, () => m.finalizeRequest("r", "m1", r, { adapter, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), adapter, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]);
      const r2 = req(); mutate(r2);
      const adapter2 = countingAdapter((u) => u);
      const env2 = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
      await expectRefused(`${name}: ${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name) }, slotEnvelope: env2, adapter: adapter2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), adapter2, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]);
    }
  }
  // the age-gated succession keeps its covenant delay on the root input (control: honest) but refuses a sequence on the fee input
  {
    const sm = manifestOf("root_succession");
    const frozen = JSON.parse(sm.transaction.frozenCanonicalJson);
    assert.notEqual(String(frozen.inputs[0].sequence), "0", "control: the succession root input carries the covenant's relative delay");
    const successor = sm.root.template.successorPk;
    const mkReq = () => ({ id: "s1", rootCovenantId: sm.root.covenantId, kind: "rootAction", action: "succession", state: "AUTHORIZED", rootInputIndex: 0, manifest: structuredClone(sm), transaction: { unsignedSafeJson: safeJsonFromManifest(sm), signInputs: [{ index: 0, sighashType: 1 }] } }); // the successor signs the root input only (the fee input is the fuel owner's)
    const honest = countingAdapter(slotSigned);
    await m.signSingleSignerRequest({ request: mkReq(), adapter: honest, network: NET, expectedSignerAddress: "kaspatest:qsucc", connectedXOnly: successor });
    assert.equal(honest.calls, 1, "control: the honest succession (root sequence = the covenant delay, fee sequence 0) signs");
    const r = mkReq();
    const sj = JSON.parse(r.transaction.unsignedSafeJson); const f = JSON.parse(r.manifest.transaction.frozenCanonicalJson);
    const last = sj.inputs.length - 1; sj.inputs[last].sequence = "5"; f.inputs[last].sequence = "5";
    r.transaction.unsignedSafeJson = JSON.stringify(sj); r.manifest.transaction.frozenCanonicalJson = JSON.stringify(f);
    { const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; }
    const sad = countingAdapter(slotSigned);
    await expectRefused("succession: fee input sequence 5 (manifest re-hashed)", () => m.signSingleSignerRequest({ request: r, adapter: sad, network: NET, expectedSignerAddress: "kaspatest:qsucc", connectedXOnly: successor }), sad, ["PAYLOAD_MISMATCH", "REVIEW_REFUSED", "RESPONSE_BINDING_MISMATCH"]);
  }
});

/* Codex checkpoint 11 (R7-02, recipients): through the browser boundary — the setAgentRoot fixture carries every
 * policy's recipients; a set whose recipients are withheld, substituted (root kept) or whose recipient root does not fold
 * from them is refused before any wallet call, in the slot and the fee roles. The honest fixture signs once per role. */
test("Codex checkpoint 11 (R7-02, browser): the setAgentRoot review carries recipients; withheld / substituted recipients are refused with zero wallet calls in both roles", async () => {
  const { m } = mod();
  const name = "vault_set_agent_root_under_authorize";
  const manifest = manifestOf(name);
  const frozen = JSON.parse(manifest.transaction.frozenCanonicalJson);
  const rootIdx = frozen.inputs.findIndex((i) => i.utxo && i.utxo.covenantId === manifest.root.covenantId);
  const fuelIdx = frozen.inputs.length - 1;
  const slots = manifest.action.expectedSignerSlots;
  const payload = safeJsonFromManifest(manifest);
  const req = () => ({ id: "m1", kind: "rootAction", action: manifest.action.name, state: "AUTHORIZED", signaturesPresent: slots.length, requiredApprovals: manifest.action.requiredApprovals, createdBy: "kaspatest:qown1", rootInputIndex: rootIdx, manifest: structuredClone(manifest), descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name), slots: slots.map((sl) => ({ slot: sl.slot, publicKey: sl.publicKey, status: "SIGNED" })), transaction: { unsignedSafeJson: payload, signInputs: frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) } });
  const fuelSign = (u) => { const sj = JSON.parse(u); sj.inputs[fuelIdx] = { ...sj.inputs[fuelIdx], signatureScript: `41${"cc".repeat(64)}01` }; return JSON.stringify(sj); };
  // honest: the review renders the recipients and both roles sign exactly once
  const review = m.renderRequestReviewHtml(req());
  assert.match(review, /may pay ONLY these 1 recipient\(s\): 6363636363636363636363636363636363636363636363636363636363636363/);
  assert.match(review, /data-org-root-review="verified"/);
  const okFuel = countingAdapter(fuelSign);
  await m.finalizeRequest("r", "m1", req(), { adapter: okFuel, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER });
  assert.equal(okFuel.calls, 1);
  const okSlot = countingAdapter((u) => { const sj = JSON.parse(u); sj.inputs[rootIdx].signatureScript = `41${"bb".repeat(64)}01`; return JSON.stringify(sj); });
  const env = envelopeFor(manifest, slots[0], payload, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
  await m.signOwnSlot({ request: { manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name) }, slotEnvelope: env, adapter: okSlot, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" });
  assert.equal(okSlot.calls, 1);
  // hostile: inner manifest edited + re-hashed, outer re-hashed
  const rehash = (r) => { const inner = r.manifest.vaultOperations[0].manifest; const { manifestHash: ih, ...ibody } = inner; void ih; r.manifest.vaultOperations[0].manifest = { ...ibody, manifestHash: core.intent.computeManifestHashV1(ibody) }; const { manifestHash, ...body } = r.manifest; void manifestHash; r.manifest = { ...body, manifestHash: core.intent.computeManifestHashV1(body) }; };
  const ATTACKER = "0d".repeat(32);
  const cases = [
    ["recipients withheld", (r) => { delete r.manifest.vaultOperations[0].manifest.policy.agentSet[0].recipients; rehash(r); }],
    ["recipients substituted (root kept)", (r) => { r.manifest.vaultOperations[0].manifest.policy.agentSet[0].recipients = [ATTACKER]; rehash(r); }],
    ["a recipient appended (root kept)", (r) => { r.manifest.vaultOperations[0].manifest.policy.agentSet[0].recipients.push(ATTACKER); rehash(r); }],
    ["the whole policy set withheld", (r) => { delete r.manifest.vaultOperations[0].manifest.policy.agentSet; rehash(r); }]
  ];
  for (const [label, mutate] of cases) {
    const r = req(); mutate(r);
    assert.match(m.renderRequestReviewHtml(r), /data-org-root-review="refused"/, `${label}: the review renders DO NOT SIGN`);
    const adapter = countingAdapter(fuelSign);
    await expectRefused(`${label} (fee role)`, () => m.finalizeRequest("r", "m1", r, { adapter, network: NET, expectedSignerAddress: "kaspatest:qown1", connectedXOnly: FUEL_OWNER }), adapter, ["RESPONSE_BINDING_MISMATCH", "REVIEW_REFUSED", "PAYLOAD_MISMATCH"]);
    const r2 = req(); mutate(r2);
    const adapter2 = countingAdapter((u) => u);
    const env2 = envelopeFor(r2.manifest, slots[0], r2.transaction.unsignedSafeJson, { root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: rootIdx }, signerRequest: { kind: "sign-transaction", signInputs: [{ index: rootIdx, sighashType: 1 }] } });
    await expectRefused(`${label} (slot role)`, () => m.signOwnSlot({ request: { manifest: r2.manifest, state: "AUTHORIZED", rootInputIndex: rootIdx, descriptors: descriptorsOf(name), redeemScripts: redeemScriptsOf(name) }, slotEnvelope: env2, adapter: adapter2, connectedXOnly: slots[0].publicKey, network: NET, expectedSignerAddress: "kaspa:qowner1" }), adapter2, ["RESPONSE_BINDING_MISMATCH", "REVIEW_REFUSED", "PAYLOAD_MISMATCH"]);
  }
});
