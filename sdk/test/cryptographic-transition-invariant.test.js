"use strict";

/*
 * PERMANENT REGRESSION — owner addendum §F (rc11 internal review F-04):
 *
 *   "No server-side state transition with cryptographic meaning may be driven
 *    by field presence alone. The cryptographic evidence must first be
 *    verified against the exact expected signer, key/slot, request domain,
 *    and commitment."
 *
 * RED before the fix: POST .../signature with a 66-byte ZERO signature script
 * moved a v5 genesis request and a v7 root-genesis request to SIGNED
 * (docs/postlaunch/audit-evidence/rc11-internal-review/logs/tenancy-probe.json
 * T7 / T16) — presence of a blob was sufficient.
 *
 * Every SIGNED transition now executes EVERY input of the signed transaction
 * on the production Kaspa script engine (sdk/src/vm-preflight.js) against its
 * spent UTXO before persisting. Negative matrix per generation:
 *   1. arbitrary string / structurally valid zero signature;
 *   2. structurally valid signature from the WRONG key;
 *   3. the RIGHT key over the WRONG commitment (replay from another request);
 *   4. correct signature => SIGNED (control), and refusals leave the request
 *      in its pre-signature state (never wedged, never SIGNED).
 * Org-root M-of-N slot evidence (core/signer/org-root-slot-v7) is exercised
 * for wrong slot / outsider key / replay / stale predecessor-root binding.
 * Classified REQUIREMENT_NOT_AVAILABLE (skipped) without silverc/pv_* binaries.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const { PREFLIGHT_PATH } = require("../src/vm-preflight");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const wr5 = require("../src/wallet-requests-v5");
const wr7 = require("../src/wallet-requests-v7");
const wr4 = require("../src/wallet-requests-v4");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-cti-")) });
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(PREFLIGHT_PATH);
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_vm_preflight";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const fundingUtxoFor = (key, amount = 50n * KAS) => ({ outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(key)}ac` });

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
/* keep every consensus field, replace only the signature scripts */
function withSigScripts(unsignedSafeJson, scripts) {
  const t = JSON.parse(unsignedSafeJson);
  t.inputs = t.inputs.map((i, k) => ({ ...i, signatureScript: scripts[k] ?? scripts[0] }));
  return JSON.stringify(t);
}
/* the signature scripts a wallet produced for ANOTHER transaction (replay) */
function sigScriptsOf(signedSafeJson) {
  return JSON.parse(signedSafeJson).inputs.map((i) => i.signatureScript);
}

function v5Descriptor() {
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  return {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "CTI Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
}

test("v5 GENESIS: zero / wrong-key / replayed signatures never reach SIGNED; the real signature does", { skip: SKIP }, async () => {
  const owner = KEY(0x61), stranger = KEY(0x62), agent = KEY(0x63), recipient = KEY(0x64);
  const rTree = buildRecipientTree([XO(recipient)]);
  const agentPolicy = { agentPk: XO(agent), tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: rTree.root, recipients: [XO(recipient)] };
  const descriptor = v5Descriptor();
  const build = (label) => wr5.buildCreateWalletRequestV5({ config, label, descriptor, templateIndex: 0, initialAgents: [agentPolicy], feeReserveKas: "5", signerAddress: ADDR(owner), funding: [fundingUtxoFor(owner)] });
  const A = await build("A"), B = await build("B");
  const attempt = (signedSafeJson) => wr5.submitSignatureV5({ config, requestId: A.requestId, signedSafeJson });
  // 1. structurally valid ZERO signature (the audit's exact bogus blob)
  await assert.rejects(() => attempt(withSigScripts(A.transaction.unsignedSafeJson, ["41" + "00".repeat(65)])), (e) => e.code === "SIGNATURE_INVALID");
  // 1b. arbitrary non-hex string
  await assert.rejects(() => attempt(withSigScripts(A.transaction.unsignedSafeJson, ["not a signature"])), (e) => e.code === "SIGNATURE_INVALID");
  // 2. real Schnorr signature from the WRONG key over the right transaction
  await assert.rejects(() => attempt(signAll(A.transaction.unsignedSafeJson, A.transaction.signInputs.map((s) => [s.index, stranger]))), (e) => e.code === "SIGNATURE_INVALID");
  // 3. the RIGHT key over the WRONG commitment: B's real signature scripts applied to A
  const signedB = signAll(B.transaction.unsignedSafeJson, B.transaction.signInputs.map((s) => [s.index, owner]));
  await assert.rejects(() => attempt(withSigScripts(A.transaction.unsignedSafeJson, sigScriptsOf(signedB))), (e) => e.code === "SIGNATURE_INVALID");
  // refusals are pure: A is still BUILT, never SIGNED, never wedged
  assert.equal((await wr5.loadWalletRequestV5(config, A.requestId)).state, "BUILT");
  // 4. control
  const ok = await attempt(signAll(A.transaction.unsignedSafeJson, A.transaction.signInputs.map((s) => [s.index, owner])));
  assert.equal(ok.state, "SIGNED");
});

test("v7 ROOT GENESIS: zero / wrong-key / replayed funder signatures never reach SIGNED; the funder's does", { skip: SKIP }, async () => {
  const funder = KEY(0x71), stranger = KEY(0x72), o2 = KEY(0x73), o3 = KEY(0x74);
  const build = (label) => wr7.buildRootGenesisRequest({ config, label, owners: [{ slot: 1, address: ADDR(funder) }, { slot: 2, address: ADDR(o2) }, { slot: 3, address: ADDR(o3) }], ownerM: 2, emergencyK: 1, recoveryM: 2, recoveryDelayDaa: "100", successionDelayDaa: "100", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder), funding: [fundingUtxoFor(funder)] });
  const A = await build("A"), B = await build("B");
  const attempt = (signedSafeJson) => wr7.submitOrgRootRequestSignature({ config, requestId: A.id, signedSafeJson });
  await assert.rejects(() => attempt(withSigScripts(A.transaction.unsignedSafeJson, ["41" + "00".repeat(65)])), (e) => e.code === "SIGNATURE_INVALID");
  await assert.rejects(() => attempt(signAll(A.transaction.unsignedSafeJson, [[0, stranger]])), (e) => e.code === "SIGNATURE_INVALID");
  const signedB = signAll(B.transaction.unsignedSafeJson, [[0, funder]]);
  await assert.rejects(() => attempt(withSigScripts(A.transaction.unsignedSafeJson, sigScriptsOf(signedB))), (e) => e.code === "SIGNATURE_INVALID");
  assert.equal((await wr7.loadOrgRootRequest(config, A.id)).state, "AUTHORIZED", "refusals leave the request AUTHORIZED for the legitimate funder");
  const ok = await attempt(signAll(A.transaction.unsignedSafeJson, [[0, funder]]));
  assert.equal(ok.state, "SIGNED");
});

test("v4 SPEND: a correct covenant signature with a WRONG-KEY fuel signature is refused (every input verified, not only the covenant input)", { skip: SKIP }, async () => {
  const { normalizeAgentPolicyV4, buildAgentTreeV4 } = require("../../core/model/agent-merkle-v4");
  const vs4 = require("../../core/model/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const owner = KEY(0x81), agent = KEY(0x82), recipient = KEY(0x83), stranger = KEY(0x84);
  const VAULT_ID = "3c".repeat(32);
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const entry = { agentPk: XO(agent), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)] };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  await persistManifestV4(config, { schema: MANIFEST_SCHEMA_V4, contractVersion: vs4.CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID, label: "cti", status: "ACTIVE", template, agentRegistry: [entry], live: { state: vs4.stateToJsonV4(state), stateId: vs4.computeStateIdV4({ networkId: config.networkId, template, state }), outpoint: { transactionId: "0c".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) }, creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null });
  const fuel = { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(agent)}ac` };
  const req = await wr4.buildWalletRequestV4({ config, vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: XO(agent), recipient: XO(recipient), fuel }, signerAddress: ADDR(agent) });
  assert.equal(req.transaction.signInputs.length, 2, "covenant input + fuel input");
  // covenant input signed by the agent (correct), FUEL input signed by a stranger (wrong key)
  const mixed = signAll(req.transaction.unsignedSafeJson, [[0, agent], [1, stranger]]);
  await assert.rejects(() => wr4.finalizeWalletRequestV4({ config, requestId: req.requestId, signedSafeJson: mixed }), (e) => /PREFLIGHT_FAILED|SIGNATURE_INVALID/.test(e.code));
  const after = await wr4.loadRequest(config, req.requestId);
  assert.notEqual(after.state, "PREFLIGHT_VERIFIED");
  assert.match(String(after.error || ""), /input 1|preflight/i);
});

function mockRpc() {
  const table = {};
  return {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; }
  };
}
const utxo = (address, txId, index, amountSompi, covenantId) => ({ address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null });

/* genesis a LIVE root on a mock chain (the org-roots API test's exact driver) */
async function liveRoot(label, funder, owners) {
  const { covenantAddress } = require("../src/chain");
  const req = await wr7.buildRootGenesisRequest({ config, label, owners: owners.map((k, i) => ({ slot: i + 1, address: ADDR(k) })), ownerM: 2, emergencyK: 1, recoveryM: 2, recoveryDelayDaa: "100", successionDelayDaa: "100", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder), funding: [fundingUtxoFor(funder)] });
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: req.id, signedSafeJson: signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder])) });
  const rpc = mockRpc();
  const addr = covenantAddress(config, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: req.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return req.rootCovenantId;
}

test("org-root M-of-N slot evidence: wrong slot, outsider key, replay from another request, and a stale predecessor-root binding are all refused before any SIGNED state", { skip: SKIP }, async () => {
  const funder = KEY(0x91), o1 = KEY(0x92), o2 = KEY(0x93), o3 = KEY(0x94), outsider = KEY(0x95), fuel = KEY(0x96);
  const { verifyRootSlotSignatureResponse } = require("../../core/signer/org-root-slot-v7");
  const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
  const rootA = await liveRoot("A", funder, [o1, o2, o3]);
  const rootB = await liveRoot("B", funder, [o1, o2, o3]);
  const actA = await wr7.buildRootActionRequest({ config, rootCovenantId: rootA, action: "authorize", params: { fuel: fundingUtxoFor(fuel) }, signerAddress: ADDR(o1) });
  const actB = await wr7.buildRootActionRequest({ config, rootCovenantId: rootB, action: "authorize", params: { fuel: fundingUtxoFor(fuel) }, signerAddress: ADDR(o1) });
  const ownerSet = normalizeRootStateV7((await wr7.loadOrgRoot(config, rootA)).state);
  const sign65 = (req, key) => kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(req.transaction.unsignedSafeJson), req.rootInputIndex, key).slice(2);
  const respond = (env, req, key, over = {}) => ({ responseVersion: "policyvault-org-root-slot-response/1", requestVersion: env.requestVersion, requestId: env.requestId, network: env.network, manifestHash: env.manifestHash, txId: env.txId, root: env.root, slot: env.slot, signerAddress: ADDR(key), signatureHex: sign65(req, key), sighashType: 1, signedAtMs: Date.now(), ...over });
  const envA1 = await wr7.getOrCreateSlotSigningRequest({ config, requestId: actA.id, slot: 1 });
  const envB1 = await wr7.getOrCreateSlotSigningRequest({ config, requestId: actB.id, slot: 1 });
  const now = Date.now();
  // control: slot-1 owner signs its own envelope
  assert.equal(verifyRootSlotSignatureResponse({ request: envA1, response: respond(envA1, actA, o1), ownerSet, nowMs: now }).slot, 1);
  // outsider key
  assert.throws(() => verifyRootSlotSignatureResponse({ request: envA1, response: respond(envA1, actA, outsider), ownerSet, nowMs: now }));
  // wrong slot: slot-2 owner's key on the slot-1 envelope
  assert.throws(() => verifyRootSlotSignatureResponse({ request: envA1, response: respond(envA1, actA, o2), ownerSet, nowMs: now }));
  // replay: request B's envelope response presented against A's envelope
  assert.throws(() => verifyRootSlotSignatureResponse({ request: envA1, response: respond(envB1, actB, o1), ownerSet, nowMs: now }));
  // stale predecessor-root binding: verified against an owner set that rotated o1 out
  const base = normalizeRootStateV7((await wr7.loadOrgRoot(config, rootA)).state);
  const rotated = { ...base, owners: base.owners.map((k, i) => (i === 0 ? XO(outsider) : k)) }; // slot 1 rotated out in the predecessor set
  assert.throws(() => verifyRootSlotSignatureResponse({ request: envA1, response: respond(envA1, actA, o1), ownerSet: rotated, nowMs: now }));
  // zero signature blob
  assert.throws(() => verifyRootSlotSignatureResponse({ request: envA1, response: respond(envA1, actA, o1, { signatureHex: "00".repeat(64) }), ownerSet, nowMs: now }));
  // the durable request never moved: still AUTHORIZED with zero signatures
  const after = await wr7.loadOrgRootRequest(config, actA.id);
  assert.equal(after.state, "AUTHORIZED"); assert.equal(after.signaturesPresent, 0);
  // through the SDK route: the same hostile responses are refused by submitSlotSignature (no state change)
  await assert.rejects(() => wr7.submitSlotSignature({ config, requestId: actA.id, slot: 1, response: respond(envA1, actA, outsider) }));
  await assert.rejects(() => wr7.submitSlotSignature({ config, requestId: actA.id, slot: 2, response: respond(envA1, actA, o1) }));
  assert.equal((await wr7.loadOrgRootRequest(config, actA.id)).signaturesPresent, 0);
});
