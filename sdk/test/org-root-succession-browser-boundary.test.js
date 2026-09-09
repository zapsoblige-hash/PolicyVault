"use strict";

/*
 * LAYER: SDK + BROWSER MODULE on a REAL durable record (Codex checkpoint 3,
 * UX-10 / rc18 review R3-10).
 *
 * A real 2-of-3 organizational root is built and submitted (mock chain) with
 * a PINNED successor key; a real succession request installing a MULTI-OWNER
 * replacement set (3 owners, 2-of-3) is then driven through the browser
 * signing boundary (web/org-root-ui.js signSingleSignerRequest) exactly as the
 * hosted UI does — the record is presented the way the server presents it
 * (no `build`), the wallet adapter signs with a real key, and the SDK verifies
 * the resulting signatures on the real VM before SIGNED.
 *
 *   - the PINNED successor signs: ONE wallet call, SIGNED on the real VM;
 *   - an active owner of the OLD set is refused (zero wallet calls);
 *   - the FIRST owner of the NEW set (the retired `ownerSet.after.slots[0]`
 *     heuristic) is refused (zero wallet calls);
 *   - the SDK refuses a raw signature that does not come from the pinned
 *     successor, and refuses a non-successor BUILDING a succession.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const { loadConfig } = require("../src/config");
const { OWNER_SLOTS_V7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const core = require("../../web/core-bundle.js");
const orgRootUiMod = require("../../web/org-root-ui.js");
const setupMod = require("../../web/setup-ui.js");

function freshConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv7-succ-browser-")) });
}
const config = freshConfig();
const available = fs.existsSync(config.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(config.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const SKIP = !available && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const kaspa = available ? require(config.rustyKaspaModule) : null;

const KAS = 100000000n;
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();

function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, key] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, key);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function mockRpc(byAddress = {}) {
  const table = byAddress;
  return {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; }
  };
}
function utxo(address, txId, index, amountSompi, covenantId) {
  return { address, outpoint: { transactionId: txId, index }, amount: BigInt(amountSompi), covenantId: covenantId ?? null };
}
function fuelUtxoFor(fuelKey, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${XO(fuelKey)}ac` };
}
function dense(keys) { const out = []; for (let i = 0; i < OWNER_SLOTS_V7; i += 1) out.push(i < keys.length ? keys[i] : INACTIVE_SLOT_KEY); return out; }
/* The server strips the SDK build (server/src/org-roots.js presentOrgRootRequest). */
function present(request) {
  const { build, encoderBuildDir, finalTransaction, signedSafeJson, slotRequestEnvelopes, ...rest } = request;
  void build; void encoderBuildDir; void finalTransaction; void signedSafeJson; void slotRequestEnvelopes;
  return structuredClone(rest);
}
function realAdapter(key) {
  const a = { calls: 0, seen: null, signInputs: async (u, list, opts) => { a.calls++; a.seen = { u, list, opts }; return signAll(u, list.map((s) => [s.index, key])); } };
  return a;
}
function browserModule(cfg) {
  const calls = [];
  const api = {
    calls,
    getJSON: async () => ({}),
    postJSON: async (p, body) => {
      calls.push({ p, body });
      const m = /\/org-roots\/[^/]+\/requests\/([^/]+)\/signature$/.exec(p);
      if (!m) throw new Error(`unexpected route ${p}`);
      const request = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: decodeURIComponent(m[1]), signedSafeJson: body.signedSafeJson });
      return { request: present(request) };
    },
    resolveXOnly: async (a) => a
  };
  return { api, m: orgRootUiMod.createModule({ api, core, setup: setupMod.createModule({ core }) }) };
}

async function setupRootWithSuccessor(cfg) {
  const owner1 = KEY(0x71), owner2 = KEY(0x72), owner3 = KEY(0x73), successor = KEY(0x5c), funder = KEY(0xf0);
  const rpc = mockRpc();
  const req = await wr7.buildRootGenesisRequest({
    config: cfg, label: "succession org",
    owners: [{ slot: 1, publicKey: XO(owner1) }, { slot: 2, publicKey: XO(owner2) }, { slot: 3, publicKey: XO(owner3) }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: ADDR(successor),
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: ADDR(funder), funding: [fuelUtxoFor(funder)]
  });
  const signed = signAll(req.transaction.unsignedSafeJson, req.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config: cfg, requestId: req.id, signedSafeJson: signed });
  const { covenantAddress } = require("../src/chain");
  const addr = covenantAddress(cfg, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config: cfg, requestId: req.id, rpc });
  return { rootCovenantId: submitted.rootCovenantId, owner1, owner2, owner3, successor, funder, rpc };
}

test("UX-10 (real record): the PINNED successor signs a MULTI-OWNER replacement through the browser boundary and the SDK verifies it on the real VM; an old owner and the new set's first owner are refused with zero wallet calls", { skip: SKIP }, async () => {
  const cfg = freshConfig();
  const { rootCovenantId, owner1, successor } = await setupRootWithSuccessor(cfg);
  const n1 = KEY(0x81), n2 = KEY(0x82), n3 = KEY(0x83);
  const newOwnerSet = { owners: dense([XO(n1), XO(n2), XO(n3)]), ownerM: "2", emergencyK: "1", recoveryM: "1" };

  // a non-successor (an ACTIVE owner of the old set) cannot even BUILD a succession
  await assert.rejects(
    () => wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "succession", params: { newOwnerSet, fuel: fuelUtxoFor(owner1) }, signerAddress: ADDR(owner1) }),
    (e) => { assert.equal(e.code, "NOT_AN_ACTIVE_SLOT"); return true; }
  );

  const raw = await wr7.buildRootActionRequest({ config: cfg, rootCovenantId, action: "succession", params: { newOwnerSet, fuel: fuelUtxoFor(successor) }, signerAddress: ADDR(successor) });
  assert.equal(raw.state, "AUTHORIZED");
  assert.equal(raw.action, "succession");
  const after = raw.manifest.ownerSet.after;
  assert.equal(after.slots.filter((s) => s && s.publicKey && s.publicKey !== INACTIVE_SLOT_KEY).length, 3, "the replacement installs THREE owners (multi-owner succession)");
  assert.equal(String(after.ownerM), "2");
  assert.equal(String(raw.manifest.root.template.successorPk).toLowerCase(), XO(successor), "the manifest pins the successor key");
  assert.notEqual(String(after.slots[0].publicKey).toLowerCase(), XO(successor), "the successor is NOT the first installed owner — the retired slots[0] heuristic would pick the wrong signer");
  const presented = present(raw);
  assert.equal(presented.build, undefined);
  assert.equal(typeof presented.transaction.unsignedSafeJson, "string");
  assert.equal(presented.transaction.signInputs.length, 2, "root input + the successor's own fuel input");

  const NET = cfg.networkId;
  const refused = async (label, connectedKey, codes) => {
    const { m } = browserModule(cfg);
    const adapter = realAdapter(connectedKey);
    let err = null;
    try { await m.signSingleSignerRequest({ request: structuredClone(presented), adapter, network: NET, expectedSignerAddress: ADDR(connectedKey), connectedXOnly: XO(connectedKey) }); } catch (e) { err = e; }
    assert.ok(err, `${label}: refused`);
    assert.ok(codes.includes(err.code), `${label}: code ${err.code} (${err.message})`);
    assert.equal(adapter.calls, 0, `${label}: ZERO wallet calls`);
    assert.equal((await wr7.loadOrgRootRequest(cfg, raw.id)).state, "AUTHORIZED", `${label}: the durable record is untouched`);
  };
  await refused("an active owner of the OLD set connected", owner1, ["NOT_THE_SIGNER"]);
  await refused("the FIRST owner of the NEW set connected (retired ownerSet.after.slots[0] heuristic)", n1, ["NOT_THE_SIGNER"]);

  // the SDK itself refuses a raw signature that is not the pinned successor's
  await assert.rejects(
    () => wr7.submitOrgRootRequestSignature({ config: cfg, requestId: raw.id, signatureHex: "aa".repeat(65), signerAddress: ADDR(owner1), fuelSignatureScriptHex: "41" + "bb".repeat(64) + "01" }),
    (e) => { assert.equal(e.code, "NOT_AN_ACTIVE_SLOT"); return true; }
  );

  // the pinned successor: one wallet call over EXACTLY the frozen payload, then SIGNED (real-VM verified by the SDK)
  const { api, m } = browserModule(cfg);
  const adapter = realAdapter(successor);
  const out = await m.signSingleSignerRequest({ request: structuredClone(presented), adapter, network: NET, expectedSignerAddress: ADDR(successor), connectedXOnly: XO(successor) });
  assert.equal(adapter.calls, 1);
  assert.equal(adapter.seen.u, presented.transaction.unsignedSafeJson, "the payload verified is the payload signed");
  assert.deepEqual(adapter.seen.list.map((s) => s.index), [0, 1]);
  assert.equal(api.calls.length, 1);
  assert.equal(out.request.state, "SIGNED");
  const stored = await wr7.loadOrgRootRequest(cfg, raw.id);
  assert.equal(stored.state, "SIGNED");
  assert.ok(stored.finalTransaction, "the SDK finalized the succession transaction (VM-verified inputs)");
});
