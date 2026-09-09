"use strict";

/*
 * Test harness for the x402 FACILITATOR suites. The facilitator's node
 * access is the ONLY thing stubbed (a scripted UTXO-index + DAG view that
 * records every observation so suites can assert "zero node calls");
 * everything else is the real runtime: real schema/json-guard, real
 * wasm address parsing + txid recomputation, real core/assets KCC20
 * codec on the real compiler-captured template fixture, real JSON claim
 * store, real principal store, real HTTP service.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const http = require("node:http");

const REPO = path.join(__dirname, "..", "..", "..");
const WASM = path.join(os.homedir(), "rusty-kaspa/wasm/nodejs/kaspa");
const chainConfig = Object.freeze({ networkId: "testnet-10", rpcUrl: "ws://127.0.0.1:18210", rustyKaspaModule: WASM });

const assets = require(path.join(REPO, "core/assets"));
const kcc20 = assets.kcc20;
const fixture = require(path.join(REPO, "core/assets/test/fixtures/kcc20-template-v1.json"));
const { scriptPublicKeyForAddress, addressForScriptPublicKey } = require(path.join(REPO, "sdk/src/tx-identity"));
const { AssetRegistry } = require("../../x402-facilitator/assets");
const { JsonClaimStore } = require("../../x402-facilitator/claims");
const { PrincipalStore } = require("../../x402-facilitator/principals");
const { Facilitator } = require("../../x402-facilitator/facilitator");
const { createFacilitatorService } = require("../../x402-facilitator/service");
const { NETWORKS } = require("../../x402-facilitator/constants");

let kaspaModule = null;
function kaspa() {
  if (!kaspaModule) kaspaModule = require(WASM);
  return kaspaModule;
}
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const KEY = (v) => new (kaspa().PrivateKey)(v.toString(16).padStart(2, "0").repeat(32));
const XO = (priv) => priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (priv) => priv.toPublicKey().toAddress("testnet-10").toString();
const P2PK_SPK = (priv) => `20${XO(priv)}ac`;

/* ---------------- token fixture (real compiler bytes, familyBound 2) ---------------- */
const bound2 = fixture.bounds.find((b) => b.familyBound === 2);
const FAMILY_ID = "a7".repeat(32);
const DESCRIPTOR = Object.freeze({
  schema: "policyvault-asset-descriptor/1",
  assetId: FAMILY_ID,
  displayName: "Test Token",
  tokenStandard: "kcc20/1",
  tokenCovenantId: FAMILY_ID,
  acceptedTransferTemplates: [{ templateVmHashBlake2b256: kcc20.templateVmHashHex(bound2.prefixHex, bound2.suffixHex), prefixLen: bound2.prefixLen, suffixLen: bound2.suffixLen, stateLayout: "kcc20-state/1" }],
  decimalsDisplay: 0,
  issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
});
const DESCRIPTOR_HASH = assets.computeDescriptorHash(DESCRIPTOR);
const TOKEN_ASSET = `pvad1:${DESCRIPTOR_HASH}`;

/* A KCC20 redeem for a state, from the real template bytes. */
function tokenRedeemHex(state) {
  return kcc20.bytesToHex(kcc20.reconstructRedeem(bound2.prefixHex, kcc20.encodeState(state), bound2.suffixHex));
}
function tokenSpkHex(state) {
  return kcc20.p2shSpkHex(tokenRedeemHex(state));
}

/* ---------------- stub node ---------------- */
class StubNode {
  constructor({ virtualDaaScore = 1_000_000n, networkId = "testnet-10", isSynced = true, hasUtxoIndex = true } = {}) {
    this.virtualDaaScore = virtualDaaScore;
    this.networkId = networkId;
    this.isSynced = isSynced;
    this.hasUtxoIndex = hasUtxoIndex;
    this.entriesByAddress = new Map();
    this.calls = [];
    this.failWith = null; // Error to throw on observe (node unavailable)
  }
  addEntry(address, entry) {
    const list = this.entriesByAddress.get(address) ?? [];
    list.push({ outpoint: { transactionId: entry.transactionId, index: entry.index }, amount: BigInt(entry.amount), scriptPublicKeyHex: entry.scriptPublicKeyHex, covenantId: entry.covenantId ?? null, blockDaaScore: BigInt(entry.blockDaaScore), isCoinbase: entry.isCoinbase ?? false });
    this.entriesByAddress.set(address, list);
  }
  removeEntry(transactionId, index) {
    for (const [addr, list] of this.entriesByAddress) this.entriesByAddress.set(addr, list.filter((e) => !(e.outpoint.transactionId === transactionId && e.outpoint.index === index)));
  }
  async observe(addresses) {
    this.calls.push([...addresses]);
    if (this.failWith) throw this.failWith;
    const { verifyNodeIdentity } = require("../../x402-facilitator/network");
    const { normalizeEntry } = require("../../x402-facilitator/node");
    const node = verifyNodeIdentity(NETWORKS["kaspa:testnet-10"], { networkId: this.networkId, isSynced: this.isSynced, hasUtxoIndex: this.hasUtxoIndex, serverVersion: "stub-2.0.1" });
    const entries = new Map();
    for (const a of addresses) entries.set(a, (this.entriesByAddress.get(a) ?? []).map(normalizeEntry));
    return Object.freeze({ node, virtualDaaScore: this.virtualDaaScore, entries, observedAt: new Date().toISOString() });
  }
  async close() {}
}

/* ---------------- facilitator under test ---------------- */
function buildFacilitator({ node = new StubNode(), minDepthDaa = 100n, descriptors = [{ descriptorHash: DESCRIPTOR_HASH, descriptor: DESCRIPTOR }], claimsDir = tmp("x402f-claims-") } = {}) {
  const claims = new JsonClaimStore({ dir: claimsDir });
  const registry = new AssetRegistry(descriptors);
  const facilitator = new Facilitator({
    chainConfig,
    bound: NETWORKS["kaspa:testnet-10"],
    assets: registry,
    claims,
    node,
    minDepthDaa,
    addressGate: (address) => scriptPublicKeyForAddress(chainConfig, address),
    addressForScript: (scriptHex) => addressForScriptPublicKey(chainConfig, scriptHex)
  });
  return { facilitator, claims, node, registry, claimsDir };
}

/* ---------------- wire-object builders ---------------- */
function requirements({ payTo, amount = "100000000", asset = "KAS", validFrom = 999_000n, validUntil = 1_001_000n, requirementId = crypto.randomUUID(), resourceUrl = "https://api.example.test/data", network = "kaspa:testnet-10", maxTimeoutSeconds = 30, extraOverrides = {}, overrides = {} } = {}) {
  return {
    scheme: "exact",
    network,
    amount,
    asset,
    payTo,
    maxTimeoutSeconds,
    extra: {
      paymentFlow: "upfront",
      kaspaScheme: "pv-x402-kaspa-exact-upfront/1",
      settlementPolicy: "pv-x402-settlement/1",
      requirementId,
      resourceUrl,
      validFromDaaScore: validFrom.toString(),
      validUntilDaaScore: validUntil.toString(),
      ...extraOverrides
    },
    ...overrides
  };
}
function payload({ accepted, transactionId, outputIndex = 0, payer, transactionHex, outputRedeems, resource } = {}) {
  const inner = { transactionId, outputIndex };
  if (payer !== undefined) inner.payer = payer;
  if (transactionHex !== undefined) inner.transactionHex = transactionHex;
  if (outputRedeems !== undefined) inner.outputRedeems = outputRedeems;
  const p = { x402Version: 2, accepted, payload: inner };
  if (resource !== undefined) p.resource = resource;
  return p;
}
function body({ requirements: r, payload: p, x402Version = 2 }) {
  return JSON.stringify({ x402Version, paymentPayload: p, paymentRequirements: r });
}

/* Real wasm transaction → safe JSON → hex carriage. inputs: [{ txid, index, sigscript, utxoSpk, amount }], outputs: [{ value, spk, covenantId? }] */
function transactionCarriage({ inputs, outputs, payload: payloadHex = "" }) {
  const k = kaspa();
  // Covenant bindings go INTO the constructor: the wasm Transaction caches its
  // id at construction, and the consensus id commits to the bindings
  // (verified against tests/vm pv_tx_probe).
  const tx = new k.Transaction({
    version: 1,
    inputs: inputs.map((i) => ({ previousOutpoint: { transactionId: i.txid, index: i.index }, signatureScript: i.sigscript ?? "", sequence: 0n, sigOpCount: 0, computeBudget: i.computeBudget ?? 10, utxo: { outpoint: { transactionId: i.txid, index: i.index }, amount: BigInt(i.amount ?? 100000000n), scriptPublicKey: { version: 0, script: i.utxoSpk ?? `20${"11".repeat(32)}ac` }, blockDaaScore: 5n, isCoinbase: false } })),
    outputs: outputs.map((o) => ({ value: BigInt(o.value), scriptPublicKey: { version: 0, script: o.spk }, ...(o.covenantId ? { covenant: { authorizingInput: o.authorizingInput ?? 0, covenantId: o.covenantId } } : {}) })),
    lockTime: 0n,
    subnetworkId: "00".repeat(20),
    gas: 0n,
    payload: payloadHex
  });
  const safe = tx.serializeToSafeJSON();
  return { transactionId: String(tx.id).toLowerCase(), safeJson: safe, transactionHex: Buffer.from(safe, "utf8").toString("hex"), tx };
}

/* A P2SH spend's signature script: <sig push> <redeem push> — the redeem is the LAST push. */
function p2shSigscript(redeemHex) {
  const sig = "41" + "ab".repeat(65);
  const redeem = Buffer.from(redeemHex, "hex");
  let push;
  if (redeem.length <= 75) push = redeem.length.toString(16).padStart(2, "0");
  else if (redeem.length <= 255) push = `4c${redeem.length.toString(16).padStart(2, "0")}`;
  else push = `4d${(redeem.length & 0xff).toString(16).padStart(2, "0")}${(redeem.length >> 8).toString(16).padStart(2, "0")}`;
  return `${sig}${push}${redeemHex}`;
}

/* ---------------- HTTP service harness ---------------- */
async function startService({ facilitator, principalsDir = tmp("x402f-principals-"), rateLimitPerMinute = 120, log } = {}) {
  const principals = new PrincipalStore({ dir: principalsDir });
  const logs = [];
  const server = createFacilitatorService({ facilitator, principals, rateLimitPerMinute, log: log ?? ((l) => logs.push(l)) });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const request = (method, pathName, { body: text, headers = {} } = {}) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port, method, path: pathName, headers: { "Content-Type": "application/json", ...headers } }, (res) => {
        let buf = "";
        res.on("data", (d) => (buf += d));
        res.on("end", () => {
          let json = null;
          try {
            json = buf ? JSON.parse(buf) : null;
          } catch {
            json = { raw: buf };
          }
          resolve({ status: res.statusCode, headers: res.headers, json });
        });
      });
      r.on("error", reject);
      if (text !== undefined) r.write(text);
      r.end();
    });
  return { server, principals, port, request, logs, close: () => new Promise((r) => server.close(r)) };
}

module.exports = { REPO, WASM, chainConfig, kaspa, tmp, KEY, XO, ADDR, P2PK_SPK, StubNode, buildFacilitator, requirements, payload, body, transactionCarriage, p2shSigscript, startService, DESCRIPTOR, DESCRIPTOR_HASH, TOKEN_ASSET, FAMILY_ID, tokenRedeemHex, tokenSpkHex, bound2, assets, kcc20, addressForScriptPublicKey, scriptPublicKeyForAddress };
