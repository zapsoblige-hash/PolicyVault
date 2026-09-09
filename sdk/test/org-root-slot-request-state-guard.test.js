"use strict";
/*
 * rc16 internal review N-02 (server-side guard) — an owner slot signing
 * request is issued ONLY while the org-root request is AUTHORIZED. Once it
 * is finalized (SIGNED) or beyond, GET .../slot-request/:slot (which runs
 * getOrCreateSlotSigningRequest) must refuse — even when an envelope for
 * that slot was minted and cached earlier — so no wallet is ever asked to
 * sign for a request that can no longer accept approvals.
 * RED-first: rc16 (d1362d7) returned the cached envelope for every state
 * (reviewer probe p5, docs/postlaunch/audit-evidence/rc16-internal-review/).
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { loadConfig } = require("../src/config");
const wr7 = require("../src/wallet-requests-v7");
const core = require("../../web/core-bundle.js");

const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "core", "explain", "test", "fixtures", "v7-org-root-manifests.json"), "utf8"));

function recordFor(state) {
  const manifest = FIX.manifests.find((m) => m.name === "root_authorize_2of3").manifest;
  const slots = manifest.action.expectedSignerSlots;
  const unsigned = { version: 0, inputs: [{ previousOutpoint: { transactionId: manifest.root.outpoint.transactionId, index: manifest.root.outpoint.index }, sequence: 0, sigOpCount: 1, signatureScript: "" }], outputs: [], lockTime: 0, subnetworkId: "00".repeat(20), gas: 0, payload: "" };
  const envelope = { requestVersion: core.orgRootSlotV7.ORG_ROOT_SLOT_REQUEST_VERSION_1, requestId: "d".repeat(32), manifestHash: manifest.manifestHash, txId: manifest.transaction.txId, network: manifest.network.networkId,
    root: { covenantId: manifest.root.covenantId, outpoint: manifest.root.outpoint, inputIndex: 0 }, slot: { number: slots[2].slot, index: slots[2].slot - 1, publicKey: slots[2].publicKey },
    unsignedSafeJson: JSON.stringify(unsigned), signerRequest: { kind: "sign-transaction", signInputs: [{ index: 0, sighashType: 1 }] }, expiresAtMs: Date.now() + 100000 };
  return { id: "11111111-2222-4333-8444-555555555555", schemaVersion: wr7.ORG_ROOT_REQUEST_SCHEMA, kind: "rootAction", action: "authorize", state, txId: manifest.transaction.txId, rootCovenantId: manifest.root.covenantId, createdAt: new Date().toISOString(),
    slots: [{ slot: 1, publicKey: slots[0].publicKey, status: "SIGNED" }, { slot: 2, publicKey: slots[1].publicKey, status: "SIGNED" }, { slot: 3, publicKey: slots[2].publicKey, status: "PENDING" }],
    manifest, slotRequestEnvelopes: { "3": envelope } };
}

test("getOrCreateSlotSigningRequest refuses for every non-AUTHORIZED state, even with a cached envelope; AUTHORIZED returns the cached envelope", async () => {
  const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-slot-guard-")) });
  try {
    for (const state of ["SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "REFUSED", "FAILED"]) {
      await wr7.saveOrgRootRequest(config, recordFor(state));
      await assert.rejects(() => wr7.getOrCreateSlotSigningRequest({ config, requestId: "11111111-2222-4333-8444-555555555555", slot: 3 }), (e) => e.code === "REQUEST_NOT_SIGNABLE" && new RegExp(`request is ${state}, not AUTHORIZED`).test(e.message), state);
    }
    await wr7.saveOrgRootRequest(config, recordFor("AUTHORIZED"));
    const env = await wr7.getOrCreateSlotSigningRequest({ config, requestId: "11111111-2222-4333-8444-555555555555", slot: 3 });
    assert.equal(env.slot.number, 3);
  } finally {
    fs.rmSync(config.dataRoot, { recursive: true, force: true });
  }
});
