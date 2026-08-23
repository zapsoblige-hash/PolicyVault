"use strict";

/* SDK — canonical frozen-transaction representation: fail-closed
 * normalization, deterministic commitment, and AUTHORITATIVE
 * txId/sighash/verification agreement between the real rusty-kaspa WASM
 * and the real consensus code in pv_tx_probe. Fully offline. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const {
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  describeFrozenTx,
  verifyApprovalSignature,
  feeDescriptorFromFrozen,
  frozenToWasmTransaction
} = require("../src/frozen-tx-v3");

const config = loadConfig({});
const kaspa = require(config.rustyKaspaModule);

const priv = new kaspa.PrivateKey("14".repeat(32));
const XONLY = priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const SPK = `20${XONLY}ac`;

function baseTx(over = {}) {
  return {
    version: 1,
    inputs: [
      {
        previousOutpoint: { transactionId: "ab".repeat(32), index: 0 },
        sequence: "0",
        computeBudget: 31,
        utxo: { amount: "1000000000", scriptPublicKey: { version: 0, scriptHex: SPK }, covenantId: "41".repeat(32), blockDaaScore: "0" }
      },
      {
        previousOutpoint: { transactionId: "cd".repeat(32), index: 1 },
        sequence: "0",
        computeBudget: 10,
        utxo: { amount: "500000000", scriptPublicKey: { version: 0, scriptHex: SPK }, covenantId: null, blockDaaScore: "0" }
      }
    ],
    outputs: [
      { value: "400000000", scriptPublicKey: { version: 0, scriptHex: SPK }, covenant: null },
      { value: "590000000", scriptPublicKey: { version: 0, scriptHex: SPK }, covenant: { authorizingInput: 0, covenantId: "41".repeat(32) } }
    ],
    lockTime: "0",
    ...over
  };
}

test("normalization fails closed on signed inputs, wrong version, non-native fields", () => {
  assert.throws(() => normalizeFrozenTxV3(baseTx({ version: 0 })), /version 1/);
  const signed = baseTx();
  signed.inputs[0].signatureScript = "aa";
  assert.throws(() => normalizeFrozenTxV3(signed), /must not carry a signatureScript/);
  assert.throws(() => normalizeFrozenTxV3(baseTx({ subnetworkId: "01".repeat(20) })), /native subnetwork/);
  assert.throws(() => normalizeFrozenTxV3(baseTx({ gas: "1" })), /gas 0/);
  assert.throws(() => normalizeFrozenTxV3(baseTx({ payload: "aa" })), /empty payload/);
  assert.throws(() => normalizeFrozenTxV3(baseTx({ inputs: [] })), /at least one input/);
  const noUtxo = baseTx();
  delete noUtxo.inputs[0].utxo;
  assert.throws(() => normalizeFrozenTxV3(noUtxo), /utxo is required/);
});

test("canonical serialization is deterministic; commitment changes on every field mutation", () => {
  const frozen = normalizeFrozenTxV3(baseTx());
  assert.equal(canonicalFrozenTxJson(frozen), canonicalFrozenTxJson(normalizeFrozenTxV3(baseTx())));
  const c0 = frozenTxCommitment(frozen);

  const mutations = [
    (t) => (t.inputs[0].previousOutpoint.transactionId = "ac".repeat(32)),
    (t) => (t.inputs[0].previousOutpoint.index = 1),
    (t) => (t.inputs[0].sequence = "1"),
    (t) => (t.inputs[0].computeBudget = 135),
    (t) => (t.inputs[0].utxo.amount = "1000000001"),
    (t) => (t.inputs[0].utxo.scriptPublicKey.scriptHex = `20${"99".repeat(32)}ac`),
    (t) => (t.inputs[0].utxo.covenantId = "42".repeat(32)),
    (t) => (t.outputs[0].value = "400000001"),
    (t) => (t.outputs[0].scriptPublicKey.scriptHex = `20${"98".repeat(32)}ac`),
    (t) => (t.outputs[1].covenant.covenantId = "42".repeat(32)),
    (t) => (t.outputs[1].covenant.authorizingInput = 1),
    (t) => (t.lockTime = "541000000")
  ];
  for (const [i, mutate] of mutations.entries()) {
    const doc = baseTx();
    mutate(doc);
    assert.notEqual(frozenTxCommitment(normalizeFrozenTxV3(doc)), c0, `mutation ${i} must change the commitment`);
  }
});

test("probe txId equals the WASM finalize txId (cross-implementation, covenant outputs included)", () => {
  const frozen = normalizeFrozenTxV3(baseTx());
  const described = describeFrozenTx(frozen);
  const wtx = frozenToWasmTransaction(config, frozen);
  assert.equal(described.txId, wtx.finalize().toString().toLowerCase());
  assert.equal(described.sighashAll.length, 2);
  assert.match(described.sighashAll[0], /^[0-9a-f]{64}$/);
  assert.notEqual(described.sighashAll[0], described.sighashAll[1], "per-input sighashes differ");
});

test("real WASM signature verifies; every tampered variant fails", () => {
  const frozen = normalizeFrozenTxV3(baseTx());
  const wtx = frozenToWasmTransaction(config, frozen);
  const sig = kaspa.createInputSignature(wtx, 0, priv).slice(2); // strip 0x41 push

  assert.deepEqual(verifyApprovalSignature(frozen, 0, sig, XONLY), { valid: true });

  // wrong signer key
  assert.equal(verifyApprovalSignature(frozen, 0, sig, "22".repeat(32)).valid, false);
  // signature for input 0 presented for input 1
  assert.equal(verifyApprovalSignature(frozen, 1, sig, XONLY).valid, false);
  // truncated (64 bytes, missing sighash byte)
  assert.equal(verifyApprovalSignature(frozen, 0, sig.slice(0, 128), XONLY).valid, false);
  // extended (66 bytes)
  assert.equal(verifyApprovalSignature(frozen, 0, sig + "00", XONLY).valid, false);
  // trailing byte not SIG_HASH_ALL
  for (const suffix of ["02", "03", "81", "82", "83", "00", "ff"]) {
    const v = verifyApprovalSignature(frozen, 0, sig.slice(0, -2) + suffix, XONLY);
    assert.equal(v.valid, false, `suffix ${suffix}`);
    assert.match(v.reason, /SIG_HASH_ALL/);
  }
  // corrupted body byte
  const flipped = (parseInt(sig.slice(0, 2), 16) ^ 1).toString(16).padStart(2, "0") + sig.slice(2);
  assert.equal(verifyApprovalSignature(frozen, 0, flipped, XONLY).valid, false);
  // sig against a MUTATED transaction (freeze binding at consensus level)
  const mutated = normalizeFrozenTxV3((() => { const d = baseTx(); d.outputs[0].value = "400000001"; return d; })());
  assert.equal(verifyApprovalSignature(mutated, 0, sig, XONLY).valid, false);
});

test("real non-ALL sighash signatures are rejected by the gate (full matrix)", () => {
  const frozen = normalizeFrozenTxV3(baseTx());
  const wtx = frozenToWasmTransaction(config, frozen);
  const variants = [
    ["None", kaspa.SighashType.None],
    ["Single", kaspa.SighashType.Single],
    ["AllAnyOneCanPay", kaspa.SighashType.AllAnyOneCanPay],
    ["NoneAnyOneCanPay", kaspa.SighashType.NoneAnyOneCanPay],
    ["SingleAnyOneCanPay", kaspa.SighashType.SingleAnyOneCanPay]
  ];
  for (const [name, ty] of variants) {
    const sig = kaspa.createInputSignature(wtx, 0, priv, ty).slice(2);
    assert.equal(sig.length, 130, `${name} sig is 65 bytes`);
    const v = verifyApprovalSignature(frozen, 0, sig, XONLY);
    assert.equal(v.valid, false, `${name} must be rejected`);
    assert.match(v.reason, /SIG_HASH_ALL/, `${name} rejected at the type gate`);
  }
});

test("fee descriptor carries the planned sig-script lengths and covenant flags", () => {
  const frozen = normalizeFrozenTxV3(baseTx());
  const d = feeDescriptorFromFrozen(frozen, [29977, 66]);
  assert.equal(d.inputs[0].signatureScriptHex.length / 2, 29977);
  assert.equal(d.inputs[1].signatureScriptHex.length / 2, 66);
  assert.equal(d.outputs[1].hasCovenant, true);
  assert.throws(() => feeDescriptorFromFrozen(frozen, [100]), /one final sig-script length per input/);
});
