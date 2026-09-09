"use strict";

/* PRODUCTION-BYTE — sdk/src/tx-identity.js (the read-only txid /
 * script-public-key leaf the x402 facilitator relies on). The recomputed
 * consensus id of a carried transaction is driven through the REAL
 * validator-side hasher (tests/vm pv_tx_probe, describeFrozenTx) — never
 * only a harness that rebuilds the same bytes in-process — for a
 * covenant-carrying transaction, and the two wasm behaviours that make
 * the rebuild necessary are pinned: (1) deserializeFromSafeJSON echoes
 * the embedded `id`; (2) the wasm Transaction caches `.id` at
 * construction, so bindings set afterwards leave a stale id. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { loadConfig } = require("../src/config");
const { normalizeFrozenTxV3 } = require("../../core/model/frozen-tx-v3");
const { describeFrozenTx, frozenToWasmTransaction, TX_PROBE_PATH } = require("../src/frozen-tx-v3");
const { parseSignedTransactionSafeJson, scriptPublicKeyForAddress, addressForScriptPublicKey } = require("../src/tx-identity");

const config = loadConfig({ networkId: "testnet-10" });
const skip = fs.existsSync(TX_PROBE_PATH) ? undefined : "REQUIREMENT_NOT_AVAILABLE: tests/vm pv_tx_probe binary";
const kaspa = require(config.rustyKaspaModule);

const draft = () => ({
  version: 1,
  inputs: [{ previousOutpoint: { transactionId: "aa".repeat(32), index: 0 }, sequence: 0n, computeBudget: 10, utxo: { amount: 500000000n, scriptPublicKey: { version: 0, scriptHex: `20${"11".repeat(32)}ac` }, covenantId: null, blockDaaScore: 0n } }],
  outputs: [
    { value: 100000000n, scriptPublicKey: { version: 0, scriptHex: `aa20${"22".repeat(32)}87` }, covenant: { authorizingInput: 0, covenantId: "cc".repeat(32) } },
    { value: 399990000n, scriptPublicKey: { version: 0, scriptHex: `20${"11".repeat(32)}ac` }, covenant: null }
  ],
  lockTime: 0n, subnetworkId: "00".repeat(20), gas: 0n, payload: ""
});

test("PRODUCTION-BYTE: the rebuilt consensus id of a covenant-carrying transaction equals the Rust tx-probe id, even when the carried document's embedded id is stale or tampered", { skip }, () => {
  const frozen = normalizeFrozenTxV3(draft());
  const probeId = describeFrozenTx(frozen).txId;
  const wasmTx = frozenToWasmTransaction(config, frozen); // bindings assigned post-construction → stale cached .id
  const safe = wasmTx.serializeToSafeJSON();
  assert.notEqual(JSON.parse(safe).id, probeId, "pin: the wasm caches its id at construction (stale embedded id)");
  assert.equal(String(wasmTx.id), JSON.parse(safe).id);
  const view = parseSignedTransactionSafeJson(config, safe);
  assert.equal(view.transactionId, probeId, "rebuild must reproduce the validator-side id");
  assert.equal(view.outputs[0].covenantId, "cc".repeat(32));
  assert.equal(view.outputs[0].authorizingInput, 0);
  assert.equal(view.outputs[1].covenantId, null);
  const tampered = JSON.parse(safe);
  tampered.id = "00".repeat(32);
  assert.equal(kaspa.Transaction.deserializeFromSafeJSON(JSON.stringify(tampered)).id, "00".repeat(32), "pin: deserializeFromSafeJSON echoes the embedded id");
  assert.equal(parseSignedTransactionSafeJson(config, JSON.stringify(tampered)).transactionId, probeId, "the embedded id is ignored");
});

test("PRODUCTION-BYTE: consensus-committed fields change the rebuilt id exactly as they change the probe id; non-committed fields do not", { skip }, () => {
  const base = normalizeFrozenTxV3(draft());
  const baseId = describeFrozenTx(base).txId;
  const mutate = (fn) => {
    const d = draft();
    fn(d);
    return normalizeFrozenTxV3(d);
  };
  const cases = [
    ["output value", mutate((d) => (d.outputs[0].value = 100000001n)), true],
    ["covenant id", mutate((d) => (d.outputs[0].covenant = { authorizingInput: 0, covenantId: "cd".repeat(32) })), true],
    ["covenant removed", mutate((d) => (d.outputs[0].covenant = null)), true],
    ["lockTime", mutate((d) => (d.lockTime = 9n)), true],
    ["computeBudget", mutate((d) => (d.inputs[0].computeBudget = 99)), false]
  ];
  for (const [label, frozen, changes] of cases) {
    const probeId = describeFrozenTx(frozen).txId;
    assert.equal(probeId !== baseId, changes, `probe: ${label}`);
    const view = parseSignedTransactionSafeJson(config, frozenToWasmTransaction(config, frozen).serializeToSafeJSON());
    assert.equal(view.transactionId, probeId, `rebuild == probe for ${label}`);
  }
  // signature scripts are not committed (probe cannot carry them; the wasm rebuild must not let them matter)
  const withSig = JSON.parse(frozenToWasmTransaction(config, base).serializeToSafeJSON());
  withSig.inputs[0].signatureScript = `41${"ab".repeat(65)}`;
  assert.equal(parseSignedTransactionSafeJson(config, JSON.stringify(withSig)).transactionId, baseId);
});

test("script public keys: PubKey / ScriptHash / PubKeyECDSA addresses round-trip through the wasm parser; wrong network, mixed case, whitespace, bad checksum refuse", () => {
  const priv = new kaspa.PrivateKey("77".repeat(32));
  const p2pk = priv.toPublicKey().toAddress("testnet-10").toString();
  const s = scriptPublicKeyForAddress(config, p2pk);
  assert.equal(s.addressVersion, "PubKey");
  assert.equal(s.scriptHex, `20${priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase()}ac`);
  assert.equal(addressForScriptPublicKey(config, s.scriptHex), p2pk);
  const p2shAddr = addressForScriptPublicKey(config, `aa20${"22".repeat(32)}87`);
  assert.equal(scriptPublicKeyForAddress(config, p2shAddr).addressVersion, "ScriptHash");
  assert.equal(scriptPublicKeyForAddress(config, p2shAddr).scriptHex, `aa20${"22".repeat(32)}87`);
  const ecdsa = addressForScriptPublicKey(config, `21${"02".padEnd(66, "3")}ab`);
  assert.equal(scriptPublicKeyForAddress(config, ecdsa).addressVersion, "PubKeyECDSA");
  for (const bad of [p2pk.replace("kaspatest:", "kaspa:"), p2pk.toUpperCase(), ` ${p2pk}`, `${p2pk.slice(0, -1)}q`, "kaspatest:qq", "", 42]) {
    assert.throws(() => scriptPublicKeyForAddress(config, bad), /tx-identity/);
  }
});
