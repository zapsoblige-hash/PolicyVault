"use strict";

/*
 * `transactionHex` carriage (spec §17.2): lowercase hex of the UTF-8 bytes
 * of the rusty-kaspa wasm `Transaction.serializeToSafeJSON()` document.
 * Decode: hex → UTF-8 → strict closed JSON (json-guard: duplicate keys,
 * prototype keys, depth, byte caps) → the sanctioned SDK leaf, which
 * REBUILDS the transaction through the engine and returns the CONSENSUS
 * id (the embedded `id` and every embedded `utxo` are payer-supplied and
 * never trusted).
 */

const { parseStrictJson, GuardError, utf8TextOf } = require("../lib/json-guard");
const { parseSignedTransactionSafeJson } = require("../../sdk/src/tx-identity");
const { refuse } = require("./codes");

const MAX_TX_JSON_BYTES = 384 * 1024;

function parseTransactionCarriage(config, transactionHex) {
  const bytes = Buffer.from(transactionHex, "hex");
  if (bytes.length === 0 || bytes.length > MAX_TX_JSON_BYTES) refuse("SCHEMA_INVALID", "transactionHex decodes to an empty or oversized document");
  let text;
  try {
    text = utf8TextOf(bytes, "SCHEMA_INVALID");
    parseStrictJson(text, { maxBytes: MAX_TX_JSON_BYTES, maxDepth: 8, maxStringBytes: 128 * 1024, tolerateNonIntegerNumbers: false });
  } catch (e) {
    if (e instanceof GuardError) refuse("SCHEMA_INVALID", `transactionHex: ${e.message}`);
    throw e;
  }
  try {
    return parseSignedTransactionSafeJson(config, text);
  } catch (e) {
    refuse("SCHEMA_INVALID", `transactionHex: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
  }
}

module.exports = { parseTransactionCarriage, MAX_TX_JSON_BYTES };
