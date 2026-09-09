"use strict";

/*
 * READ-ONLY transaction-identity + script-public-key helpers backed by the
 * authoritative rusty-kaspa WASM bindings. This is the second sanctioned
 * SDK leaf the x402 facilitator may import (spec §14; the first is
 * sdk/src/chain.js). It signs nothing, builds nothing, broadcasts
 * nothing, holds no state, and never touches a store: it only recomputes
 * consensus identities from bytes handed to it.
 *
 *   parseSignedTransactionSafeJson(config, text)
 *       wasm Transaction.deserializeFromSafeJSON → the CONSENSUS txid and a
 *       normalized read-only view (inputs' outpoints + signature scripts,
 *       outputs' value + script-public-key hex). The embedded `id` and
 *       every embedded `utxo` are caller-supplied and are NOT trusted:
 *       the id is recomputed by the engine, and utxo fields are not
 *       surfaced. NOTE (evidentiary weight): the Kaspa transaction id
 *       does NOT commit to signature scripts (nor to covenant bindings);
 *       a caller must treat signature scripts as consistency data only.
 *   scriptPublicKeyForAddress(config, address)
 *       the canonical script public key of a Kaspa address literal for
 *       the configured network (PubKey / ScriptHash / PubKeyECDSA) via
 *       the WASM parser — no hand-rolled bech32.
 *   addressForScriptPublicKey(config, scriptHex)
 *       the reverse mapping for standard scripts (null when the script is
 *       not a standard address script).
 *   transactionIdOfRpcBody(config, body)            (Codex checkpoint 7, UX-05)
 *       the CONSENSUS id of a transaction BODY as the node returns it in
 *       getBlocks / getBlock / getMempoolEntry answers, recomputed by the
 *       engine constructor from the body's own consensus fields (version,
 *       inputs' previousOutpoint + sequence, outputs' value + script +
 *       covenant binding, lockTime, subnetworkId, gas, payload). The
 *       body's verboseData.transactionId is NOT trusted: a reconciliation
 *       that must prove "transaction X spends outpoint O" derives X from
 *       the bytes that spend O, never from a label riding next to them.
 *       Verified live on testnet-10 (2026-09-06): 101/101 bodies of a
 *       getBlocks batch — coinbase, version 0, version 1, covenant outputs
 *       — recompute to the node's verbose ids. Codex checkpoint 8: every
 *       identity-relevant field is REQUIRED and read strictly (no defaults,
 *       no unsafe JS numbers, no incomplete covenant objects) — a body that
 *       cannot be read exactly has no identity here (it throws).
 *   blockHashOfRpcHeader(config, header)            (Codex checkpoint 7, UX-05)
 *       the block hash recomputed by the engine from a block HEADER as the
 *       node returns it (Header.finalize()); a tampered header field yields
 *       a different hash. Binds a returned block to the hash the answer
 *       lists it under.
 */

const { loadKaspa } = require("./chain");

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

function fail(message) {
  const e = new Error(`tx-identity: ${message}`);
  e.code = "TX_IDENTITY_INVALID";
  throw e;
}

function hexOf(value, label) {
  const hex = typeof value === "string" ? value.toLowerCase() : null;
  if (hex === null || !HEX_RE.test(hex)) fail(`${label} is not even-length hex`);
  return hex;
}

/* The safe-JSON form carries script public keys as "<u16 version LE><script>"
 * hex; the deserialized object exposes them as ScriptPublicKey objects. */
function spkView(spk) {
  if (!spk || typeof spk !== "object") fail("output scriptPublicKey missing");
  const version = Number(spk.version);
  const script = hexOf(spk.script, "output scriptPublicKey.script");
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) fail("output scriptPublicKey.version out of range");
  return { version, scriptHex: script };
}

function parseSignedTransactionSafeJson(config, text) {
  if (typeof text !== "string" || !text) fail("transaction JSON text is required");
  const kaspa = loadKaspa(config);
  let decoded;
  try {
    decoded = kaspa.Transaction.deserializeFromSafeJSON(text);
  } catch (error) {
    fail(`the engine refused the transaction JSON: ${String(error && error.message ? error.message : error).slice(0, 200)}`);
  }
  /*
   * deserializeFromSafeJSON ECHOES the document's embedded `id` (verified
   * against rusty-kaspa 2.0.1 wasm: a tampered `id` field is returned
   * verbatim), and the wasm Transaction caches its id AT CONSTRUCTION
   * (covenant bindings assigned afterwards are NOT reflected in `.id` —
   * verified against the Rust consensus hasher, tests/vm pv_tx_probe).
   * The consensus id is therefore RECOMPUTED by rebuilding the
   * transaction through the engine constructor from the decoded consensus
   * fields INCLUDING each output's covenant binding. Verified against the
   * probe: the id commits to version, inputs' previousOutpoint + sequence,
   * outputs' value + script + covenant binding (authorizing input +
   * covenant id), lockTime, subnetworkId, gas, payload — and NOT to
   * signature scripts, sigOpCount, computeBudget, or utxo entries.
   */
  const inputs = decoded.inputs.map((input, i) => {
    const po = input.previousOutpoint;
    if (!po || typeof po !== "object") fail(`input ${i} previousOutpoint missing`);
    const transactionId = String(po.transactionId).toLowerCase();
    const index = Number(po.index);
    if (!/^[0-9a-f]{64}$/.test(transactionId) || !Number.isInteger(index) || index < 0) fail(`input ${i} previousOutpoint malformed`);
    const utxo = input.utxo;
    const utxoSpk = utxo && utxo.scriptPublicKey ? spkView(utxo.scriptPublicKey) : null;
    return Object.freeze({
      previousOutpoint: Object.freeze({ transactionId, index }),
      signatureScriptHex: hexOf(input.signatureScript ?? "", `input ${i} signatureScript`),
      sequence: BigInt(input.sequence),
      sigOpCount: Number(input.sigOpCount ?? 0),
      computeBudget: Number(input.computeBudget ?? 0),
      // payer-supplied consistency data only (not consensus-verified here)
      suppliedUtxoScriptPublicKeyHex: utxoSpk ? utxoSpk.scriptHex : null
    });
  });
  const outputs = decoded.outputs.map((output, i) => {
    const value = BigInt(output.value);
    if (value < 0n) fail(`output ${i} value negative`);
    const spk = spkView(output.scriptPublicKey);
    const cov = output.covenant;
    const covenantId = cov && cov.covenantId !== undefined ? String(cov.covenantId).toLowerCase() : null;
    if (covenantId !== null && !/^[0-9a-f]{64}$/.test(covenantId)) fail(`output ${i} covenant id malformed`);
    const authorizingInput = covenantId !== null ? Number(cov.authorizingInput) : null;
    if (covenantId !== null && (!Number.isInteger(authorizingInput) || authorizingInput < 0)) fail(`output ${i} covenant authorizingInput malformed`);
    // The covenant binding IS committed by the consensus id (probe-verified), so it is consensus data once the id matches.
    return Object.freeze({ index: i, value, scriptVersion: spk.version, scriptPublicKeyHex: spk.scriptHex, covenantId, authorizingInput });
  });
  let rebuilt;
  try {
    rebuilt = new kaspa.Transaction({
      version: Number(decoded.version),
      inputs: inputs.map((input) => ({
        previousOutpoint: { transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index },
        signatureScript: input.signatureScriptHex,
        sequence: input.sequence,
        sigOpCount: input.sigOpCount,
        computeBudget: input.computeBudget
      })),
      outputs: outputs.map((o) => ({
        value: o.value,
        scriptPublicKey: { version: o.scriptVersion, script: o.scriptPublicKeyHex },
        ...(o.covenantId !== null ? { covenant: { authorizingInput: o.authorizingInput, covenantId: o.covenantId } } : {})
      })),
      lockTime: BigInt(decoded.lockTime),
      subnetworkId: String(decoded.subnetworkId),
      gas: BigInt(decoded.gas),
      payload: String(decoded.payload ?? "")
    });
  } catch (error) {
    fail(`the engine refused to rebuild the transaction: ${String(error && error.message ? error.message : error).slice(0, 200)}`);
  }
  const id = String(rebuilt.id).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(id)) fail("engine returned a malformed transaction id");
  return Object.freeze({
    transactionId: id,
    version: Number(decoded.version),
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    lockTime: BigInt(decoded.lockTime),
    subnetworkId: String(decoded.subnetworkId).toLowerCase(),
    gas: BigInt(decoded.gas),
    payloadHex: hexOf(String(decoded.payload ?? ""), "payload")
  });
}

/*
 * Canonical script public key of an address literal on the configured
 * network. Refuses non-literal / wrong-prefix / invalid addresses and
 * unknown address versions (fail closed). Returns
 * { address, prefix, addressVersion, version: 0, scriptHex }.
 */
function scriptPublicKeyForAddress(config, addressInput) {
  const kaspa = loadKaspa(config);
  if (typeof addressInput !== "string" || !addressInput || addressInput.length > 256) fail("address must be a non-empty string");
  if (addressInput !== addressInput.trim()) fail("address carries surrounding whitespace");
  if (!kaspa.Address.validate(addressInput)) fail("address is not a valid Kaspa address literal");
  const address = new kaspa.Address(addressInput);
  const addressVersion = String(address.version);
  if (addressVersion !== "PubKey" && addressVersion !== "ScriptHash" && addressVersion !== "PubKeyECDSA") {
    fail(`unknown address version ${addressVersion} — fail closed`);
  }
  const spk = kaspa.payToAddressScript(address.toString());
  const view = spkView(spk);
  if (view.version !== 0) fail("only script-public-key version 0 is supported — fail closed");
  return Object.freeze({
    address: address.toString(),
    prefix: String(address.prefix),
    addressVersion,
    version: 0,
    scriptHex: view.scriptHex
  });
}

function addressForScriptPublicKey(config, scriptHex) {
  const kaspa = loadKaspa(config);
  const hex = hexOf(scriptHex, "scriptHex");
  const address = kaspa.addressFromScriptPublicKey({ version: 0, script: hex }, config.networkId);
  return address ? address.toString() : null;
}

const HEX64_RE = /^[0-9a-f]{64}$/;
const U8_MAX = 0xffn, U16_MAX = 0xffffn, U32_MAX = 0xffffffffn, U64_MAX = 0xffffffffffffffffn;

/*
 * Codex checkpoint 8 (UX-05): STRICT field discipline for node-returned bodies. A value is accepted only as a bigint,
 * a SAFE-integer JS number, or a canonical decimal digit string; it must lie inside the field's consensus domain.
 * Everything else is refused: a missing field (null / undefined) is never a zero or an empty payload, a float or a
 * negative is never an integer, a non-canonical string is never a number, and an UNSAFE JS number is never trusted
 * (a raw JSON 9007199254740993 has already become 9007199254740992 by the time any JS code sees it — the bytes are
 * lost before this function runs, so the only honest answer is to refuse the representation). Missing identity-
 * relevant bytes must never turn into guessed values: a body that cannot be read exactly has no identity here.
 */
function strictUint(value, max, label) {
  let v;
  if (typeof value === "bigint") v = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(`${label} is not a safe integer JS number (unsafe magnitude or non-integer) — refusing the representation`);
    v = BigInt(value);
  } else if (typeof value === "string") {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} is not a canonical decimal integer string`);
    v = BigInt(value);
  } else fail(`${label} is missing or not an integer`);
  if (v < 0n || v > max) fail(`${label} is outside its consensus domain`);
  return v;
}
function requireHexString(value, label) {
  if (typeof value !== "string") fail(`${label} is missing or not a hex string`);
  return hexOf(value, label);
}

/* A script public key as the RPC hands it over: either { version, script } or the "safe" string form
 * "<u16 version LE><script>" (what the WASM client's getBlocks / getMempoolEntry bodies carry). Strict: a missing
 * version or script is refused, never defaulted. */
function rpcSpkView(spk, label) {
  if (typeof spk === "string") {
    const hex = hexOf(spk, label);
    if (hex.length < 4) fail(`${label} is shorter than its version prefix`);
    return { version: parseInt(hex.slice(2, 4) + hex.slice(0, 2), 16), scriptHex: hex.slice(4) };
  }
  if (!spk || typeof spk !== "object" || Array.isArray(spk)) fail(`${label} missing`);
  const version = Number(strictUint(spk.version, U16_MAX, `${label}.version`));
  const scriptHex = requireHexString(spk.script, `${label}.script`);
  return { version, scriptHex };
}

/*
 * The consensus id of a node-returned transaction BODY, recomputed by the engine from the body's own fields. Every
 * identity-relevant field is REQUIRED and read strictly (see strictUint): version, inputs' previousOutpoint
 * (transactionId + index) and sequence, outputs' value + script public key + COMPLETE covenant binding (an object
 * carrying an authorizingInput without a covenantId — or the reverse — is malformed, never "no covenant"), lockTime,
 * subnetworkId, gas and payload. signatureScript must be present as hex (it does not enter the id). sigOpCount and
 * computeBudget are the two documented OPTIONAL, non-identity fields (validated when present, u8 / u16). A covenant's
 * authorizingInput must index an input of this body. verboseData is never read here.
 */
function transactionIdOfRpcBody(config, body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) fail("transaction body missing");
  const version = Number(strictUint(body.version, U16_MAX, "version"));
  if (!Array.isArray(body.inputs)) fail("inputs must be an array");
  if (!Array.isArray(body.outputs)) fail("outputs must be an array");
  const inputs = body.inputs.map((input, i) => {
    if (!input || typeof input !== "object" || Array.isArray(input)) fail(`input ${i} missing`);
    const po = input.previousOutpoint;
    if (!po || typeof po !== "object" || Array.isArray(po)) fail(`input ${i} previousOutpoint missing`);
    if (typeof po.transactionId !== "string" || !HEX64_RE.test(po.transactionId.toLowerCase())) fail(`input ${i} previousOutpoint.transactionId missing or malformed`);
    const transactionId = po.transactionId.toLowerCase();
    const index = Number(strictUint(po.index, U32_MAX, `input ${i} previousOutpoint.index`));
    const sequence = strictUint(input.sequence, U64_MAX, `input ${i} sequence`);
    const signatureScript = requireHexString(input.signatureScript, `input ${i} signatureScript`);
    const sigOpCount = input.sigOpCount === undefined || input.sigOpCount === null ? 0 : Number(strictUint(input.sigOpCount, U8_MAX, `input ${i} sigOpCount`));
    const computeBudget = input.computeBudget === undefined || input.computeBudget === null ? 0 : Number(strictUint(input.computeBudget, U16_MAX, `input ${i} computeBudget`));
    return { previousOutpoint: { transactionId, index }, signatureScript, sequence, sigOpCount, computeBudget };
  });
  const outputs = body.outputs.map((output, i) => {
    if (!output || typeof output !== "object" || Array.isArray(output)) fail(`output ${i} missing`);
    const value = strictUint(output.value, U64_MAX, `output ${i} value`);
    if (output.scriptPublicKey === undefined || output.scriptPublicKey === null) fail(`output ${i} scriptPublicKey missing`);
    const spk = rpcSpkView(output.scriptPublicKey, `output ${i} scriptPublicKey`);
    const cov = output.covenant;
    let covenant = null;
    if (cov !== undefined && cov !== null) {
      if (typeof cov !== "object" || Array.isArray(cov)) fail(`output ${i} covenant malformed`);
      if (typeof cov.covenantId !== "string" || !HEX64_RE.test(cov.covenantId.toLowerCase())) fail(`output ${i} covenant.covenantId missing or malformed (an incomplete covenant object is never "no covenant")`);
      const authorizingInput = Number(strictUint(cov.authorizingInput, U16_MAX, `output ${i} covenant.authorizingInput`));
      if (authorizingInput >= inputs.length) fail(`output ${i} covenant.authorizingInput names no input of this body`);
      covenant = { authorizingInput, covenantId: cov.covenantId.toLowerCase() };
    }
    return { value, scriptPublicKey: { version: spk.version, script: spk.scriptHex }, ...(covenant ? { covenant } : {}) };
  });
  const lockTime = strictUint(body.lockTime, U64_MAX, "lockTime");
  const gas = strictUint(body.gas, U64_MAX, "gas");
  const subnetworkId = requireHexString(body.subnetworkId, "subnetworkId");
  if (subnetworkId.length !== 40) fail("subnetworkId is not 20 bytes");
  const payload = requireHexString(body.payload, "payload");
  const kaspa = loadKaspa(config);
  let rebuilt;
  try {
    rebuilt = new kaspa.Transaction({ version, inputs, outputs, lockTime, subnetworkId, gas, payload });
  } catch (error) {
    fail(`the engine refused to rebuild the transaction body: ${String(error && error.message ? error.message : error).slice(0, 200)}`);
  }
  const id = String(rebuilt.id).toLowerCase();
  if (!HEX64_RE.test(id)) fail("engine returned a malformed transaction id");
  return Object.freeze({
    transactionId: id,
    version,
    previousOutpoints: Object.freeze(inputs.map((i) => Object.freeze({ ...i.previousOutpoint }))),
    outputCount: outputs.length
  });
}

function blockHashOfRpcHeader(config, header) {
  if (!header || typeof header !== "object" || Array.isArray(header)) fail("block header missing");
  const kaspa = loadKaspa(config);
  let hash;
  try {
    hash = String(new kaspa.Header(header).finalize()).toLowerCase();
  } catch (error) {
    fail(`the engine refused to hash the block header: ${String(error && error.message ? error.message : error).slice(0, 200)}`);
  }
  if (!HEX64_RE.test(hash)) fail("engine returned a malformed block hash");
  return hash;
}

module.exports = { parseSignedTransactionSafeJson, scriptPublicKeyForAddress, addressForScriptPublicKey, transactionIdOfRpcBody, blockHashOfRpcHeader };
