"use strict";

/*
 * Canonical FROZEN (unsigned) transaction representation for PolicyVault
 * v0.3 approval collection (Phase 4H §7/§8).
 *
 * The frozen form is the security object approvers sign against: once a
 * transaction is frozen, every consensus/sighash-visible field is
 * immutable. It deliberately carries NO signature scripts — for
 * version-1 Kaspa transactions neither the transaction ID nor the
 * SIG_HASH_ALL sighash commits signature scripts, so signatures can be
 * collected in any order against the frozen form and the txId computed
 * here equals the final broadcast txId
 * (source: rusty-kaspa consensus/core/src/hashing/{tx.rs,sighash.rs}).
 *
 * SIG_HASH_ALL (v1) COMMITS: tx version; every input's outpoint and
 * sequence; the signed input's spent-UTXO script + amount (which pins the
 * exact predecessor covenant state script); every output's value, script,
 * and covenant binding (authorizingInput + covenantId); lockTime;
 * subnetworkId; gas; payload; and the sighash-type byte.
 *
 * SIG_HASH_ALL (v1) DOES NOT COMMIT: signature scripts, and each input's
 * committed COMPUTE BUDGET. The budget is therefore frozen here as an
 * APPLICATION-INTEGRITY rule (covered by the canonical commitment), not a
 * consensus binding: consensus tolerates budget malleation, which can only
 * make the transaction non-viable (fee shortfall / execution abort), never
 * change where funds go.
 *
 * All authoritative computations on the frozen form (txId, per-input
 * SIG_HASH_ALL sighash, approval signature verification) run through the
 * REAL rusty-kaspa consensus code via the pv_tx_probe binary — never a JS
 * reimplementation of consensus hashing or Schnorr verification.
 */

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { parseSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");

const TX_PROBE_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_tx_probe");
const NATIVE_SUBNETWORK = "00".repeat(20);

function fail(message) {
  throw new Error(`frozen-tx-v3: ${message}`);
}

function normalizeTxId(value, field) {
  return normalizeHex(value, 32, field);
}

function normalizeSpk(input, label) {
  if (!input || typeof input !== "object") {
    fail(`${label} must be a { version, scriptHex } object`);
  }
  const version = Number(input.version ?? 0);
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
    fail(`${label}.version out of range`);
  }
  const scriptHex = String(input.scriptHex ?? "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(scriptHex) || scriptHex.length % 2 !== 0) {
    fail(`${label}.scriptHex must be even-length hex`);
  }
  return Object.freeze({ version, scriptHex });
}

/*
 * Normalize + deep-freeze an unsigned transaction descriptor. Fails closed
 * on anything missing, malformed, or carrying a signature script.
 */
function normalizeFrozenTxV3(input) {
  if (!input || typeof input !== "object") {
    fail("transaction descriptor is required");
  }
  if (Number(input.version) !== 1) {
    fail("frozen transactions must be version 1 (Toccata)");
  }
  if (!Array.isArray(input.inputs) || input.inputs.length === 0) {
    fail("at least one input is required");
  }
  if (!Array.isArray(input.outputs) || input.outputs.length === 0) {
    fail("at least one output is required");
  }
  const inputs = input.inputs.map((entry, i) => {
    if (entry.signatureScript !== undefined && entry.signatureScript !== "") {
      fail(`inputs[${i}] must not carry a signatureScript — the frozen form is unsigned`);
    }
    const op = entry.previousOutpoint;
    if (!op || typeof op !== "object") {
      fail(`inputs[${i}].previousOutpoint is required`);
    }
    const index = Number(op.index);
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
      fail(`inputs[${i}].previousOutpoint.index out of range`);
    }
    const computeBudget = Number(entry.computeBudget);
    if (!Number.isInteger(computeBudget) || computeBudget < 0 || computeBudget > 0xffff) {
      fail(`inputs[${i}].computeBudget out of u16 range`);
    }
    const utxo = entry.utxo;
    if (!utxo || typeof utxo !== "object") {
      fail(`inputs[${i}].utxo is required (amount + scriptPublicKey + covenantId)`);
    }
    return Object.freeze({
      previousOutpoint: Object.freeze({
        transactionId: normalizeTxId(op.transactionId, `inputs[${i}].previousOutpoint.transactionId`),
        index
      }),
      sequence: parseSompi(entry.sequence ?? 0n, `inputs[${i}].sequence`),
      computeBudget,
      utxo: Object.freeze({
        amount: parseSompi(utxo.amount, `inputs[${i}].utxo.amount`),
        scriptPublicKey: normalizeSpk(utxo.scriptPublicKey, `inputs[${i}].utxo.scriptPublicKey`),
        covenantId: utxo.covenantId == null ? null : normalizeHex(utxo.covenantId, 32, `inputs[${i}].utxo.covenantId`),
        blockDaaScore: parseSompi(utxo.blockDaaScore ?? 0n, `inputs[${i}].utxo.blockDaaScore`)
      })
    });
  });
  const outputs = input.outputs.map((entry, i) => {
    const covenant = entry.covenant == null
      ? null
      : Object.freeze({
          authorizingInput: (() => {
            const a = Number(entry.covenant.authorizingInput);
            if (!Number.isInteger(a) || a < 0 || a > 0xffff) {
              fail(`outputs[${i}].covenant.authorizingInput out of range`);
            }
            return a;
          })(),
          covenantId: normalizeHex(entry.covenant.covenantId, 32, `outputs[${i}].covenant.covenantId`)
        });
    return Object.freeze({
      value: parseSompi(entry.value, `outputs[${i}].value`),
      scriptPublicKey: normalizeSpk(entry.scriptPublicKey, `outputs[${i}].scriptPublicKey`),
      covenant
    });
  });
  const subnetworkId = String(input.subnetworkId ?? NATIVE_SUBNETWORK).toLowerCase();
  if (subnetworkId !== NATIVE_SUBNETWORK) {
    fail("frozen transactions must use the native subnetwork");
  }
  const gas = parseSompi(input.gas ?? 0n, "gas");
  if (gas !== 0n) {
    fail("frozen transactions must carry gas 0");
  }
  const payload = String(input.payload ?? "").toLowerCase();
  if (payload !== "") {
    fail("frozen transactions must carry an empty payload");
  }
  return Object.freeze({
    version: 1,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    lockTime: parseSompi(input.lockTime ?? 0n, "lockTime"),
    subnetworkId,
    gas: 0n,
    payload: ""
  });
}

/*
 * The canonical serialization: fixed field order, digit strings for every
 * 64-bit quantity. One frozen transaction has exactly one canonical JSON
 * string; the local package commitment hashes this string.
 */
function canonicalFrozenTxJson(frozen) {
  const doc = {
    version: frozen.version,
    inputs: frozen.inputs.map((i) => ({
      previousOutpoint: { transactionId: i.previousOutpoint.transactionId, index: i.previousOutpoint.index },
      sequence: i.sequence.toString(),
      computeBudget: i.computeBudget,
      utxo: {
        amount: i.utxo.amount.toString(),
        scriptPublicKey: { version: i.utxo.scriptPublicKey.version, scriptHex: i.utxo.scriptPublicKey.scriptHex },
        covenantId: i.utxo.covenantId,
        blockDaaScore: i.utxo.blockDaaScore.toString()
      }
    })),
    outputs: frozen.outputs.map((o) => ({
      value: o.value.toString(),
      scriptPublicKey: { version: o.scriptPublicKey.version, scriptHex: o.scriptPublicKey.scriptHex },
      covenant: o.covenant ? { authorizingInput: o.covenant.authorizingInput, covenantId: o.covenant.covenantId } : null
    })),
    lockTime: frozen.lockTime.toString(),
    subnetworkId: frozen.subnetworkId,
    gas: frozen.gas.toString(),
    payload: frozen.payload
  };
  return JSON.stringify(doc);
}

/* sha256 of the canonical serialization — the LOCAL integrity commitment.
 * NEVER a signing digest: approver authority is the Kaspa Schnorr
 * signature over the real transaction sighash (pv_tx_probe), only. */
function frozenTxCommitment(frozen) {
  return crypto.createHash("sha256").update(canonicalFrozenTxJson(frozen), "utf8").digest("hex");
}

function runTxProbe(args, { allowInvalid = false } = {}) {
  if (!fs.existsSync(TX_PROBE_PATH)) {
    fail(`pv_tx_probe not built: ${TX_PROBE_PATH} (cd tests/vm && cargo build --bin pv_tx_probe)`);
  }
  const result = spawnSync(TX_PROBE_PATH, args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) {
    fail(`pv_tx_probe failed: ${result.stderr?.trim() ?? result.status}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout.trim());
  } catch {
    fail("pv_tx_probe returned invalid JSON");
  }
  if (!allowInvalid && parsed.valid === false) {
    fail(`pv_tx_probe reported invalid: ${parsed.reason}`);
  }
  return parsed;
}

function withFrozenFile(frozen, callback) {
  const p = path.join(os.tmpdir(), `pv3-frozen-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(p, canonicalFrozenTxJson(frozen), { mode: 0o600 });
  try {
    return callback(p);
  } finally {
    fs.unlinkSync(p);
  }
}

/*
 * AUTHORITATIVE description of the frozen transaction from real consensus
 * code: { txId, sighashAll: [hex per input] }. The txId equals the final
 * broadcast txId (v1 txId excludes signature scripts and budgets).
 */
function describeFrozenTx(frozen) {
  const out = withFrozenFile(frozen, (p) => runTxProbe(["describe", p]));
  if (!/^[0-9a-f]{64}$/.test(out.txId ?? "") || !Array.isArray(out.sighashAll)) {
    fail("pv_tx_probe describe returned an unexpected shape");
  }
  return Object.freeze({ txId: out.txId, sighashAll: Object.freeze(out.sighashAll.slice()) });
}

/*
 * AUTHORITATIVE approval-signature verification against the frozen
 * transaction: 65 bytes, trailing 0x01 (SIG_HASH_ALL), Schnorr-valid over
 * the real input sighash for the given x-only key. Returns
 * { valid, reason } and never throws for a merely-invalid signature.
 */
function verifyApprovalSignature(frozen, inputIndex, signatureHex, xOnlyPubkey) {
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= frozen.inputs.length) {
    fail("verifyApprovalSignature: input index out of range");
  }
  if (typeof signatureHex !== "string" || !/^[0-9a-f]*$/.test(signatureHex) || signatureHex.length % 2 !== 0) {
    return Object.freeze({ valid: false, reason: "signature must be lowercase hex" });
  }
  const key = normalizeHex(xOnlyPubkey, 32, "approver key");
  const out = withFrozenFile(frozen, (p) =>
    runTxProbe(["verify", p, String(inputIndex), signatureHex, key], { allowInvalid: true })
  );
  if (out.valid === true) {
    return Object.freeze({ valid: true });
  }
  return Object.freeze({ valid: false, reason: String(out.reason ?? "invalid") });
}

/*
 * Fee/mass descriptor for the frozen transaction with the KNOWN final
 * signature-script lengths supplied per input (the frozen form itself is
 * unsigned). Feeds sdk/src/fee-mass.js calculateRequiredFee.
 */
function feeDescriptorFromFrozen(frozen, sigScriptLengths) {
  if (!Array.isArray(sigScriptLengths) || sigScriptLengths.length !== frozen.inputs.length) {
    fail("feeDescriptorFromFrozen needs one final sig-script length per input");
  }
  return {
    version: frozen.version,
    payloadHex: frozen.payload,
    inputs: frozen.inputs.map((input, i) => {
      const len = sigScriptLengths[i];
      if (!Number.isInteger(len) || len < 0) {
        fail(`sigScriptLengths[${i}] must be a non-negative integer`);
      }
      return { signatureScriptHex: "00".repeat(len), computeBudget: input.computeBudget };
    }),
    outputs: frozen.outputs.map((o) => ({ scriptHex: o.scriptPublicKey.scriptHex, hasCovenant: o.covenant !== null }))
  };
}

/*
 * Build a WASM Transaction object (rusty-kaspa wasm bindings) from the
 * frozen form — the exact object wallet adapters / the dev signer sign.
 * Uses the shared loadKaspa module loader; works fully offline.
 */
function frozenToWasmTransaction(config, frozen) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const { Transaction, CovenantBinding, Hash } = kaspa;
  const txObject = {
    version: 1,
    inputs: frozen.inputs.map((input) => ({
      previousOutpoint: { transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index },
      signatureScript: "",
      sequence: input.sequence,
      sigOpCount: 0,
      computeBudget: input.computeBudget,
      utxo: {
        outpoint: { transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index },
        amount: input.utxo.amount,
        scriptPublicKey: { version: input.utxo.scriptPublicKey.version, script: input.utxo.scriptPublicKey.scriptHex },
        blockDaaScore: input.utxo.blockDaaScore,
        isCoinbase: false
      }
    })),
    outputs: frozen.outputs.map((o) => ({
      value: o.value,
      scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex }
    })),
    lockTime: frozen.lockTime,
    subnetworkId: frozen.subnetworkId,
    gas: frozen.gas,
    payload: frozen.payload
  };
  const transaction = new Transaction(txObject);
  const outs = transaction.outputs;
  let bound = false;
  frozen.outputs.forEach((o, i) => {
    if (o.covenant) {
      outs[i].covenant = new CovenantBinding(o.covenant.authorizingInput, new Hash(o.covenant.covenantId));
      bound = true;
    }
  });
  if (bound) {
    transaction.outputs = outs;
  }
  return transaction;
}

module.exports = {
  TX_PROBE_PATH,
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  describeFrozenTx,
  verifyApprovalSignature,
  feeDescriptorFromFrozen,
  frozenToWasmTransaction
};
