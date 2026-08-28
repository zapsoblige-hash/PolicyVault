"use strict";

/*
 * Canonical FROZEN (unsigned) transaction representation for PolicyVault
 * v0.3+ approval collection (Phase 4H §7/§8) — PURE MODEL CORE.
 *
 * Shared-core extraction step 3 (interface split): this module carries the
 * deterministic members of sdk/src/frozen-tx-v3.js — normalization, the
 * canonical serialization, the local sha256 commitment, and the fee
 * descriptor. The AUTHORITATIVE consensus computations (txId, per-input
 * SIG_HASH_ALL sighash, approval-signature verification via the real
 * rusty-kaspa pv_tx_probe binary) and the WASM transaction builder are
 * IMPURE (child_process/fs/WASM) and live in sdk/src/frozen-tx-v3.js,
 * which composes this module. Member bodies are verbatim from the
 * pre-split sdk implementation.
 *
 * The frozen form is the security object approvers sign against: once a
 * transaction is frozen, every consensus/sighash-visible field is
 * immutable. It deliberately carries NO signature scripts — for
 * version-1 Kaspa transactions neither the transaction ID nor the
 * SIG_HASH_ALL sighash commits signature scripts, so signatures can be
 * collected in any order against the frozen form and the txId computed
 * from it equals the final broadcast txId
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
 */

const crypto = require("crypto");

const { parseSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");

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

/*
 * Fee/mass descriptor for the frozen transaction with the KNOWN final
 * signature-script lengths supplied per input (the frozen form itself is
 * unsigned). Feeds core/model/fee-mass.js calculateRequiredFee.
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

module.exports = {
  fail,
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  feeDescriptorFromFrozen
};
