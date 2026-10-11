"use strict";

/*
 * PolicyVault v0.3 FROZEN-transaction module — sdk COMPOSITION SHELL
 * (shared-core extraction step 3).
 *
 * The deterministic model members (normalization, canonical
 * serialization, local sha256 commitment, fee descriptor) live in
 * core/model/frozen-tx-v3.js and are re-exported here unchanged. This
 * file keeps ONLY the impure members, verbatim from the pre-split
 * implementation except for RC45 R1-04's harness-failure marker
 * (harnessStep):
 *
 *   - describeFrozenTx / verifyApprovalSignature — the AUTHORITATIVE
 *     consensus computations (txId, per-input SIG_HASH_ALL sighash,
 *     Schnorr approval verification) through the REAL rusty-kaspa
 *     consensus code via the pv_tx_probe binary — never a JS
 *     reimplementation of consensus hashing or Schnorr verification;
 *   - frozenToWasmTransaction — the rusty-kaspa WASM Transaction builder
 *     wallet adapters / the dev signer sign;
 *   - TX_PROBE_PATH and the temp-file/spawn plumbing.
 *
 * See core/model/frozen-tx-v3.js for the frozen-form/sighash-semantics
 * commentary (what SIG_HASH_ALL v1 commits and does not commit).
 */

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { normalizeHex } = require("./vault-state");
const {
  fail,
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  feeDescriptorFromFrozen
} = require("../../core/model/frozen-tx-v3");

const TX_PROBE_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_tx_probe");

/* RC45 R1-04 (plan R1 ST-01, C10): a failure of the pv_tx_probe harness itself
 * says nothing about the frozen transaction and is marked `harnessFailure`: the
 * binary missing (ENOENT, before or at the spawn), a spawn error, termination
 * by a signal, or a temp-file I/O error (create, write, the probe's read,
 * unlink). A probe rejection (the probe ran and refused its input) or an
 * invalid output shape stays unmarked. The marker changes no error code and no
 * other caller's behaviour (a spawn error or a signal now names itself in the
 * message); wallet-recovery-v4.js validateIdentity carries it into
 * environmentStep. A non-Error or non-extensible throw is carried in a new
 * Error with the same message, so it is still marked. */
function harnessStep(step) {
  try {
    return step();
  } catch (error) {
    const marked = error instanceof Error && Object.isExtensible(error) ? error : new Error(String(error?.message ?? error));
    marked.harnessFailure = true;
    throw marked;
  }
}

function runTxProbe(args, { allowInvalid = false } = {}) {
  if (!fs.existsSync(TX_PROBE_PATH)) {
    harnessStep(() => fail(`pv_tx_probe not built: ${TX_PROBE_PATH} (cd tests/vm && cargo build --bin pv_tx_probe)`));
  }
  const result = spawnSync(TX_PROBE_PATH, args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (result.error) harnessStep(() => fail(`pv_tx_probe failed: ${result.error.message}`));
  if (result.signal) harnessStep(() => fail(`pv_tx_probe failed: terminated by ${result.signal}`));
  if (result.status !== 0) {
    // The probe's own read of its input file failed (pv_tx_probe.rs parse_frozen:
    // "cannot read <path>: <error>"); the file holds only the JSON written here.
    const stderr = result.stderr?.trim();
    if (stderr?.startsWith(`pv_tx_probe: cannot read ${args[1]}: `)) harnessStep(() => fail(`pv_tx_probe failed: ${stderr}`));
    fail(`pv_tx_probe failed: ${stderr ?? result.status}`);
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
  const json = canonicalFrozenTxJson(frozen); // a record-shape throw stays unmarked
  harnessStep(() => fs.writeFileSync(p, json, { mode: 0o600 }));
  try {
    return callback(p);
  } finally {
    harnessStep(() => fs.unlinkSync(p));
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
