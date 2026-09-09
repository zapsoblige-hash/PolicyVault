"use strict";

/*
 * PRODUCTION-COVENANT VM PREFLIGHT — shared runner + SIGNED-INPUT VERIFICATION
 * (rc11 internal security review F-04; owner addendum §F standing invariant:
 * "No server-side state transition with cryptographic meaning may be driven by
 * field presence alone. The cryptographic evidence must first be verified
 * against the exact expected signer, key/slot, request domain, and commitment.")
 *
 * `pv_vm_preflight <final-tx.json> [input-index]` executes ONE input of a
 * fully described transaction on the REAL Kaspa TxScriptEngine (covenants
 * enabled) — never a JS re-implementation of consensus. Every input's spent
 * UTXO (amount, scriptPublicKey, covenantId) travels inside the descriptor,
 * so the verdict is exactly what a node would compute for that input:
 *   - a P2PK funding / fuel input verifies the Schnorr signature over the
 *     real sighash of THIS transaction with the key the UTXO script names;
 *   - a covenant input executes the redeem script with the assembled call.
 * A signature that is an arbitrary string, structurally valid but from the
 * wrong key, from the right key over a different transaction (replay from
 * another request), or truncated therefore FAILS here, before any request is
 * persisted as SIGNED. The v0.4 pipeline has used this exact binary for its
 * covenant input since Checkpoint G; this module makes it the single runner
 * and extends the check to EVERY input and every generation.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

/* Same discipline as POLICYVAULT_PV_CALL_ENCODER_PATH (vault-builders-v4.js):
 * an optional development/test override for a private binary copy; unset =
 * the repo-relative production path the image ships. */
const PREFLIGHT_PATH = process.env.POLICYVAULT_PV_VM_PREFLIGHT_PATH || path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_vm_preflight");
const HEX_RE = /^[0-9a-f]+$/;

function fail(message, code) {
  const e = new Error(`vm-preflight: ${message}`);
  e.code = code;
  throw e;
}

/* Execute ONE input; returns the harness verdict {valid, reason?}. */
function runPreflight(finalTx, inputIndex = 0) {
  if (!fs.existsSync(PREFLIGHT_PATH)) fail(`pv_vm_preflight not built: ${PREFLIGHT_PATH}`, "PREFLIGHT_FAILED");
  if (!Number.isInteger(inputIndex) || inputIndex < 0) fail("input index must be a non-negative integer", "PREFLIGHT_FAILED");
  const p = path.join(os.tmpdir(), `pv-preflight-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(p, JSON.stringify(finalTx), { mode: 0o600 });
  try {
    const r = spawnSync(PREFLIGHT_PATH, [p, String(inputIndex)], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    if (r.status !== 0) fail(`preflight harness error: ${r.stderr ? r.stderr.trim() : r.status}`, "PREFLIGHT_FAILED");
    let out;
    try {
      out = JSON.parse(r.stdout.trim());
    } catch {
      fail("preflight returned invalid JSON", "PREFLIGHT_FAILED");
    }
    if (typeof out.valid !== "boolean") fail("preflight returned no verdict", "PREFLIGHT_FAILED");
    return out;
  } finally {
    try {
      fs.unlinkSync(p);
    } catch {
      /* already gone */
    }
  }
}

/* Execute EVERY input; the first invalid input names itself. */
function preflightAllInputs(finalTx) {
  if (!finalTx || !Array.isArray(finalTx.inputs) || finalTx.inputs.length === 0) fail("final transaction has no inputs", "PREFLIGHT_FAILED");
  for (let i = 0; i < finalTx.inputs.length; i++) {
    const v = runPreflight(finalTx, i);
    if (v.valid !== true) return { valid: false, inputIndex: i, reason: v.reason ?? "script execution failed" };
  }
  return { valid: true, inputs: finalTx.inputs.length };
}

/*
 * Build the executable descriptor for a wallet-signed Safe JSON: the build's
 * frozen canonical descriptor (every input with its spent UTXO) plus the
 * signature scripts the wallet returned. Consensus-visible fields are NOT
 * taken from the wallet's copy (callers assert immutability separately);
 * only `signatureScript` per input is adopted, and each must be non-empty hex.
 */
function descriptorFromSignedSafeJson({ frozenCanonicalJson, signedSafeJson }) {
  if (typeof frozenCanonicalJson !== "string" || !frozenCanonicalJson) fail("build carries no frozen canonical descriptor", "PREFLIGHT_FAILED");
  const descriptor = JSON.parse(frozenCanonicalJson);
  let signed;
  try {
    signed = typeof signedSafeJson === "string" ? JSON.parse(signedSafeJson) : signedSafeJson;
  } catch {
    fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  if (!signed || !Array.isArray(signed.inputs) || signed.inputs.length !== descriptor.inputs.length) {
    fail(`signed transaction has ${signed && Array.isArray(signed.inputs) ? signed.inputs.length : "no"} inputs, the build has ${descriptor.inputs.length}`, "SIGNATURE_INVALID");
  }
  descriptor.inputs = descriptor.inputs.map((input, i) => {
    const sig = signed.inputs[i] && signed.inputs[i].signatureScript;
    if (typeof sig !== "string" || sig.length === 0 || sig.length % 2 !== 0 || !HEX_RE.test(sig)) {
      fail(`input ${i}: signatureScript must be non-empty even-length lowercase hex`, "SIGNATURE_INVALID");
    }
    return { ...input, signatureScript: sig };
  });
  return descriptor;
}

/*
 * VERIFY BEFORE SIGNED: every input of the wallet-signed transaction must
 * execute on the real engine against its spent UTXO. Throws SIGNATURE_INVALID
 * (with the failing input index and engine reason) — never returns a
 * half-verified verdict. Returns the executable descriptor on success so the
 * caller can persist/broadcast exactly the bytes that were verified.
 */
function verifySignedSafeJsonInputs({ frozenCanonicalJson, signedSafeJson }) {
  const descriptor = descriptorFromSignedSafeJson({ frozenCanonicalJson, signedSafeJson });
  const verdict = preflightAllInputs(descriptor);
  if (!verdict.valid) fail(`input ${verdict.inputIndex} did not verify on the production VM: ${verdict.reason}`, "SIGNATURE_INVALID");
  return descriptor;
}

/* Same contract for an already-assembled final transaction (finalizer output). */
function verifyFinalTransactionInputs(finalTx) {
  const verdict = preflightAllInputs(finalTx);
  if (!verdict.valid) fail(`input ${verdict.inputIndex} did not verify on the production VM: ${verdict.reason}`, "SIGNATURE_INVALID");
  return verdict;
}

module.exports = { PREFLIGHT_PATH, runPreflight, preflightAllInputs, descriptorFromSignedSafeJson, verifySignedSafeJsonInputs, verifyFinalTransactionInputs };
