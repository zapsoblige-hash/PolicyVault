"use strict";

/*
 * PolicyVault v0.3 approval collection (Phase 4H §7–§10).
 *
 * An approval package is the canonical, durable, serializable object an
 * above-threshold delegate spend collects approver signatures into. Its
 * fundamental invariant:
 *
 *   THE EXACT TRANSACTION IS FROZEN BEFORE ANY APPROVAL IS COLLECTED.
 *
 * Approvers sign the REAL Kaspa transaction: a 65-byte Schnorr signature
 * (64 bytes + trailing 0x01 = SIG_HASH_ALL) over the covenant input's
 * transaction sighash, verified here through the real rusty-kaspa
 * consensus code (pv_tx_probe) BEFORE the SDK accepts it. Consensus
 * SIG_HASH_ALL binds the exact predecessor outpoint + predecessor state
 * script, every output (recipient, amount, successor state + value +
 * covenant binding), lockTime, network-level fields, and the fee (input
 * minus output totals) — so a collected approval cannot survive any
 * mutation of the fields it authorizes.
 *
 * The package additionally carries a LOCAL COMMITMENT: sha256 over the
 * canonical serialization of every security-relevant field. Changing ANY
 * such field produces a different commitment and the package fails
 * integrity. THE COMMITMENT IS NOT A SIGNING DIGEST — approver authority
 * comes only from the Kaspa transaction signature. The commitment merely
 * identifies "this exact frozen approval package" and closes the fields
 * consensus does not commit (notably the covenant input's compute budget,
 * which the v1 sighash does NOT cover — see frozen-tx-v3.js).
 *
 * Fixed-slot semantics (production covenant): 10 slots x 65 bytes = one
 * 650-byte blob; slot i verifies ONLY approver i's configured key;
 * sentinel (all-zero) slots never count; the canonical absent/placeholder
 * signature is 64 x 0x00 || 0x01.
 */

const crypto = require("crypto");

const { parseSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");
const { APPROVER_SENTINEL, MAX_APPROVERS, CONTRACT_VERSION_V3 } = require("./vault-state-v3");
const { verifyRecipientProof } = require("./recipient-merkle-v3");
const {
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  describeFrozenTx,
  verifyApprovalSignature
} = require("./frozen-tx-v3");

const APPROVAL_PACKAGE_SCHEMA = "policyvault-approval-package/v1";
const PLACEHOLDER_APPROVAL = "00".repeat(64) + "01";
const APPROVALS_BLOB_BYTES = 65 * MAX_APPROVERS;

function fail(message, code) {
  const error = new Error(`approval-package-v3: ${message}`);
  if (code) error.code = code;
  throw error;
}

/* P2PK script for an x-only key: OpData32 push + key + OpCheckSig. */
function p2pkScriptHex(xOnly) {
  return `20${xOnly}ac`;
}

/*
 * The canonical commitment preimage: EVERY security-relevant field in a
 * fixed order. Excludes only `approvals` (the collected material — each
 * approval's validity is independently bound to the sighash), `createdAt`
 * (explicitly NONSECURITY metadata), and the commitment itself.
 */
function commitmentPreimage(pkg) {
  return JSON.stringify({
    schema: pkg.schema,
    contractVersion: pkg.contractVersion,
    networkId: pkg.networkId,
    vaultId: pkg.vaultId,
    action: pkg.action,
    predecessorOutpoint: { transactionId: pkg.predecessorOutpoint.transactionId, index: pkg.predecessorOutpoint.index },
    predecessorStateId: pkg.predecessorStateId,
    successorStateId: pkg.successorStateId,
    policyNonce: pkg.policyNonce,
    txId: pkg.txId,
    covenantInputIndex: pkg.covenantInputIndex,
    covenantSighash: pkg.covenantSighash,
    frozenTransaction: pkg.frozenTransaction,
    recipient: pkg.recipient,
    payAmountSompi: pkg.payAmountSompi,
    recipientProof: {
      root: pkg.recipientProof.root,
      siblingsHex: pkg.recipientProof.siblingsHex,
      pathBits: pkg.recipientProof.pathBits
    },
    approvalThresholdAmount: pkg.approvalThresholdAmount,
    approvalM: pkg.approvalM,
    approverSlots: pkg.approverSlots,
    computeBudget: pkg.computeBudget,
    requiredFeeSompi: pkg.requiredFeeSompi
  });
}

function packageCommitmentV3(pkg) {
  return crypto.createHash("sha256").update(commitmentPreimage(pkg), "utf8").digest("hex");
}

/*
 * Create a canonical approval package for a frozen above-threshold spend.
 * Every cross-field consistency rule is asserted HERE so an inconsistent
 * package cannot exist:
 *   - the frozen covenant input spends exactly the stated predecessor;
 *   - output 0 is exactly P2PK(recipient) with exactly payAmount;
 *   - the recipient proof verifies against the stated root;
 *   - the committed compute budget matches the frozen covenant input;
 *   - the stated fee equals frozen inputs minus outputs;
 *   - the active approver slots are distinct and can satisfy approvalM;
 *   - txId + covenant sighash come from the REAL consensus code.
 */
function createApprovalPackageV3({
  networkId,
  vaultId,
  action,
  predecessorOutpoint,
  predecessorStateId,
  successorStateId,
  policyNonce,
  frozenTransaction,
  covenantInputIndex = 0,
  recipient,
  payAmountSompi,
  recipientProof,
  approvalThresholdAmount,
  approvalM,
  approverSlots,
  requiredFeeSompi
}) {
  if (typeof networkId !== "string" || !networkId) {
    fail("networkId is required");
  }
  if (action !== "delegateSpend" && action !== "rolloverAndSpend") {
    fail(`approval packages exist only for spend entrypoints, got ${JSON.stringify(action)}`);
  }
  const frozen = normalizeFrozenTxV3(frozenTransaction);
  if (!Number.isInteger(covenantInputIndex) || covenantInputIndex < 0 || covenantInputIndex >= frozen.inputs.length) {
    fail("covenantInputIndex out of range");
  }

  const vault = normalizeHex(vaultId, 32, "vaultId");
  const outpointTxId = normalizeHex(predecessorOutpoint?.transactionId, 32, "predecessorOutpoint.transactionId");
  const outpointIndex = Number(predecessorOutpoint?.index);
  if (!Number.isInteger(outpointIndex) || outpointIndex < 0) {
    fail("predecessorOutpoint.index must be a non-negative integer");
  }
  const covIn = frozen.inputs[covenantInputIndex];
  if (covIn.previousOutpoint.transactionId !== outpointTxId || covIn.previousOutpoint.index !== outpointIndex) {
    fail("frozen covenant input does not spend the stated predecessor outpoint — refusing an inconsistent package");
  }

  const pay = parseSompi(payAmountSompi, "payAmountSompi");
  const threshold = parseSompi(approvalThresholdAmount, "approvalThresholdAmount");
  if (pay <= threshold) {
    fail("payAmount is not above approvalThresholdAmount — no approval package is required for delegate-only spends");
  }

  const recipientKey = normalizeHex(recipient, 32, "recipient");
  const payOut = frozen.outputs[0];
  if (payOut.scriptPublicKey.version !== 0 || payOut.scriptPublicKey.scriptHex !== p2pkScriptHex(recipientKey)) {
    fail("frozen output 0 is not P2PK(recipient) — the covenant binds the payment to output 0");
  }
  if (payOut.value !== pay) {
    fail(`frozen output 0 value ${payOut.value} != payAmount ${pay}`);
  }

  if (!recipientProof || typeof recipientProof !== "object") {
    fail("recipientProof { root, siblingsHex, pathBits } is required");
  }
  const proof = {
    root: normalizeHex(recipientProof.root, 32, "recipientProof.root"),
    siblingsHex: String(recipientProof.siblingsHex ?? "").toLowerCase(),
    pathBits: parseSompi(recipientProof.pathBits ?? 0n, "recipientProof.pathBits").toString()
  };
  if (!verifyRecipientProof({ root: proof.root, recipient: recipientKey, siblingsHex: proof.siblingsHex, pathBits: BigInt(proof.pathBits) })) {
    fail("recipient proof does not verify against the stated root — refusing an inconsistent package");
  }

  if (!Array.isArray(approverSlots) || approverSlots.length !== MAX_APPROVERS) {
    fail(`approverSlots must be the exact ${MAX_APPROVERS}-slot layout`);
  }
  const slots = approverSlots.map((s, i) => normalizeHex(s, 32, `approverSlots[${i}]`));
  const seen = new Set();
  let activeCount = 0;
  for (const [i, s] of slots.entries()) {
    if (s !== APPROVER_SENTINEL) {
      if (seen.has(s)) {
        fail(`approverSlots[${i}] duplicates an active approver key — the predecessor set is malformed (fails closed on chain too)`);
      }
      seen.add(s);
      activeCount += 1;
    }
  }
  const m = parseSompi(approvalM, "approvalM");
  if (m < 1n) {
    fail("approvalM < 1 with an above-threshold spend — the covenant rejects this predecessor (malformed genesis); failing closed early");
  }
  if (m > BigInt(activeCount)) {
    fail(`approvalM ${m} exceeds the active approver count ${activeCount} — this spend can never collect enough approvals`);
  }

  const fee = parseSompi(requiredFeeSompi, "requiredFeeSompi");
  const totalIn = frozen.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = frozen.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== fee) {
    fail(`stated fee ${fee} != frozen inputs-minus-outputs ${totalIn - totalOut}`);
  }

  const described = describeFrozenTx(frozen);

  const pkg = {
    schema: APPROVAL_PACKAGE_SCHEMA,
    contractVersion: CONTRACT_VERSION_V3,
    networkId,
    vaultId: vault,
    action,
    predecessorOutpoint: { transactionId: outpointTxId, index: outpointIndex },
    predecessorStateId: String(predecessorStateId ?? "") || fail("predecessorStateId is required"),
    successorStateId: String(successorStateId ?? "") || fail("successorStateId is required"),
    policyNonce: parseSompi(policyNonce, "policyNonce").toString(),
    txId: described.txId,
    covenantInputIndex,
    covenantSighash: described.sighashAll[covenantInputIndex],
    frozenTransaction: JSON.parse(canonicalFrozenTxJson(frozen)),
    recipient: recipientKey,
    payAmountSompi: pay.toString(),
    recipientProof: proof,
    approvalThresholdAmount: threshold.toString(),
    approvalM: m.toString(),
    approverSlots: slots,
    computeBudget: covIn.computeBudget,
    requiredFeeSompi: fee.toString(),
    createdAt: new Date().toISOString(), // NONSECURITY metadata
    approvals: Array.from({ length: MAX_APPROVERS }, () => null)
  };
  pkg.commitment = packageCommitmentV3(pkg);
  return pkg;
}

/*
 * Full integrity gate, run before ANY approval is accepted and before the
 * blob is emitted:
 *  1. the stored commitment matches a recomputation over the current
 *     field values (any mutation -> reject);
 *  2. the frozen transaction re-normalizes and its REAL consensus
 *     txId/sighash still match the stored ones (defense in depth against
 *     a mutated frozen body + recomputed commitment by a buggy caller —
 *     the sighash is what approvals actually bind).
 */
function assertPackageIntegrity(pkg) {
  if (!pkg || pkg.schema !== APPROVAL_PACKAGE_SCHEMA) {
    fail(`unknown approval-package schema ${JSON.stringify(pkg?.schema)} — failing closed`);
  }
  if (pkg.contractVersion !== CONTRACT_VERSION_V3) {
    fail(`unknown contractVersion ${JSON.stringify(pkg.contractVersion)} — failing closed`);
  }
  const expected = packageCommitmentV3(pkg);
  if (pkg.commitment !== expected) {
    fail("package commitment mismatch — a protected field was mutated after freeze; collected approvals are void", "PACKAGE_MUTATED");
  }
  const frozen = normalizeFrozenTxV3(pkg.frozenTransaction);
  const described = describeFrozenTx(frozen);
  if (described.txId !== pkg.txId || described.sighashAll[pkg.covenantInputIndex] !== pkg.covenantSighash) {
    fail("frozen transaction no longer matches the committed txId/sighash — package void", "PACKAGE_MUTATED");
  }
  return frozen;
}

function collectedCount(pkg) {
  return pkg.approvals.filter((a) => typeof a === "string").length;
}

/*
 * Accept one approver signature into its FIXED slot.
 *   signatureHex — 65 bytes (64-byte Schnorr + 0x01), lowercase hex;
 *   approverXOnly — the signer identity; its slot is located by exact key
 *     match against the configured slots. An optional slotIndex must agree.
 * Every rejection path is fail-closed and side-effect-free. Returns a NEW
 * package object (the input is not mutated).
 */
function submitApprovalV3(pkg, { signatureHex, approverXOnly, slotIndex }) {
  const frozen = assertPackageIntegrity(pkg);

  const key = normalizeHex(approverXOnly, 32, "approverXOnly");
  if (key === APPROVER_SENTINEL) {
    fail("the sentinel is not a signer identity", "UNKNOWN_APPROVER");
  }
  const canonicalSlot = pkg.approverSlots.indexOf(key);
  if (canonicalSlot < 0) {
    fail(`signer ${key} is not a configured approver for this package`, "UNKNOWN_APPROVER");
  }
  if (slotIndex !== undefined && Number(slotIndex) !== canonicalSlot) {
    fail(`signer ${key} belongs to slot ${canonicalSlot}, not slot ${slotIndex} — approvals are fixed-slot-bound`, "WRONG_SLOT");
  }
  if (pkg.approvals[canonicalSlot] !== null) {
    fail(`slot ${canonicalSlot} already holds an approval`, "DUPLICATE_APPROVAL");
  }

  if (typeof signatureHex !== "string" || !/^[0-9a-f]+$/.test(signatureHex)) {
    fail("signature must be lowercase hex", "SIGNATURE_INVALID");
  }
  if (signatureHex.length !== 130) {
    fail(`approvals must be exactly 65 bytes (64-byte Schnorr + sighash byte), got ${signatureHex.length / 2}`, "SIGNATURE_INVALID");
  }
  if (!signatureHex.endsWith("01")) {
    fail(`approval sighash byte 0x${signatureHex.slice(-2)} != 0x01 — only SIG_HASH_ALL approvals are accepted`, "SIGHASH_NOT_ALL");
  }
  if (signatureHex === PLACEHOLDER_APPROVAL) {
    fail("the canonical placeholder is not a real approval", "SIGNATURE_INVALID");
  }

  const verdict = verifyApprovalSignature(frozen, pkg.covenantInputIndex, signatureHex, key);
  if (verdict.valid !== true) {
    fail(`approval rejected: ${verdict.reason}`, "SIGNATURE_INVALID");
  }

  const approvals = pkg.approvals.slice();
  approvals[canonicalSlot] = signatureHex;
  return { ...pkg, approvals };
}

/* Slots still missing a real approval (active slots only). */
function missingSlots(pkg) {
  const missing = [];
  pkg.approverSlots.forEach((key, i) => {
    if (key !== APPROVER_SENTINEL && pkg.approvals[i] === null) {
      missing.push(i);
    }
  });
  return missing;
}

function isCompleteV3(pkg) {
  return BigInt(collectedCount(pkg)) >= BigInt(pkg.approvalM);
}

/*
 * Emit the exact 650-byte approvals blob for the covenant call: every
 * collected approval in its fixed slot, the canonical 65-byte placeholder
 * (64 x 0x00 || 0x01) everywhere else. Fails closed unless the package is
 * integral AND complete (>= approvalM collected approvals).
 */
function approvalsBlobV3(pkg) {
  assertPackageIntegrity(pkg);
  if (!isCompleteV3(pkg)) {
    fail(
      `insufficient approvals: ${collectedCount(pkg)} collected, ${pkg.approvalM} required — refusing final construction`,
      "INSUFFICIENT_APPROVALS"
    );
  }
  let blob = "";
  for (let i = 0; i < MAX_APPROVERS; i++) {
    blob += pkg.approvals[i] ?? PLACEHOLDER_APPROVAL;
  }
  if (blob.length !== APPROVALS_BLOB_BYTES * 2) {
    fail("internal: approvals blob is not 650 bytes");
  }
  return blob;
}

/* The all-placeholder blob for at/below-threshold delegate-only spends. */
function placeholderApprovalsBlob() {
  return PLACEHOLDER_APPROVAL.repeat(MAX_APPROVERS);
}

/* Durable JSON round-trip: load re-validates integrity fail-closed. */
function approvalPackageToJson(pkg) {
  assertPackageIntegrity(pkg);
  return JSON.stringify(pkg);
}

function loadApprovalPackage(json) {
  let pkg;
  try {
    pkg = JSON.parse(json);
  } catch {
    fail("approval package is not valid JSON");
  }
  assertPackageIntegrity(pkg);
  if (!Array.isArray(pkg.approvals) || pkg.approvals.length !== MAX_APPROVERS) {
    fail("approval package approvals array is malformed");
  }
  return pkg;
}

module.exports = {
  APPROVAL_PACKAGE_SCHEMA,
  PLACEHOLDER_APPROVAL,
  createApprovalPackageV3,
  packageCommitmentV3,
  assertPackageIntegrity,
  submitApprovalV3,
  approvalsBlobV3,
  placeholderApprovalsBlob,
  missingSlots,
  isCompleteV3,
  collectedCount,
  approvalPackageToJson,
  loadApprovalPackage,
  p2pkScriptHex
};
