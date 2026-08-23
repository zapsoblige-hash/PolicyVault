"use strict";

/*
 * PolicyVault v0.4 approval collection (Checkpoint E §E7/§E8).
 *
 * An approval package is the canonical, durable, serializable object an
 * above-threshold AGENT spend collects approver signatures into. Its
 * fundamental invariant (identical to the hardened v0.3 rule):
 *
 *   THE EXACT TRANSACTION IS FROZEN BEFORE ANY APPROVAL IS COLLECTED.
 *
 * Approvers sign the REAL Kaspa transaction: a 65-byte Schnorr signature
 * (64 bytes + trailing 0x01 = SIG_HASH_ALL) over the covenant input's
 * transaction sighash, verified through the real rusty-kaspa consensus
 * code (pv_tx_probe) BEFORE the SDK accepts it. Consensus SIG_HASH_ALL
 * binds the exact predecessor outpoint + predecessor state script, every
 * output (recipient, amount, successor state + value + covenant binding),
 * lockTime, sequences, network-level fields, and the fee (input minus
 * output totals) — so a collected approval cannot survive any mutation of
 * the fields it authorizes, and cannot be replayed against a different
 * predecessor outpoint (staleness is consensus-enforced).
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
 * v0.4 differences from v0.3 (frozen ABI, docs/covenant-spec-v0.4.md):
 *   - the approval threshold is PER-AGENT (a leaf field), not vault state;
 *   - the recipient tree is PER-AGENT (leaf.agentRecipientRoot);
 *   - the package binds the full agent-policy leaf + its Merkle co-path
 *     under the predecessor agentRoot (the key->policy authority);
 *   - fee-reserve accounting (reserveConsumed) is a committed field and
 *     is cross-checked against the frozen covenant-value delta.
 *
 * Fixed-slot semantics (production covenant, unchanged from v0.3): 10
 * slots x 65 bytes = one 650-byte blob; slot i verifies ONLY approver i's
 * configured key; sentinel (all-zero) slots never count; the canonical
 * absent/placeholder signature is 64 x 0x00 || 0x01.
 */

const crypto = require("crypto");

const { parseSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");
const { APPROVER_SENTINEL, MAX_APPROVERS, CONTRACT_VERSION_V4 } = require("./vault-state-v4");
const { verifyRecipientProof } = require("./recipient-merkle-v3");
const { normalizeAgentPolicyV4, verifyAgentProofV4, foldAgentPolicyV4 } = require("./agent-merkle-v4");
const { PLACEHOLDER_APPROVAL, placeholderApprovalsBlob, p2pkScriptHex } = require("./approval-package-v3");
const {
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  describeFrozenTx,
  verifyApprovalSignature
} = require("./frozen-tx-v3");

const APPROVAL_PACKAGE_SCHEMA_V4 = "policyvault-approval-package/v4";
const APPROVALS_BLOB_BYTES = 65 * MAX_APPROVERS;

function fail(message, code) {
  const error = new Error(`approval-package-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

function policyToJson(policy) {
  return {
    agentPk: policy.agentPk,
    maxPerSpend: policy.maxPerSpend.toString(),
    periodBudget: policy.periodBudget.toString(),
    periodLengthDaa: policy.periodLengthDaa.toString(),
    periodStartDaa: policy.periodStartDaa.toString(),
    periodSpent: policy.periodSpent.toString(),
    approvalThreshold: policy.approvalThreshold.toString(),
    agentMaxFeePerTx: policy.agentMaxFeePerTx.toString(),
    agentRecipientRoot: policy.agentRecipientRoot
  };
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
    agentPolicy: pkg.agentPolicy,
    agentProof: { root: pkg.agentProof.root, siblingsHex: pkg.agentProof.siblingsHex, pathBits: pkg.agentProof.pathBits },
    successorAgentRoot: pkg.successorAgentRoot,
    periodsElapsed: pkg.periodsElapsed,
    recipient: pkg.recipient,
    payAmountSompi: pkg.payAmountSompi,
    recipientProof: { root: pkg.recipientProof.root, siblingsHex: pkg.recipientProof.siblingsHex, pathBits: pkg.recipientProof.pathBits },
    reserveConsumedSompi: pkg.reserveConsumedSompi,
    approvalM: pkg.approvalM,
    approverSlots: pkg.approverSlots,
    computeBudget: pkg.computeBudget,
    requiredFeeSompi: pkg.requiredFeeSompi
  });
}

function packageCommitmentV4(pkg) {
  return crypto.createHash("sha256").update(commitmentPreimage(pkg), "utf8").digest("hex");
}

/*
 * Create a canonical approval package for a frozen above-threshold agent
 * spend. Every cross-field consistency rule is asserted HERE so an
 * inconsistent package cannot exist:
 *   - the frozen covenant input spends exactly the stated predecessor and
 *     carries exactly protectedValue + feeReserve;
 *   - output 0 is exactly P2PK(recipient) with exactly payAmount;
 *   - exactly one covenant-bound successor output exists, and the
 *     covenant-value delta equals payAmount + reserveConsumed;
 *   - the agent-policy proof verifies against the predecessor agentRoot
 *     (the leaf is the sole key->policy authority);
 *   - the successor agentRoot equals the single-leaf accounting fold;
 *   - the recipient proof verifies against the LEAF's own recipient root;
 *   - payAmount is strictly above the LEAF's approvalThreshold;
 *   - reserveConsumed <= leaf.agentMaxFeePerTx and <= the network fee;
 *   - the committed compute budget matches the frozen covenant input;
 *   - the stated fee equals frozen inputs minus outputs;
 *   - the active approver slots are distinct and can satisfy approvalM;
 *   - txId + covenant sighash come from the REAL consensus code.
 */
function createApprovalPackageV4({
  networkId,
  vaultId,
  predecessorOutpoint,
  predecessorStateId,
  successorStateId,
  policyNonce,
  predecessorProtectedSompi,
  predecessorFeeReserveSompi,
  frozenTransaction,
  covenantInputIndex = 0,
  agentPolicy,
  agentProof,
  successorAgentRoot,
  periodsElapsed,
  recipient,
  payAmountSompi,
  recipientProof,
  reserveConsumedSompi,
  approvalM,
  approverSlots,
  requiredFeeSompi
}) {
  if (typeof networkId !== "string" || !networkId) {
    fail("networkId is required");
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

  const protectedValue = parseSompi(predecessorProtectedSompi, "predecessorProtectedSompi");
  const feeReserve = parseSompi(predecessorFeeReserveSompi, "predecessorFeeReserveSompi");
  if (covIn.utxo.amount !== protectedValue + feeReserve) {
    fail(
      `frozen covenant input carries ${covIn.utxo.amount} sompi but the stated predecessor holds protected ${protectedValue} + reserve ${feeReserve}`
    );
  }

  const policy = normalizeAgentPolicyV4(agentPolicy);
  const pay = parseSompi(payAmountSompi, "payAmountSompi");
  if (pay <= policy.approvalThreshold) {
    fail("payAmount is not above this agent's approvalThreshold — no approval package is required for agent-only spends");
  }
  const consumed = parseSompi(reserveConsumedSompi, "reserveConsumedSompi");
  if (consumed > policy.agentMaxFeePerTx) {
    fail("reserveConsumed exceeds this agent's agentMaxFeePerTx — the covenant rejects this spend");
  }
  if (consumed > feeReserve) {
    fail("reserveConsumed exceeds the predecessor fee reserve");
  }

  if (!agentProof || typeof agentProof !== "object") {
    fail("agentProof { root, siblingsHex, pathBits } is required");
  }
  const aProof = {
    root: normalizeHex(agentProof.root, 32, "agentProof.root"),
    siblingsHex: String(agentProof.siblingsHex ?? "").toLowerCase(),
    pathBits: parseSompi(agentProof.pathBits ?? 0n, "agentProof.pathBits").toString()
  };
  if (!verifyAgentProofV4({ root: aProof.root, policy, siblingsHex: aProof.siblingsHex, pathBits: BigInt(aProof.pathBits) })) {
    fail("agent-policy proof does not verify against the stated agentRoot — refusing an inconsistent package");
  }

  const periods = parseSompi(periodsElapsed ?? 0n, "periodsElapsed");
  let newStart = policy.periodStartDaa;
  let newSpent = policy.periodSpent + pay;
  if (periods >= 1n) {
    newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
    newSpent = pay;
  }
  const newPolicy = normalizeAgentPolicyV4({ ...policy, periodStartDaa: newStart, periodSpent: newSpent });
  const succRoot = normalizeHex(successorAgentRoot, 32, "successorAgentRoot");
  const foldedRoot = foldAgentPolicyV4(newPolicy, aProof.siblingsHex, BigInt(aProof.pathBits));
  if (foldedRoot !== succRoot) {
    fail("successorAgentRoot does not equal the single-leaf accounting fold — refusing an inconsistent package");
  }

  const recipientKey = normalizeHex(recipient, 32, "recipient");
  const payOut = frozen.outputs[0];
  if (payOut.scriptPublicKey.version !== 0 || payOut.scriptPublicKey.scriptHex !== p2pkScriptHex(recipientKey)) {
    fail("frozen output 0 is not P2PK(recipient) — the covenant binds the payment to output 0");
  }
  if (payOut.value !== pay) {
    fail(`frozen output 0 value ${payOut.value} != payAmount ${pay}`);
  }

  const covenantOutputs = frozen.outputs.filter((o) => o.covenant !== null);
  if (covenantOutputs.length !== 1) {
    fail(`frozen transaction carries ${covenantOutputs.length} covenant-bound outputs; the singleton covenant requires exactly 1`);
  }
  const succOut = covenantOutputs[0];
  const expectedSuccValue = protectedValue - pay + (feeReserve - consumed);
  if (succOut.value !== expectedSuccValue) {
    fail(
      `frozen successor output value ${succOut.value} != (protected - pay) + (reserve - reserveConsumed) = ${expectedSuccValue} — reserve accounting mismatch`
    );
  }

  if (!recipientProof || typeof recipientProof !== "object") {
    fail("recipientProof { root, siblingsHex, pathBits } is required");
  }
  const rProof = {
    root: normalizeHex(recipientProof.root, 32, "recipientProof.root"),
    siblingsHex: String(recipientProof.siblingsHex ?? "").toLowerCase(),
    pathBits: parseSompi(recipientProof.pathBits ?? 0n, "recipientProof.pathBits").toString()
  };
  if (rProof.root !== policy.agentRecipientRoot) {
    fail("recipient proof root is not this agent's agentRecipientRoot — recipients are authorized per agent leaf");
  }
  if (!verifyRecipientProof({ root: rProof.root, recipient: recipientKey, siblingsHex: rProof.siblingsHex, pathBits: BigInt(rProof.pathBits) })) {
    fail("recipient proof does not verify against the agent's recipient root — refusing an inconsistent package");
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
    fail("approvalM < 1 with an above-threshold spend — the covenant rejects this predecessor; failing closed early");
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
  if (consumed > fee) {
    fail(`reserveConsumed ${consumed} exceeds the network fee ${fee} — the covenant rejects this spend`);
  }
  if (frozen.inputs.length > 8 || frozen.outputs.length > 8) {
    fail("the v0.4 covenant fee introspection is bounded to <= 8 inputs and <= 8 outputs");
  }

  const described = describeFrozenTx(frozen);

  const pkg = {
    schema: APPROVAL_PACKAGE_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId,
    vaultId: vault,
    action: "agentSpend",
    predecessorOutpoint: { transactionId: outpointTxId, index: outpointIndex },
    predecessorStateId: String(predecessorStateId ?? "") || fail("predecessorStateId is required"),
    successorStateId: String(successorStateId ?? "") || fail("successorStateId is required"),
    policyNonce: parseSompi(policyNonce, "policyNonce").toString(),
    txId: described.txId,
    covenantInputIndex,
    covenantSighash: described.sighashAll[covenantInputIndex],
    frozenTransaction: JSON.parse(canonicalFrozenTxJson(frozen)),
    agentPolicy: policyToJson(policy),
    agentProof: aProof,
    successorAgentRoot: succRoot,
    periodsElapsed: periods.toString(),
    recipient: recipientKey,
    payAmountSompi: pay.toString(),
    recipientProof: rProof,
    reserveConsumedSompi: consumed.toString(),
    approvalM: m.toString(),
    approverSlots: slots,
    computeBudget: covIn.computeBudget,
    requiredFeeSompi: fee.toString(),
    createdAt: new Date().toISOString(), // NONSECURITY metadata
    approvals: Array.from({ length: MAX_APPROVERS }, () => null)
  };
  pkg.commitment = packageCommitmentV4(pkg);
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
function assertPackageIntegrityV4(pkg) {
  if (!pkg || pkg.schema !== APPROVAL_PACKAGE_SCHEMA_V4) {
    fail(`unknown approval-package schema ${JSON.stringify(pkg?.schema)} — failing closed`);
  }
  if (pkg.contractVersion !== CONTRACT_VERSION_V4) {
    fail(`unknown contractVersion ${JSON.stringify(pkg.contractVersion)} — failing closed`);
  }
  const expected = packageCommitmentV4(pkg);
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

function collectedCountV4(pkg) {
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
function submitApprovalV4(pkg, { signatureHex, approverXOnly, slotIndex }) {
  const frozen = assertPackageIntegrityV4(pkg);

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
function missingSlotsV4(pkg) {
  const missing = [];
  pkg.approverSlots.forEach((key, i) => {
    if (key !== APPROVER_SENTINEL && pkg.approvals[i] === null) {
      missing.push(i);
    }
  });
  return missing;
}

function isCompleteV4(pkg) {
  return BigInt(collectedCountV4(pkg)) >= BigInt(pkg.approvalM);
}

/*
 * Emit the exact 650-byte approvals blob for the covenant call: every
 * collected approval in its fixed slot, the canonical 65-byte placeholder
 * (64 x 0x00 || 0x01) everywhere else. Fails closed unless the package is
 * integral AND complete (>= approvalM collected approvals).
 */
function approvalsBlobV4(pkg) {
  assertPackageIntegrityV4(pkg);
  if (!isCompleteV4(pkg)) {
    fail(
      `insufficient approvals: ${collectedCountV4(pkg)} collected, ${pkg.approvalM} required — refusing final construction`,
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

/* Durable JSON round-trip: load re-validates integrity fail-closed. */
function approvalPackageToJsonV4(pkg) {
  assertPackageIntegrityV4(pkg);
  return JSON.stringify(pkg);
}

function loadApprovalPackageV4(json) {
  let pkg;
  try {
    pkg = JSON.parse(json);
  } catch {
    fail("approval package is not valid JSON");
  }
  assertPackageIntegrityV4(pkg);
  if (!Array.isArray(pkg.approvals) || pkg.approvals.length !== MAX_APPROVERS) {
    fail("approval package approvals array is malformed");
  }
  return pkg;
}

module.exports = {
  APPROVAL_PACKAGE_SCHEMA_V4,
  PLACEHOLDER_APPROVAL,
  placeholderApprovalsBlob,
  p2pkScriptHex,
  createApprovalPackageV4,
  packageCommitmentV4,
  assertPackageIntegrityV4,
  submitApprovalV4,
  approvalsBlobV4,
  missingSlotsV4,
  isCompleteV4,
  collectedCountV4,
  approvalPackageToJsonV4,
  loadApprovalPackageV4
};
