"use strict";

/* Request-scoped, observation-only recovery of retained v0.4.1 transitions.
 * No signing, rebuilding, broadcast, new historical anchor, or negative inference.
 * A durable journal precedes advancement; a receipt and audit precede own-claim
 * cleanup; CHAIN_VERIFIED is the last write. The supported deployment has one
 * shared writer. This process lock is not a distributed submitter lock.
 */
const { createHash } = require("node:crypto");
const { canonicalJsonStringify } = require("../../core/intent/canonical");
const { getStore, Categories } = require("./store");
const { assertOperationalNetwork, assertGenerationMainnetOperable } = require("./config");
const { loadRequest, saveRequest, listVaultRequests, ROLE_BY_ACTION } = require("./wallet-requests-v4");
const { withVaultIdentityLock } = require("./vault-identity");
const { loadManifestV4, normalizeManifestV4 } = require("./manifest-v4");
const { CONTRACT_VERSION_V4_1, computeStateIdV4, normalizeStateV4 } = require("./vault-state-v4");
const { canonicalFrozenTxJson, normalizeFrozenTxV3, describeFrozenTx } = require("./frozen-tx-v3");
const { preflightAllInputs } = require("./vm-preflight");
const { frozenScriptAddress } = require("./genesis-recovery");
const { connectVerified, getAddressUtxos } = require("./chain");
const { recordedNegativeIsEstablished } = require("./submission-classification");
const { transitionClaimKey } = require("./submission-claim");
const { reservationKey, RESERVATION_SCHEMA } = require("./budget-reservation");
const { appendAudit, readAudit } = require("./audit");
const submit = require("./wallet-submit-v4");

const RECOVERY_SCHEMA = "policyvault-transition-recovery/v1";
const HEX64 = /^[0-9a-f]{64}$/;
const RECOVERABLE = new Set(["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "SUBMISSION_REJECTED", "NOT_BROADCAST", "CHAIN_VERIFIED"]);
const plain = (x) => JSON.parse(JSON.stringify(x, (_k, v) => typeof v === "bigint" ? String(v) : v));
function canonicalRecordFingerprint(record) {
  return createHash("sha256").update(canonicalJsonStringify(plain(record))).digest("hex");
}
const equal = (a, b) => canonicalRecordFingerprint(a) === canonicalRecordFingerprint(b);
function fail(message, code = "TRANSITION_RECOVERY_REFUSED") {
  const error = new Error(`wallet-recovery-v4: ${message}`); error.code = code; throw error;
}
function isTransitionV41(r) {
  return r?.schema === "policyvault-wallet-request/v4" && r.contractVersion === CONTRACT_VERSION_V4_1 &&
    (r.kind === undefined || r.kind === "transition") && Object.hasOwn(ROLE_BY_ACTION, r.action) &&
    r.sdkAction === (["addAgent", "removeAgent", "rotateAgent", "rePolicyAgent"].includes(r.action) ? "ownerSetAgentRoot" : r.action);
}
/* Ordinary vault reconciliation may neither infer rejection from a live
 * predecessor nor replace an unresolved historical transition with UNKNOWN.
 * The guard also covers pre-migration negative labels with no sound proof.
 */
async function findProtectedTransitionV4(config, vaultId, { excludeRequestId } = {}) {
  for (const r of await listVaultRequests(config, vaultId)) {
    if (r?.schema !== "policyvault-wallet-request/v4" || r.contractVersion !== CONTRACT_VERSION_V4_1 || r.kind === "genesis") continue;
    // Self-exclusion is only for an ordinary unmarked build/finalize/submit.
    // A malformed lifecycle label must never hide its own protection journal.
    if (r.requestId === excludeRequestId && !r.transitionRecovery &&
        ["BUILT", "AWAITING_APPROVALS", "SIGNED", "FINALIZED", "PREFLIGHT_VERIFIED"].includes(r.state)) continue;
    if (r.transitionRecovery) {
      const j = r.transitionRecovery;
      try { assertJournal(r, j, immutableBinding(r)); } catch { return r; }
      if (j.schema !== RECOVERY_SCHEMA || j.phase !== "COMPLETE" || r.state !== "CHAIN_VERIFIED" ||
          j.requestBinding !== immutableBinding(r) || !HEX64.test(j.expectedFingerprint ?? "") ||
          !HEX64.test(j.expectedManifestFingerprint ?? "")) return r;
      const receipt = await getStore(config).read(Categories.RECEIPT, r.txId);
      const terminal = r.sdkAction === "ownerRecover";
      const expected = {kind: terminal ? "recover" : "successor", index: terminal ? 0 : r.build?.frozen?.outputs?.findIndex((o) => o.covenant != null),
        valueSompi: terminal ? r.build?.accounting?.terminalPayout : r.build?.accounting?.successorTotal};
      if (!receiptMatches(receipt, r, expected, j.requestBinding)) return r;
      if (await getStore(config).read(Categories.SUBMISSION_CLAIM, r.txId) ||
          await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(r.predecessorOutpoint))) return r;
      const events = await readAudit(config, {vaultId: r.vaultId, txId: r.txId, limit: 1000});
      if (!events.some((e) => e.action === "transition_recovery_completed" && e.requestId === r.requestId &&
          e.requestBinding === j.requestBinding && e.result === "CHAIN_VERIFIED")) return r;
    }
    // Older submission saved CHAIN_VERIFIED before its receipt. That label
    // cannot bypass request recovery when completion was interrupted.
    if (r.state === "CHAIN_VERIFIED" && !r.transitionRecovery) {
      if (!HEX64.test(r.txId ?? "")) return r;
      const receipt = await getStore(config).read(Categories.RECEIPT, r.txId);
      if (receipt?.schema !== "policyvault-receipt/v1" || receipt.txId !== r.txId || receipt.vaultId !== r.vaultId || receipt.action !== r.action) return r;
    }
    // Inspected historical transition writers did not emit NOT_BROADCAST;
    // an unexpected bare label is still protected, never trusted as proof.
    if (["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "NOT_BROADCAST"].includes(r.state)) return r;
    if (r.state === "SUBMISSION_REJECTED" && !recordedNegativeIsEstablished(r)) return r;
  }
  return null;
}
async function assertNoProtectedTransitionV4(config, vaultId, options) {
  if (await findProtectedTransitionV4(config, vaultId, options)) fail("vault has an unresolved transition; request-scoped recovery is required", "REQUEST_RECOVERY_REQUIRED");
}
/* Bind all original fields, including signatures and build metadata. Only
 * the lifecycle label and this module's journal may change during recovery.
 * Original error/classification/anchor fields remain byte-for-byte values.
 */
function immutableBinding(r) {
  const copy = plain(r); delete copy.state; delete copy.transitionRecovery;
  return canonicalRecordFingerprint(copy);
}
function manifestFingerprint(m) { return canonicalRecordFingerprint(submit.manifestToJson(m)); }
function assertJournal(r, journal, binding) {
    if (journal.schema !== RECOVERY_SCHEMA || journal.requestBinding !== binding ||
        !["PROTECTED", "EFFECT_PROVEN", "COMPLETE"].includes(journal.phase) || !RECOVERABLE.has(journal.originalState) ||
        !Array.isArray(journal.claimFingerprints) || journal.claimFingerprints.length !== 2 ||
        journal.claimFingerprints.some((v) => v !== null && !HEX64.test(v ?? "")) ||
        (journal.reservationFingerprint !== null && !HEX64.test(journal.reservationFingerprint ?? "")) ||
        (journal.phase === "COMPLETE" ? r.state !== "CHAIN_VERIFIED" : r.state !== "RECONCILIATION_REQUIRED")) fail("recovery journal no longer binds the original request");
    if (journal.phase !== "PROTECTED" && (!HEX64.test(journal.expectedManifestFingerprint ?? "") ||
        !HEX64.test(journal.expectedFingerprint ?? "") ||
        (journal.predecessorManifestFingerprint !== null && !HEX64.test(journal.predecessorManifestFingerprint ?? "")))) fail("completion journal is incomplete");
}

function validateOriginal(config, r) {
  if (!isTransitionV41(r) || !RECOVERABLE.has(r.state)) fail("request is not a recoverable v0.4.1 transition");
  assertOperationalNetwork(config); assertGenerationMainnetOperable(config, r.contractVersion);
  const b = r.build;
  if (r.networkId !== config.networkId || b?.networkId !== r.networkId || b?.contractVersion !== r.contractVersion ||
      b?.kind !== "transition" || b.action !== r.sdkAction || b.role !== r.signerRole ||
      ROLE_BY_ACTION[r.action] !== r.signerRole || b.template?.vaultId !== r.vaultId || !HEX64.test(r.vaultId ?? "") ||
      !HEX64.test(r.txId ?? "") || b.txId !== r.txId || !equal(b.predecessorOutpoint, r.predecessorOutpoint) ||
      b.predecessorStateId !== r.predecessorStateId || b.covenantId !== r.covenantId ||
      b.successorStateId !== r.successorStateId) fail("original request/build identity differs");
  const frozen = normalizeFrozenTxV3(b.frozen);
  if (canonicalFrozenTxJson(frozen) !== canonicalFrozenTxJson(JSON.parse(b.frozenCanonicalJson)) ||
      !equal(frozen.inputs[0].previousOutpoint, r.predecessorOutpoint) ||
      String(frozen.inputs[0].utxo.covenantId) !== r.covenantId || describeFrozenTx(frozen).txId !== r.txId) fail("original frozen transaction differs");
  const predecessor = submit.successorAddressAndScript(config, b.template, b.stateJson, r.contractVersion);
  if (computeStateIdV4({networkId: r.networkId, template: b.template, state: normalizeStateV4(b.stateJson), contractVersion: r.contractVersion}) !== r.predecessorStateId ||
      predecessor.address !== frozenScriptAddress(config, frozen.inputs[0].utxo.scriptPublicKey)) fail("original predecessor is not bound to its frozen script");
  let expected;
  if (r.sdkAction === "ownerRecover") {
    expected = {kind: "recover", txId: r.txId, index: 0, valueSompi: b.accounting.terminalPayout, ownerAddress: r.signerAddress};
    if (b.successorState !== null || frozen.outputs[0].covenant !== null ||
        frozenScriptAddress(config, frozen.outputs[0].scriptPublicKey) !== r.signerAddress) fail("terminal payout differs");
  } else {
    const index = frozen.outputs.findIndex((o) => o.covenant !== null);
    const successor = submit.successorAddressAndScript(config, b.template, b.successorState, r.contractVersion);
    expected = {kind: "successor", txId: r.txId, index,
      valueSompi: String(BigInt(b.successorState.protectedValue) + BigInt(b.successorState.feeReserve)),
      covenantId: r.covenantId, address: successor.address, scriptSha256: successor.scriptSha256, stateId: r.successorStateId};
    if (index < 0 || computeStateIdV4({networkId: r.networkId, template: b.template, state: normalizeStateV4(b.successorState), contractVersion: r.contractVersion}) !== r.successorStateId ||
        frozenScriptAddress(config, frozen.outputs[index].scriptPublicKey) !== expected.address ||
        frozen.outputs[index].covenant?.covenantId !== r.covenantId || Number(frozen.outputs[index].covenant?.authorizingInput) !== 0) fail("successor differs from frozen output");
  }
  if (String(frozen.outputs[expected.index].value) !== expected.valueSompi) fail("expected value differs from frozen output");
  const identity = require("./address-identity").resolveAddressIdentity(config, r.signerAddress).xOnlyPubkey;
  if (identity !== r.signerXOnly || identity !== (r.signerRole === "owner" ? b.template.owner : r.agentPk)) fail("recorded signer identity differs");
  let signed = false;
  if (r.finalTransaction) {
    const unsigned = plain(r.finalTransaction);
    for (const input of unsigned.inputs ?? []) delete input.signatureScript;
    if (canonicalFrozenTxJson(unsigned) !== canonicalFrozenTxJson(frozen)) fail("retained signed transaction changed immutable fields");
    if (!preflightAllInputs(r.finalTransaction).valid) fail("retained transaction signatures or covenant execution are invalid");
    const tx = submit.finalTxToWasm(config, r.finalTransaction); tx.finalize();
    if (tx.id !== r.txId) fail("retained signed transaction id differs");
    signed = true;
  }
  return {frozen, predecessor, expected, signed};
}

function expectedClaim(r, expected) {
  return expected.kind === "recover" ? {...expected, contractVersion: r.contractVersion} : {
    kind: "successor", txId: r.txId, index: expected.index, valueSompi: expected.valueSompi,
    covenantId: r.covenantId, scriptSha256: expected.scriptSha256, stateId: r.successorStateId,
    state: r.build.successorState, newRegistry: r.newRegistry, action: r.sdkAction, contractVersion: r.contractVersion
  };
}
function claimRows(r, expected) {
  return [
    [Categories.TRANSITION_CLAIM, transitionClaimKey(r.predecessorOutpoint), {
      schema: "policyvault-transition-claim/v1", outpoint: r.predecessorOutpoint, action: r.action,
      txId: r.txId, vaultId: r.vaultId, stateId: r.predecessorStateId, expected: expectedClaim(r, expected), requestId: r.requestId, requestBinding: immutableBinding(r)}],
    [Categories.SUBMISSION_CLAIM, r.txId, {schema: "policyvault-submission-claim/v1", txId: r.txId, vaultId: r.vaultId, action: r.action,
      requestId: r.requestId, requestBinding: immutableBinding(r)}]
  ];
}
function ownsClaim(row, expected) {
  if (!row) return true;
  for (const [key, value] of Object.entries(expected)) {
    // Historical v4 claims have no request identity; any present identity is binding.
    if ((key === "requestId" || key === "requestBinding") && row[key] === undefined) continue;
    if (!equal(row[key] ?? null, value ?? null)) return false;
  }
  // An optional expectation on a submission claim cannot point elsewhere.
  if (expected.schema === "policyvault-submission-claim/v1" && row.expected != null) return false;
  return true;
}
async function checkClaims(store, rows) {
  for (const [category, key, expected] of rows) if (!ownsClaim(await store.read(category, key), expected)) fail("a claim belongs to another attempt", "CLAIM_CONFLICT");
}
async function ensureClaims(store, rows) {
  for (const [category, key, expected] of rows) {
    if (await store.read(category, key) === null) await store.createExclusive(category, key, {...expected, createdAt: new Date().toISOString()});
  }
  await checkClaims(store, rows);
}
async function ownReservation(store, r) {
  if (r.sdkAction !== "agentSpend") return null;
  const key = reservationKey({vaultId: r.vaultId, agentPk: r.agentPk, requestId: r.requestId});
  const record = await store.read(Categories.TRANSITION_CLAIM, key);
  if (!record) return null;
  const ce = r.build.callExtra, periods = BigInt(ce.periodsElapsed ?? "0"), pay = BigInt(r.build.accounting.payAmount);
  const window = BigInt(ce.periodStartDaa) + (periods >= 1n ? periods * BigInt(ce.periodLengthDaa) : 0n);
  const expected = {schema: RESERVATION_SCHEMA, requestId: r.requestId, vaultId: r.vaultId, agentPk: r.agentPk,
    action: "agentSpend", amountSompi: String(pay), reserveConsumedSompi: String(r.build.accounting.reserveConsumed ?? "0"),
    windowStartDaa: String(window), newSpentSompi: String(periods >= 1n ? pay : BigInt(ce.periodSpent) + pay),
    periodBudgetSompi: String(ce.periodBudget), predecessorStateId: r.predecessorStateId, predecessorOutpoint: r.predecessorOutpoint};
  if (Object.entries(expected).some(([k, v]) => !equal(record[k] ?? null, v)) ||
      !["ACTIVE", "CONSUMED"].includes(record.status) || (record.txId != null && record.txId !== r.txId)) fail("budget reservation does not bind this original request", "CLAIM_CONFLICT");
  return {key, record};
}
function receiptMatches(receipt, r, expected, binding) {
  const p = receipt?.proof;
  return receipt?.schema === "policyvault-receipt/v1" && receipt.txId === r.txId && receipt.vaultId === r.vaultId &&
    receipt.action === r.action && p?.requestId === r.requestId &&
    p.successorOutpoint === (expected.kind === "recover" ? null : `${r.txId}:${expected.index}`) && p.value === expected.valueSompi &&
    (p.requestBinding === undefined || p.requestBinding === binding);
}
function exactAdvanced(m, r, expected) {
  if (m.latestTransitionTxId !== r.txId || !equal(m.template, r.build.template)) return false;
  const transition = {action: expected.kind === "recover" ? "ownerRecover" : r.action, txId: r.txId,
    oldStateId: r.predecessorStateId, newStateId: expected.kind === "recover" ? null : r.successorStateId,
    oldOutpoint: r.predecessorOutpoint, newOutpoint: expected.kind === "recover" ? null : {transactionId: r.txId, index: expected.index}, contractVersion: r.contractVersion};
  if (!equal(m.lastTransition, transition)) return false;
  if (expected.kind === "recover") return m.status === "RECOVERED" && m.live === null;
  return m.status === (Number(r.build.successorState.paused) === 1 ? "PAUSED" : "ACTIVE") &&
    equal(submit.manifestToJson(m).live, {state: r.build.successorState, stateId: r.successorStateId,
      outpoint: {transactionId: r.txId, index: expected.index}, outpointValue: expected.valueSompi,
      scriptSha256: expected.scriptSha256, covenantId: r.covenantId});
}

/* A typed preservation result for one inspected historical shape, not a
 * negative-proof family or a general CLAIM_CONFLICT handler. Both attempts
 * still bind their original signed bytes. The other attempt's ordinary
 * completion receipt and exact closed manifest explain the foreign claim;
 * they establish no rejection/non-acceptance outcome for this request.
 */
/* Snapshot-only proof assessment. It validates retained transaction bytes and
 * recorded completion evidence; it never calls a store, route, RPC, signer or
 * transaction builder. No observation or negative outcome is inferred here.
 */
function foreignRecoveryWinner(r, manifest, rows, signed, receipt, others, foreign) {
  if (!signed || r.transitionRecovery || r.state !== "SUBMISSION_REJECTED" ||
      recordedNegativeIsEstablished(r) || r.sdkAction !== "ownerRecover" || receipt ||
      manifest.status !== "RECOVERED" || manifest.live !== null) return null;
  if (!foreign || ownsClaim(foreign, rows[0][2]) || !HEX64.test(foreign.txId ?? "") ||
      foreign.txId === r.txId || foreign.vaultId !== r.vaultId ||
      !equal(foreign.outpoint, r.predecessorOutpoint)) return null;
  const matching = others.filter((other) => other.requestId !== r.requestId && other.txId === foreign.txId);
  if (matching.length !== 1) return null;
  const winner = matching[0];
  if (winner.transitionRecovery || winner.state !== "CHAIN_VERIFIED" ||
      winner.sdkAction !== "ownerRecover" || winner.vaultId !== r.vaultId ||
      winner.predecessorStateId !== r.predecessorStateId ||
      !equal(winner.predecessorOutpoint, r.predecessorOutpoint)) return null;
  return winner;
}
function foreignRecoveryEvidence(config, manifest, foreign, winner, winnerSubmission, winnerReceipt) {
  let checked;
  try { checked = validateOriginal(config, winner); } catch { return null; }
  if (!checked.signed || !exactAdvanced(manifest, winner, checked.expected)) return null;
  const winnerRows = claimRows(winner, checked.expected);
  if (!ownsClaim(foreign, winnerRows[0][2]) || !ownsClaim(winnerSubmission, winnerRows[1][2]) ||
      !receiptMatches(winnerReceipt, winner, checked.expected, immutableBinding(winner))) return null;
  return winnerRows;
}
function inspectForeignCompletedRecoveryV4(config, snapshot) {
  const keys = ["request", "manifest", "requests", "transitionClaim", "submissionClaim", "receipt", "winnerSubmissionClaim", "winnerReceipt"];
  if (!snapshot || Object.keys(snapshot).sort().join() !== keys.sort().join() ||
      !Array.isArray(snapshot.requests) || snapshot.requests.length > 1000 ||
      keys.some((k) => snapshot[k] === undefined)) fail("complete bounded read-only snapshot required", "RECOVERY_SNAPSHOT_INVALID");
  const r = snapshot.request;
  const checked = validateOriginal(config, r), rows = claimRows(r, checked.expected);
  const manifest = normalizeManifestV4(snapshot.manifest);
  if (manifest.contractVersion !== r.contractVersion || manifest.networkId !== r.networkId ||
      !equal(manifest.template, r.build.template)) fail("current vault identity differs");
  const matches = snapshot.requests.filter((other) => other.requestId === r.requestId);
  if (matches.length !== 1 || !equal(matches[0], r) || snapshot.requests.some((other) => other.vaultId !== r.vaultId))
    fail("snapshot request census differs", "RECOVERY_SNAPSHOT_INVALID");
  if (!ownsClaim(snapshot.submissionClaim, rows[1][2])) fail("a claim belongs to another attempt", "CLAIM_CONFLICT");
  for (const other of snapshot.requests) {
    if (other.requestId !== r.requestId && other.txId === r.txId && other.finalTransaction && RECOVERABLE.has(other.state) &&
        !recordedNegativeIsEstablished(other)) fail("transaction identity is shared by another unresolved signed request", "CLAIM_CONFLICT");
  }
  const winner = foreignRecoveryWinner(r, manifest, rows, checked.signed, snapshot.receipt, snapshot.requests, snapshot.transitionClaim);
  const eligible = !!winner && !!foreignRecoveryEvidence(config, manifest, snapshot.transitionClaim, winner, snapshot.winnerSubmissionClaim, snapshot.winnerReceipt);
  return { schema: "policyvault-foreign-owner-recovery-inspection/v1", eligible,
    disposition: eligible ? "PROTECTED_UNRESOLVED" : null,
    requestOutcomeEstablished: false, newAdmissionAuthorized: false, writesAuthorized: false };
}
async function foreignCompletedRecoveryIsProtected(config, r, manifest, store, rows, signed, receipt, others) {
  const foreign = await store.read(rows[0][0], rows[0][1]);
  const winner = foreignRecoveryWinner(r, manifest, rows, signed, receipt, others, foreign);
  if (!winner) return false;
  const winnerSubmission = await store.read(Categories.SUBMISSION_CLAIM, winner.txId);
  const winnerReceipt = await store.read(Categories.RECEIPT, winner.txId);
  const winnerRows = foreignRecoveryEvidence(config, manifest, foreign, winner, winnerSubmission, winnerReceipt);
  if (!winnerRows) return false;
  // Refuse drift even though this branch performs no writes and grants no
  // new admission. The supported deployment still has one shared writer.
  if (!equal(await loadRequest(config, r.requestId), r) ||
      !equal(await loadRequest(config, winner.requestId), winner) ||
      !equal(await store.read(rows[0][0], rows[0][1]), foreign) ||
      !equal(await store.read(winnerRows[1][0], winnerRows[1][1]), winnerSubmission) ||
      !equal(await store.read(Categories.RECEIPT, winner.txId), winnerReceipt) ||
      manifestFingerprint(await loadManifestV4(config, r.vaultId)) !== manifestFingerprint(manifest)) return false;
  await checkClaims(store, rows.slice(1));
  if (await store.read(Categories.RECEIPT, r.txId)) return false;
  return true;
}

async function reconcileTransitionWalletRequestV4(args) {
  const initial = await loadRequest(args.config, args.requestId);
  if (!initial) fail("request does not exist");
  return withVaultIdentityLock(initial.vaultId, () => reconcileUnlocked(args));
}
async function reconcileUnlocked({config, requestId, rpc: providedRpc, expectedFingerprint}) {
  let r = await loadRequest(config, requestId);
  if (expectedFingerprint !== undefined && expectedFingerprint !== canonicalRecordFingerprint(r)) fail("selected request fingerprint changed", "REQUEST_FINGERPRINT_MISMATCH");
  const {frozen, predecessor, expected, signed} = validateOriginal(config, r);
  const binding = immutableBinding(r), store = getStore(config), rows = claimRows(r, expected);
  let journal = r.transitionRecovery;
  if (journal) assertJournal(r, journal, binding);
  let manifest = await loadManifestV4(config, r.vaultId);
  if (!manifest || manifest.contractVersion !== r.contractVersion || manifest.networkId !== r.networkId || !equal(manifest.template, r.build.template)) fail("current vault identity differs");
  await checkClaims(store, rows.slice(1));
  const reservation = await ownReservation(store, r);
  const claimFingerprints = [];
  for (const [category, key] of rows) {
    const record = await store.read(category, key);
    claimFingerprints.push(record ? canonicalRecordFingerprint(record) : null);
  }
  if (journal) {
    if (reservation && canonicalRecordFingerprint(reservation.record) !== journal.reservationFingerprint) fail("reservation changed since protection", "CLAIM_CONFLICT");
    for (let i = 0; i < rows.length; i++) if (claimFingerprints[i] && journal.claimFingerprints?.[i] && claimFingerprints[i] !== journal.claimFingerprints[i]) fail("retained claim changed since protection", "CLAIM_CONFLICT");
  }
  const others = await listVaultRequests(config, r.vaultId);
  for (const other of others) {
    if (other.requestId !== r.requestId && other.txId === r.txId && other.finalTransaction && RECOVERABLE.has(other.state) && !recordedNegativeIsEstablished(other)) fail("transaction identity is shared by another unresolved signed request", "CLAIM_CONFLICT");
  }
  let receipt = await store.read(Categories.RECEIPT, r.txId);
  if (receipt && !receiptMatches(receipt, r, expected, binding)) fail("existing receipt does not bind this request", "RECEIPT_CONFLICT");
  if (await foreignCompletedRecoveryIsProtected(config, r, manifest, store, rows, signed, receipt, others)) {
    return {request: r, outcome: "PROTECTED_UNRESOLVED", detail: "another recorded completed owner recovery owns this predecessor claim; the historical request remains unresolved and the recorded closed vault accepts no new actions"};
  }
  await checkClaims(store, rows);
  const predecessorMatches = manifest.live?.stateId === r.predecessorStateId && equal(manifest.live.outpoint, r.predecessorOutpoint) &&
    manifest.live.covenantId === r.covenantId && manifest.live.scriptSha256 === predecessor.scriptSha256;
  const advanced = exactAdvanced(manifest, r, expected);
  // Store protection before creating missing historical claims. A crash here
  // still blocks ordinary reconcile and admission through the request guard.
  if (!journal) {
    journal = {schema: RECOVERY_SCHEMA, requestBinding: binding, originalState: r.state, phase: "PROTECTED",
      claimFingerprints, reservationFingerprint: reservation ? canonicalRecordFingerprint(reservation.record) : null, startedAt: new Date().toISOString()};
    r = {...r, state: "RECONCILIATION_REQUIRED", transitionRecovery: journal};
    await saveRequest(config, r);
  }
  if (journal.phase === "PROTECTED") await ensureClaims(store, rows);
  const unresolved = async (detail) => ({request: r, outcome: "PROTECTED_UNRESOLVED", detail});
  if (!signed) return unresolved("retained signed transaction is unavailable; original data and claims remain protected");
  if (!predecessorMatches && !advanced) return unresolved("current vault is unrelated or later; it has been preserved");

  const currentFingerprint = manifestFingerprint(manifest);
  if (journal.expectedManifestFingerprint && advanced && journal.expectedManifestFingerprint !== currentFingerprint) return unresolved("current completed manifest differs from the saved completion fingerprint");
  if (journal.predecessorManifestFingerprint && predecessorMatches && journal.predecessorManifestFingerprint !== currentFingerprint) return unresolved("current predecessor differs from the saved completion fingerprint");
  let proved = journal.phase === "EFFECT_PROVEN" || journal.phase === "COMPLETE";
  if (proved && (!journal.expectedManifestFingerprint || journal.expectedFingerprint !== canonicalRecordFingerprint(expected))) fail("completion proof lacks exact immutable bindings");
  // An exact own receipt can resume bookkeeping after the effect is spent;
  // without it or our journal, a current positive read is still required.
  if (!proved && !(advanced && receipt)) {
    const owned = !providedRpc;
    const {rpc} = owned ? await connectVerified(config) : {rpc: providedRpc};
    try {
      const observed = await submit.proveExpectedEffectV4(rpc, expected);
      // The queried address is not proof of the returned UTXO script. Bind
      // both actual script bytes and its explicit version to the signed output.
      const outputScript = frozen.outputs[expected.index].scriptPublicKey;
      const effect = observed && observed.scriptPublicKeyHex === outputScript.scriptHex &&
        observed.scriptPublicKeyVersion === outputScript.version ? observed : null;
      const refs = await getAddressUtxos(rpc, predecessor.address);
      const live = refs.some((u) => equal(u.outpoint, frozen.inputs[0].previousOutpoint));
      if (!effect || live) return unresolved(effect ? "effect and predecessor are both indexed; observation is inconclusive" : "exact original effect is not observed; absence does not prove rejection");
    } catch (_error) {
      return unresolved("chain observation is unavailable; original data and claims remain protected");
    } finally { if (owned) await rpc.disconnect(); }
  }
  if (!proved) {
    const expectedManifest = predecessorMatches ? normalizeManifestV4(submit.expectedManifestAndRegistryV4(manifest, r, expected)) : manifest;
    journal = {...journal, phase: "EFFECT_PROVEN", expectedFingerprint: canonicalRecordFingerprint(expected),
      predecessorManifestFingerprint: predecessorMatches ? currentFingerprint : null,
      expectedManifestFingerprint: manifestFingerprint(expectedManifest), provedAt: new Date().toISOString()};
    r = {...r, transitionRecovery: journal}; await saveRequest(config, r); proved = true;
  }
  // Check the current record again immediately before the only vault write.
  // Single-writer deployment is required; no interprocess CAS is claimed.
  manifest = await loadManifestV4(config, r.vaultId);
  if (manifestFingerprint(manifest) !== journal.expectedManifestFingerprint) {
    if (manifestFingerprint(manifest) !== journal.predecessorManifestFingerprint) return unresolved("vault changed before completion; current record preserved");
    await submit.advanceManifestAndRegistryV4(config, manifest, r, expected);
    manifest = await loadManifestV4(config, r.vaultId);
    if (manifestFingerprint(manifest) !== journal.expectedManifestFingerprint) fail("completed manifest differs from the saved expected record");
  }
  if (!receipt) {
    const created = await store.createExclusive(Categories.RECEIPT, r.txId, {
      schema: "policyvault-receipt/v1", txId: r.txId, vaultId: r.vaultId, action: r.action,
      proof: {requestId, requestBinding: binding, successorOutpoint: expected.kind === "recover" ? null : `${r.txId}:${expected.index}`,
        value: expected.valueSompi, reconciled: true}, verifiedAt: new Date().toISOString()});
    receipt = await store.read(Categories.RECEIPT, r.txId);
    if (!receiptMatches(receipt, r, expected, binding)) fail("completion receipt collision", "RECEIPT_CONFLICT");
    void created;
  }
  const events = await readAudit(config, {vaultId: r.vaultId, txId: r.txId, limit: 1000});
  if (!events.some((e) => e.action === "transition_recovery_completed" && e.requestId === requestId && e.requestBinding === binding && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, {vaultId: r.vaultId, action: "transition_recovery_completed", actor: "system",
      contractVersion: r.contractVersion, txId: r.txId, requestId, requestBinding: binding,
      result: "CHAIN_VERIFIED", oldStateId: r.predecessorStateId, newStateId: r.successorStateId});
  }
  await checkClaims(store, rows);
  const remainingReservation = await ownReservation(store, r);
  if (remainingReservation) {
    if (canonicalRecordFingerprint(remainingReservation.record) !== journal.reservationFingerprint) fail("reservation changed before cleanup", "CLAIM_CONFLICT");
    await store.remove(Categories.TRANSITION_CLAIM, remainingReservation.key);
  }
  for (const [category, key, own] of rows) {
    const claim = await store.read(category, key);
    if (!ownsClaim(claim, own)) fail("claim changed before completion cleanup", "CLAIM_CONFLICT");
    if (claim) await store.remove(category, key);
  }
  if (r.state !== "CHAIN_VERIFIED" || journal.phase !== "COMPLETE") {
    r = {...r, state: "CHAIN_VERIFIED", transitionRecovery: {...journal, phase: "COMPLETE", completedAt: new Date().toISOString()}};
    await saveRequest(config, r);
  }
  return {request: r, outcome: "CHAIN_VERIFIED", detail: "original effect and completion bookkeeping verified"};
}

module.exports = {inspectForeignCompletedRecoveryV4, reconcileTransitionWalletRequestV4, findProtectedTransitionV4, assertNoProtectedTransitionV4, canonicalRecordFingerprint, RECOVERY_SCHEMA};
