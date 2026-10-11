"use strict";

/* Request-scoped, observation-only recovery of retained v0.4-family transitions.
 * No signing, rebuilding, broadcast, new historical anchor, or negative inference.
 * RC45 F7 (plan r2 §2.6): it decides before it writes. A journal-free record
 * that is not PENDING answers its own label with zero writes and node calls; a
 * journal-free PENDING record is finished from a recorded advancement (no node
 * call) or settled by the Verify settlement pass under the same lock; no
 * journal is written and no claim is re-created. Journaled RC42/RC44 history
 * keeps its journal path (claims are no longer re-created; its observation
 * settles only at depth D). CHAIN_VERIFIED is the last write. The supported
 * deployment has one shared writer. This process lock is not a distributed
 * submitter lock.
 */
const { createHash } = require("node:crypto");
const { canonicalJsonStringify } = require("../../core/intent/canonical");
const { getStore, Categories } = require("./store");
const { assertOperationalNetwork, assertGenerationMainnetOperable } = require("./config");
const { loadRequest, saveRequest, listVaultRequests, ROLE_BY_ACTION, RequestState } = require("./wallet-requests-v4");
const { withVaultIdentityLock } = require("./vault-identity");
const { loadManifestV4, normalizeManifestV4 } = require("./manifest-v4");
const { VaultStatus } = require("./manifest");
const { CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1, computeStateIdV4, normalizeStateV4, normalizeTemplateV4 } = require("./vault-state-v4");
const { canonicalFrozenTxJson, normalizeFrozenTxV3, describeFrozenTx } = require("./frozen-tx-v3");
const { preflightAllInputs } = require("./vm-preflight");
const { frozenScriptAddress } = require("./genesis-recovery");
const { connectVerified, getAddressUtxos, getVirtualDaaScore, canonicalDaaScore } = require("./chain");
const { recordedNegativeIsEstablished } = require("./submission-classification");
const { transitionClaimKey } = require("./submission-claim");
const { reservationKey, RESERVATION_SCHEMA } = require("./budget-reservation");
const { appendAudit, readAudit } = require("./audit");
const submit = require("./wallet-submit-v4");
// Lazy import keeps this module's load order independent of the Verify pass.
const reconcile = () => require("./reconcile-v4");

const RECOVERY_SCHEMA = "policyvault-transition-recovery/v1";
const HEX64 = /^[0-9a-f]{64}$/;
const RECOVERABLE = new Set(["PREFLIGHT_VERIFIED", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "SUBMISSION_REJECTED", "NOT_BROADCAST", "CHAIN_VERIFIED"]);
const plain = (x) => JSON.parse(JSON.stringify(x, (_k, v) => typeof v === "bigint" ? String(v) : v));
function canonicalRecordFingerprint(record) {
  return createHash("sha256").update(canonicalJsonStringify(plain(record))).digest("hex");
}
const equal = (a, b) => canonicalRecordFingerprint(a) === canonicalRecordFingerprint(b);
function fail(message, code = "TRANSITION_RECOVERY_REFUSED") {
  const error = new Error(`wallet-recovery-v4: ${message}`); error.code = code; throw error;
}
function isTransitionV4(r) {
  return r?.schema === "policyvault-wallet-request/v4" && [CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1].includes(r.contractVersion) &&
    (r.kind === undefined || r.kind === "transition") && Object.hasOwn(ROLE_BY_ACTION, r.action) &&
    r.sdkAction === (["addAgent", "removeAgent", "rotateAgent", "rePolicyAgent"].includes(r.action) ? "ownerSetAgentRoot" : r.action);
}
/* Ordinary vault reconciliation may neither infer rejection from a live
 * predecessor nor replace an unresolved historical transition with UNKNOWN.
 * The guard also covers pre-migration negative labels with no sound proof.
 * RC45 F2 (plan r2 §2.0): the per-record predicate PENDING(r), extracted
 * unchanged from the RC38/LEAD-5 vault-wide scan.
 */
async function isPendingTransitionV4(config, r) {
  // Protection covers the v4 request schema, including legacy or malformed
  // version labels. Recovery support is validated separately; an unsupported
  // record must never become permission to discard unresolved evidence.
  if (r?.schema !== "policyvault-wallet-request/v4" || r.kind === "genesis") return false;
  if (r.transitionRecovery) {
    const j = r.transitionRecovery;
    try { assertJournal(r, j, immutableBinding(r)); } catch { return true; }
    if (j.schema !== RECOVERY_SCHEMA || j.phase !== "COMPLETE" || r.state !== "CHAIN_VERIFIED" ||
        j.requestBinding !== immutableBinding(r) || !HEX64.test(j.expectedFingerprint ?? "") ||
        !HEX64.test(j.expectedManifestFingerprint ?? "")) return true;
    const receipt = await getStore(config).read(Categories.RECEIPT, r.txId);
    const terminal = r.sdkAction === "ownerRecover";
    const expected = {kind: terminal ? "recover" : "successor", index: terminal ? 0 : r.build?.frozen?.outputs?.findIndex((o) => o.covenant != null),
      valueSompi: terminal ? r.build?.accounting?.terminalPayout : r.build?.accounting?.successorTotal};
    if (!receiptMatches(receipt, r, expected, j.requestBinding)) return true;
    if (await getStore(config).read(Categories.SUBMISSION_CLAIM, r.txId) ||
        await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(r.predecessorOutpoint))) return true;
    const events = await readAudit(config, {vaultId: r.vaultId, txId: r.txId, limit: 1000});
    if (!events.some((e) => e.action === "transition_recovery_completed" && e.requestId === r.requestId &&
        e.requestBinding === j.requestBinding && e.result === "CHAIN_VERIFIED")) return true;
  }
  // Older submission saved CHAIN_VERIFIED before its receipt. That label
  // cannot bypass request recovery when completion was interrupted.
  if (r.state === "CHAIN_VERIFIED" && !r.transitionRecovery) {
    if (!HEX64.test(r.txId ?? "")) return true;
    const receipt = await getStore(config).read(Categories.RECEIPT, r.txId);
    if (receipt?.schema !== "policyvault-receipt/v1" || receipt.txId !== r.txId || receipt.vaultId !== r.vaultId || receipt.action !== r.action) return true;
  }
  // Inspected historical transition writers did not emit NOT_BROADCAST;
  // an unexpected bare label is still protected, never trusted as proof.
  // Finalization creates claims before submission. Retained signed bytes
  // can still land out of band; generic reconciliation may not unlock them.
  if (["SIGNED", "FINALIZED", "PREFLIGHT_VERIFIED", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "NOT_BROADCAST"].includes(r.state)) return true;
  return r.state === "SUBMISSION_REJECTED" && !recordedNegativeIsEstablished(r);
}
// Self-exclusion is only for an ordinary unmarked build/finalize/submit.
// A malformed lifecycle label must never hide its own protection journal,
// and a record without a request id never matches an absent caller id.
function selfExcluded(r, excludeRequestId) {
  return excludeRequestId !== undefined && r?.requestId === excludeRequestId && !r.transitionRecovery &&
    ["BUILT", "AWAITING_APPROVALS", "SIGNED", "FINALIZED", "PREFLIGHT_VERIFIED"].includes(r.state);
}
async function findProtectedTransitionV4(config, vaultId, { excludeRequestId } = {}) {
  for (const r of await listVaultRequests(config, vaultId)) {
    if (selfExcluded(r, excludeRequestId)) continue;
    if (await isPendingTransitionV4(config, r)) return r;
  }
  return null;
}
/* ON(r, o) is a blocking-only predicate (plan r2 §2.0, CR-L10): a missing or
 * malformed predecessor outpoint counts as ON the live outpoint, never as
 * elsewhere. Writes and contest membership need exact identity instead. */
function onOutpoint(r, outpoint) {
  const p = r?.predecessorOutpoint;
  if (!p || typeof p !== "object" || Array.isArray(p) || Object.keys(p).sort().join() !== "index,transactionId" ||
      typeof p.transactionId !== "string" || !HEX64.test(p.transactionId) || !Number.isSafeInteger(p.index) || p.index < 0) return true;
  return p.transactionId === outpoint.transactionId && p.index === Number(outpoint.index);
}
/* RC45 F2 (plan r2 §2.1(2)-(3)): blocking is scoped to the live outpoint,
 * never released or narrowed by age, absence or options.
 *   - closed vault (no live state): the first vault-wide PENDING record
 *     refuses every action, break-glass included (RC40: protected admission
 *     authorizes no second recovery);
 *   - live vault, owner break-glass (ownerPause / ownerRecover): never refused;
 *   - otherwise: the first PENDING record ON the live outpoint whose txid
 *     differs from the caller's (a same-txid twin is the same transaction and
 *     never refuses it, CR-L14); a record elsewhere cannot compete, because
 *     every build spends the live outpoint (H-23/24);
 *   - claimCheck (ordinary builds): after the PENDING check, any transition
 *     claim on the live outpoint refuses pre-sign (H-04/15/21, CR2-I8).
 * The caller's txid is that of its own listed record (excludeRequestId); a
 * build has none, so every PENDING record on the live outpoint refuses it.
 * Read-only: returns null or {pending, record, claim}.
 */
async function findBlockingTransitionV4(config, vaultId, { excludeRequestId, breakGlass = false, claimCheck = false } = {}) {
  const manifest = await loadManifestV4(config, vaultId);
  const live = manifest?.live ?? null;
  if (live && breakGlass === true) return null;
  const requests = await listVaultRequests(config, vaultId);
  if (!live) {
    for (const r of requests) {
      if (selfExcluded(r, excludeRequestId)) continue;
      if (await isPendingTransitionV4(config, r)) return {pending: true, record: r, claim: null};
    }
    return null;
  }
  const own = excludeRequestId === undefined ? null : requests.find((r) => r?.requestId === excludeRequestId);
  const ownTxId = HEX64.test(own?.txId ?? "") ? own.txId : null;
  const claim = await getStore(config).read(Categories.TRANSITION_CLAIM, transitionClaimKey(live.outpoint));
  for (const r of requests) {
    if (own && r === own) continue;
    if (ownTxId !== null && r?.txId === ownTxId) continue;
    if (!onOutpoint(r, live.outpoint)) continue;
    if (await isPendingTransitionV4(config, r)) return {pending: true, record: r, claim};
  }
  if (claimCheck === true && claim) {
    const holder = HEX64.test(claim.txId ?? "") ? requests.find((r) => r?.txId === claim.txId) ?? null : null;
    return {pending: false, record: holder, claim};
  }
  return null;
}
/* 422 REQUEST_RECOVERY_REQUIRED for a PENDING record, 409 CLAIM_CONFLICT for
 * a pre-sign claim; error.extra names the blocking record and the claim on
 * the live outpoint (plan r2 §2.1(2)). Nothing is written. */
async function assertNoBlockingTransitionV4(config, vaultId, options) {
  const blocking = await findBlockingTransitionV4(config, vaultId, options);
  if (!blocking) return;
  const {pending, record, claim} = blocking;
  const error = new Error(pending
    ? `wallet-recovery-v4: vault has an unresolved transition (request ${record.requestId ?? "unknown"}, ${record.state ?? "unknown"}); request-scoped recovery is required`
    : `wallet-recovery-v4: the live outpoint is already claimed by transaction ${claim.txId ?? "unknown"}; no new request is built until that claim resolves`);
  error.code = pending ? "REQUEST_RECOVERY_REQUIRED" : "CLAIM_CONFLICT";
  // A claim without a listed holder is named by the claim's own action only.
  const named = record ?? {action: claim?.action};
  error.extra = {requestId: named.requestId ?? null, action: named.action ?? null, state: named.state ?? null,
    signerRole: named.signerRole ?? null, claimTxId: claim?.txId ?? null};
  throw error;
}
/* RC45 F3 (plan r2 §2.3 submit contest row; CR-H2, H-08, H-37): a submit is
 * CONTESTED, returning right after its SUBMITTED save so that only Verify
 * completes it at depth, when
 *   - it is an ownerRecover (every recover, break-glass or not: nothing hosted
 *     writes a terminal status at zero depth), or
 *   - it is the owner's break-glass (`breakGlass`) and the claim on its
 *     predecessor P names another txid (`foreignClaim`), or another-txid
 *     request exactly on P is PENDING or not owner-signed (a BUILT, rejected or
 *     closed delegate request counts: the delegate can still sign its bytes).
 * Contest membership needs exact outpoint equality (CR-L10), never ON's
 * missing-or-malformed rule; a same-txid twin is the same transaction. An
 * ordinary submit is never contested. Read-only. */
async function submitContestedV4(config, request, { breakGlass = false, foreignClaim = false } = {}) {
  if (request.sdkAction === "ownerRecover") return true;
  if (breakGlass !== true) return false;
  if (foreignClaim === true) return true;
  for (const r of await listVaultRequests(config, request.vaultId)) {
    if (!r || r.requestId === request.requestId || r.txId === request.txId) continue;
    if (!equal(r.predecessorOutpoint ?? null, request.predecessorOutpoint)) continue;
    if (r.signerRole !== "owner" || await isPendingTransitionV4(config, r)) return true;
  }
  return false;
}
/* RC45 F2 (plan r2 §2.3 staleness row; H-35, CR-M5, CR2-L16, CR-L14): the
 * finalize/submit verdict on the current manifest. A closed manifest is never
 * a STALE label: 422 with no write (VAULT_TERMINAL when RECOVERED, otherwise
 * RECONCILIATION_REQUIRED). A live manifest that differs by stateId OR outpoint
 * (the stateId recurs after pause/unpause) makes the request STALE, unless the
 * manifest was advanced by this request's own transaction (then 422, no write).
 * Pure: returns null, {stale: true} or {refuse: code, message}. */
function predecessorDispositionV4(manifest, request) {
  if (!manifest?.live) {
    if (manifest?.status === VaultStatus.RECOVERED) {
      return {refuse: "VAULT_TERMINAL", message: `vault is ${manifest.status} (closed) — it is read-only history and accepts no further operations; nothing was written`};
    }
    return {refuse: "RECONCILIATION_REQUIRED", message: `${manifest ? `vault is ${manifest.status} with` : "the vault has"} no recorded live state; nothing was written — verify the vault state`};
  }
  if (manifest.live.stateId === request.predecessorStateId && equal(manifest.live.outpoint, request.predecessorOutpoint ?? null)) return null;
  if (HEX64.test(request.txId ?? "") && manifest.latestTransitionTxId === request.txId) {
    return {refuse: "RECONCILIATION_REQUIRED", message: "the vault was already advanced by this request's own transaction; nothing was written — verify the vault state"};
  }
  return {stale: true};
}
/* RC45 R1-06 (ST-03; K4): the finalize/submit receipt guard, run before the
 * live-outpoint blocking check and predecessorDispositionV4. A receipt for
 * request.txId that receiptMatches THIS request (proof.requestId, the expected
 * outpoint and value) records its transaction as executed, so the request is
 * never labelled STALE: 422 RECONCILIATION_REQUIRED with no write, whatever
 * the staleness verdict, and Verify finishes it. Read-only, no node call; the
 * expected outpoint and value come from the record as validateIdentity derives
 * them, without a compile. Returns null or {refuse, message}. */
async function ownReceiptRefusalV4(config, request) {
  if (!HEX64.test(request?.txId ?? "") || typeof request.requestId !== "string") return null;
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (receipt?.proof?.requestId !== request.requestId) return null;
  const expected = recordedEffect(request);
  if (!expected || !ownReceiptMatches(receipt, request, expected)) return null;
  return {refuse: "RECONCILIATION_REQUIRED", message: "a completion receipt records this request's own transaction as executed; nothing was written — verify the vault state"};
}
/* The expected effect's outpoint index and value as the record fixes them
 * (validateIdentity's derivation, no compile); null when the record does not
 * carry them. */
function recordedEffect(r) {
  try {
    if (r.sdkAction === "ownerRecover") {
      const valueSompi = r.build.accounting.terminalPayout;
      return typeof valueSompi === "string" ? {kind: "recover", index: 0, valueSompi} : null;
    }
    const index = normalizeFrozenTxV3(r.build.frozen).outputs.findIndex((o) => o.covenant !== null);
    const s = r.build.successorState;
    return index < 0 ? null : {kind: "successor", index, valueSompi: String(BigInt(s.protectedValue) + BigInt(s.feeReserve))};
  } catch {
    return null;
  }
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
  if (!isTransitionV4(r) || !RECOVERABLE.has(r.state)) fail("request is not a recoverable v0.4-family transition");
  if (r.state === "PREFLIGHT_VERIFIED" && !r.finalTransaction) fail("preflight recovery requires the retained signed transaction");
  return validateIdentity(config, r);
}
/* RC45 F5 (plan r2 §2.0 validateIdentity errors; CR-M2, CR2-L3): errors are
 * classified by call site. Only assertOperationalNetwork, the compiler
 * invocation, the VM preflight harness (vm-preflight.js runPreflight) and
 * (RC45 R1-04, ST-01, C10) the pv_tx_probe harness failures of describeFrozenTx
 * are environment errors, marked `environmentError`: the Verify settlement
 * answers them with 422 and writes nothing. Of describeFrozenTx's throws only
 * those frozen-tx-v3.js marks `harnessFailure` qualify (`isEnvironment`); a
 * probe rejection or an invalid output shape stays a record error. Every other
 * throw is record-dependent and excludes only that record. The marker changes
 * no other caller's behaviour; a non-Error or non-extensible throw (e.g. a
 * string from WASM) is carried in a new Error with the same message, so it is
 * still marked. */
function environmentStep(step, isEnvironment = () => true) {
  try {
    return step();
  } catch (error) {
    if (!isEnvironment(error)) throw error;
    const marked = error instanceof Error && Object.isExtensible(error) ? error : new Error(String(error?.message ?? error));
    marked.environmentError = true;
    throw marked;
  }
}
/* RC45 F4 (plan r2 §2.0 validateIdentity): validateOriginal without its state
 * gate. The record's immutable identity is bound to its frozen transaction and
 * its expected effect is derived; retained signed bytes are optional and are
 * checked when present. Throws on any mismatch; never reads the store or chain. */
function validateIdentity(config, r) {
  if (!isTransitionV4(r)) fail("request is not a v0.4-family transition");
  environmentStep(() => assertOperationalNetwork(config)); assertGenerationMainnetOperable(config, r.contractVersion);
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
      String(frozen.inputs[0].utxo.covenantId) !== r.covenantId ||
      environmentStep(() => describeFrozenTx(frozen), (error) => error?.harnessFailure === true).txId !== r.txId) fail("original frozen transaction differs");
  // The state and template are normalized first, so their record-shape throws
  // stay record errors; only the compiler invocation itself is marked.
  const compile = (stateJson) => {
    normalizeStateV4(stateJson); normalizeTemplateV4(b.template);
    return environmentStep(() => submit.successorAddressAndScript(config, b.template, stateJson, r.contractVersion));
  };
  const predecessor = compile(b.stateJson);
  if (computeStateIdV4({networkId: r.networkId, template: b.template, state: normalizeStateV4(b.stateJson), contractVersion: r.contractVersion}) !== r.predecessorStateId ||
      predecessor.address !== frozenScriptAddress(config, frozen.inputs[0].utxo.scriptPublicKey)) fail("original predecessor is not bound to its frozen script");
  let expected;
  if (r.sdkAction === "ownerRecover") {
    expected = {kind: "recover", txId: r.txId, index: 0, valueSompi: b.accounting.terminalPayout, ownerAddress: r.signerAddress};
    if (b.successorState !== null || frozen.outputs[0].covenant !== null ||
        frozenScriptAddress(config, frozen.outputs[0].scriptPublicKey) !== r.signerAddress) fail("terminal payout differs");
  } else {
    const index = frozen.outputs.findIndex((o) => o.covenant !== null);
    const successor = compile(b.successorState);
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
    if (!environmentStep(() => preflightAllInputs(r.finalTransaction)).valid) fail("retained transaction signatures or covenant execution are invalid");
    const tx = submit.finalTxToWasm(config, r.finalTransaction); tx.finalize();
    if (tx.id !== r.txId) fail("retained signed transaction id differs");
    signed = true;
  }
  return {frozen, predecessor, expected, signed};
}

/* The transition claim's `expected` payload as finalize records it. RC45 F4
 * (plan r2 §2.3 submit row, CR2-L7): submit re-creates a missing own claim with
 * exactly this payload, so request-scoped recovery's claim check accepts it. */
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
// RC45 F7 (plan r2 §2.6 steps 3 and 5, H-45): request-scoped recovery never
// re-creates a claim; RC44's ensureClaims is deleted.
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
/* RC45 R1-06 (K4, C2): receiptMatches bound to the record's own immutable
 * binding (the receipt guard and Verify's receipt-matching finish). */
function ownReceiptMatches(receipt, r, expected) {
  return receiptMatches(receipt, r, expected, immutableBinding(r));
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
/* RC45 F7 (plan r2 §2.6 step 4; CR-L2, CR-L12, CR2-L10): a journal-free
 * PENDING record after RC44's read-only checks. A manifest advanced by exactly
 * this transaction is finished with no node call (finishRecordedV4: it is
 * written only after a positive observation); otherwise the Verify settlement
 * pass runs under the vault identity lock this call already holds. The answer
 * is the record's own settled label (CHAIN_VERIFIED or STALE), else
 * PROTECTED_UNRESOLVED. An observation or read failure of the pass (its 422
 * RECONCILE_FAILED, or a failed or malformed node answer) is
 * PROTECTED_UNRESOLVED with no further write; store and write errors
 * propagate. No journal is written and no claim is re-created. */
async function settleJournalFree(config, r, manifest, advanced, providedRpc) {
  const pass = reconcile();
  let result = null;
  if (advanced) {
    await pass.finishRecordedV4(config, manifest, await pass.listSettlementRequests(config, r.vaultId));
  } else {
    const owned = !providedRpc;
    const {rpc} = owned ? await connectVerified(config) : {rpc: providedRpc};
    try {
      result = await pass.reconcileVaultV4Unlocked(config, r.vaultId, {rpc});
    } catch (error) {
      if (error?.observationError !== true && error?.code !== "RECONCILE_FAILED") throw error;
      return {request: await loadRequest(config, r.requestId) ?? r, outcome: "PROTECTED_UNRESOLVED",
        detail: error.observationError === true
          ? "chain observation is unavailable; nothing further was written and the original data remains protected"
          : `the Verify settlement pass could not decide (${error.message}); the original data remains protected`};
    } finally { if (owned) await rpc.disconnect(); }
  }
  const fresh = await loadRequest(config, r.requestId);
  if (fresh && !fresh.transitionRecovery && [RequestState.CHAIN_VERIFIED, RequestState.STALE].includes(fresh.state) &&
      !(await isPendingTransitionV4(config, fresh))) {
    return {request: fresh, outcome: fresh.state, detail: fresh.state === RequestState.STALE
      ? "superseded by another transaction confirmed at the settlement depth; its own claims and reservation are released"
      : advanced ? "the recorded advancement of this transaction is finished; no node call was needed"
        : "the original effect is observed at the settlement depth and completed by the Verify settlement pass"};
  }
  return {request: fresh ?? r, outcome: "PROTECTED_UNRESOLVED", detail: advanced
    ? "the recorded advancement of this transaction cannot finish this record; the original data remains protected"
    : `not settled by the Verify settlement pass (${result?.status ?? "no answer"}); the original data remains protected`};
}

async function reconcileUnlocked({config, requestId, rpc: providedRpc, expectedFingerprint}) {
  let r = await loadRequest(config, requestId);
  if (!r) fail("request does not exist");
  if (expectedFingerprint !== undefined && expectedFingerprint !== canonicalRecordFingerprint(r)) fail("selected request fingerprint changed", "REQUEST_FINGERPRINT_MISMATCH");
  // RC45 F7 (plan r2 §2.6 step 2; RV-SRR-01 SR-A..SR-D): the pure disposition,
  // before validation and before any write or node call. A non-transition or
  // genesis record is refused; a journal-free record that is not PENDING is
  // answered with its own label and nothing else happens. An unknown label is
  // refused (fail closed), never reported as an outcome.
  if (!isTransitionV4(r)) fail("request is not a v0.4-family transition");
  if (!r.transitionRecovery && !(await isPendingTransitionV4(config, r))) {
    if (!Object.values(RequestState).includes(r.state)) fail("request carries an unknown lifecycle label");
    return {request: r, outcome: r.state, detail: [RequestState.BUILT, RequestState.AWAITING_APPROVALS].includes(r.state)
      ? "no signed transaction is recorded for this request; nothing to recover"
      : "already settled; nothing to recover"};
  }
  // Step 4 preconditions (CR-L12): RC44's read-only checks run unchanged, so a
  // contested break-glass record fails closed at the claim check below (the
  // predecessor claim is the delegate's) with zero writes; Verify completes it.
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
  // RC45 F7 (plan r2 §2.6 step 5, H-45): journal-free records never get a
  // protection journal, re-created claims or the unsigned exit.
  if (!journal) return settleJournalFree(config, r, manifest, advanced, providedRpc);
  // Step 3: journaled RC42/RC44 history keeps the RC44 path, minus claim
  // re-creation, plus depth >= D on its observation.
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
      // RC45 F7 (plan r2 §2.6 step 3, §2.0 D): the virtual DAA score is read
      // before the reads it judges; the effect settles only at depth >= D.
      const vDaa = await getVirtualDaaScore(rpc);
      const observed = await submit.proveExpectedEffectV4(rpc, expected);
      // The queried address is not proof of the returned UTXO script. Bind
      // both actual script bytes and its explicit version to the signed output.
      const outputScript = frozen.outputs[expected.index].scriptPublicKey;
      const effect = observed && observed.scriptPublicKeyHex === outputScript.scriptHex &&
        observed.scriptPublicKeyVersion === outputScript.version ? observed : null;
      const refs = await getAddressUtxos(rpc, predecessor.address);
      const live = refs.some((u) => equal(u.outpoint, frozen.inputs[0].previousOutpoint));
      if (!effect || live) return unresolved(effect ? "effect and predecessor are both indexed; observation is inconclusive" : "exact original effect is not observed; absence does not prove rejection");
      // RC45 R1-05 (ST-02; C4, K1): the effect is the judged entry. Its RAW
      // blockDaaScore must be canonical, else the observation failed and
      // nothing further is written; a score above vDaa is below depth.
      const score = canonicalDaaScore(effect.blockDaaScoreRaw);
      if (score === null) return unresolved("the node's blockDaaScore for the exact original effect is not a canonical DAA score; the observation failed and nothing further was written");
      const depth = vDaa - score;
      if (depth < reconcile().SETTLE_DEPTH_DAA) return unresolved(`exact original effect is observed below the settlement depth (${depth} of ${reconcile().SETTLE_DEPTH_DAA} DAA); nothing further was written`);
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

module.exports = {inspectForeignCompletedRecoveryV4, reconcileTransitionWalletRequestV4, isPendingTransitionV4, findProtectedTransitionV4,
  findBlockingTransitionV4, assertNoBlockingTransitionV4, submitContestedV4, predecessorDispositionV4, ownReceiptRefusalV4, ownReceiptMatches, validateIdentity,
  expectedClaim, canonicalRecordFingerprint, exactAdvanced, onOutpoint, RECOVERY_SCHEMA};
