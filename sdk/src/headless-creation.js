"use strict";

/*
 * DURABLE HEADLESS IDENTITY RESERVATION + OBSERVATION-ONLY RECOVERY — RC35-RES-01 (independent RC35 affected review,
 * 2026-09-11; owner recovery/reservation repair directive of the same day).
 *
 * The headless v0.1 / v0.2 creators (sdk/src/create-vault.js, sdk/src/vault-ops-v2.js — direct SDK / source / testnet
 * utilities, never a hosted route) used to persist ONLY a submission claim keyed by txid before their broadcast. The
 * identity scan (sdk/src/vault-identity.js) never read claims, so a crash after the claim / broadcast left a live claim
 * while the vault identity looked free — even under the documented single-writer model, across a plain restart
 * (reviewer's exact-image check headless-reservation.json). The repair:
 *
 *   1. a DURABLE HEADLESS CREATION RECORD (Categories.REQUEST, schema policyvault-headless-creation/v1) is written the
 *      moment the signed genesis transaction exists — BEFORE the submission claim and BEFORE the broadcast — binding the
 *      vault identity to the authorized creation identity (the funder), the exact expected chain outcome (address /
 *      output index / value / covenant id / script hash / state id), the immutable definition (policy or template +
 *      initial state) and the exact signed bytes. The identity scan already treats every REQUEST naming a vault id as a
 *      reservation, in both phases, so the reservation survives any restart on both storage backends;
 *   2. the identity scan ALSO treats a durable SUBMISSION claim naming the identity as a reservation (RC35-RES-01 in
 *      sdk/src/vault-identity.js), which covers claims retained by EARLIER runtimes that wrote no record: their binding
 *      (vaultId <-> txId) is exactly what the claim carries — nothing is inferred;
 *   3. recovery is OBSERVATION ONLY through the original record (recoverHeadlessCreation): the expected outcome is
 *      re-derived from the immutable definition, the signed bytes are bound to the txid, the exact output is observed,
 *      and the same replayable create-only completion runs; an unobserved output keeps an ESTABLISHED negative as it
 *      is, PROTECTS a false / unknown negative (claim re-established, RECONCILIATION_REQUIRED) and leaves every other
 *      unresolved creation unresolved with its claim. Nothing is rebuilt, re-signed or rebroadcast;
 *   4. a LEGACY retained claim (no record) is listed by listUnresolvedHeadlessClaims and can be completed ONLY when the
 *      operator supplies the ORIGINAL definition (recoverLegacyHeadlessClaim): the derived identity must equal the
 *      claim's, the derived address is observed under the claim's txid, the covenant id is READ from the observed
 *      output, and the record is created create-only. Without the original definition the claim keeps reserving the
 *      identity forever — a precise recorded limitation, never a silent discard.
 *
 * Supported contract (recorded honestly): ONE service writer per data root (the released single-server / single-
 * operator shape); the per-identity lock is process-local; the durable arbiters (create-only record, create-only
 * claim) hold across processes. Nothing here changes consensus-visible bytes.
 */

const crypto = require("crypto");
const { getStore, Categories } = require("./store");
const { withVaultIdentityLock, normalizeVaultId } = require("./vault-identity");
const { releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { appendAudit, readAudit } = require("./audit");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { assertOperationalNetwork, assertGenerationMainnetOperable } = require("./config");
const { settleGenesisSubmitError, ensureOwnSubmissionClaim, refreshUnobservedGenesis, observeOutputUnderTxId } = require("./genesis-recovery");
const { firstLine } = require("./submission-classification");

const HEADLESS_CREATION_SCHEMA = "policyvault-headless-creation/v1";
const HEADLESS_GENESIS_ACTIONS = Object.freeze(new Set(["createVault", "createVaultV2"]));
const RECOVERABLE_STATES = Object.freeze(new Set(["SIGNED", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "SUBMISSION_REJECTED", "CHAIN_VERIFIED"]));

function fail(message, code) {
  const e = new Error(`headless-creation: ${message}`);
  if (code) e.code = code;
  return e;
}

/* ------------------------------------------------------------------ */
/* durable record                                                      */
/* ------------------------------------------------------------------ */

async function loadHeadlessCreation(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  if (r && r.requestId !== requestId) throw fail("request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return r && r.schema === HEADLESS_CREATION_SCHEMA ? r : null;
}
async function saveHeadlessCreation(config, record) {
  record.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, record.requestId, record);
  return record;
}
async function listHeadlessCreations(config, { vaultId, states } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST);
  return all
    .filter((r) => r && r.schema === HEADLESS_CREATION_SCHEMA && (vaultId === undefined || r.vaultId === vaultId) && (states === undefined || states.includes(r.state)))
    .sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/*
 * Open the durable record for a SIGNED headless genesis (create-only; a fresh request id). Written BEFORE the submission
 * claim and BEFORE the broadcast — from this moment the identity is reserved durably and the exact outcome is bound.
 */
async function openHeadlessCreation(config, { generation, action, contractVersion, vaultId, creator, label = "", definition, expected, txId, signedSafeJson }) {
  if (!HEADLESS_GENESIS_ACTIONS.has(action)) throw fail(`unknown headless genesis action ${JSON.stringify(action)}`, "UNKNOWN_ACTION");
  if (!["v1", "v2"].includes(generation)) throw fail(`unknown headless generation ${JSON.stringify(generation)}`, "UNKNOWN_VERSION");
  const record = {
    schema: HEADLESS_CREATION_SCHEMA,
    requestId: crypto.randomUUID(),
    kind: "genesis",
    generation,
    action,
    contractVersion,
    networkId: config.networkId,
    vaultId: normalizeVaultId(vaultId),
    creator,
    label,
    definition,
    expected: { address: expected.address, index: Number(expected.index), value: String(expected.value), covenantId: String(expected.covenantId).toLowerCase(), scriptSha256: expected.scriptSha256, stateId: expected.stateId },
    txId: String(txId).toLowerCase(),
    signedSafeJson,
    state: "SIGNED",
    error: undefined,
    submissionOutcome: undefined,
    submissionResponse: undefined,
    chain: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  const created = await getStore(config).createExclusive(Categories.REQUEST, record.requestId, record);
  if (!created) throw fail(`headless creation record ${record.requestId} already exists — internal`, "REQUEST_ID_MISMATCH");
  return record;
}

/* ------------------------------------------------------------------ */
/* definition -> expected outcome (immutable definitions, never labels) */
/* ------------------------------------------------------------------ */

/* Re-derive the exact genesis script / address / value / state id from the record's definition. Compares them with the
 * outcome the record was written with: any difference is a corrupted or mis-bound record — fail closed. */
function deriveHeadlessExpected(config, record) {
  let derived;
  if (record.generation === "v1") {
    const { compileExactState } = require("./contract-compiler");
    const { normalizePolicy, normalizeState, computeStateId } = require("./vault-state");
    const policy = normalizePolicy(record.definition.policyInput);
    const createdState = normalizeState({ protectedValue: policy.initValue, periodStartDaa: policy.initPeriodStartDaa, periodSpent: "0", paused: "0" });
    const stateId = computeStateId({ networkId: config.networkId, policy, state: createdState });
    const compiled = compileExactState({ config, policy, state: createdState });
    derived = { vaultId: policy.vaultId, address: covenantAddress(config, compiled.scriptBytes), value: policy.initValue.toString(), scriptSha256: compiled.scriptSha256, stateId, policy, createdState };
  } else if (record.generation === "v2") {
    const { compileExactStateV2 } = require("./contract-compiler-v2");
    const { normalizeTemplateV2, normalizeStateV2, computeStateIdV2 } = require("./vault-state-v2");
    const template = normalizeTemplateV2(record.definition.templateInput);
    const state = normalizeStateV2(record.definition.initialStateInput);
    const stateId = computeStateIdV2({ networkId: config.networkId, template, state });
    const compiled = compileExactStateV2({ config, template, state });
    derived = { vaultId: template.vaultId, address: covenantAddress(config, compiled.scriptBytes), value: state.protectedValue.toString(), scriptSha256: compiled.scriptSha256, stateId, template, state };
  } else {
    throw fail(`unknown headless generation ${JSON.stringify(record.generation)} — failing closed`, "UNKNOWN_VERSION");
  }
  if (derived.vaultId !== record.vaultId) throw fail("the record's definition names a different vault identity than the record — refusing", "RECONCILIATION_REQUIRED");
  const e = record.expected ?? {};
  if (derived.address !== e.address || derived.value !== String(e.value) || derived.scriptSha256 !== e.scriptSha256 || derived.stateId !== e.stateId) {
    throw fail("the record's expected outcome differs from the outcome re-derived from its definition — refusing to complete", "RECONCILIATION_REQUIRED");
  }
  return { ...derived, index: Number(e.index), covenantId: String(e.covenantId).toLowerCase(), txId: record.txId };
}

/* The signed bytes must reconstruct the record's txid (binds the record to what was, or was not, broadcast). */
function assertSignedHeadlessBinding(config, record) {
  if (typeof record.signedSafeJson !== "string" || !record.signedSafeJson) throw fail("the record carries no signed genesis transaction — nothing was broadcast for it and nothing is constructed here", "RECONCILIATION_REQUIRED");
  const { loadKaspa } = require("./chain");
  const { Transaction } = loadKaspa(config);
  const tx = Transaction.deserializeFromSafeJSON(record.signedSafeJson);
  const txId = tx.finalize().toString().toLowerCase();
  if (txId !== record.txId) throw fail(`reconstructed txid ${txId} != recorded ${record.txId}`, "TXID_MISMATCH");
}

/* Legacy observation records intentionally have no signatures. Their authority is the retained original claim plus
 * the immutable definition, or an exact receipt after our own completion released that claim. A marker alone is never
 * enough to bypass signed-byte binding. This also handles RC36 records interrupted before their final state write. */
async function assertLegacyHeadlessBinding(config, record) {
  const generationAction = record.generation === "v1" ? "createVault" : record.generation === "v2" ? "createVaultV2" : null;
  const version = record.generation === "v1" ? require("./config").CONTRACT_VERSION : require("./vault-state-v2").CONTRACT_VERSION_V2;
  if (!generationAction || record.action !== generationAction || record.contractVersion !== version || record.signedSafeJson !== null || !record.legacyClaimRecovery || !/^[0-9a-f]{64}$/.test(record.txId ?? "") || !Number.isSafeInteger(record.expected?.index) || record.expected.index < 0 || !/^[0-9a-f]{64}$/.test(record.expected?.covenantId ?? "")) throw fail("legacy recovery record has missing or mismatched original metadata", "RECONCILIATION_REQUIRED");
  const store = getStore(config);
  const claim = await store.read(Categories.SUBMISSION_CLAIM, record.txId);
  if (claim) {
    if (claim.schema !== "policyvault-submission-claim/v1" || claim.txId !== record.txId || claim.vaultId !== record.vaultId || claim.action !== record.action) throw fail("legacy recovery claim differs from the retained original operation", "CLAIM_CONFLICT");
    if (record.legacyClaimRecovery.claimCreatedAt === null || record.legacyClaimRecovery.claimCreatedAt === claim.createdAt) return;
    // A retry may have re-established our claim after the original completion released it. Only our exact receipt
    // can justify the new timestamp; an arbitrary replacement claim never supplies missing original evidence.
  }
  const receipt = await store.read(Categories.RECEIPT, record.txId);
  const outpoint = receipt?.proof?.outpoint;
  if (!receipt || receipt.txId !== record.txId || receipt.vaultId !== record.vaultId || receipt.action !== record.action || receipt.proof?.requestId !== record.requestId || outpoint?.transactionId !== record.txId || outpoint?.index !== record.expected.index || String(receipt.proof?.amount) !== record.expected.value || receipt.proof?.covenantId !== record.expected.covenantId) throw fail("legacy recovery has neither its original claim nor its own completed-output receipt", "RECONCILIATION_REQUIRED");
}

function assertSuppliedLegacyDefinition(config, record, { policyInput, templateInput, initialStateInput }) {
  if (!policyInput && !templateInput && !initialStateInput) return; // the original definition is already durable
  const supplied = record.generation === "v1" ? { policyInput } : { templateInput, initialStateInput };
  let derived;
  try { derived = deriveHeadlessDefinition(config, { generation: record.generation, definition: supplied }); }
  catch { throw fail("the supplied original definition is incomplete or invalid", "DEFINITION_MISMATCH"); }
  const original = deriveHeadlessExpected(config, record);
  if (["vaultId", "address", "value", "scriptSha256", "stateId"].some((field) => derived[field] !== original[field])) throw fail("the supplied definition differs from the durable original definition", "DEFINITION_MISMATCH");
}

/* ------------------------------------------------------------------ */
/* settlement of a broadcast error (shared classifier + output check)  */
/* ------------------------------------------------------------------ */

/* Returns { decision, error? }: REJECTED (record SUBMISSION_REJECTED, claim released, `error` to throw), UNCERTAIN (record
 * RECONCILIATION_REQUIRED, claim kept, `error` to throw) or OBSERVE (the node already holds / accepted the transaction —
 * the caller proceeds exactly as after an accepted response). */
async function settleHeadlessBroadcast(config, rpc, record, cause) {
  const message = firstLine(cause);
  record.error = message;
  const settled = await settleGenesisSubmitError({ config, rpc, request: record, message, txId: record.txId, expected: record.expected });
  if (settled.decision === "REJECTED") {
    record.state = "SUBMISSION_REJECTED";
    record.submissionOutcome = { outcome: "SUBMISSION_REJECTED", reason: message, txId: record.txId, proof: settled.proof };
    await saveHeadlessCreation(config, record); // durable proof before release; interrupted releases are replayable
    await releaseSubmissionClaim(config, record.txId);
    return { decision: "REJECTED", error: fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED") };
  }
  if (settled.decision === "UNCERTAIN") {
    record.state = "RECONCILIATION_REQUIRED";
    record.error = `${message} — ${settled.reason}`;
    await saveHeadlessCreation(config, record);
    return { decision: "UNCERTAIN", error: fail(`submit failed: ${message} — ${settled.reason}; recover with recoverHeadlessCreation (nothing is rebroadcast)`, "RECONCILIATION_REQUIRED") };
  }
  record.submissionResponse = { kind: "ALREADY_KNOWN", variant: settled.classification.variant, reason: message, at: new Date().toISOString() };
  await saveHeadlessCreation(config, record);
  return { decision: "OBSERVE" };
}

/* ------------------------------------------------------------------ */
/* ONE replayable completion                                           */
/* ------------------------------------------------------------------ */

async function observeHeadlessOutcome(rpc, expected, { pollAttempts = 1, pollDelayMs = 0 } = {}) {
  let proof = null;
  for (let i = 0; i < pollAttempts && !proof; i++) {
    const observed = await observeOutputUnderTxId(rpc, expected);
    if (observed.ref && observed.exact) proof = observed.ref;
    if (!proof && i + 1 < pollAttempts) await new Promise((r) => setTimeout(r, pollDelayMs));
  }
  return proof;
}

function ownHeadlessReceipt(record, receipt) {
  const outpoint = receipt?.proof?.outpoint;
  return receipt && receipt.txId === record.txId && receipt.vaultId === record.vaultId && receipt.action === record.action && receipt.proof?.requestId === record.requestId && outpoint?.transactionId === record.txId && outpoint?.index === record.expected.index && String(receipt.proof?.amount) === record.expected.value && receipt.proof?.covenantId === record.expected.covenantId;
}
async function ownHeadlessManifest(config, record) {
  const raw = await getStore(config).read(Categories.VAULT, record.vaultId);
  const schema = record.generation === "v1" ? require("./manifest").MANIFEST_SCHEMA : require("./manifest-v2").MANIFEST_SCHEMA_V2;
  if (!raw || raw.schema !== schema || raw.contractVersion !== record.contractVersion || raw.networkId !== record.networkId || raw.vaultId !== record.vaultId || raw.creationTxId !== record.txId) return null;
  if (record.generation === "v1") {
    const manifest = await require("./manifest").loadManifest(config, record.vaultId);
    const policy = require("./vault-state").normalizePolicy(record.definition.policyInput);
    const encode = (value) => JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item);
    return encode(manifest.policy) === encode(policy) ? manifest : null;
  }
  const manifest = await require("./manifest-v2").loadManifestV2(config, record.vaultId);
  const template = require("./vault-state-v2").normalizeTemplateV2(record.definition.templateInput);
  return manifest.template.owner === template.owner && manifest.template.vaultId === template.vaultId ? manifest : null;
}

/* Create-only manifest (RC33-ID-01 arbiter), idempotent receipt + audit, own-claim release, record CHAIN_VERIFIED last. */
async function completeHeadlessCreation(config, record, proof, { fee = null, via = "create" } = {}) {
  const derived = deriveHeadlessExpected(config, record);
  const store = getStore(config);
  // Check a competing operation before any completion write, including interrupted legacy recovery.
  const held = await store.read(Categories.SUBMISSION_CLAIM, record.txId);
  if (held && (held.txId !== record.txId || held.vaultId !== record.vaultId || held.action !== record.action)) throw fail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  const priorReceipt = await store.read(Categories.RECEIPT, record.txId);
  if (priorReceipt && !ownHeadlessReceipt(record, priorReceipt)) throw fail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  const live = {
    stateId: derived.stateId,
    outpoint: { transactionId: record.txId, index: derived.index },
    outpointValue: derived.value,
    scriptSha256: derived.scriptSha256,
    covenantId: derived.covenantId
  };
  let manifest = priorReceipt ? await ownHeadlessManifest(config, record) : null;
  try {
    // An exact original receipt can replay genesis bookkeeping after its output has been spent. Never replace
    // an existing later manifest, and never interpret this as proof of the later transition's chain outcome.
    if (!manifest && record.generation === "v1") {
      const { createManifest, VaultStatus, MANIFEST_SCHEMA } = require("./manifest");
      const { CONTRACT_VERSION } = require("./config");
      ({ manifest } = await createManifest(config, {
        schema: MANIFEST_SCHEMA, contractVersion: CONTRACT_VERSION, networkId: config.networkId, vaultId: record.vaultId, label: record.label ?? "", status: VaultStatus.ACTIVE,
        policy: record.definition.policyInput,
        live: { ...live, state: { protectedValue: derived.createdState.protectedValue.toString(), periodStartDaa: derived.createdState.periodStartDaa.toString(), periodSpent: "0", paused: "0" } },
        creationTxId: record.txId, latestTransitionTxId: null
      }));
    } else if (!manifest) {
      const { VaultStatus } = require("./manifest");
      const { MANIFEST_SCHEMA_V2, createManifestV2 } = require("./manifest-v2");
      const { CONTRACT_VERSION_V2, stateToJson } = require("./vault-state-v2");
      ({ manifest } = await createManifestV2(config, {
        schema: MANIFEST_SCHEMA_V2, contractVersion: CONTRACT_VERSION_V2, networkId: config.networkId, vaultId: record.vaultId, label: record.label ?? "", status: VaultStatus.ACTIVE,
        template: { owner: derived.template.owner, vaultId: derived.template.vaultId },
        live: { ...live, state: stateToJson(derived.state) },
        creationTxId: record.txId, latestTransitionTxId: null, lastTransition: null
      }));
    }
  } catch (e) {
    if (e.code !== "RECONCILIATION_REQUIRED") throw e;
    /* RC33-ID-01: the identity holds a DIFFERENT record (any generation) — preserved untouched; the proven chain effect stays
     * on THIS record (signed bytes, txid, submission claim intact) as RECONCILIATION_REQUIRED */
    record.state = "RECONCILIATION_REQUIRED";
    record.error = `chain effect proven but the vault record could not be created: ${firstLine(e)}`;
    await saveHeadlessCreation(config, record);
    throw fail(record.error, "RECONCILIATION_REQUIRED");
  }
  const receipt = await store.read(Categories.RECEIPT, record.txId);
  if (receipt && (receipt.vaultId !== record.vaultId || receipt.action !== record.action)) throw fail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  if (!receipt) {
    await persistReceipt(config, {
      txId: record.txId, vaultId: record.vaultId, action: record.action,
      proof: { outpoint: proof.outpoint, amount: proof.amount.toString(), covenantId: proof.covenantId, requestId: record.requestId, ...(fee ? { requiredFeeSompi: fee.requiredFee.toString(), actualFeeSompi: fee.actualFee.toString() } : {}), ...(via !== "create" ? { reconciled: true } : {}) }
    });
  }
  if (!(await readAudit(config, { vaultId: record.vaultId, txId: record.txId, limit: 500 })).some((e) => e.action === "vault_created" && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, { vaultId: record.vaultId, action: "vault_created", actor: "owner", ...(record.generation === "v2" ? { contractVersion: record.contractVersion } : {}), txId: record.txId, result: "CHAIN_VERIFIED", ...(fee ? { feeSompi: fee.actualFee.toString() } : {}), newStateId: derived.stateId, ...(via !== "create" ? { via: `headless/${via}` } : {}) });
  }
  const submission = await store.read(Categories.SUBMISSION_CLAIM, record.txId);
  if (submission && (submission.vaultId !== record.vaultId || submission.action !== record.action)) throw fail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  if (submission) await releaseSubmissionClaim(config, record.txId);
  record.state = "CHAIN_VERIFIED";
  record.error = undefined;
  record.chain = { successorOutpoint: `${record.txId}:${derived.index}`, observedAt: record.chain?.observedAt ?? new Date().toISOString(), completion: { via, completedAt: new Date().toISOString() } };
  await saveHeadlessCreation(config, record);
  return { manifest, record };
}

/* Every durable record of a CHAIN_VERIFIED headless creation actually present? (local; no node) */
async function verifyHeadlessCompletion(config, record) {
  const missing = [];
  const store = getStore(config);
  const manifest = await ownHeadlessManifest(config, record);
  if (!manifest) missing.push("VAULT record");
  const receipt = await store.read(Categories.RECEIPT, record.txId);
  if (!ownHeadlessReceipt(record, receipt)) missing.push("receipt");
  if (!(await readAudit(config, { vaultId: record.vaultId, txId: record.txId, limit: 500 })).some((e) => e.action === "vault_created" && e.result === "CHAIN_VERIFIED")) missing.push("audit");
  if (await store.read(Categories.SUBMISSION_CLAIM, record.txId)) missing.push("claim release");
  return { complete: missing.length === 0, missing, genesisProven: Boolean(manifest && ownHeadlessReceipt(record, receipt)), manifest, receipt };
}

/* ------------------------------------------------------------------ */
/* observation-only recovery                                           */
/* ------------------------------------------------------------------ */

async function recoverHeadlessCreation(config, { requestId, rpc: providedRpc, pollAttempts = 1, pollDelayMs = 0 }) {
  const peek = await loadHeadlessCreation(config, requestId);
  if (!peek) throw fail(`no headless creation ${requestId}`, "REQUEST_NOT_FOUND");
  return withVaultIdentityLock(peek.vaultId, () => recoverHeadlessCreationUnlocked(config, { requestId, rpc: providedRpc, pollAttempts, pollDelayMs }));
}
async function recoverHeadlessCreationUnlocked(config, { requestId, rpc: providedRpc, pollAttempts, pollDelayMs }) {
  const record = await loadHeadlessCreation(config, requestId);
  if (!record) throw fail(`no headless creation ${requestId}`, "REQUEST_NOT_FOUND");
  if (record.networkId !== config.networkId) throw fail(`record network ${record.networkId} != configured ${config.networkId} — refusing`, "NETWORK_MISMATCH");
  if (!RECOVERABLE_STATES.has(record.state)) throw fail(`headless creation ${requestId} is ${record.state}; nothing to recover`, record.state);
  assertOperationalNetwork(config);
  assertGenerationMainnetOperable(config, record.contractVersion);
  const expected = deriveHeadlessExpected(config, record); // immutable definitions, bound to the record's stored outcome
  if (record.signedSafeJson === null && record.legacyClaimRecovery) await assertLegacyHeadlessBinding(config, record);
  else assertSignedHeadlessBinding(config, record);
  const verified = await verifyHeadlessCompletion(config, record);
  if (verified.genesisProven) {
    if (record.state === "CHAIN_VERIFIED" && verified.complete) return { record, outcome: "CHAIN_VERIFIED", detail: "already complete" };
    const proof = { outpoint: verified.receipt.proof.outpoint, amount: BigInt(verified.receipt.proof.amount), covenantId: verified.receipt.proof.covenantId };
    const { manifest } = await completeHeadlessCreation(config, record, proof, { via: "receipt-recovery" });
    return { record, manifest, outcome: "CHAIN_VERIFIED", detail: "original genesis receipt proves completion; missing bookkeeping replayed, existing vault state preserved" };
  }
  const fromNegative = record.state === "SUBMISSION_REJECTED";
  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    const proof = await observeHeadlessOutcome(rpc, expected, { pollAttempts, pollDelayMs });
    if (!proof) {
      const disposition = await refreshUnobservedGenesis({ config, rpc, request: record, claim: { txId: record.txId, vaultId: record.vaultId, action: record.action }, save: (q) => saveHeadlessCreation(config, q) });
      if (disposition.action === "KEEP_NEGATIVE") return { record, outcome: "SUBMISSION_REJECTED", detail: `the recorded rejection of ${record.txId} is established (a bound node rejection of this attempt) and its vault output is not observed — nothing to recover, nothing rebroadcast` };
      if (record.state === "CHAIN_VERIFIED") return { record, outcome: "PENDING", detail: `${record.txId} is labelled CHAIN_VERIFIED but its durable records are incomplete and its vault output is not observed — prior records are preserved` };
      await ensureOwnSubmissionClaim(config, { txId: record.txId, vaultId: record.vaultId, action: record.action }); // idempotent; never another operation's
      record.state = "RECONCILIATION_REQUIRED";
      record.error = disposition.reason ?? `${record.txId} is not observed at ${expected.address}:${expected.index} — outcome unresolved; the claim and the signed transaction are retained (nothing is rebroadcast)`;
      await saveHeadlessCreation(config, record);
      return { record, outcome: "PENDING", detail: record.error };
    }
    await ensureOwnSubmissionClaim(config, { txId: record.txId, vaultId: record.vaultId, action: record.action }); // completion is always this operation's; interrupted claim release is replayable
    const { manifest } = await completeHeadlessCreation(config, record, proof, { via: "recovery" });
    return { record, manifest, outcome: "CHAIN_VERIFIED", detail: `vault output ${record.txId}:${expected.index} observed — completed by observation${fromNegative ? " (the recorded rejection was a false negative)" : ""}` };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* ------------------------------------------------------------------ */
/* legacy retained claims (written by earlier runtimes without a record) */
/* ------------------------------------------------------------------ */

/* Headless genesis submission claims whose identity has no vault record and no headless creation record: the binding
 * vaultId <-> txId is exactly what the claim carries; everything else needs the ORIGINAL definition (below). Each such
 * claim reserves its identity durably (sdk/src/vault-identity.js) until it is completed or the operator resolves it. */
async function listUnresolvedHeadlessClaims(config) {
  const store = getStore(config);
  const out = [];
  for (const claim of await store.listValues(Categories.SUBMISSION_CLAIM)) {
    if (!claim || !HEADLESS_GENESIS_ACTIONS.has(claim.action) || typeof claim.vaultId !== "string" || typeof claim.txId !== "string") continue;
    const vault = await store.read(Categories.VAULT, claim.vaultId).catch(() => "unreadable");
    if (vault !== null) continue; // the identity is occupied by a record (or unreadable — occupied either way)
    const records = (await listHeadlessCreations(config, { vaultId: claim.vaultId })).filter((r) => r.txId === claim.txId.toLowerCase());
    out.push({ txId: claim.txId, vaultId: claim.vaultId, action: claim.action, createdAt: claim.createdAt ?? null, recordId: records.length ? records[0].requestId : null, disposition: records.length ? "RECOVER_RECORD" : "NEEDS_ORIGINAL_DEFINITION" });
  }
  return out;
}

/*
 * Complete a LEGACY retained claim from the ORIGINAL definition supplied by the operator (v1: { policyInput }; v2:
 * { templateInput, initialStateInput }). Observation only: the derived identity must equal the claim's, the derived
 * address is observed under the claim's txid (any output index; the exact value), the covenant id is READ from the
 * observed output (never guessed), and the record is created create-only. An unobserved output leaves the claim exactly
 * as it is (it keeps reserving the identity) and reports UNRESOLVED.
 */
async function recoverLegacyHeadlessClaim(config, { txId, policyInput = null, templateInput = null, initialStateInput = null, label = "", rpc: providedRpc }) {
  const id = String(txId ?? "").toLowerCase();
  const store = getStore(config);
  // Resume a durable legacy observation record even if a crash happened after its claim was released.
  const retained = (await listHeadlessCreations(config)).filter((r) => r.txId === id);
  if (retained.length) {
    if (retained.length !== 1 || !retained[0].legacyClaimRecovery || retained[0].signedSafeJson !== null) throw fail("transaction has another durable creation record; recover its request directly", "RECORD_EXISTS");
    const original = retained[0];
    return withVaultIdentityLock(original.vaultId, async () => {
      const fresh = await loadHeadlessCreation(config, original.requestId);
      if (!fresh || fresh.txId !== id) throw fail("legacy recovery request changed", "REQUEST_ID_MISMATCH");
      assertSuppliedLegacyDefinition(config, fresh, { policyInput, templateInput, initialStateInput });
      const result = await recoverHeadlessCreationUnlocked(config, { requestId: fresh.requestId, rpc: providedRpc, pollAttempts: 1, pollDelayMs: 0 });
      return { ...result, txId: id, vaultId: fresh.vaultId, requestId: fresh.requestId };
    });
  }
  const claim = await store.read(Categories.SUBMISSION_CLAIM, id);
  if (!claim || !HEADLESS_GENESIS_ACTIONS.has(claim.action) || typeof claim.vaultId !== "string") throw fail(`no retained headless genesis claim for ${id}`, "CLAIM_NOT_FOUND");
  const generation = claim.action === "createVault" ? "v1" : "v2";
  if (generation === "v1" && !policyInput) throw fail("the original policy input is required to complete a v0.1 headless claim — nothing is inferred", "DEFINITION_REQUIRED");
  if (generation === "v2" && (!templateInput || !initialStateInput)) throw fail("the original template and initial state are required to complete a v0.2 headless claim — nothing is inferred", "DEFINITION_REQUIRED");
  const definition = generation === "v1" ? { policyInput } : { templateInput, initialStateInput };
  const vaultId = normalizeVaultId(claim.vaultId);
  return withVaultIdentityLock(vaultId, async () => {
    const currentClaim = await store.read(Categories.SUBMISSION_CLAIM, id);
    if (!currentClaim || currentClaim.txId !== id || currentClaim.vaultId !== vaultId || currentClaim.action !== claim.action || currentClaim.createdAt !== claim.createdAt) throw fail("retained claim changed before recovery acquired its lock", "CLAIM_CONFLICT");
    const concurrent = (await listHeadlessCreations(config, { vaultId })).filter((r) => r.txId === id);
    if (concurrent.length) {
      if (concurrent.length !== 1 || !concurrent[0].legacyClaimRecovery || concurrent[0].signedSafeJson !== null) throw fail("transaction has another durable creation record", "RECORD_EXISTS");
      assertSuppliedLegacyDefinition(config, concurrent[0], { policyInput, templateInput, initialStateInput });
      const result = await recoverHeadlessCreationUnlocked(config, { requestId: concurrent[0].requestId, rpc: providedRpc, pollAttempts: 1, pollDelayMs: 0 });
      return { ...result, txId: id, vaultId, requestId: concurrent[0].requestId };
    }
    /* derive from the supplied definition (the identity must match the claim's — a mismatched definition is refused) */
    const probe = { schema: HEADLESS_CREATION_SCHEMA, generation, definition, vaultId, expected: null };
    let derived;
    try {
      const partial = deriveHeadlessDefinition(config, probe);
      derived = partial;
    } catch (e) {
      throw fail(`the supplied definition cannot be compiled: ${firstLine(e)}`, e.code ?? "DEFINITION_INVALID");
    }
    if (derived.vaultId !== vaultId) throw fail("the supplied definition names a different vault identity than the retained claim — refusing", "DEFINITION_MISMATCH");
    assertOperationalNetwork(config);
    assertGenerationMainnetOperable(config, generation === "v1" ? require("./config").CONTRACT_VERSION : require("./vault-state-v2").CONTRACT_VERSION_V2);
    const owned = !providedRpc;
    const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
    try {
      if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
      const refs = (await getAddressUtxos(rpc, derived.address)).filter((u) => u.outpoint.transactionId === id && String(u.amount) === derived.value && u.covenantId);
      if (refs.length !== 1) return { outcome: "UNRESOLVED", txId: id, vaultId, detail: refs.length ? "more than one matching output under this transaction — ambiguous, refusing" : `no output of ${id} with the derived value is observed unspent at ${derived.address} — the claim keeps reserving the identity; nothing is rebroadcast` };
      const proof = refs[0];
      const record = {
        schema: HEADLESS_CREATION_SCHEMA, requestId: crypto.randomUUID(), kind: "genesis", generation, action: claim.action,
        contractVersion: generation === "v1" ? require("./config").CONTRACT_VERSION : require("./vault-state-v2").CONTRACT_VERSION_V2,
        networkId: config.networkId, vaultId, creator: null, label, definition,
        expected: { address: derived.address, index: proof.outpoint.index, value: derived.value, covenantId: proof.covenantId, scriptSha256: derived.scriptSha256, stateId: derived.stateId },
        txId: id, signedSafeJson: null, state: "SUBMITTED", error: undefined, submissionOutcome: undefined, submissionResponse: undefined, chain: { observedAt: new Date().toISOString() },
        legacyClaimRecovery: { claimCreatedAt: claim.createdAt ?? null, definitionSuppliedAt: new Date().toISOString() },
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      };
      if (!await store.createExclusive(Categories.REQUEST, record.requestId, record)) throw fail("record id collision — internal", "REQUEST_ID_MISMATCH");
      const { manifest } = await completeHeadlessCreation(config, record, proof, { via: "legacy-claim-recovery" });
      return { outcome: "CHAIN_VERIFIED", txId: id, vaultId, requestId: record.requestId, manifest, detail: `output ${id}:${proof.outpoint.index} observed at the address derived from the supplied definition; covenant id ${proof.covenantId} read from the chain` };
    } finally {
      if (owned) await rpc.disconnect();
    }
  });
}

/* definition -> derived outcome without an `expected` to compare against (legacy-claim path) */
function deriveHeadlessDefinition(config, record) {
  if (record.generation === "v1") {
    const { compileExactState } = require("./contract-compiler");
    const { normalizePolicy, normalizeState, computeStateId } = require("./vault-state");
    const policy = normalizePolicy(record.definition.policyInput);
    const createdState = normalizeState({ protectedValue: policy.initValue, periodStartDaa: policy.initPeriodStartDaa, periodSpent: "0", paused: "0" });
    const stateId = computeStateId({ networkId: config.networkId, policy, state: createdState });
    const compiled = compileExactState({ config, policy, state: createdState });
    return { vaultId: policy.vaultId, address: covenantAddress(config, compiled.scriptBytes), value: policy.initValue.toString(), scriptSha256: compiled.scriptSha256, stateId };
  }
  const { compileExactStateV2 } = require("./contract-compiler-v2");
  const { normalizeTemplateV2, normalizeStateV2, computeStateIdV2 } = require("./vault-state-v2");
  const template = normalizeTemplateV2(record.definition.templateInput);
  const state = normalizeStateV2(record.definition.initialStateInput);
  const stateId = computeStateIdV2({ networkId: config.networkId, template, state });
  const compiled = compileExactStateV2({ config, template, state });
  return { vaultId: template.vaultId, address: covenantAddress(config, compiled.scriptBytes), value: state.protectedValue.toString(), scriptSha256: compiled.scriptSha256, stateId };
}

module.exports = {
  HEADLESS_CREATION_SCHEMA,
  HEADLESS_GENESIS_ACTIONS,
  RECOVERABLE_STATES,
  loadHeadlessCreation,
  saveHeadlessCreation,
  listHeadlessCreations,
  openHeadlessCreation,
  deriveHeadlessExpected,
  assertSignedHeadlessBinding,
  settleHeadlessBroadcast,
  completeHeadlessCreation,
  verifyHeadlessCompletion,
  recoverHeadlessCreation,
  listUnresolvedHeadlessClaims,
  recoverLegacyHeadlessClaim
};
