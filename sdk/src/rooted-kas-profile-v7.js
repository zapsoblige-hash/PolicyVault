"use strict";

/*
 * The v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT profile adapter for the shared
 * organizational-root request pipeline (sdk/src/wallet-requests-v7.js) —
 * v0.7 mainnet-enablement directive (2026-09-10).
 *
 * Owner operations on a rooted KAS vault (ownerSetAgentRoot / ownerSetApprovers /
 * ownerTopUp / ownerTopUpReserve / ownerPause / ownerUnpause /
 * ownerEmergencyPause / ownerRecover) ride the SAME root transaction pipeline
 * the frozen payment profile uses — the root's M-of-N slot signing, the
 * finalize/submit ladder, durable claims, and the ONE replayable, validated
 * completion (Codex checkpoints 11/12) — because their authority IS the same
 * root input. What differs per profile is the vault side: how the vault
 * operation is built, which manifest family describes and verifies it, how
 * the M-of-N owner blob is assembled into the vault's call, and how the
 * vault's durable record is classified and advanced once the root successor
 * is proven. This module supplies exactly those pieces for the KAS profile;
 * the pipeline dispatches on the vault record's schema and keeps the payment
 * profile's own code path byte-identical.
 *
 * Never requires wallet-requests-v7.js at load time (the pipeline requires
 * THIS module); the KAS delegate-request loader is resolved lazily.
 *
 * Status: IMPLEMENTED. Exercised by sdk/test/wallet-v7-kas-api.test.js.
 */

const { canonicalJsonStringify } = require("../../core/intent/canonical");
const { CONTRACT_VERSION_V7_KAS, resolveOwnerOpAuthorityV7Kas, computeStateIdV7Kas } = require("../../core/model/vault-state-v7-kas");
const { normalizeStateV4, stateToJsonV4 } = require("../../core/model/vault-state-v4");
const { buildOrgRootIntentManifestV7Kas, verifyOrgRootIntentManifestV7Kas } = require("../../core/intent/org-root-manifest-v7-kas");
const { buildV7KasTransaction, finalizeV7KasTransaction } = require("./vault-builders-v7-kas");
const { compileExactStateV7Kas } = require("./contract-compiler-v7-kas");
const { ensureBuildDir } = require("./build-cache");
const { normalizeHex } = require("./vault-state");
const { VaultStatus } = require("./manifest");
const {
  MANIFEST_SCHEMA_V7_KAS,
  loadManifestV7Kas,
  persistManifestV7Kas,
  normalizeManifestV7Kas,
  manifestToJsonV7Kas,
  normalizeRegistry,
  registryEntryToJson,
  liveValueOfStateKas
} = require("./manifest-v7-kas");

const OWNER_OP_ACTIONS_KAS = Object.freeze({
  ownerSetAgentRoot: "ownerSetAgentRoot",
  ownerSetApprovers: "ownerSetApprovers",
  ownerTopUp: "ownerTopUp",
  ownerTopUpReserve: "ownerTopUpReserve",
  ownerPause: "ownerPause",
  ownerUnpause: "ownerUnpause",
  ownerEmergencyPause: "ownerEmergencyPause",
  ownerRecover: "ownerRecover"
});
const COMPLETION_HISTORY_LIMIT = 128;
const DELEGATE_PENDING_STATES = new Set(["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"]);

function fail(message, code) {
  const e = new Error(`rooted-kas-profile-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}
function isKasVaultRecord(record) {
  return !!record && typeof record === "object" && record.schema === MANIFEST_SCHEMA_V7_KAS && record.contractVersion === CONTRACT_VERSION_V7_KAS;
}
function isKasBuild(build) {
  return !!build && typeof build === "object" && build.contractVersion === CONTRACT_VERSION_V7_KAS;
}
function normalizeOutpoint(op, label) {
  return Object.freeze({ transactionId: normalizeHex(op?.transactionId, 32, `${label}.transactionId`), index: Number(op?.index) });
}
function sameOutpoint(a, b) {
  return Boolean(a && b) && String(a.transactionId).toLowerCase() === String(b.transactionId).toLowerCase() && Number(a.index) === Number(b.index);
}
function describeOutpoint(op) {
  return op ? `${op.transactionId}:${op.index}` : "(no live outpoint)";
}
/* The model's normalized state (BigInt fields, 10 slots) and its JSON shape both canonicalize through the shared v4 normalizer. */
function canonicalStateJsonKas(state) {
  if (!state || typeof state !== "object") fail("state object is required");
  return stateToJsonV4(normalizeStateV4(typeof state.protectedValue === "bigint" ? stateToJsonV4(state) : state));
}
function sameVaultStateKas(a, b) {
  return a === null || b === null ? a === b : canonicalJsonStringify(canonicalStateJsonKas(a)) === canonicalJsonStringify(canonicalStateJsonKas(b));
}
function manifestDocKas(normalized) {
  return manifestToJsonV7Kas(normalized);
}
function liveValueKas(record) {
  if (!record || !record.live) fail("the KAS vault record carries no live outpoint", "ROOT_STALE_OUTPOINT");
  return liveValueOfStateKas(record.live.state).toString();
}
function vaultSuccessorIndexOf(request) {
  return request.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.build.covenantId);
}

/* ---- build / manifest / verify / finalize (owner operations riding a root transition) ---- */

/* ownerSetAgentRoot installs a FULL new delegate policy set: the caller supplies REGISTRY ENTRIES (v0.4.1 policy fields +
 * each agent's recipient allowlist, the genesis `agents` shape); they are validated here, the builder derives the new
 * agentRoot from the policies (never from a caller-supplied root), the manifest carries the policies for the owners'
 * review, and the durable registry is replaced by these entries only once the transition is CHAIN-VERIFIED. */
function prepareOwnerOpParamsKas(action, params = {}) {
  if (action !== "ownerSetAgentRoot") return { opParams: { ...params }, newRegistry: null };
  if (!Array.isArray(params.agents)) fail("ownerSetAgentRoot requires params.agents — the FULL new delegate policy set with each agent's recipients (never a bare root)", "AGENT_SET_REQUIRED");
  let normalized;
  try { normalized = normalizeRegistry(params.agents); } catch (e) { fail(`ownerSetAgentRoot: the new delegate policy set is malformed: ${e.message}`, e.code || "AGENT_SET_INVALID"); }
  const newRegistry = normalized.entries.map((e) => registryEntryToJson(e));
  return { opParams: { ...params, agents: newRegistry.map((e) => ({ ...e })), newAgentRoot: normalized.tree.root }, newRegistry };
}
function resolveOwnerOpAuthorityKas(action) {
  return resolveOwnerOpAuthorityV7Kas(action);
}
function buildOwnerOpKas({ config, vaultRecord, action, params, fuel, root, changeXOnly }) {
  return buildV7KasTransaction({
    config,
    contractVersion: CONTRACT_VERSION_V7_KAS,
    templateInput: vaultRecord.template,
    stateInput: stateToJsonV4(vaultRecord.live.state),
    action,
    params,
    chain: { predecessorOutpoint: vaultRecord.live.outpoint, covenantId: vaultRecord.live.covenantId, predecessorValue: liveValueKas(vaultRecord), fuel, root },
    changeXOnly
  });
}
function buildOrgManifestKas({ build, vaultOperations }) {
  return buildOrgRootIntentManifestV7Kas({ build, vaultOperations: vaultOperations.map((op) => ({ build: op.build })) });
}
function verifyOrgManifestKas({ manifest, redeemScripts }) {
  return verifyOrgRootIntentManifestV7Kas({ manifest, redeemScripts });
}
function finalizeOwnerOpKas({ build, approvals, fuelSignatureScriptHex }) {
  return finalizeV7KasTransaction({ build, approvals, fuelSignatureScriptHex });
}
/* F-03: an evicted compiled-artifact cache entry is recompiled deterministically from the build's own template/state. */
function ensureBuildDirKas(config, build) {
  return ensureBuildDir({ config, buildDir: build.encoderBuildDir, recompile: () => compileExactStateV7Kas({ config, template: build.template, state: build.stateJson, contractVersion: build.contractVersion }) });
}

/* ---- durable completion (the vault side of a proven root action, or a proven delegate spend) ---- */

/* The successor registry a chain-verified vault operation installs: ownerSetAgentRoot replaces the registry with the
 * request's validated entries (re-derived and matched to the successor agentRoot — a record that could not reproduce
 * the on-chain tree is never written); a delegate spend advances ONLY the spending agent's period accounting; every
 * other operation keeps the current registry. */
function advanceRegistryAfterSpendKas(registry, build) {
  const agentPk = build.callExtra.agentPk;
  const periodsElapsed = BigInt(build.callExtra.periodsElapsed ?? "0");
  const spendAmount = BigInt(build.payment.value);
  return registry.map((e) => {
    if (e.agentPk !== agentPk) return e;
    let newStart = BigInt(e.periodStartDaa);
    let newSpent = BigInt(e.periodSpent) + spendAmount;
    if (periodsElapsed >= 1n) {
      newStart = BigInt(e.periodStartDaa) + periodsElapsed * BigInt(e.periodLengthDaa);
      newSpent = spendAmount;
    }
    return { ...e, periodStartDaa: newStart.toString(), periodSpent: newSpent.toString() };
  });
}
/* `vaultManifest` is either the record AT THE PREDECESSOR (the successor is being WRITTEN: a delegate spend advances the
 * spending agent's accounting from the predecessor registry) or a record already at/after the successor (the doc is
 * being COMPARED: its registry already reflects every completed transition and is used as-is, exactly like the payment
 * profile's successorRegistryJson — the manifest normalizer independently pins registry root == covenant agentRoot). */
function successorRegistryKas(vaultManifest, request) {
  const successorVaultState = request.build.successorState;
  const opAction = Array.isArray(request.vaultOperations) && request.vaultOperations[0] ? request.vaultOperations[0].action : request.action;
  if (opAction === "ownerSetAgentRoot") {
    if (!Array.isArray(request.newRegistry)) fail("a chain-verified ownerSetAgentRoot request carries no newRegistry — the durable registry cannot be advanced; refusing to record a manifest that could not reproduce the on-chain tree", "REGISTRY_ROOT_MISMATCH");
    const { entries, tree } = normalizeRegistry(request.newRegistry);
    if (tree.root !== String(successorVaultState.agentRoot).toLowerCase()) fail(`the request's newRegistry folds to ${tree.root}, not the chain-verified successor agentRoot ${successorVaultState.agentRoot}`, "REGISTRY_ROOT_MISMATCH");
    return entries.map((e) => registryEntryToJson(e));
  }
  const current = manifestDocKas(vaultManifest).agentRegistry;
  const atPredecessor = Boolean(vaultManifest.live) && sameOutpoint(vaultManifest.live.outpoint, request.build.predecessorOutpoint);
  if (atPredecessor && opAction === "agentSpend" && isKasBuild(request.build) && request.build.action === "agentSpend") {
    const advanced = advanceRegistryAfterSpendKas(current, request.build);
    const { tree } = normalizeRegistry(advanced);
    if (tree.root !== String(successorVaultState.agentRoot).toLowerCase()) fail(`the advanced registry folds to ${tree.root}, not the successor agentRoot ${successorVaultState.agentRoot}`, "REGISTRY_ROOT_MISMATCH");
    return advanced;
  }
  return current;
}
/* The complete vault record this request's proven transition produces (what is written, and what a record is compared against). */
function expectedVaultSuccessorDocKas(config, vaultManifest, request, idx, generation) {
  const base = manifestDocKas(vaultManifest);
  if (request.build.successorState === null) {
    /* TERMINAL ownerRecover: protectedValue + feeReserve were paid out to the pinned recovery key; no vault continuation exists */
    return { ...base, status: VaultStatus.RECOVERED, live: null, latestTransitionTxId: request.txId, generation };
  }
  if (!(idx >= 0)) fail("the proven transition carries no vault continuation output — refusing", "RECONCILIATION_REQUIRED");
  const successorVaultState = request.build.successorState;
  const state = normalizeStateV4(successorVaultState);
  const stateId = computeStateIdV7Kas({ networkId: config.networkId, template: vaultManifest.template, state, contractVersion: vaultManifest.contractVersion });
  return {
    ...base,
    agentRegistry: successorRegistryKas(vaultManifest, request),
    status: state.paused === 1n ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
    live: {
      state: successorVaultState,
      stateId,
      outpoint: { transactionId: request.txId, index: idx },
      outpointValue: liveValueOfStateKas(state).toString(),
      scriptSha256: request.build.successorScriptSha256,
      covenantId: vaultManifest.live ? vaultManifest.live.covenantId : request.build.covenantId
    },
    latestTransitionTxId: request.txId,
    generation
  };
}
/* Field-by-field differences between a vault record already AT the successor outpoint and the expected successor record. */
function vaultSuccessorDifferencesKas(config, vaultManifest, request, idx) {
  const doc = manifestDocKas(vaultManifest);
  const diffs = [];
  if (request.build.successorState === null) {
    if (doc.status !== VaultStatus.RECOVERED) diffs.push(`status ${doc.status} != ${VaultStatus.RECOVERED}`);
    if (doc.live !== null) diffs.push("a live outpoint remains after a terminal recovery");
    if (doc.latestTransitionTxId !== request.txId) diffs.push(`latestTransitionTxId ${doc.latestTransitionTxId ?? "none"} != ${request.txId}`);
    return diffs;
  }
  let expected;
  try {
    expected = expectedVaultSuccessorDocKas(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0));
  } catch (e) {
    /* a comparison never throws: an underivable successor record is a DIFFERENCE (the record stays unexplained / fail closed) */
    return [`the expected successor record could not be derived: ${String(e && e.message ? e.message : e).split("\n")[0]}`];
  }
  if (doc.latestTransitionTxId !== request.txId) diffs.push(`latestTransitionTxId ${doc.latestTransitionTxId ?? "none"} != ${request.txId}`);
  if (!doc.live) { diffs.push("no live outpoint"); return diffs; }
  if (!sameVaultStateKas(doc.live.state, expected.live.state)) diffs.push("live.state != successor state");
  if (String(doc.live.stateId) !== String(expected.live.stateId)) diffs.push("live.stateId != successor state id");
  if (canonicalJsonStringify(doc.agentRegistry) !== canonicalJsonStringify(expected.agentRegistry)) diffs.push("agentRegistry != the registry this transition installs");
  if (doc.status !== expected.status) diffs.push(`status ${doc.status} != ${expected.status}`);
  if (String(doc.live.covenantId).toLowerCase() !== String(expected.live.covenantId).toLowerCase()) diffs.push("live.covenantId differs");
  if (String(doc.live.scriptSha256).toLowerCase() !== String(expected.live.scriptSha256).toLowerCase()) diffs.push("live.scriptSha256 != successor script");
  if (String(doc.live.outpointValue) !== String(expected.live.outpointValue)) diffs.push("live.outpointValue != successor protectedValue + feeReserve");
  return diffs;
}
/* Walk the vault's completed transition history (root actions carrying this vault + KAS delegate spends) back from
 * the record's latest transition to THIS request's successor: BEYOND only through a coherent chain of completed
 * requests whose states link up. `completedRequestAt` is the pipeline's own receipt-bound lookup. */
async function traceVaultCompletionKas(config, vault, request, idx, completedRequestAt) {
  if (request.build.successorState === null) return null;
  const wanted = { transactionId: request.txId, index: idx };
  let cursor = vault.live ? vault.live.outpoint : null;
  let expected = vault.live ? vault.live.state : null;
  let txId = vault.latestTransitionTxId;
  let firstVaultStep = true;
  const seen = new Set();
  const links = [];
  for (let i = 0; i < COMPLETION_HISTORY_LIMIT; i++) {
    if (!txId || seen.has(txId)) return null;
    seen.add(txId);
    const q = await completedRequestAt(config, txId);
    if (!q || !isKasBuild(q.build)) return null;
    const isRoot = q.kind === "rootAction";
    if (isRoot ? q.rootCovenantId !== request.rootCovenantId || !Array.isArray(q.vaultOperations) || q.vaultOperations.length !== 1 || q.vaultOperations[0].vaultId !== vault.vaultId : q.vaultId !== vault.vaultId || q.action !== "agentSpend") return null;
    const successor = q.build.successorState;
    const outIndex = successor === null ? -1 : vaultSuccessorIndexOf(q);
    if (successor === null ? cursor !== null : !sameOutpoint(cursor, { transactionId: txId, index: outIndex })) return null;
    if (!sameVaultStateKas(successor, expected)) return null;
    const view = isRoot ? q : { ...q, vaultOperations: [{ vaultId: vault.vaultId, action: q.action }] };
    if (firstVaultStep) {
      const doc = manifestDocKas(vault);
      doc.latestTransitionTxId = txId;
      if (vaultSuccessorDifferencesKas(config, normalizeManifestV7Kas(doc), view, outIndex).length) return null;
      firstVaultStep = false;
    }
    links.push(q.id ?? q.requestId);
    cursor = normalizeOutpoint(q.build.predecessorOutpoint, "history.vault.predecessor");
    expected = q.build.stateJson;
    if (sameOutpoint(cursor, wanted)) return sameVaultStateKas(expected, request.build.successorState) ? links : null;
    txId = cursor.transactionId;
  }
  return null;
}
/* Where a vault record stands relative to THIS request's transition: SUCCESSOR (consistent or not), PREDECESSOR,
 * BEYOND (provably advanced past it by later transitions), or OTHER (unexplained — fail closed). */
async function classifyVaultRecordKas(config, vaultManifest, request, idx, { completedRequestAt } = {}) {
  if (typeof completedRequestAt !== "function") fail("classifyVaultRecordKas requires the pipeline's completedRequestAt lookup");
  const predecessor = normalizeOutpoint(request.build.predecessorOutpoint, "build.predecessorOutpoint");
  const live = vaultManifest.live ? vaultManifest.live.outpoint : null;
  const atPredecessor = Boolean(live) && sameOutpoint(live, predecessor);
  if (request.build.successorState === null) {
    if (!vaultManifest.live && vaultManifest.latestTransitionTxId === request.txId) {
      const diffs = vaultSuccessorDifferencesKas(config, vaultManifest, request, idx);
      return { position: "SUCCESSOR", consistent: diffs.length === 0, differences: diffs };
    }
    if (atPredecessor) return { position: "PREDECESSOR", consistent: false, differences: vaultManifest.latestTransitionTxId === request.txId ? ["latestTransitionTxId names this transaction while the live outpoint is still the predecessor"] : [] };
    return { position: "OTHER", consistent: false, differences: [`live ${describeOutpoint(live)}, status ${vaultManifest.status}, last transition ${vaultManifest.latestTransitionTxId ?? "none"}`] };
  }
  const successor = { transactionId: request.txId, index: idx };
  if (live && sameOutpoint(live, successor)) {
    const diffs = vaultSuccessorDifferencesKas(config, vaultManifest, request, idx);
    if (diffs.length) {
      const history = await traceVaultCompletionKas(config, vaultManifest, request, idx, completedRequestAt);
      if (history) return { position: "BEYOND", consistent: true, differences: [], history };
    }
    return { position: "SUCCESSOR", consistent: diffs.length === 0, differences: diffs };
  }
  if (atPredecessor) return { position: "PREDECESSOR", consistent: false, differences: vaultManifest.latestTransitionTxId === request.txId ? ["latestTransitionTxId names this transaction while the live outpoint is still the predecessor"] : [] };
  const history = await traceVaultCompletionKas(config, vaultManifest, request, idx, completedRequestAt);
  if (history) return { position: "BEYOND", consistent: true, differences: [], history };
  return { position: "OTHER", consistent: false, differences: [`no coherent completed transition history connects this record (generation ${Number(vaultManifest.generation ?? 0)}) to the request successor`] };
}

/* ---- delegate requests of a KAS vault (lazy: the request module requires the root pipeline, which requires this) ---- */

function loadKasWalletRequest(config, requestId) {
  return require("./wallet-requests-v7-kas").loadKasWalletRequest(config, requestId);
}
async function unfinishedDelegateRequestsKas(config, vault) {
  const wrk = require("./wallet-requests-v7-kas");
  const all = await wrk.listKasWalletRequests(config, { vaultId: vault.vaultId });
  return all.filter((q) => q.kind === "agentSpend" && (DELEGATE_PENDING_STATES.has(q.state) || q.state === "SIGNED" && !!q.submissionAttempt));
}

module.exports = {
  CONTRACT_VERSION_V7_KAS,
  MANIFEST_SCHEMA_V7_KAS,
  OWNER_OP_ACTIONS_KAS,
  COMPLETION_HISTORY_LIMIT,
  isKasVaultRecord,
  isKasBuild,
  loadManifestV7Kas,
  persistManifestV7Kas,
  manifestDoc: manifestDocKas,
  liveValue: liveValueKas,
  sameVaultState: sameVaultStateKas,
  canonicalStateJson: canonicalStateJsonKas,
  vaultSuccessorIndexOf,
  prepareOwnerOpParams: prepareOwnerOpParamsKas,
  resolveOwnerOpAuthority: resolveOwnerOpAuthorityKas,
  buildOwnerOp: buildOwnerOpKas,
  buildOrgManifest: buildOrgManifestKas,
  verifyOrgManifest: verifyOrgManifestKas,
  finalizeOwnerOp: finalizeOwnerOpKas,
  ensureBuildDirKas,
  advanceRegistryAfterSpend: advanceRegistryAfterSpendKas,
  successorRegistry: successorRegistryKas,
  expectedVaultSuccessorDoc: expectedVaultSuccessorDocKas,
  vaultSuccessorDifferences: vaultSuccessorDifferencesKas,
  classifyVaultRecord: classifyVaultRecordKas,
  traceVaultCompletion: traceVaultCompletionKas,
  loadKasWalletRequest,
  unfinishedDelegateRequests: unfinishedDelegateRequestsKas
};
