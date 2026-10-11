"use strict";
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV4 } = require("./contract-compiler-v4");
const { ownGet } = require("../../core/model/own-get");

/*
 * Signer-agnostic wallet request pipeline for PolicyVault v0.4
 * (Checkpoint G §G1/§G6/§G7). OFFLINE: this checkpoint ends at production
 * covenant VM PREFLIGHT and NEVER broadcasts. The live-node broadcast /
 * chain-proof / manifest-advance is Checkpoint H.
 *
 * It reuses the Checkpoint-F-cleared v0.4 SDK security nucleus unchanged
 * (agent-merkle-v4, vault-transitions-v4, approval-package-v4,
 * vault-builders-v4) and the version-agnostic hardened infrastructure
 * (submission-claim, address-identity, durable-json). It adds ONLY thin
 * orchestration: authorization, durable request state, high-level agent
 * lifecycle mapping to ownerSetAgentRoot, approval collection, and VM
 * preflight. No consensus arithmetic is recreated here.
 *
 * Durable request state machine (data/requests/<id>.json):
 *   BUILT -> [AWAITING_APPROVALS ->] PREFLIGHT_VERIFIED
 * (RC45 F4: finalize's first request write is PREFLIGHT_VERIFIED with the
 * signed bytes; SIGNED and FINALIZED are historical labels no v4 writer emits.)
 * Fail-closed states: WALLET_REJECTED, SIGNATURE_INVALID, PREFLIGHT_FAILED,
 *   STALE, CLAIM_CONFLICT, AUTHORIZATION_FAILED / NOT_OWNER / NOT_AGENT,
 *   INSUFFICIENT_APPROVALS, BUILD_FAILED.
 *
 * The server orchestrates the SDK; it never trusts the browser. Signer
 * authorization is enforced at BUILD and re-enforced at FINALIZE against the
 * current manifest. Security-relevant successor fields are DERIVED by the
 * SDK; the browser may not supply them.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { getStore, Categories } = require("./store");
const { assertVaultIdentityFree, withVaultIdentityLock } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): global vault-record uniqueness
const { assertOperationalNetwork, assertGenerationMainnetCreatable } = require("./config");
const { CONTRACT_VERSION_V4, resolveV4Abi, normalizeTemplateV4, normalizeStateV4, stateToJsonV4 } = require("./vault-state-v4");
const { buildAgentTreeV4, generateAgentProofV4, normalizeAgentPolicyV4 } = require("./agent-merkle-v4");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const {
  buildV4Transaction,
  buildCreateV4,
  finalizeV4Transaction,
  createApprovalPackageForBuildV4
} = require("./vault-builders-v4");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { submitApprovalV4, isCompleteV4, missingSlotsV4, collectedCountV4 } = require("./approval-package-v4");
const { loadManifestV4, persistManifestV4, MANIFEST_SCHEMA_V4, registryEntryToJson, anchoredLeafPks, anchorRegistryStarts, assertLeafStartsFresh, assertRegistryFoldsToRoot } = require("./manifest-v4");
const { resolveAddressIdentity, addressForXOnlyPubkey } = require("./address-identity");
const { claimTransition, claimSubmission, loadTransitionClaim, persistReceipt } = require("./submission-claim");
const { reserveForSpendBuild, consumeReservationForRequest, releaseReservationForRequest } = require("./budget-reservation");
const { sompiToKas } = require("./amounts");
const { appendAudit } = require("./audit");
const { VaultStatus } = require("./manifest");

const { PREFLIGHT_PATH } = require("./vm-preflight"); // shared runner (F-04)
const REQUEST_SCHEMA_V4 = "policyvault-wallet-request/v4";

const RequestState = Object.freeze({
  BUILT: "BUILT",
  AWAITING_APPROVALS: "AWAITING_APPROVALS",
  SIGNED: "SIGNED",
  FINALIZED: "FINALIZED",
  PREFLIGHT_VERIFIED: "PREFLIGHT_VERIFIED",
  // Checkpoint H live-submission states (broadcast pipeline).
  SUBMITTING: "SUBMITTING",
  SUBMITTED: "SUBMITTED",
  CHAIN_VERIFIED: "CHAIN_VERIFIED",
  SUBMISSION_REJECTED: "SUBMISSION_REJECTED",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  TERMINATED_UNKNOWN: "TERMINATED_UNKNOWN",
  // Fail-closed states.
  WALLET_REJECTED: "WALLET_REJECTED",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  PREFLIGHT_FAILED: "PREFLIGHT_FAILED",
  STALE: "STALE",
  CLAIM_CONFLICT: "CLAIM_CONFLICT",
  AUTHORIZATION_FAILED: "AUTHORIZATION_FAILED",
  INSUFFICIENT_APPROVALS: "INSUFFICIENT_APPROVALS",
  BUILD_FAILED: "BUILD_FAILED"
});

/* The one source consulted BEFORE construction. Unknown actions fail closed. */
const ROLE_BY_ACTION = Object.freeze({
  agentSpend: "agent",
  ownerSetAgentRoot: "owner",
  ownerSetApprovers: "owner",
  ownerTopUp: "owner",
  ownerTopUpReserve: "owner",
  ownerPause: "owner",
  ownerUnpause: "owner",
  ownerRecover: "owner",
  // high-level owner operations that MAP to ownerSetAgentRoot
  addAgent: "owner",
  removeAgent: "owner",
  rotateAgent: "owner",
  rePolicyAgent: "owner"
});

/* RC45 F2 (plan r2 §2.0 BREAK_GLASS_V4): the owner's authority-reducing exits —
 * exactly the actions marked breakGlass in server/src/governance.js
 * ACTION_MATRIX (ownerPause freeze, ownerRecover terminal recovery; never
 * governance-gated). A request is break-glass only when it is the owner's own
 * request for one of them; anything else fails closed to ordinary handling. */
const BREAK_GLASS_V4 = Object.freeze(["ownerPause", "ownerRecover"]);
function isBreakGlassV4(r) {
  return BREAK_GLASS_V4.includes(r?.action) && r.sdkAction === r.action && r.signerRole === "owner";
}

function fail(message, code) {
  const error = new Error(`wallet-requests-v4: ${message}`);
  if (code) error.code = code;
  return error;
}

// Consensus amount params arrive over the API as untrusted JSON. `String(x)`
// LAUNDERS a JSON number, array, or boolean into a valid-looking decimal
// string before the strict downstream parseSompi ever sees it — and a JSON
// number above 2^53 has already lost precision by the time it reaches here
// (String(9007199254740993) === "9007199254740992"). Per the permanent
// CLAUDE.md numeric rule, accept ONLY a bigint or a CANONICAL base-10 string
// (no leading zeros except "0" itself, no sign/dot/space/hex), fail closed
// on everything else, and return the canonical string form. This is a
// boundary hardening; it does not alter core parseSompi's grammar.
function canonicalAmountParam(value, field) {
  if (typeof value === "bigint") {
    if (value < 0n) throw fail(`${field} must not be negative`, "AMOUNT_INVALID");
    return value.toString();
  }
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw fail(`${field} must be a canonical base-10 sompi string or a bigint (numbers, arrays, leading zeros, and other forms are refused), got ${typeof value === "string" ? JSON.stringify(value) : typeof value}`, "AMOUNT_INVALID");
  }
  return value;
}

function requestPath(config, requestId) {
  return path.join(config.dataRoot, "requests", `${requestId}.json`); // json-layout helper (tests/tools)
}
async function saveRequest(config, request) {
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function loadRequest(config, requestId) {
  const request = await getStore(config).read(Categories.REQUEST, requestId);
  if (request && request.requestId !== requestId) throw fail("request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return request;
}
async function listVaultRequests(config, vaultId) {
  const all = await getStore(config).listValues(Categories.REQUEST);
  const out = all.filter((r) => r && r.vaultId === vaultId && r.schema === REQUEST_SCHEMA_V4);
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/*
 * Filtered request listing for the approval inbox / reload-restore path:
 * the browser re-derives ALL pending-approval UI from this durable server
 * state (never from in-memory browser state). Read-only.
 */
async function listWalletRequestsV4(config, { vaultId, states } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST);
  const out = all.filter((r) => {
    if (!r || r.schema !== REQUEST_SCHEMA_V4) return false;
    if (vaultId !== undefined && r.vaultId !== vaultId) return false;
    if (states !== undefined && !states.includes(r.state)) return false;
    return true;
  });
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/*
 * Authorization gate. The connected signer's canonical identity (resolved
 * from its wallet address through the shared boundary) must equal the exact
 * key the covenant will enforce for the requested role. For owner ops that
 * is template.owner. For agentSpend it is the SPENDING agent's key, which
 * must additionally be an active member of the current agent registry.
 * Runs BEFORE construction and again against the current manifest at
 * FINALIZE. UI role filtering is convenience only; this is mandatory.
 */
function assertSignerAuthorizedV4(config, { role, signerAddress, template, manifest, action, agentPk }) {
  let signerXOnly;
  try {
    signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  } catch (e) {
    throw fail(`signer address rejected: ${e.message}`, "AUTHORIZATION_FAILED");
  }
  if (role === "owner") {
    if (signerXOnly !== template.owner) {
      throw fail(`${action} is an owner operation; the connected wallet is not this vault's owner`, "NOT_OWNER");
    }
    return signerXOnly;
  }
  if (role === "agent") {
    if (typeof agentPk !== "string" || signerXOnly !== agentPk) {
      throw fail(`${action} is an agent operation; the connected wallet is not the acting agent`, "NOT_AGENT");
    }
    const member = manifest.agentRegistry.find((e) => e.policy.agentPk === signerXOnly);
    if (!member) {
      throw fail("the connected wallet is not an active agent of this vault (removed/rotated?)", "NOT_AGENT");
    }
    return signerXOnly;
  }
  throw fail(`unknown signer role ${role} — failing closed`, "AUTHORIZATION_FAILED");
}

/* The durable registry as SDK agent policies (agentRecipientRoot recomputed). */
function registryPolicies(manifest) {
  return manifest.agentRegistry.map((e) => ({ ...e.policy }));
}
function registryEntry(manifest, agentPk) {
  return manifest.agentRegistry.find((e) => e.policy.agentPk === agentPk) ?? null;
}

/* Apply a high-level agent-lifecycle op to the durable registry, returning
 * the NEW registry entries (JSON) + the new agent tree. Never mutates. */
function nextRegistry(manifest, action, params) {
  const current = manifest.agentRegistry.map((e) => registryEntryToJson(e));
  const byPk = (pk) => current.find((e) => e.agentPk === pk);
  switch (action) {
    case "addAgent": {
      const entry = normalizeNewAgentEntry(params.agent);
      if (byPk(entry.agentPk)) throw fail(`agent ${entry.agentPk} already exists`, "BUILD_FAILED");
      return [...current, entry];
    }
    case "removeAgent": {
      const pk = requireXOnly(params.agentPk, "agentPk");
      if (!byPk(pk)) throw fail(`agent ${pk} is not in this vault`, "BUILD_FAILED");
      return current.filter((e) => e.agentPk !== pk);
    }
    case "rotateAgent": {
      const oldPk = requireXOnly(params.agentPk, "agentPk");
      const existing = byPk(oldPk);
      if (!existing) throw fail(`agent ${oldPk} is not in this vault`, "BUILD_FAILED");
      const entry = normalizeNewAgentEntry(params.agent);
      if (entry.agentPk === oldPk) throw fail("rotation requires a NEW agent key", "BUILD_FAILED");
      if (byPk(entry.agentPk)) throw fail(`agent ${entry.agentPk} already exists`, "BUILD_FAILED");
      return [...current.filter((e) => e.agentPk !== oldPk), entry];
    }
    case "rePolicyAgent": {
      const pk = requireXOnly(params.agentPk, "agentPk");
      const existing = byPk(pk);
      if (!existing) throw fail(`agent ${pk} is not in this vault`, "BUILD_FAILED");
      const entry = normalizeNewAgentEntry({ ...params.agent, agentPk: pk });
      return current.map((e) => (e.agentPk === pk ? entry : e));
    }
    default:
      throw fail(`unknown agent-lifecycle action ${action}`, "BUILD_FAILED");
  }
}

function requireXOnly(v, field) {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) throw fail(`${field} must be 32-byte x-only hex`, "BUILD_FAILED");
  return v;
}

/* Normalize a caller-supplied new agent into a durable registry entry. */
function normalizeNewAgentEntry(agent) {
  if (!agent || typeof agent !== "object") throw fail("agent policy object is required", "BUILD_FAILED");
  if (!Array.isArray(agent.recipients) || agent.recipients.length === 0) {
    throw fail("agent.recipients must be a non-empty array of x-only keys", "BUILD_FAILED");
  }
  const recipients = agent.recipients.map((r) => requireXOnly(r, "recipient"));
  const recipientRoot = buildRecipientTree(recipients).root;
  const policy = normalizeAgentPolicyV4({ ...agent, agentRecipientRoot: recipientRoot });
  return registryEntryToJson({ policy, recipients });
}

/* Build the human-readable canonical review from a frozen build. */
function reviewForBuild(config, manifest, build, extra = {}) {
  const acc = build.accounting;
  const base = {
    action: build.action,
    network: config.networkId,
    vaultId: manifest.vaultId,
    predecessorOutpoint: build.predecessorOutpoint,
    predecessorStateId: build.predecessorStateId,
    policyNonceBefore: manifest.live.state.policyNonce.toString(),
    protectedBeforeKas: sompiToKas(BigInt(acc.predecessorProtected)),
    reserveBeforeKas: sompiToKas(BigInt(acc.predecessorFeeReserve)),
    feeKas: sompiToKas(BigInt(acc.fee)),
    feeSompi: acc.fee,
    computeBudget: build.computeBudget,
    ...extra
  };
  if (!build.successorState) {
    // terminal recover
    base.terminal = "VAULT CLOSED — protected value + fee reserve return to the owner wallet";
    base.recoveredKas = sompiToKas(BigInt(acc.terminalPayout));
    base.protectedAfterKas = "0";
    base.reserveAfterKas = "0";
  } else {
    base.protectedAfterKas = sompiToKas(BigInt(acc.successorProtected));
    base.reserveAfterKas = sompiToKas(BigInt(acc.successorFeeReserve));
    base.reserveConsumedKas = sompiToKas(BigInt(acc.reserveConsumed));
    base.externalFuelKas = sompiToKas(BigInt(acc.externalIn));
    base.policyNonceAfter = build.successorState.policyNonce;
    base.successorAgentRoot = build.successorState.agentRoot;
    base.successorStateId = build.successorStateId;
  }
  if (build.payment) {
    base.recipient = build.payment.recipient;
    base.recipientAddress = addressForXOnlyPubkey(config, build.payment.recipient);
    base.paymentKas = sompiToKas(BigInt(build.payment.value));
    base.fundingMode = build.hasFuelInput ? "FUEL-FUNDED" : "RESERVE-FUNDED";
  }
  if (build.aboveThreshold) {
    base.approvalsRequired = manifest.live.state.approvalM.toString();
  }
  return base;
}

/*
 * Resolve an action + params into the SDK build parameters + role + review
 * context. High-level agent-lifecycle ops become ownerSetAgentRoot with the
 * recomputed root; the NEW registry travels in the request and is applied to
 * the manifest atomically at preflight-verify.
 */
function planV4(config, manifest, action, params) {
  const template = manifest.template;
  const state = manifest.live.state;

  if (action === "agentSpend") {
    const agentPk = requireXOnly(params.agentPk, "agentPk");
    const entry = registryEntry(manifest, agentPk);
    if (!entry) throw fail(`agent ${agentPk} is not in this vault`, "BUILD_FAILED");
    return {
      role: "agent",
      agentPk,
      sdkAction: "agentSpend",
      sdkParams: {
        payAmountSompi: canonicalAmountParam(params.payAmountSompi, "payAmountSompi"),
        agentPk,
        agents: registryPolicies(manifest),
        recipient: requireXOnly(params.recipient, "recipient"),
        recipients: [...entry.recipients],
        periodsElapsed: params.periodsElapsed !== undefined ? canonicalAmountParam(params.periodsElapsed, "periodsElapsed") : "0",
        ...(params.reserveConsumedSompi !== undefined ? { reserveConsumedSompi: canonicalAmountParam(params.reserveConsumedSompi, "reserveConsumedSompi") } : {})
      }
    };
  }

  // High-level agent lifecycle -> ownerSetAgentRoot(newAgents)
  if (["addAgent", "removeAgent", "rotateAgent", "rePolicyAgent"].includes(action)) {
    const newReg = nextRegistry(manifest, action, params);
    const newPolicies = newReg.map((e) => ({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
    const newRoot = buildAgentTreeV4(newPolicies.map((p) => normalizeAgentPolicyV4(p))).root;
    return {
      role: "owner",
      sdkAction: "ownerSetAgentRoot",
      newRegistry: newReg,
      highLevel: action,
      sdkParams: { newAgentRoot: newRoot }
    };
  }

  switch (action) {
    case "ownerSetAgentRoot":
      // direct root replacement requires a full new registry so metadata stays consistent
      if (!Array.isArray(params.newAgents)) throw fail("ownerSetAgentRoot requires params.newAgents (the full new agent set)", "BUILD_FAILED");
      {
        const newReg = params.newAgents.map((a) => normalizeNewAgentEntry(a));
        const newPolicies = newReg.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
        return { role: "owner", sdkAction: "ownerSetAgentRoot", newRegistry: newReg, sdkParams: { newAgentRoot: buildAgentTreeV4(newPolicies).root } };
      }
    case "ownerSetApprovers":
      return { role: "owner", sdkAction: "ownerSetApprovers", sdkParams: { newApprovers: params.newApprovers ?? {} } };
    case "ownerTopUp":
      return { role: "owner", sdkAction: "ownerTopUp", sdkParams: { topUpAmountSompi: canonicalAmountParam(params.topUpAmountSompi, "topUpAmountSompi") } };
    case "ownerTopUpReserve":
      return { role: "owner", sdkAction: "ownerTopUpReserve", sdkParams: { topUpReserveAmountSompi: canonicalAmountParam(params.topUpReserveAmountSompi, "topUpReserveAmountSompi") } };
    case "ownerPause":
      return { role: "owner", sdkAction: "ownerPause", sdkParams: {} };
    case "ownerUnpause":
      return { role: "owner", sdkAction: "ownerUnpause", sdkParams: {} };
    case "ownerRecover":
      return { role: "owner", sdkAction: "ownerRecover", sdkParams: {} };
    default:
      throw fail(`unknown action ${action} — failing closed`, "BUILD_FAILED");
  }
  void template;
  void state;
}

function normalizeFuel(fuel) {
  if (!fuel || typeof fuel !== "object") return null;
  const spk = String(fuel.scriptPublicKeyHex ?? "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(spk) || spk.length % 2 !== 0) throw fail("fuel.scriptPublicKeyHex must be hex", "BUILD_FAILED");
  const op = fuel.outpoint ?? {};
  return {
    outpoint: { transactionId: requireXOnly(String(op.transactionId ?? ""), "fuel.outpoint.transactionId"), index: Number(op.index) },
    amount: String(fuel.amount),
    scriptPublicKeyHex: spk
  };
}

/*
 * RC45 delegate period-start rule, anchor at build (the rule itself is in
 * manifest-v4.js). Applied by the builder AFTER every gate and never inside
 * planV4: governance derives the approved after-state through planV4 from the
 * requested params, so a stored proposal of any origin keeps matching its
 * execution. A leaf of the new registry that is not byte-identical to its
 * predecessor leaf commits periodStartDaa = max(requested, D), D being the
 * configured synced node's canonical virtual DAA score (an unreadable node
 * refuses PERIOD_START_REQUIRED); every other field, periodSpent included, is
 * committed as requested and the agent root is re-derived from the committed
 * leaves. A later start never grants more than was requested or approved. A
 * registry without such a leaf (removeAgent, an unchanged re-policy) reads no
 * DAA. Returns the plan to build and the DAA it was anchored at (null when
 * nothing was anchored). The dry run (server/src/simulate.js) calls it too.
 */
async function anchorPlanStartsV4(config, manifest, plan) {
  if (plan.sdkAction !== "ownerSetAgentRoot" || !Array.isArray(plan.newRegistry)) return { plan, anchorDaa: null };
  const predecessorEntries = manifest.agentRegistry.map((e) => registryEntryToJson(e));
  if (anchoredLeafPks(predecessorEntries, plan.newRegistry).length === 0) return { plan, anchorDaa: null };
  const anchorDaa = await require("./chain").readAnchorDaa(config);
  const anchored = anchorRegistryStarts({ predecessorEntries, nextEntries: plan.newRegistry, anchorDaa });
  return { plan: { ...plan, newRegistry: anchored.entries, sdkParams: { ...plan.sdkParams, newAgentRoot: anchored.root } }, anchorDaa };
}

/*
 * RC45 delegate period-start rule, check before the point of no return of a
 * lifecycle request (finalize and submit). Writes nothing. An ownerSetAgentRoot
 * record's stored registry must first be a list folding to exactly the
 * successor agent root its frozen build commits (REGISTRY_ROOT_MISMATCH
 * otherwise; a missing registry is refused, never skipped; no node is read).
 * Then, only when that registry holds a leaf that is not byte-identical to its
 * predecessor leaf in `manifest`, readDaa() answers the node's canonical
 * virtual DAA score and such a leaf whose start lags it by more than its
 * window refuses PERIOD_START_STALE. Requests of other SDK actions set no
 * delegate leaf and read nothing.
 */
async function assertLifecycleStartsFreshV4({ request, manifest, readDaa, stage }) {
  if (request.sdkAction !== "ownerSetAgentRoot") return;
  assertRegistryFoldsToRoot({ entries: request.newRegistry, committedAgentRoot: request.build?.successorState?.agentRoot, stage });
  const predecessorEntries = manifest.agentRegistry.map((e) => registryEntryToJson(e));
  if (anchoredLeafPks(predecessorEntries, request.newRegistry).length === 0) return;
  assertLeafStartsFresh({ predecessorEntries, nextEntries: request.newRegistry, currentDaa: await readDaa(), stage });
}

/*
 * BUILD stage (OFFLINE). Authorizes the signer, reconstructs the agent /
 * recipient trees from the durable registry (root-equality already enforced
 * by the manifest loader), builds + freezes the v0.4 transaction through the
 * SDK, and persists a durable BUILT request with the unsigned Safe JSON and
 * canonical review. No key, no broadcast. The one node read is the delegate
 * period-start anchor of a new or changed delegate leaf (anchorPlanStartsV4).
 */
async function buildWalletRequestV4({ config, vaultId, action, params = {}, signerAddress }) {
  // Gate R (2026-08-22): operational networks are testnet-10 and dual-flag-
  // unlocked mainnet; everything else fails closed.
  try {
    assertOperationalNetwork(config);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = await loadManifestV4(config, vaultId);
  if (!manifest) throw fail(`no v0.4 manifest for vault ${vaultId}`, "BUILD_FAILED");
  const abi = resolveV4Abi(manifest.contractVersion); // accepts the v0.4 family; fails closed otherwise
  // TERMINAL vaults (RECOVERED / TERMINATED_UNKNOWN — live === null) are
  // permanently read-only: EVERY write action is refused here, before any
  // durable request/claim/manifest mutation can occur. The browser hides the
  // controls, but this server-side rejection is the independent backstop.
  // RC40: unresolved PROTECTED history on a closed vault takes priority over
  // the terminal refusal — protected admission authorizes no second recovery
  // (pinned by v4-foreign-recovery-rc40; RC45 F2: a closed vault keeps the
  // vault-wide scan for every action). A separate statement on purpose:
  // the terminal refusal below stays the exact line the permanent
  // production-guard-sabotage suite (S1) anchors on.
  if (!manifest.live) await require("./wallet-recovery-v4").assertNoBlockingTransitionV4(config, vaultId);
  if (!manifest.live) throw fail(`vault is ${manifest.status} (closed) — it is read-only history and accepts no further operations`, "VAULT_TERMINAL");

  const requiredRole = ownGet(ROLE_BY_ACTION, action); // own-property only (F-05)
  if (!requiredRole) throw fail(`unknown action ${action} — failing closed`, "BUILD_FAILED");

  let plan = planV4(config, manifest, action, params);
  if (plan.role !== requiredRole) throw fail(`role map disagreement for ${action} — failing closed`, "BUILD_FAILED");

  // AUTHORIZE before construction.
  assertSignerAuthorizedV4(config, { role: requiredRole, signerAddress, template: manifest.template, manifest, action, agentPk: plan.agentPk });

  // LEAD-5 (RC38; widened at lane checkpoint 6ff4539): an unresolved PROTECTED
  // transition refuses ANOTHER build. Checked AFTER the read-only network /
  // manifest / action / authorization checks (LEAD5-PRECEDENCE-01): an
  // unauthorized signer or an unknown action is refused on its own terms and
  // learns nothing about the vault's transition state; the guard still
  // precedes every durable write (nothing above this line persists).
  // RC45 F2 (plan r2 §2.1(2)): scoped to the live outpoint. The owner's
  // break-glass is never refused on a live vault; any other build is refused
  // by a PENDING record on the live outpoint (422) and, pre-sign, by any claim
  // on it (409 CLAIM_CONFLICT).
  const breakGlass = isBreakGlassV4({ action, sdkAction: plan.sdkAction, signerRole: plan.role });
  await require("./wallet-recovery-v4").assertNoBlockingTransitionV4(config, vaultId, { breakGlass, claimCheck: !breakGlass });

  // Delegate/agent actions need an ACTIVE vault; owner ops may target PAUSED.
  if (plan.role === "agent" && manifest.status !== VaultStatus.ACTIVE) {
    throw fail(`vault status is ${manifest.status} — agent operations need ACTIVE`, "BUILD_FAILED");
  }

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const fuel = normalizeFuel(params.fuel);
  const isSpend = plan.sdkAction === "agentSpend";
  // Owner ops + fuel-funded spends require a fuel UTXO; reserve-funded agent
  // spends omit it.
  if (!isSpend && !fuel) {
    throw fail(`${action} pins every covenant value, so its network fee must come from an ordinary fuel UTXO — provide params.fuel`, "BUILD_FAILED");
  }

  // RC45 delegate period-start rule: anchor every new or changed delegate leaf
  // here, after every gate and before anything durable is written.
  const anchoredPlan = await anchorPlanStartsV4(config, manifest, plan);
  plan = anchoredPlan.plan;
  const anchorReview = anchoredPlan.anchorDaa === null ? {} : { periodStartAnchorDaa: anchoredPlan.anchorDaa.toString() };

  const chain = {
    predecessorOutpoint: manifest.live.outpoint,
    predecessorValue: (manifest.live.state.protectedValue + manifest.live.state.feeReserve).toString(),
    covenantId: manifest.live.covenantId,
    ...(fuel ? { fuel } : {})
  };
  const changeXOnly = signerXOnly;

  let build;
  try {
    build = buildV4Transaction({
      config,
      contractVersion: abi.version,
      templateInput: { owner: manifest.template.owner, vaultId: manifest.vaultId },
      stateInput: stateToJsonV4(manifest.live.state),
      action: plan.sdkAction,
      params: plan.sdkParams,
      chain,
      changeXOnly
    });
  } catch (error) {
    throw fail(`SDK build failed: ${error.message}`, error.code || "BUILD_FAILED");
  }

  // Stale check: the compiled predecessor script must match the manifest.
  if (build.successorScriptSha256 !== null && manifest.live.scriptSha256 && build.predecessorStateId !== manifest.live.stateId) {
    throw fail("predecessor drift at build — failing closed", "STALE");
  }

  // Registry-to-root integrity: the registry this request stores must fold to
  // exactly the agent root its frozen transaction commits (REGISTRY_ROOT_MISMATCH
  // otherwise; nothing is written).
  if (plan.sdkAction === "ownerSetAgentRoot") {
    assertRegistryFoldsToRoot({ entries: plan.newRegistry, committedAgentRoot: build.successorState?.agentRoot, stage: "build" });
  }

  // Unsigned Safe JSON for the wallet (bridge the frozen build to the
  // KasWare signPskt contract). finalize() first: Kaspa txids exclude
  // signature scripts, so finalizing the UNSIGNED transaction stamps the
  // true consensus id into the payload — the browser verifier holds the
  // embedded id to strict equality with request.txId (F2-1,
  // docs/postlaunch/f2-fee-state-recomputation.md).
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const signInputs = build.frozen.inputs.map((_, index) => ({ index, sighashType: 1 }));

  const aboveThreshold = build.aboveThreshold === true;
  const requestId = crypto.randomUUID();

  /*
   * PRE-PERSIST PERIOD-BUDGET RESERVATION (full-scale surface 15,
   * sdk/src/budget-reservation.js). Agent spends take a durable
   * reservation on this window's headroom BEFORE the request becomes
   * durable, so concurrent builds can no longer optimistically over-
   * commit the period budget: the over-committing build refuses HERE
   * (BUDGET_RESERVED_EXCEEDED — pure, nothing persisted). Availability/
   * coordination only — the covenant remains the sole financial
   * authority; the finalize-time transition claim is unchanged. Owner
   * operations and the zero-persistence simulate path take none.
   */
  let reservation = null;
  if (isSpend) {
    reservation = await reserveForSpendBuild(config, { manifest, build, requestId });
  }

  let request;
  try {
    request = await saveRequest(config, {
    schema: REQUEST_SCHEMA_V4,
    requestId,
    state: aboveThreshold ? RequestState.AWAITING_APPROVALS : RequestState.BUILT,
    contractVersion: abi.version,
    networkId: config.networkId,
    vaultId,
    action,
    sdkAction: plan.sdkAction,
    highLevel: plan.highLevel ?? null,
    signerRole: plan.role,
    signerAddress,
    signerXOnly,
    agentPk: plan.agentPk ?? null,
    aboveThreshold,
    predecessorOutpoint: build.predecessorOutpoint,
    predecessorStateId: build.predecessorStateId,
    covenantId: build.covenantId,
    successorStateId: build.successorStateId,
    newRegistry: plan.newRegistry ?? null,
    build, // the frozen SDK build (JSON-safe); finalize re-loads it
    approvalPackage: null,
    review: reviewForBuild(config, manifest, build, anchorReview),
    transaction: { unsignedSafeJson, signInputs, covenantInputIndex: 0 },
    txId: build.txId,
    reservationKey: reservation ? reservation.key : null,
    createdAt: new Date().toISOString()
    });
  } catch (error) {
    // The request never became durable: free the reservation (a crash here
    // instead is reclaimed by the deterministic orphan sweep).
    if (reservation) {
      await releaseReservationForRequest(config, { schema: REQUEST_SCHEMA_V4, sdkAction: "agentSpend", vaultId, agentPk: plan.agentPk, requestId });
    }
    throw error;
  }
  return request;
}

/*
 * Create the approval package for an above-threshold spend request (lazy —
 * the first collectApproval call materializes it). Bound to the frozen tx.
 */
async function ensureApprovalPackage(config, request) {
  if (request.approvalPackage) return request.approvalPackage;
  const pkg = createApprovalPackageForBuildV4(request.build);
  request.approvalPackage = pkg;
  await saveRequest(config, request);
  return pkg;
}

/*
 * Collect one approver signature (a 65-byte SIG_HASH_ALL Schnorr signature
 * over the frozen covenant input) into its fixed slot. The approver signs
 * the SAME unsigned transaction the spender does (input 0). Returns the
 * updated request with approval progress.
 */
async function collectApprovalV4({ config, requestId, approverAddress, signedSafeJson, signatureHex }) {
  const request = await loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.schema !== REQUEST_SCHEMA_V4) throw fail("not a v0.4 request", "BUILD_FAILED");
  if (!request.aboveThreshold) throw fail("this spend does not require approvals", "BUILD_FAILED");
  if (request.state !== RequestState.AWAITING_APPROVALS) throw fail(`request is ${request.state}, not AWAITING_APPROVALS`, request.state);

  let approverXOnly;
  try {
    approverXOnly = resolveAddressIdentity(config, approverAddress).xOnlyPubkey;
  } catch (e) {
    throw fail(`approver address rejected: ${e.message}`, "SIGNATURE_INVALID");
  }

  // Extract the 65-byte approval signature from either a signed Safe JSON
  // (input 0's signature script) or a raw signatureHex.
  let sig = signatureHex;
  if (!sig && typeof signedSafeJson === "string") {
    let parsed;
    try {
      parsed = JSON.parse(signedSafeJson);
    } catch {
      throw fail("approver signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
    }
    sig = parsed.inputs?.[0]?.signatureScript;
  }
  if (typeof sig !== "string" || !/^[0-9a-f]+$/.test(sig)) throw fail("approval signature is required (hex or signed Safe JSON)", "SIGNATURE_INVALID");
  // strip a 0x41 sigscript push prefix if present -> raw 65-byte sig
  if (sig.length === 132 && sig.startsWith("41")) sig = sig.slice(2);

  let pkg = await ensureApprovalPackage(config, request);
  try {
    pkg = submitApprovalV4(pkg, { signatureHex: sig, approverXOnly });
  } catch (e) {
    throw fail(`approval rejected: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.approvalPackage = pkg;
  if (isCompleteV4(pkg)) {
    request.state = RequestState.BUILT; // enough approvals collected; ready to finalize
  }
  await saveRequest(config, request);
  return {
    request,
    approvals: { collected: collectedCountV4(pkg), required: Number(pkg.approvalM), complete: isCompleteV4(pkg), missingSlots: missingSlotsV4(pkg) }
  };
}

/* Assert the signed tx changed ONLY input signature scripts. */
function assertPackageImmutable(unsigned, signed) {
  const strip = (tx) => ({
    version: tx.version,
    lockTime: tx.lockTime,
    subnetworkId: tx.subnetworkId,
    gas: tx.gas,
    payload: tx.payload,
    inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })),
    outputs: tx.outputs
  });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) {
    throw fail("signed package mutated a consensus-visible field", "SIGNATURE_INVALID");
  }
}

/*
 * Move a request into a fail-closed state, persist it, and free its
 * period-budget reservation (surface 15) — from these states the request
 * can never reach broadcast, so its reserved headroom returns to the
 * window. No-op release for non-spend requests; the admission sweep is
 * the deterministic backstop if the process dies between the two writes.
 */
async function failRequestClosed(config, request, state, errorMessage) {
  request.state = state;
  if (errorMessage !== undefined) request.error = errorMessage;
  await saveRequest(config, request);
  await releaseReservationForRequest(config, request);
}

/*
 * RC45 F4 (plan r2 §2.4(1)-(2), CR-L11, CR2-M1): finalize decides on the record
 * it loaded, and each durable step first re-reads the stored record. Unless it
 * is still BUILT with the load-time canonical fingerprint (a reject, a sibling
 * finalize or a Verify settlement moved it meanwhile), finalize fails closed
 * with no further write: the not-BUILT refusal, or REQUEST_FINGERPRINT_MISMATCH.
 * Returns the stored record.
 */
async function rereadBuiltRequestV4(config, requestId, loadedFingerprint) {
  const current = await loadRequest(config, requestId);
  if (!current) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (current.state !== RequestState.BUILT) throw fail(`request ${requestId} is ${current.state}, not BUILT`, current.state);
  if (require("./wallet-recovery-v4").canonicalRecordFingerprint(current) !== loadedFingerprint) {
    throw fail(`request ${requestId} changed while it was being finalized; nothing was written`, "REQUEST_FINGERPRINT_MISMATCH");
  }
  return current;
}

/* Every finalize close (a verdict, or the ordinary CLAIM_CONFLICT) writes only
 * an unchanged BUILT record, never the load-time snapshot over a sibling's
 * PREFLIGHT_VERIFIED; otherwise it throws with no write. The one await between
 * this re-read and the write is the documented L-9 residual. */
async function closeBuiltRequestV4(config, requestId, loadedFingerprint, state, errorMessage) {
  await failRequestClosed(config, await rereadBuiltRequestV4(config, requestId, loadedFingerprint), state, errorMessage);
}

/*
 * RC45 F4 (plan r2 §2.0 claim-error rule, §2.4(4), CR-H1): take the transition
 * claim on the request's predecessor for `txId`. After a claimTransition error
 * the claim is read back: the same txid is this transaction's own (a crashed or
 * concurrent attempt of the same signed transaction, or a same-txid twin), a
 * foreign txid is a conflict returned to the caller; anything else (absent, a
 * store or a read error) is rethrown, and nothing more is written here.
 * Returns {own: true} or {own: false, claim, error} (error.code CLAIM_CONFLICT).
 */
async function claimOwnTransitionV4(config, request, txId, expected) {
  try {
    await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected });
    return { own: true };
  } catch (error) {
    const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
    if (!claim) throw error;
    if (claim.txId === txId) return { own: true };
    const conflict = error?.code === "CLAIM_CONFLICT" ? error
      : fail(`outpoint ${request.predecessorOutpoint.transactionId}:${request.predecessorOutpoint.index} is already claimed by ${claim.action} tx ${claim.txId}`, "CLAIM_CONFLICT");
    return { own: false, claim, error: conflict };
  }
}

/* F-04: the shared production-VM preflight runner (sdk/src/vm-preflight.js) —
 * every input (covenant AND fuel) must execute on the real engine before the
 * request may become PREFLIGHT_VERIFIED. */
const { preflightAllInputs } = require("./vm-preflight");

/*
 * FINALIZE + PREFLIGHT stage (OFFLINE, no broadcast). Re-authorizes the
 * signer against the CURRENT manifest, validates package immutability,
 * finalizes the covenant call through the SDK, PREFLIGHTS the exact bytes
 * against the production covenant VM, then creates the durable transition +
 * submission claims (the broadcast itself is Checkpoint H). Applies the new
 * agent registry to the manifest atomically with the preflight-verified
 * state advance is DEFERRED to H — in G the manifest live outpoint does not
 * advance (nothing was broadcast); the request records the preflight-proven
 * successor. The one node read is the period-start freshness check of a new
 * or changed delegate leaf (assertLifecycleStartsFreshV4).
 *
 * RC45 F4 (plan r2 §2.4, §4 finalize rows; RV-L5-01, CR-H1, CR2-M1): the whole
 * verdict is decided while the record is BUILT, with no write (a VM harness
 * throw leaves it BUILT); FINALIZED is never written. Every verdict close
 * writes only an unchanged BUILT record. The first request write (W1) is
 * PREFLIGHT_VERIFIED with the signed bytes. Ordinary order: W2 transition
 * claim -> W1 -> W3 submission claim -> W4 reservation consume -> audit, so a
 * PREFLIGHT_VERIFIED ordinary record always holds its own claim; the owner's
 * break-glass writes W1 first and then claims (absent -> claim, same txid ->
 * own, foreign -> contested: no claim, the delegate's claim untouched).
 * Nothing relabels the record after W1.
 */
async function finalizeWalletRequestV4({ config, requestId, signedSafeJson }) {
  const request = await loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.schema !== REQUEST_SCHEMA_V4) throw fail("not a v0.4 request", "BUILD_FAILED");
  if (request.state !== RequestState.BUILT) {
    if (request.state === RequestState.AWAITING_APPROVALS) throw fail("approvals are still required before finalize", "INSUFFICIENT_APPROVALS");
    throw fail(`request ${requestId} is ${request.state}, not BUILT`, request.state);
  }

  const recovery = require("./wallet-recovery-v4");
  // RC45 F4 (plan r2 §2.4(1), CR2-M1): every later re-read and close compares
  // the stored record with this load-time fingerprint.
  const loadedFingerprint = recovery.canonicalRecordFingerprint(request);
  const close = (state, errorMessage) => closeBuiltRequestV4(config, requestId, loadedFingerprint, state, errorMessage);
  const breakGlass = isBreakGlassV4(request);
  // RC45 R1-06 (ST-03, K4): a receipt recording this request's own
  // transaction as executed answers 422 with no write, before the blocking
  // check and the staleness verdict (an executed request is never STALE).
  const executed = await recovery.ownReceiptRefusalV4(config, request);
  if (executed) throw fail(executed.message, executed.refuse);
  await recovery.assertNoBlockingTransitionV4(config, request.vaultId, { excludeRequestId: requestId, breakGlass });
  const manifest = await loadManifestV4(config, request.vaultId);
  // RC45 F2 (plan r2 §2.3): a closed or self-advanced manifest answers 422
  // with no write; STALE only when the live state differs by stateId or
  // outpoint (H-35).
  const disposition = recovery.predecessorDispositionV4(manifest, request);
  if (disposition?.refuse) throw fail(disposition.message, disposition.refuse);
  if (disposition) {
    await close(RequestState.STALE);
    throw fail("vault advanced since this request was built — rebuild required", "STALE");
  }

  // Re-authorize against the CURRENT manifest (defense in depth).
  try {
    assertSignerAuthorizedV4(config, { role: request.signerRole, signerAddress: request.signerAddress, template: manifest.template, manifest, action: request.action, agentPk: request.agentPk });
  } catch (e) {
    await close(RequestState.AUTHORIZATION_FAILED, e.message);
    throw e;
  }

  // RC45 delegate period-start rule, before the signature is parsed or any
  // claim taken: registry-to-root integrity, then the freshness of every new
  // or changed delegate's start at the configured node's current position.
  // A refusal writes nothing: the request stays BUILT.
  await assertLifecycleStartsFreshV4({ request, manifest, readDaa: () => require("./chain").readAnchorDaa(config), stage: "finalize" });

  // Parse the signed Safe JSON, assert immutability, extract signatures.
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    await close(RequestState.SIGNATURE_INVALID);
    throw fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertPackageImmutable(unsigned, signed);

  const covenantSig = signed.inputs?.[0]?.signatureScript;
  if (!covenantSig) {
    await close(RequestState.WALLET_REJECTED);
    throw fail("wallet did not sign the covenant input", "WALLET_REJECTED");
  }
  const hasFuel = request.build.hasFuelInput === true;
  const fuelSig = hasFuel ? signed.inputs?.[1]?.signatureScript : undefined;
  if (hasFuel && !fuelSig) {
    await close(RequestState.WALLET_REJECTED);
    throw fail("wallet did not sign the fuel input", "WALLET_REJECTED");
  }

  // Approval package (above-threshold spends).
  let approvalPackage = null;
  if (request.aboveThreshold) {
    if (!request.approvalPackage || !isCompleteV4(request.approvalPackage)) {
      await close(RequestState.INSUFFICIENT_APPROVALS);
      throw fail("insufficient approvals for this above-threshold spend", "INSUFFICIENT_APPROVALS");
    }
    approvalPackage = request.approvalPackage;
  }

  let finalized;
  try {
    ensureBuildDir({ config, buildDir: request.build.encoderBuildDir, recompile: () => compileExactStateV4({ config, template: request.build.template, state: normalizeStateV4(request.build.stateJson), contractVersion: request.build.contractVersion }) }); // F-03: evicted cache entry -> deterministic recompile
    finalized = finalizeV4Transaction({
      build: request.build,
      covenantSignatureHex: covenantSig,
      fuelSignatureScriptHex: fuelSig,
      approvalPackage
    });
  } catch (e) {
    await close(e.code === "FEE_DRIFT" ? RequestState.PREFLIGHT_FAILED : RequestState.SIGNATURE_INVALID, e.message);
    throw fail(`finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }

  // Network hard gate (again) before preflight: the config must still be an
  // operational network and the request must be stamped with EXACTLY it.
  let preflightNetworkError = null;
  try {
    assertOperationalNetwork(config);
  } catch (e) {
    preflightNetworkError = e.message;
  }
  if (!preflightNetworkError && request.networkId !== config.networkId) {
    preflightNetworkError = `request network ${request.networkId} != configured ${config.networkId}`;
  }
  if (preflightNetworkError) {
    await close(RequestState.PREFLIGHT_FAILED);
    throw fail(`network drift at preflight — ${preflightNetworkError}`, "PREFLIGHT_FAILED");
  }

  // PRODUCTION COVENANT VM PREFLIGHT (no broadcast). A harness throw (the
  // engine could not run) propagates with nothing written: still BUILT.
  const verdict = preflightAllInputs(finalized.finalTransaction); // F-04: covenant input AND fuel input
  if (verdict.valid !== true) {
    const rejected = `VM preflight rejected: ${verdict.reason ?? "unknown"}`;
    await close(RequestState.PREFLIGHT_FAILED, rejected);
    throw fail(rejected, "PREFLIGHT_FAILED");
  }

  // Durable transition + submission claims (broadcast is Checkpoint H).
  const terminal = request.sdkAction === "ownerRecover";
  const expected = terminal
    ? { kind: "recover", txId: finalized.txId, index: 0, valueSompi: request.build.accounting.terminalPayout, ownerAddress: request.signerAddress, contractVersion: request.contractVersion }
    : {
        kind: "successor",
        txId: finalized.txId,
        index: request.build.frozen.outputs.findIndex((o) => o.covenant !== null),
        valueSompi: (BigInt(request.build.successorState.protectedValue) + BigInt(request.build.successorState.feeReserve)).toString(),
        covenantId: request.covenantId,
        scriptSha256: request.build.successorScriptSha256,
        stateId: request.successorStateId,
        state: request.build.successorState,
        newRegistry: request.newRegistry,
        action: request.sdkAction,
        contractVersion: request.contractVersion
      };

  // RC45 F4 (plan r2 §2.4(2)-(4), CR-L11): re-read before the first durable
  // write. An ordinary finalize claims first (option (i)); a foreign claim read
  // back means it lost the race and it is closed CLAIM_CONFLICT while BUILT,
  // before bytes (its build txId kept, never a finalTransaction). It re-reads
  // again before W1: a record that moved meanwhile gets no W1 and keeps only
  // its own claim (L-16).
  await rereadBuiltRequestV4(config, requestId, loadedFingerprint);
  if (!breakGlass) {
    const held = await claimOwnTransitionV4(config, request, finalized.txId, expected);
    if (!held.own) {
      await close(RequestState.CLAIM_CONFLICT, held.error.message);
      throw held.error;
    }
    await rereadBuiltRequestV4(config, requestId, loadedFingerprint);
  }

  // W1: the first request write carries the signed bytes.
  request.state = RequestState.PREFLIGHT_VERIFIED;
  request.txId = finalized.txId;
  request.finalTransaction = finalized.finalTransaction;
  await saveRequest(config, request);

  // Break-glass W2 after W1: absent -> claim, same txid -> own, foreign ->
  // contested (no claim; the delegate's claim is never seized or released).
  // A store or read error is rethrown with the record left PREFLIGHT_VERIFIED;
  // submit re-creates the missing own claim.
  if (breakGlass) await claimOwnTransitionV4(config, request, finalized.txId, expected);

  await claimSubmission(config, { txId: finalized.txId, vaultId: request.vaultId, action: request.action });

  // Surface 15: mark the reservation CONSUMED by this finalized txid. The
  // transition claim above REMAINS the exclusivity arbiter; the consumed
  // reservation keeps counting against its period window until the
  // manifest actually advances (the spend is in flight on this state).
  await consumeReservationForRequest(config, request, { txId: finalized.txId });

  await appendAudit(config, {
    vaultId: request.vaultId,
    action: request.action,
    actor: request.signerRole,
    contractVersion: request.contractVersion,
    txId: finalized.txId,
    result: "PREFLIGHT_VERIFIED",
    feeSompi: request.build.accounting.fee,
    oldStateId: request.predecessorStateId,
    newStateId: terminal ? null : request.successorStateId,
    via: "wallet-offline-preflight"
  });

  return request;
}

/*
 * GENESIS BUILD (OFFLINE). Produces the funding transaction descriptor +
 * durable registry so the created vault's manifest can be persisted once its
 * genesis is confirmed (Checkpoint H). Here it is preflight-agnostic (no
 * covenant input to execute); we validate the SDK build and persist a BUILT
 * genesis request with the vault covenantId and initial registry.
 */
async function buildCreateWalletRequestV4(args) {
  /* RC33-ID-01 (2026-09-11): the build (uniqueness check -> request write) is serialized per vault identity (the API holds
   * the per-signer lock OUTSIDE this); a malformed template falls through and is refused exactly as before */
  let vaultId = null;
  try { vaultId = normalizeTemplateV4(args.templateInput).vaultId; } catch { vaultId = null; }
  if (vaultId === null) return buildCreateWalletRequestV4Unlocked(args);
  return withVaultIdentityLock(vaultId, () => buildCreateWalletRequestV4Unlocked(args));
}
async function buildCreateWalletRequestV4Unlocked({ config, templateInput, initialAgents = [], initialState, signerAddress, funding, label = "", contractVersion = CONTRACT_VERSION_V4 }) {
  try {
    assertOperationalNetwork(config); // Gate R: testnet-10 or unlocked mainnet
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const abi = resolveV4Abi(contractVersion); // fails closed on unknown versions
  assertGenerationMainnetCreatable(config, abi.version); // F-02: on mainnet only the v0.4.1 generation may be NEWLY created (v0.4 = non-standard relay)
  const template = normalizeTemplateV4(templateInput);
  // Owner funds + owns genesis.
  assertSignerAuthorizedV4(config, { role: "owner", signerAddress, template, manifest: { agentRegistry: [] }, action: "createVault" });
  await assertVaultIdentityFree(config, template.vaultId); // RC33-ID-01: an identity held by ANY generation's record or ANY request is refused before anything is built or written

  let registry = initialAgents.map((a) => normalizeNewAgentEntry(a));
  // RC45 delegate period-start rule (anchorPlanStartsV4): a creation has no
  // predecessor leaf, so every delegate commits periodStartDaa = max(requested,
  // D), D being the configured synced node's canonical virtual DAA score read
  // after every check above; a creation without delegates reads no DAA.
  let anchorDaa = null;
  if (registry.length > 0) {
    anchorDaa = await require("./chain").readAnchorDaa(config);
    registry = anchorRegistryStarts({ predecessorEntries: [], nextEntries: registry, anchorDaa }).entries;
  }
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;

  const state = normalizeStateV4({
    protectedValue: canonicalAmountParam(initialState.protectedValue, "initialState.protectedValue"),
    feeReserve: canonicalAmountParam(initialState.feeReserve, "initialState.feeReserve"),
    paused: "0",
    agentRoot,
    approvers: initialState.approvers ?? [],
    approvalM: canonicalAmountParam(initialState.approvalM ?? "0", "initialState.approvalM"),
    policyNonce: "0"
  });

  let genesis;
  try {
    genesis = buildCreateV4({
      config,
      contractVersion: abi.version,
      templateInput: { owner: template.owner, vaultId: template.vaultId },
      initialStateInput: stateToJsonV4(state),
      funding,
      changeXOnly: resolveAddressIdentity(config, signerAddress).xOnlyPubkey
    });
  } catch (e) {
    throw fail(`genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  // Registry-to-root integrity: the stored initial registry must fold to the
  // agent root of the genesis build whose bytes are broadcast, and that root
  // must be the top-level initial state's (REGISTRY_ROOT_MISMATCH otherwise;
  // nothing is written).
  assertRegistryFoldsToRoot({ entries: registry, committedAgentRoot: genesis.initialState?.agentRoot, stage: "create" });
  if (String(genesis.initialState.agentRoot).toLowerCase() !== String(stateToJsonV4(state).agentRoot).toLowerCase()) {
    throw fail("create: the genesis build's agent root differs from the initial state's agent root — refusing", "REGISTRY_ROOT_MISMATCH");
  }

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  // F2-1: finalize the unsigned tx so the payload embeds the consensus id
  // (txids exclude signature scripts) — see the spend-path comment above.
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  return await saveRequest(config, {
    schema: REQUEST_SCHEMA_V4,
    requestId,
    kind: "genesis",
    state: RequestState.BUILT,
    contractVersion: abi.version,
    networkId: config.networkId,
    vaultId: template.vaultId,
    action: "createVault",
    signerRole: "owner",
    signerAddress,
    label,
    template: { owner: template.owner, vaultId: template.vaultId },
    initialState: stateToJsonV4(state),
    initialRegistry: registry,
    covenantId: genesis.covenantId,
    vaultOutputIndex: genesis.vaultOutputIndex,
    scriptSha256: genesis.scriptSha256,
    build: genesis,
    review: (() => {
      // Human-readable canonical review (§8): budget/period/approvals as plain
      // language; raw DAA values stay read-only under `technical` (the browser
      // renders them under Advanced). Presentation only — the signed bytes are
      // the frozen transaction above, unchanged by any of this.
      const { describeDaa } = require("../../core/model/duration-daa");
      const approverCount = state.approvers.filter((s) => s !== "00".repeat(32)).length;
      const single = registry.length === 1 ? registry[0] : null;
      return {
        action: "createVault",
        network: config.networkId,
        depositKas: sompiToKas(state.protectedValue),
        reserveKas: sompiToKas(state.feeReserve),
        agentCount: registry.length,
        ...(single
          ? {
              maxPerSpendKas: sompiToKas(BigInt(single.maxPerSpend)),
              // the same words the setup form shows for this period (rc15 review F-08)
              budget: `${sompiToKas(BigInt(single.periodBudget))} KAS per period (${describeDaa(single.periodLengthDaa, { largestUnit: "week" }).text})`,
              approvalAboveKas: sompiToKas(BigInt(single.approvalThreshold))
            }
          : {}),
        approvalPolicy: approverCount > 0 ? `${state.approvalM.toString()} of ${approverCount} approvers` : "none (agent-only)",
        agents: registry.map((e) => ({ agentPk: e.agentPk, maxPerSpendKas: sompiToKas(BigInt(e.maxPerSpend)), recipients: e.recipients })),
        ...(anchorDaa === null ? {} : { periodStartAnchorDaa: anchorDaa.toString() }),
        covenantId: genesis.covenantId,
        technical: {
          ...(single ? { periodLengthDaa: String(single.periodLengthDaa), periodStartDaa: String(single.periodStartDaa) } : {}),
          approvalM: state.approvalM.toString()
        }
      };
    })(),
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })), covenantInputIndex: null },
    txId: genesis.txId,
    createdAt: new Date().toISOString()
  });
}

async function markWalletRejected(config, requestId) {
  const request = await loadRequest(config, requestId);
  if (request && (request.state === RequestState.BUILT || request.state === RequestState.AWAITING_APPROVALS)) {
    // Rejection releases the period-budget reservation (surface 15): the
    // request can never reach broadcast, so its headroom returns to the window.
    await failRequestClosed(config, request, RequestState.WALLET_REJECTED);
  }
  return request;
}

module.exports = {
  RequestState,
  ROLE_BY_ACTION,
  BREAK_GLASS_V4,
  isBreakGlassV4,
  claimOwnTransitionV4,
  REQUEST_SCHEMA_V4,
  buildWalletRequestV4,
  buildCreateWalletRequestV4,
  collectApprovalV4,
  finalizeWalletRequestV4,
  markWalletRejected,
  loadRequest,
  saveRequest,
  requestPath,
  listVaultRequests,
  listWalletRequestsV4,
  assertSignerAuthorizedV4,
  planV4,
  anchorPlanStartsV4,
  assertLifecycleStartsFreshV4,
  nextRegistry,
  reviewForBuild
};
