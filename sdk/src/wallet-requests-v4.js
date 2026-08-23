"use strict";

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
 *   BUILT -> [AWAITING_APPROVALS ->] SIGNED -> FINALIZED -> PREFLIGHT_VERIFIED
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

const { persistJsonDurably, readJsonStrict } = require("./durable-json");
const { assertOperationalNetwork } = require("./config");
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
const { loadManifestV4, persistManifestV4, MANIFEST_SCHEMA_V4, registryEntryToJson } = require("./manifest-v4");
const { resolveAddressIdentity, addressForXOnlyPubkey } = require("./address-identity");
const { claimTransition, claimSubmission, persistReceipt } = require("./submission-claim");
const { sompiToKas } = require("./amounts");
const { appendAudit } = require("./audit");
const { VaultStatus } = require("./manifest");

const PREFLIGHT_PATH = path.join(__dirname, "..", "..", "tests/vm/target/debug/pv_vm_preflight");
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

function fail(message, code) {
  const error = new Error(`wallet-requests-v4: ${message}`);
  if (code) error.code = code;
  return error;
}

function requestPath(config, requestId) {
  return path.join(config.dataRoot, "requests", `${requestId}.json`);
}
function saveRequest(config, request) {
  persistJsonDurably({ filePath: requestPath(config, request.requestId), value: request });
  return request;
}
function loadRequest(config, requestId) {
  const p = requestPath(config, requestId);
  return fs.existsSync(p) ? readJsonStrict(p, "wallet request") : null;
}
function listVaultRequests(config, vaultId) {
  const dir = path.join(config.dataRoot, "requests");
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    try {
      const r = readJsonStrict(path.join(dir, f), "wallet request");
      if (r.vaultId === vaultId && r.schema === REQUEST_SCHEMA_V4) out.push(r);
    } catch {
      /* a corrupted request fails in its own flow */
    }
  }
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/*
 * Filtered request listing for the approval inbox / reload-restore path:
 * the browser re-derives ALL pending-approval UI from this durable server
 * state (never from in-memory browser state). Read-only.
 */
function listWalletRequestsV4(config, { vaultId, states } = {}) {
  const dir = path.join(config.dataRoot, "requests");
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    try {
      const r = readJsonStrict(path.join(dir, f), "wallet request");
      if (r.schema !== REQUEST_SCHEMA_V4) continue;
      if (vaultId !== undefined && r.vaultId !== vaultId) continue;
      if (states !== undefined && !states.includes(r.state)) continue;
      out.push(r);
    } catch {
      /* a corrupted request fails in its own flow */
    }
  }
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
        payAmountSompi: String(params.payAmountSompi),
        agentPk,
        agents: registryPolicies(manifest),
        recipient: requireXOnly(params.recipient, "recipient"),
        recipients: [...entry.recipients],
        periodsElapsed: params.periodsElapsed !== undefined ? String(params.periodsElapsed) : "0",
        ...(params.reserveConsumedSompi !== undefined ? { reserveConsumedSompi: String(params.reserveConsumedSompi) } : {})
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
      return { role: "owner", sdkAction: "ownerTopUp", sdkParams: { topUpAmountSompi: String(params.topUpAmountSompi) } };
    case "ownerTopUpReserve":
      return { role: "owner", sdkAction: "ownerTopUpReserve", sdkParams: { topUpReserveAmountSompi: String(params.topUpReserveAmountSompi) } };
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
 * BUILD stage (OFFLINE). Authorizes the signer, reconstructs the agent /
 * recipient trees from the durable registry (root-equality already enforced
 * by the manifest loader), builds + freezes the v0.4 transaction through the
 * SDK, and persists a durable BUILT request with the unsigned Safe JSON and
 * canonical review. No key, no broadcast.
 */
function buildWalletRequestV4({ config, vaultId, action, params = {}, signerAddress }) {
  // Gate R (2026-08-22): operational networks are testnet-10 and dual-flag-
  // unlocked mainnet; everything else fails closed.
  try {
    assertOperationalNetwork(config);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = loadManifestV4(config, vaultId);
  if (!manifest) throw fail(`no v0.4 manifest for vault ${vaultId}`, "BUILD_FAILED");
  const abi = resolveV4Abi(manifest.contractVersion); // accepts the v0.4 family; fails closed otherwise
  // TERMINAL vaults (RECOVERED / TERMINATED_UNKNOWN — live === null) are
  // permanently read-only: EVERY write action is refused here, before any
  // durable request/claim/manifest mutation can occur. The browser hides the
  // controls, but this server-side rejection is the independent backstop.
  if (!manifest.live) throw fail(`vault is ${manifest.status} (closed) — it is read-only history and accepts no further operations`, "VAULT_TERMINAL");

  const requiredRole = ROLE_BY_ACTION[action];
  if (!requiredRole) throw fail(`unknown action ${action} — failing closed`, "BUILD_FAILED");

  const plan = planV4(config, manifest, action, params);
  if (plan.role !== requiredRole) throw fail(`role map disagreement for ${action} — failing closed`, "BUILD_FAILED");

  // AUTHORIZE before construction.
  assertSignerAuthorizedV4(config, { role: requiredRole, signerAddress, template: manifest.template, manifest, action, agentPk: plan.agentPk });

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

  // Unsigned Safe JSON for the wallet (bridge the frozen build to the
  // KasWare signPskt contract).
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const wtx = frozenToWasmTransaction(config, build.frozen);
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const signInputs = build.frozen.inputs.map((_, index) => ({ index, sighashType: 1 }));

  const aboveThreshold = build.aboveThreshold === true;
  const requestId = crypto.randomUUID();
  const request = saveRequest(config, {
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
    review: reviewForBuild(config, manifest, build),
    transaction: { unsignedSafeJson, signInputs, covenantInputIndex: 0 },
    txId: build.txId,
    createdAt: new Date().toISOString()
  });
  return request;
}

/*
 * Create the approval package for an above-threshold spend request (lazy —
 * the first collectApproval call materializes it). Bound to the frozen tx.
 */
function ensureApprovalPackage(config, request) {
  if (request.approvalPackage) return request.approvalPackage;
  const pkg = createApprovalPackageForBuildV4(request.build);
  request.approvalPackage = pkg;
  saveRequest(config, request);
  return pkg;
}

/*
 * Collect one approver signature (a 65-byte SIG_HASH_ALL Schnorr signature
 * over the frozen covenant input) into its fixed slot. The approver signs
 * the SAME unsigned transaction the spender does (input 0). Returns the
 * updated request with approval progress.
 */
function collectApprovalV4({ config, requestId, approverAddress, signedSafeJson, signatureHex }) {
  const request = loadRequest(config, requestId);
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

  let pkg = ensureApprovalPackage(config, request);
  try {
    pkg = submitApprovalV4(pkg, { signatureHex: sig, approverXOnly });
  } catch (e) {
    throw fail(`approval rejected: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.approvalPackage = pkg;
  if (isCompleteV4(pkg)) {
    request.state = RequestState.BUILT; // enough approvals collected; ready to finalize
  }
  saveRequest(config, request);
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

function runPreflight(finalTx) {
  if (!fs.existsSync(PREFLIGHT_PATH)) throw fail(`pv_vm_preflight not built: ${PREFLIGHT_PATH}`, "PREFLIGHT_FAILED");
  const p = path.join(os.tmpdir(), `pv4-preflight-${process.pid}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(p, JSON.stringify(finalTx), { mode: 0o600 });
  try {
    const r = spawnSync(PREFLIGHT_PATH, [p, "0"], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    if (r.status !== 0) throw fail(`preflight harness error: ${r.stderr?.trim() ?? r.status}`, "PREFLIGHT_FAILED");
    let out;
    try {
      out = JSON.parse(r.stdout.trim());
    } catch {
      throw fail("preflight returned invalid JSON", "PREFLIGHT_FAILED");
    }
    return out;
  } finally {
    fs.unlinkSync(p);
  }
}

/*
 * FINALIZE + PREFLIGHT stage (OFFLINE, no broadcast). Re-authorizes the
 * signer against the CURRENT manifest, validates package immutability,
 * finalizes the covenant call through the SDK, PREFLIGHTS the exact bytes
 * against the production covenant VM, then creates the durable transition +
 * submission claims (the broadcast itself is Checkpoint H). Applies the new
 * agent registry to the manifest atomically with the preflight-verified
 * state advance is DEFERRED to H — in G the manifest live outpoint does not
 * advance (nothing was broadcast); the request records the preflight-proven
 * successor.
 */
function finalizeWalletRequestV4({ config, requestId, signedSafeJson }) {
  const request = loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.schema !== REQUEST_SCHEMA_V4) throw fail("not a v0.4 request", "BUILD_FAILED");
  if (request.state !== RequestState.BUILT) {
    if (request.state === RequestState.AWAITING_APPROVALS) throw fail("approvals are still required before finalize", "INSUFFICIENT_APPROVALS");
    throw fail(`request ${requestId} is ${request.state}, not BUILT`, request.state);
  }

  const manifest = loadManifestV4(config, request.vaultId);
  if (!manifest || !manifest.live || manifest.live.stateId !== request.predecessorStateId) {
    request.state = RequestState.STALE;
    saveRequest(config, request);
    throw fail("vault advanced since this request was built — rebuild required", "STALE");
  }

  // Re-authorize against the CURRENT manifest (defense in depth).
  try {
    assertSignerAuthorizedV4(config, { role: request.signerRole, signerAddress: request.signerAddress, template: manifest.template, manifest, action: request.action, agentPk: request.agentPk });
  } catch (e) {
    request.state = RequestState.AUTHORIZATION_FAILED;
    request.error = e.message;
    saveRequest(config, request);
    throw e;
  }

  // Parse the signed Safe JSON, assert immutability, extract signatures.
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    saveRequest(config, request);
    throw fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertPackageImmutable(unsigned, signed);

  const covenantSig = signed.inputs?.[0]?.signatureScript;
  if (!covenantSig) {
    request.state = RequestState.WALLET_REJECTED;
    saveRequest(config, request);
    throw fail("wallet did not sign the covenant input", "WALLET_REJECTED");
  }
  const hasFuel = request.build.hasFuelInput === true;
  const fuelSig = hasFuel ? signed.inputs?.[1]?.signatureScript : undefined;
  if (hasFuel && !fuelSig) {
    request.state = RequestState.WALLET_REJECTED;
    saveRequest(config, request);
    throw fail("wallet did not sign the fuel input", "WALLET_REJECTED");
  }

  // Approval package (above-threshold spends).
  let approvalPackage = null;
  if (request.aboveThreshold) {
    if (!request.approvalPackage || !isCompleteV4(request.approvalPackage)) {
      request.state = RequestState.INSUFFICIENT_APPROVALS;
      saveRequest(config, request);
      throw fail("insufficient approvals for this above-threshold spend", "INSUFFICIENT_APPROVALS");
    }
    approvalPackage = request.approvalPackage;
  }

  let finalized;
  try {
    finalized = finalizeV4Transaction({
      build: request.build,
      covenantSignatureHex: covenantSig,
      fuelSignatureScriptHex: fuelSig,
      approvalPackage
    });
  } catch (e) {
    request.state = e.code === "FEE_DRIFT" ? RequestState.PREFLIGHT_FAILED : RequestState.SIGNATURE_INVALID;
    request.error = e.message;
    saveRequest(config, request);
    throw fail(`finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }

  request.state = RequestState.FINALIZED;
  request.txId = finalized.txId;
  saveRequest(config, request);

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
    request.state = RequestState.PREFLIGHT_FAILED;
    saveRequest(config, request);
    throw fail(`network drift at preflight — ${preflightNetworkError}`, "PREFLIGHT_FAILED");
  }

  // PRODUCTION COVENANT VM PREFLIGHT (no broadcast).
  const verdict = runPreflight(finalized.finalTransaction);
  if (verdict.valid !== true) {
    request.state = RequestState.PREFLIGHT_FAILED;
    request.error = `VM preflight rejected: ${verdict.reason ?? "unknown"}`;
    saveRequest(config, request);
    throw fail(request.error, "PREFLIGHT_FAILED");
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
  try {
    claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: finalized.txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected });
  } catch (e) {
    request.state = RequestState.CLAIM_CONFLICT;
    request.error = e.message;
    saveRequest(config, request);
    throw e;
  }
  claimSubmission(config, { txId: finalized.txId, vaultId: request.vaultId, action: request.action });

  request.state = RequestState.PREFLIGHT_VERIFIED;
  request.finalTransaction = finalized.finalTransaction;
  saveRequest(config, request);

  appendAudit(config, {
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
function buildCreateWalletRequestV4({ config, templateInput, initialAgents = [], initialState, signerAddress, funding, label = "", contractVersion = CONTRACT_VERSION_V4 }) {
  try {
    assertOperationalNetwork(config); // Gate R: testnet-10 or unlocked mainnet
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const abi = resolveV4Abi(contractVersion); // fails closed on unknown versions
  const template = normalizeTemplateV4(templateInput);
  // Owner funds + owns genesis.
  assertSignerAuthorizedV4(config, { role: "owner", signerAddress, template, manifest: { agentRegistry: [] }, action: "createVault" });

  const registry = initialAgents.map((a) => normalizeNewAgentEntry(a));
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;

  const state = normalizeStateV4({
    protectedValue: String(initialState.protectedValue),
    feeReserve: String(initialState.feeReserve),
    paused: "0",
    agentRoot,
    approvers: initialState.approvers ?? [],
    approvalM: String(initialState.approvalM ?? "0"),
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

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  return saveRequest(config, {
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
      const { daaToHumanPeriod } = require("./ux-normalize-v4");
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
              budget: `${sompiToKas(BigInt(single.periodBudget))} KAS approximately every ${daaToHumanPeriod(single.periodLengthDaa)}`,
              approvalAboveKas: sompiToKas(BigInt(single.approvalThreshold))
            }
          : {}),
        approvalPolicy: approverCount > 0 ? `${state.approvalM.toString()} of ${approverCount} approvers` : "none (agent-only)",
        agents: registry.map((e) => ({ agentPk: e.agentPk, maxPerSpendKas: sompiToKas(BigInt(e.maxPerSpend)), recipients: e.recipients })),
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

function markWalletRejected(config, requestId) {
  const request = loadRequest(config, requestId);
  if (request && (request.state === RequestState.BUILT || request.state === RequestState.AWAITING_APPROVALS)) {
    request.state = RequestState.WALLET_REJECTED;
    saveRequest(config, request);
  }
  return request;
}

module.exports = {
  RequestState,
  ROLE_BY_ACTION,
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
  nextRegistry
};
