"use strict";

/*
 * PolicyVault backend API (versioned, machine-readable errors).
 *
 * This backend is NOT the security boundary. It never holds owner or
 * delegate private keys and never claims a transaction succeeded before
 * chain proof. Funds-critical mutations (create/spend/recover) run through
 * the CLI tools that hold test keys; the API exposes read/status plus a
 * lifecycle-aware view so a frontend can present exact state.
 */

const { loadConfig } = require("../../sdk/src/config");
const { listVaultIds } = require("../../sdk/src/manifest");
const { loadAnyManifest } = require("../../sdk/src/manifest-v2");
const { compileExactState } = require("../../sdk/src/contract-compiler");
const { covenantAddress, connectVerified, getVirtualDaaScore } = require("../../sdk/src/chain");
const { sompiToKas } = require("../../sdk/src/amounts");
const { readAudit } = require("./audit");

const API_VERSION = "v1";

function apiError(status, code, message, extra) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  if (extra) {
    error.extra = extra;
  }
  return error;
}

/* Present a manifest as an API resource (KAS strings + derived fields). */
function presentVault(config, manifest, { virtualDaa } = {}) {
  const policy = manifest.policy;
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: policy.owner,
    delegate: policy.delegate,
    policy: {
      maxPerSpendKas: sompiToKas(policy.maxPerSpend),
      periodBudgetKas: sompiToKas(policy.periodBudget),
      periodLengthDaa: policy.periodLengthDaa.toString(),
      recipients: policy.recipients.slice(0, policy.declaredRecipientCount),
      initValueKas: sompiToKas(policy.initValue)
    },
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    updatedAt: manifest.updatedAt
  };
  if (manifest.live) {
    const state = manifest.live.state;
    const remaining = policy.periodBudget - state.periodSpent;
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      periodStartDaa: state.periodStartDaa.toString(),
      periodSpentKas: sompiToKas(state.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      paused: state.paused === 1n,
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      const elapsed = virtualDaa - state.periodStartDaa;
      base.live.periodElapsedDaa = (elapsed > 0n ? elapsed : 0n).toString();
      base.live.periodComplete = elapsed >= policy.periodLengthDaa;
    }
  }
  return base;
}

/*
 * Operational status for the dashboard: derived ONLY from durable
 * backend truth (manifest + transition claim + request records). The
 * derivation is fail-closed and offers no claim-override input.
 */
function operationalFor(config, manifest) {
  const { deriveOperationalStatus } = require("../../sdk/src/operational-status");
  const { loadTransitionClaim } = require("../../sdk/src/submission-claim");
  const { listVaultRequests } = require("../../sdk/src/wallet-requests-v2");
  const claim = manifest.live ? loadTransitionClaim(config, manifest.live.outpoint) : null;
  return deriveOperationalStatus({ manifest, claim, requests: listVaultRequests(config, manifest.vaultId) });
}

/* Display-only wallet-address form of a stored x-only pubkey. */
function addressOf(config, xOnly) {
  try {
    return require("../../sdk/src/address-identity").addressForXOnlyPubkey(config, xOnly);
  } catch {
    return null;
  }
}

/* Present a v0.2 manifest (policy fields live in mutable state). */
function presentVaultV2(config, manifest, { virtualDaa } = {}) {
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: manifest.template.owner,
    ownerAddress: addressOf(config, manifest.template.owner),
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    lastTransition: manifest.lastTransition,
    updatedAt: manifest.updatedAt
  };
  if (manifest.live) {
    const state = manifest.live.state;
    const remaining = state.periodBudget - state.periodSpent;
    base.delegate = state.delegate;
    base.delegateAddress = addressOf(config, state.delegate);
    base.policy = {
      maxPerSpendKas: sompiToKas(state.maxPerSpend),
      periodBudgetKas: sompiToKas(state.periodBudget),
      periodLengthDaa: state.periodLengthDaa.toString(),
      recipients: [...state.recipients],
      policyNonce: state.policyNonce.toString()
    };
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      periodStartDaa: state.periodStartDaa.toString(),
      periodSpentKas: sompiToKas(state.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      paused: state.paused === 1n,
      delegateActive: state.delegateActive === 1n,
      policyNonce: state.policyNonce.toString(),
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      const elapsed = virtualDaa - state.periodStartDaa;
      base.live.periodElapsedDaa = (elapsed > 0n ? elapsed : 0n).toString();
      base.live.periodComplete = elapsed >= state.periodLengthDaa;
    }
  }
  base.operational = operationalFor(config, manifest);
  return base;
}

/*
 * Present a v0.4 manifest: fixed template + mutable state (protected value,
 * fee reserve, paused, agentRoot, approver slots) + the durable agent
 * registry (the verified reconstruction of the agent tree). Agent policy
 * lives in the authenticated tree, so the registry is display-derived from
 * the metadata whose root the covenant enforces.
 */
function presentVaultV4(config, manifest, { virtualDaa } = {}) {
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: manifest.template.owner,
    ownerAddress: addressOf(config, manifest.template.owner),
    agentRegistryRoot: manifest.agentRegistryRoot,
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    lastTransition: manifest.lastTransition,
    updatedAt: manifest.updatedAt
  };
  // Agents are display-derived from the durable registry (root-verified).
  base.agents = manifest.agentRegistry.map((e) => {
    const p = e.policy;
    const remaining = p.periodBudget - p.periodSpent;
    return {
      agentPk: p.agentPk,
      agentAddress: addressOf(config, p.agentPk),
      maxPerSpendKas: sompiToKas(p.maxPerSpend),
      periodBudgetKas: sompiToKas(p.periodBudget),
      periodSpentKas: sompiToKas(p.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      periodLengthDaa: p.periodLengthDaa.toString(),
      periodStartDaa: p.periodStartDaa.toString(),
      approvalThresholdKas: sompiToKas(p.approvalThreshold),
      agentMaxFeePerTxKas: sompiToKas(p.agentMaxFeePerTx),
      agentRecipientRoot: p.agentRecipientRoot,
      recipients: [...e.recipients],
      recipientAddresses: e.recipients.map((r) => addressOf(config, r))
    };
  });
  if (manifest.live) {
    const state = manifest.live.state;
    base.approverSlots = [...state.approvers];
    base.approvalM = state.approvalM.toString();
    base.activeApproverCount = state.activeApproverCount;
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      feeReserveKas: sompiToKas(state.feeReserve),
      covenantValueKas: sompiToKas(state.protectedValue + state.feeReserve),
      paused: state.paused === 1n,
      agentRoot: state.agentRoot,
      approvalM: state.approvalM.toString(),
      policyNonce: state.policyNonce.toString(),
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      base.live.virtualDaaScore = virtualDaa.toString();
    }
  }
  base.operational = operationalForV4(config, manifest);
  return base;
}

/* Operational status for a v0.4 vault (reuses the v0.2 derivation, which is
 * pure over durable truth: manifest + transition claim + v0.4 requests). */
function operationalForV4(config, manifest) {
  const { deriveOperationalStatus } = require("../../sdk/src/operational-status");
  const { loadTransitionClaim } = require("../../sdk/src/submission-claim");
  const { listVaultRequests } = require("../../sdk/src/wallet-requests-v4");
  const claim = manifest.live ? loadTransitionClaim(config, manifest.live.outpoint) : null;
  return deriveOperationalStatus({ manifest, claim, requests: listVaultRequests(config, manifest.vaultId) });
}

/*
 * Off-chain organization annotation for a vault (display only — never
 * authority). Corrupt org metadata degrades to an error marker without
 * ever hiding the vault itself.
 */
function organizationRef(config, vaultId) {
  const { assignmentFor, loadOrganization } = require("../../sdk/src/organization");
  const assignment = assignmentFor(config, vaultId);
  if (!assignment) return null;
  let name = null;
  let metadataError = null;
  try {
    name = loadOrganization(config, assignment.orgId)?.name ?? null;
  } catch (e) {
    metadataError = "CORRUPT_METADATA";
  }
  return { orgId: assignment.orgId, name, group: assignment.group, ...(metadataError ? { metadataError } : {}) };
}

/* Version-aware presenter: dispatch on the stored manifest schema. */
function presentAny(config, vaultId, opts) {
  const loaded = loadAnyManifest(config, vaultId);
  if (!loaded) {
    return null;
  }
  const presented =
    loaded.version === "v4"
      ? presentVaultV4(config, loaded.manifest, opts)
      : loaded.version === "v2"
        ? presentVaultV2(config, loaded.manifest, opts)
        : presentVault(config, loaded.manifest, opts);
  presented.organization = organizationRef(config, vaultId);
  return presented;
}

/*
 * The API handler dispatch. Returns { status, body }. Pure over the
 * filesystem/chain; the HTTP layer in server.js adapts it.
 */
/* Present a wallet request without server-side filesystem/internal details.
 * v0.4 requests carry a heavy internal `build` (with encoder build dirs), the
 * approval package, the pending registry, and the finalized transaction —
 * none of which the browser needs (it signs `transaction.unsignedSafeJson`).
 * The approval PROGRESS is surfaced separately, without slot signatures. */
function presentRequest(request) {
  if (!request) {
    return null;
  }
  const { encoderBuildDir, build, approvalPackage, newRegistry, finalTransaction, ...rest } = request;
  if (approvalPackage && typeof approvalPackage === "object") {
    const approvedSlots = Array.isArray(approvalPackage.approvals) ? approvalPackage.approvals.map((a) => typeof a === "string") : [];
    const collected = approvedSlots.filter(Boolean).length;
    const required = Number(approvalPackage.approvalM);
    rest.approvalProgress = { collected, required, approverSlots: approvalPackage.approverSlots, approvedSlots, complete: collected >= required };
  } else if (rest.aboveThreshold) {
    // The approval package is materialized lazily on the first approval;
    // a fresh above-threshold request still reports authoritative progress
    // so the browser can render "0 of M" from SERVER state alone.
    rest.approvalProgress = { collected: 0, required: Number(rest.review?.approvalsRequired ?? 0), approverSlots: null, approvedSlots: null, complete: false };
  }
  void build;
  void newRegistry;
  void finalTransaction;
  return rest;
}

async function handle(config, method, segments, query, body) {
  // GET /health
  if (method === "GET" && segments.length === 1 && segments[0] === "health") {
    return { status: 200, body: { ok: true, api: API_VERSION, networkId: config.networkId } };
  }

  // GET /support — the voluntary-support (donation) surface. The address is
  // an explicitly configured PUBLIC mainnet address (never derived from any
  // wallet/vault/test key) and is served ONLY after canonical validation;
  // a misconfigured/testnet/malformed address fails closed to `support: null`
  // with the exact validation error surfaced for the operator.
  if (method === "GET" && segments.length === 1 && segments[0] === "support") {
    const { validateDonationAddress } = require("../../sdk/src/donation-address");
    try {
      const donation = validateDonationAddress(config, config.donationAddress);
      return { status: 200, body: { support: { donation } } };
    } catch (e) {
      return { status: 200, body: { support: null, reason: e.code || "DONATION_INVALID", message: e.message } };
    }
  }

  // POST /identity/resolve-address  { address }
  // The single address->pubkey boundary for browser clients: normal users
  // enter wallet addresses; this resolves them to the canonical x-only
  // form via the shared SDK utility (WASM-backed). Fail-closed 422s carry
  // user-facing messages; strict pubkey validation downstream is unchanged.
  if (method === "POST" && segments.length === 2 && segments[0] === "identity" && segments[1] === "resolve-address") {
    const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
    try {
      const identity = resolveAddressIdentity(config, body?.address);
      return { status: 200, body: { identity, expectedNetwork: config.networkId } };
    } catch (error) {
      throw apiError(error.status || 422, error.code || "ADDRESS_INVALID", error.message);
    }
  }

  // ---- Wallet request pipeline (browser signing flow) ----
  const walletRequests = require("../../sdk/src/wallet-requests-v2");

  // POST /wallet/create  { templateInput, initialStateInput, signerAddress, delegateFuelSompi?, label? }
  if (method === "POST" && segments.length === 2 && segments[0] === "wallet" && segments[1] === "create") {
    // LEGACY CREATION IS PRODUCTION-DISABLED (Checkpoint I §4): new vaults use
    // the current protocol (v0.4.1). Existing legacy vaults remain fully
    // supported (display / verify / manage / recover / audit) — only NEW
    // legacy creation is gated, behind an explicit developer flag.
    if (process.env.POLICYVAULT_LEGACY_CREATE !== "1") {
      throw apiError(403, "LEGACY_CREATE_DISABLED", "Legacy v0.2 vault creation is disabled in production. New vaults use the current protocol; existing legacy vaults remain fully supported. Set POLICYVAULT_LEGACY_CREATE=1 for development use only.");
    }
    const { templateInput, initialStateInput, signerAddress, delegateFuelSompi, label } = body ?? {};
    if (typeof signerAddress !== "string" || !signerAddress.startsWith("kaspatest:")) {
      throw apiError(400, "BAD_SIGNER", "signerAddress must be a testnet address");
    }
    // Fail closed with a precise diagnosis when a client sends a raw
    // 33-byte compressed provider pubkey (KasWare getPublicKey form) as
    // the owner: normalization belongs at the wallet-adapter boundary,
    // never here — template validation stays strict x-only.
    if (typeof templateInput?.owner === "string" && /^0[23][0-9a-fA-F]{64}$/.test(templateInput.owner.trim())) {
      throw apiError(422, "COMPRESSED_OWNER_PUBKEY", "template.owner is a 33-byte compressed provider public key; the wallet adapter must normalize it to 32-byte x-only hex (normalizePublicKeyToXOnly)");
    }
    try {
      const request = await walletRequests.buildCreateWalletRequestV2({ config, templateInput, initialStateInput, signerAddress, delegateFuelSompi: delegateFuelSompi ?? "0", label: label ?? "" });
      return { status: 201, body: { request: presentRequest(request) } };
    } catch (error) {
      const authz = ["NOT_OWNER", "NOT_DELEGATE", "AUTHORIZATION_FAILED"].includes(error.code);
      throw apiError(authz ? 403 : 422, error.code || "BUILD_FAILED", error.message);
    }
  }

  // POST /wallet/requests  { vaultId, action, params, signerAddress }
  if (method === "POST" && segments.length === 2 && segments[0] === "wallet" && segments[1] === "requests") {
    const { vaultId, action, params, signerAddress } = body ?? {};
    if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) {
      throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
    }
    if (typeof action !== "string" || !action) {
      throw apiError(400, "BAD_ACTION", "action is required");
    }
    if (typeof signerAddress !== "string" || !signerAddress.startsWith("kaspatest:")) {
      throw apiError(400, "BAD_SIGNER", "signerAddress must be a testnet address");
    }
    try {
      const request = await walletRequests.buildWalletRequestV2({ config, vaultId, action, params: params ?? {}, signerAddress });
      return { status: 201, body: { request: presentRequest(request) } };
    } catch (error) {
      const authz = ["NOT_OWNER", "NOT_DELEGATE", "AUTHORIZATION_FAILED"].includes(error.code);
      throw apiError(authz ? 403 : 422, error.code || "BUILD_FAILED", error.message);
    }
  }

  // POST /wallet/requests/:id/signature  { signedSafeJson }
  if (method === "POST" && segments.length === 4 && segments[0] === "wallet" && segments[1] === "requests" && segments[3] === "signature") {
    const requestId = segments[2];
    const { signedSafeJson } = body ?? {};
    if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) {
      throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
    }
    try {
      const request = await walletRequests.attachWalletSignatureV2({ config, requestId, signedSafeJson });
      return { status: 200, body: { request: presentRequest(request) } };
    } catch (error) {
      const request = walletRequests.loadRequest(config, requestId);
      throw apiError(422, error.code || "FINALIZE_FAILED", error.message, { request: presentRequest(request) });
    }
  }

  // POST /wallet/requests/:id/reject  (user declined in the wallet)
  if (method === "POST" && segments.length === 4 && segments[0] === "wallet" && segments[1] === "requests" && segments[3] === "reject") {
    const request = walletRequests.markWalletRejected(config, segments[2]);
    if (!request) {
      throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[2]}`);
    }
    return { status: 200, body: { request: presentRequest(request) } };
  }

  // GET /wallet/requests/:id
  if (method === "GET" && segments.length === 3 && segments[0] === "wallet" && segments[1] === "requests") {
    const request = walletRequests.loadRequest(config, segments[2]);
    if (!request) {
      throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[2]}`);
    }
    return { status: 200, body: { request: presentRequest(request) } };
  }

  // ---- v0.4 wallet request pipeline (OFFLINE: BUILD -> approvals -> sign
  //      -> FINALIZE -> production covenant VM preflight; NO broadcast) ----
  if (segments[0] === "wallet" && segments[1] === "v4") {
    const wr4 = require("../../sdk/src/wallet-requests-v4");
    const v4Error = (error) => {
      const authz = ["NOT_OWNER", "NOT_AGENT", "AUTHORIZATION_FAILED"].includes(error.code);
      const stateCodes = ["STALE", "CLAIM_CONFLICT", "PREFLIGHT_FAILED", "SIGNATURE_INVALID", "INSUFFICIENT_APPROVALS", "WALLET_REJECTED"];
      const status = authz ? 403 : stateCodes.includes(error.code) ? 409 : 422;
      return apiError(status, error.code || "BUILD_FAILED", error.message);
    };
    // Gate R: the v0.4 family serves the CONFIGURED network — signer/approver
    // addresses must carry that network's canonical prefix (kaspatest: on
    // testnet-10, kaspa: on mainnet). Full validation happens in the SDK.
    const requiredPrefix = `${require("../../sdk/src/address-identity").requiredAddressPrefix(config.networkId)}:`;
    const badSignerMsg = (field) => `${field} must be a ${config.networkId} address (${requiredPrefix}...)`;
    const badSigner = (a) => typeof a !== "string" || !a.startsWith(requiredPrefix);

    // POST /wallet/v4/create   { ..., contractVersion? }
    // Two schemas:
    //  - canonical (tools/tests): { templateInput, initialAgents, initialState, funding }
    //  - friendly (browser, §2–§14): { vaultId, label, depositKas, feeReserveKas,
    //    agent:{ agentAddress, maxPerSpendKas, budgetKas, budgetPeriod, approvalThresholdKas,
    //    maxFeePerTxKas?, recipientAddresses[] }, approvers?:{ addresses[], approvalM }, funding? }.
    // The friendly schema is normalized to the IDENTICAL canonical shape here,
    // server-side (§26): owner x-only from the signer, node-derived periodStartDaa,
    // periodSpent=0, KAS→sompi, addresses→x-only. The browser never supplies
    // consensus-visible values.
    if (method === "POST" && segments.length === 3 && segments[2] === "create") {
      const { templateInput, initialAgents, initialState, signerAddress, funding, label, contractVersion, vaultId, depositKas, feeReserveKas, agent, approvers } = body ?? {};
      if (badSigner(signerAddress)) throw apiError(400, "BAD_SIGNER", badSignerMsg("signerAddress"));
      try {
        if (agent) {
          // ---- friendly schema -> canonical, server-authoritative ----
          const { kasToSompi } = require("../../sdk/src/amounts");
          const { normalizeAgentPolicyInputV4, normalizeApproversInputV4 } = require("../../sdk/src/ux-normalize-v4");
          const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
          const { getAddressUtxos } = require("../../sdk/src/chain");
          if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
          const ownerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
          const depositSompi = kasToSompi(depositKas, "deposit");
          const reserveSompi = kasToSompi(feeReserveKas, "feeReserve");
          if (depositSompi <= 0n) throw apiError(422, "BAD_DEPOSIT", "deposit must be > 0 KAS");
          const { rpc } = await connectVerified(config);
          let policy, appr, chosenFunding;
          try {
            const daa = await getVirtualDaaScore(rpc);
            policy = normalizeAgentPolicyInputV4(config, agent, daa); // periodStartDaa = daa, periodSpent = 0
            appr = normalizeApproversInputV4(config, approvers ?? {});
            if (Array.isArray(funding) && funding.length) {
              chosenFunding = funding;
            } else {
              const need = depositSompi + reserveSompi;
              const utxos = (await getAddressUtxos(rpc, signerAddress)).filter((u) => u.covenantId === null && u.amount > need).sort((a, b) => (a.amount < b.amount ? 1 : -1));
              if (!utxos.length) throw apiError(422, "INSUFFICIENT_FUNDS", `no owner UTXO covering ${depositKas} + ${feeReserveKas} KAS + fee — fund the owner address first`);
              chosenFunding = [{ outpoint: utxos[0].outpoint, amount: utxos[0].amount.toString(), scriptPublicKeyHex: utxos[0].scriptPublicKeyHex }];
            }
          } finally {
            await rpc.disconnect();
          }
          const request = await Promise.resolve(wr4.buildCreateWalletRequestV4({
            config,
            contractVersion: contractVersion ?? "policyvault-0.4.1",
            templateInput: { owner: ownerXOnly, vaultId },
            initialAgents: [{ ...policy, recipients: policy.recipients }],
            initialState: { protectedValue: depositSompi.toString(), feeReserve: reserveSompi.toString(), approvers: appr.approvers, approvalM: appr.approvalM },
            signerAddress,
            funding: chosenFunding,
            label: label ?? ""
          }));
          return { status: 201, body: { request: presentRequest(request) } };
        }
        // ---- canonical schema (backward compatible) ----
        const request = await Promise.resolve(wr4.buildCreateWalletRequestV4({ config, templateInput, initialAgents: initialAgents ?? [], initialState, signerAddress, funding, label: label ?? "", ...(contractVersion ? { contractVersion } : {}) }));
        return { status: 201, body: { request: presentRequest(request) } };
      } catch (error) {
        if (error.status) throw error;
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/requests  { vaultId, action, params, signerAddress }
    if (method === "POST" && segments.length === 3 && segments[2] === "requests") {
      const { vaultId, action, params, signerAddress } = body ?? {};
      if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
      if (typeof action !== "string" || !action) throw apiError(400, "BAD_ACTION", "action is required");
      if (badSigner(signerAddress)) throw apiError(400, "BAD_SIGNER", badSignerMsg("signerAddress"));
      try {
        const request = wr4.buildWalletRequestV4({ config, vaultId, action, params: params ?? {}, signerAddress });
        return { status: 201, body: { request: presentRequest(request) } };
      } catch (error) {
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/requests/:id/approvals  { approverAddress, signedSafeJson|signatureHex }
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "approvals") {
      const { approverAddress, signedSafeJson, signatureHex } = body ?? {};
      if (badSigner(approverAddress)) throw apiError(400, "BAD_APPROVER", badSignerMsg("approverAddress"));
      try {
        const result = wr4.collectApprovalV4({ config, requestId: segments[3], approverAddress, signedSafeJson, signatureHex });
        return { status: 200, body: { request: presentRequest(result.request), approvals: result.approvals } };
      } catch (error) {
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/requests/:id/signature  { signedSafeJson }  -> FINALIZE + PREFLIGHT
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "signature") {
      const { signedSafeJson } = body ?? {};
      if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
      try {
        const request = wr4.finalizeWalletRequestV4({ config, requestId: segments[3], signedSafeJson });
        return { status: 200, body: { request: presentRequest(request) } };
      } catch (error) {
        const request = wr4.loadRequest(config, segments[3]);
        const e = v4Error(error);
        e.extra = { request: presentRequest(request) };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/submit  -> LIVE broadcast of a FINALIZED
    // transition (build -> sign -> FINALIZE happened already). The SDK submit
    // path enforces config==request==manifest==node network agreement on an
    // operational network (testnet-10, or mainnet under the Gate R dual-flag
    // unlock); it verifies node-txid == frozen-txid, chain-proves the exact
    // successor, and advances the manifest+registry atomically.
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "submit") {
      const submit4 = require("../../sdk/src/wallet-submit-v4");
      try {
        const result = await submit4.submitWalletRequestV4({ config, requestId: segments[3] });
        return { status: 200, body: { request: presentRequest(result.request), txId: result.txId, successorIndex: result.expected?.index ?? null } };
      } catch (error) {
        const request = wr4.loadRequest(config, segments[3]);
        const e = v4Error(error);
        e.extra = { request: request ? presentRequest(request) : null };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/genesis-submit  { signedSafeJson }  -> the
    // owner's KasWare-signed genesis funding is broadcast; the authoritative
    // manifest is created only AFTER the exact covenant output is chain-proven.
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "genesis-submit") {
      const { signedSafeJson } = body ?? {};
      if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
      const submit4 = require("../../sdk/src/wallet-submit-v4");
      try {
        const result = await submit4.submitCreateWalletRequestV4({ config, requestId: segments[3], signedSafeJson });
        return { status: 200, body: { request: presentRequest(result.request), txId: result.txId } };
      } catch (error) {
        const request = wr4.loadRequest(config, segments[3]);
        const e = v4Error(error);
        e.extra = { request: request ? presentRequest(request) : null };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/reject
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "reject") {
      const request = wr4.markWalletRejected(config, segments[3]);
      if (!request) throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
      return { status: 200, body: { request: presentRequest(request) } };
    }

    // GET /wallet/v4/requests?vaultId=&open=1 — durable request listing for
    // the approval inbox and reload-restore: the browser derives ALL pending
    // approval UI from this server state, never from its own memory.
    // open=1 -> the pre-finalize actionable states (AWAITING_APPROVALS, BUILT).
    if (method === "GET" && segments.length === 3 && segments[2] === "requests") {
      const states = query?.open ? [wr4.RequestState.AWAITING_APPROVALS, wr4.RequestState.BUILT] : undefined;
      const requests = wr4
        .listWalletRequestsV4(config, { ...(query?.vaultId ? { vaultId: query.vaultId } : {}), ...(states ? { states } : {}) })
        .slice(0, 100)
        .map(presentRequest);
      return { status: 200, body: { requests } };
    }

    // GET /wallet/v4/requests/:id
    if (method === "GET" && segments.length === 4 && segments[2] === "requests") {
      const request = wr4.loadRequest(config, segments[3]);
      if (!request) throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
      return { status: 200, body: { request: presentRequest(request) } };
    }

    throw apiError(404, "NOT_FOUND", "unknown wallet/v4 route");
  }

  // ---- TEST-ONLY dev signer endpoints (mock adapter / architecture test) ----
  // Gated by POLICYVAULT_DEV_SIGNER=1 and testnet only. Never on mainnet.
  const devSignerEnabled = process.env.POLICYVAULT_DEV_SIGNER === "1" && config.networkId !== "mainnet";

  if (segments[0] === "wallet" && (segments[1] === "dev-accounts" || segments[1] === "dev-sign")) {
    if (!devSignerEnabled) {
      throw apiError(404, "DEV_SIGNER_DISABLED", "dev signer is disabled (set POLICYVAULT_DEV_SIGNER=1 on testnet)");
    }
    const { loadOrCreateTestKeys } = require("../../sdk/src/keys");
    const { makeDevSigner } = require("../../sdk/src/signer-dev");
    const keys = loadOrCreateTestKeys(config);
    const roster = ["owner", "delegate", "recipient1", "recipient2", "recipient3"]
      .filter((role) => keys[role])
      .map((role) => ({ role, address: keys[role].address, xonly: keys[role].xonly }));

    // GET /wallet/dev-accounts
    if (method === "GET" && segments.length === 2) {
      return { status: 200, body: { warning: "TEST-ONLY dev signer (testnet)", accounts: roster } };
    }
    // POST /wallet/dev-sign  { address, unsignedSafeJson, signInputs }
    if (method === "POST" && segments.length === 2 && segments[1] === "dev-sign") {
      const { address, unsignedSafeJson, signInputs } = body ?? {};
      const match = roster.find((a) => a.address === address);
      if (!match) {
        throw apiError(400, "UNKNOWN_DEV_ACCOUNT", "address is not in the test keyring");
      }
      try {
        const signer = makeDevSigner(config, { secretHex: keys[match.role].secret, expectedAddress: address });
        const signedSafeJson = signer.signInputs(unsignedSafeJson, signInputs);
        return { status: 200, body: { signedSafeJson } };
      } catch (error) {
        throw apiError(422, "DEV_SIGN_FAILED", error.message);
      }
    }
  }

  // GET /wallet/fuel/:address — ordinary (non-covenant) UTXOs for an address
  // on the CONFIGURED network, largest first, so the browser can auto-select
  // genesis funding / owner-op fuel instead of hand-crafting UTXO JSON.
  // Read-only public receiving info; no keys, no signing.
  if (method === "GET" && segments.length === 3 && segments[0] === "wallet" && segments[1] === "fuel") {
    // path segments are not URL-decoded upstream; the kaspa address colon
    // arrives percent-encoded (%3A) from encodeURIComponent.
    const address = decodeURIComponent(segments[2] || "");
    const fuelPrefix = `${require("../../sdk/src/address-identity").requiredAddressPrefix(config.networkId)}:`;
    if (typeof address !== "string" || !address.startsWith(fuelPrefix)) throw apiError(400, "BAD_ADDRESS", `address must be a ${config.networkId} address (${fuelPrefix}...)`);
    const { getAddressUtxos } = require("../../sdk/src/chain");
    const { rpc } = await connectVerified(config);
    try {
      const utxos = (await getAddressUtxos(rpc, address)).filter((u) => u.covenantId === null);
      utxos.sort((a, b) => (a.amount < b.amount ? 1 : -1));
      return { status: 200, body: { address, utxos: utxos.map((u) => ({ outpoint: u.outpoint, amount: u.amount.toString(), scriptPublicKeyHex: u.scriptPublicKeyHex })) } };
    } finally {
      await rpc.disconnect();
    }
  }

  // GET /network/status
  if (method === "GET" && segments.length === 2 && segments[0] === "network" && segments[1] === "status") {
    const { rpc, serverInfo } = await connectVerified(config);
    try {
      const daa = await getVirtualDaaScore(rpc);
      return {
        status: 200,
        body: {
          networkId: serverInfo.networkId,
          isSynced: serverInfo.isSynced,
          hasUtxoIndex: serverInfo.hasUtxoIndex,
          serverVersion: serverInfo.serverVersion,
          virtualDaaScore: daa.toString()
        }
      };
    } finally {
      await rpc.disconnect();
    }
  }

  // ---- Organizations (OFF-CHAIN application metadata; never authority) ----
  if (segments[0] === "organizations") {
    const org = require("../../sdk/src/organization");
    const orgError = (error) => {
      const status =
        error.code === "VERSION_CONFLICT" || error.code === "ORG_NOT_EMPTY" ? 409
        : error.code === "ORG_NOT_FOUND" || error.code === "MEMBER_NOT_FOUND" || error.code === "ASSIGNMENT_NOT_FOUND" || error.code === "VAULT_NOT_FOUND" ? 404
        : 422;
      const e = apiError(status, error.code || "ORG_ERROR", error.message);
      if (error.assignedVaultIds) e.extra = { assignedVaultIds: error.assignedVaultIds };
      return e;
    };
    const vaultExists = (vaultId) => loadAnyManifest(config, vaultId) !== null;
    const assignedVaultIds = (orgId) => {
      const record = org.loadAssignments(config); // throws on corruption (surfaced as 422)
      return Object.entries(record.assignments)
        .filter(([, a]) => a.orgId === orgId)
        .map(([vaultId]) => vaultId);
    };
    try {
      // GET /organizations — list incl. corrupt-record markers + assignments version
      if (method === "GET" && segments.length === 1) {
        let assignments;
        let assignmentsError = null;
        try {
          assignments = org.loadAssignments(config);
        } catch (e) {
          assignments = null;
          assignmentsError = e.message;
        }
        return {
          status: 200,
          body: {
            organizations: org.listOrganizations(config),
            assignmentsVersion: assignments ? assignments.version : null,
            assignments: assignments ? assignments.assignments : null,
            ...(assignmentsError ? { assignmentsError } : {}),
            roleLabels: org.ROLE_LABELS,
            note: "Organization roles are application metadata. They do not grant or modify Kaspa covenant authority."
          }
        };
      }
      // POST /organizations { name }
      if (method === "POST" && segments.length === 1) {
        return { status: 201, body: { organization: org.createOrganization(config, { name: body?.name }) } };
      }

      const orgId = segments[1];
      // Every scoped route resolves ONLY this organization; unknown or
      // mismatched ids fail cleanly server-side (isolation is not a
      // frontend filter).
      if (method === "GET" && segments.length === 2) {
        const record = org.loadOrganization(config, orgId);
        if (!record) throw apiError(404, "ORG_NOT_FOUND", `no organization ${orgId}`);
        return { status: 200, body: { organization: record, vaultIds: assignedVaultIds(orgId) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "rename") {
        return { status: 200, body: { organization: org.renameOrganization(config, orgId, { name: body?.name, expectedVersion: body?.expectedVersion }) } };
      }
      // Lifecycle (§ org management): archive/restore/delete are LOCAL METADATA
      // VISIBILITY operations only — they never touch vaults, covenant
      // authority, or on-chain state. Delete fails closed (409 ORG_NOT_EMPTY,
      // with assignedVaultIds) while any vault is still assigned.
      if (method === "POST" && segments.length === 3 && segments[2] === "archive") {
        return { status: 200, body: { organization: org.archiveOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "restore") {
        return { status: 200, body: { organization: org.restoreOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "delete") {
        return { status: 200, body: org.deleteOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) };
      }
      if (method === "GET" && segments.length === 3 && segments[2] === "members") {
        const record = org.loadOrganization(config, orgId);
        if (!record) throw apiError(404, "ORG_NOT_FOUND", `no organization ${orgId}`);
        return { status: 200, body: { members: record.members, version: record.version } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "members") {
        const { org: updated, member } = org.addMember(config, orgId, { ...body, expectedVersion: body?.expectedVersion });
        return { status: 201, body: { member, version: updated.version } };
      }
      if (method === "POST" && segments.length === 5 && segments[2] === "members" && segments[4] === "remove") {
        const updated = org.removeMember(config, orgId, segments[3], { expectedVersion: body?.expectedVersion });
        return { status: 200, body: { version: updated.version } };
      }
      if (method === "POST" && segments.length === 4 && segments[2] === "members") {
        const { org: updated, member } = org.updateMember(config, orgId, segments[3], { ...body, expectedVersion: body?.expectedVersion });
        return { status: 200, body: { member, version: updated.version } };
      }
      if (method === "GET" && segments.length === 3 && segments[2] === "vaults") {
        if (!org.loadOrganization(config, orgId)) throw apiError(404, "ORG_NOT_FOUND", `no organization ${orgId}`);
        const vaults = assignedVaultIds(orgId).map((id) => presentAny(config, id)).filter(Boolean);
        return { status: 200, body: { vaults } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "vaults") {
        const assignment = org.assignVault(config, {
          vaultId: body?.vaultId,
          orgId,
          group: body?.group ?? null,
          expectedVersion: body?.expectedVersion,
          vaultExists
        });
        return { status: 200, body: { assignment } };
      }
      if (method === "POST" && segments.length === 5 && segments[2] === "vaults" && segments[4] === "unassign") {
        const current = org.assignmentFor(config, segments[3]);
        if (!current || current.orgId !== orgId) {
          throw apiError(404, "ASSIGNMENT_NOT_FOUND", `vault ${segments[3]} is not assigned to organization ${orgId}`);
        }
        org.unassignVault(config, { vaultId: segments[3], expectedVersion: body?.expectedVersion });
        return { status: 200, body: { unassigned: true } };
      }
      // GET /organizations/:id/audit — chain events for assigned vaults +
      // this organization's metadata events, each explicitly typed.
      if (method === "GET" && segments.length === 3 && segments[2] === "audit") {
        if (!org.loadOrganization(config, orgId)) throw apiError(404, "ORG_NOT_FOUND", `no organization ${orgId}`);
        const vaultSet = new Set(assignedVaultIds(orgId));
        const events = readAudit(config, { limit: 1000 })
          .filter((e) => (e.kind === "metadata" ? e.orgId === orgId : e.vaultId && vaultSet.has(e.vaultId)))
          .map((e) => ({ ...e, eventType: e.kind === "metadata" ? "APPLICATION METADATA EVENT" : "CHAIN EVENT" }))
          .slice(0, Number(query?.limit) > 0 ? Number(query.limit) : 300);
        return { status: 200, body: { events } };
      }
      throw apiError(404, "NOT_FOUND", "unknown organizations route");
    } catch (error) {
      if (error.status) throw error;
      throw orgError(error);
    }
  }

  // POST /vaults/:id/reconcile — "Verify Vault State". Invokes ONLY the
  // existing reconcile-v2 exact-proof path with its default gates; no
  // force/override/claim-deletion inputs exist or are accepted.
  if (method === "POST" && segments.length === 3 && segments[0] === "vaults" && segments[2] === "reconcile") {
    const vaultId = segments[1];
    const loaded = loadAnyManifest(config, vaultId);
    if (!loaded) {
      throw apiError(404, "VAULT_NOT_FOUND", `no vault ${vaultId}`);
    }
    // Route by the vault's version to the matching exact-proof reconciler. Both
    // reconcilers use only their default gates; no force/override/claim-deletion
    // input exists or is accepted. The v0.4 reconciler serves the v0.4 family
    // (v0.4 + v0.4.1); it fails closed on any other version internally.
    try {
      if (loaded.version === "v2") {
        const { reconcileVaultV2 } = require("../../sdk/src/reconcile-v2");
        const result = await reconcileVaultV2(config, vaultId);
        return { status: 200, body: { reconcile: result, vault: presentAny(config, vaultId) } };
      }
      if (loaded.version === "v4") {
        const { reconcileVaultV4 } = require("../../sdk/src/reconcile-v4");
        const result = await reconcileVaultV4(config, vaultId);
        return { status: 200, body: { reconcile: result, vault: presentAny(config, vaultId) } };
      }
      throw apiError(422, "UNSUPPORTED_VERSION", `reconcile is not available for vault version ${loaded.version}`);
    } catch (error) {
      if (error.status) throw error;
      throw apiError(422, "RECONCILE_FAILED", error.message);
    }
  }

  // GET /vaults
  if (method === "GET" && segments.length === 1 && segments[0] === "vaults") {
    const ids = listVaultIds(config);
    const vaults = ids.map((id) => presentAny(config, id));
    return { status: 200, body: { vaults } };
  }

  // GET /vaults/:id  and  /vaults/:id/status | /audit
  if (method === "GET" && segments.length >= 2 && segments[0] === "vaults") {
    const vaultId = segments[1];
    const loaded = loadAnyManifest(config, vaultId);
    if (!loaded) {
      throw apiError(404, "VAULT_NOT_FOUND", `no vault ${vaultId}`);
    }
    const manifest = loaded.manifest;

    if (segments.length === 2) {
      return { status: 200, body: presentAny(config, vaultId) };
    }
    if (segments.length === 3 && segments[2] === "status") {
      const { rpc } = await connectVerified(config);
      try {
        const daa = await getVirtualDaaScore(rpc);
        const body = presentAny(config, vaultId, { virtualDaa: daa });
        if (manifest.live) {
          const compiled =
            loaded.version === "v2"
              ? require("../../sdk/src/contract-compiler-v2").compileExactStateV2({
                  config,
                  template: manifest.template,
                  state: manifest.live.state
                })
              : compileExactState({ config, policy: manifest.policy, state: manifest.live.state });
          const address = covenantAddress(config, compiled.scriptBytes);
          const resp = await rpc.getUtxosByAddresses({ addresses: [address] });
          body.live.chainConfirmed = (resp.entries ?? []).some((e) => {
            const o = e.outpoint ?? e.entry?.outpoint;
            return (
              String(o.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
              Number(o.index) === manifest.live.outpoint.index
            );
          });
        }
        return { status: 200, body };
      } finally {
        await rpc.disconnect();
      }
    }
    if (segments.length === 3 && segments[2] === "audit") {
      return { status: 200, body: { events: readAudit(config, { vaultId }) } };
    }
  }

  // GET /audit
  if (method === "GET" && segments.length === 1 && segments[0] === "audit") {
    return { status: 200, body: { events: readAudit(config, { limit: Number(query.limit) || 200 }) } };
  }

  throw apiError(404, "NOT_FOUND", `no route for ${method} /${segments.join("/")}`);
}

module.exports = { handle, presentVault, API_VERSION, apiError, loadConfig };
