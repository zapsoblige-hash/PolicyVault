"use strict";

/*
 * PolicyVault v0.7 ON-CHAIN ORGANIZATIONAL ROOT — server routes
 * (docs/postlaunch/v0.7-app-surface-contract.md §2, as amended by the
 * coordinator's two clarifications of 2026-09-03: ONE vault operation per
 * root transition — closed code ONE_VAULT_OPERATION_PER_ROOT_TRANSITION,
 * covenant-verified, not merely an SDK-tooling limit — and a dedicated
 * single-signer POST .../requests/:id/signature route for root genesis /
 * rooted-vault genesis / succession, separate from the M-of-N
 * POST .../requests/:id/finalize route).
 *
 * This module ONLY orchestrates HTTP shape (auth, scopes already gated by
 * server/src/api.js's deny-by-default dispatcher, request/response
 * presentation, closed refusal codes). Every funds-relevant decision
 * stays in sdk/src/wallet-requests-v7.js / sdk/src/reconcile-v7.js /
 * core/model / core/intent — never re-derived here. No server-only
 * financial fact is introduced.
 *
 * Hosted organization admins get NO root authority: nowhere in this file
 * is a hosted /organizations membership or role consulted. The ONLY
 * authority check for creating a root-authorized request is
 * sdk/src/wallet-requests-v7.js's assertInitiatingOwner (the initiating
 * signer must be an active owner slot of the CURRENT root state — or, for
 * succession, the root's pinned successor key).
 */

const wr7 = require("../../sdk/src/wallet-requests-v7");
const wr7hd = require("../../sdk/src/wallet-requests-v7-hd");
const wr7kas = require("../../sdk/src/wallet-requests-v7-kas"); // v0.7 enablement (2026-09-10): rooted KAS safe-payment vault (CANDIDATE)
const { registryEntryToJson: kasRegistryEntryToJson, CONTRACT_VERSION_V7_KAS } = require("../../sdk/src/manifest-v7-kas");
const { reconcileOrgRootV7 } = require("../../sdk/src/reconcile-v7");
const { listRootedVaultsV7, registryEntryToJson } = require("../../sdk/src/manifest-v7");
const { loadManifestV7Hd } = require("../../sdk/src/manifest-v7-hd");
const { sompiToKas } = require("../../sdk/src/amounts");
const { structured: explainOrgRoot } = require("../../core/explain/org-root-explain");
const tenancy = require("./tenancy");
const { loadAnyManifestAll } = require("./manifest-any");

/*
 * rc11 internal security review F-04 (2026-09-04) — HOSTED TENANCY for every
 * org-root / rooted-vault route. Authority is resolved from DURABLE facts
 * only (the root record's active owner slots + pinned successor, the vault
 * manifest's agents, the request's own creator). The presented principal
 * is never discarded; the initiating signer of every build is BOUND to it.
 * Self-hosted mode (tenancy disabled) is unchanged. Foreign objects answer
 * the non-oracle 404.
 */
/* rc12 review R-08: malformed wallet payloads answer a CLOSED 400 BAD_SIGNATURE, never an internal TypeError message. */
function requireSignedSafeJsonShape(signedSafeJson) {
  let parsed;
  try {
    parsed = JSON.parse(signedSafeJson);
  } catch {
    throw orgRootsError(400, "BAD_SIGNATURE", "signedSafeJson must be the wallet's signed Safe JSON transaction");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.inputs) || parsed.inputs.length === 0 || !parsed.inputs.every((i) => i && typeof i === "object")) {
    throw orgRootsError(400, "BAD_SIGNATURE", "signedSafeJson must carry a non-empty inputs[] array of signed inputs");
  }
}
function forbidden(code, message) {
  return orgRootsError(403, code, message);
}
async function bindSignerToPrincipal(config, principal, signerAddress) {
  if (!config.tenancyEnforced) return;
  const xo = tenancy.xOnlyOfAddress(config, signerAddress);
  if (!xo) throw orgRootsError(400, "BAD_SIGNER", "signerAddress must be a valid address for this network");
  if (xo !== principal.xOnlyPubkey) throw forbidden("SIGNER_NOT_PRINCIPAL", "hosted mode: the initiating signer must be the signed-in wallet (or the machine credential's creating wallet) — an organizational-root action is never built on another wallet's behalf");
}
async function loadRootScoped(config, rootId, principal, need = "read") {
  const root = await wr7.loadOrgRoot(config, rootId);
  if (!config.tenancyEnforced) return root;
  return tenancy.requireOrgRootAccess(config, root, principal, need); // 404 non-oracle / 403 NOT_AN_ACTIVE_SLOT
}
/* A request under /org-roots/:rootId/requests/:id — the root may not exist yet (pending genesis). */
async function loadRequestScoped(config, rootId, requestId, principal, { mutation = false } = {}) {
  const request = await wr7.loadOrgRootRequest(config, requestId);
  if (!request || request.rootCovenantId !== rootId) throw orgRootsError(404, "REQUEST_NOT_FOUND", `no request ${requestId}`);
  if (!config.tenancyEnforced) return request;
  const root = await wr7.loadOrgRoot(config, rootId);
  const allowed = mutation ? tenancy.orgRootRequestMutationAllowed(config, request, root, principal) : tenancy.orgRootRequestAccessAllowed(config, request, root, principal);
  if (!allowed) {
    if (mutation && tenancy.orgRootRequestAccessAllowed(config, request, root, principal)) throw forbidden("REQUEST_FORBIDDEN", "this wallet may review this request; it cannot sign, finalize, submit or reject it");
    throw orgRootsError(404, "REQUEST_NOT_FOUND", `no request ${requestId}`);
  }
  return request;
}
function requireSlotOwner(config, request, slot, principal) {
  if (!config.tenancyEnforced) return;
  const entry = (request.slots || []).find((s) => s.slot === Number(slot));
  if (!entry) throw orgRootsError(422, "SLOT_INACTIVE", `slot ${slot} is not one of this request's expected signer slots`);
  if (entry.publicKey !== principal.xOnlyPubkey) throw forbidden("NOT_AN_ACTIVE_SLOT", "only the wallet holding this owner slot may request or attach its slot signature");
}
/* Rooted-vault (v7 / v7hd / v7kas) build authority — the v4 rule, owners = the root's active slots. */
async function requireRootedBuildAuthority(config, principal, vaultId, signerAddress) {
  if (!config.tenancyEnforced) return null;
  const loaded = await loadAnyManifestAll(config, vaultId);
  if (!loaded || !tenancy.isRootedVaultVersion(loaded.version)) throw orgRootsError(404, "VAULT_NOT_FOUND", `no rooted vault ${vaultId}`);
  await tenancy.requireAnyVaultAccess(config, loaded, principal, "build"); // 404 foreign, 403 read-only participant
  const roles = await tenancy.rootedVaultRoles(config, loaded);
  const signerXOnly = tenancy.xOnlyOfAddress(config, signerAddress);
  if (!signerXOnly) throw orgRootsError(400, "BAD_SIGNER", "signerAddress must be a valid address for this network");
  const key = principal.xOnlyPubkey;
  if (!roles.owner.has(signerXOnly) && !roles.agents.has(signerXOnly)) throw forbidden("SIGNER_NOT_PARTICIPANT", "signerAddress is not a participant of this rooted vault — a request is never built into a stranger's inbox");
  if (!roles.owner.has(key) && signerXOnly !== key) throw forbidden("SIGNER_NOT_PRINCIPAL", "an agent builds requests only for its own key; only an active root owner may build for the vault's registered agents");
  return loaded;
}
async function walletRequestVisible(config, principal, request, cache) {
  if (!config.tenancyEnforced) return true;
  const signer = tenancy.xOnlyOfAddress(config, request.signerAddress);
  if (signer && signer === principal.xOnlyPubkey) return true;
  const vaultId = request.vaultId;
  if (typeof vaultId !== "string") return false;
  if (!cache.has(vaultId)) {
    let loaded = null;
    try { loaded = await loadAnyManifestAll(config, vaultId); } catch { loaded = null; }
    cache.set(vaultId, loaded);
  }
  const loaded = cache.get(vaultId);
  return loaded ? tenancy.anyVaultAccessAllowed(config, loaded, principal, "read") : false;
}
async function requireWalletRequest(config, principal, request, { mutation = false } = {}) {
  if (!request) throw orgRootsError(404, "REQUEST_NOT_FOUND", "no such request");
  if (!config.tenancyEnforced) return request;
  const cache = new Map();
  if (!(await walletRequestVisible(config, principal, request, cache))) throw orgRootsError(404, "REQUEST_NOT_FOUND", "no such request");
  if (mutation) {
    const signer = tenancy.xOnlyOfAddress(config, request.signerAddress);
    const loaded = cache.get(request.vaultId) ?? (await loadAnyManifestAll(config, request.vaultId).catch(() => null));
    const mayBuild = loaded ? await tenancy.anyVaultAccessAllowed(config, loaded, principal, "build") : false;
    if (!(signer === principal.xOnlyPubkey || mayBuild)) throw forbidden("REQUEST_FORBIDDEN", "this wallet may review this request; it cannot sign, submit or reject it");
  }
  return request;
}

const AUTHORITY_MODEL = Object.freeze({
  ON_CHAIN_ORGANIZATIONAL_ROOT: "ON_CHAIN_ORGANIZATIONAL_ROOT",
  HOSTED_ORGANIZATION: "HOSTED_ORGANIZATION",
  SINGLE_ON_CHAIN_OWNER: "SINGLE_ON_CHAIN_OWNER"
});

function orgRootsError(status, code, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (extra) e.extra = extra;
  return e;
}

/*
 * Map an SDK (sdk/src/wallet-requests-v7.js / core/*) error CODE to an
 * HTTP status. Every closed code named in the app-surface contract §2
 * gets its own row; anything unrecognized is 422 (a validated refusal,
 * never a raw 500) unless the error already carries a status (rethrown
 * as-is).
 */
const STATUS_BY_CODE = Object.freeze({
  AGENT_NOT_REGISTERED: 403, // v0.7-kas request layer (2026-09-10)
  NOT_AN_APPROVER: 403, // v0.7-kas request layer (2026-09-10)
  UNKNOWN_APPROVER: 403, // v0.7-kas request layer (2026-09-10)
  VAULT_PAUSED: 409, // v0.7-kas request layer (2026-09-10)
  VAULT_PENDING_REQUEST: 409, // v0.7-kas request layer (2026-09-10)
  VAULT_ID_IN_USE: 409, // RC33-ID-01 (2026-09-11): global vault-record uniqueness (sdk/src/vault-identity.js) — the identity is held by a record or request of ANY generation
  INSUFFICIENT_APPROVALS: 409, // v0.7-kas request layer (2026-09-10)
  DUPLICATE_APPROVAL: 409, // v0.7-kas request layer (2026-09-10)
  WRONG_SLOT: 409, // v0.7-kas request layer (2026-09-10)
  REQUEST_ID_MISMATCH: 409, // v0.7-kas request layer (2026-09-10)
  AGENT_SET_REQUIRED: 422, // v0.7-kas request layer (2026-09-10)
  AGENT_SET_INVALID: 422, // v0.7-kas request layer (2026-09-10)
  AGENT_ROOT_MISMATCH: 422, // v0.7-kas request layer (2026-09-10)
  RECIPIENT_ROOT_MISMATCH: 422, // v0.7-kas request layer (2026-09-10)
  OVER_CAP: 422, // v0.7-kas request layer (2026-09-10)
  OVER_BUDGET: 422, // v0.7-kas request layer (2026-09-10)
  OVER_AGENT_FEE_CAP: 422, // v0.7-kas request layer (2026-09-10)
  INSUFFICIENT_RESERVE: 422, // v0.7-kas request layer (2026-09-10)
  BAD_APPROVER: 400, // v0.7-kas request layer (2026-09-10)
  GENERATION_NOT_MAINNET_AUTHORIZED: 403, // v0.7-kas request layer (2026-09-10)
  REQUEST_NOT_FOUND: 404,
  ROOT_NOT_FOUND: 404,
  VAULT_NOT_FOUND: 404,
  NOT_AN_ACTIVE_SLOT: 403,
  OWNER_SET_ILL_FORMED: 422,
  UNDER_QUORUM: 409,
  DUPLICATE_SLOT_SIGNATURE: 409,
  SLOT_KEY_MISMATCH: 409,
  RESPONSE_BINDING_MISMATCH: 409,
  RESPONSE_REPLAYED: 409,
  MANIFEST_HASH_MISMATCH: 409,
  TXID_DRIFT: 409,
  ROOT_FROZEN: 409,
  ALREADY_FROZEN: 409,
  NOT_FROZEN: 409,
  ROOT_STALE_OUTPOINT: 409,
  ROOT_PENDING_REQUEST: 409,
  DELAY_NOT_ELAPSED: 409,
  ROOT_INPUT_REQUIRED: 422,
  OWNER_PATH_TAKES_NO_SIGNATURE: 422,
  HOSTED_ORG_IS_NOT_A_ROOT: 422,
  ONE_VAULT_OPERATION_PER_ROOT_TRANSITION: 422,
  NOT_A_SLOT_REQUEST: 422,
  SUCCESSION_TAKES_NO_SLOTS: 422,
  NOT_A_SINGLE_SIGNER_REQUEST: 422,
  NOT_AN_MOFN_REQUEST: 422,
  SLOT_INACTIVE: 422,
  SLOT_OUT_OF_RANGE: 422,
  WALLET_REJECTED: 422,
  SIGNATURE_INVALID: 422,
  BAD_SIGNATURE: 400,
  UNKNOWN_ROOT_ACTION: 422,
  UNKNOWN_ACTION: 422,
  UNKNOWN_REQUEST_KIND: 422,
  BUILD_FAILED: 422,
  AMOUNT_INVALID: 422,
  INSUFFICIENT_FUNDS: 422,
  INSUFFICIENT_FUEL: 422,
  TEMPLATE_PIN_MISSING: 422,
  DESCRIPTOR_PIN_MISMATCH: 422,
  DESCRIPTOR_MISMATCH: 422,
  WRONG_TOKEN_FAMILY: 422,
  TOKEN_POSITION_ALREADY_HELD: 409,
  INTENT_VERIFICATION_FAILED: 422,
  MANIFEST_BUILD_FAILED: 422,
  RECONCILIATION_REQUIRED: 409,
  SUBMISSION_REJECTED: 409,
  TXID_MISMATCH: 500,
  CLAIM_CONFLICT: 409,
  NETWORK_MISMATCH: 409,
  CANNOT_REJECT: 409,
  /* wallet-requests-v7.js follows the established v4 convention of using
   * the request's CURRENT STATE as the error code when an action is
   * attempted from the wrong state ("request is SIGNED, not AUTHORIZED")
   * — a client can act on the exact state without parsing the message.
   * Every such state is a conflict with the request's lifecycle, not a
   * validation failure of the call's own body. */
  AUTHORIZED: 409,
  SIGNED: 409,
  BROADCAST: 409,
  CHAIN_SEEN: 409,
  CHAIN_VERIFIED: 409,
  VERIFIED_OUTCOME: 409,
  REFUSED: 409,
  FAILED: 409,
  STALE: 409,
  BUILT: 409,
  SUBMITTING: 409,
  SUBMITTED: 409,
  /* v0.7-payment-hd (CANDIDATE) additions — Wave 2 Track E */
  VAULT_NOT_FOUND: 404,
  VAULT_TERMINAL: 409,
  CONTRACT_VERSION_MISMATCH: 422,
  TOKEN_POSITION_ALREADY_HELD: 409,
  HD_LEVEL_UNPROVEN: 422,
  HD_CHAIN_STALE: 422,
  HD_AUTHORITY_EXCEEDS_ANCESTOR: 422,
  DELEGATION_WHILE_PAUSED: 409,
  DELEGATION_WHILE_ROOT_FROZEN: 409,
  DELEGATION_SPLICE_INVALID: 422,
  LEVEL_OUT_OF_RANGE: 422,
  CHAIN_REQUIRED: 422,
  PAUSED: 409,
  DELEGATION_PATH_TAKES_NO_ROOT: 422,
  SPEND_PATH_TAKES_NO_ROOT: 422
});

function mapError(error) {
  if (error && error.status) return error;
  const code = error && error.code;
  const status = (code && STATUS_BY_CODE[code]) || 422;
  return orgRootsError(status, code || "ORG_ROOTS_ERROR", (error && error.message) || "org-roots request failed");
}

/* ------------------------------------------------------------------ */
/* presentation                                                        */
/* ------------------------------------------------------------------ */

function presentOrgRootSummary(root) {
  return {
    rootCovenantId: root.rootCovenantId,
    orgId: root.orgId,
    label: root.label,
    authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT,
    ownerSlotsActive: (root.slots ?? []).length,
    ownerM: root.state ? String(root.state.ownerM) : null,
    emergencyK: root.state ? String(root.state.emergencyK) : null,
    recoveryM: root.state ? String(root.state.recoveryM) : null,
    frozen: root.state ? root.state.frozen === "1" : null,
    generation: root.generation,
    pendingRequestId: root.pendingRequestId,
    live: root.live ? { outpoint: root.live.outpoint } : null
  };
}

function presentOrgRootFull(root) {
  return {
    ...presentOrgRootSummary(root),
    template: root.template,
    state: root.state,
    slots: root.slots,
    rootPins: root.rootPins,
    live: root.live,
    vaults: root.vaults,
    networkId: root.networkId,
    contractVersion: root.contractVersion,
    createdAt: root.createdAt,
    updatedAt: root.updatedAt
  };
}

function presentOrgRootRequest(request) {
  if (!request) return null;
  const { build, encoderBuildDir, finalTransaction, signedSafeJson, slotRequestEnvelopes, ...rest } = request;
  const slots = (request.slots ?? []).map((s) => {
    const { _approval, ...slotRest } = s;
    void _approval;
    return slotRest;
  });
  void build;
  void encoderBuildDir;
  void finalTransaction;
  void signedSafeJson;
  void slotRequestEnvelopes;
  return { ...rest, slots, authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT };
}

function presentRootedVaultSummary(manifest) {
  /* R7-05 (browser initiation of rooted-vault owner operations, launch
   * scope 2026-09-08): the presentation ALSO carries what an owner needs
   * to prefill and review an operation truthfully — the installed delegate
   * registry (every policy with its exact values AND its recipient list,
   * the same JSON shape the SDK's registry normalizer accepts back), the
   * pinned recovery key a terminal recovery pays to, the generation and the
   * asset's display fields. Presentation only: the route's tenancy scoping
   * is unchanged and nothing here is an input the server trusts back. */
  const descriptor = manifest.asset && manifest.asset.descriptor ? manifest.asset.descriptor : null;
  return {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    orgRootCovenantId: manifest.orgRootCovenantId,
    authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT,
    contractVersion: manifest.contractVersion,
    generation: Number.isInteger(manifest.generation) ? manifest.generation : null,
    latestTransitionTxId: manifest.latestTransitionTxId ?? null,
    recoveryPk: manifest.template && typeof manifest.template.recoveryPk === "string" ? manifest.template.recoveryPk : null,
    agents: Array.isArray(manifest.agentRegistry) ? manifest.agentRegistry.map((entry) => registryEntryToJson(entry)) : [],
    asset: descriptor ? { assetId: descriptor.assetId ?? null, displayName: descriptor.displayName ?? null, tokenStandard: descriptor.tokenStandard ?? null, decimalsDisplay: descriptor.decimalsDisplay ?? null } : null,
    live: manifest.live
      ? {
          covenantId: manifest.live.covenantId,
          outpoint: manifest.live.outpoint,
          feeReserveKas: sompiToKas(manifest.live.state.feeReserve),
          paused: manifest.live.state.paused === 1n,
          /* the FULL position (not just amount/outpoint) so a caller can
           * build a tokenAgentSpend's chain.tokenPosition directly from
           * this response without a second lookup. */
          tokenPosition: manifest.live.tokenPosition
            ? {
                outpoint: manifest.live.tokenPosition.outpoint,
                value: manifest.live.tokenPosition.value.toString(),
                scriptPublicKeyHex: manifest.live.tokenPosition.scriptPublicKeyHex,
                covenantId: manifest.live.tokenPosition.covenantId,
                state: {
                  ownerIdentifier: manifest.live.tokenPosition.state.ownerIdentifier,
                  identifierType: manifest.live.tokenPosition.state.identifierType,
                  amount: manifest.live.tokenPosition.state.amount.toString(),
                  isMinter: manifest.live.tokenPosition.state.isMinter
                }
              }
            : null
        }
      : null
  };
}

/* v0.7-payment-hd (CANDIDATE) presentation — Wave 2 Track E. */
function presentRootedHdVaultSummary(manifest) {
  return {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    orgRootCovenantId: manifest.orgRootCovenantId,
    authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT,
    contractVersion: manifest.contractVersion,
    candidateStatus: "CANDIDATE",
    live: manifest.live
      ? {
          covenantId: manifest.live.covenantId,
          outpoint: manifest.live.outpoint,
          feeReserveKas: sompiToKas(manifest.live.state.feeReserve),
          paused: manifest.live.state.paused === 1n,
          tokenPosition: manifest.live.tokenPosition
            ? { outpoint: manifest.live.tokenPosition.outpoint, value: manifest.live.tokenPosition.value.toString(), scriptPublicKeyHex: manifest.live.tokenPosition.scriptPublicKeyHex, covenantId: manifest.live.tokenPosition.covenantId, state: { ownerIdentifier: manifest.live.tokenPosition.state.ownerIdentifier, identifierType: manifest.live.tokenPosition.state.identifierType, amount: manifest.live.tokenPosition.state.amount.toString(), isMinter: manifest.live.tokenPosition.state.isMinter } }
            : null
        }
      : null
  };
}
function presentOrgRootRequestHd(request) {
  if (!request) return null;
  const { build, encoderBuildDir, finalTransaction, signedSafeJson, ...rest } = request;
  void build;
  void encoderBuildDir;
  void finalTransaction;
  void signedSafeJson;
  return { ...rest, authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT, status: "CANDIDATE" };
}

/* v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT (CANDIDATE) presentation — v0.7 enablement (2026-09-10). Everything an owner,
 * delegate or approver needs to review truthfully: the protected principal and fee reserve, the installed delegate
 * registry (exact policies + recipients), the vault-level approver slots and threshold M, the pinned recovery key. */
function presentRootedKasVaultSummary(manifest) {
  const state = manifest.live ? manifest.live.state : null;
  return {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    orgRootCovenantId: manifest.orgRootCovenantId,
    authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT,
    contractVersion: manifest.contractVersion,
    candidateStatus: "CANDIDATE",
    profile: "kas",
    generation: Number.isInteger(manifest.generation) ? manifest.generation : null,
    latestTransitionTxId: manifest.latestTransitionTxId ?? null,
    recoveryPk: manifest.template && typeof manifest.template.recoveryPk === "string" ? manifest.template.recoveryPk : null,
    agents: Array.isArray(manifest.agentRegistry) ? manifest.agentRegistry.map((entry) => kasRegistryEntryToJson(entry)) : [],
    approvers: state ? state.approvers.filter((k) => k !== "00".repeat(32)) : [],
    approvalM: state ? state.approvalM.toString() : null,
    live: manifest.live
      ? {
          covenantId: manifest.live.covenantId,
          outpoint: manifest.live.outpoint,
          protectedValueKas: sompiToKas(state.protectedValue),
          feeReserveKas: sompiToKas(state.feeReserve),
          totalKas: sompiToKas(manifest.live.outpointValue),
          paused: state.paused === 1n,
          policyNonce: state.policyNonce.toString()
        }
      : null
  };
}
function presentKasWalletRequest(request) {
  if (!request) return null;
  const { build, encoderBuildDir, finalTransaction, signedSafeJson, approvalPackage, predecessorVault, ...rest } = request;
  void build; void encoderBuildDir; void finalTransaction; void signedSafeJson; void approvalPackage; void predecessorVault;
  return { ...rest, ...wr7kas.kasPresentation(request) };
}

function presentV7WalletRequest(request) {
  if (!request) return null;
  const { build, encoderBuildDir, finalTransaction, ...rest } = request;
  void build;
  void encoderBuildDir;
  void finalTransaction;
  /* the vault's authority IS the organizational root even though a
   * delegate spend / token deposit never touches it (the covenant
   * enforces that in-VM) — never SINGLE_ON_CHAIN_OWNER, which is reserved
   * for a legacy v0.4/v0.4.1/v0.5/v0.6 vault with an actual owner key. */
  return { ...rest, authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT };
}

/* ------------------------------------------------------------------ */
/* route dispatch                                                      */
/* ------------------------------------------------------------------ */

/*
 * dispatch(config, method, segments, query, body, ctx) -> { status, body }
 * segments[0] is either "org-roots" or ["wallet","v7"]. Auth/scope
 * enforcement already ran in server/src/api.js's handle() (scopes read:org-
 * roots / write:org-roots, deny-by-default, NOT implied by hosted-
 * organization scopes); this module reads the resolved principal only to
 * attribute createdBy, never to grant authority.
 */
async function dispatch(config, method, segments, query, body, ctx) {
  const { requestAuthPrincipal } = require("./api");
  const principal = config.tenancyEnforced ? await requestAuthPrincipal(config, ctx, { required: true }) : await requestAuthPrincipal(config, ctx, { required: false });
  try {
    if (segments[0] === "wallet" && segments[1] === "v7") {
      return await dispatchWalletV7(config, method, segments, query, body, principal);
    }
    if (segments[0] !== "org-roots") {
      throw orgRootsError(404, "NOT_FOUND", "unknown org-roots route");
    }
    return await dispatchOrgRoots(config, method, segments, query, body, principal);
  } catch (error) {
    throw mapError(error);
  }
}

async function dispatchOrgRoots(config, method, segments, query, body, principal) {

  // GET /org-roots
  if (method === "GET" && segments.length === 1) {
    const roots = (await wr7.listOrgRoots(config)).filter((r) => tenancy.orgRootAccessAllowed(config, r, principal, "read")); // F-04: a tenant sees only roots it participates in
    return { status: 200, body: { orgRoots: roots.map(presentOrgRootSummary) } };
  }

  // POST /org-roots  { label, owners, ownerM, emergencyK, recoveryM,
  //   recoveryDelayDaa, successionDelayDaa, successorAddress|null,
  //   rootValueKas, rootMaxFeePerTxKas, signerAddress, funding? }
  if (method === "POST" && segments.length === 1) {
    const b = body ?? {};
    await bindSignerToPrincipal(config, principal, b.signerAddress); // F-04
    const request = await wr7.buildRootGenesisRequest({
      config,
      label: b.label ?? "",
      orgId: b.orgId,
      owners: b.owners,
      ownerM: b.ownerM,
      emergencyK: b.emergencyK,
      recoveryM: b.recoveryM,
      recoveryDelayDaa: b.recoveryDelayDaa,
      successionDelayDaa: b.successionDelayDaa,
      successorAddress: b.successorAddress ?? null,
      rootValueKas: b.rootValueKas,
      rootMaxFeePerTxKas: b.rootMaxFeePerTxKas,
      signerAddress: b.signerAddress,
      funding: b.funding
    });
    return { status: 201, body: { request: presentOrgRootRequest(request) } };
  }

  if (segments.length === 1) throw orgRootsError(404, "NOT_FOUND", "unknown org-roots route");
  const rootId = segments[1];

  // GET /org-roots/:rootId
  if (method === "GET" && segments.length === 2) {
    const root = await loadRootScoped(config, rootId, principal, "read"); // F-04
    if (!root) throw orgRootsError(404, "ROOT_NOT_FOUND", `no organizational root ${rootId}`);
    let explain = null;
    if (root.pendingRequestId) {
      const pending = await wr7.loadOrgRootRequest(config, root.pendingRequestId);
      if (pending && pending.manifest && pending.manifest.manifestVersion) explain = explainOrgRoot({ manifest: pending.manifest });
    }
    return { status: 200, body: { orgRoot: presentOrgRootFull(root), explain } };
  }

  // GET /org-roots/:rootId/vaults
  if (method === "GET" && segments.length === 3 && segments[2] === "vaults") {
    if (config.tenancyEnforced) await loadRootScoped(config, rootId, principal, "read"); // F-04
    const vaults = await listRootedVaultsV7(config, { orgRootCovenantId: rootId });
    const hdVaults = await wr7hd.listRootedHdVaultsV7(config, { orgRootCovenantId: rootId });
    const kasVaults = await wr7kas.listRootedKasVaultsV7(config, { orgRootCovenantId: rootId });
    return { status: 200, body: { vaults: [...vaults.map(presentRootedVaultSummary), ...hdVaults.map(presentRootedHdVaultSummary), ...kasVaults.map(presentRootedKasVaultSummary)] } };
  }

  // POST /org-roots/:rootId/vaults  { profile, label, descriptor,
  //   templateIndex?, agents?, recoveryAddress, depositKas?, feeReserveKas,
  //   signerAddress, funding? }
  if (method === "POST" && segments.length === 3 && segments[2] === "vaults") {
    const b = body ?? {};
    if (config.tenancyEnforced) {
      await loadRootScoped(config, rootId, principal, "owner"); // F-04: only an active root owner creates rooted vaults
      await bindSignerToPrincipal(config, principal, b.signerAddress);
    }
    if (b.profile !== undefined && b.profile !== "policyvault-0.7-payment" && b.profile !== "policyvault-0.7-payment-hd" && b.profile !== CONTRACT_VERSION_V7_KAS) {
      throw orgRootsError(422, "UNKNOWN_VERSION", `unsupported rooted-vault profile ${JSON.stringify(b.profile)} — failing closed`);
    }
    if (b.profile === CONTRACT_VERSION_V7_KAS) {
      /* v0.7 enablement (2026-09-10) — ROOTED KAS SAFE-PAYMENT VAULT (CANDIDATE). `agents` is the v0.4.1 delegate policy
       * set with each agent's recipients; `approvers` + `approvalM` the vault-level tier; depositKas the protected
       * principal; the funder signs its own funding inputs through /wallet/v7/requests/:id/signature. */
      const request = await wr7kas.buildKasVaultGenesisRequest({
        config,
        rootCovenantId: rootId,
        label: b.label ?? "",
        agents: b.agents ?? [],
        approvers: b.approvers ?? [],
        approvalM: b.approvalM ?? 0,
        recoveryAddress: b.recoveryAddress,
        depositKas: b.depositKas,
        feeReserveKas: b.feeReserveKas,
        signerAddress: b.signerAddress,
        funding: b.funding,
        vaultId: b.vaultId
      });
      return { status: 201, body: { request: presentKasWalletRequest(request) } };
    }
    if (b.profile === "policyvault-0.7-payment-hd") {
      /* Wave 2 Track E — HIERARCHICAL DELEGATION CANDIDATE (NOT covenant-
       * byte-frozen). `agents` here is the level-1 HD leaf forest
       * (docs/postlaunch/v0.7-app-surface-contract.md §6.1). */
      const request = await wr7hd.buildHdVaultGenesisRequest({
        config,
        rootCovenantId: rootId,
        label: b.label ?? "",
        descriptor: b.descriptor,
        templateIndex: b.templateIndex ?? 0,
        initialAgents: b.agents ?? [],
        recoveryAddress: b.recoveryAddress,
        feeReserveKas: b.feeReserveKas,
        signerAddress: b.signerAddress,
        funding: b.funding,
        vaultId: b.vaultId
      });
      return { status: 201, body: { request: presentOrgRootRequestHd(request) } };
    }
    const request = await wr7.buildRootedVaultGenesisRequest({
      config,
      rootCovenantId: rootId,
      label: b.label ?? "",
      descriptor: b.descriptor,
      templateIndex: b.templateIndex ?? 0,
      agents: b.agents ?? [],
      recoveryAddress: b.recoveryAddress,
      feeReserveKas: b.feeReserveKas,
      signerAddress: b.signerAddress,
      funding: b.funding,
      vaultId: b.vaultId
    });
    return { status: 201, body: { request: presentOrgRootRequest(request) } };
  }

  // POST /org-roots/:rootId/reconcile
  if (method === "POST" && segments.length === 3 && segments[2] === "reconcile") {
    if (config.tenancyEnforced) await loadRootScoped(config, rootId, principal, "owner"); // F-04
    const result = await reconcileOrgRootV7(config, rootId);
    return { status: 200, body: { reconcile: result } };
  }

  if (segments.length >= 3 && segments[2] === "requests") {
    // POST /org-roots/:rootId/requests  { action, params, vaultOperations?, signerAddress }
    if (method === "POST" && segments.length === 3) {
      const b = body ?? {};
      if (config.tenancyEnforced) {
        await loadRootScoped(config, rootId, principal, "read"); // F-04: strangers get the non-oracle 404 before any lock
        await bindSignerToPrincipal(config, principal, b.signerAddress); // the initiating owner IS the caller
      }
      const request = await wr7.buildRootActionRequest({
        config,
        rootCovenantId: rootId,
        action: b.action,
        params: b.params ?? {},
        vaultOperations: b.vaultOperations ?? [],
        signerAddress: b.signerAddress
      });
      return { status: 201, body: { request: presentOrgRootRequest(request), warnings: request.warnings } };
    }
    // GET /org-roots/:rootId/requests
    if (method === "GET" && segments.length === 3) {
      let requests = await wr7.listOrgRootRequests(config, { rootCovenantId: rootId });
      if (config.tenancyEnforced) { // F-04: a LIVE root answers only its participants (non-oracle 404); a pending genesis lists to its creator
        const root = await wr7.loadOrgRoot(config, rootId);
        if (root) tenancy.requireOrgRootAccess(config, root, principal, "read");
        requests = requests.filter((r) => tenancy.orgRootRequestAccessAllowed(config, r, root, principal));
      }
      return { status: 200, body: { requests: requests.map(presentOrgRootRequest) } };
    }
    // GET /org-roots/:rootId/requests/:id
    if (method === "GET" && segments.length === 4) {
      const request = await loadRequestScoped(config, rootId, segments[3], principal); // F-04
      return { status: 200, body: { request: presentOrgRootRequest(request) } };
    }
    // GET /org-roots/:rootId/requests/:id/slot-request/:slot
    if (method === "GET" && segments.length === 6 && segments[4] === "slot-request") {
      const request = await loadRequestScoped(config, rootId, segments[3], principal); // F-04
      requireSlotOwner(config, request, segments[5], principal);
      const envelope = await wr7.getOrCreateSlotSigningRequest({ config, requestId: segments[3], slot: segments[5] });
      return { status: 200, body: { slotRequest: envelope } };
    }
    // POST /org-roots/:rootId/requests/:id/slot-signatures  { slot, response }
    if (method === "POST" && segments.length === 5 && segments[4] === "slot-signatures") {
      const b = body ?? {};
      requireSlotOwner(config, await loadRequestScoped(config, rootId, segments[3], principal), b.slot, principal); // F-04
      const request = await wr7.submitSlotSignature({ config, requestId: segments[3], slot: b.slot, response: b.response });
      return { status: 200, body: { request: presentOrgRootRequest(request) } };
    }
    // POST /org-roots/:rootId/requests/:id/signature — SINGLE-SIGNER path
    // (root genesis / rooted-vault genesis / succession), mirroring
    // /wallet/v4/requests/:id/signature's body shape.
    if (method === "POST" && segments.length === 5 && segments[4] === "signature") {
      const b = body ?? {};
      const signingRequest = await loadRequestScoped(config, rootId, segments[3], principal, { mutation: true }); // F-04
      if (config.tenancyEnforced) { // rc13 review N-02: genesis → the creator's wallet; succession → the pinned successor's wallet; nobody else reaches the finalizer
        const creator = tenancy.xOnlyOfAddress(config, signingRequest.createdBy ?? signingRequest.signerAddress);
        let allowed = creator === principal.xOnlyPubkey;
        if (!allowed && signingRequest.action === "succession") {
          const root = await wr7.loadOrgRoot(config, rootId);
          allowed = Boolean(root) && tenancy.orgRootParticipants(root).successor.has(principal.xOnlyPubkey);
        }
        if (!allowed) throw forbidden("NOT_THE_SIGNER", "only the wallet that signs this request (its creator, or the pinned successor for a succession) may attach its signature");
      }
      if (typeof b.signedSafeJson === "string") requireSignedSafeJsonShape(b.signedSafeJson); // rc12 review R-08 (a raw signatureHex succession path has its own checks)
      const request = await wr7.submitOrgRootRequestSignature({
        config,
        requestId: segments[3],
        signedSafeJson: b.signedSafeJson,
        signatureHex: b.signatureHex,
        fuelSignatureScriptHex: b.fuelSignatureScriptHex,
        signerAddress: b.signerAddress
      });
      return { status: 200, body: { request: presentOrgRootRequest(request) } };
    }
    // POST /org-roots/:rootId/requests/:id/finalize — M-of-N ONLY
    if (method === "POST" && segments.length === 5 && segments[4] === "finalize") {
      const b = body ?? {};
      await loadRequestScoped(config, rootId, segments[3], principal, { mutation: true }); // F-04
      const request = await wr7.finalizeOrgRootRequest({ config, requestId: segments[3], fuelSignatureScriptHex: b?.fuelSignatureScriptHex });
      return { status: 200, body: { request: presentOrgRootRequest(request) } };
    }
    // POST /org-roots/:rootId/requests/:id/submit
    if (method === "POST" && segments.length === 5 && segments[4] === "submit") {
      await loadRequestScoped(config, rootId, segments[3], principal, { mutation: true }); // F-04
      const request = await wr7.submitOrgRootRequest({ config, requestId: segments[3] });
      return { status: 200, body: { request: presentOrgRootRequest(request), txId: request.txId } };
    }
    // POST /org-roots/:rootId/requests/:id/reject  { reason }
    if (method === "POST" && segments.length === 5 && segments[4] === "reject") {
      await loadRequestScoped(config, rootId, segments[3], principal, { mutation: true }); // F-04
      const request = await wr7.rejectOrgRootRequest({ config, requestId: segments[3], reason: body?.reason });
      return { status: 200, body: { request: presentOrgRootRequest(request) } };
    }
  }

  throw orgRootsError(404, "NOT_FOUND", "unknown org-roots route");
}

/*
 * /wallet/v7/requests — delegate spend / token deposit on a rooted
 * v0.7-payment vault (no root input; the existing wallet/v4 build->
 * sign->submit->reconcile pattern), EXTENDED (Wave 2 Track E) with the
 * v0.7-payment-hd HIERARCHICAL-DELEGATION CANDIDATE's five spend/
 * delegation entrypoints + its own tokenDeposit + its genesis follow-up
 * (signature/submit/reject) — routed by which manifest family the
 * vaultId actually resolves to (a v0.7-payment vault and a
 * v0.7-payment-hd vault never share a vaultId, so this is unambiguous),
 * or, for a request-id GET/signature/submit/reject, by which durable
 * request schema the id resolves to (a v0.7-payment request never
 * collides with a v0.7-payment-hd request id — both are random UUIDs).
 */
async function dispatchWalletV7(config, method, segments, query, body, principal) {
  // POST /wallet/v7/requests  { vaultId, action, params, signerAddress }
  if (method === "POST" && segments.length === 3 && segments[2] === "requests") {
    const b = body ?? {};
    await requireRootedBuildAuthority(config, principal, b.vaultId, b.signerAddress); // F-04
    if (wr7kas.KAS_ACTIONS.has(b.action)) {
      /* v0.7 enablement: a delegate spend on a rooted KAS vault (only the KAS family carries `agentSpend`) */
      const request = await wr7kas.buildKasWalletRequest({ config, vaultId: b.vaultId, action: b.action, params: b.params ?? {}, signerAddress: b.signerAddress });
      return { status: 201, body: { request: presentKasWalletRequest(request) } };
    }
    if (wr7hd.HD_ACTIONS.has(b.action) || b.action === "tokenDeposit") {
      /* tokenDeposit is shared between the payment and HD families —
       * disambiguate by which manifest the vaultId actually resolves to. */
      const hdManifest = b.action === "tokenDeposit" ? await loadManifestV7Hd(config, b.vaultId) : true;
      if (hdManifest) {
        const request = await wr7hd.buildHdWalletRequest({ config, vaultId: b.vaultId, action: b.action, params: b.params ?? {}, signerAddress: b.signerAddress });
        return { status: 201, body: { request } };
      }
    }
    const request = await wr7.buildV7WalletRequest({ config, vaultId: b.vaultId, action: b.action, params: b.params ?? {}, signerAddress: b.signerAddress });
    return { status: 201, body: { request: presentV7WalletRequest(request) } };
  }
  // GET /wallet/v7/vaults — every rooted vault this principal TAKES PART IN (v0.7 enablement, 2026-09-10): a delegate or a
  // vault-level approver is not a participant of the organizational ROOT (it cannot read /org-roots/:id), yet it must find
  // the vault it pays from / approves for. Presented summaries only; tenant-scoped through the same any-generation
  // access rule the request routes use (owner / agent / approver); self-hosted mode lists every rooted vault.
  if (method === "GET" && segments.length === 3 && segments[2] === "vaults") {
    const kas = await wr7kas.listRootedKasVaultsV7(config, {});
    const payment = await listRootedVaultsV7(config, {});
    const out = [];
    for (const [version, list, present] of [["v7kas", kas, presentRootedKasVaultSummary], ["v7", payment, presentRootedVaultSummary]]) {
      for (const manifest of list) {
        if (config.tenancyEnforced && !(await tenancy.anyVaultAccessAllowed(config, { version, manifest }, principal, "read"))) continue;
        out.push(present(manifest));
      }
    }
    return { status: 200, body: { vaults: out } };
  }
  // GET /wallet/v7/requests?vaultId=
  if (method === "GET" && segments.length === 3 && segments[2] === "requests") {
    let requests = await wr7.listV7WalletRequests(config, { vaultId: query?.vaultId });
    let hdRequests = await wr7hd.listHdWalletRequests(config, { vaultId: query?.vaultId });
    let kasRequests = await wr7kas.listKasWalletRequests(config, { vaultId: query?.vaultId });
    if (config.tenancyEnforced) { // F-04: tenant-scoped listing
      const cache = new Map();
      const keep = async (list) => { const out = []; for (const r of list) if (await walletRequestVisible(config, principal, r, cache)) out.push(r); return out; };
      requests = await keep(requests);
      hdRequests = await keep(hdRequests);
      kasRequests = await keep(kasRequests);
    }
    return { status: 200, body: { requests: [...requests.map(presentV7WalletRequest), ...hdRequests.map((r) => ({ ...r, ...wr7hd.hdPresentation(r.build ?? {}) })), ...kasRequests.map(presentKasWalletRequest)] } };
  }
  // GET /wallet/v7/requests/:id
  if (method === "GET" && segments.length === 4 && segments[2] === "requests") {
    const request = await wr7.loadV7WalletRequest(config, segments[3]);
    if (request) { await requireWalletRequest(config, principal, request); return { status: 200, body: { request: presentV7WalletRequest(request) } }; } // F-04
    const hdRequest = await wr7hd.loadHdWalletRequest(config, segments[3]);
    if (hdRequest) { await requireWalletRequest(config, principal, hdRequest); return { status: 200, body: { request: { ...hdRequest, ...wr7hd.hdPresentation(hdRequest.build ?? {}) } } }; }
    const kasRequest = await wr7kas.loadKasWalletRequest(config, segments[3]);
    if (kasRequest) { await requireWalletRequest(config, principal, kasRequest); return { status: 200, body: { request: presentKasWalletRequest(kasRequest) } }; }
    throw orgRootsError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
  }
  // POST /wallet/v7/requests/:id/signature  { signedSafeJson }
  if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "signature") {
    const b = body ?? {};
    if (typeof b.signedSafeJson !== "string" || !b.signedSafeJson.trim()) throw orgRootsError(400, "BAD_SIGNATURE", "signedSafeJson is required");
    const existingHd = await wr7hd.loadHdWalletRequest(config, segments[3]);
    const existingKas = existingHd ? null : await wr7kas.loadKasWalletRequest(config, segments[3]);
    const signingRequest = await requireWalletRequest(config, principal, existingHd ?? existingKas ?? (await wr7.loadV7WalletRequest(config, segments[3])), { mutation: true }); // F-04
    if (config.tenancyEnforced) { // rc13 review N-02: only the signer's wallet reaches the finalizer
      const signer = tenancy.xOnlyOfAddress(config, signingRequest.signerAddress);
      if (!signer || signer !== principal.xOnlyPubkey) throw forbidden("NOT_THE_SIGNER", "only the wallet that signs this request may attach its signature");
    }
    requireSignedSafeJsonShape(b.signedSafeJson); // rc12 review R-08
    if (existingHd) {
      const request = await wr7hd.finalizeHdWalletRequest({ config, requestId: segments[3], signedSafeJson: b.signedSafeJson });
      return { status: 200, body: { request } };
    }
    if (existingKas) {
      const request = await wr7kas.finalizeKasWalletRequest({ config, requestId: segments[3], signedSafeJson: b.signedSafeJson });
      return { status: 200, body: { request: presentKasWalletRequest(request) } };
    }
    const request = await wr7.finalizeV7WalletRequest({ config, requestId: segments[3], signedSafeJson: b.signedSafeJson });
    return { status: 200, body: { request: presentV7WalletRequest(request) } };
  }
  // POST /wallet/v7/requests/:id/submit
  if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "submit") {
    const existingHd = await wr7hd.loadHdWalletRequest(config, segments[3]);
    const existingKas = existingHd ? null : await wr7kas.loadKasWalletRequest(config, segments[3]);
    await requireWalletRequest(config, principal, existingHd ?? existingKas ?? (await wr7.loadV7WalletRequest(config, segments[3])), { mutation: true }); // F-04
    if (existingHd) {
      const request = await wr7hd.submitHdWalletRequest({ config, requestId: segments[3] });
      return { status: 200, body: { request, txId: request.txId } };
    }
    if (existingKas) {
      const request = await wr7kas.submitKasWalletRequest({ config, requestId: segments[3] });
      return { status: 200, body: { request: presentKasWalletRequest(request), txId: request.txId } };
    }
    const request = await wr7.submitV7WalletRequest({ config, requestId: segments[3] });
    return { status: 200, body: { request: presentV7WalletRequest(request), txId: request.txId } };
  }
  // POST /wallet/v7/requests/:id/approvals  { approverAddress, signedSafeJson|signatureHex } — v0.7-kas ONLY
  // (v0.7 enablement, 2026-09-10): ONE vault-level approver's 65-byte SIG_HASH_ALL signature over the frozen covenant
  // input of an ABOVE-THRESHOLD delegate spend. The approver's authority is its approval signature alone: it must be
  // the signed-in wallet AND one of the vault's approver slots (403 NOT_AN_APPROVER); it never reaches the request
  // lifecycle (signature/submit/reject) — the external-approver rule of the v4 family, applied to this profile.
  if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "approvals") {
    const b = body ?? {};
    const kasRequest = await wr7kas.loadKasWalletRequest(config, segments[3]);
    await requireWalletRequest(config, principal, kasRequest); // F-04: visibility (404 non-oracle for strangers)
    if (config.tenancyEnforced) {
      const approver = tenancy.xOnlyOfAddress(config, b.approverAddress);
      if (!approver) throw orgRootsError(400, "BAD_APPROVER", "approverAddress must be a valid address for this network");
      if (approver !== principal.xOnlyPubkey) throw forbidden("SIGNER_NOT_PRINCIPAL", "an approval is attached only by the approver's own signed-in wallet");
      const loaded = await loadAnyManifestAll(config, kasRequest.vaultId);
      const roles = loaded ? await tenancy.rootedVaultRoles(config, loaded) : null;
      if (!roles || !roles.approvers.has(approver)) throw forbidden("NOT_AN_APPROVER", "only one of this vault's approver slots may attach an approval");
    }
    if (typeof b.signedSafeJson === "string") requireSignedSafeJsonShape(b.signedSafeJson); // rc12 review R-08
    const result = await wr7kas.collectApprovalKas({ config, requestId: segments[3], approverAddress: b.approverAddress, signedSafeJson: b.signedSafeJson, signatureHex: b.signatureHex });
    return { status: 200, body: { request: presentKasWalletRequest(result.request), approvals: result.approvals } };
  }
  // POST /wallet/v7/requests/:id/reject
  if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "reject") {
    const existingHd = await wr7hd.loadHdWalletRequest(config, segments[3]);
    const existingKas = existingHd ? null : await wr7kas.loadKasWalletRequest(config, segments[3]);
    await requireWalletRequest(config, principal, existingHd ?? existingKas ?? (await wr7.loadV7WalletRequest(config, segments[3])), { mutation: true }); // F-04
    if (existingHd) {
      const request = await wr7hd.markHdWalletRejected(config, segments[3]);
      return { status: 200, body: { request } };
    }
    if (existingKas) {
      const request = await wr7kas.markKasWalletRejected(config, segments[3]);
      return { status: 200, body: { request } };
    }
    const request = await wr7.markV7WalletRejected(config, segments[3]);
    if (!request) throw orgRootsError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
    return { status: 200, body: { request: presentV7WalletRequest(request) } };
  }
  throw orgRootsError(404, "NOT_FOUND", "unknown wallet/v7 route");
}

module.exports = {
  dispatch,
  AUTHORITY_MODEL,
  presentOrgRootSummary,
  presentOrgRootFull,
  presentOrgRootRequest,
  presentRootedVaultSummary,
  presentRootedKasVaultSummary,
  presentKasWalletRequest,
  presentV7WalletRequest,
  mapError
};
