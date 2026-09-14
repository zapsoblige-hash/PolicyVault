"use strict";

/*
 * PolicyVault v0.5 (FROZEN token controller) / v0.6 (FROZEN optional-
 * atomic-composability controller) wallet-request routes — Wave 2 Track E
 * (docs/postlaunch/v0.7-app-surface-contract.md §6.1). Mirrors the shape
 * and discipline of server/src/org-roots.js's /wallet/v7 dispatch: this
 * module ONLY orchestrates HTTP shape (route matching, presentation,
 * closed refusal codes) — every funds-relevant decision stays in
 * sdk/src/wallet-requests-v5.js / -v6.js / sdk/src/vault-builders-v5.js /
 * -v6.js. No server-only financial fact is introduced.
 *
 * Route family (identical shape for v5 and v6 — see the app-surface
 * contract table):
 *   POST   /wallet/v{5,6}/create
 *   POST   /wallet/v{5,6}/requests
 *   GET    /wallet/v{5,6}/requests[?vaultId=]
 *   GET    /wallet/v{5,6}/requests/:id
 *   POST   /wallet/v{5,6}/requests/:id/signature
 *   POST   /wallet/v{5,6}/requests/:id/submit
 *   POST   /wallet/v{5,6}/requests/:id/reject
 */

const wr5 = require("../../sdk/src/wallet-requests-v5");
const wr6 = require("../../sdk/src/wallet-requests-v6");
const tenancy = require("./tenancy");
const { loadAnyManifestAll } = require("./manifest-any");

/*
 * rc11 internal security review F-04 (2026-09-04): this surface was
 * dispatched WITHOUT the request context, so in hosted mode any caller
 * (even unauthenticated) could create controllers, build requests into
 * foreign inboxes, list every tenant's requests and sign / submit / reject
 * them. Hosted tenancy now mirrors the v4 rule set exactly:
 *   create   — signerAddress (the funding owner) must be the principal;
 *   requests — principal holds build authority on the vault (owner or
 *              registered agent); signer is a participant; an agent builds
 *              only for its own key; owner may build for its own agents;
 *   list/GET — the request's signer or a vault participant;
 *   mutate   — the request's signer or a wallet with build authority.
 * Foreign objects answer the non-oracle 404. Self-hosted mode unchanged.
 */
/* rc12 review R-08: a malformed wallet payload answers a CLOSED code/message (400 BAD_SIGNATURE), never the text of an internal TypeError. */
function requireSignedSafeJsonShape(signedSafeJson) {
  let parsed;
  try {
    parsed = JSON.parse(signedSafeJson);
  } catch {
    throw surfaceError(400, "BAD_SIGNATURE", "signedSafeJson must be the wallet's signed Safe JSON transaction");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.inputs) || parsed.inputs.length === 0 || !parsed.inputs.every((i) => i && typeof i === "object")) {
    throw surfaceError(400, "BAD_SIGNATURE", "signedSafeJson must carry a non-empty inputs[] array of signed inputs");
  }
}
/* rc13 review N-02: a signature-bearing route is for the request's SIGNER only — another participant could otherwise burn the request into a terminal SIGNATURE_INVALID state. */
function requireRequestSigner(config, principal, request) {
  if (!config.tenancyEnforced || !request) return;
  const signer = xOnly(config, request.signerAddress);
  if (!signer || signer !== principal.xOnlyPubkey) throw surfaceError(403, "NOT_THE_SIGNER", "only the wallet that signs this request may attach its signature");
}
function xOnly(config, address) {
  return tenancy.xOnlyOfAddress(config, address);
}
async function loadVaultScoped(config, vaultId) {
  if (typeof vaultId !== "string" || !vaultId) return null;
  try {
    return await loadAnyManifestAll(config, vaultId);
  } catch {
    return null;
  }
}
async function requireTokenBuildAuthority(config, principal, wallet, vaultId, signerAddress) {
  if (!config.tenancyEnforced) return;
  const loaded = await loadVaultScoped(config, vaultId);
  if (!loaded || loaded.version !== wallet) throw surfaceError(404, "VAULT_NOT_FOUND", `no ${wallet} vault ${vaultId}`);
  await tenancy.requireAnyVaultAccess(config, loaded, principal, "build");
  const roles = tenancy.vaultRoles(loaded);
  const signerXOnly = xOnly(config, signerAddress);
  if (!signerXOnly) throw surfaceError(400, "BAD_SIGNER", "signerAddress must be a valid address for this network");
  const key = principal.xOnlyPubkey;
  if (!roles.owner.has(signerXOnly) && !roles.agents.has(signerXOnly)) throw surfaceError(403, "SIGNER_NOT_PARTICIPANT", "signerAddress is not a participant of this vault — a request is never built into a stranger's inbox");
  if (!roles.owner.has(key) && signerXOnly !== key) throw surfaceError(403, "SIGNER_NOT_PRINCIPAL", "an agent builds requests only for its own key; only the vault owner may build for its registered agents");
}
async function requestVisible(config, principal, request, cache) {
  if (!config.tenancyEnforced) return true;
  const signer = xOnly(config, request.signerAddress);
  if (signer && signer === principal.xOnlyPubkey) return true;
  const vaultId = request.vaultId;
  if (typeof vaultId !== "string") return false;
  if (!cache.has(vaultId)) cache.set(vaultId, await loadVaultScoped(config, vaultId));
  const loaded = cache.get(vaultId);
  return loaded ? tenancy.anyVaultAccessAllowed(config, loaded, principal, "read") : false;
}
async function requireRequestAccess(config, principal, request, requestId, { mutation = false } = {}) {
  if (!request) throw surfaceError(404, "REQUEST_NOT_FOUND", `no request ${requestId}`);
  if (!config.tenancyEnforced) return request;
  const cache = new Map();
  if (!(await requestVisible(config, principal, request, cache))) throw surfaceError(404, "REQUEST_NOT_FOUND", `no request ${requestId}`);
  if (mutation) {
    const signer = xOnly(config, request.signerAddress);
    const loaded = cache.has(request.vaultId) ? cache.get(request.vaultId) : await loadVaultScoped(config, request.vaultId);
    const mayBuild = loaded ? await tenancy.anyVaultAccessAllowed(config, loaded, principal, "build") : false;
    if (!(signer === principal.xOnlyPubkey || mayBuild)) throw surfaceError(403, "REQUEST_FORBIDDEN", "this wallet may review this request; it cannot sign, submit or reject it");
  }
  return request;
}

function surfaceError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/*
 * Map an SDK error CODE to an HTTP status. Every closed code named in the
 * app-surface contract §6.1 gets its own row; a request-state name used
 * as its own code (v4/v7 convention: "request is SIGNED, not BUILT")
 * maps to 409 (a lifecycle conflict, not a validation failure); anything
 * unrecognized is 422 (a validated refusal, never a raw 500).
 */
const STATUS_BY_CODE = Object.freeze({
  REQUEST_NOT_FOUND: 404,
  VAULT_NOT_FOUND: 404,
  VAULT_TERMINAL: 409,
  CONTRACT_VERSION_MISMATCH: 422,
  UNKNOWN_COVENANT_VERSION: 422,
  UNKNOWN_ACTION: 422,
  UNKNOWN_VERSION: 422,
  VENUE_PROFILE_UNSUPPORTED: 422,
  ASSET_DESCRIPTOR_INVALID: 422,
  TOKEN_TEMPLATE_MISMATCH: 422,
  TEMPLATE_PIN_MISMATCH: 422,
  TEMPLATE_PIN_MISSING: 422,
  DESCRIPTOR_PIN_MISMATCH: 422,
  DESCRIPTOR_MISMATCH: 422,
  WRONG_TOKEN_FAMILY: 422,
  TOKEN_NOT_OWNED: 422,
  TOKEN_MINTER_POSITION: 422,
  TOKEN_POSITION_REQUIRED: 422,
  TOKEN_POSITION_ALREADY_HELD: 409,
  USER_POSITION_REQUIRED: 422,
  USER_POSITION_NOT_P2PK: 422,
  AGENT_ROOT_MISMATCH: 422,
  AGENT_PROOF_INVALID: 422,
  RECIPIENT_ROOT_MISMATCH: 422,
  RECIPIENT_PROOF_INVALID: 422,
  SWAP_ROOT_MISMATCH: 422,
  SWAP_PROOF_INVALID: 422,
  PROFILE_PIN_MISMATCH: 422,
  POOL_PIN_MISMATCH: 422,
  POOL_STATE_MISMATCH: 422,
  POOL_VALUE_MISMATCH: 422,
  POOL_TEMPLATE_MISMATCH: 422,
  POOL_FEE_MISMATCH: 422,
  POOL_REQUIRED: 422,
  WRONG_POOL_FAMILY: 422,
  CARRY_TOO_LARGE: 422,
  CARRY_MISMATCH: 422,
  ZERO_DEPOSIT: 422,
  ZERO_SPEND: 422,
  INSUFFICIENT_TOKENS: 422,
  RESERVE_OVER_FEE: 422,
  RESERVE_UNDERFLOW: 422,
  INSUFFICIENT_FUEL: 422,
  INSUFFICIENT_FUNDS: 422,
  FUEL_REQUIRED: 422,
  FUEL_FORBIDDEN: 422,
  DESCRIPTOR_REQUIRED: 422,
  CONTROLLER_REQUIRED: 422,
  AMOUNT_INVALID: 422,
  STORAGE_MASS_OVER_LIMIT: 422,
  DEADLINE_PASSED: 409,
  DAA_REQUIRED: 422,
  BAD_SIGNATURE: 400,
  WALLET_REJECTED: 422,
  SIGNATURE_INVALID: 422,
  SIGHASH_NOT_ALL: 422,
  BUILD_FAILED: 422,
  STALE: 409,
  CLAIM_CONFLICT: 409,
  VAULT_ID_IN_USE: 409, // RC33-ID-01 (2026-09-11): global vault-record uniqueness (sdk/src/vault-identity.js)
  NETWORK_MISMATCH: 409,
  TXID_MISMATCH: 500,
  SUBMISSION_REJECTED: 409,
  RECONCILIATION_REQUIRED: 409,
  CANNOT_REJECT: 409,
  /* request-state-as-code convention (v4/v7): the request's CURRENT
   * STATE is used as the code when an action is attempted from the wrong
   * lifecycle state. */
  BUILT: 409,
  SIGNED: 409,
  SUBMITTING: 409,
  SUBMITTED: 409,
  CHAIN_VERIFIED: 409,
  WALLET_REJECTED_STATE: 409
});

function mapError(error) {
  if (error && error.status) return error;
  const code = error && error.code;
  const status = (code && STATUS_BY_CODE[code]) || 422;
  return surfaceError(status, code || "TOKEN_SURFACE_ERROR", (error && error.message) || "token-surface request failed");
}

/* ------------------------------------------------------------------ */
/* presentation                                                        */
/* ------------------------------------------------------------------ */

function presentRequestV5(request) {
  if (!request) return null;
  const { build, transaction, covenantSignatureHex, ...rest } = request;
  void build;
  return { ...rest, transaction: { unsignedSafeJson: transaction?.unsignedSafeJson, signInputs: transaction?.signInputs }, authorityModel: wr5.AUTHORITY_MODEL_V5, status: "FROZEN" };
}
function presentRequestV6(request) {
  if (!request) return null;
  const { build, transaction, covenantSignatureHex, ...rest } = request;
  void build;
  void covenantSignatureHex;
  return { ...rest, transaction: { unsignedSafeJson: transaction?.unsignedSafeJson, signInputs: transaction?.signInputs }, authorityModel: wr6.AUTHORITY_MODEL_V6, status: "FROZEN" };
}

/* ------------------------------------------------------------------ */
/* route dispatch                                                      */
/* ------------------------------------------------------------------ */

async function dispatchWalletTokenSurface(config, method, segments, query, body, ctx) {
  const wallet = segments[1]; // "v5" | "v6"
  // F-04: hosted mode REQUIRES a principal (wallet session or machine credential).
  const { requestAuthPrincipal } = require("./api");
  const principal = await requestAuthPrincipal(config, ctx, { required: !!config.tenancyEnforced });
  const wr = wallet === "v5" ? wr5 : wr6;
  const presentRequest = wallet === "v5" ? presentRequestV5 : presentRequestV6;
  const buildCreate = wallet === "v5" ? wr5.buildCreateWalletRequestV5 : wr6.buildCreateWalletRequestV6;
  const buildRequest = wallet === "v5" ? wr5.buildWalletRequestV5 : wr6.buildWalletRequestV6;
  const submitSignature = wallet === "v5" ? wr5.submitSignatureV5 : wr6.submitSignatureV6;
  const submitRequest = wallet === "v5" ? wr5.submitWalletRequestV5 : wr6.submitWalletRequestV6;
  const markRejected = wallet === "v5" ? wr5.markWalletRejectedV5 : wr6.markWalletRejectedV6;
  const loadRequest = wallet === "v5" ? wr5.loadWalletRequestV5 : wr6.loadWalletRequestV6;
  const listRequests = wallet === "v5" ? wr5.listWalletRequestsV5 : wr6.listWalletRequestsV6;

  try {
    // POST /wallet/v{5,6}/create
    if (method === "POST" && segments.length === 3 && segments[2] === "create") {
      const b = body ?? {};
      if (config.tenancyEnforced) { // F-04: the funding owner IS the caller
        const signerXOnly = xOnly(config, b.signerAddress);
        if (!signerXOnly) throw surfaceError(400, "BAD_SIGNER", "signerAddress must be a valid address for this network");
        if (signerXOnly !== principal.xOnlyPubkey) throw surfaceError(403, "SIGNER_NOT_PRINCIPAL", "hosted mode: a controller is created only by the signed-in owner wallet (or the machine credential's creating wallet)");
      }
      const request =
        wallet === "v5"
          ? await buildCreate({ config, label: b.label, descriptor: b.descriptor, templateIndex: b.templateIndex, initialAgents: b.initialAgents, feeReserveKas: b.feeReserveKas, signerAddress: b.signerAddress, funding: b.funding, vaultId: b.vaultId })
          : await buildCreate({ config, label: b.label, descriptor: b.descriptor, templateIndex: b.templateIndex, initialAgents: b.initialAgents, initialSwapPolicies: b.initialSwapPolicies, feeReserveKas: b.feeReserveKas, swapPrincipalKas: b.swapPrincipalKas, signerAddress: b.signerAddress, funding: b.funding, vaultId: b.vaultId });
      return { status: 201, body: { request: presentRequest(request) } };
    }
    // POST /wallet/v{5,6}/requests
    if (method === "POST" && segments.length === 3 && segments[2] === "requests") {
      const b = body ?? {};
      await requireTokenBuildAuthority(config, principal, wallet, b.vaultId, b.signerAddress); // F-04
      const request = await buildRequest({ config, vaultId: b.vaultId, action: b.action, params: b.params ?? {}, signerAddress: b.signerAddress });
      return { status: 201, body: { request: presentRequest(request) } };
    }
    // GET /wallet/v{5,6}/requests?vaultId=
    if (method === "GET" && segments.length === 3 && segments[2] === "requests") {
      let requests = await listRequests(config, { vaultId: query?.vaultId });
      if (config.tenancyEnforced) { // F-04: tenant-scoped listing
        const cache = new Map();
        const kept = [];
        for (const r of requests) if (await requestVisible(config, principal, r, cache)) kept.push(r);
        requests = kept;
      }
      return { status: 200, body: { requests: requests.map(presentRequest) } };
    }
    // GET /wallet/v{5,6}/requests/:id
    if (method === "GET" && segments.length === 4 && segments[2] === "requests") {
      const request = await requireRequestAccess(config, principal, await loadRequest(config, segments[3]), segments[3]); // F-04
      return { status: 200, body: { request: presentRequest(request) } };
    }
    // POST /wallet/v{5,6}/requests/:id/signature
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "signature") {
      const b = body ?? {};
      if (typeof b.signedSafeJson !== "string" || !b.signedSafeJson.trim()) throw surfaceError(400, "BAD_SIGNATURE", "signedSafeJson is required");
      const signingRequest = await requireRequestAccess(config, principal, await loadRequest(config, segments[3]), segments[3], { mutation: true }); // F-04
      requireRequestSigner(config, principal, signingRequest); // rc13 review N-02 (all families): only the signer's wallet reaches the finalizer
      requireSignedSafeJsonShape(b.signedSafeJson); // rc12 review R-08: closed refusal, never a raw TypeError message
      const request = await submitSignature({ config, requestId: segments[3], signedSafeJson: b.signedSafeJson });
      return { status: 200, body: { request: presentRequest(request) } };
    }
    // POST /wallet/v{5,6}/requests/:id/submit
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "submit") {
      await requireRequestAccess(config, principal, await loadRequest(config, segments[3]), segments[3], { mutation: true }); // F-04
      const request = await submitRequest({ config, requestId: segments[3] });
      return { status: 200, body: { request: presentRequest(request), txId: request.txId } };
    }
    // POST /wallet/v{5,6}/requests/:id/reject
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "reject") {
      await requireRequestAccess(config, principal, await loadRequest(config, segments[3]), segments[3], { mutation: true }); // F-04
      const request = await markRejected(config, segments[3]);
      if (!request) throw surfaceError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
      return { status: 200, body: { request: presentRequest(request) } };
    }
  } catch (error) {
    throw mapError(error);
  }
  throw surfaceError(404, "NOT_FOUND", `unknown wallet/${wallet} route`);
}

module.exports = { dispatchWalletTokenSurface, mapError, presentRequestV5, presentRequestV6 };
