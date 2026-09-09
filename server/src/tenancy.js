"use strict";

/*
 * Hosted multi-tenant authorization (Phase C).
 *
 * THREE INDEPENDENT LAYERS (directive §3/§13):
 *   1. hosted authentication  — "which wallet is this session?" (auth.js)
 *   2. hosted tenancy authz   — "may this wallet SEE/EDIT this hosted
 *                                object?" (THIS module)
 *   3. Kaspa covenant authority — "did the right wallet SIGN the exact
 *                                 transaction?" (unchanged; consensus)
 * A session never implies (3). An organization role never implies (3).
 * This module governs (2) only, and only when the server enforces
 * tenancy (config.tenancyEnforced, i.e. hosted authentication is on).
 * With tenancy disabled (the released self-hosted single-operator
 * product) every gate returns "allow" — behavior is unchanged.
 *
 * TENANT ROOT = an authenticated wallet identity (its canonical x-only
 * public key). IDs are authoritative; a human-readable name never grants
 * access. Default deny: an ambiguous rule denies (directive §12).
 *
 * VAULT access derives from the COVENANT itself — a vault's participants
 * are the wallets the covenant already binds (owner / agents / approvers
 * / v0.2 delegate). No separate ownership column can disagree with the
 * covenant. Owner-role (metadata write, reconcile trigger) is the
 * template owner only. This means hosted vault visibility exactly tracks
 * on-chain participation and cannot be widened by hosted metadata.
 *
 * ORGANIZATION access uses an explicit stored owner (`tenantOwner`, the
 * creating wallet's x-only). Members with a wallet identity get READ;
 * the owner gets full control. Pre-Phase-C org records (no tenantOwner)
 * are LEGACY: readable/writable only in self-hosted mode; in hosted
 * mode they are inaccessible until claimed (fail closed — never a free
 * cross-tenant object).
 */

function tenancyError(code, message, status = 403) {
  const e = new Error(message);
  e.code = code;
  e.status = status;
  return e;
}

/* The all-zero x-only key is the covenant's EMPTY approver-slot sentinel
 * (core/model/vault-state-v4 APPROVER_SENTINEL). It can never be a real
 * secp256k1 wallet key and must never become a participant. */
const APPROVER_SLOT_SENTINEL = "0".repeat(64);

/* Role-precise covenant key sets for a LOADED manifest, by role.
 * Version-aware; unknown shapes contribute nothing (fail closed).
 *
 * SHAPE CONTRACT (2026-08-27 mainnet external-approver incident): the
 * manifests reaching this module come from loadAnyManifest, which returns
 * the NORMALIZED manifest — for v4 the live state is
 * core/model/vault-state-v4 normalizeStateV4 output, whose padded
 * approver-slot array is named `approvers`. The persisted JSON spells it
 * `approverSlots` (stateToJsonV4 renames on the way out). Reading the
 * persisted name off the normalized object silently dropped every
 * approver from vault participation, hiding vaults/requests from
 * external covenant approvers in hosted mode. Both spellings are read
 * here so neither shape can ever regress the derivation; empty-slot
 * sentinels are skipped. */
function vaultRoles(loaded) {
  const owner = new Set();
  const agents = new Set();
  const approvers = new Set();
  const delegates = new Set();
  if (!loaded || !loaded.manifest) return { owner, agents, approvers, delegates };
  const m = loaded.manifest;
  const add = (set, v) => {
    if (typeof v === "string" && /^[0-9a-f]{64}$/.test(v) && v !== APPROVER_SLOT_SENTINEL) set.add(v.toLowerCase());
  };
  if (loaded.version === "v4") {
    add(owner, m.template && m.template.owner);
    for (const entry of m.agentRegistry || []) add(agents, entry.policy ? entry.policy.agentPk : entry.agentPk);
    // Approver slots live in the live covenant state (sentinel-padded).
    const state = m.live && m.live.state ? m.live.state : null;
    const slots = state ? (state.approvers ?? state.approverSlots) : null;
    if (Array.isArray(slots)) for (const k of slots) add(approvers, k);
  } else if (loaded.version === "v2") {
    add(owner, m.template && m.template.owner);
    if (m.live && m.live.state) add(delegates, m.live.state.delegate);
  } else if (loaded.version === "v1") {
    add(owner, m.template && m.template.owner);
    add(delegates, m.policy && m.policy.delegate);
  } else if (loaded.version === "v5" || loaded.version === "v6") {
    /* rc11 review F-04: v0.5 / v0.6 token controllers — a single on-chain
     * owner (template.owner) plus the registered agent keys. */
    add(owner, m.template && m.template.owner);
    for (const entry of m.agentRegistry || []) add(agents, entry.policy ? entry.policy.agentPk : entry.agentPk);
  } else if (loaded.version === "v7") {
    /* v0.7 rooted vault: its OWNERS are the organizational root's active
     * owner slots (see rootedVaultRoles, which resolves the root record);
     * here only the vault-local agents are derivable. */
    for (const entry of m.agentRegistry || []) add(agents, entry.policy ? entry.policy.agentPk : entry.agentPk);
  } else if (loaded.version === "v7hd") {
    /* v0.7-payment-hd candidate: every delegation-forest leaf key at every
     * level is an agent participant; owners come from the root record. */
    const walk = (nodes) => {
      for (const node of nodes || []) {
        add(agents, node && node.leaf && node.leaf.pk);
        walk(node && node.kids);
      }
    };
    const forest = m.forest;
    walk(Array.isArray(forest) ? forest : forest && Array.isArray(forest.nodes) ? forest.nodes : []);
  }
  return { owner, agents, approvers, delegates };
}

/* Collect every covenant x-only key bound to a vault manifest. */
function vaultParticipants(loaded) {
  const { owner, agents, approvers, delegates } = vaultRoles(loaded);
  const others = new Set([...agents, ...approvers, ...delegates]);
  return { owner, others };
}

/*
 * Vault access decision for a principal (or null when unauthenticated).
 * `need` is "read" or "owner". Returns true/false; never throws (callers
 * choose 403 vs 404). With tenancy disabled, always true.
 */
function vaultAccessAllowed(config, loaded, principal, need) {
  if (!config.tenancyEnforced) return true;
  if (!principal) return false;
  const key = principal.xOnlyPubkey;
  const { owner, others } = vaultParticipants(loaded);
  // Network must match too: a principal authenticated on network X can
  // never reach vault state persisted for network Y (defence in depth on
  // top of the per-network data separation).
  if (loaded && loaded.manifest && loaded.manifest.networkId !== principal.networkId) return false;
  if (need === "owner") return owner.has(key);
  return owner.has(key) || others.has(key);
}

/* Organization access. `need` is "read" | "owner". */
function orgAccessAllowed(config, org, principal, need) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !org) return false;
  const key = principal.xOnlyPubkey;
  const tenantOwner = typeof org.tenantOwner === "string" ? org.tenantOwner.toLowerCase() : null;
  if (!tenantOwner) return false; // legacy/unclaimed org: inaccessible in hosted mode (fail closed)
  if (need === "owner") return tenantOwner === key;
  if (tenantOwner === key) return true;
  // members with a wallet identity may READ
  if (need === "read" && Array.isArray(org.members)) {
    return org.members.some((mem) => typeof mem.xOnlyPubkey === "string" && mem.xOnlyPubkey.toLowerCase() === key && mem.status !== "REMOVED");
  }
  return false;
}

/*
 * WALLET-REQUEST access (Phase F). A durable wallet request (build / sign
 * / approval / submit record) is a private hosted object: its review
 * carries the intended action, amount, and recipient, and its id is the
 * handle for cancel/submit. Tenancy mirrors the request's VAULT: a
 * principal may reach a request iff it is a covenant participant of the
 * request's vault (owner / agents / approvers — the same rule as vault
 * READ) OR it is the request's own signer (covers a GENESIS-create
 * request, whose vault has no manifest yet — the owner-signer is the only
 * legitimate party). Server-derived only: the request's stored
 * signerAddress/vaultId are trusted (they were fixed at build time under
 * covenant authorization), never a client-supplied body field. Default
 * deny. With tenancy disabled (self-hosted) every request is allowed —
 * released behavior unchanged.
 */
function requestAccessAllowed(config, request, principal, loadedVault) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !request) return false;
  // Signer rule (also the only rule for a not-yet-on-chain genesis vault).
  if (typeof request.signerAddress === "string") {
    try {
      const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
      if (resolveAddressIdentity(config, request.signerAddress).xOnlyPubkey === principal.xOnlyPubkey) return true;
    } catch {
      /* an unresolvable stored signer never grants access (fail closed) */
    }
  }
  // Covenant-participant rule (owner / agents / approvers of the vault).
  if (loadedVault && vaultAccessAllowed(config, loadedVault, principal, "read")) return true;
  return false;
}

/*
 * WALLET-REQUEST MUTATION rule (external-approver incident hardening,
 * 2026-08-27). Discovery / read / approval-route reachability mirror
 * vault READ (every covenant participant — owner / agents / approvers /
 * delegate — plus the request's own signer). MUTATING the request
 * lifecycle (reject/cancel, attaching the spend signature, submit)
 * additionally excludes approver-ONLY principals: an external covenant
 * approver's entire authority is their own approval signature over the
 * frozen package — never the request lifecycle. This preserves the
 * effective pre-incident authorization set (approvers, being
 * undiscoverable, could never mutate) instead of widening it silently
 * alongside the discovery fix. Same trust posture as
 * requestAccessAllowed: server-derived fields only, default deny, and
 * with tenancy disabled (self-hosted) everything is allowed unchanged.
 */
function requestMutationAllowed(config, request, principal, loadedVault) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !request) return false;
  // Signer rule (also the only rule for a not-yet-on-chain genesis vault).
  if (typeof request.signerAddress === "string") {
    try {
      const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
      if (resolveAddressIdentity(config, request.signerAddress).xOnlyPubkey === principal.xOnlyPubkey) return true;
    } catch {
      /* an unresolvable stored signer never grants access (fail closed) */
    }
  }
  if (!loadedVault || !loadedVault.manifest) return false;
  // Same defence-in-depth network equality as vaultAccessAllowed.
  if (loadedVault.manifest.networkId !== principal.networkId) return false;
  const { owner, agents, delegates } = vaultRoles(loadedVault);
  const key = principal.xOnlyPubkey;
  return owner.has(key) || agents.has(key) || delegates.has(key);
}

/*
 * Route guard helpers. In hosted mode a denied VAULT/ORG access returns
 * 404 (not 403) so the API never confirms the existence of another
 * tenant's object (directive §14 — avoid existence oracles). A missing
 * object is likewise 404. Self-hosted mode keeps the original 404-only-
 * when-absent behavior.
 */
function requireVaultAccess(config, loaded, principal, need = "read") {
  if (!loaded) throw tenancyError("VAULT_NOT_FOUND", "no such vault", 404);
  if (!vaultAccessAllowed(config, loaded, principal, need)) {
    // 404 for read (hide existence); 403 for a known participant lacking
    // the higher owner role (they already know the vault exists).
    const { owner, others } = vaultParticipants(loaded);
    const known = principal && (owner.has(principal.xOnlyPubkey) || others.has(principal.xOnlyPubkey));
    if (need === "owner" && known) throw tenancyError("VAULT_FORBIDDEN", "owner action requires the vault owner wallet", 403);
    throw tenancyError("VAULT_NOT_FOUND", "no such vault", 404);
  }
  return loaded;
}

function requireOrgAccess(config, org, principal, need = "read") {
  if (!org) throw tenancyError("ORG_NOT_FOUND", "no such organization", 404);
  if (!orgAccessAllowed(config, org, principal, need)) {
    if (need === "owner" && orgAccessAllowed(config, org, principal, "read")) {
      throw tenancyError("ORG_FORBIDDEN", "this action requires the organization owner", 403);
    }
    throw tenancyError("ORG_NOT_FOUND", "no such organization", 404);
  }
  return org;
}

/* ------------------------------------------------------------------ */
/* rc11 internal security review F-04 (2026-09-04): ON-CHAIN ORGANIZATIONAL  */
/* ROOTS and ROOTED VAULTS.                                                   */
/*                                                                            */
/* TENANT ROOT for an org root = the wallets the ROOT COVENANT ITSELF binds:  */
/* the active owner slots of its CURRENT state (durable record, normalized     */
/* through the shared core) plus the pinned successor key (read-only until a  */
/* succession). A hosted /organizations role is NEVER consulted (hosted org   */
/* != on-chain root). Rooted vaults inherit their OWNERS from the root and add */
/* their own agent keys. Default deny; foreign objects are 404 (no oracle).   */
/* ------------------------------------------------------------------ */

const ZERO_KEY = "0".repeat(64);

function xOnlyOfAddress(config, address) {
  if (typeof address !== "string") return null;
  try {
    return require("../../sdk/src/address-identity").resolveAddressIdentity(config, address).xOnlyPubkey;
  } catch {
    return null;
  }
}

/* Active owner slot keys + pinned successor of an ORG_ROOT record. */
function orgRootParticipants(root) {
  const owners = new Set();
  const successor = new Set();
  if (!root || typeof root !== "object") return { owners, successor, all: new Set() };
  let listed = null;
  try {
    const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
    const { activeOwnerSlotsV7 } = require("../../core/model/owner-set-v7");
    listed = activeOwnerSlotsV7(normalizeRootStateV7(root.state)).map((s) => s.publicKey);
  } catch {
    listed = null; // malformed durable state: fall back to the recorded slots only
  }
  const keys = listed !== null ? listed : (root.slots || []).map((s) => s && s.publicKey);
  for (const k of keys) if (typeof k === "string" && /^[0-9a-f]{64}$/.test(k) && k !== ZERO_KEY) owners.add(k.toLowerCase());
  const succ = root.template && root.template.successorPk;
  if (typeof succ === "string" && /^[0-9a-f]{64}$/.test(succ) && succ !== ZERO_KEY) successor.add(succ.toLowerCase());
  return { owners, successor, all: new Set([...owners, ...successor]) };
}

/* need: "read" (any participant) | "owner" (an ACTIVE owner slot). */
function orgRootAccessAllowed(config, root, principal, need) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !root) return false;
  if (root.networkId !== undefined && root.networkId !== principal.networkId) return false;
  const { owners, all } = orgRootParticipants(root);
  return need === "owner" ? owners.has(principal.xOnlyPubkey) : all.has(principal.xOnlyPubkey);
}

/*
 * ORG_ROOT_REQUEST access: any root participant, or the request's own creator
 * (the genesis funder before the root record exists). Mutation (signature,
 * slot-signature, finalize, submit, reject): an ACTIVE owner slot or the
 * creator; the pinned successor only for a succession request.
 */
function orgRootRequestAccessAllowed(config, request, root, principal) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !request) return false;
  const creator = xOnlyOfAddress(config, request.createdBy ?? request.signerAddress);
  if (creator && creator === principal.xOnlyPubkey) return true;
  return root ? orgRootAccessAllowed(config, root, principal, "read") : false;
}
function orgRootRequestMutationAllowed(config, request, root, principal) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !request) return false;
  const creator = xOnlyOfAddress(config, request.createdBy ?? request.signerAddress);
  if (creator && creator === principal.xOnlyPubkey) return true;
  if (!root) return false;
  const { owners, successor } = orgRootParticipants(root);
  if (owners.has(principal.xOnlyPubkey)) return true;
  return request.action === "succession" && successor.has(principal.xOnlyPubkey);
}

function requireOrgRootAccess(config, root, principal, need = "read") {
  if (!root) throw tenancyError("ROOT_NOT_FOUND", "no such organizational root", 404);
  if (!orgRootAccessAllowed(config, root, principal, need)) {
    if (need === "owner" && orgRootAccessAllowed(config, root, principal, "read")) {
      throw tenancyError("NOT_AN_ACTIVE_SLOT", "this action requires an active owner slot of the organizational root", 403);
    }
    throw tenancyError("ROOT_NOT_FOUND", "no such organizational root", 404);
  }
  return root;
}

/*
 * ROOTED VAULT roles (v7 / v7hd): owners = the root's active slots (durable
 * root record resolved by covenant id), agents = the vault's own registry /
 * forest leaves. Returns the same shape as vaultRoles plus the root.
 */
async function rootedVaultRoles(config, loaded) {
  const roles = vaultRoles(loaded);
  let root = null;
  const rootId = loaded && loaded.manifest && loaded.manifest.orgRootCovenantId;
  if (typeof rootId === "string") {
    try {
      root = await require("../../sdk/src/wallet-requests-v7").loadOrgRoot(config, rootId);
    } catch {
      root = null;
    }
  }
  if (root) for (const k of orgRootParticipants(root).owners) roles.owner.add(k);
  return { ...roles, root };
}

/* Vault access for a loaded manifest of ANY generation (async because rooted
 * vaults resolve their root). need: "read" | "owner" | "build". */
async function anyVaultAccessAllowed(config, loaded, principal, need) {
  if (!config.tenancyEnforced) return true;
  if (!principal || !loaded) return false;
  if (loaded.manifest && loaded.manifest.networkId !== undefined && loaded.manifest.networkId !== principal.networkId) return false;
  const roles = loaded.version === "v7" || loaded.version === "v7hd" ? await rootedVaultRoles(config, loaded) : vaultRoles(loaded);
  const key = principal.xOnlyPubkey;
  if (need === "owner") return roles.owner.has(key);
  if (need === "build") return roles.owner.has(key) || roles.agents.has(key) || roles.delegates.has(key);
  return roles.owner.has(key) || roles.agents.has(key) || roles.approvers.has(key) || roles.delegates.has(key);
}

async function requireAnyVaultAccess(config, loaded, principal, need = "read") {
  if (!loaded) throw tenancyError("VAULT_NOT_FOUND", "no such vault", 404);
  if (!(await anyVaultAccessAllowed(config, loaded, principal, need))) {
    const known = await anyVaultAccessAllowed(config, loaded, principal, "read");
    if (need !== "read" && known) throw tenancyError("VAULT_FORBIDDEN", need === "owner" ? "owner action requires the vault owner wallet" : "this wallet holds no build authority on this vault", 403);
    throw tenancyError("VAULT_NOT_FOUND", "no such vault", 404);
  }
  return loaded;
}

module.exports = {
  vaultRoles,
  vaultParticipants,
  vaultAccessAllowed,
  orgAccessAllowed,
  requestAccessAllowed,
  requestMutationAllowed,
  requireVaultAccess,
  requireOrgAccess,
  tenancyError,
  orgRootParticipants,
  orgRootAccessAllowed,
  orgRootRequestAccessAllowed,
  orgRootRequestMutationAllowed,
  requireOrgRootAccess,
  rootedVaultRoles,
  anyVaultAccessAllowed,
  requireAnyVaultAccess,
  xOnlyOfAddress
};
