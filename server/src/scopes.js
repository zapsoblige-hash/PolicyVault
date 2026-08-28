"use strict";

/*
 * Deny-by-default SCOPE model for machine (AI/agent) identities
 * (completion-standard surface 6; docs/postlaunch/platform-agent-api-spec.md).
 *
 * Scopes gate MACHINE PRINCIPALS ONLY. A hosted wallet-session principal
 * (a human who signed in with a real wallet) is NEVER scope-checked here —
 * it already goes through the full tenancy + covenant-signer authorization
 * pipeline unchanged (server/src/tenancy.js, sdk assertSignerAuthorizedV4).
 * Scopes are an ADDITIONAL, narrower gate layered on top of a machine
 * identity's inherited tenancy (server/src/machine-identity.js: a machine
 * principal's xOnlyPubkey is its creating wallet's xOnlyPubkey, so it can
 * never see/touch more than that wallet already could — scopes can only
 * narrow that further, never widen it).
 *
 * Derived honestly from the real route map in server/src/api.js (mission
 * directive: "derive sensible scopes from the actual route map"). Unknown
 * routes and unknown scopes both FAIL CLOSED — a new route added later
 * without an entry here is unreachable by any machine identity until a
 * human deliberately classifies it (never silently open).
 */

const SCOPES = Object.freeze([
  "read:vaults",
  "read:requests",
  "read:governance",
  "read:risk",
  "read:organizations",
  "read:manifests",
  "read:network",
  "read:audit",
  "request:build",
  "request:sign",
  "request:submit",
  "request:reject",
  "request:break-glass",
  "governance:propose",
  "governance:approve",
  "governance:cancel",
  "risk:release",
  "vaults:reconcile",
  "vaults:suspend-agents",
  "organizations:manage",
  "read:events",
  "webhooks:manage",
  "read:metrics",
  "read:notifications",
  "notifications:manage"
]);
const SCOPE_SET = new Set(SCOPES);

function isKnownScope(scope) {
  return typeof scope === "string" && SCOPE_SET.has(scope);
}

/* Actions that bypass governance/risk entirely (governance-spec §6.1
 * "break-glass"). A machine identity holding ordinary request:build may
 * still attempt these API calls — the covenant/build pipeline is
 * unaffected — but the API layer additionally requires the operator to
 * have explicitly granted request:break-glass, so a compromised or
 * over-eager machine credential cannot freeze or terminally recover a
 * vault merely because it can build ordinary spends/policy changes.
 * (Restated: this is an API-surface conservatism, not a covenant rule —
 * the covenant enforces owner-signature authority over these actions
 * regardless of what the API allows an automated caller to ATTEMPT.) */
const BREAK_GLASS_ACTIONS = Object.freeze(new Set(["ownerPause", "ownerRecover"]));

/* Routes reachable with NO principal/scope at all (public, exactly like
 * /health today) — never gated, whether the caller is a machine identity,
 * a wallet session, or unauthenticated. */
function isPublicRoute(method, segments) {
  if (segments[0] === "health") return true;
  if (method === "GET" && segments.length === 1 && segments[0] === "support") return true;
  if (method === "GET" && segments.length === 1 && segments[0] === "capabilities") return true;
  if (segments[0] === "auth") return true; // wallet sign-in; not a machine-identity concern
  if (method === "POST" && segments.length === 2 && segments[0] === "identity" && segments[1] === "resolve-address") return true;
  return false;
}

/*
 * Routes NEVER reachable by a machine principal, regardless of any scope
 * it holds — a structural rule, not a grantable capability:
 *   - /identities* (machine-identity management: creating, listing,
 *     rotating, or revoking machine identities/credentials is a wallet-
 *     session-only human action; a token can never mint or widen its own
 *     — or a sibling's — authority; conservative-by-design per the
 *     mission's break-glass instruction).
 *   - /wallet/dev-accounts, /wallet/dev-sign (TEST-ONLY dev signer,
 *     already testnet-gated and env-gated; a machine credential gets no
 *     special path near even a test keyring).
 */
function isWalletSessionOnlyRoute(method, segments) {
  if (segments[0] === "identities") return true;
  if (segments[0] === "wallet" && (segments[1] === "dev-accounts" || segments[1] === "dev-sign")) return true;
  return false;
}

/*
 * requiredScopesFor(method, segments, body) -> string[] | null.
 * null means "not a machine-reachable route at all" (isWalletSessionOnlyRoute)
 * — distinct from an ordinary unmapped route, which also fails closed but
 * with a different, more actionable error code (see server/src/api.js).
 * An empty array is intentionally impossible: every non-public,
 * non-wallet-session-only route requires at least one real scope.
 */
function requiredScopesFor(method, segments, body) {
  if (isPublicRoute(method, segments)) return [];
  if (isWalletSessionOnlyRoute(method, segments)) return null;

  const s0 = segments[0];

  if (s0 === "vaults") {
    if (method === "POST" && segments[2] === "reconcile") return ["vaults:reconcile"];
    // Hosted-layer agent suspend/unsuspend (surface 21 residual): a
    // dedicated deny-by-default scope — request:build/reconcile etc. never
    // imply it; the route ALSO requires vault-OWNER tenancy.
    if (method === "POST" && segments[2] === "agent-suspensions") return ["vaults:suspend-agents"];
    if (method === "GET") return ["read:vaults"];
    return null; // no other /vaults mutation exists
  }
  // Operational metrics (surface 25): aggregate non-secret numbers only;
  // scope-gated for machine credentials (see api.js for the route's own
  // principal requirements in hosted mode).
  if (s0 === "metrics" && method === "GET") return ["read:metrics"];
  if (s0 === "audit" && method === "GET") return ["read:audit"];
  if (s0 === "manifests" && method === "GET") return ["read:manifests"];
  if (s0 === "network" && method === "GET") return ["read:network"];

  if (s0 === "wallet") {
    const s1 = segments[1];
    if (s1 === "fuel" && method === "GET") return ["read:network"];
    if (s1 === "v4") {
      const tail = segments[4];
      if (method === "GET") return ["read:requests"];
      if (segments[2] === "create" || (segments[2] === "requests" && segments.length === 3) || segments[2] === "simulate") {
        const scopes = ["request:build"];
        if (body && typeof body.action === "string" && BREAK_GLASS_ACTIONS.has(body.action)) scopes.push("request:break-glass");
        return scopes;
      }
      if (tail === "submit" || tail === "genesis-submit") return ["request:submit"];
      if (tail === "signature" || tail === "approvals") return ["request:sign"];
      if (tail === "reject") return ["request:reject"];
      return null;
    }
    // legacy v0.2 wallet routes
    if (method === "GET") return ["read:requests"];
    if (s1 === "create" || (s1 === "requests" && segments.length === 2)) return ["request:build"];
    if (s1 === "requests" && segments[3] === "signature") return ["request:sign"];
    if (s1 === "requests" && segments[3] === "reject") return ["request:reject"];
    return null;
  }

  if (s0 === "governance") {
    if (method === "GET") return ["read:governance"];
    if (segments[1] === "proposals" && segments.length === 2) return ["governance:propose"];
    if (segments[1] === "proposals" && segments[3] === "approvals") return ["governance:approve"];
    if (segments[1] === "proposals" && segments[3] === "cancel") return ["governance:cancel"];
    return null;
  }

  if (s0 === "risk" && segments[1] === "evaluations") {
    if (method === "GET") return ["read:risk"];
    if (segments[3] === "release") return ["risk:release"];
    return null;
  }

  if (s0 === "organizations") {
    if (method === "GET") return ["read:organizations"];
    return ["organizations:manage"];
  }

  // Asynchronous events + webhooks (surface 18). Events a machine
  // credential can poll are exactly the events its creating wallet could
  // already read (tenancy inherits from creatorXOnly); webhooks:manage
  // additionally lets the credential point deliveries of that same data
  // at a URL — a deliberate, operator-granted capability, deny-by-default
  // like everything else.
  if (s0 === "events" && method === "GET") return ["read:events"];
  if (s0 === "webhooks") return ["webhooks:manage"];

  // Human-notification rules (surface 19). Same inheritance story as
  // webhooks: a rule can only be notified of events its creating wallet
  // could already read; notifications:manage additionally lets the
  // credential point human alerts at a channel — operator-granted,
  // deny-by-default.
  if (s0 === "notifications") {
    if (method === "GET") return ["read:notifications"];
    return ["notifications:manage"];
  }

  return null; // unmapped route: deny-by-default
}

module.exports = { SCOPES, isKnownScope, BREAK_GLASS_ACTIONS, isPublicRoute, isWalletSessionOnlyRoute, requiredScopesFor };
