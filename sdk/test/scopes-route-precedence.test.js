"use strict";

/*
 * PERMANENT REGRESSION — rc11 internal security review F-06 (2026-09-04).
 *
 * RED before the fix: the `/wallet/v7` scope block in server/src/scopes.js
 * sat AFTER the `s0 === "wallet"` branch's `return null`, so no machine
 * credential could ever reach POST /wallet/v7/requests ("not reachable by
 * any machine-identity scope") and GET /wallet/v7/requests was mis-scoped to
 * read:requests instead of the documented read:org-roots. The MCP tool
 * policyvault_create_v7_request was therefore dead.
 *
 * This pins the documented scope contract and the ROUTE PRECEDENCE inside
 * the wallet branch for every wallet family, so a later reorder cannot
 * silently deny (or widen) a family.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { requiredScopesFor, isWalletSessionOnlyRoute, isPublicRoute } = require("../../server/src/scopes");

const ROOT = "ab".repeat(32);
const ID = "00000000-0000-4000-8000-000000000001";

test("F-06: /wallet/v7 family resolves to the org-roots scopes (documented contract) and is reachable by machine credentials", () => {
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v7", "requests"], {}), ["write:org-roots"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v7", "requests", ID, "signature"], {}), ["write:org-roots"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v7", "requests", ID, "submit"], {}), ["write:org-roots"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v7", "requests", ID, "reject"], {}), ["write:org-roots"]);
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "v7", "requests"], {}), ["read:org-roots"]);
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "v7", "requests", ID], {}), ["read:org-roots"]);
  assert.notDeepEqual(requiredScopesFor("GET", ["wallet", "v7", "requests"], {}), ["read:requests"], "GET must not fall through to the legacy read:requests scope");
});

test("route precedence inside the wallet branch: every family keeps its own scopes (no family widens or denies another)", () => {
  // v4
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "create"], {}), ["request:build"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests"], { action: "ownerPause" }), ["request:build", "request:break-glass"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "submit"], {}), ["request:submit"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "genesis-submit"], {}), ["request:submit"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "signature"], {}), ["request:sign"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "approvals"], {}), ["request:sign"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "reject"], {}), ["request:reject"]);
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "v4", "requests"], {}), ["read:requests"]);
  assert.equal(requiredScopesFor("POST", ["wallet", "v4", "requests", ID, "unknown"], {}), null);
  // v5 / v6
  for (const v of ["v5", "v6"]) {
    assert.deepEqual(requiredScopesFor("POST", ["wallet", v, "create"], {}), ["request:build"]);
    assert.deepEqual(requiredScopesFor("POST", ["wallet", v, "requests"], {}), ["request:build"]);
    assert.deepEqual(requiredScopesFor("POST", ["wallet", v, "requests", ID, "signature"], {}), ["request:sign"]);
    assert.deepEqual(requiredScopesFor("POST", ["wallet", v, "requests", ID, "submit"], {}), ["request:submit"]);
    assert.deepEqual(requiredScopesFor("POST", ["wallet", v, "requests", ID, "reject"], {}), ["request:reject"]);
    assert.deepEqual(requiredScopesFor("GET", ["wallet", v, "requests"], {}), ["read:requests"]);
  }
  // legacy v0.2
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "create"], {}), ["request:build"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "requests"], {}), ["request:build"]);
  assert.deepEqual(requiredScopesFor("POST", ["wallet", "requests", ID, "signature"], {}), ["request:sign"]);
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "requests", ID], {}), ["read:requests"]);
  // fuel is a network read
  assert.deepEqual(requiredScopesFor("GET", ["wallet", "fuel", "kaspatest:q"], {}), ["read:network"]);
  // dev signer routes are never machine-reachable; identities never machine-reachable
  assert.equal(requiredScopesFor("POST", ["wallet", "dev-sign"], {}), null);
  assert.equal(isWalletSessionOnlyRoute("POST", ["wallet", "dev-sign"]), true);
  assert.equal(isWalletSessionOnlyRoute("POST", ["identities"]), true);
  // unknown wallet families deny by default (prototype keys included)
  for (const fam of ["v8", "V7", "constructor", "__proto__", ""]) assert.equal(requiredScopesFor("POST", ["wallet", fam, "requests"], {}), null, `family ${fam}`);
});

test("org-roots family: reads require read:org-roots, every mutation requires write:org-roots; hosted-org scopes never imply them", () => {
  assert.deepEqual(requiredScopesFor("GET", ["org-roots"], {}), ["read:org-roots"]);
  assert.deepEqual(requiredScopesFor("GET", ["org-roots", ROOT, "requests", ID], {}), ["read:org-roots"]);
  for (const tail of [["requests"], ["vaults"], ["reconcile"], ["requests", ID, "signature"], ["requests", ID, "slot-signatures"], ["requests", ID, "finalize"], ["requests", ID, "submit"], ["requests", ID, "reject"]]) {
    assert.deepEqual(requiredScopesFor("POST", ["org-roots", ROOT, ...tail], {}), ["write:org-roots"], tail.join("/"));
  }
  assert.deepEqual(requiredScopesFor("POST", ["organizations"], {}), ["organizations:manage"]);
  assert.equal(isPublicRoute("GET", ["org-roots"]), false);
});
