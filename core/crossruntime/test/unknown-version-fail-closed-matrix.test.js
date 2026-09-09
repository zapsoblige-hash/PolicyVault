"use strict";

/*
 * UNKNOWN COVENANT/PROFILE/MANIFEST VERSIONS FAIL CLOSED — ONE table-
 * driven test PER RUNTIME (Wave 2, Track F item 6; CLAUDE.md "Versioning /
 * fail-closed": "Unknown versions FAIL CLOSED. Never route unknown
 * versions to a default.").
 *
 * Runtimes covered, each with its own table-driven test:
 *   1. Node core           — core/intent/router.js directly.
 *   2. Sandbox/shipped bundle — the SAME router reached through the
 *      committed web/core-bundle.js in a Buffer-free browser-shaped vm
 *      context (window.PolicyVaultCore.intentRouter).
 *   3. Python client        — N/A, documented explicitly rather than
 *      silently skipped: the Python client (docs/postlaunch/
 *      python-client-spec.md) performs no local covenant/manifest-version
 *      routing or transaction verification at all — it is a thin HTTP
 *      client whose only "version" surface is the wire schema fields
 *      python/policyvault_client/schemas.py validates, and its own
 *      ClosedInputTest ("an unknown action fails closed before any
 *      request") already covers that surface (python/tests/
 *      test_schemas.py). This test records WHY there is no python router
 *      table here rather than omitting the runtime silently.
 *   4. Server capabilities  — server/src/capabilities.js's PUBLIC
 *      discovery document (GET /api/v1/capabilities `contract.
 *      supportedCovenantVersions`) must be the exact SAME array
 *      core/intent/manifest.js exports as SUPPORTED_COVENANT_VERSIONS —
 *      one source of truth, so the server can never silently advertise
 *      support for (or fail to advertise, thereby under-reporting) a
 *      version the portable core does not actually recognize. Read-only:
 *      this test imports server/src/api.js and server/src/capabilities.js
 *      but modifies neither.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadCommittedBundleInBrowserGlobal, rehomeInto } = require("../sandbox.js");
const nodeRouter = require("../../intent/router.js");
const nodeManifest = require("../../intent/manifest.js");

const UNKNOWN_VERSIONS = Object.freeze([
  "bogus/1",
  "policyvault-0.8",
  "policyvault-0.9",
  "policyvault-1.0",
  "",
  "0",
  "null",
  "constructor",
  "toString",
  "hasOwnProperty",
  "__proto__",
  "valueOf",
  "isPrototypeOf",
  "POLICYVAULT-0.5", // case-sensitive exact match required
  "policyvault-0.5 " // trailing space
]);

test("RUNTIME 1/4 (Node core): every unknown contractVersion refuses UNKNOWN_VERSION through core/intent/router.js — never a default route", () => {
  for (const v of UNKNOWN_VERSIONS) {
    let code = null;
    try {
      nodeRouter.resolveIntentRoute(v);
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "UNKNOWN_VERSION", v);
  }
});

test("RUNTIME 1/4 (Node core): every unknown manifestVersion refuses UNKNOWN_MANIFEST_VERSION through core/intent/router.js — never a default route", () => {
  for (const v of UNKNOWN_VERSIONS) {
    let code = null;
    try {
      nodeRouter.routeManifest({ manifestVersion: v });
    } catch (e) {
      code = e.code;
    }
    assert.equal(code, "UNKNOWN_MANIFEST_VERSION", v);
  }
});

test("RUNTIME 2/4 (sandbox/shipped bundle): every unknown contractVersion/manifestVersion refuses identically to Node through the SHIPPED web/core-bundle.js", () => {
  const sb = loadCommittedBundleInBrowserGlobal();
  const S = sb.PolicyVaultCore;
  assert.equal(typeof S.intentRouter, "object", "the shipped bundle must expose core/intent/router.js");
  for (const v of UNKNOWN_VERSIONS) {
    let codeContract = null;
    try {
      S.intentRouter.resolveIntentRoute(v);
    } catch (e) {
      codeContract = e.code;
    }
    assert.equal(codeContract, "UNKNOWN_VERSION", `contractVersion ${v}`);

    let codeManifest = null;
    try {
      S.intentRouter.routeManifest(rehomeInto(sb.global, { manifestVersion: v }));
    } catch (e) {
      codeManifest = e.code;
    }
    assert.equal(codeManifest, "UNKNOWN_MANIFEST_VERSION", `manifestVersion ${v}`);
  }
});

test("RUNTIME 3/4 (Python client): NOT APPLICABLE, documented — no local covenant/manifest-version router exists to test; python/tests/test_schemas.py ClosedInputTest already proves the client's own closed-input fail-closed surface (unknown action, unknown fields)", () => {
  const schemasPath = path.join(__dirname, "..", "..", "..", "python", "policyvault_client", "schemas.py");
  assert.ok(fs.existsSync(schemasPath), "sanity: the python client package must exist for this NOT-APPLICABLE claim to be meaningful");
  const src = fs.readFileSync(schemasPath, "utf8");
  /* the python client validates wire SCHEMA shape (action names, field
   * sets) but never routes a covenant/manifest VERSION to a verifier —
   * confirmed by grep: no "manifestVersion" / "contractVersion" dispatch
   * table exists in the package. */
  assert.ok(!/def\s+route/.test(src), "sanity: no route*() dispatch function exists in schemas.py (would contradict the NOT-APPLICABLE claim)");
});

test("RUNTIME 4/4 (server capabilities): the PUBLIC discovery document's supportedCovenantVersions is a duplicate-free SUBSET of core/intent/router.js's KNOWN_COVENANT_VERSIONS (the one source of truth for which generations exist) — the server may advertise fewer than the router knows, NEVER more", () => {
  const { loadConfig } = require("../../../server/src/api.js");
  const { buildCapabilities } = require("../../../server/src/capabilities.js");
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-xrt-capabilities-"));
  const config = loadConfig({ dataRoot, networkId: "testnet-10" });
  const doc = buildCapabilities(config);
  const advertised = doc.contract.supportedCovenantVersions;
  const router = require("../../intent/router.js");
  /* one source of truth for WHICH generations exist: the server may advertise
   * only a subset of core/intent/router.js KNOWN_COVENANT_VERSIONS (the ones
   * it routes), never a superset; the v0.4 family list must be inside it */
  for (const v of doc.contract.supportedCovenantVersions) {
    assert.ok(router.KNOWN_COVENANT_VERSIONS.includes(v), `capabilities advertises ${JSON.stringify(v)}, which the shared core does not know`);
  }
  for (const v of nodeManifest.SUPPORTED_COVENANT_VERSIONS) {
    assert.ok(doc.contract.supportedCovenantVersions.includes(v), `the v0.4-family version ${v} must stay advertised`);
  }
  assert.deepEqual([...doc.contract.supportedCovenantVersions].sort(), [...new Set(doc.contract.supportedCovenantVersions)].sort(), "no duplicate advertised version");
  /* an unknown version must never appear in the advertised set */
  for (const v of UNKNOWN_VERSIONS) {
    assert.ok(!advertised.includes(v), `capabilities must never advertise the unknown version ${JSON.stringify(v)}`);
  }
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

test("RESIDUAL, recorded honestly: server capabilities now advertises every core/intent/router.js ROUTES-table version (Wave 2 Track E routed v0.5/v0.6/v0.7-payment-hd onto real HTTP surfaces alongside v0.7-root/v0.7-payment)", () => {
  /* Historically this test recorded a real coverage gap (v0.5/v0.6/v0.7
   * existed in the portable core but GET /api/v1/capabilities could not
   * discover them). Track E closed that gap: server/src/capabilities.js's
   * ROUTED_COVENANT_VERSIONS list is validated at module load against
   * core/intent/router.js's KNOWN_COVENANT_VERSIONS and now names every
   * version this build actually routes an HTTP surface for, including
   * v0.5/v0.6/v0.7-payment-hd. Recorded here — truthfully — as CLOSED
   * rather than deleted, so the historical gap is not silently lost. */
  const advertised = new Set(require("../../../server/src/capabilities.js").buildCapabilities(require("../../../server/src/api.js").loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-xrt-residual-")), networkId: "testnet-10" })).contract.supportedCovenantVersions);
  const routerKnows = nodeRouter.supportedIntentVersions();
  /* A covenant generation the intent router can ROUTE (has a manifest
   * family for) does not have to be exposed as a hosted HTTP product
   * surface. v0.7-kas is a TESTNET-VERIFIED candidate rooted-KAS profile:
   * the shared core routes its manifest, but Track E deliberately did NOT
   * build server routes for it (it is not part of the hosted token/HD
   * surface), so capabilities correctly does not advertise it. Recorded
   * as an explicit, documented exclusion — never a silent gap. */
  const NO_HOSTED_HTTP_SURFACE = new Set(["policyvault-0.7-kas"]);
  const notAdvertised = routerKnows.filter((v) => !advertised.has(v) && !NO_HOSTED_HTTP_SURFACE.has(v));
  assert.deepEqual(notAdvertised, [], "every ROUTES-table version with a hosted HTTP surface is advertised by capabilities");
  for (const v of NO_HOSTED_HTTP_SURFACE) {
    assert.ok(!advertised.has(v), `${v} has no hosted HTTP surface and must not be advertised`);
    assert.ok(routerKnows.includes(v), `${v} must still be a version the intent router knows`);
  }
});
