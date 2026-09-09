"use strict";

/*
 * BROWSER-LOCAL VERSION-AWARE MANIFEST VERIFICATION (Wave 2, Track F:
 * docs/postlaunch/hybrid-core-gap-analysis.md gap G2/G3).
 *
 * Drives web/verify-intent.js's verifyManifestBeforeSigning() — the
 * ADDITIVE counterpart to verifyBeforeSigning() that routes an
 * already-built manifest through the bundled core/intent/router.js to the
 * verifier that owns its exact manifestVersion (policyvault-0.5 token
 * controller, policyvault-0.6 controller ops, policyvault-0.6 atomic
 * swaps, policyvault-0.7-root organizational root). A
 * policyvault-0.7-payment (rooted-vault) manifest has no standalone
 * verifier by design and must refuse VERIFY_WITHIN_PARENT.
 *
 * verifyBeforeSigning() itself (the v0.4/v0.4.1 path) is NOT modified by
 * this addition — sibling suite web/test/verify-intent.test.js and the
 * rest of `node --test web/test/` (437 tests before and after this wave's
 * bundling + router-wiring commits) is the byte-identical-behavior proof:
 * same source, same assertions, same pass count.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const core = require("../core-bundle.js");
const { createVerifyIntent } = require("../verify-intent.js");

const vi = createVerifyIntent(core);

const tokenV5 = core.tokenManifestV5;
const controllerV6 = core.controllerManifestV6;
const swapV6 = core.swapManifestV6;
const orgRootV7 = core.orgRootManifestV7;

/* ------------------------------------------------------------------ */
/* fail-closed: >=10 unknown/malformed manifestVersion values          */
/* ------------------------------------------------------------------ */

const UNKNOWN_MANIFEST_VERSIONS = [
  "bogus/1",
  "policyvault-token-intent-manifest/2", // right family, wrong revision
  "policyvault-controller-intent-manifest/0",
  "policyvault-swap-intent-manifest/2",
  "policyvault-org-root-manifest/2",
  "policyvault-intent-manifest/1", // the v0.4 manifestVersion string — not routed here
  "POLICYVAULT-TOKEN-INTENT-MANIFEST/1", // case-sensitive exact match required
  "policyvault-token-intent-manifest/1 ", // trailing space
  "",
  "0",
  "policyvault-0.4",
  "policyvault-0.5",
  "constructor" // prototype-pollution-shaped key must not resolve to anything
];

test("FAIL CLOSED: every unknown/malformed manifestVersion refuses UNKNOWN_MANIFEST_VERSION, never a default route", () => {
  for (const v of UNKNOWN_MANIFEST_VERSIONS) {
    const out = vi.verifyManifestBeforeSigning({ manifest: { manifestVersion: v } });
    assert.equal(out.ok, false, `manifestVersion ${JSON.stringify(v)} must refuse`);
    assert.deepEqual(out.refusalCodes, ["UNKNOWN_MANIFEST_VERSION"], `manifestVersion ${JSON.stringify(v)}`);
    assert.equal(out.manifestHash, null);
    assert.equal(out.txId, null);
    assert.equal(out.unsignedSafeJson, null);
  }
});

test("FAIL CLOSED: a rooted-vault (policyvault-0.7-payment) manifest has no standalone verifier — VERIFY_WITHIN_PARENT", () => {
  const out = vi.verifyManifestBeforeSigning({ manifest: { manifestVersion: orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1 } });
  assert.equal(out.ok, false);
  assert.deepEqual(out.refusalCodes, ["VERIFY_WITHIN_PARENT"]);
  assert.match(out.failures[0].detail, /policyvault-org-root-manifest\/1/);
});

test("FAIL CLOSED: no core bundle -> CORE_UNAVAILABLE, never a silent pass", () => {
  const noCore = createVerifyIntent(null);
  const out = noCore.verifyManifestBeforeSigning({ manifest: { manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1 } });
  assert.equal(out.ok, false);
  assert.deepEqual(out.refusalCodes, ["CORE_UNAVAILABLE"]);
});

test("FAIL CLOSED: a core bundle without intentRouter also refuses CORE_UNAVAILABLE (the router is mandatory, not optional)", () => {
  const partial = createVerifyIntent({ ...core, intentRouter: undefined });
  const out = partial.verifyManifestBeforeSigning({ manifest: { manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1 } });
  assert.equal(out.ok, false);
  assert.deepEqual(out.refusalCodes, ["CORE_UNAVAILABLE"]);
});

test("FAIL CLOSED: malformed args (not an object, or no manifest) refuse VERIFY_INPUT_INVALID, never throw", () => {
  for (const bad of [undefined, null, {}, { manifest: null }, { manifest: "x" }, { manifest: 42 }, "x", 7, []]) {
    const out = vi.verifyManifestBeforeSigning(bad);
    assert.equal(out.ok, false, JSON.stringify(bad));
    assert.deepEqual(out.refusalCodes, ["VERIFY_INPUT_INVALID"], JSON.stringify(bad));
  }
});

/* ------------------------------------------------------------------ */
/* real routing + real check propagation (REFUSED path — no VM needed; */
/* the VERIFIED positive path over real builds lives in                */
/* sdk/test/token-manifest-v{5,6}.test.js and                          */
/* sdk/test/org-root-manifest-v7.test.js, which need silverc + the     */
/* encoder — this suite proves the BROWSER WIRING, not the covenant    */
/* arithmetic those suites already prove)                              */
/* ------------------------------------------------------------------ */

const ROUTED_FAMILIES = [
  { label: "v0.5 token controller", manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1, extra: { descriptor: {} } },
  { label: "v0.6 controller ops", manifestVersion: controllerV6.CONTROLLER_MANIFEST_VERSION_1, extra: { descriptor: {} } },
  { label: "v0.6 atomic swap", manifestVersion: swapV6.SWAP_MANIFEST_VERSION_1, extra: { descriptor: {} } },
  { label: "v0.7 organizational root", manifestVersion: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1, extra: { descriptors: {} } }
];

for (const fam of ROUTED_FAMILIES) {
  test(`ROUTED: ${fam.label} manifest reaches its own verifier and real checks/failures propagate (REFUSED — the manifest here is a minimal schema stub, not a real signed build)`, () => {
    const out = vi.verifyManifestBeforeSigning({ manifest: { manifestVersion: fam.manifestVersion }, ...fam.extra });
    assert.equal(out.ok, false, fam.label);
    assert.equal(out.verdict, "REFUSED");
    assert.ok(Array.isArray(out.checks) && out.checks.length > 0, `${fam.label}: real recomputed checks must be present, not a generic refusal`);
    assert.ok(out.failures.length > 0);
    assert.ok(out.lines.length > 0);
    /* never fabricate a pass: the DO-NOT-SIGN framing (or the org-root
     * explain module's own equivalent framing) must be present */
    const joined = out.lines.join("\n");
    assert.ok(/REFUSED/.test(joined), `${fam.label}: lines must say REFUSED somewhere`);
    assert.equal(out.manifest.manifestVersion, fam.manifestVersion);
  });
}

test("ROUTED: an explain-renderer failure (malformed manifest a dedicated renderer cannot narrate) falls back to the generic, checks-derived lines instead of losing the real verification result", () => {
  /* token-explain.explainTokenIntent reads manifest.accounting.kas/.token
   * unconditionally; a bare { manifestVersion, descriptor: {} } manifest
   * makes it throw. verifyManifestBeforeSigning must still return the
   * REAL router-computed verification (checks/failures), not a generic
   * BROWSER_VERIFIER_INTERNAL that discards it. */
  const out = vi.verifyManifestBeforeSigning({ manifest: { manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1 }, descriptor: {} });
  assert.equal(out.ok, false);
  assert.notDeepEqual(out.refusalCodes, ["BROWSER_VERIFIER_INTERNAL"], "the real recomputed refusal must survive an explain-renderer throw");
  assert.ok(out.checks.length > 0);
  assert.ok(out.lines.some((l) => l.startsWith("FAIL ")), "falls back to the generic checks-derived line renderer");
});

test("ROUTED: v0.7 organizational-root manifests use the dedicated org-root-explain renderer, not the generic fallback", () => {
  const out = vi.verifyManifestBeforeSigning({ manifest: { manifestVersion: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1 }, descriptors: {} });
  assert.equal(out.ok, false);
  /* the dedicated renderer's own framing, distinct from the generic
   * "BROWSER VERIFICATION REFUSED —" line genericManifestLines() emits */
  assert.ok(out.lines.some((l) => /ORGANIZATION ROOT APPROVAL REFUSED/.test(l)), "must use org-root-explain's own refusal framing");
});

test("decodeUnsignedSafeTransaction and verifyBeforeSigning remain on the returned surface unchanged (purely additive wiring)", () => {
  assert.equal(typeof vi.decodeUnsignedSafeTransaction, "function");
  assert.equal(typeof vi.verifyBeforeSigning, "function");
  assert.equal(typeof vi.verifyManifestBeforeSigning, "function");
});
