"use strict";

/*
 * UNIT (offline, no toolchain): the version-aware manifest router's
 * FAIL-CLOSED dispatch surface, and the v0.6 controller manifest's own
 * refusal surface. Every case here is a refusal or a routing decision —
 * the positive path over REAL builds lives in
 * sdk/test/token-manifest-v6.test.js (which needs silverc + the encoder).
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const router = require("../router");
const controllerV6 = require("../token-manifest-v6");
const tokenV5 = require("../token-manifest-v5");
const swapV6 = require("../swap-manifest-v6");
const orgRootV7 = require("../org-root-manifest-v7");
const orgRootKasV7 = require("../org-root-manifest-v7-kas");

function code(fn) {
  try {
    fn();
  } catch (e) {
    return e.code ?? "NO_CODE";
  }
  return "DID_NOT_THROW";
}

test("router: every supported manifest version maps to exactly one module, and the set is closed", () => {
  assert.deepEqual(router.SUPPORTED_MANIFEST_VERSIONS, [
    "policyvault-controller-intent-manifest/1",
    "policyvault-org-root-kas-manifest/1",
    "policyvault-org-root-manifest/1",
    "policyvault-rooted-hd-vault-manifest/1",
    "policyvault-rooted-kas-vault-manifest/1",
    "policyvault-rooted-vault-manifest/1",
    "policyvault-swap-intent-manifest/1",
    "policyvault-token-intent-manifest/1"
  ]);
  /* one module per (contractVersion, manifestVersion) family; the two v0.7
   * families deliberately share core/intent/org-root-manifest-v7.js (and the
   * two v0.7-kas families core/intent/org-root-manifest-v7-kas.js) because a
   * rooted-vault manifest is only ever verified INSIDE the root manifest */
  const pairs = router.SUPPORTED_MANIFEST_VERSIONS.map((v) => `${router.MANIFEST_FAMILIES[v].contractVersion}|${router.MANIFEST_FAMILIES[v].module}`);
  assert.equal(new Set(pairs).size, pairs.length, "one module per (contractVersion, manifest family)");
  for (const v of router.SUPPORTED_MANIFEST_VERSIONS) {
    const fam = router.MANIFEST_FAMILIES[v];
    assert.equal(fam.manifestVersion, v);
    assert.equal(typeof fam.build, "function");
    if (fam.verify === null) {
      /* a family with NO standalone verifier must name the parent family it is verified within */
      assert.ok(router.SUPPORTED_MANIFEST_VERSIONS.includes(fam.verifyWithin), `${v}: verifyWithin must name a supported family`);
      assert.equal(typeof router.MANIFEST_FAMILIES[fam.verifyWithin].verify, "function");
    } else {
      assert.equal(typeof fam.verify, "function");
    }
  }
  assert.equal(router.MANIFEST_FAMILIES[orgRootV7.ORG_ROOT_MANIFEST_VERSION_1].contractVersion, "policyvault-0.7-root");
  assert.equal(router.MANIFEST_FAMILIES[orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1].contractVersion, "policyvault-0.7-payment");
  assert.equal(router.MANIFEST_FAMILIES[orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1].verify, null);
  assert.equal(router.MANIFEST_FAMILIES[orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1].contractVersion, "policyvault-0.7-root");
  assert.equal(typeof router.MANIFEST_FAMILIES[orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1].verify, "function");
  assert.equal(router.MANIFEST_FAMILIES[orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1].contractVersion, "policyvault-0.7-kas");
  assert.equal(router.MANIFEST_FAMILIES[orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1].verify, null);
  assert.equal(router.MANIFEST_FAMILIES[orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1].verifyWithin, orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1);
  /* the module constants and the router table agree — no third source of truth */
  assert.equal(router.MANIFEST_FAMILIES[tokenV5.TOKEN_MANIFEST_VERSION_1].contractVersion, "policyvault-0.5");
  assert.equal(router.MANIFEST_FAMILIES[controllerV6.CONTROLLER_MANIFEST_VERSION_1].contractVersion, "policyvault-0.6");
  assert.equal(router.MANIFEST_FAMILIES[swapV6.SWAP_MANIFEST_VERSION_1].contractVersion, "policyvault-0.6");
});

test("router: build dispatch is exact — v0.5 / v0.6 non-swap / v0.6 swap / v0.6 deposit", () => {
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.5", kind: "transition", action: "tokenAgentSpend" }).module, "core/intent/token-manifest-v5.js");
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.5", kind: "tokenDeposit" }).module, "core/intent/token-manifest-v5.js");
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAgentSpend" }).module, "core/intent/token-manifest-v6.js");
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "tokenDeposit" }).module, "core/intent/token-manifest-v6.js");
  for (const action of ["ownerSetAgentRoot", "ownerSetSwapRoot", "ownerTopUpReserve", "ownerFundSwapPrincipal", "ownerPause", "ownerUnpause", "ownerRecover"]) {
    assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action }).module, "core/intent/token-manifest-v6.js", action);
  }
  for (const action of ["tokenAtomicSell", "tokenAtomicBuy"]) {
    assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action, swap: {} }).module, "core/intent/swap-manifest-v6.js", action);
  }
});

test("router: unknown versions, kinds and actions FAIL CLOSED with specific codes — never a default", () => {
  assert.equal(code(() => router.routeBuild(undefined)), "SCHEMA_INVALID");
  assert.equal(code(() => router.routeBuild({})), "SCHEMA_INVALID");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7", kind: "transition", action: "tokenAgentSpend" })), "UNKNOWN_COVENANT_VERSION", "bare policyvault-0.7 is not a generation (root/payment carry a profile suffix)");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.8", kind: "transition", action: "tokenAgentSpend" })), "UNKNOWN_COVENANT_VERSION");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.6", kind: "genesis", action: "createTokenController" })), "UNROUTABLE_BUILD_KIND");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action: "ownerDrainEverything" })), "UNKNOWN_ACTION");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.5", kind: "transition", action: "tokenAtomicSell" })), "UNKNOWN_ACTION", "v0.5 has no swap action");
  /* a swap action without a swap section, and a non-swap action WITH one, are both refusals */
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAtomicSell" })), "SCHEMA_INVALID");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAgentSpend", swap: {} })), "SCHEMA_INVALID");
});

test("router: the v0.4 family is KNOWN-but-not-portable and refuses with the exact module to call", () => {
  for (const version of ["policyvault-0.4", "policyvault-0.4.1"]) {
    let err;
    try {
      router.routeBuild({ contractVersion: version, kind: "transition", action: "agentSpend" });
    } catch (e) {
      err = e;
    }
    assert.equal(err.code, "HANDLER_NOT_PORTABLE", version);
    assert.match(err.message, /core\/intent\/bridge\/derive\.js/, "the refusal names the module that DOES handle it");
  }
});

test("router: manifest dispatch is keyed on manifestVersion and refuses anything else", () => {
  assert.equal(router.routeManifest({ manifestVersion: "policyvault-token-intent-manifest/1" }).module, "core/intent/token-manifest-v5.js");
  assert.equal(router.routeManifest({ manifestVersion: "policyvault-controller-intent-manifest/1" }).module, "core/intent/token-manifest-v6.js");
  assert.equal(router.routeManifest({ manifestVersion: "policyvault-swap-intent-manifest/1" }).module, "core/intent/swap-manifest-v6.js");
  assert.equal(router.routeManifest({ manifestVersion: "policyvault-org-root-manifest/1" }).module, "core/intent/org-root-manifest-v7.js");
  assert.equal(router.routeManifest({ manifestVersion: "policyvault-rooted-vault-manifest/1" }).module, "core/intent/org-root-manifest-v7.js");
  assert.equal(code(() => router.routeManifest({ manifestVersion: "policyvault-token-intent-manifest/2" })), "UNKNOWN_MANIFEST_VERSION");
  assert.equal(code(() => router.routeManifest({})), "UNKNOWN_MANIFEST_VERSION");
  assert.equal(code(() => router.routeManifest(null)), "SCHEMA_INVALID");
});

test("v0.6 controller manifest: build refuses wrong lineage, wrong kind, swap actions and unknown actions", () => {
  const b = controllerV6.buildControllerIntentManifestV6;
  assert.equal(code(() => b({ build: { contractVersion: "policyvault-0.5", kind: "transition", action: "tokenAgentSpend" }, descriptor: {} })), "SCHEMA_INVALID");
  assert.equal(code(() => b({ build: { contractVersion: "policyvault-0.6", kind: "genesis" }, descriptor: {} })), "SCHEMA_INVALID");
  assert.equal(code(() => b({ build: { contractVersion: "policyvault-0.6", kind: "transition", action: "tokenAtomicSell", swap: {} }, descriptor: {} })), "WRONG_MANIFEST_FOR_ACTION");
  assert.equal(code(() => b({ build: { contractVersion: "policyvault-0.6", kind: "transition", action: "nope" }, descriptor: {} })), "UNKNOWN_ACTION");
  assert.equal(code(() => b({ build: { contractVersion: "policyvault-0.6", kind: "tokenDeposit", depositMechanics: "policyvault-0.6" }, descriptor: {} })), "SCHEMA_INVALID");
});

test("v0.6 controller manifest: verify REFUSES an unknown version, an unknown action, and a non-object", () => {
  const v = controllerV6.verifyControllerIntentManifestV6;
  assert.equal(v({ manifest: { manifestVersion: "policyvault-controller-intent-manifest/2" }, descriptor: {} }).verdict, "REFUSED");
  assert.equal(v({ manifest: null, descriptor: {} }).verdict, "REFUSED");
  const r = v({ manifest: { manifestVersion: controllerV6.CONTROLLER_MANIFEST_VERSION_1, action: { sdkAction: "tokenAtomicSell" } }, descriptor: {} });
  assert.equal(r.verdict, "REFUSED");
  assert.ok(r.failures.some((f) => f.name === "exception"), "a refusal always names a failing check");
  assert.equal(r.statement, null, "no VERIFIED statement is ever emitted on a refusal");
});

test("v0.6 controller manifest: the action table covers every non-swap v0.6 SDK action and no swap action", () => {
  const actions = Object.keys(controllerV6.ACTIONS).sort();
  assert.deepEqual(actions, [
    "ownerFundSwapPrincipal",
    "ownerPause",
    "ownerRecover",
    "ownerSetAgentRoot",
    "ownerSetSwapRoot",
    "ownerTopUpReserve",
    "ownerUnpause",
    "tokenAgentSpend",
    "tokenDeposit"
  ]);
  for (const swapAction of controllerV6.SWAP_ACTIONS) {
    assert.equal(controllerV6.ACTIONS[swapAction], undefined, `${swapAction} must never be in the controller action table`);
  }
  /* the owner-control selectors mirror the covenant's own table exactly */
  const { OWNER_OP_SELECTOR_V6 } = require("../../model/vault-state-v6");
  for (const [action, sel] of Object.entries(OWNER_OP_SELECTOR_V6)) {
    assert.equal(controllerV6.ACTIONS[action].opSelector, sel, action);
  }
});

test("router + the SDK builder action sets agree: every v0.6 builder action is routable (no orphan action)", () => {
  /* The SDK's own action sets are the ground truth for what can be built.
   * Requiring them here is a READ-ONLY cross-check (this is a test, not
   * portable core code), and it is what catches a new builder action that
   * nobody taught the manifest layer about. */
  const { OWNER_CONTROL_ACTIONS, SPEND_ACTIONS, SWAP_ACTIONS } = require("../../../sdk/src/vault-builders-v6");
  for (const action of [...OWNER_CONTROL_ACTIONS, ...SPEND_ACTIONS, "ownerRecover"]) {
    assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action }).module, "core/intent/token-manifest-v6.js", `${action} must route to the controller manifest`);
  }
  for (const action of SWAP_ACTIONS) {
    assert.equal(router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action, swap: {} }).module, "core/intent/swap-manifest-v6.js", `${action} must route to the swap manifest`);
  }
});

/* ------------------------------------------------------------------ */
/* v0.7 organizational root: build dispatch + the per-contractVersion  */
/* surface (merged from lane v07-org-root; semantics unchanged)         */
/* ------------------------------------------------------------------ */

test("router: v0.7 build dispatch — root transitions route to the org-root family; rooted vault ops to the rooted family; genesis kinds are unroutable", () => {
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-root", kind: "orgRootTransition", action: "authorize" }).module, "core/intent/org-root-manifest-v7.js");
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-root", kind: "orgRootTransition", action: "authorize" }).manifestVersion, orgRootV7.ORG_ROOT_MANIFEST_VERSION_1);
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-root", kind: "orgRootGenesis" })), "UNROUTABLE_BUILD_KIND");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-root", kind: "transition", action: "authorize" })), "UNROUTABLE_BUILD_KIND", "a root build can never be routed as an ordinary vault transition");
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-payment", kind: "transition", action: "tokenAgentSpend" }).manifestVersion, orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1);
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-payment", kind: "tokenDeposit" }).manifestVersion, orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1);
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-payment", kind: "genesis" })), "UNROUTABLE_BUILD_KIND");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-payment", kind: "orgRootTransition" })), "UNROUTABLE_BUILD_KIND", "a vault build can never be routed as a root transition");
});

test("router: v0.7-kas build dispatch — agentSpend and every ownerControl/ownerRecover action route to the rooted-kas-vault family; genesis and root-kind builds are unroutable", () => {
  assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-kas", kind: "transition", action: "agentSpend" }).manifestVersion, orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1);
  for (const action of ["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"]) {
    assert.equal(router.routeBuild({ contractVersion: "policyvault-0.7-kas", kind: "transition", action }).module, "core/intent/org-root-manifest-v7-kas.js", action);
  }
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-kas", kind: "genesis" })), "UNROUTABLE_BUILD_KIND");
  assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.7-kas", kind: "orgRootTransition" })), "UNROUTABLE_BUILD_KIND", "a v0.7-kas vault build can never be routed as a root transition");
});

test("router: a rooted-kas-vault manifest has NO standalone verifier — verifyManifest refuses instead of proving half of the authority model", () => {
  assert.equal(code(() => router.verifyManifest({ manifest: { manifestVersion: orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1 } })), "VERIFY_WITHIN_PARENT");
  assert.equal(code(() => router.routeIntentManifestVerifier("policyvault-0.7-kas")), "VERIFY_WITHIN_PARENT");
  assert.equal(router.ROUTES["policyvault-0.7-kas"].verifyWithin, orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1);
});

test("router: a rooted-vault manifest has NO standalone verifier — verifyManifest refuses instead of proving half of the authority model", () => {
  assert.equal(code(() => router.verifyManifest({ manifest: { manifestVersion: orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1 } })), "VERIFY_WITHIN_PARENT");
  assert.equal(code(() => router.routeIntentManifestVerifier("policyvault-0.7-payment")), "VERIFY_WITHIN_PARENT");
  assert.equal(router.ROUTES["policyvault-0.7-payment"].verifyWithin, orgRootV7.ORG_ROOT_MANIFEST_VERSION_1);
});

test("router (per-contractVersion surface): the registered generations route to their own module, by identity", () => {
  assert.deepEqual(router.supportedIntentVersions(), ["policyvault-0.5", "policyvault-0.7-kas", "policyvault-0.7-payment", "policyvault-0.7-root"]);
  assert.equal(router.routeIntentManifestBuilder("policyvault-0.5"), tokenV5.buildTokenIntentManifest);
  assert.equal(router.routeIntentManifestVerifier("policyvault-0.5"), tokenV5.verifyTokenIntentManifest);
  assert.equal(router.routeIntentManifestBuilder("policyvault-0.7-root"), orgRootV7.buildOrgRootIntentManifest);
  assert.equal(router.routeIntentManifestVerifier("policyvault-0.7-root"), orgRootV7.verifyOrgRootIntentManifest);
  assert.equal(router.routeIntentManifestBuilder("policyvault-0.7-payment"), orgRootV7.buildRootedVaultManifestV7);
  assert.equal(router.routeIntentManifestBuilder("policyvault-0.7-kas"), orgRootKasV7.buildRootedKasVaultManifestV7);
  assert.equal(router.ROUTES["policyvault-0.7-root"].manifestVersion, orgRootV7.ORG_ROOT_MANIFEST_VERSION_1);
  assert.equal(router.ROUTES["policyvault-0.7-payment"].manifestVersion, orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1);
  assert.equal(router.ROUTES["policyvault-0.7-kas"].manifestVersion, orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1);
});

test("router (per-contractVersion surface): unknown and unsupported versions FAIL CLOSED — never a default route", () => {
  for (const v of ["policyvault-0.8", "policyvault-0.7", "policyvault-0.4", "policyvault-0.4.1", "", "policyvault-0.5 ", "POLICYVAULT-0.5", "kcc20/1"]) {
    assert.equal(code(() => router.resolveIntentRoute(v)), "UNKNOWN_VERSION", JSON.stringify(v));
  }
  assert.equal(code(() => router.resolveIntentRoute(undefined)), "UNKNOWN_VERSION");
  assert.equal(code(() => router.resolveIntentRoute(null)), "UNKNOWN_VERSION");
  /* a KNOWN generation with no per-version route names the reason instead of looking like a typo */
  assert.ok(router.UNSUPPORTED["policyvault-0.6"]);
  assert.throws(() => router.resolveIntentRoute("policyvault-0.6"), /swap-manifest-v6/);
  assert.throws(() => router.resolveIntentRoute("policyvault-0.6"), /routeBuild/);
  assert.equal(code(() => router.resolveIntentRoute("policyvault-0.6")), "UNKNOWN_VERSION");
  assert.throws(() => router.resolveIntentRoute("policyvault-0.4.1"), /bridge\/derive\.js/);
});

test("router: the two dispatch surfaces agree on every family they both describe, and the tables are frozen", () => {
  for (const [version, route] of Object.entries(router.ROUTES)) {
    const fam = router.MANIFEST_FAMILIES[route.manifestVersion];
    assert.ok(fam, `${version}: its manifestVersion is a supported family`);
    assert.equal(fam.contractVersion, version);
    assert.equal(fam.build, route.build);
    assert.equal(fam.verify, route.verify);
    assert.equal(`${fam.module}`, `${route.module}.js`);
  }
  assert.ok(Object.isFrozen(router.ROUTES));
  assert.ok(Object.isFrozen(router.MANIFEST_FAMILIES));
  for (const route of Object.values(router.ROUTES)) assert.ok(Object.isFrozen(route));
  for (const fam of Object.values(router.MANIFEST_FAMILIES)) assert.ok(Object.isFrozen(fam));
});

/*
 * PRODUCTION CODE BUG found + fixed by Wave 2 Track F (web/verify-intent.js
 * router-wiring test): every table this module indexes by a caller-
 * supplied string (MANIFEST_FAMILIES, ROUTES, NON_PORTABLE_VERSIONS,
 * UNSUPPORTED, and the imported ACTIONS tables) is a plain object literal.
 * A manifestVersion/contractVersion/action of "constructor", "toString",
 * "__proto__", "hasOwnProperty", etc. resolves through Object.prototype to
 * a truthy built-in on a bare `TABLE[key]` lookup instead of `undefined` —
 * a silent-default-route hole reachable from an ordinary bracket lookup,
 * with no explicit prototype-pollution payload required. Fixed by the
 * `ownGet()` own-property-only guard; every lookup below must still fail
 * closed with the SAME code an ordinary unknown string gets.
 */
const PROTOTYPE_SHAPED_KEYS = Object.freeze([
  "constructor",
  "toString",
  "hasOwnProperty",
  "valueOf",
  "__proto__",
  "isPrototypeOf",
  "propertyIsEnumerable",
  "toLocaleString",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__"
]);

test("FAIL CLOSED: prototype-shaped manifestVersion/contractVersion/action strings never resolve through Object.prototype to a silent default route", () => {
  for (const k of PROTOTYPE_SHAPED_KEYS) {
    assert.equal(code(() => router.routeManifest({ manifestVersion: k })), "UNKNOWN_MANIFEST_VERSION", `routeManifest(${k})`);
    assert.equal(code(() => router.resolveIntentRoute(k)), "UNKNOWN_VERSION", `resolveIntentRoute(${k})`);
    assert.equal(code(() => router.routeIntentManifestBuilder(k)), "UNKNOWN_VERSION", `routeIntentManifestBuilder(${k})`);
    assert.equal(code(() => router.routeIntentManifestVerifier(k)), "UNKNOWN_VERSION", `routeIntentManifestVerifier(${k})`);
    assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.6", kind: "transition", action: k })), "UNKNOWN_ACTION", `routeBuild v0.6 action ${k}`);
    assert.equal(code(() => router.routeBuild({ contractVersion: "policyvault-0.5", kind: "transition", action: k })), "UNKNOWN_ACTION", `routeBuild v0.5 action ${k}`);
    assert.equal(code(() => router.routeBuild({ contractVersion: k, kind: "transition", action: "tokenAgentSpend" })), "UNKNOWN_COVENANT_VERSION", `routeBuild contractVersion ${k}`);
  }
});
