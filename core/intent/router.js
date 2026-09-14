"use strict";

/*
 * VERSION-AWARE, FAIL-CLOSED INTENT-MANIFEST ROUTER (core/intent).
 *
 * ONE dispatch point from a frozen SDK build — or from a manifest that
 * arrived over a wire — to the manifest family that actually describes it.
 * Written because the alternative (each consumer deciding for itself which
 * manifest module to call) is exactly how a build silently reaches the
 * WRONG verifier, or no verifier at all: before this router,
 * `buildTokenDepositV6` produced a v0.6-labelled build that the v0.5 token
 * manifest refuses and no other module accepted, and every non-swap v0.6
 * operation had no manifest at all
 * (`docs/postlaunch/v0.6-byte-freeze-readiness.md` limitation 8).
 *
 * A signer-visible manifest is only trustworthy if the code that produced
 * and verified it belongs to the SAME covenant generation as the
 * transaction. The project rule is absolute: unknown versions FAIL CLOSED
 * and are NEVER routed to a default. This module is the one place that
 * mapping lives, so a new generation is a deliberate, reviewable table
 * entry rather than an implicit fallthrough somewhere in the SDK.
 *
 * FAIL-CLOSED RULES (CLAUDE.md "unknown versions FAIL CLOSED"):
 *   - build dispatch is keyed on the EXACT (contractVersion, kind, action)
 *     tuple of a build; manifest dispatch on the EXACT manifestVersion;
 *   - an unknown covenant version, kind, action, or manifest version is
 *     REFUSED with a specific code — never routed to a default;
 *   - a KNOWN version whose handler lives outside the portable core
 *     (the v0.4 family, whose derivation bridge depends on sdk/src) is
 *     refused with `HANDLER_NOT_PORTABLE` and the exact module to call,
 *     so a caller can never mistake "not routed here" for "unsupported";
 *   - a generation whose operation is only meaningful INSIDE a parent
 *     manifest (a v0.7 rooted-vault operation, whose authority is the
 *     organizational-root input that carries it) has NO standalone
 *     verifier: asking for one is refused with `VERIFY_WITHIN_PARENT`
 *     rather than handing back a verifier that would prove half of the
 *     authority model.
 *
 * Registered manifest families (keyed by manifestVersion):
 *   policyvault-token-intent-manifest/1       v0.5 token controller (frozen)
 *   policyvault-controller-intent-manifest/1  v0.6 controller ops (frozen)
 *   policyvault-swap-intent-manifest/1        v0.6 atomic swaps (frozen)
 *   policyvault-org-root-manifest/1           v0.7 organizational M-of-N root
 *   policyvault-rooted-vault-manifest/1       v0.7 rooted payment vault
 *                                             (verified INSIDE the root
 *                                             manifest that carries it)
 *   policyvault-org-root-kas-manifest/1       v0.7-kas org root + rooted KAS
 *                                             vault owner ops, embedded
 *                                             (CANDIDATE, not byte-frozen)
 *   policyvault-rooted-kas-vault-manifest/1   v0.7-kas rooted KAS vault op
 *                                             (verified INSIDE the org-root-
 *                                             kas manifest for owner ops;
 *                                             standalone for agentSpend)
 *
 * Two dispatch surfaces share these tables and are kept deliberately
 * consistent by the tests: `routeBuild` / `routeManifest` (keyed on the
 * build tuple / manifestVersion — the surface the v0.5/v0.6 consumers and
 * the browser use) and `resolveIntentRoute` (keyed on contractVersion — the
 * surface the v0.7 SDK tooling and hostile matrix use for generations with
 * exactly one manifest family per version).
 *
 * PORTABILITY: this module requires only sibling core/intent manifest
 * modules, so it loads unchanged in the browser/mobile runtimes.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test/router.test.js) +
 * cross-runtime (core/crossruntime/test/v5-v6-portability.test.js).
 */

const tokenV5 = require("./token-manifest-v5");
const controllerV6 = require("./token-manifest-v6");
const swapV6 = require("./swap-manifest-v6");
const orgRootV7 = require("./org-root-manifest-v7");
const orgRootHdV7 = require("./org-root-manifest-v7-hd");
const orgRootKasV7 = require("./org-root-manifest-v7-kas");

/* Covenant versions whose manifests live in the portable core. */
const CONTRACT_VERSION_V5 = "policyvault-0.5";
const CONTRACT_VERSION_V6 = "policyvault-0.6";
const CONTRACT_VERSION_V7_ROOT = "policyvault-0.7-root";
const CONTRACT_VERSION_V7_PAYMENT = "policyvault-0.7-payment";
/* Wave 2 Track D (hierarchical delegation) — additive, never mutates any
 * v0.7-payment/v0.7-root routing above. */
const CONTRACT_VERSION_V7_PAYMENT_HD = "policyvault-0.7-payment-hd";
const HD_SPEND_ACTIONS = new Set(["hdSpend", "childSpendL2", "childSpendL3"]);
const HD_DELEGATION_ACTIONS = new Set(["delegateSetChildRoot1", "delegateSetChildRoot2"]);
const HD_OWNER_ACTIONS = new Set(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"]);
const CONTRACT_VERSION_V7_KAS = "policyvault-0.7-kas";

/* Known-but-not-routed-here: the v0.4 family's manifest derivation lives in
 * core/intent/bridge/derive.js, which imports sdk/src (the single core↔sdk
 * seam) and is therefore Node-only. Named explicitly so the refusal is
 * informative instead of a generic "unknown". */
const NON_PORTABLE_VERSIONS = Object.freeze({
  "policyvault-0.4": "core/intent/bridge/derive.js (deriveManifestFromV4Build / deriveAndVerify)",
  "policyvault-0.4.1": "core/intent/bridge/derive.js (deriveManifestFromV4Build / deriveAndVerify)"
});

const MANIFEST_FAMILIES = Object.freeze({
  [tokenV5.TOKEN_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V5,
    module: "core/intent/token-manifest-v5.js",
    build: tokenV5.buildTokenIntentManifest,
    verify: tokenV5.verifyTokenIntentManifest
  }),
  [controllerV6.CONTROLLER_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: controllerV6.CONTROLLER_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V6,
    module: "core/intent/token-manifest-v6.js",
    build: controllerV6.buildControllerIntentManifestV6,
    verify: controllerV6.verifyControllerIntentManifestV6
  }),
  [swapV6.SWAP_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: swapV6.SWAP_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V6,
    module: "core/intent/swap-manifest-v6.js",
    build: swapV6.buildSwapIntentManifest,
    verify: swapV6.verifySwapIntentManifest
  }),
  [orgRootV7.ORG_ROOT_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    module: "core/intent/org-root-manifest-v7.js",
    build: orgRootV7.buildOrgRootIntentManifest,
    verify: orgRootV7.verifyOrgRootIntentManifest
  }),
  [orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V7_PAYMENT,
    module: "core/intent/org-root-manifest-v7.js",
    build: orgRootV7.buildRootedVaultManifestV7,
    /* a rooted-vault operation is verified INSIDE the organizational-root
     * manifest that carries it, because its authority is that root input —
     * verifying it alone would be verifying half of the security property */
    verify: null,
    verifyWithin: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1
  }),
  /* Wave 2 Track D — the HD vault's five spend/delegation entrypoints never
   * touch the root, so unlike ROOTED_VAULT_MANIFEST_VERSION_1 this family
   * carries a REAL standalone verifier. */
  [orgRootHdV7.ROOTED_HD_VAULT_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: orgRootHdV7.ROOTED_HD_VAULT_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V7_PAYMENT_HD,
    module: "core/intent/org-root-manifest-v7-hd.js",
    build: orgRootHdV7.buildRootedHdVaultManifestV7,
    verify: orgRootHdV7.verifyRootedHdVaultManifestV7
  }),
  [orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1,
    /* contractVersion is the ROOT's, exactly like ORG_ROOT_MANIFEST_VERSION_1
     * above — an org-root(-kas) manifest primarily represents the ROOT
     * transaction/authority, regardless of which vault profile's ops ride
     * along; ROOTED_KAS_VAULT_MANIFEST_VERSION_1 below carries the KAS
     * vault's own contractVersion. */
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    module: "core/intent/org-root-manifest-v7-kas.js",
    build: orgRootKasV7.buildOrgRootIntentManifestV7Kas,
    verify: orgRootKasV7.verifyOrgRootIntentManifestV7Kas
  }),
  [orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1]: Object.freeze({
    manifestVersion: orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1,
    contractVersion: CONTRACT_VERSION_V7_KAS,
    module: "core/intent/org-root-manifest-v7-kas.js",
    build: orgRootKasV7.buildRootedKasVaultManifestV7,
    /* an owner operation is verified INSIDE the org-root-kas manifest that
     * carries it, because its authority is that root input — verifying it
     * alone would be verifying half of the security property. A delegate
     * spend (agentSpend) never touches the root and never NEEDS the
     * org-root wrapper, but the per-op verifier's signature
     * (verifyRootedKasVaultManifestV7({ manifest, frozen, redeemHex, check })) takes
     * the frozen transaction and an accumulating check() callback — it is
     * the SAME shape the payment profile's own verifyRootedVaultManifestV7
     * uses (also NOT exposed as a router-callable standalone verifier);
     * call it directly (not through this router) when verifying a
     * standalone agentSpend manifest. */
    verify: null,
    verifyWithin: orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1
  })
});

const SUPPORTED_MANIFEST_VERSIONS = Object.freeze(Object.keys(MANIFEST_FAMILIES).sort());

/* Every covenant generation the shared core KNOWS how to describe — the
 * portable families above plus the Node-only v0.4 bridge. This is the ONE
 * list a discovery document may advertise FROM (a server may advertise a
 * subset it actually routes, never a superset): an unknown version can never
 * be advertised because it is not here. */
const KNOWN_COVENANT_VERSIONS = Object.freeze([...new Set([
  ...Object.keys(NON_PORTABLE_VERSIONS),
  ...Object.values(MANIFEST_FAMILIES).map((f) => f.contractVersion)
])].sort());

/* Per-contractVersion routes: ONLY for generations with exactly one manifest
 * family per version (v0.6 has two, selected by build.action, so it is
 * deliberately absent here and named in UNSUPPORTED with the reason). */
const ROUTES = Object.freeze({
  [CONTRACT_VERSION_V5]: Object.freeze({
    contractVersion: CONTRACT_VERSION_V5,
    manifestVersion: tokenV5.TOKEN_MANIFEST_VERSION_1,
    module: "core/intent/token-manifest-v5",
    build: tokenV5.buildTokenIntentManifest,
    verify: tokenV5.verifyTokenIntentManifest
  }),
  [CONTRACT_VERSION_V7_ROOT]: Object.freeze({
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    manifestVersion: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1,
    module: "core/intent/org-root-manifest-v7",
    build: orgRootV7.buildOrgRootIntentManifest,
    verify: orgRootV7.verifyOrgRootIntentManifest
  }),
  [CONTRACT_VERSION_V7_PAYMENT]: Object.freeze({
    contractVersion: CONTRACT_VERSION_V7_PAYMENT,
    manifestVersion: orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1,
    module: "core/intent/org-root-manifest-v7",
    build: orgRootV7.buildRootedVaultManifestV7,
    verify: null,
    verifyWithin: orgRootV7.ORG_ROOT_MANIFEST_VERSION_1
  }),
  [CONTRACT_VERSION_V7_KAS]: Object.freeze({
    contractVersion: CONTRACT_VERSION_V7_KAS,
    manifestVersion: orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1,
    module: "core/intent/org-root-manifest-v7-kas",
    build: orgRootKasV7.buildRootedKasVaultManifestV7,
    verify: null,
    verifyWithin: orgRootKasV7.ORG_ROOT_KAS_MANIFEST_VERSION_1
  })
});

/* Known covenant generations that deliberately have no per-version route. */
const UNSUPPORTED = Object.freeze({
  [CONTRACT_VERSION_V6]: "v0.6 has TWO manifest families selected by build.action — core/intent/token-manifest-v6 (controller operations) and core/intent/swap-manifest-v6 (atomic swaps); use routeBuild(build) / routeManifest(manifest), there is no single per-version route",
  [CONTRACT_VERSION_V7_PAYMENT_HD]: 'policyvault-0.7-payment-hd has TWO manifest families selected by build.kind — the STANDALONE-verifiable core/intent/org-root-manifest-v7-hd.js ("hdTransition": hdSpend/childSpendL2/childSpendL3/delegateSetChildRoot1/delegateSetChildRoot2) and, for owner ops ("hdOwnerTransition"), the SAME family v0.7-payment uses (core/intent/org-root-manifest-v7.js, verified within its org-root manifest); use routeBuild(build) / routeManifest(manifest), there is no single per-version route',
  "policyvault-0.4": `the v0.4 family is described by ${NON_PORTABLE_VERSIONS["policyvault-0.4"]}, which is not part of the portable router`,
  "policyvault-0.4.1": `the v0.4.1 family is described by ${NON_PORTABLE_VERSIONS["policyvault-0.4.1"]}, which is not part of the portable router`
});

function refuse(code, message) {
  const e = new Error(message);
  e.code = code;
  throw e;
}

/*
 * PROTOTYPE-POLLUTION-SHAPED KEY GUARD. Every table in this module
 * (MANIFEST_FAMILIES, ROUTES, NON_PORTABLE_VERSIONS, UNSUPPORTED, and the
 * imported ACTIONS tables) is a plain object literal, so a caller-supplied
 * string like "constructor", "toString", "hasOwnProperty", "valueOf",
 * "__proto__", "isPrototypeOf" or "propertyIsEnumerable" resolves through
 * Object.prototype to a truthy built-in function INSTEAD of `undefined` on
 * a bare `TABLE[key]` lookup — which is exactly the "silently routed to a
 * default" outcome CLAUDE.md's fail-closed rule forbids, from an ordinary
 * bracket lookup with no explicit prototype-pollution attempt at all.
 * `ownGet` returns the table's OWN property only (or undefined), never a
 * prototype-chain hit, so every version/action/manifestVersion lookup in
 * this file fails closed on such a key exactly like any other unknown one.
 */
const { ownGet, describeKey } = require("../model/own-get"); // shared implementation (rc11 review F-05)

/*
 * Which manifest family describes this build? Returns the frozen family
 * descriptor; throws (never guesses) otherwise.
 */
function routeBuild(build) {
  if (!build || typeof build !== "object") refuse("SCHEMA_INVALID", "a build object is required");
  const version = build.contractVersion;
  if (typeof version !== "string" || version.length === 0) refuse("SCHEMA_INVALID", "build.contractVersion is required");
  const nonPortableWhy = ownGet(NON_PORTABLE_VERSIONS, version);
  if (nonPortableWhy) {
    refuse("HANDLER_NOT_PORTABLE", `${version} builds are described by ${nonPortableWhy}, which is not part of the portable manifest router — call it directly`);
  }
  const kind = build.kind;
  if (version === CONTRACT_VERSION_V7_ROOT) {
    /* the organizational root has exactly one manifest-bearing build kind */
    if (kind !== "orgRootTransition") {
      refuse("UNROUTABLE_BUILD_KIND", `build.kind ${describeKey(kind)} has no intent manifest for ${version} (only "orgRootTransition" does) — failing closed`);
    }
    return MANIFEST_FAMILIES[orgRootV7.ORG_ROOT_MANIFEST_VERSION_1];
  }
  if (version === CONTRACT_VERSION_V7_PAYMENT_HD) {
    /* HD spend/delegation builds carry kind "hdTransition" (never "transition"
     * — a distinct build kind, so a v0.7-payment build can never be
     * mis-routed here and vice versa) and route to the STANDALONE-verifiable
     * HD family; HD owner-op builds carry kind "hdOwnerTransition" and
     * (byte-identical field shapes to the payment profile) route to the SAME
     * ROOTED_VAULT_MANIFEST_VERSION_1 family, verified within the org-root
     * manifest exactly like the payment profile's owner ops. Checked BEFORE
     * the generic "transition"/"tokenDeposit" kind gate below, since neither
     * HD build kind is "transition". */
    if (kind === "hdTransition") {
      if (!HD_SPEND_ACTIONS.has(build.action) && !HD_DELEGATION_ACTIONS.has(build.action)) {
        refuse("UNKNOWN_ACTION", `unknown ${version} HD action ${describeKey(build.action)} — failing closed`);
      }
      return MANIFEST_FAMILIES[orgRootHdV7.ROOTED_HD_VAULT_MANIFEST_VERSION_1];
    }
    if (kind === "hdOwnerTransition") {
      if (!HD_OWNER_ACTIONS.has(build.action)) refuse("UNKNOWN_ACTION", `unknown ${version} owner action ${describeKey(build.action)} — failing closed`);
      return MANIFEST_FAMILIES[orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1];
    }
    refuse("UNROUTABLE_BUILD_KIND", `build.kind ${describeKey(kind)} has no intent manifest for ${version} (only "hdTransition" and "hdOwnerTransition" do) — failing closed`);
  }
  if (kind !== "transition" && kind !== "tokenDeposit") {
    refuse("UNROUTABLE_BUILD_KIND", `build.kind ${describeKey(kind)} has no intent manifest (only "transition" and "tokenDeposit" do) — failing closed`);
  }
  if (version === CONTRACT_VERSION_V5) {
    if (kind === "tokenDeposit") return MANIFEST_FAMILIES[tokenV5.TOKEN_MANIFEST_VERSION_1];
    if (!ownGet(tokenV5.ACTIONS, build.action)) refuse("UNKNOWN_ACTION", `unknown ${version} action ${describeKey(build.action)} — failing closed`);
    return MANIFEST_FAMILIES[tokenV5.TOKEN_MANIFEST_VERSION_1];
  }
  if (version === CONTRACT_VERSION_V6) {
    if (kind === "tokenDeposit") return MANIFEST_FAMILIES[controllerV6.CONTROLLER_MANIFEST_VERSION_1];
    if (typeof build.action === "string" && controllerV6.SWAP_ACTIONS.includes(build.action)) {
      if (!build.swap) refuse("SCHEMA_INVALID", `${build.action} is a swap action but the build carries no swap section — failing closed`);
      return MANIFEST_FAMILIES[swapV6.SWAP_MANIFEST_VERSION_1];
    }
    if (build.swap) refuse("SCHEMA_INVALID", `build.action ${describeKey(build.action)} is not a swap action but the build carries a swap section — failing closed`);
    if (!ownGet(controllerV6.ACTIONS, build.action)) refuse("UNKNOWN_ACTION", `unknown ${version} action ${describeKey(build.action)} — failing closed`);
    return MANIFEST_FAMILIES[controllerV6.CONTROLLER_MANIFEST_VERSION_1];
  }
  if (version === CONTRACT_VERSION_V7_PAYMENT) {
    /* the rooted vault's own manifest module owns the action table; the
     * router only decides the family (verified within the root manifest) */
    return MANIFEST_FAMILIES[orgRootV7.ROOTED_VAULT_MANIFEST_VERSION_1];
  }
  if (version === CONTRACT_VERSION_V7_KAS) {
    /* CANDIDATE, not byte-frozen. Same shape as the payment profile: the
     * rooted-KAS-vault manifest module owns the action table (agentSpend +
     * all 7 ownerControl selectors + ownerRecover); the router only
     * decides the family (verified within the org-root-kas manifest). */
    return MANIFEST_FAMILIES[orgRootKasV7.ROOTED_KAS_VAULT_MANIFEST_VERSION_1];
  }
  refuse("UNKNOWN_COVENANT_VERSION", `build.contractVersion ${describeKey(version)} has no known manifest family — failing closed (never routed to a default)`);
  return null; /* unreachable; keeps the control flow explicit */
}

/* Which manifest family owns this manifest? Keyed on manifestVersion only. */
function routeManifest(manifest) {
  if (!manifest || typeof manifest !== "object") refuse("SCHEMA_INVALID", "a manifest object is required");
  const family = ownGet(MANIFEST_FAMILIES, manifest.manifestVersion);
  if (!family) {
    refuse("UNKNOWN_MANIFEST_VERSION", `manifestVersion ${describeKey(manifest.manifestVersion)} is not one of ${SUPPORTED_MANIFEST_VERSIONS.join(", ")} — failing closed`);
  }
  return family;
}

/*
 * Build the correct manifest for `build`. Extra per-family arguments
 * (agentPolicy, recipients, descriptor, vaultOperations, …) are passed
 * through unchanged; each family validates its own required set.
 */
function buildManifestForBuild(args) {
  const family = routeBuild(args && args.build);
  return family.build(args);
}

/*
 * Verify a manifest with the verifier that owns its version. `descriptor`
 * (and, for swaps, `currentDaaScore`) pass through unchanged. A family
 * without a standalone verifier is refused, never silently "verified".
 */
function verifyManifest(args) {
  const family = routeManifest(args && args.manifest);
  if (!family.verify) {
    refuse("VERIFY_WITHIN_PARENT", `${family.manifestVersion} manifests are verified inside a ${family.verifyWithin} manifest — verifying one in isolation would prove only half of the authority model; failing closed`);
  }
  return family.verify(args);
}

/* ---- per-contractVersion surface (v0.7 tooling + hostile matrix) ---- */

function resolveIntentRoute(contractVersion) {
  if (typeof contractVersion !== "string" || contractVersion.length === 0) {
    refuse("UNKNOWN_VERSION", "intent-router: a contractVersion string is required — failing closed");
  }
  const route = ownGet(ROUTES, contractVersion);
  if (!route) {
    const why = ownGet(UNSUPPORTED, contractVersion);
    refuse("UNKNOWN_VERSION", why ? `intent-router: ${contractVersion} has no intent-manifest route: ${why} — failing closed` : `intent-router: unknown contractVersion ${JSON.stringify(contractVersion)} — failing closed (no default route)`);
  }
  return route;
}

function routeIntentManifestBuilder(contractVersion) {
  return resolveIntentRoute(contractVersion).build;
}

function routeIntentManifestVerifier(contractVersion) {
  const route = resolveIntentRoute(contractVersion);
  if (!route.verify) {
    refuse("VERIFY_WITHIN_PARENT", `intent-router: ${contractVersion} operations are verified inside a ${route.verifyWithin} manifest — verifying one in isolation would prove only half of the authority model; failing closed`);
  }
  return route.verify;
}

function supportedIntentVersions() {
  return Object.freeze(Object.keys(ROUTES).sort());
}

module.exports = {
  SUPPORTED_MANIFEST_VERSIONS,
  KNOWN_COVENANT_VERSIONS,
  MANIFEST_FAMILIES,
  NON_PORTABLE_VERSIONS,
  routeBuild,
  routeManifest,
  buildManifestForBuild,
  verifyManifest,
  ROUTES,
  UNSUPPORTED,
  resolveIntentRoute,
  routeIntentManifestBuilder,
  routeIntentManifestVerifier,
  supportedIntentVersions
};
