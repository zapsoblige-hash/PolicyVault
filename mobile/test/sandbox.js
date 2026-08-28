"use strict";

/*
 * PolicyVault mobile — TEST HARNESS: a browser-like sandbox that loads the
 * app's OWN packaged scripts, in the app's OWN order.
 *
 * WHY THIS EXISTS. The mobile toolchain (Xcode, Android SDK, simulators)
 * is not available in this environment, so no `.ipa` or `.aab` has been
 * built and no WebView has executed this payload. What CAN be proven
 * here, deterministically and without any of that, is the property the
 * whole architecture rests on: that the verification the app runs is the
 * reviewed verification, wired the way the app wires it, producing the
 * same PASS and the same DO-NOT-SIGN.
 *
 * This harness reuses `core/crossruntime/sandbox.js`'s technique
 * (documented at length there): a fresh `vm.Context` whose global is
 * named `window`, with `crypto.getRandomValues` present and `require`,
 * `module`, `process`, and `Buffer` all deliberately ABSENT. That matters
 * for fidelity — every vendored file has a CommonJS escape hatch
 * (`typeof module !== "undefined" && module.exports`), and a plain Node
 * `require()` of the bundle would take that branch instead of the browser
 * branch a WebView actually takes. Here the browser branch is the only
 * one available, so `window.PolicyVaultCore`, `window.
 * PolicyVaultVerifyIntent`, and every `window.PolicyVaultMobile*` global
 * are populated exactly as `mobile/www/index.html` populates them.
 *
 * IT IS STILL ONE V8 PROCESS. A vm.Context gives its own intrinsics, not
 * a second JavaScript ENGINE. Real JavaScriptCore (iOS WKWebView) and
 * real Android System WebView V8 evidence is the §6.2(b) on-device
 * equivalence harness, and that is UNRUN. Nothing in this directory
 * claims otherwise.
 */

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const { makeBrowserGlobal } = require("../../core/crossruntime/sandbox.js");

const MOBILE_ROOT = path.join(__dirname, "..");
const WWW = path.join(MOBILE_ROOT, "www");

/*
 * The load order from mobile/www/index.html, kept in ONE place so a
 * divergence between what the page loads and what the tests load cannot
 * go unnoticed. `test/app-payload.test.js` asserts this list equals the
 * <script src> order actually present in index.html.
 */
const SCRIPT_ORDER = [
  "vendor/core-bundle.js",
  "vendor/verify-intent.js",
  "vendor/http-client.js",
  "js/portable/qr-frames.js",
  "js/portable/airgap.js",
  "js/portable/verification.js",
  "js/portable/api.js",
  "js/portable/signer-capabilities.js",
  "js/portable/build-integrity.js"
];

/*
 * Load the app's packaged scripts into one fresh browser-like context.
 *
 * `only` optionally limits the list (used by the CORE_UNAVAILABLE test to
 * load the verifier WITHOUT the core bundle, which is the real failure
 * mode of a mis-packaged release).
 */
function loadAppPayload(only) {
  const scripts = only || SCRIPT_ORDER;
  const sandboxGlobal = makeBrowserGlobal();
  for (const rel of scripts) {
    const abs = path.join(WWW, rel);
    const source = fs.readFileSync(abs, "utf8");
    new vm.Script(source, { filename: abs }).runInContext(sandboxGlobal);
  }
  return sandboxGlobal;
}

/*
 * Build the mobile app's verification service EXACTLY as
 * mobile/www/js/app.js `rebuildServices()` does — same globals, same
 * arguments, same order. The point of the suite is the app's own wiring,
 * not a convenient re-wiring invented for the test.
 */
function createVerificationService(sandboxGlobal) {
  const wire = new vm.Script(
    `PolicyVaultMobileVerification.createMobileVerification({
       core: window.PolicyVaultCore,
       verifyIntent: window.PolicyVaultVerifyIntent,
       airgap: window.PolicyVaultMobileAirgap
     })`,
    { filename: "mobile-test:rebuildServices" }
  );
  return wire.runInContext(sandboxGlobal);
}

/* The packaged core bundle's own sha256, reached the way app.js reaches
 * it — through PolicyVaultCore.require("crypto"). No second hash. */
function sandboxSha256Hex(sandboxGlobal) {
  const shim = new vm.Script('PolicyVaultCore.require("crypto")', { filename: "mobile-test:crypto-shim" }).runInContext(sandboxGlobal);
  return (text) => shim.createHash("sha256").update(text, "utf8").digest("hex");
}

/*
 * Move a host-realm JSON value INTO the sandbox realm. Necessary because
 * the packaged core's plain-object checks compare against the CALLER's
 * `Object.prototype`, and a vm.Context has its own intrinsics — see the
 * long explanation in core/crossruntime/sandbox.js `rehomeInto`. Inside a
 * real WebView there is only one realm, so this correction exists purely
 * because vm-based testing is artificially multi-realm.
 */
function intoSandbox(sandboxGlobal, value) {
  const targetJSON = new vm.Script("JSON", { filename: "mobile-test:json-bridge" }).runInContext(sandboxGlobal);
  return targetJSON.parse(JSON.stringify(value));
}

/* Re-home a sandbox value back to the host realm for assertions. */
function outOfSandbox(value) {
  return JSON.parse(JSON.stringify(value));
}

module.exports = {
  MOBILE_ROOT,
  WWW,
  SCRIPT_ORDER,
  loadAppPayload,
  createVerificationService,
  sandboxSha256Hex,
  intoSandbox,
  outOfSandbox
};
