"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: on-device pre-sign verification.
 *
 * This is the mobile client's OWN WIRING around the two vendored,
 * byte-identical artifacts — `www/vendor/core-bundle.js` and
 * `www/vendor/verify-intent.js`. It deliberately contains NO verification
 * logic of its own. Every decision (strict payload decode, manifest
 * derivation, the full fail-closed detector catalogue, Merkle root
 * recomputation, fee/mass and successor-state recomputation, the
 * explanation lines, the DO-NOT-SIGN verdict) is produced by the exact
 * same reviewed code the web client runs
 * (mobile-architecture-decision.md §§1, 3.1, 6.1). If this file ever
 * starts *deciding* something, the architecture has been violated.
 *
 * WHAT IT DOES ADD, all of it fail-closed plumbing:
 *
 *   1. It refuses in the verifier's OWN refusal shape when the packaged
 *      verifier is missing or malformed, so the app has exactly ONE
 *      rendering path for "do not sign" and no neutral/unknown state.
 *      (`verify-intent.js` already yields CORE_UNAVAILABLE when it is
 *      loaded without a core bundle; this file covers the case where
 *      verify-intent itself did not load at all.)
 *
 *   2. It normalises the packaged verifier's shape before trusting it —
 *      a `verifyBeforeSigning` that returns a non-object, or an `ok: true`
 *      outcome that is not bound to the exact payload string, is treated
 *      as a REFUSAL rather than a pass.
 *
 *   3. It re-exports the independent second gate (`authorizeSigning`)
 *      from ./airgap.js so every signing affordance in the platform layer
 *      goes through one function.
 *
 * PORTABLE-LAYER RULE (§3.6): no DOM, no `fetch`, no Capacitor, no
 * platform imports, no ambient globals. Dependencies are injected.
 */

(function (globalScope) {
  var REQUIRED_CORE_KEYS = [
    "intent", "intentExplain", "recipientMerkle", "agentMerkle",
    "feeMass", "frozenTx", "vaultStateV4", "vaultTransitionsV4",
    "computeBudgetV4", "signerInterface"
  ];

  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  /*
   * A refusal shaped EXACTLY like web/verify-intent.js's own
   * `refusalOutcome` (same keys, same `lines[0]`, same sorted
   * `refusalCodes`, `unsignedSafeJson: null`), so a refusal originating
   * here is indistinguishable to the renderer from a refusal originating
   * inside the reviewed verifier. Duplicating the SHAPE is safe and
   * necessary; duplicating a DECISION would not be.
   */
  function refusal(failures, context) {
    var codes = [];
    for (var i = 0; i < failures.length; i++) if (codes.indexOf(failures[i].code) < 0) codes.push(failures[i].code);
    codes.sort();
    var lines = [];
    lines.push("!! DO NOT SIGN !!");
    lines.push("ON-DEVICE VERIFICATION REFUSED — this transaction FAILED independent verification on this device and must not be signed.");
    lines.push("Refusal codes: " + codes.join(", ") + ".");
    for (var j = 0; j < failures.length; j++) lines.push("- " + failures[j].code + ": " + failures[j].detail);
    if (context) lines.push("Context: " + context);
    lines.push("Nothing was signed and nothing was sent. Reload the app, rebuild the request, and verify again.");
    return Object.freeze({
      ok: false,
      verdict: "REFUSED",
      refusalCodes: codes,
      failures: failures.slice(),
      lines: lines,
      structured: null,
      manifest: null,
      manifestHash: null,
      txId: null,
      unsignedSafeJson: null,
      checks: null,
      notes: []
    });
  }

  /**
   * createMobileVerification({ core, verifyIntent })
   *
   *   core        — the object the packaged core bundle installed
   *                 (window.PolicyVaultCore), or null/undefined.
   *   verifyIntent— the object the packaged verifier installed
   *                 (window.PolicyVaultVerifyIntent), or null/undefined.
   *
   * Returns { available, unavailableReason, missingCoreModules,
   *           clientMaxFeeSompi, verify, authorizeSigning }.
   *
   * `verify(args)` is TOTAL: it never throws and never returns a neutral
   * verdict. Its argument object is passed through unchanged to
   * `verifyBeforeSigning` (request / vault / createContext / clientAction
   * / clientParams / clientFuel / sessionNetwork / sessionXOnly / role).
   */
  function createMobileVerification(deps) {
    var d = isPlainObject(deps) ? deps : {};
    var core = d.core;
    var verifyIntent = d.verifyIntent;

    var missingCoreModules = [];
    if (isPlainObject(core)) {
      for (var i = 0; i < REQUIRED_CORE_KEYS.length; i++) {
        if (!core[REQUIRED_CORE_KEYS[i]]) missingCoreModules.push(REQUIRED_CORE_KEYS[i]);
      }
    }

    var unavailableReason = null;
    if (!isPlainObject(core)) {
      unavailableReason = "the packaged core bundle (www/vendor/core-bundle.js) did not load";
    } else if (missingCoreModules.length) {
      /* §6.1 rule: a core bundle lacking required modules is treated as no
       * core at all, not as a partially-capable one. */
      unavailableReason = "the packaged core bundle is missing required modules (" + missingCoreModules.join(", ") + ") — a partial core is treated as no core";
    } else if (!isPlainObject(verifyIntent) || typeof verifyIntent.verifyBeforeSigning !== "function") {
      unavailableReason = "the packaged verifier (www/vendor/verify-intent.js) did not load";
    }

    var available = unavailableReason === null;

    function verify(args) {
      if (!available) {
        return refusal([{ code: "CORE_UNAVAILABLE", detail: unavailableReason + " — independent verification cannot run, and an error is never a pass" }]);
      }

      var expectedPayload = null;
      if (isPlainObject(args) && isPlainObject(args.request) && isPlainObject(args.request.transaction) && typeof args.request.transaction.unsignedSafeJson === "string") {
        expectedPayload = args.request.transaction.unsignedSafeJson;
      }

      var outcome;
      try {
        outcome = verifyIntent.verifyBeforeSigning(args);
      } catch (e) {
        /* verifyBeforeSigning is documented TOTAL; if it ever throws, that
         * is an internal defect, and an internal defect is a refusal. */
        return refusal([{ code: "VERIFIER_INTERNAL", detail: "the packaged verifier threw instead of returning an outcome: " + ((e && e.message) || String(e)) }]);
      }

      if (!isPlainObject(outcome) || typeof outcome.ok !== "boolean" || !Array.isArray(outcome.lines)) {
        return refusal([{ code: "VERIFIER_INTERNAL", detail: "the packaged verifier returned a value that is not a verification outcome" }]);
      }

      /* A PASS is only a PASS if it is bound to the exact bytes we asked
       * about. This can only ever turn a pass into a refusal. */
      if (outcome.ok === true && expectedPayload !== null && outcome.unsignedSafeJson !== expectedPayload) {
        return refusal([{
          code: "VERIFICATION_TX_BINDING_MISMATCH",
          detail: "the verifier returned a pass bound to different transaction bytes than the ones submitted for verification"
        }]);
      }

      return outcome;
    }

    return Object.freeze({
      available: available,
      unavailableReason: unavailableReason,
      missingCoreModules: missingCoreModules,
      clientMaxFeeSompi: available && verifyIntent ? verifyIntent.CLIENT_MAX_FEE_SOMPI : null,
      verify: verify,
      /* Injected so the platform layer has one entry point; the
       * implementation lives in ./airgap.js. */
      authorizeSigning: isPlainObject(d.airgap) && typeof d.airgap.authorizeSigning === "function"
        ? d.airgap.authorizeSigning
        : function () { return { ok: false, code: "VERIFICATION_REQUIRED", detail: "the air-gap module did not load — no signing path is available" }; }
    });
  }

  var api = {
    REQUIRED_CORE_KEYS: REQUIRED_CORE_KEYS,
    createMobileVerification: createMobileVerification,
    refusal: refusal
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileVerification = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
