"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: hosted-API access.
 *
 * The mobile client talks to the hosted control plane through the SAME
 * client the SDK ships — `sdk/src/http-client.js`, carried into this app
 * VERBATIM by mobile/tools/sync-portable.js and installed on the host
 * global as `PolicyVaultHttpClient`. There is no second API client, no
 * hand-rolled fetch wrapper, and no re-implementation of a route map.
 *
 * WHAT THE VENDORED CLIENT ALREADY GUARANTEES (and why re-implementing it
 * would be a downgrade): the credential lives in a module-private WeakMap
 * and cannot be logged, stringified, or thrown; integer sompi stay
 * decimal STRINGS end to end (JSON.parse would destroy a u64); server
 * refusals are carried verbatim and never reinterpreted; and there are NO
 * automatic retries, because a client cannot distinguish "never arrived"
 * from "executed, response lost" — instead every mutating call carries an
 * Idempotency-Key the caller can safely replay.
 *
 * THIS FILE IS COORDINATION ONLY. It contains no financial authority, no
 * policy semantics, no successor derivation, no verification, and no
 * reinterpretation of a server decision. A server response is DISPLAY
 * DATA and, for signing flows, INPUT to the on-device verifier — never a
 * verdict this app repeats.
 *
 * PORTABLE-LAYER RULE (§3.6): no DOM. `fetch` is INJECTED, not read off
 * a global, so this module is host-agnostic and testable.
 */

(function (globalScope) {
  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  /*
   * Session state, honestly modelled. Hosted sessions are wallet-bound (a
   * Schnorr signature over PersonalMessageSigningHash), so even READ-ONLY
   * use requires one signature per session (§5.1). How that signature is
   * obtained on mobile is OPEN QUESTION 3 in the architecture decision —
   * QR login (5.1a, recommended) vs a reviewed desktop->mobile session
   * hand-off (5.1b, which is a credential transfer and needs its own
   * hostile review). Neither is implemented here, and this scaffold does
   * not pick one: `sessionBootstrap` reports UNDECIDED so the UI can say
   * so instead of pretending a sign-in flow exists.
   */
  var SESSION_BOOTSTRAP = Object.freeze({
    status: "UNDECIDED",
    reason:
      "Hosted sessions are wallet-bound, so even read-only use needs one signature per session. The mobile bootstrap method (QR login vs a reviewed desktop-to-mobile session hand-off) is an open architecture decision and is NOT implemented in this scaffold.",
    candidates: Object.freeze([
      Object.freeze({
        id: "qr-login",
        label: "QR login with the offline CLI signer",
        recommended: true,
        note: "Uses the same adapter and lifecycle as transaction signing; adds no new credential type. Costs friction at every session start."
      }),
      Object.freeze({
        id: "desktop-handoff",
        label: "Desktop-to-mobile session hand-off",
        recommended: false,
        note: "Better UX, but it is a CREDENTIAL TRANSFER: it needs its own threat model (QR photography, replay, device binding, revocation, what a stolen phone inherits) and its own hostile review. Not a v1 shortcut."
      })
    ])
  });

  /**
   * createMobileApi({ httpClient, baseUrl, token, fetchImpl, headers })
   *
   *   httpClient — the vendored module's exports (PolicyVaultHttpClient).
   *   baseUrl    — the hosted deployment origin. REQUIRED; there is no
   *                default, because silently defaulting a financial
   *                app's server is exactly the kind of guess this project
   *                does not make.
   *   fetchImpl  — REQUIRED. Injected by the platform layer.
   *
   * Returns { configured, unconfiguredReason, client, sessionBootstrap,
   *           describeError }.
   *
   * When `configured` is false, `client` is null and every screen must
   * render the reason — never an empty list that looks like "you have no
   * vaults".
   */
  function createMobileApi(options) {
    var o = isPlainObject(options) ? options : {};
    var httpClient = o.httpClient;

    var reason = null;
    if (!isPlainObject(httpClient) || typeof httpClient.createClient !== "function") {
      reason = "the vendored API client (www/vendor/http-client.js) did not load";
    } else if (typeof o.baseUrl !== "string" || !o.baseUrl.trim()) {
      reason = "no PolicyVault server URL is configured for this build — set it in Settings before the control plane can be read";
    } else if (typeof o.fetchImpl !== "function") {
      reason = "no HTTP transport was provided by the platform layer";
    }

    var client = null;
    if (reason === null) {
      try {
        client = httpClient.createClient({
          baseUrl: o.baseUrl,
          token: o.token,
          fetchImpl: o.fetchImpl,
          headers: isPlainObject(o.headers) ? o.headers : undefined
        });
      } catch (e) {
        reason = "the API client refused this configuration: " + ((e && e.message) || String(e));
        client = null;
      }
    }

    /*
     * Turn any thrown client error into DISPLAY TEXT without
     * reinterpreting it. The server's own code and message are surfaced
     * verbatim; a transport failure is named as a transport failure and
     * NOT as a refusal, because the two mean opposite things for a
     * mutating call (see the vendored client's no-retry rationale).
     */
    function describeError(e) {
      if (!e) return { kind: "UNKNOWN", code: "UNKNOWN", text: "an unknown error occurred", retrySafe: false };
      if (e.name === "PolicyVaultApiError") {
        return {
          kind: "SERVER_REFUSAL",
          code: e.code,
          status: e.status,
          text: e.serverMessage,
          idempotencyKey: e.idempotencyKey || null,
          replayed: e.replayed === true,
          retrySafe: false
        };
      }
      if (e.name === "PolicyVaultNetworkError") {
        return {
          kind: "TRANSPORT_FAILURE",
          code: "TRANSPORT_FAILURE",
          text: "the request never produced an answer, so whether the server executed it is UNKNOWN — do not assume it failed",
          idempotencyKey: e.idempotencyKey || null,
          retrySafe: true,
          retryNote: "Retry with the SAME Idempotency-Key shown here; the server executes it at most once."
        };
      }
      return { kind: "CLIENT_ERROR", code: "CLIENT_ERROR", text: (e && e.message) || String(e), retrySafe: false };
    }

    return Object.freeze({
      configured: reason === null,
      unconfiguredReason: reason,
      baseUrl: reason === null ? o.baseUrl : null,
      client: client,
      sessionBootstrap: SESSION_BOOTSTRAP,
      describeError: describeError
    });
  }

  var api = {
    SESSION_BOOTSTRAP: SESSION_BOOTSTRAP,
    createMobileApi: createMobileApi
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileApi = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
