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
   * use requires one signature per session. The mobile bootstrap method
   * was OPEN QUESTION 3 in the architecture decision; it is now FROZEN
   * (mobile/docs/session-bootstrap-DESIGN.md §3, commit 917c2a5): QR login
   * with the offline CLI signer is bootstrap v1, implemented below
   * (fetchAuthChallenge / completeAuthVerifyBearer) — manual-paste
   * transport only, since this build has no camera/QR-scan capture.
   * Desktop-to-mobile session hand-off remains DEFERRED (§5): it is a
   * CREDENTIAL TRANSFER and needs its own dedicated hostile review before
   * it ships, not a v1 shortcut.
   */
  var SESSION_BOOTSTRAP = Object.freeze({
    status: "QR_LOGIN_V1",
    reason:
      "Bootstrap v1 (mobile/docs/session-bootstrap-DESIGN.md §3): fetch a sign-in challenge, sign it with the offline CLI signer over the existing air-gap document/QR framing, and complete verify requesting bearer transport (Authorization header — this app cannot use a Set-Cookie session, see mobile/docs/session-bootstrap-options.md §1). Camera-based QR scanning is not implemented in this build; the signed response is brought back by manual paste, exactly like transaction signing today. Bearer sessions additionally require the server's POLICYVAULT_AUTH_BEARER_SESSIONS flag to be on — if it is not, sign-in is reported as unavailable, never fabricated as a success.",
    candidates: Object.freeze([
      Object.freeze({
        id: "qr-login",
        label: "QR login with the offline CLI signer",
        recommended: true,
        implemented: true,
        note: "Implemented (manual-paste transport; camera/QR-scan capture is not built). Uses the same adapter and lifecycle as transaction signing, adds no new credential type. Costs friction at every session start."
      }),
      Object.freeze({
        id: "desktop-handoff",
        label: "Desktop-to-mobile session hand-off",
        recommended: false,
        implemented: false,
        note: "DEFERRED (mobile/docs/session-bootstrap-DESIGN.md §5). Better UX, but it is a CREDENTIAL TRANSFER: it needs its own threat model (QR photography, replay, device binding, revocation, what a stolen phone inherits) and its own dedicated hostile review. Not built."
      })
    ])
  });

  /**
   * fetchAuthChallenge({ client, walletAddress })
   *
   * POST /auth/challenge — public, unauthenticated (server/src/api.js).
   * Step (a) of QR-login bootstrap v1. Returns the server-issued challenge
   * UNMODIFIED; this module invents no default wallet address and no
   * fallback challenge.
   *
   * ok:   { ok: true, challenge: { nonce, message, walletAddress, networkId, expiresAt } }
   * fail: { ok: false, reason }
   */
  function fetchAuthChallenge(args) {
    var a = isPlainObject(args) ? args : {};
    if (!isPlainObject(a.client) || typeof a.client.request !== "function") {
      return Promise.resolve({ ok: false, reason: "no API client is configured — open Settings" });
    }
    if (typeof a.walletAddress !== "string" || !a.walletAddress.trim()) {
      return Promise.resolve({ ok: false, reason: "a wallet address is required to request a sign-in challenge" });
    }
    return a.client
      .request("POST", "/auth/challenge", { body: { walletAddress: a.walletAddress }, idempotencyKey: null })
      .then(function (data) {
        if (!isPlainObject(data) || !isPlainObject(data.challenge)) {
          return { ok: false, reason: "the server returned no readable challenge" };
        }
        return { ok: true, challenge: data.challenge };
      })
      .catch(function (e) {
        return { ok: false, reason: (e && e.message) || String(e), error: e };
      });
  }

  /**
   * completeAuthVerifyBearer({ client, nonce, signature, publicKey, walletAddress })
   *
   * POST /auth/verify with `transport: "bearer"` explicitly requested —
   * step (d) of QR-login bootstrap v1. The server honors bearer transport
   * ONLY when its own POLICYVAULT_AUTH_BEARER_SESSIONS flag is on
   * (server/src/api.js); otherwise it silently answers with the existing
   * cookie-only shape (no `token` field), which this app cannot use (a
   * SameSite=Strict cookie cannot ride this app's cross-origin requests —
   * mobile/docs/session-bootstrap-options.md §1). That case is reported
   * here as an honest refusal, never a fabricated success.
   *
   * ok:   { ok: true, token, session }
   * fail: { ok: false, reason }
   */
  function completeAuthVerifyBearer(args) {
    var a = isPlainObject(args) ? args : {};
    if (!isPlainObject(a.client) || typeof a.client.request !== "function") {
      return Promise.resolve({ ok: false, reason: "no API client is configured — open Settings" });
    }
    var required = ["nonce", "signature", "publicKey", "walletAddress"];
    for (var i = 0; i < required.length; i++) {
      if (typeof a[required[i]] !== "string" || !a[required[i]]) {
        return Promise.resolve({ ok: false, reason: "missing " + required[i] + " — the signed response must be fully parsed first" });
      }
    }
    return a.client
      .request("POST", "/auth/verify", {
        body: { nonce: a.nonce, signature: a.signature, publicKey: a.publicKey, walletAddress: a.walletAddress, transport: "bearer" },
        idempotencyKey: null
      })
      .then(function (data) {
        if (!isPlainObject(data) || typeof data.token !== "string" || !/^[0-9a-f]{64}$/.test(data.token)) {
          return { ok: false, reason: "the server did not return a bearer session token — bearer sessions may not be enabled on this deployment" };
        }
        return { ok: true, token: data.token, session: data.session };
      })
      .catch(function (e) {
        return { ok: false, reason: (e && e.message) || String(e), error: e };
      });
  }

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
    createMobileApi: createMobileApi,
    fetchAuthChallenge: fetchAuthChallenge,
    completeAuthVerifyBearer: completeAuthVerifyBearer
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileApi = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
