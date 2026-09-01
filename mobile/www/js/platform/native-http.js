"use strict";

/*
 * PolicyVault mobile — PLATFORM LAYER: native HTTP transport adapter.
 *
 * WHY THIS EXISTS (NATIVE MOBILE TRANSPORT directive, Phase B). The app's
 * WebView origin is `https://localhost`; the hosted API is served
 * same-origin with NO CORS headers, by deliberate design. An ordinary
 * WebView `fetch` from the app origin to the hosted API is therefore a
 * cross-origin read the browser blocks — even though DNS/TLS/HTTP
 * reachability is fine. The approved fix is NOT to weaken the web origin
 * model (no CORS, no remote-load) but to give the NATIVE client an
 * explicit native HTTP transport that is not subject to the browser's
 * same-origin policy.
 *
 * SHAPE (deliberately narrow):
 *   - The web/browser build keeps ordinary `fetch` (env.js falls back to
 *     it when this adapter reports unavailable).
 *   - The native build routes each request through the EXPLICIT
 *     `CapacitorHttp.request(...)` call. We do NOT enable Capacitor's
 *     global fetch/XHR patching — nothing else in the app changes, and
 *     the seam stays auditable in one place.
 *   - The higher-level PolicyVault API semantics are unchanged: this
 *     adapter presents the SAME minimal fetch-response contract the
 *     vendored http-client already consumes (`.ok`, `.status`, `.text()`),
 *     so no financial or auth semantics move into platform code.
 *
 * SECURITY INVARIANTS enforced here (bearer/transport):
 *   - HTTPS ONLY. A non-`https:` URL is refused before any request — a
 *     bearer credential must never ride cleartext. (targetSdk 35 also
 *     blocks cleartext at the platform level; this is defence in depth.)
 *   - REDIRECTS DISABLED for every request. The API never legitimately
 *     redirects; following a 3xx could re-send the Authorization header to
 *     another host. We refuse to follow, and additionally verify the
 *     response host equals the requested host.
 *   - The bearer token only ever travels in the `Authorization` request
 *     header this adapter forwards verbatim. It is never placed in a URL
 *     or query string, never persisted, never logged, never copied into a
 *     response object.
 *   - Standard TLS certificate validation (the Capacitor bridge's default
 *     socket factory); certificate validation is never weakened here.
 */

(function (globalScope) {
  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  function hostOf(u) {
    try { return new URL(u).host; } catch (e) { return null; }
  }

  /* The native CapacitorHttp plugin IFF we are on a native Capacitor
   * platform AND the plugin is actually present; otherwise null so env.js
   * falls back to ordinary browser fetch. Never returns a partial/faked
   * transport. */
  function nativeHttp(scope) {
    var C = scope && scope.Capacitor;
    if (!C || typeof C.getPlatform !== "function") return null;
    var platform;
    try { platform = C.getPlatform(); } catch (e) { return null; }
    if (platform !== "android" && platform !== "ios") return null;
    var H = C.Plugins && C.Plugins.CapacitorHttp;
    return (H && typeof H.request === "function") ? H : null;
  }

  /* A fetch-shaped function backed by CapacitorHttp. The vendored
   * http-client calls fetchImpl(url, { method, headers, body, signal }) and
   * reads response.text(), response.ok and response.status; we satisfy
   * exactly that contract (plus a case-insensitive headers.get() and url,
   * which cost nothing and help error classification). */
  function createNativeFetch(deps) {
    var d = isPlainObject(deps) ? deps : {};
    var http = d.capacitorHttp;
    var timeoutMs = typeof d.timeoutMs === "number" && d.timeoutMs > 0 ? d.timeoutMs : 20000;
    if (!http || typeof http.request !== "function") {
      throw new TypeError("createNativeFetch requires a CapacitorHttp plugin with .request()");
    }

    return function nativeFetch(url, init) {
      init = isPlainObject(init) ? init : {};

      var parsedUrl;
      try { parsedUrl = new URL(url); } catch (e) {
        return Promise.reject(new TypeError("native transport: unparseable URL"));
      }
      if (parsedUrl.protocol !== "https:") {
        return Promise.reject(new TypeError("native transport refuses a non-HTTPS URL — a bearer credential never rides cleartext"));
      }
      var requestHost = parsedUrl.host;
      var requestOrigin = parsedUrl.protocol + "//" + parsedUrl.host;

      /* Declare our Origin explicitly, exactly as the hosted API's
       * request-protection layer expects a programmatic client to
       * (server/src/limits.js verifyOrigin: "programmatic hosted clients
       * set Origin: <appOrigin> explicitly"). The native client only ever
       * dials its one configured PolicyVault server, so its origin IS that
       * server's origin. This is NOT a CSRF weakening: a browser forbids JS
       * from forging Origin, so only a native/programmatic client can set
       * it, and such a client carries no ambient cookie to ride — the
       * exact case the origin wall already allows. Pre-auth challenge/verify
       * POSTs need this (they carry no bearer yet); authenticated POSTs are
       * additionally bearer-exempt. We never override a caller-set Origin. */
      var headers = isPlainObject(init.headers) ? Object.assign({}, init.headers) : {};
      var hasOrigin = false;
      for (var hk in headers) { if (Object.prototype.hasOwnProperty.call(headers, hk) && hk.toLowerCase() === "origin") { hasOrigin = true; break; } }
      if (!hasOrigin) headers.Origin = requestOrigin;

      var opts = {
        url: url,
        method: init.method || "GET",
        headers: headers,
        connectTimeout: timeoutMs,
        readTimeout: timeoutMs,
        /* Never follow a redirect on an authenticated request: a 3xx to a
         * different host would otherwise re-send Authorization. The API
         * never legitimately redirects. */
        disableRedirects: true
      };
      /* The http-client hands us a fully-serialized JSON string body with
       * its own Content-Type header already set; pass it through verbatim
       * so the bytes on the wire are exactly what the caller built. */
      if (init.body !== undefined && init.body !== null) opts.data = init.body;

      var reqPromise = http.request(opts).then(function (res) {
        /* Redirects are disabled, but verify rather than assume: never
         * surface a body delivered from a host other than the one dialed. */
        var finalHost = hostOf(res && res.url ? res.url : url);
        if (finalHost && requestHost && finalHost !== requestHost) {
          throw new TypeError("native transport: response host " + finalHost + " != requested host " + requestHost + " — refusing");
        }
        var status = res.status;
        var data = res.data;
        /* CapacitorHttp returns a PARSED object for application/json
         * responses and a string otherwise. The http-client re-parses text
         * itself, so hand it a string. PolicyVault sompi values are JSON
         * strings, so an object→string round-trip is lossless. */
        var bodyText = (typeof data === "string") ? data
          : (data === undefined || data === null) ? ""
          : JSON.stringify(data);
        var headers = isPlainObject(res.headers) ? res.headers : {};
        return {
          ok: status >= 200 && status < 300,
          status: status,
          url: (res && res.url) || url,
          headers: {
            get: function (name) {
              if (!name) return null;
              var lc = String(name).toLowerCase();
              for (var k in headers) {
                if (Object.prototype.hasOwnProperty.call(headers, k) && k.toLowerCase() === lc) return headers[k];
              }
              return null;
            }
          },
          text: function () { return Promise.resolve(bodyText); },
          json: function () { return Promise.resolve(bodyText ? JSON.parse(bodyText) : null); }
        };
      });

      /* Honor an AbortSignal if the caller passes one; native timeouts are
       * the primary mechanism, this only adds explicit cancellation. */
      var signal = init.signal;
      if (signal && typeof signal.addEventListener === "function") {
        return new Promise(function (resolve, reject) {
          if (signal.aborted) {
            reject(Object.assign(new Error("the request was aborted"), { name: "AbortError" }));
            return;
          }
          signal.addEventListener("abort", function () {
            reject(Object.assign(new Error("the request was aborted"), { name: "AbortError" }));
          }, { once: true });
          reqPromise.then(resolve, reject);
        });
      }
      return reqPromise;
    };
  }

  var api = { nativeHttp: nativeHttp, createNativeFetch: createNativeFetch };
  if (typeof window !== "undefined") window.PolicyVaultMobileNativeHttp = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
