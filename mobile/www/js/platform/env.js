"use strict";

/*
 * PolicyVault mobile — PLATFORM LAYER: host environment report.
 *
 * The platform layer is the swappable half of the seam
 * (mobile-architecture-decision.md §3.6): DOM, navigation, transport,
 * camera, share sheet, push, biometrics, deep links. If the client is
 * ever rebuilt on a different host (React Native is the documented escape
 * hatch), THIS layer is rewritten and the portable layer moves unmodified.
 *
 * Its job here is narrow and specific: look at the actual host and report
 * — HONESTLY — what exists. It never claims a capability it did not
 * observe, and it never returns "maybe". The portable layer turns these
 * reports into offers or refusals; this file just tells the truth about
 * the device.
 *
 * DELIBERATELY NOT IMPLEMENTED IN THIS SCAFFOLD, each reported as
 * unavailable rather than stubbed into something that looks like it
 * works:
 *   - camera / QR capture   (needs a native capture plugin: M3)
 *   - share sheet / Files   (needs a native filesystem+share plugin: M3)
 *   - push registration     (APNs/FCM; depends on surface 19: M3)
 *   - biometric session gate(Keychain/Keystore: M3)
 *   - deep links            (M3)
 * See docs/postlaunch/mobile-v1-scaffold.md for the full unverified list.
 */

(function (globalScope) {
  var doc = typeof document !== "undefined" ? document : null;
  var nav = typeof navigator !== "undefined" ? navigator : null;

  /* --------------------------------------------------------------- */
  /* Host detection                                                   */
  /* --------------------------------------------------------------- */

  function detectHost() {
    var cap = globalScope.Capacitor;
    if (cap && typeof cap.getPlatform === "function") {
      var platform;
      try { platform = cap.getPlatform(); } catch (e) { platform = "unknown"; }
      return {
        capacitor: true,
        platform: platform,
        native: platform === "ios" || platform === "android",
        /* WKWebView runs JavaScriptCore; Android System WebView runs V8.
         * Recorded because cross-ENGINE equivalence evidence is one of the
         * reasons this architecture was chosen (§3.1) — and because the
         * Android engine is an independently-updatable APK, so it is NOT
         * pinned by our build (§3.1 residual, risk R5). */
        engine: platform === "ios" ? "JavaScriptCore (WKWebView)" : platform === "android" ? "V8 (Android System WebView)" : "unknown"
      };
    }
    return { capacitor: false, platform: "web", native: false, engine: "the host browser's engine" };
  }

  /* --------------------------------------------------------------- */
  /* Transport: fetch + reading our own packaged files                */
  /* --------------------------------------------------------------- */

  /* A LOCAL binding, never a method call: a browser's global fetch throws
   * "Illegal invocation" when its receiver is anything but the global. */
  function fetchImpl() {
    if (typeof fetch !== "function") return null;
    return function (url, init) { return fetch(url, init); };
  }

  /* Reads a file out of the app's OWN payload (relative URL, same origin)
   * for the Build-integrity screen. Rejects on any non-2xx so a missing
   * artifact surfaces as a failure, never as an empty string that would
   * hash to something. */
  function readPackagedText(relPath) {
    var f = fetchImpl();
    if (!f) return Promise.reject(new Error("this host has no fetch, so packaged files cannot be read back"));
    return f(relPath, { cache: "no-store" }).then(function (res) {
      if (!res || !res.ok) throw new Error("HTTP " + (res ? res.status : "?") + " reading " + relPath);
      return res.text();
    });
  }

  /* --------------------------------------------------------------- */
  /* Capability reports (honest; unavailable is the default)          */
  /* --------------------------------------------------------------- */

  function cameraReport() {
    /* Even where getUserMedia exists (it does in a plain browser), this
     * build ships NO QR DECODER, so there is no camera *capture of QR
     * frames* to offer. Reporting "available" because a video stream can
     * be opened would be exactly the kind of fake affordance §6.3 rule 2
     * forbids. */
    return {
      available: false,
      reason: "this build has no QR decoder, so scanning is not available — the signed response can still be brought back by pasting the signer's response document"
    };
  }

  function fileReport() {
    return {
      available: false,
      reason: "this build has no share-sheet or Files integration — the request and response documents can still be moved by copy and paste"
    };
  }

  function clipboardReport() {
    var can = Boolean(nav && nav.clipboard && typeof nav.clipboard.writeText === "function");
    return {
      available: can,
      reason: can ? null : "this host exposes no clipboard API — select the document text and copy it manually"
    };
  }

  function writeClipboard(text) {
    if (!(nav && nav.clipboard && typeof nav.clipboard.writeText === "function")) {
      return Promise.reject(new Error("no clipboard API on this host"));
    }
    return nav.clipboard.writeText(text);
  }

  function pushReport() {
    return {
      available: false,
      reason: "push notifications are not implemented: the notification surface is still being designed, and this app is fully correct without it"
    };
  }

  function biometricReport() {
    return {
      available: false,
      reason: "biometric/Keychain session gating is not implemented in this build"
    };
  }

  /*
   * Probe for an INJECTED wallet provider. Inside PolicyVault's own
   * Capacitor WebView there is none by construction (§4.3 Mode A) — this
   * probe exists for the Mode B case where the PolicyVault WEB payload is
   * opened inside a wallet's in-app browser. It reports METHOD NAMES, not
   * the provider object: the portable negotiation layer must never be
   * handed a live host object to call.
   */
  function injectedProviderProbe() {
    var provider = globalScope.kasware;
    if (!provider || typeof provider !== "object") {
      return { present: false, methods: [], network: null };
    }
    var candidates = ["requestAccounts", "getAccounts", "getPublicKey", "getNetwork", "switchNetwork", "signMessage", "verifyMessage", "signPskt", "pushTx", "sendKaspa"];
    var methods = [];
    for (var i = 0; i < candidates.length; i++) {
      try { if (typeof provider[candidates[i]] === "function") methods.push(candidates[i]); } catch (e) { /* a throwing getter is not a method */ }
    }
    /* The network is only knowable asynchronously; the synchronous probe
     * reports null and negotiation therefore refuses until a real probe
     * supplies it. Fail-closed by construction. */
    return { present: true, methods: methods, network: null };
  }

  function report() {
    return {
      host: detectHost(),
      camera: cameraReport(),
      file: fileReport(),
      clipboard: clipboardReport(),
      push: pushReport(),
      biometrics: biometricReport(),
      injectedProvider: injectedProviderProbe()
    };
  }

  var api = {
    detectHost: detectHost,
    fetchImpl: fetchImpl,
    readPackagedText: readPackagedText,
    writeClipboard: writeClipboard,
    report: report,
    document: doc
  };

  if (typeof window !== "undefined") window.PolicyVaultMobilePlatform = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
