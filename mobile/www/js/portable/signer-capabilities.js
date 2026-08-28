"use strict";

/*
 * PolicyVault mobile — PORTABLE LAYER: signer roster + capability
 * limitations.
 *
 * Implements mobile-architecture-decision.md §4.1 (adapter roster) and
 * §4.2 (capability-limitation UX) as DATA plus one pure function. It
 * decides nothing about money; it decides what the app is honest enough
 * to offer.
 *
 * THE RULES THIS FILE EXISTS TO ENFORCE
 *
 *   - NEVER INVENT AN UNSUPPORTED WALLET CAPABILITY. Wallets with no
 *     verifiable external signing interface are listed as NOT BUILT with
 *     the concrete reason, never hidden and never optimistically probed.
 *   - A CAPABILITY LIMITATION NEVER DOWNGRADES VERIFICATION. There is no
 *     "reduced verification mode", no "sign without local check", no
 *     "the wallet says it is fine". Every limitation ends by pointing at
 *     the supported alternative, so a flow is never a dead end.
 *   - AN UNAVAILABLE TRANSPORT IS RENDERED AS UNAVAILABLE, NOT AS A
 *     DISABLED BUTTON THAT MIGHT WORK. The platform layer reports what it
 *     actually has; this file turns that report into an offer or a
 *     refusal. Nothing here claims a capability the platform did not
 *     report.
 *   - KASWARE MOBILE IS UNCLAIMED. Its Android in-app-browser provider is
 *     documented only in release notes and has never been device-probed
 *     by this project. It is present as a runtime-probed, fail-closed
 *     negotiation path with an explicitly UNVERIFIED status — never as an
 *     advertised feature.
 *
 * PORTABLE-LAYER RULE (§3.6): pure data + pure functions. This file never
 * touches `window`, never probes a provider itself, and never performs
 * I/O. The platform layer probes and passes findings in.
 */

(function (globalScope) {
  /*
   * Universal Signer Interface capability descriptors, copied from the
   * roster the architecture decision fixes for v1 (§4.1). These describe
   * what each adapter WOULD declare through core/signer/interface.js;
   * `implementation` states plainly how much of it exists today.
   */
  var ADAPTERS = [
    {
      id: "qr-airgap",
      label: "Offline CLI signer over QR",
      role: "v1 PRIMARY",
      implementation: "SCAFFOLDED",
      transport: "camera",
      summary: "Renders the signing request as animated QR frames for the PolicyVault offline CLI signer on a second machine, then scans the signed response back.",
      features: {
        airGapped: true,
        asynchronousApproval: true,
        messageSigning: true,
        transactionSigning: true,
        specificInputSigning: true,
        multiAccount: false,
        accountEvents: false,
        networkSwitching: false,
        hardwareDisplay: false
      },
      scaffoldNote: "The request/response DOCUMENTS and the QR framing are implemented and tested. Camera capture is a platform stub in this build, so this transport reports UNAVAILABLE until a QR-scanning plugin is integrated."
    },
    {
      id: "qr-airgap-file",
      label: "Offline CLI signer over files",
      role: "v1 PRIMARY (fallback)",
      implementation: "SCAFFOLDED",
      transport: "file",
      summary: "Exchanges the identical request/response documents as files through the OS share sheet — for payloads too large for practical QR framing, or devices with no usable camera.",
      features: {
        airGapped: true,
        asynchronousApproval: true,
        messageSigning: true,
        transactionSigning: true,
        specificInputSigning: true,
        multiAccount: false,
        accountEvents: false,
        networkSwitching: false,
        hardwareDisplay: false
      },
      scaffoldNote: "Same documents as qr-airgap, so no second security review. Share-sheet/Files integration is a platform stub in this build; copy/paste of the document text is the working path."
    },
    {
      id: "kasware-mobile",
      label: "KasWare in-app browser (Android)",
      role: "OPPORTUNISTIC — UNVERIFIED",
      implementation: "PROBE ONLY",
      transport: "injected-provider",
      summary: "Reachable only when the PolicyVault WEB client is opened inside KasWare's Android in-app browser — never inside this app, which has no injected provider by construction.",
      features: null,
      scaffoldNote: "Capabilities are declared from what a runtime probe actually finds, never assumed. No device probe has been performed by this project; nothing about KasWare mobile is claimed."
    }
  ];

  /*
   * Wallets a user may plausibly hold KAS in, listed rather than hidden
   * (§4.2: a user who cannot find their wallet assumes the app is broken
   * and goes looking for a workaround). Wording is factual and
   * non-derogatory, and each entry ends at the supported alternative.
   */
  var SUPPORTED_ALTERNATIVE =
    "Approvals can still be made with the PolicyVault offline CLI signer, which signs on a separate machine and never exposes a key to this device.";

  var LIMITATIONS = [
    {
      id: "kaspium",
      label: "Kaspium",
      status: "NOT BUILT — no interface exists",
      body: "Kaspium holds KAS safely, but it does not currently offer an interface for approving a transaction that was built by another application. PolicyVault cannot use it as a signer. Nothing about your vault is less safe — it only means approvals must come from a signer that supports this.",
      alternative: SUPPORTED_ALTERNATIVE
    },
    {
      id: "tangem",
      label: "Tangem",
      status: "NOT BUILT — signature scheme mismatch",
      body: "Tangem cards sign with ECDSA. PolicyVault's covenant path requires BIP-340 Schnorr signatures, so the Universal Signer Interface refuses this pairing automatically during scheme negotiation. This is an enforced refusal, not a preference — a Tangem signature could not satisfy the covenant even if it were offered.",
      alternative: SUPPORTED_ALTERNATIVE
    },
    {
      id: "ledger",
      label: "Ledger",
      status: "NOT BUILT — no interface exists",
      body: "Ledger supports holding and transferring KAS, but exposes no documented interface for a third-party mobile app to submit a transaction or message for signing.",
      alternative: SUPPORTED_ALTERNATIVE
    },
    {
      id: "walletconnect",
      label: "WalletConnect / Reown",
      status: "NOT BUILT — no Kaspa namespace",
      body: "WalletConnect requires a CAIP-2 chain namespace. No Kaspa namespace exists in the chain-agnostic registry, so there is no protocol for a Kaspa wallet and PolicyVault to negotiate over.",
      alternative: SUPPORTED_ALTERNATIVE
    },
    {
      id: "kasware-extension",
      label: "KasWare browser extension",
      status: "SUPPORTED ON DESKTOP ONLY",
      body: "The KasWare browser extension is PolicyVault's production signing path on desktop. Browser extensions do not exist inside a native mobile app, so it cannot be reached from here.",
      alternative: SUPPORTED_ALTERNATIVE
    }
  ];

  /* The one property a capability limitation must never have. Asserted by
   * the test suite so a future edit cannot quietly add a bypass. */
  var VERIFICATION_IS_NEVER_OPTIONAL =
    "A capability limitation never downgrades verification. There is no reduced-verification mode and no proceed-anyway path.";

  function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

  /**
   * buildSignerRoster({ platform })
   *
   * `platform` is the platform layer's HONEST report of what this build
   * actually has, e.g.
   *   { camera: { available: false, reason: "..." },
   *     file:   { available: false, reason: "..." },
   *     clipboard: { available: true },
   *     injectedProvider: { present: false } }
   *
   * Returns adapters annotated with `offered` (true only when the
   * platform reported a working transport) and `unavailableReason`
   * (always a sentence, never null, when `offered` is false), plus the
   * limitation cards. A missing/malformed platform report yields
   * everything UNAVAILABLE — the fail-closed direction.
   */
  function buildSignerRoster(args) {
    var a = isPlainObject(args) ? args : {};
    var p = isPlainObject(a.platform) ? a.platform : {};

    var adapters = ADAPTERS.map(function (adapter) {
      var offered = false;
      var reason;

      if (adapter.transport === "camera") {
        var cam = isPlainObject(p.camera) ? p.camera : null;
        offered = Boolean(cam && cam.available === true);
        reason = offered ? null : (cam && cam.reason) || "this build has no QR camera capture — the platform layer reported no camera transport";
      } else if (adapter.transport === "file") {
        var file = isPlainObject(p.file) ? p.file : null;
        offered = Boolean(file && file.available === true);
        reason = offered ? null : (file && file.reason) || "this build has no share-sheet/file transport — the platform layer reported no file transport";
      } else if (adapter.transport === "injected-provider") {
        var inj = isPlainObject(p.injectedProvider) ? p.injectedProvider : null;
        offered = Boolean(inj && inj.present === true && inj.negotiated === true);
        reason = offered
          ? null
          : (inj && inj.reason) || "no wallet provider is injected into this app, and none can be: a WebView PolicyVault controls receives no wallet injection by construction";
      } else {
        reason = "unknown transport " + JSON.stringify(adapter.transport) + " — failing closed";
      }

      return {
        id: adapter.id,
        label: adapter.label,
        role: adapter.role,
        implementation: adapter.implementation,
        transport: adapter.transport,
        summary: adapter.summary,
        features: adapter.features,
        scaffoldNote: adapter.scaffoldNote,
        offered: offered,
        unavailableReason: reason
      };
    });

    return {
      adapters: adapters,
      limitations: LIMITATIONS.slice(),
      anyOffered: adapters.some(function (x) { return x.offered; }),
      verificationRule: VERIFICATION_IS_NEVER_OPTIONAL
    };
  }

  /**
   * negotiateInjectedProvider(found)
   *
   * Fail-closed negotiation for Mode B (§4.3): the PolicyVault WEB client
   * running inside a wallet's in-app browser. `found` is what the
   * platform layer actually observed on the host global — a list of
   * method names and a reported network — NOT the provider object itself.
   *
   * Refuses unless every required method is present AND the reported
   * network is an operational PolicyVault network. Never assumes a method
   * exists because a wallet's desktop build has it.
   */
  function negotiateInjectedProvider(found) {
    var f = isPlainObject(found) ? found : {};
    if (f.present !== true) {
      return { present: false, negotiated: false, reason: "no injected wallet provider was found on this host" };
    }
    var methods = Array.isArray(f.methods) ? f.methods : [];
    var required = ["requestAccounts", "getPublicKey", "getNetwork", "signPskt"];
    var missing = required.filter(function (m) { return methods.indexOf(m) < 0; });
    if (missing.length) {
      return {
        present: true,
        negotiated: false,
        reason: "the injected provider does not expose " + missing.join(", ") + " — PolicyVault refuses to negotiate a partial signing surface"
      };
    }
    if (f.network !== "testnet-10" && f.network !== "mainnet") {
      return {
        present: true,
        negotiated: false,
        reason: "the injected provider reports network " + JSON.stringify(String(f.network).slice(0, 32)) + ", which is not an operational PolicyVault network"
      };
    }
    return {
      present: true,
      negotiated: true,
      network: f.network,
      reason: null,
      caveat: "This provider was accepted from a runtime probe on this device only. PolicyVault claims no general KasWare-mobile support."
    };
  }

  var api = {
    ADAPTERS: ADAPTERS,
    LIMITATIONS: LIMITATIONS,
    SUPPORTED_ALTERNATIVE: SUPPORTED_ALTERNATIVE,
    VERIFICATION_IS_NEVER_OPTIONAL: VERIFICATION_IS_NEVER_OPTIONAL,
    buildSignerRoster: buildSignerRoster,
    negotiateInjectedProvider: negotiateInjectedProvider
  };

  if (typeof window !== "undefined") window.PolicyVaultMobileSignerCapabilities = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
