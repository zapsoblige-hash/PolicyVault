"use strict";

/*
 * KasWare behind the UNIVERSAL SIGNER INTERFACE v1
 * (PostLaunchUpgradeOG completion-standard item 4, browser side).
 *
 * This file is the ONLY place KasWare-specific code (window.kasware) lives
 * in the production flows. It provides:
 *
 *   1. createKasWareUsiAdapter({ win }) — the core/signer interface-v1
 *      adapter for the KasWare browser extension, per the file:line
 *      mapping in docs/postlaunch/signer-kasware-mapping.md. Every
 *      existing provider behavior is preserved bit-for-bit:
 *        - connect: kw.requestAccounts() -> accounts[0]; USER_REJECTED on
 *          e.code 4001 / /reject/i (web/wallet.js:109-131);
 *        - live network via normalizeNetwork(kw.getNetwork())
 *          (wallet.js:73-80 semantics, restated below);
 *        - personal messages: kw.signMessage(message, { type: "schnorr" })
 *          — the scheme is FORCED from the request's explicit scheme,
 *          never "auto" (wallet.js:192-210);
 *        - transactions: kw.signPskt({ txJsonString, options:
 *          { signInputs } }) over the EXACT frozen Safe JSON and the
 *          EXACT canonical { index, sighashType: 1 } entries
 *          (wallet.js:245-263);
 *        - account/network change events (wallet.js:227-240).
 *
 *   2. createKasWareSessionAdapter({ win }) — the drop-in session adapter
 *      consumed by web/app.js / web/app-v4.js (the legacy WalletAdapter
 *      surface), which routes EVERY signing operation through
 *      core/signer executeSigning + the frozen request creators, so the
 *      interface's fail-closed gates (capability, scheme, live network,
 *      pre/post identity) run on every signature in addition to the
 *      app-level checks that remain in place. UI-only conveniences the
 *      interface deliberately does not model (silent reconnect resume,
 *      the raw-pubkey fetch for hosted auth verify, the public-key
 *      normalization diagnostic log) stay here, isolated, direct.
 *
 * Error surface: SignerError codes (core/signer/errors.js) are attached
 * as BOTH `signerCode` and `code`, plus the legacy `walletCategory` name
 * where a 1:1 legacy category exists (web/wallet.js WalletError) — no
 * caller loses specificity, and existing walletCategory branches keep
 * working.
 *
 * Loadable in Node for the web/test suites: pass { win } (a mock window
 * carrying `kasware`) and { core } (the core bundle / core modules).
 */

(function () {
  function createModule(core) {
    var iface = core.signerInterface;
    var errors = core.signerErrors;
    var SignerErrorCodes = errors.SignerErrorCodes;

    /* Legacy walletCategory names for each v1 code (1:1 where the legacy
     * boundary had a category; new codes surface themselves verbatim). */
    var LEGACY_CATEGORY = {
      SIGNER_NOT_FOUND: "WALLET_NOT_FOUND",
      SIGNER_DISCONNECTED: "WALLET_DISCONNECTED",
      USER_REJECTED: "USER_REJECTED",
      WRONG_NETWORK: "WRONG_NETWORK",
      ACCOUNT_CHANGED: "ACCOUNT_CHANGED",
      UNSUPPORTED_CAPABILITY: "SIGNING_UNSUPPORTED",
      INVALID_SIGNATURE_RESPONSE: "INVALID_SIGNATURE_RESPONSE",
      INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY",
      PROVIDER_ERROR: "PROVIDER_ERROR"
    };

    /* Exact web/wallet.js normalizeNetwork semantics (restated so this
     * module has no load-order dependency on wallet.js). */
    function normalizeNetwork(n) {
      if (!n) return null;
      var s = String(n).toLowerCase();
      if (s.indexOf("testnet") >= 0 && (s.indexOf("10") >= 0 || s.indexOf("tn10") >= 0)) return "testnet-10";
      if (s === "kaspa_testnet_10" || s === "testnet-10") return "testnet-10";
      if (s.indexOf("mainnet") >= 0 || s === "kaspa_mainnet") return "mainnet";
      return s;
    }

    function adapterFail(code, message, cause) {
      /* the sanctioned adapter-side classification channel: an error-like
       * object carrying a KNOWN signerCode (normalizeAdapterFailure wraps
       * it into a SignerError preserving code + message + cause). */
      var e = new Error(message || code);
      e.signerCode = code;
      if (cause !== undefined) e.cause = cause;
      return e;
    }

    function isRejection(e) {
      return !!(e && (e.code === 4001 || /reject|denied/i.test((e && e.message) || "")));
    }

    /* ------------------------------------------------------------------ */
    /* 1. The USI v1 KasWare adapter                                       */
    /* ------------------------------------------------------------------ */

    function createKasWareUsiAdapter(options) {
      options = options || {};
      var win = options.win !== undefined ? options.win : typeof window !== "undefined" ? window : undefined;

      var state = {
        account: null,
        network: null,
        subscribed: false,
        listeners: { accountChanged: [], networkChanged: [] }
      };

      function kw() {
        var provider = win ? win.kasware : undefined;
        if (!provider) throw adapterFail(SignerErrorCodes.SIGNER_NOT_FOUND, "KasWare extension not detected");
        return provider;
      }

      function subscribe(provider) {
        if (state.subscribed) return;
        state.subscribed = true;
        if (typeof provider.on === "function") {
          provider.on("accountsChanged", function (accts) {
            state.account = Array.isArray(accts) && accts.length ? accts[0] : null;
            state.listeners.accountChanged.forEach(function (cb) { cb(state.account); });
          });
          provider.on("networkChanged", function (n) {
            state.network = normalizeNetwork(n);
            state.listeners.networkChanged.forEach(function (cb) { cb(state.network); });
          });
        }
      }

      var adapter = {
        /* KasWare-internal conveniences used by the session wrapper only
         * (NOT part of the interface contract): silent session resume and
         * the raw provider public key for the hosted auth verify call. */
        _resume: async function () {
          var provider = kw();
          var accounts = typeof provider.getAccounts === "function" ? await provider.getAccounts() : [];
          if (Array.isArray(accounts) && accounts.length) {
            state.account = accounts[0];
            state.network = normalizeNetwork(await provider.getNetwork());
            subscribe(provider);
            return { address: state.account, network: state.network };
          }
          return null;
        },
        _rawPublicKey: async function () {
          var provider = kw();
          if (typeof provider.getPublicKey !== "function") {
            throw adapterFail(SignerErrorCodes.INVALID_PUBLIC_KEY, "KasWare does not expose getPublicKey");
          }
          var raw;
          try {
            raw = await provider.getPublicKey();
          } catch (e) {
            throw adapterFail(SignerErrorCodes.PROVIDER_ERROR, (e && e.message) || "getPublicKey failed", e);
          }
          if (typeof raw !== "string" || !raw.trim()) {
            throw adapterFail(SignerErrorCodes.INVALID_PUBLIC_KEY, "KasWare returned an empty public key");
          }
          return raw.trim().toLowerCase();
        },

        describe: function () {
          return {
            interfaceVersion: iface.SIGNER_INTERFACE_VERSION,
            provider: "kasware",
            label: "KasWare",
            kind: "browser-extension",
            schemes: ["schnorr"],
            networks: ["mainnet", "testnet-10"],
            features: {
              messageSigning: true,
              transactionSigning: true,
              specificInputSigning: true,
              multiAccount: false,
              networkSwitching: false,
              accountEvents: true,
              asynchronousApproval: false,
              airGapped: false,
              hardwareDisplay: false
            }
          };
        },

        detect: function () {
          return !!(win && win.kasware);
        },

        connect: async function () {
          var provider = kw();
          var accounts;
          try {
            accounts = await provider.requestAccounts();
          } catch (e) {
            if (e && (e.code === 4001 || /reject/i.test(e.message || ""))) {
              throw adapterFail(SignerErrorCodes.USER_REJECTED, "You declined the connection", e);
            }
            throw adapterFail(SignerErrorCodes.PROVIDER_ERROR, (e && e.message) || "connect failed", e);
          }
          if (!Array.isArray(accounts) || !accounts.length) {
            throw adapterFail(SignerErrorCodes.PROVIDER_ERROR, "KasWare returned no accounts");
          }
          state.account = accounts[0];
          try {
            state.network = normalizeNetwork(await provider.getNetwork());
          } catch (e) {
            state.network = null;
          }
          subscribe(provider);
          return { address: state.account, network: state.network };
        },

        disconnect: async function () {
          try {
            var provider = kw();
            /* origin-scoped disconnect is a KasWare detail; the interface
             * passes no origin (signer-kasware-mapping.md §6.5). */
            if (typeof provider.disconnect === "function" && win && win.location) {
              await provider.disconnect(win.location.origin);
            }
          } catch (e) {
            /* best-effort, exactly like the legacy adapter */
          }
          state.account = null;
          state.network = null;
        },

        getActiveAccount: async function () {
          return state.account ? { address: state.account } : null;
        },

        getNetwork: async function () {
          state.network = normalizeNetwork(await kw().getNetwork());
          return state.network;
        },

        getPublicKey: async function () {
          return adapter._rawPublicKey();
        },

        on: function (event, cb) {
          if (state.listeners[event]) state.listeners[event].push(cb);
        },

        signMessage: async function (request) {
          var provider = kw();
          if (typeof provider.signMessage !== "function") {
            throw adapterFail(SignerErrorCodes.UNSUPPORTED_CAPABILITY, "KasWare does not support signMessage");
          }
          if (request.scheme !== "schnorr") {
            /* defense in depth: executeSigning refuses non-schnorr before
             * ever invoking the adapter; never fall back to "auto". */
            throw adapterFail(SignerErrorCodes.UNSUPPORTED_SCHEME, "this adapter signs personal messages with the schnorr scheme only");
          }
          try {
            return await provider.signMessage(request.message, { type: "schnorr" });
          } catch (e) {
            if (isRejection(e)) throw adapterFail(SignerErrorCodes.USER_REJECTED, "You declined the sign-in signature", e);
            throw adapterFail(SignerErrorCodes.PROVIDER_ERROR, (e && e.message) || "signMessage failed", e);
          }
        },

        signTransaction: async function (request) {
          var provider = kw();
          if (typeof provider.signPskt !== "function") {
            throw adapterFail(SignerErrorCodes.UNSUPPORTED_CAPABILITY, "KasWare does not support signPskt");
          }
          /* plain-object copies of the frozen canonical entries — content
           * byte-identical to the legacy path ({ index, sighashType: 1 }). */
          var signInputs = request.signInputs.map(function (si) {
            return { index: si.index, sighashType: si.sighashType };
          });
          try {
            return await provider.signPskt({ txJsonString: request.unsignedSafeJson, options: { signInputs: signInputs } });
          } catch (e) {
            if (isRejection(e)) throw adapterFail(SignerErrorCodes.USER_REJECTED, "You declined the signature", e);
            throw adapterFail(SignerErrorCodes.PROVIDER_ERROR, (e && e.message) || "signPskt failed", e);
          }
        }
      };

      return adapter;
    }

    /* ------------------------------------------------------------------ */
    /* 2. The session adapter (legacy WalletAdapter surface over the USI)  */
    /* ------------------------------------------------------------------ */

    /* Opt-in wallet diagnostics (never secrets): localStorage "pv.debug" = "1".
   * Guarded — storage may be unavailable or throw (privacy modes). */
  function walletDebugEnabled() {
    try {
      return typeof localStorage !== "undefined" && localStorage !== null && localStorage.getItem("pv.debug") === "1";
    } catch (_) {
      return false;
    }
  }

  function toLegacyError(e) {
      if (e && e.walletCategory) return e; // already legacy-shaped
      var code = e && e.signerCode ? e.signerCode : SignerErrorCodes.PROVIDER_ERROR;
      var out = new Error((e && e.message) || code);
      out.signerCode = code;
      out.code = code;
      out.walletCategory = LEGACY_CATEGORY[code] || code;
      if (e !== undefined) out.cause = e;
      return out;
    }

    function createKasWareSessionAdapter(options) {
      options = options || {};
      var usi = createKasWareUsiAdapter(options);
      /* Validate the adapter against the v1 contract ONCE at creation —
       * a contract breach (missing method, malformed descriptor) refuses
       * the whole session adapter rather than degrading. */
      var registration = iface.validateAdapter(usi);

      var session = {
        provider: "kasware",
        label: "KasWare",
        interfaceVersion: registration.descriptor.interfaceVersion,
        usiAdapter: usi,
        descriptor: registration.descriptor,

        detect: function () {
          return usi.detect();
        },

        /* legacy capability object (web/wallet.js:99-108 key names) —
         * derived from the validated v1 descriptor. */
        getCapabilities: function () {
          var d = registration.descriptor;
          return {
            canSignTransaction: d.features.transactionSigning,
            canSignSpecificInputs: d.features.specificInputSigning,
            canReturnRawSignedTx: true,
            canSwitchNetwork: d.features.networkSwitching,
            canExposeXOnlyPubkey: true,
            supportsAccountChangeEvents: d.features.accountEvents
          };
        },

        connect: async function () {
          try {
            return await usi.connect();
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "connect"));
          }
        },

        disconnect: async function () {
          return usi.disconnect();
        },

        /* silent session resume — KasWare-specific UI convenience, kept
         * adapter-internal (signer-kasware-mapping.md §6.1). */
        reconnect: async function () {
          try {
            return await usi._resume();
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "reconnect"));
          }
        },

        getActiveAddress: function () {
          /* synchronous tracked-account read, as the legacy surface
           * expects; connect()/reconnect()/events keep the mirror current. */
          return session.__address || null;
        },

        getNetwork: async function () {
          try {
            return await usi.getNetwork();
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "getNetwork"));
          }
        },

        getPublicKeyRaw: async function () {
          try {
            return await usi._rawPublicKey();
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "getPublicKey"));
          }
        },

        getPublicKeyXOnly: async function () {
          try {
            var raw = await usi._rawPublicKey();
            var xonly = iface.normalizePublicKeyToXOnly(raw, "KasWare");
            /* the legacy public-key normalization diagnostic (PUBLIC
             * material only) stays at this layer by design — but it is
             * OPT-IN (localStorage "pv.debug" = "1"): production consoles
             * never repeat wallet-identity dumps on every reconnect. */
            if (typeof console !== "undefined" && walletDebugEnabled()) {
              console.info("[PolicyVault] KasWare public key " + raw + " (" + raw.trim().length + " hex chars) -> x-only " + xonly);
            }
            return xonly;
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "getPublicKey"));
          }
        },

        on: function (event, cb) {
          /* legacy event names: "account" / "network" */
          if (event === "account") usi.on("accountChanged", cb);
          if (event === "network") usi.on("networkChanged", cb);
        },

        /*
         * Hosted sign-in signature — THROUGH the interface: a frozen
         * message-signing request with the explicit schnorr scheme, the
         * expected signer identity, and (when canonical) the live network,
         * executed with every interface gate. Returns the validated
         * 128-hex Schnorr signature, lowercased — byte-identical result
         * contract to the legacy signAuthMessage.
         */
        signAuthMessage: async function (message, expectations) {
          expectations = expectations || {};
          try {
            var expectedSigner = expectations.expectedSignerAddress !== undefined ? expectations.expectedSignerAddress : session.__address || undefined;
            var network = expectations.network !== undefined ? expectations.network : session.__network || undefined;
            if (network !== "mainnet" && network !== "testnet-10") network = undefined; // network binding is optional for auth messages
            var request = iface.createMessageSigningRequest({
              message: message,
              scheme: "schnorr",
              network: network,
              expectedSignerAddress: expectedSigner
            });
            var result = await iface.executeSigning(registration, request);
            return result.result.signature;
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "signAuthMessage"));
          }
        },

        /*
         * Frozen-transaction signing — THROUGH the interface: a frozen
         * transaction-signing request over the EXACT unsigned Safe JSON
         * and the EXACT canonical signInputs, with the interface's
         * capability/scheme/live-network/pre+post-identity gates.
         * `expectations` { network, expectedSignerAddress } comes from the
         * caller's session snapshot (web/app-v4.js walletSign); both are
         * REQUIRED by the v1 request contract — fall back to the tracked
         * session identity/network when the caller omits them.
         */
        signInputs: async function (unsignedSafeJson, signInputs, expectations) {
          expectations = expectations || {};
          try {
            var expectedSigner = expectations.expectedSignerAddress !== undefined ? expectations.expectedSignerAddress : session.__address;
            var network = expectations.network !== undefined ? expectations.network : session.__network;
            var request = iface.createTransactionSigningRequest({
              unsignedSafeJson: unsignedSafeJson,
              signInputs: signInputs,
              network: network,
              expectedSignerAddress: expectedSigner
            });
            var result = await iface.executeSigning(registration, request);
            return result.result.signedSafeJson;
          } catch (e) {
            throw toLegacyError(errors.normalizeAdapterFailure(e, "signInputs"));
          }
        }
      };

      /* keep a synchronous mirror of the tracked identity/network for the
       * legacy synchronous getActiveAddress + request defaults. */
      session.__address = null;
      session.__network = null;
      var origConnect = session.connect;
      session.connect = async function () {
        var out = await origConnect();
        session.__address = out.address;
        session.__network = out.network;
        return out;
      };
      var origReconnect = session.reconnect;
      session.reconnect = async function () {
        var out = await origReconnect();
        if (out) {
          session.__address = out.address;
          session.__network = out.network;
        }
        return out;
      };
      var origDisconnect = session.disconnect;
      session.disconnect = async function () {
        await origDisconnect();
        session.__address = null;
        session.__network = null;
      };
      var origGetNetwork = session.getNetwork;
      session.getNetwork = async function () {
        var n = await origGetNetwork();
        session.__network = n;
        return n;
      };
      usi.on("accountChanged", function (address) {
        session.__address = address;
      });
      usi.on("networkChanged", function (network) {
        session.__network = network;
      });

      return session;
    }

    return {
      createKasWareUsiAdapter: createKasWareUsiAdapter,
      createKasWareSessionAdapter: createKasWareSessionAdapter,
      LEGACY_CATEGORY: LEGACY_CATEGORY,
      normalizeNetwork: normalizeNetwork
    };
  }

  if (typeof window !== "undefined" && window.PolicyVaultCore) {
    window.PolicyVaultKasWareSigner = createModule(window.PolicyVaultCore);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createModule: createModule };
  }
})();
