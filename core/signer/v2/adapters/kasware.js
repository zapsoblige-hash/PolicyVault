"use strict";
const { ownGet } = require("../../../model/own-get");

/*
 * PolicyVault Universal Signer Interface v2 — KasWare capability PROFILE.
 *
 * DOM-FREE BY CONSTRUCTION. This module holds the truthful v2
 * declarations for the KasWare browser extension and the pure function
 * that turns an OBSERVED provider report into a v2 probe report. It never
 * touches `window`, never probes anything itself, and performs no I/O —
 * exactly the split the mobile portable layer already uses
 * (mobile/www/js/portable/signer-capabilities.js negotiateInjectedProvider):
 * the browser layer observes, this layer judges.
 *
 * web/signer-kasware-adapter.js composes these declarations with the
 * EXISTING, unchanged v1 KasWare adapter through core/signer/v2/adapters/
 * lift.js. No production signing semantics change: the same
 * `kw.signMessage(message, { type: "schnorr" })` and
 * `kw.signPskt({ txJsonString, options: { signInputs } })` calls are made,
 * with the same arguments, by the same v1 adapter code.
 *
 * WHY EACH DECLARATION IS WHAT IT IS (evidence, not assumption):
 *
 *   sighash: { all: true, none/single/anyoneCanPay: false }
 *       The production flow emits ONLY `{ index, sighashType: 1 }`
 *       entries (web/app-v4.js assertCanonicalSignInputs; the
 *       server/SDK build path in sdk/src/wallet-requests-v4.js maps every
 *       input to sighashType 1). This project has never verified KasWare
 *       accepting any other sighash type, so the adapter declares only
 *       what it uses and can stand behind. A descriptor may offer LESS
 *       than its provider; it may never offer more.
 *
 *   pskt: { supported: false, roles: [] }
 *       The provider method is NAMED `signPskt`, but its payload is
 *       `{ txJsonString, options: { signInputs } }` and its return value
 *       is a Kaspa **Safe JSON transaction serialization** — the exact
 *       string the SDK feeds to `Transaction.deserializeFromSafeJSON`
 *       (web/wallet.js, sdk/src/signer-dev.js "Mirrors KasWare's signPskt
 *       return shape", sdk/src/wallet-requests-v4.js). It is NOT a
 *       BIP-370 partially-signed-transaction bundle: rusty-kaspa's real
 *       PSKT lives in `wallet/pskt` (roles in `wallet/pskt/src/role.rs`,
 *       WASM class `PSKT`) and nothing in this path constructs, combines,
 *       finalizes or extracts one. Declaring pskt support because of the
 *       method's NAME would be exactly the kind of unverified capability
 *       claim v2 exists to make impossible.
 *
 *   transactionFormats: ["kaspa-safe-json/1"]   — per the above.
 *   userPresence: "required"                    — the extension opens a
 *       popup and a human clicks Sign for every signature.
 *   transport: "in-page"                        — injected provider in
 *       the same page.
 *   cancellation: "unsupported"                 — KasWare exposes no
 *       cancellation API (docs/postlaunch/signer-kasware-mapping.md §2);
 *       consumers needing revocable approvals must refuse it, and now
 *       structurally do.
 *
 * Pure CommonJS, browser-portable. Zero external dependencies.
 */

const { SIGNER_INTERFACE_VERSION_V2 } = require("../errors");
const { TRANSACTION_FORMATS, SIGNER_NETWORKS } = require("../interface");

/* Frozen v2 declaration set for the KasWare browser extension. */
const KASWARE_V2_DECLARATIONS = Object.freeze({
  sighash: Object.freeze({ all: true, none: false, single: false, anyoneCanPay: false }),
  pskt: Object.freeze({ supported: false, roles: Object.freeze([]) }),
  transactionFormats: Object.freeze([TRANSACTION_FORMATS[0]]),
  userPresence: "required",
  transport: "in-page",
  cancellation: "unsupported",
  /* A human may leave the popup open; five minutes is the longest wait
   * this adapter will claim it can honour. */
  maxTimeoutMs: 300000
});

/*
 * Provider method name -> interface method name. The probe vocabulary is
 * the INTERFACE's, so the translation happens here, once, where the
 * evidence for it lives.
 */
const PROVIDER_METHOD_MAP = Object.freeze({
  signMessage: "signMessage",
  signPskt: "signTransaction",
  on: "on"
});

/* Exactly the provider surface the v1 KasWare adapter drives. A provider
 * missing any of these cannot support the declared features. */
const REQUIRED_PROVIDER_METHODS = Object.freeze(["requestAccounts", "getAccounts", "getNetwork", "getPublicKey", "signMessage", "signPskt"]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/*
 * probeKasWareProvider(found) -> a v2 probe report.
 *
 * `found` is the browser layer's HONEST observation of the injected
 * provider — NOT the provider object itself:
 *   { present: boolean, methods: [<provider method names>],
 *     network: <normalized network id> | null }
 *
 * Rules:
 *   - no provider  -> probed: false with the reason (never an optimistic
 *     "assume it is there"); the v2 core then refuses any consumer that
 *     required probed capabilities, and the descriptor's declarations are
 *     never silently accepted as observations;
 *   - a provider present but missing a method the declared features need
 *     is reported as probed WITHOUT that method, so
 *     verifyDeclaredCapabilities raises CAPABILITY_MISMATCH — the refusal
 *     happens before a popup opens, not after a human clicks Sign;
 *   - sighash / pskt / transaction formats are reported as this project
 *     has evidence for them, and no further.
 */
function probeKasWareProvider(found) {
  const f = isPlainObject(found) ? found : {};
  if (f.present !== true) {
    return {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: false,
      reason: "no KasWare provider is injected into this page — capabilities cannot be observed"
    };
  }
  const observed = Array.isArray(f.methods) ? f.methods : [];
  const methods = [];
  for (const name of observed) {
    const mapped = ownGet(PROVIDER_METHOD_MAP, name);
    if (mapped !== undefined && !methods.includes(mapped)) methods.push(mapped);
  }
  const report = {
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    probed: true,
    methods,
    /* KasWare is driven with SIGHASH_ALL only; nothing else is claimed on
     * its behalf. `false` here would ASSERT the provider cannot do it —
     * which this project has not established — so the other flags are
     * simply reported as unsupported-by-this-adapter, matching what the
     * descriptor declares. */
    sighash: { all: methods.includes("signTransaction"), none: false, single: false, anyoneCanPay: false },
    /* the signPskt method is a Safe-JSON transaction signer, not a PSKT
     * surface (see the header) */
    pskt: { supported: false, roles: [] },
    transactionFormats: methods.includes("signTransaction") ? [TRANSACTION_FORMATS[0]] : []
  };
  if (typeof f.network === "string" && SIGNER_NETWORKS.includes(f.network)) report.network = f.network;
  return report;
}

/* Convenience for the browser layer: the list of provider method names to
 * look for on the injected object. Kept here so the observation site has
 * no hard-coded knowledge of its own. */
function providerMethodNames() {
  return [...REQUIRED_PROVIDER_METHODS, "on", "disconnect"];
}

module.exports = {
  KASWARE_V2_DECLARATIONS,
  PROVIDER_METHOD_MAP,
  REQUIRED_PROVIDER_METHODS,
  probeKasWareProvider,
  providerMethodNames
};
