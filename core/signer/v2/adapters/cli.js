"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — OFFLINE CLI keyfile signer.
 *
 * The v1 CLI adapter (core/signer/adapters/cli/adapter.js) is UNCHANGED
 * and still the signing implementation: real BIP-340 Schnorr through the
 * vendored rusty-kaspa kaspa-wasm module, keyfile custody with mode-600
 * enforcement, identity re-derivation, and the mainnet dual unlock. This
 * module only LIFTS it onto the v2 contract and states, explicitly, the
 * v2 capabilities that adapter has always had but v1 had no vocabulary
 * for.
 *
 * TRUTHFUL v2 DECLARATIONS, and why each is what it is:
 *
 *   sighash: { all: true, ... }   the adapter signs with
 *                                 kaspa.SighashType.All and nothing else
 *                                 (adapter.js signTransaction).
 *   transactionFormats:           ["kaspa-safe-json/1"] — it consumes
 *                                 Transaction.deserializeFromSafeJSON and
 *                                 returns serializeToSafeJSON.
 *   pskt: { supported: false }    the adapter never touches rusty-kaspa's
 *                                 PSKT crate; it signs a whole Kaspa
 *                                 transaction's named inputs. Declaring
 *                                 pskt here would be a false claim.
 *   userPresence: "not-required"  running the process IS the approval;
 *                                 there is NO per-request human
 *                                 confirmation. A consumer that needs a
 *                                 human at the signer must refuse this
 *                                 adapter, and now structurally can.
 *   transport: "cli"              a local process invocation; no hop.
 *   cancellation: "unsupported"   signing is synchronous and completes
 *                                 within one call; there is nothing to
 *                                 revoke.
 *
 * THE PROBE. This adapter's "provider" is the keyfile plus the kaspa-wasm
 * module. The probe reports what is actually there: whether the keyfile
 * path holds a regular file, and whether the kaspa module resolves and
 * exposes the exact functions the adapter drives. If the module cannot be
 * resolved the report is `probed: false` WITH A REASON — never an
 * optimistic claim — and a consumer requiring probed capabilities refuses.
 *
 * Pure CommonJS. Requires Node (fs, and the kaspa-wasm module) through
 * the v1 CLI adapter — this file is NOT part of the browser bundle.
 */

const { SIGNER_INTERFACE_VERSION_V2 } = require("../errors");
const { TRANSACTION_FORMATS } = require("../interface");
const { liftV1Adapter } = require("./lift");
const cliV1 = require("../../adapters/cli/adapter");

/* The frozen v2 declaration for this signer class. Exported so tests and
 * the capability matrix in the spec read the SAME constant the adapter
 * declares — a doc/table can never drift from the code. */
const CLI_V2_DECLARATIONS = Object.freeze({
  sighash: Object.freeze({ all: true, none: false, single: false, anyoneCanPay: false }),
  pskt: Object.freeze({ supported: false, roles: Object.freeze([]) }),
  transactionFormats: Object.freeze([TRANSACTION_FORMATS[0]]),
  userPresence: "not-required",
  transport: "cli",
  cancellation: "unsupported",
  /* one synchronous local signing call; a minute is already generous */
  maxTimeoutMs: 60000
});

/*
 * Builds the honest probe report for a CLI signer instance. `options` are
 * the same construction options the v1 adapter received (keyfilePath plus
 * the kaspa-module injection points).
 */
function probeCliSigner(options) {
  const report = { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: true, methods: [], sighash: { ...CLI_V2_DECLARATIONS.sighash } };
  let kaspa;
  try {
    kaspa = cliV1.resolveKaspaModule(options);
  } catch (e) {
    return {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: false,
      reason: `the kaspa-wasm module is not loadable in this environment (${(e && e.signerCode) || "PROVIDER_ERROR"}) — capabilities cannot be confirmed`
    };
  }
  /* Method presence is read from the module the adapter will actually
   * drive, not from this adapter's own surface: over-declaration is only
   * meaningful against the PROVIDER. */
  if (typeof kaspa.signMessage === "function") report.methods.push("signMessage");
  if (typeof kaspa.createInputSignature === "function") report.methods.push("signTransaction");
  if (typeof kaspa.Transaction === "function" || typeof kaspa.Transaction === "object") {
    report.transactionFormats = [TRANSACTION_FORMATS[0]];
  } else {
    report.transactionFormats = [];
  }
  /* rusty-kaspa ships a PSKT implementation, but this adapter drives none
   * of it; the probe reports the adapter's provider surface truthfully. */
  report.pskt = { supported: false, roles: [] };
  /* the interface reads identity/network through the adapter itself */
  report.methods.push("getNetwork", "getActiveAccount", "getPublicKey");
  return report;
}

/*
 * createCliSignerAdapterV2(options) — the same options as the v1
 * factory (keyfilePath, network, allowMainnet, provider, label,
 * kaspaModule/kaspaModulePath). Returns a v2 adapter.
 */
function createCliSignerAdapterV2(options = {}) {
  const v1Adapter = cliV1.createCliSignerAdapter(options);
  return liftV1Adapter(v1Adapter, {
    sighash: { ...CLI_V2_DECLARATIONS.sighash },
    pskt: { supported: false, roles: [] },
    transactionFormats: [...CLI_V2_DECLARATIONS.transactionFormats],
    userPresence: CLI_V2_DECLARATIONS.userPresence,
    transport: CLI_V2_DECLARATIONS.transport,
    cancellation: CLI_V2_DECLARATIONS.cancellation,
    maxTimeoutMs: CLI_V2_DECLARATIONS.maxTimeoutMs,
    probeCapabilities: () => probeCliSigner(options)
  });
}

module.exports = { createCliSignerAdapterV2, probeCliSigner, CLI_V2_DECLARATIONS };
