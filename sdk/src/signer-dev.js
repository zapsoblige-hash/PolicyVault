"use strict";

/*
 * TEST-ONLY development signer (mission §43: clearly labeled unsafe /
 * non-production). It mimics the browser wallet contract exactly — given an
 * unsigned transaction Safe JSON and a list of input indices to sign, it
 * returns the signed transaction Safe JSON with each named input carrying a
 * standard signature-script push — so the wallet-request finalizer can be
 * exercised end-to-end without a browser extension. It NEVER touches the
 * covenant-call encoding or any consensus-visible byte logic; it only
 * produces authorization material at the signer boundary, just like a real
 * wallet adapter.
 *
 * Refuses to operate on mainnet. Holds a testnet key only.
 */

const { loadKaspa } = require("./chain");

function fail(message) {
  throw new Error(`signer-dev: ${message}`);
}

/*
 * Build a dev signer for one account key.
 *   secretHex: 32-byte testnet private key hex
 * Returns an object with the generic signer surface used by the pipeline:
 *   getActiveAddress(), getNetwork(), signInputs(unsignedSafeJson, signInputs)
 */
function makeDevSigner(config, { secretHex, expectedAddress } = {}) {
  if (config.networkId === "mainnet") {
    fail("the development signer must never be used on mainnet");
  }
  if (!/^[0-9a-f]{64}$/.test(secretHex || "")) {
    fail("makeDevSigner requires a 32-byte hex secret");
  }
  const kaspa = loadKaspa(config);
  const priv = new kaspa.PrivateKey(secretHex);
  const address = priv.toPublicKey().toAddress(config.networkId).toString();
  if (expectedAddress && expectedAddress !== address) {
    fail(`dev signer key does not match expected address ${expectedAddress}`);
  }

  return {
    kind: "UNSAFE_DEV_SIGNER",
    provider: "dev",
    capabilities: {
      canSignTransaction: true,
      canSignSpecificInputs: true,
      canReturnRawSignedTx: true,
      canSwitchNetwork: false,
      canExposeXOnlyPubkey: true,
      supportsAccountChangeEvents: false
    },
    getActiveAddress() {
      return address;
    },
    getNetwork() {
      return config.networkId;
    },
    /*
     * Sign the named inputs and return signed Safe JSON. Mirrors KasWare's
     * `signPskt({ txJsonString, options: { signInputs } })` return shape: a
     * transaction whose signed inputs carry a signature-script push of the
     * 65-byte Schnorr signature (64-byte sig + sighash-type byte).
     */
    signInputs(unsignedSafeJson, signInputs) {
      if (typeof unsignedSafeJson !== "string" || !unsignedSafeJson.trim()) {
        fail("signInputs requires the unsigned transaction Safe JSON");
      }
      if (!Array.isArray(signInputs) || signInputs.length === 0) {
        fail("signInputs requires a non-empty list of input indices");
      }
      const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
      for (const entry of signInputs) {
        const index = Number(entry.index ?? entry);
        if (!Number.isInteger(index) || index < 0 || index >= tx.inputs.length) {
          fail(`signInputs index ${entry} out of range`);
        }
        const sigScript = kaspa.createInputSignature(tx, index, priv);
        const ins = tx.inputs;
        ins[index].signatureScript = sigScript;
        tx.inputs = ins;
      }
      return tx.serializeToSafeJSON();
    }
  };
}

module.exports = { makeDevSigner };
