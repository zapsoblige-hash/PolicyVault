"use strict";

/*
 * Voluntary-support donation address validation (Checkpoint I §8/§9).
 *
 * The donation destination is an explicitly configured PUBLIC mainnet Kaspa
 * address owned by the project owner (docs/product-policy.md). It is NEVER
 * derived from the connected wallet, a vault owner, a testnet account, or any
 * developer key, and PolicyVault stores no private key for it.
 *
 * Validation is canonical and fails closed:
 *   - syntax + checksum via the kaspa wasm Address parser;
 *   - network: the MAINNET prefix `kaspa:` is required regardless of the
 *     process network (a testnet address must never render in production);
 *   - address type: standard spendable wallet addresses only — PubKey
 *     (Schnorr) or PubKeyECDSA. This is a RECEIVING address, not a covenant
 *     identity, so ECDSA is acceptable here (covenant roles remain
 *     Schnorr-only through the separate address-identity boundary);
 *     ScriptHash and unknown future versions fail closed.
 */

const { loadKaspa } = require("./chain");

function donationError(code, message) {
  const e = new Error(message);
  e.code = code;
  e.status = 422;
  return e;
}

const SUPPORTED_TYPES = Object.freeze(["PubKey", "PubKeyECDSA"]);

function validateDonationAddress(config, addressInput) {
  if (addressInput === undefined || addressInput === null || String(addressInput).trim() === "") {
    throw donationError("DONATION_NOT_CONFIGURED", "No donation address is configured.");
  }
  const trimmed = String(addressInput).trim();
  const kaspa = loadKaspa(config);
  if (!kaspa.Address.validate(trimmed)) {
    throw donationError("DONATION_ADDRESS_INVALID", "The configured donation address is not a valid Kaspa address (syntax/checksum).");
  }
  const address = new kaspa.Address(trimmed);
  if (address.prefix !== "kaspa") {
    throw donationError("DONATION_WRONG_NETWORK", `The configured donation address is a ${address.prefix}: address — a MAINNET kaspa: address is required.`);
  }
  if (!SUPPORTED_TYPES.includes(address.version)) {
    throw donationError("DONATION_TYPE_UNSUPPORTED", `The configured donation address type (${address.version}) is not a standard spendable wallet address.`);
  }
  return Object.freeze({ address: address.toString(), addressType: address.version, network: "mainnet" });
}

module.exports = { validateDonationAddress, SUPPORTED_TYPES };
