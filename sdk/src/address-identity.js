"use strict";

/*
 * Shared Kaspa address -> covenant identity resolution — the ONE place
 * PolicyVault converts a human-facing wallet address into the canonical
 * 32-byte x-only pubkey the covenant requires. Backed exclusively by the
 * authoritative rusty-kaspa WASM parser (Address / XOnlyPublicKey); no
 * hand-rolled bech32.
 *
 * Only version "PubKey" addresses (32-byte Schnorr x-only payload) are
 * supported, for every role (owner / delegate / recipient): the covenant
 * authorizes delegates and owners with direct Schnorr pubkeys and pays
 * recipients via ScriptPubKeyP2PK(x-only), so the mapping is lossless in
 * both directions ONLY for that type. ScriptHash addresses carry a script
 * hash (no pubkey can be recovered), PubKeyECDSA addresses carry a
 * 33-byte key for the ECDSA path — both fail closed, as do unknown future
 * versions.
 *
 * NOTE: XOnlyPublicKey.fromAddress does NOT check the address version
 * upstream (wallet/keys/src/publickey.rs — it parses the raw payload, so
 * a 32-byte ScriptHash payload would silently "convert"). The version
 * gate below is therefore mandatory, before any payload conversion.
 *
 * The address prefix identifies only the network FAMILY (kaspa /
 * kaspatest); it cannot distinguish testnet-10 from testnet-11. The
 * runtime wallet==server==testnet-10 verification remains the authority —
 * this module adds a family gate, it never replaces network verification.
 */

const { loadKaspa } = require("./chain");

/* Network family gate: configured networkId -> required address prefix. */
const PREFIX_BY_NETWORK = Object.freeze({
  "testnet-10": "kaspatest",
  mainnet: "kaspa"
});

/* The canonical address prefix (without ':') demanded by a configured
 * network. Unknown networks fail closed (Gate R operational set only). */
function requiredAddressPrefix(networkId) {
  const prefix = PREFIX_BY_NETWORK[networkId];
  if (!prefix) throw identityError("NETWORK_UNSUPPORTED", `no address prefix for network ${JSON.stringify(networkId)} — failing closed`);
  return prefix;
}

function identityError(code, message) {
  const e = new Error(message);
  e.code = code;
  e.status = 422;
  return e;
}

/*
 * Resolve a user-entered Kaspa wallet address into the covenant identity:
 *   { address, xOnlyPubkey, network, addressType }
 * `address` is the canonical string form; `xOnlyPubkey` is 64-hex
 * lowercase; `network` is the address family ("testnet" | "mainnet");
 * `addressType` is the address version ("PubKey").
 *
 * Fails closed (Error with .code + user-facing message) on: missing or
 * non-string input, malformed address / bad checksum, wrong network
 * family, unsupported address type, or any payload that does not
 * round-trip exactly to the same address.
 */
function resolveAddressIdentity(config, addressInput) {
  const kaspa = loadKaspa(config);
  const expectedPrefix = PREFIX_BY_NETWORK[config.networkId];
  if (!expectedPrefix) {
    throw identityError("NETWORK_UNSUPPORTED", `no address rules for network ${config.networkId} — failing closed`);
  }

  if (typeof addressInput !== "string" || !addressInput.trim()) {
    throw identityError("ADDRESS_REQUIRED", "Enter a valid Kaspa wallet address.");
  }
  const trimmed = addressInput.trim();
  if (!kaspa.Address.validate(trimmed)) {
    throw identityError("ADDRESS_INVALID", "Enter a valid Kaspa wallet address.");
  }
  const address = new kaspa.Address(trimmed);

  if (address.prefix !== expectedPrefix) {
    throw identityError(
      "ADDRESS_WRONG_NETWORK",
      `That address is not valid for the current network — a ${expectedPrefix}: address is required.`
    );
  }

  if (address.version === "ScriptHash") {
    throw identityError(
      "ADDRESS_TYPE_UNSUPPORTED",
      "That Kaspa address type (script-hash) cannot be used here. PolicyVault requires a standard Schnorr public-key address."
    );
  }
  if (address.version === "PubKeyECDSA") {
    throw identityError(
      "ADDRESS_TYPE_UNSUPPORTED",
      "That Kaspa address type (ECDSA) cannot be used here. PolicyVault requires a standard Schnorr public-key address."
    );
  }
  if (address.version !== "PubKey") {
    // Unknown future versions fail closed — never routed to a default.
    throw identityError(
      "ADDRESS_TYPE_UNSUPPORTED",
      `That Kaspa address type (${address.version}) cannot be used here. PolicyVault requires a standard Schnorr public-key address.`
    );
  }

  let xOnlyPubkey;
  try {
    xOnlyPubkey = kaspa.XOnlyPublicKey.fromAddress(address).toString().toLowerCase();
  } catch (e) {
    throw identityError("ADDRESS_PAYLOAD_INVALID", "That address does not contain a usable public key.");
  }
  if (!/^[0-9a-f]{64}$/.test(xOnlyPubkey)) {
    throw identityError("ADDRESS_PAYLOAD_INVALID", "That address does not contain a usable public key.");
  }

  // Exactness guarantee: the derived key must reproduce the same address.
  const canonical = address.toString();
  const roundTrip = new kaspa.XOnlyPublicKey(xOnlyPubkey).toAddress(config.networkId).toString();
  if (roundTrip !== canonical) {
    throw identityError("ADDRESS_PAYLOAD_INVALID", "That address does not map unambiguously to a public key.");
  }

  return Object.freeze({
    address: canonical,
    xOnlyPubkey,
    network: address.prefix === "kaspatest" ? "testnet" : "mainnet",
    addressType: address.version
  });
}

/* Display-only reverse mapping: canonical x-only pubkey -> wallet address. */
function addressForXOnlyPubkey(config, xOnlyPubkey) {
  const kaspa = loadKaspa(config);
  if (typeof xOnlyPubkey !== "string" || !/^[0-9a-f]{64}$/.test(xOnlyPubkey)) {
    throw identityError("PUBKEY_INVALID", "internal: addressForXOnlyPubkey requires 64-hex x-only");
  }
  return new kaspa.XOnlyPublicKey(xOnlyPubkey).toAddress(config.networkId).toString();
}

module.exports = { resolveAddressIdentity, addressForXOnlyPubkey, requiredAddressPrefix };
