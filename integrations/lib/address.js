"use strict";

/*
 * Destination-address handling for the adapters.
 *
 * The AUTHORITATIVE decode is `sdk/src/address-identity.js`
 * resolveAddressIdentity — the ONE place PolicyVault converts an address
 * into the canonical 32-byte x-only pubkey, backed exclusively by the
 * rusty-kaspa WASM parser with the mandatory address-version gate ("no
 * hand-rolled bech32"). This module adds PURE literal-form pre-gates in
 * front of it (x402 §3.3 "Destination", adversarial X-3): they refuse
 * obviously non-literal forms cheaply and deterministically, and they
 * NEVER replace the authoritative decode — everything that passes the
 * pre-gates still goes through resolveAddressIdentity, and the final
 * authority over destinations remains the covenant allowlist on chain.
 *
 * The adapter never accepts a raw pubkey, a "role constant", a resolvable
 * name, a URL, or a redirect — indirection is a destination-substitution
 * vector. Only a literal, lowercase, network-prefixed Kaspa bech32
 * address is ever considered.
 */

const { resolveAddressIdentity, requiredAddressPrefix, addressForXOnlyPubkey } = require("../../sdk/src/address-identity");

class AddressError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AddressError";
    this.code = code;
  }
}

/* bech32 payload charset (lowercase only — mixed case refuses). */
const BECH32_BODY_RE = /^[02-9ac-hj-np-z]+$/;

/*
 * Literal-form gate. Distinguishes, per the spec's refusal split:
 *   - NOT_LITERAL: role constants, names, URLs, anything without the
 *     exact `<prefix>:` shape of a Kaspa address literal;
 *   - INVALID: right shape, wrong network prefix / bad charset / mixed
 *     case / non-ASCII (IDN homograph fuel).
 */
function assertLiteralAddressForm(payTo, networkId, { notLiteralCode, invalidCode }) {
  if (typeof payTo !== "string" || payTo.length === 0 || payTo.length > 256) {
    throw new AddressError(notLiteralCode, "destination must be a literal Kaspa address string");
  }
  // eslint-disable-next-line no-control-regex
  if (/[^\x21-\x7e]/.test(payTo)) {
    throw new AddressError(invalidCode, "destination contains non-ASCII or whitespace characters — refusing (homograph/formatting refusal)");
  }
  if (payTo.includes("://") || payTo.includes("/") || payTo.includes("@") || payTo.includes("?")) {
    throw new AddressError(notLiteralCode, "destination looks like a URL/name/indirection — only a literal Kaspa address is accepted");
  }
  const colon = payTo.indexOf(":");
  if (colon <= 0 || payTo.indexOf(":", colon + 1) !== -1) {
    throw new AddressError(notLiteralCode, "destination is not a `prefix:payload` Kaspa address literal");
  }
  const prefix = payTo.slice(0, colon);
  const body = payTo.slice(colon + 1);
  const required = requiredAddressPrefix(networkId); // fails closed on unknown networks
  if (prefix !== required) {
    throw new AddressError(invalidCode, `destination prefix ${JSON.stringify(prefix)} does not match the configured network (${networkId} requires ${required}:) — hard refusal, not a normalization`);
  }
  if (body !== body.toLowerCase()) {
    throw new AddressError(invalidCode, "mixed-case address — refusing");
  }
  if (!BECH32_BODY_RE.test(body)) {
    throw new AddressError(invalidCode, "address payload contains characters outside the bech32 charset — refusing");
  }
  return payTo;
}

/*
 * Full resolution: literal-form gates, then the authoritative WASM decode
 * (network family + address-version "PubKey" gate + 32-byte x-only
 * payload). Returns { address, xOnlyPubkey }.
 */
function resolveLiteralDestination(config, payTo, { notLiteralCode, invalidCode }) {
  assertLiteralAddressForm(payTo, config.networkId, { notLiteralCode, invalidCode });
  let identity;
  try {
    identity = resolveAddressIdentity(config, payTo);
  } catch (error) {
    throw new AddressError(invalidCode, `destination rejected by the authoritative address parser: ${error.message}`);
  }
  return { address: identity.address, xOnlyPubkey: identity.xOnlyPubkey };
}

module.exports = { AddressError, assertLiteralAddressForm, resolveLiteralDestination, requiredAddressPrefix, addressForXOnlyPubkey };
