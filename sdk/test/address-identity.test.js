"use strict";

/*
 * UNIT — shared Kaspa address -> covenant identity resolution
 * (sdk/src/address-identity.js), against the REAL rusty-kaspa WASM parser.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const { loadKaspa } = require("../src/chain");
const { resolveAddressIdentity, addressForXOnlyPubkey } = require("../src/address-identity");

const config = loadConfig();
const kaspa = loadKaspa(config);

const X = "cbaedc26f03fd3ba02fc936f338e980c9e2172c5e23128877ed46827e935296f";
const ADDR = new kaspa.XOnlyPublicKey(X).toAddress(config.networkId).toString();

const code = (expected) => (e) => e.code === expected;

test("valid testnet PubKey address -> exact 32-byte x-only pubkey", () => {
  const id = resolveAddressIdentity(config, ADDR);
  assert.equal(id.xOnlyPubkey, X);
  assert.equal(id.address, ADDR);
  assert.equal(id.addressType, "PubKey");
  assert.equal(id.network, "testnet");
});

test("round trip: x-only -> address -> same x-only", () => {
  const addr = addressForXOnlyPubkey(config, X);
  assert.equal(addr, ADDR);
  assert.equal(resolveAddressIdentity(config, addr).xOnlyPubkey, X);
});

test("surrounding whitespace accepted (trim rule, matching normalizeHex)", () => {
  assert.equal(resolveAddressIdentity(config, `  ${ADDR}\n`).xOnlyPubkey, X);
});

test("malformed address / checksum failure rejected", () => {
  assert.throws(() => resolveAddressIdentity(config, "kaspatest:qq123"), code("ADDRESS_INVALID"));
  const flipped = ADDR.slice(0, -1) + (ADDR.endsWith("a") ? "b" : "a");
  assert.throws(() => resolveAddressIdentity(config, flipped), code("ADDRESS_INVALID"));
  assert.throws(() => resolveAddressIdentity(config, "not an address"), code("ADDRESS_INVALID"));
  assert.throws(() => resolveAddressIdentity(config, X), code("ADDRESS_INVALID")); // raw pubkey is not an address
});

test("wrong network family (mainnet address on testnet) rejected", () => {
  const mainnet = new kaspa.XOnlyPublicKey(X).toAddress("mainnet").toString();
  assert.throws(() => resolveAddressIdentity(config, mainnet), code("ADDRESS_WRONG_NETWORK"));
});

test("ScriptHash address rejected (no pubkey is recoverable from a script hash)", () => {
  const spk = kaspa.payToScriptHashScript("51");
  const p2sh = kaspa.addressFromScriptPublicKey(spk, config.networkId).toString();
  assert.throws(() => resolveAddressIdentity(config, p2sh), code("ADDRESS_TYPE_UNSUPPORTED"));
});

test("PubKeyECDSA address rejected (covenant uses the Schnorr path)", () => {
  const ecdsa = new kaspa.PublicKey(`02${X}`).toAddressECDSA(config.networkId).toString();
  assert.throws(() => resolveAddressIdentity(config, ecdsa), code("ADDRESS_TYPE_UNSUPPORTED"));
});

test("missing / empty / non-string input rejected", () => {
  assert.throws(() => resolveAddressIdentity(config, ""), code("ADDRESS_REQUIRED"));
  assert.throws(() => resolveAddressIdentity(config, "   "), code("ADDRESS_REQUIRED"));
  assert.throws(() => resolveAddressIdentity(config, null), code("ADDRESS_REQUIRED"));
  assert.throws(() => resolveAddressIdentity(config, undefined), code("ADDRESS_REQUIRED"));
  assert.throws(() => resolveAddressIdentity(config, 42), code("ADDRESS_REQUIRED"));
  assert.throws(() => resolveAddressIdentity(config, { address: ADDR }), code("ADDRESS_REQUIRED"));
});

test("unknown configured network fails closed", () => {
  assert.throws(
    () => resolveAddressIdentity({ ...config, networkId: "testnet-11" }, ADDR),
    code("NETWORK_UNSUPPORTED")
  );
});

test("error messages are user-facing, not 32-byte-hex jargon", () => {
  try {
    resolveAddressIdentity(config, "junk");
    assert.fail("should throw");
  } catch (e) {
    assert.match(e.message, /Kaspa wallet address/);
    assert.doesNotMatch(e.message, /32-byte|x-only|hex/i);
  }
});
