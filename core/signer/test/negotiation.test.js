"use strict";

/*
 * UNIT — Universal Signer Interface v1: capability negotiation.
 * Consumers express requirements against the closed vocabularies; an
 * adapter that cannot satisfy them is refused with a structured result,
 * and malformed/unknown requirements are themselves refused fail-closed.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SignerErrorCodes,
  negotiateCapabilities,
  requireCapabilities,
  createMockSignerAdapter
} = require("../index");

function descriptorOf(options) {
  return createMockSignerAdapter(options).describe();
}

test("consumer requiring schnorr refuses an ecdsa-only adapter (Tangem-class)", () => {
  const ecdsaOnly = descriptorOf({ provider: "tangem-like", schemes: ["ecdsa"] });
  const result = negotiateCapabilities(ecdsaOnly, { schemes: ["schnorr"] });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodes.UNSUPPORTED_SCHEME);
  assert.deepEqual([...result.missing], ["schnorr"]);
  assert.ok(Object.isFrozen(result));
});

test("requireCapabilities throws the structured refusal for the schnorr-vs-ecdsa case", () => {
  const ecdsaOnly = descriptorOf({ provider: "tangem-like", schemes: ["ecdsa"] });
  assert.throws(
    () => requireCapabilities(ecdsaOnly, { schemes: ["schnorr"] }),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_SCHEME && e.details.missing.includes("schnorr")
  );
});

test("schnorr-capable adapter satisfies a schnorr requirement", () => {
  const result = negotiateCapabilities(descriptorOf({}), { schemes: ["schnorr"] });
  assert.deepEqual({ ...result }, { ok: true, provider: "mock" });
});

test("adapter declaring both schemes satisfies either requirement", () => {
  const both = descriptorOf({ provider: "dual", schemes: ["schnorr", "ecdsa"] });
  assert.equal(negotiateCapabilities(both, { schemes: ["schnorr"] }).ok, true);
  assert.equal(negotiateCapabilities(both, { schemes: ["ecdsa"] }).ok, true);
  assert.equal(negotiateCapabilities(both, { schemes: ["schnorr", "ecdsa"] }).ok, true);
});

test("missing feature refuses with UNSUPPORTED_CAPABILITY listing exactly the gaps", () => {
  const noHardware = descriptorOf({});
  const result = negotiateCapabilities(noHardware, { features: ["messageSigning", "hardwareDisplay", "airGapped"] });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodes.UNSUPPORTED_CAPABILITY);
  assert.deepEqual([...result.missing], ["hardwareDisplay", "airGapped"]);
});

test("network requirement not declared by the adapter refuses with WRONG_NETWORK", () => {
  const testnetOnly = descriptorOf({ networks: ["testnet-10"] });
  const result = negotiateCapabilities(testnetOnly, { network: "mainnet" });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodes.WRONG_NETWORK);
  assert.deepEqual([...result.missing], ["mainnet"]);
});

test("declared network satisfies the requirement", () => {
  const both = descriptorOf({ networks: ["mainnet", "testnet-10"] });
  assert.equal(negotiateCapabilities(both, { network: "mainnet" }).ok, true);
});

test("combined requirements must ALL hold", () => {
  const desc = descriptorOf({ networks: ["testnet-10"], schemes: ["schnorr"] });
  assert.equal(negotiateCapabilities(desc, { schemes: ["schnorr"], features: ["transactionSigning"], network: "testnet-10" }).ok, true);
  assert.equal(negotiateCapabilities(desc, { schemes: ["schnorr"], network: "mainnet" }).ok, false);
});

test("unknown requirement key is refused fail-closed (never silently unmatched)", () => {
  assert.throws(
    () => negotiateCapabilities(descriptorOf({}), { keyCustody: true }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown requirement key/.test(e.message)
  );
});

test("unknown required scheme value is refused fail-closed", () => {
  assert.throws(
    () => negotiateCapabilities(descriptorOf({}), { schemes: ["quantum"] }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID
  );
});

test("unknown required feature value is refused fail-closed", () => {
  assert.throws(
    () => negotiateCapabilities(descriptorOf({}), { features: ["timeTravel"] }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID
  );
});

test("unknown required network value is refused fail-closed", () => {
  assert.throws(
    () => negotiateCapabilities(descriptorOf({}), { network: "testnet-11" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID
  );
});

test("empty requirement arrays are refused (a vacuous requirement is a caller bug)", () => {
  assert.throws(() => negotiateCapabilities(descriptorOf({}), { schemes: [] }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => negotiateCapabilities(descriptorOf({}), { features: [] }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
});

test("negotiation revalidates the descriptor (a corrupted descriptor cannot negotiate)", () => {
  const corrupted = { ...descriptorOf({}), schemes: ["quantum"] };
  assert.throws(() => negotiateCapabilities(corrupted, { schemes: ["schnorr"] }), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
});
