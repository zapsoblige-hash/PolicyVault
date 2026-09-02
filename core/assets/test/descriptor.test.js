"use strict";

/*
 * v0.5 asset descriptor draft — validator tests (DESIGN-STAGE; the
 * module is not imported by any production path). Pins the fail-closed
 * contract the design gate reviews: closed schema, closed enums,
 * versioned refusal, dual-binding presence, hash-convention separation,
 * explicit issuer powers, atomic-amount numeric discipline.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SCHEMA_V1,
  DescriptorError,
  validateAssetDescriptor,
  parseAtomicAmount
} = require("../descriptor.js");

const HEX = (c) => c.repeat(64);

function validDescriptor() {
  return {
    schema: SCHEMA_V1,
    assetId: HEX("a"),
    displayName: "Example Token",
    tokenStandard: "kcc20/1",
    tokenCovenantId: HEX("b"),
    acceptedTransferTemplates: [
      {
        templateVmHashBlake2b256: HEX("c"),
        templateKcc1HashBlake3: HEX("d"),
        prefixLen: 1200,
        suffixLen: 800,
        stateLayout: "kcc20-state/1"
      }
    ],
    decimalsDisplay: 8,
    issuerPowers: {
      mint: true,
      burn: false,
      freeze: false,
      blacklist: false,
      redemptionControl: false,
      upgradeMigration: true,
      controllerRotation: false,
      emergencyControl: false
    },
    notes: "Draft fixture."
  };
}

function refuses(mutate, expectedCode) {
  const d = validDescriptor();
  mutate(d);
  assert.throws(
    () => validateAssetDescriptor(d),
    (e) => e instanceof DescriptorError && e.code === expectedCode,
    `expected ${expectedCode}`
  );
}

test("a valid descriptor normalizes and freezes", () => {
  const out = validateAssetDescriptor(validDescriptor());
  assert.equal(out.schema, SCHEMA_V1);
  assert.ok(Object.isFrozen(out) && Object.isFrozen(out.issuerPowers) && Object.isFrozen(out.acceptedTransferTemplates));
  assert.equal(out.issuerPowers.mint, true);
});

test("unknown schema version fails closed (never routes to a default)", () => {
  refuses((d) => (d.schema = "policyvault-asset-descriptor/2"), "DESCRIPTOR_UNKNOWN_VERSION");
  refuses((d) => delete d.schema, "DESCRIPTOR_UNKNOWN_VERSION");
});

test("closed schema: any unknown field refuses", () => {
  refuses((d) => (d.extra = 1), "DESCRIPTOR_UNKNOWN_FIELD");
  refuses((d) => (d.acceptedTransferTemplates[0].surprise = 1), "DESCRIPTOR_UNKNOWN_FIELD");
  refuses((d) => (d.issuerPowers.pause = true), "DESCRIPTOR_UNKNOWN_FIELD");
});

test("closed enums: unknown standard/state layout refuse", () => {
  refuses((d) => (d.tokenStandard = "krc20/1"), "DESCRIPTOR_UNKNOWN_STANDARD");
  refuses((d) => (d.acceptedTransferTemplates[0].stateLayout = "kcc20-state/2"), "DESCRIPTOR_UNKNOWN_STANDARD");
});

test("DUAL BINDING: template pinning is mandatory, covenant-id alone never suffices", () => {
  refuses((d) => (d.acceptedTransferTemplates = []), "DESCRIPTOR_MISSING_BINDING");
  refuses((d) => delete d.acceptedTransferTemplates, "DESCRIPTOR_MISSING_BINDING");
});

test("hash conventions stay separate: the in-VM blake2b identity is required and never inferred", () => {
  // Missing in-VM hash refuses even when the KCC-0001 hash is present.
  refuses((d) => delete d.acceptedTransferTemplates[0].templateVmHashBlake2b256, "DESCRIPTOR_MALFORMED");
  // The KCC-0001 hash is optional but must be well-formed when present.
  refuses((d) => (d.acceptedTransferTemplates[0].templateKcc1HashBlake3 = "zz"), "DESCRIPTOR_MALFORMED");
  const d = validDescriptor();
  delete d.acceptedTransferTemplates[0].templateKcc1HashBlake3;
  assert.equal(validateAssetDescriptor(d).acceptedTransferTemplates[0].templateKcc1HashBlake3, undefined);
});

test("issuer powers must be EXPLICIT booleans — omission is not deniability", () => {
  refuses((d) => delete d.issuerPowers.freeze, "DESCRIPTOR_MALFORMED");
  refuses((d) => (d.issuerPowers.mint = "yes"), "DESCRIPTOR_MALFORMED");
});

test("hex and bounds discipline", () => {
  refuses((d) => (d.assetId = HEX("A")), "DESCRIPTOR_MALFORMED"); // uppercase refused
  refuses((d) => (d.tokenCovenantId = "1234"), "DESCRIPTOR_MALFORMED");
  refuses((d) => (d.decimalsDisplay = 19), "DESCRIPTOR_MALFORMED");
  refuses((d) => (d.decimalsDisplay = 1.5), "DESCRIPTOR_MALFORMED");
  refuses((d) => (d.acceptedTransferTemplates[0].prefixLen = -1), "DESCRIPTOR_MALFORMED");
  refuses((d) => (d.displayName = ""), "DESCRIPTOR_MALFORMED");
});

test("atomic amounts: sompi-grade rejection discipline, separate domain from KAS", () => {
  assert.equal(parseAtomicAmount("0"), 0n);
  assert.equal(parseAtomicAmount("12345678901234567"), 12345678901234567n);
  for (const bad of ["", "-1", "+1", "01", "1.5", "1e3", " 1", "0x10", "18446744073709551616", 5, null]) {
    assert.throws(() => parseAtomicAmount(bad), DescriptorError, `must refuse ${JSON.stringify(bad)}`);
  }
});
