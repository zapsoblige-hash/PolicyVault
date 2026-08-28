"use strict";

/*
 * UNIT — Universal Signer Interface v1: adapter conformance.
 * A valid mock adapter registers; every broken-contract variant is
 * REFUSED with a structured error (never partially accepted, never
 * defaulted).
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  validateCapabilityDescriptor,
  validateAdapter,
  SignerRegistry,
  createMockSignerAdapter
} = require("../index");

function brokenDescriptor(mutate) {
  const adapter = createMockSignerAdapter();
  const base = adapter.describe();
  mutate(base);
  return { ...adapter, describe: () => base };
}

test("valid mock adapter passes validation and registration (sync mode)", () => {
  const adapter = createMockSignerAdapter();
  const record = validateAdapter(adapter);
  assert.equal(record.descriptor.interfaceVersion, SIGNER_INTERFACE_VERSION);
  assert.equal(record.descriptor.provider, "mock");
  assert.equal(record.descriptor.kind, "mock");
  assert.deepEqual([...record.descriptor.schemes], ["schnorr"]);
  assert.equal(record.descriptor.features.messageSigning, true);
  assert.ok(Object.isFrozen(record.descriptor));
  assert.ok(Object.isFrozen(record.descriptor.features));

  const registry = new SignerRegistry();
  const descriptor = registry.register(adapter);
  assert.equal(descriptor.provider, "mock");
  assert.ok(registry.has("mock"));
  assert.equal(registry.get("mock").adapter, adapter);
  assert.equal(registry.list().length, 1);
});

test("valid async-approval mock adapter passes validation", () => {
  const adapter = createMockSignerAdapter({ provider: "mock-async", asyncApproval: true });
  const record = validateAdapter(adapter);
  assert.equal(record.descriptor.features.asynchronousApproval, true);
});

test("descriptor with unknown interface version is refused fail-closed", () => {
  const adapter = brokenDescriptor((d) => {
    d.interfaceVersion = "policyvault-signer/2";
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED);
});

test("descriptor missing the interface version is refused", () => {
  const adapter = brokenDescriptor((d) => {
    delete d.interfaceVersion;
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED);
});

test("descriptor declaring an unknown scheme is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.schemes = ["schnorr", "quantum"];
  });
  assert.throws(
    () => validateAdapter(adapter),
    (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /unknown value "quantum"/.test(e.message)
  );
});

test("descriptor with empty schemes is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.schemes = [];
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("descriptor with duplicate scheme entries is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.schemes = ["schnorr", "schnorr"];
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /more than once/.test(e.message));
});

test("descriptor declaring an unknown network is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.networks = ["testnet-10", "testnet-11"];
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /testnet-11/.test(e.message));
});

test("descriptor with unknown adapter kind is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.kind = "smartwatch";
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("descriptor with an unknown top-level key is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.custody = "server-side"; // structurally inexpressible: even the KEY is refused
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /unknown key "custody"/.test(e.message));
});

test("descriptor declaring an unknown feature is refused (unknown capabilities never ignored)", () => {
  const adapter = brokenDescriptor((d) => {
    d.features = { ...d.features, keyExport: true };
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /keyExport/.test(e.message));
});

test("descriptor omitting a feature is refused (explicit declaration, no defaults)", () => {
  const adapter = brokenDescriptor((d) => {
    const f = { ...d.features };
    delete f.airGapped;
    d.features = f;
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /airGapped/.test(e.message));
});

test("descriptor with a non-boolean feature value is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.features = { ...d.features, messageSigning: "yes" };
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /strictly boolean/.test(e.message));
});

test("descriptor with a malformed provider id is refused", () => {
  const adapter = brokenDescriptor((d) => {
    d.provider = "Mock Signer!";
  });
  assert.throws(() => validateAdapter(adapter), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("adapter missing an unconditional method is refused", () => {
  const adapter = createMockSignerAdapter();
  const broken = { ...adapter };
  delete broken.getNetwork;
  assert.throws(
    () => validateAdapter(broken),
    (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /getNetwork/.test(e.message)
  );
});

test("declared messageSigning without signMessage is refused", () => {
  const adapter = createMockSignerAdapter();
  const broken = { ...adapter };
  delete broken.signMessage;
  assert.throws(
    () => validateAdapter(broken),
    (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /signMessage \(required by feature messageSigning\)/.test(e.message)
  );
});

test("declared transactionSigning without signTransaction is refused", () => {
  const adapter = createMockSignerAdapter();
  const broken = { ...adapter };
  delete broken.signTransaction;
  assert.throws(() => validateAdapter(broken), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /signTransaction/.test(e.message));
});

test("declared asynchronousApproval without cancelSigning is refused", () => {
  const adapter = createMockSignerAdapter({ asyncApproval: true });
  const broken = { ...adapter };
  delete broken.cancelSigning;
  assert.throws(() => validateAdapter(broken), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /cancelSigning/.test(e.message));
});

test("declared accountEvents without on() is refused", () => {
  const adapter = createMockSignerAdapter();
  const broken = { ...adapter };
  delete broken.on;
  assert.throws(() => validateAdapter(broken), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /\bon \(required by feature accountEvents\)/.test(e.message));
});

test("adapter without describe() is refused", () => {
  assert.throws(() => validateAdapter({}), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /describe/.test(e.message));
});

test("adapter whose describe() throws is refused with the failure preserved", () => {
  const adapter = createMockSignerAdapter();
  const broken = {
    ...adapter,
    describe() {
      throw new Error("provider exploded");
    }
  };
  assert.throws(() => validateAdapter(broken), (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && /provider exploded/.test(e.message));
});

test("duplicate provider registration is refused", () => {
  const registry = new SignerRegistry();
  registry.register(createMockSignerAdapter());
  assert.throws(
    () => registry.register(createMockSignerAdapter()),
    (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && /already registered/.test(e.message)
  );
});

test("registry lookup of an unregistered provider fails closed", () => {
  const registry = new SignerRegistry();
  assert.throws(() => registry.get("kasware"), (e) => e.signerCode === SignerErrorCodes.SIGNER_NOT_FOUND);
});

test("validated descriptor is deep-frozen and normalized (adapter mutation cannot leak in later)", () => {
  const descriptor = validateCapabilityDescriptor(createMockSignerAdapter().describe());
  assert.ok(Object.isFrozen(descriptor));
  assert.ok(Object.isFrozen(descriptor.schemes));
  assert.ok(Object.isFrozen(descriptor.networks));
  assert.ok(Object.isFrozen(descriptor.features));
  assert.throws(() => {
    descriptor.features.messageSigning = false;
  }, TypeError);
});
