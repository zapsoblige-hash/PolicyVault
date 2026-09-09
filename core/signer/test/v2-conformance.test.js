"use strict";

/*
 * UNIT — Universal Signer Interface v2: descriptor conformance, adapter
 * registration, capability negotiation, and the ADDITIVE-VERSIONING
 * boundary between v1 and v2.
 *
 * The load-bearing property proven here is that v1 is untouched: a v1
 * descriptor is refused by v2, a v2 descriptor is refused by v1, and both
 * cores keep working side by side in one process.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const v1 = require("../index");
const {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  SIGHASH_FLAGS,
  TRANSACTION_FORMATS,
  PSKT_ROLES,
  TRANSPORT_KINDS,
  USER_PRESENCE_MODES,
  CANCELLATION_MODES,
  SIGNING_STATES_V2,
  REQUIRED_METHODS_V2,
  DESCRIPTOR_KEYS_V2,
  POLICYVAULT_TRANSACTION_REQUIREMENTS,
  validateCapabilityDescriptorV2,
  validateAdapterV2,
  SignerRegistryV2,
  negotiateCapabilitiesV2,
  requireCapabilitiesV2,
  verifyDeclaredCapabilities,
  createMockSignerAdapterV2
} = require("../v2");

function brokenDescriptor(mutate, options) {
  const adapter = createMockSignerAdapterV2(options);
  const base = adapter.describe();
  mutate(base);
  return { ...adapter, describe: () => base };
}

/* ============ additive versioning: v1 and v2 refuse each other ======== */

test("v1 is untouched: the frozen v1 core still validates its own adapters and still refuses a v2 version string", () => {
  const v1Adapter = v1.createMockSignerAdapter();
  const record = v1.validateAdapter(v1Adapter);
  assert.equal(record.descriptor.interfaceVersion, "policyvault-signer/1");

  const v2Adapter = createMockSignerAdapterV2();
  assert.throws(() => v1.validateAdapter(v2Adapter), (e) => e.signerCode === v1.SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED);
});

test("v2 refuses a v1 descriptor by EXACT-EQUALITY version matching — no downgrade path exists", () => {
  const v1Adapter = v1.createMockSignerAdapter();
  assert.throws(() => validateAdapterV2(v1Adapter), (e) => e.signerCode === SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED);
});

test("the v2 error vocabulary is a strict superset of v1's, with v1 meanings preserved", () => {
  for (const [name, code] of Object.entries(v1.SignerErrorCodes)) {
    assert.equal(SignerErrorCodesV2[name], code, `v1 code ${name} must keep its exact value in v2`);
  }
  const v2Only = Object.keys(SignerErrorCodesV2).filter((k) => !(k in v1.SignerErrorCodes));
  assert.deepEqual(v2Only.sort(), [
    "CAPABILITY_MISMATCH",
    "DUPLICATE_SETTLEMENT",
    "PAYLOAD_MUTATED",
    "REPLAY_DETECTED",
    "REQUEST_CANCELLED",
    "REQUEST_EXPIRED",
    "RESPONSE_BINDING_MISMATCH",
    "TRANSPORT_UNSUPPORTED",
    "UNSUPPORTED_SIGHASH",
    "UNSUPPORTED_TRANSACTION_FORMAT",
    "USER_PRESENCE_REQUIRED"
  ]);
});

test("v2 vocabularies are closed and frozen", () => {
  for (const vocab of [SIGHASH_FLAGS, TRANSACTION_FORMATS, PSKT_ROLES, TRANSPORT_KINDS, USER_PRESENCE_MODES, CANCELLATION_MODES, SIGNING_STATES_V2, DESCRIPTOR_KEYS_V2]) {
    assert.ok(Object.isFrozen(vocab));
  }
  assert.deepEqual([...TRANSPORT_KINDS], ["in-page", "deep-link", "qr-airgap", "file", "cli"]);
  assert.deepEqual([...TRANSACTION_FORMATS], ["kaspa-safe-json/1"]);
  /* PSKT roles mirror rusty-kaspa wallet/pskt/src/role.rs, in its order */
  assert.deepEqual([...PSKT_ROLES], ["creator", "constructor", "updater", "signer", "combiner", "finalizer", "extractor"]);
  assert.ok(REQUIRED_METHODS_V2.includes("probeCapabilities"), "v2 requires a capability probe on every adapter");
});

/* ==================== descriptor conformance ========================= */

test("a valid v2 mock adapter validates, registers, and yields a deep-frozen descriptor", () => {
  const adapter = createMockSignerAdapterV2();
  const { descriptor } = validateAdapterV2(adapter);
  assert.equal(descriptor.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
  assert.deepEqual({ ...descriptor.sighash }, { all: true, none: false, single: false, anyoneCanPay: false });
  assert.equal(descriptor.transactionFormats[0], "kaspa-safe-json/1");
  assert.equal(descriptor.pskt.supported, false);
  assert.ok(Object.isFrozen(descriptor) && Object.isFrozen(descriptor.features) && Object.isFrozen(descriptor.sighash) && Object.isFrozen(descriptor.pskt));

  const registry = new SignerRegistryV2();
  assert.equal(registry.register(adapter).provider, "mockv2");
  assert.throws(() => registry.register(adapter), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => registry.get("nope"), (e) => e.signerCode === SignerErrorCodesV2.SIGNER_NOT_FOUND);
  assert.equal(registry.list().length, 1);
});

test("every v2 descriptor key is REQUIRED — none is defaulted", () => {
  for (const key of DESCRIPTOR_KEYS_V2) {
    if (key === "interfaceVersion") continue;
    const adapter = brokenDescriptor((d) => {
      delete d[key];
    });
    assert.throws(
      () => validateAdapterV2(adapter),
      (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION,
      `missing ${key} must refuse the descriptor`
    );
  }
});

test("unknown descriptor keys, sighash flags and pskt keys are refused (closed schema)", () => {
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.custody = true; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.sighash.everything = true; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.pskt.magic = 1; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
});

test("sighash flags must be strictly boolean and completely declared", () => {
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.sighash.all = "yes"; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { delete d.sighash.anyoneCanPay; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
});

test("unknown transport / userPresence / cancellation / transaction-format values are refused", () => {
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.transport = "carrier-pigeon"; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.userPresence = "maybe"; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.cancellation = "best-effort"; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.transactionFormats = ["bitcoin-psbt/0"]; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
});

test("self-contradictory declarations are refused", () => {
  /* async approval without a way to revoke it */
  assert.throws(
    () => validateAdapterV2(brokenDescriptor((d) => { d.features.asynchronousApproval = true; d.cancellation = "unsupported"; })),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION && /never be revoked/.test(e.message)
  );
  /* pskt support with no roles, and roles with no support */
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.pskt = { supported: true, roles: [] }; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.pskt = { supported: false, roles: ["signer"] }; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  /* transaction signing with no sighash behaviour and no format */
  assert.throws(
    () => validateAdapterV2(brokenDescriptor((d) => { d.sighash = { all: false, none: false, single: false, anyoneCanPay: false }; })),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION
  );
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.transactionFormats = []; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  /* air-gapped in-page is impossible */
  assert.throws(
    () => validateAdapterV2(brokenDescriptor((d) => { d.features.airGapped = true; d.transport = "in-page"; })),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION && /airGapped/.test(e.message)
  );
});

test("maxTimeoutMs must be a bounded positive integer", () => {
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.maxTimeoutMs = 0; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.maxTimeoutMs = 1.5; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
  assert.throws(() => validateAdapterV2(brokenDescriptor((d) => { d.maxTimeoutMs = 1e12; })), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
});

test("an adapter missing probeCapabilities is refused registration", () => {
  const adapter = createMockSignerAdapterV2();
  const stripped = { ...adapter };
  delete stripped.probeCapabilities;
  assert.throws(
    () => validateAdapterV2(stripped),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION && /probeCapabilities/.test(e.message)
  );
});

test("an adapter declaring cancellation support without cancelSigning is refused", () => {
  const adapter = createMockSignerAdapterV2({ cancellation: "supported" });
  const stripped = { ...adapter };
  delete stripped.cancelSigning;
  assert.throws(
    () => validateAdapterV2(stripped),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION && /cancelSigning/.test(e.message)
  );
});

/* ======================== negotiation ================================ */

test("negotiation refuses an ecdsa-only (Tangem-class) signer when schnorr is required", () => {
  const adapter = createMockSignerAdapterV2({ schemes: ["ecdsa"] });
  const result = negotiateCapabilitiesV2(adapter.describe(), { schemes: ["schnorr"] });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodesV2.UNSUPPORTED_SCHEME);
  assert.deepEqual([...result.missing], ["schnorr"]);
});

test("negotiation refuses a signer that does not offer SIGHASH_ALL", () => {
  const adapter = createMockSignerAdapterV2({ sighash: { all: false, none: false, single: true, anyoneCanPay: false } });
  const result = negotiateCapabilitiesV2(adapter.describe(), { sighash: ["all"] });
  assert.equal(result.code, SignerErrorCodesV2.UNSUPPORTED_SIGHASH);
});

test("negotiation refuses an unknown transaction format and a format the signer does not speak", () => {
  const adapter = createMockSignerAdapterV2();
  assert.throws(
    () => negotiateCapabilitiesV2(adapter.describe(), { transactionFormat: "bitcoin-psbt/0" }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID
  );
  const noTx = createMockSignerAdapterV2({
    features: { transactionSigning: false, specificInputSigning: false },
    transactionFormats: []
  });
  const result = negotiateCapabilitiesV2(noTx.describe(), { transactionFormat: "kaspa-safe-json/1" });
  assert.equal(result.code, SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT);
});

test("negotiation refuses a transport the consumer does not accept", () => {
  const adapter = createMockSignerAdapterV2({
    transport: "qr-airgap",
    kind: "air-gapped",
    features: { airGapped: true, asynchronousApproval: true },
    cancellation: "supported"
  });
  const result = negotiateCapabilitiesV2(adapter.describe(), { transports: ["in-page", "cli"] });
  assert.equal(result.code, SignerErrorCodesV2.TRANSPORT_UNSUPPORTED);
  assert.deepEqual([...result.missing], ["qr-airgap"]);
});

test("negotiation refuses a signer with no human present when presence is required", () => {
  const adapter = createMockSignerAdapterV2({ userPresence: "not-required" });
  const result = negotiateCapabilitiesV2(adapter.describe(), { userPresence: "required" });
  assert.equal(result.code, SignerErrorCodesV2.USER_PRESENCE_REQUIRED);
});

test("negotiation refuses a signer whose declared maxTimeoutMs is shorter than the consumer needs", () => {
  const adapter = createMockSignerAdapterV2({ maxTimeoutMs: 5000 });
  const result = negotiateCapabilitiesV2(adapter.describe(), { minTimeoutMs: 3600000 });
  assert.equal(result.code, SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);
});

test("negotiation refuses a PSKT role requirement no signer in this codebase satisfies", () => {
  const adapter = createMockSignerAdapterV2();
  const result = negotiateCapabilitiesV2(adapter.describe(), { pskt: ["combiner"] });
  assert.equal(result.code, SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);
  assert.deepEqual([...result.missing], ["pskt:combiner"]);
});

test("unknown requirement keys and unknown requirement values THROW rather than silently not matching", () => {
  const desc = createMockSignerAdapterV2().describe();
  assert.throws(() => negotiateCapabilitiesV2(desc, { quantumResistance: true }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => negotiateCapabilitiesV2(desc, { sighash: ["everything"] }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => negotiateCapabilitiesV2(desc, { transports: [] }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("the canonical PolicyVault funds-path requirement set is satisfied by a conformant signer and is itself frozen", () => {
  const adapter = createMockSignerAdapterV2();
  assert.equal(requireCapabilitiesV2(adapter.describe(), { ...POLICYVAULT_TRANSACTION_REQUIREMENTS }).ok, true);
  assert.ok(Object.isFrozen(POLICYVAULT_TRANSACTION_REQUIREMENTS));
  assert.deepEqual([...POLICYVAULT_TRANSACTION_REQUIREMENTS.sighash], ["all"]);
});

/* ======================== probe cross-check ========================== */

test("a probe may report MORE than the descriptor declares — an adapter offering less than its provider is legitimate", () => {
  const adapter = createMockSignerAdapterV2({
    probe: {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: true,
      methods: ["signMessage", "signTransaction", "on", "cancelSigning"],
      sighash: { all: true, none: true, single: true, anyoneCanPay: true },
      pskt: { supported: true, roles: ["signer", "combiner"] },
      transactionFormats: ["kaspa-safe-json/1"]
    }
  });
  const result = verifyDeclaredCapabilities(adapter.describe(), adapter.probeCapabilities());
  assert.deepEqual({ ...result }, { ok: true, provider: "mockv2", probed: true });
});

test("a probe report is deep-validated: unknown keys and non-boolean flags are contract breaches", () => {
  const desc = createMockSignerAdapterV2().describe();
  assert.throws(
    () => verifyDeclaredCapabilities(desc, { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: true, extra: 1 }),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION
  );
  assert.throws(
    () => verifyDeclaredCapabilities(desc, { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: true, sighash: { all: "true" } }),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION
  );
});

test("a probe reporting a network the adapter does not declare is a mismatch", () => {
  const adapter = createMockSignerAdapterV2({ networks: ["testnet-10"] });
  assert.throws(
    () =>
      verifyDeclaredCapabilities(adapter.describe(), {
        interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
        probed: true,
        network: "mainnet"
      }),
    (e) => e.signerCode === SignerErrorCodesV2.CAPABILITY_MISMATCH
  );
});
