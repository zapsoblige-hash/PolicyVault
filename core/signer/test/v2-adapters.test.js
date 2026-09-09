"use strict";

/*
 * UNIT — Universal Signer Interface v2 adapters:
 *
 *   - the v1 -> v2 LIFT (how the existing, unchanged v1 adapters reach the
 *     v2 contract, and what it refuses to infer for them);
 *   - the KasWare capability PROFILE (declarations + the DOM-free probe);
 *   - the AIR-GAP transport adapter (QR/file shuttle to the offline CLI
 *     signer, over that signer's OWN frozen document schemas);
 *   - the CLI signer's v2 declarations and its honest probe.
 *
 * Real kaspa-wasm signing through the v2 pipeline is proven separately in
 * core/signer/adapters/cli/test/v2-conformance.test.js (that suite needs
 * the vendored rusty-kaspa wasm build; this one is dependency-free).
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const v1 = require("../index");
const {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  validateAdapterV2,
  negotiateCapabilitiesV2,
  executeSigningV2,
  createTransactionSigningRequestV2,
  createMessageSigningRequestV2,
  liftV1Adapter,
  KASWARE_V2_DECLARATIONS,
  probeKasWareProvider,
  kaswareProviderMethodNames,
  createAirGapSignerAdapter,
  AIRGAP_LIMITATIONS
} = require("../v2");
const airgapModule = require("../v2/adapters/airgap");
const { CLI_V2_DECLARATIONS, probeCliSigner, createCliSignerAdapterV2 } = require("../v2/adapters/cli");

const TX = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0 }], outputs: [] });
const SIGNED_TX = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0, signatureScript: "41" + "cd".repeat(65) }], outputs: [] });
const OTHER_TX = JSON.stringify({ id: "b".repeat(64), version: 0, inputs: [], outputs: [] });
const OFFLINE_ADDRESS = "kaspatest:qqofflinesignerv2000000000000000000000000000000000000000000000";
const MESSAGE = "PolicyVault sign-in. This signature only signs you in. It cannot move funds.";

function deriveTransactionId(safeJson) {
  return JSON.parse(safeJson).id;
}

/* ==================================================================== */
/* the v1 -> v2 lift                                                     */
/* ==================================================================== */

const LIFT_DECLARATIONS = Object.freeze({
  sighash: { all: true, none: false, single: false, anyoneCanPay: false },
  pskt: { supported: false, roles: [] },
  transactionFormats: ["kaspa-safe-json/1"],
  userPresence: "required",
  transport: "in-page",
  cancellation: "unsupported",
  maxTimeoutMs: 120000,
  probeCapabilities: () => ({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    probed: true,
    methods: ["signMessage", "signTransaction", "on"],
    sighash: { all: true, none: false, single: false, anyoneCanPay: false },
    transactionFormats: ["kaspa-safe-json/1"]
  })
});

function liftedMock(extra = {}) {
  const base = v1.createMockSignerAdapter({ provider: "liftedv1", networks: ["testnet-10"] });
  return { v1Adapter: base, lifted: liftV1Adapter(base, { ...LIFT_DECLARATIONS, ...extra }) };
}

test("LIFT: an unchanged v1 adapter passes the v2 contract, carrying its v1 half verbatim", () => {
  const { v1Adapter, lifted } = liftedMock();
  const { descriptor } = validateAdapterV2(lifted);
  const v1Descriptor = v1.validateAdapter(v1Adapter).descriptor;
  assert.equal(descriptor.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
  assert.equal(descriptor.provider, v1Descriptor.provider);
  assert.equal(descriptor.kind, v1Descriptor.kind);
  assert.deepEqual([...descriptor.schemes], [...v1Descriptor.schemes]);
  assert.deepEqual({ ...descriptor.features }, { ...v1Descriptor.features });
  /* and the v1 adapter itself still works through the v1 core */
  assert.equal(v1.validateAdapter(v1Adapter).descriptor.interfaceVersion, "policyvault-signer/1");
});

test("LIFT: every v2-only capability must be declared EXPLICITLY — nothing is inferred", () => {
  const base = v1.createMockSignerAdapter({ provider: "liftedv1" });
  for (const key of ["sighash", "pskt", "transactionFormats", "userPresence", "transport", "cancellation", "maxTimeoutMs"]) {
    const declarations = { ...LIFT_DECLARATIONS };
    delete declarations[key];
    assert.throws(
      () => liftV1Adapter(base, declarations),
      (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID && new RegExp(key).test(e.message),
      `omitting ${key} must refuse the lift`
    );
  }
  assert.throws(
    () => liftV1Adapter(base, { ...LIFT_DECLARATIONS, probeCapabilities: undefined }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID
  );
  assert.throws(() => liftV1Adapter(base, { ...LIFT_DECLARATIONS, somethingElse: 1 }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("LIFT: a broken v1 adapter is refused by the v1 contract before v2 ever sees it", () => {
  const base = v1.createMockSignerAdapter();
  const broken = { ...base };
  delete broken.signMessage;
  assert.throws(() => liftV1Adapter(broken, LIFT_DECLARATIONS), (e) => e.signerCode === v1.SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("LIFT: the v2 request is translated to the v1 shape the underlying adapter expects", async () => {
  const { v1Adapter, lifted } = liftedMock();
  let seen = null;
  const spied = {
    ...lifted,
    signTransaction: async (request) => {
      const original = v1Adapter.signTransaction;
      v1Adapter.signTransaction = async (downstream) => {
        seen = downstream;
        return original.call(v1Adapter, downstream);
      };
      try {
        return await lifted.signTransaction(request);
      } finally {
        v1Adapter.signTransaction = original;
      }
    }
  };
  await v1Adapter.connect();
  const request = createTransactionSigningRequestV2({
    unsignedSafeJson: TX,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: "kaspatest:mocksigneraccount0",
    ttlMs: 60000
  });
  const outcome = await executeSigningV2(spied, request);
  assert.equal(outcome.status, "approved");
  assert.equal(seen.interfaceVersion, "policyvault-signer/1", "the downstream adapter receives a v1 request");
  assert.equal(seen.requestId, request.requestId, "the request id is carried across so diagnostics line up");
  assert.equal(seen.nonce, undefined, "v2-only fields are NOT pushed into a v1 adapter's closed schema");
  assert.equal(seen.payloadSha256, undefined);
  assert.deepEqual(seen.signInputs.map((s) => ({ ...s })), [{ index: 0, sighashType: 1 }]);
});

test("LIFT: a lifted signer that returns bytes for a DIFFERENT transaction is still caught by id re-derivation", async () => {
  const { v1Adapter, lifted } = liftedMock();
  await v1Adapter.connect();
  const cheating = { ...lifted, signTransaction: async (request) => lifted.signTransaction(request) };
  /* make the underlying v1 adapter answer with other bytes */
  v1Adapter.signTransaction = async () => OTHER_TX;
  const request = createTransactionSigningRequestV2({
    unsignedSafeJson: TX,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: "kaspatest:mocksigneraccount0",
    ttlMs: 60000
  });
  await assert.rejects(
    () => executeSigningV2(cheating, request, { deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.PAYLOAD_MUTATED
  );
});

/* ==================================================================== */
/* KasWare capability profile                                            */
/* ==================================================================== */

test("KASWARE: the v2 declarations state exactly what the shipped flow does — and no PSKT claim", () => {
  assert.deepEqual({ ...KASWARE_V2_DECLARATIONS.sighash }, { all: true, none: false, single: false, anyoneCanPay: false });
  assert.equal(KASWARE_V2_DECLARATIONS.pskt.supported, false, "signPskt is a Safe-JSON transaction signer, not a BIP-370 PSKT surface");
  assert.deepEqual([...KASWARE_V2_DECLARATIONS.pskt.roles], []);
  assert.deepEqual([...KASWARE_V2_DECLARATIONS.transactionFormats], ["kaspa-safe-json/1"]);
  assert.equal(KASWARE_V2_DECLARATIONS.userPresence, "required");
  assert.equal(KASWARE_V2_DECLARATIONS.transport, "in-page");
  assert.equal(KASWARE_V2_DECLARATIONS.cancellation, "unsupported", "KasWare exposes no cancellation API");
  assert.ok(Object.isFrozen(KASWARE_V2_DECLARATIONS));
});

test("KASWARE: with no provider injected the probe reports probed:false WITH a reason", () => {
  const report = probeKasWareProvider({ present: false });
  assert.equal(report.probed, false);
  assert.match(report.reason, /no KasWare provider is injected/);
  assert.equal(probeKasWareProvider(undefined).probed, false);
});

test("KASWARE: provider method names are mapped to INTERFACE method names", () => {
  const report = probeKasWareProvider({ present: true, methods: kaswareProviderMethodNames(), network: "mainnet" });
  assert.equal(report.probed, true);
  assert.deepEqual(report.methods.sort(), ["on", "signMessage", "signTransaction"]);
  assert.equal(report.network, "mainnet");
  assert.equal(report.pskt.supported, false);
  assert.deepEqual(report.transactionFormats, ["kaspa-safe-json/1"]);
});

test("KASWARE: a provider missing signPskt is reported without transaction signing — the mismatch refuses before a popup", () => {
  const report = probeKasWareProvider({ present: true, methods: ["requestAccounts", "getNetwork", "getPublicKey", "signMessage"] });
  assert.deepEqual(report.methods, ["signMessage"]);
  assert.deepEqual(report.transactionFormats, []);
  assert.equal(report.sighash.all, false);
});

test("KASWARE: a non-operational network claim is simply not reported (never coerced)", () => {
  const report = probeKasWareProvider({ present: true, methods: ["signMessage"], network: "kaspa_devnet" });
  assert.equal("network" in report, false);
});

/* ==================================================================== */
/* air-gap transport adapter                                             */
/* ==================================================================== */

function airgapAdapter(exchange, extra = {}) {
  return createAirGapSignerAdapter({
    network: "testnet-10",
    signerAddress: OFFLINE_ADDRESS,
    exchange,
    ...extra
  });
}

function airgapTxRequest() {
  return createTransactionSigningRequestV2({
    unsignedSafeJson: TX,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: OFFLINE_ADDRESS,
    ttlMs: 600000
  });
}

function airgapMsgRequest() {
  return createMessageSigningRequestV2({
    message: MESSAGE,
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: OFFLINE_ADDRESS,
    ttlMs: 600000
  });
}

function signedTxDocument(overrides = {}) {
  return JSON.stringify({
    format: "policyvault-cli-signer-signed-transaction/1",
    requestId: "0".repeat(32),
    kind: "sign-transaction",
    network: "testnet-10",
    address: OFFLINE_ADDRESS,
    signedSafeJson: SIGNED_TX,
    ...overrides
  });
}

function signatureDocument(request, overrides = {}) {
  return JSON.stringify({
    format: "policyvault-cli-signer-signature/1",
    requestId: "0".repeat(32),
    kind: "sign-message",
    network: "testnet-10",
    address: OFFLINE_ADDRESS,
    publicKey: "02" + "ab".repeat(32),
    scheme: "schnorr",
    messageSha256: request.payloadSha256,
    signature: "ab".repeat(64),
    ...overrides
  });
}

test("AIRGAP: the descriptor is a conformant air-gapped, asynchronous, cancellable signer", () => {
  const { descriptor } = validateAdapterV2(airgapAdapter(async () => signedTxDocument()));
  assert.equal(descriptor.kind, "air-gapped");
  assert.equal(descriptor.transport, "qr-airgap");
  assert.equal(descriptor.features.airGapped, true);
  assert.equal(descriptor.features.asynchronousApproval, true);
  assert.equal(descriptor.cancellation, "supported");
  assert.equal(descriptor.userPresence, "required");
  assert.equal(descriptor.pskt.supported, false);
});

test("AIRGAP: the file transport is the same adapter with a different declared transport", () => {
  const { descriptor } = validateAdapterV2(airgapAdapter(async () => signedTxDocument(), { transport: "file" }));
  assert.equal(descriptor.transport, "file");
  assert.equal(negotiateCapabilitiesV2(descriptor, { transports: ["file"] }).ok, true);
  assert.equal(negotiateCapabilitiesV2(descriptor, { transports: ["in-page"] }).code, SignerErrorCodesV2.TRANSPORT_UNSUPPORTED);
});

test("AIRGAP: an unknown transport, network or missing signer address is refused at construction", () => {
  assert.throws(() => airgapAdapter(async () => "", { transport: "deep-link" }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(
    () => createAirGapSignerAdapter({ network: "devnet", signerAddress: OFFLINE_ADDRESS, exchange: async () => "" }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID
  );
  assert.throws(() => createAirGapSignerAdapter({ network: "testnet-10", exchange: async () => "" }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => createAirGapSignerAdapter({ network: "testnet-10", signerAddress: OFFLINE_ADDRESS }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("AIRGAP: the emitted request document is the offline signer's OWN closed schema, in its fixed key order", async () => {
  let handed = null;
  const adapter = airgapAdapter(async ({ documentText, document }) => {
    handed = { documentText, document };
    return signedTxDocument();
  });
  await adapter.connect();
  const request = airgapTxRequest();
  const outcome = await executeSigningV2(adapter, request, { timeoutMs: 60000, deriveTransactionId });
  assert.equal(outcome.status, "approved");
  assert.deepEqual(Object.keys(handed.document), ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
  assert.equal(handed.document.format, "policyvault-cli-signing-request/1");
  assert.equal(handed.document.unsignedSafeJson, TX, "the frozen bytes cross the gap verbatim");
  assert.deepEqual(handed.document.signInputs, [{ index: 0, sighashType: 1 }]);
  assert.equal(handed.documentText, JSON.stringify(handed.document));
  assert.equal(outcome.txIdVerified, true);
});

test("AIRGAP: a message request shuttles the message's EXACT bytes — no new format is invented", async () => {
  let handed = null;
  const adapter = airgapAdapter(async ({ documentText, document, request }) => {
    handed = { documentText, document };
    return signatureDocument(request);
  });
  await adapter.connect();
  const outcome = await executeSigningV2(adapter, airgapMsgRequest(), { timeoutMs: 60000 });
  assert.equal(handed.documentText, MESSAGE);
  assert.equal(handed.document, null);
  assert.equal(outcome.result.signature, "ab".repeat(64));
});

test("AIRGAP: an unknown response format, kind, network or address fails closed with a distinct code", async () => {
  const cases = [
    [{ format: "policyvault-cli-signer-signed-transaction/2" }, SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH],
    [{ kind: "sign-message" }, SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH],
    [{ network: "mainnet" }, SignerErrorCodesV2.WRONG_NETWORK],
    [{ address: "kaspatest:somebodyelse" }, SignerErrorCodesV2.ACCOUNT_CHANGED],
    [{ signedSafeJson: "" }, SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE]
  ];
  for (const [override, code] of cases) {
    const adapter = airgapAdapter(async () => signedTxDocument(override));
    await adapter.connect();
    await assert.rejects(
      () => executeSigningV2(adapter, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
      (e) => {
        assert.equal(e.signerCode, code, `override ${JSON.stringify(override)}`);
        return true;
      }
    );
  }
});

test("AIRGAP: an extra or missing key in the response document is refused (closed schema)", async () => {
  const extra = airgapAdapter(async () => signedTxDocument({ txId: "a".repeat(64) }));
  await extra.connect();
  await assert.rejects(
    () => executeSigningV2(extra, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH
  );
  const missing = airgapAdapter(async () => {
    const doc = JSON.parse(signedTxDocument());
    delete doc.address;
    return JSON.stringify(doc);
  });
  await missing.connect();
  await assert.rejects(
    () => executeSigningV2(missing, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH
  );
});

test("AIRGAP: a signature document whose messageSha256 is not the message's digest is discarded", async () => {
  const adapter = airgapAdapter(async (args) => signatureDocument(args.request, { messageSha256: "c".repeat(64) }));
  await adapter.connect();
  await assert.rejects(
    () => executeSigningV2(adapter, airgapMsgRequest(), { timeoutMs: 60000 }),
    (e) => e.signerCode === SignerErrorCodesV2.PAYLOAD_MUTATED
  );
});

test("AIRGAP: a response carrying bytes for a different transaction is caught by id re-derivation", async () => {
  const adapter = airgapAdapter(async () => signedTxDocument({ signedSafeJson: OTHER_TX }));
  await adapter.connect();
  await assert.rejects(
    () => executeSigningV2(adapter, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.PAYLOAD_MUTATED
  );
});

test("AIRGAP: non-JSON and oversized shuttle output is a transport fault, not a signature", async () => {
  const adapter = airgapAdapter(async () => "<html>404</html>");
  await adapter.connect();
  await assert.rejects(
    () => executeSigningV2(adapter, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.PROVIDER_ERROR
  );
  const empty = airgapAdapter(async () => "");
  await empty.connect();
  await assert.rejects(
    () => executeSigningV2(empty, airgapTxRequest(), { timeoutMs: 60000, deriveTransactionId }),
    (e) => e.signerCode === SignerErrorCodesV2.PROVIDER_ERROR
  );
});

test("AIRGAP: an abandoned shuttle refuses a document that arrives afterwards", async () => {
  let release;
  const gate = new Promise((r) => {
    release = r;
  });
  const adapter = airgapAdapter(async () => {
    await gate;
    return signedTxDocument();
  });
  await adapter.connect();
  const request = airgapTxRequest();
  const run = adapter.signTransaction(request);
  await adapter.cancelSigning(request.requestId);
  release();
  await assert.rejects(() => run, (e) => e.signerCode === SignerErrorCodesV2.REQUEST_CANCELLED);
});

test("AIRGAP: capabilities cannot be probed, and a consumer requiring a probe correctly refuses", async () => {
  const adapter = airgapAdapter(async () => signedTxDocument());
  await adapter.connect();
  const report = adapter.probeCapabilities();
  assert.equal(report.probed, false);
  assert.match(report.reason, /cannot be interrogated before the document crosses the gap/);
  await assert.rejects(
    () => executeSigningV2(adapter, airgapTxRequest(), { timeoutMs: 60000, requireProbedCapabilities: true }),
    (e) => e.signerCode === SignerErrorCodesV2.CAPABILITY_MISMATCH
  );
});

test("AIRGAP: the capability limitations are exported, frozen, and carried on the adapter for the UI to render", () => {
  const adapter = airgapAdapter(async () => signedTxDocument());
  assert.equal(adapter.limitations, AIRGAP_LIMITATIONS);
  assert.ok(Object.isFrozen(AIRGAP_LIMITATIONS) && AIRGAP_LIMITATIONS.length >= 4);
  const ids = AIRGAP_LIMITATIONS.map((l) => l.id);
  assert.deepEqual(ids, ["no-nonce-across-the-gap", "payload-identity-binding-only", "no-preflight-probe", "no-local-signature-verification"]);
  for (const limitation of AIRGAP_LIMITATIONS) {
    assert.ok(Object.isFrozen(limitation));
    for (const key of ["summary", "consequence", "fix"]) {
      assert.equal(typeof limitation[key], "string");
      assert.ok(limitation[key].length > 0, `${limitation.id}.${key} must say something`);
    }
  }
});

test("AIRGAP: the document formats it restates are exactly the offline signer's frozen ones", () => {
  assert.equal(airgapModule.SIGNING_REQUEST_FORMAT, "policyvault-cli-signing-request/1");
  assert.deepEqual([...airgapModule.SIGNING_REQUEST_KEYS], ["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
  assert.equal(airgapModule.SIGNED_TX_FORMAT, "policyvault-cli-signer-signed-transaction/1");
  assert.deepEqual([...airgapModule.SIGNED_TX_KEYS], ["format", "requestId", "kind", "network", "address", "signedSafeJson"]);
  assert.equal(airgapModule.SIGNATURE_FORMAT, "policyvault-cli-signer-signature/1");
  assert.deepEqual([...airgapModule.SIGNATURE_KEYS], ["format", "requestId", "kind", "network", "address", "publicKey", "scheme", "messageSha256", "signature"]);
});

/* ==================================================================== */
/* CLI signer v2 declarations + probe                                    */
/* ==================================================================== */

const FAKE_KASPA = {
  signMessage: () => "00".repeat(64),
  createInputSignature: () => "",
  PrivateKey: function PrivateKey() {},
  Keypair: { random: () => ({}) },
  Transaction: function Transaction() {},
  SighashType: { All: 1 }
};

test("CLI: the v2 declarations are truthful about an unattended, uncancellable, non-PSKT signer", () => {
  assert.deepEqual({ ...CLI_V2_DECLARATIONS.sighash }, { all: true, none: false, single: false, anyoneCanPay: false });
  assert.equal(CLI_V2_DECLARATIONS.userPresence, "not-required", "running the process IS the approval — there is no per-request human confirmation");
  assert.equal(CLI_V2_DECLARATIONS.transport, "cli");
  assert.equal(CLI_V2_DECLARATIONS.cancellation, "unsupported");
  assert.equal(CLI_V2_DECLARATIONS.pskt.supported, false);
});

test("CLI: a v2 adapter validates without touching the keyfile or the network", () => {
  const adapter = createCliSignerAdapterV2({ keyfilePath: "/nonexistent/pv-test-key.json", network: "testnet-10", kaspaModule: FAKE_KASPA });
  const { descriptor } = validateAdapterV2(adapter);
  assert.equal(descriptor.kind, "cli");
  assert.equal(descriptor.transport, "cli");
  assert.equal(descriptor.userPresence, "not-required");
  assert.deepEqual([...descriptor.networks], ["testnet-10"]);
  assert.equal(adapter.detect(), false, "no keyfile present -> detect() is false, and it never throws");
});

test("CLI: a consumer requiring a human at the signer refuses the CLI signer in negotiation", () => {
  const adapter = createCliSignerAdapterV2({ keyfilePath: "/nonexistent/pv-test-key.json", network: "testnet-10", kaspaModule: FAKE_KASPA });
  const result = negotiateCapabilitiesV2(adapter.describe(), { userPresence: "required" });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodesV2.USER_PRESENCE_REQUIRED);
});

test("CLI: the probe reports the module surface it will actually drive", () => {
  const report = probeCliSigner({ kaspaModule: FAKE_KASPA });
  assert.equal(report.probed, true);
  assert.ok(report.methods.includes("signMessage") && report.methods.includes("signTransaction"));
  assert.deepEqual(report.transactionFormats, ["kaspa-safe-json/1"]);
  assert.equal(report.pskt.supported, false);
});

test("CLI: with no loadable kaspa module the probe says probed:false WITH a reason — never an optimistic claim", () => {
  const report = probeCliSigner({ kaspaModulePath: "/definitely/not/a/kaspa/module" });
  assert.equal(report.probed, false);
  assert.match(report.reason, /not loadable in this environment/);
});

test("CLI: a module missing the functions the adapter drives makes the probe refuse rather than assume", () => {
  const report = probeCliSigner({ kaspaModule: { ...FAKE_KASPA, signMessage: undefined } });
  /* resolveKaspaModule refuses a partial module handle outright */
  assert.equal(report.probed, false);
});
