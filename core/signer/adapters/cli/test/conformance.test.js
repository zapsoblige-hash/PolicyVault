"use strict";

/*
 * UNIT — CLI keyfile signer: v1 interface conformance.
 *
 * The CLI adapter must pass the SAME gates the mock adapter passes:
 * validateAdapter / registry registration, exact capability declaration,
 * consumer negotiation, and the full executeSigning lifecycle for both
 * request kinds — with REAL kaspa-wasm Schnorr cryptography instead of
 * placeholders. TEST keys only (throwaway, generated per run, testnet).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  validateAdapter,
  SignerRegistry,
  negotiateCapabilities,
  requireCapabilities,
  normalizePublicKeyToXOnly,
  createMessageSigningRequest,
  createTransactionSigningRequest,
  executeSigning
} = require("../../../index");
const { generateKeyfile, createCliSignerAdapter } = require("../adapter");
const { loadKaspaOrExplain, makeTempDir, buildUnsignedTxSafeJson } = require("../testkit");

const kaspa = loadKaspaOrExplain();
const dir = makeTempDir("pv-cli-signer-conf-");
const keyfilePath = path.join(dir, "test-key.json");
const identity = generateKeyfile({ out: keyfilePath, network: "testnet-10", label: "conformance test key", kaspaModule: kaspa });

function makeAdapter() {
  return createCliSignerAdapter({ keyfilePath, network: "testnet-10", kaspaModule: kaspa });
}

test("CLI adapter passes validateAdapter and registry registration (same gate as the mock)", () => {
  const adapter = makeAdapter();
  const record = validateAdapter(adapter);
  assert.equal(record.descriptor.interfaceVersion, SIGNER_INTERFACE_VERSION);
  assert.equal(record.descriptor.provider, "cli-keyfile");
  assert.equal(record.descriptor.kind, "cli");
  assert.ok(Object.isFrozen(record.descriptor));

  const registry = new SignerRegistry();
  const descriptor = registry.register(adapter);
  assert.equal(descriptor.provider, "cli-keyfile");
  assert.ok(registry.has("cli-keyfile"));
  assert.equal(registry.get("cli-keyfile").adapter, adapter);
});

test("descriptor declares exactly the mission capability profile", () => {
  const d = validateAdapter(makeAdapter()).descriptor;
  assert.deepEqual([...d.schemes], ["schnorr"]);
  assert.deepEqual([...d.networks], ["testnet-10"]);
  assert.deepEqual(
    { ...d.features },
    {
      messageSigning: true,
      transactionSigning: true,
      specificInputSigning: true,
      multiAccount: false,
      networkSwitching: false,
      accountEvents: false,
      asynchronousApproval: false,
      airGapped: false,
      hardwareDisplay: false
    }
  );
});

test("negotiation: the production requirement set is satisfied", () => {
  const d = makeAdapter().describe();
  const result = negotiateCapabilities(d, {
    schemes: ["schnorr"],
    features: ["messageSigning", "transactionSigning", "specificInputSigning"],
    network: "testnet-10"
  });
  assert.equal(result.ok, true);
  assert.equal(result.provider, "cli-keyfile");
});

test("negotiation: an ecdsa-requiring consumer refuses the CLI adapter fail-closed", () => {
  const result = negotiateCapabilities(makeAdapter().describe(), { schemes: ["ecdsa"] });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodes.UNSUPPORTED_SCHEME);
});

test("negotiation: requiring asynchronousApproval refuses (synchronous signer)", () => {
  assert.throws(
    () => requireCapabilities(makeAdapter().describe(), { features: ["asynchronousApproval"] }),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_CAPABILITY
  );
});

test("negotiation: requiring mainnet refuses a testnet-configured adapter", () => {
  const result = negotiateCapabilities(makeAdapter().describe(), { network: "mainnet" });
  assert.equal(result.ok, false);
  assert.equal(result.code, SignerErrorCodes.WRONG_NETWORK);
});

test("detect/connect/identity surface behaves per contract", async () => {
  const adapter = makeAdapter();
  assert.equal(adapter.detect(), true);
  assert.equal(await adapter.getActiveAccount(), null); // disconnected -> null
  const session = await adapter.connect();
  assert.equal(session.address, identity.address);
  assert.equal(session.network, "testnet-10");
  assert.deepEqual(await adapter.getActiveAccount(), { address: identity.address });
  assert.equal(await adapter.getNetwork(), "testnet-10");
  const pub = await adapter.getPublicKey();
  assert.equal(pub, identity.publicKey); // provider-native 66-hex compressed
  assert.equal(normalizePublicKeyToXOnly(pub, "cli adapter"), identity.xOnlyPublicKey);
  await adapter.disconnect();
  assert.equal(await adapter.getActiveAccount(), null);
});

test("detect() never throws for absence and reports false", () => {
  const adapter = createCliSignerAdapter({ keyfilePath: path.join(dir, "does-not-exist.json"), kaspaModule: kaspa });
  assert.equal(adapter.detect(), false);
});

test("getPublicKey while disconnected fails closed with SIGNER_DISCONNECTED", async () => {
  const adapter = makeAdapter();
  await assert.rejects(adapter.getPublicKey(), (e) => e.signerCode === SignerErrorCodes.SIGNER_DISCONNECTED);
});

test("executeSigning drives a message request to APPROVED with a REAL verifying Schnorr signature", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const transitions = [];
  const request = createMessageSigningRequest({
    message: "conformance: personal message verbatim signing",
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: identity.address
  });
  const outcome = await executeSigning(adapter, request, { onTransition: (t) => transitions.push(t.state) });
  assert.equal(outcome.status, "approved");
  assert.match(outcome.result.signature, /^[0-9a-f]{128}$/);
  assert.deepEqual(transitions, ["SUBMITTED", "APPROVED"]);
  /* not a placeholder: it cryptographically verifies (kaspa-wasm) */
  assert.equal(
    kaspa.verifyMessage({
      message: "conformance: personal message verbatim signing",
      signature: outcome.result.signature,
      publicKey: identity.xOnlyPublicKey
    }),
    true
  );
});

test("executeSigning drives a transaction request to APPROVED; named input signed; txid frozen", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const { unsignedSafeJson, unsignedId } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const request = createTransactionSigningRequest({
    unsignedSafeJson,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: identity.address
  });
  const outcome = await executeSigning(adapter, request);
  assert.equal(outcome.status, "approved");
  const signed = kaspa.Transaction.deserializeFromSafeJSON(outcome.result.signedSafeJson);
  assert.equal(String(signed.id), unsignedId); // frozen-txid discipline
  const sigScript = signed.inputs[0].signatureScript;
  assert.match(sigScript, /^41[0-9a-f]{130}$/); // 65-byte push: 64-byte Schnorr sig + SIG_HASH_ALL byte
  assert.equal(sigScript.slice(-2), "01"); // sighash ALL
});

test("wrong-network request is REFUSED before the signer is invoked", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const transitions = [];
  const request = createMessageSigningRequest({
    message: "wrong network",
    scheme: "schnorr",
    network: "mainnet",
    expectedSignerAddress: identity.address
  });
  await assert.rejects(
    executeSigning(adapter, request, { onTransition: (t) => transitions.push(t.state) }),
    (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK
  );
  assert.deepEqual(transitions, ["REFUSED"]); // never SUBMITTED
});

test("ecdsa message request is REFUSED pre-invocation (no v1 response contract)", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const transitions = [];
  const request = createMessageSigningRequest({ message: "ecdsa refusal", scheme: "ecdsa" });
  await assert.rejects(
    executeSigning(adapter, request, { onTransition: (t) => transitions.push(t.state) }),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_SCHEME
  );
  assert.deepEqual(transitions, ["REFUSED"]);
});

test("expected-identity mismatch is REFUSED with ACCOUNT_CHANGED", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const request = createMessageSigningRequest({
    message: "identity binding",
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: "kaspatest:someoneelseentirely"
  });
  await assert.rejects(executeSigning(adapter, request), (e) => e.signerCode === SignerErrorCodes.ACCOUNT_CHANGED);
});

test("signing while disconnected is REFUSED with SIGNER_DISCONNECTED", async () => {
  const adapter = makeAdapter(); // never connected
  const request = createMessageSigningRequest({
    message: "disconnected",
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: identity.address
  });
  await assert.rejects(executeSigning(adapter, request), (e) => e.signerCode === SignerErrorCodes.SIGNER_DISCONNECTED);
});

test("adapter-direct signMessage also enforces bindings (defense in depth without executeSigning)", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const good = createMessageSigningRequest({ message: "direct call", scheme: "schnorr", network: "testnet-10" });
  assert.match(await adapter.signMessage(good), /^[0-9a-f]{128}$/);
  const wrongNet = { ...good, network: "mainnet" };
  await assert.rejects(adapter.signMessage(wrongNet), (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK);
  const wrongVersion = { ...good, interfaceVersion: "policyvault-signer/2" };
  await assert.rejects(adapter.signMessage(wrongVersion), (e) => e.signerCode === SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED);
});

test("transaction request with an out-of-range input index is refused", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const { unsignedSafeJson } = buildUnsignedTxSafeJson(kaspa, identity.address);
  const request = createTransactionSigningRequest({
    unsignedSafeJson,
    signInputs: [{ index: 1, sighashType: 1 }], // tx has exactly 1 input
    network: "testnet-10",
    expectedSignerAddress: identity.address
  });
  await assert.rejects(executeSigning(adapter, request), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /out of range/.test(e.message));
});

test("transaction request whose unsignedSafeJson is not a transaction is refused", async () => {
  const adapter = makeAdapter();
  await adapter.connect();
  const request = createTransactionSigningRequest({
    unsignedSafeJson: JSON.stringify({ not: "a transaction" }),
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: identity.address
  });
  await assert.rejects(executeSigning(adapter, request), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
});
