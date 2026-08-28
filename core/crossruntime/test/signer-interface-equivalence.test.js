"use strict";

/*
 * Cross-runtime equivalence: the Universal Signer Interface (core/signer)
 * — Node direct vs the browser bundle. core/signer/errors.js and
 * core/signer/interface.js are two of the eight modules web/core-bundle.js
 * embeds verbatim (web/tools/build-core-bundle.js MODULES); this file
 * proves the request/descriptor/error SHAPES they produce agree
 * byte-for-byte, which is exactly the surface the CLI signer adapter and
 * KasWare-behind-the-interface both build on (see
 * cli-signer-core-path.test.js for the CLI adapter's own overlap).
 *
 * Two fields are INTENTIONALLY non-deterministic per call — requestId
 * (crypto.randomBytes entropy) and createdAtMs (Date.now()) — and are
 * normalized out of the equality checks below while their FORMAT is
 * still asserted in each runtime independently.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCommittedBundleInBrowserGlobal, rehome, rehomeInto } = require("../sandbox.js");
const { MESSAGE_SIGNING_VECTORS, TRANSACTION_SIGNING_VECTORS, PUBLIC_KEY_NORMALIZATION_VECTORS, CAPABILITY_NEGOTIATION_REQUIREMENTS } = require("../vectors.js");

const nodeErrors = require("../../signer/errors.js");
const nodeInterface = require("../../signer/interface.js");

const { PolicyVaultCore, global: sandboxGlobal } = loadCommittedBundleInBrowserGlobal();

function stripNonDeterministic(request) {
  const { requestId, createdAtMs, ...rest } = request;
  return rest;
}

test("SignerErrorCodes vocabulary is byte-identical, node vs bundle", () => {
  assert.deepEqual(Object.keys(nodeErrors.SignerErrorCodes).sort(), Object.keys(PolicyVaultCore.signerErrors.SignerErrorCodes).sort());
  assert.deepEqual(Object.values(nodeErrors.SignerErrorCodes).sort(), Object.values(PolicyVaultCore.signerErrors.SignerErrorCodes).sort());
  assert.equal(PolicyVaultCore.signerErrors.SIGNER_INTERFACE_VERSION, nodeErrors.SIGNER_INTERFACE_VERSION);
});

test("SignerError shape is byte-identical, node vs bundle, for every known code", () => {
  for (const code of Object.values(nodeErrors.SignerErrorCodes)) {
    const eNode = nodeErrors.signerError(code, `msg for ${code}`);
    const eBundle = PolicyVaultCore.signerErrors.signerError(code, `msg for ${code}`);
    assert.equal(eNode.name, "SignerError");
    assert.equal(eBundle.name, eNode.name);
    assert.equal(eBundle.signerCode, eNode.signerCode);
    assert.equal(eBundle.message, eNode.message);
    assert.ok(eNode instanceof Error, "own-realm instanceof sanity (node)");
  }
});

test("an unknown error code is refused identically (PROTOCOL_VIOLATION) in both runtimes", () => {
  let nodeCode = null;
  try {
    nodeErrors.signerError("NOT_A_REAL_CODE");
  } catch (e) {
    nodeCode = e.signerCode;
  }
  let bundleCode = null;
  try {
    PolicyVaultCore.signerErrors.signerError("NOT_A_REAL_CODE");
  } catch (e) {
    bundleCode = e.signerCode;
  }
  assert.equal(nodeCode, "PROTOCOL_VIOLATION");
  assert.equal(bundleCode, nodeCode);
});

test("normalizeAdapterFailure classifies the same raw inputs identically in both runtimes", () => {
  const cases = [
    new Error("plain error"),
    { signerCode: "WRONG_NETWORK", message: "claims a known code" },
    { signerCode: "TOTALLY_UNKNOWN", message: "claims an unknown code" },
    "a bare string",
    undefined
  ];
  for (const raw of cases) {
    const nodeResult = nodeErrors.normalizeAdapterFailure(raw, "ctx");
    const bundleResult = PolicyVaultCore.signerErrors.normalizeAdapterFailure(raw, "ctx");
    assert.equal(bundleResult.signerCode, nodeResult.signerCode, `case ${JSON.stringify(String(raw))}`);
    assert.equal(bundleResult.message, nodeResult.message);
  }
});

for (const vector of MESSAGE_SIGNING_VECTORS) {
  test(`createMessageSigningRequest equivalence (mod. requestId/createdAtMs) for ${JSON.stringify(vector).slice(0, 60)}...`, () => {
    const reqNode = nodeInterface.createMessageSigningRequest(vector);
    const reqBundle = PolicyVaultCore.signerInterface.createMessageSigningRequest(rehomeInto(sandboxGlobal, vector));

    assert.match(reqNode.requestId, /^[0-9a-f]{32}$/);
    assert.match(reqBundle.requestId, /^[0-9a-f]{32}$/);
    assert.ok(Number.isInteger(reqNode.createdAtMs) && reqNode.createdAtMs > 0);
    assert.ok(Number.isInteger(reqBundle.createdAtMs) && reqBundle.createdAtMs > 0);

    assert.deepEqual(rehome(stripNonDeterministic(reqBundle)), rehome(stripNonDeterministic(reqNode)));
  });
}

for (const vector of TRANSACTION_SIGNING_VECTORS) {
  test(`createTransactionSigningRequest equivalence (mod. requestId/createdAtMs) for network=${vector.network}`, () => {
    const reqNode = nodeInterface.createTransactionSigningRequest(vector);
    const reqBundle = PolicyVaultCore.signerInterface.createTransactionSigningRequest(rehomeInto(sandboxGlobal, vector));

    assert.match(reqBundle.requestId, /^[0-9a-f]{32}$/);
    assert.deepEqual(rehome(stripNonDeterministic(reqBundle)), rehome(stripNonDeterministic(reqNode)));
  });
}

test("assertCanonicalSignInputs accepts/refuses identically in both runtimes", () => {
  const valid = [
    { index: 0, sighashType: 1 },
    { index: 41, sighashType: 1 }
  ];
  assert.deepEqual(rehome(PolicyVaultCore.signerInterface.assertCanonicalSignInputs(rehomeInto(sandboxGlobal, valid))), rehome(nodeInterface.assertCanonicalSignInputs(valid)));

  const malformedCases = [[], [{ index: -1, sighashType: 1 }], [{ index: 0, sighashType: 2 }], [{ index: 0, sighashType: 1, extra: true }], "not-an-array"];
  for (const bad of malformedCases) {
    let nodeCode = null;
    try {
      nodeInterface.assertCanonicalSignInputs(bad);
    } catch (e) {
      nodeCode = e.signerCode;
    }
    let bundleCode = null;
    try {
      PolicyVaultCore.signerInterface.assertCanonicalSignInputs(typeof bad === "object" && bad !== null ? rehomeInto(sandboxGlobal, bad) : bad);
    } catch (e) {
      bundleCode = e.signerCode;
    }
    assert.equal(nodeCode, "REQUEST_INVALID", `sanity: ${JSON.stringify(bad)} must be refused on Node`);
    assert.equal(bundleCode, nodeCode, `case ${JSON.stringify(bad)}`);
  }
});

for (const vector of PUBLIC_KEY_NORMALIZATION_VECTORS) {
  test(`normalizePublicKeyToXOnly equivalence for input ${JSON.stringify(vector.input).slice(0, 20)}...`, () => {
    let nodeResult = { ok: true, value: null, code: null };
    try {
      nodeResult.value = nodeInterface.normalizePublicKeyToXOnly(vector.input, "test");
    } catch (e) {
      nodeResult = { ok: false, value: null, code: e.signerCode };
    }
    let bundleResult = { ok: true, value: null, code: null };
    try {
      bundleResult.value = PolicyVaultCore.signerInterface.normalizePublicKeyToXOnly(vector.input, "test");
    } catch (e) {
      bundleResult = { ok: false, value: null, code: e.signerCode };
    }
    assert.equal(nodeResult.ok, vector.expectOk, "sanity: vector's expected outcome must match Node's real behavior");
    assert.deepEqual(bundleResult, nodeResult);
  });
}

test("validateCapabilityDescriptor + negotiateCapabilities agree node vs bundle over a representative descriptor", () => {
  const descriptor = {
    interfaceVersion: nodeInterface.SIGNER_INTERFACE_VERSION,
    provider: "cross-runtime-mock",
    label: "Cross-runtime mock signer",
    kind: "mock",
    schemes: ["schnorr"],
    networks: ["testnet-10", "mainnet"],
    features: {
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
  };

  const normNode = nodeInterface.validateCapabilityDescriptor(descriptor);
  const normBundle = PolicyVaultCore.signerInterface.validateCapabilityDescriptor(rehomeInto(sandboxGlobal, descriptor));
  assert.deepEqual(rehome(normBundle), rehome(normNode));

  for (const requirement of CAPABILITY_NEGOTIATION_REQUIREMENTS) {
    const rNode = nodeInterface.negotiateCapabilities(normNode, requirement);
    const rBundle = PolicyVaultCore.signerInterface.negotiateCapabilities(normBundle, rehomeInto(sandboxGlobal, requirement));
    assert.deepEqual(rehome(rBundle), rehome(rNode), `requirement ${JSON.stringify(requirement)}`);
  }
});

test("an unknown capability in a descriptor is refused identically (PROTOCOL_VIOLATION) in both runtimes", () => {
  const bad = {
    interfaceVersion: nodeInterface.SIGNER_INTERFACE_VERSION,
    provider: "bad-mock",
    label: "Bad mock",
    kind: "mock",
    schemes: ["schnorr"],
    networks: ["testnet-10"],
    features: { messageSigning: true, notARealFeature: true }
  };
  let nodeCode = null;
  try {
    nodeInterface.validateCapabilityDescriptor(bad);
  } catch (e) {
    nodeCode = e.signerCode;
  }
  let bundleCode = null;
  try {
    PolicyVaultCore.signerInterface.validateCapabilityDescriptor(rehomeInto(sandboxGlobal, bad));
  } catch (e) {
    bundleCode = e.signerCode;
  }
  assert.equal(nodeCode, "PROTOCOL_VIOLATION");
  assert.equal(bundleCode, nodeCode);
});
