"use strict";

/*
 * UNIT — Universal Signer Interface v1: signing-request creation,
 * canonical signInputs, provider public-key normalization, and response
 * contracts (frozen-bytes discipline).
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  createMessageSigningRequest,
  createTransactionSigningRequest,
  assertSigningRequest,
  assertCanonicalSignInputs,
  normalizePublicKeyToXOnly,
  validateSignatureResponse,
  validateSignedTransactionResponse
} = require("../index");

const CHALLENGE =
  "PolicyVault authentication\norigin: https://app.policy-vault.org\nnetwork: testnet-10\naddress: kaspatest:qq0\nnonce: 00ff\nissued: 2026-08-25T00:00:00.000Z\nThis signature only signs you in. It cannot move funds.";

test("message request: explicit schnorr scheme, frozen, versioned, unique ids", () => {
  const a = createMessageSigningRequest({ message: CHALLENGE, scheme: "schnorr", network: "testnet-10", expectedSignerAddress: "kaspatest:qq0" });
  const b = createMessageSigningRequest({ message: CHALLENGE, scheme: "schnorr" });
  assert.equal(a.interfaceVersion, SIGNER_INTERFACE_VERSION);
  assert.equal(a.kind, "sign-message");
  assert.equal(a.message, CHALLENGE); // verbatim — the signer displays exactly this
  assert.equal(a.scheme, "schnorr");
  assert.equal(a.network, "testnet-10");
  assert.match(a.requestId, /^[0-9a-f]{32}$/);
  assert.notEqual(a.requestId, b.requestId);
  assert.ok(Object.isFrozen(a));
  assert.equal(assertSigningRequest(a), a);
});

test("message request: scheme is never defaulted or auto-selected", () => {
  assert.throws(
    () => createMessageSigningRequest({ message: CHALLENGE }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /never defaults or auto-selects/.test(e.message)
  );
  assert.throws(
    () => createMessageSigningRequest({ message: CHALLENGE, scheme: "auto" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown signature scheme/.test(e.message)
  );
});

test("message request: empty/oversized message and unknown network are refused", () => {
  assert.throws(() => createMessageSigningRequest({ message: "", scheme: "schnorr" }), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(
    () => createMessageSigningRequest({ message: "x".repeat(16385), scheme: "schnorr" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID
  );
  assert.throws(
    () => createMessageSigningRequest({ message: CHALLENGE, scheme: "schnorr", network: "testnet-11" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown network/.test(e.message)
  );
});

test("transaction request: frozen bytes pass through verbatim; deep-frozen", () => {
  const unsigned = JSON.stringify({ version: 1, inputs: [{}, {}], outputs: [] });
  const req = createTransactionSigningRequest({
    unsignedSafeJson: unsigned,
    signInputs: [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: "kaspatest:qq0"
  });
  assert.equal(req.kind, "sign-transaction");
  assert.equal(req.unsignedSafeJson, unsigned); // NEVER re-encoded/trimmed
  assert.deepEqual(
    req.signInputs.map((s) => ({ ...s })),
    [{ index: 0, sighashType: 1 }, { index: 1, sighashType: 1 }]
  );
  assert.ok(Object.isFrozen(req));
  assert.ok(Object.isFrozen(req.signInputs));
  assert.ok(Object.isFrozen(req.signInputs[0]));
  assert.equal(assertSigningRequest(req), req);
});

test("transaction request: network and expectedSignerAddress are REQUIRED (funds path is always bound)", () => {
  const base = { unsignedSafeJson: "{}", signInputs: [{ index: 0, sighashType: 1 }] };
  assert.throws(
    () => createTransactionSigningRequest({ ...base, expectedSignerAddress: "kaspatest:qq0" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /network is required/.test(e.message)
  );
  assert.throws(
    () => createTransactionSigningRequest({ ...base, network: "testnet-10" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /expectedSignerAddress is required/.test(e.message)
  );
});

test("canonical signInputs: the exact frozen { index, sighashType: 1 } shape, nothing else", () => {
  assert.throws(() => assertCanonicalSignInputs([]), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => assertCanonicalSignInputs(undefined), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  // The real-KasWare incident shape: a reconstructed entry that dropped sighashType.
  assert.throws(() => assertCanonicalSignInputs([{ index: 0 }]), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => assertCanonicalSignInputs([{ index: 0, sighashType: 0 }]), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => assertCanonicalSignInputs([{ index: -1, sighashType: 1 }]), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(() => assertCanonicalSignInputs([{ index: 0.5, sighashType: 1 }]), (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID);
  assert.throws(
    () => assertCanonicalSignInputs([{ index: 0, sighashType: 1, sighashTypes: [1] }]),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown key/.test(e.message)
  );
  const ok = assertCanonicalSignInputs([{ index: 3, sighashType: 1 }]);
  assert.deepEqual(ok.map((s) => ({ ...s })), [{ index: 3, sighashType: 1 }]);
});

test("assertSigningRequest: unknown kind and unknown version fail closed", () => {
  const good = createMessageSigningRequest({ message: "m", scheme: "schnorr" });
  assert.throws(
    () => assertSigningRequest({ ...good, kind: "sign-blob" }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown signing request kind/.test(e.message)
  );
  assert.throws(
    () => assertSigningRequest({ ...good, interfaceVersion: "policyvault-signer/9" }),
    (e) => e.signerCode === SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED
  );
});

/* ---- provider public-key normalization (exact web/wallet.js rules) ---- */

const X = "a".repeat(64);

test("pubkey: 64-hex x-only is canonicalized (trim + lowercase)", () => {
  assert.equal(normalizePublicKeyToXOnly(X), X);
  assert.equal(normalizePublicKeyToXOnly(`  ${X.toUpperCase()}  `), X);
});

test("pubkey: 66-hex compressed (02/03) yields its X coordinate", () => {
  assert.equal(normalizePublicKeyToXOnly("02" + X), X);
  assert.equal(normalizePublicKeyToXOnly("03" + X.toUpperCase()), X);
});

test("pubkey: uncompressed 04-keys are refused", () => {
  assert.throws(
    () => normalizePublicKeyToXOnly("04" + "b".repeat(128)),
    (e) => e.signerCode === SignerErrorCodes.INVALID_PUBLIC_KEY && /uncompressed/.test(e.message)
  );
});

test("pubkey: missing / non-hex / wrong-length values are refused with shape-only diagnostics", () => {
  assert.throws(() => normalizePublicKeyToXOnly(undefined), (e) => e.signerCode === SignerErrorCodes.INVALID_PUBLIC_KEY);
  assert.throws(() => normalizePublicKeyToXOnly("   "), (e) => e.signerCode === SignerErrorCodes.INVALID_PUBLIC_KEY);
  assert.throws(
    () => normalizePublicKeyToXOnly("zz".repeat(32), "test provider"),
    (e) => e.signerCode === SignerErrorCodes.INVALID_PUBLIC_KEY && /non-hex data/.test(e.message) && !e.message.includes("zz")
  );
  assert.throws(
    () => normalizePublicKeyToXOnly("ab".repeat(20)),
    (e) => e.signerCode === SignerErrorCodes.INVALID_PUBLIC_KEY && /40-char hex/.test(e.message)
  );
});

/* ---- response contracts ---- */

test("schnorr signature response: 128-hex accepted and canonicalized; anything else refused", () => {
  const req = createMessageSigningRequest({ message: "m", scheme: "schnorr" });
  const sig = "AB".repeat(64);
  assert.equal(validateSignatureResponse(req, ` ${sig} `), "ab".repeat(64));
  for (const bad of [undefined, "", "ab".repeat(32), "ab".repeat(65), "zz".repeat(64), 42]) {
    assert.throws(() => validateSignatureResponse(req, bad), (e) => e.signerCode === SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  }
});

test("ecdsa signature response contract is UNDEFINED in v1 — refused fail-closed", () => {
  const req = createMessageSigningRequest({ message: "m", scheme: "ecdsa" });
  assert.throws(
    () => validateSignatureResponse(req, "ab".repeat(64)),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_SCHEME && /no verified ECDSA/.test(e.message)
  );
});

test("signed-transaction response: non-empty string returned VERBATIM; empty refused", () => {
  const raw = '  {"signed":true}  ';
  assert.equal(validateSignedTransactionResponse(raw), raw); // no trimming — bytes discipline
  for (const bad of [undefined, null, "", "   ", {}]) {
    assert.throws(() => validateSignedTransactionResponse(bad), (e) => e.signerCode === SignerErrorCodes.INVALID_SIGNATURE_RESPONSE);
  }
});
