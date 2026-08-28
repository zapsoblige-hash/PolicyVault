"use strict";

/*
 * UNIT — Universal Signer Interface v1: error taxonomy + fail-closed
 * mapping of unknown adapter failures.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SignerErrorCodes,
  SignerError,
  signerError,
  isSignerError,
  isKnownErrorCode,
  assertKnownErrorCode,
  normalizeAdapterFailure
} = require("../index");

const EXPECTED_CODES = [
  "SIGNER_NOT_FOUND",
  "SIGNER_DISCONNECTED",
  "SIGNER_LOCKED",
  "USER_REJECTED",
  "WRONG_NETWORK",
  "ACCOUNT_CHANGED",
  "UNSUPPORTED_CAPABILITY",
  "UNSUPPORTED_SCHEME",
  "INVALID_PUBLIC_KEY",
  "INVALID_SIGNATURE_RESPONSE",
  "SIGNER_TIMEOUT",
  "PROVIDER_ERROR",
  "PROTOCOL_VIOLATION",
  "INTERFACE_VERSION_UNSUPPORTED",
  "REQUEST_INVALID"
];

test("the v1 vocabulary is exactly the specified closed set", () => {
  assert.deepEqual(Object.keys(SignerErrorCodes).sort(), [...EXPECTED_CODES].sort());
  for (const code of EXPECTED_CODES) {
    assert.equal(SignerErrorCodes[code], code);
    assert.ok(isKnownErrorCode(code));
  }
  assert.ok(Object.isFrozen(SignerErrorCodes));
});

test("every known code constructs a SignerError carrying that code", () => {
  for (const code of EXPECTED_CODES) {
    const e = signerError(code, `message for ${code}`);
    assert.ok(isSignerError(e));
    assert.ok(e instanceof Error);
    assert.equal(e.signerCode, code);
    assert.equal(e.message, `message for ${code}`);
  }
});

test("constructing a SignerError with an unknown code is itself refused", () => {
  assert.throws(() => signerError("TOTALLY_NEW_CODE", "nope"), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
  assert.throws(() => new SignerError(undefined, "nope"), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("assertKnownErrorCode: known passes through, unknown fails closed", () => {
  assert.equal(assertKnownErrorCode("USER_REJECTED"), "USER_REJECTED");
  assert.throws(() => assertKnownErrorCode("USER_DECLINED"), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
  assert.throws(() => assertKnownErrorCode(4001), (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION);
  assert.equal(isKnownErrorCode("USER_DECLINED"), false);
});

test("normalizeAdapterFailure passes an existing SignerError through unchanged", () => {
  const original = signerError(SignerErrorCodes.WRONG_NETWORK, "wrong net");
  assert.equal(normalizeAdapterFailure(original, "ctx"), original);
});

test("normalizeAdapterFailure wraps an adapter-classified KNOWN code, preserving code + cause", () => {
  const raw = { signerCode: "USER_REJECTED", message: "the holder declined" };
  const e = normalizeAdapterFailure(raw, "signMessage");
  assert.ok(isSignerError(e));
  assert.equal(e.signerCode, SignerErrorCodes.USER_REJECTED);
  assert.match(e.message, /signMessage: the holder declined/);
  assert.equal(e.cause, raw);
});

test("normalizeAdapterFailure maps an UNKNOWN claimed code to PROTOCOL_VIOLATION (fail closed, never passed through)", () => {
  const raw = { signerCode: "WALLET_ON_FIRE", message: "??" };
  const e = normalizeAdapterFailure(raw, "signTransaction");
  assert.equal(e.signerCode, SignerErrorCodes.PROTOCOL_VIOLATION);
  assert.match(e.message, /unknown error code "WALLET_ON_FIRE"/);
  assert.equal(e.details.claimedCode, "WALLET_ON_FIRE");
  assert.equal(e.cause, raw);
});

test("normalizeAdapterFailure maps a non-string claimed code to PROTOCOL_VIOLATION", () => {
  const e = normalizeAdapterFailure({ signerCode: 4001, message: "numeric provider code" });
  assert.equal(e.signerCode, SignerErrorCodes.PROTOCOL_VIOLATION);
  assert.equal(e.details.claimedCode, "4001");
});

test("normalizeAdapterFailure maps a plain Error to PROVIDER_ERROR with cause preserved", () => {
  const raw = new Error("socket hang up");
  const e = normalizeAdapterFailure(raw, "connect");
  assert.equal(e.signerCode, SignerErrorCodes.PROVIDER_ERROR);
  assert.match(e.message, /connect: socket hang up/);
  assert.equal(e.cause, raw);
});

test("normalizeAdapterFailure maps non-error garbage to PROVIDER_ERROR", () => {
  assert.equal(normalizeAdapterFailure("boom").signerCode, SignerErrorCodes.PROVIDER_ERROR);
  assert.equal(normalizeAdapterFailure(undefined).signerCode, SignerErrorCodes.PROVIDER_ERROR);
  assert.equal(normalizeAdapterFailure(null).signerCode, SignerErrorCodes.PROVIDER_ERROR);
  assert.equal(normalizeAdapterFailure(42).signerCode, SignerErrorCodes.PROVIDER_ERROR);
});
