"use strict";

/*
 * UNIT — Universal Signer Interface v2: request construction, response
 * envelopes, and the signing lifecycle (gate order, transitions,
 * deadlines, observers).
 *
 * The hostile cases live in hostile-v2.test.js; this file pins the
 * CONTRACT: what a well-behaved consumer and a well-behaved signer do,
 * and the exact order in which the fail-closed gates run.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  SIGHASH_ALL,
  MIN_TTL_MS,
  MAX_TTL_MS,
  createMockSignerAdapterV2,
  createMessageSigningRequestV2,
  createTransactionSigningRequestV2,
  assertSigningRequestV2,
  buildResponseEnvelope,
  validateResponseEnvelope,
  executeSigningV2,
  createReplayGuard,
  createCancellationToken,
  validateAdapterV2
} = require("../v2");

const ACCOUNT_A = "kaspatest:mockv2signeraccount0";
const TX = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0 }], outputs: [] });
const MESSAGE = "PolicyVault sign-in. This signature only signs you in. It cannot move funds.";

function txRequest(overrides = {}) {
  return createTransactionSigningRequestV2({
    unsignedSafeJson: TX,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: ACCOUNT_A,
    ttlMs: 60000,
    ...overrides
  });
}

function msgRequest(overrides = {}) {
  return createMessageSigningRequestV2({ message: MESSAGE, scheme: "schnorr", network: "testnet-10", expectedSignerAddress: ACCOUNT_A, ttlMs: 60000, ...overrides });
}

function deriveTransactionId(safeJson) {
  const parsed = JSON.parse(safeJson);
  return typeof parsed.base === "string" ? JSON.parse(parsed.base).id : parsed.id;
}

/* ======================= request construction ======================== */

test("a v2 transaction request is frozen and carries the full binding set", () => {
  const request = txRequest();
  assert.ok(Object.isFrozen(request));
  assert.equal(request.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
  assert.match(request.requestId, /^[0-9a-f]{32}$/);
  assert.match(request.nonce, /^[0-9a-f]{64}$/, "32 CSPRNG bytes of nonce");
  assert.match(request.payloadSha256, /^[0-9a-f]{64}$/);
  assert.equal(request.transactionFormat, "kaspa-safe-json/1");
  assert.deepEqual({ ...request.sighash }, { all: true, none: false, single: false, anyoneCanPay: false });
  assert.equal(request.expiresAtMs - request.createdAtMs, 60000);
  assert.equal(request.signInputs[0].sighashType, SIGHASH_ALL);
  assert.ok(Object.isFrozen(request.signInputs) && Object.isFrozen(request.signInputs[0]));
});

test("nonces and request ids are unique per request", () => {
  const seen = new Set();
  for (let i = 0; i < 64; i += 1) {
    const r = txRequest();
    assert.equal(seen.has(r.nonce), false);
    assert.equal(seen.has(r.requestId), false);
    seen.add(r.nonce);
    seen.add(r.requestId);
  }
});

test("every request MUST expire, within bounds", () => {
  assert.throws(() => txRequest({ ttlMs: undefined }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => txRequest({ ttlMs: MIN_TTL_MS - 1 }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => txRequest({ ttlMs: MAX_TTL_MS + 1 }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  // ONE request: expiresAtMs - createdAtMs of the SAME request is exactly the
  // ttl. (Comparing two separately created requests flaked by 1 ms whenever
  // the clock ticked between the two constructions under CPU load.)
  const maxed = txRequest({ ttlMs: MAX_TTL_MS });
  assert.equal(maxed.expiresAtMs - maxed.createdAtMs, MAX_TTL_MS);
});

test("transaction requests REQUIRE a network and an expected signer; message requests do not", () => {
  assert.throws(() => txRequest({ network: undefined }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => txRequest({ expectedSignerAddress: undefined }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  const bare = createMessageSigningRequestV2({ message: MESSAGE, scheme: "schnorr", ttlMs: 5000 });
  assert.equal(bare.network, undefined);
  assert.equal(bare.expectedSignerAddress, undefined);
});

test("the signature scheme is ALWAYS explicit — never defaulted, never auto", () => {
  assert.throws(
    () => createMessageSigningRequestV2({ message: MESSAGE, ttlMs: 5000 }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID && /never defaults or auto-selects/.test(e.message)
  );
  assert.throws(() => createMessageSigningRequestV2({ message: MESSAGE, scheme: "auto", ttlMs: 5000 }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("signInputs keep the canonical closed shape; unknown keys are refused", () => {
  assert.throws(() => txRequest({ signInputs: [{ index: 0, sighashType: 1, utxo: {} }] }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => txRequest({ signInputs: [{ index: -1, sighashType: 1 }] }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => txRequest({ signInputs: [] }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("assertSigningRequestV2 re-validates structurally — a v1 request is refused", () => {
  assert.throws(
    () => assertSigningRequestV2({ ...txRequest(), interfaceVersion: "policyvault-signer/1" }),
    (e) => e.signerCode === SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED
  );
  assert.throws(() => assertSigningRequestV2({ ...txRequest(), nonce: "short" }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.throws(() => assertSigningRequestV2({ ...txRequest(), kind: "sign-anything" }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

/* ======================= response envelopes ========================== */

test("buildResponseEnvelope copies every binding field from the request and validates back clean", () => {
  const request = txRequest();
  const envelope = buildResponseEnvelope(request, { signedSafeJson: TX }, { signerAddress: ACCOUNT_A });
  assert.ok(Object.isFrozen(envelope));
  assert.equal(envelope.requestId, request.requestId);
  assert.equal(envelope.nonce, request.nonce);
  assert.equal(envelope.payloadSha256, request.payloadSha256);
  assert.equal(envelope.sighashType, SIGHASH_ALL);
  assert.deepEqual({ ...validateResponseEnvelope(request, envelope) }, { signedSafeJson: TX });
});

test("a message envelope carries null sighash/format and a lowercased 128-hex signature", () => {
  const request = msgRequest();
  const envelope = buildResponseEnvelope(request, { signature: "AB".repeat(64) });
  assert.equal(envelope.sighashType, null);
  assert.equal(envelope.transactionFormat, null);
  assert.equal(validateResponseEnvelope(request, envelope).signature, "ab".repeat(64));
});

test("buildResponseEnvelope refuses unknown extras", () => {
  assert.throws(() => buildResponseEnvelope(txRequest(), { signedSafeJson: TX }, { privateKey: "x" }), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
});

test("an ECDSA message request is refused at the response contract as well as before invocation", async () => {
  const adapter = createMockSignerAdapterV2({ schemes: ["schnorr", "ecdsa"] });
  const request = msgRequest({ scheme: "ecdsa" });
  await assert.rejects(() => executeSigningV2(adapter, request), (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_SCHEME);
  assert.equal(adapter.control.invocations, 0, "no prompt may open for a scheme with no verified response contract");
  const envelope = buildResponseEnvelope(request, { signature: "ab".repeat(64) });
  assert.throws(() => validateResponseEnvelope(request, envelope), (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_SCHEME);
});

/* ========================= lifecycle ================================= */

test("the happy path emits exactly SUBMITTED then APPROVED and returns a frozen outcome", async () => {
  const adapter = createMockSignerAdapterV2();
  const states = [];
  const outcome = await executeSigningV2(adapter, txRequest(), { deriveTransactionId, onTransition: (t) => states.push(t.state) });
  assert.deepEqual(states, ["SUBMITTED", "APPROVED"]);
  assert.ok(Object.isFrozen(outcome));
  assert.equal(outcome.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
  assert.equal(outcome.status, "approved");
  assert.equal(outcome.provider, "mockv2");
  assert.equal(outcome.transport, "in-page");
  assert.equal(outcome.capabilitiesProbed, true);
  assert.equal(outcome.txIdVerified, true);
  assert.equal(outcome.transactionId, "a".repeat(64));
});

test("a message signature runs the same lifecycle and returns the validated signature", async () => {
  const adapter = createMockSignerAdapterV2();
  const outcome = await executeSigningV2(adapter, msgRequest());
  assert.match(outcome.result.signature, /^[0-9a-f]{128}$/);
  assert.equal(outcome.txIdVerified, false, "message signing performs no transaction-id check");
});

test("unknown executeSigning options are refused (closed option vocabulary)", async () => {
  await assert.rejects(
    () => executeSigningV2(createMockSignerAdapterV2(), txRequest(), { retryOnFailure: true }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID
  );
});

test("an asynchronous signer REQUIRES an explicit timeoutMs — an unbounded wait is refused", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  await assert.rejects(() => executeSigningV2(adapter, txRequest()), (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID);
  assert.equal(adapter.control.invocations, 0);
});

test("a timeoutMs longer than the signer's declared maxTimeoutMs is refused rather than waited out", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true, maxTimeoutMs: 5000 });
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest(), { timeoutMs: 3600000 }),
    (e) => e.signerCode === SignerErrorCodesV2.REQUEST_INVALID && /declares it can honour/.test(e.message)
  );
});

test("an out-of-band approval that never arrives times out, cancels best-effort, and discards late settlements", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest();
  const states = [];
  await assert.rejects(
    () => executeSigningV2(adapter, request, { timeoutMs: 30, onTransition: (t) => states.push(t.state) }),
    (e) => e.signerCode === SignerErrorCodesV2.SIGNER_TIMEOUT
  );
  assert.deepEqual(states, ["SUBMITTED", "TIMED_OUT"]);
  assert.deepEqual(adapter.control.cancelled, [request.requestId]);
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(states, ["SUBMITTED", "TIMED_OUT"], "no second terminal transition is ever emitted");
});

test("an out-of-band approval that DOES arrive completes normally", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest();
  const run = executeSigningV2(adapter, request, { timeoutMs: 5000, deriveTransactionId });
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(adapter.control.listPending(), [request.requestId]);
  adapter.control.approve(request.requestId);
  const outcome = await run;
  assert.equal(outcome.status, "approved");
});

test("the transport gate refuses an adapter whose transport the consumer does not accept", async () => {
  const adapter = createMockSignerAdapterV2();
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest(), { allowedTransports: ["qr-airgap", "file"] }),
    (e) => e.signerCode === SignerErrorCodesV2.TRANSPORT_UNSUPPORTED
  );
  assert.equal(adapter.control.invocations, 0);
  const ok = await executeSigningV2(adapter, txRequest(), { allowedTransports: ["in-page"], deriveTransactionId });
  assert.equal(ok.status, "approved");
});

test("the user-presence gate refuses an unattended signer when a human is required", async () => {
  const unattended = createMockSignerAdapterV2({ userPresence: "not-required" });
  await assert.rejects(
    () => executeSigningV2(unattended, txRequest(), { requireUserPresence: true }),
    (e) => e.signerCode === SignerErrorCodesV2.USER_PRESENCE_REQUIRED
  );
  assert.equal(unattended.control.invocations, 0);
  const attended = createMockSignerAdapterV2({ userPresence: "required" });
  assert.equal((await executeSigningV2(attended, txRequest(), { requireUserPresence: true, deriveTransactionId })).status, "approved");
});

test("a capability the adapter does not declare is refused before any provider contact", async () => {
  const noTx = createMockSignerAdapterV2({
    features: { transactionSigning: false, specificInputSigning: false },
    transactionFormats: []
  });
  await assert.rejects(() => executeSigningV2(noTx, txRequest()), (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_CAPABILITY);

  const wholeTxOnly = createMockSignerAdapterV2({ features: { specificInputSigning: false } });
  await assert.rejects(
    () => executeSigningV2(wholeTxOnly, txRequest()),
    (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_CAPABILITY && /specificInputSigning/.test(e.message)
  );
});

test("a provider failure carrying an UNKNOWN code is a contract breach, not a guess", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.failNextSignWith({ signerCode: "SOMETHING_ELSE", message: "nope" });
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest()),
    (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION && e.details.claimedCode === "SOMETHING_ELSE"
  );
});

test("a provider throwing a plain exception is classified PROVIDER_ERROR with the cause preserved", async () => {
  const adapter = createMockSignerAdapterV2();
  const boom = new Error("extension crashed");
  adapter.control.failNextSignWith(boom);
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest()),
    (e) => e.signerCode === SignerErrorCodesV2.PROVIDER_ERROR && e.cause === boom
  );
});

test("a locked signer surfaces SIGNER_LOCKED through the sanctioned adapter classification channel", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.lock();
  await assert.rejects(() => executeSigningV2(adapter, txRequest()), (e) => e.signerCode === SignerErrorCodesV2.SIGNER_LOCKED);
});

test("an exception thrown by an observer can never alter the signing outcome", async () => {
  const adapter = createMockSignerAdapterV2();
  const outcome = await executeSigningV2(adapter, txRequest(), {
    deriveTransactionId,
    onTransition: () => {
      throw new Error("observer exploded");
    }
  });
  assert.equal(outcome.status, "approved");
});

test("transition records are frozen and carry the request id, state and a timestamp", async () => {
  const seen = [];
  await executeSigningV2(createMockSignerAdapterV2(), txRequest(), { deriveTransactionId, onTransition: (t) => seen.push(t) });
  for (const record of seen) {
    assert.ok(Object.isFrozen(record));
    assert.match(record.requestId, /^[0-9a-f]{32}$/);
    assert.equal(typeof record.atMs, "number");
  }
});

test("a pre-validated registration record can be reused without re-running describe()", async () => {
  const adapter = createMockSignerAdapterV2();
  const registration = validateAdapterV2(adapter);
  const outcome = await executeSigningV2(registration, txRequest(), { deriveTransactionId });
  assert.equal(outcome.status, "approved");
});

test("a replay guard shared across DIFFERENT requests admits each exactly once", async () => {
  const guard = createReplayGuard();
  const adapter = createMockSignerAdapterV2();
  for (let i = 0; i < 3; i += 1) {
    const outcome = await executeSigningV2(adapter, txRequest(), { replayGuard: guard, deriveTransactionId });
    assert.equal(outcome.status, "approved");
  }
  assert.deepEqual({ ...guard.stats() }, { open: 0, settled: 3, noncesSeen: 3 });
});

test("a cancellation token cancels once and reports its reason", () => {
  const token = createCancellationToken();
  assert.equal(token.cancelled, false);
  assert.equal(token.cancel("because"), true);
  assert.equal(token.cancel("again"), false, "cancellation is idempotent");
  assert.equal(token.reason, "because");
  let observed = null;
  token.onCancel((r) => {
    observed = r;
  });
  assert.equal(observed, "because", "a listener registered after cancellation fires immediately");
});
