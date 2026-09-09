"use strict";

/*
 * ADVERSARIAL / HOSTILE — Universal Signer Interface v2.
 *
 * Every test here drives a MISBEHAVING signer, a MISBEHAVING transport,
 * or a MISBEHAVING consumer and asserts that PolicyVault fails CLOSED
 * with a specific structured error code. Nothing here is a happy path.
 *
 * The threat model these cases come from is deliberately hostile to the
 * signer boundary itself: PolicyVault is non-custodial, so the signer is
 * NOT trusted to be honest — it is trusted only to hold a key. Every
 * claim it makes (network, account, capabilities, "here is your
 * signature") is checked against something PolicyVault fixed BEFORE the
 * request left, and consensus remains the security boundary underneath
 * all of it.
 *
 * Covered, one block each:
 *   H1  wrong network (declared and live)
 *   H2  wrong account
 *   H3  account changed mid-request
 *   H4  transaction mutated after local verification
 *   H5  unsupported sighash — requested, declared, and returned
 *   H6  signer returning malformed bytes
 *   H7  signer signing a DIFFERENT transaction (txid drift)
 *   H8  stale request (expiry, before and during)
 *   H9  cancellation — by the holder and by the consumer
 *   H10 duplicate settlement (a callback delivered twice)
 *   H11 transport replay (an old response replayed at a new request)
 *   H12 a signer claiming a capability it does not have (probe mismatch)
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SignerErrorCodesV2,
  SIGNER_INTERFACE_VERSION_V2,
  createMockSignerAdapterV2,
  createMessageSigningRequestV2,
  createTransactionSigningRequestV2,
  executeSigningV2,
  validateAdapterV2,
  createReplayGuard,
  createCancellationToken,
  buildResponseEnvelope,
  validateResponseEnvelope,
  assertCanonicalSignInputsV2
} = require("../v2");

const ACCOUNT_A = "kaspatest:mockv2signeraccount0";
const ACCOUNT_B = "kaspatest:mockv2signeraccount1";
const TX_A = JSON.stringify({ id: "a".repeat(64), version: 0, inputs: [{ index: 0 }], outputs: [] });
const TX_B = JSON.stringify({ id: "b".repeat(64), version: 0, inputs: [{ index: 0 }], outputs: [] });

/* A stand-in for the authoritative kaspa-wasm id derivation: the core
 * holds no transaction code, so consumers inject this. The stub reads the
 * id the mock's "signed" payload carries — enough to prove the CORE's
 * comparison logic; the real derivation is kaspa-wasm's. */
function deriveTransactionId(safeJson) {
  const parsed = JSON.parse(safeJson);
  if (typeof parsed.base === "string") return JSON.parse(parsed.base).id;
  return parsed.id;
}

function txRequest(overrides = {}) {
  return createTransactionSigningRequestV2({
    unsignedSafeJson: TX_A,
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: ACCOUNT_A,
    ttlMs: 60000,
    ...overrides
  });
}

function msgRequest(overrides = {}) {
  return createMessageSigningRequestV2({
    message: "PolicyVault sign-in. This signature only signs you in. It cannot move funds.",
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: ACCOUNT_A,
    ttlMs: 60000,
    ...overrides
  });
}

async function refusedWith(code, fn, what) {
  await assert.rejects(fn, (e) => {
    assert.equal(e.signerCode, code, `${what}: expected ${code}, got ${e.signerCode} (${e.message})`);
    assert.equal(e.interfaceVersion, SIGNER_INTERFACE_VERSION_V2);
    return true;
  });
}

/* ==================================================================== */
/* H1 — wrong network                                                    */
/* ==================================================================== */

test("H1a wrong network: the signer's LIVE network differs from the request's — refused before invocation", async () => {
  const adapter = createMockSignerAdapterV2({ networks: ["mainnet", "testnet-10"], network: "mainnet" });
  const states = [];
  await refusedWith(
    SignerErrorCodesV2.WRONG_NETWORK,
    () => executeSigningV2(adapter, txRequest(), { onTransition: (t) => states.push(t.state) }),
    "live network mismatch"
  );
  assert.deepEqual(states, ["REFUSED"], "the signer must never be invoked on a network mismatch");
  assert.equal(adapter.control.invocations, 0);
});

test("H1b wrong network: an adapter that does not DECLARE the request's network is refused", async () => {
  const adapter = createMockSignerAdapterV2({ networks: ["testnet-10"], network: "testnet-10" });
  await refusedWith(SignerErrorCodesV2.WRONG_NETWORK, () => executeSigningV2(adapter, txRequest({ network: "mainnet", expectedSignerAddress: ACCOUNT_A })), "undeclared network");
  assert.equal(adapter.control.invocations, 0);
});

test("H1c wrong network: a signer whose live network answer is null/unknown fails closed", async () => {
  const adapter = createMockSignerAdapterV2();
  const broken = { ...adapter, getNetwork: async () => null };
  await refusedWith(SignerErrorCodesV2.WRONG_NETWORK, () => executeSigningV2(broken, txRequest()), "null live network");
});

test("H1d wrong network: a RESPONSE envelope carrying a different network is discarded", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, network: "mainnet" });
  await refusedWith(SignerErrorCodesV2.WRONG_NETWORK, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "response network drift");
});

/* ==================================================================== */
/* H2 — wrong account                                                    */
/* ==================================================================== */

test("H2a wrong account: the live active account is not the expected signer — refused pre-invocation", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.setActiveAccount(ACCOUNT_B);
  await refusedWith(SignerErrorCodesV2.ACCOUNT_CHANGED, () => executeSigningV2(adapter, txRequest()), "wrong active account");
  assert.equal(adapter.control.invocations, 0);
});

test("H2b wrong account: no connected account at all fails closed as SIGNER_DISCONNECTED", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.setConnected(false);
  await refusedWith(SignerErrorCodesV2.SIGNER_DISCONNECTED, () => executeSigningV2(adapter, txRequest()), "disconnected signer");
});

test("H2c wrong account: an envelope signed by a DIFFERENT identity is discarded", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, signerAddress: ACCOUNT_B });
  await refusedWith(SignerErrorCodesV2.ACCOUNT_CHANGED, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "envelope identity drift");
});

/* ==================================================================== */
/* H3 — account changed mid-request                                      */
/* ==================================================================== */

test("H3 account changed WHILE the signer holds the request: the returned signature is discarded", async () => {
  const adapter = createMockSignerAdapterV2();
  /* the switch happens after the pre-gate passed and while signing runs;
   * the envelope still claims the ORIGINAL address (a wallet that switched
   * silently), so only the post-approval re-check can catch it */
  adapter.control.duringSign = () => adapter.control.setActiveAccount(ACCOUNT_B);
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, signerAddress: ACCOUNT_A });
  const states = [];
  await refusedWith(
    SignerErrorCodesV2.ACCOUNT_CHANGED,
    () => executeSigningV2(adapter, txRequest(), { deriveTransactionId, onTransition: (t) => states.push(t.state) }),
    "mid-request account switch"
  );
  assert.deepEqual(states, ["SUBMITTED", "FAILED"], "exactly one terminal transition, and it is not APPROVED");
});

/* ==================================================================== */
/* H4 — transaction mutated after local verification                     */
/* ==================================================================== */

test("H4a the frozen bytes were altered after the request was created — refused before the signer is invoked", async () => {
  const good = txRequest();
  /* an attacker (or a defect) swaps the payload while keeping the digest
   * of the bytes the human actually verified */
  const tampered = Object.freeze({ ...good, unsignedSafeJson: TX_B });
  const adapter = createMockSignerAdapterV2();
  await refusedWith(SignerErrorCodesV2.PAYLOAD_MUTATED, () => executeSigningV2(adapter, tampered, { deriveTransactionId }), "request payload swap");
  assert.equal(adapter.control.invocations, 0, "a mutated payload must never reach the signer");
});

test("H4b the signer reports a different payload digest than the bytes it was handed", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, payloadSha256: "c".repeat(64) });
  await refusedWith(SignerErrorCodesV2.PAYLOAD_MUTATED, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "digest drift");
});

test("H4c a message request whose digest does not match its own message is refused", async () => {
  const good = msgRequest();
  const tampered = Object.freeze({ ...good, message: "Approve a 1,000,000 KAS withdrawal" });
  await refusedWith(SignerErrorCodesV2.PAYLOAD_MUTATED, () => executeSigningV2(createMockSignerAdapterV2(), tampered), "message swap");
});

/* ==================================================================== */
/* H5 — unsupported sighash                                              */
/* ==================================================================== */

test("H5a a request naming any sighash type other than SIGHASH_ALL is refused at creation", () => {
  assert.throws(
    () => txRequest({ signInputs: [{ index: 0, sighashType: 2 }] }),
    (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_SIGHASH
  );
  assert.throws(
    () => assertCanonicalSignInputsV2([{ index: 0, sighashType: 0x81 }]),
    (e) => e.signerCode === SignerErrorCodesV2.UNSUPPORTED_SIGHASH
  );
});

test("H5b a signer that does not DECLARE SIGHASH_ALL is refused before invocation", async () => {
  const adapter = createMockSignerAdapterV2({ sighash: { all: false, none: false, single: true, anyoneCanPay: false } });
  await refusedWith(SignerErrorCodesV2.UNSUPPORTED_SIGHASH, () => executeSigningV2(adapter, txRequest()), "no SIGHASH_ALL declared");
  assert.equal(adapter.control.invocations, 0);
});

test("H5c a signer RETURNING a different sighash type has its signature discarded", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, sighashType: 0x81 });
  await refusedWith(SignerErrorCodesV2.UNSUPPORTED_SIGHASH, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "returned sighash drift");
});

test("H5d a signer returning a different transaction FORMAT is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, transactionFormat: null });
  await refusedWith(
    SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT,
    () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }),
    "returned format drift"
  );
});

/* ==================================================================== */
/* H6 — malformed bytes                                                  */
/* ==================================================================== */

test("H6a a bare string instead of a bound envelope is refused (v2 responses are envelopes)", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = () => "ab".repeat(64);
  await refusedWith(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, () => executeSigningV2(adapter, msgRequest()), "bare-string response");
});

test("H6b a personal-message signature that is not 128-hex Schnorr is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, result: { signature: "not-a-signature" } });
  await refusedWith(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, () => executeSigningV2(adapter, msgRequest()), "malformed signature");
});

test("H6c an empty signed serialization is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, result: { signedSafeJson: "   " } });
  await refusedWith(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "empty serialization");
});

test("H6d a result object carrying extra keys (or the wrong key) is refused — closed shape", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, result: { signedSafeJson: TX_A, privateKeyHex: "deadbeef" } });
  await refusedWith(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "extra result keys");
});

test("H6e an envelope carrying an unknown top-level key is refused — closed schema", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, seedPhrase: "never" });
  await refusedWith(SignerErrorCodesV2.PROTOCOL_VIOLATION, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "unknown envelope key");
});

test("H6f a signed serialization that cannot be parsed to re-derive its id is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.signedPayloadFor = () => "{not json";
  await refusedWith(SignerErrorCodesV2.PAYLOAD_MUTATED, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "unparseable signed bytes");
});

/* ==================================================================== */
/* H7 — the signer signed a DIFFERENT transaction                        */
/* ==================================================================== */

test("H7a txid drift: the signer returns a signature over other bytes — detected and discarded", async () => {
  const adapter = createMockSignerAdapterV2();
  /* the envelope is perfectly bound (right ids, right digest) — only the
   * BYTES differ. Nothing but re-deriving the id can catch this. */
  adapter.control.signedPayloadFor = () => JSON.stringify({ mockSigned: true, base: TX_B });
  const states = [];
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest(), { deriveTransactionId, onTransition: (t) => states.push(t.state) }),
    (e) => {
      assert.equal(e.signerCode, SignerErrorCodesV2.PAYLOAD_MUTATED);
      assert.equal(e.details.expectedTxId, "a".repeat(64));
      assert.equal(e.details.returnedTxId, "b".repeat(64));
      return true;
    }
  );
  assert.deepEqual(states, ["SUBMITTED", "FAILED"]);
});

test("H7b an envelope claiming a txid the signed bytes do not produce is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.mutateEnvelope = (envelope) => ({ ...envelope, signedTxId: "f".repeat(64) });
  await refusedWith(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }), "claimed txid drift");
});

test("H7c WITHOUT an injected id deriver the core reports the check as NOT performed — never as passed", async () => {
  const adapter = createMockSignerAdapterV2();
  adapter.control.signedPayloadFor = () => JSON.stringify({ mockSigned: true, base: TX_B });
  const outcome = await executeSigningV2(adapter, txRequest());
  assert.equal(outcome.status, "approved");
  assert.equal(outcome.txIdVerified, false, "the core must not claim a verification it did not perform");
  assert.equal(outcome.transactionId, null);
});

/* ==================================================================== */
/* H8 — stale request                                                    */
/* ==================================================================== */

test("H8a an already-expired request never reaches the signer", async () => {
  const adapter = createMockSignerAdapterV2();
  const request = txRequest({ ttlMs: 1000, nowMs: 1000 });
  const states = [];
  await refusedWith(
    SignerErrorCodesV2.REQUEST_EXPIRED,
    () => executeSigningV2(adapter, request, { nowMs: 999999999, onTransition: (t) => states.push(t.state) }),
    "stale request"
  );
  assert.deepEqual(states, ["REFUSED"]);
  assert.equal(adapter.control.invocations, 0);
});

test("H8b a request that expires WHILE the signer holds it is cancelled fail-closed", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest({ ttlMs: 1000 });
  const started = Date.now();
  const states = [];
  await refusedWith(
    SignerErrorCodesV2.REQUEST_EXPIRED,
    () =>
      executeSigningV2(adapter, Object.freeze({ ...request, expiresAtMs: started + 40 }), {
        timeoutMs: 5000,
        deriveTransactionId,
        onTransition: (t) => states.push(t.state)
      }),
    "expiry during approval"
  );
  assert.deepEqual(states, ["SUBMITTED", "EXPIRED"]);
  assert.deepEqual(adapter.control.cancelled, [request.requestId], "expiry must attempt best-effort revocation");
});

test("H8c a LATE approval after expiry is discarded — no second terminal transition, no signature", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest({ ttlMs: 1000 });
  const started = Date.now();
  const states = [];
  await refusedWith(
    SignerErrorCodesV2.REQUEST_EXPIRED,
    () => executeSigningV2(adapter, Object.freeze({ ...request, expiresAtMs: started + 30 }), { timeoutMs: 5000, onTransition: (t) => states.push(t.state) }),
    "expiry"
  );
  /* the provider settles afterwards; nothing may deliver it */
  assert.deepEqual(adapter.control.listPending(), [], "cancelSigning removed the pending exchange");
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(states, ["SUBMITTED", "EXPIRED"], "exactly one terminal transition");
});

test("H8d the consumer's timeout is never allowed to outlive the request's own expiry", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest({ ttlMs: 1000 });
  const states = [];
  /* timeoutMs (5s) > remaining validity (~30ms): the EXPIRY must win */
  await refusedWith(
    SignerErrorCodesV2.REQUEST_EXPIRED,
    () => executeSigningV2(adapter, Object.freeze({ ...request, expiresAtMs: Date.now() + 30 }), { timeoutMs: 5000, onTransition: (t) => states.push(t.state) }),
    "expiry beats timeout"
  );
  assert.ok(states.includes("EXPIRED") && !states.includes("TIMED_OUT"));
});

/* ==================================================================== */
/* H9 — cancellation                                                     */
/* ==================================================================== */

test("H9a the signer's HOLDER declines: USER_REJECTED, terminal REJECTED", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest();
  const states = [];
  const run = executeSigningV2(adapter, request, { timeoutMs: 5000, onTransition: (t) => states.push(t.state) });
  await new Promise((r) => setTimeout(r, 10));
  adapter.control.reject(request.requestId);
  await refusedWith(SignerErrorCodesV2.USER_REJECTED, () => run, "holder declined");
  assert.deepEqual(states, ["SUBMITTED", "REJECTED"]);
});

test("H9b the CONSUMER cancels: REQUEST_CANCELLED, terminal CANCELLED, best-effort revocation", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const request = txRequest();
  const cancellation = createCancellationToken();
  const states = [];
  const run = executeSigningV2(adapter, request, { timeoutMs: 5000, cancellation, onTransition: (t) => states.push(t.state) });
  await new Promise((r) => setTimeout(r, 10));
  cancellation.cancel("the approver navigated away");
  await refusedWith(SignerErrorCodesV2.REQUEST_CANCELLED, () => run, "consumer cancellation");
  assert.deepEqual(states, ["SUBMITTED", "CANCELLED"]);
  assert.deepEqual(adapter.control.cancelled, [request.requestId]);
});

test("H9c a request cancelled BEFORE execution never reaches the signer", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const cancellation = createCancellationToken();
  cancellation.cancel("revoked by policy");
  await refusedWith(
    SignerErrorCodesV2.REQUEST_CANCELLED,
    () => executeSigningV2(adapter, txRequest(), { timeoutMs: 5000, cancellation }),
    "pre-cancelled request"
  );
});

test("H9d a sabotaged cancelSigning cannot mask the terminal condition", async () => {
  const adapter = createMockSignerAdapterV2({ asyncApproval: true });
  const sabotaged = { ...adapter, cancelSigning: async () => { throw new Error("provider exploded during cancel"); } };
  const cancellation = createCancellationToken();
  const run = executeSigningV2(sabotaged, txRequest(), { timeoutMs: 5000, cancellation });
  await new Promise((r) => setTimeout(r, 10));
  cancellation.cancel("stop");
  await refusedWith(SignerErrorCodesV2.REQUEST_CANCELLED, () => run, "sabotaged cancellation");
});

/* ==================================================================== */
/* H10 — duplicate settlement                                            */
/* ==================================================================== */

test("H10a a settlement accepted once cannot be accepted twice (duplicate callback)", async () => {
  const guard = createReplayGuard();
  const adapter = createMockSignerAdapterV2();
  const request = txRequest();
  const first = await executeSigningV2(adapter, request, { replayGuard: guard, deriveTransactionId });
  assert.equal(first.status, "approved");
  await refusedWith(
    SignerErrorCodesV2.DUPLICATE_SETTLEMENT,
    () => executeSigningV2(adapter, request, { replayGuard: guard, deriveTransactionId }),
    "same request executed twice"
  );
});

test("H10b the replay guard refuses a second consume directly", () => {
  const guard = createReplayGuard();
  const request = txRequest();
  guard.open(request);
  guard.consume(request);
  assert.throws(() => guard.consume(request), (e) => e.signerCode === SignerErrorCodesV2.DUPLICATE_SETTLEMENT);
  assert.equal(guard.isSettled(request.requestId), true);
});

test("H10c a settlement for a request this session never issued is refused", () => {
  const guard = createReplayGuard();
  assert.throws(() => guard.consume(txRequest()), (e) => e.signerCode === SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH);
});

/* ==================================================================== */
/* H11 — transport replay                                                */
/* ==================================================================== */

test("H11a an old, validly-signed response replayed at a NEW request is refused", async () => {
  const adapter = createMockSignerAdapterV2();
  const first = txRequest();
  let captured = null;
  adapter.control.mutateEnvelope = (envelope) => {
    if (captured === null) captured = envelope;
    return envelope;
  };
  await executeSigningV2(adapter, first, { deriveTransactionId });
  assert.ok(captured, "captured the first, legitimate envelope");

  /* the transport now replays that exact envelope at a fresh request */
  const second = txRequest();
  adapter.control.mutateEnvelope = () => captured;
  await assert.rejects(
    () => executeSigningV2(adapter, second, { deriveTransactionId }),
    (e) => {
      assert.equal(e.signerCode, SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH);
      assert.equal(e.details.field, "requestId");
      return true;
    }
  );
});

test("H11b a nonce reused across two requests in one session is refused as a replay", () => {
  const guard = createReplayGuard();
  const first = txRequest();
  guard.open(first);
  const forged = Object.freeze({ ...txRequest(), nonce: first.nonce });
  assert.throws(() => guard.open(forged), (e) => e.signerCode === SignerErrorCodesV2.REPLAY_DETECTED);
});

test("H11c an envelope answering with a different nonce is refused", () => {
  const request = txRequest();
  const envelope = buildResponseEnvelope(request, { signedSafeJson: TX_A });
  assert.throws(
    () => validateResponseEnvelope(request, { ...envelope, nonce: "0".repeat(64) }),
    (e) => e.signerCode === SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH && e.details.field === "nonce"
  );
});

test("H11d a response for the WRONG KIND is refused", () => {
  const request = msgRequest();
  const envelope = buildResponseEnvelope(request, { signature: "ab".repeat(64) });
  assert.throws(
    () => validateResponseEnvelope(request, { ...envelope, kind: "sign-transaction" }),
    (e) => e.signerCode === SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH && e.details.field === "kind"
  );
});

/* ==================================================================== */
/* H12 — a signer claiming a capability it does not have                 */
/* ==================================================================== */

test("H12a a descriptor declaring transactionSigning while the provider exposes no signer method is refused", async () => {
  const adapter = createMockSignerAdapterV2({
    probe: {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: true,
      methods: ["signMessage", "getNetwork"], /* NO signTransaction */
      sighash: { all: true, none: false, single: false, anyoneCanPay: false },
      transactionFormats: ["kaspa-safe-json/1"]
    }
  });
  await assert.rejects(
    () => executeSigningV2(adapter, txRequest(), { deriveTransactionId }),
    (e) => {
      assert.equal(e.signerCode, SignerErrorCodesV2.CAPABILITY_MISMATCH);
      assert.match(e.details.mismatches.join(" "), /transactionSigning declared but the provider exposes no signTransaction/);
      return true;
    }
  );
  assert.equal(adapter.control.invocations, 0, "no prompt may open for a capability the provider lacks");
});

test("H12b a descriptor declaring SIGHASH_ALL the provider denies is refused", async () => {
  const adapter = createMockSignerAdapterV2({
    probe: {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: true,
      methods: ["signMessage", "signTransaction", "on"],
      sighash: { all: false, none: false, single: true, anyoneCanPay: false },
      transactionFormats: ["kaspa-safe-json/1"]
    }
  });
  await refusedWith(SignerErrorCodesV2.CAPABILITY_MISMATCH, () => executeSigningV2(adapter, txRequest()), "sighash over-declaration");
});

test("H12c a descriptor claiming PSKT support the provider does not have is refused", async () => {
  const adapter = createMockSignerAdapterV2({
    pskt: { supported: true, roles: ["signer", "combiner"] },
    probe: {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: true,
      methods: ["signMessage", "signTransaction", "on"],
      pskt: { supported: false, roles: [] }
    }
  });
  await refusedWith(SignerErrorCodesV2.CAPABILITY_MISMATCH, () => executeSigningV2(adapter, txRequest()), "pskt over-declaration");
});

test("H12d a descriptor claiming a PSKT ROLE the provider does not offer is refused", async () => {
  const adapter = createMockSignerAdapterV2({
    pskt: { supported: true, roles: ["signer", "finalizer"] },
    probe: {
      interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
      probed: true,
      methods: ["signMessage", "signTransaction", "on"],
      pskt: { supported: true, roles: ["signer"] }
    }
  });
  await refusedWith(SignerErrorCodesV2.CAPABILITY_MISMATCH, () => executeSigningV2(adapter, txRequest()), "pskt role over-declaration");
});

test("H12e an UNPROBEABLE signer is refused when the consumer requires probed capabilities (and allowed when it does not)", async () => {
  const adapter = createMockSignerAdapterV2({ probe: null });
  await refusedWith(
    SignerErrorCodesV2.CAPABILITY_MISMATCH,
    () => executeSigningV2(adapter, txRequest(), { requireProbedCapabilities: true, deriveTransactionId }),
    "unprobeable signer under a probe requirement"
  );
  const permissive = await executeSigningV2(adapter, txRequest(), { deriveTransactionId });
  assert.equal(permissive.status, "approved");
  assert.equal(permissive.capabilitiesProbed, false, "the outcome must record that nothing was probed");
});

test("H12f a probe report claiming an unknown value is a contract breach, not a capability", async () => {
  const adapter = createMockSignerAdapterV2({
    probe: { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: true, transactionFormats: ["bitcoin-psbt/0"] }
  });
  await refusedWith(SignerErrorCodesV2.PROTOCOL_VIOLATION, () => executeSigningV2(adapter, txRequest()), "unknown probe value");
});

test("H12g a probe report of the WRONG interface version fails closed", async () => {
  const adapter = createMockSignerAdapterV2({ probe: { interfaceVersion: "policyvault-signer/1", probed: true } });
  await refusedWith(SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED, () => executeSigningV2(adapter, txRequest()), "wrong-version probe");
});

test("H12h an unprobed report with no reason is refused — silence is not an answer", async () => {
  const adapter = createMockSignerAdapterV2({ probe: { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: false } });
  await refusedWith(SignerErrorCodesV2.PROTOCOL_VIOLATION, () => executeSigningV2(adapter, txRequest()), "reasonless unprobed report");
});

/* ==================================================================== */
/* structural non-custody: there is nowhere to put a secret              */
/* ==================================================================== */

test("H13 no vocabulary position accepts key material — a custody capability cannot even be declared", () => {
  const adapter = createMockSignerAdapterV2();
  const base = adapter.describe();
  const withCustody = { ...adapter, describe: () => ({ ...base, features: { ...base.features, keyExport: true } }) };
  assert.throws(() => validateAdapterV2(withCustody), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);

  const withTopLevel = { ...adapter, describe: () => ({ ...base, privateKeyHex: "00".repeat(32) }) };
  assert.throws(() => validateAdapterV2(withTopLevel), (e) => e.signerCode === SignerErrorCodesV2.PROTOCOL_VIOLATION);
});
