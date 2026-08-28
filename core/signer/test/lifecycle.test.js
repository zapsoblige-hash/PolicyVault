"use strict";

/*
 * UNIT — Universal Signer Interface v1: executeSigning lifecycle.
 * Sync + asynchronous approval (approve / reject / timeout), fail-closed
 * gates (capability, scheme, network, identity), error normalization,
 * and single-terminal-transition discipline (late settlements discarded).
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SignerErrorCodes,
  createMessageSigningRequest,
  createTransactionSigningRequest,
  executeSigning,
  validateAdapter,
  createMockSignerAdapter
} = require("../index");

const ADDR0 = "kaspatest:mocksigneraccount0";
const ADDR1 = "kaspatest:mocksigneraccount1";

function messageRequest(overrides = {}) {
  return createMessageSigningRequest({
    message: "PolicyVault authentication\nnonce: 00ff",
    scheme: "schnorr",
    network: "testnet-10",
    expectedSignerAddress: ADDR0,
    ...overrides
  });
}

function transactionRequest(overrides = {}) {
  return createTransactionSigningRequest({
    unsignedSafeJson: JSON.stringify({ version: 1, inputs: [{}], outputs: [] }),
    signInputs: [{ index: 0, sighashType: 1 }],
    network: "testnet-10",
    expectedSignerAddress: ADDR0,
    ...overrides
  });
}

function recordTransitions() {
  const seen = [];
  return { seen, onTransition: (t) => seen.push(t) };
}

async function connected(options) {
  const adapter = createMockSignerAdapter(options);
  await adapter.connect();
  return adapter;
}

test("sync approval: message signing returns a validated schnorr signature with SUBMITTED->APPROVED", async () => {
  const adapter = await connected();
  const { seen, onTransition } = recordTransitions();
  const request = messageRequest();
  const settlement = await executeSigning(adapter, request, { onTransition });
  assert.equal(settlement.status, "approved");
  assert.equal(settlement.requestId, request.requestId);
  assert.match(settlement.result.signature, /^[0-9a-f]{128}$/);
  assert.ok(Object.isFrozen(settlement));
  assert.ok(Object.isFrozen(settlement.result));
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "APPROVED"]);
  assert.ok(seen.every((t) => t.requestId === request.requestId && Object.isFrozen(t)));
});

test("sync approval: transaction signing returns the signed serialization verbatim", async () => {
  const adapter = await connected();
  const request = transactionRequest();
  const settlement = await executeSigning(adapter, request, {});
  const parsed = JSON.parse(settlement.result.signedSafeJson);
  assert.equal(parsed.mockSigned, true);
  assert.equal(parsed.base, request.unsignedSafeJson); // frozen bytes echoed, never rewritten
  assert.equal(parsed.signedBy, ADDR0);
});

test("a pre-validated registration record is accepted in place of the bare adapter", async () => {
  const adapter = await connected();
  const registration = validateAdapter(adapter);
  const settlement = await executeSigning(registration, messageRequest());
  assert.equal(settlement.status, "approved");
});

test("sync rejection: adapter-classified USER_REJECTED surfaces with terminal REJECTED", async () => {
  const adapter = await connected();
  adapter.control.failNextSignWith({ signerCode: "USER_REJECTED", message: "You declined the signature" });
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.USER_REJECTED
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "REJECTED"]);
});

test("locked signer: adapter-classified SIGNER_LOCKED passes through classification", async () => {
  const adapter = await connected();
  adapter.control.lock();
  await assert.rejects(executeSigning(adapter, messageRequest()), (e) => e.signerCode === SignerErrorCodes.SIGNER_LOCKED);
});

test("unknown adapter error code maps to PROTOCOL_VIOLATION with terminal FAILED (fail closed)", async () => {
  const adapter = await connected();
  adapter.control.failNextSignWith({ signerCode: "KASWARE_SPECIFIC_CODE_7", message: "??" });
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.PROTOCOL_VIOLATION && e.details.claimedCode === "KASWARE_SPECIFIC_CODE_7"
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "FAILED"]);
  assert.equal(seen[1].code, SignerErrorCodes.PROTOCOL_VIOLATION);
});

test("raw provider exception maps to PROVIDER_ERROR with cause preserved", async () => {
  const adapter = await connected();
  const boom = new Error("wasm unreachable");
  adapter.control.failNextSignWith(boom);
  await assert.rejects(
    executeSigning(adapter, messageRequest()),
    (e) => e.signerCode === SignerErrorCodes.PROVIDER_ERROR && e.cause === boom
  );
});

test("malformed signature response fails closed with INVALID_SIGNATURE_RESPONSE", async () => {
  const adapter = await connected();
  const bad = { ...adapter, signMessage: async () => "not-a-signature" };
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(bad, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.INVALID_SIGNATURE_RESPONSE
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "FAILED"]);
});

/* ---- fail-closed gates (REFUSED before the signer is ever invoked) ---- */

test("scheme gate: consumer request for a scheme the adapter does not declare is refused pre-invocation", async () => {
  const adapter = await connected(); // declares schnorr only
  const forged = { ...messageRequest(), scheme: "ecdsa" }; // structurally valid, wrong scheme
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, forged, { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_SCHEME
  );
  assert.deepEqual(seen.map((t) => t.state), ["REFUSED"]);
  assert.equal(adapter.control.invocations, 0); // the provider was never contacted
});

test("ecdsa message signing is refused BEFORE invocation even when the adapter declares ecdsa (no v1 response contract)", async () => {
  const adapter = await connected({ provider: "tangem-like", schemes: ["ecdsa", "schnorr"] });
  const request = { ...messageRequest(), scheme: "ecdsa" };
  await assert.rejects(
    executeSigning(adapter, request),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_SCHEME && /before invoking/.test(e.message)
  );
  assert.equal(adapter.control.invocations, 0);
});

test("capability gate: transaction signing against a message-only adapter is refused", async () => {
  const adapter = await connected({ features: { transactionSigning: false, specificInputSigning: false } });
  await assert.rejects(
    executeSigning(adapter, transactionRequest()),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_CAPABILITY
  );
  assert.equal(adapter.control.invocations, 0);
});

test("capability gate: v1 transaction requests refuse adapters without specificInputSigning", async () => {
  const adapter = await connected({ features: { specificInputSigning: false } });
  await assert.rejects(
    executeSigning(adapter, transactionRequest()),
    (e) => e.signerCode === SignerErrorCodes.UNSUPPORTED_CAPABILITY && /named inputs/.test(e.message)
  );
});

test("network gate: request network outside the adapter's declared set is refused", async () => {
  const adapter = await connected({ networks: ["testnet-10"] });
  const request = messageRequest({ network: "mainnet" });
  await assert.rejects(executeSigning(adapter, request), (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK);
  assert.equal(adapter.control.invocations, 0);
});

test("network gate: LIVE network mismatch is refused fail-closed (declared networks are not trusted)", async () => {
  const adapter = await connected({ networks: ["mainnet", "testnet-10"] });
  adapter.control.setNetwork("mainnet"); // live network differs from the request
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK && /reports network "mainnet", required "testnet-10"/.test(e.message)
  );
  assert.deepEqual(seen.map((t) => t.state), ["REFUSED"]);
  assert.equal(adapter.control.invocations, 0);
});

test("network gate: an unknown/absent live network is refused (never assumed)", async () => {
  const adapter = await connected();
  adapter.control.setNetwork(undefined);
  await assert.rejects(executeSigning(adapter, messageRequest()), (e) => e.signerCode === SignerErrorCodes.WRONG_NETWORK);
});

test("identity gate: disconnected signer is refused when an expected signer is bound", async () => {
  const adapter = createMockSignerAdapter(); // never connected
  await assert.rejects(executeSigning(adapter, messageRequest()), (e) => e.signerCode === SignerErrorCodes.SIGNER_DISCONNECTED);
});

test("identity gate: active account != expected signer is refused pre-invocation", async () => {
  const adapter = await connected();
  adapter.control.setActiveAccount(ADDR1);
  await assert.rejects(executeSigning(adapter, messageRequest()), (e) => e.signerCode === SignerErrorCodes.ACCOUNT_CHANGED);
  assert.equal(adapter.control.invocations, 0);
});

test("identity gate: an account switch DURING signing is refused post-approval (signature discarded)", async () => {
  const adapter = await connected();
  adapter.control.duringSign = () => adapter.control.setActiveAccount(ADDR1); // mid-popup switch
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.ACCOUNT_CHANGED && /during signing/.test(e.message)
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "FAILED"]);
});

test("unknown executeSigning option is refused fail-closed", async () => {
  const adapter = await connected();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { retries: 3 }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /unknown executeSigning option/.test(e.message)
  );
});

/* ---- asynchronous approval lifecycle ---- */

test("async approval requires an explicit timeout (unbounded waits refused)", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, messageRequest(), { onTransition }),
    (e) => e.signerCode === SignerErrorCodes.REQUEST_INVALID && /timeoutMs is required/.test(e.message)
  );
  assert.deepEqual(seen.map((t) => t.state), ["REFUSED"]);
});

test("async approve: out-of-band approval settles the request with APPROVED", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  const request = messageRequest();
  const { seen, onTransition } = recordTransitions();
  const pending = executeSigning(adapter, request, { timeoutMs: 5000, onTransition });
  await new Promise((r) => setImmediate(r)); // let the request reach the signer
  assert.deepEqual(adapter.control.listPending(), [request.requestId]);
  adapter.control.approve(request.requestId);
  const settlement = await pending;
  assert.equal(settlement.status, "approved");
  assert.match(settlement.result.signature, /^[0-9a-f]{128}$/);
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "APPROVED"]);
});

test("async reject: out-of-band rejection surfaces USER_REJECTED with terminal REJECTED", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  const request = transactionRequest();
  const { seen, onTransition } = recordTransitions();
  const pending = executeSigning(adapter, request, { timeoutMs: 5000, onTransition });
  await new Promise((r) => setImmediate(r));
  adapter.control.reject(request.requestId);
  await assert.rejects(pending, (e) => e.signerCode === SignerErrorCodes.USER_REJECTED);
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "REJECTED"]);
});

test("async timeout: deadline elapses -> SIGNER_TIMEOUT, cancelSigning invoked, request no longer approvable", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  const request = messageRequest();
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(adapter, request, { timeoutMs: 25, onTransition }),
    (e) => e.signerCode === SignerErrorCodes.SIGNER_TIMEOUT && /cancelled fail-closed/.test(e.message)
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "TIMED_OUT"]);
  assert.deepEqual(adapter.control.cancelled, [request.requestId]); // best-effort cancel reached the signer
  assert.deepEqual(adapter.control.listPending(), []); // nothing left to approve
  assert.throws(() => adapter.control.approve(request.requestId), /no pending signing request/);
});

test("async timeout: a LATE approval after the deadline is DISCARDED (single terminal transition)", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  // Sabotage cancellation so the provider-side request survives the timeout.
  const uncancellable = { ...adapter, cancelSigning: async () => { throw new Error("device unreachable"); } };
  const request = messageRequest();
  const { seen, onTransition } = recordTransitions();
  await assert.rejects(
    executeSigning(uncancellable, request, { timeoutMs: 25, onTransition }),
    (e) => e.signerCode === SignerErrorCodes.SIGNER_TIMEOUT
  );
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "TIMED_OUT"]);
  // The signer approves AFTER the deadline: the settlement must go nowhere.
  adapter.control.approve(request.requestId);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(seen.map((t) => t.state), ["SUBMITTED", "TIMED_OUT"]); // no extra transition, no delivered result
});

test("async approval works with a registration record and a long timeout without holding the process (timer cleared)", async () => {
  const adapter = await connected({ provider: "mock-async", asyncApproval: true });
  const registration = validateAdapter(adapter);
  const request = transactionRequest();
  const pending = executeSigning(registration, request, { timeoutMs: 600000 });
  await new Promise((r) => setImmediate(r));
  adapter.control.approve(request.requestId);
  const settlement = await pending;
  assert.equal(settlement.status, "approved"); // node:test would hang/leak if the 10-minute timer survived
});

test("observer exceptions never alter signing outcomes", async () => {
  const adapter = await connected();
  const settlement = await executeSigning(adapter, messageRequest(), {
    onTransition: () => {
      throw new Error("observer bug");
    }
  });
  assert.equal(settlement.status, "approved");
});
