"use strict";

/*
 * UNIT — dashboard operational-status derivation (pure over durable
 * backend truth). Fail-closed mapping; no claim-override surface exists.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const statusModule = require("../src/operational-status");
const { OperationalStatus, deriveOperationalStatus } = statusModule;

const LIVE_STATE_ID = "11".repeat(32);
const CLAIM_TX = "22".repeat(32);
const OUTPOINT = { transactionId: "33".repeat(32), index: 1 };

function manifest(overrides = {}) {
  return {
    vaultId: "44".repeat(32),
    status: "ACTIVE",
    live: { stateId: LIVE_STATE_ID, outpoint: OUTPOINT },
    latestTransitionTxId: null,
    ...overrides
  };
}

const claim = (overrides = {}) => ({
  action: "ownerTopUp",
  txId: CLAIM_TX,
  outpoint: OUTPOINT,
  createdAt: "2026-08-16T09:27:55.218Z",
  expected: { kind: "successor", stateId: "55".repeat(32) },
  ...overrides
});

const request = (state, overrides = {}) => ({
  requestId: "req-1",
  action: "ownerTopUp",
  state,
  txId: CLAIM_TX,
  signerRole: "owner",
  predecessorStateId: LIVE_STATE_ID,
  predecessorOutpoint: OUTPOINT,
  createdAt: "2026-08-16T09:27:00Z",
  ...overrides
});

test("state 1: live vault, no claim, no requests -> ACTIVE", () => {
  assert.equal(deriveOperationalStatus({ manifest: manifest(), claim: null, requests: [] }).status, OperationalStatus.ACTIVE);
});

test("state 2: BUILT request bound to the current state -> WAITING_FOR_SIGNATURE", () => {
  const r = deriveOperationalStatus({ manifest: manifest(), claim: null, requests: [request("BUILT", { txId: null })] });
  assert.equal(r.status, OperationalStatus.WAITING_FOR_SIGNATURE);
  assert.equal(r.request.requestId, "req-1");
});

test("stale BUILT request (old state) does not block -> ACTIVE", () => {
  const stale = request("BUILT", { txId: null, predecessorStateId: "99".repeat(32) });
  assert.equal(deriveOperationalStatus({ manifest: manifest(), claim: null, requests: [stale] }).status, OperationalStatus.ACTIVE);
});

test("state 3: claim held by SUBMITTING/SUBMITTED request -> TRANSACTION_PENDING (never success)", () => {
  for (const st of ["SUBMITTING", "SUBMITTED"]) {
    const r = deriveOperationalStatus({ manifest: manifest(), claim: claim(), requests: [request(st)] });
    assert.equal(r.status, OperationalStatus.TRANSACTION_PENDING);
    assert.equal(r.claim.txId, CLAIM_TX);
  }
});

test("state 6/9: claim without a live submission -> ACTION_REQUIRED_VERIFY", () => {
  // RECONCILIATION_REQUIRED request
  assert.equal(
    deriveOperationalStatus({ manifest: manifest(), claim: claim(), requests: [request("RECONCILIATION_REQUIRED")] }).status,
    OperationalStatus.ACTION_REQUIRED_VERIFY
  );
  // crashed: claim exists, no request record at all
  assert.equal(
    deriveOperationalStatus({ manifest: manifest(), claim: claim(), requests: [] }).status,
    OperationalStatus.ACTION_REQUIRED_VERIFY
  );
  // request in an unexpected state: fail toward verification, not success
  assert.equal(
    deriveOperationalStatus({ manifest: manifest(), claim: claim(), requests: [request("FINALIZED")] }).status,
    OperationalStatus.ACTION_REQUIRED_VERIFY
  );
});

test("state 7: terminal recovery -> CLOSED", () => {
  assert.equal(deriveOperationalStatus({ manifest: manifest({ status: "RECOVERED", live: null }) }).status, OperationalStatus.CLOSED);
});

test("state 8: TERMINATED_UNKNOWN / liveless / missing manifest -> UNKNOWN fail closed", () => {
  assert.equal(deriveOperationalStatus({ manifest: manifest({ status: "TERMINATED_UNKNOWN", live: null }) }).status, OperationalStatus.UNKNOWN);
  assert.equal(deriveOperationalStatus({ manifest: manifest({ status: "ACTIVE", live: null }) }).status, OperationalStatus.UNKNOWN);
  assert.equal(deriveOperationalStatus({ manifest: null }).status, OperationalStatus.UNKNOWN);
});

test("summaries expose public identifiers only (no key material fields)", () => {
  const r = deriveOperationalStatus({ manifest: manifest(), claim: claim(), requests: [request("RECONCILIATION_REQUIRED", { error: "submit failed: x" })] });
  const flat = JSON.stringify(r).toLowerCase();
  for (const banned of ["secret", "private", "seed", "mnemonic"]) {
    assert.ok(!flat.includes(banned), `summary must not carry ${banned}`);
  }
  assert.equal(r.request.error, "submit failed: x");
});

test("test 10: the status module offers NO deletion/override/unlock surface", () => {
  assert.deepEqual(Object.keys(statusModule).sort(), ["OperationalStatus", "deriveOperationalStatus", "requestSummary"]);
});
