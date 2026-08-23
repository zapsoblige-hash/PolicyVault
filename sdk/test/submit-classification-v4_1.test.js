"use strict";

/* SDK — H2 §24 submission-outcome classification (v0.4/v0.4.1 submit path).
 * DEFINITIVE = the node evaluated + rejected the tx; every such rejection
 * carries rusty-kaspa's "Rejected transaction {id}: {reason}" marker
 * (rpc/core/src/error.rs). The classifier must recognize that marker whether it
 * arrives bare, SDK-prefixed, or WRAPPED by the wRPC transport, while transport
 * failures stay AMBIGUOUS (false ambiguous is acceptable; false definitive is
 * not — and even a definitive hint is re-verified by chain proof before any
 * claim release). */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { isDefinitiveSubmitRejection } = require("../src/wallet-submit-v4");

const ID = "600a5ea0b8f3c1d2e4a6b8c0d2e4f60718293a4b5c6d7e8f9012345678b87b43";

test("§24 DEFINITIVE: bare, prefixed, wrapped, and JS-form rejections", () => {
  const definitive = [
    // bare rpc/core Display (observed live in Checkpoint H)
    `Rejected transaction ${ID}: transaction ${ID} is not standard: too many sig ops`,
    // SDK-prefixed
    `wallet-submit-v4: submit failed: Rejected transaction ${ID}: insufficient fee`,
    // wRPC transport wrapper (rpc/core/src/error.rs:117)
    `RPC Server (remote error) -> Rejected transaction ${ID}: transaction already spends the same UTXO`,
    // JS/WASM wRPC client form with backtick-quoted inner message
    "RPC Server (remote error) -> ServerError { code: -32000, message: `Rejected transaction " + ID + ": non-standard` }",
    // a policy-invalid consensus rejection (§23 adversarial)
    `Rejected transaction ${ID}: script ran, but verification failed`
  ];
  for (const m of definitive) {
    assert.equal(isDefinitiveSubmitRejection(m), true, `must be DEFINITIVE: ${m.slice(0, 60)}…`);
  }
});

test("§24 AMBIGUOUS: transport/connection failures keep claims", () => {
  const ambiguous = [
    "",
    null,
    undefined,
    "timeout",
    "request timed out after 30000ms",
    "WebSocket is not connected",
    "RPC Server (remote error) -> not connected",
    "connection reset by peer",
    "ECONNREFUSED 127.0.0.1:18210",
    "socket hang up",
    "node is not synced",
    // a message that merely mentions the word transaction but is NOT a rejection
    "failed to serialize transaction for submission"
  ];
  for (const m of ambiguous) {
    assert.equal(isDefinitiveSubmitRejection(m), false, `must be AMBIGUOUS: ${String(m).slice(0, 60)}`);
  }
});

test("§24 the exact Checkpoint-H non-standard rejection is DEFINITIVE", () => {
  // The real message that blocked v0.4 in Checkpoint H (docs/v04-h-standardness-finding.md).
  const h = `Rejected transaction ${ID}: transaction ${ID} is not standard: transaction input #0 has 18 signature operations which is more than the allowed max of 15`;
  assert.equal(isDefinitiveSubmitRejection(h), true);
});
