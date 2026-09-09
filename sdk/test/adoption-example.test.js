"use strict";

/*
 * ADOPTION EXAMPLE TEST (Track J, flagship wave 2). Drives the offline
 * adoption example (sdk/examples/adoption-authority-boundary.js) through
 * node:test, so the example's three claims are mechanically re-verified,
 * not just narrated in docs:
 *
 *   (a) a permitted delegated spend (within cap, within budget, to an
 *       allowlisted recipient) builds and finalizes to real production
 *       bytes with only the agent's signature;
 *   (b) an over-authority spend (a policy-valid amount redirected to a
 *       non-allowlisted recipient) is REFUSED deterministically, before
 *       any signature is requested, with the closed error code
 *       RECIPIENT_PROOF_INVALID — never built, never signed;
 *   (c) an owner intervention (ownerPause), a different authority than
 *       the agent's, builds and finalizes independently.
 *
 * Same production-byte path as sdk/test/vault-builders-v4_1.test.js (real
 * silverc compiles + the real pv_call_encoder), entirely offline — no
 * Kaspa node, no network call, no broadcast.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  CONTRACT_VERSION,
  makeConfig,
  buildFixture,
  runPermittedSpend,
  runRefusedSpend,
  runOwnerIntervention
} = require("../examples/adoption-authority-boundary");

const config = makeConfig();
const fx = buildFixture(config);

test("adoption example: contractVersion is the v0.4.1 KAS profile", () => {
  assert.equal(CONTRACT_VERSION, "policyvault-0.4.1");
});

test("adoption example (a): a permitted delegated spend builds and finalizes", () => {
  const { build, finalized } = runPermittedSpend(config, fx);
  assert.equal(build.contractVersion, CONTRACT_VERSION);
  assert.equal(build.encoderFunction, "agentSpend");
  assert.equal(typeof finalized.txId, "string");
  assert.equal(finalized.txId.length, 64, "txId must be a 32-byte hex transaction id");
  assert.equal(finalized.covenantCallHex.length, build.plannedCallHexLength, "final call length must equal the planned length");
});

test("adoption example (b): an over-authority spend (non-allowlisted recipient) is refused BEFORE any signature, with the closed code", () => {
  const refusal = runRefusedSpend(config, fx);
  assert.ok(refusal instanceof Error, "the over-authority spend must throw, not build");
  assert.equal(refusal.code, "RECIPIENT_PROOF_INVALID");
  assert.match(refusal.message, /recipient proof does not verify/);
});

test("adoption example (b): the refused amount was itself policy-valid (only the recipient was unauthorized)", () => {
  // Re-run the SAME amount to the ALLOWLISTED recipient to prove the
  // refusal in (b) was about recipient authorization, not the amount.
  const { finalized } = runPermittedSpend(config, fx);
  assert.equal(typeof finalized.txId, "string");
});

test("adoption example (c): an owner intervention (pause) builds and finalizes independently of the agent policy", () => {
  const { build, finalized } = runOwnerIntervention(config, fx);
  assert.equal(build.contractVersion, CONTRACT_VERSION);
  assert.equal(build.encoderFunction, "ownerControl");
  assert.equal(typeof finalized.txId, "string");
  assert.equal(finalized.txId.length, 64);
});
