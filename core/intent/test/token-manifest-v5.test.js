"use strict";

/* UNIT: closed-schema / fail-closed behaviour of the v0.5 token intent
 * manifest that needs no builder (the builder-driven VERIFIED/REFUSED
 * matrix lives in sdk/test/token-manifest-v5.test.js). */

const test = require("node:test");
const assert = require("node:assert/strict");
const tm = require("../token-manifest-v5");

test("unknown manifest version / action / non-v5 build fail closed", () => {
  const r = tm.verifyTokenIntentManifest({ manifest: { manifestVersion: "policyvault-token-intent-manifest/2" }, descriptor: {} });
  assert.equal(r.verdict, "REFUSED");
  assert.match(r.failures[0].detail, /UNKNOWN_MANIFEST_VERSION/);
  assert.throws(() => tm.buildTokenIntentManifest({ build: { kind: "transition", contractVersion: "policyvault-0.4.1" }, descriptor: {} }), /v0.5 transition/);
  assert.throws(() => tm.buildTokenIntentManifest({ build: { kind: "transition", contractVersion: "policyvault-0.5", action: "agentSpend" }, descriptor: {} }), /unknown v0.5 action/);
  assert.deepEqual(Object.keys(tm.ACTIONS), ["tokenAgentSpend", "ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerRecover", "tokenDeposit"]);
  assert.equal(tm.VERIFIED_STATEMENT, "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE COVENANT ENFORCES. SIGNERS RETAIN CUSTODY.");
});
