"use strict";

/*
 * UNIT — manifest schema validation + build (core/intent/manifest.js).
 *
 * Valid manifests for every supported action validate; every invalid
 * field class refuses with its specific code; unknown versions/actions
 * are never routed to a default.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  MANIFEST_VERSION_1,
  validateManifest,
  validateRequestedIntent,
  buildIntentManifest,
  diffStates
} = require("../manifest");
const {
  agentSpendFixture,
  ownerTopUpFixture,
  ownerPauseFixture,
  ownerSetApproversFixture,
  ownerSetAgentRootFixture,
  ownerRecoverFixture,
  createVaultFixture,
  clone,
  rehash,
  OWNER,
  ATTACKER,
  K1,
  AGENT_ROOT_1,
  AGENT_ROOT_2,
  STATE_BEFORE
} = require("../testutil/fixtures");

const FIXTURES = {
  agentSpend: agentSpendFixture,
  ownerTopUp: ownerTopUpFixture,
  ownerPause: ownerPauseFixture,
  ownerSetApprovers: ownerSetApproversFixture,
  ownerSetAgentRoot: ownerSetAgentRootFixture,
  ownerRecover: ownerRecoverFixture,
  createVault: createVaultFixture
};

function refuses(manifest, code, label) {
  assert.throws(() => validateManifest(manifest), (e) => e.code === code, `${label} must refuse with ${code}`);
}

/* Tamper + rehash (attacker-controlled hash), then expect a schema code. */
function tamper(fixtureFn, mutate) {
  const m = clone(fixtureFn().manifest);
  mutate(m);
  return rehash(m);
}

test("schema: every supported action's golden manifest validates", () => {
  for (const [name, fn] of Object.entries(FIXTURES)) {
    const { manifest } = fn();
    const ctx = validateManifest(manifest);
    assert.equal(ctx.sdkAction, name, `${name}: fixture action`);
    assert.equal(manifest.manifestVersion, MANIFEST_VERSION_1, name);
  }
});

test("schema: high-level lifecycle actions map onto ownerSetAgentRoot", () => {
  for (const highLevel of ["addAgent", "removeAgent", "rotateAgent", "rePolicyAgent"]) {
    const { manifest } = ownerSetAgentRootFixture(highLevel);
    assert.equal(manifest.action.sdkAction, "ownerSetAgentRoot");
    assert.equal(manifest.action.highLevelAction, highLevel);
    assert.ok(validateManifest(manifest));
  }
});

test("fail closed: unknown manifest version", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.manifestVersion = "policyvault-intent-manifest/2"; }), "UNKNOWN_MANIFEST_VERSION", "future version");
  refuses(tamper(agentSpendFixture, (m) => { m.manifestVersion = "totally-unknown"; }), "UNKNOWN_MANIFEST_VERSION", "garbage version");
  refuses({ manifestVersion: undefined }, "UNKNOWN_MANIFEST_VERSION", "missing version");
});

test("fail closed: unknown / unsupported covenant version (v0.3 is not covered by manifest v1)", () => {
  refuses(
    tamper(agentSpendFixture, (m) => { m.vault.covenantVersion = "policyvault-0.3"; m.requested.covenantVersion = "policyvault-0.3"; }),
    "UNSUPPORTED_COVENANT_VERSION",
    "v0.3"
  );
  refuses(
    tamper(agentSpendFixture, (m) => { m.vault.covenantVersion = "policyvault-9.9"; m.requested.covenantVersion = "policyvault-9.9"; }),
    "UNSUPPORTED_COVENANT_VERSION",
    "unknown future covenant"
  );
});

test("fail closed: unknown action", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.action.sdkAction = "ownerDrainVault"; }), "UNKNOWN_ACTION", "unknown sdkAction");
  assert.throws(
    () => validateRequestedIntent({ ...agentSpendFixture().requestedIntent, action: "teleportFunds" }),
    (e) => e.code === "UNKNOWN_ACTION"
  );
});

test("fail closed: unknown requested-intent version", () => {
  refuses(
    tamper(agentSpendFixture, (m) => { m.requested.intentVersion = "policyvault-requested-intent/2"; }),
    "UNKNOWN_INTENT_VERSION",
    "future intent version"
  );
});

test("fail closed: closed schemas refuse unknown and missing keys", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.surprise = true; }), "SCHEMA_INVALID", "extra top-level key");
  {
    // undefined is not canonically serializable, so it cannot even be
    // rehashed — validate refuses the shape before reaching the hash.
    const m = clone(agentSpendFixture().manifest);
    m.accounting = undefined;
    refuses(m, "SCHEMA_INVALID", "undefined accounting");
  }
  const missingTop = clone(agentSpendFixture().manifest);
  delete missingTop.effects;
  refuses(rehash(missingTop), "SCHEMA_INVALID", "missing top-level key");
  refuses(tamper(agentSpendFixture, (m) => { m.accounting.bonus = "1"; }), "SCHEMA_INVALID", "extra accounting key");
  const missingAcc = clone(agentSpendFixture().manifest);
  delete missingAcc.accounting.fee;
  refuses(rehash(missingAcc), "SCHEMA_INVALID", "missing accounting field");
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.inputs[0].utxo.extra = 1; }), "SCHEMA_INVALID", "extra utxo key");
  refuses(tamper(agentSpendFixture, (m) => { m.requested.params.bonusField = "1"; }), "SCHEMA_INVALID", "extra intent param");
});

test("fail closed: actor identity rules", () => {
  refuses(tamper(ownerTopUpFixture, (m) => { m.actor.signerXOnly = ATTACKER; }), "SCHEMA_INVALID", "owner op signed by non-owner");
  refuses(tamper(agentSpendFixture, (m) => { m.actor.agentPk = ATTACKER; }), "SCHEMA_INVALID", "agentPk != signer");
  refuses(tamper(ownerTopUpFixture, (m) => { m.actor.agentPk = ATTACKER; }), "SCHEMA_INVALID", "agentPk non-null on owner op");
  refuses(tamper(agentSpendFixture, (m) => { m.actor.role = "owner"; }), "SCHEMA_INVALID", "role contradicts the action table");
});

test("fail closed: action flag and section null-ness matrix", () => {
  refuses(tamper(ownerTopUpFixture, (m) => { m.action.aboveThreshold = true; }), "SCHEMA_INVALID", "aboveThreshold outside agentSpend");
  refuses(tamper(ownerTopUpFixture, (m) => { m.action.terminal = true; }), "SCHEMA_INVALID", "terminal flag contradicts table");
  refuses(tamper(ownerTopUpFixture, (m) => { m.payment = clone(agentSpendFixture().manifest.payment); }), "SCHEMA_INVALID", "payment on owner op");
  refuses(tamper(agentSpendFixture, (m) => { m.payment = null; }), "SCHEMA_INVALID", "agentSpend without payment");
  refuses(tamper(agentSpendFixture, (m) => { m.limits = null; }), "SCHEMA_INVALID", "agentSpend without limits");
  refuses(tamper(ownerTopUpFixture, (m) => { m.stateBefore = null; }), "SCHEMA_INVALID", "null stateBefore outside genesis");
  refuses(
    tamper(ownerRecoverFixture, (m) => { m.stateAfter = clone(ownerTopUpFixture().manifest.stateAfter); }),
    "SCHEMA_INVALID",
    "stateAfter on the terminal action"
  );
  refuses(tamper(createVaultFixture, (m) => { m.stateBefore = clone(ownerTopUpFixture().manifest.stateBefore); }), "SCHEMA_INVALID", "stateBefore at genesis");
});

test("fail closed: approver-set structural rules", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.stateBefore.state.approverSlots = m.stateBefore.state.approverSlots.slice(0, 9); }), "SCHEMA_INVALID", "9 slots");
  refuses(
    tamper(agentSpendFixture, (m) => { m.stateBefore.state.approverSlots[1] = K1; m.stateAfter.state.approverSlots[1] = K1; }),
    "SCHEMA_INVALID",
    "duplicate active approver"
  );
  refuses(
    tamper(agentSpendFixture, (m) => { m.stateBefore.state.approvalM = "0"; m.stateAfter.state.approvalM = "0"; }),
    "SCHEMA_INVALID",
    "approvalM 0 with active approvers"
  );
});

test("fail closed: transaction envelope rules (frozen-form discipline)", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.version = 2; }), "SCHEMA_INVALID", "tx version 2");
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.gas = "1"; }), "SCHEMA_INVALID", "nonzero gas");
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.payload = "aa"; }), "SCHEMA_INVALID", "nonempty payload");
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.subnetworkId = "01" + "00".repeat(19); }), "SCHEMA_INVALID", "non-native subnetwork");
  refuses(tamper(agentSpendFixture, (m) => { m.transaction.outputs = []; }), "SCHEMA_INVALID", "no outputs");
});

test("fail closed: effects must classify everything, consistently with covenant bindings", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.effects.outputs.pop(); }), "SCHEMA_INVALID", "unclassified output");
  refuses(tamper(agentSpendFixture, (m) => { m.effects.outputs[1].kind = "payment"; }), "SCHEMA_INVALID", "payment kind on a covenant-bound output"); // successor is output 1
  refuses(tamper(agentSpendFixture, (m) => { m.effects.inputs[0].kind = "external"; }), "SCHEMA_INVALID", "external kind on the covenant input");
  refuses(tamper(agentSpendFixture, (m) => { m.effects.outputs[1].kind = "teleport"; }), "SCHEMA_INVALID", "unknown output kind");
});

test("fail closed: requested-intent identity must match the manifest identity", () => {
  refuses(tamper(agentSpendFixture, (m) => { m.requested.networkId = "mainnet"; }), "SCHEMA_INVALID", "network mismatch");
  refuses(tamper(agentSpendFixture, (m) => { m.requested.vaultId = ATTACKER; }), "SCHEMA_INVALID", "vault mismatch");
  refuses(tamper(ownerPauseFixture, (m) => { m.requested.action = "ownerUnpause"; }), "SCHEMA_INVALID", "action mismatch");
});

test("fail closed: any post-build mutation without a canonical rehash is MANIFEST_HASH_MISMATCH", () => {
  const m = clone(agentSpendFixture().manifest);
  m.accounting.fee = "4999";
  refuses(m, "MANIFEST_HASH_MISMATCH", "tampered fee, stale hash");
  const m2 = clone(agentSpendFixture().manifest);
  m2.manifestHash = "00".repeat(32);
  refuses(m2, "MANIFEST_HASH_MISMATCH", "bogus hash");
});

test("build: deterministic and self-validating; derived sections are correct", () => {
  const a = agentSpendFixture();
  const b = agentSpendFixture();
  assert.equal(a.manifest.manifestHash, b.manifest.manifestHash);
  assert.deepEqual(a.manifest.policyMutations.map((x) => x.field), ["protectedValue", "feeReserve", "agentRoot"]);
  assert.deepEqual(
    ownerSetApproversFixture().manifest.policyMutations.map((x) => x.field),
    ["approverSlots", "approvalM", "policyNonce"]
  );
  assert.deepEqual(ownerRecoverFixture().manifest.policyMutations, []);
  assert.deepEqual(createVaultFixture().manifest.policyMutations, []);
  const spend = a.manifest;
  assert.equal(spend.stateAfter.expectedOutpoint.transactionId, spend.transaction.txId);
  assert.equal(spend.stateAfter.expectedOutpoint.index, 1); // successor is output 1 (payment is output 0)
  assert.equal(spend.action.role, "agent");
  assert.equal(spend.actor.agentPk, spend.actor.signerXOnly);
});

test("build: refuses inconsistent structured inputs instead of guessing", () => {
  const { buildInputs } = agentSpendFixture();
  const noSuccessor = clone(buildInputs);
  noSuccessor.effects.outputs = ["payment", "payment"];
  assert.throws(() => buildIntentManifest(noSuccessor), (e) => e.code === "SCHEMA_INVALID", "non-terminal build without a successor classification");
  const extraKey = clone(buildInputs);
  extraKey.verdict = "VERIFIED_EXACT";
  assert.throws(() => buildIntentManifest(extraKey), (e) => e.code === "SCHEMA_INVALID", "caller-supplied verdict is refused");
});

test("diffStates: deterministic, ordered, exact", () => {
  const after = { ...clone(STATE_BEFORE), agentRoot: AGENT_ROOT_2, policyNonce: "8" };
  const diff = diffStates(clone(STATE_BEFORE), after);
  assert.deepEqual(diff.map((d) => d.field), ["agentRoot", "policyNonce"]);
  assert.equal(diff[0].before, AGENT_ROOT_1);
  assert.equal(diff[0].after, AGENT_ROOT_2);
  assert.deepEqual(diffStates(clone(STATE_BEFORE), clone(STATE_BEFORE)), []);
});

test("schema: owner change is structurally impossible to hide (single owner field, hash-bound)", () => {
  // The vault owner is template-immutable; the manifest carries exactly one
  // owner field and the hash binds it. A swapped owner invalidates the
  // owner-op actor rule (signer != owner) — refused at validation.
  refuses(tamper(ownerTopUpFixture, (m) => { m.vault.owner = ATTACKER; }), "SCHEMA_INVALID", "owner swap breaks the actor rule");
});
