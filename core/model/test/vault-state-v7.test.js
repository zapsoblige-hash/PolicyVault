"use strict";

/*
 * UNIT — v0.7 ROOTED PAYMENT VAULT state: the template pins (token pins from
 * the frozen v0.5 plus the organizational-root pins and the cold recovery
 * destination), the v0.5-identical mutable state, the owner-op → root-authority
 * table, and the state ID.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  CONTRACT_VERSION_V7,
  OWNER_OP_SELECTOR_V7,
  OWNER_OP_ROOT_AUTHORITY_V7,
  ROOT_STATE_LEN_V7,
  resolveV7Abi,
  resolveOwnerOpAuthorityV7,
  normalizeTemplateV7,
  normalizeStateV7,
  normalizeStateV7ForRecovery,
  computeStateIdV7,
  stateToJsonV7,
  templateToJsonV7
} = require("../vault-state-v7");
const { KCC20_STATE_LEN } = require("../token-amounts");
const { normalizeStateV5 } = require("../vault-state-v5");

const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const TEMPLATE = {
  vaultId: H(0x44),
  descriptorHash: H(0x11),
  tokenCovenantId: H(0x54),
  templateVmHash: H(0x22),
  templatePrefixLen: 1,
  templateStateLen: KCC20_STATE_LEN,
  templateSuffixLen: 1521,
  orgRootCovenantId: H(0x52),
  rootTemplateVmHash: H(0x33),
  rootPrefixLen: 1,
  rootStateLen: ROOT_STATE_LEN_V7,
  rootSuffixLen: 11077,
  recoveryPk: H(0x51)
};
const STATE = { feeReserve: "500000000", paused: "0", agentRoot: H(0x99), policyNonce: "0" };

function refuses(fn, code) {
  assert.throws(fn, (e) => {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return true;
  });
}

test("the ABI is v0.7-payment and unknown versions fail closed", () => {
  assert.equal(CONTRACT_VERSION_V7, "policyvault-0.7-payment");
  assert.equal(resolveV7Abi(CONTRACT_VERSION_V7).contractName, "PolicyVaultRootedToken");
  assert.equal(resolveV7Abi(CONTRACT_VERSION_V7).rootAuthorized, true);
  refuses(() => resolveV7Abi("policyvault-0.5"), "UNKNOWN_VERSION");
  refuses(() => resolveV7Abi("policyvault-0.7-root"), "UNKNOWN_VERSION");
});

test("the template carries the root pins and refuses a geometry that would self-lock", () => {
  const t = normalizeTemplateV7(TEMPLATE);
  assert.equal(t.orgRootCovenantId, H(0x52));
  assert.equal(t.rootStateLen, ROOT_STATE_LEN_V7);
  assert.equal(t.recoveryPk, H(0x51));
  assert.equal(templateToJsonV7(TEMPLATE).rootSuffixLen, 11077);
  assert.ok(!("owner" in t), "a rooted vault has NO owner key at all");

  refuses(() => normalizeTemplateV7({ ...TEMPLATE, rootStateLen: 466 }), "ROOT_GEOMETRY_MISMATCH");
  refuses(() => normalizeTemplateV7({ ...TEMPLATE, rootPrefixLen: 0 }), "ROOT_GEOMETRY_MISMATCH");
  refuses(() => normalizeTemplateV7({ ...TEMPLATE, rootSuffixLen: 0 }), "ROOT_GEOMETRY_MISMATCH");
  refuses(() => normalizeTemplateV7({ ...TEMPLATE, orgRootCovenantId: "00".repeat(32) }), "ROOT_PIN_MISSING");
  assert.throws(() => normalizeTemplateV7({ ...TEMPLATE, templateStateLen: KCC20_STATE_LEN + 1 }), /kcc20-state\/1/);
  assert.throws(() => normalizeTemplateV7({ ...TEMPLATE, recoveryPk: "zz".repeat(32) }), /recoveryPk/);
});

test("the mutable state is the frozen v0.5 state, verbatim", () => {
  const a = normalizeStateV7(STATE);
  const b = normalizeStateV5(STATE);
  assert.deepEqual(stateToJsonV7(a), { feeReserve: "500000000", paused: "0", agentRoot: H(0x99), policyNonce: "0" });
  assert.deepEqual(a, b, "v0.7 must not fork the v0.5 state normalizer");
  assert.equal(normalizeStateV7ForRecovery({ ...STATE, paused: "7" }).recoveryParse, true, "break-glass shape-only parse survives a malformed field");
  assert.throws(() => normalizeStateV7({ ...STATE, paused: "2" }), /paused out of range/);
});

test("every owner op names the exact root path and frozen byte it requires", () => {
  assert.deepEqual(OWNER_OP_SELECTOR_V7, { ownerSetAgentRoot: 0, ownerTopUpReserve: 1, ownerPause: 2, ownerUnpause: 3, ownerEmergencyPause: 4 });
  for (const action of ["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause"]) {
    const a = resolveOwnerOpAuthorityV7(action);
    assert.equal(a.rootActionName, "authorize", `${action} rides a FULL-quorum AUTHORIZE`);
    assert.equal(a.expectFrozenAfter, 0n);
  }
  const emergency = resolveOwnerOpAuthorityV7("ownerEmergencyPause");
  assert.equal(emergency.rootActionName, "freeze", "selector 4 is the ONLY effect the lighter emergency quorum can reach");
  assert.equal(emergency.expectFrozenAfter, 1n);
  assert.equal(emergency.opSelector, 4);
  const recover = resolveOwnerOpAuthorityV7("ownerRecover");
  assert.equal(recover.rootActionName, "authorize", "terminating a vault needs the FULL quorum");
  assert.equal(recover.opSelector, null);
  refuses(() => resolveOwnerOpAuthorityV7("ownerRotateDelegate"), "UNKNOWN_ACTION");
  assert.equal(OWNER_OP_ROOT_AUTHORITY_V7.ownerPause.opSelector, 2);
});

test("the state ID binds every template pin, including the root pins", () => {
  const id = computeStateIdV7({ networkId: "testnet-10", template: TEMPLATE, state: normalizeStateV7(STATE) });
  assert.match(id, /^[0-9a-f]{64}$/);
  const vary = (over) => computeStateIdV7({ networkId: "testnet-10", template: { ...TEMPLATE, ...over }, state: normalizeStateV7(STATE) });
  for (const over of [{ orgRootCovenantId: H(0x53) }, { rootTemplateVmHash: H(0x34) }, { rootPrefixLen: 2 }, { rootSuffixLen: 11078 }, { recoveryPk: H(0x50) }, { vaultId: H(0x45) }]) {
    assert.notEqual(vary(over), id, `changing ${Object.keys(over)[0]} must change the state ID`);
  }
  assert.notEqual(computeStateIdV7({ networkId: "mainnet", template: TEMPLATE, state: normalizeStateV7(STATE) }), id);
  assert.throws(() => computeStateIdV7({ networkId: "", template: TEMPLATE, state: normalizeStateV7(STATE) }), /networkId is required/);
});
