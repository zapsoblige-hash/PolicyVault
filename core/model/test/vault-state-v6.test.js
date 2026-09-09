"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vs = require("../vault-state-v6");

const template = {
  owner: "aa".repeat(32),
  vaultId: "11".repeat(32),
  descriptorHash: "d5".repeat(32),
  tokenCovenantId: "54".repeat(32),
  templateVmHash: "77".repeat(32),
  templatePrefixLen: 1,
  templateStateLen: 46,
  templateSuffixLen: 2686
};
const state = { feeReserve: "500000000", swapPrincipal: "300000000", paused: "0", agentRoot: "00".repeat(32), swapRoot: "00".repeat(32), policyNonce: "0" };

test("v0.6 ABI resolves only its own version and is never byte-frozen by inference", () => {
  const abi = vs.resolveV6Abi("policyvault-0.6");
  assert.equal(abi.contractName, "PolicyVaultV6");
  assert.equal(abi.contractRelPath, "contracts/PolicyVault.v0.6.sil");
  assert.equal(abi.byteFrozen, false);
  assert.throws(() => vs.resolveV6Abi("policyvault-0.5"), /failing closed/);
  assert.throws(() => vs.resolveV6Abi("policyvault-1.6.0"), /failing closed/);
});

test("state normalization: closed layout, two KAS domains, controller value = feeReserve + swapPrincipal", () => {
  const s = vs.normalizeStateV6(state);
  assert.equal(s.feeReserve, 500_000_000n);
  assert.equal(s.swapPrincipal, 300_000_000n);
  assert.equal(vs.controllerValueV6(s), 800_000_000n);
  assert.throws(() => vs.normalizeStateV6({ ...state, extra: 1 }), /closed layout/);
  assert.throws(() => vs.normalizeStateV6({ ...state, swapPrincipal: "-1" }), /swapPrincipal/);
  assert.throws(() => vs.normalizeStateV6({ ...state, paused: "2" }), /out of range/);
  const { swapPrincipal, ...v5shaped } = state;
  assert.throws(() => vs.normalizeStateV6(v5shaped), /swapPrincipal/);
});

test("state id commits every field incl. swapPrincipal and swapRoot; JSON round-trips", () => {
  const t = vs.normalizeTemplateV6(template);
  const s = vs.normalizeStateV6(state);
  const id = vs.computeStateIdV6({ networkId: "testnet-10", template: t, state: s });
  const id2 = vs.computeStateIdV6({ networkId: "testnet-10", template: t, state: vs.normalizeStateV6({ ...state, swapPrincipal: "300000001" }) });
  const id3 = vs.computeStateIdV6({ networkId: "testnet-10", template: t, state: vs.normalizeStateV6({ ...state, swapRoot: "01".repeat(32) }) });
  assert.notEqual(id, id2);
  assert.notEqual(id, id3);
  assert.deepEqual(vs.stateToJsonV6(s), state);
  assert.equal(vs.OWNER_OP_SELECTOR_V6.ownerSetSwapRoot, 4);
  assert.equal(vs.OWNER_OP_SELECTOR_V6.ownerFundSwapPrincipal, 5);
});

test("recovery parse is quarantined and template geometry is pinned to kcc20-state/1", () => {
  const r = vs.normalizeStateV6ForRecovery({ ...state, paused: "7" });
  assert.equal(r.recoveryParse, true);
  assert.throws(() => vs.normalizeTemplateV6({ ...template, templateStateLen: 45 }), /must be 46/);
});
