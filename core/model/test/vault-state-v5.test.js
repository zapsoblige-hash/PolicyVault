"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const vs = require("../vault-state-v5");

const TPL = {
  owner: "11".repeat(32),
  vaultId: "44".repeat(32),
  descriptorHash: "d5".repeat(32),
  tokenCovenantId: "54".repeat(32),
  templateVmHash: "9e".repeat(32),
  templatePrefixLen: 1,
  templateStateLen: 46,
  templateSuffixLen: 1521
};
const ST = { feeReserve: "500000000", paused: "0", agentRoot: "13".repeat(32), policyNonce: "0" };

test("template/state normalize, state id is deterministic and pins every binding", () => {
  const t = vs.normalizeTemplateV5(TPL);
  const s = vs.normalizeStateV5(ST);
  const id = vs.computeStateIdV5({ networkId: "mainnet", template: t, state: s });
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(vs.computeStateIdV5({ networkId: "mainnet", template: t, state: s }), id);
  for (const [k, v] of [["templateVmHash", "9f".repeat(32)], ["tokenCovenantId", "55".repeat(32)], ["descriptorHash", "d6".repeat(32)], ["templateSuffixLen", 1522]]) {
    assert.notEqual(vs.computeStateIdV5({ networkId: "mainnet", template: vs.normalizeTemplateV5({ ...TPL, [k]: v }), state: s }), id, k);
  }
  assert.notEqual(vs.computeStateIdV5({ networkId: "testnet-10", template: t, state: s }), id);
  assert.deepEqual(vs.stateToJsonV5(s), { feeReserve: "500000000", paused: "0", agentRoot: "13".repeat(32), policyNonce: "0" });
});

test("fail-closed: unknown version, wrong state length, malformed fields, recovery-parse marker", () => {
  assert.throws(() => vs.resolveV5Abi("policyvault-0.4.1"), /unknown contract version/);
  assert.throws(() => vs.resolveV5Abi(undefined), /unknown contract version/);
  assert.equal(vs.resolveV5Abi("policyvault-0.5").contractRelPath, "contracts/PolicyVault.v0.5.sil");
  assert.throws(() => vs.normalizeTemplateV5({ ...TPL, templateStateLen: 45 }), /must be 46/);
  assert.throws(() => vs.normalizeTemplateV5({ ...TPL, templateVmHash: "zz" }));
  assert.throws(() => vs.normalizeStateV5({ ...ST, paused: "2" }), /out of range/);
  assert.throws(() => vs.normalizeStateV5({ ...ST, feeReserve: "-1" }));
  const r = vs.normalizeStateV5ForRecovery({ ...ST, paused: "7" });
  assert.equal(r.recoveryParse, true);
  assert.deepEqual(vs.OWNER_OP_SELECTOR_V5, { ownerSetAgentRoot: 0, ownerTopUpReserve: 1, ownerPause: 2, ownerUnpause: 3 });
});
