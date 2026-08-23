"use strict";

/* UNIT layer — vault state normalization, state IDs, successors. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizePolicy,
  normalizeState,
  computeStateId,
  spendSuccessor,
  rolloverSuccessor
} = require("../src/vault-state");

const PK = (b) => b.repeat(64);

function samplePolicy(overrides = {}) {
  return normalizePolicy({
    owner: PK("1"),
    delegate: PK("2"),
    vaultId: PK("3"),
    maxPerSpend: "10000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "864000",
    recipients: [PK("4"), PK("5")],
    initValue: "100000000000",
    initPeriodStartDaa: "541000000",
    ...overrides
  });
}

function sampleState(overrides = {}) {
  return normalizeState({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    ...overrides
  });
}

test("policy normalization pads recipients to 3", () => {
  const policy = samplePolicy();
  assert.equal(policy.recipients.length, 3);
  assert.equal(policy.recipients[2], policy.recipients[1]);
  assert.equal(policy.declaredRecipientCount, 2);
});

test("policy rejects budget below cap", () => {
  assert.throws(
    () => samplePolicy({ periodBudget: "9999999999" }),
    /periodBudget must be >= /
  );
});

test("policy rejects malformed pubkeys and ids", () => {
  assert.throws(() => samplePolicy({ owner: "xyz" }), /lowercase hex/);
  assert.throws(() => samplePolicy({ vaultId: PK("3").slice(0, 62) }), /lowercase hex/);
  assert.throws(() => samplePolicy({ recipients: [] }), /1 to 3/);
});

test("state rejects paused outside 0..1 and DAA above threshold", () => {
  assert.throws(() => sampleState({ paused: "2" }), /out of range/);
  assert.throws(() => sampleState({ periodStartDaa: "500000000000" }), /threshold/);
});

test("state ID is deterministic and distinguishes every field", () => {
  const policy = samplePolicy();
  const state = sampleState();
  const base = computeStateId({ networkId: "testnet-10", policy, state });
  assert.equal(base, computeStateId({ networkId: "testnet-10", policy, state }));

  assert.notEqual(base, computeStateId({ networkId: "mainnet", policy, state }));
  assert.notEqual(base, computeStateId({ networkId: "testnet-10", policy: samplePolicy({ vaultId: PK("9") }), state }));
  assert.notEqual(
    base,
    computeStateId({ networkId: "testnet-10", policy, state: sampleState({ periodSpent: "1" }) })
  );
});

test("spend successor exact accounting", () => {
  const state = sampleState();
  const succ = spendSuccessor(state, "2500000000");
  assert.equal(succ.protectedValue, 97_500_000_000n);
  assert.equal(succ.periodSpent, 2_500_000_000n);
  assert.equal(succ.periodStartDaa, state.periodStartDaa);
  assert.equal(succ.paused, 0n);
});

test("spend successor rejects zeroing the vault", () => {
  const state = sampleState({ protectedValue: "100" });
  assert.throws(() => spendSuccessor(state, "100"), /positive successor/);
});

test("rollover successor advances whole periods and resets periodSpent", () => {
  const policy = samplePolicy();
  const state = sampleState({ periodSpent: "50000000000" });
  const succ = rolloverSuccessor(policy, state, "3000000000", "2");
  assert.equal(succ.periodStartDaa, 541_000_000n + 2n * 864_000n);
  assert.equal(succ.periodSpent, 3_000_000_000n);
  assert.throws(() => rolloverSuccessor(policy, state, "1", "0"), /out of range/);
  assert.throws(() => rolloverSuccessor(policy, state, "1", "1001"), /out of range/);
});
