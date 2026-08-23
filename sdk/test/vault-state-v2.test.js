"use strict";

/* UNIT layer — v0.2 exact live-state model. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeTemplateV2,
  normalizeStateV2,
  computeStateIdV2,
  spendSuccessorV2,
  rolloverSuccessorV2,
  pauseSuccessorV2,
  revokeSuccessorV2,
  rotateSuccessorV2,
  topUpSuccessorV2,
  migrateSuccessorV2
} = require("../src/vault-state-v2");

const PK = (n) => n.toString(16).padStart(2, "0").repeat(32);

function baseState() {
  return normalizeStateV2({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "4000000000",
    paused: "0",
    delegate: PK(2),
    maxPerSpend: "10000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "864000",
    recipients: [PK(3), PK(4), PK(5)],
    delegateActive: "1",
    policyNonce: "0"
  });
}

test("v2 template/state normalize and stateId is deterministic and version-tagged", () => {
  const template = normalizeTemplateV2({ owner: PK(1), vaultId: PK(9) });
  const state = baseState();
  const id1 = computeStateIdV2({ networkId: "testnet-10", template, state });
  const id2 = computeStateIdV2({ networkId: "testnet-10", template, state });
  assert.equal(id1, id2);
  const idOtherNet = computeStateIdV2({ networkId: "mainnet", template, state });
  assert.notEqual(id1, idOtherNet);
});

test("v2 spend successor: only accounting moves", () => {
  const state = baseState();
  const succ = spendSuccessorV2(state, 1_000_000_000n);
  assert.equal(succ.protectedValue, state.protectedValue - 1_000_000_000n);
  assert.equal(succ.periodSpent, state.periodSpent + 1_000_000_000n);
  assert.equal(succ.delegate, state.delegate);
  assert.equal(succ.policyNonce, state.policyNonce);
  assert.throws(() => spendSuccessorV2(state, state.maxPerSpend + 1n), /maxPerSpend/);
  assert.throws(() => spendSuccessorV2({ ...state, paused: 1n }, 1n), /paused/);
  assert.throws(() => spendSuccessorV2({ ...state, delegateActive: 0n }, 1n), /revoked/);
});

test("v2 rollover successor advances whole periods and resets periodSpent", () => {
  const state = baseState();
  const succ = rolloverSuccessorV2(state, 2_000_000_000n, 3n);
  assert.equal(succ.periodStartDaa, state.periodStartDaa + 3n * state.periodLengthDaa);
  assert.equal(succ.periodSpent, 2_000_000_000n);
});

test("v2 lifecycle successors: pause/revoke/rotate/topUp preserve accounting", () => {
  const state = baseState();

  const paused = pauseSuccessorV2(state, true);
  assert.equal(paused.paused, 1n);
  assert.equal(paused.periodSpent, state.periodSpent);
  assert.throws(() => pauseSuccessorV2(paused, true), /already/);

  const revoked = revokeSuccessorV2(state);
  assert.equal(revoked.delegateActive, 0n);
  assert.equal(revoked.periodSpent, state.periodSpent);
  assert.throws(() => revokeSuccessorV2(revoked), /already/);

  const rotated = rotateSuccessorV2(revoked, PK(7));
  assert.equal(rotated.delegate, PK(7));
  assert.equal(rotated.delegateActive, 1n);
  assert.equal(rotated.periodSpent, state.periodSpent, "rotation must not reset periodSpent");
  assert.equal(rotated.periodStartDaa, state.periodStartDaa, "rotation must not reset periodStartDaa");

  const topped = topUpSuccessorV2(state, 5_000_000_000n);
  assert.equal(topped.protectedValue, state.protectedValue + 5_000_000_000n);
  assert.equal(topped.periodSpent, state.periodSpent);
  assert.throws(() => topUpSuccessorV2(state, 0n), /greater than zero/);
});

test("v2 migration successor bumps nonce by 1 and preserves accounting", () => {
  const state = baseState();
  const migrated = migrateSuccessorV2(state, { maxPerSpend: "20000000000", periodBudget: "100000000000" });
  assert.equal(migrated.policyNonce, 1n);
  assert.equal(migrated.maxPerSpend, 20_000_000_000n);
  assert.equal(migrated.periodSpent, state.periodSpent, "migration must not reset periodSpent");
  assert.equal(migrated.periodStartDaa, state.periodStartDaa);
  assert.equal(migrated.delegate, state.delegate);

  const relisted = migrateSuccessorV2(state, { recipients: [PK(8)] });
  assert.equal(relisted.recipients[0], PK(8));
  assert.equal(relisted.policyNonce, 1n);

  // budget < cap fails closed in normalization
  assert.throws(() => migrateSuccessorV2(state, { periodBudget: "1" }), /periodBudget/);
});

test("v2 state rejects malformed inputs", () => {
  assert.throws(() => normalizeStateV2({ ...JSON.parse(JSON.stringify({})), protectedValue: "1" }), /recipients|state/);
  const good = {
    protectedValue: "1000",
    periodStartDaa: "1",
    periodSpent: "0",
    paused: "0",
    delegate: PK(2),
    maxPerSpend: "10",
    periodBudget: "100",
    periodLengthDaa: "600",
    recipients: [PK(3)],
    delegateActive: "1",
    policyNonce: "0"
  };
  assert.throws(() => normalizeStateV2({ ...good, paused: "2" }), /paused/);
  assert.throws(() => normalizeStateV2({ ...good, delegate: "zz" }), /delegate/);
  assert.throws(() => normalizeStateV2({ ...good, protectedValue: "-1" }), /protectedValue/);
  const state = normalizeStateV2(good);
  assert.equal(state.recipients.length, 3, "allowlist pads to 3");
});
