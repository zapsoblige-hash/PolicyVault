"use strict";

/* UNIT layer — manifest fail-closed validation. */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { normalizeManifest, MANIFEST_SCHEMA, VaultStatus } = require("../src/manifest");
const { CONTRACT_VERSION } = require("../src/config");
const { computeStateId, normalizePolicy, normalizeState } = require("../src/vault-state");

const PK = (b) => b.repeat(64);

const policyInput = {
  owner: PK("1"),
  delegate: PK("2"),
  vaultId: PK("3"),
  maxPerSpend: "10000000000",
  periodBudget: "50000000000",
  periodLengthDaa: "864000",
  recipients: [PK("4")],
  initValue: "100000000000",
  initPeriodStartDaa: "541000000"
};

function activeManifest() {
  const policy = normalizePolicy(policyInput);
  const state = normalizeState({
    protectedValue: "80000000000",
    periodStartDaa: "541000000",
    periodSpent: "20000000000",
    paused: "0"
  });
  const stateId = computeStateId({ networkId: "testnet-10", policy, state });
  return {
    schema: MANIFEST_SCHEMA,
    contractVersion: CONTRACT_VERSION,
    networkId: "testnet-10",
    vaultId: policyInput.vaultId,
    status: VaultStatus.ACTIVE,
    policy: policyInput,
    live: {
      state: { protectedValue: "80000000000", periodStartDaa: "541000000", periodSpent: "20000000000", paused: "0" },
      stateId,
      outpoint: { transactionId: PK("a"), index: 1 },
      outpointValue: "80000000000",
      scriptSha256: PK("b"),
      covenantId: PK("c")
    },
    creationTxId: PK("d"),
    latestTransitionTxId: null
  };
}

test("valid active manifest normalizes", () => {
  const m = normalizeManifest(activeManifest());
  assert.equal(m.status, "ACTIVE");
  assert.equal(m.live.outpointValue, 80_000_000_000n);
});

test("unknown schema fails closed", () => {
  assert.throws(() => normalizeManifest({ ...activeManifest(), schema: "other/v9" }), /unknown manifest schema/);
});

test("unknown contract version fails closed", () => {
  assert.throws(() => normalizeManifest({ ...activeManifest(), contractVersion: "policyvault-9.9" }), /unknown contract version/);
});

test("stateId mismatch fails closed", () => {
  const bad = activeManifest();
  bad.live.stateId = PK("e");
  assert.throws(() => normalizeManifest(bad), /stateId does not match/);
});

test("outpoint value not equal to protectedValue fails closed", () => {
  const bad = activeManifest();
  bad.live.outpointValue = "1";
  assert.throws(() => normalizeManifest(bad), /outpoint value does not equal/);
});

test("terminal status must carry live: null", () => {
  const bad = activeManifest();
  bad.status = VaultStatus.RECOVERED;
  assert.throws(() => normalizeManifest(bad), /terminal manifest must carry live: null/);
});
