"use strict";

/*
 * INTEGRATION layer — exact live-state compilation through the real
 * silverc binary. Uses a temp dataRoot; the repo contract source is read
 * but never written.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { normalizePolicy, normalizeState } = require("../src/vault-state");
const { compileExactState } = require("../src/contract-compiler");

const PK = (b) => b.repeat(64);

const policy = normalizePolicy({
  owner: PK("1"),
  delegate: PK("2"),
  vaultId: PK("3"),
  maxPerSpend: "10000000000",
  periodBudget: "50000000000",
  periodLengthDaa: "864000",
  recipients: [PK("4"), PK("5"), PK("6")],
  initValue: "100000000000",
  initPeriodStartDaa: "541000000"
});

const state = normalizeState({
  protectedValue: "100000000000",
  periodStartDaa: "541000000",
  periodSpent: "0",
  paused: "0"
});

function tempConfig() {
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-compiler-test-"));
  return { config: loadConfig({ dataRoot }), dataRoot };
}

test("compiles exact state deterministically", () => {
  const { config, dataRoot } = tempConfig();
  try {
    const first = compileExactState({ config, policy, state });
    assert.ok(first.scriptBytes.length > 500);
    assert.ok(first.stateLayout.len > 0);
    assert.equal(first.contractName, "PolicyVault");

    // Recompiling the same state reuses artifacts byte-for-byte.
    const second = compileExactState({ config, policy, state });
    assert.equal(second.scriptHex, first.scriptHex);
    assert.equal(second.stateId, first.stateId);
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});

test("different states share the template but differ in state region", () => {
  const { config, dataRoot } = tempConfig();
  try {
    const a = compileExactState({ config, policy, state });
    const spent = { ...state, protectedValue: 97_500_000_000n, periodSpent: 2_500_000_000n };
    const b = compileExactState({ config, policy, state: spent });

    assert.notEqual(a.stateId, b.stateId);
    assert.notEqual(a.scriptHex, b.scriptHex);
    // Same immutable policy => identical template identity.
    assert.equal(a.templateHash, b.templateHash);
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});

test("different policy changes the template identity", () => {
  const { config, dataRoot } = tempConfig();
  try {
    const a = compileExactState({ config, policy, state });
    const otherPolicy = normalizePolicy({
      owner: PK("1"),
      delegate: PK("2"),
      vaultId: PK("3"),
      maxPerSpend: "20000000000",
      periodBudget: "50000000000",
      periodLengthDaa: "864000",
      recipients: [PK("4"), PK("5"), PK("6")],
      initValue: "100000000000",
      initPeriodStartDaa: "541000000"
    });
    const b = compileExactState({ config, policy: otherPolicy, state });
    assert.notEqual(a.templateHash, b.templateHash);
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});

test("tampered build artifacts are refused", () => {
  const { config, dataRoot } = tempConfig();
  try {
    const first = compileExactState({ config, policy, state });
    const sourcePath = path.join(first.buildDir, "PolicyVault.state.sil");
    fs.writeFileSync(sourcePath, fs.readFileSync(sourcePath, "utf8") + "\n// tampered\n");
    assert.throws(() => compileExactState({ config, policy, state }), /different deterministic contents/);
  } finally {
    fs.rmSync(dataRoot, { recursive: true, force: true });
  }
});
