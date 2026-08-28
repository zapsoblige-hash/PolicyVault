"use strict";

/*
 * SDK layer — pv_call_encoder boundVaultId regression.
 *
 * The VM harness builds the newState struct in-process (v2_state_arg) and so
 * never exercised pv_call_encoder's boundVaultId injection, which pulls the
 * vaultId from a constructor-arg INDEX that differs between v0.1 (2) and
 * v0.2 (1). A wrong index silently set boundVaultId to the delegate key and
 * every v0.2 transition failed on-chain at `newState.boundVaultId ==
 * prevState.boundVaultId`. This test compiles a real v0.2 state and asserts
 * the encoder's first pushed field equals the vaultId.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { loadConfig } = require("../src/config");
const { normalizeTemplateV2, normalizeStateV2 } = require("../src/vault-state-v2");
const { compileExactStateV2 } = require("../src/contract-compiler-v2");

const ENCODER = path.resolve(__dirname, "..", "..", "tests/vm/target/debug/pv_call_encoder"); // checkout-relative (public portability)
const PK = (n) => n.toString(16).padStart(2, "0").repeat(32);

test("pv_call_encoder emits the vaultId as boundVaultId for v0.2 calls", (t) => {
  if (!fs.existsSync(ENCODER)) {
    t.skip("pv_call_encoder not built");
    return;
  }
  const config = loadConfig();
  const vaultId = crypto.randomBytes(32).toString("hex");
  const template = normalizeTemplateV2({ owner: PK(1), vaultId });
  const state = normalizeStateV2({
    protectedValue: "100000000000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    paused: "0",
    delegate: PK(2),
    maxPerSpend: "10000000000",
    periodBudget: "50000000000",
    periodLengthDaa: "600",
    recipients: [PK(3), PK(4), PK(5)],
    delegateActive: "1",
    policyNonce: "0"
  });

  let compiled;
  try {
    compiled = compileExactStateV2({ config, template, state });
  } catch (err) {
    t.skip(`silverc unavailable: ${err.message}`);
    return;
  }

  const call = {
    contractVersion: "policyvault-0.2",
    function: "revokeDelegate",
    successor: {
      protectedValue: "100000000000",
      periodStartDaa: "541000000",
      periodSpent: "0",
      paused: 0,
      delegate: PK(2),
      maxPerSpend: "10000000000",
      periodBudget: "50000000000",
      periodLengthDaa: "600",
      recipient1: PK(3),
      recipient2: PK(4),
      recipient3: PK(5),
      delegateActive: 0,
      policyNonce: "0"
    },
    signature: "00".repeat(65)
  };
  const callPath = path.join(os.tmpdir(), `pv-enc-test-${crypto.randomUUID()}.json`);
  fs.writeFileSync(callPath, JSON.stringify(call));
  try {
    const r = spawnSync(
      ENCODER,
      [path.join(compiled.buildDir, "PolicyVault.state.sil"), path.join(compiled.buildDir, "constructor-args.json"), callPath],
      { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }
    );
    assert.equal(r.status, 0, `encoder failed: ${r.stderr}`);
    const hex = r.stdout.trim();
    // First push in the encoded call is boundVaultId: OpData32 (0x20) + 32 bytes.
    assert.equal(hex.slice(0, 2), "20", "first push must be a 32-byte value");
    assert.equal(hex.slice(2, 66), vaultId, "boundVaultId must equal the vaultId, not the delegate key");
  } finally {
    fs.unlinkSync(callPath);
  }
});
