"use strict";

/*
 * Shared-core extraction step 2 — golden byte-identity gate.
 *
 * The fixture was captured from the ORIGINAL sdk/src implementations
 * BEFORE the step-2 extraction (pre-refactor baseline). Both require
 * roots — core/model directly, and sdk/src through the re-export shims —
 * must reproduce it exactly. Any divergence means the move changed
 * observable behavior and MUST fail.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const { computeGolden2 } = require("../testutil/golden2");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v2.json"), "utf8"));
const sdkMod = (n) => require(path.join(__dirname, "..", "..", "..", "sdk", "src", n));
const coreMod = (n) => require(path.join(__dirname, "..", n));

/* JSON round-trip so number identity (-0 vs 0) matches the parsed fixture. */
const viaJson = (v) => JSON.parse(JSON.stringify(v));

const MODS = (root) => ({
  vaultStateV2: root("vault-state-v2"),
  vaultStateV3: root("vault-state-v3"),
  vaultStateV4: root("vault-state-v4"),
  vaultTransitionsV3: root("vault-transitions-v3"),
  vaultTransitionsV4: root("vault-transitions-v4"),
  recipientMerkle: root("recipient-merkle-v3"),
  feeMass: root("fee-mass"),
  computeBudgetV3: root("compute-budget-v3"),
  computeBudgetV4: root("compute-budget-v4"),
  agentMerkle: root("agent-merkle-v4")
});

test("golden2: core/model reproduces the pre-extraction sdk fixture exactly", () => {
  assert.deepStrictEqual(viaJson(computeGolden2(MODS(coreMod))), FIXTURE);
});

test("golden2: sdk require root (through the re-export shims) reproduces the fixture exactly", () => {
  assert.deepStrictEqual(viaJson(computeGolden2(MODS(sdkMod))), FIXTURE);
});
