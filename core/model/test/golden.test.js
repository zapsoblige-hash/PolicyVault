"use strict";

/*
 * Shared-core extraction step 1 — golden byte-identity gate.
 *
 * The fixture was captured from the ORIGINAL sdk/src implementations
 * BEFORE the extraction (commit "pre-refactor baseline"). Both require
 * roots — core/model directly, and sdk/src through the re-export shims —
 * must reproduce it exactly. Any divergence means the move changed
 * observable behavior and MUST fail.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const { computeGolden } = require("../testutil/golden");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v1.json"), "utf8"));
const sdkMod = (n) => require(path.join(__dirname, "..", "..", "..", "sdk", "src", n));
const coreMod = (n) => require(path.join(__dirname, "..", n));

/* JSON round-trip so number identity (-0 vs 0) matches the parsed fixture. */
const viaJson = (v) => JSON.parse(JSON.stringify(v));

test("golden: core/model reproduces the pre-extraction sdk fixture exactly", () => {
  const got = computeGolden({
    amounts: coreMod("amounts"),
    canonicalJson: coreMod("canonical-json"),
    vaultState: coreMod("vault-state"),
    agentMerkle: coreMod("agent-merkle-v4")
  });
  assert.deepStrictEqual(viaJson(got), FIXTURE);
});

test("golden: sdk require root (through the re-export shims) reproduces the fixture exactly", () => {
  const got = computeGolden({
    amounts: sdkMod("amounts"),
    canonicalJson: sdkMod("canonical-json"),
    vaultState: sdkMod("vault-state"),
    agentMerkle: sdkMod("agent-merkle-v4")
  });
  assert.deepStrictEqual(viaJson(got), FIXTURE);
});
