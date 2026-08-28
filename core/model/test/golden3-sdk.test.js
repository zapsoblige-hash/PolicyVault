"use strict";

/*
 * Shared-core extraction step 3 — IMPURE-member golden gate (sdk shell).
 *
 * The impure members that STAYED in the sdk composition modules
 * (pv_tx_probe-backed describe/verify/create/integrity/submit/blob/
 * round-trip) must reproduce their deterministic pre-split outputs and
 * fail-closed error surfaces exactly (fixture captured from the ORIGINAL
 * sdk implementations, commit 2e95066).
 *
 * ENVIRONMENT: requires the built pv_tx_probe
 * (tests/vm/target/debug/pv_tx_probe) — the same expectation the sdk
 * suite has always had. Fails loudly (never skips) if it is missing.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");

const { computeGolden3Impure, captureApiSurface } = require("../testutil/golden3");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v3.json"), "utf8"));
const SDK = path.join(__dirname, "..", "..", "..", "sdk", "src");

function sdkModules() {
  return {
    frozenTx: require(path.join(SDK, "frozen-tx-v3")),
    apV3: require(path.join(SDK, "approval-package-v3")),
    apV4: require(path.join(SDK, "approval-package-v4")),
    recipientMerkle: require(path.join(SDK, "recipient-merkle-v3")),
    agentMerkle: require(path.join(SDK, "agent-merkle-v4"))
  };
}

test("golden3 impure battery reproduces the pre-split fixture through the sdk composition modules", () => {
  assert.deepStrictEqual(computeGolden3Impure(sdkModules()), FIXTURE.impure);
});

test("golden3 sdk API surface (keys + types) is unchanged by the split", () => {
  assert.deepStrictEqual(captureApiSurface(sdkModules()), FIXTURE.apiSurface);
});
