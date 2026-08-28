"use strict";

/*
 * Shared-core extraction step 3 — PURE golden gate.
 *
 * The pure members split out of frozen-tx-v3 / approval-package-v3 /
 * approval-package-v4 must reproduce the pre-split fixture (captured from
 * the ORIGINAL sdk implementations, commit 2e95066) EXACTLY, through BOTH
 * require roots:
 *   - core/model directly (the single implementation), and
 *   - sdk/src through the composition modules (what production code
 *     actually loads).
 * Hermetic: no probe, no fs beyond the fixture, no network.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");

const { computeGolden3Pure } = require("../testutil/golden3");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v3.json"), "utf8"));
const CORE = path.join(__dirname, "..");
const SDK = path.join(__dirname, "..", "..", "..", "sdk", "src");

test("golden3 pure battery reproduces the pre-split fixture through core/model", () => {
  const computed = computeGolden3Pure({
    frozenTx: require(path.join(CORE, "frozen-tx-v3")),
    apV3: require(path.join(CORE, "approval-package-v3")),
    apV4: require(path.join(CORE, "approval-package-v4"))
  });
  assert.deepStrictEqual(computed, FIXTURE.pure);
});

test("golden3 pure battery reproduces the pre-split fixture through sdk/src (composition modules)", () => {
  const computed = computeGolden3Pure({
    frozenTx: require(path.join(SDK, "frozen-tx-v3")),
    apV3: require(path.join(SDK, "approval-package-v3")),
    apV4: require(path.join(SDK, "approval-package-v4"))
  });
  assert.deepStrictEqual(computed, FIXTURE.pure);
});
