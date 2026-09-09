"use strict";

/* UNIT — HIERARCHICAL DELEGATION DESIGN FREEZE guard (owner-accepted 2026-09-03,
 * Flagship Wave 2 §0; record: docs/postlaunch/hierarchical-delegation-design-freeze.md).
 * This pins the DESIGN record and the probe evidence it rests on — NOT
 * production covenant bytes (none exist for hierarchical delegation; the
 * experimental probe covenant is a measurement/falsification artefact, never
 * a product). Any drift means the frozen design was edited in place: revise by
 * a NEW additive design record instead. The v0.5 baseline the probe was derived
 * from is re-pinned so the probe can never be mistaken for a v0.5 edit. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..", "..");
const FROZEN = {
  designRecord: {
    file: "docs/postlaunch/hierarchical-delegation-design.md",
    sha256: /* STALE ASSUMPTION (2026-09-05): the owner's policy sweep (commit 9d54cfc,
     * documentation-only — external-security-audit wording removed) touched
     * ONE sentence of the design record; the design itself is unchanged. */
    "5c2dcb845546d70c4ec9404b9e51adbf553c2bfc13d6e6a83605c9c461107d96"
  },
  probeCovenant: {
    file: "contracts/experiments/HDProbe.sil",
    sha256: "dbee385d117beb5ec4de5f29dbc9e19873663f8e0599625b40a59b57cf9c246d"
  },
  probeSuite: {
    file: "tests/vm/tests/hd_experiment.rs",
    sha256: "78d4b5944d663f33149e21be4c83ac54804d7494d20cc4c2a4c0e57d78b88c89"
  },
  baselineV5: {
    file: "contracts/PolicyVault.v0.5.sil",
    sha256: "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9"
  }
};

function sha256Of(relPath) {
  return crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, relPath))).digest("hex");
}

test("the hierarchical-delegation DESIGN record is frozen at the recorded sha256", () => {
  assert.equal(sha256Of(FROZEN.designRecord.file), FROZEN.designRecord.sha256,
    "hierarchical-delegation-design.md drifted — the design is frozen; write a NEW additive design record instead of editing it");
});

test("the probe evidence the design freeze rests on is unchanged (experimental covenant + real-engine suite)", () => {
  assert.equal(sha256Of(FROZEN.probeCovenant.file), FROZEN.probeCovenant.sha256, "contracts/experiments/HDProbe.sil drifted (measurement artefact; not a product)");
  assert.equal(sha256Of(FROZEN.probeSuite.file), FROZEN.probeSuite.sha256, "tests/vm/tests/hd_experiment.rs drifted");
});

test("frozen v0.5 (the probe's baseline) remains byte-identical", () => {
  assert.equal(sha256Of(FROZEN.baselineV5.file), FROZEN.baselineV5.sha256, "contracts/PolicyVault.v0.5.sil drifted — frozen lineages are never mutated in place");
});

test("the design-freeze record states the binding rules verbatim and denies any byte freeze", () => {
  const text = fs.readFileSync(path.join(repoRoot, "docs/postlaunch/hierarchical-delegation-design-freeze.md"), "utf8");
  for (const phrase of [
    "HIERARCHICAL-DELEGATION-DESIGN-FROZEN",
    "Authority may NEVER increase descending",
    "MAX_LEVEL = 3 is an implementation constraint derived from measured stack limits",
    "Every ancestor policy participates in the effective intersection",
    "Removing a parent removes its subtree authority",
    "Stale child proofs fail closed",
    "NOT a consensus upper-bound expiry",
    "No owner entrypoint may treat a delegate leaf as owner authority",
    "measured/proven rather than assumed",
    "freezes **no\nproduction covenant bytes**"
  ]) {
    assert.ok(text.includes(phrase), `design-freeze record must state: ${phrase}`);
  }
});
