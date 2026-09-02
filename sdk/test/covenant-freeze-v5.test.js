"use strict";

/* UNIT — v0.5 COVENANT BYTE FREEZE guard (owner-authorized 2026-09-02;
 * record: docs/postlaunch/v0.5-covenant-byte-freeze.md). The frozen bytes
 * of contracts/PolicyVault.v0.5.sil, their byte-identical regeneration by
 * the frozen generator, and the vendored KCC20 reference program are
 * pinned by sha256. Any drift fails this suite: a change to v0.5 is a NEW
 * additive covenant version, never an in-place edit, unless the
 * established freeze-reopen process has been invoked by the owner. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..", "..");
const FROZEN = {
  covenant: {
    file: "contracts/PolicyVault.v0.5.sil",
    sha256: "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9"
  },
  generator: {
    file: "tools/gen_v5.js",
    sha256: "984df6b83dd7421df5e6a249dbf065b2f4e326ea096af25747287cebc19bd273"
  },
  kcc20Reference: {
    file: "contracts/vendor/kcc20-reference.sil",
    sha256: "2b7d59b06c0f34461bb01ae32b642c13491dd5b90a7cb4d5b827fcebf389ef73"
  }
};

function sha256Of(relPath) {
  return crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, relPath))).digest("hex");
}

test("v0.5 covenant bytes are FROZEN at the owner-authorized sha256", () => {
  assert.equal(sha256Of(FROZEN.covenant.file), FROZEN.covenant.sha256,
    "contracts/PolicyVault.v0.5.sil drifted from the frozen bytes — v0.5 is byte-frozen; make a new additive version or invoke the freeze-reopen process");
});

test("the frozen v0.5 generator is unchanged and regenerates the frozen bytes byte-identically", () => {
  assert.equal(sha256Of(FROZEN.generator.file), FROZEN.generator.sha256, "tools/gen_v5.js drifted from the frozen generator identity");
  const outPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pv5-freeze-")), "regen.sil");
  const result = spawnSync("node", [path.join(repoRoot, FROZEN.generator.file)], {
    encoding: "utf8",
    env: { ...process.env, OUT: outPath }
  });
  assert.equal(result.status, 0, `generator failed: ${result.stderr}`);
  const regenerated = fs.readFileSync(outPath);
  const committed = fs.readFileSync(path.join(repoRoot, FROZEN.covenant.file));
  assert.ok(regenerated.equals(committed), "regenerated v0.5 covenant must equal the frozen committed source byte-for-byte");
});

test("the vendored KCC20 reference program pinned by v0.5 is unchanged", () => {
  assert.equal(sha256Of(FROZEN.kcc20Reference.file), FROZEN.kcc20Reference.sha256, "contracts/vendor/kcc20-reference.sil drifted from the frozen identity");
});
