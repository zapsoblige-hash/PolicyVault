"use strict";

/* UNIT — deterministic v0.3 covenant regeneration (Phase 4.5 review item
 * 17, made durable in Phase 4H): tools/gen_v3.js must reproduce the
 * committed production covenant byte-identically. The committed .sil
 * remains authoritative; the generator is a source-authoring tool that
 * proves the repetitive 10-slot/45-pair sections are correct by
 * construction. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

test("tools/gen_v3.js regenerates contracts/PolicyVault.v0.3.sil byte-identically", () => {
  const repoRoot = path.join(process.env.HOME, "policyvault");
  const outPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pv3-gen-")), "regen.sil");
  const result = spawnSync("node", [path.join(repoRoot, "tools/gen_v3.js")], {
    encoding: "utf8",
    env: { ...process.env, OUT: outPath }
  });
  assert.equal(result.status, 0, `generator failed: ${result.stderr}`);
  const regenerated = fs.readFileSync(outPath, "utf8");
  const committed = fs.readFileSync(path.join(repoRoot, "contracts/PolicyVault.v0.3.sil"), "utf8");
  assert.equal(regenerated, committed, "regenerated covenant must equal the committed production source");
});
