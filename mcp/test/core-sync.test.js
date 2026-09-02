"use strict";

/*
 * PACKAGING: the shared-core files packaged into mcp/core/ are VERBATIM,
 * byte-identical copies of the canonical sources (ONE implementation), the
 * manifest is current, and any drift/edit/extra file is detected.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const sync = require("../tools/sync-core");

const sha256 = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

test("mcp/core is byte-identical to the canonical core sources and the manifest is current", () => {
  assert.deepEqual(sync.check(), []);
  for (const rel of sync.CORE_FILES) {
    const canonical = path.join(sync.REPO_ROOT, rel);
    const packaged = path.join(sync.OUT_ROOT, rel.replace(/^core\//, ""));
    assert.equal(sha256(packaged), sha256(canonical), rel);
  }
  const manifest = JSON.parse(fs.readFileSync(sync.MANIFEST_PATH, "utf8"));
  assert.equal(manifest.manifest, "policyvault-mcp-core-sync/1");
  assert.equal(manifest.files.length, sync.CORE_FILES.length);
});

test("drift detection: an edited copy, a missing copy, and a stray file each FAIL the check (then restored)", () => {
  const packaged = path.join(sync.OUT_ROOT, "model", "canonical-json.js");
  const original = fs.readFileSync(packaged);
  try {
    fs.writeFileSync(packaged, Buffer.concat([original, Buffer.from("\n// local edit\n")]));
    assert.ok(sync.check().some((p) => /drift/.test(p)), "edited copy must be flagged as drift");
    fs.unlinkSync(packaged);
    assert.ok(sync.check().some((p) => /missing packaged copy/.test(p)), "missing copy must be flagged");
  } finally {
    fs.writeFileSync(packaged, original);
  }
  const stray = path.join(sync.OUT_ROOT, "model", "extra.js");
  try {
    fs.writeFileSync(stray, "module.exports = {};\n");
    assert.ok(sync.check().some((p) => /unexpected file/.test(p)), "stray file must be flagged (no ad-hoc duplicates)");
  } finally {
    fs.unlinkSync(stray);
  }
  assert.deepEqual(sync.check(), []);
});

test("the packaged copy is a pure module (node builtins only) — packaging it cannot pull a second implementation", () => {
  const text = fs.readFileSync(path.join(sync.OUT_ROOT, "model", "canonical-json.js"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const requires = [...text.matchAll(/require\(\s*(["'])([^"')]+)\1\s*\)/g)].map((m) => m[2]);
  assert.deepEqual(requires, [], "canonical-json must not require anything");
});
