"use strict";

/*
 * PORTABILITY / PURITY GATE for core/attest.
 *
 * core/attest is meant to run unchanged in the server, the CLI, the
 * browser bundle and the mobile runtime, so its top-level modules must
 * depend ONLY on:
 *   - core/attest siblings, and
 *   - the ONE sanctioned cross-core import, core/intent/canonical (the
 *     project's single G-2 canonical serializer; core/attest must never
 *     grow a second copy of it).
 * No sdk/, no server/, no web/, no external packages, no process.env, no
 * filesystem, no network. Node builtins are limited to node:crypto, and
 * even that is reached indirectly through core/intent/canonical.
 *
 * (test/ and testutil/ are harness code and are exempt: the vector
 * builder deliberately reads the repository's evidence file from disk.)
 *
 * Layer: UNIT.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { isBuiltin } = require("node:module");

const DIR = path.join(__dirname, "..");
const SANCTIONED_CROSS_CORE = ["../intent/canonical"];

function moduleFiles() {
  return fs
    .readdirSync(DIR, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".js"))
    .map((e) => e.name)
    .sort();
}

const stripComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

test("purity: core/attest contains exactly the published module set", () => {
  assert.deepStrictEqual(moduleFiles(), ["canonical.js", "export.js", "index.js", "record.js", "schema.js", "summary.js", "verify.js"]);
});

for (const file of moduleFiles()) {
  test(`purity: core/attest/${file} imports only siblings and the sanctioned canonicalizer`, () => {
    const text = stripComments(fs.readFileSync(path.join(DIR, file), "utf8"));
    const requires = [...text.matchAll(/require\(\s*(["'])([^"')]+)\1\s*\)/g)].map((m) => m[2]);
    for (const target of requires) {
      if (SANCTIONED_CROSS_CORE.includes(target)) continue;
      assert.ok(!isBuiltin(target) || target === "node:crypto", `${file}: unexpected node builtin ${target}`);
      if (isBuiltin(target)) continue;
      assert.match(target, /^\.\/[a-z0-9-]+$/, `${file}: non-portable require ${JSON.stringify(target)}`);
      assert.ok(fs.existsSync(path.join(DIR, `${target.slice(2)}.js`)), `${file}: ${target} must resolve inside core/attest`);
    }
    assert.ok(!/process\.env/.test(text), `${file}: must not read process.env`);
    for (const banned of ["sdk/", "server/", "web/", "node_modules", "'fs'", '"fs"', '"net"', '"http"', '"https"', '"child_process"']) {
      assert.ok(!text.includes(banned), `${file}: must not reference ${banned}`);
    }
  });
}

test("purity: core/attest does not define a second canonical JSON serializer", () => {
  /* The G-2 rule: one canonicalizer, imported verbatim. A second copy is
   * a silent drift surface that only shows up as a hash divergence in
   * production. */
  let definitions = 0;
  for (const file of moduleFiles()) {
    const text = stripComments(fs.readFileSync(path.join(DIR, file), "utf8"));
    if (/function\s+canonicalJsonStringify\s*\(/.test(text)) definitions += 1;
  }
  assert.equal(definitions, 0, "core/attest must import core/intent/canonical, never redefine it");
  const canonical = require("../canonical");
  assert.equal(canonical.canonicalJsonStringify, require("../../intent/canonical").canonicalJsonStringify);
});
