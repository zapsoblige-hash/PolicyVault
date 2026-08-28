"use strict";

/*
 * Shared-core extraction step 1 — portability / purity gate.
 *
 * The portable core (top-level core/model/*.js) must depend ONLY on
 * node builtins and sibling core/model modules: no sdk/, server/, web/,
 * no external packages, no process.env, no filesystem or network access.
 * (testutil/, tools/ and test/ are harness code and are exempt — they
 * deliberately require sdk/src to prove equivalence.)
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { isBuiltin } = require("node:module");

const MODEL_DIR = path.join(__dirname, "..");

function modelFiles() {
  return fs
    .readdirSync(MODEL_DIR, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".js"))
    .map((e) => e.name)
    .sort();
}

test("purity: core/model contains the extracted module set", () => {
  assert.deepStrictEqual(modelFiles(), [
    "agent-merkle-v4.js",
    "amounts.js",
    "approval-package-v3.js",
    "approval-package-v4.js",
    "canonical-json.js",
    "compute-budget-v3.js",
    "compute-budget-v4.js",
    "contract-version.js",
    "fee-mass.js",
    "frozen-tx-v3.js",
    "recipient-merkle-v3.js",
    "vault-state-v2.js",
    "vault-state-v3.js",
    "vault-state-v4.js",
    "vault-state.js",
    "vault-transitions-v3.js",
    "vault-transitions-v4.js"
  ]);
});

/* Strip comments so documentation cannot trip (or hide) the scan. */
function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

for (const file of modelFiles()) {
  test(`purity: core/model/${file} requires only node builtins + core/model siblings`, () => {
    const text = stripComments(fs.readFileSync(path.join(MODEL_DIR, file), "utf8"));
    const requires = [...text.matchAll(/require\(\s*(["'])([^"')]+)\1\s*\)/g)].map((m) => m[2]);
    for (const target of requires) {
      if (isBuiltin(target)) continue;
      assert.match(target, /^\.\/[a-z0-9-]+$/, `${file}: non-portable require ${JSON.stringify(target)}`);
      const resolved = path.join(MODEL_DIR, `${target.slice(2)}.js`);
      assert.ok(fs.existsSync(resolved), `${file}: ${target} must resolve inside core/model`);
    }
    assert.ok(!/process\.env/.test(text), `${file}: must not read process.env`);
    for (const banned of ["sdk/", "server/", "web/", "node_modules"]) {
      assert.ok(!requires.some((r) => r.includes(banned)), `${file}: must not require from ${banned}`);
    }
  });
}
