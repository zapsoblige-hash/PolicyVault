"use strict";

/*
 * CONTRACT_VERSION single-source proof (extraction step 2).
 *
 * Step 1 severed the frozen v1 protocol-identity constant into
 * core/model/contract-version.js while sdk/src/config.js still carried a
 * duplicate literal, guarded here by an exact-equality test. Step 2
 * unified them: config.js now requires the core module instead of
 * defining its own literal, so the constant exists exactly ONCE. This
 * file keeps the (now structurally-guaranteed) equality regression and
 * adds the structural proof: config's source contains no independent
 * definition of the constant.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");

const CONFIG_PATH = path.join(__dirname, "..", "..", "..", "sdk", "src", "config.js");

test("contract-version: sdk config re-exports exactly the core/model constant", () => {
  const core = require(path.join(__dirname, "..", "contract-version"));
  const config = require(CONFIG_PATH);
  assert.strictEqual(typeof core.CONTRACT_VERSION, "string");
  assert.strictEqual(core.CONTRACT_VERSION, config.CONTRACT_VERSION);
});

test("contract-version: single source — config.js requires core/model and defines no literal", () => {
  const source = fs.readFileSync(CONFIG_PATH, "utf8");
  assert.match(
    source,
    /require\("\.\.\/\.\.\/core\/model\/contract-version"\)/,
    "sdk/src/config.js must consume core/model/contract-version.js"
  );
  assert.ok(
    !source.includes('"policyvault-0.1-beta"'),
    "sdk/src/config.js must not carry an independent CONTRACT_VERSION literal"
  );
});

test("contract-version: the frozen v1 identity tag is unchanged", () => {
  const core = require(path.join(__dirname, "..", "contract-version"));
  assert.strictEqual(core.CONTRACT_VERSION, "policyvault-0.1-beta");
});
