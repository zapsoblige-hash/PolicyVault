"use strict";

/*
 * Shared-core extraction step 1 — API-surface equality.
 *
 * The sdk files for the extracted modules are thin re-export shims, so
 * requiring either path must yield the SAME object (strict identity — no
 * duplicate implementation can exist), and the exported names/types must
 * equal the surface recorded in the pre-extraction fixture.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v1.json"), "utf8"));
const MODULES = [
  ["amounts", "amounts"],
  ["canonical-json", "canonicalJson"],
  ["vault-state", "vaultState"],
  ["agent-merkle-v4", "agentMerkle"]
];

for (const [file, fixtureKey] of MODULES) {
  test(`api surface: sdk/src/${file} IS core/model/${file} (single implementation)`, () => {
    const viaSdk = require(path.join(__dirname, "..", "..", "..", "sdk", "src", file));
    const viaCore = require(path.join(__dirname, "..", file));
    assert.strictEqual(viaSdk, viaCore, "the sdk path must re-export the exact core module object");
  });

  test(`api surface: core/model/${file} exports exactly the pre-extraction surface`, () => {
    const mod = require(path.join(__dirname, "..", file));
    const keys = Object.keys(mod).sort();
    const types = {};
    for (const k of keys) types[k] = typeof mod[k];
    assert.deepStrictEqual({ keys, types }, FIXTURE.apiSurface[fixtureKey]);
  });
}
