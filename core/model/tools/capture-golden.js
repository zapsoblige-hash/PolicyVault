"use strict";

/*
 * Shared-core extraction step 1 — golden fixture capture CLI.
 *
 * Runs the deterministic golden battery (core/model/testutil/golden.js)
 * against a chosen implementation root and writes the result as JSON.
 *
 *   node capture-golden.js sdk  <out.json>   — sdk/src implementations
 *   node capture-golden.js core <out.json>   — core/model implementations
 *
 * The COMMITTED fixture (core/model/test/fixtures/golden-v1.json) was
 * captured with `sdk` BEFORE the extraction refactor, i.e. from the
 * original in-sdk implementations. core/model/test/golden.test.js then
 * proves both require roots still reproduce it byte-for-byte.
 */

const fs = require("fs");
const path = require("path");
const { computeGolden } = require("../testutil/golden");

const mode = process.argv[2];
const outPath = process.argv[3];
if ((mode !== "sdk" && mode !== "core") || !outPath) {
  console.error("usage: node capture-golden.js <sdk|core> <out.json>");
  process.exit(1);
}

const root =
  mode === "sdk"
    ? (name) => require(path.join(__dirname, "..", "..", "..", "sdk", "src", name))
    : (name) => require(path.join(__dirname, "..", name));

const golden = computeGolden({
  amounts: root("amounts"),
  canonicalJson: root("canonical-json"),
  vaultState: root("vault-state"),
  agentMerkle: root("agent-merkle-v4")
});

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, `${JSON.stringify(golden, null, 1)}\n`);
console.log(`captured golden (${mode}) -> ${outPath}`);
