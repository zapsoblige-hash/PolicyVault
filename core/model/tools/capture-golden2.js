"use strict";

/*
 * Shared-core extraction step 2 — golden fixture capture CLI.
 *
 * Runs the step-2 deterministic golden battery
 * (core/model/testutil/golden2.js) against a chosen implementation root
 * and writes the result as JSON.
 *
 *   node capture-golden2.js sdk  <out.json>   — sdk/src implementations
 *   node capture-golden2.js core <out.json>   — core/model implementations
 *
 * The COMMITTED fixture (core/model/test/fixtures/golden-v2.json) was
 * captured with `sdk` BEFORE the step-2 extraction refactor, i.e. from
 * the original in-sdk implementations. core/model/test/golden2.test.js
 * then proves both require roots still reproduce it byte-for-byte.
 */

const fs = require("fs");
const path = require("path");
const { computeGolden2 } = require("../testutil/golden2");

const mode = process.argv[2];
const outPath = process.argv[3];
if ((mode !== "sdk" && mode !== "core") || !outPath) {
  console.error("usage: node capture-golden2.js <sdk|core> <out.json>");
  process.exit(1);
}

const root =
  mode === "sdk"
    ? (name) => require(path.join(__dirname, "..", "..", "..", "sdk", "src", name))
    : (name) => require(path.join(__dirname, "..", name));

const golden = computeGolden2({
  vaultStateV2: root("vault-state-v2"),
  vaultStateV3: root("vault-state-v3"),
  vaultStateV4: root("vault-state-v4"),
  vaultTransitionsV3: root("vault-transitions-v3"),
  vaultTransitionsV4: root("vault-transitions-v4"),
  recipientMerkle: root("recipient-merkle-v3"),
  feeMass: root("fee-mass"),
  computeBudgetV3: root("compute-budget-v3"),
  computeBudgetV4: root("compute-budget-v4"),
  agentMerkle: root("agent-merkle-v4")
});

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, `${JSON.stringify(golden, null, 1)}\n`);
console.log(`captured golden2 (${mode}) -> ${outPath}`);
