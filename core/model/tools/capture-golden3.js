"use strict";

/*
 * Capture CLI for the step-3 golden battery (interface split of
 * frozen-tx-v3 / approval-package-v3 / approval-package-v4).
 *
 * Modes:
 *   sdk        — full capture { apiSurface, pure, impure } through the
 *                sdk/src modules (pre-split: the originals; post-split:
 *                the composition modules). Requires the built pv_tx_probe.
 *   core       — { pure } only, through the core/model modules
 *                (post-split only; the pure members are all that exist
 *                there by design).
 *   pure-sdk   — { pure } only, through sdk/src (byte-comparable with the
 *                core mode output).
 *
 * Usage: node capture-golden3.js <sdk|core|pure-sdk> [outFile]
 * Writes canonical JSON (2-space=1 indent, trailing newline) to stdout or
 * outFile. The pre-split fixture is captured with mode `sdk` from the
 * ORIGINAL modules and committed BEFORE any refactor.
 */

const fs = require("fs");
const path = require("path");

const { computeGolden3Pure, computeGolden3Impure, captureApiSurface } = require("../testutil/golden3");

const mode = process.argv[2];
const outFile = process.argv[3];

const SDK_SRC = path.join(__dirname, "..", "..", "..", "sdk", "src");
const CORE_MODEL = path.join(__dirname, "..");

function sdkModules() {
  return {
    frozenTx: require(path.join(SDK_SRC, "frozen-tx-v3")),
    apV3: require(path.join(SDK_SRC, "approval-package-v3")),
    apV4: require(path.join(SDK_SRC, "approval-package-v4")),
    recipientMerkle: require(path.join(SDK_SRC, "recipient-merkle-v3")),
    agentMerkle: require(path.join(SDK_SRC, "agent-merkle-v4"))
  };
}

function coreModules() {
  return {
    frozenTx: require(path.join(CORE_MODEL, "frozen-tx-v3")),
    apV3: require(path.join(CORE_MODEL, "approval-package-v3")),
    apV4: require(path.join(CORE_MODEL, "approval-package-v4"))
  };
}

let result;
if (mode === "sdk") {
  const mods = sdkModules();
  result = {
    apiSurface: captureApiSurface(mods),
    pure: computeGolden3Pure(mods),
    impure: computeGolden3Impure(mods)
  };
} else if (mode === "core") {
  result = { pure: computeGolden3Pure(coreModules()) };
} else if (mode === "pure-sdk") {
  result = { pure: computeGolden3Pure(sdkModules()) };
} else {
  console.error("usage: node capture-golden3.js <sdk|core|pure-sdk> [outFile]");
  process.exit(1);
}

const json = `${JSON.stringify(result, null, 1)}\n`;
if (outFile) {
  fs.writeFileSync(outFile, json);
  console.error(`wrote ${mode} capture to ${outFile}`);
} else {
  process.stdout.write(json);
}
