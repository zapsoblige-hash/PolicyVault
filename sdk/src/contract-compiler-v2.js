"use strict";

/*
 * Exact live-state compiler for the PolicyVault v0.2 covenant.
 *
 * Same write-or-assert + silverc pipeline as the v0.1 compiler, for the
 * v0.2 field set: all 13 mutable initializers are templated with exact
 * live values; constructor args carry the template constants plus the
 * (baked-over) init values so the constant region stays deterministic.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { computeStateIdV2, CONTRACT_VERSION_V2 } = require("./vault-state-v2");

function fail(message) {
  throw new Error(`contract-compiler-v2: ${message}`);
}

function replaceExact(source, oldValue, newValue, label) {
  const matches = source.split(oldValue).length - 1;
  if (matches !== 1) {
    fail(`expected exactly one ${label} initializer, found ${matches}`);
  }
  return source.replace(oldValue, newValue);
}

function buildLiveStateSourceV2(originalSource, state) {
  let source = originalSource;
  const swaps = [
    ["int protectedValue = initValue;", `int protectedValue = ${state.protectedValue};`, "protectedValue"],
    ["int periodStartDaa = initPeriodStartDaa;", `int periodStartDaa = ${state.periodStartDaa};`, "periodStartDaa"],
    ["int periodSpent = 0;", `int periodSpent = ${state.periodSpent};`, "periodSpent"],
    ["int paused = 0;", `int paused = ${state.paused};`, "paused"],
    ["pubkey delegate = initDelegate;", `pubkey delegate = 0x${state.delegate};`, "delegate"],
    ["int maxPerSpend = initMaxPerSpend;", `int maxPerSpend = ${state.maxPerSpend};`, "maxPerSpend"],
    ["int periodBudget = initPeriodBudget;", `int periodBudget = ${state.periodBudget};`, "periodBudget"],
    ["int periodLengthDaa = initPeriodLengthDaa;", `int periodLengthDaa = ${state.periodLengthDaa};`, "periodLengthDaa"],
    ["pubkey recipient1 = initRecipient1;", `pubkey recipient1 = 0x${state.recipients[0]};`, "recipient1"],
    ["pubkey recipient2 = initRecipient2;", `pubkey recipient2 = 0x${state.recipients[1]};`, "recipient2"],
    ["pubkey recipient3 = initRecipient3;", `pubkey recipient3 = 0x${state.recipients[2]};`, "recipient3"],
    ["int delegateActive = 1;", `int delegateActive = ${state.delegateActive};`, "delegateActive"],
    ["int policyNonce = 0;", `int policyNonce = ${state.policyNonce};`, "policyNonce"]
  ];
  for (const [oldValue, newValue, label] of swaps) {
    source = replaceExact(source, oldValue, newValue, label);
  }
  return source;
}

function intArg(value, field) {
  if (typeof value !== "bigint") {
    fail(`${field} must be BigInt`);
  }
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${field} exceeds the safe constructor-arg integer range`);
  }
  return { kind: "int", data: Number(value) };
}

function bytesArg(hex, field) {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) {
    fail(`${field} must be lowercase hex`);
  }
  const data = [];
  for (let i = 0; i < hex.length; i += 2) {
    data.push({ kind: "byte", data: parseInt(hex.slice(i, i + 2), 16) });
  }
  return { kind: "array", data };
}

/*
 * v0.2 constructor: owner, vaultId, initDelegate, initMaxPerSpend,
 * initPeriodBudget, initPeriodLengthDaa, initRecipient1..3, initValue,
 * initPeriodStartDaa. The init* values are baked over by the state
 * templating; passing the live values keeps the arg file deterministic
 * per state.
 */
function constructorArgsV2(template, state) {
  return [
    bytesArg(template.owner, "owner"),
    bytesArg(template.vaultId, "vaultId"),
    bytesArg(state.delegate, "initDelegate"),
    intArg(state.maxPerSpend, "initMaxPerSpend"),
    intArg(state.periodBudget, "initPeriodBudget"),
    intArg(state.periodLengthDaa, "initPeriodLengthDaa"),
    bytesArg(state.recipients[0], "initRecipient1"),
    bytesArg(state.recipients[1], "initRecipient2"),
    bytesArg(state.recipients[2], "initRecipient3"),
    intArg(state.protectedValue, "initValue"),
    intArg(state.periodStartDaa, "initPeriodStartDaa")
  ];
}

function writeExactOrAssert(filePath, contents) {
  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, "utf8");
    if (existing !== contents) {
      fail(`refusing to reuse a state file with different deterministic contents: ${filePath}`);
    }
    return false;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
  return true;
}

function runSilverc({ silvercPath, sourcePath, constructorArgsPath, outputPath }) {
  if (!fs.existsSync(silvercPath)) {
    fail(`silverc not found: ${silvercPath}`);
  }
  const result = spawnSync(silvercPath, [sourcePath, "--constructor-args", constructorArgsPath, "--output", outputPath], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024
  });
  if (result.status !== 0 || !fs.existsSync(outputPath)) {
    fail(
      ["silverc v0.2 state compilation failed", `source: ${sourcePath}`, `exit: ${result.status}`, result.stdout?.trim() ?? "", result.stderr?.trim() ?? ""]
        .filter(Boolean)
        .join("\n")
    );
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function compileExactStateV2({ config, template, state }) {
  const stateId = computeStateIdV2({ networkId: config.networkId, template, state });
  const buildDir = path.join(config.dataRoot, "build-v2", stateId);

  const contractSource = path.join(config.repoRoot, "contracts/PolicyVault.v0.2.sil");
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV2(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV2(template, state), null, 2) + "\n";

  const sourcePath = path.join(buildDir, "PolicyVault.state.sil");
  const argsPath = path.join(buildDir, "constructor-args.json");
  const artifactPath = path.join(buildDir, "artifact.json");

  writeExactOrAssert(sourcePath, liveSource);
  writeExactOrAssert(argsPath, argsJson);

  if (!fs.existsSync(artifactPath)) {
    runSilverc({ silvercPath: config.silvercPath, sourcePath, constructorArgsPath: argsPath, outputPath: artifactPath });
  }

  let artifact;
  try {
    artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  } catch (error) {
    fail(`corrupt compiled artifact at ${artifactPath}: ${error.message}`);
  }
  if (!Array.isArray(artifact.script) || !artifact.state_layout) {
    fail(`compiled artifact is missing script/state_layout: ${artifactPath}`);
  }

  const scriptBytes = Buffer.from(artifact.script);
  const layout = artifact.state_layout;
  if (!Number.isInteger(layout.start) || !Number.isInteger(layout.len) || layout.start < 0 || layout.start + layout.len > scriptBytes.length) {
    fail(`compiled artifact has an invalid state layout: ${JSON.stringify(layout)}`);
  }

  const prefix = scriptBytes.subarray(0, layout.start);
  const suffix = scriptBytes.subarray(layout.start + layout.len);
  const templateHash = sha256Hex(Buffer.concat([prefix, suffix]));

  return Object.freeze({
    contractVersion: CONTRACT_VERSION_V2,
    stateId,
    buildDir,
    artifactPath,
    scriptBytes,
    scriptHex: scriptBytes.toString("hex"),
    scriptSha256: sha256Hex(scriptBytes),
    stateLayout: Object.freeze({ start: layout.start, len: layout.len }),
    templateHash,
    contractName: artifact.contract_name,
    compilerVersion: artifact.compiler_version
  });
}

module.exports = {
  compileExactStateV2,
  buildLiveStateSourceV2,
  constructorArgsV2
};
