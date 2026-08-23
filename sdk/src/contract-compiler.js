"use strict";

/*
 * Exact live-state compiler for the PolicyVault covenant.
 *
 * For a given (policy, state) pair this module:
 *   1. templates the exact state values into the .sil state initializers
 *      (asserting exactly one match per replacement);
 *   2. writes the deterministic source + constructor args under
 *      data/build/<stateId>/ with write-or-assert semantics;
 *   3. runs silverc with the constructor args;
 *   4. returns the parsed artifact (script bytes, state layout) plus
 *      deterministic identities.
 *
 * Proven pattern from JobVault contract-compiler-v04.js, rewritten for the
 * PolicyVault state tuple.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { computeStateId } = require("./vault-state");

function fail(message) {
  throw new Error(`contract-compiler: ${message}`);
}

function replaceExact(source, oldValue, newValue, label) {
  const matches = source.split(oldValue).length - 1;
  if (matches !== 1) {
    fail(`expected exactly one ${label} initializer, found ${matches}`);
  }
  return source.replace(oldValue, newValue);
}

function buildLiveStateSource(originalSource, state) {
  let source = originalSource;
  source = replaceExact(
    source,
    "int protectedValue =\n        initValue;",
    `int protectedValue =\n        ${state.protectedValue};`,
    "protectedValue"
  );
  source = replaceExact(
    source,
    "int periodStartDaa =\n        initPeriodStartDaa;",
    `int periodStartDaa =\n        ${state.periodStartDaa};`,
    "periodStartDaa"
  );
  source = replaceExact(source, "int periodSpent = 0;", `int periodSpent = ${state.periodSpent};`, "periodSpent");
  source = replaceExact(source, "int paused = 0;", `int paused = ${state.paused};`, "paused");
  return source;
}

/*
 * silverc constructor args use typed Expr JSON. Integers ride as JSON
 * numbers, so any value above Number.MAX_SAFE_INTEGER would silently lose
 * precision — fail closed instead. (2^53-1 sompi ≈ 90M KAS per vault;
 * documented limitation of v0.1.)
 */
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

function constructorArgs(policy) {
  return [
    bytesArg(policy.owner, "owner"),
    bytesArg(policy.delegate, "delegate"),
    bytesArg(policy.vaultId, "vaultId"),
    intArg(policy.maxPerSpend, "maxPerSpend"),
    intArg(policy.periodBudget, "periodBudget"),
    intArg(policy.periodLengthDaa, "periodLengthDaa"),
    bytesArg(policy.recipients[0], "recipient1"),
    bytesArg(policy.recipients[1], "recipient2"),
    bytesArg(policy.recipients[2], "recipient3"),
    intArg(policy.initValue, "initValue"),
    intArg(policy.initPeriodStartDaa, "initPeriodStartDaa")
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
  const result = spawnSync(
    silvercPath,
    [sourcePath, "--constructor-args", constructorArgsPath, "--output", outputPath],
    { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }
  );
  if (result.status !== 0 || !fs.existsSync(outputPath)) {
    fail(
      [
        "silverc state compilation failed",
        `source: ${sourcePath}`,
        `exit: ${result.status}`,
        result.stdout?.trim() ?? "",
        result.stderr?.trim() ?? ""
      ]
        .filter(Boolean)
        .join("\n")
    );
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/*
 * Compile the exact live state. Returns:
 *   stateId, buildDir, scriptBytes (Buffer), scriptHex, stateLayout,
 *   templateHash (sha256 of prefix+suffix — the policy identity of the
 *   compiled template, app-level), artifactPath.
 */
function compileExactState({ config, policy, state }) {
  const stateId = computeStateId({ networkId: config.networkId, policy, state });
  const buildDir = path.join(config.dataRoot, "build", stateId);

  const originalSource = fs.readFileSync(config.contractSource, "utf8");
  const liveSource = buildLiveStateSource(originalSource, state);
  const argsJson = JSON.stringify(constructorArgs(policy), null, 2) + "\n";

  const sourcePath = path.join(buildDir, "PolicyVault.state.sil");
  const argsPath = path.join(buildDir, "constructor-args.json");
  const artifactPath = path.join(buildDir, "artifact.json");

  writeExactOrAssert(sourcePath, liveSource);
  writeExactOrAssert(argsPath, argsJson);

  if (!fs.existsSync(artifactPath)) {
    runSilverc({
      silvercPath: config.silvercPath,
      sourcePath,
      constructorArgsPath: argsPath,
      outputPath: artifactPath
    });
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
  if (
    !Number.isInteger(layout.start) ||
    !Number.isInteger(layout.len) ||
    layout.start < 0 ||
    layout.start + layout.len > scriptBytes.length
  ) {
    fail(`compiled artifact has an invalid state layout: ${JSON.stringify(layout)}`);
  }

  const prefix = scriptBytes.subarray(0, layout.start);
  const suffix = scriptBytes.subarray(layout.start + layout.len);
  const templateHash = sha256Hex(Buffer.concat([prefix, suffix]));

  return Object.freeze({
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
  compileExactState,
  buildLiveStateSource,
  constructorArgs
};
