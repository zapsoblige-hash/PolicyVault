"use strict";

/*
 * Exact live-state compiler for the PolicyVault v0.5 TOKEN CONTROLLER
 * covenant (contracts/PolicyVault.v0.5.sil). Same write-or-assert + silverc
 * pipeline as v0.4: the 4 mutable initializers are templated with exact live
 * values; the 10 constructor args carry the immutable pins (owner, vaultId,
 * descriptorHash, tokenCovenantId, templateVmHash, geometry) + the
 * (baked-over) init values so the constant region stays deterministic.
 * Field order/anchors match the PRODUCTION contract's declaration order;
 * any anchor mismatch fails closed. The controller's OWN template identity
 * (sha256 of its prefix||suffix, v0.4 convention) is returned as
 * templateHash; its in-VM blake2b identity is returned as
 * controllerVmHashBlake2b256 for verifiers that read the revealed redeem.
 *
 * Status: IMPLEMENTED (SDK). Exercised by sdk/test/contract-compiler-v5.test.js
 * only when silverc is available (REQUIREMENT_NOT_AVAILABLE otherwise).
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { computeStateIdV5, CONTRACT_VERSION_V5, resolveV5Abi, normalizeTemplateV5, normalizeStateV5 } = require("./vault-state-v5");
const { blake2bHex } = require("../../core/assets/blake2b");

function fail(message) {
  throw new Error(`contract-compiler-v5: ${message}`);
}

function replaceExact(source, oldValue, newValue, label) {
  const matches = source.split(oldValue).length - 1;
  if (matches !== 1) {
    fail(`expected exactly one ${label} initializer, found ${matches}`);
  }
  return source.replace(oldValue, newValue);
}

function buildLiveStateSourceV5(originalSource, state) {
  let source = originalSource;
  const swaps = [
    ["int feeReserve = initFeeReserve;", `int feeReserve = ${state.feeReserve};`, "feeReserve"],
    ["int paused = 0;", `int paused = ${state.paused};`, "paused"],
    ["byte[32] agentRoot = initAgentRoot;", `byte[32] agentRoot = 0x${state.agentRoot};`, "agentRoot"],
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
function smallIntArg(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) {
    fail(`${field} must be an integer 0..1000000`);
  }
  return { kind: "int", data: value };
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
 * v0.5 constructor (10 args, declaration order — vaultId at index 1, where
 * pv_call_encoder pulls boundVaultId from): owner, vaultId, descriptorHash,
 * tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen,
 * templateSuffixLen, initAgentRoot, initFeeReserve.
 */
function constructorArgsV5(template, state) {
  return [
    bytesArg(template.owner, "owner"),
    bytesArg(template.vaultId, "vaultId"),
    bytesArg(template.descriptorHash, "descriptorHash"),
    bytesArg(template.tokenCovenantId, "tokenCovenantId"),
    bytesArg(template.templateVmHash, "templateVmHash"),
    smallIntArg(template.templatePrefixLen, "templatePrefixLen"),
    smallIntArg(template.templateStateLen, "templateStateLen"),
    smallIntArg(template.templateSuffixLen, "templateSuffixLen"),
    bytesArg(state.agentRoot, "initAgentRoot"),
    intArg(state.feeReserve, "initFeeReserve")
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
    maxBuffer: 64 * 1024 * 1024
  });
  if (result.status !== 0 || !fs.existsSync(outputPath)) {
    fail(
      ["silverc v0.5 state compilation failed", `source: ${sourcePath}`, `exit: ${result.status}`, result.stdout?.trim() ?? "", result.stderr?.trim() ?? ""]
        .filter(Boolean)
        .join("\n")
    );
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function compileExactStateV5({ config, template: templateInput, state: stateInput, contractVersion }) {
  const abi = resolveV5Abi(contractVersion ?? CONTRACT_VERSION_V5);
  const template = normalizeTemplateV5(templateInput);
  const state = stateInput.recoveryParse === true ? stateInput : normalizeStateV5(stateInput);
  const stateId = computeStateIdV5({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV5(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV5(template, state), null, 2) + "\n";

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

  return Object.freeze({
    contractVersion: abi.version,
    stateId,
    buildDir,
    artifactPath,
    scriptBytes,
    scriptHex: scriptBytes.toString("hex"),
    scriptSha256: sha256Hex(scriptBytes),
    stateLayout: Object.freeze({ start: layout.start, len: layout.len }),
    templateHash: sha256Hex(Buffer.concat([prefix, suffix])),
    controllerVmHashBlake2b256: blake2bHex([new Uint8Array(prefix), new Uint8Array(suffix)], 32),
    contractName: artifact.contract_name,
    compilerVersion: artifact.compiler_version
  });
}

module.exports = {
  compileExactStateV5,
  buildLiveStateSourceV5,
  constructorArgsV5
};
