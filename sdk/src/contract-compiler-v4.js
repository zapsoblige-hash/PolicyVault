"use strict";

/*
 * Exact live-state compiler for the PolicyVault v0.4 covenant (FROZEN ABI).
 * Same write-or-assert + silverc pipeline as v0.1/v0.2/v0.3: the 16 mutable
 * initializers are templated with exact live values; the 17 constructor args
 * carry the template constants + the (baked-over) init values so the constant
 * region stays deterministic. Field order/anchors match the PRODUCTION
 * contract's declaration order. Any anchor mismatch fails closed.
 *
 * Low-level state/compiler layer only (Checkpoint C scope) — no high-level
 * transaction builders.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { computeStateIdV4, CONTRACT_VERSION_V4, MAX_APPROVERS, resolveV4Abi } = require("./vault-state-v4");

function fail(message) {
  throw new Error(`contract-compiler-v4: ${message}`);
}

function replaceExact(source, oldValue, newValue, label) {
  const matches = source.split(oldValue).length - 1;
  if (matches !== 1) {
    fail(`expected exactly one ${label} initializer, found ${matches}`);
  }
  return source.replace(oldValue, newValue);
}

function buildLiveStateSourceV4(originalSource, state) {
  let source = originalSource;
  const swaps = [
    ["int protectedValue = initValue;", `int protectedValue = ${state.protectedValue};`, "protectedValue"],
    ["int feeReserve = initFeeReserve;", `int feeReserve = ${state.feeReserve};`, "feeReserve"],
    ["int paused = 0;", `int paused = ${state.paused};`, "paused"],
    ["byte[32] agentRoot = initAgentRoot;", `byte[32] agentRoot = 0x${state.agentRoot};`, "agentRoot"]
  ];
  for (let i = 1; i <= MAX_APPROVERS; i++) {
    swaps.push([
      `pubkey approver${i} = initApprover${i};`,
      `pubkey approver${i} = 0x${state.approvers[i - 1]};`,
      `approver${i}`
    ]);
  }
  swaps.push(["int approvalM = initApprovalM;", `int approvalM = ${state.approvalM};`, "approvalM"]);
  swaps.push(["int policyNonce = 0;", `int policyNonce = ${state.policyNonce};`, "policyNonce"]);
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
 * v0.4 constructor (17 args, declaration order — vaultId at index 1, which
 * is where pv_call_encoder pulls boundVaultId from): owner, vaultId,
 * initAgentRoot, initFeeReserve, initApprover1..10, initApprovalM, initValue.
 */
function constructorArgsV4(template, state) {
  const args = [
    bytesArg(template.owner, "owner"),
    bytesArg(template.vaultId, "vaultId"),
    bytesArg(state.agentRoot, "initAgentRoot"),
    intArg(state.feeReserve, "initFeeReserve")
  ];
  for (let i = 0; i < MAX_APPROVERS; i++) {
    args.push(bytesArg(state.approvers[i], `initApprover${i + 1}`));
  }
  args.push(intArg(state.approvalM, "initApprovalM"));
  args.push(intArg(state.protectedValue, "initValue"));
  return args;
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
      ["silverc v0.4 state compilation failed", `source: ${sourcePath}`, `exit: ${result.status}`, result.stdout?.trim() ?? "", result.stderr?.trim() ?? ""]
        .filter(Boolean)
        .join("\n")
    );
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function compileExactStateV4({ config, template, state, contractVersion }) {
  if (!Array.isArray(state.approvers) || state.approvers.length !== MAX_APPROVERS) {
    fail(`state.approvers must be the normalized ${MAX_APPROVERS}-slot layout`);
  }
  // Resolve the version-ABI (default v0.4 preserves every existing artifact
  // path and stateId exactly). The state templating + constructor args are
  // byte-identical across v0.4 and v0.4.1, so only the source file, build
  // subdir, and version label differ.
  const abi = resolveV4Abi(contractVersion);
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV4(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV4(template, state), null, 2) + "\n";

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
    contractVersion: abi.version,
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
  compileExactStateV4,
  buildLiveStateSourceV4,
  constructorArgsV4
};
