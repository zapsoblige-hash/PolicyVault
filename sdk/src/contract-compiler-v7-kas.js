"use strict";
const { enforceBuildCacheBound, minimizeArtifactFile, touchCacheEntry } = require("./build-cache");

/*
 * Exact live-state compiler for contracts/PolicyVault.v0.7-kas.sil
 * (contract `PolicyVaultRootedKas`). Sibling of sdk/src/contract-compiler-v7.js's
 * "ROOTED PAYMENT VAULT" section, but the mutable STATE is byte-for-byte the
 * FROZEN v0.4.1 state (protectedValue, feeReserve, paused, agentRoot,
 * approver1..10, approvalM, policyNonce) — every state-templating anchor
 * (`int protectedValue = initValue;`, `int feeReserve = initFeeReserve;`,
 * `int paused = 0;`, `byte[32] agentRoot = initAgentRoot;`, the ten
 * `pubkey approverN = initApproverN;` lines, `int approvalM = initApprovalM;`,
 * `int policyNonce = 0;`) is carried UNCHANGED by tools/gen_v7_kas.js's
 * exact-match delta, so this module REUSES `buildLiveStateSourceV4`
 * (sdk/src/contract-compiler-v4.js) for the state-templating swap verbatim
 * — never re-implementing it — and adds ONLY the new 21-argument constructor
 * shape (`pubkey owner` REMOVED; the six root-pin template fields
 * `orgRootCovenantId, rootTemplateVmHash, rootPrefixLen, rootStateLen,
 * rootSuffixLen, recoveryPk` inserted before `initAgentRoot`).
 *
 * The ROOT side of a rooted-KAS transaction is UNCHANGED from the payment
 * profile (same `contracts/PolicyVault.v0.7-root.sil`): this module reuses
 * `compileExactStateV7Root` / `deriveRootPinsV7` from
 * sdk/src/contract-compiler-v7.js unmodified for anything that touches the
 * root — never re-implementing root compilation.
 *
 * Status: IMPLEMENTED (SDK). Production-byte proof:
 * sdk/tools/gen-v7-kas-vectors.js + tests/vm/tests/v7_kas_sdk_integration.rs
 * drive every SDK-built shape through the real engine.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { CONTRACT_VERSION_V7_KAS, resolveV7KasAbi, normalizeTemplateV7Kas, computeStateIdV7Kas } = require("../../core/model/vault-state-v7-kas");
const { MAX_APPROVERS } = require("../../core/model/vault-state-v4");
const { buildLiveStateSourceV4 } = require("./contract-compiler-v4");
const { compileExactStateV7Root, deriveRootPinsV7 } = require("./contract-compiler-v7");
const { blake2bHex } = require("../../core/assets/blake2b");

function fail(message, code) {
  const e = new Error(`contract-compiler-v7-kas: ${message}`);
  if (code) e.code = code;
  throw e;
}

function intArg(value, field) {
  const v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n || v > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${field} exceeds the safe constructor-arg integer range`);
  return { kind: "int", data: Number(v) };
}
function smallIntArg(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > 1_000_000) fail(`${field} must be an integer 0..1000000`);
  return { kind: "int", data: value };
}
function bytesArg(hex, field) {
  if (typeof hex !== "string" || !/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) fail(`${field} must be lowercase hex`);
  const data = [];
  for (let i = 0; i < hex.length; i += 2) data.push({ kind: "byte", data: parseInt(hex.slice(i, i + 2), 16) });
  return { kind: "array", data };
}

/*
 * v0.7-kas constructor (21 args, declaration order — vaultId at index 0,
 * where pv_call_encoder pulls boundVaultId from; `pubkey owner` is REMOVED
 * relative to the frozen v0.4.1, and six new root-pin fields are inserted
 * before initAgentRoot): vaultId, orgRootCovenantId, rootTemplateVmHash,
 * rootPrefixLen, rootStateLen, rootSuffixLen, recoveryPk, initAgentRoot,
 * initFeeReserve, initApprover1..10, initApprovalM, initValue.
 */
function constructorArgsV7Kas(template, state) {
  const args = [
    bytesArg(template.vaultId, "vaultId"),
    bytesArg(template.orgRootCovenantId, "orgRootCovenantId"),
    bytesArg(template.rootTemplateVmHash, "rootTemplateVmHash"),
    smallIntArg(template.rootPrefixLen, "rootPrefixLen"),
    smallIntArg(template.rootStateLen, "rootStateLen"),
    smallIntArg(template.rootSuffixLen, "rootSuffixLen"),
    bytesArg(template.recoveryPk, "recoveryPk"),
    bytesArg(state.agentRoot, "initAgentRoot"),
    intArg(state.feeReserve, "initFeeReserve")
  ];
  for (let i = 0; i < MAX_APPROVERS; i += 1) args.push(bytesArg(state.approvers[i], `initApprover${i + 1}`));
  args.push(intArg(state.approvalM, "initApprovalM"));
  args.push(intArg(state.protectedValue, "initValue"));
  return args;
}

function writeExactOrAssert(filePath, contents) {
  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, "utf8");
    if (existing !== contents) fail(`refusing to reuse a state file with different deterministic contents: ${filePath}`);
    return false;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
  return true;
}

function runSilverc({ silvercPath, sourcePath, constructorArgsPath, outputPath }) {
  if (!fs.existsSync(silvercPath)) fail(`silverc not found: ${silvercPath}`);
  const result = spawnSync(silvercPath, [sourcePath, "--constructor-args", constructorArgsPath, "--output", outputPath], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024
  });
  if (result.status !== 0 || !fs.existsSync(outputPath)) {
    fail(
      ["silverc v0.7-kas state compilation failed", `source: ${sourcePath}`, `exit: ${result.status}`, result.stdout?.trim() ?? "", result.stderr?.trim() ?? ""]
        .filter(Boolean)
        .join("\n")
    );
  }
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function readArtifact(artifactPath) {
  let artifact;
  try {
    artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  } catch (error) {
    fail(`corrupt compiled artifact at ${artifactPath}: ${error.message}`);
  }
  if (!Array.isArray(artifact.script) || !artifact.state_layout) fail(`compiled artifact is missing script/state_layout: ${artifactPath}`);
  const scriptBytes = Buffer.from(artifact.script);
  const layout = artifact.state_layout;
  if (!Number.isInteger(layout.start) || !Number.isInteger(layout.len) || layout.start < 0 || layout.start + layout.len > scriptBytes.length) {
    fail(`compiled artifact has an invalid state layout: ${JSON.stringify(layout)}`);
  }
  return { artifact, scriptBytes, layout };
}

function describe({ artifact, scriptBytes, layout }) {
  const prefix = scriptBytes.subarray(0, layout.start);
  const suffix = scriptBytes.subarray(layout.start + layout.len);
  return {
    scriptBytes,
    scriptHex: scriptBytes.toString("hex"),
    scriptSha256: sha256Hex(scriptBytes),
    stateLayout: Object.freeze({ start: layout.start, len: layout.len }),
    stateRegionHex: scriptBytes.subarray(layout.start, layout.start + layout.len).toString("hex"),
    prefixHex: prefix.toString("hex"),
    suffixHex: suffix.toString("hex"),
    templateHash: sha256Hex(Buffer.concat([prefix, suffix])),
    vmHashBlake2b256: blake2bHex([new Uint8Array(prefix), new Uint8Array(suffix)], 32),
    geometry: Object.freeze({ prefixLen: prefix.length, stateLen: layout.len, suffixLen: suffix.length }),
    contractName: artifact.contract_name,
    compilerVersion: artifact.compiler_version
  };
}

/*
 * `state` MUST already be normalized (via normalizeStateV7Kas /
 * normalizeStateV7KasForRecovery — BigInt fields, state.approvers the padded
 * 10-slot array) — exactly like contract-compiler-v4.js's compileExactStateV4,
 * which this module's state-templating half reuses verbatim.
 * Re-normalizing here would be UNSAFE: a normalized state's `approvers`
 * field is the padded 10-slot array (10 entries, sentinels included), which
 * normalizeStateV4 would otherwise misinterpret as the "active keys only"
 * input form and reject on the first sentinel slot (see the identical
 * warning in core/model/vault-transitions-v7-kas.js). Callers normalize
 * ONCE, at the SDK boundary, and every downstream function (transitions,
 * this compiler) trusts that shape.
 */
function compileExactStateV7Kas({ config, template: templateInput, state, contractVersion }) {
  const abi = resolveV7KasAbi(contractVersion ?? CONTRACT_VERSION_V7_KAS);
  const template = normalizeTemplateV7Kas(templateInput);
  if (!state || typeof state !== "object" || !Array.isArray(state.approvers) || state.approvers.length !== MAX_APPROVERS || typeof state.policyNonce !== "bigint") {
    fail("state must already be normalized via normalizeStateV7Kas/normalizeStateV7KasForRecovery (BigInt fields, padded approvers array) before compiling");
  }
  const stateId = computeStateIdV7Kas({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV4(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV7Kas(template, state), null, 2) + "\n";

  const sourcePath = path.join(buildDir, "PolicyVault.state.sil");
  const argsPath = path.join(buildDir, "constructor-args.json");
  const artifactPath = path.join(buildDir, "artifact.json");

  writeExactOrAssert(sourcePath, liveSource);
  writeExactOrAssert(argsPath, argsJson);
  if (!fs.existsSync(artifactPath)) {
    enforceBuildCacheBound(config, { keep: buildDir }); // F-03: bounded cache, LRU eviction, never ENOSPC
    runSilverc({ silvercPath: config.silvercPath, sourcePath, constructorArgsPath: argsPath, outputPath: artifactPath });
    minimizeArtifactFile(artifactPath, config); // F-03: keep only what consumers read (script/state_layout/name/version)
  } else {
    touchCacheEntry(artifactPath);
  }

  const parsed = readArtifact(artifactPath);
  const d = describe(parsed);
  if (d.contractName !== abi.contractName) fail(`compiled contract ${d.contractName} != ${abi.contractName}`, "CONTRACT_NAME_MISMATCH");

  return Object.freeze({
    contractVersion: abi.version,
    kind: "rootedKasVault",
    stateId,
    buildDir,
    artifactPath,
    ...d,
    controllerVmHashBlake2b256: d.vmHashBlake2b256
  });
}

/*
 * Cross-check the root pins a rooted KAS vault carries against a REAL
 * compiled root of the claimed template. Identical purpose to
 * assertRootPinsMatchV7 in contract-compiler-v7.js (which is reused
 * verbatim for the root side itself); this wrapper exists only because the
 * vault-side template shape (normalizeTemplateV7Kas) differs from the
 * payment profile's.
 */
function assertRootPinsMatchV7Kas({ config, vaultTemplate, rootTemplate, rootOwnerSet }) {
  const t = normalizeTemplateV7Kas(vaultTemplate);
  const { genesisRootStateV7 } = require("../../core/model/vault-state-v7-root");
  const compiled = compileExactStateV7Root({ config, template: rootTemplate, state: genesisRootStateV7({ template: rootTemplate, ownerSet: rootOwnerSet }) });
  const drift = [];
  if (compiled.rootTemplateVmHash !== t.rootTemplateVmHash) drift.push(`rootTemplateVmHash ${t.rootTemplateVmHash} != compiled ${compiled.rootTemplateVmHash}`);
  if (compiled.rootPrefixLen !== t.rootPrefixLen) drift.push(`rootPrefixLen ${t.rootPrefixLen} != compiled ${compiled.rootPrefixLen}`);
  if (compiled.rootStateLen !== t.rootStateLen) drift.push(`rootStateLen ${t.rootStateLen} != compiled ${compiled.rootStateLen}`);
  if (compiled.rootSuffixLen !== t.rootSuffixLen) drift.push(`rootSuffixLen ${t.rootSuffixLen} != compiled ${compiled.rootSuffixLen}`);
  if (drift.length) {
    fail(`the vault's pinned root template does not match a real compiled root: ${drift.join("; ")} — the owner path would be unusable; failing closed`, "ROOT_PIN_DRIFT");
  }
  return compiled;
}

module.exports = {
  compileExactStateV7Kas,
  assertRootPinsMatchV7Kas,
  constructorArgsV7Kas,
  /* re-exported so a caller never has to import contract-compiler-v7.js
   * directly just to derive root pins for a v0.7-kas genesis */
  deriveRootPinsV7
};
