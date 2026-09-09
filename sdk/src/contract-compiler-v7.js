"use strict";
const { enforceBuildCacheBound, minimizeArtifactFile, touchCacheEntry } = require("./build-cache");

/*
 * Exact live-state compiler for BOTH v0.7 covenants:
 *   contracts/PolicyVault.v0.7-root.sil     (PolicyVaultOrgRoot)
 *   contracts/PolicyVault.v0.7-payment.sil  (PolicyVaultRootedToken)
 *
 * Same write-or-assert + silverc pipeline as v0.5/v0.6, with one structural
 * difference for the ROOT: its 18 state fields ARE constructor arguments, so
 * no source templating is needed at all — the source file is written into the
 * build directory verbatim and the live state is carried entirely by
 * constructor-args.json. The ROOTED PAYMENT profile keeps the frozen v0.5
 * anchors (feeReserve / paused / agentRoot / policyNonce) because the
 * generator delta never touched them.
 *
 * GEOMETRY IS CHECKED, NOT ASSUMED. Every root compile asserts the
 * compiler's own `state_layout.len` equals the measured constant
 * (rootStateLen = 467) and that the region's last 11 bytes are exactly the
 * TAIL the core serializer builds — because a rooted vault slices those
 * offsets in-VM, and a silent drift would make it slice the wrong bytes and
 * self-lock. Every rooted-vault compile asserts the pinned root geometry it
 * was given is self-consistent with a real compiled root.
 *
 * The controller's own template identity is returned two ways, as in v0.5:
 * `templateHash` (sha256 of prefix||suffix, the v0.4 application convention)
 * and `vmHashBlake2b256` (the in-VM blake2b-256 identity a verifier that
 * reads the revealed redeem must reproduce — for the ROOT this is exactly
 * the `rootTemplateVmHash` a rooted vault pins at genesis).
 *
 * Status: IMPLEMENTED (SDK). Exercised by sdk/test/contract-compiler-v7.test.js
 * when silverc is available (REQUIREMENT_NOT_AVAILABLE otherwise) and driven
 * end-to-end through the real engine by tests/vm/tests/v7_sdk_integration.rs.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const {
  CONTRACT_VERSION_V7_ROOT,
  ROOT_STATE_LEN_V7,
  ROOT_TAIL_LEN_V7,
  resolveV7RootAbi,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  computeRootStateIdV7,
  serializeRootStateHexV7,
  rootStateTailHexV7
} = require("../../core/model/vault-state-v7-root");
const { CONTRACT_VERSION_V7, resolveV7Abi, normalizeTemplateV7, normalizeStateV7, computeStateIdV7 } = require("../../core/model/vault-state-v7");
const { OWNER_SLOTS_V7 } = require("../../core/model/owner-set-v7");
const { blake2bHex } = require("../../core/assets/blake2b");

function fail(message, code) {
  const e = new Error(`contract-compiler-v7: ${message}`);
  if (code) e.code = code;
  throw e;
}

function replaceExact(source, oldValue, newValue, label) {
  const matches = source.split(oldValue).length - 1;
  if (matches !== 1) fail(`expected exactly one ${label} initializer, found ${matches}`);
  return source.replace(oldValue, newValue);
}

/* The frozen v0.5 anchors, carried unchanged by tools/gen_v7_payment.js. */
function buildLiveStateSourceV7(originalSource, state) {
  let source = originalSource;
  const swaps = [
    ["int feeReserve = initFeeReserve;", `int feeReserve = ${state.feeReserve};`, "feeReserve"],
    ["int paused = 0;", `int paused = ${state.paused};`, "paused"],
    ["byte[32] agentRoot = initAgentRoot;", `byte[32] agentRoot = 0x${state.agentRoot};`, "agentRoot"],
    ["int policyNonce = 0;", `int policyNonce = ${state.policyNonce};`, "policyNonce"]
  ];
  for (const [oldValue, newValue, label] of swaps) source = replaceExact(source, oldValue, newValue, label);
  return source;
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
function byteArg(value, field) {
  const v = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isInteger(v) || v < 0 || v > 255) fail(`${field} must be a single byte`);
  return { kind: "byte", data: v };
}
function bytesArg(hex, field) {
  if (typeof hex !== "string" || !/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) fail(`${field} must be lowercase hex`);
  const data = [];
  for (let i = 0; i < hex.length; i += 2) data.push({ kind: "byte", data: parseInt(hex.slice(i, i + 2), 16) });
  return { kind: "array", data };
}

/*
 * ROOT constructor (22 args, declaration order — orgId at index 0, where
 * pv_call_encoder pulls boundOrgId from): orgId, initOwner1..initOwner12,
 * initOwnerM, initEmergencyK, initRecoveryM, initFrozen, initRootNonce,
 * recoveryDelayDaa, successorPk, successionDelayDaa, rootMaxFeePerTx.
 */
function constructorArgsV7Root(template, state) {
  const nonce = Buffer.alloc(8);
  nonce.writeBigUInt64LE(state.rootNonce);
  const args = [bytesArg(template.orgId, "orgId")];
  for (let i = 0; i < OWNER_SLOTS_V7; i += 1) args.push(bytesArg(state.owners[i], `initOwner${i + 1}`));
  args.push(intArg(state.ownerM, "initOwnerM"));
  args.push(intArg(state.emergencyK, "initEmergencyK"));
  args.push(intArg(state.recoveryM, "initRecoveryM"));
  args.push(byteArg(state.frozen, "initFrozen"));
  args.push(bytesArg(nonce.toString("hex"), "initRootNonce"));
  args.push(intArg(template.recoveryDelayDaa, "recoveryDelayDaa"));
  args.push(bytesArg(template.successorPk, "successorPk"));
  args.push(intArg(template.successionDelayDaa, "successionDelayDaa"));
  args.push(intArg(template.rootMaxFeePerTx, "rootMaxFeePerTx"));
  return args;
}

/*
 * ROOTED PAYMENT constructor (15 args, declaration order — vaultId at index
 * 0, where pv_call_encoder pulls boundVaultId from; `pubkey owner` is REMOVED
 * relative to the frozen v0.5, which is why every later index shifts down by
 * one): vaultId, descriptorHash, tokenCovenantId, templateVmHash,
 * templatePrefixLen, templateStateLen, templateSuffixLen, orgRootCovenantId,
 * rootTemplateVmHash, rootPrefixLen, rootStateLen, rootSuffixLen, recoveryPk,
 * initAgentRoot, initFeeReserve.
 */
function constructorArgsV7(template, state) {
  return [
    bytesArg(template.vaultId, "vaultId"),
    bytesArg(template.descriptorHash, "descriptorHash"),
    bytesArg(template.tokenCovenantId, "tokenCovenantId"),
    bytesArg(template.templateVmHash, "templateVmHash"),
    smallIntArg(template.templatePrefixLen, "templatePrefixLen"),
    smallIntArg(template.templateStateLen, "templateStateLen"),
    smallIntArg(template.templateSuffixLen, "templateSuffixLen"),
    bytesArg(template.orgRootCovenantId, "orgRootCovenantId"),
    bytesArg(template.rootTemplateVmHash, "rootTemplateVmHash"),
    smallIntArg(template.rootPrefixLen, "rootPrefixLen"),
    smallIntArg(template.rootStateLen, "rootStateLen"),
    smallIntArg(template.rootSuffixLen, "rootSuffixLen"),
    bytesArg(template.recoveryPk, "recoveryPk"),
    bytesArg(state.agentRoot, "initAgentRoot"),
    intArg(state.feeReserve, "initFeeReserve")
  ];
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
  const result = spawnSync(silvercPath, [sourcePath, "--constructor-args", constructorArgsPath, "--output", outputPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0 || !fs.existsSync(outputPath)) {
    fail(["silverc v0.7 state compilation failed", `source: ${sourcePath}`, `exit: ${result.status}`, result.stdout?.trim() ?? "", result.stderr?.trim() ?? ""].filter(Boolean).join("\n"));
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

/* ------------------------------------------------------------------ */
/* the ORGANIZATIONAL ROOT                                             */
/* ------------------------------------------------------------------ */

function compileExactStateV7Root({ config, template: templateInput, state: stateInput, contractVersion }) {
  const abi = resolveV7RootAbi(contractVersion ?? CONTRACT_VERSION_V7_ROOT);
  const template = normalizeRootTemplateV7(templateInput);
  const state = normalizeRootStateV7(stateInput);
  if (state.boundOrgId !== template.orgId) {
    fail("state.boundOrgId != template.orgId — a root's bound identity is immutable; failing closed", "ORG_ID_MISMATCH");
  }
  const stateId = computeRootStateIdV7({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  /* The root needs NO source templating: its state IS its constructor args. */
  const liveSource = fs.readFileSync(contractSource, "utf8");
  const argsJson = JSON.stringify(constructorArgsV7Root(template, state), null, 2) + "\n";

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

  /* GEOMETRY GATE — a rooted vault slices these exact offsets in-VM. */
  if (d.geometry.stateLen !== ROOT_STATE_LEN_V7) {
    fail(`the compiler produced a ${d.geometry.stateLen}-byte root state region, but the pinned rootStateLen is ${ROOT_STATE_LEN_V7} — a rooted vault would slice the wrong bytes; failing closed`, "ROOT_STATE_LEN_DRIFT");
  }
  const expectedRegion = serializeRootStateHexV7(state);
  if (d.stateRegionHex !== expectedRegion) {
    fail("the compiled root state region does not equal the core serializer's bytes — the SDK and consensus would disagree on the live state; failing closed", "ROOT_STATE_REGION_DRIFT");
  }
  const expectedTail = rootStateTailHexV7({ frozen: state.frozen, rootNonce: state.rootNonce });
  if (d.stateRegionHex.slice(-ROOT_TAIL_LEN_V7 * 2) !== expectedTail) {
    fail("the compiled root state TAIL is not 0x01||frozen||0x08||nonce8 — the fixed-width tail the vault rebuilds has moved; failing closed", "ROOT_TAIL_DRIFT");
  }

  return Object.freeze({
    contractVersion: abi.version,
    kind: "orgRoot",
    stateId,
    buildDir,
    artifactPath,
    ...d,
    /* the identity a rooted vault pins at genesis as rootTemplateVmHash */
    rootTemplateVmHash: d.vmHashBlake2b256,
    rootPrefixLen: d.geometry.prefixLen,
    rootStateLen: d.geometry.stateLen,
    rootSuffixLen: d.geometry.suffixLen
  });
}

/*
 * The pins a rooted vault must carry to authorize against THIS root version.
 * Derived from a real compile so the geometry can never be typed by hand.
 */
function deriveRootPinsV7({ config, template, ownerSet, covenantId }) {
  const { genesisRootStateV7 } = require("../../core/model/vault-state-v7-root");
  const compiled = compileExactStateV7Root({ config, template, state: genesisRootStateV7({ template, ownerSet }) });
  return Object.freeze({
    orgRootCovenantId: covenantId,
    rootTemplateVmHash: compiled.rootTemplateVmHash,
    rootPrefixLen: compiled.rootPrefixLen,
    rootStateLen: compiled.rootStateLen,
    rootSuffixLen: compiled.rootSuffixLen
  });
}

/* ------------------------------------------------------------------ */
/* the ROOTED PAYMENT VAULT                                            */
/* ------------------------------------------------------------------ */

function compileExactStateV7({ config, template: templateInput, state: stateInput, contractVersion }) {
  const abi = resolveV7Abi(contractVersion ?? CONTRACT_VERSION_V7);
  const template = normalizeTemplateV7(templateInput);
  const state = stateInput.recoveryParse === true ? stateInput : normalizeStateV7(stateInput);
  const stateId = computeStateIdV7({ networkId: config.networkId, template, state, contractVersion: abi.version });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV7(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV7(template, state), null, 2) + "\n";

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
    kind: "rootedVault",
    stateId,
    buildDir,
    artifactPath,
    ...d,
    controllerVmHashBlake2b256: d.vmHashBlake2b256
  });
}

/*
 * Cross-check the root pins a rooted vault carries against a REAL compiled
 * root of the claimed template. Any drift means the vault would rebuild a
 * successor redeem the root will never produce — i.e. a permanently unusable
 * owner path — so it is refused at build time, never at spend time.
 */
function assertRootPinsMatchV7({ config, vaultTemplate, rootTemplate, rootOwnerSet }) {
  const t = normalizeTemplateV7(vaultTemplate);
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

/* ------------------------------------------------------------------ */
/* the ROOTED HD (hierarchical delegation) VAULT (Wave 2 Track D)       */
/* ------------------------------------------------------------------ */

/*
 * `contracts/PolicyVault.v0.7-payment-hd.sil` (contract
 * `PolicyVaultRootedTokenHD`, tools/gen_v7_payment_hd.js) — a candidate
 * additive sibling of `policyvault-0.7-payment`, NOT registered in
 * core/model/vault-state-v7.js's V7_ABIS (that module is shared with the
 * v0.7-payment lane and is left untouched). Its live-state anchors
 * (feeReserve/paused/agentRoot/policyNonce) and its 15-argument constructor
 * layout are byte-identical to v0.7-payment's (design record + readiness
 * record §3: "the ROOTED owner paths are carried over BYTE-IDENTICAL"), so
 * this block reuses buildLiveStateSourceV7/constructorArgsV7/
 * normalizeTemplateV7/normalizeStateV7 UNCHANGED and only supplies the HD
 * candidate's own contract name / source path / build subdirectory and a
 * local (application-identity-only, non-consensus-critical) state-ID
 * function, since `computeStateIdV7`/`resolveV7Abi` fail closed on any
 * contractVersion they do not recognize.
 *
 * Status: IMPLEMENTED. Production-byte proof: sdk/tools/gen-v7-hd-vectors.js
 * + tests/vm/tests/v7_hd_sdk_integration.rs.
 */
const CONTRACT_VERSION_V7_HD = "policyvault-0.7-payment-hd";
const V7_HD_ABI = Object.freeze({
  version: CONTRACT_VERSION_V7_HD,
  contractName: "PolicyVaultRootedTokenHD",
  contractRelPath: "contracts/PolicyVault.v0.7-payment-hd.sil",
  buildSubdir: "build-v7-payment-hd",
  rootAuthorized: true
});

function resolveV7HdAbi(contractVersion) {
  if (contractVersion !== undefined && contractVersion !== CONTRACT_VERSION_V7_HD) {
    fail(`unknown contract version ${JSON.stringify(contractVersion)} for the v0.7-payment-hd lineage — failing closed (no cross-version fallback)`, "UNKNOWN_VERSION");
  }
  return V7_HD_ABI;
}

/* Deterministic application-identity state ID (NOT consensus-critical —
 * mirrors computeStateIdV7's canonical-string shape with the HD contract
 * tag, so the two lineages can never collide on the same stateId). */
function computeStateIdV7Hd({ networkId, template, state }) {
  if (typeof networkId !== "string" || networkId.length === 0) fail("networkId is required for the state ID");
  const t = normalizeTemplateV7(template);
  const canonical = [
    "policyvault-state/v7-hd",
    `network:${networkId}`,
    `contract:${V7_HD_ABI.version}`,
    `vaultId:${t.vaultId}`,
    `descriptorHash:${t.descriptorHash}`,
    `tokenCovenantId:${t.tokenCovenantId}`,
    `templateVmHash:${t.templateVmHash}`,
    `templateGeometry:${t.templatePrefixLen}/${t.templateStateLen}/${t.templateSuffixLen}`,
    `orgRootCovenantId:${t.orgRootCovenantId}`,
    `rootTemplateVmHash:${t.rootTemplateVmHash}`,
    `rootGeometry:${t.rootPrefixLen}/${t.rootStateLen}/${t.rootSuffixLen}`,
    `recoveryPk:${t.recoveryPk}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `policyNonce:${state.policyNonce}`
  ].join("\n");
  return sha256Hex(Buffer.from(canonical, "utf8"));
}

function compileExactStateV7Hd({ config, template: templateInput, state: stateInput, contractVersion }) {
  const abi = resolveV7HdAbi(contractVersion);
  const template = normalizeTemplateV7(templateInput);
  const state = stateInput.recoveryParse === true ? stateInput : normalizeStateV7(stateInput);
  const stateId = computeStateIdV7Hd({ networkId: config.networkId, template, state });
  const buildDir = path.join(config.dataRoot, abi.buildSubdir, stateId);

  const contractSource = path.join(config.repoRoot, abi.contractRelPath);
  const originalSource = fs.readFileSync(contractSource, "utf8");
  const liveSource = buildLiveStateSourceV7(originalSource, state);
  const argsJson = JSON.stringify(constructorArgsV7(template, state), null, 2) + "\n";

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
    kind: "rootedHdVault",
    stateId,
    buildDir,
    artifactPath,
    ...d,
    controllerVmHashBlake2b256: d.vmHashBlake2b256
  });
}

module.exports = {
  compileExactStateV7Root,
  compileExactStateV7,
  deriveRootPinsV7,
  assertRootPinsMatchV7,
  constructorArgsV7Root,
  constructorArgsV7,
  buildLiveStateSourceV7,
  CONTRACT_VERSION_V7_HD,
  V7_HD_ABI,
  resolveV7HdAbi,
  computeStateIdV7Hd,
  compileExactStateV7Hd
};
