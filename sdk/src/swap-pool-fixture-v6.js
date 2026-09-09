"use strict";
const { enforceBuildCacheBound, minimizeArtifactFile, touchCacheEntry } = require("./build-cache");

/*
 * v0.6 POOL FIXTURE program helper — compiles the constant-product pool
 * fixture (contracts/experiments/V6PoolFixture.sil) at an exact live state
 * so PolicyVault's swap builder can (a) PROVE a live pool UTXO is the
 * owner-approved venue (template identity + geometry + P2SH reproduce the
 * chain), (b) compute the pool's successor script, and (c) encode the
 * pool's own covenant call through the deterministic encoder.
 *
 * NOT A POLICYVAULT PRODUCT. The fixture is the approved venue of the VM
 * suite and the testnet-10 live proof only (test assets). A production
 * venue would ship its own profile-described program; PolicyVault never
 * runs pools, never holds liquidity, never market-makes. Everything here is
 * derived from the venue profile's protocol facts and the owner's swap
 * policy leaf; nothing is trusted from a DEX API or indexer.
 *
 * Status: IMPLEMENTED (SDK; fixture-only). Production-byte proof:
 * tests/vm/tests/v6_sdk_integration.rs executes SDK-built swaps whose pool
 * bytes come from this module.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { parseAtomicAmount } = require("../../core/model/token-amounts");
const { blake2bHex } = require("../../core/assets/blake2b");

const POOL_FIXTURE_REL = "contracts/experiments/V6PoolFixture.sil";
const POOL_FIXTURE_VERSION = "v6-pool-fixture/1";
const POOL_STATE_LEN = 36;

function fail(message, code) {
  const e = new Error(`swap-pool-fixture-v6: ${message}`);
  if (code) e.code = code;
  throw e;
}
function bytesArg(hex, field) {
  if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) fail(`${field} must be lowercase hex`);
  const data = [];
  for (let i = 0; i < hex.length; i += 2) data.push({ kind: "byte", data: parseInt(hex.slice(i, i + 2), 16) });
  return { kind: "array", data };
}
function intArg(value, field) {
  const n = typeof value === "bigint" ? value : BigInt(value);
  if (n < 0n || n > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${field} out of the safe constructor-arg range`);
  return { kind: "int", data: Number(n) };
}
function writeExactOrAssert(filePath, contents) {
  if (fs.existsSync(filePath)) {
    if (fs.readFileSync(filePath, "utf8") !== contents) fail(`refusing to reuse a build file with different deterministic contents: ${filePath}`);
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
}

function normalizePoolParams(input) {
  if (!input || typeof input !== "object") fail("pool params are required");
  const kcc20 = input.kcc20;
  if (!kcc20 || typeof kcc20 !== "object") fail("params.kcc20 { prefixHex, suffixHex, templateVmHashBlake2b256 } is required");
  const prefixHex = String(kcc20.prefixHex ?? "").toLowerCase();
  const suffixHex = String(kcc20.suffixHex ?? "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(prefixHex) || !/^[0-9a-f]+$/.test(suffixHex) || prefixHex.length % 2 || suffixHex.length % 2) fail("kcc20 prefix/suffix must be hex");
  const expectHash = normalizeHex(kcc20.templateVmHashBlake2b256, 32, "params.kcc20.templateVmHashBlake2b256");
  const computed = blake2bHex([Buffer.from(prefixHex, "hex"), Buffer.from(suffixHex, "hex")], 32);
  if (computed !== expectHash) fail("kcc20 template bytes do not hash to the declared templateVmHashBlake2b256 — failing closed", "TEMPLATE_HASH_MISMATCH");
  const feeBps = parseSompi(input.feeBps, "params.feeBps");
  const protocolFeeBps = parseSompi(input.protocolFeeBps, "params.protocolFeeBps");
  if (feeBps >= 10_000n || protocolFeeBps > 10_000n) fail("fee bps out of range");
  return Object.freeze({
    tokenCovenantId: normalizeHex(input.tokenCovenantId, 32, "params.tokenCovenantId"),
    kcc20: Object.freeze({ prefixHex, suffixHex, templateVmHashBlake2b256: expectHash }),
    protocolFeePk: normalizeXOnlyPubkey(input.protocolFeePk, "params.protocolFeePk"),
    protocolFeeBps,
    kasReserve: parsePositiveSompi(input.kasReserve, "params.kasReserve"),
    tokenReserve: parseAtomicAmount(input.tokenReserve, "params.tokenReserve"),
    feeBps,
    nonce: parseSompi(input.nonce ?? 0n, "params.nonce")
  });
}

function constructorArgsPool(p) {
  return [
    bytesArg(p.tokenCovenantId, "tokenId"),
    intArg(p.kcc20.prefixHex.length / 2, "kcc20PrefixLen"),
    intArg(p.kcc20.suffixHex.length / 2, "kcc20SuffixLen"),
    bytesArg(p.kcc20.templateVmHashBlake2b256, "kcc20Hash"),
    bytesArg(p.kcc20.prefixHex, "kcc20Prefix"),
    bytesArg(p.kcc20.suffixHex, "kcc20Suffix"),
    bytesArg(p.protocolFeePk, "protocolFeePk"),
    intArg(p.protocolFeeBps, "protocolFeeBps"),
    intArg(p.kasReserve, "initKasReserve"),
    intArg(p.tokenReserve, "initTokenReserve"),
    intArg(p.feeBps, "initFeeBps"),
    intArg(p.nonce, "initNonce")
  ];
}

/* Deterministic pool-state id (application identity). */
function poolStateId(p) {
  const canonical = [
    POOL_FIXTURE_VERSION,
    `token:${p.tokenCovenantId}`,
    `kcc20:${p.kcc20.templateVmHashBlake2b256}/${p.kcc20.prefixHex.length / 2}/${p.kcc20.suffixHex.length / 2}`,
    `feePk:${p.protocolFeePk}`,
    `protoBps:${p.protocolFeeBps}`,
    `kas:${p.kasReserve}`,
    `tok:${p.tokenReserve}`,
    `feeBps:${p.feeBps}`,
    `nonce:${p.nonce}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function compilePoolFixtureV6({ config, params }) {
  const p = normalizePoolParams(params);
  const id = poolStateId(p);
  const dir = path.join(config.dataRoot, "build-v6-pool", id);
  const sourceRel = POOL_FIXTURE_REL;
  const original = fs.readFileSync(path.join(config.repoRoot, sourceRel), "utf8");
  const sourcePath = path.join(dir, "V6PoolFixture.state.sil");
  const argsPath = path.join(dir, "constructor-args.json");
  const artifactPath = path.join(dir, "artifact.json");
  writeExactOrAssert(sourcePath, original);
  writeExactOrAssert(argsPath, JSON.stringify(constructorArgsPool(p), null, 2) + "\n");
  if (!fs.existsSync(artifactPath)) {
    if (!fs.existsSync(config.silvercPath)) fail(`silverc not found: ${config.silvercPath}`);
    enforceBuildCacheBound(config, { keep: dir }); // F-03: bounded cache, LRU eviction, never ENOSPC
    const r = spawnSync(config.silvercPath, [sourcePath, "--constructor-args", argsPath, "--output", artifactPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0 || !fs.existsSync(artifactPath)) fail(`silverc pool fixture compilation failed: ${r.stderr?.trim() ?? r.status}`);
    minimizeArtifactFile(artifactPath, config); // F-03
  } else {
    touchCacheEntry(artifactPath);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  if (!Array.isArray(artifact.script) || !artifact.state_layout) fail("corrupt pool artifact");
  const script = Buffer.from(artifact.script);
  const layout = artifact.state_layout;
  if (layout.len !== POOL_STATE_LEN) fail(`pool fixture state length ${layout.len} != ${POOL_STATE_LEN} — failing closed`);
  const prefix = script.subarray(0, layout.start);
  const suffix = script.subarray(layout.start + layout.len);
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const p2shSpkHex = String(kaspa.payToScriptHashScript(script.toString("hex")).script).toLowerCase();
  return Object.freeze({
    fixtureVersion: POOL_FIXTURE_VERSION,
    sourceRel,
    sourceSha256: crypto.createHash("sha256").update(original, "utf8").digest("hex"),
    stateId: id,
    params: p,
    sourcePath,
    constructorArgsPath: argsPath,
    scriptHex: script.toString("hex"),
    scriptSha256: crypto.createHash("sha256").update(script).digest("hex"),
    p2shSpkHex,
    geometry: Object.freeze({ prefixLen: layout.start, stateLen: layout.len, suffixLen: suffix.length }),
    templateVmHashBlake2b256: blake2bHex([new Uint8Array(prefix), new Uint8Array(suffix)], 32),
    templateHashSha256: crypto.createHash("sha256").update(Buffer.concat([prefix, suffix])).digest("hex")
  });
}

/* The venue profile (protocol facts only) that DESCRIBES a fixture pool family. */
function poolFixtureVenueProfile({ networkId, poolCovenantId, compiled, profileId }) {
  return {
    profileVersion: "policyvault-swap-venue-profile/1",
    profileId: profileId ?? `v6-pool-fixture:${poolCovenantId.slice(0, 16)}`,
    networkId,
    poolCovenantId,
    poolTemplateVmHashBlake2b256: compiled.templateVmHashBlake2b256,
    poolTemplateGeometry: { prefixLen: compiled.geometry.prefixLen, stateLen: compiled.geometry.stateLen, suffixLen: compiled.geometry.suffixLen },
    poolStateLayout: "constant-product-pool-state/1",
    tokenStandard: "kcc20-state/1",
    tokenCovenantId: compiled.params.tokenCovenantId,
    invariantModel: "constant-product-bps-fee/1",
    feeModel: { poolFeeBps: compiled.params.feeBps.toString(), protocolFeeBps: compiled.params.protocolFeeBps.toString(), protocolFeePk: compiled.params.protocolFeePk },
    requiredShape: { tokenFamilyInputs: 2, tokenFamilyOutputs: 2, poolInputs: 1, poolOutputs: 1, outputsTypeA: 5, outputsTypeB: 6 },
    signerSemantics: { sighash: "ALL", postSignIdentityVerification: true, poolOutpointBinding: "exact" },
    provenance: { sourceRelPath: compiled.sourceRel, sourceSha256: compiled.sourceSha256, reference: "PolicyVault v0.6 constant-product pool FIXTURE (test venue; not a product; not an endorsement of any venue)" }
  };
}

module.exports = { POOL_FIXTURE_REL, POOL_FIXTURE_VERSION, POOL_STATE_LEN, normalizePoolParams, constructorArgsPool, compilePoolFixtureV6, poolFixtureVenueProfile };
