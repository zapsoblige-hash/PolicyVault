"use strict";

/*
 * kcc20/1 ASSET ADAPTER (SDK side): compiles the vendored KCC20 reference
 * program (contracts/vendor/kcc20-reference.sil, byte-exact copy of the
 * upstream example; sha256 pinned by core/assets/test/fixtures) for a given
 * family bound + token state through silverc, and PROVES the result against
 * consensus-visible bytes before anything uses it:
 *
 *   - the compiled template (prefix || suffix) must hash to the descriptor's
 *     pinned templateVmHashBlake2b256 under the pinned geometry
 *     (core/assets corroborateTemplate — standardness envelope included);
 *   - the compiled redeem for the token position's revealed state must
 *     reproduce the position UTXO's EXACT P2SH script public key.
 *
 * Any mismatch fails closed: "unsupported token program" — PolicyVault never
 * encodes a token call for bytes it cannot reproduce byte-for-byte.
 *
 * The family bound is NOT a descriptor field (carriage/encoding is an
 * execution concern): it is RESOLVED by compiling the vendored program at
 * bounds 1..15 (the standardness envelope) until the pinned template hash
 * matches — deterministic and cached per descriptor template.
 *
 * Status: IMPLEMENTED (SDK). Exercised end-to-end by the v5 SDK
 * production-byte integration (tests/vm/tests/v5_sdk_integration.rs).
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const assets = require("../../core/assets");
const { kcc20 } = assets;

const VENDORED_SOURCE_REL = "contracts/vendor/kcc20-reference.sil";
const VENDORED_SOURCE_SHA256 = "2b7d59b06c0f34461bb01ae32b642c13491dd5b90a7cb4d5b827fcebf389ef73";
const MAX_FAMILY_BOUND = 15; // MAX_STANDARD_P2SH_SIG_OPS: one checkSig per unrolled iteration

function fail(message, code) {
  const e = new Error(`token-program-kcc20: ${message}`);
  if (code) e.code = code;
  throw e;
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function vendoredSource(config) {
  const p = path.join(config.repoRoot, VENDORED_SOURCE_REL);
  const src = fs.readFileSync(p);
  if (sha256Hex(src) !== VENDORED_SOURCE_SHA256) {
    fail(`vendored KCC20 reference program at ${p} does not match the pinned sha256 — refusing to encode token calls from an unverified program`, "PROGRAM_DRIFT");
  }
  return { path: p, text: src.toString("utf8") };
}

function bytesArg(hex) {
  const data = [];
  for (let i = 0; i < hex.length; i += 2) data.push({ kind: "byte", data: parseInt(hex.slice(i, i + 2), 16) });
  return { kind: "array", data };
}

/* Constructor args of the reference program: (genesisPk, genesisAmount, genesisIdentifierType, genesisIsMinter, maxCovIns, maxCovOuts). */
function constructorArgsKcc20(state, familyBound) {
  const s = kcc20.normalizeState(state);
  if (s.amount > BigInt(Number.MAX_SAFE_INTEGER)) fail("token amount exceeds the safe constructor-arg integer range");
  return [
    bytesArg(s.ownerIdentifier),
    { kind: "int", data: Number(s.amount) },
    { kind: "byte", data: s.identifierType },
    { kind: "bool", data: s.isMinter },
    { kind: "int", data: familyBound },
    { kind: "int", data: familyBound }
  ];
}

function programBuildDir(config, familyBound, state) {
  const s = kcc20.normalizeState(state);
  const key = sha256Hex(Buffer.from(`kcc20/1\n${familyBound}\n${s.ownerIdentifier}\n${s.identifierType}\n${s.amount}\n${s.isMinter}`, "utf8"));
  return path.join(config.dataRoot, "build-kcc20", key);
}

function writeExactOrAssert(filePath, contents) {
  if (fs.existsSync(filePath)) {
    if (fs.readFileSync(filePath, "utf8") !== contents) fail(`refusing to reuse a build file with different deterministic contents: ${filePath}`);
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, contents, { mode: 0o600 });
}

/* Compile the reference program for (familyBound, state). Cached on disk by content key. */
function compileKcc20Program({ config, state, familyBound }) {
  if (!Number.isInteger(familyBound) || familyBound < 1 || familyBound > MAX_FAMILY_BOUND) fail(`familyBound must be 1..${MAX_FAMILY_BOUND}`);
  const src = vendoredSource(config);
  const dir = programBuildDir(config, familyBound, state);
  const sourcePath = path.join(dir, "KCC20.state.sil");
  const argsPath = path.join(dir, "constructor-args.json");
  const artifactPath = path.join(dir, "artifact.json");
  writeExactOrAssert(sourcePath, src.text);
  writeExactOrAssert(argsPath, JSON.stringify(constructorArgsKcc20(state, familyBound), null, 2) + "\n");
  if (!fs.existsSync(artifactPath)) {
    if (!fs.existsSync(config.silvercPath)) fail(`silverc not found: ${config.silvercPath}`);
    const r = spawnSync(config.silvercPath, [sourcePath, "--constructor-args", argsPath, "--output", artifactPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0 || !fs.existsSync(artifactPath)) fail(`silverc kcc20 compilation failed: ${r.stderr?.trim() ?? r.status}`);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const script = new Uint8Array(artifact.script);
  const layout = artifact.state_layout;
  const geometry = { prefixLen: layout.start, stateLen: layout.len, suffixLen: script.length - layout.start - layout.len };
  const parts = kcc20.splitRedeem(script, geometry);
  return Object.freeze({
    familyBound,
    buildDir: dir,
    sourcePath,
    constructorArgsPath: argsPath,
    scriptHex: kcc20.bytesToHex(script),
    prefixHex: kcc20.bytesToHex(parts.prefix),
    suffixHex: kcc20.bytesToHex(parts.suffix),
    stateHex: kcc20.bytesToHex(parts.state),
    geometry,
    templateVmHashBlake2b256: kcc20.templateVmHashHex(parts.prefix, parts.suffix),
    p2shSpkHex: kcc20.p2shSpkHex(script)
  });
}

const boundCache = new Map();

/*
 * Resolve the family bound of an accepted template by compiling the
 * reference program at bounds 1..15 until the pinned VM hash matches.
 * Fails closed when no bound reproduces the descriptor's template (a token
 * program this adapter does not support).
 */
function resolveFamilyBound({ config, descriptor, templateIndex = 0 }) {
  const validated = assets.validateAssetDescriptor(descriptor);
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (!tpl) fail(`templateIndex ${templateIndex} is not an accepted template`);
  const cacheKey = `${assets.computeDescriptorHash(validated)}:${templateIndex}`;
  if (boundCache.has(cacheKey)) return boundCache.get(cacheKey);
  for (let bound = 1; bound <= MAX_FAMILY_BOUND; bound++) {
    const program = compileKcc20Program({ config, state: kcc20.ZERO_STATE, familyBound: bound });
    if (program.geometry.prefixLen !== tpl.prefixLen || program.geometry.suffixLen !== tpl.suffixLen) continue;
    if (program.templateVmHashBlake2b256 !== tpl.templateVmHashBlake2b256) continue;
    /* full corroboration incl. the standardness envelope */
    assets.corroborateTemplate({ descriptor: validated, templateIndex, prefixHex: program.prefixHex, suffixHex: program.suffixHex });
    boundCache.set(cacheKey, bound);
    return bound;
  }
  fail("no family bound of the vendored KCC20 reference program reproduces the descriptor's accepted template — unsupported token program for the kcc20/1 adapter; failing closed", "UNSUPPORTED_TOKEN_PROGRAM");
}

/*
 * Compile the token position's exact redeem and PROVE it against the live
 * UTXO's script public key (production-byte rule) and the descriptor's
 * pinned template. Returns the verified program artifact.
 */
function verifiedTokenPosition({ config, descriptor, templateIndex = 0, state, scriptPublicKeyHex }) {
  const familyBound = resolveFamilyBound({ config, descriptor, templateIndex });
  const program = compileKcc20Program({ config, state, familyBound });
  const spk = String(scriptPublicKeyHex ?? "").toLowerCase();
  if (program.p2shSpkHex !== spk) {
    fail(
      "the token position's script public key does not equal the P2SH of the reference program compiled with the claimed state — stale/forged state or unsupported program; failing closed",
      "TOKEN_POSITION_SPK_MISMATCH"
    );
  }
  const validated = assets.validateAssetDescriptor(descriptor);
  const tpl = validated.acceptedTransferTemplates[templateIndex];
  if (program.templateVmHashBlake2b256 !== tpl.templateVmHashBlake2b256) fail("compiled template hash != descriptor pin", "TEMPLATE_HASH_MISMATCH");
  return Object.freeze({ ...program, state: kcc20.normalizeState(state) });
}

module.exports = {
  VENDORED_SOURCE_REL,
  VENDORED_SOURCE_SHA256,
  MAX_FAMILY_BOUND,
  compileKcc20Program,
  constructorArgsKcc20,
  resolveFamilyBound,
  verifiedTokenPosition
};
