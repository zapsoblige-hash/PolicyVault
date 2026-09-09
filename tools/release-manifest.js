"use strict";

/*
 * tools/release-manifest.js — builds a `policyvault-release-manifest/1`
 * artifact-identity manifest from a release tree (TRACK 9 release signing;
 * docs/postlaunch/release-trust-model.md).
 *
 * Every hash this tool records is COMPUTED BY THIS TOOL from real bytes on
 * disk (see tools/lib/release-hashes.js for the exact algorithms) — the
 * caller never gets to assert a hash value directly. The only exceptions
 * are `--image-digest` and `--base-image-digest`: a container registry
 * digest and a resolved base-image digest are facts from a different
 * trust domain (Docker/the registry) that this tool has no way to
 * recompute without a Docker daemon; they are validated for SHAPE only
 * and the manifest records them as caller-supplied, non-self-computed
 * identity.
 *
 * Usage:
 *   node tools/release-manifest.js --tree <path> --commit <40-hex-sha>
 *     --version <string> [--out <path>]
 *     [--image-digest sha256:<hex>] [--archive <path-to-archive-file>]
 *     [--base-image-digest sha256:<hex>]
 *     [--vendor-kaspa-wasm <path>]  (default: <tree>/deploy/vendor/kaspa
 *                                    if present, else omitted -> null)
 *     [--timestamp <ISO-8601>]      (default: now)
 *     [--candidate-versions v0.7,...]     (default: v0.7 — the current
 *                                        non-frozen covenant lineage; v0.6
 *                                        is frozen since 2026-09-03)
 *
 * Writes the manifest as canonical JSON + a single trailing newline (the
 * EXACT bytes tools/release-sign.js signs and tools/release-verify.js
 * verifies — never a pretty-printed re-serialization) to --out, defaulting
 * to <tree>/../<version>.policyvault-release-manifest.json next to the
 * tree, and also prints it to stdout.
 */

const fs = require("fs");
const path = require("path");
const { hashTree, sha256File, covenantPath, DEFAULT_COVENANT_VERSIONS, DEFAULT_CANDIDATE_VERSIONS, DEFAULT_LOCKFILE_PATHS, IMAGE_DIGEST_RE, GIT_COMMIT_RE } = require("./lib/release-hashes");
const { manifestBytes, assertManifestShape } = require("./lib/release-manifest-schema");

function usageError(message) {
  console.error(`error: ${message}`);
  console.error("usage: node tools/release-manifest.js --tree <path> --commit <sha> --version <v> [--out <path>] [--image-digest sha256:...] [--archive <path>] [--base-image-digest sha256:...] [--vendor-kaspa-wasm <path>] [--timestamp <iso>] [--candidate-versions v0.7,...]");
  process.exit(2);
}

/* buildManifest is a LIBRARY function (imported directly by
 * tools/release-verify.js's tests and by other tooling) — it must throw on
 * invalid input, never call process.exit. Only the CLI entry point (main,
 * below) is allowed to exit the process. */
function inputError(message) {
  const e = new Error(message);
  e.code = "RELEASE_MANIFEST_INPUT_INVALID";
  return e;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) usageError(`--${key} requires a value`);
    out[key] = next;
    i++;
  }
  return out;
}

function buildManifest(opts) {
  const treeRoot = path.resolve(opts.tree);
  if (!fs.existsSync(treeRoot) || !fs.statSync(treeRoot).isDirectory()) throw inputError(`--tree ${opts.tree} is not a directory`);
  if (!opts.commit || !GIT_COMMIT_RE.test(opts.commit)) throw inputError("--commit must be a 40-hex (or 64-hex) git commit id");
  if (!opts.version) throw inputError("--version is required");

  const releaseTimestamp = opts.timestamp || new Date().toISOString();
  if (new Date(releaseTimestamp).toISOString() !== releaseTimestamp) throw inputError("--timestamp must be a canonical ISO-8601 UTC string, e.g. 2026-09-02T00:00:00.000Z");

  let archiveSha256 = null;
  if (opts.archive) {
    const abs = path.resolve(opts.archive);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) throw inputError(`--archive ${opts.archive} is not a file`);
    archiveSha256 = sha256File(abs);
  }

  let imageDigest = null;
  if (opts["image-digest"] !== undefined) {
    if (!IMAGE_DIGEST_RE.test(opts["image-digest"])) throw inputError("--image-digest must match sha256:<64hex>");
    imageDigest = opts["image-digest"];
  }

  let baseImageDigest = null;
  if (opts["base-image-digest"] !== undefined) {
    if (!IMAGE_DIGEST_RE.test(opts["base-image-digest"])) throw inputError("--base-image-digest must match sha256:<64hex>");
    baseImageDigest = opts["base-image-digest"];
  }

  const candidateVersions = new Set((opts["candidate-versions"] || DEFAULT_CANDIDATE_VERSIONS.join(",")).split(",").map((s) => s.trim()).filter(Boolean));

  const covenants = {};
  for (const version of DEFAULT_COVENANT_VERSIONS) {
    const rel = covenantPath(version);
    const abs = path.join(treeRoot, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue; // not every tree carries every version
    covenants[version] = { path: rel, sha256: sha256File(abs), label: candidateVersions.has(version) ? "candidate" : "frozen" };
  }
  if (Object.keys(covenants).length === 0) throw inputError(`no covenant files found under --tree at any of: ${DEFAULT_COVENANT_VERSIONS.map(covenantPath).join(", ")}`);

  const lockfiles = {};
  for (const rel of DEFAULT_LOCKFILE_PATHS) {
    const abs = path.join(treeRoot, rel);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) lockfiles[rel] = sha256File(abs);
  }

  let vendoredKaspaWasmHash = null;
  const vendorArg = opts["vendor-kaspa-wasm"];
  const vendorDefault = path.join(treeRoot, "deploy/vendor/kaspa");
  const vendorPath = vendorArg ? path.resolve(vendorArg) : vendorDefault;
  if (vendorArg || (fs.existsSync(vendorDefault) && fs.statSync(vendorDefault).isDirectory())) {
    if (!fs.existsSync(vendorPath) || !fs.statSync(vendorPath).isDirectory()) throw inputError(`--vendor-kaspa-wasm ${vendorArg} is not a directory`);
    vendoredKaspaWasmHash = hashTree(vendorPath);
  }

  const treeHash = hashTree(treeRoot);

  const manifest = {
    schema: "policyvault-release-manifest/1",
    version: opts.version,
    releaseTimestamp,
    sourceCommit: opts.commit,
    treeHash,
    archiveSha256,
    imageDigest,
    baseImageDigest,
    covenants,
    dependencies: { lockfiles, vendoredKaspaWasmHash },
    generator: { tool: "tools/release-manifest.js", nodeVersion: process.version }
  };
  assertManifestShape(manifest); // self-check before writing anything
  return manifest;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.tree) usageError("--tree is required");
  const manifest = buildManifest(opts);
  const bytes = manifestBytes(manifest);
  const outPath = opts.out ? path.resolve(opts.out) : path.resolve(path.dirname(path.resolve(opts.tree)), `${opts.version.replace(/[^A-Za-z0-9._-]/g, "_")}.policyvault-release-manifest.json`);
  fs.writeFileSync(outPath, bytes);
  process.stdout.write(bytes);
  console.error(`\nwrote ${outPath} (${bytes.length} bytes)`);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`release-manifest failed: ${e.message}`);
    process.exit(1);
  }
}

module.exports = { buildManifest };
