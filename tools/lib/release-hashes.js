"use strict";

/*
 * Shared, zero-dependency hashing/identity helpers for the release-signing
 * tool family (tools/release-manifest.js, tools/release-sign.js,
 * tools/release-verify.js — TRACK 9, docs/postlaunch/release-trust-model.md).
 *
 * Every hash in a release manifest must be SELF-COMPUTED by these tools
 * from real bytes on disk — never accepted as a bare string the caller
 * asserts (that would defeat the point of an artifact-identity manifest).
 * The two exceptions are values this tooling structurally cannot compute
 * itself because they come from a different trust domain at build time
 * (a container registry's content-addressed digest, a base image's
 * resolved digest) — those are still validated for SHAPE, never trusted
 * for correctness beyond that; the manifest labels them as caller-supplied.
 *
 * treeHash algorithm (deliberately NOT git's internal tree-object format,
 * so it never depends on a local `git` binary or git's object encoding):
 *   1. Recursively list every regular file under the root, excluding a
 *      top-level or nested ".git" directory by name.
 *   2. For each file, compute sha256 of its raw bytes.
 *   3. Build lines "<posix-relative-path>:<sha256hex>", one per file,
 *      relative paths using "/" regardless of platform.
 *   4. Sort the lines byte-wise (plain JS string sort on the exact line).
 *   5. treeHash = sha256(utf8 bytes of the lines joined by "\n", plus a
 *      trailing "\n").
 * Symlinks are refused (fail closed) rather than silently followed or
 * skipped — a symlink inside a release tree is either unintended or a
 * potential escape, and this tool never guesses which.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function sha256Bytes(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

/* Recursively collect "<posixRelPath>:<sha256hex>" lines under root. */
function collectFileHashLines(root, dir, lines) {
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      throw hashError(`symlink present under the hashed tree: ${path.relative(root, path.join(dir, entry.name))} — refusing (fail closed)`);
    }
    if (entry.isDirectory()) {
      if (entry.name === ".git") continue; // checkout mechanism, not content
      collectFileHashLines(root, path.join(dir, entry.name), lines);
      continue;
    }
    if (!entry.isFile()) {
      throw hashError(`unsupported filesystem entry type under the hashed tree: ${path.relative(root, path.join(dir, entry.name))} — refusing (fail closed)`);
    }
    const abs = path.join(dir, entry.name);
    const rel = path.relative(root, abs).split(path.sep).join("/");
    lines.push(`${rel}:${sha256File(abs)}`);
  }
}

function hashError(message) {
  const e = new Error(`release-hashes: ${message}`);
  e.code = "RELEASE_HASH_INVALID";
  return e;
}

/* Deterministic content hash of an entire directory tree. See algorithm
 * doc above. Throws RELEASE_HASH_INVALID if `root` is not a directory. */
function hashTree(root) {
  const st = statOrNull(root);
  if (!st || !st.isDirectory()) throw hashError(`--tree ${JSON.stringify(root)} is not a directory`);
  const lines = [];
  collectFileHashLines(root, root, lines);
  lines.sort();
  return sha256Bytes(Buffer.from(lines.join("\n") + "\n", "utf8"));
}

function statOrNull(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

/* Known covenant source files, relative to a release tree root. v0.6 is
 * carried as a labelled CANDIDATE (not byte-frozen) by default — override
 * with --candidate-versions if the freeze status of a version changes;
 * this tool never silently asserts "frozen" for a version the caller has
 * not explicitly excluded from the candidate list. */
const DEFAULT_COVENANT_VERSIONS = ["v0.1.beta", "v0.2", "v0.3", "v0.4", "v0.4.1", "v0.5", "v0.6"];
const DEFAULT_CANDIDATE_VERSIONS = ["v0.7"]; // v0.6 was COVENANT-BYTE-FROZEN 2026-09-03 (docs/postlaunch/v0.6-covenant-byte-freeze.md); v0.7 is the current candidate lineage

function covenantPath(version) {
  return `contracts/PolicyVault.${version}.sil`;
}

/* Known package-lock.json locations, relative to a release tree root.
 * Only paths that actually exist in the given tree are included in the
 * manifest — a missing sub-package lockfile is not an error (not every
 * release tree carries every workspace). */
const DEFAULT_LOCKFILE_PATHS = ["sdk/package-lock.json", "mobile/package-lock.json", "server/package-lock.json", "mcp/package-lock.json", "integrations/package-lock.json", "web/package-lock.json"];

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const GIT_COMMIT_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/; // 40-hex (sha1) or 64-hex (future sha256 git)
const SSH_PUBLIC_KEY_RE = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) [A-Za-z0-9+/]+=*$/;
const UNFILLED_PLACEHOLDER = "OWNER-TO-FILL";

module.exports = {
  sha256Bytes,
  sha256File,
  hashTree,
  hashError,
  covenantPath,
  DEFAULT_COVENANT_VERSIONS,
  DEFAULT_CANDIDATE_VERSIONS,
  DEFAULT_LOCKFILE_PATHS,
  SHA256_HEX_RE,
  IMAGE_DIGEST_RE,
  GIT_COMMIT_RE,
  SSH_PUBLIC_KEY_RE,
  UNFILLED_PLACEHOLDER
};
