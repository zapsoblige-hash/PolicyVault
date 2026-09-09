"use strict";

/*
 * tools/release-verify.js — verifies a `policyvault-release-manifest/1`
 * file against a checked-in `release-signers.json` policy and (optionally)
 * against a real tree/artifacts (TRACK 9 release signing; docs/postlaunch/
 * release-trust-model.md).
 *
 * Two independent checks, BOTH must pass:
 *   1. SIGNATURE POLICY: at least `threshold` DISTINCT, currently-valid,
 *      non-revoked, non-placeholder signers (per release-signers.json)
 *      produced a cryptographically valid `ssh-keygen -Y verify` result
 *      over the exact manifest bytes, under the fixed namespace.
 *   2. HASH RE-VERIFICATION (only for whichever of --tree/--archive is
 *      given): every self-computable hash the manifest claims is
 *      recomputed FROM SCRATCH and compared byte-for-byte. A manifest
 *      that signs correctly but whose claimed hashes do not match the
 *      real tree is NOT a passing verification — the signature only
 *      proves who published the claim, not that the claim is true.
 *
 * This is multi-signer CAPABLE today (arbitrary N signatures, threshold
 * configurable in the policy file) even though the checked-in policy
 * currently lists exactly one real signer. See docs/postlaunch/
 * release-trust-model.md for why, and for the one-signer-to-multi-signer
 * transition plan.
 *
 * Usage:
 *   node tools/release-verify.js --manifest <path> --policy <path>
 *     [--sig-dir <dir>]          (default: dirname(manifest); auto-discovers
 *                                 <manifest>.sig.<signerId> files)
 *     [--tree <path>] [--archive <path>]
 *     [--now <ISO-8601>]         (default: current time)
 *     [--json]                   (machine-readable report on stdout)
 *
 * Exit 0 = PASS, 1 = FAIL (a machine-readable report is always printed).
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const os = require("os");
const crypto = require("crypto");
const { hashTree, sha256File, SSH_PUBLIC_KEY_RE, UNFILLED_PLACEHOLDER } = require("./lib/release-hashes");
const { manifestBytes, assertManifestShape } = require("./lib/release-manifest-schema");
const { NAMESPACE: SIGN_NAMESPACE } = require("./release-sign");

const POLICY_SCHEMA = "policyvault-release-signers/1";

function policyError(message) {
  const e = new Error(`release-signers policy: ${message}`);
  e.code = "RELEASE_SIGNERS_POLICY_INVALID";
  return e;
}

function loadPolicy(policyPath) {
  const raw = JSON.parse(fs.readFileSync(policyPath, "utf8"));
  if (!raw || typeof raw !== "object") throw policyError("must be a JSON object");
  if (raw.schema !== POLICY_SCHEMA) {
    const e = policyError(`unknown policy schema ${JSON.stringify(raw.schema)} — this tool only understands ${JSON.stringify(POLICY_SCHEMA)}; failing closed`);
    e.code = "RELEASE_SIGNERS_POLICY_UNKNOWN_VERSION";
    throw e;
  }
  if (typeof raw.namespace !== "string" || !raw.namespace) throw policyError("namespace must be a non-empty string");
  if (!Number.isInteger(raw.threshold) || raw.threshold < 1) throw policyError("threshold must be a positive integer");
  if (!Array.isArray(raw.signers) || raw.signers.length === 0) throw policyError("signers must be a non-empty array");
  const seen = new Set();
  for (const s of raw.signers) {
    if (!s || typeof s !== "object" || typeof s.id !== "string" || !s.id) throw policyError("every signer needs a non-empty string id");
    if (seen.has(s.id)) throw policyError(`duplicate signer id ${JSON.stringify(s.id)}`);
    seen.add(s.id);
    if (typeof s.publicKey !== "string" || !s.publicKey) throw policyError(`signer ${s.id}: publicKey must be a non-empty string`);
    for (const k of ["validFrom", "revokedAt"]) {
      const v = s[k];
      if (v !== null && v !== undefined && (typeof v !== "string" || new Date(v).toISOString() !== v)) {
        throw policyError(`signer ${s.id}: ${k} must be an ISO-8601 UTC string or null`);
      }
    }
  }
  return raw;
}

/* Runs `ssh-keygen -Y verify` for one signer's claimed public key over the
 * exact manifest bytes. Never throws on a cryptographic failure — returns
 * { valid, detail }. Only throws on an environment problem (ssh-keygen
 * missing entirely). */
function verifyOneSignature({ bytes, namespace, principal, publicKeyLine, sigBytes }) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-release-verify-"));
  try {
    const allowedSignersPath = path.join(tmpDir, "allowed_signers");
    const sigPath = path.join(tmpDir, "message.sig");
    fs.writeFileSync(allowedSignersPath, `${principal} ${publicKeyLine}\n`);
    fs.writeFileSync(sigPath, sigBytes);
    const res = spawnSync("ssh-keygen", ["-Y", "verify", "-f", allowedSignersPath, "-I", principal, "-n", namespace, "-s", sigPath], { input: bytes, encoding: "utf8" });
    if (res.error) throw res.error;
    return { valid: res.status === 0, detail: (res.stderr || res.stdout || "").trim() };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

const SIG_FILE_RE = /\.sig\.([a-z0-9][a-z0-9._-]{0,63})$/;

function discoverSignatureFiles(manifestPath, sigDir) {
  const base = path.basename(manifestPath);
  const dir = sigDir || path.dirname(manifestPath);
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    if (!name.startsWith(`${base}.sig.`)) continue;
    const m = name.match(SIG_FILE_RE);
    if (!m) continue;
    out.push({ signerId: m[1], path: path.join(dir, name) });
  }
  return out;
}

/* Fingerprint used to dedupe by ACTUAL key material (never merely by
 * signer id) — two policy entries pointing at the same physical key must
 * count once, and the same signer id signing twice must count once. */
function keyFingerprint(publicKeyLine) {
  return crypto.createHash("sha256").update(publicKeyLine.trim()).digest("hex");
}

/*
 * Core verification. Pure(ish) — the only I/O is reading the given files
 * and invoking ssh-keygen; never mutates anything. Returns a full report;
 * never throws for an ordinary FAIL (throws only for structurally invalid
 * inputs: bad manifest JSON, bad policy JSON, missing files).
 */
function verifyRelease({ manifestPath, policyPath, sigDir, tree, archive, imageDigest, baseImageDigest, now = new Date().toISOString() }) {
  if (new Date(now).toISOString() !== now) throw new Error("--now must be a canonical ISO-8601 UTC string");
  const rawManifestBytesOnDisk = fs.readFileSync(manifestPath);
  const manifest = JSON.parse(rawManifestBytesOnDisk.toString("utf8"));
  assertManifestShape(manifest); // throws RELEASE_MANIFEST_UNKNOWN_VERSION / RELEASE_MANIFEST_INVALID
  // Signatures were made over manifestBytes(manifest) — the canonical form
  // of the parsed content — never over whatever bytes happen to sit on
  // disk (which could carry incidental re-formatting). Re-deriving here
  // means a cosmetic re-save of the file never breaks a signature, while
  // any VALUE change still changes the canonical bytes and invalidates it.
  const bytes = manifestBytes(manifest);
  const manifestBytesCanonicalOnDisk = bytes.equals(rawManifestBytesOnDisk);

  const policy = loadPolicy(policyPath);

  const sigFiles = discoverSignatureFiles(manifestPath, sigDir);
  const results = [];
  const validFingerprints = new Set();

  for (const { signerId, path: sigPath } of sigFiles) {
    const entry = policy.signers.find((s) => s.id === signerId);
    if (!entry) {
      results.push({ signerId, status: "INVALID", reason: "SIGNER_NOT_IN_POLICY" });
      continue;
    }
    if (entry.publicKey === UNFILLED_PLACEHOLDER) {
      results.push({ signerId, status: "INVALID", reason: "SIGNER_PLACEHOLDER_UNFILLED" });
      continue;
    }
    if (!SSH_PUBLIC_KEY_RE.test(entry.publicKey)) {
      results.push({ signerId, status: "INVALID", reason: "SIGNER_KEY_INVALID" });
      continue;
    }
    const sigBytes = fs.readFileSync(sigPath);
    const { valid, detail } = verifyOneSignature({ bytes, namespace: policy.namespace, principal: signerId, publicKeyLine: entry.publicKey, sigBytes });
    if (!valid) {
      results.push({ signerId, status: "INVALID", reason: "SIGNATURE_INVALID", detail });
      continue;
    }
    if (entry.validFrom && now < entry.validFrom) {
      results.push({ signerId, status: "INVALID", reason: "SIGNER_NOT_YET_VALID" });
      continue;
    }
    if (entry.revokedAt && now >= entry.revokedAt) {
      results.push({ signerId, status: "INVALID", reason: "SIGNER_REVOKED" });
      continue;
    }
    const fp = keyFingerprint(entry.publicKey);
    const dedup = validFingerprints.has(fp);
    validFingerprints.add(fp);
    results.push({ signerId, status: "VALID", keyFingerprint: fp, countedTowardThreshold: !dedup });
  }

  const distinctValidCount = validFingerprints.size;
  const thresholdMet = distinctValidCount >= policy.threshold;

  const hashCheck = recomputeAndCompareHashes(manifest, { tree, archive, imageDigest, baseImageDigest });

  const ok = thresholdMet && hashCheck.ok;
  return {
    ok,
    manifestBytesCanonicalOnDisk,
    manifest: { schema: manifest.schema, version: manifest.version, sourceCommit: manifest.sourceCommit, treeHash: manifest.treeHash },
    policy: { schema: policy.schema, namespace: policy.namespace, threshold: policy.threshold },
    signatures: results,
    distinctValidSigners: distinctValidCount,
    thresholdMet,
    hashCheck
  };
}

function recomputeAndCompareHashes(manifest, { tree, archive, imageDigest, baseImageDigest }) {
  const mismatches = [];
  const checked = [];
  if (tree) {
    const treeRoot = path.resolve(tree);
    const recomputedTreeHash = hashTree(treeRoot);
    checked.push("treeHash");
    if (recomputedTreeHash !== manifest.treeHash) mismatches.push({ field: "treeHash", expected: manifest.treeHash, actual: recomputedTreeHash });

    for (const [ver, entry] of Object.entries(manifest.covenants)) {
      const abs = path.join(treeRoot, entry.path);
      checked.push(`covenants.${ver}`);
      if (!fs.existsSync(abs)) {
        mismatches.push({ field: `covenants.${ver}`, expected: entry.sha256, actual: "FILE_MISSING" });
        continue;
      }
      const actual = sha256File(abs);
      if (actual !== entry.sha256) mismatches.push({ field: `covenants.${ver}`, expected: entry.sha256, actual });
    }

    for (const [rel, expected] of Object.entries(manifest.dependencies.lockfiles || {})) {
      const abs = path.join(treeRoot, rel);
      checked.push(`dependencies.lockfiles.${rel}`);
      if (!fs.existsSync(abs)) {
        mismatches.push({ field: `dependencies.lockfiles.${rel}`, expected, actual: "FILE_MISSING" });
        continue;
      }
      const actual = sha256File(abs);
      if (actual !== expected) mismatches.push({ field: `dependencies.lockfiles.${rel}`, expected, actual });
    }

    if (manifest.dependencies.vendoredKaspaWasmHash) {
      const vendorPath = path.join(treeRoot, "deploy/vendor/kaspa");
      checked.push("dependencies.vendoredKaspaWasmHash");
      if (!fs.existsSync(vendorPath)) {
        mismatches.push({ field: "dependencies.vendoredKaspaWasmHash", expected: manifest.dependencies.vendoredKaspaWasmHash, actual: "DIR_MISSING" });
      } else {
        const actual = hashTree(vendorPath);
        if (actual !== manifest.dependencies.vendoredKaspaWasmHash) mismatches.push({ field: "dependencies.vendoredKaspaWasmHash", expected: manifest.dependencies.vendoredKaspaWasmHash, actual });
      }
    }
  }
  if (archive) {
    checked.push("archiveSha256");
    const actual = sha256File(path.resolve(archive));
    if (actual !== manifest.archiveSha256) mismatches.push({ field: "archiveSha256", expected: manifest.archiveSha256, actual });
  }
  if (imageDigest !== undefined) {
    checked.push("imageDigest");
    if (imageDigest !== manifest.imageDigest) mismatches.push({ field: "imageDigest", expected: manifest.imageDigest, actual: imageDigest });
  }
  if (baseImageDigest !== undefined) {
    checked.push("baseImageDigest");
    if (baseImageDigest !== manifest.baseImageDigest) mismatches.push({ field: "baseImageDigest", expected: manifest.baseImageDigest, actual: baseImageDigest });
  }
  return { ok: mismatches.length === 0, checked, mismatches };
}

function usageError(message) {
  console.error(`error: ${message}`);
  console.error("usage: node tools/release-verify.js --manifest <path> --policy <path> [--sig-dir <dir>] [--tree <path>] [--archive <path>] [--now <iso>] [--json]");
  process.exit(2);
}

function parseArgs(argv) {
  const out = { flags: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out.flags.add(key);
      continue;
    }
    out[key] = next;
    i++;
  }
  return out;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.manifest) usageError("--manifest is required");
  if (!opts.policy) usageError("--policy is required");
  const report = verifyRelease({
    manifestPath: path.resolve(opts.manifest),
    policyPath: path.resolve(opts.policy),
    sigDir: opts["sig-dir"] ? path.resolve(opts["sig-dir"]) : undefined,
    tree: opts.tree,
    archive: opts.archive,
    imageDigest: opts["image-digest"],
    baseImageDigest: opts["base-image-digest"],
    now: opts.now
  });
  if (opts.flags.has("json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`release-verify: ${report.ok ? "PASS" : "FAIL"}`);
    console.log(`  manifest: ${report.manifest.version} (${report.manifest.sourceCommit})`);
    console.log(`  signers: ${report.distinctValidSigners}/${report.policy.threshold} distinct valid (threshold ${report.thresholdMet ? "MET" : "NOT MET"})`);
    for (const r of report.signatures) console.log(`    ${r.status.padEnd(7)} ${r.signerId}${r.reason ? ` (${r.reason})` : ""}`);
    console.log(`  hash check: ${report.hashCheck.ok ? "OK" : "MISMATCH"} (checked: ${report.hashCheck.checked.join(", ") || "none — no --tree/--archive given"})`);
    for (const m of report.hashCheck.mismatches) console.log(`    MISMATCH ${m.field}: expected ${m.expected} got ${m.actual}`);
  }
  process.exit(report.ok ? 0 : 1);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`release-verify failed: ${e.message}`);
    process.exit(1);
  }
}

module.exports = { verifyRelease, loadPolicy, discoverSignatureFiles, verifyOneSignature, recomputeAndCompareHashes, POLICY_SCHEMA, SIGN_NAMESPACE };
