"use strict";

/*
 * tools/release-sign.js — signs a `policyvault-release-manifest/1` file
 * with an OpenSSH key using `ssh-keygen -Y sign` (TRACK 9 release signing;
 * docs/postlaunch/release-trust-model.md). No cryptography is implemented
 * here — this is a thin, auditable wrapper around the OpenSSH signature
 * format (SSHSIG), which any operator can also invoke by hand.
 *
 * Signs the EXACT manifest file bytes on disk (tools/lib/release-manifest-
 * schema.js manifestBytes — canonical JSON + one trailing newline) under
 * the fixed namespace "policyvault-release". Output:
 *   <manifest>.sig.<signerId>
 * so a manifest directory can hold one signature per signer without
 * collisions (multi-signer capable from day one — see
 * docs/postlaunch/release-trust-model.md for why today's checked-in
 * policy still lists exactly one real signer).
 *
 * Usage:
 *   node tools/release-sign.js --manifest <path> --key <ssh-key-path>
 *     --signer-id <id> [--out <path>]
 *
 * `--key` is the PRIVATE key file (ssh-keygen -Y sign reads it directly;
 * this tool never reads or logs its contents). Never run this against a
 * real maintainer signing key from an automated/non-interactive context
 * without the operator's own deliberate action — see the trust-model
 * doc's emergency-release and key-handling sections.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function usageError(message) {
  console.error(`error: ${message}`);
  console.error("usage: node tools/release-sign.js --manifest <path> --key <ssh-key-path> --signer-id <id> [--out <path>]");
  process.exit(2);
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

const NAMESPACE = "policyvault-release";
const SIGNER_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/* Signs manifestPath with keyPath under the fixed namespace, returning the
 * signature bytes (does not touch outPath — caller decides placement). */
function signManifestFile({ manifestPath, keyPath }) {
  if (!fs.existsSync(manifestPath) || !fs.statSync(manifestPath).isFile()) {
    throw new Error(`manifest not found: ${manifestPath}`);
  }
  if (!fs.existsSync(keyPath) || !fs.statSync(keyPath).isFile()) {
    throw new Error(`signing key not found: ${keyPath}`);
  }
  // ssh-keygen -Y sign writes "<file>.sig" beside the input file; sign a
  // private temp copy path so concurrent signers never race on one .sig.
  const sigPath = `${manifestPath}.sig`;
  if (fs.existsSync(sigPath)) fs.unlinkSync(sigPath);
  const res = spawnSync("ssh-keygen", ["-Y", "sign", "-n", NAMESPACE, "-f", keyPath, manifestPath], { encoding: "utf8" });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`ssh-keygen -Y sign failed (exit ${res.status}): ${res.stderr || res.stdout}`);
  }
  if (!fs.existsSync(sigPath)) throw new Error("ssh-keygen -Y sign reported success but produced no .sig file");
  const sig = fs.readFileSync(sigPath);
  fs.unlinkSync(sigPath); // caller places the final copy at <manifest>.sig.<signerId>
  return sig;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.manifest) usageError("--manifest is required");
  if (!opts.key) usageError("--key is required");
  if (!opts["signer-id"] || !SIGNER_ID_RE.test(opts["signer-id"])) {
    usageError('--signer-id is required and must match ^[a-z0-9][a-z0-9._-]{0,63}$ (matching a release-signers.json entry id)');
  }
  const manifestPath = path.resolve(opts.manifest);
  const sig = signManifestFile({ manifestPath, keyPath: path.resolve(opts.key) });
  const outPath = opts.out ? path.resolve(opts.out) : `${manifestPath}.sig.${opts["signer-id"]}`;
  fs.writeFileSync(outPath, sig);
  console.error(`wrote ${outPath} (${sig.length} bytes, namespace ${NAMESPACE})`);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`release-sign failed: ${e.message}`);
    process.exit(1);
  }
}

module.exports = { signManifestFile, NAMESPACE, SIGNER_ID_RE };
