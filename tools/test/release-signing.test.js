"use strict";

/*
 * UNIT/INTEGRATION — release-manifest.js / release-sign.js / release-
 * verify.js (TRACK 9 release signing; docs/postlaunch/release-trust-
 * model.md). Generates disposable ED25519 TEST keys in a fresh temp
 * directory for every run (never touches a real maintainer key, never
 * reads release-signers.json's real content beyond loading its shape).
 *
 * Run: node --test tools/test/release-signing.test.js
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { buildManifest } = require("../release-manifest");
const { signManifestFile, NAMESPACE, SIGNER_ID_RE } = require("../release-sign");
const { verifyRelease, loadPolicy, POLICY_SCHEMA } = require("../release-verify");
const { manifestBytes, assertManifestShape, MANIFEST_SCHEMA } = require("../lib/release-manifest-schema");
const { hashTree, UNFILLED_PLACEHOLDER } = require("../lib/release-hashes");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const FAKE_COMMIT = "a".repeat(40);

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/* A minimal fixture "release tree" with just enough real content for
 * buildManifest to produce a valid manifest (a v0.3 + v0.6 covenant file
 * and one lockfile). Not a real PolicyVault checkout. */
function makeFixtureTree(root, { v03 = "pragma silverscript ^0.1.0;\n// v0.3 fixture\n", v06 = "// v0.6 candidate fixture\n" } = {}) {
  fs.mkdirSync(path.join(root, "contracts"), { recursive: true });
  fs.mkdirSync(path.join(root, "sdk"), { recursive: true });
  fs.writeFileSync(path.join(root, "contracts", "PolicyVault.v0.3.sil"), v03);
  fs.writeFileSync(path.join(root, "contracts", "PolicyVault.v0.6.sil"), v06);
  fs.writeFileSync(path.join(root, "sdk", "package-lock.json"), JSON.stringify({ name: "policyvault-sdk-fixture", lockfileVersion: 3 }));
  return root;
}

function genKey(dir, name) {
  const keyPath = path.join(dir, name);
  const res = spawnSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", name, "-f", keyPath], { encoding: "utf8" });
  assert.equal(res.status, 0, `ssh-keygen keygen failed: ${res.stderr || res.stdout}`);
  const pubRaw = fs.readFileSync(`${keyPath}.pub`, "utf8").trim();
  const parts = pubRaw.split(/\s+/);
  const publicKeyLine = `${parts[0]} ${parts[1]}`; // strip the trailing comment
  return { keyPath, publicKeyLine };
}

function writeManifestFile(dir, manifest) {
  const p = path.join(dir, "manifest.json");
  fs.writeFileSync(p, manifestBytes(manifest));
  return p;
}

function policyOf(signers, threshold = 1, overrides = {}) {
  return { schema: POLICY_SCHEMA, namespace: NAMESPACE, threshold, signers, updatedAt: new Date().toISOString(), ...overrides };
}

function writePolicy(dir, policy) {
  const p = path.join(dir, "release-signers.json");
  fs.writeFileSync(p, JSON.stringify(policy, null, 2));
  return p;
}

/* ------------------------------------------------------------------ */
/* release-manifest.js                                                */
/* ------------------------------------------------------------------ */

test("release-manifest: builds a well-formed manifest with self-computed hashes", () => {
  const tmp = mkTmp("pv-relmanifest-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v9.9.9-test" });
  assertManifestShape(manifest); // throws on any violation
  assert.equal(manifest.schema, MANIFEST_SCHEMA);
  assert.equal(manifest.sourceCommit, FAKE_COMMIT);
  assert.equal(manifest.treeHash, hashTree(path.resolve(tree)));
  assert.equal(manifest.covenants["v0.3"].label, "frozen");
  assert.equal(manifest.covenants["v0.6"].label, "frozen"); // v0.6 COVENANT-BYTE-FROZEN 2026-09-03; the default candidate list is now v0.7 (STALE ASSUMPTION re-pinned)
  assert.ok(manifest.dependencies.lockfiles["sdk/package-lock.json"]);
  assert.equal(manifest.imageDigest, null);
  assert.equal(manifest.archiveSha256, null);
});

test("release-manifest schema: unknown top-level fields are refused, never silently accepted", () => {
  const tmp = mkTmp("pv-relmanifest-unknownfield-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1" });
  assert.throws(() => assertManifestShape({ ...manifest, extraField: "not part of the schema" }), (e) => e.code === "RELEASE_MANIFEST_INVALID");
});

test("release-manifest: refuses a non-canonical/invalid --commit and missing covenants", () => {
  const tmp = mkTmp("pv-relmanifest-bad-");
  const emptyTree = path.join(tmp, "empty");
  fs.mkdirSync(emptyTree);
  assert.throws(() => buildManifest({ tree: emptyTree, commit: "not-a-sha", version: "v1" }), /--commit/);
});

/* ------------------------------------------------------------------ */
/* Core round trip: 1-of-1 threshold                                  */
/* ------------------------------------------------------------------ */

test("end-to-end: sign with 1 key, verify passes at threshold 1", () => {
  const tmp = mkTmp("pv-relverify-basic-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  const sig = signManifestFile({ manifestPath, keyPath });
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, sig);
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: null }], 1));

  const report = verifyRelease({ manifestPath, policyPath, tree });
  assert.equal(report.ok, true, JSON.stringify(report, null, 2));
  assert.equal(report.distinctValidSigners, 1);
  assert.equal(report.thresholdMet, true);
  assert.equal(report.hashCheck.ok, true);
  assert.deepEqual(report.hashCheck.mismatches, []);
});

test("threshold 2 with one valid signature FAILS", () => {
  const tmp = mkTmp("pv-relverify-thresh2-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, signManifestFile({ manifestPath, keyPath }));
  // A second policy signer exists (structurally valid) but never signs.
  const { publicKeyLine: pubB } = genKey(tmp, "signer-b");
  const policyPath = writePolicy(
    tmp,
    policyOf(
      [
        { id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: null },
        { id: "signer-b", publicKey: pubB, validFrom: null, revokedAt: null }
      ],
      2
    )
  );

  const report = verifyRelease({ manifestPath, policyPath });
  assert.equal(report.ok, false);
  assert.equal(report.distinctValidSigners, 1);
  assert.equal(report.thresholdMet, false);
});

test("the same physical key signing under two signer ids counts once toward threshold", () => {
  const tmp = mkTmp("pv-relverify-samekey-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "shared-key");
  const sig = signManifestFile({ manifestPath, keyPath });
  fs.writeFileSync(`${manifestPath}.sig.alias-one`, sig);
  fs.writeFileSync(`${manifestPath}.sig.alias-two`, sig);
  const policyPath = writePolicy(
    tmp,
    policyOf(
      [
        { id: "alias-one", publicKey: publicKeyLine, validFrom: null, revokedAt: null },
        { id: "alias-two", publicKey: publicKeyLine, validFrom: null, revokedAt: null }
      ],
      2 // deliberately requires 2 — must NOT be met by one physical key wearing two ids
    )
  );

  const report = verifyRelease({ manifestPath, policyPath });
  assert.equal(report.signatures.filter((r) => r.status === "VALID").length, 2, "both signature files verify cryptographically");
  assert.equal(report.distinctValidSigners, 1, "but they are the same key — counted once");
  assert.equal(report.thresholdMet, false);
  assert.equal(report.ok, false);
});

test("a revoked signer's valid signature is not counted", () => {
  const tmp = mkTmp("pv-relverify-revoked-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, signManifestFile({ manifestPath, keyPath }));
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: "2020-01-01T00:00:00.000Z" }], 1));

  const report = verifyRelease({ manifestPath, policyPath, now: "2026-01-01T00:00:00.000Z" });
  assert.equal(report.ok, false);
  assert.equal(report.distinctValidSigners, 0);
  const row = report.signatures.find((r) => r.signerId === "signer-a");
  assert.equal(row.status, "INVALID");
  assert.equal(row.reason, "SIGNER_REVOKED");
});

test("a not-yet-valid signer's signature is not counted", () => {
  const tmp = mkTmp("pv-relverify-notyet-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, signManifestFile({ manifestPath, keyPath }));
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: "2099-01-01T00:00:00.000Z", revokedAt: null }], 1));

  const report = verifyRelease({ manifestPath, policyPath, now: "2026-01-01T00:00:00.000Z" });
  assert.equal(report.ok, false);
  const row = report.signatures.find((r) => r.signerId === "signer-a");
  assert.equal(row.reason, "SIGNER_NOT_YET_VALID");
});

test("a tampered manifest byte invalidates the signature", () => {
  const tmp = mkTmp("pv-relverify-tamper-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, signManifestFile({ manifestPath, keyPath }));
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: null }], 1));

  // Flip one visible character in the version string post-signing.
  const tampered = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  tampered.version = `${tampered.version}X`;
  fs.writeFileSync(manifestPath, JSON.stringify(tampered)); // not even canonical form — still must fail

  const report = verifyRelease({ manifestPath, policyPath });
  assert.equal(report.ok, false);
  const row = report.signatures.find((r) => r.signerId === "signer-a");
  assert.equal(row.status, "INVALID");
  assert.equal(row.reason, "SIGNATURE_INVALID");
});

test("a signature made under the wrong namespace fails", () => {
  const tmp = mkTmp("pv-relverify-namespace-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");

  // Sign directly with ssh-keygen under a DIFFERENT namespace, bypassing
  // tools/release-sign.js's fixed NAMESPACE on purpose.
  const res = spawnSync("ssh-keygen", ["-Y", "sign", "-n", "not-policyvault-release", "-f", keyPath, manifestPath], { encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  fs.renameSync(`${manifestPath}.sig`, `${manifestPath}.sig.signer-a`);

  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: null }], 1));
  const report = verifyRelease({ manifestPath, policyPath }); // policy namespace is the correct one
  assert.equal(report.ok, false);
  const row = report.signatures.find((r) => r.signerId === "signer-a");
  assert.equal(row.status, "INVALID");
  assert.equal(row.reason, "SIGNATURE_INVALID");
  assert.match(row.detail, /namespace/i);
});

test("a hash mismatch against the real tree fails even with a valid, threshold-meeting signature", () => {
  const tmp = mkTmp("pv-relverify-hashmismatch-");
  const tree = path.join(tmp, "tree");
  makeFixtureTree(tree);
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath, publicKeyLine } = genKey(tmp, "signer-a");
  fs.writeFileSync(`${manifestPath}.sig.signer-a`, signManifestFile({ manifestPath, keyPath }));
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: publicKeyLine, validFrom: null, revokedAt: null }], 1));

  // Mutate the TREE after the manifest was built (a real tampered/rebuilt
  // artifact would look exactly like this).
  fs.writeFileSync(path.join(tree, "contracts", "PolicyVault.v0.3.sil"), "pragma silverscript ^0.1.0;\n// MUTATED\n");

  const report = verifyRelease({ manifestPath, policyPath, tree });
  assert.equal(report.thresholdMet, true, "the signature itself is still cryptographically valid");
  assert.equal(report.hashCheck.ok, false);
  assert.equal(report.ok, false, "overall verification must fail on a hash mismatch regardless of signatures");
  assert.ok(report.hashCheck.mismatches.some((m) => m.field === "treeHash"));
  assert.ok(report.hashCheck.mismatches.some((m) => m.field === "covenants.v0.3"));
});

test("an unknown manifest schema version fails closed", () => {
  const tmp = mkTmp("pv-relverify-unknownver-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  manifest.schema = "policyvault-release-manifest/2"; // future/unknown version
  const manifestPath = writeManifestFile(tmp, manifest);
  const policyPath = writePolicy(tmp, policyOf([{ id: "signer-a", publicKey: UNFILLED_PLACEHOLDER, validFrom: null, revokedAt: null }], 1));

  assert.throws(() => verifyRelease({ manifestPath, policyPath }), (e) => e.code === "RELEASE_MANIFEST_UNKNOWN_VERSION");
});

test("an unfilled OWNER-TO-FILL placeholder signer is refused, never silently counted", () => {
  const tmp = mkTmp("pv-relverify-placeholder-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  // A bogus signature file claiming to be from the placeholder signer —
  // its content is irrelevant because the placeholder check happens
  // before any cryptographic attempt.
  fs.writeFileSync(`${manifestPath}.sig.maintainer-primary`, "-----BEGIN SSH SIGNATURE-----\nnot-a-real-signature\n-----END SSH SIGNATURE-----\n");
  const policyPath = writePolicy(tmp, policyOf([{ id: "maintainer-primary", publicKey: UNFILLED_PLACEHOLDER, validFrom: null, revokedAt: null }], 1));

  const report = verifyRelease({ manifestPath, policyPath });
  assert.equal(report.ok, false);
  assert.equal(report.distinctValidSigners, 0);
  const row = report.signatures.find((r) => r.signerId === "maintainer-primary");
  assert.equal(row.status, "INVALID");
  assert.equal(row.reason, "SIGNER_PLACEHOLDER_UNFILLED");
});

/* ------------------------------------------------------------------ */
/* The checked-in release-signers.json policy file                    */
/* ------------------------------------------------------------------ */

test("the checked-in release-signers.json is a well-formed, honest one-real-signer placeholder policy", () => {
  const policyPath = path.join(REPO_ROOT, "release-signers.json");
  const policy = loadPolicy(policyPath);
  assert.equal(policy.schema, POLICY_SCHEMA);
  assert.equal(policy.namespace, NAMESPACE);
  assert.equal(policy.threshold, 1);
  assert.equal(policy.signers.length, 1);
  assert.equal(policy.signers[0].publicKey, UNFILLED_PLACEHOLDER, "no real key may be checked in by this track");
});

test("release-verify refuses to count any signature against the real checked-in policy today (nothing is filled in)", () => {
  const tmp = mkTmp("pv-relverify-realpolicy-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifest = buildManifest({ tree, commit: FAKE_COMMIT, version: "v1.0.0-test" });
  const manifestPath = writeManifestFile(tmp, manifest);
  const { keyPath } = genKey(tmp, "maintainer-primary");
  fs.writeFileSync(`${manifestPath}.sig.maintainer-primary`, signManifestFile({ manifestPath, keyPath }));

  const report = verifyRelease({ manifestPath, policyPath: path.join(REPO_ROOT, "release-signers.json") });
  assert.equal(report.ok, false);
  assert.equal(report.distinctValidSigners, 0);
});

/* ------------------------------------------------------------------ */
/* release-sign.js input validation                                   */
/* ------------------------------------------------------------------ */

test("release-sign: rejects a malformed --signer-id", () => {
  assert.equal(SIGNER_ID_RE.test("Signer A"), false);
  assert.equal(SIGNER_ID_RE.test("signer-a"), true);
  assert.equal(SIGNER_ID_RE.test(""), false);
});

/* ------------------------------------------------------------------ */
/* Full CLI round trip (drives the real command-line entry points)    */
/* ------------------------------------------------------------------ */

test("CLI: release-manifest.js -> release-sign.js -> release-verify.js end to end", () => {
  const tmp = mkTmp("pv-relverify-cli-");
  const tree = makeFixtureTree(path.join(tmp, "tree"));
  const manifestPath = path.join(tmp, "manifest.json");

  const gen = spawnSync("node", [path.join(REPO_ROOT, "tools", "release-manifest.js"), "--tree", tree, "--commit", FAKE_COMMIT, "--version", "v1.0.0-cli-test", "--out", manifestPath], { encoding: "utf8" });
  assert.equal(gen.status, 0, gen.stderr);
  assert.ok(fs.existsSync(manifestPath));

  const { keyPath, publicKeyLine } = genKey(tmp, "cli-signer");
  const sign = spawnSync("node", [path.join(REPO_ROOT, "tools", "release-sign.js"), "--manifest", manifestPath, "--key", keyPath, "--signer-id", "cli-signer"], { encoding: "utf8" });
  assert.equal(sign.status, 0, sign.stderr);
  assert.ok(fs.existsSync(`${manifestPath}.sig.cli-signer`));

  const policyPath = writePolicy(tmp, policyOf([{ id: "cli-signer", publicKey: publicKeyLine, validFrom: null, revokedAt: null }], 1));
  const verify = spawnSync("node", [path.join(REPO_ROOT, "tools", "release-verify.js"), "--manifest", manifestPath, "--policy", policyPath, "--tree", tree, "--json"], { encoding: "utf8" });
  assert.equal(verify.status, 0, verify.stdout + verify.stderr);
  const report = JSON.parse(verify.stdout);
  assert.equal(report.ok, true);
});
