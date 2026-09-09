"use strict";

/*
 * UNIT / INTEGRATION (docker-free) — deployment pipeline transfer
 * mechanics (Track 8, deploy/pipeline/).
 *
 * The pipeline's funds-adjacent property is NOT "the transfer is small";
 * it is "the target can only ever activate the exact image the operator
 * built". That rests on three mechanical facts this suite drives
 * directly, with a SYNTHETIC OCI archive and no docker at all:
 *
 *   1. the deterministic tar helper produces identical bytes for
 *      identical content (artifact identity is stable);
 *   2. pack-delta ships exactly the blobs the target lacks, and
 *      apply-delta reassembles an archive that resolves to the SAME
 *      image digest (with --no-load: everything up to `docker load`);
 *   3. every failure mode fails CLOSED — a tampered blob, a stale
 *      inventory that omits a required blob, and a digest the caller
 *      did not expect are all refused, not repaired.
 *
 * Real-image, real-docker coverage lives in
 * deploy/pipeline/local-proof.sh (transcript:
 * docs/postlaunch/deployment-pipeline-local-proof.txt).
 */

const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const PIPELINE = path.join(__dirname, "..", "..", "deploy", "pipeline");
const sh = (script, args, opts = {}) =>
  spawnSync("bash", [path.join(PIPELINE, script), ...args], { encoding: "utf8", ...opts });

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pv-pipeline-test-"));
}

/*
 * A synthetic OCI image archive: blobs/sha256/<sha256-of-content> for a
 * config, two "layers" and a manifest, plus index.json + oci-layout —
 * the exact shape `docker buildx --output type=oci` produces.
 */
function makeOciArchive(dir, { layerBodies }) {
  const layout = path.join(dir, "layout");
  fs.mkdirSync(path.join(layout, "blobs", "sha256"), { recursive: true });
  const put = (buf) => {
    const d = sha256(buf);
    fs.writeFileSync(path.join(layout, "blobs", "sha256", d), buf);
    return { digest: `sha256:${d}`, size: buf.length };
  };
  const layers = layerBodies.map((b) => ({
    mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
    ...put(Buffer.from(b))
  }));
  const config = put(Buffer.from(JSON.stringify({ architecture: "amd64", os: "linux" })));
  const manifestBuf = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", ...config },
    layers
  }));
  const manifest = put(manifestBuf);
  fs.writeFileSync(path.join(layout, "index.json"), JSON.stringify({
    schemaVersion: 2,
    manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json", ...manifest }]
  }));
  fs.writeFileSync(path.join(layout, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));

  const tar = path.join(dir, "image.oci.tar");
  const r = spawnSync("bash", ["-c",
    `. "${path.join(PIPELINE, "pipeline-lib.sh")}"; pv_tar_deterministic "${layout}" "${tar}" 0`],
    { encoding: "utf8" });
  assert.equal(r.status, 0, `deterministic tar failed: ${r.stderr}`);
  return { tar, digest: manifest.digest, layout };
}

test("deterministic tar: identical content => identical bytes", () => {
  const dir = mkTmp();
  try {
    const src = path.join(dir, "src");
    fs.mkdirSync(path.join(src, "a"), { recursive: true });
    fs.writeFileSync(path.join(src, "a", "one.txt"), "one");
    fs.writeFileSync(path.join(src, "two.txt"), "two");
    const run = (out) => spawnSync("bash", ["-c",
      `. "${path.join(PIPELINE, "pipeline-lib.sh")}"; pv_tar_deterministic "${src}" "${out}" 1700000000`],
      { encoding: "utf8" });
    assert.equal(run(path.join(dir, "t1.tar")).status, 0);
    // touch the files: mtimes change, bytes must not.
    const future = new Date(Date.now() + 60000);
    fs.utimesSync(path.join(src, "two.txt"), future, future);
    assert.equal(run(path.join(dir, "t2.tar")).status, 0);
    assert.deepEqual(fs.readFileSync(path.join(dir, "t1.tar")), fs.readFileSync(path.join(dir, "t2.tar")));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("delta round trip: seed ships everything, the second delta ships only what changed", () => {
  const dir = mkTmp();
  try {
    const cache = path.join(dir, "cache");
    const v1 = makeOciArchive(path.join(dir, "v1"), { layerBodies: ["BIG-STABLE-LAYER", "app-v1"] });
    fs.mkdirSync(path.join(dir, "v2"), { recursive: true });
    const v2 = makeOciArchive(path.join(dir, "v2"), { layerBodies: ["BIG-STABLE-LAYER", "app-v2"] });
    assert.notEqual(v1.digest, v2.digest, "a changed layer must change the image digest");

    // seed: empty inventory => every blob ships
    fs.mkdirSync(cache, { recursive: true });
    let r = sh("image-inventory.sh", ["--cache", cache, "--out", path.join(dir, "inv0.txt")]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readFileSync(path.join(dir, "inv0.txt"), "utf8"), "");
    r = sh("pack-delta.sh", ["--image", v1.tar, "--out", path.join(dir, "seed.tar"),
      "--inventory", path.join(dir, "inv0.txt")]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /blobs shipped {2}: 4 /);
    r = sh("apply-delta.sh", ["--bundle", path.join(dir, "seed.tar"), "--cache", cache,
      "--expect-digest", v1.digest, "--no-load"]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), v1.digest, "reassembled archive must resolve to the built digest");

    // delta: inventory now holds v1's blobs => only the new ones ship
    r = sh("image-inventory.sh", ["--cache", cache, "--out", path.join(dir, "inv1.txt")]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.readFileSync(path.join(dir, "inv1.txt"), "utf8").trim().split("\n").length, 4);
    r = sh("pack-delta.sh", ["--image", v2.tar, "--out", path.join(dir, "delta.tar"),
      "--inventory", path.join(dir, "inv1.txt")]);
    assert.equal(r.status, 0, r.stderr);
    // only the changed layer + the new manifest ship; the stable layer and
    // the (identical) config stay in the target's cache.
    assert.match(r.stderr, /blobs shipped {2}: 2 /, "the shared layer must NOT be re-shipped");
    assert.ok(fs.statSync(path.join(dir, "delta.tar")).size < fs.statSync(path.join(dir, "seed.tar")).size);
    r = sh("apply-delta.sh", ["--bundle", path.join(dir, "delta.tar"), "--cache", cache,
      "--expect-digest", v2.digest, "--no-load"]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), v2.digest);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("fail closed: tampered blob, unexpected digest, and a stale inventory are all refused", () => {
  const dir = mkTmp();
  try {
    const cache = path.join(dir, "cache");
    fs.mkdirSync(cache, { recursive: true });
    const v1 = makeOciArchive(path.join(dir, "v1"), { layerBodies: ["stable", "app-v1"] });
    let r = sh("pack-delta.sh", ["--image", v1.tar, "--out", path.join(dir, "seed.tar")]);
    assert.equal(r.status, 0, r.stderr);

    // (a) a blob whose bytes do not hash to its name
    const work = path.join(dir, "work");
    fs.mkdirSync(work, { recursive: true });
    assert.equal(spawnSync("tar", ["-xf", path.join(dir, "seed.tar"), "-C", work]).status, 0);
    const blobDir = path.join(work, "blobs", "sha256");
    const victim = fs.readdirSync(blobDir)[0];
    fs.appendFileSync(path.join(blobDir, victim), "TAMPER");
    assert.equal(spawnSync("bash", ["-c",
      `. "${path.join(PIPELINE, "pipeline-lib.sh")}"; pv_tar_deterministic "${work}" "${path.join(dir, "bad.tar")}" 0`]).status, 0);
    r = sh("apply-delta.sh", ["--bundle", path.join(dir, "bad.tar"), "--cache", cache, "--no-load"]);
    assert.notEqual(r.status, 0, "a tampered blob must be refused");
    assert.match(r.stderr, /BLOB INTEGRITY FAILURE/);
    assert.equal(fs.readdirSync(path.join(cache, "blobs", "sha256")).length, 0,
      "nothing may be installed from a bundle that failed integrity");

    // (b) a digest the caller did not expect
    r = sh("apply-delta.sh", ["--bundle", path.join(dir, "seed.tar"), "--cache", cache, "--no-load",
      "--expect-digest", "sha256:" + "0".repeat(64)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /but sha256:0{64} was expected/);

    // (c) a STALE inventory: the target claims a blob it does not have
    const fakeInv = path.join(dir, "stale-inv.txt");
    const allBlobs = spawnSync("bash", ["-c",
      `. "${path.join(PIPELINE, "pipeline-lib.sh")}"; pv_oci_blobs "${v1.tar}" | awk '{print $1}'`],
      { encoding: "utf8" }).stdout.trim().split("\n");
    fs.writeFileSync(fakeInv, allBlobs[0] + "\n");
    r = sh("pack-delta.sh", ["--image", v1.tar, "--out", path.join(dir, "short.tar"), "--inventory", fakeInv]);
    assert.equal(r.status, 0, r.stderr);
    r = sh("apply-delta.sh", ["--bundle", path.join(dir, "short.tar"), "--cache", cache, "--no-load"]);
    assert.notEqual(r.status, 0, "a delta whose required blobs are absent must be refused");
    assert.match(r.stderr, /MISSING required blob|required blob\(s\) missing/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("signing: ssh-keygen -Y verification is required and rejects tampered bytes", () => {
  const dir = mkTmp();
  try {
    const key = path.join(dir, "k");
    const kg = spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "pv-test", "-f", key],
      { encoding: "utf8" });
    if (kg.status !== 0) { test.skip("ssh-keygen unavailable"); return; }
    fs.writeFileSync(path.join(dir, "allowed_signers"),
      `pv-test ${fs.readFileSync(key + ".pub", "utf8")}`);
    const artifact = path.join(dir, "artifact.bin");
    fs.writeFileSync(artifact, "policyvault pipeline artifact");
    let r = sh("sign-bundle.sh", ["--file", artifact, "--key", key]);
    assert.equal(r.status, 0, r.stderr);
    r = sh("verify-bundle.sh", ["--file", artifact, "--allowed-signers", path.join(dir, "allowed_signers"),
      "--identity", "pv-test", "--sha256", sha256(fs.readFileSync(artifact))]);
    assert.equal(r.status, 0, r.stderr);

    fs.appendFileSync(artifact, "!");
    r = sh("verify-bundle.sh", ["--file", artifact, "--allowed-signers", path.join(dir, "allowed_signers"),
      "--identity", "pv-test"]);
    assert.notEqual(r.status, 0, "a modified artifact must not verify");
    assert.match(r.stderr, /SIGNATURE VERIFICATION FAILED/);

    r = sh("verify-bundle.sh", ["--file", artifact, "--allowed-signers", path.join(dir, "nope"),
      "--identity", "pv-test"]);
    assert.notEqual(r.status, 0, "a missing allowed_signers file must fail closed");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("deploy-by-digest: refuses a mainnet env without the explicit owner acknowledgement", () => {
  const dir = mkTmp();
  try {
    const env = path.join(dir, "prod.env");
    fs.writeFileSync(env, [
      "KASPA_NETWORK_ID=mainnet",
      "POLICYVAULT_ALLOW_MAINNET=1",
      "PV_PROD_APP_TAG=fullscale-rcX",
      "POLICYVAULT_PG_PASSWORD=not-a-real-secret"
    ].join("\n") + "\n");
    const before = fs.readFileSync(env, "utf8");
    const r = sh("deploy-by-digest.sh", ["--digest", "sha256:" + "a".repeat(64),
      "--tag", "t8-never", "--env", env]);
    assert.notEqual(r.status, 0, "a production env must not be touched without the owner gate");
    assert.match(r.stderr, /REFUSING/);
    assert.equal(fs.readFileSync(env, "utf8"), before, "the env file must be byte-identical after a refusal");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
