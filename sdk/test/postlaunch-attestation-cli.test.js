"use strict";

/*
 * INTEGRATION — tools/attestation-verify.js, the INDEPENDENT verifier.
 *
 * The whole point of an attestation is that its verifier is not the
 * service that issued it, so this suite drives the REAL CLI as a separate
 * process over REAL files and asserts the contract a third party actually
 * relies on: the exit codes.
 *
 *   0  everything passed the requested level
 *   1  something is invalid or the chain contradicts it
 *   3  --chain requested, nothing contradicted, but something could not be
 *      confirmed  ("I could not check", never "it is fine")
 *   2  usage / input error
 *
 * The structural pass must work with no server, no session, no credential
 * and no network. (The --chain path against a real node is covered by
 * core/attest/test/chain-facts.test.js for the pure logic and by the
 * live-node evidence recorded in
 * docs/postlaunch/execution-attestation-spec.md §11.)
 *
 * Layer: INTEGRATION (child process + filesystem; no node, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("node:child_process");

const attest = require("../../core/attest");
const V = require("../../core/attest/testutil/vectors");

const CLI = path.join(__dirname, "..", "..", "tools", "attestation-verify.js");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-attest-cli-"));

function write(name, text) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, text);
  return file;
}
function run(...args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}

const LIVE = V.liveTestnetSellAttestation();
const SPEND = V.syntheticSpendAttestation();
const REFUSED = V.refusedAttestation();

test("a valid single record verifies structurally with no server, session, credential or network — exit 0", () => {
  const file = write("one.json", attest.exportAttestationJson(LIVE));
  const r = run(file);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /STRUCTURE_VERIFIED/);
  assert.match(r.out, /1 record\(s\): 0 chain-confirmed, 1 structurally verified/);
  assert.match(r.out, /batch digest [0-9a-f]{64}/);
  /* gaps in the source evidence are REPORTED, not hidden */
  assert.match(r.out, /SIGNER_DIGEST_NOT_RECORDED/);
});

test("a pretty-printed single record is not mistaken for a batch", () => {
  const file = write("pretty.json", JSON.stringify(JSON.parse(attest.exportAttestationJson(SPEND)), null, 2));
  const r = run(file);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /1 record\(s\)/);
});

test("an NDJSON batch verifies line by line — exit 0", () => {
  const file = write("batch.ndjson", attest.exportAttestationBatchNdjson([LIVE, SPEND, REFUSED]));
  const r = run(file);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /3 record\(s\): 0 chain-confirmed, 3 structurally verified/);
});

test("a tampered record fails — exit 1, with the exact failure code", () => {
  const tampered = V.clone(SPEND);
  tampered.amounts.amount = "1";
  const file = write("tampered.json", JSON.stringify(tampered));
  const r = run(file);
  assert.equal(r.code, 1);
  assert.match(r.out, /ATTESTATION_INVALID/);
  assert.match(r.out, /FAILURE HASH_MISMATCH/);
});

test("one bad record in a batch fails the whole run — exit 1", () => {
  const tampered = V.clone(SPEND);
  tampered.outcome.chain.outputs[0].valueSompi = "1";
  const file = write("mixed.ndjson", `${attest.exportAttestationJson(LIVE)}\n${JSON.stringify(tampered)}\n`);
  const r = run(file);
  assert.equal(r.code, 1);
  assert.match(r.out, /1 structurally verified/);
  assert.match(r.out, /1 invalid/);
});

test("expectation pins are enforced by the READER — a re-hashed substitution is caught — exit 1", () => {
  const moved = V.clone(SPEND);
  moved.subject.vaultId = V.H("bb");
  moved.attestationHash = attest.recomputeAttestationHash(moved);
  const file = write("moved.json", JSON.stringify(moved));

  assert.equal(run(file).code, 0, "integrity is intact; truth is not integrity");

  const pinned = run(file, "--expect-vault", V.H("a1"));
  assert.equal(pinned.code, 1);
  assert.match(pinned.out, /EXPECTED_VAULT_MISMATCH/);
});

test("an unknown attestation version FAILS CLOSED at the reader — exit 2, never routed to a default", () => {
  const alien = { ...V.clone(SPEND), attestationVersion: "policyvault-execution-attestation/2" };
  const file = write("alien.json", JSON.stringify(alien));
  const r = run(file);
  assert.equal(r.code, 2);
  assert.match(r.err, /ATTESTATION_VERSION_UNSUPPORTED/);
});

test("a batch reader never silently skips a line it could not read — exit 2", () => {
  const file = write("broken.ndjson", `${attest.exportAttestationJson(LIVE)}\nnot json\n`);
  const r = run(file);
  assert.equal(r.code, 2);
  assert.match(r.err, /ATTESTATION_SCHEMA_INVALID/);
});

test("usage errors are exit 2 and never a silent pass", () => {
  assert.equal(run().code, 2);
  assert.equal(run(path.join(dir, "does-not-exist.json")).code, 2);
  assert.equal(run(write("x.json", attest.exportAttestationJson(LIVE)), "--nonsense").code, 2);
});

test("--json emits a machine-readable report; --summary renders the human one with no forbidden vocabulary", () => {
  const file = write("report.json", attest.exportAttestationBatchNdjson([LIVE, REFUSED]));
  const asJson = run(file, "--json");
  assert.equal(asJson.code, 0, asJson.err);
  const report = JSON.parse(asJson.out);
  assert.equal(report.reportVersion, "policyvault-attestation-verify-report/1");
  assert.equal(report.verifierVersion, attest.VERIFIER_VERSION_1);
  assert.equal(report.chainChecked, false);
  assert.equal(report.total, 2);
  assert.equal(report.structureOnly, 2);
  assert.equal(report.confirmed, 0);

  const withSummary = run(file, "--summary");
  assert.equal(withSummary.code, 0);
  assert.match(withSummary.out, /PolicyVault policy-execution attestation/);
  assert.deepEqual(attest.forbiddenLanguageHits(withSummary.out), []);
});

test("--help documents the tool from its own header and exits 0", () => {
  const r = run("--help");
  assert.equal(r.code, 0);
  assert.match(r.out, /USAGE/);
  assert.match(r.out, /EXIT CODES/);
  assert.match(r.out, /--chain/);
});
