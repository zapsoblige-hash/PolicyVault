"use strict";

/*
 * UNIT — deterministic export formats + fail-closed reading.
 *
 * Layer: UNIT (pure core; no node, no store, no network).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const A = require("../index");
const V = require("../testutil/vectors");

const RECORDS = [V.syntheticSpendAttestation(), V.liveTestnetSellAttestation(), V.refusedAttestation()];

test("canonical JSON export is byte-deterministic and round-trips through parse unchanged", () => {
  for (const rec of RECORDS) {
    const text = A.exportAttestationJson(rec);
    assert.equal(text, A.exportAttestationJson(rec));
    const back = A.parseAttestationJson(text);
    assert.equal(A.recomputeAttestationHash(back), rec.attestationHash);
    assert.equal(A.verifyAttestation(back).structural.ok, true);
    /* key order in the source object must not change the exported bytes */
    const shuffled = Object.fromEntries(Object.entries(rec).reverse());
    assert.equal(A.exportAttestationJson(shuffled), text);
  }
});

test("the batch export is newline-delimited, one complete self-describing record per line", () => {
  const text = A.exportAttestationBatchNdjson(RECORDS);
  const lines = text.split("\n");
  assert.equal(lines[lines.length - 1], "", "the batch is newline-terminated");
  assert.equal(lines.length - 1, RECORDS.length);
  for (const line of lines.slice(0, -1)) {
    const rec = A.parseAttestationJson(line);
    assert.equal(rec.attestationVersion, A.ATTESTATION_VERSION_1);
    assert.equal(A.verifyAttestation(rec).structural.ok, true);
  }
  assert.deepEqual(
    A.parseAttestationBatchNdjson(text).map((r) => r.attestationHash),
    RECORDS.map((r) => r.attestationHash)
  );
});

test("an empty batch is an empty document, and an empty document is an empty batch", () => {
  assert.equal(A.exportAttestationBatchNdjson([]), "");
  assert.deepEqual(A.parseAttestationBatchNdjson(""), []);
});

test("UNKNOWN VERSIONS FAIL CLOSED on every read and write path", () => {
  const alien = { ...V.clone(RECORDS[0]), attestationVersion: "policyvault-execution-attestation/2" };
  for (const [label, fn] of [
    ["export single", () => A.exportAttestationJson(alien)],
    ["export batch", () => A.exportAttestationBatchNdjson([alien])],
    ["parse single", () => A.parseAttestationJson(JSON.stringify(alien))],
    ["parse batch", () => A.parseAttestationBatchNdjson(`${JSON.stringify(alien)}\n`)],
    ["batch digest", () => A.computeBatchDigest([alien])]
  ]) {
    assert.throws(fn, (e) => e.code === "ATTESTATION_VERSION_UNSUPPORTED", label);
  }
});

test("a batch reader NEVER silently skips a line it could not read", () => {
  const good = A.exportAttestationJson(RECORDS[0]);
  for (const [label, text] of [
    ["blank line", `${good}\n\n${good}\n`],
    ["garbage line", `${good}\nnot json\n`],
    ["array line", `${good}\n[1,2,3]\n`],
    ["truncated line", `${good}\n${good.slice(0, 40)}\n`]
  ]) {
    assert.throws(() => A.parseAttestationBatchNdjson(text), (e) => e.code === "ATTESTATION_SCHEMA_INVALID", label);
  }
});

test("the batch digest commits to CONTENT AND ORDER", () => {
  const digest = A.computeBatchDigest(RECORDS);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(digest, A.computeBatchDigest([...RECORDS]));
  assert.notEqual(digest, A.computeBatchDigest([RECORDS[1], RECORDS[0], RECORDS[2]]), "reordering must change the digest");
  assert.notEqual(digest, A.computeBatchDigest(RECORDS.slice(0, 2)), "removing a record must change the digest");
});

test("the batch digest is not a verification: it says nothing about whether a record is valid", () => {
  const broken = V.clone(RECORDS[0]);
  broken.amounts.amount = "1"; // hash no longer matches the body
  const digest = A.computeBatchDigest([broken]);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.equal(A.verifyAttestation(broken).verdict, A.VERDICTS.INVALID);
});
