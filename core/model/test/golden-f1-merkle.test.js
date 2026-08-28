"use strict";

/*
 * F1 browser-portability wave — Merkle byte-identity gate.
 *
 * The fixture was captured from the ORIGINAL Buffer-based implementations
 * at the F1 baseline (branch f1-portability, baseline d6799d4) BEFORE the
 * byte-native (Uint8Array) refactor. Both require roots — core/model
 * directly, and sdk/src through the re-export shims — must reproduce it
 * exactly: every leaf preimage byte, every intermediate node of every
 * level, every root, every proof sibling/pathBit, every verification and
 * fold outcome, and every fail-closed error identity. Any divergence means
 * the refactor changed observable behavior and MUST fail.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const { computeF1MerkleGolden } = require("../testutil/golden-f1-merkle");

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "golden-f1-merkle.json"), "utf8")
);
const sdkMod = (n) => require(path.join(__dirname, "..", "..", "..", "sdk", "src", n));
const coreMod = (n) => require(path.join(__dirname, "..", n));

/* JSON round-trip so value identity matches the parsed fixture exactly. */
const viaJson = (v) => JSON.parse(JSON.stringify(v));

test("golden-f1: core/model merkle modules reproduce the pre-refactor byte fixture exactly", () => {
  const got = computeF1MerkleGolden({
    recipientMerkle: coreMod("recipient-merkle-v3"),
    agentMerkle: coreMod("agent-merkle-v4")
  });
  assert.deepStrictEqual(viaJson(got), FIXTURE);
});

test("golden-f1: sdk require root (through the re-export shims) reproduces the fixture exactly", () => {
  const got = computeF1MerkleGolden({
    recipientMerkle: sdkMod("recipient-merkle-v3"),
    agentMerkle: sdkMod("agent-merkle-v4")
  });
  assert.deepStrictEqual(viaJson(got), FIXTURE);
});
