"use strict";

/*
 * Shared-core extraction step 3 — MEMBER-LEVEL API identity.
 *
 * Step 3 is an interface split, not a whole-module move: the sdk files
 * are composition modules (pure members re-exported from core/model +
 * impure probe/WASM members kept locally), so whole-module object
 * identity cannot hold. Identity is proven member-by-member:
 *
 *   1. every MOVED member is the SAME function/value object through both
 *      require roots (structurally excludes a duplicate implementation);
 *   2. the sdk modules' exported key + typeof sets are UNCHANGED from the
 *      pre-split fixture;
 *   3. the core modules export exactly the designed pure surface and
 *      NONE of the impure members (no probe/WASM code can hide in core);
 *   4. the newly-exported core commitment preimage builders are exactly
 *      the preimages of the commitment hashers (sha256 consistency).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const { fixtures } = require("../testutil/golden3");

const FIXTURE = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", "golden-v3.json"), "utf8"));
const CORE = path.join(__dirname, "..");
const SDK = path.join(__dirname, "..", "..", "..", "sdk", "src");

const SPLIT = [
  {
    file: "frozen-tx-v3",
    fixtureKey: "frozenTx",
    moved: ["normalizeFrozenTxV3", "canonicalFrozenTxJson", "frozenTxCommitment", "feeDescriptorFromFrozen"],
    coreOnly: ["fail"],
    sdkImpure: ["TX_PROBE_PATH", "describeFrozenTx", "verifyApprovalSignature", "frozenToWasmTransaction"]
  },
  {
    file: "approval-package-v3",
    fixtureKey: "apV3",
    moved: [
      "APPROVAL_PACKAGE_SCHEMA",
      "PLACEHOLDER_APPROVAL",
      "p2pkScriptHex",
      "packageCommitmentV3",
      "collectedCount",
      "missingSlots",
      "isCompleteV3",
      "placeholderApprovalsBlob"
    ],
    coreOnly: ["commitmentPreimage"],
    sdkImpure: [
      "createApprovalPackageV3",
      "assertPackageIntegrity",
      "submitApprovalV3",
      "approvalsBlobV3",
      "approvalPackageToJson",
      "loadApprovalPackage"
    ]
  },
  {
    file: "approval-package-v4",
    fixtureKey: "apV4",
    moved: [
      "APPROVAL_PACKAGE_SCHEMA_V4",
      "PLACEHOLDER_APPROVAL",
      "placeholderApprovalsBlob",
      "p2pkScriptHex",
      "packageCommitmentV4",
      "collectedCountV4",
      "missingSlotsV4",
      "isCompleteV4"
    ],
    coreOnly: ["commitmentPreimage"],
    sdkImpure: [
      "createApprovalPackageV4",
      "assertPackageIntegrityV4",
      "submitApprovalV4",
      "approvalsBlobV4",
      "approvalPackageToJsonV4",
      "loadApprovalPackageV4"
    ]
  }
];

for (const { file, fixtureKey, moved, coreOnly, sdkImpure } of SPLIT) {
  const viaCore = require(path.join(CORE, file));
  const viaSdk = require(path.join(SDK, file));

  test(`api split: every moved ${file} member is the SAME object through both roots`, () => {
    for (const member of moved) {
      assert.ok(member in viaCore, `core/model/${file} must export ${member}`);
      assert.ok(member in viaSdk, `sdk/src/${file} must export ${member}`);
      assert.strictEqual(
        viaSdk[member],
        viaCore[member],
        `${file}.${member} must be the exact core object (single implementation)`
      );
    }
  });

  test(`api split: sdk/src/${file} exported keys + types are UNCHANGED from the pre-split fixture`, () => {
    const keys = Object.keys(viaSdk).sort();
    const types = {};
    for (const k of keys) types[k] = typeof viaSdk[k];
    assert.deepStrictEqual({ keys, types }, FIXTURE.apiSurface[fixtureKey]);
  });

  test(`api split: core/model/${file} exports exactly the designed pure surface`, () => {
    assert.deepStrictEqual(Object.keys(viaCore).sort(), [...moved, ...coreOnly].sort());
    for (const member of sdkImpure) {
      assert.ok(!(member in viaCore), `core/model/${file} must NOT export impure member ${member}`);
      assert.ok(member in viaSdk, `sdk/src/${file} must still export impure member ${member}`);
    }
  });
}

test("api split: core commitment preimage builders are exactly the hashers' preimages", () => {
  const coreV3 = require(path.join(CORE, "approval-package-v3"));
  const coreV4 = require(path.join(CORE, "approval-package-v4"));
  const sha256 = (s) => crypto.createHash("sha256").update(s, "utf8").digest("hex");

  const sp3 = fixtures.syntheticPackageV3();
  assert.strictEqual(sha256(coreV3.commitmentPreimage(sp3)), coreV3.packageCommitmentV3(sp3));
  assert.strictEqual(coreV3.packageCommitmentV3(sp3), FIXTURE.pure.apV3.syntheticCommitment);

  const sp4 = fixtures.syntheticPackageV4();
  assert.strictEqual(sha256(coreV4.commitmentPreimage(sp4)), coreV4.packageCommitmentV4(sp4));
  assert.strictEqual(coreV4.packageCommitmentV4(sp4), FIXTURE.pure.apV4.syntheticCommitment);
});
