"use strict";

/* UNIT — v0.6 COVENANT BYTE FREEZE guard (owner-authorized by the flagship
 * directive of 2026-09-03 §2, conditional on exact mechanical
 * re-verification; record: docs/postlaunch/v0.6-covenant-byte-freeze.md).
 * The frozen bytes of contracts/PolicyVault.v0.6.sil, their byte-identical
 * regeneration by the frozen generator, the pool FIXTURE the production-byte
 * and live proofs were made against (a conformance fixture, NOT a product or
 * a venue endorsement), and the leaf fixtures pinned to the Rust leaf
 * functions are pinned by sha256. Any drift fails this suite: a change to
 * v0.6 is a NEW additive covenant version, never an in-place edit, unless the
 * established freeze-reopen process has been invoked by the owner. Frozen
 * v0.5 keeps its own guard (covenant-freeze-v5.test.js); both lineages stay
 * frozen independently. Covenant generation v0.6 is unrelated to application
 * release v1.6.0. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..", "..");
const FROZEN = {
  covenant: {
    file: "contracts/PolicyVault.v0.6.sil",
    sha256: "c7c5f22c54a55d933ec8440a28bc2c628b9b99262541d50dbe9ffbdd16ba025c"
  },
  generator: {
    file: "tools/gen_v6.js",
    sha256: "6e10c2c82bffc89ab2c53635a2a84b9a9aa8d9e49b689ef8a651875bb5e08870"
  },
  poolFixture: {
    file: "contracts/experiments/V6PoolFixture.sil",
    sha256: "c3590c82d81679bd00b3a8342604ffd220bf557fc72d937e84832a12c96a6faa"
  },
  agentLeafFixture: {
    file: "core/model/test/fixtures/token-agent-leaf-v6.json",
    sha256: "d6c4d21bf4d98cfcd2bbf6d1f520727fdbb12abb3b8cabed56793e731a14c9c4"
  },
  swapPolicyLeafFixture: {
    file: "core/model/test/fixtures/swap-policy-leaf-v6.json",
    sha256: "c76812334103642d6e76f214eecffc21eef3dc4c8951b18755b26cfb5c1ab6d2"
  },
  /* the frozen prior lineage this candidate was proven beside; re-pinned here
   * so a v0.6 change can never be smuggled in as a v0.5 edit or vice versa */
  priorV5: {
    file: "contracts/PolicyVault.v0.5.sil",
    sha256: "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9"
  }
};

function sha256Of(relPath) {
  return crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, relPath))).digest("hex");
}

test("v0.6 covenant bytes are FROZEN at the recorded sha256", () => {
  assert.equal(sha256Of(FROZEN.covenant.file), FROZEN.covenant.sha256,
    "contracts/PolicyVault.v0.6.sil drifted from the frozen bytes — v0.6 is byte-frozen; make a new additive version or invoke the freeze-reopen process");
});

test("the frozen v0.6 generator is unchanged and regenerates the frozen bytes byte-identically", () => {
  assert.equal(sha256Of(FROZEN.generator.file), FROZEN.generator.sha256, "tools/gen_v6.js drifted from the frozen generator identity");
  const outPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pv6-freeze-")), "regen.sil");
  const result = spawnSync("node", [path.join(repoRoot, FROZEN.generator.file)], {
    encoding: "utf8",
    env: { ...process.env, OUT: outPath }
  });
  assert.equal(result.status, 0, `generator failed: ${result.stderr}`);
  const regenerated = fs.readFileSync(outPath);
  const committed = fs.readFileSync(path.join(repoRoot, FROZEN.covenant.file));
  assert.ok(regenerated.equals(committed), "regenerated v0.6 covenant must equal the frozen committed source byte-for-byte");
});

test("the pool FIXTURE and the leaf fixtures the v0.6 proofs were made against are unchanged", () => {
  assert.equal(sha256Of(FROZEN.poolFixture.file), FROZEN.poolFixture.sha256, "contracts/experiments/V6PoolFixture.sil drifted (the conformance fixture is pinned; it is not a product)");
  assert.equal(sha256Of(FROZEN.agentLeafFixture.file), FROZEN.agentLeafFixture.sha256, "token-agent-leaf-v6.json fixture drifted");
  assert.equal(sha256Of(FROZEN.swapPolicyLeafFixture.file), FROZEN.swapPolicyLeafFixture.sha256, "swap-policy-leaf-v6.json fixture drifted");
});

test("frozen v0.5 remains byte-identical beside frozen v0.6 (additive lineages)", () => {
  assert.equal(sha256Of(FROZEN.priorV5.file), FROZEN.priorV5.sha256, "contracts/PolicyVault.v0.5.sil drifted — frozen lineages are never mutated in place");
});

test("no protocol-level artifact names a real DEX venue (fixture-only venue support)", () => {
  const protocolFiles = [
    FROZEN.covenant.file,
    FROZEN.generator.file,
    "core/model/swap-policy-v6.js",
    "core/model/vault-transitions-v6.js",
    "core/intent/swap-manifest-v6.js",
    "sdk/src/vault-builders-v6.js"
  ];
  for (const rel of protocolFiles) {
    const text = fs.readFileSync(path.join(repoRoot, rel), "utf8");
    for (const venue of ["kaspakaha", "kron"]) {
      assert.ok(!text.toLowerCase().includes(venue), `${rel} references "${venue}" — protocol artifacts must not bless a venue`);
    }
  }
});
