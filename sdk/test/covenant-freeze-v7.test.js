"use strict";

/* UNIT — v0.7 ORGANIZATIONAL M-of-N OWNER ROOT COVENANT BYTE FREEZE guard
 * (owner-authorized by the Flagship Wave 2 directive of 2026-09-03 §0/§2,
 * conditional on a fresh mechanical pre-freeze verification reproducing the
 * recorded candidate exactly; record: docs/postlaunch/v0.7-covenant-byte-freeze.md).
 * The frozen bytes of contracts/PolicyVault.v0.7-root.sil (PolicyVaultOrgRoot)
 * and contracts/PolicyVault.v0.7-payment.sil (PolicyVaultRootedToken), their
 * byte-identical regeneration by the frozen generators (the payment generator
 * derives from FROZEN v0.5 by 13 exact-match edits and fails closed unless the
 * v0.5 bytes are the frozen ones), the frozen priors v0.5 / v0.6 they were
 * proven beside, and the live testnet-10 evidence identity are pinned by
 * sha256. Any drift fails this suite: a change to v0.7 is a NEW additive
 * covenant version (or rooted profile), never an in-place edit, unless the
 * established freeze-reopen process has been invoked by the owner. A byte
 * freeze deploys nothing, creates no mainnet organization, forces no
 * migration, and does not supersede frozen v0.5/v0.6. Covenant generation
 * v0.7 is unrelated to application release numbers. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..", "..");
const FROZEN = {
  root: {
    file: "contracts/PolicyVault.v0.7-root.sil",
    sha256: "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce",
    generator: { file: "tools/gen_v7_root.js", sha256: "dba4e37f79c893b24eb34893f78072eb0e70e0cf1ad502bdd10080bf48eb0763" }
  },
  payment: {
    file: "contracts/PolicyVault.v0.7-payment.sil",
    sha256: "09cdbb6c284d8bd6c4cd2f4aad20d9682172eea3e048631176034b517be25091",
    generator: { file: "tools/gen_v7_payment.js", sha256: "0d4d4008dcf0eeb65dd242764a81a352b3b63191f5e60a6f38a2cb6a3467817b" }
  },
  /* the frozen prior lineages this generation was proven beside; re-pinned so
   * a v0.7 change can never be smuggled in as a v0.5/v0.6 edit or vice versa */
  priorV5: {
    file: "contracts/PolicyVault.v0.5.sil",
    sha256: "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9"
  },
  priorV6: {
    file: "contracts/PolicyVault.v0.6.sil",
    sha256: "c7c5f22c54a55d933ec8440a28bc2c628b9b99262541d50dbe9ffbdd16ba025c"
  },
  /* the live testnet-10 organizational lifecycle the freeze rests on */
  liveEvidence: {
    file: "docs/testnet-v7-org-root-evidence.json",
    sha256: "8874ae62b8f46df33675828f80f3db72257cbd17cf10b5ba6e56492c127d790d"
  }
};

function sha256Of(relPath) {
  return crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, relPath))).digest("hex");
}

function regenerates(entry, label) {
  assert.equal(sha256Of(entry.generator.file), entry.generator.sha256, `${entry.generator.file} drifted from the frozen generator identity`);
  const outPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), `pv7-freeze-${label}-`)), "regen.sil");
  const result = spawnSync("node", [path.join(repoRoot, entry.generator.file)], {
    encoding: "utf8",
    env: { ...process.env, OUT: outPath }
  });
  assert.equal(result.status, 0, `generator failed: ${result.stderr}`);
  const regenerated = fs.readFileSync(outPath);
  const committed = fs.readFileSync(path.join(repoRoot, entry.file));
  assert.ok(regenerated.equals(committed), `regenerated ${entry.file} must equal the frozen committed source byte-for-byte`);
}

test("v0.7 ROOT covenant bytes (PolicyVaultOrgRoot) are FROZEN at the recorded sha256", () => {
  assert.equal(sha256Of(FROZEN.root.file), FROZEN.root.sha256,
    "contracts/PolicyVault.v0.7-root.sil drifted from the frozen bytes — v0.7 is byte-frozen; make a new additive version or invoke the freeze-reopen process");
});

test("v0.7 ROOTED PAYMENT covenant bytes (PolicyVaultRootedToken) are FROZEN at the recorded sha256", () => {
  assert.equal(sha256Of(FROZEN.payment.file), FROZEN.payment.sha256,
    "contracts/PolicyVault.v0.7-payment.sil drifted from the frozen bytes — v0.7 is byte-frozen; make a new additive rooted profile or invoke the freeze-reopen process");
});

test("the frozen v0.7 generators are unchanged and regenerate both frozen covenants byte-identically", () => {
  regenerates(FROZEN.root, "root");
  regenerates(FROZEN.payment, "payment");
});

test("frozen v0.5 and v0.6 remain byte-identical beside frozen v0.7 (additive lineages)", () => {
  assert.equal(sha256Of(FROZEN.priorV5.file), FROZEN.priorV5.sha256, "contracts/PolicyVault.v0.5.sil drifted — frozen lineages are never mutated in place");
  assert.equal(sha256Of(FROZEN.priorV6.file), FROZEN.priorV6.sha256, "contracts/PolicyVault.v0.6.sil drifted — frozen lineages are never mutated in place");
});

test("the live testnet-10 evidence the v0.7 freeze rests on is unchanged", () => {
  assert.equal(sha256Of(FROZEN.liveEvidence.file), FROZEN.liveEvidence.sha256, "docs/testnet-v7-org-root-evidence.json drifted (closed evidence is never edited)");
  const evidence = JSON.parse(fs.readFileSync(path.join(repoRoot, FROZEN.liveEvidence.file), "utf8"));
  assert.equal(evidence.summary.lifecycleStepsAccepted, 19);
  assert.equal(evidence.summary.negativeValidationsRejected, 9);
  assert.equal(evidence.summary.ageProofs, 2);
  assert.equal(evidence.summary.rootCovenantId, "9a654cb0cbf6e67178e0d228bf5fa39ae6aca7655718dcf63166273df135edf6");
  assert.equal(evidence.summary.finalRootOutpoint, "6626f2daedc2d5349d5f099706e9c65dea969af446c04584997ab9bf00d1ef57:1");
  assert.equal(evidence.mainnet, false);
});

test("the rooted payment generator fails closed when its frozen v0.5 base is not the frozen bytes", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv7-freeze-drift-"));
  const driftedBase = path.join(dir, "drifted-v0.5.sil");
  fs.writeFileSync(driftedBase, fs.readFileSync(path.join(repoRoot, FROZEN.priorV5.file), "utf8") + "\n// drift\n");
  const result = spawnSync("node", [path.join(repoRoot, FROZEN.payment.generator.file)], {
    encoding: "utf8",
    env: { ...process.env, OUT: path.join(dir, "out.sil"), BASE: driftedBase }
  });
  if (result.status === 0) {
    /* the generator ignores BASE: it must then still have read the frozen base and produced the frozen bytes */
    assert.ok(fs.readFileSync(path.join(dir, "out.sil")).equals(fs.readFileSync(path.join(repoRoot, FROZEN.payment.file))),
      "a generator that ignores BASE must still reproduce the frozen bytes from the frozen base");
  } else {
    assert.match(`${result.stderr}${result.stdout}`, /c693aeff|frozen|sha256|drift/i, "the refusal names the base identity check");
  }
});
