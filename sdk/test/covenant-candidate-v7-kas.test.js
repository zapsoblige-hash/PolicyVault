"use strict";
/* UNIT — v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT: CANDIDATE IDENTITY PIN
 * (v0.7 mainnet-enablement directive, 2026-09-10).
 *
 * This is NOT a byte freeze. The KAS treasury profile is promoted to the
 * owner-reviewed mainnet set as a CANDIDATE: the exact bytes the release was
 * reviewed, reproduced, proven (VM / SDK production-byte / live testnet-10)
 * and Codex-reviewed against are pinned here so that a change to them is a
 * DELIBERATE new candidate (update the pin AND the readiness record
 * docs/postlaunch/v0.7-kas-profile-readiness.md, re-run the proofs) and never
 * a silent drift. A byte FREEZE of this profile is a separate, owner-decided
 * step (exact identities + fresh reproducibility + proofs + Codex
 * confirmation); until then every surface labels the profile CANDIDATE.
 * Frozen priors (v0.7-root it is rooted on, v0.4.1 whose delegate rules it
 * carries) are re-pinned so a KAS change can never be smuggled in as an edit
 * to a frozen generation or vice versa. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const repoRoot = path.resolve(__dirname, "..", "..");
const CANDIDATE = {
  file: "contracts/PolicyVault.v0.7-kas.sil",
  sha256: "393f2130b48d06ba4d5b29ad8846098dd16ae89ebfd658a2df163f0801ac1d8b",
  generator: { file: "tools/gen_v7_kas.js", sha256: "1cd3d30be883afb338ac156c4bb9c983b198e954e27c4e0ef1a5769a161a7014" },
  /* the mechanically derived template skeleton (R7-04) belongs to exactly this source */
  skeleton: { file: "core/intent/vault-script-v7-kas.js", sha256: "13709e50585d8d77a95eb3c981045bb153ec95c08d8ba837acc21b8d1f4d1904" },
  status: "CANDIDATE"
};
const FROZEN_PRIORS = {
  root: { file: "contracts/PolicyVault.v0.7-root.sil", sha256: "69417514f90d61b0281ea673e6fb5a5fd858c2bd50e14a4eb9043d5fdf17f8ce" },
  v041: { file: "contracts/PolicyVault.v0.4.1.sil", sha256: "421bfed824cf66a9e989f90c5b86fc7359faa070a5d94aace3c325f35ad1da4e" }
};
const sha256Of = (rel) => crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, rel))).digest("hex");

test("v0.7-kas CANDIDATE: the reviewed covenant source and its generator are pinned (a change is a deliberate new candidate, never a silent drift)", () => {
  assert.equal(sha256Of(CANDIDATE.file), CANDIDATE.sha256, `${CANDIDATE.file} drifted from the reviewed CANDIDATE bytes — re-pin deliberately with a new readiness record and fresh proofs`);
  assert.equal(sha256Of(CANDIDATE.generator.file), CANDIDATE.generator.sha256, `${CANDIDATE.generator.file} drifted from the reviewed generator`);
});

test("v0.7-kas CANDIDATE: the generator regenerates the reviewed source byte for byte (OUT=<path>)", () => {
  const outPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pv7kas-candidate-")), "regen.sil");
  const result = spawnSync("node", [path.join(repoRoot, CANDIDATE.generator.file)], { encoding: "utf8", env: { ...process.env, OUT: outPath } });
  assert.equal(result.status, 0, `generator failed: ${result.stderr}`);
  assert.ok(fs.readFileSync(outPath).equals(fs.readFileSync(path.join(repoRoot, CANDIDATE.file))), "regenerated source must equal the committed candidate byte for byte");
});

test("v0.7-kas CANDIDATE: the shared-core template skeleton is bound to exactly this source (R7-04 reconstruction identity)", () => {
  const V = require("../../core/intent/vault-script-v7-kas");
  assert.equal(V.VAULT_SCRIPT_COVENANT_SOURCE_SHA256_V7_KAS, CANDIDATE.sha256, "the skeleton module names the candidate source it was derived from");
  assert.equal(V.VAULT_SCRIPT_SKELETON_SHA256_V7_KAS, CANDIDATE.skeleton.sha256, "the skeleton identity is the reviewed one");
  assert.equal(crypto.createHash("sha256").update(V.VAULT_SCRIPT_CHUNKS_V7_KAS.join("|") + "#" + V.VAULT_SCRIPT_HOLES_V7_KAS.join(",")).digest("hex"), CANDIDATE.skeleton.sha256, "the embedded chunks + holes hash to the pinned skeleton identity (same derivation as tools/derive-vault-script-skeleton-v7-kas.js)");
  assert.equal(V.VAULT_STATE_REGION_LEN_V7_KAS, 441);
  assert.equal(V.VAULT_SCRIPT_HOLES_V7_KAS.length, 27);
});

test("v0.7-kas CANDIDATE is labelled CANDIDATE (not frozen) wherever a status is declared: the contract-version registry, the readiness record and the freeze records", () => {
  const cv = require("../../core/model/contract-version");
  const entry = typeof cv.describeContractVersion === "function" ? cv.describeContractVersion("policyvault-0.7-kas") : null;
  if (entry && entry.status) assert.notEqual(String(entry.status).toUpperCase(), "FROZEN", "the registry must not call the candidate frozen");
  const readiness = fs.readFileSync(path.join(repoRoot, "docs/postlaunch/v0.7-kas-profile-readiness.md"), "utf8");
  assert.match(readiness, /CANDIDATE/);
  assert.ok(readiness.includes(CANDIDATE.sha256), "the readiness record names the exact candidate source identity");
  const freezeRecord = fs.readFileSync(path.join(repoRoot, "docs/postlaunch/v0.7-covenant-byte-freeze.md"), "utf8");
  assert.doesNotMatch(freezeRecord, /PolicyVault\.v0\.7-kas\.sil[^\n]*FROZEN/, "the v0.7 freeze record never lists the KAS profile as frozen");
  const capabilities = fs.readFileSync(path.join(repoRoot, "server/src/capabilities.js"), "utf8");
  assert.match(capabilities, /CONTRACT_VERSION_V7_KAS, status: "CANDIDATE"/, "the hosted discovery labels the profile CANDIDATE");
});

test("frozen priors the candidate is built beside stay frozen (a KAS change is never an edit to v0.7-root or v0.4.1)", () => {
  for (const [k, e] of Object.entries(FROZEN_PRIORS)) assert.equal(sha256Of(e.file), e.sha256, `${k}: ${e.file} drifted from its FROZEN bytes`);
});
