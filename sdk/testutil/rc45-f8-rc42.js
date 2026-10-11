"use strict";
/*
 * RC45 F8 test support: RC42-written governed-request shapes for the T8 ladder
 * twin (plan rc45-simplified-plan-r2 §8 rules (CR-M13, CR2-L11: a missing or
 * mismatched POLICYVAULT_TEST_RC42_TREE is a FAIL, never a SKIP) and T8
 * "ladder twin (CR-M10)"). Internal RED-first regression material for the
 * RC45 candidate; not an audit.
 *
 * The RC42 writer is the EXISTING one of sdk/test/governance-attestation-ladder.test.js
 * (run as a child in its "rc42-writer" mode, unchanged): it loads ONLY the a84e2a9
 * modules of the tree it is given and writes the reviewed ladder population,
 * including TWIN_DEF_CREATOR_BUILT (the RC42 defect creator, BUILT, whose build
 * was refused 409 GOVERNANCE_PROPOSAL_TERMINAL) and TWIN_SHARER_CV (its
 * content-identical retry with a new proposal and the same fuel, advanced to
 * CHAIN_VERIFIED + receipt through RC42's own modules).
 *
 * The read-only extraction named by POLICYVAULT_TEST_RC42_TREE ships no VM
 * binaries, and its modules resolve pv_tx_probe / pv_call_encoder /
 * pv_vm_preflight tree-relatively, so the writer runs on a test-local overlay:
 * byte copies of the RC42 sdk/src, server/src, core and contracts (the writer
 * pins re-verified on the copy), links to the remaining RC42 directories and
 * dependencies, and links to this tree's VM binaries. The parent never loads
 * an RC42 module. TEST keys only (the writer's deterministic keys); every
 * config the writer builds reads no node (it never broadcasts or observes).
 */
const path = require("node:path"), fs = require("node:fs"), cp = require("node:child_process"), crypto = require("node:crypto");
const assert = require("node:assert/strict");

/* sdk/test/governance-attestation-ladder.test.js RC42_WRITER_PINS (a84e2a9), unchanged. */
const RC42_WRITER_PINS = Object.freeze({
  "server/src/api.js": "2b2c52907dd02c80989e41e59df112a58df2984afc562a3d3552925998b879f9",
  "server/src/governance.js": "d473675125157e7806b60832f4baf317766b6eb03a8b6e65fdf9f584a89b5fb3",
  "server/src/intent-records.js": "a3be61ac1f91b54daf8bec1841da7ea7607742efe0e3378b4cc0cc5494e12444",
  "sdk/src/store.js": "340cc27939a32d3f988d6066c7b5e104313d346922e7f003d176ce40cbdaaee6",
  "sdk/src/wallet-requests-v4.js": "267ea76b5f580cdf10495d83721b862748f416b7c5b1dea570047dd4d3178dfe",
  "server/src/migrate.js": "5214503c431c265f783cd6bc5ab32067a4aca02c94357c9933607eb081121413",
  "server/migrations/011_org_roots.sql": "9b0655f1c6de0eed7d2bd50b93bf81d775bd214ce0d71d522c0c8cb7b9822daf",
  "sdk/src/submission-claim.js": "fa79ee52c645f7004edc04a2d02a06bd8119ab949026750df8cb9816860c7e35"
});
const LADDER_SUITE = path.join(__dirname, "..", "test", "governance-attestation-ladder.test.js");
const VM_BIN = path.join(__dirname, "..", "..", "tests", "vm", "target", "debug");
const RESULT_TAG = "RC42-WRITER-RESULT ";
const sha256File = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

function verifyRc42Tree(tree) {
  assert.ok(typeof tree === "string" && path.isAbsolute(tree), "POLICYVAULT_TEST_RC42_TREE must name the absolute a84e2a9 extraction (a missing tree is a FAIL, never a SKIP; CR2-L11)");
  for (const [rel, pin] of Object.entries(RC42_WRITER_PINS)) assert.equal(sha256File(path.join(tree, rel)), pin, `RC42 writer file ${rel} is not the pinned a84e2a9 byte sequence`);
}
/* A test-local copy of the a84e2a9 extraction that can run its writers (see the header). */
function rc42Overlay(tree, root) {
  verifyRc42Tree(tree);
  for (const entry of fs.readdirSync(tree)) {
    if (entry === "sdk" || entry === "server") continue;
    if (entry === "core" || entry === "contracts") fs.cpSync(path.join(tree, entry), path.join(root, entry), { recursive: true });
    else fs.symlinkSync(path.join(tree, entry), path.join(root, entry));
  }
  for (const pkg of ["sdk", "server"]) {
    fs.mkdirSync(path.join(root, pkg));
    for (const entry of fs.readdirSync(path.join(tree, pkg))) {
      if (entry === "src") fs.cpSync(path.join(tree, pkg, "src"), path.join(root, pkg, "src"), { recursive: true });
      else fs.symlinkSync(path.join(tree, pkg, entry), path.join(root, pkg, entry));
    }
  }
  fs.mkdirSync(path.join(root, "tests", "vm", "target", "debug"), { recursive: true });
  for (const bin of ["pv_tx_probe", "pv_call_encoder", "pv_vm_preflight"]) {
    assert.ok(fs.existsSync(path.join(VM_BIN, bin)), `this tree's ${bin} is built (a missing VM toolchain is a FAIL, never a SKIP)`);
    fs.symlinkSync(path.join(VM_BIN, bin), path.join(root, "tests", "vm", "target", "debug", bin));
  }
  // The extraction is read-only; make the COPIED directories removable (links are never followed).
  (function writable(dir) {
    fs.chmodSync(dir, 0o755);
    for (const entry of fs.readdirSync(dir)) { const p = path.join(dir, entry); if (fs.lstatSync(p).isDirectory()) writable(p); }
  })(root);
  verifyRc42Tree(root);
  return root;
}

/*
 * Run the ladder suite's RC42 writer (unchanged) against `overlay`: backend "json" or "postgres" (then `pg` names the
 * database the parent created). Returns the writer's result ({ backend, networkId, control, defect, cases, twin }).
 */
function runRc42LadderWriter({ overlay, backend, dataRoot, pg = null, vaultId = "39".repeat(32), vaultPrefix = "3a".repeat(31) }) {
  const env = { ...process.env };
  delete env.POLICYVAULT_PV_VM_PREFLIGHT_PATH; delete env.POLICYVAULT_PV_CALL_ENCODER_PATH;
  const input = { tree: overlay, backend, dataRoot, vaultId, vaultPrefix, pg: pg ?? { host: "127.0.0.1", port: 0, user: "", database: "" } };
  const child = cp.spawnSync(process.execPath, [LADDER_SUITE, "rc42-writer", JSON.stringify(input)], { encoding: "utf8", env, timeout: 600000, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(child.status, 0, `the RC42 ladder writer failed (${backend}): ${(child.stderr || "").slice(-4000)}`);
  const line = (child.stdout || "").split("\n").find((l) => l.startsWith(RESULT_TAG));
  assert.ok(line, "the RC42 ladder writer reported its result");
  return JSON.parse(line.slice(RESULT_TAG.length));
}

module.exports = { RC42_WRITER_PINS, verifyRc42Tree, rc42Overlay, runRc42LadderWriter };
