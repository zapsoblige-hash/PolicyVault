"use strict";
/*
 * Codex checkpoint 3 (UX-02) — the shared-core reconstruction of the v0.7
 * root locking script (core/intent/root-script-v7.js) is cross-checked
 * against the REAL vendored compiler (silverc) across a value matrix: for
 * every template constant encoding class (OP_0, OP_1..16, 1..5-byte pushes,
 * zero/non-zero successor) and owner-set sizes 1/3/5/12 the reconstructed
 * script and its P2SH must equal silverc's output byte for byte. Any drift
 * between the skeleton and the frozen generation breaks this test.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { loadConfig } = require("../src/config");
const { compileExactStateV7Root } = require("../src/contract-compiler-v7");
const { genesisRootStateV7, normalizeRootTemplateV7 } = require("../../core/model/vault-state-v7-root");
const { normalizeOwnerSetV7, INACTIVE_SLOT_KEY } = require("../../core/model/owner-set-v7");
const R = require("../../core/intent/root-script-v7");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rootscript-")) });
const available = fs.existsSync(config.silvercPath);
const K = (b) => b.toString(16).padStart(2, "0").repeat(32);
const owners = (n) => Array.from({ length: 12 }, (_, i) => (i < n ? K(0x71 + i) : INACTIVE_SLOT_KEY));
const BASE = { orgId: K(0xa1), recoveryDelayDaa: "287454020", successorPk: K(0xb2), successionDelayDaa: "1432778632", rootMaxFeePerTx: "180079837" };

function silvercScript(t, os_) {
  const template = normalizeRootTemplateV7(t);
  const state = genesisRootStateV7({ template, ownerSet: normalizeOwnerSetV7(os_) });
  const c = compileExactStateV7Root({ config, template, state });
  return { hex: c.scriptHex, prefixLen: c.rootPrefixLen, stateLen: c.rootStateLen, suffixLen: c.rootSuffixLen, state, template };
}

test("silverc cross-check: reconstruction equals the compiler byte for byte across the constant-encoding matrix and owner-set sizes", { skip: !available && "vendored silverc not staged" }, () => {
  const matrix = [];
  for (const v of ["1", "16", "17", "127", "128", "255", "256", "65536", "2147483647", "2147483648", "4294967295"]) matrix.push({ t: { ...BASE, recoveryDelayDaa: v }, os: owners(3) });
  for (const v of ["1", "128", "4294967295"]) matrix.push({ t: { ...BASE, successionDelayDaa: v }, os: owners(3) });
  for (const v of ["0", "1", "16", "17", "127", "128", "1000", "100000", "100000000000"]) matrix.push({ t: { ...BASE, rootMaxFeePerTx: v }, os: owners(3) });
  for (const v of ["00".repeat(32), "ff".repeat(32)]) matrix.push({ t: { ...BASE, successorPk: v }, os: owners(3) });
  matrix.push({ t: { ...BASE, orgId: K(0x05), recoveryDelayDaa: "38880000", successorPk: "00".repeat(32), successionDelayDaa: "77760000", rootMaxFeePerTx: "100000" }, os: owners(3) });
  for (const [n, m, k, r] of [[1, "1", "1", "0"], [5, "3", "2", "2"], [12, "12", "12", "12"]]) matrix.push({ t: BASE, os: owners(n), m, k, r });
  let checked = 0;
  for (const c of matrix) {
    const os_ = { owners: c.os, ownerM: c.m || "2", emergencyK: c.k || "1", recoveryM: c.r || "1" };
    const want = silvercScript(c.t, os_);
    const got = R.reconstructRootScriptHexV7({ template: want.template, state: want.state });
    assert.equal(got, want.hex.toLowerCase(), `reconstruction differs from silverc for ${JSON.stringify({ t: c.t, os: os_.ownerM })}`);
    assert.equal(want.prefixLen, 1); assert.equal(want.stateLen, 467);
    assert.equal(R.genesisRootSpkHexV7({ template: c.t, ownerSet: os_ }), R.p2shSpkHexOf(want.hex.toLowerCase()));
    checked += 1;
  }
  assert.ok(checked >= 28, `matrix size ${checked}`);
});

test("silverc cross-check: the skeleton belongs to the FROZEN generation (script size class and pins)", { skip: !available && "vendored silverc not staged" }, () => {
  const want = silvercScript(BASE, { owners: owners(3), ownerM: "2", emergencyK: "1", recoveryM: "1" });
  assert.equal(want.hex.length / 2, 1 + 467 + want.suffixLen);
  assert.ok(want.suffixLen > 11000 && want.suffixLen < 11200, `suffix ${want.suffixLen}`);
});
