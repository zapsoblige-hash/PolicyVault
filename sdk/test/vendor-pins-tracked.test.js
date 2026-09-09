"use strict";

/*
 * PERMANENT PIN — rc12 internal review R-06 (2026-09-05): the vendored
 * consensus-facing binaries (pv_call_encoder, pv_vm_preflight, pv_tx_probe,
 * silverc) are pinned in the TRACKED file deploy/vendor-pins.sha256 — the
 * reviewed source of truth for tools/verify-image-vendor-pins.sh — and the
 * machine-local staging inventory deploy/vendor/SHA256SUMS.txt (gitignored)
 * must agree with it whenever it exists. A divergent local vendor set can
 * therefore no longer be verified "against itself".
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const TRACKED = path.join(ROOT, "deploy/vendor-pins.sha256");
const LOCAL = path.join(ROOT, "deploy/vendor/SHA256SUMS.txt");
const REQUIRED = ["bin/pv_call_encoder", "bin/pv_vm_preflight", "bin/pv_tx_probe", "bin/silverc", "kaspa/kaspa.js", "kaspa/kaspa_bg.wasm"];

function parse(text) {
  const out = new Map();
  for (const line of text.split("\n")) {
    const m = line.match(/^([0-9a-f]{64})\s+(\S+)$/);
    if (m) out.set(m[2], m[1]);
  }
  return out;
}

test("deploy/vendor-pins.sha256 is tracked, well-formed, and pins the four consensus-facing binaries and the WASM module/glue", () => {
  assert.ok(fs.existsSync(TRACKED), "tracked pins file missing");
  const pins = parse(fs.readFileSync(TRACKED, "utf8"));
  assert.deepEqual([...pins.keys()].sort(), [...REQUIRED].sort());
  for (const [k, v] of pins) assert.match(v, /^[0-9a-f]{64}$/, k);
  const src = fs.readFileSync(path.join(ROOT, "tools/verify-image-vendor-pins.sh"), "utf8");
  assert.match(src, /deploy\/vendor-pins\.sha256/, "the verifier defaults to the tracked pins");
});

test("the machine-local staging inventory (when present) agrees byte-for-byte with the tracked pins; the staged binaries hash to the pins", () => {
  const pins = parse(fs.readFileSync(TRACKED, "utf8"));
  if (!fs.existsSync(LOCAL)) return; // no local vendor staging on this machine: nothing to compare (the image-side check is tools/verify-image-vendor-pins.sh)
  const local = parse(fs.readFileSync(LOCAL, "utf8"));
  for (const k of REQUIRED) assert.equal(local.get(k), pins.get(k), `${k}: local staging inventory diverges from the tracked pins`);
  const crypto = require("node:crypto");
  for (const k of REQUIRED) {
    const f = path.join(ROOT, "deploy/vendor", k);
    if (!fs.existsSync(f)) continue;
    const h = crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
    assert.equal(h, pins.get(k), `${k}: staged binary does not hash to the tracked pin`);
  }
});
