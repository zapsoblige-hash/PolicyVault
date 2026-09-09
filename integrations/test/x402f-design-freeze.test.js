"use strict";

/* UNIT — x402 FACILITATOR DESIGN FREEZE guard (owner-authorized 2026-09-02;
 * record docs/postlaunch/x402-facilitator-design-freeze.md). Pins the
 * frozen spec revision 3, the freeze record, and the frozen constants in
 * code. Any drift fails this suite: a change to the semantics of
 * pv-x402-kaspa-exact-upfront/1 or pv-x402-settlement/1 is a NEW version
 * or an owner-authorized freeze reopen, never an in-place edit. */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.join(__dirname, "..", "..");
const C = require("../x402-facilitator/constants");
const { CODE_NAMES, CODES } = require("../x402-facilitator/codes");

const FROZEN = {
  spec: { file: "docs/postlaunch/x402-facilitator-spec.md", sha256: "34493cc98e3183047bac30536e4208cab2171b7dd4d9da957abe68dacf50e308" },
  record: { file: "docs/postlaunch/x402-facilitator-design-freeze.md", sha256: "634e1a0343600a7da22e085dbb32d02da6b1692aab6a8acdf0e250b8a8a241e5" },
  covenantV5: { file: "contracts/PolicyVault.v0.5.sil", sha256: "c693aeffb59286d21d44452bde0943d78840b66cf480b629624b7747b4197dd9" }
};

const sha256Of = (rel) => crypto.createHash("sha256").update(fs.readFileSync(path.join(REPO, rel))).digest("hex");

test("the frozen design spec (revision 3) is byte-identical to the owner-authorized freeze", () => {
  assert.equal(sha256Of(FROZEN.spec.file), FROZEN.spec.sha256, "x402-facilitator-spec.md drifted from the frozen revision 3 — semantics changes are a new version or a freeze reopen; editorial re-pins must say so in the commit");
});

test("the freeze record is unchanged", () => {
  assert.equal(sha256Of(FROZEN.record.file), FROZEN.record.sha256, "x402-facilitator-design-freeze.md drifted");
});

test("the frozen v0.5 covenant bytes the token path relies on are untouched", () => {
  assert.equal(sha256Of(FROZEN.covenantV5.file), FROZEN.covenantV5.sha256);
});

test("frozen constants in code equal the freeze record", () => {
  assert.equal(C.X402_VERSION, 2);
  assert.equal(C.SCHEME, "exact");
  assert.equal(C.PAYMENT_FLOW, "upfront");
  assert.equal(C.KASPA_SCHEME_ID, "pv-x402-kaspa-exact-upfront/1");
  assert.equal(C.SETTLEMENT_POLICY_ID, "pv-x402-settlement/1");
  assert.equal(C.MIN_DEPTH_DAA_DEFAULT, 100n);
  assert.equal(C.MIN_DEPTH_DAA_FLOOR, 20n);
  assert.equal(C.MAX_WINDOW_DAA, 36000n);
  assert.deepEqual(C.NETWORK_IDENTIFIERS, ["kaspa:mainnet", "kaspa:testnet-10"]);
  assert.deepEqual(C.NETWORKS["kaspa:mainnet"], { identifier: "kaspa:mainnet", kaspadNetworkId: "mainnet", addressPrefix: "kaspa" });
  assert.deepEqual(C.NETWORKS["kaspa:testnet-10"], { identifier: "kaspa:testnet-10", kaspadNetworkId: "testnet-10", addressPrefix: "kaspatest" });
  assert.equal(C.ASSET_KAS, "KAS");
  assert.equal(C.ASSET_DESCRIPTOR_PREFIX, "pvad1:");
  assert.equal(C.EVIDENCE_SCHEMA, "policyvault-x402-facilitator-evidence/1");
  assert.equal(C.REQUIREMENT_DIGEST_DOMAIN, "policyvault-x402-facilitator-requirement/1");
  assert.equal(C.EVIDENCE_DIGEST_DOMAIN, "policyvault-x402-facilitator-evidence/1");
  assert.equal(C.CREDENTIAL_PREFIX, "pvx402f_");
  assert.ok(C.CREDENTIAL_RE.test(`pvx402f_${"0".repeat(64)}`));
  assert.ok(!C.CREDENTIAL_RE.test(`pvmk_${"0".repeat(64)}`), "a PolicyVault machine credential is never a facilitator credential");
  assert.deepEqual(C.PRINCIPAL_OPERATIONS, ["verify", "settle"]);
});

test("the reason-code set is closed: 5 RETRY, 2 PENDING, 24 REFUSE, 4 AUTH", () => {
  const byClass = {};
  for (const name of CODE_NAMES) byClass[CODES[name].cls] = (byClass[CODES[name].cls] ?? 0) + 1;
  assert.deepEqual(byClass, { RETRY: 5, PENDING: 2, REFUSE: 24, AUTH: 4 });
  assert.equal(CODE_NAMES.length, 35);
  assert.deepEqual(
    CODE_NAMES.filter((n) => CODES[n].cls === "AUTH"),
    ["CREDENTIAL_REQUIRED", "CREDENTIAL_INVALID", "SCOPE_FORBIDDEN", "PRINCIPAL_FORBIDDEN"]
  );
  assert.equal(CODES.toString, undefined, "null-prototype code table");
});

test("the frozen spec text carries the frozen identifiers verbatim", () => {
  const text = fs.readFileSync(path.join(REPO, FROZEN.spec.file), "utf8");
  for (const needle of ["pv-x402-kaspa-exact-upfront/1", "pv-x402-settlement/1", "`kaspa:mainnet`", "`kaspa:testnet-10`", "PROVISIONAL", "MIN_DEPTH_DAA = 100", "HARD FLOOR `20`", "MAX_WINDOW_DAA = 36,000", "FACILITATOR-ISSUED API KEY OVER HTTPS", "mTLS = OPTIONAL FUTURE HARDENING", "policyvault-x402-facilitator-requirement/1", "pvx402f_"]) {
    assert.ok(text.includes(needle), `spec must contain ${needle}`);
  }
});
