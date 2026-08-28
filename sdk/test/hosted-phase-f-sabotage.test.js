"use strict";

/*
 * PHASE F sabotage sensitivity (directive §43). The wallet-request
 * tenancy guard added in Phase F (server/src/tenancy.js
 * `requestAccessAllowed`) is the load-bearing check behind findings
 * F-1/F-2 (cross-tenant request read + reject). Each essential clause is
 * neutralized by a REAL in-source edit, the guard is shown to go RED
 * (a foreign or unauthenticated principal is wrongly allowed), then the
 * file is restored BYTE-IDENTICALLY. A clause whose removal changes
 * nothing would be a blind spot. Nothing sabotaged is ever committed.
 *
 * In-band, exclusive ownership of the tenancy source — the SDK suite runs
 * with --test-concurrency=1 (docs/test-plan.md rule 7), which is what
 * makes in-place mutation of a shared file safe here.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");

const TENANCY_SRC = path.join(__dirname, "..", "..", "server", "src", "tenancy.js");
const ORIGINAL = fs.readFileSync(TENANCY_SRC);
const ORIGINAL_SHA = crypto.createHash("sha256").update(ORIGINAL).digest("hex");

// A hosted config (tenancy enforced) and two distinct identities.
const config = loadConfig({ authMode: "enabled", authCookieInsecure: true, appOrigin: "http://app.pv-test.example", dataRoot: fs.mkdtempSync(require("os").tmpdir() + path.sep + "pv-f-sab-") });
const kaspa = require(config.rustyKaspaModule);
function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress("testnet-10").toString() };
}
const A = wallet("a1");
const B = wallet("b2");
const principalA = { xOnlyPubkey: A.xonly, networkId: "testnet-10" };
const principalB = { xOnlyPubkey: B.xonly, networkId: "testnet-10" };
const requestB = { signerAddress: B.address, vaultId: "b".repeat(64) };

/* Load a FRESH copy of tenancy.js from disk (bypassing require cache) so
 * an on-disk mutation is actually exercised, then restore byte-identically. */
function withSabotage(find, replace, fn) {
  const mutated = ORIGINAL.toString().replace(find, replace);
  assert.notEqual(mutated, ORIGINAL.toString(), "sabotage pattern must actually change the source");
  fs.writeFileSync(TENANCY_SRC, mutated);
  try {
    const tmp = path.join(path.dirname(TENANCY_SRC), `.tenancy.sabotage.${process.pid}.${Math.random().toString(36).slice(2)}.js`);
    fs.copyFileSync(TENANCY_SRC, tmp);
    try {
      const mod = require(tmp);
      return fn(mod);
    } finally {
      delete require.cache[require.resolve(tmp)];
      fs.unlinkSync(tmp);
    }
  } finally {
    fs.writeFileSync(TENANCY_SRC, ORIGINAL);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(TENANCY_SRC)).digest("hex"), ORIGINAL_SHA, "tenancy.js restored byte-identically");
  }
}

test("SABOTAGE baseline (control): the real guard denies a foreign/unauthenticated principal", () => {
  const mod = require(TENANCY_SRC);
  assert.equal(mod.requestAccessAllowed(config, requestB, principalB, null), true, "B (signer) allowed");
  assert.equal(mod.requestAccessAllowed(config, requestB, principalA, null), false, "A (foreign) DENIED");
  assert.equal(mod.requestAccessAllowed(config, requestB, null, null), false, "unauthenticated DENIED");
});

test("SABOTAGE S1: neutralizing default-deny lets a FOREIGN principal through (guard is load-bearing)", () => {
  // Replace the final default-deny with an allow.
  withSabotage("  // Covenant-participant rule (owner / agents / approvers of the vault).\n  if (loadedVault && vaultAccessAllowed(config, loadedVault, principal, \"read\")) return true;\n  return false;\n}",
    "  if (loadedVault && vaultAccessAllowed(config, loadedVault, principal, \"read\")) return true;\n  return true;\n}",
    (mod) => {
      // With default-deny removed, foreign A is wrongly allowed → the
      // Phase F cross-tenant assertion would FAIL.
      assert.equal(mod.requestAccessAllowed(config, requestB, principalA, null), true, "sabotage detected: foreign principal now allowed");
    });
  // restored: real guard denies again
  assert.equal(require(TENANCY_SRC).requestAccessAllowed(config, requestB, principalA, null), false);
});

test("SABOTAGE S2: neutralizing the tenancy switch bypasses hosted enforcement entirely", () => {
  // Force the self-hosted short-circuit even under hosted config.
  withSabotage("function requestAccessAllowed(config, request, principal, loadedVault) {\n  if (!config.tenancyEnforced) return true;",
    "function requestAccessAllowed(config, request, principal, loadedVault) {\n  if (true) return true;",
    (mod) => {
      assert.equal(mod.requestAccessAllowed(config, requestB, principalA, null), true, "sabotage detected: hosted enforcement bypassed");
      assert.equal(mod.requestAccessAllowed(config, requestB, null, null), true, "sabotage detected: even unauthenticated allowed");
    });
  assert.equal(require(TENANCY_SRC).requestAccessAllowed(config, requestB, null, null), false);
});

test("SABOTAGE integrity: tenancy.js SHA-256 is unchanged after the suite", () => {
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(TENANCY_SRC)).digest("hex"), ORIGINAL_SHA);
});
