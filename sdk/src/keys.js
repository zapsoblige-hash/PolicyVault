"use strict";

/*
 * Test-key management (TESTNET ONLY — never production key custody).
 *
 * Keys live under <repo>/keys/ which is gitignored. The funding key is a
 * dedicated testnet faucet-style key. PolicyVault never requests or
 * stores seed phrases or production owner keys; this module exists so
 * local testnet lifecycles can run unattended.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");
const { loadKaspa } = require("./chain");

const KEYS_SCHEMA = "policyvault-test-keys/v1";

function fail(message) {
  throw new Error(`keys: ${message}`);
}

function keysPath(config) {
  return path.join(config.repoRoot, "keys", "policyvault_test_keys.json");
}

function describeKey(kaspa, secretHex, networkId) {
  const sk = new kaspa.PrivateKey(secretHex);
  const pub = sk.toPublicKey();
  return {
    secret: secretHex,
    xonly: pub.toXOnlyPublicKey().toString(),
    address: pub.toAddress(networkId).toString()
  };
}

/*
 * Load the test keyring, generating fresh random keys on first use.
 * `fundingSecretHex` (optional) seeds the funding role explicitly.
 */
function loadOrCreateTestKeys(config, { fundingSecretHex } = {}) {
  if (config.networkId === "mainnet") {
    fail("test keys must never be used on mainnet");
  }
  const kaspa = loadKaspa(config);
  const filePath = keysPath(config);

  if (fs.existsSync(filePath)) {
    const stored = readJsonStrict(filePath, "test keys");
    if (stored.schema !== KEYS_SCHEMA) {
      fail(`unknown keys schema ${JSON.stringify(stored.schema)} — failing closed`);
    }
    const roles = {};
    for (const [role, secret] of Object.entries(stored.secrets)) {
      roles[role] = describeKey(kaspa, secret, config.networkId);
    }
    return roles;
  }

  const secrets = {
    owner: crypto.randomBytes(32).toString("hex"),
    delegate: crypto.randomBytes(32).toString("hex"),
    recipient1: crypto.randomBytes(32).toString("hex"),
    recipient2: crypto.randomBytes(32).toString("hex"),
    recipient3: crypto.randomBytes(32).toString("hex"),
    attacker: crypto.randomBytes(32).toString("hex")
  };
  if (fundingSecretHex) {
    if (!/^[0-9a-f]{64}$/.test(fundingSecretHex)) {
      fail("fundingSecretHex must be 32-byte hex");
    }
    secrets.funding = fundingSecretHex;
  }

  persistJsonDurably({
    filePath,
    value: {
      schema: KEYS_SCHEMA,
      warning: "TESTNET TEST KEYS ONLY - DO NOT USE WITH REAL MONEY",
      createdAt: new Date().toISOString(),
      secrets
    }
  });

  const roles = {};
  for (const [role, secret] of Object.entries(secrets)) {
    roles[role] = describeKey(kaspa, secret, config.networkId);
  }
  return roles;
}

module.exports = { loadOrCreateTestKeys, keysPath };
