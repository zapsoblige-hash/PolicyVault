"use strict";

/*
 * CHECKPOINT I §31 — production-guard sabotage sensitivity.
 *
 * For each declared production guard, this NEUTRALIZES the guard in the real
 * production source (string mutation), busts the module cache, proves the
 * protecting assertion turns RED, then restores the file BYTE-IDENTICALLY
 * (SHA re-checked). Guards covered here (the live/consensus guard set is
 * covered by the established §35 suite + live matrices):
 *
 *   S1 terminal-vault write rejection        (wallet-requests-v4.js)
 *   S2 dev-signer production disable         (server/src/api.js)
 *   S3 donation-address network validation   (donation-address.js)
 *   S4 legacy-creation production disable    (server/src/api.js)
 *   S5 cross-network data-root separation    (config.js)
 *   S6 mainnet dual-flag lock                (config.js)
 *
 * Target: 0 blind spots for the declared production guard set.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const SDK_SRC = path.join(__dirname, "..", "src");
const SERVER_SRC = path.join(__dirname, "..", "..", "server", "src");
const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function bustCache() {
  for (const k of Object.keys(require.cache)) {
    if (k.includes(`${path.sep}sdk${path.sep}src${path.sep}`) || k.includes(`${path.sep}server${path.sep}src${path.sep}`)) {
      delete require.cache[k];
    }
  }
}

async function withSabotage(absFile, from, to, scenario) {
  const original = fs.readFileSync(absFile);
  const originalSha = sha(original);
  const text = original.toString("utf8");
  assert.ok(text.includes(from), `sabotage anchor must be present in ${path.basename(absFile)}: ${from.slice(0, 60)}`);
  const mutated = text.replace(from, to);
  assert.notEqual(mutated, text, "mutation must change the source");
  try {
    fs.writeFileSync(absFile, mutated);
    bustCache();
    await scenario();
  } finally {
    fs.writeFileSync(absFile, original);
    bustCache();
    assert.equal(sha(fs.readFileSync(absFile)), originalSha, `${path.basename(absFile)} must be restored byte-identically`);
  }
}

// Fresh config/module loaders (post-cache-bust safe).
const freshConfig = (over = {}) => require("../src/config").loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-sab-")), ...over });

// Shared fixtures for the terminal guard.
function seedRecovered(config) {
  bustCache();
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const vaultId = "7b".repeat(32);
  persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: "policyvault-0.4.1", networkId: config.networkId, vaultId,
    label: "sab-terminal", status: "RECOVERED", template: { owner: XO(1), vaultId },
    agentRegistry: [{ agentPk: XO(0x1e), maxPerSpend: "1", periodBudget: "1", periodLengthDaa: "864000", periodStartDaa: "1", periodSpent: "0", approvalThreshold: "0", agentMaxFeePerTx: "1", recipients: [XO(0x28)] }],
    live: null, creationTxId: "42".repeat(32), latestTransitionTxId: "43".repeat(32), lastTransition: null
  });
  return { vaultId, agentAddr: KEY(0x1e).toPublicKey().toAddress(config.networkId).toString(), XO };
}

test("S1 terminal-vault write rejection is load-bearing", async () => {
  const config = freshConfig();
  const { vaultId, agentAddr, XO } = seedRecovered(config);
  const attempt = () => {
    const wr4 = require("../src/wallet-requests-v4");
    try {
      wr4.buildWalletRequestV4({ config, vaultId, action: "agentSpend", params: { agentPk: XO(0x1e), recipient: XO(0x28), payAmountSompi: "1" }, signerAddress: agentAddr });
      return "BUILT";
    } catch (e) {
      return e.code;
    }
  };
  assert.equal(attempt(), "VAULT_TERMINAL", "REAL guard refuses terminal writes with VAULT_TERMINAL");
  await withSabotage(
    path.join(SDK_SRC, "wallet-requests-v4.js"),
    'if (!manifest.live) throw fail(`vault is ${manifest.status} (closed)',
    'if (false && !manifest.live) throw fail(`vault is ${manifest.status} (closed)',
    () => {
      assert.notEqual(attempt(), "VAULT_TERMINAL", "SABOTAGED guard no longer produces VAULT_TERMINAL -> protecting assertion is RED");
    }
  );
  assert.equal(attempt(), "VAULT_TERMINAL", "restored guard is green again");
});

test("S2 dev-signer production disable is load-bearing", async () => {
  assert.notEqual(process.env.POLICYVAULT_DEV_SIGNER, "1", "suite must run without the dev env");
  const config = freshConfig();
  const probe = async () => {
    const api = require("../../server/src/api");
    try {
      await api.handle(config, "GET", ["wallet", "dev-accounts"], {}, null);
      return "SERVED";
    } catch (e) {
      return e.code;
    }
  };
  assert.equal(await probe(), "DEV_SIGNER_DISABLED", "REAL guard hides the dev signer without the env");
  await withSabotage(
    path.join(SERVER_SRC, "api.js"),
    'const devSignerEnabled = process.env.POLICYVAULT_DEV_SIGNER === "1" && config.networkId !== "mainnet";',
    "const devSignerEnabled = true;",
    async () => {
      assert.notEqual(await probe(), "DEV_SIGNER_DISABLED", "SABOTAGED guard exposes the dev signer -> RED");
    }
  );
  assert.equal(await probe(), "DEV_SIGNER_DISABLED");
});

test("S3 donation-address network validation is load-bearing", async () => {
  const config = freshConfig();
  const kaspa = require(config.rustyKaspaModule);
  const testnetAddr = new kaspa.PrivateKey("11".repeat(32)).toPublicKey().toAddress("testnet-10").toString();
  const probe = () => {
    const { validateDonationAddress } = require("../src/donation-address");
    try {
      validateDonationAddress(config, testnetAddr);
      return "ACCEPTED";
    } catch (e) {
      return e.code;
    }
  };
  assert.equal(probe(), "DONATION_WRONG_NETWORK", "REAL guard rejects a testnet donation address");
  await withSabotage(
    path.join(SDK_SRC, "donation-address.js"),
    'if (address.prefix !== "kaspa") {',
    "if (false) {",
    () => {
      assert.equal(probe(), "ACCEPTED", "SABOTAGED guard accepts a testnet donation address -> RED");
    }
  );
  assert.equal(probe(), "DONATION_WRONG_NETWORK");
});

test("S4 legacy-creation production disable is load-bearing", async () => {
  assert.notEqual(process.env.POLICYVAULT_LEGACY_CREATE, "1", "suite must run without the legacy env");
  const config = freshConfig();
  const probe = async () => {
    const api = require("../../server/src/api");
    try {
      await api.handle(config, "POST", ["wallet", "create"], {}, { signerAddress: "junk" });
      return "SERVED";
    } catch (e) {
      return e.code;
    }
  };
  assert.equal(await probe(), "LEGACY_CREATE_DISABLED", "REAL guard blocks legacy creation");
  await withSabotage(
    path.join(SERVER_SRC, "api.js"),
    'if (process.env.POLICYVAULT_LEGACY_CREATE !== "1") {',
    "if (false) {",
    async () => {
      assert.equal(await probe(), "BAD_SIGNER", "SABOTAGED guard lets legacy creation reach validation -> RED");
    }
  );
  assert.equal(await probe(), "LEGACY_CREATE_DISABLED");
});

test("S5 cross-network data-root separation is load-bearing", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pv-sab-net-"));
  fs.writeFileSync(path.join(root, ".pv-network"), "testnet-10\n");
  const probe = () => {
    const { assertDataRootNetwork } = require("../src/config");
    try {
      assertDataRootNetwork({ networkId: "mainnet", dataRoot: root });
      return "ACCEPTED";
    } catch (e) {
      return /cross-network/.test(e.message) ? "REFUSED" : "OTHER";
    }
  };
  assert.equal(probe(), "REFUSED", "REAL guard refuses a foreign-network data root");
  await withSabotage(
    path.join(SDK_SRC, "config.js"),
    "if (owner !== config.networkId) {",
    "if (false) {",
    () => {
      assert.equal(probe(), "ACCEPTED", "SABOTAGED guard consumes a foreign-network data root -> RED");
    }
  );
  assert.equal(probe(), "REFUSED");
});

test("S6 mainnet dual-flag lock is load-bearing", async () => {
  // The probe supplies an explicit rpcUrl so the (separate, Gate R) explicit-
  // RPC guard is satisfied and the ONLY thing standing between the probe and
  // a mainnet config is the dual-flag lock under test. Without the rpcUrl the
  // sabotaged run would still be blocked by that second guard — proven by the
  // final DEFENSE-IN-DEPTH assertion below.
  const probe = (extra = {}) => {
    const { loadConfig } = require("../src/config");
    try {
      loadConfig({ networkId: "mainnet", rpcUrl: "ws://127.0.0.1:1", dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-sab-main-")), ...extra });
      return "UNLOCKED";
    } catch (e) {
      return /mainnet mode is locked/.test(e.message) ? "LOCKED" : "OTHER";
    }
  };
  assert.equal(probe(), "LOCKED", "REAL lock refuses mainnet without both flags");
  await withSabotage(
    path.join(SDK_SRC, "config.js"),
    "if (networkId === Network.MAINNET && !allowMainnet) {",
    "if (false) {",
    () => {
      assert.equal(probe(), "UNLOCKED", "SABOTAGED lock builds a mainnet config -> RED");
      // DEFENSE IN DEPTH (Gate R): even with the dual-flag lock neutralized,
      // a mainnet config with NO explicit rpcUrl is still refused by the
      // independent explicit-RPC guard.
      assert.equal(probe({ rpcUrl: undefined }), "OTHER", "explicit-RPC guard still blocks the sabotaged lock");
    }
  );
  assert.equal(probe(), "LOCKED");
});
