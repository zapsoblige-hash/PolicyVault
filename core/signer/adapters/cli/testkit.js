"use strict";

/*
 * UNIT-TEST support for the CLI keyfile signer suites (NOT a test file —
 * kept outside test/ so the node:test runner never counts it). Pure
 * helpers, no side effects at import, TEST keys only.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { defaultKaspaModulePath, KASPA_MODULE_ENV } = require("./adapter");

const CLI_PATH = path.join(__dirname, "cli.js");
const REPO_ROOT = path.resolve(__dirname, "../../../..");

/* Resolve the kaspa-wasm module path used by every suite (env override
 * respected; same default as the adapter / loadConfig()). */
function kaspaModulePath() {
  return process.env[KASPA_MODULE_ENV] || defaultKaspaModulePath();
}

function loadKaspaOrExplain() {
  const modulePath = kaspaModulePath();
  try {
    return require(modulePath);
  } catch (e) {
    throw new Error(
      `CLI signer tests need the vendored rusty-kaspa wasm nodejs build at ${modulePath} ` +
        `(set ${KASPA_MODULE_ENV} to override): ${e.message}`
    );
  }
}

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/* Deterministic THROWAWAY testnet secrets for fixtures that need a known
 * key (never used outside unit tests; sha256-derived, clearly labeled). */
function throwawayTestSecretHex(seed) {
  return crypto.createHash("sha256").update(`policyvault-cli-signer-throwaway-test-key:${seed}`, "utf8").digest("hex");
}

/*
 * Minimal single-input unsigned transaction whose input pays FROM the
 * given address (P2PK), serialized to Safe JSON — the frozen-bytes
 * fixture for signTransaction tests. Structure mirrors the probe used in
 * sdk builders (version/inputs/outputs/lockTime/subnetworkId/gas/payload).
 */
function buildUnsignedTxSafeJson(kaspa, address, { amount = 500_000_000n, fee = 10_000n } = {}) {
  const spk = kaspa.payToAddressScript(new kaspa.Address(address));
  const tx = new kaspa.Transaction({
    version: 0,
    inputs: [
      {
        previousOutpoint: { transactionId: "aa".repeat(32), index: 0 },
        signatureScript: "",
        sequence: 0n,
        sigOpCount: 1,
        utxo: {
          outpoint: { transactionId: "aa".repeat(32), index: 0 },
          amount,
          scriptPublicKey: spk,
          blockDaaScore: 1000n,
          isCoinbase: false
        }
      }
    ],
    outputs: [{ value: amount - fee, scriptPublicKey: spk }],
    lockTime: 0n,
    subnetworkId: "00".repeat(20),
    gas: 0n,
    payload: ""
  });
  return { unsignedSafeJson: tx.serializeToSafeJSON(), unsignedId: String(tx.id) };
}

/* Run the CLI as a child process with captured stdio. Environment is the
 * parent env plus overrides; the kaspa module path is always pinned so
 * the child resolves the same module as the test. */
function runCli(args, { env = {}, input } = {}) {
  const result = spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: "utf8",
    input,
    env: { ...process.env, [KASPA_MODULE_ENV]: kaspaModulePath(), ...env },
    timeout: 60_000
  });
  return { status: result.status, stdout: result.stdout || "", stderr: result.stderr || "" };
}

/*
 * Install a Module._load hook that satisfies `require("websocket")` with
 * an OFFLINE stub whose constructor throws — the hosted-auth interop test
 * loads the REAL server/src/auth.js (whose sdk/src/chain.js dependency
 * installs a global WebSocket transport at require time) inside this
 * worktree, which deliberately has no node_modules and must stay offline.
 * Any attempt to actually CONSTRUCT a socket during the flow fails the
 * test loudly. Returns an uninstaller.
 */
function installOfflineWebsocketStub() {
  const Module = require("module");
  const original = Module._load;
  Module._load = function offlineStubLoader(request) {
    if (request === "websocket") {
      return {
        w3cwebsocket: function OfflineStubWebSocket() {
          throw new Error("offline interop test: a network transport was constructed — the CLI signer flow must be fully offline");
        }
      };
    }
    return original.apply(this, arguments);
  };
  return () => {
    Module._load = original;
  };
}

module.exports = {
  CLI_PATH,
  REPO_ROOT,
  kaspaModulePath,
  loadKaspaOrExplain,
  makeTempDir,
  throwawayTestSecretHex,
  buildUnsignedTxSafeJson,
  runCli,
  installOfflineWebsocketStub
};
