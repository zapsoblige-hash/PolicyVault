"use strict";

const path = require("path");
const fs = require("fs");

const HOME = process.env.HOME;

if (!HOME) {
  throw new Error("HOME environment variable is missing");
}

/*
 * The repository root is derived from this module's location (sdk/src/..),
 * NOT from a fixed home-directory name, so a checkout works wherever it is
 * cloned: contracts resolve inside the checkout and per-network data roots
 * live inside the checkout (data/ and data-mainnet/, both gitignored).
 * External sibling toolchains (silverscript, rusty-kaspa) remain
 * HOME-anchored documented prerequisites.
 */
const REPO_ROOT = path.join(__dirname, "..", "..");

const Network = Object.freeze({
  TESTNET_10: "testnet-10",
  MAINNET: "mainnet"
});

const CONTRACT_VERSION = "policyvault-0.1-beta";

/*
 * Voluntary-support donation destination (docs/product-policy.md): the
 * project owner's PUBLIC mainnet receiving address. Overridable via
 * POLICYVAULT_DONATION_ADDRESS; never derived from any wallet/vault/test
 * key; validated through sdk/src/donation-address.js before display.
 */
const DEFAULT_DONATION_ADDRESS = "kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn";

/*
 * Mainnet is intentionally locked. Enabling it requires BOTH the explicit
 * environment flag and a per-call override, and broadcasting on mainnet
 * additionally requires separate explicit human authorization (mission
 * §62). Unknown networks fail closed.
 */
function loadConfig(overrides = {}) {
  const networkId = overrides.networkId ?? process.env.KASPA_NETWORK_ID ?? Network.TESTNET_10;

  if (!Object.values(Network).includes(networkId)) {
    throw new Error(`config: unknown networkId ${JSON.stringify(networkId)} — failing closed`);
  }

  const explicitRpcUrl = overrides.rpcUrl ?? process.env.KASPA_RPC_URL;
  const rpcUrl = explicitRpcUrl ?? "ws://127.0.0.1:18210";

  const allowMainnet =
    (overrides.allowMainnet ?? false) === true &&
    process.env.POLICYVAULT_ALLOW_MAINNET === "true";

  if (networkId === Network.MAINNET && !allowMainnet) {
    throw new Error(
      "config: PolicyVault mainnet mode is locked. " +
        "It requires POLICYVAULT_ALLOW_MAINNET=true and an explicit allowMainnet override " +
        "(the Gate R release procedure, docs/production-release.md §8)."
    );
  }

  // A mainnet process must never inherit the testnet default RPC endpoint:
  // the node URL is part of the explicit Gate R deployment procedure (§8).
  if (networkId === Network.MAINNET && !explicitRpcUrl) {
    throw new Error(
      "config: mainnet requires an explicit KASPA_RPC_URL (or rpcUrl override) — refusing the testnet default endpoint."
    );
  }

  return Object.freeze({
    networkId,
    rpcUrl,
    contractVersion: CONTRACT_VERSION,

    repoRoot: REPO_ROOT,
    contractSource: path.join(REPO_ROOT, "contracts/PolicyVault.v0.1.beta.sil"),
    silvercPath: overrides.silvercPath ?? path.join(HOME, "silverscript/target/debug/silverc"),
    rustyKaspaModule: overrides.rustyKaspaModule ?? path.join(HOME, "rusty-kaspa/wasm/nodejs/kaspa"),

    // NETWORK DATA SEPARATION (Checkpoint I §11): mainnet and testnet
    // persistent state never share a directory. testnet-10 keeps the
    // historical `data/` root (all existing evidence stays valid); mainnet
    // uses its own `data-mainnet/` root. assertDataRootNetwork() additionally
    // stamps and enforces the owning network per root.
    dataRoot:
      overrides.dataRoot ??
      (networkId === Network.MAINNET ? path.join(REPO_ROOT, "data-mainnet") : path.join(REPO_ROOT, "data")),

    donationAddress: overrides.donationAddress ?? process.env.POLICYVAULT_DONATION_ADDRESS ?? DEFAULT_DONATION_ADDRESS,

    allowMainnet
  });
}

/*
 * Operational-network gate (Gate R, authorized by the owner 2026-08-22:
 * "Authorize Gate R. Enable PolicyVault mainnet production release.").
 * The live transaction pipeline (build / preflight / submit / reconcile)
 * operates on EXACTLY two networks: testnet-10, and mainnet when — and only
 * when — the config object carries the dual-flag unlock that loadConfig
 * grants (env flag AND explicit override). A hand-rolled mainnet config
 * without that unlock, and every other network id, fails closed here even
 * though loadConfig would already have refused to construct it.
 */
function assertOperationalNetwork(config) {
  const networkId = config ? config.networkId : undefined;
  if (networkId === Network.TESTNET_10) return networkId;
  if (networkId === Network.MAINNET) {
    if (config.allowMainnet !== true) {
      const e = new Error("network: mainnet config lacks the dual-flag unlock (allowMainnet) — refusing");
      e.code = "NETWORK_UNSUPPORTED";
      throw e;
    }
    return networkId;
  }
  const e = new Error(`network: ${JSON.stringify(networkId)} is not an operational PolicyVault network — failing closed`);
  e.code = "NETWORK_UNSUPPORTED";
  throw e;
}

/*
 * Cross-network contamination gate (§11): every data root is stamped with the
 * ONE network that owns it (`.pv-network`, write-once). A process configured
 * for a different network REFUSES to touch the root — a mainnet process can
 * never consume testnet manifests/requests/claims, and vice versa. Called at
 * server startup; safe to call repeatedly.
 */
function assertDataRootNetwork(config) {
  fs.mkdirSync(config.dataRoot, { recursive: true });
  const marker = path.join(config.dataRoot, ".pv-network");
  if (fs.existsSync(marker)) {
    const owner = fs.readFileSync(marker, "utf8").trim();
    if (owner !== config.networkId) {
      throw new Error(
        `data root ${config.dataRoot} belongs to network ${JSON.stringify(owner)} but this process is configured for ${JSON.stringify(config.networkId)} — refusing to start (cross-network data contamination)`
      );
    }
    return config.dataRoot;
  }
  fs.writeFileSync(marker, `${config.networkId}\n`, { mode: 0o600 });
  return config.dataRoot;
}

module.exports = {
  Network,
  CONTRACT_VERSION,
  DEFAULT_DONATION_ADDRESS,
  loadConfig,
  assertOperationalNetwork,
  assertDataRootNetwork
};
