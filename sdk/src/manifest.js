"use strict";

/*
 * Durable, versioned vault manifest — the exact-chain-state record for one
 * vault. The manifest only advances through proven chain reconciliation
 * (never on build/sign/submit alone). Unknown schema versions and
 * ambiguous live state fail closed.
 */

const path = require("path");
const fs = require("fs");

const { persistJsonDurably, readJsonStrict } = require("./durable-json");
const { normalizePolicy, normalizeState, computeStateId, normalizeHex } = require("./vault-state");
const { CONTRACT_VERSION } = require("./config");

const MANIFEST_SCHEMA = "policyvault-vault-manifest/v1";

const VaultStatus = Object.freeze({
  PENDING_CREATE: "PENDING_CREATE",
  ACTIVE: "ACTIVE",
  PAUSED: "PAUSED",
  RECOVERED: "RECOVERED",
  TERMINATED_UNKNOWN: "TERMINATED_UNKNOWN"
});

const TERMINAL_STATUSES = new Set([VaultStatus.RECOVERED, VaultStatus.TERMINATED_UNKNOWN]);

function fail(message) {
  throw new Error(`manifest: ${message}`);
}

function manifestPath(config, vaultId) {
  return path.join(config.dataRoot, "vaults", vaultId, "manifest.json");
}

function normalizeOutpoint(input, field) {
  if (!input || typeof input !== "object") {
    fail(`${field} outpoint object required`);
  }
  const transactionId = normalizeHex(input.transactionId, 32, `${field}.transactionId`);
  const index = Number(input.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffff) {
    fail(`${field}.index must be a small non-negative integer`);
  }
  return Object.freeze({ transactionId, index });
}

/*
 * Validate a full manifest object (as loaded from disk or about to be
 * persisted). Returns the normalized form with BigInt amounts.
 */
function normalizeManifest(input) {
  if (!input || typeof input !== "object") {
    fail("manifest object required");
  }
  if (input.schema !== MANIFEST_SCHEMA) {
    fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  if (input.contractVersion !== CONTRACT_VERSION) {
    fail(`unknown contract version ${JSON.stringify(input.contractVersion)} — failing closed`);
  }
  if (typeof input.networkId !== "string" || input.networkId.length === 0) {
    fail("networkId required");
  }
  if (!Object.values(VaultStatus).includes(input.status)) {
    fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);
  }

  const policy = normalizePolicy(input.policy);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status)) {
    if (input.live !== null) {
      fail(`terminal manifest must carry live: null`);
    }
  } else if (input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null) {
      fail("PENDING_CREATE manifest must carry live: null");
    }
  } else {
    const state = normalizeState(input.live?.state);
    const stateId = computeStateId({ networkId: input.networkId, policy, state });
    if (input.live.stateId !== stateId) {
      fail("manifest live.stateId does not match its state tuple — failing closed");
    }
    if (state.protectedValue.toString() !== String(input.live.outpointValue)) {
      fail("manifest live outpoint value does not equal protectedValue — failing closed");
    }
    live = Object.freeze({
      state,
      stateId,
      outpoint: normalizeOutpoint(input.live.outpoint, "live.outpoint"),
      outpointValue: state.protectedValue,
      scriptSha256: normalizeHex(input.live.scriptSha256, 32, "live.scriptSha256"),
      covenantId: normalizeHex(input.live.covenantId, 32, "live.covenantId")
    });
  }

  return Object.freeze({
    schema: MANIFEST_SCHEMA,
    contractVersion: CONTRACT_VERSION,
    networkId: input.networkId,
    vaultId: policy.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    policy,
    live,
    creationTxId: input.creationTxId === null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId:
      input.latestTransitionTxId === null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function loadManifest(config, vaultId) {
  const filePath = manifestPath(config, vaultId);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return normalizeManifest(readJsonStrict(filePath, "vault manifest"));
}

function persistManifest(config, manifest) {
  const normalized = normalizeManifest({ ...manifest, updatedAt: new Date().toISOString() });
  persistJsonDurably({
    filePath: manifestPath(config, normalized.vaultId),
    value: normalized
  });
  return normalized;
}

function listVaultIds(config) {
  const dir = path.join(config.dataRoot, "vaults");
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs
    .readdirSync(dir)
    .filter((name) => /^[0-9a-f]{64}$/.test(name) && fs.existsSync(path.join(dir, name, "manifest.json")));
}

module.exports = {
  MANIFEST_SCHEMA,
  VaultStatus,
  TERMINAL_STATUSES,
  normalizeManifest,
  loadManifest,
  persistManifest,
  listVaultIds,
  manifestPath
};
