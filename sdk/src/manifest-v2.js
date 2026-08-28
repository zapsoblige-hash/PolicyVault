"use strict";

/*
 * Durable, versioned vault manifest for PolicyVault v0.2 vaults.
 *
 * Same discipline as the v1 manifest: only proven chain reconciliation
 * advances it; unknown schemas/contract versions and ambiguous live state
 * fail closed. v2 additionally records the last lifecycle transition with
 * full predecessor AND successor identities.
 */

const path = require("path");
const fs = require("fs");

const { getStore, Categories } = require("./store");
const { normalizeHex } = require("./vault-state");
const { normalizeTemplateV2, normalizeStateV2, computeStateIdV2, CONTRACT_VERSION_V2, stateToJson } = require("./vault-state-v2");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");

const MANIFEST_SCHEMA_V2 = "policyvault-vault-manifest/v2";

function fail(message) {
  throw new Error(`manifest-v2: ${message}`);
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

function normalizeTransition(input) {
  if (input === null || input === undefined) {
    return null;
  }
  return Object.freeze({
    action: String(input.action),
    txId: normalizeHex(input.txId, 32, "lastTransition.txId"),
    oldStateId: normalizeHex(input.oldStateId, 32, "lastTransition.oldStateId"),
    newStateId: input.newStateId === null ? null : normalizeHex(input.newStateId, 32, "lastTransition.newStateId"),
    oldOutpoint: normalizeOutpoint(input.oldOutpoint, "lastTransition.oldOutpoint"),
    newOutpoint: input.newOutpoint === null ? null : normalizeOutpoint(input.newOutpoint, "lastTransition.newOutpoint"),
    contractVersion: CONTRACT_VERSION_V2
  });
}

function normalizeManifestV2(input) {
  if (!input || typeof input !== "object") {
    fail("manifest object required");
  }
  if (input.schema !== MANIFEST_SCHEMA_V2) {
    fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  if (input.contractVersion !== CONTRACT_VERSION_V2) {
    fail(`unknown contract version ${JSON.stringify(input.contractVersion)} — failing closed`);
  }
  if (typeof input.networkId !== "string" || input.networkId.length === 0) {
    fail("networkId required");
  }
  if (!Object.values(VaultStatus).includes(input.status)) {
    fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);
  }

  const template = normalizeTemplateV2(input.template);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null) {
      fail(`${input.status} manifest must carry live: null`);
    }
  } else {
    const state = normalizeStateV2(input.live?.state);
    const stateId = computeStateIdV2({ networkId: input.networkId, template, state });
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
    schema: MANIFEST_SCHEMA_V2,
    contractVersion: CONTRACT_VERSION_V2,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    template,
    live,
    creationTxId: input.creationTxId === null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId:
      input.latestTransitionTxId === null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    lastTransition: normalizeTransition(input.lastTransition ?? null),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

async function loadManifestV2(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  return stored === null ? null : normalizeManifestV2(stored);
}

async function persistManifestV2(config, manifest) {
  const normalized = normalizeManifestV2({ ...manifest, updatedAt: new Date().toISOString() });
  /* Re-encode live state JSON-safely (BigInt fields). */
  const encoded = {
    ...normalized,
    live: normalized.live
      ? {
          ...normalized.live,
          state: stateToJson(normalized.live.state),
          outpointValue: normalized.live.outpointValue.toString()
        }
      : null
  };
  await getStore(config).write(Categories.VAULT, normalized.vaultId, encoded);
  return normalized;
}

/*
 * Version-aware loader: dispatches on the stored schema tag. Unknown
 * schemas fail closed; callers get { version: "v1" | "v2", manifest }.
 */
async function loadAnyManifest(config, vaultId) {
  const raw = await getStore(config).read(Categories.VAULT, vaultId);
  if (raw === null) {
    return null;
  }
  if (raw.schema === MANIFEST_SCHEMA_V2) {
    return { version: "v2", manifest: normalizeManifestV2(raw) };
  }
  if (raw.schema === "policyvault-vault-manifest/v4") {
    const { normalizeManifestV4 } = require("./manifest-v4");
    return { version: "v4", manifest: normalizeManifestV4(raw) };
  }
  if (raw.schema === "policyvault-vault-manifest/v1") {
    const { normalizeManifest } = require("./manifest");
    return { version: "v1", manifest: normalizeManifest(raw) };
  }
  fail(`unknown manifest schema ${JSON.stringify(raw.schema)} — failing closed`);
}

module.exports = {
  MANIFEST_SCHEMA_V2,
  normalizeManifestV2,
  loadManifestV2,
  persistManifestV2,
  loadAnyManifest
};
