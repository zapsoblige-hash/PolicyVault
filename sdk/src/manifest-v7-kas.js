"use strict";

/*
 * Durable, versioned manifest for a PolicyVault v0.7-kas ROOTED KAS
 * SAFE-PAYMENT VAULT (contractVersion "policyvault-0.7-kas" — CANDIDATE,
 * not covenant-byte-frozen; docs/postlaunch/v0.7-kas-profile-readiness.md).
 * v0.7 mainnet-enablement directive (2026-09-10).
 *
 * Mirrors sdk/src/manifest-v7.js's rooted-vault discipline (unknown
 * schemas/versions fail closed; only a proven successor advances `live`;
 * NO owner key here at all — the vault's owner authority IS its pinned
 * organizational root, enforced in-VM) with the frozen v0.4.1 STATE and
 * AGENT REGISTRY shapes, verbatim:
 *   - state: protectedValue / feeReserve / paused / agentRoot /
 *     approverSlots(10) / approvalM / policyNonce (core/model/vault-state-v4);
 *   - registry: v0.4.1 agent policies (maxPerSpend, periodBudget,
 *     periodLengthDaa, periodStartDaa, periodSpent, approvalThreshold,
 *     agentMaxFeePerTx, agentRecipientRoot) + each agent's recipient list
 *     (sdk/src/manifest-v4.js normalizeRegistry) — the registry MUST
 *     reproduce the covenant agentRoot or the record is refused;
 *   - the covenant UTXO carries protectedValue + feeReserve (plain KAS —
 *     unlike the payment profile whose covenant value is just feeReserve);
 *     no descriptor, no token family, no token position.
 *
 * Stored under the SAME Categories.VAULT category every other manifest
 * uses (one JSON object per vaultId), discriminated by its `schema` tag.
 *
 * Status: IMPLEMENTED. Exercised by sdk/test/wallet-v7-kas-api.test.js.
 */

const { getStore, Categories } = require("./store");
const { createVaultRecordOrMatch } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): atomic create-only genesis completion
const { normalizeHex } = require("./vault-state");
const { CONTRACT_VERSION_V7_KAS, resolveV7KasAbi, normalizeTemplateV7Kas, computeStateIdV7Kas } = require("../../core/model/vault-state-v7-kas");
const { normalizeStateV4, stateToJsonV4 } = require("../../core/model/vault-state-v4");
const { normalizeRegistry, registryEntryToJson } = require("./manifest-v4");
const { rootPinsFromTemplate } = require("./manifest-v7");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");

const MANIFEST_SCHEMA_V7_KAS = "policyvault-rooted-kas-vault-manifest-record/1";

function fail(message, code) {
  const error = new Error(`manifest-v7-kas: ${message}`);
  if (code) error.code = code;
  throw error;
}

function normalizeOutpoint(input, field) {
  if (!input || typeof input !== "object") fail(`${field} outpoint object required`);
  const transactionId = normalizeHex(input.transactionId, 32, `${field}.transactionId`);
  const index = Number(input.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffff) fail(`${field}.index must be a small non-negative integer`);
  return Object.freeze({ transactionId, index });
}

/* The covenant UTXO value a v0.7-kas state pins: protectedValue + feeReserve. */
function liveValueOfStateKas(state) {
  return state.protectedValue + state.feeReserve;
}

function normalizeManifestV7Kas(input) {
  if (!input || typeof input !== "object") fail("manifest object required");
  if (input.schema !== MANIFEST_SCHEMA_V7_KAS) fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed (a vault stored under a different covenant generation's schema is refused, never adapted)`, "UNKNOWN_VERSION");
  const abi = resolveV7KasAbi(input.contractVersion);
  if (typeof input.networkId !== "string" || input.networkId.length === 0) fail("networkId required");
  if (!Object.values(VaultStatus).includes(input.status)) fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);

  const template = normalizeTemplateV7Kas(input.template);
  if (input.orgRootCovenantId !== undefined && normalizeHex(input.orgRootCovenantId, 32, "orgRootCovenantId") !== template.orgRootCovenantId) {
    fail("orgRootCovenantId != template.orgRootCovenantId — a rooted vault's root pin is immutable; failing closed", "ROOT_PIN_MISMATCH");
  }
  const rootPins = rootPinsFromTemplate(template);
  if (input.rootPins !== undefined) {
    const declared = input.rootPins;
    const drift = ["orgRootCovenantId", "rootTemplateVmHash", "rootPrefixLen", "rootStateLen", "rootSuffixLen"].filter((f) => String(declared?.[f]) !== String(rootPins[f]));
    if (drift.length) fail(`manifest.rootPins does not match the template's own root pins: ${drift.join(", ")} — failing closed`, "ROOT_PIN_MISMATCH");
  }

  const { entries, tree } = normalizeRegistry(input.agentRegistry);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null && input.live !== undefined) fail(`${input.status} manifest must carry live: null`);
  } else {
    const state = normalizeStateV4(input.live?.state);
    const stateId = computeStateIdV7Kas({ networkId: input.networkId, template, state, contractVersion: abi.version });
    if (input.live.stateId !== stateId) fail("manifest live.stateId does not match its state tuple — failing closed");
    if (liveValueOfStateKas(state).toString() !== String(input.live.outpointValue)) fail("manifest live outpoint value does not equal protectedValue + feeReserve — failing closed");
    if (tree.root !== state.agentRoot) {
      fail(`agent registry root ${tree.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "REGISTRY_ROOT_MISMATCH");
    }
    if ((Number(state.paused) === 1) !== (input.status === VaultStatus.PAUSED)) fail(`status ${input.status} disagrees with the covenant paused byte ${state.paused} — failing closed`);
    live = Object.freeze({
      state,
      stateId,
      outpoint: normalizeOutpoint(input.live.outpoint, "live.outpoint"),
      outpointValue: liveValueOfStateKas(state),
      scriptSha256: normalizeHex(input.live.scriptSha256, 32, "live.scriptSha256"),
      covenantId: normalizeHex(input.live.covenantId, 32, "live.covenantId")
    });
  }

  return Object.freeze({
    schema: MANIFEST_SCHEMA_V7_KAS,
    contractVersion: abi.version,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    orgRootCovenantId: template.orgRootCovenantId,
    rootPins,
    template,
    agentRegistry: Object.freeze(entries),
    agentRegistryRoot: tree.root,
    live,
    creationTxId: input.creationTxId == null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId: input.latestTransitionTxId == null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    generation: Number.isInteger(input.generation) ? input.generation : 0,
    createdAt: typeof input.createdAt === "string" ? input.createdAt : new Date().toISOString(),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function manifestToJsonV7Kas(normalized) {
  return {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    live: normalized.live
      ? { ...normalized.live, state: stateToJsonV4(normalized.live.state), outpointValue: normalized.live.outpointValue.toString() }
      : null
  };
}

async function loadManifestV7Kas(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  if (stored === null) return null;
  if (stored.schema !== MANIFEST_SCHEMA_V7_KAS) return null; // another generation's record under the same category — let the caller try its family
  return normalizeManifestV7Kas(stored);
}

async function persistManifestV7Kas(config, manifest) {
  const normalized = normalizeManifestV7Kas({ ...manifest, updatedAt: new Date().toISOString() });
  await getStore(config).write(Categories.VAULT, normalized.vaultId, manifestToJsonV7Kas(normalized));
  return normalized;
}

/*
 * RC33-ID-01 (2026-09-11): the CREATE-ONLY sibling of the persist function above, for a PROVEN genesis — the SAME
 * normalization and encoding, then sdk/src/vault-identity.js's atomic create-or-match write instead of an overwrite.
 * Returns { manifest, outcome: "CREATED" | "ALREADY_PRESENT" }; throws RECONCILIATION_REQUIRED when the identity holds a
 * DIFFERENT record of any generation (left untouched). Transitions keep advancing an existing record through persist.
 */
async function createManifestV7Kas(config, manifest) {
  const normalized = normalizeManifestV7Kas({ ...manifest, updatedAt: new Date().toISOString() });
  const { outcome } = await createVaultRecordOrMatch(config, normalized.vaultId, manifestToJsonV7Kas(normalized));
  return { manifest: normalized, outcome };
}

async function listRootedKasVaultsV7(config, { orgRootCovenantId } = {}) {
  const all = await getStore(config).listValues(Categories.VAULT);
  const out = [];
  for (const v of all) {
    if (!v || v.schema !== MANIFEST_SCHEMA_V7_KAS) continue;
    if (orgRootCovenantId !== undefined && v.orgRootCovenantId !== orgRootCovenantId) continue;
    try {
      out.push(normalizeManifestV7Kas(v));
    } catch {
      /* a corrupt record is skipped in listings, exactly like every other category */
    }
  }
  return out;
}

module.exports = {
  MANIFEST_SCHEMA_V7_KAS,
  CONTRACT_VERSION_V7_KAS,
  normalizeManifestV7Kas,
  manifestToJsonV7Kas,
  loadManifestV7Kas,
  persistManifestV7Kas,
  createManifestV7Kas,
  listRootedKasVaultsV7,
  liveValueOfStateKas,
  normalizeRegistry,
  registryEntryToJson
};
