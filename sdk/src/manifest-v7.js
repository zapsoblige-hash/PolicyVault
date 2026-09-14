"use strict";

/*
 * Durable, versioned manifest for a PolicyVault v0.7 ROOTED PAYMENT VAULT
 * (docs/postlaunch/v0.7-app-surface-contract.md §1; derived from the
 * proven manifest-v5.js discipline: unknown schemas/versions fail closed,
 * only a proven successor advances `live`, the agent registry MUST
 * reproduce the covenant agentRoot).
 *
 * What is different from a v0.5 controller manifest: there is NO owner key
 * and NO owner authorization here at all. A rooted vault's owner authority
 * IS its pinned organizational root (`orgRootCovenantId` + the exact
 * template identity/geometry `rootPins`), enforced in-VM. This module never
 * checks a signer against an "owner" field — that check does not exist for
 * v0.7 — every owner-operation authorization lives in the root's own
 * quorum, verified by `sdk/src/wallet-requests-v7.js` and ultimately by
 * Kaspa consensus.
 *
 * Stored under the SAME Categories.VAULT category the v0.2/v0.4/v0.5
 * manifests use (one JSON object per vaultId) — `resolveV7Abi` distinguishes
 * a v0.7 record by its `contractVersion`.
 *
 * Status: IMPLEMENTED (Wave 2 Track B). UNIT-TESTED by
 * sdk/test/org-roots-api.test.js and sdk/test/hosted-pg-org-roots.test.js.
 */

const path = require("path");
const { getStore, Categories } = require("./store");
const { createVaultRecordOrMatch } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): atomic create-only genesis completion
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { CONTRACT_VERSION_V7, resolveV7Abi, normalizeTemplateV7, normalizeStateV7, computeStateIdV7, stateToJsonV7 } = require("../../core/model/vault-state-v7");
const { buildTokenAgentTreeV5, normalizeTokenAgentPolicyV5, tokenAgentPolicyToJsonV5 } = require("./agent-merkle-v5");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");
const assets = require("../../core/assets");
const { parseSompi } = require("./amounts");

const MANIFEST_SCHEMA_V7 = "policyvault-rooted-vault-manifest-record/1";

function fail(message, code) {
  const error = new Error(`manifest-v7: ${message}`);
  if (code) error.code = code;
  throw error;
}

function manifestPath(config, vaultId) {
  return path.join(config.dataRoot, "vaults", vaultId, "manifest.json");
}

function normalizeOutpoint(input, field) {
  if (!input || typeof input !== "object") fail(`${field} outpoint object required`);
  const transactionId = normalizeHex(input.transactionId, 32, `${field}.transactionId`);
  const index = Number(input.index);
  if (!Number.isInteger(index) || index < 0 || index > 0xffff) fail(`${field}.index must be a small non-negative integer`);
  return Object.freeze({ transactionId, index });
}

function normalizeRegistryEntry(entry, i) {
  if (!entry || typeof entry !== "object") fail(`agentRegistry[${i}] must be an object`);
  if (!Array.isArray(entry.recipients) || entry.recipients.length === 0) fail(`agentRegistry[${i}].recipients must be a non-empty array of x-only keys`);
  const recipients = entry.recipients.map((r, j) => normalizeXOnlyPubkey(r, `agentRegistry[${i}].recipients[${j}]`));
  const recipientRoot = buildRecipientTree(recipients).root;
  if (entry.agentRecipientRoot !== undefined) {
    const declared = normalizeHex(entry.agentRecipientRoot, 32, `agentRegistry[${i}].agentRecipientRoot`);
    if (declared !== recipientRoot) fail(`agentRegistry[${i}].agentRecipientRoot does not match its recipient set — failing closed`, "REGISTRY_RECIPIENT_MISMATCH");
  }
  const policy = normalizeTokenAgentPolicyV5({
    agentPk: entry.agentPk,
    tokenMaxPerSpend: entry.tokenMaxPerSpend,
    tokenPeriodBudget: entry.tokenPeriodBudget,
    periodLengthDaa: entry.periodLengthDaa,
    periodStartDaa: entry.periodStartDaa,
    tokenPeriodSpent: entry.tokenPeriodSpent,
    agentMaxFeePerTx: entry.agentMaxFeePerTx,
    agentMaxCarryKas: entry.agentMaxCarryKas,
    agentRecipientRoot: recipientRoot
  });
  return { policy, recipients: Object.freeze(recipients) };
}

function registryEntryToJson({ policy, recipients }) {
  return { ...tokenAgentPolicyToJsonV5(policy), recipients: [...recipients] };
}

function normalizeRegistry(input) {
  const entries = (Array.isArray(input) ? input : []).map(normalizeRegistryEntry);
  const tree = buildTokenAgentTreeV5(entries.map((e) => e.policy));
  return { entries, tree };
}

/* The vault's token position — the TOKEN domain's live balance. */
function normalizeTokenPosition(input, expectedFamilyId) {
  if (input === null || input === undefined) return null;
  if (typeof input !== "object") fail("tokenPosition must be an object or null");
  const state = assets.kcc20.normalizeState(input.state);
  const covenantId = normalizeHex(input.covenantId, 32, "tokenPosition.covenantId");
  if (covenantId !== expectedFamilyId) fail("tokenPosition.covenantId != the vault's pinned tokenCovenantId — wrong asset family; failing closed", "WRONG_TOKEN_FAMILY");
  return Object.freeze({
    outpoint: normalizeOutpoint(input.outpoint, "tokenPosition.outpoint"),
    value: parseSompi(input.value, "tokenPosition.value"),
    scriptPublicKeyHex: String(input.scriptPublicKeyHex ?? "").toLowerCase(),
    covenantId,
    state
  });
}

/* `rootPins` — the exact identity a rooted vault must present at ITS root
 * to authorize an owner path: named separately from `template` (which
 * carries them too) because reconcile-v7 and the explain layer read them
 * without re-normalizing the whole template. Always derived FROM the
 * normalized template, never accepted as an independent input, so the two
 * can never silently disagree. */
function rootPinsFromTemplate(t) {
  return Object.freeze({
    orgRootCovenantId: t.orgRootCovenantId,
    rootTemplateVmHash: t.rootTemplateVmHash,
    rootPrefixLen: t.rootPrefixLen,
    rootStateLen: t.rootStateLen,
    rootSuffixLen: t.rootSuffixLen
  });
}

function normalizeManifestV7(input) {
  if (!input || typeof input !== "object") fail("manifest object required");
  if (input.manifestVersion !== MANIFEST_SCHEMA_V7) fail(`unknown manifest schema ${JSON.stringify(input.manifestVersion)} — failing closed`);
  const abi = resolveV7Abi(input.contractVersion);
  if (typeof input.networkId !== "string" || input.networkId.length === 0) fail("networkId required");
  if (!Object.values(VaultStatus).includes(input.status)) fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);

  const template = normalizeTemplateV7(input.template);

  /* DESCRIPTOR PIN: the accepted descriptor must hash to the vault's pinned descriptorHash. */
  const descriptor = assets.validateAssetDescriptor(input.asset?.descriptor);
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  if (descriptorHash !== template.descriptorHash) fail("accepted descriptor hash != the vault's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (input.asset.descriptorHash !== undefined && String(input.asset.descriptorHash).toLowerCase() !== descriptorHash) fail("asset.descriptorHash does not match the descriptor — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (descriptor.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != vault tokenCovenantId — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  const templateIndex = Number.isInteger(input.asset.templateIndex) ? input.asset.templateIndex : 0;
  const tpl = descriptor.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("asset.templateIndex does not name the descriptor template the vault pins (hash/geometry) — failing closed", "TEMPLATE_PIN_MISMATCH");
  }

  if (normalizeHex(input.orgRootCovenantId, 32, "orgRootCovenantId") !== template.orgRootCovenantId) {
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
    const state = normalizeStateV7(input.live?.state);
    const stateId = computeStateIdV7({ networkId: input.networkId, template, state, contractVersion: abi.version });
    if (input.live.stateId !== stateId) fail("manifest live.stateId does not match its state tuple — failing closed");
    if (state.feeReserve.toString() !== String(input.live.outpointValue)) fail("manifest live outpoint value does not equal feeReserve — failing closed");
    if (tree.root !== state.agentRoot) {
      fail(`agent registry root ${tree.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "REGISTRY_ROOT_MISMATCH");
    }
    const tokenPosition = normalizeTokenPosition(input.live.tokenPosition, template.tokenCovenantId);
    if (tokenPosition && (tokenPosition.state.ownerIdentifier !== normalizeHex(input.live.covenantId, 32, "live.covenantId") || tokenPosition.state.identifierType !== assets.kcc20.OWNER_SCHEMES.COVENANT_ID)) {
      fail("live.tokenPosition is not owned by this vault's covenant id — failing closed", "TOKEN_NOT_OWNED");
    }
    live = Object.freeze({
      state,
      stateId,
      outpoint: normalizeOutpoint(input.live.outpoint, "live.outpoint"),
      outpointValue: state.feeReserve,
      scriptSha256: normalizeHex(input.live.scriptSha256, 32, "live.scriptSha256"),
      covenantId: normalizeHex(input.live.covenantId, 32, "live.covenantId"),
      tokenPosition
    });
  }

  return Object.freeze({
    manifestVersion: MANIFEST_SCHEMA_V7,
    contractVersion: abi.version,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    orgRootCovenantId: template.orgRootCovenantId,
    rootPins,
    template,
    asset: Object.freeze({ descriptor, descriptorHash, templateIndex }),
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

function manifestToJsonV7(normalized) {
  return {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    live: normalized.live
      ? {
          ...normalized.live,
          state: stateToJsonV7(normalized.live.state),
          outpointValue: normalized.live.outpointValue.toString(),
          tokenPosition: normalized.live.tokenPosition
            ? { ...normalized.live.tokenPosition, value: normalized.live.tokenPosition.value.toString(), state: { ...normalized.live.tokenPosition.state, amount: normalized.live.tokenPosition.state.amount.toString() } }
            : null
        }
      : null
  };
}

async function loadManifestV7(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  if (stored === null) return null;
  if (stored.manifestVersion !== MANIFEST_SCHEMA_V7) return null; // a v2/v4/v5 record under the same category — not ours
  return normalizeManifestV7(stored);
}

async function persistManifestV7(config, manifest) {
  const normalized = normalizeManifestV7({ ...manifest, updatedAt: new Date().toISOString() });
  await getStore(config).write(Categories.VAULT, normalized.vaultId, manifestToJsonV7(normalized));
  return normalized;
}

/*
 * RC33-ID-01 (2026-09-11): the CREATE-ONLY sibling of the persist function above, for a PROVEN genesis — the SAME
 * normalization and encoding, then sdk/src/vault-identity.js's atomic create-or-match write instead of an overwrite.
 * Returns { manifest, outcome: "CREATED" | "ALREADY_PRESENT" }; throws RECONCILIATION_REQUIRED when the identity holds a
 * DIFFERENT record of any generation (left untouched). Transitions keep advancing an existing record through persist.
 */
async function createManifestV7(config, manifest) {
  const normalized = normalizeManifestV7({ ...manifest, updatedAt: new Date().toISOString() });
  const { outcome } = await createVaultRecordOrMatch(config, normalized.vaultId, manifestToJsonV7(normalized));
  return { manifest: normalized, outcome };
}

async function listRootedVaultsV7(config, { orgRootCovenantId } = {}) {
  const all = await getStore(config).listValues(Categories.VAULT);
  const out = [];
  for (const v of all) {
    if (!v || v.manifestVersion !== MANIFEST_SCHEMA_V7) continue;
    if (orgRootCovenantId !== undefined && v.orgRootCovenantId !== orgRootCovenantId) continue;
    try {
      out.push(normalizeManifestV7(v));
    } catch {
      /* a corrupt record is skipped in listings, exactly like every other category */
    }
  }
  return out;
}

module.exports = {
  MANIFEST_SCHEMA_V7,
  CONTRACT_VERSION_V7,
  normalizeManifestV7,
  manifestToJsonV7,
  loadManifestV7,
  persistManifestV7,
  createManifestV7,
  listRootedVaultsV7,
  normalizeRegistry,
  registryEntryToJson,
  rootPinsFromTemplate,
  manifestPath
};
