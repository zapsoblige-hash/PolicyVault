"use strict";

/*
 * Durable, versioned manifest for a PolicyVault v0.6 OPTIONAL-ATOMIC-
 * COMPOSABILITY TOKEN CONTROLLER instance (Wave 2 Track E; mirrors the
 * proven sdk/src/manifest-v5.js discipline: unknown schemas/versions fail
 * closed, only a proven chain successor advances `live`, and every local
 * registry MUST reproduce its covenant-enforced merkle root before the
 * manifest is trusted for a build).
 *
 * Beyond manifest-v5.js's fields, a v0.6 manifest additionally carries:
 *   - the SWAP POLICY REGISTRY (owner-approved venue/pool/price-bound
 *     leaves, core/model/swap-policy-v6.js) whose root MUST reproduce the
 *     live state's swapRoot — exactly the same "local metadata must
 *     reconstruct the on-chain tree, or refuse" discipline as the agent
 *     registry;
 *   - swapPrincipal, the SECOND KAS domain a v0.6 controller UTXO carries
 *     (feeReserve + swapPrincipal == the controller UTXO's value; never
 *     summed with the token-domain balance, never summed with feeReserve
 *     in application logic beyond the one place the covenant itself sums
 *     them for the UTXO value).
 *
 * Status: IMPLEMENTED + UNIT-TESTED (sdk/test/wallet-v6-api.test.js).
 */

const path = require("path");
const { getStore, Categories } = require("./store");
const { createVaultRecordOrMatch } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): atomic create-only genesis completion
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { CONTRACT_VERSION_V6, resolveV6Abi, normalizeTemplateV6, normalizeStateV6, computeStateIdV6, stateToJsonV6, controllerValueV6 } = require("./vault-state-v6");
const { buildTokenAgentTreeV6, normalizeTokenAgentPolicyV6, tokenAgentPolicyToJsonV6 } = require("./agent-merkle-v6");
const { buildSwapPolicyTreeV6, normalizeSwapPolicyV6, swapPolicyToJsonV6 } = require("./swap-policy-v6");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");
const assets = require("../../core/assets");
const { parseSompi } = require("./amounts");

const MANIFEST_SCHEMA_V6 = "policyvault-controller-manifest/v6";

function fail(message, code) {
  const error = new Error(`manifest-v6: ${message}`);
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
  const policy = normalizeTokenAgentPolicyV6({
    agentPk: entry.agentPk,
    tokenMaxPerSpend: entry.tokenMaxPerSpend,
    tokenPeriodBudget: entry.tokenPeriodBudget,
    periodLengthDaa: entry.periodLengthDaa,
    periodStartDaa: entry.periodStartDaa,
    tokenPeriodSpent: entry.tokenPeriodSpent,
    agentMaxFeePerTx: entry.agentMaxFeePerTx,
    agentMaxCarryKas: entry.agentMaxCarryKas,
    kasMaxPerSwap: entry.kasMaxPerSwap ?? 0n,
    kasPeriodBudget: entry.kasPeriodBudget ?? 0n,
    kasPeriodSpent: entry.kasPeriodSpent ?? 0n,
    agentRecipientRoot: recipientRoot
  });
  return { policy, recipients: Object.freeze(recipients) };
}

function registryEntryToJson({ policy, recipients }) {
  return { ...tokenAgentPolicyToJsonV6(policy), recipients: [...recipients] };
}

function normalizeRegistry(input) {
  const entries = (Array.isArray(input) ? input : []).map(normalizeRegistryEntry);
  const tree = buildTokenAgentTreeV6(entries.map((e) => e.policy));
  return { entries, tree };
}

function normalizeSwapRegistry(input) {
  const entries = (Array.isArray(input) ? input : []).map((p) => normalizeSwapPolicyV6(p));
  const tree = buildSwapPolicyTreeV6(entries);
  return { entries, tree };
}

/* The controller's token position — the TOKEN domain's live balance (byte-
 * identical shape/mechanics to manifest-v5.js: the v0.6 token-family
 * mechanics are the SAME kcc20 covenant-id/v1 ownership scheme). */
function normalizeTokenPosition(input, expectedFamilyId) {
  if (input === null || input === undefined) return null;
  if (typeof input !== "object") fail("tokenPosition must be an object or null");
  const state = assets.kcc20.normalizeState(input.state);
  const covenantId = normalizeHex(input.covenantId, 32, "tokenPosition.covenantId");
  if (covenantId !== expectedFamilyId) fail("tokenPosition.covenantId != the controller's pinned tokenCovenantId — wrong asset family; failing closed", "WRONG_TOKEN_FAMILY");
  return Object.freeze({
    outpoint: normalizeOutpoint(input.outpoint, "tokenPosition.outpoint"),
    value: parseSompi(input.value, "tokenPosition.value"),
    scriptPublicKeyHex: String(input.scriptPublicKeyHex ?? "").toLowerCase(),
    covenantId,
    state
  });
}

function normalizeManifestV6(input) {
  if (!input || typeof input !== "object") fail("manifest object required");
  if (input.schema !== MANIFEST_SCHEMA_V6) fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed (a vault stored under a different covenant generation's schema is refused, never silently migrated)`, "CONTRACT_VERSION_MISMATCH");
  const abi = resolveV6Abi(input.contractVersion);
  if (typeof input.networkId !== "string" || input.networkId.length === 0) fail("networkId required");
  if (!Object.values(VaultStatus).includes(input.status)) fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);

  const template = normalizeTemplateV6(input.template);

  /* DESCRIPTOR PIN: the accepted descriptor must hash to the controller's pinned descriptorHash. */
  const descriptor = assets.validateAssetDescriptor(input.asset?.descriptor);
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  if (descriptorHash !== template.descriptorHash) fail("accepted descriptor hash != the controller's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (input.asset.descriptorHash !== undefined && String(input.asset.descriptorHash).toLowerCase() !== descriptorHash) fail("asset.descriptorHash does not match the descriptor — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (descriptor.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != controller tokenCovenantId — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  const templateIndex = Number.isInteger(input.asset.templateIndex) ? input.asset.templateIndex : 0;
  const tpl = descriptor.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("asset.templateIndex does not name the descriptor template the controller pins (hash/geometry) — failing closed", "TEMPLATE_PIN_MISMATCH");
  }

  const { entries, tree } = normalizeRegistry(input.agentRegistry);
  const { entries: swapEntries, tree: swapTree } = normalizeSwapRegistry(input.swapRegistry);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null && input.live !== undefined) fail(`${input.status} manifest must carry live: null`);
  } else {
    const state = normalizeStateV6(input.live?.state);
    const stateId = computeStateIdV6({ networkId: input.networkId, template, state, contractVersion: abi.version });
    if (input.live.stateId !== stateId) fail("manifest live.stateId does not match its state tuple — failing closed");
    if (controllerValueV6(state).toString() !== String(input.live.outpointValue)) fail("manifest live outpoint value does not equal feeReserve + swapPrincipal — failing closed");
    if (tree.root !== state.agentRoot) {
      fail(`agent registry root ${tree.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "REGISTRY_ROOT_MISMATCH");
    }
    if (swapTree.root !== state.swapRoot) {
      fail(`swap policy registry root ${swapTree.root} does not match the covenant swapRoot ${state.swapRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "SWAP_REGISTRY_ROOT_MISMATCH");
    }
    const tokenPosition = normalizeTokenPosition(input.live.tokenPosition, template.tokenCovenantId);
    if (tokenPosition && (tokenPosition.state.ownerIdentifier !== normalizeHex(input.live.covenantId, 32, "live.covenantId") || tokenPosition.state.identifierType !== assets.kcc20.OWNER_SCHEMES.COVENANT_ID)) {
      fail("live.tokenPosition is not owned by this controller's covenant id — failing closed", "TOKEN_NOT_OWNED");
    }
    live = Object.freeze({
      state,
      stateId,
      outpoint: normalizeOutpoint(input.live.outpoint, "live.outpoint"),
      outpointValue: controllerValueV6(state),
      scriptSha256: normalizeHex(input.live.scriptSha256, 32, "live.scriptSha256"),
      covenantId: normalizeHex(input.live.covenantId, 32, "live.covenantId"),
      tokenPosition
    });
  }

  return Object.freeze({
    schema: MANIFEST_SCHEMA_V6,
    contractVersion: abi.version,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    template,
    asset: Object.freeze({ descriptor, descriptorHash, templateIndex }),
    agentRegistry: Object.freeze(entries),
    agentRegistryRoot: tree.root,
    swapRegistry: Object.freeze(swapEntries),
    swapRegistryRoot: swapTree.root,
    live,
    creationTxId: input.creationTxId == null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId: input.latestTransitionTxId == null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function manifestToJsonV6(normalized) {
  return {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    swapRegistry: normalized.swapRegistry.map((p) => swapPolicyToJsonV6(p)),
    live: normalized.live
      ? {
          ...normalized.live,
          state: stateToJsonV6(normalized.live.state),
          outpointValue: normalized.live.outpointValue.toString(),
          tokenPosition: normalized.live.tokenPosition
            ? { ...normalized.live.tokenPosition, value: normalized.live.tokenPosition.value.toString(), state: { ...normalized.live.tokenPosition.state, amount: normalized.live.tokenPosition.state.amount.toString() } }
            : null
        }
      : null
  };
}

async function loadManifestV6(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  return stored === null ? null : normalizeManifestV6(stored);
}

async function persistManifestV6(config, manifest) {
  const normalized = normalizeManifestV6({ ...manifest, updatedAt: new Date().toISOString() });
  await getStore(config).write(Categories.VAULT, normalized.vaultId, manifestToJsonV6(normalized));
  return normalized;
}

/*
 * RC33-ID-01 (2026-09-11): the CREATE-ONLY sibling of the persist function above, for a PROVEN genesis — the SAME
 * normalization and encoding, then sdk/src/vault-identity.js's atomic create-or-match write instead of an overwrite.
 * Returns { manifest, outcome: "CREATED" | "ALREADY_PRESENT" }; throws RECONCILIATION_REQUIRED when the identity holds a
 * DIFFERENT record of any generation (left untouched). Transitions keep advancing an existing record through persist.
 */
async function createManifestV6(config, manifest) {
  const normalized = normalizeManifestV6({ ...manifest, updatedAt: new Date().toISOString() });
  const { outcome } = await createVaultRecordOrMatch(config, normalized.vaultId, manifestToJsonV6(normalized));
  return { manifest: normalized, outcome };
}

module.exports = {
  MANIFEST_SCHEMA_V6,
  CONTRACT_VERSION_V6,
  normalizeManifestV6,
  manifestToJsonV6,
  loadManifestV6,
  persistManifestV6,
  createManifestV6,
  normalizeRegistry,
  normalizeSwapRegistry,
  registryEntryToJson,
  manifestPath
};
