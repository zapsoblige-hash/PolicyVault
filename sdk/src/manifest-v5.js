"use strict";

/*
 * Durable, versioned manifest for a PolicyVault v0.5 TOKEN CONTROLLER
 * instance (frozen design §I.6 / §II).
 *
 * Beyond the v0.4 manifest discipline (durable agent registry that MUST
 * reproduce the covenant agentRoot; only proven chain reconciliation
 * advances live state; unknown schemas/versions fail closed), a v0.5
 * manifest carries:
 *   - the ACCEPTED ASSET DESCRIPTOR verbatim + its pinned hash: the hash
 *     MUST equal the controller template's descriptorHash (the value baked
 *     into the revealed redeem) — descriptor substitution/downgrade fails
 *     closed here, before any builder runs;
 *   - the controller's TOKEN POSITION (outpoint, KAS carry, revealed
 *     state): the two accounting domains are separate fields, never
 *     summed; the position's amount is the token-domain balance, the
 *     controller UTXO value is the KAS fee reserve;
 *   - per-agent TOKEN policies (atomic units) with their recipient sets.
 *
 * Status: IMPLEMENTED + UNIT-TESTED (sdk/test/manifest-v5.test.js).
 */

const path = require("path");
const { getStore, Categories } = require("./store");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { CONTRACT_VERSION_V5, resolveV5Abi, normalizeTemplateV5, normalizeStateV5, computeStateIdV5, stateToJsonV5 } = require("./vault-state-v5");
const { buildTokenAgentTreeV5, normalizeTokenAgentPolicyV5, tokenAgentPolicyToJsonV5 } = require("./agent-merkle-v5");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");
const assets = require("../../core/assets");
const { parseSompi } = require("./amounts");

const MANIFEST_SCHEMA_V5 = "policyvault-token-controller-manifest/v5";

function fail(message, code) {
  const error = new Error(`manifest-v5: ${message}`);
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

/* The controller's token position — the TOKEN domain's live balance. */
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

function normalizeManifestV5(input) {
  if (!input || typeof input !== "object") fail("manifest object required");
  if (input.schema !== MANIFEST_SCHEMA_V5) fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed`);
  const abi = resolveV5Abi(input.contractVersion);
  if (typeof input.networkId !== "string" || input.networkId.length === 0) fail("networkId required");
  if (!Object.values(VaultStatus).includes(input.status)) fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);

  const template = normalizeTemplateV5(input.template);

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

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null && input.live !== undefined) fail(`${input.status} manifest must carry live: null`);
  } else {
    const state = normalizeStateV5(input.live?.state);
    const stateId = computeStateIdV5({ networkId: input.networkId, template, state, contractVersion: abi.version });
    if (input.live.stateId !== stateId) fail("manifest live.stateId does not match its state tuple — failing closed");
    if (state.feeReserve.toString() !== String(input.live.outpointValue)) fail("manifest live outpoint value does not equal feeReserve — failing closed");
    if (tree.root !== state.agentRoot) {
      fail(`agent registry root ${tree.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "REGISTRY_ROOT_MISMATCH");
    }
    const tokenPosition = normalizeTokenPosition(input.live.tokenPosition, template.tokenCovenantId);
    if (tokenPosition && (tokenPosition.state.ownerIdentifier !== normalizeHex(input.live.covenantId, 32, "live.covenantId") || tokenPosition.state.identifierType !== assets.kcc20.OWNER_SCHEMES.COVENANT_ID)) {
      fail("live.tokenPosition is not owned by this controller's covenant id — failing closed", "TOKEN_NOT_OWNED");
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
    schema: MANIFEST_SCHEMA_V5,
    contractVersion: abi.version,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    template,
    asset: Object.freeze({ descriptor, descriptorHash, templateIndex }),
    agentRegistry: Object.freeze(entries),
    agentRegistryRoot: tree.root,
    live,
    creationTxId: input.creationTxId == null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId: input.latestTransitionTxId == null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function manifestToJsonV5(normalized) {
  return {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    live: normalized.live
      ? {
          ...normalized.live,
          state: stateToJsonV5(normalized.live.state),
          outpointValue: normalized.live.outpointValue.toString(),
          tokenPosition: normalized.live.tokenPosition
            ? { ...normalized.live.tokenPosition, value: normalized.live.tokenPosition.value.toString(), state: { ...normalized.live.tokenPosition.state, amount: normalized.live.tokenPosition.state.amount.toString() } }
            : null
        }
      : null
  };
}

async function loadManifestV5(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  return stored === null ? null : normalizeManifestV5(stored);
}

async function persistManifestV5(config, manifest) {
  const normalized = normalizeManifestV5({ ...manifest, updatedAt: new Date().toISOString() });
  await getStore(config).write(Categories.VAULT, normalized.vaultId, manifestToJsonV5(normalized));
  return normalized;
}

module.exports = { MANIFEST_SCHEMA_V5, CONTRACT_VERSION_V5, normalizeManifestV5, manifestToJsonV5, loadManifestV5, persistManifestV5, normalizeRegistry, registryEntryToJson, manifestPath };
