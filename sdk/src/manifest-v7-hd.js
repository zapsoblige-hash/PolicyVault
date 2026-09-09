"use strict";

/*
 * Durable, versioned manifest for a PolicyVault v0.7 ROOTED HIERARCHICAL-
 * DELEGATION vault (CANDIDATE, contractVersion "policyvault-0.7-payment-hd";
 * NOT covenant-byte-frozen — docs/postlaunch/v0.7-hd-readiness.md). Wave 2
 * Track E. Mirrors sdk/src/manifest-v7.js's rooted-vault discipline
 * (unknown schemas/versions fail closed; only a proven successor advances
 * `live`; no owner key here at all — the vault's owner authority IS its
 * pinned organizational root, exactly as v0.7-payment's) plus the SAME
 * template/state SHAPE v0.7-payment uses (byte-identical fields; reused
 * unchanged — sdk/src/vault-builders-v7-hd.js's own header explains why).
 *
 * WHAT IS NEW: the durable DELEGATION FOREST — the full level-1..3 tree of
 * HD leaves (core/model/hd-leaf-v7.js), stored so a spend/delegation
 * request needs only a `path` (child indices) rather than the caller
 * reconstructing ancestor proofs by hand. `hd.forestRoot(forest)` MUST
 * reproduce the covenant's live `agentRoot` before this manifest is
 * trusted for a build — the SAME "local metadata must reconstruct the
 * on-chain tree, or refuse" rule the token-controller registries follow.
 *
 * Status: IMPLEMENTED (Wave 2 Track E). UNIT/API-TESTED by
 * sdk/test/wallet-v7-hd-api.test.js.
 */

const { getStore, Categories } = require("./store");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { normalizeTemplateV7, normalizeStateV7, stateToJsonV7 } = require("../../core/model/vault-state-v7");
const { computeStateIdV7Hd } = require("./contract-compiler-v7");
const hd = require("../../core/model/hd-leaf-v7");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");
const assets = require("../../core/assets");
const { parseSompi } = require("./amounts");

const MANIFEST_SCHEMA_V7_HD = "policyvault-rooted-hd-vault-manifest-record/1";
const CONTRACT_VERSION_V7_HD = "policyvault-0.7-payment-hd";

function fail(message, code) {
  const error = new Error(`manifest-v7-hd: ${message}`);
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

/* ---- delegation forest: nodes { leaf, recipients, kids: [node...] } ---- */

function normalizeForestNode(input, level, i) {
  if (!input || typeof input !== "object") fail(`forest node at level ${level}[${i}] must be an object`);
  if (!Array.isArray(input.recipients) || input.recipients.length === 0) fail(`forest node at level ${level}[${i}].recipients must be a non-empty array of x-only keys`);
  const recipients = input.recipients.map((r, j) => normalizeXOnlyPubkey(r, `forest[${level}][${i}].recipients[${j}]`));
  const recipientRoot = buildRecipientTree(recipients).root;
  /* `expiryIsNotConsensusEnforced` is an OUTPUT-ONLY human-readable
   * disclaimer that hd.hdLeafToJson / hd.effectiveAuthority attach; the
   * core normalizer fails closed on it (closed leaf layout). Strip it
   * before re-normalizing, mirroring sdk/src/vault-builders-v7-hd.js and
   * core/intent/org-root-manifest-v7-hd.js. */
  const { expiryIsNotConsensusEnforced, ...leafOwnFields } = input.leaf || {};
  void expiryIsNotConsensusEnforced;
  const leafInput = { ...leafOwnFields, recipientRoot, childRoot: hd.ZERO_ROOT_HEX };
  const kids = Array.isArray(input.kids) ? input.kids.map((k, j) => normalizeForestNode(k, level + 1, j)) : [];
  /* childRoot is IGNORED and recomputed by hd.resolvedLeaf from `kids`
   * (mirrors core/model/hd-leaf-v7.js's own contract) — normalize just the
   * leaf's OWN fields here; the tree functions take { leaf, kids }. */
  const leaf = hd.normalizeHdLeaf(leafInput);
  return Object.freeze({ leaf, recipients: Object.freeze(recipients), kids: Object.freeze(kids) });
}

function forestNodeToJson(node) {
  return {
    leaf: hd.hdLeafToJson(node.leaf),
    recipients: [...node.recipients],
    kids: node.kids.map(forestNodeToJson)
  };
}

function normalizeForest(input) {
  const nodes = (Array.isArray(input) ? input : []).map((n, i) => normalizeForestNode(n, 1, i));
  const root = nodes.length > 0 ? hd.forestRoot(nodes) : hd.ZERO_ROOT_HEX;
  return { nodes, root };
}

/* The controller's token position — byte-identical mechanics to
 * manifest-v5.js / manifest-v7.js (the SAME kcc20 covenant-id/v1 scheme). */
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

function normalizeManifestV7Hd(input) {
  if (!input || typeof input !== "object") fail("manifest object required");
  if (input.schema !== MANIFEST_SCHEMA_V7_HD) fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed (a vault stored under a different covenant generation's schema is refused, never silently migrated)`, "CONTRACT_VERSION_MISMATCH");
  if (input.contractVersion !== CONTRACT_VERSION_V7_HD) fail(`unknown contract version ${JSON.stringify(input.contractVersion)} for the v0.7-payment-hd lineage — failing closed`, "UNKNOWN_VERSION");
  if (typeof input.networkId !== "string" || input.networkId.length === 0) fail("networkId required");
  if (!Object.values(VaultStatus).includes(input.status)) fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);

  const template = normalizeTemplateV7(input.template);
  if (typeof template.orgRootCovenantId !== "string" || !/^[0-9a-f]{64}$/.test(template.orgRootCovenantId)) fail("a rooted HD vault template must pin orgRootCovenantId — failing closed", "ROOT_INPUT_REQUIRED");

  const descriptor = assets.validateAssetDescriptor(input.asset?.descriptor);
  const descriptorHash = assets.computeDescriptorHash(descriptor);
  if (descriptorHash !== template.descriptorHash) fail("accepted descriptor hash != the vault's pinned descriptorHash — descriptor substitution/downgrade; failing closed", "DESCRIPTOR_PIN_MISMATCH");
  if (descriptor.tokenCovenantId !== template.tokenCovenantId) fail("descriptor.tokenCovenantId != vault tokenCovenantId — failing closed", "DESCRIPTOR_PIN_MISMATCH");
  const templateIndex = Number.isInteger(input.asset.templateIndex) ? input.asset.templateIndex : 0;
  const tpl = descriptor.acceptedTransferTemplates[templateIndex];
  if (!tpl || tpl.templateVmHashBlake2b256 !== template.templateVmHash || tpl.prefixLen !== template.templatePrefixLen || tpl.suffixLen !== template.templateSuffixLen) {
    fail("asset.templateIndex does not name the descriptor template the vault pins (hash/geometry) — failing closed", "TEMPLATE_PIN_MISMATCH");
  }

  const forest = normalizeForest(input.forest);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null && input.live !== undefined) fail(`${input.status} manifest must carry live: null`);
  } else {
    const state = normalizeStateV7(input.live?.state);
    const stateId = computeStateIdV7Hd({ networkId: input.networkId, template, state });
    if (input.live.stateId !== stateId) fail("manifest live.stateId does not match its state tuple — failing closed");
    if (state.feeReserve.toString() !== String(input.live.outpointValue)) fail("manifest live outpoint value does not equal feeReserve — failing closed");
    if (forest.nodes.length > 0 && forest.root !== state.agentRoot) {
      fail(`delegation forest root ${forest.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`, "REGISTRY_ROOT_MISMATCH");
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
    schema: MANIFEST_SCHEMA_V7_HD,
    contractVersion: CONTRACT_VERSION_V7_HD,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    orgRootCovenantId: template.orgRootCovenantId,
    template,
    asset: Object.freeze({ descriptor, descriptorHash, templateIndex }),
    forest: Object.freeze(forest.nodes),
    forestRootCached: forest.root,
    live,
    creationTxId: input.creationTxId == null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId: input.latestTransitionTxId == null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    generation: Number.isInteger(input.generation) ? input.generation : 0,
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function manifestToJsonV7Hd(normalized) {
  return {
    ...normalized,
    forest: normalized.forest.map(forestNodeToJson),
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

async function loadManifestV7Hd(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  if (stored === null) return null;
  if (stored.schema !== MANIFEST_SCHEMA_V7_HD) return null; // let the caller try a different manifest family
  return normalizeManifestV7Hd(stored);
}

async function persistManifestV7Hd(config, manifest) {
  const normalized = normalizeManifestV7Hd({ ...manifest, updatedAt: new Date().toISOString() });
  await getStore(config).write(Categories.VAULT, normalized.vaultId, manifestToJsonV7Hd(normalized));
  return normalized;
}

async function listRootedHdVaultsV7(config, { orgRootCovenantId } = {}) {
  const all = await getStore(config).listValues(Categories.VAULT);
  const out = all
    .filter((v) => v && v.schema === MANIFEST_SCHEMA_V7_HD && (orgRootCovenantId === undefined || v.orgRootCovenantId === orgRootCovenantId))
    .map((v) => normalizeManifestV7Hd(v));
  return out;
}

/* Resolve a caller-supplied `path` (array of child indices, one per level)
 * against the durable forest into the exact `params.tree` shape
 * sdk/src/vault-builders-v7-hd.js's resolveHdChain expects: the RAW forest
 * nodes (leaf inputs, never the recomputed/resolved form — the builder
 * recomputes childRoot itself). */
function forestAsTreeInput(manifest) {
  /* strip the OUTPUT-ONLY expiryIsNotConsensusEnforced disclaimer that
   * hdLeafToJson attaches — this is re-normalization input for the SDK
   * builder, not display (the core leaf normalizer fails closed on it). */
  const toTreeNode = (node) => { const { expiryIsNotConsensusEnforced, ...leaf } = hd.hdLeafToJson(node.leaf); void expiryIsNotConsensusEnforced; return { leaf, kids: node.kids.map(toTreeNode) }; };
  return manifest.forest.map(toTreeNode);
}

module.exports = {
  MANIFEST_SCHEMA_V7_HD,
  CONTRACT_VERSION_V7_HD,
  normalizeManifestV7Hd,
  manifestToJsonV7Hd,
  loadManifestV7Hd,
  persistManifestV7Hd,
  listRootedHdVaultsV7,
  normalizeForest,
  normalizeForestNode,
  forestNodeToJson,
  forestAsTreeInput
};
