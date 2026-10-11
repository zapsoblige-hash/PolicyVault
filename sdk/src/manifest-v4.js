"use strict";

/*
 * Durable, versioned vault manifest for PolicyVault v0.4 vaults
 * (Checkpoint G §G2).
 *
 * v0.4 places every agent's policy INSIDE the authenticated agent tree, so
 * the covenant state exposes only `agentRoot`, not the individual agents.
 * The application therefore keeps a durable AGENT REGISTRY: the full list of
 * agent policies (+ each agent's recipient set) sufficient to reconstruct
 * the canonical `agentRoot` and every per-agent `agentRecipientRoot`.
 *
 * The registry is NEVER trusted merely because it exists. Whenever a live
 * state is present, this loader RECOMPUTES the canonical agentRoot from the
 * registry (agent-merkle-v4) and REQUIRES equality with the covenant state's
 * agentRoot; it likewise recomputes each agent's recipient root from its
 * recipient set. If the registry cannot reproduce the on-chain root, the
 * manifest FAILS CLOSED (REGISTRY_ROOT_MISMATCH) — the covenant identity is
 * authoritative, the local metadata is a verified reconstruction, and a vault
 * whose metadata cannot reproduce its root is an operational state requiring
 * investigation, never a guess or a silent rebuild.
 *
 * Same durability discipline as the v1/v2 manifests: only proven chain
 * reconciliation advances the live state; unknown schemas/contract versions
 * and ambiguous live state fail closed. The v0.4 covenant UTXO holds
 * protectedValue + feeReserve, so live.outpointValue equals that sum.
 */

const path = require("path");
const fs = require("fs");

const { getStore, Categories } = require("./store");
const { createVaultRecordOrMatch } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): atomic create-only genesis completion
const { normalizeHex } = require("./vault-state");
const {
  CONTRACT_VERSION_V4,
  resolveV4Abi,
  normalizeTemplateV4,
  normalizeStateV4,
  computeStateIdV4,
  stateToJsonV4
} = require("./vault-state-v4");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("./agent-merkle-v4");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const { normalizeXOnlyPubkey } = require("./vault-state");
const { parsePositiveSompi } = require("./amounts");
const { VaultStatus, TERMINAL_STATUSES } = require("./manifest");

const MANIFEST_SCHEMA_V4 = "policyvault-vault-manifest/v4";

function fail(message, code) {
  const error = new Error(`manifest-v4: ${message}`);
  if (code) error.code = code;
  throw error;
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
 * Normalize one durable agent-registry entry into a full agent policy.
 * Its recipients (>=1 x-only keys) canonically reproduce agentRecipientRoot;
 * an entry that names a recipientRoot inconsistent with its recipient set is
 * rejected (fail closed).
 */
function normalizeRegistryEntry(entry, i) {
  if (!entry || typeof entry !== "object") {
    fail(`agentRegistry[${i}] must be an object`);
  }
  if (!Array.isArray(entry.recipients) || entry.recipients.length === 0) {
    fail(`agentRegistry[${i}].recipients must be a non-empty array of x-only keys`);
  }
  const recipients = entry.recipients.map((r, j) => normalizeXOnlyPubkey(r, `agentRegistry[${i}].recipients[${j}]`));
  const recipientRoot = buildRecipientTree(recipients).root;
  if (entry.agentRecipientRoot !== undefined) {
    const declared = normalizeHex(entry.agentRecipientRoot, 32, `agentRegistry[${i}].agentRecipientRoot`);
    if (declared !== recipientRoot) {
      fail(`agentRegistry[${i}].agentRecipientRoot does not match its recipient set — failing closed`, "REGISTRY_RECIPIENT_MISMATCH");
    }
  }
  const policy = normalizeAgentPolicyV4({
    agentPk: entry.agentPk,
    maxPerSpend: entry.maxPerSpend,
    periodBudget: entry.periodBudget,
    periodLengthDaa: entry.periodLengthDaa,
    periodStartDaa: entry.periodStartDaa,
    periodSpent: entry.periodSpent,
    approvalThreshold: entry.approvalThreshold,
    agentMaxFeePerTx: entry.agentMaxFeePerTx,
    agentRecipientRoot: recipientRoot
  });
  return { policy, recipients: Object.freeze(recipients) };
}

/* JSON-safe registry entry (digit strings). */
function registryEntryToJson({ policy, recipients }) {
  return {
    agentPk: policy.agentPk,
    maxPerSpend: policy.maxPerSpend.toString(),
    periodBudget: policy.periodBudget.toString(),
    periodLengthDaa: policy.periodLengthDaa.toString(),
    periodStartDaa: policy.periodStartDaa.toString(),
    periodSpent: policy.periodSpent.toString(),
    approvalThreshold: policy.approvalThreshold.toString(),
    agentMaxFeePerTx: policy.agentMaxFeePerTx.toString(),
    agentRecipientRoot: policy.agentRecipientRoot,
    recipients: [...recipients]
  };
}

/*
 * Normalize the durable agent registry into { entries, tree }. The canonical
 * agentRoot the registry reproduces is `tree.root`. An empty registry is
 * canonical (the "no agents" tree = the unspendable padding leaf).
 */
function normalizeRegistry(input) {
  const rawEntries = Array.isArray(input) ? input : [];
  const entries = rawEntries.map(normalizeRegistryEntry);
  const tree = buildAgentTreeV4(entries.map((e) => e.policy));
  return { entries, tree };
}

function normalizeManifestV4(input) {
  if (!input || typeof input !== "object") {
    fail("manifest object required");
  }
  if (input.schema !== MANIFEST_SCHEMA_V4) {
    fail(`unknown manifest schema ${JSON.stringify(input.schema)} — failing closed`);
  }
  // Accept the v0.4 family (v0.4 and v0.4.1); resolveV4Abi FAILS CLOSED on any
  // other version. The resolved version is echoed back verbatim so a manifest
  // never silently changes version.
  const abi = resolveV4Abi(input.contractVersion);
  if (typeof input.networkId !== "string" || input.networkId.length === 0) {
    fail("networkId required");
  }
  if (!Object.values(VaultStatus).includes(input.status)) {
    fail(`unknown vault status ${JSON.stringify(input.status)} — failing closed`);
  }

  const template = normalizeTemplateV4(input.template);
  const { entries, tree } = normalizeRegistry(input.agentRegistry);

  let live = null;
  if (TERMINAL_STATUSES.has(input.status) || input.status === VaultStatus.PENDING_CREATE) {
    if (input.live !== null && input.live !== undefined) {
      fail(`${input.status} manifest must carry live: null`);
    }
  } else {
    const state = normalizeStateV4(input.live?.state);
    const stateId = computeStateIdV4({ networkId: input.networkId, template, state, contractVersion: abi.version });
    if (input.live.stateId !== stateId) {
      fail("manifest live.stateId does not match its state tuple — failing closed");
    }
    const covenantValue = state.protectedValue + state.feeReserve;
    if (covenantValue.toString() !== String(input.live.outpointValue)) {
      fail("manifest live outpoint value does not equal protectedValue + feeReserve — failing closed");
    }
    /* ROOT-EQUALITY (G2): the durable registry MUST reproduce the covenant
     * agentRoot. This is the load-bearing check — the covenant identity is
     * authoritative; the registry is a verified reconstruction. */
    if (tree.root !== state.agentRoot) {
      fail(
        `agent registry root ${tree.root} does not match the covenant agentRoot ${state.agentRoot} — the local metadata cannot reproduce the on-chain tree; refusing to operate (reconcile/investigate)`,
        "REGISTRY_ROOT_MISMATCH"
      );
    }
    live = Object.freeze({
      state,
      stateId,
      outpoint: normalizeOutpoint(input.live.outpoint, "live.outpoint"),
      outpointValue: covenantValue,
      scriptSha256: normalizeHex(input.live.scriptSha256, 32, "live.scriptSha256"),
      covenantId: normalizeHex(input.live.covenantId, 32, "live.covenantId")
    });
  }

  return Object.freeze({
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: abi.version,
    networkId: input.networkId,
    vaultId: template.vaultId,
    label: typeof input.label === "string" ? input.label : "",
    status: input.status,
    template,
    agentRegistry: Object.freeze(entries),
    agentRegistryRoot: tree.root,
    live,
    creationTxId: input.creationTxId == null ? null : normalizeHex(input.creationTxId, 32, "creationTxId"),
    latestTransitionTxId: input.latestTransitionTxId == null ? null : normalizeHex(input.latestTransitionTxId, 32, "latestTransitionTxId"),
    lastTransition: normalizeTransition(input.lastTransition ?? null, abi.version),
    updatedAt: typeof input.updatedAt === "string" ? input.updatedAt : new Date().toISOString()
  });
}

function normalizeTransition(input, contractVersion = CONTRACT_VERSION_V4) {
  if (input == null) {
    return null;
  }
  // The transition inherits the manifest's version; a stored transition whose
  // version disagrees with its manifest is refused (fail closed).
  if (input.contractVersion != null && input.contractVersion !== contractVersion) {
    fail(`lastTransition contractVersion ${JSON.stringify(input.contractVersion)} != manifest ${JSON.stringify(contractVersion)} — failing closed`);
  }
  return Object.freeze({
    action: String(input.action),
    txId: normalizeHex(input.txId, 32, "lastTransition.txId"),
    oldStateId: normalizeHex(input.oldStateId, 32, "lastTransition.oldStateId"),
    newStateId: input.newStateId == null ? null : normalizeHex(input.newStateId, 32, "lastTransition.newStateId"),
    oldOutpoint: normalizeOutpoint(input.oldOutpoint, "lastTransition.oldOutpoint"),
    newOutpoint: input.newOutpoint == null ? null : normalizeOutpoint(input.newOutpoint, "lastTransition.newOutpoint"),
    contractVersion
  });
}

async function loadManifestV4(config, vaultId) {
  const stored = await getStore(config).read(Categories.VAULT, vaultId);
  return stored === null ? null : normalizeManifestV4(stored);
}

async function persistManifestV4(config, manifest) {
  const normalized = normalizeManifestV4({ ...manifest, updatedAt: new Date().toISOString() });
  const encoded = {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    live: normalized.live
      ? {
          ...normalized.live,
          state: stateToJsonV4(normalized.live.state),
          outpointValue: normalized.live.outpointValue.toString()
        }
      : null
  };
  await getStore(config).write(Categories.VAULT, normalized.vaultId, encoded);
  return normalized;
}

/*
 * RC33-ID-01 (2026-09-11): the CREATE-ONLY sibling of the persist function above, for a PROVEN genesis — the SAME
 * normalization and encoding, then sdk/src/vault-identity.js's atomic create-or-match write instead of an overwrite.
 * Returns { manifest, outcome: "CREATED" | "ALREADY_PRESENT" }; throws RECONCILIATION_REQUIRED when the identity holds a
 * DIFFERENT record of any generation (left untouched). Transitions keep advancing an existing record through persist.
 */
async function createManifestV4(config, manifest) {
  const normalized = normalizeManifestV4({ ...manifest, updatedAt: new Date().toISOString() });
  const encoded = {
    ...normalized,
    agentRegistry: normalized.agentRegistry.map(registryEntryToJson),
    live: normalized.live
      ? { ...normalized.live, state: stateToJsonV4(normalized.live.state), outpointValue: normalized.live.outpointValue.toString() }
      : null
  };
  const { outcome } = await createVaultRecordOrMatch(config, normalized.vaultId, encoded);
  return { manifest: normalized, outcome };
}

/*
 * RC45 delegate period-start rule (v0.4-family and v0.7-kas registries; both
 * fold through normalizeRegistry above). Pure, BigInt only, no I/O: the node
 * read lives in chain.readAnchorDaa.
 *
 * A leaf of a new registry N whose agentPk is in the predecessor registry P
 * (the root-verified durable registry; empty for a creation) and whose nine
 * committed fields equal that predecessor leaf is CARRIED: committed exactly
 * as it is, never re-anchored, never judged. Every other leaf (new key,
 * rotated key, any changed field) is ANCHORED:
 *   - at the build its periodStartDaa becomes max(requested, D) with D the
 *     node's canonical virtual DAA score; every other field, periodSpent
 *     included, is committed exactly as requested;
 *   - before the point of no return it is refused PERIOD_START_STALE when
 *     D - periodStartDaa > W(periodLengthDaa).
 * A later start never grants more spend capacity at any consensus time, so
 * anchoring only ever restricts what was requested. The covenant does not
 * bound how many unused periods an idle CARRIED leaf can roll over at once;
 * nothing here changes that.
 *
 * W(L) = max(L - PERIOD_START_ACCEPT_MARGIN_DAA, PERIOD_START_MIN_WINDOW_DAA):
 * a leaf that passes the check and is accepted within the margin confirms
 * with no banked budget whenever L >= margin + floor. Both are code constants
 * (10 minutes and 1 minute at 10 DAA per second), never configuration.
 */
const PERIOD_START_ACCEPT_MARGIN_DAA = 6000n;
const PERIOD_START_MIN_WINDOW_DAA = 600n;

/* The nine fields that make up a committed agent leaf. */
const COMMITTED_LEAF_FIELDS = Object.freeze([
  "agentPk", "maxPerSpend", "periodBudget", "periodLengthDaa", "periodStartDaa",
  "periodSpent", "approvalThreshold", "agentMaxFeePerTx", "agentRecipientRoot"
]);

function refusal(message, code, extra) {
  const error = new Error(`manifest-v4: ${message}`);
  error.code = code;
  if (extra) error.extra = extra;
  return error;
}

function stagePrefix(stage) {
  return typeof stage === "string" && stage.length > 0 ? `${stage}: ` : "";
}

/* The longest a committed start may lag the node's position, in DAA. */
function periodStartWindowDaa(periodLengthDaa) {
  const length = parsePositiveSompi(periodLengthDaa, "periodLengthDaa");
  const lag = length - PERIOD_START_ACCEPT_MARGIN_DAA;
  return lag > PERIOD_START_MIN_WINDOW_DAA ? lag : PERIOD_START_MIN_WINDOW_DAA;
}

/* The committed leaf policies of JSON registry entries, in entry order. */
function committedPolicies(entries, field) {
  if (!Array.isArray(entries)) fail(`${field} must be an array of agent-registry entries`);
  return entries.map((entry, i) => normalizeRegistryEntry(entry, i).policy);
}

function samePolicy(a, b) {
  return Boolean(a) && Boolean(b) && COMMITTED_LEAF_FIELDS.every((field) => a[field] === b[field]);
}

/* True when two JSON registry entries commit byte-identical leaves. */
function committedLeafEqual(a, b) {
  return samePolicy(normalizeRegistryEntry(a, 0).policy, normalizeRegistryEntry(b, 0).policy);
}

/* The agentPk of every ANCHORED leaf of nextEntries, in entry order. */
function anchoredLeafPks(predecessorEntries, nextEntries) {
  const before = new Map();
  for (const policy of committedPolicies(predecessorEntries, "predecessorEntries")) {
    if (before.has(policy.agentPk)) fail(`predecessorEntries holds agent ${policy.agentPk} twice — failing closed`);
    before.set(policy.agentPk, policy);
  }
  return committedPolicies(nextEntries, "nextEntries")
    .filter((policy) => !samePolicy(before.get(policy.agentPk), policy))
    .map((policy) => policy.agentPk);
}

/* A DAA score handed to the rule: a non-negative BigInt, nothing else. */
function requireDaaScore(value, field) {
  if (typeof value !== "bigint" || value < 0n) {
    throw refusal(`${field} must be the node's canonical virtual DAA score (a non-negative BigInt) — refusing to judge a delegate's budget period without it`, "PERIOD_START_REQUIRED");
  }
  return value;
}

/*
 * Anchor at build: returns { entries, anchoredAgentPks, root } with entries in
 * the order given (copies; the inputs are never mutated) and root the agent
 * root of the committed leaves. anchorDaa is required only when some leaf is
 * ANCHORED, so a registry of CARRIED leaves needs no node read.
 */
function anchorRegistryStarts({ predecessorEntries, nextEntries, anchorDaa } = {}) {
  const next = committedPolicies(nextEntries, "nextEntries");
  const anchoredAgentPks = anchoredLeafPks(predecessorEntries, nextEntries);
  const anchored = new Set(anchoredAgentPks);
  const daa = anchored.size > 0 ? requireDaaScore(anchorDaa, "anchorDaa") : null;
  const entries = nextEntries.map((entry, i) => {
    const copy = { ...entry, recipients: [...entry.recipients] };
    if (anchored.has(next[i].agentPk)) {
      const requested = next[i].periodStartDaa;
      copy.periodStartDaa = (requested > daa ? requested : daa).toString();
    }
    return copy;
  });
  const root = buildAgentTreeV4(entries.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }))).root;
  assertRegistryFoldsToRoot({ entries, committedAgentRoot: root, stage: "anchor" });
  return { entries, anchoredAgentPks, root };
}

/*
 * Freshness before the point of no return: refuses PERIOD_START_STALE (with
 * agentPk, periodStartDaa, currentDaa, periodLengthDaa and windowDaa as
 * decimal strings in error.extra) when an ANCHORED leaf's start lags currentDaa
 * by more than its window. Returns the ANCHORED agentPks it judged.
 */
function assertLeafStartsFresh({ predecessorEntries, nextEntries, currentDaa, stage } = {}) {
  const next = committedPolicies(nextEntries, "nextEntries");
  const anchored = new Set(anchoredLeafPks(predecessorEntries, nextEntries));
  if (anchored.size === 0) return [];
  const daa = requireDaaScore(currentDaa, "currentDaa");
  for (const policy of next) {
    if (!anchored.has(policy.agentPk)) continue;
    const windowDaa = periodStartWindowDaa(policy.periodLengthDaa);
    if (daa - policy.periodStartDaa > windowDaa) {
      throw refusal(
        `${stagePrefix(stage)}delegate ${policy.agentPk} has budget period start ${policy.periodStartDaa}, ${daa - policy.periodStartDaa} DAA behind the current network position ${daa}; a new or changed delegate may be committed only while its start is at most ${windowDaa} DAA behind (budget period ${policy.periodLengthDaa} DAA), so confirming this request could hand it more than one period's budget at once — refusing; build the action again`,
        "PERIOD_START_STALE",
        {
          agentPk: policy.agentPk,
          periodStartDaa: policy.periodStartDaa.toString(),
          currentDaa: daa.toString(),
          periodLengthDaa: policy.periodLengthDaa.toString(),
          windowDaa: windowDaa.toString()
        }
      );
    }
  }
  return [...anchored];
}

/*
 * Registry-to-root integrity: the registry a step judges must fold to exactly
 * the agent root it is about to commit. A registry that is not an array is
 * refused, never folded as the empty registry (normalizeRegistry's default).
 * Returns the fold.
 */
function assertRegistryFoldsToRoot({ entries, committedAgentRoot, stage } = {}) {
  const where = stagePrefix(stage);
  if (!Array.isArray(entries)) {
    throw refusal(`${where}the agent registry to check is ${entries === null ? "null" : typeof entries === "object" ? "not a list" : `of type ${typeof entries}`} — a missing registry is refused, never treated as empty`, "REGISTRY_ROOT_MISMATCH");
  }
  if (typeof committedAgentRoot !== "string" || !/^[0-9a-fA-F]{64}$/.test(committedAgentRoot)) {
    throw refusal(`${where}the committed agent root is not 32-byte hex — refusing`, "REGISTRY_ROOT_MISMATCH");
  }
  let root;
  try {
    root = normalizeRegistry(entries).tree.root;
  } catch (error) {
    throw refusal(`${where}the agent registry cannot be folded to an agent root (${error.message}) — refusing`, "REGISTRY_ROOT_MISMATCH");
  }
  if (root.toLowerCase() !== committedAgentRoot.toLowerCase()) {
    throw refusal(`${where}the agent registry folds to ${root}, not to the agent root ${committedAgentRoot.toLowerCase()} about to be committed — refusing`, "REGISTRY_ROOT_MISMATCH");
  }
  return root;
}

module.exports = {
  MANIFEST_SCHEMA_V4,
  normalizeManifestV4,
  loadManifestV4,
  persistManifestV4,
  createManifestV4,
  normalizeRegistry,
  registryEntryToJson,
  PERIOD_START_ACCEPT_MARGIN_DAA,
  PERIOD_START_MIN_WINDOW_DAA,
  periodStartWindowDaa,
  committedLeafEqual,
  anchoredLeafPks,
  anchorRegistryStarts,
  assertLeafStartsFresh,
  assertRegistryFoldsToRoot
};
