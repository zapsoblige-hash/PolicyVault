"use strict";
const { verifySignedSafeJsonInputs, verifyFinalTransactionInputs } = require("./vm-preflight");
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV7Root, compileExactStateV7 } = require("./contract-compiler-v7");

/* F-03: an evicted compiled-artifact cache entry is recompiled deterministically
 * from the build's own template/state/version; the recompiled directory must
 * be exactly the one the build names (stateId identity) or finalize fails closed. */
function ensureBuildDirV7(config, build) {
  const isRoot = build && build.kind === "orgRootTransition";
  return ensureBuildDir({
    config, // rc12 review R-03: finalize recompile may force-evict a saturated in-grace cache
    buildDir: build.encoderBuildDir,
    recompile: () =>
      isRoot
        ? compileExactStateV7Root({ config, template: build.template, state: build.stateJson, contractVersion: build.contractVersion })
        : compileExactStateV7({ config, template: build.template, state: build.stateJson, contractVersion: build.contractVersion })
  });
}
const { ownGet } = require("../../core/model/own-get");

/*
 * PolicyVault v0.7 ON-CHAIN ORGANIZATIONAL ROOT — server-orchestrated
 * request pipeline (docs/postlaunch/v0.7-app-surface-contract.md §1-§2).
 *
 * Mirrors the PROVEN v0.4 discipline (sdk/src/wallet-requests-v4.js +
 * sdk/src/wallet-submit-v4.js): strict stages intent -> build -> sign ->
 * finalize -> submit -> reconcile; builders never broadcast; a submit
 * result is never treated as success without exact chain proof; durable
 * transition + submission claims are created BEFORE broadcast so a crash
 * on either side is unambiguous; only PROVEN chain reconciliation advances
 * a durable record (sdk/src/reconcile-v7.js owns the deferred/crash-
 * recovery path exactly as reconcile-v4.js does).
 *
 * EVERY funds-relevant decision stays in core/model, core/intent and the
 * v0.7 SDK builders (sdk/src/vault-builders-v7.js, untouched by this
 * file); this module ONLY orchestrates durable records, out-of-band
 * signature collection into the covenant's OWN blob assembler, submission,
 * and proven reconciliation. No server-only financial fact is introduced.
 *
 * TWO durable record families (store categories ORG_ROOT / ORG_ROOT_REQUEST,
 * sdk/src/store.js; PG migration server/migrations/011_org_roots.sql):
 *   ORG_ROOT           one row per organizational root (key rootCovenantId)
 *   ORG_ROOT_REQUEST   one row per root-authorized workflow (key requestId)
 * Rooted-vault delegate spend / token deposit requests reuse the EXISTING
 * Categories.REQUEST family (contractVersion "policyvault-0.7-payment"),
 * with their own small state ladder below — they never touch the root at
 * all, exactly as the covenant enforces.
 *
 * Status: IMPLEMENTED (Wave 2 Track B). UNIT/API-TESTED by
 * sdk/test/org-roots-api.test.js, sdk/test/hosted-pg-org-roots.test.js,
 * sdk/test/org-roots-hostile.test.js. Live: tools/testnet-v7-http-e2e.js.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { getStore, Categories } = require("./store");
const { withOrgRootLock } = require("./org-root-lock");
const { assertOperationalNetwork, assertGenerationMainnetCreatable } = require("./config");
const { parseSompi, parsePositiveSompi, kasToSompi, sompiToKas } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { resolveAddressIdentity, addressForXOnlyPubkey } = require("./address-identity");
const { connectVerified, getAddressUtxos } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { p2pkScriptHex } = require("./approval-package-v4");
const { claimTransition, claimSubmission, loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
const { appendAudit, readAudit } = require("./audit");
const assets = require("../../core/assets");

const {
  OWNER_SLOTS_V7,
  INACTIVE_SLOT_KEY,
  normalizeOwnerSetV7,
  activeOwnerSlotsV7,
  resolveRootActionV7,
  requiredApprovalsV7
} = require("../../core/model/owner-set-v7");
const {
  CONTRACT_VERSION_V7_ROOT,
  normalizeRootTemplateV7,
  normalizeRootStateV7,
  rootTemplateToJsonV7,
  rootStateToJsonV7,
  computeRootStateDigestV7
} = require("../../core/model/vault-state-v7-root");
const { CONTRACT_VERSION_V7, resolveOwnerOpAuthorityV7, normalizeTemplateV7, normalizeStateV7, stateToJsonV7, computeStateIdV7 } = require("../../core/model/vault-state-v7");
const {
  buildCreateV7Root,
  buildV7RootTransaction,
  finalizeV7RootTransaction,
  buildCreateV7Vault,
  buildV7Transaction,
  finalizeV7Transaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7
} = require("./vault-builders-v7");
const { buildOrgRootIntentManifest, verifyOrgRootIntentManifest, buildRootedVaultManifestV7, verifyRootedVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7");
const { canonicalFrozenTxJson, normalizeFrozenTxV3 } = require("../../core/model/frozen-tx-v3");
const { reconstructVaultScriptHexV7 } = require("../../core/intent/vault-script-v7");
const { V7_BUDGET } = require("../../core/model/compute-budget-v7");
const { computeManifestHashV1, canonicalJsonStringify } = require("../../core/intent/canonical");
const { normalizeRegistry, registryEntryToJson, rootPinsFromTemplate, loadManifestV7, persistManifestV7, MANIFEST_SCHEMA_V7 } = require("./manifest-v7");
const { tokenAgentPolicyToJsonV5 } = require("./agent-merkle-v5"); // rc26 round-7 review R7-02
const { VaultStatus } = require("./manifest");

const ORG_ROOT_SCHEMA = "policyvault-org-root-record/1";
const ORG_ROOT_REQUEST_SCHEMA = "policyvault-org-root-request/1";
const V7_WALLET_REQUEST_SCHEMA = "policyvault-wallet-request/v7";

/* The RequestState ladder — additive to, and structurally identical in
 * spirit to, the v4/v2 ladders (mission "version everything"). PENDING is
 * never presented as success. */
const RequestState = Object.freeze({
  AUTHORIZED: "AUTHORIZED",
  SIGNED: "SIGNED",
  BROADCAST: "BROADCAST",
  CHAIN_SEEN: "CHAIN_SEEN",
  CHAIN_VERIFIED: "CHAIN_VERIFIED",
  VERIFIED_OUTCOME: "VERIFIED_OUTCOME",
  REFUSED: "REFUSED",
  FAILED: "FAILED",
  SUBMISSION_REJECTED: "SUBMISSION_REJECTED",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  STALE: "STALE"
});

const ROOT_ACTION_NAMES = new Set(["authorize", "rotate", "freeze", "unfreeze", "ownerRecover", "succession"]);
const OWNER_OP_ACTIONS = Object.freeze({
  ownerSetAgentRoot: "ownerSetAgentRoot",
  ownerTopUpReserve: "ownerTopUpReserve",
  ownerPause: "ownerPause",
  ownerUnpause: "ownerUnpause",
  ownerEmergencyPause: "ownerEmergencyPause",
  ownerRecover: "ownerRecover"
});
const VAULT_OP_ACTION_BY_ROOT_ACTION_PARAM = new Set(Object.keys(OWNER_OP_ACTIONS));

const AUTHORITY_MODEL = Object.freeze({
  ON_CHAIN_ORGANIZATIONAL_ROOT: "ON_CHAIN_ORGANIZATIONAL_ROOT",
  SINGLE_ON_CHAIN_OWNER: "SINGLE_ON_CHAIN_OWNER"
});

function fail(message, code) {
  const e = new Error(`wallet-requests-v7: ${message}`);
  if (code) e.code = code;
  return e;
}
function throwFail(message, code) {
  throw fail(message, code);
}

/* Consensus amount params arrive over the API as untrusted JSON — accept
 * ONLY a bigint or a canonical base-10 string, exactly the v4 boundary
 * hardening (CLAUDE.md numeric safety). */
function canonicalAmountParam(value, field) {
  if (typeof value === "bigint") {
    if (value < 0n) throwFail(`${field} must not be negative`, "AMOUNT_INVALID");
    return value.toString();
  }
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throwFail(`${field} must be a canonical base-10 sompi string or a bigint`, "AMOUNT_INVALID");
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* durable store helpers                                               */
/* ------------------------------------------------------------------ */

async function loadOrgRoot(config, rootCovenantId) {
  const record = await getStore(config).read(Categories.ORG_ROOT, rootCovenantId);
  if (record && record.rootCovenantId !== rootCovenantId) throwFail("root identity differs from its storage key", "ROOT_ID_MISMATCH");
  return record;
}
async function saveOrgRoot(config, root) {
  await getStore(config).write(Categories.ORG_ROOT, root.rootCovenantId, root);
  return root;
}
async function listOrgRoots(config) {
  const all = await getStore(config).listValues(Categories.ORG_ROOT);
  return all.filter((r) => r && r.schemaVersion === ORG_ROOT_SCHEMA).sort((a, b) => String(a.createdAt ?? "").localeCompare(String(b.createdAt ?? "")));
}

async function loadOrgRootRequest(config, requestId) {
  const record = await getStore(config).read(Categories.ORG_ROOT_REQUEST, requestId);
  if (record && record.id !== requestId) throwFail("root request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return record;
}

// Every public root-request writer uses the same queue as submission and
// reconciliation. Reload inside it; a cached caller object is never writable.
async function withRootRequestLock(config, requestId, callback) {
  const peek = await loadOrgRootRequest(config, requestId);
  if (!peek) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  return withOrgRootLock(peek.rootCovenantId, async () => {
    const fresh = await loadOrgRootRequest(config, requestId);
    if (!fresh || fresh.rootCovenantId !== peek.rootCovenantId) throwFail("request changed its guarded root identity", "REQUEST_ID_MISMATCH");
    return callback();
  });
}
async function saveOrgRootRequest(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.ORG_ROOT_REQUEST, request.id, request);
  return request;
}
async function listOrgRootRequests(config, { rootCovenantId } = {}) {
  const all = await getStore(config).listValues(Categories.ORG_ROOT_REQUEST, { strict: true });
  const out = all.filter((r) => r && r.schemaVersion === ORG_ROOT_REQUEST_SCHEMA && (rootCovenantId === undefined || r.rootCovenantId === rootCovenantId));
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/* delegate spend / deposit requests (Categories.REQUEST, contractVersion
 * policyvault-0.7-payment) */
async function loadV7WalletRequest(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  if (r && r.schema === V7_WALLET_REQUEST_SCHEMA && r.requestId !== requestId) throwFail("wallet request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return r && r.schema === V7_WALLET_REQUEST_SCHEMA ? r : null;
}
async function saveV7WalletRequest(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function listV7WalletRequests(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST, { strict: true });
  const out = all.filter((r) => r && r.schema === V7_WALLET_REQUEST_SCHEMA && (vaultId === undefined || r.vaultId === vaultId));
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/* ------------------------------------------------------------------ */
/* chain helpers                                                       */
/* ------------------------------------------------------------------ */

function normalizeOutpoint(op, label) {
  const transactionId = normalizeHex(op?.transactionId, 32, `${label}.transactionId`);
  const index = Number(op?.index);
  if (!Number.isInteger(index) || index < 0) throwFail(`${label}.index out of range`);
  return { transactionId, index };
}

async function autoFuel(config, rpc, signerAddress, minSompi) {
  const utxos = (await getAddressUtxos(rpc, signerAddress)).filter((u) => u.covenantId === null && u.amount > minSompi).sort((a, b) => (a.amount < b.amount ? 1 : -1));
  if (!utxos.length) throwFail(`no ordinary UTXO > ${minSompi} sompi at ${signerAddress} to pay the network fee — fund the signer address first`, "INSUFFICIENT_FUNDS");
  return { outpoint: utxos[0].outpoint, amount: utxos[0].amount.toString(), scriptPublicKeyHex: utxos[0].scriptPublicKeyHex };
}

async function resolveFuel(config, params, signerAddress, minSompi) {
  if (params && params.fuel) return params.fuel;
  const { rpc } = await connectVerified(config);
  try {
    return await autoFuel(config, rpc, signerAddress, minSompi);
  } finally {
    await rpc.disconnect();
  }
}

async function resolveFunding(config, params, signerAddress, minSompi) {
  if (Array.isArray(params?.funding) && params.funding.length) return params.funding;
  const { rpc } = await connectVerified(config);
  try {
    const u = await autoFuel(config, rpc, signerAddress, minSompi);
    return [u];
  } finally {
    await rpc.disconnect();
  }
}

/* ------------------------------------------------------------------ */
/* signer-authority gate — the CORE of "hosted-org admins get no root    */
/* authority": the initiating signer must be an ACTIVE SLOT of the root  */
/* set (or, for succession, the pinned successor key). No hosted        */
/* organization membership/admin role is ever consulted here.           */
/* ------------------------------------------------------------------ */

function assertInitiatingOwner(config, { rootState, action, signerAddress, successorPk }) {
  let signerXOnly;
  try {
    signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  } catch (e) {
    throwFail(`signer address rejected: ${e.message}`, "AUTHORIZATION_FAILED");
  }
  if (action === "succession") {
    if (signerXOnly !== successorPk) {
      throwFail("succession is authorized by the root's pinned successor key; the connected wallet does not hold it", "NOT_AN_ACTIVE_SLOT");
    }
    return signerXOnly;
  }
  const active = activeOwnerSlotsV7(rootState).map((s) => s.publicKey);
  if (!active.includes(signerXOnly)) {
    throwFail("the connected wallet is not an active owner slot of this organizational root — a hosted-organization role grants NO on-chain root authority", "NOT_AN_ACTIVE_SLOT");
  }
  return signerXOnly;
}

/* ------------------------------------------------------------------ */
/* WARNINGS — the closed vocabulary of §1                              */
/* ------------------------------------------------------------------ */

function warningsFor(action, landsFrozen) {
  const out = [];
  if (action === "ownerRecover") out.push("DANGEROUS_RECOVERY");
  if (action === "succession") out.push("DANGEROUS_SUCCESSION");
  if (action === "rotate") out.push("DANGEROUS_ROTATION");
  if (action === "unfreeze") out.push("DANGEROUS_UNFREEZE");
  if (landsFrozen === true) out.push("LANDS_FROZEN");
  return out;
}

/* ------------------------------------------------------------------ */
/* 1. ROOT GENESIS                                                     */
/* ------------------------------------------------------------------ */

/*
 * POST /org-roots: normalize the caller's owner set + thresholds through
 * core/model/owner-set-v7 EXACTLY (WF(S)), build the genesis transaction,
 * and persist a durable request awaiting the funder's OWN wallet signature
 * (an ordinary P2PK funding input — NOT the M-of-N owner blob, which does
 * not exist until the root itself exists).
 */
async function buildRootGenesisRequest({
  config,
  label = "",
  orgId,
  owners,
  ownerM,
  emergencyK,
  recoveryM,
  recoveryDelayDaa,
  successionDelayDaa,
  successorAddress = null,
  rootValueKas,
  rootMaxFeePerTxKas,
  signerAddress,
  funding
}) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  } catch (e) {
    throwFail(e.message, "BUILD_FAILED");
  }
  if (typeof signerAddress !== "string") throwFail("signerAddress (the funder) is required", "BUILD_FAILED");
  const funderXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;

  const slots = new Array(OWNER_SLOTS_V7).fill(INACTIVE_SLOT_KEY);
  const slotMeta = [];
  if (!Array.isArray(owners) || owners.length === 0) throwFail("owners must be a non-empty array of { slot, address | publicKey, label? }", "OWNER_SET_ILL_FORMED");
  for (const o of owners) {
    const slotNum = Number(o.slot);
    if (!Number.isInteger(slotNum) || slotNum < 1 || slotNum > OWNER_SLOTS_V7) throwFail(`owners[].slot must be 1..${OWNER_SLOTS_V7}`, "OWNER_SET_ILL_FORMED");
    let pk;
    if (typeof o.publicKey === "string") pk = normalizeXOnlyPubkey(o.publicKey, `owners[slot ${slotNum}].publicKey`);
    else if (typeof o.address === "string") pk = resolveAddressIdentity(config, o.address).xOnlyPubkey;
    else throwFail(`owners[slot ${slotNum}] requires address or publicKey`, "OWNER_SET_ILL_FORMED");
    if (slots[slotNum - 1] !== INACTIVE_SLOT_KEY) throwFail(`owners[] repeats slot ${slotNum}`, "OWNER_SET_ILL_FORMED");
    slots[slotNum - 1] = pk;
    let displayAddress = typeof o.address === "string" ? o.address : null;
    if (displayAddress === null) {
      /* addressForXOnlyPubkey's underlying WASM curve-point check can throw
       * a bare string (not an Error) for hex that is well-formed but not a
       * valid secp256k1 point — never let that escape unclassified. */
      try {
        displayAddress = addressForXOnlyPubkey(config, pk);
      } catch (e) {
        throw fail(`owners[slot ${slotNum}].publicKey is not a valid secp256k1 point: ${e && e.message ? e.message : e}`, "OWNER_SET_ILL_FORMED");
      }
    }
    slotMeta.push({ slot: slotNum, publicKey: pk, address: displayAddress, label: typeof o.label === "string" ? o.label : "" });
  }

  const successorPk = successorAddress ? resolveAddressIdentity(config, successorAddress).xOnlyPubkey : INACTIVE_SLOT_KEY;
  const orgIdHex = orgId ? normalizeHex(orgId, 32, "orgId") : crypto.randomBytes(32).toString("hex");

  const template = {
    orgId: orgIdHex,
    recoveryDelayDaa: canonicalAmountParam(recoveryDelayDaa, "recoveryDelayDaa"),
    successorPk,
    successionDelayDaa: canonicalAmountParam(successionDelayDaa, "successionDelayDaa"),
    rootMaxFeePerTx: kasToSompi(rootMaxFeePerTxKas, "rootMaxFeePerTxKas").toString()
  };
  /* ownerM/emergencyK/recoveryM are small THRESHOLDS (1..12), not amounts —
   * core/model/owner-set-v7's own normalizer already accepts a BigInt,
   * integer, or canonical digit string and fails closed on anything else
   * (smallInt); passed through unchanged rather than pre-validated with the
   * amount-shaped canonicalAmountParam. */
  const ownerSet = { owners: slots, ownerM, emergencyK, recoveryM };
  let normalizedOwnerSet;
  try {
    normalizedOwnerSet = normalizeOwnerSetV7(ownerSet);
  } catch (e) {
    throw fail(e.message, "OWNER_SET_ILL_FORMED");
  }
  void normalizedOwnerSet;

  const rootValueSompi = kasToSompi(rootValueKas, "rootValueKas");
  const fundingInputs = await resolveFunding(config, { funding }, signerAddress, rootValueSompi + 1_000_000n);

  let genesis;
  try {
    genesis = buildCreateV7Root({ config, template, ownerSet, rootValueSompi, funding: fundingInputs, changeXOnly: funderXOnly });
  } catch (e) {
    throw fail(`root genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  const summary = {
    kind: "genesis-summary",
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    networkId: config.networkId,
    orgId: orgIdHex,
    covenantId: genesis.covenantId,
    template: rootTemplateToJsonV7(template),
    slots: slotMeta,
    initialState: genesis.initialState,
    rootValueKas: sompiToKas(rootValueSompi),
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi
  };
  const signerVisibleDigest = computeManifestHashV1(summary);

  const request = {
    schemaVersion: ORG_ROOT_REQUEST_SCHEMA,
    id: requestId,
    rootCovenantId: genesis.covenantId,
    orgId: orgIdHex,
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    kind: "rootGenesis",
    action: null,
    actionClass: null,
    vaultOperations: [],
    manifest: summary,
    manifestHash: null,
    signerVisibleDigest,
    requiredApprovals: "1",
    slots: [],
    signaturesPresent: 0,
    state: RequestState.AUTHORIZED,
    build: genesis,
    finalizedTxHex: null,
    txId: genesis.txId,
    chain: null,
    warnings: [],
    createdBy: signerAddress,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    label
  };
  await saveOrgRootRequest(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 2. ROOTED VAULT GENESIS                                              */
/* ------------------------------------------------------------------ */

function templateFieldsFromDescriptor(descriptor, templateIndex) {
  const validated = assets.validateAssetDescriptor(descriptor);
  const tpl = validated.acceptedTransferTemplates[templateIndex ?? 0];
  if (!tpl) throwFail(`descriptor has no acceptedTransferTemplates[${templateIndex ?? 0}]`, "TEMPLATE_PIN_MISSING");
  return {
    validated,
    descriptorHash: assets.computeDescriptorHash(validated),
    tokenCovenantId: validated.tokenCovenantId,
    templateVmHash: tpl.templateVmHashBlake2b256,
    templatePrefixLen: tpl.prefixLen,
    templateStateLen: require("../../core/model/token-amounts").KCC20_STATE_LEN,
    templateSuffixLen: tpl.suffixLen
  };
}

async function buildRootedVaultGenesisRequest({ config, rootCovenantId, label = "", descriptor, templateIndex = 0, agents = [], recoveryAddress, depositKas, feeReserveKas, signerAddress, funding, vaultId }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  } catch (e) {
    throwFail(e.message, "BUILD_FAILED");
  }
  const root = await loadOrgRoot(config, rootCovenantId);
  if (!root) throwFail(`no organizational root ${rootCovenantId}`, "ROOT_NOT_FOUND");
  if (!root.live) throwFail("this root has no confirmed on-chain outpoint yet — reconcile the root genesis first", "ROOT_STALE_OUTPOINT");

  const funderXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const recoveryPk = resolveAddressIdentity(config, recoveryAddress).xOnlyPubkey;
  const { validated, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen } = templateFieldsFromDescriptor(descriptor, templateIndex);

  const { entries, tree } = normalizeRegistry(agents);
  const initialRegistry = entries.map((e) => registryEntryToJson(e));

  const vId = vaultId ? normalizeHex(vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex");
  const template = {
    vaultId: vId,
    descriptorHash,
    tokenCovenantId,
    templateVmHash,
    templatePrefixLen,
    templateStateLen,
    templateSuffixLen,
    orgRootCovenantId: root.rootCovenantId,
    rootTemplateVmHash: root.template.rootTemplateVmHash ?? (root.rootPins && root.rootPins.rootTemplateVmHash),
    rootPrefixLen: root.rootPins ? root.rootPins.rootPrefixLen : root.template.rootPrefixLen,
    rootStateLen: root.rootPins ? root.rootPins.rootStateLen : root.template.rootStateLen,
    rootSuffixLen: root.rootPins ? root.rootPins.rootSuffixLen : root.template.rootSuffixLen,
    recoveryPk
  };
  const feeReserveSompi = kasToSompi(feeReserveKas, "feeReserveKas");
  const initialState = { feeReserve: feeReserveSompi.toString(), paused: "0", agentRoot: tree.root, policyNonce: "0" };

  const fundingInputs = await resolveFunding(config, { funding }, signerAddress, feeReserveSompi + 1_000_000n);

  let genesis;
  try {
    genesis = buildCreateV7Vault({ config, templateInput: template, initialStateInput: initialState, funding: fundingInputs, changeXOnly: funderXOnly, descriptor: validated });
  } catch (e) {
    throw fail(`rooted vault genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  const summary = {
    kind: "genesis-summary",
    contractVersion: CONTRACT_VERSION_V7,
    networkId: config.networkId,
    vaultId: vId,
    covenantId: genesis.covenantId,
    orgRootCovenantId: root.rootCovenantId,
    template: genesis.template,
    initialState: genesis.initialState,
    depositAgentCount: agents.length,
    feeReserveKas: sompiToKas(feeReserveSompi),
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi
  };
  const signerVisibleDigest = computeManifestHashV1(summary);

  const request = {
    schemaVersion: ORG_ROOT_REQUEST_SCHEMA,
    id: requestId,
    rootCovenantId: root.rootCovenantId,
    orgId: root.orgId,
    contractVersion: CONTRACT_VERSION_V7,
    kind: "rootedVaultGenesis",
    action: null,
    actionClass: null,
    vaultOperations: [],
    manifest: summary,
    manifestHash: null,
    signerVisibleDigest,
    requiredApprovals: "1",
    slots: [],
    signaturesPresent: 0,
    state: RequestState.AUTHORIZED,
    build: genesis,
    finalizedTxHex: null,
    txId: genesis.txId,
    chain: null,
    warnings: [],
    createdBy: signerAddress,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    label,
    descriptor: validated,
    templateIndex,
    initialRegistry
  };
  await saveOrgRootRequest(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 3. ROOT ACTION (+ AT MOST ONE vault operation, the SDK builder's own  */
/*    limit — a single transaction carries one root input and one vault */
/*    input; see docs/postlaunch/v0.7-organizational-root-design.md      */
/*    §14.5 "THE SERIALIZATION POINT")                                  */
/* ------------------------------------------------------------------ */

async function buildRootActionRequest(args) {
  return withOrgRootLock(args.rootCovenantId, () => buildRootActionRequestUnlocked(args));
}
async function buildRootActionRequestUnlocked({ config, rootCovenantId, action, params = {}, vaultOperations = [], signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  } catch (e) {
    throwFail(e.message, "BUILD_FAILED");
  }
  if (!ROOT_ACTION_NAMES.has(action)) throwFail(`unknown root action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ROOT_ACTION");
  const root = await loadOrgRoot(config, rootCovenantId);
  if (!root) throwFail(`no organizational root ${rootCovenantId}`, "ROOT_NOT_FOUND");
  if (!root.live) throwFail("this root has no confirmed on-chain outpoint yet", "ROOT_STALE_OUTPOINT");
  if (root.pendingRequestId) throwFail(`this root already has a pending request ${root.pendingRequestId} — one owner-authorized transition per root outpoint at a time`, "ROOT_PENDING_REQUEST");
  const orphaned = (await pendingRootRequests(config, root))[0];
  if (orphaned) throwFail(`root request ${orphaned.id} already reserves this predecessor — resume or withdraw that request`, "ROOT_PENDING_REQUEST");
  if (!Array.isArray(vaultOperations) || vaultOperations.length > 1) {
    /* Not merely an SDK-tooling limit: PolicyVault.v0.7-payment.sil's
     * requireOnlyRootCovenantInputs() requires every non-vault, non-root
     * input to carry covenant id ZERO, so a second rooted vault riding the
     * same transaction is a foreign covenant rider the engine itself
     * refuses (coordinator-verified against the covenant source, adversarial
     * probe 20). Refuse before any durable record, never build/store one. */
    throwFail("at most ONE vault operation may ride a single root transition — the covenant refuses a second rooted vault as a foreign covenant input", "ONE_VAULT_OPERATION_PER_ROOT_TRANSITION");
  }

  const rootState = normalizeRootStateV7(root.state);
  const rootTemplate = normalizeRootTemplateV7(root.template);
  assertInitiatingOwner(config, { rootState, action, signerAddress, successorPk: rootTemplate.successorPk });

  /* rc21 review R6-06: the change returns to the OWNER OF THE FUEL INPUT (whoever signs the fee input), never to the
   * initiating signer by default — with an explicitly supplied fuel UTXO those can differ, and the shared verifier
   * (feePayerChangeBound) refuses a change output that is not the fuel owner's own P2PK. */
  const changeForFuel = (fuel) => {
    const m = /^20([0-9a-f]{64})ac$/i.exec(String((fuel && fuel.scriptPublicKeyHex) || ""));
    if (!m) throwFail("the fuel input must be an ordinary single-key (P2PK) output — its owner signs the fee input and receives the change", "FUEL_INVALID");
    return m[1].toLowerCase();
  };
  const rootChain = { predecessorOutpoint: normalizeOutpoint(root.live.outpoint, "root.live.outpoint"), covenantId: root.rootCovenantId, predecessorValue: root.live.value };

  let vaultOpEntry = null;
  let build;
  let vaultRecord = null;
  let newRegistry = null; // rc26 round-7 review R7-02: the validated registry entries an ownerSetAgentRoot installs (null for every other request)
  if (vaultOperations.length === 1) {
    const op = vaultOperations[0];
    if (!ownGet(OWNER_OP_ACTIONS, op.action)) throwFail(`unknown rooted-vault owner action ${JSON.stringify(op.action)} — failing closed`, "UNKNOWN_ACTION");
    vaultRecord = await loadManifestV7(config, op.vaultId);
    if (!vaultRecord) throwFail(`no rooted vault ${op.vaultId}`, "VAULT_NOT_FOUND");
    await assertVaultCompletionAvailable(config, vaultRecord);
    if (vaultRecord.orgRootCovenantId !== root.rootCovenantId) throwFail("this vault is not pinned to this root", "HOSTED_ORG_IS_NOT_A_ROOT");
    if (!vaultRecord.live) throwFail("this rooted vault has no confirmed on-chain outpoint yet", "ROOT_STALE_OUTPOINT");
    const authority = resolveOwnerOpAuthorityV7(op.action);
    if (authority.rootActionName !== action) {
      throwFail(`${op.action} requires the root to run ${authority.rootActionName}, not ${action}`, "OWNER_PATH_TAKES_NO_SIGNATURE");
    }
    const fuel = await resolveFuel(config, params, signerAddress, 500_000n);
    /* rc26 round-7 review R7-02: ownerSetAgentRoot installs a FULL new delegate policy set. The caller supplies the set
     * as REGISTRY ENTRIES (policy fields + each agent's recipient allowlist, exactly the genesis `agents` shape); the
     * entries are validated here (recipient roots reproduce, closed layout), the builder derives the new agentRoot from
     * the policies (never from a caller-supplied root), the manifest carries the policies for the owners' review, and
     * the durable registry is replaced by these entries only once the transition is CHAIN-VERIFIED. */
    let opParams = op.params ?? {};
    if (op.action === "ownerSetAgentRoot") {
      if (!Array.isArray(opParams.agents)) throwFail("ownerSetAgentRoot requires params.agents — the FULL new delegate policy set with each agent's recipients (never a bare root)", "AGENT_SET_REQUIRED");
      let normalized;
      try { normalized = normalizeRegistry(opParams.agents); } catch (e) { throw fail(`ownerSetAgentRoot: the new delegate policy set is malformed: ${e.message}`, e.code || "AGENT_SET_INVALID"); }
      newRegistry = normalized.entries.map((e) => registryEntryToJson(e));
      opParams = { ...opParams, agents: normalized.entries.map((e) => ({ ...tokenAgentPolicyToJsonV5(e.policy), recipients: [...e.recipients] })), newAgentRoot: normalized.tree.root }; // Codex checkpoint 11 (R7-02): the FULL entries (policy + recipients) reach the builder and therefore the manifest
    }
    try {
      build = buildV7Transaction({
        config,
        contractVersion: CONTRACT_VERSION_V7,
        templateInput: vaultRecord.template,
        stateInput: stateToJsonV7(vaultRecord.live.state),
        action: op.action,
        params: opParams,
        chain: {
          predecessorOutpoint: normalizeOutpoint(vaultRecord.live.outpoint, "vault.live.outpoint"),
          covenantId: vaultRecord.live.covenantId,
          predecessorValue: vaultRecord.live.state.feeReserve.toString(),
          ...(op.action === "ownerRecover" && vaultRecord.live.tokenPosition ? { tokenPosition: vaultManifestTokenPositionJson(vaultRecord.live.tokenPosition) } : {}),
          fuel,
          root: { template: root.template, state: root.state, outpoint: rootChain.predecessorOutpoint, covenantId: root.rootCovenantId, value: root.live.value }
        },
        changeXOnly: changeForFuel(fuel),
        descriptor: vaultRecord.asset.descriptor,
        templateIndex: vaultRecord.asset.templateIndex
      });
    } catch (e) {
      throw fail(`rooted-vault owner-op build failed: ${e.message}`, e.code || "BUILD_FAILED");
    }
    vaultOpEntry = { build, descriptor: vaultRecord.asset.descriptor };
  } else {
    const fuel = await resolveFuel(config, params, signerAddress, 500_000n);
    try {
      build = buildV7RootTransaction({
        config,
        contractVersion: CONTRACT_VERSION_V7_ROOT,
        templateInput: root.template,
        stateInput: root.state,
        action,
        params: action === "rotate" || action === "ownerRecover" || action === "succession" ? { newOwnerSet: params.newOwnerSet } : {},
        chain: { ...rootChain, fuel },
        changeXOnly: changeForFuel(fuel)
      });
    } catch (e) {
      throw fail(`root action build failed: ${e.message}`, e.code || "BUILD_FAILED");
    }
  }

  const manifestSourceBuild = vaultOpEntry ? vaultOpEntry.build : build;
  const descriptors = vaultRecord ? { [vaultRecord.live.covenantId]: vaultRecord.asset.descriptor } : {};
  // Codex checkpoint 6 (UX-02 / UX-13): the vault's predecessor redeem script travels with the request so every verifier
  // (this one, the browser boundary, attestations) rebuilds and binds the vault SUCCESSOR script — never skipped.
  const redeemScripts = vaultOpEntry && vaultOpEntry.build && typeof vaultOpEntry.build.vaultRedeemScriptHex === "string" ? { [vaultRecord.live.covenantId]: vaultOpEntry.build.vaultRedeemScriptHex } : {};
  let manifest;
  try {
    manifest = buildOrgRootIntentManifest({ build: manifestSourceBuild, vaultOperations: vaultOpEntry ? [vaultOpEntry] : [] });
  } catch (e) {
    throw fail(`manifest build failed: ${e.message}`, e.code || "MANIFEST_BUILD_FAILED");
  }
  const verification = verifyOrgRootIntentManifest({ manifest, descriptors, redeemScripts });
  if (verification.verdict !== "VERIFIED") {
    throw fail(`the built transaction failed org-root manifest verification: ${verification.failures.map((f) => f.name).join(", ")}`, "INTENT_VERIFICATION_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, manifestSourceBuild.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const rootInputIndex = manifestSourceBuild.frozen.inputs.findIndex((i) => i.utxo.covenantId === root.rootCovenantId);

  const requiredApprovals = manifest.action.requiredApprovals;
  const expectedSlots = manifest.action.expectedSignerSlots.map((s) => {
    const meta = (root.slots ?? []).find((m) => m.slot === s.slot) ?? {};
    return { slot: s.slot, publicKey: s.publicKey, address: meta.address ?? addressForXOnlyPubkey(config, s.publicKey), label: meta.label ?? "", status: "PENDING", signedAt: null, responseEnvelopeHash: null };
  });

  const requestId = crypto.randomUUID();
  const request = {
    schemaVersion: ORG_ROOT_REQUEST_SCHEMA,
    id: requestId,
    rootCovenantId: root.rootCovenantId,
    orgId: root.orgId,
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    kind: "rootAction",
    action,
    actionClass: manifest.action.authorityClass,
    /* Codex checkpoint 12 (R7-02): the vault PREDECESSOR identities (outpoint, generation, last transition) are captured
     * from the manifest the build consumed and travel with the request, so a replay after the vault already advanced
     * releases the OLD claim key and can tell a genuinely newer vault transition from a stale record. */
    vaultOperations: vaultOpEntry ? [{ vaultId: vaultRecord.vaultId, action: vaultOperations[0].action, params: vaultOperations[0].params ?? {}, predecessor: { outpoint: normalizeOutpoint(vaultRecord.live.outpoint, "vault.live.outpoint"), generation: Number(vaultRecord.generation ?? 0), latestTransitionTxId: vaultRecord.latestTransitionTxId ?? null } }] : [],
    newRegistry, // rc26 round-7 review R7-02: the validated registry entries an ownerSetAgentRoot installs (null otherwise); applied to the durable registry only on CHAIN_VERIFIED
    manifest,
    redeemScripts, // Codex checkpoint 6: the predecessor redeem script this verification rebuilt the successor from travels with the request (bound by the vault input's P2SH + stateBefore)
    descriptors, // rc21 review R6-02: the descriptors this verification used travel with the request (the browser verifies with them; their hash + the token UTXO script bind them)
    manifestHash: manifest.manifestHash,
    signerVisibleDigest: manifest.manifestHash,
    requiredApprovals,
    slots: expectedSlots,
    signaturesPresent: 0,
    state: action === "succession" ? RequestState.AUTHORIZED : RequestState.AUTHORIZED,
    build: manifestSourceBuild,
    rootInputIndex,
    finalizedTxHex: null,
    txId: manifestSourceBuild.txId,
    chain: null,
    warnings: warningsFor(action, manifest.root ? manifest.rootState.after.state.frozen === "1" : false),
    createdBy: signerAddress,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    transaction: { unsignedSafeJson, signInputs: manifestSourceBuild.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) }
  };
  await saveOrgRootRequest(config, request);
  root.pendingRequestId = requestId;
  await saveOrgRoot(config, root);
  return request;
}

/* ------------------------------------------------------------------ */
/* 4. SLOT SIGNING                                                      */
/* ------------------------------------------------------------------ */

/*
 * The slot-request envelope carries a freshly random requestId and a
 * Date.now()-derived expiry (core/signer/org-root-slot-v7's own createRoot-
 * SlotSigningRequest is deliberately non-deterministic — every USI request
 * is). It is therefore generated ONCE per (org-root request, slot) and
 * persisted on the durable ORG_ROOT_REQUEST record, so the SAME envelope
 * is what GET .../slot-request/:slot hands to a wallet and what POST
 * .../slot-signatures verifies the response against — never regenerated
 * (which would mint a NEW requestId every call and make every response
 * look like a replay against the wrong request, RESPONSE_REPLAYED).
 */
function getSlotSigningRequest({ config, request, slot }) {
  if (request.kind !== "rootAction") throwFail("only a rootAction request has owner slots to sign", "NOT_A_SLOT_REQUEST");
  if (request.action === "succession") throwFail("a succession is authorized by the successor key through its own entrypoint, not by an owner slot", "SUCCESSION_TAKES_NO_SLOTS");
  const slotEntry = request.slots.find((s) => s.slot === Number(slot));
  if (!slotEntry) throwFail(`slot ${slot} is not one of this request's expected signer slots`, "SLOT_INACTIVE");
  const cached = request.slotRequestEnvelopes && request.slotRequestEnvelopes[String(slot)];
  if (cached) return cached;
  const { createRootSlotSigningRequest } = require("../../core/signer/org-root-slot-v7");
  const expiresAtMs = Date.now() + 60 * 60 * 1000;
  return createRootSlotSigningRequest({
    manifest: request.manifest,
    descriptors: request.descriptors && typeof request.descriptors === "object" && !Array.isArray(request.descriptors) ? request.descriptors : {}, // rc21 review R6-02
    redeemScripts: request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {}, // Codex checkpoint 6 (UX-02 / UX-13)
    slot: Number(slot),
    expectedSignerAddress: slotEntry.address,
    unsignedSafeJson: request.transaction.unsignedSafeJson,
    rootInputIndex: request.rootInputIndex,
    expiresAtMs
  });
}

/* Same as getSlotSigningRequest but persists the FIRST envelope generated
 * for a slot, so every later caller (GET slot-request, and the verify step
 * inside submitSlotSignature) sees the identical one. */
/*
 * Takes a requestId (not a caller-held request object) and reloads fresh
 * from the store before writing — so two concurrent callers (or a caller
 * holding a stale in-memory copy from before an earlier slot signature was
 * recorded) can never clobber another slot's already-persisted signature
 * by racing a save of a stale snapshot.
 */
async function getOrCreateSlotSigningRequest(args) {
  return withRootRequestLock(args.config, args.requestId, () => getOrCreateSlotSigningRequestUnlocked(args));
}
async function getOrCreateSlotSigningRequestUnlocked({ config, requestId, slot }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  // rc16 review N-02 (server-side guard): an owner slot signing request is
  // handed out ONLY while approvals are still being collected. After the
  // request is finalized (SIGNED) or beyond, a cached envelope must not be
  // returned either — a wallet must never be asked to sign for nothing.
  if (request.state !== RequestState.AUTHORIZED) throwFail(`request is ${request.state}, not AUTHORIZED — no owner slot signing request is issued`, "REQUEST_NOT_SIGNABLE");
  await assertRootRequestNotAttempted(config, request);
  const existing = request.slotRequestEnvelopes && request.slotRequestEnvelopes[String(slot)];
  if (existing) return existing;
  const envelope = getSlotSigningRequest({ config, request, slot });
  request.slotRequestEnvelopes = { ...(request.slotRequestEnvelopes ?? {}), [String(slot)]: envelope };
  await saveOrgRootRequest(config, request);
  return envelope;
}

/*
 * POST .../slot-signatures — verify ONE owner's response envelope (foreign
 * key / duplicate slot / mismatched digest / expired -> the signer
 * module's own closed refusal vocabulary) and store it.
 */
async function submitSlotSignature(args) {
  return withRootRequestLock(args.config, args.requestId, () => submitSlotSignatureUnlocked(args));
}
async function submitSlotSignatureUnlocked({ config, requestId, slot, response }) {
  const preCheck = await loadOrgRootRequest(config, requestId);
  if (!preCheck) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (preCheck.kind !== "rootAction") throwFail("only a rootAction request accepts slot signatures", "NOT_A_SLOT_REQUEST");
  if (preCheck.state !== RequestState.AUTHORIZED) throwFail(`request is ${preCheck.state}, not AUTHORIZED`, preCheck.state);
  await assertRootRequestNotAttempted(config, preCheck);
  const slotIndexPre = preCheck.slots.findIndex((s) => s.slot === Number(slot));
  if (slotIndexPre < 0) throwFail(`slot ${slot} is not one of this request's expected signer slots`, "SLOT_INACTIVE");
  if (preCheck.slots[slotIndexPre].status === "SIGNED") throwFail(`slot ${slot} already carries a signature`, "DUPLICATE_SLOT_SIGNATURE");

  /* getOrCreateSlotSigningRequest reloads AND may persist independently
   * (the FIRST GET/POST for a slot mints and caches its envelope); reload
   * again AFTER it returns so the mutation below is applied to the record
   * THAT write produced, never a stale snapshot that would clobber it. */
  const requestEnvelope = await getOrCreateSlotSigningRequestUnlocked({ config, requestId, slot });
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  const slotIndex = request.slots.findIndex((s) => s.slot === Number(slot));
  if (slotIndex < 0) throwFail(`slot ${slot} is not one of this request's expected signer slots`, "SLOT_INACTIVE");
  if (request.slots[slotIndex].status === "SIGNED") throwFail(`slot ${slot} already carries a signature`, "DUPLICATE_SLOT_SIGNATURE");

  const { verifyRootSlotSignatureResponse } = require("../../core/signer/org-root-slot-v7");
  const predecessorOwnerSet = normalizeRootStateV7(request.manifest.rootState.before.state);
  let verified;
  try {
    verified = verifyRootSlotSignatureResponse({ request: requestEnvelope, response, ownerSet: predecessorOwnerSet, nowMs: Date.now() });
  } catch (e) {
    throw fail(e.message, e.details?.reason || e.code || "SLOT_KEY_MISMATCH");
  }
  const responseEnvelopeHash = crypto.createHash("sha256").update(canonicalJsonStringify(response)).digest("hex");
  request.slots[slotIndex] = { ...request.slots[slotIndex], status: "SIGNED", signedAt: new Date().toISOString(), responseEnvelopeHash, _approval: { slot: verified.slot, publicKey: verified.publicKey, signatureHex: verified.signatureHex } };
  request.signaturesPresent = request.slots.filter((s) => s.status === "SIGNED").length;
  await saveOrgRootRequest(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 5. FINALIZE                                                          */
/* ------------------------------------------------------------------ */

/*
 * kind rootAction  -> M-of-N finalize via the SDK finalizer; UNDER_QUORUM
 *                     refused with present/required.
 * kind rootGenesis / rootedVaultGenesis -> the funder's OWN signed Safe
 *                     JSON (ordinary P2PK funding inputs); immutability
 *                     asserted exactly as the v4 genesis path does.
 */
/*
 * POST .../requests/:id/signature — the SINGLE-SIGNER path, mirroring
 * /wallet/v4/requests/:id/signature's body shape (signedSafeJson, or a raw
 * signatureHex + signerAddress). Covers exactly the three request shapes
 * that are authorized by ONE signature rather than an M-of-N owner blob:
 *   - rootGenesis          the funder's own signature over its funding UTXO(s)
 *   - rootedVaultGenesis   likewise
 *   - rootAction/succession the PINNED SUCCESSOR key's signature over the
 *     root input (core/signer/org-root-slot-v7 refuses to route a
 *     succession through the slot-blob path at all: SUCCESSION_TAKES_NO_SLOTS)
 * Any other request kind/action is refused with a closed code telling the
 * caller to use /finalize (M-of-N) instead.
 */
async function submitOrgRootRequestSignature(args) {
  return withRootRequestLock(args.config, args.requestId, () => submitOrgRootRequestSignatureUnlocked(args));
}
async function submitOrgRootRequestSignatureUnlocked({ config, requestId, signedSafeJson, signatureHex, fuelSignatureScriptHex, signerAddress }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.AUTHORIZED) throwFail(`request is ${request.state}, not AUTHORIZED`, request.state);
  await assertRootRequestNotAttempted(config, request);

  if (request.kind === "rootGenesis" || request.kind === "rootedVaultGenesis") {
    if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throwFail("signedSafeJson is required to sign a genesis request", "BAD_SIGNATURE");
    const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
    let signed;
    try {
      signed = JSON.parse(signedSafeJson);
    } catch {
      throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
    }
    assertImmutable(unsigned, signed);
    for (let i = 0; i < unsigned.inputs.length; i++) {
      if (!signed.inputs[i]?.signatureScript) throwFail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
    }
    /* F-04: VERIFY BEFORE SIGNED — every funding input executes on the real
     * engine (Schnorr over THIS genesis with the key the UTXO names). A bogus,
     * foreign or replayed signature is a pure refusal; the request stays
     * AUTHORIZED for the legitimate funder. */
    try {
      verifySignedSafeJsonInputs({ frozenCanonicalJson: request.build.frozenCanonicalJson, signedSafeJson });
    } catch (e) {
      throwFail(`genesis signature rejected: ${e.message}`, "SIGNATURE_INVALID");
    }
    request.signedSafeJson = signedSafeJson;
    request.state = RequestState.SIGNED;
    await saveOrgRootRequest(config, request);
    return request;
  }

  if (request.kind !== "rootAction" || request.action !== "succession") {
    throwFail("this request requires M-of-N owner slot signatures via slot-signatures + finalize, not a single signature", "NOT_A_SINGLE_SIGNER_REQUEST");
  }

  /* succession: the PINNED successor key's signature over the root input.
   * Either a full signedSafeJson (covers the root input AND the fuel input
   * in one wallet call — the ordinary case) or a raw successor signatureHex
   * (+ the required identity check against the template's pinned
   * successorPk) with fuelSignatureScriptHex supplied alongside it. */
  let successorSignatureHex = null;
  let fuelSig = fuelSignatureScriptHex;
  if (typeof signedSafeJson === "string" && signedSafeJson.trim()) {
    const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
    let signed;
    try {
      signed = JSON.parse(signedSafeJson);
    } catch {
      throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
    }
    assertImmutable(unsigned, signed);
    successorSignatureHex = signed.inputs?.[request.rootInputIndex]?.signatureScript;
    fuelSig = signed.inputs?.[signed.inputs.length - 1]?.signatureScript;
    if (!successorSignatureHex) throwFail("wallet did not sign the root (successor) input", "WALLET_REJECTED");
    if (!fuelSig) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
  } else if (typeof signatureHex === "string" && signatureHex.trim()) {
    if (typeof signerAddress !== "string") throwFail("signerAddress is required alongside a raw signatureHex", "BAD_SIGNATURE");
    const claimedXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
    const pinnedSuccessorPk = normalizeRootTemplateV7(request.build.template).successorPk;
    if (claimedXOnly !== pinnedSuccessorPk) throwFail("signerAddress does not hold this root's pinned successor key", "NOT_AN_ACTIVE_SLOT");
    successorSignatureHex = signatureHex;
  } else {
    throwFail("signedSafeJson or signatureHex + signerAddress is required", "BAD_SIGNATURE");
  }

  let fin;
  try {
    ensureBuildDirV7(config, request.build); // F-03
    fin = finalizeV7RootTransaction({ build: request.build, successorSignatureHex, fuelSignatureScriptHex: fuelSig });
    verifyFinalTransactionInputs(fin.finalTransaction); // F-04: successor + fuel inputs on the real VM before SIGNED
  } catch (e) {
    throw fail(`sign failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.finalizedTxHex = fin.covenantCallHex;
  request.finalTransaction = fin.finalTransaction;
  request.state = RequestState.SIGNED;
  await saveOrgRootRequest(config, request);
  return request;
}

/*
 * POST .../requests/:id/finalize — the M-of-N path ONLY (root action or a
 * root action carrying one vault operation, both non-succession). Genesis
 * and succession requests are single-signer and go through
 * submitOrgRootRequestSignature (POST .../requests/:id/signature) instead;
 * this route refuses them with a closed code rather than accepting a body
 * shape that would never apply.
 */
async function finalizeOrgRootRequest(args) {
  return withRootRequestLock(args.config, args.requestId, () => finalizeOrgRootRequestUnlocked(args));
}
async function finalizeOrgRootRequestUnlocked({ config, requestId, fuelSignatureScriptHex }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.AUTHORIZED) throwFail(`request is ${request.state}, not AUTHORIZED`, request.state);
  await assertRootRequestNotAttempted(config, request);

  if (request.kind === "rootGenesis" || request.kind === "rootedVaultGenesis") {
    throwFail("a genesis request is signed via POST .../requests/:id/signature, not /finalize", "NOT_AN_MOFN_REQUEST");
  }
  if (request.kind !== "rootAction") throwFail(`unknown request kind ${request.kind}`, "UNKNOWN_REQUEST_KIND");
  if (request.action === "succession") {
    throwFail("a succession is signed via POST .../requests/:id/signature (the pinned successor key), not /finalize", "NOT_AN_MOFN_REQUEST");
  }

  const approvals = request.slots.filter((s) => s.status === "SIGNED").map((s) => s._approval);
  const required = Number(request.requiredApprovals);
  if (approvals.length < required) {
    throw fail(`insufficient owner approvals: ${approvals.length} present, ${required} required`, "UNDER_QUORUM");
  }
  const isRootOnly = request.build.kind === "orgRootTransition";
  let fin;
  try {
    ensureBuildDirV7(config, request.build); // F-03
    fin = isRootOnly
      ? finalizeV7RootTransaction({ build: request.build, approvals, fuelSignatureScriptHex })
      : finalizeV7Transaction({ build: request.build, approvals, fuelSignatureScriptHex });
    verifyFinalTransactionInputs(fin.finalTransaction); // F-04: the assembled M-of-N transaction executes on the real VM before SIGNED
  } catch (e) {
    throw fail(`finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.finalizedTxHex = fin.covenantCallHex;
  request.finalTransaction = fin.finalTransaction;
  request.state = RequestState.SIGNED;
  await saveOrgRootRequest(config, request);
  return request;
}

function assertImmutable(unsigned, signed) {
  const strip = (tx) => ({ version: tx.version, lockTime: tx.lockTime, subnetworkId: tx.subnetworkId, gas: tx.gas, payload: tx.payload, inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })), outputs: tx.outputs });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throwFail("signed transaction mutated a consensus-visible field", "SIGNATURE_INVALID");
}

/* ------------------------------------------------------------------ */
/* 6. SUBMIT — the ONLY place a v0.7 org-root transaction is broadcast.  */
/*    Durable claims BEFORE broadcast; PENDING is never success; only    */
/*    exact chain proof advances ORG_ROOT / VAULT records.               */
/* ------------------------------------------------------------------ */

async function findOutpoint(rpc, address, txId, index) {
  const utxos = await getAddressUtxos(rpc, address);
  return utxos.find((u) => u.outpoint.transactionId === txId && Number(u.outpoint.index) === Number(index)) ?? null;
}

/* A P2SH scriptPublicKey (as carried by every frozen build's outputs, shape
 * { version, scriptHex }) -> its canonical address on this network. */
function spkToAddress(config, spk) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const address = kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId);
  if (!address) throwFail("could not derive an address from a scriptPublicKey — internal");
  return address.toString();
}

/* Codex checkpoint 12 (R7-02): a root action in one of these states may have an on-chain effect whose durable records are
 * incomplete (crash / persistence failure after the broadcast, a legacy partial record, a CHAIN_VERIFIED label written
 * beside a stale vault). Submission RECOVERS such a request from chain evidence instead of refusing it as "not SIGNED" or
 * returning early on the label; it NEVER rebroadcasts. */
const RECOVERABLE_ROOT_ACTION_STATES = new Set([RequestState.BROADCAST, RequestState.CHAIN_SEEN, RequestState.RECONCILIATION_REQUIRED, RequestState.CHAIN_VERIFIED]);

async function hasBoundRootCompletionReceipt(config, request) {
  if (request.kind !== "rootAction" || !request.finalTransaction) return false;
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (!receiptPointerMatches(receipt, request) || !receiptMatches(receipt, request, rootSuccessorTarget(config, request))) return false;
  assertFrozenRequestTransaction(config, request);
  return auditLinePresent(config, request);
}
async function submitOrgRootRequest(args) {
  return withRootRequestLock(args.config, args.requestId, () => submitOrgRootRequestUnlocked(args));
}
async function submitOrgRootRequestUnlocked({ config, requestId, pollAttempts = 30, pollDelayMs = 2000, rpc: providedRpc }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state === RequestState.VERIFIED_OUTCOME) return request; // idempotent
  let priorAttempt = false;
  if (request.kind === "rootAction" && request.state === "SIGNED") {
    const root = await loadOrgRoot(config, request.rootCovenantId);
    const claim = await loadTransitionClaim(config, request.manifest.root.outpoint);
    priorAttempt = !sameOutpoint(root?.live?.outpoint, request.manifest.root.outpoint) || claim?.txId === request.txId && claim.expected?.requestId === request.id || !!request.submissionAttempt;
    if (priorAttempt) {
      const completed = await completedRequestAt(config, request.txId);
      if (completed && completed.id !== request.id) throwFail("this transaction's canonical completion belongs to another request — this draft cannot claim that completion", "RECONCILIATION_REQUIRED");
    }
  }
  const recovering = request.kind === "rootAction" && (priorAttempt || RECOVERABLE_ROOT_ACTION_STATES.has(request.state) || ["SIGNED", "SUBMISSION_REJECTED"].includes(request.state) && await hasBoundRootCompletionReceipt(config, request));
  if (recovering && request.state === RequestState.CHAIN_VERIFIED) {
    /* a terminal label is not evidence of complete local state: every durable record is verified before the idempotent return */
    const verified = await verifyRootActionCompletion(config, request);
    if (verified.complete) return request;
  } else if (request.state === RequestState.CHAIN_VERIFIED) {
    return request; // genesis kinds: idempotent
  } else if (!recovering && request.state !== RequestState.SIGNED) {
    throwFail(`request is ${request.state}, not SIGNED`, request.state);
  }

  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  } catch (e) {
    throw fail(e.message, "NETWORK_MISMATCH");
  }

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");

    if (recovering) return await recoverRootActionRequest({ config, rpc, request });
    if (request.kind === "rootGenesis") return await submitRootGenesis({ config, rpc, request });
    if (request.kind === "rootedVaultGenesis") return await submitVaultGenesis({ config, rpc, request });
    if (request.kind === "rootAction") return await submitRootAction({ config, rpc, request });
    throw fail(`unknown request kind ${request.kind}`, "UNKNOWN_REQUEST_KIND");
  } finally {
    if (owned) await rpc.disconnect();
  }
}

async function broadcastSignedGenesis(config, rpc, request) {
  const { Transaction } = require("./chain").loadKaspa(config);
  const transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
  const signed = JSON.parse(request.signedSafeJson);
  const ins = transaction.inputs;
  for (let i = 0; i < ins.length; i++) ins[i].signatureScript = signed.inputs[i].signatureScript;
  transaction.inputs = ins;
  const txId = transaction.finalize().toString().toLowerCase();
  if (txId !== request.txId) throw fail(`reconstructed txid ${txId} != frozen ${request.txId}`, "TXID_MISMATCH");
  await claimSubmission(config, { txId, vaultId: request.rootCovenantId, action: request.kind });
  request.state = RequestState.BROADCAST;
  await saveOrgRootRequest(config, request);
  try {
    const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    const returned = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returned !== txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveOrgRootRequest(config, request);
      throw fail(`node returned ${returned}, expected ${txId} — reconcile`, "RECONCILIATION_REQUIRED");
    }
  } catch (e) {
    if (e.code === "RECONCILIATION_REQUIRED") throw e;
    const message = String(e.message ?? e).split("\n")[0];
    request.error = message;
    if (isDefinitiveSubmitRejection(message)) {
      await releaseSubmissionClaim(config, txId);
      request.state = RequestState.SUBMISSION_REJECTED;
      await saveOrgRootRequest(config, request);
      throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
    }
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
  }
  return txId;
}

async function submitRootGenesis({ config, rpc, request }) {
  const txId = await broadcastSignedGenesis(config, rpc, request);
  /* rootScriptHex is the RAW covenant redeem script (pre-P2SH) — wrap it
   * exactly as the builder did (p2shOf) before deriving an address. */
  const { covenantAddress } = require("./chain");
  const address = covenantAddress(config, Buffer.from(request.build.rootScriptHex, "hex"));
  let proof = null;
  for (let i = 0; i < 30 && !proof; i++) {
    const ref = await findOutpoint(rpc, address, txId, request.build.rootOutputIndex);
    if (ref && String(ref.covenantId ?? "").toLowerCase() === request.rootCovenantId) proof = ref;
    if (!proof) await new Promise((r) => setTimeout(r, 2000));
  }
  if (!proof) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`root genesis ${txId} submitted but the covenant output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
  }
  const rootState = normalizeRootStateV7(request.build.initialState);
  const root = {
    schemaVersion: ORG_ROOT_SCHEMA,
    rootCovenantId: request.rootCovenantId,
    orgId: request.orgId,
    label: request.label ?? "",
    networkId: config.networkId,
    contractVersion: CONTRACT_VERSION_V7_ROOT,
    authorityModel: AUTHORITY_MODEL.ON_CHAIN_ORGANIZATIONAL_ROOT,
    template: request.build.template,
    state: request.build.initialState,
    slots: request.manifest.slots ?? request.build.ownerSlots.map((s) => ({ slot: s.slot, publicKey: s.publicKey, address: addressForXOnlyPubkey(config, s.publicKey), label: "" })),
    rootPins: request.build.rootPins,
    live: { outpoint: { transactionId: txId, index: request.build.rootOutputIndex }, value: request.build.accounting.kas.rootValue, address, blockDaaScore: proof.blockDaaScore ? proof.blockDaaScore.toString() : null },
    generation: 0,
    pendingRequestId: null,
    vaults: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveOrgRoot(config, root);
  await persistReceipt(config, { txId, vaultId: request.rootCovenantId, action: "rootGenesis", proof: { outpoint: `${txId}:${request.build.rootOutputIndex}`, covenantId: request.rootCovenantId } });
  await appendAudit(config, { vaultId: request.rootCovenantId, action: "rootGenesis", actor: "owner", contractVersion: CONTRACT_VERSION_V7_ROOT, txId, result: "CHAIN_VERIFIED", via: "org-roots" });
  request.state = RequestState.CHAIN_VERIFIED;
  request.chain = { successorOutpoint: `${txId}:${request.build.rootOutputIndex}`, observedAt: new Date().toISOString() };
  await saveOrgRootRequest(config, request);
  return request;
}

async function submitVaultGenesis({ config, rpc, request }) {
  const txId = await broadcastSignedGenesis(config, rpc, request);
  const { covenantAddress } = require("./chain");
  const address = covenantAddress(config, Buffer.from(request.build.vaultScriptHex, "hex"));
  let proof = null;
  for (let i = 0; i < 30 && !proof; i++) {
    const ref = await findOutpoint(rpc, address, txId, request.build.vaultOutputIndex);
    if (ref && String(ref.covenantId ?? "").toLowerCase() === request.build.covenantId) proof = ref;
    if (!proof) await new Promise((r) => setTimeout(r, 2000));
  }
  if (!proof) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`vault genesis ${txId} submitted but the covenant output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
  }
  const state = normalizeStateV7(request.build.initialState);
  const stateId = computeStateIdV7({ networkId: config.networkId, template: request.build.template, state, contractVersion: CONTRACT_VERSION_V7 });
  const manifest = await persistManifestV7(config, {
    manifestVersion: MANIFEST_SCHEMA_V7,
    contractVersion: CONTRACT_VERSION_V7,
    networkId: config.networkId,
    vaultId: request.build.template.vaultId,
    label: request.label ?? "",
    status: VaultStatus.ACTIVE,
    orgRootCovenantId: request.build.orgRootCovenantId,
    template: request.build.template,
    asset: { descriptor: request.descriptor, templateIndex: request.templateIndex ?? 0 },
    agentRegistry: request.initialRegistry ?? [],
    live: { state: stateToJsonV7(state), stateId, outpoint: { transactionId: txId, index: request.build.vaultOutputIndex }, outpointValue: state.feeReserve.toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId, tokenPosition: null },
    creationTxId: txId,
    latestTransitionTxId: null,
    generation: 0
  });
  const root = await loadOrgRoot(config, request.rootCovenantId);
  if (root && !root.vaults.includes(manifest.vaultId)) {
    root.vaults.push(manifest.vaultId);
    await saveOrgRoot(config, root);
  }
  await persistReceipt(config, { txId, vaultId: manifest.vaultId, action: "rootedVaultGenesis", proof: { outpoint: `${txId}:${request.build.vaultOutputIndex}`, covenantId: request.build.covenantId } });
  await appendAudit(config, { vaultId: manifest.vaultId, action: "rootedVaultGenesis", actor: "owner", contractVersion: CONTRACT_VERSION_V7, txId, result: "CHAIN_VERIFIED", via: "org-roots" });
  request.state = RequestState.CHAIN_VERIFIED;
  request.chain = { successorOutpoint: `${txId}:${request.build.vaultOutputIndex}`, observedAt: new Date().toISOString() };
  await saveOrgRootRequest(config, request);
  return request;
}

async function submitRootAction({ config, rpc, request }) {
  for (const op of request.vaultOperations ?? []) {
    const vault = await loadManifestV7(config, op.vaultId);
    if (!vault) throwFail(`no rooted vault ${op.vaultId}`, "VAULT_NOT_FOUND");
    await assertVaultCompletionAvailable(config, vault, request.id);
  }
  /* The ROOT outpoint is the transition's serialization point (design §14.5
   * "THE SERIALIZATION POINT" — every root-authorized transaction spends the
   * SAME root UTXO, whether or not it also carries a vault operation), so
   * the durable claim is keyed on it rather than on request.build's own
   * predecessorOutpoint (which, for a vault-op build, names the VAULT'S
   * outpoint, not the root's). */
  const rootOutpoint = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  assertFrozenRequestTransaction(config, request);
  const claim = await loadTransitionClaim(config, rootOutpoint);
  if (claim && (claim.txId !== request.txId || claim.expected?.requestId !== request.id)) throwFail("the root predecessor belongs to another or unbound submission attempt — reconcile its original request", "CLAIM_CONFLICT");
  const arbitration = require("./submission-outcome-v7");
  request.submitStartHash = await arbitration.readSubmissionStartHash(rpc);
  request.submittedAt = new Date().toISOString();
  request.submissionAttempt = { id: crypto.randomUUID(), phase: "PREPARING", requestFingerprint: completionReceiptPointer(request).requestFingerprint, at: request.submittedAt };
  await saveOrgRootRequest(config, request);
  if (!claim || claim.txId !== request.txId) {
    try {
      await claimTransition(config, { outpoint: rootOutpoint, action: request.action, txId: request.txId, vaultId: request.rootCovenantId, stateId: request.manifest.rootState.before.digest ?? null, expected: { kind: "orgRootRequest", requestId: request.id } });
    } catch (e) {
      throw fail(e.message, "CLAIM_CONFLICT");
    }
  }
  await claimSubmission(config, { txId: request.txId, vaultId: request.rootCovenantId, action: request.action });

  request.state = RequestState.BROADCAST;
  request.submissionAttempt.phase = "BROADCAST_STARTED";
  await saveOrgRootRequest(config, request);

  const transaction = finalTxToWasm(config, request.finalTransaction);
  const computedTxId = transaction.finalize().toString().toLowerCase();
  if (computedTxId !== request.txId) throw fail(`reconstructed txid ${computedTxId} != frozen ${request.txId} — refusing to broadcast`, "TXID_MISMATCH");

  let submitted;
  try {
    submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
  } catch (e) {
    const message = String(e.message ?? e).split("\n")[0];
    request.error = message;
    if (arbitration.isBoundRejection(e, request.txId)) {
      request.submissionAttempt.phase = "REJECTED_RESPONSE";
      request.submissionAttempt.error = String(e.message ?? e);
    }
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
  }
  request.submissionAttempt.phase = "ACCEPTED_RESPONSE";
  const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
  if (returnedTxId !== request.txId) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
  }

  const isRootOnly = request.build.kind === "orgRootTransition";
  const isTerminalRecover = !isRootOnly && request.build.successorState === null;
  const rootOutIndex = request.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.rootCovenantId);
  const rootAddress = spkToAddress(config, request.build.frozen.outputs[rootOutIndex].scriptPublicKey);
  const rootExpectedValue = request.build.frozen.outputs[rootOutIndex].value.toString();

  let proof = null;
  for (let i = 0; i < 30 && !proof; i++) {
    const ref = await findOutpoint(rpc, rootAddress, request.txId, rootOutIndex);
    if (ref && ref.amount.toString() === rootExpectedValue) proof = ref;
    if (!proof) await new Promise((r) => setTimeout(r, 2000));
  }
  if (!proof) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`${request.txId} submitted but the root successor was not observed — reconcile`, "RECONCILIATION_REQUIRED");
  }

  let vaultOutIndex = null;
  if (!isRootOnly && !isTerminalRecover) {
    vaultOutIndex = request.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.build.covenantId);
    const vaultAddress = spkToAddress(config, request.build.frozen.outputs[vaultOutIndex].scriptPublicKey);
    const expectedValue = request.build.frozen.outputs[vaultOutIndex].value.toString();
    let vaultProof = null;
    for (let i = 0; i < 30 && !vaultProof; i++) {
      const ref = await findOutpoint(rpc, vaultAddress, request.txId, vaultOutIndex);
      if (ref && ref.amount.toString() === expectedValue) vaultProof = ref;
      if (!vaultProof) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!vaultProof) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveOrgRootRequest(config, request);
      throw fail(`${request.txId} submitted but the vault successor was not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
  } else if (isTerminalRecover) {
    /* TERMINAL ownerRecover: output 0 pays the fee reserve to P2PK(recoveryPk); no vault continuation exists. */
    const payoutAddress = spkToAddress(config, request.build.frozen.outputs[0].scriptPublicKey);
    const payoutValue = request.build.frozen.outputs[0].value.toString();
    let payoutProof = null;
    for (let i = 0; i < 30 && !payoutProof; i++) {
      const ref = await findOutpoint(rpc, payoutAddress, request.txId, 0);
      if (ref && ref.amount.toString() === payoutValue) payoutProof = ref;
      if (!payoutProof) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!payoutProof) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveOrgRootRequest(config, request);
      throw fail(`${request.txId} submitted but the terminal recovery payout was not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
  }

  /* PROVEN on chain: complete EVERY durable record through the ONE replayable completion the deferred
   * reconciliation path (sdk/src/reconcile-v7.js) uses as well — Codex checkpoint 11 (R7-02, durable completion). */
  try {
    await completeProvenRootAction(config, request, { rootOutIndex, rootAddress, rootExpectedValue, rootBlockDaaScore: proof.blockDaaScore ? proof.blockDaaScore.toString() : null, vaultOutIndex, rpc, via: "submit" });
  } catch (e) {
    /* truthful incomplete status: the chain effect is proven, one or more durable records are not — replay by reconciliation or a retried submit */
    throw await recordCompletionFailure(config, request, e);
  }
  return request;
}

/*
 * Codex checkpoint 12 (R7-02): RECOVER a root action that was already broadcast (BROADCAST / CHAIN_SEEN /
 * RECONCILIATION_REQUIRED, or CHAIN_VERIFIED with incomplete local records) through the SAME public submit entry point.
 * Chain evidence first: observe the exact successor or a current root linked to it by completed transitions;
 * only then is the shared completion replayed. Missing evidence yields a truthful unresolved state — nothing is guessed and nothing is rebroadcast.
 */
async function recoverRootActionRequest({ config, rpc, request }) {
  const target = rootSuccessorTarget(config, request);
  const ref = await findOutpoint(rpc, target.rootAddress, request.txId, target.rootOutIndex);
  let proven = Boolean(ref) && ref.amount.toString() === target.rootExpectedValue;
  if (!proven) {
    const current = await loadOrgRoot(config, request.rootCovenantId);
    if (current && (await classifyRootRecord(config, current, request, target)).position === "BEYOND") {
      const live = await findOutpoint(rpc, current.live.address, current.live.outpoint.transactionId, current.live.outpoint.index);
      proven = Boolean(live) && live.amount.toString() === String(current.live.value);
    }
  }
  if (!proven) {
    const verified = await verifyRootActionCompletion(config, request);
    const message = `${request.txId} was already broadcast (request ${request.state}) and its exact root successor ${request.txId}:${target.rootOutIndex} is not observed unspent at ${target.rootAddress} — nothing is rebroadcast; ${verified.complete ? "the durable records are complete" : `durable records incomplete: ${verified.missing.join("; ")}`} — reconcile the root`;
    if (request.state !== RequestState.CHAIN_VERIFIED) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      request.error = message;
      await saveOrgRootRequest(config, request);
    }
    throw fail(message, "RECONCILIATION_REQUIRED");
  }
  try {
    await completeProvenRootAction(config, request, { rootOutIndex: target.rootOutIndex, rootAddress: target.rootAddress, rootExpectedValue: target.rootExpectedValue, rootBlockDaaScore: ref?.blockDaaScore ? ref.blockDaaScore.toString() : null, vaultOutIndex: null, rpc, via: "submit-recovery" });
  } catch (e) {
    throw await recordCompletionFailure(config, request, e);
  }
  return request;
}

/* The truthful durable state after a completion step failed: the request is RECONCILIATION_REQUIRED with the failing
 * step named. Only a failure clearing the final pending pointer retains CHAIN_VERIFIED; other incomplete effects remain unresolved.
 * Returns the error to throw; never swallows the failure. */
async function recordCompletionFailure(config, request, e) {
  const detail = String(e && e.message ? e.message : e).split("\n")[0];
  if (e && e.code === "PENDING_POINTER_NOT_CLEARED") {
    return fail(`${request.txId} is on chain and every durable record is complete, but the root's pending pointer could not be cleared (${detail}) — reconcile the root to clear it`, "RECONCILIATION_REQUIRED");
  }
  const fresh = (await loadOrgRootRequest(config, request.id).catch(() => null)) ?? request;
  if (fresh.state === RequestState.CHAIN_VERIFIED && !e.completionStarted) {
    return fail(`verification of completed request ${request.id} is unavailable: ${detail} — prior completion is preserved`, "RECONCILIATION_REQUIRED");
  }
  if (!e.completionStarted) {
    fresh.state = RequestState.RECONCILIATION_REQUIRED;
    fresh.error = `submission outcome cannot currently be verified (${detail}) — retain this request and reconcile`;
    try { await saveOrgRootRequest(config, fresh); } catch { /* prior durable guard remains; never report completion */ }
    return fail(fresh.error, "RECONCILIATION_REQUIRED");
  }
  {
    fresh.state = RequestState.RECONCILIATION_REQUIRED;
    fresh.error = `chain effect proven but durable completion failed (${detail}) — reconcile (or retry the submission) to complete the vault/root records`;
    try {
      await saveOrgRootRequest(config, fresh);
    } catch (persistError) {
      return fail(`${request.txId} is on chain but its durable records are incomplete: ${detail}; recording that state also failed (${String(persistError && persistError.message ? persistError.message : persistError).split("\n")[0]}) — reconcile`, "RECONCILIATION_REQUIRED");
    }
  }
  return fail(`${request.txId} is on chain but its durable records are incomplete: ${detail} — reconcile`, "RECONCILIATION_REQUIRED");
}

/*
 * ONE replayable completion of a root action whose ROOT SUCCESSOR OUTPUT has
 * been proven on chain (by the submit path's own readback, by a retried
 * submission that re-observed it, or by deferred reconciliation). Codex
 * checkpoint 11 (rc26 round-7 review R7-02) introduced the shared, ordered
 * completion; Codex checkpoint 12 (R7-02, "durable completion remains
 * defective") made it DISCOVERABLE and VALIDATED:
 *
 *   ORDER — vault record FIRST (state, outpoint, registry; terminal
 *   RECOVERED), root record next (state, outpoint, generation, slots) with
 *   the root's pendingRequestId KEPT (restored if a legacy record cleared
 *   it) as the incomplete-request guard, then the claims against the
 *   IMMUTABLE predecessor identities the request itself carries (root:
 *   manifest.root.outpoint; vault: build.predecessorOutpoint), the receipt,
 *   the audit line, the request (CHAIN_VERIFIED) — and ONLY THEN the pending
 *   pointer is cleared. A failure at any step leaves the request truthfully
 *   incomplete, the guard in place, and the work discoverable through the
 *   public entry points (submitOrgRootRequest recovers it; reconcile-v7
 *   finds it through the pointer and through every request naming the
 *   live outpoint's transaction) after a reload.
 *
 *   VALIDATED, NOT MARKED — no step is skipped on a transaction-id marker
 *   alone: the vault must be at this request's exact successor outpoint
 *   with the successor state, state id, registry, status and script hash;
 *   the root at the successor outpoint with the successor state, value,
 *   address and (after an owner-set change) the successor slots. A record
 *   at the predecessor is advanced (exactly one generation); a record at
 *   the successor with inconsistent fields is repaired in place (generation
 *   unchanged); coherent later state is preserved only through a bounded
 *   chain of completed requests, bound receipts, audits and matching
 *   predecessor/successor state. Generation alone proves nothing.
 *   Anything else FAILS CLOSED (VAULT_STATE_UNEXPECTED /
 *   ROOT_STATE_UNEXPECTED) rather than overwriting an unexplained record.
 *
 *   CLAIMS — each release reports RELEASED / ABSENT / FOREIGN:<txid>
 *   (another attempt's claim stays protected); a persistence failure
 *   propagates (never swallowed, never reported as cleanup).
 *
 *   IDEMPOTENT — repeated entry never advances a generation twice, never
 *   duplicates the receipt or the CHAIN_VERIFIED audit line, never
 *   rebroadcasts (this function only reads the node).
 */
async function completeProvenRootAction(config, request, { rootOutIndex, rootAddress, rootExpectedValue, rootBlockDaaScore = null, vaultOutIndex = null, rpc = null, via }) {
  let completionStarted = false;
  try {
  assertFrozenRequestTransaction(config, request);
  async function assertConsumedInputsAbsent(provingRequest) {
    if (!rpc) throwFail("root completion requires node verification", "RECONCILIATION_REQUIRED");
    for (const input of provingRequest.build.frozen.inputs) {
      const refs = await getAddressUtxos(rpc, spkToAddress(config, input.utxo.scriptPublicKey));
      if (refs.some((r) => sameOutpoint(r.outpoint, input.previousOutpoint))) throwFail("root successor observation contradicts an unspent consumed input — retain the original request and reconcile", "RECONCILIATION_REQUIRED");
    }
  }
  await assertConsumedInputsAbsent(request);
  const isRootOnly = request.build.kind === "orgRootTransition";
  const hasVaultOp = !isRootOnly && Array.isArray(request.vaultOperations) && request.vaultOperations.length === 1;
  const target = { rootOutIndex: Number(rootOutIndex), rootAddress, rootExpectedValue: String(rootExpectedValue) };
  if (!sameJson(target, rootSuccessorTarget(config, request))) throwFail("root completion target differs from the frozen transaction", "RECONCILIATION_REQUIRED");
  const now = new Date().toISOString();
  const completion = { via, vault: "NONE", root: null, pendingPointer: null, claims: {}, receipt: null, audit: null };

  /* 0. the IMMUTABLE predecessor identities — from the request, never from a record that may already have advanced */
  const rootPredecessorOutpoint = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  const vaultPredecessor = hasVaultOp ? vaultPredecessorOutpoint(request) : null;

  // Validate the root before any vault write. A later root needs a proven
  // lineage, never a generation guess. Restore a lost legacy guard first.
  const root = await loadOrgRoot(config, request.rootCovenantId);
  if (!root) throwFail(`no organizational root ${request.rootCovenantId}`, "ROOT_NOT_FOUND");
  const rc = await classifyRootRecord(config, root, request, target);
  if (!["PREDECESSOR", "SUCCESSOR", "BEYOND"].includes(rc.position)) throwFail("root record is unexplained — refusing durable completion", "ROOT_STATE_UNEXPECTED");
  for (const id of rc.history ?? []) {
    const step = await loadOrgRootRequest(config, id);
    if (!step) throwFail("root completion history became unavailable", "RECONCILIATION_REQUIRED");
    await assertConsumedInputsAbsent(step);
  }
  // A historical request's successor may already be spent. Its validated
  // lineage must end at an exactly observed current root, not an amount-only
  // row carrying the requested transaction ID.
  const observedRequest = rc.position === "BEYOND" ? await completedRequestAt(config, root.live.outpoint.transactionId) : request;
  const observedIndex = rc.position === "BEYOND" ? root.live.outpoint.index : target.rootOutIndex;
  if (!observedRequest || !await frozenOutputObserved(config, rpc, observedRequest, observedIndex)) throwFail("root continuation metadata is absent, contradictory or ambiguous — retain the request and reconcile", "RECONCILIATION_REQUIRED");

  let vaultManifest = null, c = null;
  const vaultId = hasVaultOp ? request.vaultOperations[0].vaultId : null;
  const idx = hasVaultOp ? (vaultOutIndex ?? vaultSuccessorIndex(request)) : null;
  if (hasVaultOp) {
    vaultManifest = await loadManifestV7(config, vaultId);
    if (!vaultManifest) throwFail(`no rooted vault ${vaultId} for a proven root action — refusing to record an unrecoverable completion`, "RECONCILIATION_REQUIRED");
    c = await classifyVaultRecord(config, vaultManifest, request, idx);
    if (!["PREDECESSOR", "SUCCESSOR", "BEYOND"].includes(c.position)) throwFail(`rooted vault ${vaultId} has no proven dependency history for this request`, "VAULT_STATE_UNEXPECTED");
    if (rc.position === "BEYOND" && (c.position === "PREDECESSOR" || c.position === "SUCCESSOR" && !c.consistent) && request.build.successorState !== null) {
      if (!await frozenOutputObserved(config, rpc, request, idx)) throwFail("historical root effect is proven but the vault continuation is not observed — refusing to overwrite potentially newer vault state", "RECONCILIATION_REQUIRED");
    }
  }
  const existingReceipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (hasReceiptPointer(existingReceipt) && (existingReceipt.proof.requestId !== request.id || existingReceipt.proof.requestKind !== "rootAction")) throwFail("completion receipt names another request", "REQUEST_ID_MISMATCH");
  const auditPresent = await auditLinePresent(config, request);
  await loadTransitionClaim(config, rootPredecessorOutpoint);
  if (vaultPredecessor) await loadTransitionClaim(config, vaultPredecessor);
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  if (submission && (submission.txId !== request.txId || submission.vaultId !== request.rootCovenantId || submission.action !== request.action)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");

  // All inspection prerequisites succeeded. From here, failures represent
  // actual incomplete writes and retain a replayable guard.
  completionStarted = true;
  if (root.pendingRequestId == null) {
    root.pendingRequestId = request.id;
    await saveOrgRoot(config, root);
  }
  /* 1. the vault side first (if any) — validated, replayable */
  if (hasVaultOp) {
    if (c.position === "SUCCESSOR" && c.consistent) {
      completion.vault = "ALREADY_COMPLETE";
    } else if (c.position === "PREDECESSOR") {
      await persistManifestV7(config, expectedVaultSuccessorDoc(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0) + 1));
      completion.vault = "ADVANCED";
    } else if (c.position === "SUCCESSOR") {
      await persistManifestV7(config, expectedVaultSuccessorDoc(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0)));
      completion.vault = "REPAIRED";
      completion.vaultDifferences = c.differences;
    } else if (c.position === "BEYOND") {
      completion.vault = "BEYOND";
    } else {
      throwFail(`rooted vault ${vaultId} is at ${describeOutpoint(vaultManifest.live ? vaultManifest.live.outpoint : null)} (generation ${vaultManifest.generation ?? 0}, last transition ${vaultManifest.latestTransitionTxId ?? "none"}) — neither this request's predecessor ${describeOutpoint(vaultPredecessor)} nor its successor ${request.txId}:${idx}${c.differences.length ? ` (${c.differences.join("; ")})` : ""}; refusing to overwrite an unexplained vault record`, "VAULT_STATE_UNEXPECTED");
    }
  }

  /* 2. the root record — validated, replayable; the incomplete-request guard stays until the request is complete */
  let rootChanged = false;
  if (rc.position === "PREDECESSOR") {
    applyRootSuccessor(config, root, request, target, rootBlockDaaScore, { advance: true });
    completion.root = "ADVANCED";
    rootChanged = true;
  } else if (rc.position === "SUCCESSOR" && !rc.consistent) {
    applyRootSuccessor(config, root, request, target, rootBlockDaaScore, { advance: false });
    completion.root = "REPAIRED";
    completion.rootDifferences = rc.differences;
    rootChanged = true;
  } else if (rc.position === "BEYOND") {
    completion.root = "BEYOND";
  } else if (rc.position === "SUCCESSOR") {
    completion.root = "ALREADY_COMPLETE";
  } else {
    throwFail(`organizational root ${request.rootCovenantId} is at ${describeOutpoint(root.live ? root.live.outpoint : null)} — neither this request's predecessor ${describeOutpoint(rootPredecessorOutpoint)} nor its successor ${request.txId}:${target.rootOutIndex}; refusing to overwrite an unexplained root record`, "ROOT_STATE_UNEXPECTED");
  }
  if (root.pendingRequestId === null || root.pendingRequestId === undefined) {
    root.pendingRequestId = request.id; // a legacy record cleared the guard before its records were complete: restore it until they are
    completion.pendingPointer = "RESTORED";
    rootChanged = true;
  } else if (root.pendingRequestId === request.id) {
    completion.pendingPointer = "HELD";
  } else {
    completion.pendingPointer = `FOREIGN:${root.pendingRequestId}`; // another request already owns the guard: never clobbered
  }
  if (rootChanged) {
    root.updatedAt = now;
    await saveOrgRoot(config, root);
  }

  /* 3. claims against the IMMUTABLE predecessor identities — truthful, retryable; a persistence failure propagates */
  completion.claims.rootPredecessor = await releaseOwnClaim(config, rootPredecessorOutpoint, request.txId);
  if (vaultPredecessor) completion.claims.vaultPredecessor = await releaseOwnClaim(config, vaultPredecessor, request.txId);
  completion.claims.submission = (await releaseSubmissionClaim(config, request.txId)) ? "RELEASED" : "ABSENT";

  /* 4. receipt + audit — idempotent (a replay never duplicates them) */
  if (receiptMatches(existingReceipt, request, target) && receiptPointerMatches(existingReceipt, request)) {
    completion.receipt = "ALREADY_PRESENT";
  } else {
    await persistReceipt(config, { txId: request.txId, vaultId: request.rootCovenantId, action: request.action, proof: { ...completionReceiptPointer(request), rootOutpoint: `${request.txId}:${target.rootOutIndex}`, reconciled: via !== "submit" } });
    completion.receipt = existingReceipt ? "REPAIRED" : "WRITTEN";
  }
  if (auditPresent) {
    completion.audit = "ALREADY_PRESENT";
  } else {
    await appendAudit(config, { vaultId: request.rootCovenantId, action: request.action, actor: via === "submit" ? "owners" : "system", contractVersion: CONTRACT_VERSION_V7_ROOT, txId: request.txId, result: "CHAIN_VERIFIED", via });
    completion.audit = "WRITTEN";
  }

  /* 5. the request — CHAIN_VERIFIED only now that every record above is done */
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = {
    ...(request.chain && typeof request.chain === "object" ? request.chain : {}),
    predecessorOutpoint: `${rootPredecessorOutpoint.transactionId}:${rootPredecessorOutpoint.index}`,
    successorOutpoint: `${request.txId}:${target.rootOutIndex}`,
    observedAt: request.chain && typeof request.chain.observedAt === "string" ? request.chain.observedAt : now,
    completion: { ...completion, completedAt: now }
  };
  await saveOrgRootRequest(config, request);

  /* 6. LAST: release the incomplete-request guard (the pointer) — only this request's own pointer, never another's */
  const fresh = await loadOrgRoot(config, request.rootCovenantId);
  if (fresh && fresh.pendingRequestId === request.id) {
    fresh.pendingRequestId = null;
    fresh.updatedAt = new Date().toISOString();
    try {
      await saveOrgRoot(config, fresh);
    } catch (e) {
      throw fail(`the root's pending pointer could not be cleared after request ${request.id} completed: ${String(e && e.message ? e.message : e).split("\n")[0]}`, "PENDING_POINTER_NOT_CLEARED");
    }
  }
  return request;
  } catch (e) { e.completionStarted = completionStarted; throw e; }
}

/* ---- completion helpers (Codex checkpoint 12, R7-02) ---- */

function sameOutpoint(a, b) {
  return Boolean(a && b) && String(a.transactionId).toLowerCase() === String(b.transactionId).toLowerCase() && Number(a.index) === Number(b.index);
}
function describeOutpoint(op) {
  return op ? `${op.transactionId}:${op.index}` : "(no live outpoint)";
}
async function frozenOutputObserved(config, rpc, request, index) {
  const out = request.build.frozen.outputs[index];
  if (!rpc || !out) return false;
  const refs = await getAddressUtxos(rpc, spkToAddress(config, out.scriptPublicKey));
  const matches = refs.filter((r) => sameOutpoint(r.outpoint, { transactionId: request.txId, index }));
  if (matches.length !== 1) return false;
  const ref = matches[0];
  return String(ref.amount) === String(out.value) && ref.covenantId === (out.covenant?.covenantId ?? null)
    && (ref.scriptPublicKeyHex == null || ref.scriptPublicKeyHex === out.scriptPublicKey.scriptHex);
}

/* The exact root successor output this request's FROZEN transaction declares (index, address, value). */
function rootSuccessorTarget(config, request) {
  if (!request || !request.build || !request.build.frozen || !Array.isArray(request.build.frozen.outputs)) throwFail("the request carries no frozen transaction to derive its root successor from", "RECONCILIATION_REQUIRED");
  const outputs = request.build.frozen.outputs;
  const rootOutIndex = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.rootCovenantId);
  if (rootOutIndex < 0) throwFail("the request's frozen transaction carries no root successor output", "RECONCILIATION_REQUIRED");
  return { rootOutIndex, rootAddress: spkToAddress(config, outputs[rootOutIndex].scriptPublicKey), rootExpectedValue: outputs[rootOutIndex].value.toString() };
}
function vaultSuccessorIndex(request) {
  return request.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.build.covenantId);
}
/* The vault's predecessor outpoint as the request carries it (build.predecessorOutpoint is the vault input the frozen
 * transaction spends; the checkpoint-12 request record also carries it under vaultOperations[0].predecessor). */
function vaultPredecessorOutpoint(request) {
  const carried = request.vaultOperations && request.vaultOperations[0] && request.vaultOperations[0].predecessor ? request.vaultOperations[0].predecessor.outpoint : null;
  const fromBuild = request.build && request.build.predecessorOutpoint ? request.build.predecessorOutpoint : null;
  const op = fromBuild ?? carried;
  if (!op) throwFail("the request carries no vault predecessor outpoint", "RECONCILIATION_REQUIRED");
  const normalized = normalizeOutpoint(op, "build.predecessorOutpoint");
  if (carried && !sameOutpoint(carried, normalized)) throwFail(`the request's recorded vault predecessor ${describeOutpoint(carried)} disagrees with its build's ${describeOutpoint(normalized)}`, "RECONCILIATION_REQUIRED");
  return normalized;
}
function recordedVaultPredecessorGeneration(request) {
  const p = request.vaultOperations && request.vaultOperations[0] ? request.vaultOperations[0].predecessor : null;
  return p && Number.isInteger(p.generation) && p.generation >= 0 ? p.generation : null;
}

// Receipts already witness completed effects. Add an immutable request pointer
// so later-state verification can follow exact predecessors by keyed reads,
// instead of guessing from counters or scanning an unbounded request history.
const COMPLETION_HISTORY_LIMIT = 128;
function completionReceiptPointer(request) {
  const kind = request.kind === "rootAction" ? "rootAction" : "vaultAction";
  const binding = {
    requestId: request.id ?? request.requestId, kind, txId: request.txId,
    rootCovenantId: request.rootCovenantId ?? null, vaultId: request.vaultId ?? null,
    action: request.action, networkId: request.networkId ?? request.build.networkId ?? null,
    build: request.build, manifest: request.manifest ?? null,
    vaultOperations: request.vaultOperations ?? [], newRegistry: request.newRegistry ?? null
  };
  // Conditional for compatibility with receipts made before delegate snapshots existed.
  if (request.predecessorVault) binding.predecessorVault = request.predecessorVault;
  const json = JSON.parse(JSON.stringify(binding, (_key, value) => typeof value === "bigint" ? value.toString() : value));
  return { requestId: binding.requestId, requestKind: kind,
    requestFingerprint: crypto.createHash("sha256").update(canonicalJsonStringify(json)).digest("hex") };
}
function receiptPointerMatches(receipt, request) {
  const pointer = completionReceiptPointer(request);
  return Object.entries(pointer).every(([key, value]) => receipt?.proof?.[key] === value);
}
function hasReceiptPointer(receipt) {
  return ["requestId", "requestKind", "requestFingerprint"].some((key) => Object.hasOwn(receipt?.proof ?? {}, key));
}
function assertFrozenRequestTransaction(config, request) {
  const frozen = canonicalFrozenTxJson(normalizeFrozenTxV3(request.build.frozen));
  const unsigned = { ...request.finalTransaction, inputs: request.finalTransaction?.inputs?.map(({ signatureScript, ...i }) => i) };
  delegateRequire(canonicalFrozenTxJson(normalizeFrozenTxV3(unsigned)) === frozen && finalTxToWasm(config, request.finalTransaction).finalize().toString().toLowerCase() === request.txId, "request's final transaction does not bind its frozen bytes and txid");
}
/* A request that was never finalized, or that ended in a terminal refusal before any submission, cannot have produced
 * the chain effect: builders never broadcast, finalization is what produces the final transaction, and a withdrawal is
 * only granted to an unsigned/unattempted request. Such a record is never associated as the completed request of a
 * receipt or claim, is never a completion candidate, and a failed inspection never writes onto it — otherwise a LEGACY
 * pair of requests sharing one txid (an owner operation withdrawn and rebuilt with the same fuel; a delegate spend built
 * twice) would make the completed request's association ambiguous and guard the vault forever (round-8 R8-01/R8-02). */
const NEVER_EFFECTIVE_STATES = new Set(["REFUSED", "WALLET_REJECTED", "BUILT", "AUTHORIZED"]);
function neverEffective(request) {
  if (!request) return true;
  if (NEVER_EFFECTIVE_STATES.has(request.state)) return true;
  // Root actions and the delegate family carry the final transaction from finalization on; such a record without one
  // and without any submission attempt/outcome is a draft an earlier runtime mislabelled (R8-02). Other kinds (genesis
  // requests) are judged by state only.
  const finalizes = request.kind === "rootAction" || request.schema === V7_WALLET_REQUEST_SCHEMA && ["tokenAgentSpend", "tokenDeposit"].includes(request.action);
  return finalizes && !request.finalTransaction && !request.submissionAttempt && !request.submissionOutcome;
}
/* Requests sharing one transaction id carry identical frozen bytes — ONE chain effect — and the request this system
 * completed or attempted owns it. A SIGNED record with the same txid but no submission evidence (a legacy finalize-twice
 * duplicate, round-8 R8-09; or this runtime's own second finalization) is a SAME-EFFECT DUPLICATE: never the completed
 * request, never a completion candidate, never an admission guard, never relabelled CHAIN_VERIFIED; it may be withdrawn. */
const SUBMISSION_EVIDENCE_STATES = new Set(["CHAIN_VERIFIED", "BROADCAST", "CHAIN_SEEN", "SUBMITTING", "SUBMITTED", "SUBMISSION_REJECTED", "NOT_BROADCAST", "SUPERSEDED"]);
function hasSubmissionEvidence(request) {
  return SUBMISSION_EVIDENCE_STATES.has(request.state) || !!request.submissionAttempt || !!request.submissionOutcome || !!request.chain;
}
function sameEffectDuplicate(request, group) {
  if (neverEffective(request) || hasSubmissionEvidence(request)) return false;
  const tx = String(request.txId).toLowerCase();
  return group.some((other) => other !== request && (other.id ?? other.requestId) !== (request.id ?? request.requestId) && String(other.txId).toLowerCase() === tx && !neverEffective(other) && hasSubmissionEvidence(other));
}
async function completedRequestAt(config, txId) {
  const receipt = await getStore(config).read(Categories.RECEIPT, txId);
  if (!receipt || receipt.txId !== txId) return null;
  let q;
  if (hasReceiptPointer(receipt)) {
    const kind = receipt.proof.requestKind;
    if (kind !== "rootAction" && kind !== "vaultAction" || !receipt.proof.requestId) return null;
    q = kind === "rootAction" ? await loadOrgRootRequest(config, receipt.proof.requestId) : await loadV7WalletRequest(config, receipt.proof.requestId);
    if (!q || !receiptPointerMatches(receipt, q)) return null;
  } else {
    // Earlier public APIs wrote receipts without pointers. Associate only a
    // unique canonical record with the exact transaction, entity and action.
    // A partial/wrong modern pointer never falls back to this legacy rule.
    const sharing = [...await listOrgRootRequests(config), ...await listV7WalletRequests(config)].filter((r) => r.txId === txId);
    const candidates = sharing.filter((r) => (r.action ?? r.kind) === receipt.action && !neverEffective(r) && !sameEffectDuplicate(r, sharing) &&
      (r.kind === "rootAction" || r.kind === "rootGenesis" ? r.rootCovenantId : r.vaultId ?? r.build?.template?.vaultId) === receipt.vaultId);
    if (candidates.length !== 1) return null;
    const row = candidates[0];
    q = row.id ? await loadOrgRootRequest(config, row.id) : await loadV7WalletRequest(config, row.requestId);
    if (!q || !sameJson(q, row)) return null;
  }
  const action = q.action ?? q.kind;
  const entity = q.kind === "rootAction" || q.kind === "rootGenesis" ? q.rootCovenantId : q.vaultId ?? q.build?.template?.vaultId;
  const rewound = q.kind === "rootAction" && ["SIGNED", "SUBMISSION_REJECTED"].includes(q.state) && hasReceiptPointer(receipt) && receiptPointerMatches(receipt, q);
  if (q.state !== "CHAIN_VERIFIED" && !rewound || q.txId !== txId || receipt.action !== action || receipt.vaultId !== entity) return null;
  const audit = await readAudit(config, { vaultId: entity, txId, limit: 500 });
  if (!audit.some((e) => e.txId === txId && e.action === action && e.result === "CHAIN_VERIFIED")) return null;
  if (q.kind === "rootAction") {
    assertFrozenRequestTransaction(config, q);
    const target = rootSuccessorTarget(config, q);
    if (!receiptMatches(receipt, q, target) || !rewound && (q.chain?.successorOutpoint !== `${txId}:${target.rootOutIndex}` || q.chain?.predecessorOutpoint !== describeOutpoint(q.manifest.root.outpoint))) return null;
  } else if (q.action === "tokenAgentSpend" || q.action === "tokenDeposit") {
    assertFrozenRequestTransaction(config, q);
    const expected = q.action === "tokenDeposit" ? receipt.proof?.outpoint : receipt.proof?.successorOutpoint;
    if (expected !== `${txId}:0`) return null;
  } else if (q.kind === "rootedVaultGenesis") {
    if (q.build.txId !== txId || receipt.proof?.outpoint !== `${txId}:${q.build.vaultOutputIndex}` || receipt.proof?.covenantId !== q.build.covenantId) return null;
  } else return null;
  return q;
}
async function receiptAssociationMatches(config, receipt, request) {
  const entity = request.kind === "rootAction" || request.kind === "rootGenesis" ? request.rootCovenantId : request.vaultId ?? request.build?.template?.vaultId;
  if (!receipt || receipt.txId !== request.txId || receipt.vaultId !== entity || receipt.action !== (request.action ?? request.kind)) return false;
  if (hasReceiptPointer(receipt)) return receiptPointerMatches(receipt, request);
  const q = await completedRequestAt(config, request.txId);
  return !!q && (q.id ?? q.requestId) === (request.id ?? request.requestId);
}

// Reconstruct a historical registry from a validated full seed, then replay
// each intervening spend. Never substitute today's registry after an owner
// replacement or another agent's accounting update.
async function historicalRegistryAt(config, vault, outpoint, state, seen = new Set()) {
  const key = describeOutpoint(outpoint);
  delegateRequire(seen.size < COMPLETION_HISTORY_LIMIT && !seen.has(key), "legacy registry history is cyclic or exceeds the bound");
  seen.add(key);
  const q = await completedRequestAt(config, outpoint.transactionId);
  delegateRequire(q && q.build?.template?.vaultId === vault.vaultId, "historical registry seed/transition is missing or ambiguous");
  let registry;
  if (q.kind === "rootedVaultGenesis") {
    delegateRequire(Number(outpoint.index) === q.build.vaultOutputIndex && sameVaultState(state, q.build.initialState), "genesis registry does not describe this predecessor");
    registry = q.initialRegistry;
  } else {
    delegateRequire(Number(outpoint.index) === vaultSuccessorIndex(q) && sameVaultState(state, q.build.successorState), "registry history does not connect to the requested state");
    if (q.kind === "rootAction" && q.vaultOperations?.[0]?.action === "ownerSetAgentRoot") registry = q.newRegistry;
    else {
      const pre = q.build.predecessorOutpoint;
      const before = q.build.stateJson;
      if (q.predecessorVault) {
        delegateRequire(sameOutpoint(q.predecessorVault.live?.outpoint, pre) && sameVaultState(q.predecessorVault.live.state, before), "historical snapshot differs from the consumed state");
        registry = q.predecessorVault.agentRegistry;
      } else registry = await historicalRegistryAt(config, vault, pre, before, seen);
      delegateRequire(normalizeRegistry(registry).tree.root === before.agentRoot, "historical predecessor registry root differs");
      if (q.action === "tokenAgentSpend") {
        delegateSignedEvidence(config, q, vault);
        registry = advanceRegistryAfterSpendV7(registry, q.build);
      }
    }
  }
  const normalized = normalizeRegistry(registry);
  delegateRequire(normalized.tree.root === state.agentRoot, "historical registry does not reproduce the committed root");
  return normalized.entries.map(registryEntryToJson);
}

function sameRootState(a, b) {
  return canonicalJsonStringify(rootStateToJsonV7(normalizeRootStateV7(a))) === canonicalJsonStringify(rootStateToJsonV7(normalizeRootStateV7(b)));
}
function sameVaultState(a, b) {
  return a === null || b === null ? a === b : canonicalJsonStringify(stateToJsonV7(normalizeStateV7(a))) === canonicalJsonStringify(stateToJsonV7(normalizeStateV7(b)));
}
async function traceRootCompletion(config, root, request, target) {
  if (!root.live) return null;
  const wanted = { transactionId: request.txId, index: target.rootOutIndex };
  let cursor = root.live.outpoint, expected = root.state;
  const seen = new Set(), links = [];
  for (let i = 0; i < COMPLETION_HISTORY_LIMIT && !sameOutpoint(cursor, wanted); i++) {
    if (seen.has(describeOutpoint(cursor))) return null;
    seen.add(describeOutpoint(cursor));
    const q = await completedRequestAt(config, cursor.transactionId);
    if (!q || q.kind !== "rootAction" || q.rootCovenantId !== request.rootCovenantId) return null;
    const next = rootSuccessorTarget(config, q);
    if (Number(cursor.index) !== next.rootOutIndex || !sameRootState(rootSuccessorState(q), expected)) return null;
    if (i === 0 && rootSuccessorDifferences(config, root, q, next).length) return null;
    links.push(q.id);
    cursor = normalizeOutpoint(q.manifest.root.outpoint, "history.root.predecessor");
    expected = q.manifest.rootState.before.state;
  }
  return links.length && sameOutpoint(cursor, wanted) && sameRootState(expected, rootSuccessorState(request)) ? links : null;
}
async function traceVaultCompletion(config, vault, request, idx) {
  // Terminal recovery cannot have a later covenant continuation.
  if (request.build.successorState === null) return null;
  const wanted = { transactionId: request.txId, index: idx };
  let cursor = vault.live?.outpoint ?? null, expected = vault.live?.state ?? null;
  let txId = vault.latestTransitionTxId;
  let firstVaultStep = true, tokenPositionChecked = false;
  let expectedTokenPosition = vault.live?.tokenPosition ? vaultManifestTokenPositionJson(vault.live.tokenPosition) : null;
  const seen = new Set(), links = [];
  for (let i = 0; i < COMPLETION_HISTORY_LIMIT; i++) {
    if (!txId || seen.has(txId)) return null;
    seen.add(txId);
    const q = await completedRequestAt(config, txId);
    if (!q) return null;
    if (q.kind !== "rootAction" && q.action === "tokenDeposit") {
      // A deposit changes token metadata, not the vault covenant outpoint.
      const out = q.build.frozen.outputs[0];
      const position = vault.live?.tokenPosition;
      if (i !== 0 || q.vaultId !== vault.vaultId || !cursor || !position || !sameOutpoint(position.outpoint, { transactionId: txId, index: 0 }) || String(position.value) !== String(out.value) || position.scriptPublicKeyHex !== out.scriptPublicKey.scriptHex || position.covenantId !== out.covenant.covenantId || canonicalJsonStringify(vaultManifestTokenPositionJson(position).state) !== canonicalJsonStringify(q.build.tokenNewStates[0])) return null;
      tokenPositionChecked = true;
      links.push(q.requestId);
      if (sameOutpoint(cursor, wanted)) {
        const doc = manifestDoc(vault);
        doc.latestTransitionTxId = request.txId;
        return vaultSuccessorDifferences(config, normalizeHistoryVault(doc), request, idx).length === 0 ? links : null;
      }
      txId = cursor.transactionId;
      continue;
    }
    const isRoot = q.kind === "rootAction";
    if (isRoot ? q.rootCovenantId !== request.rootCovenantId || q.vaultOperations?.length !== 1 || q.vaultOperations[0].vaultId !== vault.vaultId : q.vaultId !== vault.vaultId || q.action !== "tokenAgentSpend") return null;
    if (isRoot && q.build.successorState === null && request.action === "tokenAgentSpend") {
      expectedTokenPosition = q.build.hasTokenInput ? terminalTokenPredecessor(config, q, vault) : await legacyTerminalRetainedToken(config, q, vault);
      if (!expectedTokenPosition) return null;
      tokenPositionChecked = true;
    }
    if (!isRoot && request.action === "tokenAgentSpend") {
      // Token lineage must connect too: a later vault state alone cannot
      // justify an unrelated tracked token position or substituted input.
      if (!sameJson(expectedTokenPosition, delegateTokenPosition(q.build))) return null;
      if (q.predecessorVault) delegateEvidence(config, q, vault);
      expectedTokenPosition = delegateTokenPosition(q.build, true);
    }
    if (!isRoot && vault.live && !tokenPositionChecked) {
      const position = vault.live.tokenPosition, out = q.build.frozen.outputs[1];
      const state = { ownerIdentifier: q.build.covenantId, identifierType: 2, amount: String(q.build.accounting.token.positionAfter), isMinter: false };
      if (!position || !sameOutpoint(position.outpoint, { transactionId: txId, index: 1 }) || String(position.value) !== String(out.value) || position.scriptPublicKeyHex !== out.scriptPublicKey.scriptHex || position.covenantId !== out.covenant.covenantId || canonicalJsonStringify(vaultManifestTokenPositionJson(position).state) !== canonicalJsonStringify(state)) return null;
      tokenPositionChecked = true;
    }
    const successor = q.build.successorState;
    const outIndex = successor === null ? -1 : vaultSuccessorIndex(q);
    if (successor === null ? cursor !== null : !sameOutpoint(cursor, { transactionId: txId, index: outIndex })) return null;
    if (!sameVaultState(successor, expected)) return null;
    const view = isRoot ? q : { ...q, vaultOperations: [{ vaultId: vault.vaultId, action: q.action }] };
    if (firstVaultStep) {
      const doc = manifestDoc(vault);
      doc.latestTransitionTxId = txId; // a validated deposit may be the metadata's latest transaction
      if (vaultSuccessorDifferences(config, normalizeHistoryVault(doc), view, outIndex).length) return null;
      firstVaultStep = false;
    }
    links.push(q.id ?? q.requestId);
    cursor = isRoot ? vaultPredecessorOutpoint(q) : normalizeOutpoint(q.predecessorOutpoint ?? q.build.predecessorOutpoint, "history.vault.predecessor");
    expected = q.build.stateJson ?? q.manifest?.vaultOperations?.[0]?.manifest?.stateBefore?.state;
    if (sameOutpoint(cursor, wanted)) {
      if (request.action === "tokenAgentSpend" && !sameJson(expectedTokenPosition, delegateTokenPosition(request.build))) return null;
      return sameVaultState(expected, request.build.successorState) ? links : null;
    }
    txId = cursor.transactionId;
  }
  return null;
}
function normalizeHistoryVault(doc) {
  return require("./manifest-v7").normalizeManifestV7(doc);
}
function rootSuccessorState(request) {
  return request.build.kind === "orgRootTransition" ? request.build.successorState : request.manifest.rootState.after.state;
}

/* The successor registry (JSON entries) a chain-verified vault operation installs: ownerSetAgentRoot replaces the
 * registry with the request's validated entries (re-derived and matched to the successor agentRoot — a record that
 * could not reproduce the on-chain tree is never written); every other operation keeps the current registry. */
function successorRegistryJson(vaultManifest, request) {
  const successorVaultState = request.build.successorState;
  if (request.vaultOperations[0].action === "ownerSetAgentRoot") {
    if (!Array.isArray(request.newRegistry)) throwFail("a chain-verified ownerSetAgentRoot request carries no newRegistry — the durable registry cannot be advanced; refusing to record a manifest that could not reproduce the on-chain agentRoot", "RECONCILIATION_REQUIRED");
    const { entries, tree } = normalizeRegistry(request.newRegistry);
    if (tree.root !== String(successorVaultState.agentRoot).toLowerCase()) throwFail(`the request's newRegistry folds to ${tree.root}, not the chain-verified successor agentRoot ${successorVaultState.agentRoot}`, "REGISTRY_ROOT_MISMATCH");
    return entries.map((e) => registryEntryToJson(e));
  }
  return manifestDoc(vaultManifest).agentRegistry;
}
/* The complete vault record this request's proven transition produces (what is written, and what a record is compared against). */
function expectedVaultSuccessorDoc(config, vaultManifest, request, idx, generation) {
  const base = manifestDoc(vaultManifest);
  if (request.build.successorState === null) {
    /* TERMINAL ownerRecover: the reserve was paid out to the pinned recovery key; no vault continuation exists */
    return { ...base, status: VaultStatus.RECOVERED, live: null, latestTransitionTxId: request.txId, generation };
  }
  if (!(idx >= 0)) throwFail("the proven root action carries no vault continuation output — refusing", "RECONCILIATION_REQUIRED");
  const successorVaultState = request.build.successorState;
  const vaultStateId = computeStateIdV7({ networkId: config.networkId, template: vaultManifest.template, state: normalizeStateV7(successorVaultState), contractVersion: vaultManifest.contractVersion });
  return {
    ...base,
    agentRegistry: successorRegistryJson(vaultManifest, request),
    status: Number(successorVaultState.paused) === 1 ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
    live: { state: successorVaultState, stateId: vaultStateId, outpoint: { transactionId: request.txId, index: idx }, outpointValue: successorVaultState.feeReserve, scriptSha256: request.build.successorScriptSha256, covenantId: request.build.covenantId, tokenPosition: vaultManifest.live && vaultManifest.live.tokenPosition ? vaultManifestTokenPositionJson(vaultManifest.live.tokenPosition) : null },
    latestTransitionTxId: request.txId,
    generation
  };
}
/* Field-by-field differences between a vault record already AT the successor outpoint and the expected successor record. */
function vaultSuccessorDifferences(config, vaultManifest, request, idx) {
  const doc = manifestDoc(vaultManifest);
  const diffs = [];
  if (request.build.successorState === null) {
    if (doc.status !== VaultStatus.RECOVERED) diffs.push(`status ${doc.status} != ${VaultStatus.RECOVERED}`);
    if (doc.live !== null) diffs.push("a live outpoint remains after a terminal recovery");
    if (doc.latestTransitionTxId !== request.txId) diffs.push(`latestTransitionTxId ${doc.latestTransitionTxId ?? "none"} != ${request.txId}`);
    return diffs;
  }
  const expected = expectedVaultSuccessorDoc(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0));
  if (doc.latestTransitionTxId !== request.txId) diffs.push(`latestTransitionTxId ${doc.latestTransitionTxId ?? "none"} != ${request.txId}`);
  if (canonicalJsonStringify(stateToJsonV7(normalizeStateV7(doc.live.state))) !== canonicalJsonStringify(stateToJsonV7(normalizeStateV7(expected.live.state)))) diffs.push("live.state != successor state");
  if (String(doc.live.stateId) !== String(expected.live.stateId)) diffs.push("live.stateId != successor state id");
  if (canonicalJsonStringify(doc.agentRegistry) !== canonicalJsonStringify(expected.agentRegistry)) diffs.push("agentRegistry != the registry this transition installs");
  if (doc.status !== expected.status) diffs.push(`status ${doc.status} != ${expected.status}`);
  if (String(doc.live.covenantId).toLowerCase() !== String(expected.live.covenantId).toLowerCase()) diffs.push("live.covenantId differs");
  if (String(doc.live.scriptSha256).toLowerCase() !== String(expected.live.scriptSha256).toLowerCase()) diffs.push("live.scriptSha256 != successor script");
  if (String(doc.live.outpointValue) !== String(expected.live.outpointValue)) diffs.push("live.outpointValue != successor feeReserve");
  return diffs;
}
/* Where a vault record stands relative to THIS request's transition: SUCCESSOR (consistent or not), PREDECESSOR,
 * BEYOND (provably advanced past it by later transitions), or OTHER (unexplained — fail closed). */
async function classifyVaultRecord(config, vaultManifest, request, idx) {
  const predecessor = vaultPredecessorOutpoint(request);
  const live = vaultManifest.live ? vaultManifest.live.outpoint : null;
  const generation = Number(vaultManifest.generation ?? 0);
  const predecessorGeneration = recordedVaultPredecessorGeneration(request);
  const atPredecessor = Boolean(live) && sameOutpoint(live, predecessor);
  if (request.build.successorState === null) {
    if (!vaultManifest.live && vaultManifest.latestTransitionTxId === request.txId) {
      const diffs = vaultSuccessorDifferences(config, vaultManifest, request, idx);
      return { position: "SUCCESSOR", consistent: diffs.length === 0, differences: diffs };
    }
    if (atPredecessor) return { position: "PREDECESSOR", consistent: false, differences: vaultManifest.latestTransitionTxId === request.txId ? ["latestTransitionTxId names this transaction while the live outpoint is still the predecessor (marker without state)"] : [] };
    return { position: "OTHER", consistent: false, differences: [`live ${describeOutpoint(live)}, status ${vaultManifest.status}, last transition ${vaultManifest.latestTransitionTxId ?? "none"}`] };
  }
  const successor = { transactionId: request.txId, index: idx };
  if (live && sameOutpoint(live, successor)) {
    const diffs = vaultSuccessorDifferences(config, vaultManifest, request, idx);
    if (diffs.length) {
      const history = await traceVaultCompletion(config, vaultManifest, request, idx);
      if (history) return { position: "BEYOND", consistent: true, differences: [], history };
    }
    return { position: "SUCCESSOR", consistent: diffs.length === 0, differences: diffs };
  }
  if (atPredecessor) return { position: "PREDECESSOR", consistent: false, differences: vaultManifest.latestTransitionTxId === request.txId ? ["latestTransitionTxId names this transaction while the live outpoint is still the predecessor (marker without state)"] : [] };
  const history = await traceVaultCompletion(config, vaultManifest, request, idx);
  if (history) return { position: "BEYOND", consistent: true, differences: [], history };
  return { position: "OTHER", consistent: false, differences: [`no coherent completed transition history connects this record (generation ${generation}) to the request successor; predecessor generation ${predecessorGeneration ?? "unrecorded"} is not proof`] };
}
function rootSuccessorDifferences(config, root, request, target) {
  const successorState = rootSuccessorState(request);
  const diffs = [];
  if (canonicalJsonStringify(rootStateToJsonV7(normalizeRootStateV7(root.state))) !== canonicalJsonStringify(rootStateToJsonV7(normalizeRootStateV7(successorState)))) diffs.push("root.state != successor state");
  if (String(root.live.value) !== target.rootExpectedValue) diffs.push(`live.value ${root.live.value} != ${target.rootExpectedValue}`);
  if (root.live.address !== target.rootAddress) diffs.push("live.address != successor address");
  if (request.action === "rotate" || request.action === "ownerRecover" || request.action === "succession") {
    const expectedSlots = activeOwnerSlotsV7(normalizeRootStateV7(successorState)).map((s) => `${s.slot}:${s.publicKey}`).join(",");
    const actualSlots = (root.slots ?? []).map((s) => `${s.slot}:${s.publicKey}`).join(",");
    if (expectedSlots !== actualSlots) diffs.push("slots != the successor owner set");
  }
  return diffs;
}
async function classifyRootRecord(config, root, request, target) {
  const predecessor = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  const successor = { transactionId: request.txId, index: target.rootOutIndex };
  const live = root.live ? root.live.outpoint : null;
  if (live && sameOutpoint(live, successor)) {
    const diffs = rootSuccessorDifferences(config, root, request, target);
    return { position: "SUCCESSOR", consistent: diffs.length === 0, differences: diffs };
  }
  if (live && sameOutpoint(live, predecessor)) return { position: "PREDECESSOR", consistent: false, differences: [] };
  const history = await traceRootCompletion(config, root, request, target);
  if (history) return { position: "BEYOND", consistent: true, differences: [], history };
  return { position: "OTHER", consistent: false, differences: [`live ${describeOutpoint(live)} is neither the predecessor ${describeOutpoint(predecessor)} nor the successor ${describeOutpoint(successor)}`] };
}
function applyRootSuccessor(config, root, request, target, rootBlockDaaScore, { advance }) {
  const successorState = rootSuccessorState(request);
  const keepDaa = root.live && sameOutpoint(root.live.outpoint, { transactionId: request.txId, index: target.rootOutIndex }) ? root.live.blockDaaScore ?? null : null;
  root.state = successorState;
  root.live = { outpoint: { transactionId: request.txId, index: target.rootOutIndex }, value: target.rootExpectedValue, address: target.rootAddress, blockDaaScore: rootBlockDaaScore ?? keepDaa };
  if (advance) root.generation = (root.generation ?? 0) + 1;
  if (request.action === "rotate" || request.action === "ownerRecover" || request.action === "succession") {
    root.slots = activeOwnerSlotsV7(normalizeRootStateV7(successorState)).map((s) => ({ slot: s.slot, publicKey: s.publicKey, address: addressForXOnlyPubkey(config, s.publicKey), label: "" }));
  }
}
/* RELEASED (ours, removed) / ABSENT (nothing held) / FOREIGN:<txid> (another attempt's claim — protected, left in place);
 * a persistence failure propagates. */
async function releaseOwnClaim(config, outpoint, txId) {
  try {
    return (await releaseTransitionClaim(config, { outpoint, txId })) ? "RELEASED" : "ABSENT";
  } catch (e) {
    if (e && e.code === "CLAIM_CONFLICT" && /refusing to release claim/.test(String(e.message))) {
      const held = await loadTransitionClaim(config, outpoint);
      return `FOREIGN:${held && held.txId ? held.txId : "unknown"}`;
    }
    throw e;
  }
}
function receiptMatches(receipt, request, target) {
  return Boolean(receipt) && receipt.txId === request.txId && receipt.vaultId === request.rootCovenantId && receipt.action === request.action && Boolean(receipt.proof) && receipt.proof.rootOutpoint === `${request.txId}:${target.rootOutIndex}`;
}
async function auditLinePresent(config, request) {
  const events = await readAudit(config, { vaultId: request.rootCovenantId, txId: request.txId, limit: 500 });
  return events.some((e) => e && e.txId === request.txId && e.result === "CHAIN_VERIFIED" && e.action === request.action);
}

/*
 * Codex checkpoint 12 (R7-02): LOCAL verification that a root action's every durable record is complete — a terminal
 * label is not evidence. Reads only (no node access). Returns { complete, missing: [...], root, vault, claims, receipt,
 * audit }; used by the public entry points before an idempotent return and by reconciliation's discovery.
 */
async function verifyRootActionCompletion(config, request, { root: providedRoot = null } = {}) {
  if (!request || request.kind !== "rootAction" || !request.build || !request.manifest) throwFail("only a rootAction request with a reviewable build/manifest can be verified for completion", "NOT_A_ROOT_ACTION");
  const missing = [];
  const target = rootSuccessorTarget(config, request);
  const rootPredecessorOutpoint = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  const root = providedRoot ?? (await loadOrgRoot(config, request.rootCovenantId));
  let rootPosition = null;
  if (!root) {
    missing.push("root record missing");
  } else {
    rootPosition = await classifyRootRecord(config, root, request, target);
    if (rootPosition.position !== "SUCCESSOR" && rootPosition.position !== "BEYOND") missing.push(`root record at ${rootPosition.position}${rootPosition.differences.length ? ` (${rootPosition.differences.join("; ")})` : ""}`);
    else if (!rootPosition.consistent) missing.push(`root record inconsistent with the successor (${rootPosition.differences.join("; ")})`);
    if (root.pendingRequestId === request.id) missing.push("root pending pointer still names this request");
  }
  const hasVaultOp = request.build.kind !== "orgRootTransition" && Array.isArray(request.vaultOperations) && request.vaultOperations.length === 1;
  let vaultPosition = null;
  let vaultPredecessor = null;
  if (hasVaultOp) {
    vaultPredecessor = vaultPredecessorOutpoint(request);
    const vaultId = request.vaultOperations[0].vaultId;
    const vaultManifest = await loadManifestV7(config, vaultId);
    if (!vaultManifest) {
      missing.push(`rooted vault ${vaultId} record missing`);
    } else {
      vaultPosition = await classifyVaultRecord(config, vaultManifest, request, vaultSuccessorIndex(request));
      if (vaultPosition.position === "BEYOND") {
        /* provably advanced past this transition: nothing to complete on the vault side */
      } else if (vaultPosition.position !== "SUCCESSOR") {
        missing.push(`vault record at ${vaultPosition.position}${vaultPosition.differences.length ? ` (${vaultPosition.differences.join("; ")})` : ""}`);
      } else if (!vaultPosition.consistent) {
        missing.push(`vault record inconsistent with the successor (${vaultPosition.differences.join("; ")})`);
      }
    }
  }
  const claims = {};
  const rootClaim = await loadTransitionClaim(config, rootPredecessorOutpoint);
  claims.rootPredecessor = !rootClaim ? "ABSENT" : rootClaim.txId === request.txId ? "HELD" : `FOREIGN:${rootClaim.txId}`;
  if (rootClaim && rootClaim.txId === request.txId) missing.push("root predecessor claim still held");
  if (vaultPredecessor) {
    const vaultClaim = await loadTransitionClaim(config, vaultPredecessor);
    claims.vaultPredecessor = !vaultClaim ? "ABSENT" : vaultClaim.txId === request.txId ? "HELD" : `FOREIGN:${vaultClaim.txId}`;
    if (vaultClaim && vaultClaim.txId === request.txId) missing.push("vault predecessor claim still held");
  }
  const submissionClaim = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  claims.submission = submissionClaim ? "HELD" : "ABSENT";
  if (submissionClaim) missing.push("submission claim still held");
  const storedReceipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  const receipt = receiptMatches(storedReceipt, request, target) && await receiptAssociationMatches(config, storedReceipt, request);
  if (!receipt) missing.push("receipt missing");
  const audit = await auditLinePresent(config, request);
  if (!audit) missing.push("CHAIN_VERIFIED audit line missing");
  if (request.state !== RequestState.CHAIN_VERIFIED) missing.push(`request state ${request.state}`);
  return { complete: missing.length === 0, missing, root: rootPosition, vault: vaultPosition, claims, receipt, audit };
}

function manifestDoc(normalized) {
  const { manifestToJsonV7 } = require("./manifest-v7");
  return manifestToJsonV7(normalized);
}
function vaultManifestTokenPositionJson(tp) {
  return { ...tp, value: tp.value.toString(), state: { ...tp.state, amount: tp.state.amount.toString() } };
}

/* The successor registry (JSON entries) after ONE tokenAgentSpend build:
 * advance ONLY the spending agent's leaf accounting, exactly the rule
 * org-root-manifest-v7's successorRootDerived check pins (mirrors
 * sdk/src/wallet-submit-v4.js's deriveSuccessorRegistry for the v4 family). */
function advanceRegistryAfterSpendV7(registry, build) {
  const agentPk = build.callExtra.agentPk;
  const periodsElapsed = BigInt(build.callExtra.periodsElapsed ?? "0");
  const spendAmount = BigInt(build.payment.tokenAmount);
  return registry.map((e) => {
    if (e.agentPk !== agentPk) return e;
    let newStart = BigInt(e.periodStartDaa);
    let newSpent = BigInt(e.tokenPeriodSpent) + spendAmount;
    if (periodsElapsed >= 1n) {
      newStart = BigInt(e.periodStartDaa) + periodsElapsed * BigInt(e.periodLengthDaa);
      newSpent = spendAmount;
    }
    return { ...e, periodStartDaa: newStart.toString(), tokenPeriodSpent: newSpent.toString() };
  });
}

/* R7-02/E: delegate completion has no root transition. The durable request
 * is its pending guard, and retains the predecessor needed to replay each
 * local effect after a crash. Both public submit and reconcile enter here
 * under the existing root queue; internal helpers never reacquire it. */
const DELEGATE_PENDING_STATES = new Set(["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"]);
function sameJson(a, b) {
  const json = (v) => JSON.parse(JSON.stringify(v, (_k, x) => typeof x === "bigint" ? x.toString() : x));
  return canonicalJsonStringify(json(a)) === canonicalJsonStringify(json(b));
}
function delegateRequire(ok, message) {
  if (!ok) throwFail(`delegate recovery: ${message}`, "RECONCILIATION_REQUIRED");
}
function delegateTokenPosition(build, before = false) {
  const item = before ? build.frozen.inputs[1] : build.frozen.outputs[1];
  return {
    outpoint: before ? item.previousOutpoint : { transactionId: build.txId, index: 1 },
    value: String(before ? item.utxo.amount : item.value),
    scriptPublicKeyHex: (before ? item.utxo : item).scriptPublicKey.scriptHex,
    covenantId: before ? item.utxo.covenantId : item.covenant.covenantId,
    state: { ownerIdentifier: build.covenantId, identifierType: 2, amount: String(before ? build.accounting.token.positionBefore : build.accounting.token.positionAfter), isMinter: false }
  };
}
function vaultCompletionFields(doc) {
  return { vaultId: doc.vaultId ?? doc.template.vaultId, networkId: doc.networkId, contractVersion: doc.contractVersion,
    template: doc.template, asset: doc.asset, orgRootCovenantId: doc.orgRootCovenantId,
    agentRegistry: doc.agentRegistry, status: doc.status, live: doc.live };
}
function delegateSignedEvidence(config, request, vault) {
  const b = request.build, current = manifestDoc(vault);
  delegateRequire(request.finalTransaction, `request ${request.requestId} is a ${request.state} draft that was never finalized — nothing to complete`);
  delegateRequire(request.schema === V7_WALLET_REQUEST_SCHEMA && request.action === "tokenAgentSpend" && b?.action === request.action && b.kind === "transition", "request is not a supported delegate transition");
  delegateRequire(request.contractVersion === CONTRACT_VERSION_V7 && b.contractVersion === CONTRACT_VERSION_V7 && current.contractVersion === CONTRACT_VERSION_V7 && b.networkId === config.networkId && current.networkId === config.networkId, "generation/network mismatch");
  delegateRequire(request.vaultId === current.vaultId && request.vaultId === b.template.vaultId && sameJson(b.template, current.template), "vault/template identity mismatch");
  delegateRequire(request.txId === b.txId && sameOutpoint(request.predecessorOutpoint, b.predecessorOutpoint) && request.predecessorStateId === b.predecessorStateId, "request and build predecessor/transaction identities differ");
  const frozen = JSON.parse(canonicalFrozenTxJson(normalizeFrozenTxV3(b.frozen)));
  const finalUnsigned = { ...request.finalTransaction, inputs: request.finalTransaction?.inputs?.map(({ signatureScript, ...input }) => input) };
  delegateRequire(canonicalFrozenTxJson(normalizeFrozenTxV3(finalUnsigned)) === canonicalFrozenTxJson(frozen), "final transaction differs from frozen bytes/UTXO evidence");
  delegateRequire(finalTxToWasm(config, request.finalTransaction).finalize().toString().toLowerCase() === request.txId, "computed transaction ID differs from the durable request");
  delegateRequire(frozen.inputs.length === (b.hasFuelInput ? 3 : 2) && frozen.outputs.length >= 3 && frozen.outputs.length <= 4 && b.hasRootInput === false && b.hasTokenInput === true && b.tokenInputIndex === 1, "unsupported delegate input/output shape");
  delegateRequire(sameOutpoint(frozen.inputs[0].previousOutpoint, b.predecessorOutpoint) && frozen.inputs[0].utxo.covenantId === b.covenantId && frozen.inputs[1].utxo.covenantId === b.template.tokenCovenantId, "vault/token predecessor is not the declared input");
  delegateRequire(frozen.outputs.slice(0, 3).every((o, i) => o.covenant?.covenantId === (i === 0 ? b.covenantId : b.template.tokenCovenantId) && Number(o.covenant.authorizingInput) === (i === 0 ? 0 : 1)), "continuation covenant/authorizing input mismatch");
  const fuel = frozen.inputs[2];
  if (fuel) delegateRequire(!fuel.utxo.covenantId && Number(fuel.utxo.scriptPublicKey.version) === 0 && /^20[0-9a-f]{64}ac$/.test(fuel.utxo.scriptPublicKey.scriptHex) && fuel.computeBudget === V7_BUDGET.ORDINARY_INPUT, "unexpected funding input or compute budget");
  // This wallet-request family builds change to the initiating agent. An
  // external fuel owner approves the same frozen transaction separately.
  if (frozen.outputs[3]) delegateRequire(!!fuel && !frozen.outputs[3].covenant && Number(frozen.outputs[3].scriptPublicKey.version) === 0 && frozen.outputs[3].scriptPublicKey.scriptHex === `20${b.callExtra.agentPk}ac`, "change differs from this delegate request's initiating key");
  const redeemHex = reconstructVaultScriptHexV7({ template: b.template, state: b.stateJson });
  const successorHex = reconstructVaultScriptHexV7({ template: b.template, state: b.successorState });
  const sha = (hex) => crypto.createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");
  const stateId = (state) => computeStateIdV7({ networkId: config.networkId, template: normalizeTemplateV7(b.template), state: normalizeStateV7(state), contractVersion: CONTRACT_VERSION_V7 });
  delegateRequire(stateId(b.stateJson) === b.predecessorStateId && stateId(b.successorState) === b.successorStateId && sha(successorHex) === b.successorScriptSha256, "state ID or compiled successor identity mismatch");
  // Older requests need not retain presentation/cache fields: reconstruct
  // from frozen generation bytes and the actually finalized token witness.
  const review = buildRootedVaultManifestV7({ build: { ...b, tokenSignatureScriptHex: request.finalTransaction.inputs[1].signatureScript }, descriptor: current.asset.descriptor });
  if (request.manifest) delegateRequire(sameJson(request.manifest, review) && request.manifestHash === review.manifestHash, "saved delegate review differs from actual operation evidence");
  verifyRootedVaultManifestV7({ manifest: review, frozen, descriptor: current.asset.descriptor, redeemHex,
    check: (label, ok, detail) => delegateRequire(ok, `${label}: ${detail}`) });

  return { frozen, review, redeemHex, sha };
}
function delegateEvidence(config, request, vault, { legacyPredecessorGeneration = null, legacyRegistry = null } = {}) {
  const b = request.build, current = manifestDoc(vault);
  const { frozen, review, redeemHex, sha } = delegateSignedEvidence(config, request, vault);
  let predecessor = request.predecessorVault;
  if (!predecessor) {
    // Legacy repair needs an exact predecessor/successor or bound completed
    // history. The signed old leaf and remaining disclosed leaves must still
    // reproduce the predecessor root; missing old registry disclosure fails
    // closed, rather than guessing from a newer registry or a counter.
    const atPre = sameOutpoint(current.live?.outpoint, b.predecessorOutpoint);
    delegateRequire(atPre || sameOutpoint(current.live?.outpoint, { transactionId: b.txId, index: 0 }) || legacyPredecessorGeneration !== null, "legacy request lacks bound predecessor evidence for this later record");
    const registry = legacyRegistry ?? current.agentRegistry.map((entry) => entry.agentPk === review.policy.agentPolicy.agentPk ? { ...entry, ...review.policy.agentPolicy } : entry);
    predecessor = { ...current, status: VaultStatus.ACTIVE, agentRegistry: registry,
      generation: legacyPredecessorGeneration ?? (atPre ? current.generation : current.generation - 1),
      live: { state: b.stateJson, stateId: b.predecessorStateId, outpoint: b.predecessorOutpoint, outpointValue: b.stateJson.feeReserve,
        scriptSha256: sha(redeemHex), covenantId: b.covenantId, tokenPosition: delegateTokenPosition(b, true) } };
  }
  predecessor = manifestDoc(normalizeHistoryVault(predecessor));
  delegateRequire(Number.isSafeInteger(predecessor.generation) && predecessor.generation >= 0, "invalid predecessor generation");
  delegateRequire(sameJson(predecessor.template, current.template) && sameJson(predecessor.asset, current.asset) && predecessor.networkId === config.networkId && predecessor.vaultId === request.vaultId && predecessor.orgRootCovenantId === current.orgRootCovenantId, "predecessor snapshot belongs to another vault/network/asset");
  delegateRequire(predecessor.status === VaultStatus.ACTIVE && sameOutpoint(predecessor.live?.outpoint, b.predecessorOutpoint) && sameVaultState(predecessor.live.state, b.stateJson) && predecessor.live.stateId === b.predecessorStateId && predecessor.live.scriptSha256 === sha(redeemHex) && predecessor.live.covenantId === b.covenantId && sameJson(predecessor.live.tokenPosition, delegateTokenPosition(b, true)), "predecessor snapshot does not match the spent state/token position");
  const successor = manifestDoc(normalizeHistoryVault({ ...predecessor,
    agentRegistry: advanceRegistryAfterSpendV7(predecessor.agentRegistry, b), generation: predecessor.generation + 1, latestTransitionTxId: b.txId,
    live: { state: b.successorState, stateId: b.successorStateId, outpoint: { transactionId: b.txId, index: 0 }, outpointValue: b.successorState.feeReserve,
      scriptSha256: b.successorScriptSha256, covenantId: b.covenantId, tokenPosition: delegateTokenPosition(b) } }));
  return { predecessor, successor, frozen };
}
async function delegatePosition(config, request, vault, evidence) {
  const current = manifestDoc(vault);
  for (const [position, expected] of [["PREDECESSOR", evidence.predecessor], ["SUCCESSOR", evidence.successor]]) {
    if (sameOutpoint(current.live?.outpoint, expected.live.outpoint)) {
      delegateRequire(sameJson(vaultCompletionFields(current), vaultCompletionFields(expected)) && current.generation === expected.generation, `${position.toLowerCase()} record has unexplained state/registry/token/generation differences`);
      if (position === "SUCCESSOR") delegateRequire(current.latestTransitionTxId === request.txId, "successor record names an unrelated latest transition");
      return position;
    }
  }
  const history = await traceVaultCompletion(config, vault, { ...request, rootCovenantId: request.build.template.orgRootCovenantId }, 0);
  delegateRequire(!!history, "no coherent completed transition history connects the current vault to this request");
  return "BEYOND";
}
function delegateReceiptMatches(receipt, request) {
  return receipt?.txId === request.txId && receipt.vaultId === request.vaultId && receipt.action === request.action && receiptPointerMatches(receipt, request) && receipt.proof.successorOutpoint === `${request.txId}:0`;
}
async function delegateAuditPresent(config, request) {
  return (await readAudit(config, { vaultId: request.vaultId, txId: request.txId, limit: 500 })).some((e) => e.action === request.action && e.result === "CHAIN_VERIFIED");
}
function depositTokenPosition(request) {
  const out = request.build.frozen.outputs[0];
  return { outpoint: { transactionId: request.txId, index: 0 }, value: String(out.value), scriptPublicKeyHex: out.scriptPublicKey.scriptHex,
    covenantId: out.covenant.covenantId, state: request.build.tokenNewStates[0] };
}
function depositSignedEvidence(config, request, vault, knownCovenantId = null) {
  const b = request.build, current = manifestDoc(vault), t = current.template;
  delegateRequire(request.schema === V7_WALLET_REQUEST_SCHEMA && request.action === "tokenDeposit" && b?.kind === "tokenDeposit" && b.action === request.action, "not a supported first deposit");
  delegateRequire(b.contractVersion === CONTRACT_VERSION_V7 && request.contractVersion === CONTRACT_VERSION_V7 && b.networkId === config.networkId && current.networkId === config.networkId, "deposit generation/network differs");
  delegateRequire(request.vaultId === current.vaultId && sameJson(b.vault.template, t) && b.vault.covenantId === (current.live?.covenantId ?? request.predecessorVault?.live?.covenantId ?? knownCovenantId), "deposit names another vault/template/covenant");
  delegateRequire(b.txId === request.txId && sameOutpoint(b.frozen.inputs[0].previousOutpoint, request.predecessorOutpoint), "deposit transaction/predecessor differs");
  assertFrozenRequestTransaction(config, request);
  const f = JSON.parse(canonicalFrozenTxJson(normalizeFrozenTxV3(b.frozen))), kcc = assets.kcc20;
  const tpl = current.asset.descriptor.acceptedTransferTemplates[current.asset.templateIndex];
  delegateRequire(assets.computeDescriptorHash(current.asset.descriptor) === t.descriptorHash && tpl.templateVmHashBlake2b256 === t.templateVmHash && tpl.prefixLen === t.templatePrefixLen && tpl.suffixLen === t.templateSuffixLen, "deposit descriptor/template pins differ");
  delegateRequire(f.version === 1 && String(f.lockTime) === "0" && f.subnetworkId === "00".repeat(20) && String(f.gas) === "0" && f.payload === "" && f.inputs.length === 2, "unexpected deposit transaction header/input shape");
  const token = f.inputs[0], fuel = f.inputs[1];
  const geometry = { prefixLen: t.templatePrefixLen, stateLen: t.templateStateLen, suffixLen: t.templateSuffixLen };
  const redeem = kcc.lastPushData(request.finalTransaction.inputs[0].signatureScript);
  const parts = kcc.splitRedeem(redeem, geometry), inputState = kcc.decodeState(parts.state);
  delegateRequire(kcc.templateVmHashHex(parts.prefix, parts.suffix) === t.templateVmHash && kcc.p2shSpkHex(redeem) === token.utxo.scriptPublicKey.scriptHex && token.utxo.scriptPublicKey.version === 0 && token.utxo.covenantId === t.tokenCovenantId, "deposit token witness does not bind the pinned family/input");
  delegateRequire(inputState.identifierType === 0 && !inputState.isMinter && inputState.ownerIdentifier === b.userPk && request.signerXOnly === b.userPk && String(inputState.amount) === b.accounting.token.positionBefore, "deposit input ownership/accounting differs");
  const amount = BigInt(b.accounting.token.deposit), remainder = inputState.amount - amount;
  delegateRequire(amount > 0n && remainder >= 0n && String(remainder) === b.accounting.token.remainderToUser, "deposit token conservation differs");
  const states = [{ ownerIdentifier: b.vault.covenantId, identifierType: 2, amount: String(amount), isMinter: false }];
  if (remainder) states.push({ ownerIdentifier: b.userPk, identifierType: 0, amount: String(remainder), isMinter: false });
  delegateRequire(sameJson(states, b.tokenNewStates) && f.outputs.length === states.length + 1, "deposit continuation/remainder declarations differ");
  for (let i = 0; i < states.length; i++) {
    const out = f.outputs[i], spk = kcc.p2shSpkHex(kcc.reconstructRedeem(parts.prefix, kcc.encodeState(states[i]), parts.suffix));
    delegateRequire(out.scriptPublicKey.version === 0 && out.scriptPublicKey.scriptHex === spk && out.covenant?.covenantId === t.tokenCovenantId && out.covenant.authorizingInput === 0, "deposit output is redirected or misassociated");
  }
  const change = f.outputs.at(-1), budget = require("../../core/model/compute-budget-v7");
  delegateRequire(token.computeBudget === budget.selectTokenInputBudgetV7({ templatePrefixLen: t.templatePrefixLen, templateSuffixLen: t.templateSuffixLen, signerOwned: true }) && fuel.computeBudget === V7_BUDGET.ORDINARY_INPUT && f.inputs.every((i) => String(i.sequence) === "0"), "deposit compute budget/sequence differs");
  delegateRequire(!fuel.utxo.covenantId && fuel.utxo.scriptPublicKey.version === 0 && /^20[0-9a-f]{64}ac$/.test(fuel.utxo.scriptPublicKey.scriptHex) && !change.covenant && change.scriptPublicKey.version === 0 && change.scriptPublicKey.scriptHex === `20${request.signerXOnly}ac`, "undeclared deposit funding/change output");
  const carry = f.outputs.slice(0, states.length).reduce((n, o) => n + BigInt(o.value), 0n);
  const fee = BigInt(fuel.utxo.amount) - BigInt(change.value);
  delegateRequire(carry === BigInt(token.utxo.amount) && String(f.outputs[0].value) === b.accounting.kas.depositCarryKas && fee > 0n && String(fee) === b.requiredFeeSompi && String(fee) === b.accounting.kas.fee, "deposit KAS carry/fee differs");
  return f;
}
async function depositHasLaterTokenHistory(config, request, vault) {
  let token = vault.live?.tokenPosition ? vaultManifestTokenPositionJson(vault.live.tokenPosition) : null;
  // Terminal recovery may have consumed the final token position. Its own
  // completed root request must bind that token input before tracing it.
  if (!token && vault.status === VaultStatus.RECOVERED && vault.latestTransitionTxId) {
    const q = await completedRequestAt(config, vault.latestTransitionTxId);
    if (!q || q.kind !== "rootAction" || q.vaultOperations?.[0]?.vaultId !== request.vaultId || q.build.successorState !== null) return false;
    token = q.build.hasTokenInput ? terminalTokenPredecessor(config, q, vault) : await legacyTerminalRetainedToken(config, q, vault);
  }
  const seen = new Set();
  while (token && seen.size < COMPLETION_HISTORY_LIMIT) {
    if (sameOutpoint(token.outpoint, { transactionId: request.txId, index: 0 })) return sameJson(token, depositTokenPosition(request));
    const key = describeOutpoint(token.outpoint);
    if (seen.has(key)) return false; seen.add(key);
    const q = await completedRequestAt(config, token.outpoint.transactionId);
    if (!q || q.action !== "tokenAgentSpend" || q.vaultId !== request.vaultId || !sameJson(token, delegateTokenPosition(q.build))) return false;
    delegateSignedEvidence(config, q, vault);
    token = delegateTokenPosition(q.build, true);
  }
  return false;
}
function terminalTokenPredecessor(config, request, vault) {
  const b = request.build;
  if (b.successorState !== null || !b.hasTokenInput) return null;
  const review = buildRootedVaultManifestV7({ build: { ...b, tokenSignatureScriptHex: request.finalTransaction.inputs[b.tokenInputIndex].signatureScript }, descriptor: vault.asset.descriptor });
  verifyRootedVaultManifestV7({ manifest: review, frozen: b.frozen, descriptor: vault.asset.descriptor,
    redeemHex: reconstructVaultScriptHexV7({ template: b.template, state: b.stateJson }),
    check: (label, ok, detail) => delegateRequire(ok, `${label}: ${detail}`) });
  const i = b.frozen.inputs[b.tokenInputIndex];
  return { outpoint: i.previousOutpoint, value: String(i.utxo.amount), scriptPublicKeyHex: i.utxo.scriptPublicKey.scriptHex, covenantId: i.utxo.covenantId,
    state: { ownerIdentifier: b.covenantId, identifierType: 2, amount: String(b.accounting.token.positionBefore), isMinter: false } };
}
async function legacyTerminalRetainedToken(config, terminal, vault) {
  // Older public ownerRecover omitted the token input. It proves vault
  // termination, NOT a token sweep. Recover earlier accepted history from
  // its last proven token position without creating a live vault or claiming
  // those tokens were paid out. The omitted on-chain input cannot be repaired.
  if (terminal.build.hasTokenInput || terminal.build.successorState !== null) return null;
  let cursor = terminal.build.predecessorOutpoint;
  const seen = new Set();
  while (cursor && seen.size < COMPLETION_HISTORY_LIMIT) {
    const key = describeOutpoint(cursor); if (seen.has(key)) return null; seen.add(key);
    const q = await completedRequestAt(config, cursor.transactionId);
    if (!q) return null;
    if (q.action === "tokenAgentSpend") {
      if (q.vaultId !== vault.vaultId || Number(cursor.index) !== 0) return null;
      delegateSignedEvidence(config, q, vault);
      return delegateTokenPosition(q.build);
    }
    if (q.kind === "rootAction") {
      if (q.vaultOperations?.length !== 1 || q.vaultOperations[0].vaultId !== vault.vaultId || q.build.successorState === null || Number(cursor.index) !== vaultSuccessorIndex(q)) return null;
      cursor = q.build.predecessorOutpoint; continue;
    }
    if (q.kind !== "rootedVaultGenesis" || q.build.template.vaultId !== vault.vaultId || Number(cursor.index) !== q.build.vaultOutputIndex) return null;
    const deposits = (await listV7WalletRequests(config, { vaultId: vault.vaultId })).filter((r) => r.action === "tokenDeposit" && r.state === "CHAIN_VERIFIED");
    if (deposits.length !== 1) return null;
    const deposit = await completedRequestAt(config, deposits[0].txId);
    if (!deposit || deposit.requestId !== deposits[0].requestId) return null;
    depositSignedEvidence(config, deposit, vault, terminal.build.covenantId);
    return depositTokenPosition(deposit);
  }
  return null;
}
async function inspectDepositCompletion(config, request, vault) {
  let knownCovenantId = null;
  if (!vault.live && !request.predecessorVault && vault.creationTxId) {
    const genesis = await completedRequestAt(config, vault.creationTxId);
    if (genesis?.kind === "rootedVaultGenesis" && genesis.build.template.vaultId === request.vaultId) knownCovenantId = genesis.build.covenantId;
  }
  const frozen = depositSignedEvidence(config, request, vault, knownCovenantId), current = manifestDoc(vault);
  let position, predecessor = request.predecessorVault ?? null, successor = null;
  if (current.live && !current.live.tokenPosition) {
    predecessor ??= current;
    delegateRequire(!predecessor.live?.tokenPosition && sameJson(vaultCompletionFields(current), vaultCompletionFields(predecessor)) && current.generation === predecessor.generation, "deposit predecessor has changed or already holds a position");
    position = "PREDECESSOR";
  } else if (current.live && current.latestTransitionTxId === request.txId && sameJson(current.live.tokenPosition, depositTokenPosition(request))) {
    predecessor ??= { ...current, generation: current.generation - 1, live: { ...current.live, tokenPosition: null } };
    position = "SUCCESSOR";
  } else {
    delegateRequire(await depositHasLaterTokenHistory(config, request, vault), "deposit has no coherent later token history");
    position = "BEYOND";
  }
  if (position !== "BEYOND") {
    delegateRequire(predecessor.vaultId === request.vaultId && predecessor.generation >= 0 && !predecessor.live.tokenPosition, "invalid deposit predecessor snapshot");
    successor = { ...predecessor, generation: predecessor.generation + 1, latestTransitionTxId: request.txId, live: { ...predecessor.live, tokenPosition: depositTokenPosition(request) } };
    if (position === "SUCCESSOR") delegateRequire(sameJson(vaultCompletionFields(current), vaultCompletionFields(successor)) && current.generation === successor.generation, "deposit successor state/generation differs");
  }
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  const durableEffectProven = request.state === "CHAIN_VERIFIED" && position !== "PREDECESSOR" && receipt?.proof?.outpoint === `${request.txId}:0` && await receiptAssociationMatches(config, receipt, request) && await delegateAuditPresent(config, request);
  return { evidence: { frozen, predecessor, successor }, position, claim: null, submission, receipt, durableEffectProven, complete: durableEffectProven && !submission };
}
async function inspectDelegateCompletion(config, request, vault, { inspectAliases = true } = {}) {
  if (request.action === "tokenDeposit") return inspectDepositCompletion(config, request, vault);
  let legacyPredecessorGeneration = null;
  if (!request.predecessorVault && !sameOutpoint(vault.live?.outpoint, request.predecessorOutpoint) && !sameOutpoint(vault.live?.outpoint, { transactionId: request.txId, index: 0 })) {
    const history = await traceVaultCompletion(config, vault, { ...request, rootCovenantId: request.build.template.orgRootCovenantId }, 0);
    delegateRequire(!!history, "legacy request has no bound completed history");
    legacyPredecessorGeneration = vault.generation - history.length - 1;
  }
  const legacyRegistry = legacyPredecessorGeneration !== null ? await historicalRegistryAt(config, vault, request.build.predecessorOutpoint, request.build.stateJson) : null;
  const evidence = delegateEvidence(config, request, vault, { legacyPredecessorGeneration, legacyRegistry });
  const position = await delegatePosition(config, request, vault, evidence);
  const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  const durableEffectProven = request.state === "CHAIN_VERIFIED" && position !== "PREDECESSOR" && receipt?.proof?.successorOutpoint === `${request.txId}:0` && await receiptAssociationMatches(config, receipt, request) && await delegateAuditPresent(config, request);
  const complete = durableEffectProven && claim?.txId !== request.txId && !submission;
  if (inspectAliases && request.state === "CHAIN_VERIFIED") {
    const twins = (await listV7WalletRequests(config, { vaultId: request.vaultId }))
      .filter((q) => q.requestId !== request.requestId && q.state === "CHAIN_VERIFIED" && q.txId === request.txId);
    if (twins.length) {
      // Earlier direct submission could mark both legacy finalizations complete.
      // Preserve the existing bound receipt's representative of ONE effect;
      // this cannot reconstruct which signature witness was actually broadcast.
      // No receipt, partial pointers or contradictory history authorize a choice.
      const selected = hasReceiptPointer(receipt) && await completedRequestAt(config, request.txId);
      delegateRequire(selected?.state === "CHAIN_VERIFIED" && selected.action === request.action && selected.vaultId === request.vaultId, "completed duplicates have no valid bound effect representative");
      if (selected.requestId !== request.requestId) {
        const canonical = await inspectDelegateCompletion(config, selected, vault, { inspectAliases: false });
        delegateRequire(canonical.complete && canonical.position === position && sameJson(canonical.evidence.frozen, evidence.frozen) &&
          ["predecessor", "successor"].every((key) => canonical.evidence[key].generation === evidence[key].generation && sameJson(vaultCompletionFields(canonical.evidence[key]), vaultCompletionFields(evidence[key]))), "completed duplicate differs from the fully settled representative's transaction, funding or history");
        return { evidence, position, claim, submission, receipt, complete: true, durableEffectProven: true };
      }
    }
  }
  return { evidence, position, claim, submission, receipt, complete, durableEffectProven };
}
async function delegateCandidates(config, vault, { requireClaimAssociation = true } = {}) {
  const all = await listV7WalletRequests(config, { vaultId: vault.vaultId });
  const submissions = await getStore(config).listValues(Categories.SUBMISSION_CLAIM, { strict: true });
  const ownTxs = new Set(submissions.filter((c) => c.vaultId === vault.vaultId && ["tokenAgentSpend", "tokenDeposit"].includes(c.action)).map((c) => c.txId));
  // A delayed legacy finalizer could rewind a completed request to SIGNED
  // after its claims were released. Only its bound receipt discovers that
  // request; another prebuilt request with the same txid is not attached.
  const receipts = await getStore(config).listValues(Categories.RECEIPT, { strict: true });
  const byRequest = new Map(receipts.filter((r) => r.vaultId === vault.vaultId && ["tokenAgentSpend", "tokenDeposit"].includes(r.action) && r.proof?.requestKind === "vaultAction").map((r) => [r.proof.requestId, r]));
  const claim = vault.live && await loadTransitionClaim(config, vault.live.outpoint);
  const rows = all.filter((q) => ["tokenAgentSpend", "tokenDeposit"].includes(q.action) && !neverEffective(q) && !sameEffectDuplicate(q, all) && (DELEGATE_PENDING_STATES.has(q.state) || ownTxs.has(q.txId) && (!submissions.find((s) => s.txId === q.txId)?.expected?.requestId || submissions.find((s) => s.txId === q.txId).expected.requestId === q.requestId) || q.state === "SIGNED" && delegateReceiptMatches(byRequest.get(q.requestId), q) || q.state === "CHAIN_VERIFIED" && q.txId === vault.latestTransitionTxId || claim?.expected?.kind === "v7Successor" && q.txId === claim.txId))
    .filter((q) => q.state !== "SIGNED" || claim?.expected?.kind !== "v7Successor" || claim.txId !== q.txId || !claim.expected.requestId || q.requestId === claim.expected.requestId);
  delegateRequire(rows.length <= COMPLETION_HISTORY_LIMIT, "too many unresolved delegate candidates; refusing a truncated association");
  const requests = [];
  rows.sort((a, b) => Number(delegateReceiptMatches(byRequest.get(b.requestId), b)) - Number(delegateReceiptMatches(byRequest.get(a.requestId), a)));
  for (const row of rows) {
    const q = await loadV7WalletRequest(config, row.requestId);
    delegateRequire(q && sameJson(q, row), "candidate changed or differs from its canonical storage key");
    requests.push(q);
  }
  if (claim?.expected?.kind === "v7Successor") {
    const matches = requests.filter((q) => q.txId === claim.txId && sameOutpoint(q.predecessorOutpoint, claim.outpoint));
    if (requireClaimAssociation || matches.length) delegateRequire(matches.length === 1 && (!claim.expected.requestId || claim.expected.requestId === matches[0].requestId), "missing, wrong or ambiguous delegate claim association");
  }
  return requests;
}
async function pendingRootRequests(config, root) {
  if (!root?.live) return [];
  const pending = [];
  for (const q of await listOrgRootRequests(config, { rootCovenantId: root.rootCovenantId })) {
    if (q.kind !== "rootAction") continue;
    // An advanced root does not settle unfinished durable effects. Discover
    // those requests without writing an old pending pointer onto the root.
    if (["BROADCAST", "CHAIN_SEEN", "RECONCILIATION_REQUIRED"].includes(q.state) ||
      ["AUTHORIZED", "SIGNED"].includes(q.state) && (sameOutpoint(q.manifest?.root?.outpoint, root.live.outpoint) || await rootRequestHasBoundAttempt(config, q)) ||
      q.state === "SUBMISSION_REJECTED" && await hasBoundRootCompletionReceipt(config, q)) pending.push(q);
  }
  return pending;
}
async function rootRequestHasBoundAttempt(config, request) {
  const fingerprint = completionReceiptPointer(request).requestFingerprint;
  if (request.submissionAttempt?.requestFingerprint === fingerprint || request.submissionOutcome?.requestFingerprint === fingerprint) return true;
  for (const outpoint of [request.manifest.root.outpoint, ...(request.vaultOperations?.length ? [request.build.predecessorOutpoint] : [])]) {
    const claim = await loadTransitionClaim(config, outpoint);
    if (claim?.txId === request.txId && claim.expected?.kind === "orgRootRequest" && claim.expected.requestId === request.id) return true;
  }
  // A same-tx stranger's receipt forbids new signing, but does not make this
  // unrelated historical draft an attempted operation reserving the root.
  return hasBoundRootCompletionReceipt(config, request);
}
async function assertVaultCompletionAvailable(config, vault, exceptRequestId = null) {
  if (!vault) throwFail("vault missing", "VAULT_NOT_FOUND");
  // Only actual durable delegate requests add this guard. An unrelated
  // orphan claim must not prevent completion of an already proven root
  // action; its existing claim arbitration/release rules remain unchanged.
  for (const q of await delegateCandidates(config, vault, { requireClaimAssociation: false })) {
    if (q.requestId === exceptRequestId) continue;
    let complete = false;
    try {
      const info = await inspectDelegateCompletion(config, q, vault);
      complete = info.complete;
      if (!complete && info.durableEffectProven) {
        // Old inline completion left submission claims behind. Exact durable
        // effect + associated receipt + audit may finish those local records;
        // a supported agent build need not ask an owner to do that repair.
        await completeDelegateRequest(config, null, q);
        complete = true;
      }
    } catch { /* unresolved stays guarded */ }
    if (!complete) throwFail(`vault has unfinished delegate request ${q.requestId} — reconcile that request first`, "VAULT_PENDING_REQUEST");
  }
  const root = await loadOrgRoot(config, vault.orgRootCovenantId);
  for (const q of await pendingRootRequests(config, root)) {
    if (q.id !== exceptRequestId && q.vaultOperations?.some((op) => op.vaultId === vault.vaultId)) throwFail(`vault belongs to pending root request ${q.id}`, "VAULT_PENDING_REQUEST");
  }
  if (root?.pendingRequestId && root.pendingRequestId !== exceptRequestId) {
    const q = await loadOrgRootRequest(config, root.pendingRequestId);
    if (!q || q.rootCovenantId !== vault.orgRootCovenantId || q.vaultOperations?.some((op) => op.vaultId === vault.vaultId)) throwFail(`vault belongs to pending root request ${root.pendingRequestId}`, "VAULT_PENDING_REQUEST");
  }
  // Admission must not build on contradictory current owner-transition
  // metadata. Inspect only the transition producing this vault position,
  // not every historical root request. Recovery itself bypasses this guard
  // so a later interrupted delegate can complete before its root history.
  const currentTxIds = new Set([vault.latestTransitionTxId, vault.live?.outpoint?.transactionId].filter(Boolean));
  const ownerEffects = (await listOrgRootRequests(config, { rootCovenantId: vault.orgRootCovenantId })).filter((q) =>
    q.kind === "rootAction" && currentTxIds.has(q.txId) && q.vaultOperations?.some((op) => op.vaultId === vault.vaultId));
  for (const txId of new Set(ownerEffects.map((q) => q.txId))) {
    let complete = false;
    try {
      const q = await completedRequestAt(config, txId);
      const position = q?.kind === "rootAction" ? await classifyVaultRecord(config, vault, q, vaultSuccessorIndex(q)) : null;
      complete = position?.consistent && ["SUCCESSOR", "BEYOND"].includes(position.position);
    } catch { /* verification failure is a refusal, never a durable downgrade */ }
    if (!complete) throwFail(`vault ${vault.vaultId} has unverified owner-transition history at ${txId} — reconcile its original request`, "VAULT_PENDING_REQUEST");
  }
}
function validateDelegateClaim(claim, request) {
  if (!claim || claim.txId !== request.txId) return;
  delegateRequire(claim.vaultId === request.vaultId && claim.action === request.action && claim.stateId === request.predecessorStateId && sameOutpoint(claim.outpoint, request.predecessorOutpoint) && claim.expected?.kind === "v7Successor" && claim.expected.txId === request.txId, "claim does not bind this operation's predecessor");
  delegateRequire(!claim.expected.requestId || claim.expected.requestId === request.requestId, "claim points to another request");
  delegateRequire(!claim.expected.requestFingerprint || claim.expected.requestFingerprint === completionReceiptPointer(request).requestFingerprint, "claim request fingerprint differs");
}
function validateDelegateSubmission(submission, request) {
  delegateRequire(!submission || submission.txId === request.txId && submission.vaultId === request.vaultId && submission.action === request.action && (!submission.expected || sameJson(submission.expected, completionReceiptPointer(request))), "submission claim belongs to another operation/request");
}
async function delegateObserved(config, rpc, request, info) {
  if (info.durableEffectProven || info.position === "BEYOND") return true; // bound receipt/audit and exact state or completed lineage
  const outputs = info.evidence.frozen.outputs;
  async function continuations() {
    for (const i of (request.action === "tokenDeposit" ? [0] : [0, 1])) {
      const out = outputs[i], refs = await getAddressUtxos(rpc, spkToAddress(config, out.scriptPublicKey));
      const matches = refs.filter((r) => sameOutpoint(r.outpoint, { transactionId: request.txId, index: i }));
      if (matches.length !== 1) return false;
      const ref = matches[0];
      if (String(ref.amount) !== String(out.value) || ref.covenantId !== out.covenant.covenantId || ref.scriptPublicKeyHex != null && ref.scriptPublicKeyHex !== out.scriptPublicKey.scriptHex) return false;
    }
    return true;
  }
  // Observing these outputs under the recomputed txid binds the transaction's
  // other outputs too; the recipient need not leave their payment unspent.
  if (!await continuations()) return false;
  for (const input of info.evidence.frozen.inputs) {
    const refs = await getAddressUtxos(rpc, spkToAddress(config, input.utxo.scriptPublicKey));
    if (refs.some((r) => sameOutpoint(r.outpoint, input.previousOutpoint))) return false;
  }
  return continuations(); // contradictory/racing address queries do not prove completion
}
async function recordDelegateFailure(config, request, error) {
  let fresh;
  try { fresh = await loadV7WalletRequest(config, request.requestId); }
  catch { return; } // A failed diagnostic read never authorizes a stale write.
  if (!fresh) return;
  if (fresh?.state === "CHAIN_VERIFIED" && !error.completionStarted) return;
  if (neverEffective(fresh)) return; // a never-finalized draft / withdrawn request has nothing to reconcile: a failed inspection writes nothing
  request.state = "RECONCILIATION_REQUIRED";
  request.error = String(error.message ?? error).split("\n")[0];
  try { await saveV7WalletRequest(config, request); } catch (persistError) { request.error += `; diagnostic write failed: ${persistError.message}`; }
}
const WALLET_NEGATIVE_OUTCOMES = new Set(["NOT_BROADCAST", "SUBMISSION_REJECTED", "SUPERSEDED"]);
async function settleWalletNegativeOutcome(config, request, outcome) {
  delegateRequire(WALLET_NEGATIVE_OUTCOMES.has(outcome.outcome), "unsupported negative submission outcome");
  const pointer = completionReceiptPointer(request);
  const claim = request.action === "tokenAgentSpend" ? await loadTransitionClaim(config, request.predecessorOutpoint) : null;
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  validateDelegateClaim(claim, request); validateDelegateSubmission(submission, request);
  request.submissionOutcome = { ...outcome, ...pointer, txId: request.txId };
  request.state = "RECONCILIATION_REQUIRED";
  await saveV7WalletRequest(config, request); // negative proof before releasing only our claims
  if (claim?.txId === request.txId) await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
  if (submission) await releaseSubmissionClaim(config, request.txId);
  request.state = outcome.outcome;
  request.error = outcome.reason ?? `${outcome.outcome}: the original attempt has a supported negative outcome; no replacement was broadcast`;
  await saveV7WalletRequest(config, request); // reservation ends only after settlement is durable
  return request;
}
function savedWalletNegativeOutcome(request) {
  const outcome = request.submissionOutcome;
  return outcome && WALLET_NEGATIVE_OUTCOMES.has(outcome.outcome) && outcome.txId === request.txId && Object.entries(completionReceiptPointer(request)).every(([k, v]) => outcome[k] === v) ? outcome : null;
}
async function completeDelegateRequest(config, rpc, request, { pollAttempts = 1, pollDelayMs = 0, stalePendingMinimumMs = 120000, allowClaimRelease = true } = {}) {
  let completionStarted = false;
  try {
    const vault = await loadManifestV7(config, request.vaultId);
    const info = await inspectDelegateCompletion(config, request, vault);
    validateDelegateClaim(info.claim, request);
    validateDelegateSubmission(info.submission, request);
    if (info.complete) return request;
    let proven = false;
    for (let i = 0; i < pollAttempts && !proven; i++) {
      proven = await delegateObserved(config, rpc, request, info);
      if (!proven && i + 1 < pollAttempts) await new Promise((resolve) => setTimeout(resolve, pollDelayMs));
    }
    if (!proven && allowClaimRelease && info.position === "PREDECESSOR" && request.state !== "CHAIN_VERIFIED") {
      let outcome = savedWalletNegativeOutcome(request);
      const attempt = request.submissionAttempt;
      if (!outcome && attempt && attempt.requestFingerprint === completionReceiptPointer(request).requestFingerprint && ["PREPARING", "NOT_SENT"].includes(attempt.phase)) outcome = { outcome: "NOT_BROADCAST", reason: "durable preparation did not reach wallet transaction broadcast", proof: { attemptId: attempt.id, phase: attempt.phase } };
      if (!outcome && rpc) outcome = await require("./submission-outcome-v7").observeSubmissionOutcome(config, rpc, request, { stalePendingMinimumMs });
      if (outcome && WALLET_NEGATIVE_OUTCOMES.has(outcome.outcome)) return await settleWalletNegativeOutcome(config, request, outcome);
      if (outcome?.outcome === "ACCEPTED_OR_CONTRADICTORY") proven = await delegateObserved(config, rpc, request, info);
      if (outcome?.observationStartHash && !request.submitStartHash && !request.reconcileStartHash) {
        request.reconcileStartHash = outcome.observationStartHash;
        request.outcomeObservationAt = new Date().toISOString();
      }
    }
    delegateRequire(proven, "expected vault/token effect not observed consistently; original request remains unresolved");
    completionStarted = true;
    request.state = "RECONCILIATION_REQUIRED";
    if (!request.predecessorVault && info.evidence.predecessor) request.predecessorVault = info.evidence.predecessor;
    await saveV7WalletRequest(config, request); // replay data before completion writes
    if (info.position === "PREDECESSOR") await persistManifestV7(config, { ...manifestDoc(vault), ...info.evidence.successor });
    if (!delegateReceiptMatches(await getStore(config).read(Categories.RECEIPT, request.txId), request)) {
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action,
        proof: { ...completionReceiptPointer(request), ...(request.action === "tokenDeposit" ? { outpoint: `${request.txId}:0` } : {}), predecessorOutpoint: describeOutpoint(request.predecessorOutpoint), successorOutpoint: `${request.txId}:0`, tokenOutpoint: `${request.txId}:${request.action === "tokenDeposit" ? 0 : 1}`, via: "delegate-completion/v7" } });
    }
    if (!await delegateAuditPresent(config, request)) await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: request.action === "tokenDeposit" ? "funder" : "agent", contractVersion: CONTRACT_VERSION_V7, txId: request.txId, result: "CHAIN_VERIFIED", via: "delegate-completion/v7" });
    const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
    // A foreign claim is never released, even after this request is proven.
    if (request.action !== "tokenDeposit" && claim?.txId === request.txId) {
      validateDelegateClaim(claim, request);
      await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
    }
    const sub = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
    if (sub) {
      validateDelegateSubmission(sub, request);
      await releaseSubmissionClaim(config, request.txId);
    }
    request.state = "CHAIN_VERIFIED";
    request.error = null;
    request.chain = { predecessorOutpoint: describeOutpoint(request.predecessorOutpoint), successorOutpoint: `${request.txId}:0`, tokenOutpoint: `${request.txId}:${request.action === "tokenDeposit" ? 0 : 1}`, position: info.position, observedAt: new Date().toISOString() };
    await saveV7WalletRequest(config, request); // LAST: no earlier write clears the pending-request guard
    return request;
  } catch (e) {
    e.completionStarted = completionStarted;
    await recordDelegateFailure(config, request, e);
    throw fail(`delegate completion incomplete: ${e.message}`, "RECONCILIATION_REQUIRED");
  }
}
async function reconcileDelegateRequests(config, rpc, vault, options = {}) {
  let candidates;
  try { candidates = await delegateCandidates(config, vault); }
  catch (e) { return { status: "UNKNOWN", vaultId: vault.vaultId, reason: e.message }; }
  const completion = [];
  let failed = null;
  for (const request of candidates) {
    try {
      const fresh = await loadManifestV7(config, vault.vaultId);
      if ((await inspectDelegateCompletion(config, request, fresh)).complete) continue;
      await completeDelegateRequest(config, rpc, request, options);
      completion.push({ requestId: request.requestId, txId: request.txId, outcome: request.state });
    } catch (e) {
      // One unresolved candidate never aborts the repair of the others (a completed spend whose old inline
      // completion left claims behind is still finished); the first failure is reported.
      await recordDelegateFailure(config, request, e);
      failed ??= { requestId: request.requestId, reason: e.message };
    }
  }
  if (failed) return { status: "UNKNOWN", vaultId: vault.vaultId, requestId: failed.requestId, reason: failed.reason, completion };
  return completion.length ? { status: completion.some((c) => c.outcome === "CHAIN_VERIFIED") ? "ADVANCED" : "CLAIM_RELEASED", vaultId: vault.vaultId, completion } : null;
}
async function submitDelegateRequest({ config, request, rpc: providedRpc, pollAttempts, pollDelayMs }) {
  assertOperationalNetwork(config);
  assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  if (WALLET_NEGATIVE_OUTCOMES.has(request.state) && savedWalletNegativeOutcome(request)) return request;
  delegateRequire(request.state === "SIGNED" || request.state === "CHAIN_VERIFIED" || DELEGATE_PENDING_STATES.has(request.state), `request is ${request.state}, not signed or recoverable`);
  // R8-09: the direct submit path must honor the same effect ownership as
  // discovery. A pointerless legacy claim is not authority for an unattempted
  // sibling to take another request's completion receipt. Refuse before any
  // completion/failure write; genuinely settled negative attempts do not own
  // a positive effect and must not strand an otherwise valid signed retry.
  const equivalents = (await listV7WalletRequests(config, { vaultId: request.vaultId }))
    .filter((other) => !(WALLET_NEGATIVE_OUTCOMES.has(other.state) && savedWalletNegativeOutcome(other)));
  delegateRequire(!sameEffectDuplicate(request, equivalents), "same-effect duplicate: recover or inspect the original attempted request; this unattempted sibling may be withdrawn");
  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    delegateRequire(serverInfo.networkId === config.networkId, "node/configured network mismatch");
    const vault = await loadManifestV7(config, request.vaultId);
    if (request.action === "tokenDeposit" && request.state === "SIGNED" && !request.submissionAttempt && !await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId) && !await getStore(config).read(Categories.RECEIPT, request.txId)) {
      // A deposit spends the funder's token, not a vault outpoint. A completed
      // owner operation does not invalidate these unchanged signed bytes.
      depositSignedEvidence(config, request, vault);
      await assertVaultCompletionAvailable(config, vault, request.requestId);
      delegateRequire(vault.live && !vault.live.tokenPosition, "deposit target is closed or already holds a token position");
      request.predecessorVault = manifestDoc(vault);
    }
    const info = await inspectDelegateCompletion(config, request, vault);
    validateDelegateClaim(info.claim, request);
    validateDelegateSubmission(info.submission, request);
    if (request.state !== "SIGNED" || info.claim?.txId === request.txId || info.submission) return await completeDelegateRequest(config, rpc, request);
    if (info.position !== "PREDECESSOR") {
      delegateRequire(delegateReceiptMatches(info.receipt, request), "a rewound SIGNED request requires its own bound completion receipt");
      return await completeDelegateRequest(config, rpc, request);
    }
    await assertVaultCompletionAvailable(config, vault, request.requestId);
    delegateRequire(info.position === "PREDECESSOR", "signed request no longer spends the current vault");
    request.predecessorVault = info.evidence.predecessor;
    const arbitration = require("./submission-outcome-v7");
    const startHash = await arbitration.readSubmissionStartHash(rpc);
    request.submissionAttempt = { id: crypto.randomUUID(), phase: "PREPARING", requestFingerprint: completionReceiptPointer(request).requestFingerprint, at: new Date().toISOString() };
    request.submittedAt = request.submissionAttempt.at;
    request.submitStartHash = startHash;
    request.state = "SUBMITTING";
    await saveV7WalletRequest(config, request); // discoverable before either claim is attempted
    let invoked = false;
    try {
      if (request.action !== "tokenDeposit") await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: request.txId, vaultId: request.vaultId, stateId: request.predecessorStateId,
        expected: { kind: "v7Successor", txId: request.txId, requestId: request.requestId, requestFingerprint: completionReceiptPointer(request).requestFingerprint } });
      await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, expected: completionReceiptPointer(request) });
      request.submissionAttempt.phase = "BROADCAST_STARTED";
      await saveV7WalletRequest(config, request);
      const transaction = finalTxToWasm(config, request.finalTransaction);
      invoked = true;
      const submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
      delegateRequire(String(submitted.transactionId ?? submitted).toLowerCase() === request.txId, "node returned another transaction ID");
      request.submissionAttempt.phase = "ACCEPTED_RESPONSE";
      request.state = "SUBMITTED";
      await saveV7WalletRequest(config, request);
    } catch (e) {
      if (!invoked && e.code !== "CLAIM_CONFLICT") {
        request.submissionAttempt.phase = "NOT_SENT";
        try { await settleWalletNegativeOutcome(config, request, { outcome: "NOT_BROADCAST", reason: `pre-broadcast preparation failed: ${e.message}`, proof: { attemptId: request.submissionAttempt.id, phase: "NOT_SENT" } }); }
        catch (writeError) { await recordDelegateFailure(config, request, writeError); }
      } else {
        if (!invoked && e.code === "CLAIM_CONFLICT") request.submissionAttempt.phase = "CLAIM_OWNERSHIP_UNCERTAIN";
        if (invoked && arbitration.isBoundRejection(e, request.txId) && request.submissionAttempt.phase === "BROADCAST_STARTED") {
          request.submissionAttempt.phase = "REJECTED_RESPONSE";
          request.submissionAttempt.error = String(e.message ?? e);
        }
        await recordDelegateFailure(config, request, e);
      }
      throw fail(`wallet transaction submission: ${request.error}`, WALLET_NEGATIVE_OUTCOMES.has(request.state) ? request.state : "RECONCILIATION_REQUIRED");
    }
    return await completeDelegateRequest(config, rpc, request, { pollAttempts, pollDelayMs });
  } catch (e) {
    if (request.state === "CHAIN_VERIFIED" || DELEGATE_PENDING_STATES.has(request.state)) await recordDelegateFailure(config, request, e);
    throw e;
  } finally { if (owned) await rpc.disconnect(); }
}

/* ------------------------------------------------------------------ */
/* 7. REJECT (hosted-layer withdrawal only; never a chain fact)         */
/* ------------------------------------------------------------------ */

async function rejectOrgRootRequest(args) {
  return withRootRequestLock(args.config, args.requestId, () => rejectOrgRootRequestUnlocked(args));
}
async function rejectOrgRootRequestUnlocked({ config, requestId, reason }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (![RequestState.AUTHORIZED, RequestState.REFUSED].includes(request.state) || request.signedSafeJson || request.finalTransaction || request.slots?.some((s) => s.status === "SIGNED")) {
    throwFail(`request is ${request.state} or carries signatures — only an unsigned request may be withdrawn`, "CANNOT_REJECT");
  }
  await assertRootRequestNotAttempted(config, request, "CANNOT_REJECT");
  if (request.state !== RequestState.REFUSED) {
    request.state = RequestState.REFUSED;
    request.error = typeof reason === "string" ? reason : null;
    await saveOrgRootRequest(config, request);
  }
  if (request.kind === "rootAction") {
    const root = await loadOrgRoot(config, request.rootCovenantId);
    if (root && root.pendingRequestId === request.id) {
      root.pendingRequestId = null;
      await saveOrgRoot(config, root);
    }
  }
  return request;
}

async function rootRequestHasAttemptEvidence(config, request) {
  const store = getStore(config);
  let attempted = !!request.submissionAttempt || !!request.submissionOutcome;
  attempted ||= !!await store.read(Categories.SUBMISSION_CLAIM, request.txId) || !!await store.read(Categories.RECEIPT, request.txId);
  if (request.kind === "rootAction") {
    for (const outpoint of [request.manifest.root.outpoint, ...(request.vaultOperations?.length ? [request.build.predecessorOutpoint] : [])]) {
      const claim = await loadTransitionClaim(config, outpoint);
      attempted ||= claim?.txId === request.txId;
    }
  }
  return attempted;
}
async function assertRootRequestNotAttempted(config, request, code = "RECONCILIATION_REQUIRED") {
  if (await rootRequestHasAttemptEvidence(config, request)) throwFail("this request has durable submission/completion evidence — resume reconciliation before new signing or withdrawal", code);
}

/* ------------------------------------------------------------------ */
/* 8. DELEGATE SPEND / DEPOSIT on a rooted vault (no root input)        */
/*    POST /wallet/v7/requests                                          */
/* ------------------------------------------------------------------ */

const V7WalletRequestState = Object.freeze({
  BUILT: "BUILT",
  SIGNED: "SIGNED",
  SUBMITTING: "SUBMITTING",
  SUBMITTED: "SUBMITTED",
  CHAIN_VERIFIED: "CHAIN_VERIFIED",
  SUBMISSION_REJECTED: "SUBMISSION_REJECTED",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  WALLET_REJECTED: "WALLET_REJECTED",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  STALE: "STALE",
  BUILD_FAILED: "BUILD_FAILED"
});

async function buildV7WalletRequest(args) {
  const vault = await loadManifestV7(args.config, args.vaultId);
  if (!vault) throwFail(`no v0.7 rooted vault ${args.vaultId}`, "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => buildV7WalletRequestUnlocked(args));
}
async function buildV7WalletRequestUnlocked({ config, vaultId, action, params = {}, signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = await loadManifestV7(config, vaultId);
  if (!manifest) throwFail(`no v0.7 rooted vault ${vaultId}`, "VAULT_NOT_FOUND");
  if (!manifest.live) throwFail(`vault is ${manifest.status} (closed) — read-only history`, "VAULT_TERMINAL");
  await assertVaultCompletionAvailable(config, manifest);

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const changeXOnly = signerXOnly;

  if (action === "tokenDeposit") {
    /* buildTokenDepositV7 consumes ONLY the user's own token position, never
     * the vault's EXISTING one (there is no merge input) — depositing into a
     * vault that already holds a tracked position would create a SECOND,
     * separate same-family covenant UTXO this manifest's single tokenPosition
     * field cannot represent, silently losing track of on-chain value. Refuse
     * closed rather than guess; this is a deliberate scope limitation of the
     * server orchestration layer, not the covenant (see final report). */
    if (manifest.live.tokenPosition !== null) {
      throwFail("this vault already holds a tracked token position — a second deposit would create an untracked same-family UTXO; failing closed", "TOKEN_POSITION_ALREADY_HELD");
    }
    const fuel = await resolveFuel(config, params, signerAddress, 500_000n);
    const userPositionOutpoint = normalizeOutpoint(params.userPosition?.outpoint, "params.userPosition.outpoint");
    let build;
    try {
      build = buildTokenDepositV7({
        config,
        descriptor: manifest.asset.descriptor,
        templateIndex: manifest.asset.templateIndex,
        vault: { covenantId: manifest.live.covenantId, template: manifest.template },
        chain: { userPosition: { ...params.userPosition, outpoint: userPositionOutpoint }, fuel },
        params: { depositAmount: params.depositAmount, depositCarryKasSompi: params.depositCarryKasSompi },
        changeXOnly
      });
    } catch (e) {
      throw fail(`token deposit build failed: ${e.message}`, e.code || "BUILD_FAILED");
    }
    const wtx = frozenToWasmTransaction(config, build.frozen);
    wtx.finalize();
    const unsignedSafeJson = wtx.serializeToSafeJSON();
    const requestId = crypto.randomUUID();
    const request = {
      schema: V7_WALLET_REQUEST_SCHEMA,
      requestId,
      vaultId,
      action,
      contractVersion: CONTRACT_VERSION_V7,
      state: V7WalletRequestState.BUILT,
      signerAddress,
      signerXOnly,
      predecessorOutpoint: userPositionOutpoint,
      predecessorVault: manifestDoc(manifest),
      build,
      txId: build.txId,
      transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
      requiredFeeSompi: build.requiredFeeSompi,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    await saveV7WalletRequest(config, request);
    return request;
  }

  if (action !== "tokenAgentSpend") throwFail(`unknown v0.7 rooted-vault action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  if (manifest.status !== VaultStatus.ACTIVE) throwFail(`vault status is ${manifest.status} — a delegate spend needs ACTIVE`, "BUILD_FAILED");

  const fuel = params.fuel ? params.fuel : null;
  let build;
  try {
    build = buildV7Transaction({
      config,
      contractVersion: CONTRACT_VERSION_V7,
      templateInput: manifest.template,
      stateInput: stateToJsonV7(manifest.live.state),
      action: "tokenAgentSpend",
      params: { ...params, agentPk: signerXOnly },
      chain: {
        predecessorOutpoint: manifest.live.outpoint,
        covenantId: manifest.live.covenantId,
        predecessorValue: manifest.live.state.feeReserve.toString(),
        ...(fuel ? { fuel } : {}),
        tokenPosition: params.tokenPosition
      },
      changeXOnly,
      descriptor: manifest.asset.descriptor,
      templateIndex: manifest.asset.templateIndex
    });
  } catch (e) {
    throw fail(`delegate spend build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  let manifestDocForRequest = null;
  try {
    manifestDocForRequest = buildRootedVaultManifestV7({ build, descriptor: manifest.asset.descriptor });
  } catch {
    /* the manifest layer is signer-visible presentation only; a build that
     * produced valid frozen bytes must never be blocked by a presentation
     * failure — record with no manifest rather than refuse the request */
  }

  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const requestId = crypto.randomUUID();
  const request = {
    schema: V7_WALLET_REQUEST_SCHEMA,
    requestId,
    vaultId,
    action,
    contractVersion: CONTRACT_VERSION_V7,
    state: V7WalletRequestState.BUILT,
    signerAddress,
    signerXOnly,
    predecessorOutpoint: manifest.live.outpoint,
    predecessorStateId: manifest.live.stateId,
    predecessorVault: manifestDoc(manifest),
    build,
    manifest: manifestDocForRequest,
    manifestHash: manifestDocForRequest ? manifestDocForRequest.manifestHash : null,
    redeemScripts: typeof build.vaultRedeemScriptHex === "string" ? { [manifest.live.covenantId]: build.vaultRedeemScriptHex } : {}, // Codex checkpoint 6: successor-script carriage for the delegate path too
    txId: build.txId,
    transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    requiredFeeSompi: build.requiredFeeSompi,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveV7WalletRequest(config, request);
  return request;
}

async function finalizeV7WalletRequest(args) {
  const peek = await loadV7WalletRequest(args.config, args.requestId);
  if (!peek) throwFail(`no request ${args.requestId}`, "REQUEST_NOT_FOUND");
  const vault = await loadManifestV7(args.config, peek.vaultId);
  if (!vault) throwFail(`no vault ${peek.vaultId}`, "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => finalizeV7WalletRequestUnlocked(args));
}
async function finalizeV7WalletRequestUnlocked({ config, requestId, signedSafeJson }) {
  const request = await loadV7WalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== V7WalletRequestState.BUILT) throwFail(`request is ${request.state}, not BUILT`, request.state);
  await assertVaultCompletionAvailable(config, await loadManifestV7(config, request.vaultId), request.requestId);
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = V7WalletRequestState.SIGNATURE_INVALID;
    await saveV7WalletRequest(config, request);
    throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertImmutable(unsigned, signed);

  let finalized;
  try {
    if (request.action === "tokenDeposit") {
      const tokenOwnerSignatureHex = signed.inputs[0]?.signatureScript;
      const fuelSignatureScriptHex = signed.inputs[1]?.signatureScript;
      if (!tokenOwnerSignatureHex || !fuelSignatureScriptHex) throwFail("wallet did not sign every input", "WALLET_REJECTED");
      finalized = finalizeTokenDepositV7({ build: request.build, tokenOwnerSignatureHex, fuelSignatureScriptHex });
    } else {
      const agentSignatureHex = signed.inputs[0]?.signatureScript;
      if (!agentSignatureHex) throwFail("wallet did not sign the agent input", "WALLET_REJECTED");
      const hasFuel = request.build.hasFuelInput === true;
      const fuelIndex = request.build.frozen.inputs.length - 1;
      const fuelSignatureScriptHex = hasFuel ? signed.inputs[fuelIndex]?.signatureScript : undefined;
      if (hasFuel && !fuelSignatureScriptHex) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
      ensureBuildDirV7(config, request.build); // F-03
      finalized = finalizeV7Transaction({ build: request.build, agentSignatureHex, fuelSignatureScriptHex });
    }
  } catch (e) {
    request.state = V7WalletRequestState.SIGNATURE_INVALID;
    await saveV7WalletRequest(config, request);
    throw fail(`finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
  request.state = V7WalletRequestState.SIGNED;
  await saveV7WalletRequest(config, request);
  return request;
}

async function submitV7WalletRequest(args) {
  const peek = await loadV7WalletRequest(args.config, args.requestId);
  if (!peek) throwFail(`no request ${args.requestId}`, "REQUEST_NOT_FOUND");
  const vault = await loadManifestV7(args.config, peek.vaultId);
  if (!vault) throwFail(`no vault ${peek.vaultId}`, "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => submitV7WalletRequestUnlocked(args));
}
async function submitV7WalletRequestUnlocked({ config, requestId, rpc: providedRpc, pollAttempts = 30, pollDelayMs = 2000 }) {
  const request = await loadV7WalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (!["tokenAgentSpend", "tokenDeposit"].includes(request.action)) throwFail(`unsupported v0.7 wallet action ${request.action}`, "UNKNOWN_ACTION");
  return submitDelegateRequest({ config, request, rpc: providedRpc, pollAttempts, pollDelayMs });
}

async function markV7WalletRejected(config, requestId) {
  const peek = await loadV7WalletRequest(config, requestId);
  if (!peek) return null;
  const vault = await loadManifestV7(config, peek.vaultId);
  if (!vault) throwFail(`no vault ${peek.vaultId}`, "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => markV7WalletRejectedUnlocked(config, requestId));
}
async function markV7WalletRejectedUnlocked(config, requestId) {
  const request = await loadV7WalletRequest(config, requestId);
  // A BUILT draft — or a draft that was never finalized/attempted but that an earlier runtime marked
  // RECONCILIATION_REQUIRED (round-8 R8-02) — was never broadcast and may always be withdrawn.
  if (request && (request.state === V7WalletRequestState.BUILT || request.state === "RECONCILIATION_REQUIRED" && neverEffective(request))) {
    request.state = V7WalletRequestState.WALLET_REJECTED;
    await saveV7WalletRequest(config, request);
  } else if (request && request.state === V7WalletRequestState.SIGNED) {
    // A signed request whose transaction another request of this vault completed or attempted (identical bytes, one
    // chain effect) is a same-effect duplicate: withdrawing its record loses nothing and it never guards the vault.
    const all = await listV7WalletRequests(config, { vaultId: request.vaultId });
    if (sameEffectDuplicate(request, all)) {
      const owner = all.find((q) => q.requestId !== request.requestId && String(q.txId).toLowerCase() === String(request.txId).toLowerCase() && hasSubmissionEvidence(q));
      request.state = V7WalletRequestState.WALLET_REJECTED;
      request.error = `withdrawn as a same-effect duplicate of request ${owner?.requestId ?? "(unknown)"} (identical transaction ${request.txId})`;
      await saveV7WalletRequest(config, request);
    }
  }
  return request;
}

module.exports = {
  assertFrozenRequestTransaction,
  hasBoundRootCompletionReceipt,
  neverEffective,
  sameEffectDuplicate,
  hasSubmissionEvidence,
  reconcileDelegateRequests,
  completeProvenRootAction,
  completionReceiptPointer,
  classifyRootRecord,
  COMPLETION_HISTORY_LIMIT,
  verifyRootActionCompletion,
  recordCompletionFailure,
  rootSuccessorTarget,
  RECOVERABLE_ROOT_ACTION_STATES,
  ORG_ROOT_SCHEMA,
  ORG_ROOT_REQUEST_SCHEMA,
  V7_WALLET_REQUEST_SCHEMA,
  RequestState,
  V7WalletRequestState,
  AUTHORITY_MODEL,
  loadOrgRoot,
  saveOrgRoot,
  listOrgRoots,
  loadOrgRootRequest,
  saveOrgRootRequest,
  listOrgRootRequests,
  loadV7WalletRequest,
  saveV7WalletRequest,
  listV7WalletRequests,
  buildRootGenesisRequest,
  buildRootedVaultGenesisRequest,
  buildRootActionRequest,
  getSlotSigningRequest,
  getOrCreateSlotSigningRequest,
  submitSlotSignature,
  submitOrgRootRequestSignature,
  finalizeOrgRootRequest,
  submitOrgRootRequest,
  rejectOrgRootRequest,
  buildV7WalletRequest,
  finalizeV7WalletRequest,
  submitV7WalletRequest,
  markV7WalletRejected,
  assertInitiatingOwner,
  warningsFor,
  templateFieldsFromDescriptor
};
