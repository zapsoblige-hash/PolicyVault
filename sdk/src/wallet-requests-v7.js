"use strict";
const { verifySignedSafeJsonInputs, verifyFinalTransactionInputs } = require("./vm-preflight");
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV7Root, compileExactStateV7 } = require("./contract-compiler-v7");

/* F-03: an evicted compiled-artifact cache entry is recompiled deterministically
 * from the build's own template/state/version; the recompiled directory must
 * be exactly the one the build names (stateId identity) or finalize fails closed. */
function ensureBuildDirV7(config, build) {
  if (kasProfile.isKasBuild(build)) return kasProfile.ensureBuildDirKas(config, build); // v0.7 enablement: a rooted-KAS vault operation riding this pipeline
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
const { assertVaultIdentityFree, withVaultIdentityLock, normalizeVaultId } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): global vault-record uniqueness
const { assertOperationalNetwork, assertGenerationMainnetCreatable, assertGenerationMainnetOperable } = require("./config");
const { parseSompi, parsePositiveSompi, kasToSompi, sompiToKas } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");
const { resolveAddressIdentity, addressForXOnlyPubkey } = require("./address-identity");
const { connectVerified, getAddressUtxos, canonicalDaaScore } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { p2pkScriptHex } = require("./approval-package-v4");
const { claimTransition, claimSubmission, loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
/* RC35-REC-01 / REC-02 / legacy F4 (2026-09-11): shared submit-outcome settlement + observation-only genesis recovery primitives */
const { settleGenesisSubmitError, ensureOwnSubmissionClaim, unobservedRecoveryDisposition, refreshUnobservedGenesis } = require("./genesis-recovery");
const { firstLine } = require("./submission-classification");
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
const { normalizeRegistry, registryEntryToJson, rootPinsFromTemplate, loadManifestV7, persistManifestV7, createManifestV7, MANIFEST_SCHEMA_V7 } = require("./manifest-v7");
const { tokenAgentPolicyToJsonV5 } = require("./agent-merkle-v5"); // rc26 round-7 review R7-02
const { VaultStatus } = require("./manifest");
/* v0.7 mainnet-enablement (2026-09-10): owner operations on a ROOTED KAS SAFE-PAYMENT VAULT ride THIS pipeline (same root
 * M-of-N signing, claims, replayable completion, reconciliation); the vault side is dispatched to the profile adapter by
 * the vault record's schema, and the payment profile's own path stays byte-identical. The adapter never requires this
 * module at load time. */
const kasProfile = require("./rooted-kas-profile-v7");

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
/* A rooted vault of ANY profile this pipeline can carry (payment FROZEN, KAS CANDIDATE) — never a default. */
async function loadRootedVaultAny(config, vaultId) {
  return (await loadManifestV7(config, vaultId)) ?? (await kasProfile.loadManifestV7Kas(config, vaultId));
}
async function classifyVaultRecordAny(config, vaultManifest, request, idx) {
  return kasProfile.isKasVaultRecord(vaultManifest) ? kasProfile.classifyVaultRecord(config, vaultManifest, request, idx, { completedRequestAt }) : classifyVaultRecord(config, vaultManifest, request, idx);
}
async function persistVaultSuccessorAny(config, vaultManifest, request, idx, generation) {
  if (kasProfile.isKasVaultRecord(vaultManifest)) return kasProfile.persistManifestV7Kas(config, kasProfile.expectedVaultSuccessorDoc(config, vaultManifest, request, idx, generation));
  return persistManifestV7(config, expectedVaultSuccessorDoc(config, vaultManifest, request, idx, generation));
}
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

/*
 * RC45 R3N-B1 K2 (contract-03 clarification 01, item 1) — `preferDeep` (the fee input of a ROOT request): an ordinary
 * UTXO at least INPUT_SPENT_WITHDRAWAL_DEPTH_DAA (1,000 DAA) deep — judged against the virtual DAA score read BEFORE the
 * UTXO read, so that it is E1 at build — is preferred when one exists (the largest such). It never refuses for
 * freshness: without such a UTXO, or when that position cannot be read, the largest ordinary UTXO is taken exactly as
 * before. It narrows, and is never claimed to close, the fee path of residual r13(d).
 */
async function autoFuel(config, rpc, signerAddress, minSompi, { preferDeep = false } = {}) {
  let virtualDaa = null;
  if (preferDeep) {
    try {
      const dag = await rpc.getBlockDagInfo();
      virtualDaa = canonicalDaaScore(dag && typeof dag === "object" ? dag.virtualDaaScore : undefined);
    } catch {
      virtualDaa = null;
    }
  }
  const utxos = (await getAddressUtxos(rpc, signerAddress)).filter((u) => u.covenantId === null && u.amount > minSompi).sort((a, b) => (a.amount < b.amount ? 1 : -1));
  if (!utxos.length) throwFail(`no ordinary UTXO > ${minSompi} sompi at ${signerAddress} to pay the network fee — fund the signer address first`, "INSUFFICIENT_FUNDS");
  const deep = virtualDaa === null ? undefined : utxos.find((u) => {
    const d = canonicalDaaScore(u.blockDaaScoreRaw);
    return d !== null && virtualDaa - d >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA;
  });
  const pick = deep ?? utxos[0];
  return { outpoint: pick.outpoint, amount: pick.amount.toString(), scriptPublicKeyHex: pick.scriptPublicKeyHex };
}

async function resolveFuel(config, params, signerAddress, minSompi, { preferDeep = false } = {}) {
  if (params && params.fuel) return params.fuel;
  const { rpc } = await connectVerified(config);
  try {
    return await autoFuel(config, rpc, signerAddress, minSompi, { preferDeep });
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
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_ROOT); // v0.7 enablement: a NEW organizational root is a v0.7-root genesis
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

async function buildRootedVaultGenesisRequest(args) {
  /* RC33-ID-01 (2026-09-11): the build (uniqueness check -> request write) is serialized per vault identity; a malformed
   * identity falls through and is refused exactly as before */
  let vaultId = null;
  try { vaultId = args.vaultId ? normalizeHex(args.vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex"); } catch { vaultId = null; }
  if (vaultId === null) return buildRootedVaultGenesisRequestUnlocked(args);
  return withVaultIdentityLock(vaultId, () => buildRootedVaultGenesisRequestUnlocked({ ...args, vaultId }));
}
async function buildRootedVaultGenesisRequestUnlocked({ config, rootCovenantId, label = "", descriptor, templateIndex = 0, agents = [], recoveryAddress, depositKas, feeReserveKas, signerAddress, funding, vaultId }) {
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
  await assertVaultIdentityFree(config, vId); // RC33-ID-01: an identity held by ANY generation's record or ANY request is refused before anything is built or written
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

/* v0.7 enablement: ONE owner operation on a ROOTED KAS SAFE-PAYMENT VAULT riding this root transition. The same
 * admission rules as the payment branch (root pin, completion availability, the vault op's required root path must be
 * THIS action), then the KAS builder + the KAS org-manifest family through the profile adapter. */
async function buildKasVaultOperation({ config, root, action, op, params, signerAddress, changeForFuel, rootChain, vaultRecord }) {
  try {
    assertGenerationMainnetOperable(config, kasProfile.CONTRACT_VERSION_V7_KAS); // an owner operation MUTATES an existing KAS vault (operable set)
  } catch (e) {
    throw fail(e.message, e.code || "BUILD_FAILED");
  }
  if (!ownGet(kasProfile.OWNER_OP_ACTIONS_KAS, op.action)) throwFail(`unknown rooted-KAS-vault owner action ${JSON.stringify(op.action)} — failing closed`, "UNKNOWN_ACTION");
  /* RC45 L2-01 D7: an UNRESOLVED treasury is refused here, ahead of the completion-availability and root-pin checks
   * (its record describes a predecessor that moved on chain); record-only, nothing is written. */
  await assertTreasuryNotUnresolved(config, vaultRecord);
  await assertVaultCompletionAvailable(config, vaultRecord);
  if (vaultRecord.orgRootCovenantId !== root.rootCovenantId) throwFail("this vault is not pinned to this root", "HOSTED_ORG_IS_NOT_A_ROOT");
  if (!vaultRecord.live) throwFail("this rooted vault has no confirmed on-chain outpoint yet", "ROOT_STALE_OUTPOINT");
  const authority = kasProfile.resolveOwnerOpAuthority(op.action);
  if (authority.rootActionName !== action) throwFail(`${op.action} requires the root to run ${authority.rootActionName}, not ${action}`, "OWNER_PATH_TAKES_NO_SIGNATURE");
  const fuel = await resolveFuel(config, params, signerAddress, 500_000n, { preferDeep: true }); // RC45 R3N-B1 K2: a root request's fee input
  let recordedParams = op.params ?? {};
  let prepared;
  try { prepared = kasProfile.prepareOwnerOpParams(op.action, recordedParams); } catch (e) { throw fail(e.message, e.code || "BUILD_FAILED"); }
  /* RC45 delegate period-start rule (anchor at build; the rule is in manifest-v4.js): a delegate of the new policy set
   * that is not byte-identical in its nine committed fields to the installed leaf with the same key (a new key, a key
   * typed into an installed row, a shortened period, a raised budget, any other changed field) commits periodStartDaa =
   * max(requested, D), D being the configured synced node's canonical virtual DAA score, read also when the fee input is
   * supplied (an unreadable node refuses PERIOD_START_REQUIRED before anything is written); every other field,
   * periodSpent included, is committed as requested. The anchored set is prepared again, so the built call and its agent
   * root, the owners' reviewed policy set, the stored registry and the recorded vault operation all carry the committed
   * starts. Installed delegates the change leaves byte-identical are carried untouched, and a set without a new or
   * changed delegate reads no DAA. */
  const { anchoredLeafPks, anchorRegistryStarts, assertRegistryFoldsToRoot } = require("./manifest-v4"); // the v0.7-kas registry is the v0.4.1 one
  if (op.action === "ownerSetAgentRoot") {
    const installed = kasProfile.manifestDoc(vaultRecord).agentRegistry;
    if (anchoredLeafPks(installed, prepared.newRegistry).length > 0) {
      const anchored = anchorRegistryStarts({ predecessorEntries: installed, nextEntries: prepared.newRegistry, anchorDaa: await require("./chain").readAnchorDaa(config) });
      recordedParams = { ...recordedParams, agents: anchored.entries };
      try { prepared = kasProfile.prepareOwnerOpParams(op.action, recordedParams); } catch (e) { throw fail(e.message, e.code || "BUILD_FAILED"); }
    }
  }
  let build;
  try {
    build = kasProfile.buildOwnerOp({
      config,
      vaultRecord,
      action: op.action,
      params: prepared.opParams,
      fuel,
      root: { template: root.template, state: root.state, outpoint: rootChain.predecessorOutpoint, covenantId: root.rootCovenantId, value: root.live.value },
      changeXOnly: changeForFuel(fuel)
    });
  } catch (e) {
    throw fail(`rooted-KAS-vault owner-op build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }
  /* Registry-to-root integrity: the registry this request stores must fold to exactly the agent root its frozen
   * transaction commits for the vault successor (REGISTRY_ROOT_MISMATCH otherwise; nothing is written). */
  if (op.action === "ownerSetAgentRoot") assertRegistryFoldsToRoot({ entries: prepared.newRegistry, committedAgentRoot: build.successorState?.agentRoot, stage: "build" });
  return { build, vaultRecord, vaultOpEntry: { build }, newRegistry: prepared.newRegistry, recordedParams };
}

/*
 * RC45 L2-01 D6 — THE BUILD-TIME LIVENESS GUARD of a root request (buildRootActionRequestUnlocked, after the manifest is
 * verified and every existing refusal, before the first write). One connection to the configured synced node
 * (connectVerified) and at most one UTXO read per distinct address: every frozen input whose covenant id is the root's
 * or, for a v0.7-kas operation, the treasury's must be reported EXACTLY ONCE at its previous outpoint with the frozen
 * value, the frozen covenant id and, when the node reports them, the frozen script and script version. Otherwise 409
 * RECORDED_OUTPUT_SPENT naming the role and the outpoint; a node that cannot be connected or read refuses with its own
 * error. It never writes and keeps no state: it refuses only while the node does not report the output unspent.
 *
 * What it prevents: recording (and reserving the root with) a root request that spends a root or v0.7-kas treasury
 * output the synced node does not report unspent at build time.
 * What it does not prevent: a spend accepted after this read, or one only in the mempool; a misreporting node; the fee
 * input and v0.7-payment / HD vault inputs (not checked here); a broadcast outside PolicyVault. It does not promise that
 * an output stays unspent after the build.
 */
async function assertRecordedInputsLive(config, { root, build, vaultRecord, isKasOp }) {
  const roles = new Map([[lowerHex(root.rootCovenantId), "root"]]);
  if (isKasOp) roles.set(lowerHex(vaultRecord.live.covenantId), "treasury");
  const guarded = build.frozen.inputs
    .map((input) => ({ input, role: input && input.utxo && input.utxo.covenantId != null ? roles.get(lowerHex(input.utxo.covenantId)) : undefined }))
    .filter((g) => g.role !== undefined);
  const { rpc } = await connectVerified(config);
  try {
    const byAddress = new Map();
    for (const { input, role } of guarded) {
      const address = spkToAddress(config, input.utxo.scriptPublicKey);
      if (!byAddress.has(address)) byAddress.set(address, await getAddressUtxos(rpc, address));
      const why = recordedInputMismatch(input, byAddress.get(address));
      if (why !== null) throw recordedOutputSpent(role, input.previousOutpoint, why);
    }
  } finally {
    await rpc.disconnect();
  }
}
/* null when the node's entries report `input`'s previous outpoint exactly once and exact; otherwise why not */
function recordedInputMismatch(input, refs) {
  const at = refs.filter((r) => sameOutpoint(r.outpoint, input.previousOutpoint));
  if (at.length === 0) return "not reported unspent by the synced node";
  if (at.length > 1) return `reported ${at.length} times by the synced node`;
  const ref = at[0], spk = input.utxo.scriptPublicKey;
  const differences = [];
  if (String(ref.amount) !== String(input.utxo.amount)) differences.push(`value ${ref.amount} (recorded ${input.utxo.amount})`);
  if (ref.covenantId == null || lowerHex(ref.covenantId) !== lowerHex(input.utxo.covenantId)) differences.push(`covenant id ${ref.covenantId ?? "none"}`);
  if (ref.scriptPublicKeyHex != null && lowerHex(ref.scriptPublicKeyHex) !== lowerHex(spk.scriptHex)) differences.push("script");
  if (ref.scriptPublicKeyVersion != null && Number(ref.scriptPublicKeyVersion) !== Number(spk.version ?? 0)) differences.push(`script version ${ref.scriptPublicKeyVersion}`);
  return differences.length ? `reported by the synced node with a different ${differences.join(", ")}` : null;
}
function recordedOutputSpent(role, outpoint, why) {
  const e = fail(`the recorded ${role} output ${describeOutpoint(outpoint)} this request would spend is ${why}. Nothing was recorded and the root is not reserved; press Verify state before building again`, "RECORDED_OUTPUT_SPENT");
  e.status = 409; // a conflict with the recorded chain state (contract D6), never a validation answer
  return e;
}

async function buildRootActionRequest(args) {
  return withOrgRootLock(args.rootCovenantId, () => buildRootActionRequestUnlocked(args));
}
async function buildRootActionRequestUnlocked({ config, rootCovenantId, action, params = {}, vaultOperations = [], signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7_ROOT); // v0.7 enablement: a root action MUTATES an existing root (operable set)
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
  let recordedOpParams = null; // RC45 delegate period-start rule: a rooted-KAS operation records the params it was built from (the committed starts)
  if (vaultOperations.length === 1) {
    const op = vaultOperations[0];
    const anyRecord = await loadRootedVaultAny(config, op.vaultId);
    if (kasProfile.isKasVaultRecord(anyRecord)) {
      ({ build, vaultRecord, vaultOpEntry, newRegistry, recordedParams: recordedOpParams } = await buildKasVaultOperation({ config, root, action, op, params, signerAddress, changeForFuel, rootChain, vaultRecord: anyRecord }));
    } else {
    if (!ownGet(OWNER_OP_ACTIONS, op.action)) throwFail(`unknown rooted-vault owner action ${JSON.stringify(op.action)} — failing closed`, "UNKNOWN_ACTION");
    try { assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7); } catch (e) { throwFail(e.message, e.code || "BUILD_FAILED"); } // the rooted TOKEN profile is not in the mainnet set
    vaultRecord = await loadManifestV7(config, op.vaultId);
    if (!vaultRecord) throwFail(`no rooted vault ${op.vaultId}`, "VAULT_NOT_FOUND");
    await assertVaultCompletionAvailable(config, vaultRecord);
    if (vaultRecord.orgRootCovenantId !== root.rootCovenantId) throwFail("this vault is not pinned to this root", "HOSTED_ORG_IS_NOT_A_ROOT");
    if (!vaultRecord.live) throwFail("this rooted vault has no confirmed on-chain outpoint yet", "ROOT_STALE_OUTPOINT");
    const authority = resolveOwnerOpAuthorityV7(op.action);
    if (authority.rootActionName !== action) {
      throwFail(`${op.action} requires the root to run ${authority.rootActionName}, not ${action}`, "OWNER_PATH_TAKES_NO_SIGNATURE");
    }
    const fuel = await resolveFuel(config, params, signerAddress, 500_000n, { preferDeep: true }); // RC45 R3N-B1 K2: a root request's fee input
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
    }
  } else {
    const fuel = await resolveFuel(config, params, signerAddress, 500_000n, { preferDeep: true }); // RC45 R3N-B1 K2: a root request's fee input
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
  const isKasOp = kasProfile.isKasVaultRecord(vaultRecord);
  const descriptors = vaultRecord && !isKasOp ? { [vaultRecord.live.covenantId]: vaultRecord.asset.descriptor } : {};
  // Codex checkpoint 6 (UX-02 / UX-13): the vault's predecessor redeem script travels with the request so every verifier
  // (this one, the browser boundary, attestations) rebuilds and binds the vault SUCCESSOR script — never skipped.
  const redeemScripts = vaultOpEntry && vaultOpEntry.build && typeof vaultOpEntry.build.vaultRedeemScriptHex === "string" ? { [vaultRecord.live.covenantId]: vaultOpEntry.build.vaultRedeemScriptHex } : {};
  let manifest;
  try {
    manifest = isKasOp ? kasProfile.buildOrgManifest({ build: manifestSourceBuild, vaultOperations: [vaultOpEntry] }) : buildOrgRootIntentManifest({ build: manifestSourceBuild, vaultOperations: vaultOpEntry ? [vaultOpEntry] : [] });
  } catch (e) {
    throw fail(`manifest build failed: ${e.message}`, e.code || "MANIFEST_BUILD_FAILED");
  }
  const verification = isKasOp ? kasProfile.verifyOrgManifest({ manifest, redeemScripts }) : verifyOrgRootIntentManifest({ manifest, descriptors, redeemScripts });
  if (verification.verdict !== "VERIFIED") {
    throw fail(`the built transaction failed org-root manifest verification: ${verification.failures.map((f) => f.name).join(", ")}`, "INTENT_VERIFICATION_FAILED");
  }
  /* RC45 L2-01 D6: after every existing refusal and before the first write, one fresh read of the synced node refuses a
   * request whose root (or v0.7-kas treasury) input the node does not report unspent and exact. */
  await assertRecordedInputsLive(config, { root, build: manifestSourceBuild, vaultRecord, isKasOp });
  /* RC45 R3N-B1 D6b: then every non-root frozen input observed LIVE and exact, with the chain anchor A_b; the marker
   * rides the build's existing first write below (nothing is written on a refusal). */
  const inputObservation = await observeInputsAtBuild(config, { root, build: manifestSourceBuild, isKasOp });

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
    vaultOperations: vaultOpEntry ? [{ vaultId: vaultRecord.vaultId, profile: vaultRecord.contractVersion, action: vaultOperations[0].action, params: recordedOpParams ?? vaultOperations[0].params ?? {}, predecessor: { outpoint: normalizeOutpoint(vaultRecord.live.outpoint, "vault.live.outpoint"), generation: Number(vaultRecord.generation ?? 0), latestTransitionTxId: vaultRecord.latestTransitionTxId ?? null } }] : [],
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
    transaction: { unsignedSafeJson, signInputs: manifestSourceBuild.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    inputObservation // RC45 R3N-B1 D6b marker (optional jsonb member; not attempt evidence, not part of completionReceiptPointer)
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
  await recordExistenceAtSave(config, request); // RC45 R3N-B1 K1' (fail-soft)
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
  await recordExistenceAtSave(config, request); // RC45 R3N-B1 K1' (fail-soft)
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
/* RC33-ID-01 review finding F1 (2026-09-11): the signature and the submission of a genesis are serialized PER VAULT IDENTITY inside the existing root / signer / request lock (lock order unchanged: root / signer / request first, identity inside), so the commit-phase identity check and the signature store / claim / broadcast that follow it form ONE critical section — a pre-correction pair of drafts naming one identity can never double-sign or double-broadcast under concurrency. A request whose identity cannot be normalized falls through to the unlocked body, which refuses it exactly as before. Taken INSIDE the root request lock; only a rooted-vault GENESIS carries a vault identity. */
async function withRootedGenesisIdentityLock(config, requestId, work) {
  const peek = await loadOrgRootRequest(config, requestId);
  let vaultId = null;
  try { vaultId = peek && peek.kind === "rootedVaultGenesis" ? normalizeVaultId(peek.build && peek.build.template && peek.build.template.vaultId) : null; } catch { vaultId = null; }
  return vaultId === null ? work() : withVaultIdentityLock(vaultId, work);
}
async function submitOrgRootRequestSignature(args) {
  return withRootRequestLock(args.config, args.requestId, () => withRootedGenesisIdentityLock(args.config, args.requestId, () => submitOrgRootRequestSignatureUnlocked(args)));
}
async function submitOrgRootRequestSignatureUnlocked({ config, requestId, signedSafeJson, signatureHex, fuelSignatureScriptHex, signerAddress }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.AUTHORIZED) throwFail(`request is ${request.state}, not AUTHORIZED`, request.state);
  await assertRootRequestNotAttempted(config, request);

  if (request.kind === "rootGenesis" || request.kind === "rootedVaultGenesis") {
    if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throwFail("signedSafeJson is required to sign a genesis request", "BAD_SIGNATURE");
    /* RC33-ID-01: a rooted-vault genesis whose identity became occupied is refused before its signature is accepted (stays AUTHORIZED) */
    if (request.kind === "rootedVaultGenesis") await assertVaultIdentityFree(config, request.build.template.vaultId, { exceptRequestId: request.id, exceptTxId: request.txId, phase: "commit" });
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
  await recordExistenceAtSave(config, request); // RC45 R3N-B1 K1' at the save that finalizes a succession (fail-soft)
  await saveOrgRootRequest(config, request);
  return request;
}

/*
 * RC45 delegate period-start rule for a root request whose vault operation is a
 * v0.7-kas ownerSetAgentRoot (a delegate-rule change on a rooted KAS treasury;
 * the rule itself is in manifest-v4.js, required at call time on these paths
 * only). `recorded`: the request's recorded vault operation names it; `built`:
 * its frozen build is that operation. Records this pipeline writes carry both.
 */
function kasDelegateRuleChange(request) {
  const op = request.kind === "rootAction" && Array.isArray(request.vaultOperations) ? request.vaultOperations[0] : null;
  return {
    recorded: !!op && op.profile === kasProfile.CONTRACT_VERSION_V7_KAS && op.action === "ownerSetAgentRoot",
    built: request.kind === "rootAction" && kasProfile.isKasBuild(request.build) && request.build.action === "ownerSetAgentRoot"
  };
}
/* The treasury's installed registry (JSON entries) a delegate-rule change is judged against, or null without a record. */
async function installedKasRegistry(config, request) {
  const vaultId = request.vaultOperations?.[0]?.vaultId;
  const vault = typeof vaultId === "string" ? await kasProfile.loadManifestV7Kas(config, vaultId) : null;
  return vault ? kasProfile.manifestDoc(vault).agentRegistry : null;
}
/*
 * Check at root finalize (M-of-N collection has no expiry, and a finalized
 * request can no longer be withdrawn). Writes nothing. The stored registry
 * must be a list folding to exactly the successor agent root the frozen build
 * commits (REGISTRY_ROOT_MISMATCH otherwise; a missing registry is refused,
 * never skipped) and the treasury record must exist (VAULT_NOT_FOUND), both
 * before any node read. Then, only when the registry holds a leaf that is not
 * byte-identical to the treasury's CURRENT installed leaf with the same key
 * (after the treasury advanced, every leaf it no longer matches), the
 * configured synced node's canonical virtual DAA score is read (unreadable:
 * PERIOD_START_REQUIRED) and such a leaf whose start lags it by more than its
 * window refuses PERIOD_START_STALE. Other operations read nothing.
 */
async function assertKasDelegateRuleStartsFresh(config, request) {
  const { anchoredLeafPks, assertLeafStartsFresh, assertRegistryFoldsToRoot } = require("./manifest-v4"); // the v0.7-kas registry is the v0.4.1 one
  assertRegistryFoldsToRoot({ entries: request.newRegistry, committedAgentRoot: request.build?.successorState?.agentRoot, stage: "root-finalize" });
  const installed = await installedKasRegistry(config, request);
  if (installed === null) throwFail(`no v0.7-kas treasury record ${request.vaultOperations?.[0]?.vaultId} for this delegate-rule change — refusing to finalize it`, "VAULT_NOT_FOUND");
  if (anchoredLeafPks(installed, request.newRegistry).length === 0) return;
  assertLeafStartsFresh({ predecessorEntries: installed, nextEntries: request.newRegistry, currentDaa: await require("./chain").readAnchorDaa(config), stage: "root-finalize" });
}
/*
 * The stale withdrawal's predicate: true only when it can be evaluated and
 * holds — the stored registry is a list, the treasury record exists, some leaf
 * of the registry is not byte-identical to the installed leaf with the same
 * key, and at the node's canonical virtual DAA score read now such a leaf's
 * start lags by more than its window (the finalize check above would refuse
 * PERIOD_START_STALE). It is judged on the stored registry independently of
 * the registry-to-root check: a withdrawal only moves a request into a state
 * that is never effective. Staleness only grows with the network position, so
 * such a request could never have been finalized later. Writes nothing.
 */
async function kasDelegateRuleChangeAgedOut(config, request) {
  const { anchoredLeafPks, assertLeafStartsFresh } = require("./manifest-v4");
  let installed, currentDaa;
  try {
    if (!Array.isArray(request.newRegistry)) return false;
    installed = await installedKasRegistry(config, request);
    if (installed === null || anchoredLeafPks(installed, request.newRegistry).length === 0) return false;
    currentDaa = await require("./chain").readAnchorDaa(config);
  } catch {
    return false;
  }
  try {
    assertLeafStartsFresh({ predecessorEntries: installed, nextEntries: request.newRegistry, currentDaa, stage: "withdrawal" });
  } catch (e) {
    return e?.code === "PERIOD_START_STALE";
  }
  return false;
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
  /* RC45 delegate period-start rule: a v0.7-kas delegate-rule change (named by its recorded operation or by its frozen
   * build) is checked before the final transaction is assembled. A refusal writes nothing: the request stays AUTHORIZED
   * with its owner signatures, and once a delegate's start has aged out it can be withdrawn (rejectOrgRootRequest). */
  const kasRule = kasDelegateRuleChange(request);
  if (kasRule.recorded || kasRule.built) await assertKasDelegateRuleStartsFresh(config, request);
  const isRootOnly = request.build.kind === "orgRootTransition";
  let fin;
  try {
    ensureBuildDirV7(config, request.build); // F-03
    fin = isRootOnly
      ? finalizeV7RootTransaction({ build: request.build, approvals, fuelSignatureScriptHex })
      : kasProfile.isKasBuild(request.build)
        ? kasProfile.finalizeOwnerOp({ build: request.build, approvals, fuelSignatureScriptHex })
        : finalizeV7Transaction({ build: request.build, approvals, fuelSignatureScriptHex });
    verifyFinalTransactionInputs(fin.finalTransaction); // F-04: the assembled M-of-N transaction executes on the real VM before SIGNED
  } catch (e) {
    throw fail(`finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.finalizedTxHex = fin.covenantCallHex;
  request.finalTransaction = fin.finalTransaction;
  request.state = RequestState.SIGNED;
  await recordExistenceAtSave(config, request); // RC45 R3N-B1 K1' (fail-soft)
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
  return withRootRequestLock(args.config, args.requestId, () => withRootedGenesisIdentityLock(args.config, args.requestId, () => submitOrgRootRequestUnlocked(args)));
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
  /* RC35-REC-02 / legacy F4 (2026-09-11): a root genesis or rooted-vault genesis whose node response was lost, whose completion
   * crashed between its records, or that an earlier runtime persisted as a (possibly false) negative is RECOVERED by observation
   * through the SAME public submit entry — never rebuilt, re-signed or rebroadcast; no root record is required beforehand. */
  const recoveringGenesis = (request.kind === "rootGenesis" || request.kind === "rootedVaultGenesis") && GENESIS_RECOVERY_STATES.has(request.state);
  if (recovering && request.state === RequestState.CHAIN_VERIFIED) {
    /* a terminal label is not evidence of complete local state: every durable record is verified before the idempotent return */
    const verified = await verifyRootActionCompletion(config, request);
    if (verified.complete) return request;
  } else if (recoveringGenesis && request.state === RequestState.CHAIN_VERIFIED) {
    const verified = await verifyGenesisCompletion(config, request);
    if (verified.complete) return request; // genesis kinds: idempotent once every durable record is present
  } else if (request.state === RequestState.CHAIN_VERIFIED) {
    return request;
  } else if (!recovering && !recoveringGenesis && request.state !== RequestState.SIGNED) {
    throwFail(`request is ${request.state}, not SIGNED`, request.state);
  }

  try {
    assertOperationalNetwork(config);
    if (recoveringGenesis) assertGenerationMainnetOperable(config, request.kind === "rootGenesis" ? CONTRACT_VERSION_V7_ROOT : CONTRACT_VERSION_V7); // observation of an existing attempt is never a new creation (creation containment keeps recovery operable)
    else if (request.kind === "rootGenesis") assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_ROOT);
    else if (request.kind === "rootedVaultGenesis") assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7);
    else {
      /* v0.7 enablement: submission of a root action mutates EXISTING state — the operable set, per generation of the root AND of every vault operation riding it */
      assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7_ROOT);
      for (const op of request.vaultOperations ?? []) assertGenerationMainnetOperable(config, op.profile ?? CONTRACT_VERSION_V7);
    }
  } catch (e) {
    throw fail(e.message, "NETWORK_MISMATCH");
  }

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");

    if (recovering) return await recoverRootActionRequest({ config, rpc, request });
    if (recoveringGenesis) return request.kind === "rootGenesis" ? await recoverRootGenesisUnlocked({ config, rpc, request, pollAttempts, pollDelayMs }) : await recoverVaultGenesisUnlocked({ config, rpc, request, pollAttempts, pollDelayMs });
    if (request.kind === "rootGenesis") return await submitRootGenesis({ config, rpc, request, pollAttempts, pollDelayMs });
    if (request.kind === "rootedVaultGenesis") return await submitVaultGenesis({ config, rpc, request, pollAttempts, pollDelayMs });
    if (request.kind === "rootAction") return await submitRootAction({ config, rpc, request });
    throw fail(`unknown request kind ${request.kind}`, "UNKNOWN_REQUEST_KIND");
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* ------------------------------------------------------------------ */
/* RC35-REC-02 / legacy F4 (2026-09-11): genesis outcome derivation,   */
/* observation-only recovery and ONE replayable completion             */
/* ------------------------------------------------------------------ */

/* A genesis request in one of these states may already carry a chain effect whose durable records are incomplete: a lost
 * node response (BROADCAST / RECONCILIATION_REQUIRED), a crash between the record write and the request write, or a
 * negative an earlier runtime wrote for an "already accepted" node answer (SUBMISSION_REJECTED — the reviewer's false
 * negative). CHAIN_VERIFIED is included so a terminal label beside missing records is verified, never trusted. */
const GENESIS_RECOVERY_STATES = new Set([RequestState.BROADCAST, RequestState.CHAIN_SEEN, RequestState.RECONCILIATION_REQUIRED, RequestState.SUBMISSION_REJECTED, RequestState.CHAIN_VERIFIED]);

/* The EXACT outcome a ROOT genesis declares, derived from the ORIGINAL verified request and the immutable definitions: the
 * root script is re-derived from the request's template + initial state and must equal the build's script; the frozen
 * output at the root index must pay that script and carry the request's root covenant id. Nothing is trusted from a label. */
function rootGenesisExpected(config, request) {
  const build = request.build;
  if (!build || !build.frozen || !Array.isArray(build.frozen.outputs)) throwFail("the request carries no frozen genesis transaction", "RECONCILIATION_REQUIRED");
  const index = Number(build.rootOutputIndex);
  const out = build.frozen.outputs[index];
  const covenantId = String(request.rootCovenantId ?? "").toLowerCase();
  if (!out || !out.covenant || String(out.covenant.covenantId).toLowerCase() !== covenantId) throwFail("the frozen genesis output does not carry this request's root covenant id", "RECONCILIATION_REQUIRED");
  let compiled;
  try {
    compiled = compileExactStateV7Root({ config, template: build.template, state: build.initialState, contractVersion: request.contractVersion ?? CONTRACT_VERSION_V7_ROOT });
  } catch (e) {
    throwFail(`the root script cannot be re-derived from the request's template and initial state: ${firstLine(e)}`, "RECONCILIATION_REQUIRED");
  }
  if (compiled.scriptHex !== build.rootScriptHex) throwFail("the request's root script differs from the script re-derived from its template and initial state — refusing to complete", "RECONCILIATION_REQUIRED");
  const { covenantAddress } = require("./chain");
  const address = covenantAddress(config, Buffer.from(build.rootScriptHex, "hex"));
  if (spkToAddress(config, out.scriptPublicKey) !== address) throwFail("the frozen root output does not pay the re-derived root script", "RECONCILIATION_REQUIRED");
  return { address, txId: String(request.txId).toLowerCase(), index, value: String(build.accounting.kas.rootValue), covenantId };
}

/* The EXACT outcome a ROOTED-VAULT genesis (v0.7-payment profile) declares, derived the same way. */
function vaultGenesisExpected(config, request) {
  const build = request.build;
  if (!build || !build.frozen || !Array.isArray(build.frozen.outputs)) throwFail("the request carries no frozen genesis transaction", "RECONCILIATION_REQUIRED");
  const index = Number(build.vaultOutputIndex);
  const out = build.frozen.outputs[index];
  const covenantId = String(build.covenantId ?? "").toLowerCase();
  if (!out || !out.covenant || String(out.covenant.covenantId).toLowerCase() !== covenantId) throwFail("the frozen genesis output does not carry this request's vault covenant id", "RECONCILIATION_REQUIRED");
  let compiled;
  try {
    compiled = compileExactStateV7({ config, template: build.template, state: build.initialState, contractVersion: CONTRACT_VERSION_V7 });
  } catch (e) {
    throwFail(`the vault script cannot be re-derived from the request's template and initial state: ${firstLine(e)}`, "RECONCILIATION_REQUIRED");
  }
  if (compiled.scriptSha256 !== build.scriptSha256) throwFail("the request's vault script differs from the script re-derived from its template and initial state — refusing to complete", "RECONCILIATION_REQUIRED");
  const { covenantAddress } = require("./chain");
  const address = covenantAddress(config, Buffer.from(build.vaultScriptHex, "hex"));
  if (spkToAddress(config, out.scriptPublicKey) !== address) throwFail("the frozen vault output does not pay the re-derived vault script", "RECONCILIATION_REQUIRED");
  return { address, txId: String(request.txId).toLowerCase(), index, value: String(out.value), covenantId };
}

/* The signed genesis bytes must reconstruct the request's frozen txid (binds the durable request to what was, or was not,
 * broadcast). Returns the WASM transaction (only the submit path broadcasts it; recovery never does). */
function assertSignedGenesisBinding(config, request) {
  if (typeof request.signedSafeJson !== "string" || !request.signedSafeJson) throwFail("the request carries no signed genesis transaction — nothing was broadcast for it and nothing is constructed here", "RECONCILIATION_REQUIRED");
  const { Transaction } = require("./chain").loadKaspa(config);
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  const signed = JSON.parse(request.signedSafeJson);
  assertImmutable(unsigned, signed);
  verifySignedSafeJsonInputs({ frozenCanonicalJson: request.build.frozenCanonicalJson, signedSafeJson: request.signedSafeJson });
  const transaction = Transaction.deserializeFromSafeJSON(request.signedSafeJson);
  const txId = transaction.finalize().toString().toLowerCase();
  if (txId !== request.txId) throw fail(`reconstructed txid ${txId} != frozen ${request.txId}`, "TXID_MISMATCH");
  return transaction;
}

async function observeGenesisOutcome(rpc, expected, { pollAttempts = 30, pollDelayMs = 2000 } = {}) {
  let proof = null;
  for (let i = 0; i < pollAttempts && !proof; i++) {
    const ref = await findOutpoint(rpc, expected.address, expected.txId, expected.index);
    if (ref && String(ref.covenantId ?? "").toLowerCase() === expected.covenantId && String(ref.amount) === expected.value) proof = ref;
    if (!proof && i + 1 < pollAttempts) await new Promise((r) => setTimeout(r, pollDelayMs));
  }
  return proof;
}

/* The ONLY place a v0.7 genesis is broadcast. Durable claim BEFORE the node call; the node's answer is classified by the shared
 * classifier: an already-known answer is observed like an accepted response; a bound rejection settles the negative ONLY with
 * the expected output verified absent; anything else keeps the claim (RECONCILIATION_REQUIRED). */
async function broadcastSignedGenesis(config, rpc, request, expected) {
  const transaction = assertSignedGenesisBinding(config, request);
  const txId = request.txId;
  await claimSubmission(config, { txId, vaultId: request.rootCovenantId, action: request.kind });
  request.submitStartHash = await require("./submission-outcome-v7").readSubmissionStartHash(rpc);
  request.state = RequestState.BROADCAST;
  await saveOrgRootRequest(config, request);
  let submitted;
  try {
    submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
  } catch (e) {
    const message = firstLine(e);
    request.error = message;
    const settled = await settleGenesisSubmitError({ config, request, rpc, message, txId, expected });
    if (settled.decision === "REJECTED") {
      request.state = RequestState.SUBMISSION_REJECTED;
      request.submissionOutcome = { outcome: RequestState.SUBMISSION_REJECTED, reason: message, txId, proof: settled.proof };
      await saveOrgRootRequest(config, request);
      await releaseSubmissionClaim(config, txId);
      throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
    }
    if (settled.decision === "UNCERTAIN") {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      request.error = `${message} — ${settled.reason}`;
      await saveOrgRootRequest(config, request);
      throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.submissionResponse = { kind: "ALREADY_KNOWN", variant: settled.classification.variant, reason: message, at: new Date().toISOString() };
    await saveOrgRootRequest(config, request);
    return txId;
  }
  const returned = String(submitted.transactionId ?? submitted).toLowerCase();
  if (returned !== txId) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`node returned ${returned}, expected ${txId} — reconcile`, "RECONCILIATION_REQUIRED");
  }
  return txId;
}

/* A genesis receipt binds the original request, its transaction and exact output.
 * Legacy receipts without a fingerprint still require every original pointer;
 * a partial or contradictory modern pointer never falls back. */
function genesisReceiptBinding(request) {
  return crypto.createHash("sha256").update(canonicalJsonStringify(JSON.parse(JSON.stringify({
    id: request.id, kind: request.kind, txId: request.txId, rootCovenantId: request.rootCovenantId,
    networkId: request.networkId, build: request.build, manifest: request.manifest,
    signedSafeJson: request.signedSafeJson
  })))).digest("hex");
}
function genesisReceiptMatches(receipt, request, expected) {
  const entity = request.kind === "rootGenesis" ? request.rootCovenantId : request.build.template.vaultId;
  return !!receipt && receipt.txId === request.txId && receipt.action === request.kind && receipt.vaultId === entity &&
    receipt.proof?.outpoint === `${request.txId}:${expected.index}` && receipt.proof?.covenantId === expected.covenantId &&
    receipt.proof?.requestId === request.id &&
    (!Object.hasOwn(receipt.proof, "genesisFingerprint") || receipt.proof.genesisFingerprint === genesisReceiptBinding(request));
}
async function sameRootGenesisRecord(config, existing, request, expected) {
  if (!existing || existing.schemaVersion !== ORG_ROOT_SCHEMA || !existing.live) return false;
  if (existing.rootCovenantId !== expected.covenantId || existing.networkId !== config.networkId || existing.contractVersion !== CONTRACT_VERSION_V7_ROOT) return false;
  if (existing.orgId !== request.orgId) return false;
  const same = (a, b) => canonicalJsonStringify(JSON.parse(JSON.stringify(a ?? null))) === canonicalJsonStringify(JSON.parse(JSON.stringify(b ?? null)));
  if (!same(existing.template, request.build.template) || !same(existing.rootPins ?? null, request.build.rootPins ?? null)) return false;
  if (sameOutpoint(existing.live.outpoint, { transactionId: expected.txId, index: expected.index })) {
    const slots = activeOwnerSlotsV7(normalizeRootStateV7(request.build.initialState)).map((v) => `${v.slot}:${v.publicKey}`).join(",");
    return existing.generation === 0 && sameRootState(existing.state, request.build.initialState) &&
      String(existing.live.value) === expected.value && existing.live.address === expected.address &&
      (existing.slots ?? []).map((v) => `${v.slot}:${v.publicKey}`).join(",") === slots;
  }
  // A genesis receipt alone says nothing about an arbitrary later outpoint.
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (!genesisReceiptMatches(receipt, request, expected) || !Number.isInteger(existing.generation) || existing.generation < 1) return false;
  const links = await traceRootCompletion(config, existing, request, { rootOutIndex: expected.index });
  return !!links && links.length === existing.generation;
}

/* ONE replayable completion of a PROVEN root genesis: the root record is created ATOMICALLY (create-only) or accepted only
 * as this genesis's own root (never overwritten — a later generation of it stays as it is); receipt and audit are idempotent;
 * the submission claim is released only when it is ours; the request is CHAIN_VERIFIED last. Every step is safe to replay
 * after a crash between any two of them. */
async function finishRootGenesis(config, request, expected, proof, via) {
  const txId = request.txId;
  const held = await getStore(config).read(Categories.SUBMISSION_CLAIM, txId);
  if (held && (held.vaultId !== request.rootCovenantId || held.action !== request.kind)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  const priorReceipt = await getStore(config).read(Categories.RECEIPT, txId);
  if (priorReceipt && !genesisReceiptMatches(priorReceipt, request, expected)) throwFail("genesis receipt does not bind this request and output", "RECONCILIATION_REQUIRED");
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
    live: { outpoint: { transactionId: txId, index: expected.index }, value: request.build.accounting.kas.rootValue, address: expected.address, blockDaaScore: proof.blockDaaScore ? proof.blockDaaScore.toString() : null },
    generation: 0,
    pendingRequestId: null,
    vaults: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  const store = getStore(config);
  const created = await store.createExclusive(Categories.ORG_ROOT, request.rootCovenantId, root);
  let completion = "CREATED";
  if (!created) {
    const existing = await loadOrgRoot(config, request.rootCovenantId); // ROOT_ID_MISMATCH on a mis-keyed record — fail closed
    if (!await sameRootGenesisRecord(config, existing, request, expected)) throwFail(`organizational root ${request.rootCovenantId} holds a different durable record — that record is preserved untouched; this genesis stays on its request (signed transaction, txid, claim) for reconciliation`, "RECONCILIATION_REQUIRED");
    completion = "ALREADY_PRESENT";
  }
  const receipt = await store.read(Categories.RECEIPT, txId);
  if (receipt && !genesisReceiptMatches(receipt, request, expected)) throwFail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  if (!receipt) await persistReceipt(config, { txId, vaultId: request.rootCovenantId, action: "rootGenesis", proof: { outpoint: `${txId}:${expected.index}`, covenantId: request.rootCovenantId, requestId: request.id, genesisFingerprint: genesisReceiptBinding(request) } });
  if (!(await readAudit(config, { vaultId: request.rootCovenantId, txId, limit: 500 })).some((e) => e.action === "rootGenesis" && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, { vaultId: request.rootCovenantId, action: "rootGenesis", actor: "owner", contractVersion: CONTRACT_VERSION_V7_ROOT, txId, result: "CHAIN_VERIFIED", via: via === "submit" ? "org-roots" : `org-roots/${via}` });
  }
  const submission = await store.read(Categories.SUBMISSION_CLAIM, txId);
  if (submission && (submission.vaultId !== request.rootCovenantId || submission.action !== request.kind)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  if (submission) await releaseSubmissionClaim(config, txId);
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = { successorOutpoint: `${txId}:${expected.index}`, observedAt: request.chain?.observedAt ?? new Date().toISOString(), completion: { root: completion, via, completedAt: new Date().toISOString() } };
  await saveOrgRootRequest(config, request);
  return request;
}

/* ONE replayable completion of a PROVEN rooted-vault genesis (v0.7-payment profile): create-only vault record (RC33-ID-01),
 * root membership, idempotent receipt / audit, own-claim release, request CHAIN_VERIFIED last. */
async function finishVaultGenesis(config, request, expected, proof, via) {
  const txId = request.txId;
  const state = normalizeStateV7(request.build.initialState);
  const stateId = computeStateIdV7({ networkId: config.networkId, template: request.build.template, state, contractVersion: CONTRACT_VERSION_V7 });
  /* RC33-ID-01: ATOMIC create-only completion (sdk/src/vault-identity.js) — never read-then-overwrite; a different record of
   * any generation under this identity is preserved and the proven outcome stays on the request for reconciliation */
  let manifest;
  try {
    ({ manifest } = await createManifestV7(config, {
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
      live: { state: stateToJsonV7(state), stateId, outpoint: { transactionId: txId, index: expected.index }, outpointValue: state.feeReserve.toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId, tokenPosition: null },
      creationTxId: txId,
      latestTransitionTxId: null,
      generation: 0
    }));
  } catch (e) {
    if (e.code !== "RECONCILIATION_REQUIRED") throw e;
    /* RC33-ID-01: the identity holds a DIFFERENT record (any generation) — that record is never replaced; the proven chain
     * effect stays on THIS request (signed bytes, txid, submission claim intact) as RECONCILIATION_REQUIRED */
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = `chain effect proven but the vault record could not be created: ${firstLine(e)}`;
    await saveOrgRootRequest(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  const root = await loadOrgRoot(config, request.rootCovenantId);
  if (!root) throwFail("rooted-vault genesis root record is missing", "RECONCILIATION_REQUIRED");
  if (!root.vaults.includes(manifest.vaultId)) {
    root.vaults.push(manifest.vaultId);
    await saveOrgRoot(config, root);
  }
  const store = getStore(config);
  const receipt = await store.read(Categories.RECEIPT, txId);
  if (receipt && !genesisReceiptMatches(receipt, request, expected)) throwFail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  if (!receipt) await persistReceipt(config, { txId, vaultId: manifest.vaultId, action: "rootedVaultGenesis", proof: { outpoint: `${txId}:${expected.index}`, covenantId: request.build.covenantId, requestId: request.id, genesisFingerprint: genesisReceiptBinding(request) } });
  if (!(await readAudit(config, { vaultId: manifest.vaultId, txId, limit: 500 })).some((e) => e.action === "rootedVaultGenesis" && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, { vaultId: manifest.vaultId, action: "rootedVaultGenesis", actor: "owner", contractVersion: CONTRACT_VERSION_V7, txId, result: "CHAIN_VERIFIED", via: via === "submit" ? "org-roots" : `org-roots/${via}` });
  }
  const submission = await store.read(Categories.SUBMISSION_CLAIM, txId);
  if (submission && (submission.vaultId !== request.rootCovenantId || submission.action !== request.kind)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  if (submission) await releaseSubmissionClaim(config, txId);
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = { successorOutpoint: `${txId}:${expected.index}`, observedAt: request.chain?.observedAt ?? new Date().toISOString(), completion: { via, completedAt: new Date().toISOString() } };
  await saveOrgRootRequest(config, request);
  return request;
}

/* Are every durable record of a genesis labelled CHAIN_VERIFIED actually present? (local records only; no node) */
async function verifyGenesisCompletion(config, request) {
  const missing = [];
  assertSignedGenesisBinding(config, request);
  const expected = request.kind === "rootGenesis" ? rootGenesisExpected(config, request) : vaultGenesisExpected(config, request);
  const store = getStore(config);
  const receipt = await store.read(Categories.RECEIPT, request.txId);
  if (await store.read(Categories.SUBMISSION_CLAIM, request.txId)) missing.push("submission claim not finalized");
  if (request.kind === "rootGenesis") {
    const root = await loadOrgRoot(config, request.rootCovenantId).catch(() => null);
    if (!await sameRootGenesisRecord(config, root, request, expected)) missing.push("ORG_ROOT record or completed lineage");
    if (!genesisReceiptMatches(receipt, request, expected)) missing.push("receipt");
    if (!(await readAudit(config, { vaultId: request.rootCovenantId, txId: request.txId, limit: 500 })).some((e) => e.action === "rootGenesis" && e.result === "CHAIN_VERIFIED")) missing.push("audit");
  } else {
    const vaultId = request.build && request.build.template ? request.build.template.vaultId : null;
    const vault = vaultId ? await loadManifestV7(config, vaultId).catch(() => null) : null;
    if (!vault || vault.creationTxId !== request.txId) missing.push("VAULT record");
    const root = await loadOrgRoot(config, request.rootCovenantId).catch(() => null);
    if (!root || !vaultId || !root.vaults.includes(vaultId)) missing.push("root membership");
    if (!genesisReceiptMatches(receipt, request, expected)) missing.push("receipt");
    if (!vaultId || !(await readAudit(config, { vaultId, txId: request.txId, limit: 500 })).some((e) => e.action === "rootedVaultGenesis" && e.result === "CHAIN_VERIFIED")) missing.push("audit");
  }
  return { complete: missing.length === 0, missing };
}

async function submitRootGenesis({ config, rpc, request, pollAttempts = 30, pollDelayMs = 2000 }) {
  const expected = rootGenesisExpected(config, request);
  const txId = await broadcastSignedGenesis(config, rpc, request, expected);
  const proof = await observeGenesisOutcome(rpc, expected, { pollAttempts, pollDelayMs });
  if (!proof) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`root genesis ${txId} submitted but the covenant output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
  }
  return finishRootGenesis(config, request, expected, proof, "submit");
}

async function submitVaultGenesis({ config, rpc, request, pollAttempts = 30, pollDelayMs = 2000 }) {
  /* RC33-ID-01: an occupied identity is refused BEFORE the submission claim and the broadcast — the SIGNED request is left as it is */
  await assertVaultIdentityFree(config, request.build.template.vaultId, { exceptRequestId: request.id, exceptTxId: request.txId, phase: "commit" });
  const expected = vaultGenesisExpected(config, request);
  const txId = await broadcastSignedGenesis(config, rpc, request, expected);
  const proof = await observeGenesisOutcome(rpc, expected, { pollAttempts, pollDelayMs });
  if (!proof) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveOrgRootRequest(config, request);
    throw fail(`vault genesis ${txId} submitted but the covenant output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
  }
  return finishVaultGenesis(config, request, expected, proof, "submit");
}

/* The shared observation-only recovery of a genesis request: derive the expected outcome from the original request, bind
 * the signed bytes to the frozen txid, observe; complete on proof, otherwise keep an ESTABLISHED negative as it is, PROTECT a
 * false / unknown negative (claim re-established, RECONCILIATION_REQUIRED) and leave every other unresolved request unresolved
 * with its claim. A CHAIN_VERIFIED request keeps its label when its output is not observed (the records are replayed only on
 * proof). Nothing is constructed, signed or rebroadcast. */
async function recoverGenesisByObservation({ config, rpc, request, expected, finish, pollAttempts, pollDelayMs, via }) {
  assertSignedGenesisBinding(config, request);
  const fromNegative = request.state === RequestState.SUBMISSION_REJECTED;
  const claim = { txId: request.txId, vaultId: request.rootCovenantId, action: request.kind };
  const proof = await observeGenesisOutcome(rpc, expected, { pollAttempts, pollDelayMs });
  if (!proof) {
    const disposition = await refreshUnobservedGenesis({ config, rpc, request, claim: { txId: request.txId, vaultId: request.rootCovenantId, action: request.kind }, save: (q) => saveOrgRootRequest(config, q) });
    if (disposition.action === "KEEP_NEGATIVE") return request; // an ESTABLISHED negative: unchanged, nothing rebroadcast
    if (request.state === RequestState.CHAIN_VERIFIED) throw fail(`${request.txId} is labelled CHAIN_VERIFIED but its durable records are incomplete and its genesis output ${request.txId}:${expected.index} is not observed unspent at ${expected.address} — prior records are preserved; reconcile`, "RECONCILIATION_REQUIRED");
    await ensureOwnSubmissionClaim(config, claim); // never another operation's claim; idempotent for our own
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = disposition.reason ?? `${request.txId} was broadcast but its genesis output ${request.txId}:${expected.index} is not observed unspent at ${expected.address} — reconcile (nothing is rebroadcast)`;
    await saveOrgRootRequest(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  await ensureOwnSubmissionClaim(config, claim); // every interrupted completion protects its exact operation before writes
  return finish(config, request, expected, proof, via);
}
async function recoverRootGenesisUnlocked({ config, rpc, request, pollAttempts = 30, pollDelayMs = 2000, via = "submit-recovery" }) {
  if (request.kind !== "rootGenesis") throwFail("not a root genesis request", "UNKNOWN_REQUEST_KIND");
  assertSignedGenesisBinding(config, request);
  const expected = rootGenesisExpected(config, request);
  const root = await loadOrgRoot(config, request.rootCovenantId);
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (genesisReceiptMatches(receipt, request, expected) && await sameRootGenesisRecord(config, root, request, expected)) {
    // A spent genesis output can still complete local bookkeeping through fully
    // validated completed transition history. No new signature or broadcast.
    await ensureOwnSubmissionClaim(config, { txId: request.txId, vaultId: request.rootCovenantId, action: request.kind });
    return finishRootGenesis(config, request, expected, { blockDaaScore: null }, via);
  }
  return recoverGenesisByObservation({ config, rpc, request, expected, finish: finishRootGenesis, pollAttempts, pollDelayMs, via });
}
async function recoverVaultGenesisUnlocked({ config, rpc, request, pollAttempts = 30, pollDelayMs = 2000, via = "submit-recovery" }) {
  if (request.kind !== "rootedVaultGenesis") throwFail("not a rooted-vault genesis request", "UNKNOWN_REQUEST_KIND");
  return recoverGenesisByObservation({ config, rpc, request, expected: vaultGenesisExpected(config, request), finish: finishVaultGenesis, pollAttempts, pollDelayMs, via });
}
/* Root genesis requests for a root covenant id that has NO record yet and may be completed by observation (newest first). */
async function listRecoverableRootGenesisRequests(config, rootCovenantId) {
  const all = await listOrgRootRequests(config, { rootCovenantId });
  return all.filter((q) => q.kind === "rootGenesis" && GENESIS_RECOVERY_STATES.has(q.state) && typeof q.signedSafeJson === "string" && q.signedSafeJson);
}

async function submitRootAction({ config, rpc, request }) {
  for (const op of request.vaultOperations ?? []) {
    const vault = await loadRootedVaultAny(config, op.vaultId);
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
  /* RC45 R3N-B1 S1/S2: before the first submit-state write, the 20-deep start A_s and every frozen input (the root input
   * last) are read; a 409 / 422 answer writes nothing and broadcasts nothing; otherwise the C3 route runs from A_s. */
  request.submitStartHash = (await submitInputRead(config, rpc, request)).hash;
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
async function completeProvenRootAction(config, request, { rootOutIndex, rootAddress, rootExpectedValue, rootBlockDaaScore = null, vaultOutIndex = null, rpc = null, via, attribution = null }) {
  let completionStarted = false;
  try {
  assertRequestTransactionBinding(config, request, { attribution });
  /* RC45 L2-01 D3: an ATTRIBUTED completion (a root move broadcast outside PolicyVault): a REPLAY carries the bound marker
   * and takes the marker's mode; a FRESH one carries the in-memory attribution this module issued in D2 (its mode). Every
   * other request (no marker, no in-memory attribution) keeps C3's completion exactly. */
  const attributionMarker = boundAttributionMarker(request);
  const freshAttribution = attributionMarker === null && request.finalTransaction == null && inMemoryAttributionBinds(request, attribution) ? attribution : null;
  let attributedMode = attributionMarker !== null ? attributionMarker.mode : freshAttribution !== null ? freshAttribution.mode : null;
  if (freshAttribution !== null && ownGet(OOB_ATTRIBUTION_TREASURY_STATE, attributedMode) === undefined) throwFail(`the attribution of request ${request.id} names no mode FULL or PARTIAL — nothing is written`, "RECONCILIATION_REQUIRED");
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
    vaultManifest = await loadRootedVaultAny(config, vaultId);
    if (!vaultManifest) throwFail(`no rooted vault ${vaultId} for a proven root action — refusing to record an unrecoverable completion`, "RECONCILIATION_REQUIRED");
    c = await classifyVaultRecordAny(config, vaultManifest, request, idx);
    if (!["PREDECESSOR", "SUCCESSOR", "BEYOND"].includes(c.position)) throwFail(`rooted vault ${vaultId} has no proven dependency history for this request`, "VAULT_STATE_UNEXPECTED");
    /* RC45 C4-03d (C4-03b item check F-01): a REPLAY of a request carrying a BOUND attribution marker whose treasury record
     * stands at its predecessor is not held to the guard below; the attributed section decides from its own reads (a
     * FULL marker re-observes the treasury successor strictly: exact, the treasury follows it; absent, i.e. spent outside
     * PolicyVault since, the marker is downgraded to PARTIAL with the treasury UNRESOLVED; anything else UNSTABLE, nothing
     * written; a PARTIAL marker never writes the treasury). So a PARTIAL upgrade interrupted after its marker write is
     * completed or downgraded by the next Verify also once the root has moved on, instead of every Verify throwing here. */
    const attributedAtPredecessor = attributionMarker !== null && c.position === "PREDECESSOR";
    if (!attributedAtPredecessor && rc.position === "BEYOND" && (c.position === "PREDECESSOR" || c.position === "SUCCESSOR" && !c.consistent) && request.build.successorState !== null) {
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

  /* RC45 L2-01 D3 (contract revision 2 + addendum a item 1), the attributed completion's last inspections and first write,
   * all before completionStarted:
   *   - the treasury T1 at its PREDECESSOR: a FRESH attribution re-observes T1's successor (FULL: exact; PARTIAL: absent)
   *     and a mismatch writes nothing (UNSTABLE); a FULL-marker REPLAY re-observes it and, when it is absent (spent outside
   *     PolicyVault since), downgrades the marker to PARTIAL with T1 UNRESOLVED in ONE save; a PARTIAL-marker REPLAY never
   *     re-observes T1 (an output that reappeared is ignored here: the completing Verify never upgrades; a LATER Verify
   *     may, on fresh evidence — upgradePartialAttributions, writer decision 'PARTIAL upgrade'); this holds with the root
   *     record at A's root successor and with the root record BEYOND it (C4-03d: the historical-continuation guard above
   *     defers to these reads);
   *   - T1 not at its predecessor: no T1 read and no mode change (a FULL completion proceeds on C3's SUCCESSOR path); a
   *     PARTIAL completion requires the predecessor (it never writes T1), else VAULT_STATE_UNEXPECTED, nothing written;
   *   - a FRESH attribution's first durable write is the request carrying the bound marker, RECONCILIATION_REQUIRED
   *     (adopted in memory only after the save resolves). */
  if (attributedMode !== null) {
    if (!hasVaultOp) throwFail(`an attributed completion carries exactly one treasury operation; request ${request.id} carries none — nothing is written`, "RECONCILIATION_REQUIRED");
    if (c.position === "PREDECESSOR") {
      if (freshAttribution !== null || attributionMarker.mode === "FULL") {
        const seen = await observeTreasurySuccessorStrict(config, rpc, request, idx);
        if (freshAttribution !== null) {
          const expected = attributedMode === "FULL" ? "EXACT" : "ABSENT";
          if (seen.outcome !== expected) throwFail(`treasury ${vaultId}'s successor ${request.txId}:${idx} is ${seen.outcome} on re-observation, not ${expected} as attributed — nothing is written; Verify again`, "UNSTABLE");
        } else if (seen.outcome === "ABSENT") {
          const downgraded = { ...request, outOfBandAttribution: { ...attributionMarker, mode: "PARTIAL", modeChangedAt: new Date().toISOString(), treasury: { ...attributionMarker.treasury, state: OOB_ATTRIBUTION_TREASURY_STATE.PARTIAL } } };
          if (boundAttributionMarker(downgraded) === null) throwFail(`the PARTIAL marker of request ${request.id} would not bind — nothing is written`, "RECONCILIATION_REQUIRED");
          await saveOrgRootRequest(config, downgraded);
          Object.assign(request, downgraded);
          attributedMode = "PARTIAL";
        } else if (seen.outcome !== "EXACT") {
          throwFail(`treasury ${vaultId}'s successor ${request.txId}:${idx} is contradictory on re-observation (${seen.reason ?? seen.outcome}) — nothing is written`, "UNSTABLE");
        }
      }
    } else if (attributedMode === "PARTIAL") {
      throwFail(`a PARTIAL attribution never writes the treasury, and treasury ${vaultId} is at ${describeOutpoint(vaultManifest.live ? vaultManifest.live.outpoint : null)}, not this request's predecessor ${describeOutpoint(vaultPredecessor)} — nothing is written`, "VAULT_STATE_UNEXPECTED");
    }
    if (freshAttribution !== null) {
      const marked = {
        ...request,
        state: RequestState.RECONCILIATION_REQUIRED,
        error: `its transaction ${request.txId}, broadcast outside PolicyVault, is attributed to this request at depth ${freshAttribution.depthDaa} DAA (mode ${attributedMode}); completing its durable records`,
        outOfBandAttribution: {
          schema: OOB_ATTRIBUTION_SCHEMA,
          via: "attribution",
          txId: request.txId,
          requestId: request.id,
          observedVirtualDaa: String(freshAttribution.observedVirtualDaa),
          rootEntryDaa: String(freshAttribution.rootEntryDaa),
          depthDaa: String(freshAttribution.depthDaa),
          requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString(),
          mode: attributedMode,
          treasury: { vaultId, predecessorOutpoint: { transactionId: vaultPredecessor.transactionId, index: vaultPredecessor.index }, state: OOB_ATTRIBUTION_TREASURY_STATE[attributedMode] },
          at: new Date().toISOString()
        }
      };
      if (boundAttributionMarker(marked) === null) throwFail(`the attribution marker of request ${request.id} would not bind — nothing is written`, "RECONCILIATION_REQUIRED");
      await saveOrgRootRequest(config, marked);
      Object.assign(request, marked);
    }
  }

  // All inspection prerequisites succeeded. From here, failures represent
  // actual incomplete writes and retain a replayable guard.
  completionStarted = true;
  if (root.pendingRequestId == null) {
    root.pendingRequestId = request.id;
    await saveOrgRoot(config, root);
  }
  /* 1. the vault side first (if any) — validated, replayable */
  if (hasVaultOp) {
    if (attributedMode === "PARTIAL") {
      /* RC45 L2-01 D3: PARTIAL never writes the treasury (its successor output was spent outside PolicyVault); the record
       * stays at the predecessor (checked above) and the treasury is UNRESOLVED, never recovered */
      completion.vault = "UNRESOLVED";
    } else if (c.position === "SUCCESSOR" && c.consistent) {
      completion.vault = "ALREADY_COMPLETE";
    } else if (c.position === "PREDECESSOR") {
      await persistVaultSuccessorAny(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0) + 1);
      completion.vault = "ADVANCED";
    } else if (c.position === "SUCCESSOR") {
      await persistVaultSuccessorAny(config, vaultManifest, request, idx, Number(vaultManifest.generation ?? 0));
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

/* ---- RC45 L2-01: attribution primitives (a root move broadcast outside PolicyVault, attributed to its recorded request) ---- */

/* The depth (the node's virtual DAA score minus the accepting DAA score of the observed root successor entry) such a
 * move must reach before it is attributed: the same 1,000 DAA confirmation depth as SETTLE_DEPTH_DAA in
 * sdk/src/reconcile-v4.js. */
const ATTRIBUTION_DEPTH_DAA = 1000n;
const OOB_ATTRIBUTION_SCHEMA = "policyvault-oob-attribution/1";
/* mode -> the treasury state the marker records: FULL follows the request's treasury successor; a PARTIAL completion
 * never writes the treasury, which is UNRESOLVED until a later Verify freshly observes that successor output exact and
 * unspent at depth (upgradePartialAttributions) */
const OOB_ATTRIBUTION_TREASURY_STATE = Object.freeze({ FULL: "ADVANCED", PARTIAL: "UNRESOLVED" });
const OOB_ATTRIBUTION_REQUEST_STATES = new Set([RequestState.RECONCILIATION_REQUIRED, RequestState.CHAIN_VERIFIED]);

/*
 * STRICT observation of the frozen output `index` of `request` among `refs`, the node's entries for that output's
 * address (the caller reads each distinct address once; this only classifies). EXACT iff exactly one entry carries the
 * request's txid, at `index`, with the frozen value, the frozen covenant id (or none), a REPORTED script equal to the
 * frozen one, and the frozen script version when the node reports one; ABSENT iff no entry carries the txid; anything
 * else under the txid (another index, a second entry, another value, covenant id or script, no reported script) is a
 * CONTRADICTION. frozenOutputObserved above is unchanged.
 */
function observeFrozenOutputStrict(request, index, refs) {
  if (!Array.isArray(refs)) throwFail("the node's entries for an observed address are not a list", "OBSERVATION_ERROR");
  const out = Number.isInteger(index) && index >= 0 && Array.isArray(request?.build?.frozen?.outputs) ? request.build.frozen.outputs[index] : undefined;
  if (!out || !out.scriptPublicKey || typeof request.txId !== "string") return { outcome: "CONTRADICTION", reason: `the request declares no frozen output ${index}` };
  const tx = request.txId.toLowerCase();
  const under = refs.filter((r) => String(r?.outpoint?.transactionId ?? "").toLowerCase() === tx);
  if (under.length === 0) return { outcome: "ABSENT" };
  if (under.length > 1) return { outcome: "CONTRADICTION", reason: `${under.length} entries carry ${tx} at this address` };
  const ref = under[0];
  const covenant = out.covenant && out.covenant.covenantId != null ? String(out.covenant.covenantId).toLowerCase() : null;
  const script = typeof ref.scriptPublicKeyHex === "string" ? ref.scriptPublicKeyHex.toLowerCase() : null;
  const differences = [];
  if (Number(ref.outpoint.index) !== index) differences.push(`index ${ref.outpoint.index}`);
  if (String(ref.amount) !== String(out.value)) differences.push(`value ${ref.amount}`);
  if ((ref.covenantId == null ? null : String(ref.covenantId).toLowerCase()) !== covenant) differences.push(`covenant id ${ref.covenantId ?? "none"}`);
  if (script === null) differences.push("no reported script");
  else if (script !== String(out.scriptPublicKey.scriptHex ?? "").toLowerCase()) differences.push("script");
  if (ref.scriptPublicKeyVersion != null && Number(ref.scriptPublicKeyVersion) !== Number(out.scriptPublicKey.version ?? 0)) differences.push(`script version ${ref.scriptPublicKeyVersion}`);
  if (differences.length) return { outcome: "CONTRADICTION", reason: `the entry ${tx}:${ref.outpoint.index} is not frozen output ${index} (${differences.join(", ")})` };
  return { outcome: "EXACT", entry: ref };
}

/*
 * The attribution marker `outOfBandAttribution` (an optional request field; the request schema is unchanged). It is
 * BOUND — and only a bound marker counts anywhere — iff its schema and via match, it names this request and its txid,
 * the request carries no final transaction, is RECONCILIATION_REQUIRED or CHAIN_VERIFIED and is a v0.7-kas delegate-rule
 * change (recorded and built), and the marker names that operation's treasury and its predecessor outpoint; fail
 * closed besides: its mode is FULL (treasury ADVANCED) or PARTIAL (treasury UNRESOLVED) and its recorded depth meets
 * ATTRIBUTION_DEPTH_DAA. Returns the marker or null; never throws.
 */
function boundAttributionMarker(request) {
  if (!request || typeof request !== "object" || request.kind !== "rootAction") return null;
  const m = ownGet(request, "outOfBandAttribution");
  if (!m || typeof m !== "object" || Array.isArray(m) || m.schema !== OOB_ATTRIBUTION_SCHEMA || m.via !== "attribution") return null;
  if (typeof request.txId !== "string" || m.txId !== request.txId || typeof request.id !== "string" || m.requestId !== request.id) return null;
  if (request.finalTransaction != null || !OOB_ATTRIBUTION_REQUEST_STATES.has(request.state)) return null;
  const rule = kasDelegateRuleChange(request);
  if (!rule.recorded || !rule.built || request.vaultOperations.length !== 1) return null;
  const treasuryState = ownGet(OOB_ATTRIBUTION_TREASURY_STATE, m.mode);
  const t = m.treasury;
  if (treasuryState === undefined || !t || typeof t !== "object" || typeof t.vaultId !== "string" || t.vaultId !== request.vaultOperations[0].vaultId || t.state !== treasuryState) return null;
  try {
    if (!sameOutpoint(normalizeOutpoint(t.predecessorOutpoint, "outOfBandAttribution.treasury.predecessorOutpoint"), vaultPredecessorOutpoint(request))) return null;
  } catch {
    return null;
  }
  const required = canonicalDaaScore(m.requiredDepthDaa), depth = canonicalDaaScore(m.depthDaa);
  if (required !== ATTRIBUTION_DEPTH_DAA || depth === null || depth < ATTRIBUTION_DEPTH_DAA) return null;
  return m;
}

/* An attribution in memory: issued only by this module's own observation of the attributed transaction, never read
 * from a record or a caller's argument (the WeakSet admits only the issued objects). */
const IN_MEMORY_ATTRIBUTIONS = new WeakSet();
function issueInMemoryAttribution(fields) {
  const attribution = Object.freeze({ ...fields });
  IN_MEMORY_ATTRIBUTIONS.add(attribution);
  return attribution;
}
function inMemoryAttributionBinds(request, attribution) {
  if (!attribution || !IN_MEMORY_ATTRIBUTIONS.has(attribution)) return false;
  const rule = kasDelegateRuleChange(request);
  return rule.recorded && rule.built && attribution.requestId === request.id && attribution.txId === request.txId;
}

/*
 * The request-to-transaction binding of a root action (completion and completedRequestAt). With a final transaction:
 * assertFrozenRequestTransaction, unchanged. Without one, only for an in-memory attribution of this request or a bound
 * marker: assertAttributedTransactionBinding. Otherwise assertFrozenRequestTransaction, which refuses a request without
 * a final transaction exactly as before. hasBoundRootCompletionReceipt, submitRootAction and the root negative-outcome
 * settlement keep the strict check.
 */
function assertRequestTransactionBinding(config, request, { attribution = null } = {}) {
  if (request && request.finalTransaction == null && (inMemoryAttributionBinds(request, attribution) || boundAttributionMarker(request) !== null)) {
    return assertAttributedTransactionBinding(config, request);
  }
  return assertFrozenRequestTransaction(config, request);
}

/*
 * The binding of a request WITHOUT a final transaction to the transaction observed on chain. A Kaspa transaction id
 * excludes the signature scripts, so the id recomputed from the frozen bytes must be the request's, its build's and its
 * manifest's; the manifest's frozen canonical JSON must be the frozen bytes'; the one input carrying the root covenant id
 * must spend exactly the request's recorded root predecessor; the manifest must verify; the stored registry must fold
 * to the agent root the frozen transaction commits. Anything else is RECORD_DAMAGED. Reads no node; writes nothing.
 */
function assertAttributedTransactionBinding(config, request) {
  const damaged = (why) => throwFail(`the request's recorded transaction is damaged: ${why} — refusing to bind it to the observed transaction`, "RECORD_DAMAGED");
  let frozen, txId;
  try {
    frozen = normalizeFrozenTxV3(request.build.frozen);
    txId = frozenToWasmTransaction(config, frozen).finalize().toString().toLowerCase();
  } catch (e) {
    damaged(`its frozen bytes cannot be rebuilt (${firstLine(e)})`);
  }
  if (typeof request.txId !== "string" || txId !== request.txId || request.build.txId !== request.txId || request.manifest?.transaction?.txId !== request.txId) {
    damaged("the transaction id recomputed from its frozen bytes, its build's, its manifest's and its own are not all the same");
  }
  if (request.manifest.transaction.frozenCanonicalJson !== canonicalFrozenTxJson(frozen)) damaged("its manifest's frozen canonical JSON is not its frozen bytes'");
  let rootPredecessor;
  try {
    rootPredecessor = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  } catch (e) {
    damaged(`its recorded root predecessor is malformed (${firstLine(e)})`);
  }
  const rootCovenantId = String(request.rootCovenantId ?? "").toLowerCase();
  const rootInputs = frozen.inputs.filter((i) => i.utxo.covenantId !== null && String(i.utxo.covenantId).toLowerCase() === rootCovenantId);
  if (rootInputs.length !== 1 || !sameOutpoint(rootInputs[0].previousOutpoint, rootPredecessor)) damaged(`its root input does not spend exactly its recorded root predecessor ${describeOutpoint(rootPredecessor)}`);
  let verification;
  try {
    verification = kasProfile.verifyOrgManifest({ manifest: request.manifest, redeemScripts: request.redeemScripts ?? {} });
  } catch (e) {
    damaged(`its manifest cannot be verified (${firstLine(e)})`);
  }
  if (!verification || verification.verdict !== "VERIFIED") damaged(`its manifest does not verify (${(verification?.failures ?? []).map((f) => f.name).join(", ")})`);
  try {
    require("./manifest-v4").assertRegistryFoldsToRoot({ entries: request.newRegistry, committedAgentRoot: request.build?.successorState?.agentRoot, stage: "attribution" });
  } catch (e) {
    damaged(`its stored registry does not fold to the committed agent root (${firstLine(e)})`);
  }
}

/* ==================================================================================================================
 * RC45 R3N-B1 — the bounded repair of the B-1 root-wide hold (contract-03: addendum v2b revision 3;
 * writer amendment A1, which prevails over it; writer clarification 01, which prevails over A1). Internal.
 *   D6b  the build-time observation of every non-root frozen input (marker inputObservation) and its chain anchor A_b;
 *   K1'  existence evidence recorded final at the existing slot-request, slot-signature and finalize saves (fail-soft);
 *   S1/S2 the submit read, before the first submit-state write (start A_s, the inputs, this request's own outputs,
 *        existence evidence);
 *   W1-W8 the two-step withdrawal of a finalized, never-attempted request whose input was spent by another transaction,
 *        final at 1,000 DAA below a 20-deep selected-chain anchor.
 * Every read is of the configured synced node. Nothing here broadcasts, settles, releases a claim or adopts spent state.
 * The only writes are the build's existing first write (the marker), the existing slot / finalize saves (K1'), and at
 * withdrawal the request (the anchor, then REFUSED) and the root's pending pointer.
 * ================================================================================================================== */
const INPUT_OBSERVATION_SCHEMA = "policyvault-input-observation/1";
const INPUT_SPENT_OBSERVATION_SCHEMA = "policyvault-input-spent-observation/1";
const INPUT_SPENT_WITHDRAWAL_SCHEMA = "policyvault-input-spent-withdrawal/1";
/* WD-6 constants (B1-14c pins all four). The withdrawal depth is D4's settlement depth (assumption G5). */
const INPUT_SPENT_WITHDRAWAL_DEPTH_DAA = ATTRIBUTION_DEPTH_DAA;
/* the anchor is the sink's 20th selected parent: measured never removed (0/300, 0/120, 0/30) while 33-40% of sinks were */
const CHAIN_ANCHOR_HOPS = 20;
/* withdrawal step 2 is accepted up to 12,000 DAA (about 20 minutes at 10 BPS) after the anchor; it bounds the scan */
const WITHDRAWAL_ANCHOR_MAX_AGE_DAA = 12000n;
/* at most 64 getBlocks batches (up to 15,936 blocks at 10 BPS, above the ~12,050 merged blocks of a 12,000-DAA window) */
const WITHDRAWAL_SCAN_MAX_BATCHES = 64;
const EXISTENCE_PATHS = new Set(["E1", "E1s", "E2", "E3"]);
const HEX64_B1 = /^[0-9a-f]{64}$/;
/* the owner's sentence (criterion 5 of the owner's direction), verbatim */
const WITHDRAWAL_NON_REVOCATION_SENTENCE = "Withdrawal does not revoke signatures or prevent an otherwise valid out-of-app broadcast.";

/* An answer carrying its HTTP status on the error itself, so mapError (server/src/org-roots.js) passes it, and its
 * `extra`, through unchanged. */
function b1Error(message, code, status, extra) {
  const e = fail(message, code);
  e.status = status;
  if (extra !== undefined) e.extra = extra;
  return e;
}
const canonicalDaaString = (value) => typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
const outpointJson = (op) => ({ transactionId: lowerHex(op.transactionId), index: Number(op.index) });
const outpointKeyB1 = (op) => `${lowerHex(op.transactionId)}:${Number(op.index)}`;
/* key-sorted JSON of a stored record (the reload check compares whole records, updatedAt included) */
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

/* ---- §1.1 the selected-chain anchor ---- */

/* the block of a getBlock answer (rusty-kaspa answers { block }) */
const rpcBlockOf = (res) => (res && typeof res === "object" && res.block !== undefined ? res.block : res);
/* getBlock(hash): answered under that hash, on the node's current selected chain (isChainBlock), its header hashing to
 * it through the engine (sdk/src/tx-identity blockHashOfRpcHeader, as ws4's validateRpcBlock); its canonical header DAA.
 * Throws otherwise. */
async function verifiedSelectedChainBlock(config, rpc, hash) {
  const { blockHashOfRpcHeader } = require("./tx-identity");
  const block = rpcBlockOf(await rpc.getBlock({ hash, includeTransactions: false }));
  const vd = block && typeof block === "object" ? block.verboseData : null;
  if (!vd || typeof vd.hash !== "string" || vd.hash.toLowerCase() !== hash) throw new Error(`the node answered block ${hash} under another hash`);
  if (vd.isChainBlock !== true) throw new Error(`block ${hash} is not on the node's selected chain`);
  if (blockHashOfRpcHeader(config, block.header) !== hash) throw new Error(`the header of block ${hash} does not hash to it`);
  const daaScore = canonicalDaaScore(block.header.daaScore);
  if (daaScore === null) throw new Error(`block ${hash} carries a header DAA score that is not canonical`);
  return { hash, daaScore };
}
/*
 * selectedChainAncestor (§1.1): getBlockDagInfo (canonical virtual DAA v, 64-hex sink), then CHAIN_ANCHOR_HOPS
 * selected-parent hops from the sink (each getBlock answered under the requested hash, its 64-hex selectedParentHash
 * the next hash), then the hops' end block verified on the selected chain and bound to its header. Answers
 * { sink, v, hash, daaScore } (daaScore: the anchor's OWN header DAA, never the virtual's). Any error or malformed
 * answer throws; once v was read, the thrown error carries it as `virtualDaa` (D6b keeps v_b, §1.2 read 1).
 */
async function selectedChainAncestor(config, rpc) {
  const dag = await rpc.getBlockDagInfo();
  if (!dag || typeof dag !== "object" || dag.error != null) throw new Error("getBlockDagInfo answered an error or nothing");
  const v = canonicalDaaScore(dag.virtualDaaScore);
  if (v === null) throw new Error("the node's virtual DAA score is not canonical");
  try {
    const sink = typeof dag.sink === "string" ? dag.sink.toLowerCase() : "";
    if (!HEX64_B1.test(sink)) throw new Error("the node's sink is not a 64-hex block hash");
    let hash = sink;
    for (let hop = 0; hop < CHAIN_ANCHOR_HOPS; hop += 1) {
      const block = rpcBlockOf(await rpc.getBlock({ hash, includeTransactions: false }));
      const vd = block && typeof block === "object" ? block.verboseData : null;
      if (!vd || typeof vd.hash !== "string" || vd.hash.toLowerCase() !== hash) throw new Error(`the node answered block ${hash} under another hash`);
      const parent = typeof vd.selectedParentHash === "string" ? vd.selectedParentHash.toLowerCase() : "";
      if (!HEX64_B1.test(parent)) throw new Error(`block ${hash} carries a malformed selected parent`);
      hash = parent;
    }
    const anchor = await verifiedSelectedChainBlock(config, rpc, hash);
    return { sink, v, hash: anchor.hash, daaScore: anchor.daaScore };
  } catch (e) {
    const err = new Error(`the node's selected chain could not be walked: ${firstLine(e)}`);
    err.virtualDaa = v;
    throw err;
  }
}

/* ---- §1.2 classification and roles ---- */

/* LIVE: exactly one entry at the input's previous outpoint with equal amount, null-aware equal covenant id, and equal
 * script and script version wherever reported; ABSENT: no entry; MISMATCH: anything else. (D6's recordedInputMismatch
 * stays as it is: it reports a null covenant id as a difference, correct only for covenant inputs.) */
function classifyFrozenInput(input, refs) {
  const at = refs.filter((r) => sameOutpoint(r.outpoint, input.previousOutpoint));
  if (at.length === 0) return { status: "ABSENT", detail: "not reported unspent by the synced node" };
  if (at.length > 1) return { status: "MISMATCH", detail: `reported ${at.length} times by the synced node` };
  const ref = at[0], spk = input.utxo.scriptPublicKey;
  const differences = [];
  if (String(ref.amount) !== String(input.utxo.amount)) differences.push(`value ${ref.amount} (recorded ${input.utxo.amount})`);
  const frozenCovenant = input.utxo.covenantId == null ? null : lowerHex(input.utxo.covenantId);
  const nodeCovenant = ref.covenantId == null ? null : lowerHex(ref.covenantId);
  if (frozenCovenant !== nodeCovenant) differences.push(`covenant id ${nodeCovenant ?? "none"}`);
  if (ref.scriptPublicKeyHex != null && lowerHex(ref.scriptPublicKeyHex) !== lowerHex(spk.scriptHex)) differences.push("script");
  if (ref.scriptPublicKeyVersion != null && Number(ref.scriptPublicKeyVersion) !== Number(spk.version ?? 0)) differences.push(`script version ${ref.scriptPublicKeyVersion}`);
  return differences.length ? { status: "MISMATCH", detail: `reported by the synced node with a different ${differences.join(", ")}`, entry: ref } : { status: "LIVE", entry: ref };
}
/* roles (§1.2): fee = a null covenant id; root = the root's; treasury = the v0.7-kas vault's (a v0.7-kas operation's only
 * other covenant input); vault = any other non-null, non-root covenant id */
function frozenInputRole(rootCovenantId, kasTreasury, input) {
  const covenant = input && input.utxo && input.utxo.covenantId != null ? lowerHex(input.utxo.covenantId) : null;
  if (covenant === null) return "fee";
  if (covenant === lowerHex(rootCovenantId)) return "root";
  return kasTreasury ? "treasury" : "vault";
}
const requestCarriesKasTreasury = (request) => Array.isArray(request.vaultOperations) && request.vaultOperations[0]?.profile === kasProfile.CONTRACT_VERSION_V7_KAS;
function frozenInputsWithRoles(rootCovenantId, kasTreasury, frozen) {
  return frozen.inputs.map((input, index) => ({ input, index, role: frozenInputRole(rootCovenantId, kasTreasury, input) }));
}
/* E1 at build: v_b and d canonical, v_b - d >= 1,000 */
const deepAtBuild = (virtualDaa, blockDaaScore) => virtualDaa !== null && blockDaaScore !== null && virtualDaa - BigInt(blockDaaScore) >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA;

/* ---- §1.2 D6b ---- */

function feeInputNotLive(g, reason, detail) {
  const what = reason === "ABSENT" ? "not reported unspent" : reason === "MISMATCH" ? "reported with different contents" : "not readable from the node";
  return b1Error(`the fee input ${describeOutpoint(g.input.previousOutpoint)} is ${what} (${detail}). Nothing was recorded and the root is not reserved. Choose another fee input, or build again once it is reported unspent`, "FEE_INPUT_NOT_LIVE", 409, { feeInput: { index: g.index, outpoint: outpointJson(g.input.previousOutpoint), reason, detail: String(detail) } });
}
/*
 * D6b (after D6, before the build's first write; one connection): (1) v_b and A_b (fail-soft: the anchor null on
 * failure, v_b kept if read); (2) one UTXO read per distinct address of every non-root frozen input, in frozen order,
 * each input LIVE or the build is refused, writing nothing (WD-5): a fee input -> 409 FEE_INPUT_NOT_LIVE (ABSENT |
 * MISMATCH | READ_FAILED), a treasury or vault input -> 409 RECORDED_OUTPUT_SPENT through D6's helper, any other read
 * failure -> that error (422); (3) A_b again, header-bound and on the selected chain (fail-soft: else recorded null).
 * A1-3: a null anchor with any non-root input not E1 at build -> 422 OBSERVATION_ERROR, writing nothing. Answers the
 * marker the build's existing first write carries.
 */
async function observeInputsAtBuild(config, { root, build, isKasOp }) {
  const nonRoot = frozenInputsWithRoles(root.rootCovenantId, isKasOp, build.frozen).filter((g) => g.role !== "root");
  const { rpc } = await connectVerified(config);
  try {
    let virtualDaa = null, anchor = null;
    try {
      const a = await selectedChainAncestor(config, rpc);
      virtualDaa = a.v;
      anchor = { hash: a.hash, daaScore: a.daaScore };
    } catch (e) {
      virtualDaa = e && typeof e.virtualDaa === "bigint" ? e.virtualDaa : null;
    }
    const byAddress = new Map();
    const inputs = [];
    for (const g of nonRoot) {
      const address = spkToAddress(config, g.input.utxo.scriptPublicKey);
      if (!byAddress.has(address)) {
        let refs;
        try {
          refs = await getAddressUtxos(rpc, address);
        } catch (e) {
          if (g.role === "fee") throw feeInputNotLive(g, "READ_FAILED", firstLine(e));
          throw e;
        }
        byAddress.set(address, refs);
      }
      const c = classifyFrozenInput(g.input, byAddress.get(address));
      if (c.status !== "LIVE") {
        if (g.role === "fee") throw feeInputNotLive(g, c.status, c.detail);
        throw recordedOutputSpent(g.role, g.input.previousOutpoint, c.detail);
      }
      const d = canonicalDaaScore(c.entry.blockDaaScoreRaw);
      inputs.push({ index: g.index, role: g.role, outpoint: outpointJson(g.input.previousOutpoint), blockDaaScore: d === null ? null : d.toString() });
    }
    if (anchor !== null) {
      try {
        const again = await verifiedSelectedChainBlock(config, rpc, anchor.hash);
        if (again.daaScore !== anchor.daaScore) anchor = null;
      } catch {
        anchor = null;
      }
    }
    if (anchor === null && inputs.some((e) => !deepAtBuild(virtualDaa, e.blockDaaScore))) {
      throw b1Error("the node's chain position could not be read (or its anchor left the selected chain) while an input of this request is less than 1,000 DAA deep, so its existence could not be anchored. Nothing was recorded and the root is not reserved; build again", "OBSERVATION_ERROR", 422);
    }
    return {
      schema: INPUT_OBSERVATION_SCHEMA,
      txId: lowerHex(build.txId),
      virtualDaa: virtualDaa === null ? null : virtualDaa.toString(),
      anchor: anchor === null ? null : { hash: anchor.hash, daaScore: anchor.daaScore.toString() },
      at: new Date().toISOString(),
      inputs
    };
  } finally {
    await rpc.disconnect();
  }
}
/* The bound marker (§1.2 "Bound"), else null. */
function boundInputObservation(request) {
  const m = request && request.inputObservation;
  if (!m || typeof m !== "object" || Array.isArray(m) || m.schema !== INPUT_OBSERVATION_SCHEMA) return null;
  const txId = typeof request.txId === "string" ? request.txId.toLowerCase() : null;
  if (txId === null || typeof m.txId !== "string" || m.txId.toLowerCase() !== txId || typeof request.build?.txId !== "string" || request.build.txId.toLowerCase() !== txId) return null;
  if (m.virtualDaa !== null && !canonicalDaaString(m.virtualDaa)) return null;
  if (m.anchor !== null && !(m.anchor && typeof m.anchor === "object" && typeof m.anchor.hash === "string" && HEX64_B1.test(m.anchor.hash) && canonicalDaaString(m.anchor.daaScore))) return null;
  let expected;
  try {
    expected = frozenInputsWithRoles(request.rootCovenantId, requestCarriesKasTreasury(request), request.build.frozen).filter((g) => g.role !== "root");
  } catch {
    return null;
  }
  if (!Array.isArray(m.inputs) || m.inputs.length !== expected.length) return null;
  for (let i = 0; i < expected.length; i += 1) {
    const e = m.inputs[i];
    if (!e || typeof e !== "object" || e.index !== expected[i].index || e.role !== expected[i].role || !sameOutpoint(e.outpoint, expected[i].input.previousOutpoint)) return null;
    if (e.blockDaaScore !== null && !canonicalDaaString(e.blockDaaScore)) return null;
  }
  return m;
}

/* ---- §1.3 + A1-1 existence evidence ---- */

/* a recorded evidence object { path, block, daaScore, finalAt } (W7a, K1'), parsed; null when malformed */
function parsedExistenceRecord(x) {
  if (!x || typeof x !== "object" || Array.isArray(x) || !EXISTENCE_PATHS.has(x.path) || !canonicalDaaString(x.daaScore)) return null;
  const blockless = x.path === "E1" || x.path === "E1s";
  if (blockless ? x.block !== null : !(typeof x.block === "string" && HEX64_B1.test(x.block))) return null;
  if (x.finalAt !== null && !canonicalDaaString(x.finalAt)) return null;
  return { path: x.path, block: x.block, daaScore: BigInt(x.daaScore), finalAt: x.finalAt === null ? null : BigInt(x.finalAt) };
}
const existenceJson = (x) => ({ path: x.path, block: x.block ?? null, daaScore: x.daaScore.toString(), finalAt: x.finalAt === null ? null : x.finalAt.toString() });
/* outpoint key -> evidence recorded FINAL (finalAt set): K1' entries of the marker, then the anchor's spent entries */
function recordedFinalExistence(marker, spentObservation) {
  const out = new Map();
  for (const e of marker?.inputs ?? []) {
    const x = parsedExistenceRecord(e.existence);
    if (x && x.finalAt !== null) out.set(outpointKeyB1(e.outpoint), x);
  }
  for (const s of spentObservation?.spent ?? []) {
    const x = parsedExistenceRecord(s.existence);
    if (x && x.finalAt !== null) out.set(outpointKeyB1(s.outpoint), x);
  }
  return out;
}
/* one read per observation (a failure memoized as null) */
async function observationRead(ctx, key, read) {
  if (!ctx.cache.has(key)) {
    let value = null;
    try { value = await read(); } catch { value = null; }
    ctx.cache.set(key, value);
  }
  return ctx.cache.get(key);
}
/* the FIRST getVirtualChainFromBlock answer from `startHash`, well-formed as so7's window requires (so7:30, :45) */
async function firstVirtualChainAnswer(rpc, startHash) {
  const r = await rpc.getVirtualChainFromBlock({ startHash, includeAcceptedTransactionIds: true });
  if (!r || typeof r !== "object" || r.error != null) throw new Error("getVirtualChainFromBlock answered an error or nothing");
  const added = r.addedChainBlockHashes, entries = r.acceptedTransactionIds, removed = r.removedChainBlockHashes;
  const hashes = (list) => Array.isArray(list) && list.every((h) => typeof h === "string" && HEX64_B1.test(h)) && new Set(list).size === list.length;
  if (!hashes(added) || !hashes(removed) || !Array.isArray(entries) || entries.length !== added.length) throw new Error("malformed getVirtualChainFromBlock answer");
  for (let i = 0; i < added.length; i += 1) {
    const e = entries[i];
    if (!e || e.acceptingBlockHash !== added[i] || !Array.isArray(e.acceptedTransactionIds) || !e.acceptedTransactionIds.every((id) => typeof id === "string" && HEX64_B1.test(id))) throw new Error("malformed accepted-transaction entry");
  }
  return { added, entries, removed };
}
/* E2, then E3, from the marker's anchor A_b (fail-soft): { path, block, daaScore, finalAt } or { gap } */
async function anchoredExistence(ctx, entry) {
  const anchor = ctx.marker.anchor;
  if (!anchor) return { gap: "ANCHOR_UNAVAILABLE" };
  const ab = anchor.hash, abDaa = BigInt(anchor.daaScore);
  const finalAt = (daa) => (ctx.v - daa >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA ? ctx.v : null);
  const d = entry.blockDaaScore === null ? null : BigInt(entry.blockDaaScore);
  /* E2: d <= DAA(A_b), A_b freshly verified on the selected chain */
  if (d !== null && d <= abDaa) {
    const block = await observationRead(ctx, `block:${ab}`, () => verifiedSelectedChainBlock(ctx.config, ctx.rpc, ab));
    if (block && block.daaScore === abDaa) return { path: "E2", block: ab, daaScore: abDaa, finalAt: finalAt(abDaa) };
  }
  /* E3: the creator F_i accepted by exactly one chain block K' of the first answer from A_b, with nothing removed */
  const answer = await observationRead(ctx, `vcfb:${ab}`, () => firstVirtualChainAnswer(ctx.rpc, ab));
  if (!answer || answer.removed.length > 0) return { gap: "ANCHOR_UNAVAILABLE" };
  const creator = lowerHex(entry.outpoint.transactionId);
  const hits = answer.entries.filter((e) => e.acceptedTransactionIds.some((id) => id === creator));
  if (hits.length !== 1) return { gap: "CREATOR_NOT_LOCATED" };
  const k = hits[0].acceptingBlockHash;
  const block = await observationRead(ctx, `block:${k}`, () => verifiedSelectedChainBlock(ctx.config, ctx.rpc, k));
  if (!block) return { gap: "CREATOR_NOT_LOCATED" };
  return { path: "E3", block: k, daaScore: block.daaScore, finalAt: finalAt(block.daaScore) };
}
/*
 * E(i) of an absent non-root input (§1.3, A1-1): E1 (v_b - d >= 1,000), E1s (a LIVE sibling output of the same creating
 * transaction among this observation's entries, v - d' >= 1,000 with v read before the UTXO reads), evidence recorded
 * final earlier (W7a, K1'), E2, E3. ctx = { config, rpc, v, marker (bound) | null, siblings, recorded, cache }.
 * Answers { path, block, daaScore (the existence block's DAA), finalAt, recorded? } or { gap }. Never throws: any failed
 * or malformed read only makes that path false (WD-1).
 */
async function existenceEvidence(ctx, entry) {
  if (!ctx.marker || !entry) return { gap: "NO_MARKER" };
  try {
    const d = entry.blockDaaScore === null ? null : BigInt(entry.blockDaaScore);
    const vb = ctx.marker.virtualDaa === null ? null : BigInt(ctx.marker.virtualDaa);
    if (vb !== null && d !== null && vb - d >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA) return { path: "E1", block: null, daaScore: d, finalAt: vb };
    const creator = lowerHex(entry.outpoint.transactionId);
    for (const s of ctx.siblings) {
      if (lowerHex(s.outpoint.transactionId) !== creator || Number(s.outpoint.index) === Number(entry.outpoint.index)) continue;
      const ds = canonicalDaaScore(s.blockDaaScoreRaw);
      if (ds !== null && ctx.v - ds >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA) return { path: "E1s", block: null, daaScore: ds, finalAt: ctx.v };
    }
    const recorded = ctx.recorded.get(outpointKeyB1(entry.outpoint));
    if (recorded) return { ...recorded, recorded: true };
    return await anchoredExistence(ctx, entry);
  } catch {
    return { gap: "CREATOR_NOT_LOCATED" };
  }
}

/* ---- A1-2 K1': existence recorded at the existing saves ---- */

/*
 * At the existing slot-request, slot-signature and finalize saves (and a succession's signature save, which finalizes
 * it): for every non-root input of the bound marker without E1 and without evidence recorded final, evaluate E2 and E3
 * from A_b; evidence whose existence block is on the selected chain and at least 1,000 DAA below the virtual DAA read
 * first (the W7a rule) is recorded final in the marker entry's optional `existence`. Fail-soft: it never refuses the
 * save and a failed evaluation records nothing (the marker stays byte-identical). It adds no save.
 */
async function recordExistenceAtSave(config, request) {
  try {
    const marker = boundInputObservation(request);
    if (!marker || !marker.anchor) return;
    const vb = marker.virtualDaa === null ? null : BigInt(marker.virtualDaa);
    const open = marker.inputs.filter((e) => !deepAtBuild(vb, e.blockDaaScore) && !(parsedExistenceRecord(e.existence)?.finalAt != null));
    if (!open.length) return;
    const { rpc } = await connectVerified(config);
    try {
      const v = canonicalDaaScore((await rpc.getBlockDagInfo())?.virtualDaaScore);
      if (v === null) return;
      const ctx = { config, rpc, v, marker, cache: new Map() };
      const found = new Map();
      for (const e of open) {
        const x = await anchoredExistence(ctx, e);
        if (x.path && x.finalAt !== null) found.set(e.index, x);
      }
      if (!found.size) return;
      const next = structuredClone(marker);
      for (const e of next.inputs) if (found.has(e.index)) e.existence = existenceJson(found.get(e.index));
      request.inputObservation = next;
    } finally {
      await rpc.disconnect();
    }
  } catch {
    /* fail-soft (A1-2): nothing is recorded */
  }
}

/* ---- §2 S1/S2 the submit read ---- */

function submitReadAnswer(code, finding, g, { existence = null, existenceGap = null, recorded = false } = {}) {
  const op = describeOutpoint(g.input.previousOutpoint);
  let message;
  if (finding === "CONFLICTING_SPEND") {
    message = `The recorded ${g.role} output ${op} that this finalized request spends is no longer reported unspent, while the root output it spends still is, so this request's own transaction has not spent it: PolicyVault treats it as spent by another transaction. Nothing was recorded or broadcast; the request still reserves the root. Withdraw it (two steps; PolicyVault withdraws only once that spend is final at 1,000 DAA and checks everything again), then press Verify state.`;
    if ((existence === "E2" || existence === "E3") && !recorded) message += " Start the withdrawal while the node still holds the history from this request's build (at least about 30 hours by default); after that PolicyVault can no longer establish that the output existed.";
  } else if (finding === "ROOT_INPUT_NOT_LIVE") {
    message = "The root output this request spends is not reported unspent, and no output of this request's own transaction is observed. Either this request's transaction was broadcast outside PolicyVault and its outputs were already spent, or another root transaction spent the root output; PolicyVault cannot tell which. Nothing was recorded or broadcast. Withdrawal is not available. Press Verify state.";
  } else if (finding === "INPUT_CONTRADICTED") {
    message = `The node reports the ${g.role} input ${op} with a different value, covenant id or script than this request records. Nothing was recorded or broadcast. Withdrawal is not available. Press Verify state.`;
  } else {
    message = `The ${g.role} input ${op} is not reported unspent, and PolicyVault cannot establish that it was created on the selected chain (${existenceGap}). It may still be created, and then this request can be submitted, so PolicyVault does not treat it as spent and does not withdraw the request. Nothing was recorded or broadcast; the request still reserves the root. Submit again once the input is reported unspent, or press Verify state.`;
  }
  return b1Error(message, code, 409, { submitRead: { finding, role: g.role, outpoint: outpointJson(g.input.previousOutpoint), withdrawal: code === "RECORDED_OUTPUT_SPENT" ? "TWO_STEP" : "NONE", existence, existenceGap } });
}
/*
 * S1 (submitRootAction, after the claim check, before the first submit-state write; on the submit's open connection):
 * (a) the start A_s (an unreadable chain position -> 422 OBSERVATION_ERROR); (b) one UTXO read per distinct address of
 * every non-root frozen input in frozen order, then the root input's address LAST (D6-exact); (c) only when some input
 * is not LIVE, one read per distinct frozen-output address (OWN: any entry under X, exact or not); (d) only for a row-5
 * candidate, existence of the absent non-root inputs. S2: every input LIVE, or OWN -> answers A_s (the C3 route); else
 * 409 SUBMIT_INPUT_UNRESOLVED (ROOT_INPUT_NOT_LIVE | INPUT_CONTRADICTED | INPUT_EXISTENCE_UNPROVEN) or 409
 * RECORDED_OUTPUT_SPENT (CONFLICTING_SPEND, TWO_STEP); a node error in (a)-(c) -> that error (422). Writes nothing.
 */
async function submitInputRead(config, rpc, request) {
  let start;
  try {
    start = await selectedChainAncestor(config, rpc);
  } catch (e) {
    throw b1Error(`the node's chain position could not be read (${firstLine(e)}); nothing was recorded or broadcast`, "OBSERVATION_ERROR", 422);
  }
  const all = frozenInputsWithRoles(request.rootCovenantId, requestCarriesKasTreasury(request), request.build.frozen);
  const nonRoot = all.filter((g) => g.role !== "root"), rootInputs = all.filter((g) => g.role === "root");
  const siblings = [];
  const byAddress = new Map();
  for (const g of nonRoot) {
    const address = spkToAddress(config, g.input.utxo.scriptPublicKey);
    if (!byAddress.has(address)) {
      const refs = await getAddressUtxos(rpc, address);
      byAddress.set(address, refs);
      siblings.push(...refs);
    }
    g.observed = classifyFrozenInput(g.input, byAddress.get(address));
  }
  const rootRefs = new Map();
  for (const g of rootInputs) {
    const address = spkToAddress(config, g.input.utxo.scriptPublicKey);
    if (!rootRefs.has(address)) {
      const refs = await getAddressUtxos(rpc, address);
      rootRefs.set(address, refs);
      siblings.push(...refs);
    }
    const refs = rootRefs.get(address);
    g.observed = recordedInputMismatch(g.input, refs) === null ? { status: "LIVE" } : { status: classifyFrozenInput(g.input, refs).status === "ABSENT" ? "ABSENT" : "MISMATCH" };
  }
  const rootLive = rootInputs.length > 0 && rootInputs.every((g) => g.observed.status === "LIVE");
  if (rootLive && nonRoot.every((g) => g.observed.status === "LIVE")) return start; // row 1
  const X = lowerHex(request.txId);
  let own = false;
  for (const address of [...new Set(request.build.frozen.outputs.map((o) => spkToAddress(config, o.scriptPublicKey)))]) {
    if ((await getAddressUtxos(rpc, address)).some((r) => lowerHex(r.outpoint.transactionId) === X)) own = true;
  }
  if (own) return start; // row 2: this request's own transaction (the GAP-16 route)
  if (!rootLive) throw submitReadAnswer("SUBMIT_INPUT_UNRESOLVED", "ROOT_INPUT_NOT_LIVE", rootInputs.find((g) => g.observed.status !== "LIVE") ?? { role: "root", input: { previousOutpoint: request.manifest.root.outpoint } }); // row 3
  const contradicted = nonRoot.find((g) => g.observed.status === "MISMATCH");
  if (contradicted) throw submitReadAnswer("SUBMIT_INPUT_UNRESOLVED", "INPUT_CONTRADICTED", contradicted); // row 4
  const marker = boundInputObservation(request);
  /* E(i) includes evidence an earlier withdrawal step (W7a) or save (K1') recorded final (§1.3) */
  const ctx = { config, rpc, v: start.v, marker, siblings, recorded: recordedFinalExistence(marker, boundSpentObservation(request)), cache: new Map() };
  let firstGap = null;
  for (const g of nonRoot.filter((h) => h.observed.status === "ABSENT")) {
    const x = await existenceEvidence(ctx, marker ? marker.inputs.find((e) => e.index === g.index) : null);
    if (x.path) throw submitReadAnswer("RECORDED_OUTPUT_SPENT", "CONFLICTING_SPEND", g, { existence: x.path, recorded: x.recorded === true }); // row 5
    if (firstGap === null) firstGap = { g, gap: x.gap };
  }
  throw submitReadAnswer("SUBMIT_INPUT_UNRESOLVED", "INPUT_EXISTENCE_UNPROVEN", firstGap.g, { existenceGap: firstGap.gap }); // row 6
}

/* ---- §4 W1-W8 the withdrawal ---- */

/* the bound anchor field (W6 "Anchor field"), else null */
function boundSpentObservation(request) {
  const m = request && request.inputSpentObservation;
  if (!m || typeof m !== "object" || Array.isArray(m) || m.schema !== INPUT_SPENT_OBSERVATION_SCHEMA || m.requestId !== request.id) return null;
  if (typeof m.txId !== "string" || typeof request.txId !== "string" || m.txId.toLowerCase() !== request.txId.toLowerCase()) return null;
  if (!m.anchor || typeof m.anchor !== "object" || typeof m.anchor.hash !== "string" || !HEX64_B1.test(m.anchor.hash) || !canonicalDaaString(m.anchor.daaScore)) return null;
  if (!canonicalDaaString(m.virtualDaa) || typeof m.at !== "string" || !m.at) return null;
  if (!Array.isArray(m.spent) || m.spent.length === 0) return null;
  let nonRoot;
  try {
    nonRoot = frozenInputsWithRoles(request.rootCovenantId, requestCarriesKasTreasury(request), request.build.frozen).filter((g) => g.role !== "root");
  } catch {
    return null;
  }
  for (const s of m.spent) {
    const g = s && typeof s === "object" ? nonRoot.find((h) => h.index === s.index) : undefined;
    if (!g || g.role !== s.role || !sameOutpoint(g.input.previousOutpoint, s.outpoint) || parsedExistenceRecord(s.existence) === null) return null;
  }
  return m;
}
/* the bound withdrawal record (W8's trigger), written only by W7b */
function boundSpentWithdrawal(request) {
  const m = request && request.inputSpentWithdrawal;
  return Boolean(m && typeof m === "object" && !Array.isArray(m) && m.schema === INPUT_SPENT_WITHDRAWAL_SCHEMA && m.requestId === request.id
    && typeof m.txId === "string" && typeof request.txId === "string" && m.txId.toLowerCase() === request.txId.toLowerCase()
    && m.anchor && typeof m.anchor === "object" && typeof m.anchor.hash === "string" && HEX64_B1.test(m.anchor.hash) && canonicalDaaString(m.anchor.daaScore));
}
/* the existing withdrawal tail: release the root's reservation when it names this request */
async function releaseRootReservation(config, request) {
  const root = await loadOrgRoot(config, request.rootCovenantId);
  if (root && root.pendingRequestId === request.id) {
    root.pendingRequestId = null;
    await saveOrgRoot(config, root);
  }
}
function withdrawalPending(anchorDaa, anchorWritten) {
  const earliest = anchorDaa + INPUT_SPENT_WITHDRAWAL_DEPTH_DAA, latest = anchorDaa + WITHDRAWAL_ANCHOR_MAX_AGE_DAA;
  return b1Error(`withdrawal pending: ${anchorWritten ? "this step recorded only its chain anchor" : "nothing was written"}. The request stays finalized and still reserves the root; withdraw again from DAA ${earliest} to DAA ${latest}, when PolicyVault observes everything again and withdraws only if the spend of its input is then final at 1,000 DAA. ${WITHDRAWAL_NON_REVOCATION_SENTENCE}`, "WITHDRAWAL_DEPTH_PENDING", 409, { earliestDaa: earliest.toString(), latestDaa: latest.toString() });
}
/* W1's record preconditions (no node read): { P, rootInput, marker } when they all hold, else { why } */
async function spentInputWithdrawalRecordGap(config, request) {
  if (request.kind !== "rootAction") return { why: "it is not a root request" };
  if (request.state !== RequestState.SIGNED) return { why: `it is ${request.state}, not SIGNED` };
  if (!request.finalTransaction) return { why: "it carries no final transaction" };
  try {
    assertFrozenRequestTransaction(config, request);
  } catch (e) {
    return { why: `its final transaction does not bind its frozen bytes and txid (${firstLine(e)})` };
  }
  if (await rootRequestHasAttemptEvidence(config, request)) return { why: "it carries submission evidence (resume its reconciliation instead)" };
  /* the root binding: exactly one frozen input carries the root covenant id and it spends manifest.root.outpoint, which
   * is the root record's live outpoint (the predicate inside assertAttributedTransactionBinding, applied to B) */
  const rootCovenantId = lowerHex(request.rootCovenantId);
  const rootInputs = request.build.frozen.inputs.filter((i) => i && i.utxo && i.utxo.covenantId != null && lowerHex(i.utxo.covenantId) === rootCovenantId);
  const P = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  if (rootInputs.length !== 1 || !sameOutpoint(rootInputs[0].previousOutpoint, P)) return { why: "its frozen root input does not spend exactly its recorded root predecessor" };
  const root = await loadOrgRoot(config, request.rootCovenantId);
  if (!root || !sameOutpoint(root.live?.outpoint, P)) return { why: "the root record no longer names its root predecessor as live" };
  const marker = boundInputObservation(request);
  if (!marker) return { why: "it carries no bound build-time input observation (built before this release, or damaged)" };
  return { P, rootInput: rootInputs[0], marker };
}
/*
 * W2-W7 (a SIGNED request only, A1-4). W1 record preconditions, else CANNOT_REJECT RECORD. One connection, then: r0 the
 * anchor A (a 20-deep selected-chain ancestor); r1 the root input P LIVE and D6-exact; r2 the other input addresses (any
 * MISMATCH -> INPUT_CONTRADICTED; none absent -> INPUTS_LIVE; Ê = the absent ones with existence evidence, empty ->
 * INPUT_EXISTENCE_UNPROVEN); r3 X's mempool entry (an exact miss or orphan-only); r4 P again, the same entry; r5 every
 * frozen-output address, no entry under X. Any node error -> NODE_ERROR. Every refusal writes nothing. W6: no bound
 * anchor -> record it (W7a), pending; age < 1,000 -> pending, nothing written; age > 12,000 -> renew; the continuing set
 * K (anchored inputs of Ê whose existence block lies at or below A1 and 1,000 DAA below v) empty -> renew; the
 * acceptance window from A1 throwing or incomplete -> renew, accepting X -> ACCEPTED_IN_WINDOW; the block scan from A1
 * throwing -> SCAN_UNCLEAR, incomplete or naming any spender other than X (inclusion, not acceptance) -> renew;
 * otherwise W7b: REFUSED with inputSpentWithdrawal, then the reservation released. A reload check precedes every save.
 */
async function withdrawSpentInputRequest(config, request, reason) {
  const loadedJson = stableJson(request);
  const cannot = (finding, why) => b1Error(`this finalized request cannot be withdrawn: ${why}. Nothing was written`, "CANNOT_REJECT", 409, { withdrawal: { finding } });
  let record;
  try {
    record = await spentInputWithdrawalRecordGap(config, request);
  } catch (e) {
    record = { why: `its record cannot be checked (${firstLine(e)})` };
  }
  if (!record.marker) throw cannot("RECORD", record.why);
  const { P, rootInput, marker } = record;
  const X = lowerHex(request.txId);
  let rpc;
  try {
    ({ rpc } = await connectVerified(config));
  } catch (e) {
    throw cannot("NODE_ERROR", `the configured node could not be used (${firstLine(e)})`);
  }
  try {
    const read = async (what, fn) => {
      try {
        return await fn();
      } catch (e) {
        throw cannot("NODE_ERROR", `the node could not be read (${what}: ${firstLine(e)})`);
      }
    };
    /* r0 */
    const A = await read("the chain anchor", () => selectedChainAncestor(config, rpc));
    /* r1 */
    const rootAddress = spkToAddress(config, rootInput.utxo.scriptPublicKey);
    const r1 = await read("the root output", () => getAddressUtxos(rpc, rootAddress));
    if (recordedInputMismatch(rootInput, r1) !== null) throw cannot("ROOT_INPUT_NOT_LIVE", "the root output it spends is not reported unspent and exact (its own transaction or another root transaction may have spent it); press Verify state");
    const p1 = r1.find((r) => sameOutpoint(r.outpoint, P));
    /* r2 */
    const siblings = [...r1];
    const byAddress = new Map([[rootAddress, r1]]);
    const nonRoot = frozenInputsWithRoles(request.rootCovenantId, requestCarriesKasTreasury(request), request.build.frozen).filter((g) => g.role !== "root");
    for (const g of nonRoot) {
      const address = spkToAddress(config, g.input.utxo.scriptPublicKey);
      if (!byAddress.has(address)) {
        const refs = await read(`the ${g.role} input`, () => getAddressUtxos(rpc, address));
        byAddress.set(address, refs);
        siblings.push(...refs);
      }
      g.observed = classifyFrozenInput(g.input, byAddress.get(address));
    }
    if (nonRoot.some((g) => g.observed.status === "MISMATCH")) throw cannot("INPUT_CONTRADICTED", "an input it spends is reported with contents other than those it records");
    const absent = nonRoot.filter((g) => g.observed.status === "ABSENT");
    if (!absent.length) throw cannot("INPUTS_LIVE", "every input it spends is reported unspent: submit it");
    const anchorRecord = boundSpentObservation(request);
    const ctx = { config, rpc, v: A.v, marker, siblings, recorded: recordedFinalExistence(marker, anchorRecord), cache: new Map() };
    const evidenced = [];
    for (const g of absent) {
      const x = await existenceEvidence(ctx, marker.inputs.find((e) => e.index === g.index));
      if (x.path) evidenced.push({ g, x });
    }
    if (!evidenced.length) throw cannot("INPUT_EXISTENCE_UNPROVEN", "PolicyVault cannot establish that the input reported spent was created on the selected chain, so it does not treat it as spent");
    /* r3 */
    const { isExactMempoolMiss, classifyMempoolEntry, locateSpendingTransaction } = require("./wallet-submit-v4");
    const { transactionIdOfRpcBody, blockHashOfRpcHeader } = require("./tx-identity");
    const identityOf = (body) => transactionIdOfRpcBody(config, body);
    const headerHashOf = (header) => blockHashOfRpcHeader(config, header);
    let mempool = null, miss = false;
    try {
      mempool = await rpc.getMempoolEntry({ transactionId: X, includeOrphanPool: true, filterTransactionPool: false });
    } catch (e) {
      if (!isExactMempoolMiss(e, X)) throw cannot("NODE_ERROR", `the node could not be read (the mempool: ${firstLine(e)})`);
      miss = true;
    }
    if (!miss) {
      if (classifyMempoolEntry(mempool, X, identityOf) !== "PRESENT") throw cannot("MEMPOOL_UNCLEAR", "the node's mempool answer for its transaction is not clear");
      const entry = mempool.entry !== undefined ? mempool.entry : mempool.mempoolEntry;
      if (typeof entry.isOrphan !== "boolean") throw cannot("MEMPOOL_UNCLEAR", "the node's mempool answer for its transaction is not clear");
      if (entry.isOrphan === false) throw cannot("IN_TRANSACTION_POOL", "its transaction is in the node's transaction pool");
    }
    /* r4 */
    const r4 = await read("the root output again", () => getAddressUtxos(rpc, rootAddress));
    if (recordedInputMismatch(rootInput, r4) !== null || !sameObservedEntry(p1, r4.find((r) => sameOutpoint(r.outpoint, P)))) throw cannot("UNSTABLE", "the root output it spends changed during the observation");
    /* r5 */
    for (const address of [...new Set(request.build.frozen.outputs.map((o) => spkToAddress(config, o.scriptPublicKey)))]) {
      const refs = await read("an output address", () => getAddressUtxos(rpc, address));
      if (refs.some((r) => lowerHex(r.outpoint.transactionId) === X)) throw cannot("OWN_OUTPUT", "an output of its own transaction is observed: submit it, then press Verify state");
    }
    /* W7: the reload check before every save */
    const reloadUnchanged = async () => {
      let changed;
      try {
        const fresh = await loadOrgRootRequest(config, request.id);
        const root = await loadOrgRoot(config, request.rootCovenantId);
        changed = !fresh || stableJson(fresh) !== loadedJson || fresh.state !== RequestState.SIGNED || await rootRequestHasAttemptEvidence(config, fresh) || !root || !sameOutpoint(root.live?.outpoint, P);
      } catch {
        changed = true;
      }
      if (changed) throw cannot("STORE_CHANGED", "the request or its root changed during the observation");
    };
    /* W7a: record (or renew) the anchor from r0 and Ê; evidence recorded final for an outpoint is carried */
    const renew = async () => {
      await reloadUnchanged();
      request.inputSpentObservation = {
        schema: INPUT_SPENT_OBSERVATION_SCHEMA,
        requestId: request.id,
        txId: X,
        anchor: { hash: A.hash, daaScore: A.daaScore.toString() },
        virtualDaa: A.v.toString(),
        at: new Date().toISOString(),
        spent: evidenced.map(({ g, x }) => ({ index: g.index, role: g.role, outpoint: outpointJson(g.input.previousOutpoint), existence: existenceJson(x) }))
      };
      await saveOrgRootRequest(config, request);
      return withdrawalPending(A.daaScore, true);
    };
    /* W6 */
    if (anchorRecord === null) throw await renew(); // step 1
    const A1 = { hash: anchorRecord.anchor.hash, daaScore: BigInt(anchorRecord.anchor.daaScore) };
    const age = A.v - A1.daaScore; // A1's own header DAA, never getBlockDagInfo's
    if (age < INPUT_SPENT_WITHDRAWAL_DEPTH_DAA) throw withdrawalPending(A1.daaScore, false); // step 2
    if (age > WITHDRAWAL_ANCHOR_MAX_AGE_DAA) throw await renew(); // step 3
    /* step 4: the continuing set, each existence block at or below A1 and at least 1,000 DAA below v */
    const continuing = evidenced.filter(({ g, x }) => anchorRecord.spent.some((s) => sameOutpoint(s.outpoint, g.input.previousOutpoint)) && x.daaScore <= A1.daaScore && A.v - x.daaScore >= INPUT_SPENT_WITHDRAWAL_DEPTH_DAA);
    if (!continuing.length) throw await renew();
    /* step 5: the acceptance window from A1 (no reorganization allowance) */
    let window;
    try {
      window = await require("./submission-outcome-v7").acceptanceWindow(rpc, A1.hash, X);
    } catch {
      throw await renew();
    }
    if (!window.complete) throw await renew();
    if (window.accepted) throw cannot("ACCEPTED_IN_WINDOW", "its transaction is accepted on the selected chain after the anchor; press Verify state");
    /* step 6: the block scan from A1 (inclusion counts as spending, WD-9) */
    let scan;
    try {
      scan = await locateSpendingTransaction(rpc, { lowHash: A1.hash, sinkHash: window.sink, outpoints: request.build.frozen.inputs.map((i) => i.previousOutpoint), maxBatches: WITHDRAWAL_SCAN_MAX_BATCHES, identityOf, headerHashOf });
    } catch (e) {
      throw cannot("SCAN_UNCLEAR", `the block scan after the anchor is not clear (${firstLine(e)})`);
    }
    if (!scan.complete || scan.spenders.some((s) => lowerHex(s.txId) !== X)) throw await renew();
    /* W7b */
    await reloadUnchanged();
    request.state = RequestState.REFUSED;
    request.error = typeof reason === "string" ? reason : null;
    request.inputSpentWithdrawal = {
      schema: INPUT_SPENT_WITHDRAWAL_SCHEMA,
      requestId: request.id,
      txId: X,
      anchor: { hash: A1.hash, daaScore: A1.daaScore.toString() },
      withdrawnAt: new Date().toISOString(),
      observedVirtualDaa: A.v.toString(),
      depthDaa: age.toString(),
      sink: window.sink,
      spent: continuing.map(({ g, x }) => ({ index: g.index, role: g.role, outpoint: outpointJson(g.input.previousOutpoint), existence: existenceJson(x) })),
      windowBlocks: window.blocks,
      scanBlocks: scan.blocks,
      scanBatches: scan.batches
    };
    await saveOrgRootRequest(config, request);
  } finally {
    await rpc.disconnect();
  }
  await releaseRootReservation(config, request);
  return request;
}
/* ==================================================================================================================
 * end of RC45 R3N-B1
 * ================================================================================================================== */

/* ---- RC45 L2-01: attribution (D1/D2), attributed completion entry (D3), settlement (D4), holds after settlement (D4b),
 *      the settlement hook (D4 ii) and the replay answer keyed on the bound marker (addendum a item 5) ---- */

const ATTRIBUTION_CANDIDATE_CAP = 64;
/* a FRESH attributable request: never finalized, never attempted, withdrawn or still awaiting finalize */
const ATTRIBUTION_FRESH_STATES = new Set([RequestState.AUTHORIZED, RequestState.REFUSED]);
/* root requests S != A on the spent root outpoint P that settlement may prove SUPERSEDED */
const SETTLEABLE_ROOT_REQUEST_STATES = new Set([RequestState.AUTHORIZED, RequestState.SIGNED, RequestState.BROADCAST, RequestState.CHAIN_SEEN, RequestState.RECONCILIATION_REQUIRED]);
/* a terminal request on P whose reservation (the root's pending pointer) settlement may finish releasing */
const FINISHABLE_POINTER_STATES = new Set(["SUPERSEDED", "SUBMISSION_REJECTED", "NOT_BROADCAST", "REFUSED", "STALE", "FAILED"]);
const NODE_READ_FAILED = Symbol("wallet-requests-v7.attributionNodeReadFailed");
const lowerHex = (value) => String(value ?? "").toLowerCase();
const withoutModulePrefix = (message) => String(message ?? "").replace(/^wallet-requests-v7: /, "");

/* An attribution refusal: answered as UNKNOWN { attribution: { outcome, ... } }, never thrown out of the Verify. */
function attributionRefusal(outcome, reason, detail = {}) {
  const e = new Error(`wallet-requests-v7: ${reason}`);
  e.code = outcome;
  e.attributionOutcome = outcome;
  e.attributionReason = reason;
  e.attributionDetail = detail;
  return e;
}
function attributionUnknown(rootCovenantId, outcome, reason, detail = {}) {
  const attribution = { outcome };
  for (const key of ["requestId", "txId", "depthDaa"]) if (detail[key] !== undefined && detail[key] !== null) attribution[key] = String(detail[key]);
  attribution.requiredDepthDaa = ATTRIBUTION_DEPTH_DAA.toString();
  return { status: "UNKNOWN", rootCovenantId, reason, attribution };
}
/* The open node connection as the attributed completion sees it: every error a node call raises is marked as a node read
 * failure, so the completion's own reads before its first write answer UNKNOWN OBSERVATION_ERROR (nothing written) and
 * never turn the Verify into an error; the calls themselves are unchanged. */
function attributionNodeRpc(rpc) {
  const marked = (e) => {
    const err = new Error(`wallet-requests-v7: a node read failed (${firstLine(e)})`);
    err.code = "OBSERVATION_ERROR";
    err[NODE_READ_FAILED] = true;
    return err;
  };
  return new Proxy(rpc, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (typeof value !== "function") return value;
      return (...args) => {
        let out;
        try { out = value.apply(target, args); } catch (e) { throw marked(e); }
        return out && typeof out.then === "function" ? Promise.resolve(out).catch((e) => { throw marked(e); }) : out;
      };
    }
  });
}
/* A deliberate refusal raised by the completion's own validation (this module or the v0.7-kas profile adapter). */
function deliberateCompletionRefusal(e) {
  return Boolean(e) && typeof e.code === "string" && /^(wallet-requests-v7|rooted-kas-profile-v7): /.test(String(e.message ?? ""));
}
function sameObservedEntry(a, b) {
  return Boolean(a && b) && sameOutpoint(a.outpoint, b.outpoint) && String(a.amount) === String(b.amount) && (a.covenantId ?? null) === (b.covenantId ?? null)
    && (a.scriptPublicKeyHex ?? null) === (b.scriptPublicKeyHex ?? null) && String(a.blockDaaScoreRaw) === String(b.blockDaaScoreRaw);
}
/* The strict observation of the treasury successor output `idx` of `request` from one fresh read of its address. */
async function observeTreasurySuccessorStrict(config, rpc, request, idx) {
  const out = Number.isInteger(idx) && idx >= 0 ? request?.build?.frozen?.outputs?.[idx] : undefined;
  if (!rpc || !out) throwFail("the treasury successor of an attributed completion cannot be observed without a node connection and a frozen output", "RECONCILIATION_REQUIRED");
  return observeFrozenOutputStrict(request, idx, await getAddressUtxos(rpc, spkToAddress(config, out.scriptPublicKey)));
}

/*
 * D2 OBSERVATION (fresh reads on the open connection; writes nothing; every refusal is an attributionRefusal):
 *   1. one canonical virtual DAA read;
 *   2. one read per distinct candidate root-successor address (more than 64: CANDIDATE_CAP); a candidate's successor is
 *      observed only EXACT (observeFrozenOutputStrict); anything else under a candidate's txid is a CONTRADICTION;
 *   3. no observed txid: NO_CANDIDATE; several: CONTRADICTION;
 *   4. the records carrying the observed txid: several: AMBIGUOUS; the one record A must be a v0.7-kas delegate-rule change,
 *      FRESH (AUTHORIZED or REFUSED, no final transaction, never attempted) or a REPLAY (RECONCILIATION_REQUIRED with a
 *      bound marker); a SIGNED never-attempted request: SUBMIT_TO_RECORD; anything else: NOT_IN_SCOPE;
 *   5. the binding of A's records to the observed transaction (assertAttributedTransactionBinding): else RECORD_DAMAGED;
 *   6. every frozen input of A reported spent, and T1 recorded on this root at A's predecessor (fresh) or at A's
 *      predecessor or successor (replay): else CONTRADICTION;
 *   7. T1's successor read #1 (exact: F; nothing under A's txid: P; anything else: CONTRADICTION) — not for a PARTIAL-marker
 *      replay, nor for a FULL-marker replay whose T1 record is already at A's successor (addendum a items 1 and 2);
 *   8. the bracket: the root successor re-read (still the same exact entry) and T1's read #2 (equal to #1): else UNSTABLE;
 *   9. depth = virtual DAA - the root successor entry's canonical accepting DAA >= 1000 (else BELOW_DEPTH; non-canonical:
 *      OBSERVATION_ERROR); FULL needs T1's entry at the same accepting DAA (else CONTRADICTION);
 *  10. the mode: F/F FULL, P/P PARTIAL; a replay that reads no T1 keeps its marker's mode.
 * A node read that fails is OBSERVATION_ERROR. Store errors propagate unchanged.
 */
async function observeAttributableMove(config, rpc, { rootCovenantId, P, records, candidates }) {
  const read = async (address, what) => {
    try {
      return await getAddressUtxos(rpc, address);
    } catch (e) {
      throw attributionRefusal("OBSERVATION_ERROR", `${what} ${address} could not be read from the node (${firstLine(e)}) — nothing is written`);
    }
  };
  let virtualDaa;
  try {
    virtualDaa = await require("./chain").readCanonicalVirtualDaaScore(rpc);
  } catch (e) {
    throw attributionRefusal("OBSERVATION_ERROR", `the node's virtual DAA score could not be read as a canonical integer (${firstLine(e)}) — nothing is written`);
  }
  const byAddress = new Map();
  for (const q of candidates) {
    let target;
    try {
      target = rootSuccessorTarget(config, q);
    } catch (e) {
      throw attributionRefusal("RECORD_DAMAGED", `request ${q.id} on the root's recorded outpoint declares no readable root successor (${withoutModulePrefix(firstLine(e))}) — nothing is written`, { requestId: q.id, txId: q.txId });
    }
    if (!byAddress.has(target.rootAddress)) byAddress.set(target.rootAddress, []);
    byAddress.get(target.rootAddress).push({ q, target });
  }
  if (byAddress.size > ATTRIBUTION_CANDIDATE_CAP) throw attributionRefusal("CANDIDATE_CAP", `${byAddress.size} distinct candidate root successor addresses exceed the cap of ${ATTRIBUTION_CANDIDATE_CAP} — nothing is attributed or written`);
  const observed = new Map();
  for (const [address, list] of byAddress) {
    const refs = await read(address, "the candidate root successor address");
    for (const { q, target } of list) {
      const o = observeFrozenOutputStrict(q, target.rootOutIndex, refs);
      if (o.outcome === "CONTRADICTION") throw attributionRefusal("CONTRADICTION", `request ${q.id}'s root successor is contradicted on chain: ${o.reason} — nothing is written`, { requestId: q.id, txId: q.txId });
      if (o.outcome === "EXACT" && !observed.has(lowerHex(q.txId))) observed.set(lowerHex(q.txId), { target, address, entry: o.entry });
    }
  }
  if (observed.size === 0) throw attributionRefusal("NO_CANDIDATE", "the root's recorded outpoint is spent and no recorded request's exact root successor is observed — the move is not attributable to a PolicyVault record; nothing is written");
  if (observed.size > 1) throw attributionRefusal("CONTRADICTION", `the root successors of ${observed.size} different recorded transactions are observed at once — nothing is written`);
  const [[X, rootSeen]] = observed;
  const carrying = records.filter((q) => q && typeof q.txId === "string" && lowerHex(q.txId) === X);
  if (carrying.length !== 1) throw attributionRefusal("AMBIGUOUS", `${carrying.length} records carry the observed transaction ${X} — it is not attributed to any of them; nothing is written`, { txId: X });
  const A = carrying[0];
  const facts = { requestId: A.id, txId: A.txId };
  const rule = kasDelegateRuleChange(A);
  const inScope = rule.recorded && rule.built && Array.isArray(A.vaultOperations) && A.vaultOperations.length === 1;
  const marker = boundAttributionMarker(A);
  const attempted = await rootRequestHasAttemptEvidence(config, A);
  const fresh = inScope && ATTRIBUTION_FRESH_STATES.has(A.state) && A.finalTransaction == null && !A.signedSafeJson && !attempted;
  const replay = inScope && A.state === RequestState.RECONCILIATION_REQUIRED && marker !== null;
  if (!fresh && !replay) {
    if (A.state === RequestState.SIGNED && !attempted) throw attributionRefusal("SUBMIT_TO_RECORD", `request ${A.id} is finalized and its transaction ${A.txId}, broadcast outside PolicyVault, is already on the chain — press Submit on it, then Verify state; nothing is written`, facts);
    throw attributionRefusal("NOT_IN_SCOPE", `the observed transaction ${A.txId} belongs to request ${A.id} (${A.state}${inScope ? "" : ", not a v0.7-kas delegate-rule change"}), which this attribution does not cover — nothing is written`, facts);
  }
  try {
    assertAttributedTransactionBinding(config, A);
  } catch (e) {
    throw attributionRefusal("RECORD_DAMAGED", `${withoutModulePrefix(firstLine(e))} (request ${A.id}); nothing is written`, facts);
  }
  const inputs = new Map();
  for (const input of A.build.frozen.inputs) {
    let address;
    try {
      address = spkToAddress(config, input.utxo.scriptPublicKey);
    } catch (e) {
      throw attributionRefusal("RECORD_DAMAGED", `an input of request ${A.id} carries no readable script (${withoutModulePrefix(firstLine(e))}) — nothing is written`, facts);
    }
    if (!inputs.has(address)) inputs.set(address, []);
    inputs.get(address).push(input.previousOutpoint);
  }
  for (const [address, outpoints] of inputs) {
    const refs = await read(address, "an input address of the observed transaction");
    const present = outpoints.find((op) => refs.some((r) => sameOutpoint(r.outpoint, op)));
    if (present) throw attributionRefusal("CONTRADICTION", `input ${describeOutpoint(present)} of request ${A.id}'s transaction ${A.txId} is still reported unspent, which contradicts its acceptance — nothing is written`, facts);
  }
  const vaultId = A.vaultOperations[0].vaultId;
  let vaultPredecessor;
  try {
    vaultPredecessor = vaultPredecessorOutpoint(A);
  } catch (e) {
    throw attributionRefusal("RECORD_DAMAGED", `${withoutModulePrefix(firstLine(e))} (request ${A.id}); nothing is written`, facts);
  }
  const vIdx = kasProfile.vaultSuccessorIndexOf(A);
  if (!(vIdx >= 0)) throw attributionRefusal("RECORD_DAMAGED", `request ${A.id}'s transaction declares no treasury successor output — nothing is written`, facts);
  const vault = await kasProfile.loadManifestV7Kas(config, vaultId);
  const atPredecessor = Boolean(vault && vault.live) && sameOutpoint(vault.live.outpoint, vaultPredecessor);
  const atSuccessor = Boolean(vault && vault.live) && sameOutpoint(vault.live.outpoint, { transactionId: A.txId, index: vIdx });
  if (!vault || vault.orgRootCovenantId !== rootCovenantId || !(atPredecessor || replay && atSuccessor)) {
    throw attributionRefusal("CONTRADICTION", `treasury ${vaultId} is not recorded on this root at request ${A.id}'s ${replay ? "predecessor or successor" : "predecessor"} ${describeOutpoint(vaultPredecessor)} (recorded at ${describeOutpoint(vault && vault.live ? vault.live.outpoint : null)}) — nothing is written`, facts);
  }
  const treasuryAddress = spkToAddress(config, A.build.frozen.outputs[vIdx].scriptPublicKey);
  const readsTreasury = fresh || marker.mode === "FULL" && atPredecessor;
  let treasuryFirst = null;
  if (readsTreasury) {
    treasuryFirst = observeFrozenOutputStrict(A, vIdx, await read(treasuryAddress, "the treasury successor address"));
    if (treasuryFirst.outcome === "CONTRADICTION") throw attributionRefusal("CONTRADICTION", `treasury ${vaultId}'s successor is contradicted on chain: ${treasuryFirst.reason} — nothing is written`, facts);
  }
  const rootAgain = observeFrozenOutputStrict(A, rootSeen.target.rootOutIndex, await read(rootSeen.address, "the root successor address"));
  if (rootAgain.outcome !== "EXACT" || !sameObservedEntry(rootAgain.entry, rootSeen.entry)) {
    throw attributionRefusal("UNSTABLE", `the root successor ${A.txId}:${rootSeen.target.rootOutIndex} changed between two reads (${rootAgain.outcome === "EXACT" ? "its entry differs" : rootAgain.outcome}) — nothing is written; Verify again`, facts);
  }
  if (readsTreasury) {
    const treasurySecond = observeFrozenOutputStrict(A, vIdx, await read(treasuryAddress, "the treasury successor address"));
    if (treasurySecond.outcome !== treasuryFirst.outcome || treasuryFirst.outcome === "EXACT" && !sameObservedEntry(treasuryFirst.entry, treasurySecond.entry)) {
      throw attributionRefusal("UNSTABLE", `treasury ${vaultId}'s successor ${A.txId}:${vIdx} changed between two reads (${treasuryFirst.outcome} then ${treasurySecond.outcome}) — nothing is written; Verify again`, facts);
    }
  }
  const rootEntryDaa = canonicalDaaScore(rootSeen.entry.blockDaaScoreRaw);
  if (rootEntryDaa === null) throw attributionRefusal("OBSERVATION_ERROR", `the node reports no canonical accepting DAA score for the root successor ${A.txId}:${rootSeen.target.rootOutIndex} — nothing is written`, facts);
  if (virtualDaa < rootEntryDaa) throw attributionRefusal("CONTRADICTION", `the node's virtual DAA score ${virtualDaa} is below the root successor's accepting DAA score ${rootEntryDaa} — nothing is written`, facts);
  const depth = virtualDaa - rootEntryDaa;
  if (depth < ATTRIBUTION_DEPTH_DAA) {
    throw attributionRefusal("BELOW_DEPTH", `request ${A.id}'s transaction ${A.txId}, broadcast outside PolicyVault, is at depth ${depth} DAA, below the required ${ATTRIBUTION_DEPTH_DAA} — nothing is written; Verify again later`, { ...facts, depthDaa: depth.toString() });
  }
  if (readsTreasury && treasuryFirst.outcome === "EXACT") {
    const treasuryEntryDaa = canonicalDaaScore(treasuryFirst.entry.blockDaaScoreRaw);
    if (treasuryEntryDaa === null) throw attributionRefusal("OBSERVATION_ERROR", `the node reports no canonical accepting DAA score for treasury ${vaultId}'s successor ${A.txId}:${vIdx} — nothing is written`, facts);
    if (treasuryEntryDaa !== rootEntryDaa) throw attributionRefusal("CONTRADICTION", `treasury ${vaultId}'s successor is reported at accepting DAA ${treasuryEntryDaa}, the root successor of the same transaction at ${rootEntryDaa} — nothing is written`, facts);
  }
  const mode = readsTreasury ? (treasuryFirst.outcome === "EXACT" ? "FULL" : "PARTIAL") : marker.mode;
  return { A, X, target: rootSeen.target, virtualDaa, rootEntryDaa, depth, mode, fresh, replay };
}

/*
 * D1 + D2 + D3 + D4 + D4b — reconcile-v7's live-outpoint-gone branch calls this after its claim path found no proof and
 * before its C3 UNKNOWN, only with claim release allowed, under the root lock every hosted mutation of the root takes.
 * RECORDS FIRST: without a root request recorded on the root's recorded outpoint P (with a txid and a build) it returns
 * null — the caller answers C3's UNKNOWN byte-identically — and reads nothing from the node. Otherwise:
 *   - a refusal of the observation (D2) answers UNKNOWN { attribution: { outcome, requestId?, txId?, depthDaa?,
 *     requiredDepthDaa: "1000" } } and writes nothing; a node read error is OBSERVATION_ERROR (never an error);
 *   - the attributed completion (completeProvenRootAction with this module's in-memory attribution, via "attribution"):
 *     a refusal before its first write answers UNKNOWN (UNSTABLE / RECORD_DAMAGED / OBSERVATION_ERROR /
 *     COMPLETION_REFUSED), nothing written, no recordCompletionFailure; a failure after its first write is recorded by
 *     recordCompletionFailure and thrown, as in C3 (the next Verify or Submit replays the bound marker);
 *   - then settlement (settleStrandedByAttribution; its failures become `unsettled`, never thrown past A's completion)
 *     and the holds derived from the records afterwards (rootHoldsAfterSettlement);
 *   - ADVANCED { via: "attribution", mode, depthDaa, requiredDepthDaa, treasury: { vaultId, state }, settled, unsettled,
 *     holds, buildable }.
 * Store errors propagate as in C3.
 */
async function attributeOutOfBandRootTransition(config, rpc, root) {
  if (!root || !root.live || !root.live.outpoint) return null;
  const rootCovenantId = root.rootCovenantId;
  let P;
  try {
    P = normalizeOutpoint(root.live.outpoint, "root.live.outpoint");
  } catch {
    return null;
  }
  const records = await listOrgRootRequests(config, { rootCovenantId });
  const candidates = records.filter((q) => q && q.kind === "rootAction" && typeof q.txId === "string" && q.build && q.build.frozen && Array.isArray(q.build.frozen.outputs) && sameOutpoint(q.manifest?.root?.outpoint, P));
  if (candidates.length === 0) return null;
  let seen;
  try {
    seen = await observeAttributableMove(config, rpc, { rootCovenantId, P, records, candidates });
  } catch (e) {
    if (e && e.attributionOutcome) return attributionUnknown(rootCovenantId, e.attributionOutcome, e.attributionReason, e.attributionDetail);
    throw e;
  }
  const { A, target, virtualDaa, rootEntryDaa, depth, mode } = seen;
  const facts = { requestId: A.id, txId: A.txId };
  const attribution = issueInMemoryAttribution({ requestId: A.id, txId: A.txId, mode, observedVirtualDaa: virtualDaa.toString(), rootEntryDaa: rootEntryDaa.toString(), depthDaa: depth.toString() });
  try {
    await completeProvenRootAction(config, A, { rootOutIndex: target.rootOutIndex, rootAddress: target.rootAddress, rootExpectedValue: target.rootExpectedValue, rootBlockDaaScore: rootEntryDaa.toString(), vaultOutIndex: null, rpc: attributionNodeRpc(rpc), via: "attribution", attribution });
  } catch (e) {
    if (e && e.completionStarted) throw await recordCompletionFailure(config, A, e);
    if (e && e[NODE_READ_FAILED]) return attributionUnknown(rootCovenantId, "OBSERVATION_ERROR", `${withoutModulePrefix(firstLine(e))} during the attributed completion of request ${A.id} — nothing is written`, facts);
    if (deliberateCompletionRefusal(e)) {
      const outcome = e.code === "UNSTABLE" || e.code === "RECORD_DAMAGED" ? e.code : "COMPLETION_REFUSED";
      return attributionUnknown(rootCovenantId, outcome, `the attributed completion of request ${A.id} is refused before any write: ${withoutModulePrefix(firstLine(e))}`, facts);
    }
    throw e;
  }
  let settlement;
  try {
    settlement = await settleStrandedByAttribution(config, rpc, { request: A, depthDaa: depth.toString() });
  } catch (e) {
    settlement = { settled: [], unsettled: [{ step: "settlement", reason: firstLine(e) }] };
  }
  const { holds, buildable } = await rootHoldsAfterSettlement(config, rootCovenantId);
  const finalMarker = boundAttributionMarker(A);
  const finalMode = finalMarker !== null ? finalMarker.mode : mode;
  const vaultId = A.vaultOperations[0].vaultId;
  return {
    status: "ADVANCED",
    rootCovenantId,
    txId: A.txId,
    requestId: A.id,
    via: "attribution",
    mode: finalMode,
    depthDaa: depth.toString(),
    requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString(),
    treasury: { vaultId, state: OOB_ATTRIBUTION_TREASURY_STATE[finalMode] },
    settled: settlement.settled,
    unsettled: settlement.unsettled,
    holds,
    buildable,
    reason: finalMode === "FULL"
      ? `request ${A.id}'s transaction ${A.txId}, broadcast outside PolicyVault, consumed the root's recorded outpoint; it is attributed to that request at depth ${depth} DAA and the root and treasury ${vaultId} follow its successors`
      : `request ${A.id}'s transaction ${A.txId}, broadcast outside PolicyVault, consumed the root's recorded outpoint; it is attributed to that request at depth ${depth} DAA and the root follows its successor; the treasury output it created for ${vaultId} was spent outside PolicyVault, so ${vaultId} is UNRESOLVED (its record is unchanged)`
  };
}

/* A v0.7-kas delegate request that is unfinished (rooted-kas-profile-v7.js unfinishedDelegateRequests). */
function kasDelegateUnfinished(q) {
  return Boolean(q) && q.kind === "agentSpend" && (["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"].includes(q.state) || q.state === "SIGNED" && !!q.submissionAttempt);
}
/* The pointer naming a terminal request on P without a bound receipt (D4 "finish"), or null. Reads records only. */
async function finishablePointerRequest(config, root, request, P) {
  if (!root || !root.pendingRequestId || root.pendingRequestId === request.id) return null;
  const q = await loadOrgRootRequest(config, root.pendingRequestId);
  if (!q || q.kind !== "rootAction" || q.rootCovenantId !== request.rootCovenantId || !FINISHABLE_POINTER_STATES.has(q.state) || !sameOutpoint(q.manifest?.root?.outpoint, P) || lowerHex(q.txId) === lowerHex(request.txId)) return null;
  let bound = true;
  try {
    bound = await hasBoundRootCompletionReceipt(config, q);
  } catch {
    bound = true; // undeterminable: never finished here
  }
  return bound ? null : q;
}
/*
 * The requests an attributed request A leaves stranded, from the records only (no node read): root requests S != A of
 * this root on A's root predecessor P with S.txId != A.txId in AUTHORIZED, SIGNED, BROADCAST, CHAIN_SEEN or
 * RECONCILIATION_REQUIRED; unfinished v0.7-kas delegate requests of this root's treasuries sharing a frozen input with A
 * (T1's predecessor or A's fee input) with D.txId != A.txId; and the pointer naming a terminal request on P without a
 * bound receipt.
 */
async function strandedByAttribution(config, request, { records = null } = {}) {
  const P = normalizeOutpoint(request.manifest.root.outpoint, "manifest.root.outpoint");
  const X = lowerHex(request.txId);
  const list = records ?? (await listOrgRootRequests(config, { rootCovenantId: request.rootCovenantId }));
  const rootRequests = list.filter((q) => q && q.kind === "rootAction" && q.id !== request.id && q.rootCovenantId === request.rootCovenantId && typeof q.txId === "string" && lowerHex(q.txId) !== X && SETTLEABLE_ROOT_REQUEST_STATES.has(q.state) && sameOutpoint(q.manifest?.root?.outpoint, P));
  const attributedInputs = request.build.frozen.inputs.map((i) => i.previousOutpoint);
  const root = await loadOrgRoot(config, request.rootCovenantId);
  const delegates = [];
  for (const vaultId of root?.vaults ?? []) {
    const vault = await kasProfile.loadManifestV7Kas(config, vaultId);
    if (!vault) continue;
    for (const d of await kasProfile.unfinishedDelegateRequests(config, vault)) {
      if (typeof d.txId !== "string" || lowerHex(d.txId) === X || !Array.isArray(d.build?.frozen?.inputs)) continue;
      const shared = d.build.frozen.inputs.map((i) => i.previousOutpoint).find((o) => attributedInputs.some((a) => sameOutpoint(a, o)));
      if (shared) delegates.push({ request: d, shared });
    }
  }
  return { P, X, rootRequests, delegates, finish: await finishablePointerRequest(config, root, request, P) };
}

/*
 * D4 SETTLEMENT of the requests stranded by the attributed request A (CHAIN_VERIFIED, its transaction accepted: it spent
 * the root predecessor P and every other frozen input of A). A request is settled only on proof that it can never be
 * accepted: it spends an outpoint A's accepted transaction spent (an outpoint is spent once, so it could be accepted only
 * if A were reorganized away deeper than the attribution depth) and no output under its own txid is observed.
 *   - root request S: an unattempted, claimless S is settled SUPERSEDED in ONE save; an attempted or claimed S in the
 *     claim path's order (reconcile-v7 reconcileRootNegativeOutcome), releasing only its own claims (a claim naming
 *     another request leaves S unsettled); then the root's pointer is cleared only when it names S;
 *   - delegate request D: the delegate negative-outcome writes (wallet-requests-v7-kas recoverKasDelegateRequest);
 *   - finish: a pointer naming a terminal request on P without a bound receipt: its own claims are released and the
 *     pointer is cleared.
 * submissionOutcome { outcome: "SUPERSEDED", proof: { via: "attribution", acceptedConflictingTxId, attributedRequestId,
 * spentOutpoint, depthDaa } }. Idempotent. Each failure becomes `unsettled: [{ requestId, step, reason }]`; nothing is
 * thrown for one request. Never settled: other terminal requests, a BUILT or never-attempted SIGNED delegate request,
 * other roots' requests, anything whose proof fails. Returns { settled, unsettled }.
 */
async function settleStrandedByAttribution(config, rpc, { request, depthDaa, records = null }) {
  const settled = [], unsettled = [];
  const { P, X, rootRequests, delegates } = await strandedByAttribution(config, request, { records });
  const reads = new Map();
  const read = async (address) => {
    if (!reads.has(address)) reads.set(address, await getAddressUtxos(rpc, address));
    return reads.get(address);
  };
  const ownOutputObserved = async (q) => {
    for (const address of new Set(q.build.frozen.outputs.map((o) => spkToAddress(config, o.scriptPublicKey)))) {
      if ((await read(address)).some((r) => lowerHex(r.outpoint.transactionId) === lowerHex(q.txId))) return true;
    }
    return false;
  };
  const supersededBy = (spent, txId) => ({
    outcome: "SUPERSEDED",
    reason: `another confirmed transaction (${request.txId}, request ${request.id}, broadcast outside PolicyVault) spent ${describeOutpoint(spent)}, an output this request needs; ${txId} can never be accepted`,
    proof: { via: "attribution", acceptedConflictingTxId: request.txId, attributedRequestId: request.id, spentOutpoint: { transactionId: lowerHex(spent.transactionId), index: Number(spent.index) }, depthDaa: String(depthDaa) }
  });
  for (const listed of rootRequests) {
    let step = "load";
    try {
      const s = await loadOrgRootRequest(config, listed.id);
      if (!s || s.kind !== "rootAction" || !SETTLEABLE_ROOT_REQUEST_STATES.has(s.state) || !sameOutpoint(s.manifest?.root?.outpoint, P) || lowerHex(s.txId) === X) continue;
      step = "proof";
      if (!Array.isArray(s.build?.frozen?.inputs) || !s.build.frozen.inputs.some((i) => sameOutpoint(i.previousOutpoint, P))) {
        unsettled.push({ requestId: s.id, step, reason: `its frozen inputs do not spend the root outpoint ${describeOutpoint(P)} — not settled` });
        continue;
      }
      step = "observe";
      if (await ownOutputObserved(s)) {
        unsettled.push({ requestId: s.id, step: "proof", reason: `CONTRADICTION: an output under its own transaction ${s.txId} is observed — not settled` });
        continue;
      }
      step = "proof";
      if (await getStore(config).read(Categories.RECEIPT, s.txId)) {
        unsettled.push({ requestId: s.id, step, reason: `CONTRADICTION: a receipt exists for its own transaction ${s.txId} — not settled` });
        continue;
      }
      const outcome = supersededBy(P, s.txId);
      const pointer = completionReceiptPointer(s);
      if (!(await rootRequestHasAttemptEvidence(config, s))) {
        step = "settle";
        s.submissionOutcome = { ...outcome, ...pointer, txId: s.txId };
        s.state = "SUPERSEDED";
        s.error = outcome.reason;
        await saveOrgRootRequest(config, s);
      } else {
        step = "claims";
        const claims = [];
        let foreign = false;
        for (const outpoint of [s.manifest.root.outpoint, ...(s.vaultOperations?.length ? [s.build.predecessorOutpoint] : [])]) {
          const claim = await loadTransitionClaim(config, outpoint);
          if (claim?.txId === s.txId && claim.expected?.requestId && claim.expected.requestId !== s.id) { foreign = true; break; }
          claims.push({ outpoint, claim });
        }
        if (foreign) {
          unsettled.push({ requestId: s.id, step, reason: "claim names another request — not settled" });
          continue;
        }
        const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, s.txId);
        if (submission && (submission.vaultId !== s.rootCovenantId || submission.action !== s.action)) {
          unsettled.push({ requestId: s.id, step, reason: "submission claim belongs to another operation — not settled" });
          continue;
        }
        step = "settle";
        s.submissionOutcome = { ...outcome, ...pointer, txId: s.txId };
        s.state = RequestState.RECONCILIATION_REQUIRED;
        await saveOrgRootRequest(config, s);
        step = "claims";
        for (const { outpoint, claim } of claims) if (claim?.txId === s.txId) await releaseTransitionClaim(config, { outpoint, txId: s.txId });
        if (submission) await releaseSubmissionClaim(config, s.txId);
        step = "settle";
        s.state = "SUPERSEDED";
        s.error = outcome.reason;
        await saveOrgRootRequest(config, s);
      }
      step = "pointer";
      const fresh = await loadOrgRoot(config, s.rootCovenantId);
      if (fresh && fresh.pendingRequestId === s.id) {
        fresh.pendingRequestId = null;
        fresh.updatedAt = new Date().toISOString();
        await saveOrgRoot(config, fresh);
      }
      settled.push({ requestId: s.id, kind: "rootAction", outcome: "SUPERSEDED", spentOutpoint: describeOutpoint(P) });
    } catch (e) {
      unsettled.push({ requestId: listed.id, step, reason: firstLine(e) });
    }
  }
  const wrk = delegates.length ? require("./wallet-requests-v7-kas") : null;
  for (const { request: listed, shared } of delegates) {
    let step = "load";
    try {
      const d = await wrk.loadKasWalletRequest(config, listed.requestId);
      if (!kasDelegateUnfinished(d) || lowerHex(d.txId) === X) continue;
      step = "observe";
      if (await ownOutputObserved(d)) {
        unsettled.push({ requestId: d.requestId, step: "proof", reason: `CONTRADICTION: an output under its own transaction ${d.txId} is observed — not settled` });
        continue;
      }
      step = "claims";
      const outcome = supersededBy(shared, d.txId);
      if (d.predecessorOutpoint) {
        const claim = await loadTransitionClaim(config, d.predecessorOutpoint);
        if (claim && claim.txId === d.txId) await releaseTransitionClaim(config, { outpoint: d.predecessorOutpoint, txId: d.txId });
      }
      const sub = await getStore(config).read(Categories.SUBMISSION_CLAIM, d.txId);
      if (sub && sub.vaultId === d.vaultId && sub.action === d.action) await releaseSubmissionClaim(config, d.txId);
      step = "settle";
      d.submissionOutcome = { ...outcome, txId: d.txId };
      d.state = "SUPERSEDED";
      d.error = outcome.reason;
      await wrk.saveKasWalletRequest(config, d);
      settled.push({ requestId: d.requestId, kind: "delegate", vaultId: d.vaultId, outcome: "SUPERSEDED", spentOutpoint: describeOutpoint(shared) });
    } catch (e) {
      unsettled.push({ requestId: listed.requestId, step, reason: firstLine(e) });
    }
  }
  let finishing = null;
  try {
    const root = await loadOrgRoot(config, request.rootCovenantId);
    finishing = await finishablePointerRequest(config, root, request, P);
    if (finishing) {
      for (const outpoint of [finishing.manifest.root.outpoint, ...(finishing.vaultOperations?.length && finishing.build?.predecessorOutpoint ? [finishing.build.predecessorOutpoint] : [])]) {
        const claim = await loadTransitionClaim(config, outpoint);
        if (claim?.txId === finishing.txId && (!claim.expected?.requestId || claim.expected.requestId === finishing.id)) await releaseTransitionClaim(config, { outpoint, txId: finishing.txId });
      }
      const sub = await getStore(config).read(Categories.SUBMISSION_CLAIM, finishing.txId);
      if (sub && sub.vaultId === finishing.rootCovenantId && sub.action === finishing.action) await releaseSubmissionClaim(config, finishing.txId);
      root.pendingRequestId = null;
      root.updatedAt = new Date().toISOString();
      await saveOrgRoot(config, root);
      settled.push({ requestId: finishing.id, kind: "rootAction", step: "pointer", outcome: finishing.state, reservation: "RELEASED" });
    }
  } catch (e) {
    unsettled.push({ ...(finishing ? { requestId: finishing.id } : {}), step: "pointer", reason: firstLine(e) });
  }
  return { settled, unsettled };
}

/*
 * D4b HOLDS AFTER SETTLEMENT (records only; no node read; never writes): reload the root; `holds` = the root's pending
 * pointer and every pendingRootRequests entry as { scope: "root", requestId, state }, plus every v0.7-kas treasury of the
 * root that is UNRESOLVED (treasuryUnresolved) as { scope: vaultId, reason: "UNRESOLVED", requestId, txId }.
 * buildable = { root: no root-scope hold, treasuries: the root's treasuries without a hold when the root is buildable,
 * else [] }. Any error: { holds: null, buildable: null } (not determined).
 */
async function rootHoldsAfterSettlement(config, rootCovenantId) {
  try {
    const root = await loadOrgRoot(config, rootCovenantId);
    if (!root) return { holds: null, buildable: null };
    const holds = [];
    const named = new Set();
    if (root.pendingRequestId) {
      const q = await loadOrgRootRequest(config, root.pendingRequestId);
      holds.push({ scope: "root", requestId: root.pendingRequestId, state: q ? q.state : null });
      named.add(root.pendingRequestId);
    }
    for (const q of await pendingRootRequests(config, root)) {
      if (named.has(q.id)) continue;
      named.add(q.id);
      holds.push({ scope: "root", requestId: q.id, state: q.state });
    }
    const held = new Set();
    for (const vaultId of root.vaults ?? []) {
      const vault = await kasProfile.loadManifestV7Kas(config, vaultId);
      const unresolved = vault ? await treasuryUnresolved(config, vault) : null;
      if (unresolved) {
        holds.push({ scope: vaultId, reason: "UNRESOLVED", requestId: unresolved.requestId, txId: unresolved.txId });
        held.add(vaultId);
      }
    }
    const rootBuildable = !holds.some((h) => h.scope === "root");
    return { holds, buildable: { root: rootBuildable, treasuries: rootBuildable ? (root.vaults ?? []).filter((v) => !held.has(v)) : [] } };
  } catch {
    return { holds: null, buildable: null };
  }
}

/*
 * D7's record-only predicate: the v0.7-kas treasury `vault` is UNRESOLVED when a bound PARTIAL attribution marker of its
 * root names it while its record still stands at the marker's predecessor outpoint. Returns { requestId, txId } or null.
 * Used by D4b and by the D7 refusals (assertTreasuryNotUnresolved) and wallet-requests-v7-kas.js reconcileKasVault.
 */
function treasuryUnresolvedCandidate(vault) {
  return !!vault && kasProfile.isKasVaultRecord(vault) && !!vault.live && typeof vault.orgRootCovenantId === "string";
}
/* the predicate over `records`, a listing of the requests of the candidate `vault`'s root */
function treasuryUnresolvedAmong(records, vault) {
  for (const q of records) {
    const m = boundAttributionMarker(q);
    if (m && m.mode === "PARTIAL" && m.treasury.state === OOB_ATTRIBUTION_TREASURY_STATE.PARTIAL && m.treasury.vaultId === vault.vaultId && sameOutpoint(vault.live.outpoint, m.treasury.predecessorOutpoint)) return { requestId: q.id, txId: q.txId };
  }
  return null;
}
async function treasuryUnresolved(config, vault) {
  if (!treasuryUnresolvedCandidate(vault)) return null;
  return treasuryUnresolvedAmong(await listOrgRootRequests(config, { rootCovenantId: vault.orgRootCovenantId }), vault);
}
/*
 * RC45 C4-05 (contract D7, the org summaries): the same predicate for the v0.7-kas treasuries of ONE root from ONE listing
 * of that root's requests (records only; no node read; never writes). Returns vault -> { requestId, txId } | null, the
 * answer treasuryUnresolved(config, vault) gives over that listing. A treasury of another root is refused (thrown), never
 * answered null; a store error propagates, so a summary never shows an undetermined state as null.
 */
async function treasuryUnresolvedOfRoot(config, rootCovenantId) {
  const records = typeof rootCovenantId === "string" ? await listOrgRootRequests(config, { rootCovenantId }) : [];
  return (vault) => {
    if (!treasuryUnresolvedCandidate(vault)) return null;
    if (vault.orgRootCovenantId !== rootCovenantId) throwFail(`treasury ${vault.vaultId} belongs to root ${vault.orgRootCovenantId}, not to root ${rootCovenantId} whose requests were listed`, "RECORD_DAMAGED");
    return treasuryUnresolvedAmong(records, vault);
  };
}
/*
 * D7 REFUSAL (record-only, refusal-only; writes nothing): a hosted action on an UNRESOLVED v0.7-kas treasury is refused
 * 409 TREASURY_STATE_UNRESOLVED naming the attributed request and its txid. Placed ahead of VAULT_PAUSED /
 * VAULT_PENDING_REQUEST and the completion checks, because the treasury's recorded status and rows describe a
 * predecessor that moved on chain; network, generation, identity, genesis and action-shape checks and the root-wide
 * ROOT_PENDING_REQUEST still come first.
 */
async function assertTreasuryNotUnresolved(config, vault) {
  const unresolved = await treasuryUnresolved(config, vault);
  if (!unresolved) return;
  const e = fail(`treasury ${vault.vaultId} is UNRESOLVED: PolicyVault cannot confirm this treasury's current state — its expected output was spent outside PolicyVault after an out-of-band change to its delegate rules (root request ${unresolved.requestId}, transaction ${unresolved.txId}, broadcast outside PolicyVault). Hosted actions on this treasury stay closed; a later Verify restores them only if it finds that expected output unspent again, otherwise only the owners' direct on-chain exit can act on it. Nothing was written`, "TREASURY_STATE_UNRESOLVED");
  e.status = 409; // a conflict with the recorded chain state (contract D7), never a validation answer
  throw e;
}

/*
 * D4 (ii) THE SETTLEMENT HOOK (reconcile-v7's live branch, after discovery, only with claim release allowed): only when
 * the live outpoint's transaction is a CHAIN_VERIFIED request of this root carrying a bound marker AND the records still
 * hold a settlement candidate does it settle (with node reads); otherwise it returns null having read nothing from the
 * node and written nothing. Never throws: every error becomes `unsettled: [{ step: "hook", ... }]` beside the caller's
 * own (C3) answer. Returns null or { settled, unsettled, fields } — `fields` is what the caller adds to its answer (the
 * D4b holds and buildability only when something was settled).
 */
async function attributionSettlementHook(config, rpc, root) {
  let request, records;
  try {
    if (!root || !root.live || !root.live.outpoint) return null;
    const liveTx = lowerHex(root.live.outpoint.transactionId);
    records = await listOrgRootRequests(config, { rootCovenantId: root.rootCovenantId });
    const marked = records.filter((q) => q && q.kind === "rootAction" && typeof q.txId === "string" && lowerHex(q.txId) === liveTx && q.state === RequestState.CHAIN_VERIFIED && boundAttributionMarker(q) !== null);
    if (marked.length !== 1) return null;
    request = marked[0];
    const stranded = await strandedByAttribution(config, request, { records });
    if (!stranded.rootRequests.length && !stranded.delegates.length && !stranded.finish) return null;
  } catch (e) {
    const unsettled = [{ step: "hook", reason: `the settlement hook could not inspect the records (${firstLine(e)})` }];
    return { settled: [], unsettled, fields: { unsettled } };
  }
  let result;
  try {
    result = await settleStrandedByAttribution(config, rpc, { request, depthDaa: boundAttributionMarker(request).depthDaa, records });
  } catch (e) {
    result = { settled: [], unsettled: [{ step: "settlement", reason: firstLine(e) }] };
  }
  const unsettled = result.unsettled.map((u) => ({ step: "hook", ...(u.requestId ? { requestId: u.requestId } : {}), reason: `${u.step}: ${u.reason}` }));
  const fields = {};
  if (result.settled.length) fields.settled = result.settled;
  if (unsettled.length) fields.unsettled = unsettled;
  if (result.settled.length) Object.assign(fields, await rootHoldsAfterSettlement(config, root.rootCovenantId));
  return { settled: result.settled, unsettled, fields };
}

/*
 * Addendum a item 5: when reconcile-v7's discovery REPLAYED a request carrying a bound marker, its ADVANCED answer is the
 * attribution answer keyed on that marker (via "attribution", mode, the marker's depth, the treasury state, the hook's
 * settled / unsettled lists and the D4b holds and buildability), never the generic replay answer; its reason says that the
 * root follows the request's successor only when the root record stands there (C4-03d). Returns null when no replayed
 * request carries a bound marker.
 */
async function attributedReplayAnswer(config, rootCovenantId, completion, hook = null) {
  for (const c of completion ?? []) {
    if (!c || !c.replayed || typeof c.requestId !== "string") continue;
    const q = await loadOrgRootRequest(config, c.requestId);
    const m = boundAttributionMarker(q);
    if (m === null) continue;
    const { holds, buildable } = await rootHoldsAfterSettlement(config, rootCovenantId);
    const vaultId = m.treasury.vaultId;
    /* C4-03d (C4-03b item check F-05): the answer says the root follows A's successor only when the root record stands at
     * that exact output (the live outpoint this Verify observed unspent); discovery replays a request otherwise only when
     * the root record is proven BEYOND it, and then the answer says so, never that the root follows A's successor */
    const rootNow = await loadOrgRoot(config, rootCovenantId);
    const rootAtSuccessor = Boolean(rootNow && rootNow.live && rootNow.live.outpoint) && sameOutpoint(rootNow.live.outpoint, { transactionId: q.txId, index: rootSuccessorTarget(config, q).rootOutIndex });
    const attributed = `the durable completion of request ${q.id} was replayed: its transaction ${q.txId}, broadcast outside PolicyVault, is attributed to it (depth ${m.depthDaa} DAA when attributed)`;
    const beyond = "the root record already stands at a later transition beyond its successor";
    return {
      status: "ADVANCED",
      rootCovenantId,
      txId: q.txId,
      requestId: q.id,
      via: "attribution",
      mode: m.mode,
      depthDaa: String(m.depthDaa),
      requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString(),
      treasury: { vaultId, state: OOB_ATTRIBUTION_TREASURY_STATE[m.mode] },
      settled: hook ? hook.settled : [],
      unsettled: hook ? hook.unsettled : [],
      holds,
      buildable,
      reason: rootAtSuccessor
        ? (m.mode === "FULL"
          ? `${attributed}; the root and treasury ${vaultId} follow its successors`
          : `${attributed}; the root follows its successor and treasury ${vaultId} is UNRESOLVED (its record is unchanged)`)
        : (m.mode === "FULL"
          ? `${attributed}; treasury ${vaultId} follows its successor; ${beyond}`
          : `${attributed}; treasury ${vaultId} is UNRESOLVED (its record is unchanged); ${beyond}`)
    };
  }
  return null;
}

/*
 * WRITER DECISION 'PARTIAL upgrade' (RC45 C4-03b; owner criteria 3 — never permanently close a usable treasury — and 4 —
 * fresh evidence, never adopt known-spent state). It supersedes contract D3 (r2)'s "replay PARTIAL ... never an upgrade"
 * only for a LATER Verify: the Verify that completes a PARTIAL attribution (fresh or replayed) never upgrades it
 * (addendum a item 2). reconcile-v7's live branch calls this after discovery, only with claim release allowed and only
 * when discovery replayed nothing in that Verify, under the root lock every hosted mutation of the root takes.
 *   RECORDS FIRST (no candidate: null, nothing read from the node, nothing written): a candidate is a v0.7-kas treasury T1
 *   of this root whose record stands at the predecessor named by exactly one bound PARTIAL marker, carried by a
 *   CHAIN_VERIFIED request A of this root whose durable completion verifies complete with T1's segment UNRESOLVED and
 *   whose recorded transaction still binds (assertAttributedTransactionBinding).
 *   FRESH OBSERVATION per candidate (observeTreasuryUpgrade; any refusal, a node read error included, writes nothing and
 *   leaves T1 UNRESOLVED): one canonical virtual DAA read; T1's successor read #1 EXACT (still spent: ABSENT; anything
 *   else under A's txid: CONTRADICTION); every frozen input of A reported spent (T1's recorded predecessor among them);
 *   with the root record at A's root successor, that output re-read EXACT; the bracket, T1's successor read #2 the same
 *   entry as #1 (else UNSTABLE); depth = virtual DAA - T1's entry's canonical accepting DAA >= ATTRIBUTION_DEPTH_DAA
 *   (else BELOW_DEPTH); with the root re-read, the root entry at T1's accepting DAA (else CONTRADICTION, as D2.9).
 *   THE UPGRADE (three durable writes, in this order): (1) A's marker — mode FULL, treasury ADVANCED, upgradedFrom
 *   PARTIAL, upgradedAt (= modeChangedAt) and the observation; A stays CHAIN_VERIFIED and every identity field of the
 *   marker is kept; (2) T1's record at A's treasury successor with A's registry, exactly one generation (the same record
 *   the attributed completion's FULL vault step writes; it is built before the first write, so a record that cannot be
 *   built writes nothing); (3) one event line naming T1 and A's transaction (C4-03d, item check F-07). A crash after (1)
 *   leaves a bound FULL marker with T1 at its predecessor, which the next Verify's discovery replays with the root record
 *   at A's root successor or BEYOND it (addendum a item 1; C4-03d, item check F-01: it re-observes T1's successor,
 *   writes T1 when it is exact, downgrades the marker to PARTIAL with T1 UNRESOLVED when it is absent — never a FULL
 *   marker over a spent T1 record, never a Verify throwing because that output was spent; a contradictory observation
 *   still writes nothing, UNSTABLE, as addendum a item 1). A crash after (2) leaves the upgrade's records
 *   complete without its event line (the marker still records the upgrade). The root record and every other treasury are
 *   untouched; nothing is settled.
 * Returns null (no candidate) or { upgraded: [...], refused: [...] }; a write failure is thrown.
 */
async function upgradePartialAttributions(config, rpc, root) {
  if (!root || !root.live || !root.live.outpoint || !Array.isArray(root.vaults) || root.vaults.length === 0) return null;
  const rootCovenantId = root.rootCovenantId;
  const records = await listOrgRootRequests(config, { rootCovenantId });
  const partial = records.filter((q) => q && q.kind === "rootAction" && q.rootCovenantId === rootCovenantId && q.state === RequestState.CHAIN_VERIFIED && boundAttributionMarker(q)?.mode === "PARTIAL");
  if (partial.length === 0) return null;
  const candidates = [], refused = [];
  for (const vaultId of root.vaults) {
    let vault = null, naming = [];
    try {
      vault = await kasProfile.loadManifestV7Kas(config, vaultId);
      if (!vault || !kasProfile.isKasVaultRecord(vault) || !vault.live || vault.orgRootCovenantId !== rootCovenantId) continue;
      naming = partial.filter((q) => {
        const m = boundAttributionMarker(q);
        return m.treasury.vaultId === vaultId && sameOutpoint(vault.live.outpoint, m.treasury.predecessorOutpoint);
      });
      if (naming.length === 0) continue;
      if (naming.length > 1) {
        refused.push({ vaultId, outcome: "AMBIGUOUS", reason: `${naming.length} attribution markers name treasury ${vaultId}'s recorded outpoint — it stays UNRESOLVED; nothing is written` });
        continue;
      }
      const A = naming[0];
      const verified = await verifyRootActionCompletion(config, A);
      if (!verified.complete || verified.vault?.segment !== "UNRESOLVED") {
        refused.push({ vaultId, requestId: A.id, txId: A.txId, outcome: "NOT_COMPLETE", reason: `request ${A.id}'s durable completion does not verify as PARTIAL (${verified.missing.join("; ") || "treasury segment not UNRESOLVED"}) — nothing is written` });
        continue;
      }
      assertAttributedTransactionBinding(config, A);
      candidates.push({ A, vault });
    } catch (e) {
      refused.push({ vaultId, ...(naming.length === 1 ? { requestId: naming[0].id, txId: naming[0].txId } : {}), outcome: "RECORD_DAMAGED", reason: `the records of treasury ${vaultId} could not be inspected for an upgrade (${withoutModulePrefix(firstLine(e))}) — nothing is written` });
    }
  }
  const upgraded = [];
  for (const { A, vault } of candidates) {
    const facts = { vaultId: vault.vaultId, requestId: A.id, txId: A.txId };
    let seen;
    try {
      seen = await observeTreasuryUpgrade(config, rpc, { root, A, vault });
    } catch (e) {
      if (e && e.attributionOutcome) {
        refused.push({ ...facts, outcome: e.attributionOutcome, reason: e.attributionReason });
        continue;
      }
      throw e;
    }
    const at = new Date().toISOString();
    const m = boundAttributionMarker(A);
    const marked = {
      ...A,
      outOfBandAttribution: {
        ...m,
        mode: "FULL",
        modeChangedAt: at,
        treasury: { ...m.treasury, state: OOB_ATTRIBUTION_TREASURY_STATE.FULL },
        upgradedFrom: "PARTIAL",
        upgradedAt: at,
        upgradeObservation: {
          treasuryOutpoint: { transactionId: lowerHex(A.txId), index: seen.vIdx },
          observedVirtualDaa: seen.virtualDaa.toString(),
          treasuryEntryDaa: seen.entryDaa.toString(),
          depthDaa: seen.depth.toString(),
          requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString()
        }
      }
    };
    let successorDoc;
    try {
      if (boundAttributionMarker(marked) === null) throwFail(`the upgraded marker of request ${A.id} would not bind`, "RECORD_DAMAGED");
      successorDoc = kasProfile.expectedVaultSuccessorDoc(config, vault, A, seen.vIdx, Number(vault.generation ?? 0) + 1);
    } catch (e) {
      refused.push({ ...facts, outcome: "RECORD_DAMAGED", reason: `treasury ${vault.vaultId}'s upgrade record cannot be built (${withoutModulePrefix(firstLine(e))}) — nothing is written` });
      continue;
    }
    await saveOrgRootRequest(config, marked);
    Object.assign(A, marked);
    try {
      await kasProfile.persistManifestV7Kas(config, successorDoc);
    } catch (e) {
      throw fail(`request ${A.id}'s marker records treasury ${vault.vaultId} following its output ${A.txId}:${seen.vIdx}, but the treasury record could not be written (${firstLine(e)}) — Verify again: the next Verify re-observes that output before writing it`, "RECONCILIATION_REQUIRED");
    }
    /* C4-03d (C4-03b item check F-07): the upgrade's one event line, appended after the treasury write (as every event
     * line follows its mutation: a failure here loses the line, never the records above, and is not reported as an upgrade) */
    try {
      await appendAudit(config, { vaultId: vault.vaultId, action: "attributionUpgrade", actor: "system", contractVersion: kasProfile.CONTRACT_VERSION_V7_KAS, txId: A.txId, requestId: A.id, result: "TREASURY_FOLLOWS_ATTRIBUTED_OUTPUT", via: "attribution-upgrade", from: "PARTIAL", mode: "FULL", outpoint: `${lowerHex(A.txId)}:${seen.vIdx}`, depthDaa: seen.depth.toString(), requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString() });
    } catch (e) {
      throw fail(`treasury ${vault.vaultId}'s record now follows its output ${lowerHex(A.txId)}:${seen.vIdx} (request ${A.id}'s marker records the change), but its event line could not be appended (${firstLine(e)})`, "RECONCILIATION_REQUIRED");
    }
    upgraded.push({
      vaultId: vault.vaultId,
      requestId: A.id,
      txId: A.txId,
      from: "PARTIAL",
      mode: "FULL",
      treasury: OOB_ATTRIBUTION_TREASURY_STATE.FULL,
      outpoint: `${lowerHex(A.txId)}:${seen.vIdx}`,
      depthDaa: seen.depth.toString(),
      requiredDepthDaa: ATTRIBUTION_DEPTH_DAA.toString(),
      reason: `treasury ${vault.vaultId}'s output ${lowerHex(A.txId)}:${seen.vIdx}, created by request ${A.id}'s transaction broadcast outside PolicyVault, is observed unspent at depth ${seen.depth} DAA; the treasury record now follows that output with that request's delegate set (mode FULL)`
    });
  }
  return { upgraded, refused };
}

/*
 * The fresh observation of one PARTIAL upgrade (see upgradePartialAttributions). Reads only; every refusal is an
 * attributionRefusal (ABSENT, CONTRADICTION, UNSTABLE, BELOW_DEPTH, OBSERVATION_ERROR, RECORD_DAMAGED). Returns
 * { vIdx, virtualDaa, entryDaa, depth }.
 */
async function observeTreasuryUpgrade(config, rpc, { root, A, vault }) {
  const read = async (address, what) => {
    try {
      return await getAddressUtxos(rpc, address);
    } catch (e) {
      throw attributionRefusal("OBSERVATION_ERROR", `${what} ${address} could not be read from the node (${firstLine(e)}) — nothing is written`);
    }
  };
  const vaultId = vault.vaultId;
  let virtualDaa;
  try {
    virtualDaa = await require("./chain").readCanonicalVirtualDaaScore(rpc);
  } catch (e) {
    throw attributionRefusal("OBSERVATION_ERROR", `the node's virtual DAA score could not be read as a canonical integer (${firstLine(e)}) — nothing is written`);
  }
  const vIdx = kasProfile.vaultSuccessorIndexOf(A);
  let treasuryAddress, rootTarget;
  const inputs = new Map();
  try {
    if (!(vIdx >= 0)) throwFail(`request ${A.id}'s transaction declares no treasury successor output`, "RECORD_DAMAGED");
    treasuryAddress = spkToAddress(config, A.build.frozen.outputs[vIdx].scriptPublicKey);
    rootTarget = rootSuccessorTarget(config, A);
    for (const input of A.build.frozen.inputs) {
      const address = spkToAddress(config, input.utxo.scriptPublicKey);
      if (!inputs.has(address)) inputs.set(address, []);
      inputs.get(address).push(input.previousOutpoint);
    }
  } catch (e) {
    throw attributionRefusal("RECORD_DAMAGED", `${withoutModulePrefix(firstLine(e))} (request ${A.id}) — nothing is written`);
  }
  const first = observeFrozenOutputStrict(A, vIdx, await read(treasuryAddress, "the treasury successor address"));
  if (first.outcome === "ABSENT") throw attributionRefusal("ABSENT", `treasury ${vaultId}'s output ${A.txId}:${vIdx}, created by request ${A.id}'s transaction, is not reported unspent — ${vaultId} stays UNRESOLVED; nothing is written`);
  if (first.outcome !== "EXACT") throw attributionRefusal("CONTRADICTION", `treasury ${vaultId}'s successor is contradicted on chain: ${first.reason} — ${vaultId} stays UNRESOLVED; nothing is written`);
  for (const [address, outpoints] of inputs) {
    const refs = await read(address, "an input address of the attributed transaction");
    const present = outpoints.find((op) => refs.some((r) => sameOutpoint(r.outpoint, op)));
    if (present) throw attributionRefusal("CONTRADICTION", `input ${describeOutpoint(present)} of request ${A.id}'s transaction ${A.txId} is reported unspent, which contradicts its acceptance — ${vaultId} stays UNRESOLVED; nothing is written`);
  }
  let rootEntryDaa = null;
  if (sameOutpoint(root.live.outpoint, { transactionId: A.txId, index: rootTarget.rootOutIndex })) {
    const rootSeen = observeFrozenOutputStrict(A, rootTarget.rootOutIndex, await read(rootTarget.rootAddress, "the root successor address"));
    if (rootSeen.outcome === "ABSENT") throw attributionRefusal("UNSTABLE", `the root successor ${A.txId}:${rootTarget.rootOutIndex} is no longer reported unspent — nothing is written; Verify again`);
    if (rootSeen.outcome !== "EXACT") throw attributionRefusal("CONTRADICTION", `the root successor is contradicted on chain: ${rootSeen.reason} — nothing is written`);
    rootEntryDaa = canonicalDaaScore(rootSeen.entry.blockDaaScoreRaw);
    if (rootEntryDaa === null) throw attributionRefusal("OBSERVATION_ERROR", `the node reports no canonical accepting DAA score for the root successor ${A.txId}:${rootTarget.rootOutIndex} — nothing is written`);
  }
  const second = observeFrozenOutputStrict(A, vIdx, await read(treasuryAddress, "the treasury successor address"));
  if (second.outcome !== "EXACT" || !sameObservedEntry(first.entry, second.entry)) {
    throw attributionRefusal("UNSTABLE", `treasury ${vaultId}'s successor ${A.txId}:${vIdx} changed between two reads (EXACT then ${second.outcome === "EXACT" ? "another entry" : second.outcome}) — nothing is written; Verify again`);
  }
  const entryDaa = canonicalDaaScore(first.entry.blockDaaScoreRaw);
  if (entryDaa === null) throw attributionRefusal("OBSERVATION_ERROR", `the node reports no canonical accepting DAA score for treasury ${vaultId}'s successor ${A.txId}:${vIdx} — nothing is written`);
  if (virtualDaa < entryDaa) throw attributionRefusal("CONTRADICTION", `the node's virtual DAA score ${virtualDaa} is below the accepting DAA score ${entryDaa} of treasury ${vaultId}'s successor — nothing is written`);
  const depth = virtualDaa - entryDaa;
  if (depth < ATTRIBUTION_DEPTH_DAA) throw attributionRefusal("BELOW_DEPTH", `treasury ${vaultId}'s successor ${A.txId}:${vIdx} is at depth ${depth} DAA, below the required ${ATTRIBUTION_DEPTH_DAA} — ${vaultId} stays UNRESOLVED; nothing is written; Verify again later`);
  if (rootEntryDaa !== null && rootEntryDaa !== entryDaa) throw attributionRefusal("CONTRADICTION", `treasury ${vaultId}'s successor is reported at accepting DAA ${entryDaa}, the root successor of the same transaction at ${rootEntryDaa} — nothing is written`);
  return { vIdx, virtualDaa, entryDaa, depth };
}

/* A request that was never finalized, or that ended in a terminal refusal before any submission, cannot have produced
 * the chain effect: builders never broadcast, finalization is what produces the final transaction, and a withdrawal is
 * only granted to an unsigned/unattempted request, or (the RC45 stale delegate-rule withdrawal) to a never-attempted, unfinalized v0.7-kas
 * delegate-rule request whose period start aged out; an out-of-band broadcast of either needs the owners' quorum and the
 * fee key. Such a record is never associated as the completed request of a receipt or claim, is never a completion
 * candidate, and a failed inspection never writes onto it — otherwise a LEGACY pair of requests sharing one txid (an
 * owner operation withdrawn and rebuilt with the same fuel; a delegate spend built twice) would make the completed
 * request's association ambiguous and guard the vault forever (round-8 R8-01/R8-02). */
const NEVER_EFFECTIVE_STATES = new Set(["REFUSED", "WALLET_REJECTED", "BUILT", "AUTHORIZED"]);
function neverEffective(request) {
  if (!request) return true;
  if (NEVER_EFFECTIVE_STATES.has(request.state)) return true;
  // RC45 L2-01: a bound attribution marker records the proven chain effect of a request that never carried a final
  // transaction (its move was broadcast outside PolicyVault), so discovery replays it.
  if (boundAttributionMarker(request) !== null) return false;
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
  return SUBMISSION_EVIDENCE_STATES.has(request.state) || !!request.submissionAttempt || !!request.submissionOutcome || !!request.chain || boundAttributionMarker(request) !== null;
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
    q = kind === "rootAction" ? await loadOrgRootRequest(config, receipt.proof.requestId) : (await loadV7WalletRequest(config, receipt.proof.requestId)) ?? (await kasProfile.loadKasWalletRequest(config, receipt.proof.requestId));
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
    assertRequestTransactionBinding(config, q);
    const target = rootSuccessorTarget(config, q);
    if (!receiptMatches(receipt, q, target) || !rewound && (q.chain?.successorOutpoint !== `${txId}:${target.rootOutIndex}` || q.chain?.predecessorOutpoint !== describeOutpoint(q.manifest.root.outpoint))) return null;
  } else if (q.action === "tokenAgentSpend" || q.action === "tokenDeposit") {
    assertFrozenRequestTransaction(config, q);
    const expected = q.action === "tokenDeposit" ? receipt.proof?.outpoint : receipt.proof?.successorOutpoint;
    if (expected !== `${txId}:0`) return null;
  } else if (q.action === "agentSpend" && kasProfile.isKasBuild(q.build)) {
    assertFrozenRequestTransaction(config, q);
    if (receipt.proof?.successorOutpoint !== `${txId}:${kasProfile.vaultSuccessorIndexOf(q)}`) return null;
  } else if (q.kind === "kasGenesis" && kasProfile.isKasBuild(q.build)) {
    if (q.build.txId !== txId || receipt.proof?.outpoint !== `${txId}:${q.build.vaultOutputIndex}` || receipt.proof?.covenantId !== q.build.covenantId) return null;
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
  if (request.kind === "rootGenesis") return request.build.initialState;
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
    const vaultManifest = await loadRootedVaultAny(config, vaultId);
    if (!vaultManifest) {
      missing.push(`rooted vault ${vaultId} record missing`);
    } else {
      vaultPosition = await classifyVaultRecordAny(config, vaultManifest, request, vaultSuccessorIndex(request));
      const marker = boundAttributionMarker(request);
      if (vaultPosition.position === "BEYOND") {
        /* provably advanced past this transition: nothing to complete on the vault side */
      } else if (vaultPosition.position === "PREDECESSOR" && marker !== null && marker.mode === "PARTIAL") {
        /* RC45 L2-01: a PARTIAL attribution never writes the treasury (its successor output was spent outside
         * PolicyVault); the record left at the predecessor is this segment's complete state, UNRESOLVED, not missing */
        vaultPosition = { ...vaultPosition, segment: "UNRESOLVED" };
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
  if (kasProfile.isKasVaultRecord(vault)) {
    for (const q of await kasProfile.unfinishedDelegateRequests(config, vault)) {
      if (q.requestId !== exceptRequestId) throwFail(`vault has unfinished delegate request ${q.requestId} — reconcile that request first`, "VAULT_PENDING_REQUEST");
    }
  } else
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
      const position = q?.kind === "rootAction" ? await classifyVaultRecordAny(config, vault, q, vaultSuccessorIndex(q)) : null;
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
  assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7); // a delegate spend mutates an existing payment vault
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
/*
 * RC45 stale delegate-rule withdrawal: owner slot signatures alone no longer block the withdrawal of a v0.7-kas
 * delegate-rule change (named by both its recorded operation and its frozen build) that was never finalized and never
 * attempted and that root finalize would refuse PERIOD_START_STALE at the node's position read now
 * (kasDelegateRuleChangeAgedOut) — without it such a request would hold the root's reservation forever. Any other
 * signed request, an unreadable position, a missing treasury record or a registry that is not a list keeps
 * CANNOT_REJECT. Withdrawn, it is REFUSED (never effective, like the AUTHORIZED state it leaves) and the root's
 * reservation is released exactly as for an unsigned request.
 */
async function rejectOrgRootRequestUnlocked({ config, requestId, reason }) {
  const request = await loadOrgRootRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  /* RC45 R3N-B1 dispatch (amendment A1-4): only a SIGNED request enters the input-spent withdrawal (W1-W7); W8 finishes,
   * with no node read, a REFUSED request with a final transaction and a bound inputSpentWithdrawal (a crash between its
   * REFUSED save and the pointer save); every other request takes the existing path below, unchanged. */
  if (request.state === RequestState.SIGNED) return withdrawSpentInputRequest(config, request, reason);
  if (request.state === RequestState.REFUSED && request.finalTransaction && request.kind === "rootAction" && boundSpentWithdrawal(request)) {
    await releaseRootReservation(config, request);
    return request;
  }
  const slotSigned = request.slots?.some((s) => s.status === "SIGNED");
  const kasRule = slotSigned ? kasDelegateRuleChange(request) : null;
  if (![RequestState.AUTHORIZED, RequestState.REFUSED].includes(request.state) || request.signedSafeJson || request.finalTransaction || slotSigned && !(kasRule.recorded && kasRule.built)) {
    throwFail(`request is ${request.state} or carries signatures — only an unsigned request may be withdrawn`, "CANNOT_REJECT");
  }
  await assertRootRequestNotAttempted(config, request, "CANNOT_REJECT");
  if (slotSigned && !(await kasDelegateRuleChangeAgedOut(config, request))) {
    throwFail("request carries owner slot signatures — it may be withdrawn only once a new or changed delegate's budget period start has aged out of its window at the configured node's current network position (not the case, or not determinable now)", "CANNOT_REJECT");
  }
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
    assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7); // a delegate spend / deposit mutates an existing payment vault
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
  GENESIS_RECOVERY_STATES,
  verifyGenesisCompletion,
  recoverRootGenesisUnlocked,
  recoverVaultGenesisUnlocked,
  listRecoverableRootGenesisRequests,
  rootGenesisExpected,
  vaultGenesisExpected,
  assertFrozenRequestTransaction,
  assertRequestTransactionBinding,
  ATTRIBUTION_DEPTH_DAA,
  INPUT_SPENT_WITHDRAWAL_DEPTH_DAA,
  CHAIN_ANCHOR_HOPS,
  WITHDRAWAL_ANCHOR_MAX_AGE_DAA,
  WITHDRAWAL_SCAN_MAX_BATCHES,
  OOB_ATTRIBUTION_SCHEMA,
  observeFrozenOutputStrict,
  boundAttributionMarker,
  attributeOutOfBandRootTransition,
  settleStrandedByAttribution,
  rootHoldsAfterSettlement,
  treasuryUnresolved,
  treasuryUnresolvedOfRoot,
  assertTreasuryNotUnresolved,
  assertRecordedInputsLive,
  attributionSettlementHook,
  attributedReplayAnswer,
  upgradePartialAttributions,
  hasBoundRootCompletionReceipt,
  completedRequestAt,
  pendingRootRequests,
  loadRootedVaultAny,
  resolveFuel,
  resolveFunding,
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
