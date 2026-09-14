"use strict";
const { verifyFinalTransactionInputs } = require("./vm-preflight");
const { ownGet } = require("../../core/model/own-get");

/*
 * PolicyVault v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT (CANDIDATE — NOT
 * covenant-byte-frozen; docs/postlaunch/v0.7-kas-profile-readiness.md) —
 * server-orchestrated request pipeline. v0.7 mainnet-enablement directive
 * (2026-09-10): "the minimum contracts and product paths for a usable
 * on-chain organizational root with shared control of a native-KAS vault".
 *
 * Extends the EXISTING `/org-roots/:rootId/vaults` (genesis) and
 * `/wallet/v7/requests` (delegate spend + vault-level approvals) routes with
 * the KAS profile, mirroring sdk/src/wallet-requests-v7-hd.js's shape for
 * the funder-signed genesis and the delegate SUBMIT/reconcile ladder, and
 * sdk/src/wallet-requests-v4.js's approval collection for the vault-level
 * M-of-N tier (the frozen v0.4.1 mechanism, reused UNCHANGED through
 * sdk/src/vault-builders-v7-kas.js's createApprovalPackageForBuildV7Kas).
 *
 * ROOTED OWNER OPERATIONS (ownerSetAgentRoot / ownerSetApprovers /
 * ownerTopUp / ownerTopUpReserve / ownerPause / ownerUnpause /
 * ownerEmergencyPause / ownerRecover) are NOT built here: they are ROOT
 * REQUESTS (POST /org-roots/:rootId/requests with a vaultOperations entry)
 * and ride sdk/src/wallet-requests-v7.js's M-of-N pipeline through the
 * profile adapter sdk/src/rooted-kas-profile-v7.js — the same durable
 * claims, the same replayable completion, the same reconciliation.
 *
 * EVERY funds-relevant decision stays in sdk/src/vault-builders-v7-kas.js
 * and the shared core beneath it (core/model/vault-transitions-v7-kas.js,
 * core/intent/org-root-manifest-v7-kas.js, core/intent/vault-script-v7-kas.js);
 * this module ONLY orchestrates durable records, approval/signature
 * collection, submission and short-poll chain proof. Builders never
 * broadcast; a submit result is never success without exact chain proof;
 * only PROVEN chain reconciliation advances the durable vault record.
 *
 * Status: IMPLEMENTED. UNIT/API-TESTED by sdk/test/wallet-v7-kas-api.test.js.
 */

const crypto = require("crypto");

const { getStore, Categories } = require("./store");
const { withOrgRootLock } = require("./org-root-lock");
const { assertVaultIdentityFree, withVaultIdentityLock, normalizeVaultId } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): global vault-record uniqueness
const { assertOperationalNetwork, assertGenerationMainnetCreatable, assertGenerationMainnetOperable } = require("./config");
const { normalizeHex } = require("./vault-state");
const { kasToSompi, sompiToKas, parsePositiveSompi, parseSompi } = require("./amounts");
const { resolveAddressIdentity } = require("./address-identity");
const { connectVerified, getAddressUtxos, covenantAddress, loadKaspa } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { claimTransition, claimSubmission, loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
/* RC35-REC-01 (2026-09-11): shared submit-outcome settlement + observation-only genesis recovery primitives (sdk/src/genesis-recovery.js) */
const { settleGenesisSubmitError, settleTransitionSubmitError, anyFrozenOutputObserved, frozenInputLive, ensureOwnSubmissionClaim, unobservedRecoveryDisposition, refreshUnobservedGenesis } = require("./genesis-recovery");
const { appendAudit, readAudit } = require("./audit");
const { computeManifestHashV1 } = require("../../core/intent/canonical");
const { CONTRACT_VERSION_V7_KAS, computeStateIdV7Kas } = require("../../core/model/vault-state-v7-kas");
const { normalizeStateV4, stateToJsonV4 } = require("../../core/model/vault-state-v4");
const { buildCreateV7KasVault, buildV7KasTransaction, finalizeV7KasTransaction, createApprovalPackageForBuildV7Kas } = require("./vault-builders-v7-kas");
const { submitApprovalV4, isCompleteV4, collectedCountV4, missingSlotsV4 } = require("./approval-package-v4");
const { buildRootedKasVaultManifestV7, verifyRootedKasVaultManifestV7 } = require("../../core/intent/org-root-manifest-v7-kas");
const wr7 = require("./wallet-requests-v7");
const kasProfile = require("./rooted-kas-profile-v7");
const {
  MANIFEST_SCHEMA_V7_KAS,
  loadManifestV7Kas,
  persistManifestV7Kas,
  createManifestV7Kas,
  manifestToJsonV7Kas,
  listRootedKasVaultsV7,
  normalizeRegistry,
  registryEntryToJson,
  liveValueOfStateKas
} = require("./manifest-v7-kas");
const { VaultStatus } = require("./manifest");

const V7_KAS_WALLET_REQUEST_SCHEMA = "policyvault-wallet-request/v7-kas";
const AUTHORITY_MODEL_KAS = "ON_CHAIN_ORGANIZATIONAL_ROOT";
const KAS_ACTIONS = new Set(["agentSpend"]);
const GENESIS_ACTION = "createRootedKasVault";

const RequestState = Object.freeze({
  BUILT: "BUILT",
  AWAITING_APPROVALS: "AWAITING_APPROVALS",
  SIGNED: "SIGNED",
  SUBMITTING: "SUBMITTING",
  SUBMITTED: "SUBMITTED",
  CHAIN_VERIFIED: "CHAIN_VERIFIED",
  SUBMISSION_REJECTED: "SUBMISSION_REJECTED",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  WALLET_REJECTED: "WALLET_REJECTED",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  STALE: "STALE",
  BUILD_FAILED: "BUILD_FAILED",
  NOT_BROADCAST: "NOT_BROADCAST",
  SUPERSEDED: "SUPERSEDED"
});
const DELEGATE_PENDING_STATES = new Set([RequestState.SUBMITTING, RequestState.SUBMITTED, RequestState.RECONCILIATION_REQUIRED]);
const NEGATIVE_OUTCOMES = new Set([RequestState.NOT_BROADCAST, RequestState.SUBMISSION_REJECTED, RequestState.SUPERSEDED]);

function fail(message, code) {
  const e = new Error(`wallet-requests-v7-kas: ${message}`);
  if (code) e.code = code;
  return e;
}
function throwFail(message, code) {
  throw fail(message, code);
}

/* ------------------------------------------------------------------ */
/* durable store helpers                                               */
/* ------------------------------------------------------------------ */

async function loadKasWalletRequest(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  if (r && r.requestId !== requestId) throwFail("request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return r && r.schema === V7_KAS_WALLET_REQUEST_SCHEMA ? r : null;
}
async function saveKasWalletRequest(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function listKasWalletRequests(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST, { strict: true });
  const out = all.filter((r) => r && r.schema === V7_KAS_WALLET_REQUEST_SCHEMA && (vaultId === undefined || r.vaultId === vaultId));
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}
async function kasRequestRootId(config, request) {
  if (request.kind === "kasGenesis") {
    if (request.build.orgRootCovenantId !== request.build.template.orgRootCovenantId) throwFail("genesis root identity differs from its template", "REQUEST_ID_MISMATCH");
    return request.build.orgRootCovenantId;
  }
  const vault = await loadManifestV7Kas(config, request.vaultId);
  if (!vault) throwFail("KAS vault is missing", "VAULT_NOT_FOUND");
  return vault.orgRootCovenantId;
}
async function withKasRequestLock(config, requestId, callback) {
  const peek = await loadKasWalletRequest(config, requestId);
  if (!peek) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  const rootId = await kasRequestRootId(config, peek);
  return withOrgRootLock(rootId, async () => {
    const fresh = await loadKasWalletRequest(config, requestId);
    if (!fresh || (await kasRequestRootId(config, fresh)) !== rootId) throwFail("request changed its guarded root identity", "REQUEST_ID_MISMATCH");
    return callback();
  });
}

/* ------------------------------------------------------------------ */
/* small chain helpers (duplicated per-version by established convention) */
/* ------------------------------------------------------------------ */

function normalizeOutpoint(op, label) {
  return Object.freeze({ transactionId: normalizeHex(op?.transactionId, 32, `${label}.transactionId`), index: Number(op?.index) });
}
function sameOutpoint(a, b) {
  return Boolean(a && b) && String(a.transactionId).toLowerCase() === String(b.transactionId).toLowerCase() && Number(a.index) === Number(b.index);
}
function describeOutpoint(op) {
  return op ? `${op.transactionId}:${op.index}` : "(no live outpoint)";
}
async function findOutpoint(rpc, address, txId, index) {
  const utxos = await getAddressUtxos(rpc, address);
  return utxos.find((u) => u.outpoint.transactionId === txId && Number(u.outpoint.index) === Number(index)) ?? null;
}
function spkToAddress(config, spk) {
  const kaspa = loadKaspa(config);
  const address = kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId);
  if (!address) throwFail("could not derive an address from a scriptPublicKey — internal");
  return address.toString();
}
function assertImmutable(unsigned, signed) {
  const strip = (tx) => ({
    version: tx.version, lockTime: tx.lockTime, subnetworkId: tx.subnetworkId, gas: tx.gas, payload: tx.payload,
    inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })),
    outputs: tx.outputs
  });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throwFail("signed package mutated a consensus-visible field", "SIGNATURE_INVALID");
}
/* mode "create": a NEW KAS vault genesis (the creatable set minus the operator kill switch);
 * mode "operate": a delegate spend / approval / submission on an EXISTING vault (the operable set). */
function assertGate(config, code, mode = "operate") {
  try {
    assertOperationalNetwork(config);
    if (mode === "create") assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_KAS);
    else assertGenerationMainnetOperable(config, CONTRACT_VERSION_V7_KAS);
  } catch (e) {
    throw fail(e.message, e.code === "GENERATION_NOT_MAINNET_AUTHORIZED" ? e.code : code);
  }
}

/* Presentation the app-surface needs on EVERY KAS response: the authority
 * model (the organizational root), the candidate label, and — for a
 * delegate spend — the vault-level approval progress (counts + slots, never
 * raw signatures). */
function kasPresentation(request) {
  const pkg = request && request.approvalPackage;
  const approvalProgress = pkg
    ? { collected: collectedCountV4(pkg), required: Number(pkg.approvalM), complete: isCompleteV4(pkg), missingSlots: missingSlotsV4(pkg), approverSlots: pkg.approverSlots, approvedSlots: Array.isArray(pkg.approvals) ? pkg.approvals.map((a) => typeof a === "string") : [] }
    : request && request.kind === "agentSpend"
      ? { collected: 0, required: 0, complete: true, missingSlots: [], approverSlots: null, approvedSlots: [] }
      : null;
  return { authorityModel: AUTHORITY_MODEL_KAS, candidateStatus: "CANDIDATE", approvalProgress };
}
function present(request) {
  return { ...request, ...kasPresentation(request) };
}

/* ------------------------------------------------------------------ */
/* vault guards                                                        */
/* ------------------------------------------------------------------ */

async function assertKasGenesisComplete(config, vault) {
  const candidates = (await listKasWalletRequests(config, { vaultId: vault.vaultId })).filter((q) => q.kind === "kasGenesis" && q.txId === vault.creationTxId);
  const root = await wr7.loadOrgRoot(config, vault.orgRootCovenantId);
  if (candidates.some((q) => DELEGATE_PENDING_STATES.has(q.state)) || !root?.vaults?.includes(vault.vaultId)) throwFail("KAS genesis has unfinished durable records — submit or reconcile the genesis request first", "RECONCILIATION_REQUIRED");
}
/* The vault must have no unfinished delegate request and no pending / reserving root request naming it. */
async function assertKasVaultAvailable(config, vault, exceptRequestId = null) {
  for (const q of await kasProfile.unfinishedDelegateRequests(config, vault)) {
    if (q.requestId !== exceptRequestId) throwFail(`vault has unfinished delegate request ${q.requestId} — reconcile that request first`, "VAULT_PENDING_REQUEST");
  }
  const root = await wr7.loadOrgRoot(config, vault.orgRootCovenantId);
  for (const q of await wr7.pendingRootRequests(config, root)) {
    if (q.id !== exceptRequestId && q.vaultOperations?.some((op) => op.vaultId === vault.vaultId)) throwFail(`vault belongs to pending root request ${q.id}`, "VAULT_PENDING_REQUEST");
  }
  if (root?.pendingRequestId && root.pendingRequestId !== exceptRequestId) {
    const q = await wr7.loadOrgRootRequest(config, root.pendingRequestId);
    if (!q || q.rootCovenantId !== vault.orgRootCovenantId || q.vaultOperations?.some((op) => op.vaultId === vault.vaultId)) throwFail(`vault belongs to pending root request ${root.pendingRequestId}`, "VAULT_PENDING_REQUEST");
  }
}

/* ------------------------------------------------------------------ */
/* 1. GENESIS — POST /org-roots/:rootId/vaults { profile: "policyvault-0.7-kas" } */
/* ------------------------------------------------------------------ */

async function buildKasVaultGenesisRequest(args) {
  /* RC33-ID-01 (2026-09-11): the vault identity is fixed here so the WHOLE build (uniqueness check -> request write) is
   * serialized per identity INSIDE the root lock (lock order everywhere: root, then identity). A malformed identity falls
   * through to the unlocked build, which refuses it exactly as before. */
  let vaultId = null;
  try { vaultId = args.vaultId ? normalizeHex(args.vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex"); } catch { vaultId = null; }
  if (vaultId === null) return withOrgRootLock(args.rootCovenantId, () => buildKasVaultGenesisRequestUnlocked(args));
  return withOrgRootLock(args.rootCovenantId, () => withVaultIdentityLock(vaultId, () => buildKasVaultGenesisRequestUnlocked({ ...args, vaultId })));
}
async function buildKasVaultGenesisRequestUnlocked({ config, rootCovenantId, label = "", agents = [], approvers = [], approvalM = 0, recoveryAddress, depositKas, feeReserveKas, signerAddress, funding, vaultId }) {
  assertGate(config, "BUILD_FAILED", "create");
  const root = await wr7.loadOrgRoot(config, rootCovenantId);
  if (!root) throwFail(`no organizational root ${rootCovenantId}`, "ROOT_NOT_FOUND");
  if (!root.live) throwFail("this root has no confirmed on-chain outpoint yet — reconcile the root genesis first", "ROOT_STALE_OUTPOINT");

  const funderXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const recoveryPk = resolveAddressIdentity(config, recoveryAddress).xOnlyPubkey;
  let registry;
  try { registry = normalizeRegistry(agents); } catch (e) { throw fail(`the initial delegate policy set is malformed: ${e.message}`, e.code || "AGENT_SET_INVALID"); }
  const initialRegistry = registry.entries.map((e) => registryEntryToJson(e));
  if (!Array.isArray(approvers)) throwFail("approvers must be an array of x-only approver keys (may be empty)", "BUILD_FAILED");
  const approverKeys = approvers.map((a, i) => normalizeHex(a, 32, `approvers[${i}]`));
  const approvalMText = String(approvalM ?? 0);

  const protectedValue = kasToSompi(depositKas, "depositKas");
  if (protectedValue <= 0n) throwFail("depositKas must be a positive KAS amount — the protected principal is the vault's reason to exist", "BUILD_FAILED");
  const feeReserve = kasToSompi(feeReserveKas, "feeReserveKas");

  const vId = vaultId ? normalizeHex(vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex");
  await assertVaultIdentityFree(config, vId); // RC33-ID-01: an identity held by ANY generation's record or ANY request is refused before anything is built or written
  const template = {
    vaultId: vId,
    orgRootCovenantId: root.rootCovenantId,
    rootTemplateVmHash: root.template.rootTemplateVmHash ?? (root.rootPins && root.rootPins.rootTemplateVmHash),
    rootPrefixLen: root.rootPins ? root.rootPins.rootPrefixLen : root.template.rootPrefixLen,
    rootStateLen: root.rootPins ? root.rootPins.rootStateLen : root.template.rootStateLen,
    rootSuffixLen: root.rootPins ? root.rootPins.rootSuffixLen : root.template.rootSuffixLen,
    recoveryPk
  };
  const initialState = { protectedValue: protectedValue.toString(), feeReserve: feeReserve.toString(), paused: "0", agentRoot: registry.tree.root, approvers: approverKeys, approvalM: approvalMText, policyNonce: "0" };
  const fundingInputs = await wr7.resolveFunding(config, { funding }, signerAddress, protectedValue + feeReserve + 1_000_000n);

  let genesis;
  try {
    /* assertRootPinsMatchV7Kas inside the builder recompiles the REAL root (template + owner set) and refuses a vault whose owner path could never be exercised */
    genesis = buildCreateV7KasVault({ config, templateInput: template, initialStateInput: initialState, funding: fundingInputs, changeXOnly: funderXOnly, rootTemplate: root.template, rootOwnerSet: root.state });
  } catch (e) {
    throw fail(`v0.7-kas genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const summary = {
    kind: "genesis-summary",
    contractVersion: CONTRACT_VERSION_V7_KAS,
    networkId: config.networkId,
    vaultId: vId,
    covenantId: genesis.covenantId,
    orgRootCovenantId: root.rootCovenantId,
    template: genesis.template,
    initialState: genesis.initialState,
    agents: initialRegistry,
    approvers: approverKeys,
    approvalM: approvalMText,
    recoveryPk,
    depositKas: sompiToKas(protectedValue),
    feeReserveKas: sompiToKas(feeReserve),
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi
  };
  const requestId = crypto.randomUUID();
  const request = {
    schema: V7_KAS_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "kasGenesis",
    vaultId: vId,
    action: GENESIS_ACTION,
    contractVersion: CONTRACT_VERSION_V7_KAS,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly: funderXOnly,
    label,
    initialRegistry,
    approvers: approverKeys,
    approvalM: approvalMText,
    summary,
    signerVisibleDigest: computeManifestHashV1(summary),
    build: genesis,
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi,
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })), frozenCanonicalJson: genesis.frozenCanonicalJson }, // the browser rebuilds the vault script from the reviewed rules and cross-checks the wallet payload against these exact bytes
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveKasWalletRequest(config, request);
  return present(request);
}

/* ------------------------------------------------------------------ */
/* 2. DELEGATE SPEND — POST /wallet/v7/requests { action: "agentSpend" } */
/* ------------------------------------------------------------------ */

async function buildKasWalletRequest(args) {
  const vault = await loadManifestV7Kas(args.config, args.vaultId);
  if (!vault) throwFail(`no v0.7-kas rooted vault ${args.vaultId}`, "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => buildKasWalletRequestUnlocked(args));
}
async function buildKasWalletRequestUnlocked({ config, vaultId, action, params = {}, signerAddress }) {
  assertGate(config, "BUILD_FAILED");
  const manifest = await loadManifestV7Kas(config, vaultId);
  if (!manifest) throwFail(`no v0.7-kas rooted vault ${vaultId}`, "VAULT_NOT_FOUND");
  if (!manifest.live) throwFail(`vault is ${manifest.status} (closed) — read-only history`, "VAULT_TERMINAL");
  await assertKasGenesisComplete(config, manifest);
  if (!KAS_ACTIONS.has(action)) throwFail(`unknown v0.7-kas wallet action ${JSON.stringify(action)} — failing closed (owner operations are root requests)`, "UNKNOWN_ACTION");
  if (manifest.status !== VaultStatus.ACTIVE) throwFail(`vault status is ${manifest.status} — a delegate spend needs ACTIVE (a paused vault refuses every delegate spend in-covenant)`, "VAULT_PAUSED");
  await assertKasVaultAvailable(config, manifest);

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const entry = manifest.agentRegistry.find((e) => e.policy.agentPk === signerXOnly) ?? null;
  if (!entry) throwFail("the signer is not a registered delegate of this vault — a request is never built for a key the covenant's agent tree does not admit", "AGENT_NOT_REGISTERED");

  let recipient;
  if (typeof params.recipient === "string") recipient = normalizeHex(params.recipient, 32, "params.recipient");
  else if (typeof params.recipientAddress === "string") recipient = resolveAddressIdentity(config, params.recipientAddress).xOnlyPubkey;
  else throwFail("params.recipient (x-only key) or params.recipientAddress is required", "BUILD_FAILED");
  const payAmount = params.payAmountSompi !== undefined ? parsePositiveSompi(params.payAmountSompi, "params.payAmountSompi") : kasToSompi(params.amountKas, "params.amountKas");
  if (payAmount <= 0n) throwFail("the payment amount must be positive", "BUILD_FAILED");
  const periodsElapsed = params.periodsElapsed !== undefined ? parseSompi(params.periodsElapsed, "params.periodsElapsed") : 0n;
  const fuel = params.fuel ? params.fuel : null;

  const policies = manifest.agentRegistry.map((e) => { const { recipients, ...policy } = registryEntryToJson(e); void recipients; return policy; });
  let build;
  try {
    build = buildV7KasTransaction({
      config,
      contractVersion: CONTRACT_VERSION_V7_KAS,
      templateInput: manifest.template,
      stateInput: stateToJsonV4(manifest.live.state),
      action: "agentSpend",
      params: {
        payAmountSompi: payAmount.toString(),
        agentPk: signerXOnly,
        agents: policies,
        recipient,
        recipients: [...entry.recipients],
        periodsElapsed: periodsElapsed.toString(),
        ...(params.reserveConsumedSompi !== undefined ? { reserveConsumedSompi: params.reserveConsumedSompi } : {})
      },
      chain: { predecessorOutpoint: manifest.live.outpoint, covenantId: manifest.live.covenantId, predecessorValue: liveValueOfStateKas(manifest.live.state).toString(), ...(fuel ? { fuel } : {}) },
      changeXOnly: signerXOnly
    });
  } catch (e) {
    throw fail(`delegate spend build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  /* the vault-level M-of-N approval tier (frozen v0.4.1 mechanism, reused unchanged) — only above the agent's own threshold */
  const approvalPackage = build.aboveThreshold ? createApprovalPackageForBuildV7Kas(build) : null;

  /* the signer-visible manifest is REQUIRED and must VERIFY against the frozen bytes with the predecessor redeem bound
   * (R7-04): a request whose description cannot be verified is refused, never stored as "presentation only". */
  let manifestDoc;
  try {
    manifestDoc = buildRootedKasVaultManifestV7({ build, approvalPackage });
  } catch (e) {
    throw fail(`manifest build failed: ${e.message}`, e.code || "MANIFEST_BUILD_FAILED");
  }
  const failures = [];
  verifyRootedKasVaultManifestV7({ manifest: manifestDoc, frozen: JSON.parse(build.frozenCanonicalJson), redeemHex: build.vaultRedeemScriptHex, check: (name, ok, detail) => { if (!ok) failures.push({ name, detail }); } });
  if (failures.length) throwFail(`the built transaction failed rooted-KAS manifest verification: ${failures.map((f) => f.name).join(", ")}`, "INTENT_VERIFICATION_FAILED");

  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const requestId = crypto.randomUUID();
  const acc = build.accounting.kas;
  const request = {
    schema: V7_KAS_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "agentSpend",
    vaultId,
    action,
    contractVersion: CONTRACT_VERSION_V7_KAS,
    networkId: config.networkId,
    state: build.aboveThreshold ? RequestState.AWAITING_APPROVALS : RequestState.BUILT,
    signerAddress,
    signerXOnly,
    predecessorOutpoint: manifest.live.outpoint,
    predecessorStateId: manifest.live.stateId,
    predecessorVault: manifestToJsonV7Kas(manifest),
    build,
    manifest: manifestDoc,
    manifestHash: manifestDoc.manifestHash,
    signerVisibleDigest: manifestDoc.manifestHash,
    redeemScripts: { [manifest.live.covenantId]: build.vaultRedeemScriptHex }, // R7-04: the predecessor redeem travels with the request (browser + attestations rebuild + bind the scripts)
    aboveThreshold: build.aboveThreshold === true,
    approvalPackage,
    txId: build.txId,
    transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })), covenantInputIndex: 0, frozenCanonicalJson: build.frozenCanonicalJson }, // the browser verifies the manifest against these exact bytes (with the predecessor redeem) before the delegate signs or an approver co-signs
    requiredFeeSompi: build.requiredFeeSompi,
    review: {
      action,
      agentPk: signerXOnly,
      recipient,
      amountSompi: acc.payAmount,
      amountKas: sompiToKas(BigInt(acc.payAmount)),
      reserveConsumedSompi: acc.reserveConsumed,
      feeSompi: acc.fee,
      fuelFunded: build.hasFuelInput === true,
      aboveThreshold: build.aboveThreshold === true,
      approvalsRequired: build.aboveThreshold ? Number(build.stateJson.approvalM) : 0,
      approverSlots: build.stateJson.approverSlots.filter((k) => k !== "00".repeat(32)),
      policy: { maxPerSpend: build.callExtra.maxPerSpend, periodBudget: build.callExtra.periodBudget, periodSpent: build.callExtra.periodSpent, periodLengthDaa: build.callExtra.periodLengthDaa, periodStartDaa: build.callExtra.periodStartDaa, approvalThreshold: build.callExtra.approvalThreshold, agentMaxFeePerTx: build.callExtra.agentMaxFeePerTx },
      periodsElapsed: periodsElapsed.toString(),
      lockTime: String(build.frozen.lockTime),
      successorProtectedValue: acc.successorProtected,
      successorFeeReserve: acc.successorFeeReserve
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveKasWalletRequest(config, request);
  return present(request);
}

/* ------------------------------------------------------------------ */
/* 3. APPROVALS — POST /wallet/v7/requests/:id/approvals               */
/* ------------------------------------------------------------------ */

/* Collect ONE approver's 65-byte SIG_HASH_ALL Schnorr signature over the
 * frozen covenant input into its fixed slot (the approver signs the SAME
 * unsigned transaction the delegate does — input 0). Identical discipline to
 * sdk/src/wallet-requests-v4.js's collectApprovalV4. */
async function collectApprovalKas(args) {
  return withKasRequestLock(args.config, args.requestId, () => collectApprovalKasUnlocked(args));
}
async function collectApprovalKasUnlocked({ config, requestId, approverAddress, signedSafeJson, signatureHex }) {
  const request = await loadKasWalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.kind !== "agentSpend") throwFail("only a delegate spend collects vault-level approvals", "BUILD_FAILED");
  if (!request.aboveThreshold) throwFail("this spend is at/below the agent's approvalThreshold — agent authorization is sufficient; do not manufacture approvals", "BUILD_FAILED");
  if (request.state !== RequestState.AWAITING_APPROVALS) throwFail(`request is ${request.state}, not AWAITING_APPROVALS`, request.state);
  const vault = await loadManifestV7Kas(config, request.vaultId);
  if (!vault || !vault.live || vault.live.stateId !== request.predecessorStateId) {
    request.state = RequestState.STALE;
    await saveKasWalletRequest(config, request);
    throwFail("vault advanced since this request was built — rebuild required", "STALE");
  }
  let approverXOnly;
  try {
    approverXOnly = resolveAddressIdentity(config, approverAddress).xOnlyPubkey;
  } catch (e) {
    throw fail(`approver address rejected: ${e.message}`, "SIGNATURE_INVALID");
  }
  let sig = signatureHex;
  if (!sig && typeof signedSafeJson === "string") {
    let parsed;
    try { parsed = JSON.parse(signedSafeJson); } catch { throw fail("approver signed Safe JSON is not valid JSON", "SIGNATURE_INVALID"); }
    assertImmutable(JSON.parse(request.transaction.unsignedSafeJson), parsed);
    sig = parsed.inputs?.[0]?.signatureScript;
  }
  if (typeof sig !== "string" || !/^[0-9a-f]+$/.test(sig)) throw fail("approval signature is required (hex or signed Safe JSON)", "SIGNATURE_INVALID");
  if (sig.length === 132 && sig.startsWith("41")) sig = sig.slice(2); // strip a 0x41 push prefix -> raw 65-byte signature
  let pkg;
  try {
    pkg = submitApprovalV4(request.approvalPackage, { signatureHex: sig, approverXOnly });
  } catch (e) {
    throw fail(`approval rejected: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.approvalPackage = pkg;
  if (isCompleteV4(pkg)) request.state = RequestState.BUILT; // enough approvals collected; ready for the delegate's signature
  await saveKasWalletRequest(config, request);
  return { request: present(request), approvals: kasPresentation(request).approvalProgress };
}

/* ------------------------------------------------------------------ */
/* 4. SIGN (finalize)                                                   */
/* ------------------------------------------------------------------ */

/* RC33-ID-01 review finding F1 (2026-09-11): the signature and the submission of a genesis are serialized PER VAULT IDENTITY inside the existing root / signer / request lock (lock order unchanged: root / signer / request first, identity inside), so the commit-phase identity check and the signature store / claim / broadcast that follow it form ONE critical section — a pre-correction pair of drafts naming one identity can never double-sign or double-broadcast under concurrency. A request whose identity cannot be normalized falls through to the unlocked body, which refuses it exactly as before. Taken INSIDE the request (root) lock; the submit path locks the same way inside submitKasWalletRequestUnlocked. */
async function withKasGenesisIdentityLock(config, requestId, work) {
  const peek = await loadKasWalletRequest(config, requestId);
  let vaultId = null;
  try { vaultId = peek && peek.kind === "kasGenesis" ? normalizeVaultId(peek.vaultId) : null; } catch { vaultId = null; }
  return vaultId === null ? work() : withVaultIdentityLock(vaultId, work);
}
async function finalizeKasWalletRequest(args) {
  return withKasRequestLock(args.config, args.requestId, () => withKasGenesisIdentityLock(args.config, args.requestId, () => finalizeKasWalletRequestUnlocked(args)));
}
async function finalizeKasWalletRequestUnlocked({ config, requestId, signedSafeJson }) {
  const request = await loadKasWalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state === RequestState.AWAITING_APPROVALS) throwFail("approvals are still required before the delegate signs", "INSUFFICIENT_APPROVALS");
  if (request.state !== RequestState.BUILT) throwFail(`request is ${request.state}, not BUILT`, request.state);
  if (request.kind !== "kasGenesis") {
    const vault = await loadManifestV7Kas(config, request.vaultId);
    if (!vault) throwFail(`no vault ${request.vaultId}`, "VAULT_NOT_FOUND");
    await assertKasGenesisComplete(config, vault);
    if (!vault.live || vault.live.stateId !== request.predecessorStateId) {
      request.state = RequestState.STALE;
      await saveKasWalletRequest(config, request);
      throwFail("vault advanced since this request was built — rebuild required", "STALE");
    }
    await assertKasVaultAvailable(config, vault, request.requestId);
  }
  /* RC33-ID-01: a genesis whose identity became occupied (any generation's record, any OTHER request) is refused BEFORE its
   * signature is accepted — the request stays BUILT, nothing is stored. */
  if (request.kind === "kasGenesis") await assertVaultIdentityFree(config, request.vaultId, { exceptRequestId: request.requestId, exceptTxId: request.txId, phase: "commit" });
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    await saveKasWalletRequest(config, request);
    throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertImmutable(unsigned, signed);

  if (request.kind === "kasGenesis") {
    for (let i = 0; i < unsigned.inputs.length; i++) {
      if (!signed.inputs[i]?.signatureScript) {
        request.state = RequestState.WALLET_REJECTED;
        await saveKasWalletRequest(config, request);
        throwFail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
      }
    }
    request.signedSafeJson = signedSafeJson;
    request.state = RequestState.SIGNED;
    await saveKasWalletRequest(config, request);
    return present(request);
  }

  try {
    const agentSignatureHex = signed.inputs[0]?.signatureScript;
    if (!agentSignatureHex) throwFail("wallet did not sign the delegate (covenant) input", "WALLET_REJECTED");
    const hasFuel = request.build.hasFuelInput === true;
    const fuelIndex = request.build.frozen.inputs.length - 1;
    const fuelSignatureScriptHex = hasFuel ? signed.inputs[fuelIndex]?.signatureScript : undefined;
    if (hasFuel && !fuelSignatureScriptHex) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
    kasProfile.ensureBuildDirKas(config, request.build); // F-03
    const finalized = finalizeV7KasTransaction({ build: request.build, agentSignatureHex, approvalPackage: request.aboveThreshold ? request.approvalPackage : undefined, fuelSignatureScriptHex });
    verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
  } catch (e) {
    request.state = e.code === "WALLET_REJECTED" ? RequestState.WALLET_REJECTED : RequestState.SIGNATURE_INVALID;
    await saveKasWalletRequest(config, request);
    throw fail(`sign failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.state = RequestState.SIGNED;
  await saveKasWalletRequest(config, request);
  return present(request);
}

/* ------------------------------------------------------------------ */
/* 5. SUBMIT — the ONLY place a KAS genesis / delegate spend is broadcast */
/* ------------------------------------------------------------------ */

async function submitKasWalletRequest(args) {
  return withKasRequestLock(args.config, args.requestId, () => submitKasWalletRequestUnlocked(args));
}
async function submitKasWalletRequestUnlocked({ config, requestId, rpc: providedRpc, pollAttempts = 30, pollDelayMs = 2000 }) {
  const request = await loadKasWalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  /* RC35-REC-01 (independent RC35 affected review, 2026-09-11): a genesis persisted SUBMISSION_REJECTED is never settled by its
   * label — it is recovered by OBSERVATION ONLY through this same request (an observed vault output completes it: the negative
   * was false; an ESTABLISHED negative stays as it is; anything else is protected). Delegate negatives settle by proof. */
  if (request.kind !== "kasGenesis" && NEGATIVE_OUTCOMES.has(request.state) && request.submissionOutcome) return present(request);
  const recovering = DELEGATE_PENDING_STATES.has(request.state) || request.state === RequestState.CHAIN_VERIFIED || request.kind === "kasGenesis" && request.state === RequestState.SUBMISSION_REJECTED;
  if (request.state !== RequestState.SIGNED && !recovering) throwFail(`request is ${request.state}, not SIGNED`, request.state);
  assertGate(config, "NETWORK_MISMATCH");

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    if (request.kind === "kasGenesis") {
      if (!recovering) assertGate(config, "NETWORK_MISMATCH", "create");
      /* RC33-ID-01: submission / observation of a genesis is serialized per vault identity (inside the root lock) */
      return await withVaultIdentityLock(request.vaultId, () => submitKasGenesis({ config, rpc, request, pollAttempts, pollDelayMs, recovering }));
    }
    if (request.kind !== "agentSpend") throw fail(`unknown request kind ${request.kind}`, "UNKNOWN_REQUEST_KIND");
    if (recovering) return await recoverKasDelegateRequest({ config, rpc, request, pollAttempts: 1, pollDelayMs: 0, allowClaimRelease: true, via: "submit" });
    return await broadcastKasDelegate({ config, rpc, request, pollAttempts, pollDelayMs });
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* ---- genesis: funder-signed; the vault output IS the proof; recovery restores lost membership, never a stale record ---- */
async function submitKasGenesis({ config, rpc, request, pollAttempts, pollDelayMs, recovering }) {
  const { loadKaspa: load } = require("./chain");
  const { Transaction } = load(config);
  const outIndex = request.build.vaultOutputIndex;
  const out = request.build.frozen.outputs[outIndex];
  const address = covenantAddress(config, Buffer.from(request.build.vaultScriptHex, "hex"));
  const expectedValue = String(out.value);
  const observe = async () => {
    const ref = await findOutpoint(rpc, address, request.txId, outIndex);
    return ref && String(ref.covenantId ?? "").toLowerCase() === request.build.covenantId && String(ref.amount) === expectedValue ? ref : null;
  };
  const fromNegative = request.state === RequestState.SUBMISSION_REJECTED; // RC35-REC-01: recovering a persisted (possibly false) negative
  if (request.state === RequestState.CHAIN_VERIFIED) {
    /* a terminal label is not evidence of complete local state: the vault record must be this genesis and the root must list it */
    const current = await loadManifestV7Kas(config, request.vaultId);
    if (!current?.live || current.creationTxId !== request.txId || current.orgRootCovenantId !== request.build.orgRootCovenantId || current.live.covenantId !== request.build.covenantId) throwFail("KAS genesis recovery found a contradictory vault record — reconcile", "RECONCILIATION_REQUIRED");
    const root = await wr7.loadOrgRoot(config, current.orgRootCovenantId);
    if (!root) throwFail("KAS membership root is missing", "RECONCILIATION_REQUIRED");
    if (!root.vaults.includes(current.vaultId)) { root.vaults.push(current.vaultId); await wr7.saveOrgRoot(config, root); }
    return present(request);
  }
  if (!recovering) {
    /* RC33-ID-01: an occupied identity is refused BEFORE the submission claim and the broadcast — the SIGNED request is left exactly as it is */
    await assertVaultIdentityFree(config, request.vaultId, { exceptRequestId: request.requestId, exceptTxId: request.txId, phase: "commit" });
    const transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
    const signed = JSON.parse(request.signedSafeJson);
    const ins = transaction.inputs;
    for (let i = 0; i < ins.length; i++) ins[i].signatureScript = signed.inputs[i].signatureScript;
    transaction.inputs = ins;
    const computedTxId = transaction.finalize().toString().toLowerCase();
    if (computedTxId !== request.txId) throw fail(`reconstructed txid ${computedTxId} != frozen ${request.txId}`, "TXID_MISMATCH");
    await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.submitStartHash = await require("./submission-outcome-v7").readSubmissionStartHash(rpc);
    request.state = RequestState.SUBMITTING;
    await saveKasWalletRequest(config, request);
    let submitted;
    try {
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      /* RC35-REC-01 (the reviewer's finding): the node's "already accepted / already in the mempool" answer is a POSITIVE
       * answer about this transaction — never a rejection. A bound rejection settles the negative ONLY with the vault
       * output verified absent; anything else keeps the claim (RECONCILIATION_REQUIRED). */
      const settled = await settleGenesisSubmitError({ config, request, rpc, message, txId: request.txId, expected: { address, txId: request.txId, index: outIndex, value: expectedValue, covenantId: request.build.covenantId } });
      if (settled.decision === "REJECTED") {
        request.state = RequestState.SUBMISSION_REJECTED;
        request.submissionOutcome = { outcome: RequestState.SUBMISSION_REJECTED, reason: message, txId: request.txId, proof: settled.proof };
        await saveKasWalletRequest(config, request);
        await releaseSubmissionClaim(config, request.txId);
        throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
      }
      if (settled.decision === "UNCERTAIN") {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        request.error = `${message} — ${settled.reason}`;
        await saveKasWalletRequest(config, request);
        throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
      }
      request.submissionResponse = { kind: "ALREADY_KNOWN", variant: settled.classification.variant, reason: message, at: new Date().toISOString() };
      submitted = { transactionId: request.txId };
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveKasWalletRequest(config, request);
      throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    await saveKasWalletRequest(config, request);
  }
  let proof = null;
  for (let i = 0; i < pollAttempts && !proof; i++) {
    proof = await observe();
    if (!proof && i + 1 < pollAttempts) await new Promise((r) => setTimeout(r, pollDelayMs));
  }
  if (!proof) {
    /* RC35-REC-01: an unobserved output keeps an ESTABLISHED negative as it is (nothing rebroadcast, nothing rewritten); a false
     * negative (the stored node answer was ALREADY_KNOWN) or an unknown legacy answer is PROTECTED: claim re-established,
     * RECONCILIATION_REQUIRED; every other unresolved genesis stays unresolved with its claim */
    const disposition = await refreshUnobservedGenesis({ config, rpc, request, claim: { txId: request.txId, vaultId: request.vaultId, action: request.action }, save: (q) => saveKasWalletRequest(config, q) });
    if (disposition.action === "KEEP_NEGATIVE") return present(request);
    if (disposition.action === "PROTECT") await ensureOwnSubmissionClaim(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = disposition.reason ?? `${request.txId} submitted but the vault output was not observed — reconcile`;
    await saveKasWalletRequest(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  if (fromNegative) await ensureOwnSubmissionClaim(config, { txId: request.txId, vaultId: request.vaultId, action: request.action }); // the false negative released it; a conflicted completion must leave it in place
  const state = normalizeStateV4(request.build.initialState);
  const stateId = computeStateIdV7Kas({ networkId: config.networkId, template: request.build.template, state, contractVersion: CONTRACT_VERSION_V7_KAS });
  const expected = {
    schema: MANIFEST_SCHEMA_V7_KAS, contractVersion: CONTRACT_VERSION_V7_KAS, networkId: config.networkId,
    vaultId: request.build.template.vaultId, label: request.label ?? "", status: VaultStatus.ACTIVE,
    orgRootCovenantId: request.build.orgRootCovenantId, template: request.build.template,
    agentRegistry: request.initialRegistry ?? [],
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: request.txId, index: outIndex }, outpointValue: liveValueOfStateKas(state).toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId },
    creationTxId: request.txId, latestTransitionTxId: null, generation: 0
  };
  /* RC33-ID-01: ATOMIC create-only completion — sdk/src/vault-identity.js arbitrates the identity across EVERY generation
   * with the store's create-only primitive (never read-then-overwrite); an existing record is accepted only when it is this
   * exact genesis outcome. A different record (any generation, any creation) is never replaced. */
  let manifest;
  try {
    ({ manifest } = await createManifestV7Kas(config, expected));
  } catch (e) {
    if (e.code !== "RECONCILIATION_REQUIRED") throw e;
    /* RC33-ID-01: the identity holds a DIFFERENT record (any generation) — that record is never replaced; the proven chain
     * effect stays on THIS request (signed bytes, txid, submission claim intact) as RECONCILIATION_REQUIRED */
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = `chain effect proven but the vault record could not be created: ${String(e.message).split("\n")[0]}`;
    await saveKasWalletRequest(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  const root = await wr7.loadOrgRoot(config, request.build.orgRootCovenantId);
  if (!root) throwFail("KAS genesis root record is missing", "RECONCILIATION_REQUIRED");
  if (!root.vaults.includes(manifest.vaultId)) { root.vaults.push(manifest.vaultId); await wr7.saveOrgRoot(config, root); }
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (receipt && (receipt.vaultId !== manifest.vaultId || receipt.action !== GENESIS_ACTION)) throwFail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  if (!receipt) await persistReceipt(config, { txId: request.txId, vaultId: manifest.vaultId, action: GENESIS_ACTION, proof: { outpoint: `${request.txId}:${outIndex}`, covenantId: request.build.covenantId, requestId: request.requestId, requestKind: "vaultAction" } });
  if (!(await readAudit(config, { vaultId: manifest.vaultId, txId: request.txId, limit: 500 })).some((e) => e.action === GENESIS_ACTION && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, { vaultId: manifest.vaultId, action: GENESIS_ACTION, actor: "funder", contractVersion: CONTRACT_VERSION_V7_KAS, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v7-kas" });
  }
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  if (submission && (submission.vaultId !== manifest.vaultId || submission.action !== request.action)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  if (submission) await releaseSubmissionClaim(config, request.txId);
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = { successorOutpoint: `${request.txId}:${outIndex}`, observedAt: new Date().toISOString() };
  await saveKasWalletRequest(config, request);
  return present(request);
}

/* ---- delegate spend: durable claims BEFORE broadcast; PENDING is never success; exact successor proof advances the record ---- */
async function broadcastKasDelegate({ config, rpc, request, pollAttempts, pollDelayMs }) {
  const vault = await loadManifestV7Kas(config, request.vaultId);
  if (!vault) throwFail(`no vault ${request.vaultId}`, "VAULT_NOT_FOUND");
  await assertKasGenesisComplete(config, vault);
  if (!vault.live || vault.live.stateId !== request.predecessorStateId || !sameOutpoint(vault.live.outpoint, request.predecessorOutpoint)) {
    request.state = RequestState.STALE;
    await saveKasWalletRequest(config, request);
    throwFail("vault advanced since this request was built — rebuild required", "STALE");
  }
  await assertKasVaultAvailable(config, vault, request.requestId);
  const transaction = finalTxToWasm(config, request.finalTransaction);
  const computedTxId = transaction.finalize().toString().toLowerCase();
  if (computedTxId !== request.txId) throw fail(`reconstructed txid ${computedTxId} != frozen ${request.txId} — refusing to broadcast`, "TXID_MISMATCH");
  try {
    await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: request.txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected: { kind: "v7KasSuccessor", requestId: request.requestId } });
  } catch (e) {
    throw fail(e.message, "CLAIM_CONFLICT");
  }
  await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
  try { request.submitStartHash = await require("./submission-outcome-v7").readSubmissionStartHash(rpc); } catch { request.submitStartHash = null; }
  request.submittedAt = new Date().toISOString();
  request.submissionAttempt = { id: crypto.randomUUID(), phase: "PREPARING", requestFingerprint: wr7.completionReceiptPointer(request).requestFingerprint, at: request.submittedAt };
  request.state = RequestState.SUBMITTING;
  await saveKasWalletRequest(config, request);
  let submitted;
  try {
    request.submissionAttempt.phase = "BROADCAST_STARTED";
    await saveKasWalletRequest(config, request);
    submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
  } catch (e) {
    const message = String(e.message ?? e).split("\n")[0];
    request.error = message;
    /* RC35-REC-01: the shared classifier; a REJECTED verdict releases the claims only after the vault input is confirmed still
     * unspent AND every frozen output absent; a bound rejection the chain cannot confirm stays RECONCILIATION_REQUIRED with the
     * attempt recorded as REJECTED_RESPONSE (the outcome observer settles it by proof later); an already-known answer proceeds
     * to observation like an accepted response. */
    const settled = await settleTransitionSubmitError({ config, rpc, request, message, txId: request.txId, predecessorLive: () => frozenInputLive(config, rpc, request.build.frozen, 0), effectAbsent: async () => !(await anyFrozenOutputObserved(config, rpc, request.build.frozen, request.txId)) });
    if (settled.decision === "REJECTED") {
      request.submissionAttempt.phase = "REJECTED_RESPONSE";
      request.submissionAttempt.error = String(e.message ?? e);
      request.state = RequestState.SUBMISSION_REJECTED;
      request.submissionOutcome = { outcome: RequestState.SUBMISSION_REJECTED, reason: message, txId: request.txId, proof: settled.proof };
      await saveKasWalletRequest(config, request);
      await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
      await releaseSubmissionClaim(config, request.txId);
      throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
    }
    if (settled.decision === "UNCERTAIN") {
      if (settled.classification.kind === "REJECTED") { request.submissionAttempt.phase = "REJECTED_RESPONSE"; request.submissionAttempt.error = String(e.message ?? e); }
      request.state = RequestState.RECONCILIATION_REQUIRED;
      request.error = `${message} — ${settled.reason}`;
      await saveKasWalletRequest(config, request);
      throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.submissionResponse = { kind: "ALREADY_KNOWN", variant: settled.classification.variant, reason: message, at: new Date().toISOString() };
    submitted = { transactionId: request.txId };
  }
  request.submissionAttempt.phase = "ACCEPTED_RESPONSE";
  const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
  if (returnedTxId !== request.txId) {
    request.state = RequestState.RECONCILIATION_REQUIRED;
    await saveKasWalletRequest(config, request);
    throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
  }
  request.state = RequestState.SUBMITTED;
  await saveKasWalletRequest(config, request);
  return recoverKasDelegateRequest({ config, rpc, request, pollAttempts, pollDelayMs, allowClaimRelease: false, via: "submit" });
}

function successorTarget(config, request) {
  const idx = kasProfile.vaultSuccessorIndexOf(request);
  if (idx < 0) throwFail("the request's frozen transaction carries no vault successor output", "RECONCILIATION_REQUIRED");
  const out = request.build.frozen.outputs[idx];
  return { idx, address: spkToAddress(config, out.scriptPublicKey), value: String(out.value), covenantId: request.build.covenantId };
}
async function successorObserved(config, rpc, request) {
  const t = successorTarget(config, request);
  const ref = await findOutpoint(rpc, t.address, request.txId, t.idx);
  return ref && String(ref.amount) === t.value && String(ref.covenantId ?? "").toLowerCase() === t.covenantId ? { ...t, ref } : null;
}

/*
 * Prove the exact successor (short poll) and run the ONE replayable completion; when the successor is not observed and
 * claim release is allowed, ask the shared outcome observer for a SUPPORTED negative outcome (never age alone) and
 * settle it; otherwise the request stays truthfully RECONCILIATION_REQUIRED. Never rebroadcasts.
 */
async function recoverKasDelegateRequest({ config, rpc, request, pollAttempts = 1, pollDelayMs = 0, allowClaimRelease = true, stalePendingMinimumMs = 120000, via = "reconcile" }) {
  let proof = null;
  for (let i = 0; i < pollAttempts && !proof; i++) {
    proof = await successorObserved(config, rpc, request);
    if (!proof && i + 1 < pollAttempts) await new Promise((r) => setTimeout(r, pollDelayMs));
  }
  if (proof) {
    try {
      await completeKasDelegateRequest(config, request, { idx: proof.idx, via });
    } catch (e) {
      const detail = String(e && e.message ? e.message : e).split("\n")[0];
      request.state = RequestState.RECONCILIATION_REQUIRED;
      request.error = `chain effect proven but durable completion failed (${detail}) — reconcile to complete the vault records`;
      await saveKasWalletRequest(config, request);
      throw fail(request.error, "RECONCILIATION_REQUIRED");
    }
    return present(request);
  }
  if (request.state === RequestState.CHAIN_VERIFIED) return present(request);
  if (allowClaimRelease) {
    let outcome = null;
    const attempt = request.submissionAttempt;
    if (attempt && attempt.phase === "PREPARING" && attempt.requestFingerprint === wr7.completionReceiptPointer(request).requestFingerprint) outcome = { outcome: RequestState.NOT_BROADCAST, reason: "durable submission preparation never reached the node" };
    if (!outcome) {
      try { outcome = await require("./submission-outcome-v7").observeSubmissionOutcome(config, rpc, request, { stalePendingMinimumMs }); } catch { outcome = null; }
    }
    if (outcome && NEGATIVE_OUTCOMES.has(outcome.outcome)) {
      const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
      if (claim && claim.txId === request.txId) await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
      const sub = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
      if (sub && sub.vaultId === request.vaultId && sub.action === request.action) await releaseSubmissionClaim(config, request.txId);
      request.submissionOutcome = { ...outcome, txId: request.txId };
      request.state = outcome.outcome;
      request.error = outcome.reason ?? outcome.outcome;
      await saveKasWalletRequest(config, request);
      return present(request);
    }
  }
  request.state = RequestState.RECONCILIATION_REQUIRED;
  request.error = `${request.txId} was broadcast but its exact vault successor is not observed unspent — reconcile (nothing is rebroadcast)`;
  await saveKasWalletRequest(config, request);
  throw fail(request.error, "RECONCILIATION_REQUIRED");
}

/* ONE replayable, VALIDATED completion of a proven delegate spend: the vault record is classified against THIS request
 * (PREDECESSOR advanced by exactly one generation; SUCCESSOR repaired in place; BEYOND preserved; OTHER refused),
 * claims released only when ours, receipt + audit idempotent, the request CHAIN_VERIFIED last. */
async function completeKasDelegateRequest(config, request, { idx, via }) {
  const vault = await loadManifestV7Kas(config, request.vaultId);
  if (!vault) throwFail(`no vault ${request.vaultId} for a proven delegate spend — refusing to record an unrecoverable completion`, "RECONCILIATION_REQUIRED");
  const c = await kasProfile.classifyVaultRecord(config, vault, request, idx, { completedRequestAt: wr7.completedRequestAt });
  const completion = { via, vault: null, claims: {}, receipt: null, audit: null };
  if (c.position === "PREDECESSOR") {
    await persistManifestV7Kas(config, kasProfile.expectedVaultSuccessorDoc(config, vault, request, idx, Number(vault.generation ?? 0) + 1));
    completion.vault = "ADVANCED";
  } else if (c.position === "SUCCESSOR" && c.consistent) {
    completion.vault = "ALREADY_COMPLETE";
  } else if (c.position === "SUCCESSOR") {
    await persistManifestV7Kas(config, kasProfile.expectedVaultSuccessorDoc(config, vault, request, idx, Number(vault.generation ?? 0)));
    completion.vault = "REPAIRED";
    completion.vaultDifferences = c.differences;
  } else if (c.position === "BEYOND") {
    completion.vault = "BEYOND";
  } else {
    throwFail(`vault ${vault.vaultId} is at ${describeOutpoint(vault.live ? vault.live.outpoint : null)} — neither this request's predecessor nor its successor (${c.differences.join("; ")})`, "VAULT_STATE_UNEXPECTED");
  }
  const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
  if (claim && claim.txId === request.txId) { await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId }); completion.claims.predecessor = "RELEASED"; }
  else completion.claims.predecessor = claim ? `FOREIGN:${claim.txId}` : "ABSENT";
  const sub = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  if (sub && (sub.vaultId !== request.vaultId || sub.action !== request.action)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  completion.claims.submission = sub && (await releaseSubmissionClaim(config, request.txId)) ? "RELEASED" : "ABSENT";
  const pointer = wr7.completionReceiptPointer(request);
  const existing = await getStore(config).read(Categories.RECEIPT, request.txId);
  const receiptOk = existing && existing.txId === request.txId && existing.vaultId === request.vaultId && existing.action === request.action && existing.proof && Object.entries(pointer).every(([k, v]) => existing.proof[k] === v) && existing.proof.successorOutpoint === `${request.txId}:${idx}`;
  if (receiptOk) completion.receipt = "ALREADY_PRESENT";
  else {
    if (existing && existing.proof && existing.proof.requestId && existing.proof.requestId !== request.requestId) throwFail("completion receipt names another request", "REQUEST_ID_MISMATCH");
    await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { ...pointer, predecessorOutpoint: describeOutpoint(request.predecessorOutpoint), successorOutpoint: `${request.txId}:${idx}`, reconciled: via !== "submit" } });
    completion.receipt = existing ? "REPAIRED" : "WRITTEN";
  }
  const audit = await readAudit(config, { vaultId: request.vaultId, txId: request.txId, limit: 500 });
  if (audit.some((e) => e.txId === request.txId && e.action === request.action && e.result === "CHAIN_VERIFIED")) completion.audit = "ALREADY_PRESENT";
  else {
    await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "agent", contractVersion: CONTRACT_VERSION_V7_KAS, txId: request.txId, result: "CHAIN_VERIFIED", via: `wallet/v7-kas/${via}` });
    completion.audit = "WRITTEN";
  }
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = { predecessorOutpoint: describeOutpoint(request.predecessorOutpoint), successorOutpoint: `${request.txId}:${idx}`, observedAt: request.chain?.observedAt ?? new Date().toISOString(), completion: { ...completion, completedAt: new Date().toISOString() } };
  await saveKasWalletRequest(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 6. REJECT                                                            */
/* ------------------------------------------------------------------ */

async function markKasWalletRejected(config, requestId) {
  const peek = await loadKasWalletRequest(config, requestId);
  if (!peek) return null;
  return withKasRequestLock(config, requestId, () => markKasWalletRejectedUnlocked(config, requestId));
}
async function markKasWalletRejectedUnlocked(config, requestId) {
  const request = await loadKasWalletRequest(config, requestId);
  if (request && (request.state === RequestState.BUILT || request.state === RequestState.AWAITING_APPROVALS)) {
    request.state = RequestState.WALLET_REJECTED;
    await saveKasWalletRequest(config, request);
  }
  return request ? present(request) : null;
}

/* ------------------------------------------------------------------ */
/* 7. RECONCILE — deferred / crash-recovery for ONE KAS vault           */
/* ------------------------------------------------------------------ */

/*
 * Same case taxonomy as sdk/src/reconcile-v7.js (A CONSISTENT, B CLAIM_PENDING, C CLAIM_RELEASED, D ADVANCED,
 * E UNKNOWN, F node error propagates). Owner operations that rode a root transition are completed by the root
 * pipeline's own reconciliation (completeProvenRootAction through the profile adapter); this function finishes the
 * vault's DELEGATE requests and reads back its own outpoint. Never broadcasts, never guesses a record into a new shape.
 */
async function reconcileKasVault(config, rpc, vaultId, { stalePendingMinimumMs = 120000, allowClaimRelease = true } = {}) {
  const manifest = await loadManifestV7Kas(config, vaultId);
  if (!manifest) return { status: "NOT_FOUND", vaultId };
  const completion = [];
  let failed = null;
  for (const q of await kasProfile.unfinishedDelegateRequests(config, manifest)) {
    try {
      const fresh = await loadKasWalletRequest(config, q.requestId);
      await recoverKasDelegateRequest({ config, rpc, request: fresh, pollAttempts: 1, pollDelayMs: 0, allowClaimRelease, stalePendingMinimumMs, via: "reconcile" });
      completion.push({ requestId: fresh.requestId, txId: fresh.txId, outcome: fresh.state });
    } catch (e) {
      failed ??= { requestId: q.requestId, reason: e.message };
    }
  }
  const current = await loadManifestV7Kas(config, vaultId);
  if (!current.live) return { status: "TERMINAL", vaultId, vaultStatus: current.status, ...(completion.length ? { completion } : {}) };
  const { compileExactStateV7Kas } = require("./contract-compiler-v7-kas");
  const compiled = compileExactStateV7Kas({ config, template: current.template, state: current.live.state, contractVersion: current.contractVersion });
  if (compiled.scriptSha256 !== current.live.scriptSha256) throwFail("compiled current vault state does not match the manifest script hash — failing closed", "RECONCILIATION_REQUIRED");
  const address = covenantAddress(config, Buffer.from(compiled.scriptHex, "hex"));
  const liveRef = await findOutpoint(rpc, address, current.live.outpoint.transactionId, current.live.outpoint.index);
  const claim = await loadTransitionClaim(config, current.live.outpoint);
  const withCompletion = (result) => (completion.length ? { ...result, completion } : result);
  if (failed) return withCompletion({ status: "UNKNOWN", vaultId, requestId: failed.requestId, reason: failed.reason });
  if (liveRef) {
    if (!claim) return withCompletion({ status: completion.some((c) => c.outcome === "CHAIN_VERIFIED") ? "ADVANCED" : completion.length ? "CLAIM_RELEASED" : "CONSISTENT", vaultId });
    return withCompletion({ status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, reason: claim.expected?.kind === "orgRootRequest" ? "a root-authorized operation reserves this vault — reconcile the organizational root" : "claim outcome is unresolved; age and an unspent vault alone cannot release it" });
  }
  if (claim && claim.expected?.kind === "v7KasSuccessor" && claim.expected.requestId) {
    const req = await loadKasWalletRequest(config, claim.expected.requestId);
    if (req && req.txId === claim.txId) {
      try {
        await recoverKasDelegateRequest({ config, rpc, request: req, pollAttempts: 1, pollDelayMs: 0, allowClaimRelease, stalePendingMinimumMs, via: "reconcile" });
        return withCompletion({ status: req.state === "CHAIN_VERIFIED" ? "ADVANCED" : "CLAIM_RELEASED", vaultId, txId: req.txId, requestId: req.requestId });
      } catch (e) {
        return withCompletion({ status: "UNKNOWN", vaultId, requestId: req.requestId, reason: e.message });
      }
    }
  }
  if (claim && claim.expected?.kind === "orgRootRequest") return withCompletion({ status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, reason: "a root-authorized operation consumed this vault outpoint — reconcile the organizational root to complete it" });
  return withCompletion({ status: "UNKNOWN", vaultId, reason: claim ? "claim present but the expected effect is not provable" : "live outpoint gone, no claim" });
}

module.exports = {
  V7_KAS_WALLET_REQUEST_SCHEMA,
  AUTHORITY_MODEL_KAS,
  RequestState,
  KAS_ACTIONS,
  GENESIS_ACTION,
  loadKasWalletRequest,
  saveKasWalletRequest,
  listKasWalletRequests,
  buildKasVaultGenesisRequest,
  buildKasWalletRequest,
  collectApprovalKas,
  finalizeKasWalletRequest,
  submitKasWalletRequest,
  markKasWalletRejected,
  reconcileKasVault,
  listRootedKasVaultsV7,
  kasPresentation,
  assertKasVaultAvailable
};
