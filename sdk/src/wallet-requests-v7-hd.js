"use strict";
const { verifySignedSafeJsonInputs, verifyFinalTransactionInputs } = require("./vm-preflight");
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV7Hd } = require("./contract-compiler-v7");
const { ownGet } = require("../../core/model/own-get");

/*
 * PolicyVault v0.7-payment-hd HIERARCHICAL-DELEGATION rooted vault
 * (CANDIDATE — NOT covenant-byte-frozen, NOT production, NOT externally
 * reviewed; docs/postlaunch/v0.7-hd-readiness.md) — server-orchestrated
 * request pipeline (Wave 2 Track E; docs/postlaunch/
 * v0.7-app-surface-contract.md §6.1). Extends the EXISTING
 * `/org-roots/:rootId/vaults` (genesis) and `/wallet/v7/requests`
 * (spend/delegation/deposit) routes with the HD profile, mirroring
 * sdk/src/wallet-requests-v7.js's §8 delegate-spend pattern for the
 * SUBMIT/reconcile ladder, and reusing its genesis single-signer flow
 * (server/src/org-roots.js's POST .../vaults + .../requests/:id/signature)
 * for the funder-signed genesis.
 *
 * EVERY funds-relevant decision stays in sdk/src/vault-builders-v7-hd.js
 * (untouched by this file) and core/model/hd-leaf-v7.js beneath it; this
 * module ONLY orchestrates the durable delegation FOREST (manifest-v7-hd.js),
 * request records, signature collection, submission, and short-poll chain
 * proof.
 *
 * SCOPE (recorded honestly): rooted OWNER operations on an HD vault
 * (ownerSetAgentRoot / ownerTopUpReserve / ownerPause / ownerUnpause /
 * ownerEmergencyPause / ownerRecover) are NOT wired in this track — the
 * app-surface contract's §6.1 action list for /wallet/v7/requests names
 * only the five HD spend/delegation entrypoints + tokenDeposit for the
 * HD profile ("rooted owner ops stay ROOT REQUESTS (§2)"); wiring
 * `vault-builders-v7-hd.js`'s buildV7HdOwnerTransaction into
 * org-roots.js's buildRootActionRequest vaultOperations path is future
 * work for the track that owns §2.
 *
 * Status: IMPLEMENTED (Wave 2 Track E). UNIT/API-TESTED by
 * sdk/test/wallet-v7-hd-api.test.js.
 */

const crypto = require("crypto");

const { getStore, Categories } = require("./store");
const { withOrgRootLock } = require("./org-root-lock");
const { assertOperationalNetwork, assertGenerationMainnetCreatable } = require("./config");
const { normalizeHex } = require("./vault-state");
const { resolveAddressIdentity } = require("./address-identity");
const { connectVerified, getAddressUtxos } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { claimTransition, claimSubmission, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
const { appendAudit, readAudit } = require("./audit");
const hd = require("../../core/model/hd-leaf-v7");

const { normalizeStateV7, stateToJsonV7 } = require("../../core/model/vault-state-v7");
const { computeStateIdV7Hd } = require("./contract-compiler-v7");
const {
  CONTRACT_VERSION_V7_HD,
  HD_SPEND_LEVEL,
  HD_DELEGATION_LEVEL,
  buildCreateV7HdVault,
  buildHdSpendTransaction,
  buildHdDelegationTransaction,
  finalizeHdTransaction,
  buildTokenDepositV7,
  finalizeTokenDepositV7
} = require("./vault-builders-v7-hd");
const { loadOrgRoot, templateFieldsFromDescriptor } = require("./wallet-requests-v7");
const { loadManifestV7Hd, persistManifestV7Hd, normalizeManifestV7Hd, manifestToJsonV7Hd, listRootedHdVaultsV7, forestAsTreeInput, normalizeForestNode, MANIFEST_SCHEMA_V7_HD } = require("./manifest-v7-hd");
const { canonicalJsonStringify } = require("../../core/intent/canonical");
const { VaultStatus } = require("./manifest");

const V7_HD_WALLET_REQUEST_SCHEMA = "policyvault-wallet-request/v7-hd";
const AUTHORITY_MODEL_HD = "ON_CHAIN_ORGANIZATIONAL_ROOT";
const HD_ACTIONS = new Set([...Object.keys(HD_SPEND_LEVEL), ...Object.keys(HD_DELEGATION_LEVEL)]);

const RequestState = Object.freeze({
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

const EXPIRY_STATEMENT = "expiry is enforced by PolicyVault's core and by revocation, not by consensus";

function fail(message, code) {
  const e = new Error(`wallet-requests-v7-hd: ${message}`);
  if (code) e.code = code;
  return e;
}
function throwFail(message, code) {
  throw fail(message, code);
}

/* ------------------------------------------------------------------ */
/* durable store helpers                                               */
/* ------------------------------------------------------------------ */

async function loadHdWalletRequest(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  if (r && r.requestId !== requestId) throwFail("request identity differs from its storage key", "REQUEST_ID_MISMATCH");
  return r && r.schema === V7_HD_WALLET_REQUEST_SCHEMA ? r : null;
}
async function hdRequestRootId(config, request) {
  if (request.kind === "hdGenesis") {
    if (request.build.orgRootCovenantId !== request.build.template.orgRootCovenantId) throwFail("genesis root identity differs from its template", "REQUEST_ID_MISMATCH");
    return request.build.orgRootCovenantId;
  }
  const vault = await loadManifestV7Hd(config, request.vaultId);
  if (!vault) throwFail("HD vault is missing", "VAULT_NOT_FOUND");
  return vault.orgRootCovenantId;
}
async function withHdRequestLock(config, requestId, callback) {
  const peek = await loadHdWalletRequest(config, requestId);
  if (!peek) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  const rootId = await hdRequestRootId(config, peek);
  return withOrgRootLock(rootId, async () => {
    const fresh = await loadHdWalletRequest(config, requestId);
    if (!fresh || await hdRequestRootId(config, fresh) !== rootId) throwFail("request changed its guarded root identity", "REQUEST_ID_MISMATCH");
    return callback();
  });
}
async function assertHdGenesisComplete(config, vault) {
  const candidates = (await listHdWalletRequests(config, { vaultId: vault.vaultId })).filter((q) => q.kind === "hdGenesis" && q.txId === vault.creationTxId);
  if (candidates.some((q) => ["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"].includes(q.state)) || !(await loadOrgRoot(config, vault.orgRootCovenantId))?.vaults?.includes(vault.vaultId)) throwFail("HD genesis has unfinished durable records — resume its original submission", "RECONCILIATION_REQUIRED");
}
async function saveHdWalletRequest(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function listHdWalletRequests(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST, { strict: true });
  const out = all.filter((r) => r && r.schema === V7_HD_WALLET_REQUEST_SCHEMA && (vaultId === undefined || r.vaultId === vaultId));
  return out.sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/* ------------------------------------------------------------------ */
/* small chain helpers (duplicated per-version by established convention) */
/* ------------------------------------------------------------------ */

function normalizeOutpoint(op, label) {
  return Object.freeze({ transactionId: normalizeHex(op?.transactionId, 32, `${label}.transactionId`), index: Number(op?.index) });
}
async function findOutpoint(rpc, address, txId, index) {
  const utxos = await getAddressUtxos(rpc, address);
  return utxos.find((u) => u.outpoint.transactionId === txId && Number(u.outpoint.index) === Number(index)) ?? null;
}
function spkToAddress(config, spk) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const address = kaspa.addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId);
  if (!address) fail("could not derive an address from a scriptPublicKey — internal");
  return address.toString();
}

/* Present the ancestor chain / effective authority / expiry statement a
 * build already computed, in the shape the app-surface contract §6.1
 * requires on EVERY HD response. */
function hdPresentation(build) {
  return {
    authorityModel: AUTHORITY_MODEL_HD,
    status: "CANDIDATE",
    ancestorChain: build.ancestorChain ?? null,
    effectiveAuthority: build.effectiveAuthority ?? null,
    level: build.level ?? null,
    expiryStatement: EXPIRY_STATEMENT
  };
}

/* ------------------------------------------------------------------ */
/* 1. GENESIS — POST /org-roots/:rootId/vaults { profile: "policyvault-0.7-payment-hd" } */
/* ------------------------------------------------------------------ */

async function buildHdVaultGenesisRequest(args) {
  return withOrgRootLock(args.rootCovenantId, () => buildHdVaultGenesisRequestUnlocked(args));
}
async function buildHdVaultGenesisRequestUnlocked({ config, rootCovenantId, label = "", descriptor, templateIndex = 0, initialAgents = [], recoveryAddress, feeReserveKas, signerAddress, funding, vaultId }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_HD);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const root = await loadOrgRoot(config, rootCovenantId);
  if (!root) throwFail(`no organizational root ${rootCovenantId}`, "ROOT_NOT_FOUND");
  if (!root.live) throwFail("this root has no confirmed on-chain outpoint yet — reconcile the root genesis first", "ROOT_STALE_OUTPOINT");

  const funderXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const recoveryPk = resolveAddressIdentity(config, recoveryAddress).xOnlyPubkey;
  const { validated, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen } = templateFieldsFromDescriptor(descriptor, templateIndex);

  const forestNodes = (Array.isArray(initialAgents) ? initialAgents : []).map((a, i) => {
    const { recipients, kids, ...leaf } = a;
    return normalizeForestNode({ leaf, recipients, kids: kids ?? [] }, 1, i);
  });
  if (forestNodes.length === 0) throwFail("initialAgents (at least one level-1 HD leaf) is required", "BUILD_FAILED");
  const agentRoot = hd.forestRoot(forestNodes);
  const { kasToSompi } = require("./amounts");

  const vId = vaultId ? normalizeHex(vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex");
  const template = {
    vaultId: vId, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen,
    orgRootCovenantId: root.rootCovenantId,
    rootTemplateVmHash: root.template.rootTemplateVmHash ?? (root.rootPins && root.rootPins.rootTemplateVmHash),
    rootPrefixLen: root.rootPins ? root.rootPins.rootPrefixLen : root.template.rootPrefixLen,
    rootStateLen: root.rootPins ? root.rootPins.rootStateLen : root.template.rootStateLen,
    rootSuffixLen: root.rootPins ? root.rootPins.rootSuffixLen : root.template.rootSuffixLen,
    recoveryPk
  };
  const feeReserveSompi = kasToSompi(feeReserveKas, "feeReserveKas");
  const initialState = { feeReserve: feeReserveSompi.toString(), paused: "0", agentRoot, policyNonce: "0" };

  if (!Array.isArray(funding) || funding.length === 0) throwFail("funding (a non-empty array of the funder's ordinary UTXOs) is required", "BUILD_FAILED");

  let genesis;
  try {
    genesis = buildCreateV7HdVault({ config, templateInput: template, initialStateInput: initialState, funding, changeXOnly: funderXOnly, descriptor: validated });
  } catch (e) {
    throw fail(`v0.7-payment-hd genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  const request = {
    schema: V7_HD_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "hdGenesis",
    vaultId: vId,
    action: "createRootedHdVault",
    contractVersion: CONTRACT_VERSION_V7_HD,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly: funderXOnly,
    label,
    descriptor: validated,
    templateIndex,
    initialForest: forestNodes.map((n) => ({ leaf: hd.hdLeafToJson(n.leaf), recipients: [...n.recipients], kids: [] })),
    build: genesis,
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi,
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveHdWalletRequest(config, request);
  return { ...request, authorityModel: AUTHORITY_MODEL_HD, status: "CANDIDATE" };
}

/* ------------------------------------------------------------------ */
/* 2. SPEND / DELEGATION / TOKEN DEPOSIT — POST /wallet/v7/requests     */
/* ------------------------------------------------------------------ */

async function buildHdWalletRequest(args) {
  const vault = await loadManifestV7Hd(args.config, args.vaultId);
  if (!vault) throwFail("HD vault is missing", "VAULT_NOT_FOUND");
  return withOrgRootLock(vault.orgRootCovenantId, () => buildHdWalletRequestUnlocked(args));
}
async function buildHdWalletRequestUnlocked({ config, vaultId, action, params = {}, signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_HD);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = await loadManifestV7Hd(config, vaultId);
  if (!manifest) throwFail(`no v0.7-payment-hd rooted vault ${vaultId}`, "VAULT_NOT_FOUND");
  if (!manifest.live) throwFail(`vault is ${manifest.status} (closed) — read-only history`, "VAULT_TERMINAL");
  await assertHdGenesisComplete(config, manifest);

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const changeXOnly = signerXOnly;

  if (action === "tokenDeposit") {
    if (manifest.live.tokenPosition !== null) {
      throwFail("this vault already holds a tracked token position — a second deposit would create an untracked same-family UTXO; failing closed", "TOKEN_POSITION_ALREADY_HELD");
    }
    const userPositionOutpoint = normalizeOutpoint(params.userPosition?.outpoint, "params.userPosition.outpoint");
    let build;
    try {
      build = buildTokenDepositV7({
        config,
        descriptor: manifest.asset.descriptor,
        templateIndex: manifest.asset.templateIndex,
        vault: { covenantId: manifest.live.covenantId, template: manifest.template },
        chain: { userPosition: { ...params.userPosition, outpoint: userPositionOutpoint }, fuel: params.fuel },
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
      schema: V7_HD_WALLET_REQUEST_SCHEMA, requestId, kind: "tokenDeposit", vaultId, action,
      contractVersion: CONTRACT_VERSION_V7_HD, networkId: config.networkId, state: RequestState.BUILT,
      signerAddress, signerXOnly, predecessorOutpoint: userPositionOutpoint, build, txId: build.txId,
      transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
      requiredFeeSompi: build.requiredFeeSompi, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
    };
    await saveHdWalletRequest(config, request);
    return { ...request, authorityModel: AUTHORITY_MODEL_HD, status: "CANDIDATE" };
  }

  if (!HD_ACTIONS.has(action)) throwFail(`unknown v0.7-payment-hd action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  if (manifest.status !== VaultStatus.ACTIVE) throwFail(`vault status is ${manifest.status} — this action needs ACTIVE`, "BUILD_FAILED");

  const isSpend = ownGet(HD_SPEND_LEVEL, action) !== undefined; // own-property only (F-05)
  const treeInput = forestAsTreeInput(manifest);
  if (!Array.isArray(params.path)) throwFail("params.path (an array of child indices, one per ancestor level, resolving into the durable delegation forest) is required", "HD_CHAIN_STALE");

  /*
   * A delegation REPLACES the acting level's entire child SUBTREE. The
   * caller must supply the full new subtree (params.newChildTree, the SAME
   * forest-node JSON shape genesis uses: [{ leaf, recipients, kids }, …]),
   * never merely a bare root hash — this server tracks the durable forest,
   * and a bare hash gives it nothing to reconstruct future proofs from.
   * params.newChildRoot (what the SDK builder actually signs over) is
   * DERIVED here, never caller-trusted independently, so the two can never
   * silently diverge (AUTHORITY MAY NEVER INCREASE DESCENDING is the
   * covenant's own job; this is just "the stored tree matches its root").
   */
  let normalizedNewChildTree = null;
  const buildParams = { ...params, tree: treeInput, path: params.path };
  if (!isSpend) {
    const childLevel = params.path.length + 1;
    normalizedNewChildTree = (Array.isArray(params.newChildTree) ? params.newChildTree : []).map((n, i) => normalizeForestNode(n, childLevel, i));
    buildParams.newChildRoot = normalizedNewChildTree.length === 0 ? require("../../core/model/hd-leaf-v7").ZERO_ROOT_HEX : require("../../core/model/hd-leaf-v7").childRootOf(normalizedNewChildTree, childLevel);
  }

  const chain = {
    predecessorOutpoint: manifest.live.outpoint,
    covenantId: manifest.live.covenantId,
    predecessorValue: manifest.live.state.feeReserve.toString(),
    fuel: params.fuel,
    ...(isSpend ? { tokenPosition: params.tokenPosition } : {})
  };

  let build;
  try {
    build = isSpend
      ? buildHdSpendTransaction({ config, templateInput: manifest.template, stateInput: stateToJsonV7(manifest.live.state), action, params: buildParams, chain, changeXOnly, descriptor: manifest.asset.descriptor, templateIndex: manifest.asset.templateIndex })
      : buildHdDelegationTransaction({ config, templateInput: manifest.template, stateInput: stateToJsonV7(manifest.live.state), action, params: buildParams, chain, changeXOnly });
  } catch (e) {
    const code = e.code === "PAUSED" ? "DELEGATION_WHILE_PAUSED" : e.code;
    throw fail(`v0.7-payment-hd ${action} build failed: ${e.message}`, code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const requestId = crypto.randomUUID();
  const request = {
    schema: V7_HD_WALLET_REQUEST_SCHEMA, requestId, kind: isSpend ? "hdSpend" : "hdDelegation", vaultId, action,
    contractVersion: CONTRACT_VERSION_V7_HD, networkId: config.networkId, state: RequestState.BUILT,
    signerAddress, signerXOnly, predecessorOutpoint: manifest.live.outpoint, predecessorStateId: manifest.live.stateId,
    build, txId: build.txId,
    transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    requiredFeeSompi: build.requiredFeeSompi,
    path: params.path,
    newChildTree: normalizedNewChildTree ? normalizedNewChildTree.map((n) => ({ leaf: hd.hdLeafToJson(n.leaf), recipients: [...n.recipients], kids: [] })) : null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
  };
  await saveHdWalletRequest(config, request);
  return { ...request, ...hdPresentation(build) };
}

/* ------------------------------------------------------------------ */
/* 3. SIGN                                                              */
/* ------------------------------------------------------------------ */

function assertImmutable(unsigned, signed) {
  const strip = (tx) => ({
    version: tx.version, lockTime: tx.lockTime, subnetworkId: tx.subnetworkId, gas: tx.gas, payload: tx.payload,
    inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })),
    outputs: tx.outputs
  });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throwFail("signed package mutated a consensus-visible field", "SIGNATURE_INVALID");
}

async function finalizeHdWalletRequest(args) {
  return withHdRequestLock(args.config, args.requestId, () => finalizeHdWalletRequestUnlocked(args));
}
async function finalizeHdWalletRequestUnlocked({ config, requestId, signedSafeJson }) {
  const request = await loadHdWalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.BUILT) throwFail(`request is ${request.state}, not BUILT`, request.state);
  if (request.kind !== "hdGenesis") await assertHdGenesisComplete(config, await loadManifestV7Hd(config, request.vaultId));
  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    await saveHdWalletRequest(config, request);
    throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertImmutable(unsigned, signed);

  if (request.kind === "hdGenesis") {
    for (let i = 0; i < unsigned.inputs.length; i++) {
      if (!signed.inputs[i]?.signatureScript) {
        request.state = RequestState.WALLET_REJECTED;
        await saveHdWalletRequest(config, request);
        throwFail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
      }
    }
    request.signedSafeJson = signedSafeJson;
    request.state = RequestState.SIGNED;
    await saveHdWalletRequest(config, request);
    return { ...request, authorityModel: AUTHORITY_MODEL_HD, status: "CANDIDATE" };
  }

  try {
    let finalized;
    if (request.kind === "tokenDeposit") {
      const tokenOwnerSignatureHex = signed.inputs[0]?.signatureScript;
      const fuelSignatureScriptHex = signed.inputs[1]?.signatureScript;
      if (!tokenOwnerSignatureHex || !fuelSignatureScriptHex) throwFail("wallet did not sign every input", "WALLET_REJECTED");
      finalized = finalizeTokenDepositV7({ build: request.build, tokenOwnerSignatureHex, fuelSignatureScriptHex });
    } else {
      const signatureHex = signed.inputs[0]?.signatureScript;
      if (!signatureHex) throwFail("wallet did not sign the covenant input", "WALLET_REJECTED");
      const fuelSignatureScriptHex = signed.inputs[signed.inputs.length - 1]?.signatureScript;
      if (!fuelSignatureScriptHex) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
      ensureBuildDir({ config, buildDir: request.build.encoderBuildDir, recompile: () => compileExactStateV7Hd({ config, template: request.build.template, state: request.build.stateJson, contractVersion: request.build.contractVersion }) }); // F-03
      finalized = finalizeHdTransaction({ build: request.build, signatureHex, fuelSignatureScriptHex });
    }
    verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
  } catch (e) {
    request.state = e.code === "WALLET_REJECTED" ? RequestState.WALLET_REJECTED : RequestState.SIGNATURE_INVALID;
    await saveHdWalletRequest(config, request);
    throw fail(`sign failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.state = RequestState.SIGNED;
  await saveHdWalletRequest(config, request);
  return { ...request, ...(request.build ? hdPresentation(request.build) : {}) };
}

/* ------------------------------------------------------------------ */
/* 4. SUBMIT                                                            */
/* ------------------------------------------------------------------ */

async function submitHdWalletRequest(args) {
  return withHdRequestLock(args.config, args.requestId, () => submitHdWalletRequestUnlocked(args));
}
async function submitHdWalletRequestUnlocked({ config, requestId, rpc: providedRpc }) {
  const request = await loadHdWalletRequest(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state === RequestState.CHAIN_VERIFIED && (request.kind !== "hdGenesis" || (await loadOrgRoot(config, request.build.orgRootCovenantId))?.vaults?.includes(request.vaultId))) return request;
  const recoveringGenesis = request.kind === "hdGenesis" && ["SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED", "CHAIN_VERIFIED"].includes(request.state);
  if (request.state !== RequestState.SIGNED && !recoveringGenesis) throwFail(`request is ${request.state}, not SIGNED`, request.state);
  if (request.kind !== "hdGenesis") await assertHdGenesisComplete(config, await loadManifestV7Hd(config, request.vaultId));

  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V7_HD);
  } catch (e) {
    throw fail(e.message, "NETWORK_MISMATCH");
  }

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    let transaction;
    if (request.kind === "hdGenesis") {
      const { loadKaspa } = require("./chain");
      const { Transaction } = loadKaspa(config);
      transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
      const signed = JSON.parse(request.signedSafeJson);
      const ins = transaction.inputs;
      for (let i = 0; i < ins.length; i++) ins[i].signatureScript = signed.inputs[i].signatureScript;
      transaction.inputs = ins;
    } else {
      transaction = finalTxToWasm(config, request.finalTransaction);
    }
    const computedTxId = transaction.finalize().toString().toLowerCase();
    if (computedTxId !== request.txId) throw fail(`reconstructed txid ${computedTxId} != frozen ${request.txId}`, "TXID_MISMATCH");

    if (request.kind === "hdGenesis" && request.state === RequestState.CHAIN_VERIFIED) {
      // The former unlocked root append could be lost after valid later vault
      // activity. Restore membership from bound creation + live vault proof;
      // never replace that vault with its generation-zero manifest.
      const current = await loadManifestV7Hd(config, request.vaultId);
      const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
      const audit = await readAudit(config, { vaultId: request.vaultId, txId: request.txId, limit: 500 });
      const same = (a, b) => canonicalJsonStringify(JSON.parse(JSON.stringify(a))) === canonicalJsonStringify(JSON.parse(JSON.stringify(b)));
      if (!current?.live || current.creationTxId !== request.txId || current.orgRootCovenantId !== request.build.orgRootCovenantId || !same(current.template, request.build.template) || current.live.covenantId !== request.build.covenantId || receipt?.vaultId !== request.vaultId || receipt.action !== "createRootedHdVault" || receipt.proof?.outpoint !== `${request.txId}:${request.build.vaultOutputIndex}` || receipt.proof?.covenantId !== request.build.covenantId || !audit.some((e) => e.txId === request.txId && e.action === "createRootedHdVault" && e.result === "CHAIN_VERIFIED")) throwFail("HD membership recovery lacks bound creation/history evidence", "RECONCILIATION_REQUIRED");
      const compiled = compileExactStateV7Hd({ config, template: current.template, state: current.live.state, contractVersion: CONTRACT_VERSION_V7_HD });
      const address = require("./chain").covenantAddress(config, compiled.scriptBytes);
      const matches = (await getAddressUtxos(rpc, address)).filter((u) => u.outpoint.transactionId === current.live.outpoint.transactionId && u.outpoint.index === Number(current.live.outpoint.index));
      const observed = matches.length === 1 ? matches[0] : null;
      const expectedScript = require("../../core/assets").kcc20.p2shSpkHex(compiled.scriptBytes);
      if (compiled.scriptSha256 !== current.live.scriptSha256 || !observed || String(observed.amount) !== String(current.live.outpointValue) || observed.covenantId !== current.live.covenantId || observed.scriptPublicKeyHex != null && observed.scriptPublicKeyHex !== expectedScript) throwFail("HD membership recovery cannot prove the current vault", "RECONCILIATION_REQUIRED");
      const root = await loadOrgRoot(config, current.orgRootCovenantId);
      if (!root) throwFail("HD membership root is missing", "RECONCILIATION_REQUIRED");
      if (!root.vaults.includes(current.vaultId)) { root.vaults.push(current.vaultId); await require("./wallet-requests-v7").saveOrgRoot(config, root); }
      return request;
    }

    if (!recoveringGenesis) {
    if (request.kind !== "hdGenesis" && request.kind !== "tokenDeposit") {
      try {
        await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: request.txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected: { kind: "v7HdSuccessor", requestId: request.requestId, txId: request.txId } });
      } catch (e) {
        throw fail(e.message, "CLAIM_CONFLICT");
      }
    }
    await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.state = RequestState.SUBMITTING;
    await saveHdWalletRequest(config, request);

    let submitted;
    try {
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        if (request.kind !== "hdGenesis" && request.kind !== "tokenDeposit") await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
        await releaseSubmissionClaim(config, request.txId);
        request.state = RequestState.SUBMISSION_REJECTED;
        await saveHdWalletRequest(config, request);
        throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
      }
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveHdWalletRequest(config, request);
      throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveHdWalletRequest(config, request);
      throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    await saveHdWalletRequest(config, request);

    }

    if (request.kind === "hdGenesis") {
      const address = spkToAddress(config, request.build.frozen.outputs[request.build.vaultOutputIndex].scriptPublicKey);
      let proof = null;
      for (let i = 0; i < 30 && !proof; i++) {
        const ref = await findOutpoint(rpc, address, request.txId, request.build.vaultOutputIndex);
        if (ref && String(ref.covenantId ?? "").toLowerCase() === request.build.covenantId && String(ref.amount) === String(request.build.frozen.outputs[request.build.vaultOutputIndex].value)) proof = ref;
        if (!proof) await new Promise((r) => setTimeout(r, 2000));
      }
      if (!proof) {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        await saveHdWalletRequest(config, request);
        throw fail(`${request.txId} submitted but the vault output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      const state = normalizeStateV7(request.build.initialState);
      const stateId = computeStateIdV7Hd({ networkId: config.networkId, template: request.build.template, state });
      const expected = {
        schema: MANIFEST_SCHEMA_V7_HD, contractVersion: CONTRACT_VERSION_V7_HD, networkId: config.networkId,
        vaultId: request.build.template.vaultId, label: request.label ?? "", status: VaultStatus.ACTIVE,
        orgRootCovenantId: request.build.orgRootCovenantId, template: request.build.template,
        asset: { descriptor: request.descriptor, templateIndex: request.templateIndex ?? 0 },
        forest: request.initialForest ?? [],
        live: { state: stateToJsonV7(state), stateId, outpoint: { transactionId: request.txId, index: request.build.vaultOutputIndex }, outpointValue: state.feeReserve.toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId, tokenPosition: null },
        creationTxId: request.txId, latestTransitionTxId: null, generation: 0
      };
      const current = await loadManifestV7Hd(config, request.vaultId);
      const completionIdentity = (v) => {
        const { updatedAt, label, ...identity } = manifestToJsonV7Hd(v);
        // Compare the representation actually persisted by both JSON and PG;
        // descriptor normalization may include optional undefined properties.
        return canonicalJsonStringify(JSON.parse(JSON.stringify(identity, (_key, value) => typeof value === "bigint" ? value.toString() : value)));
      };
      if (current && completionIdentity(current) !== completionIdentity(normalizeManifestV7Hd(expected))) throwFail("HD genesis recovery would overwrite a later, unrelated or contradictory vault", "RECONCILIATION_REQUIRED");
      const manifest = current ?? await persistManifestV7Hd(config, expected);
      const root = await loadOrgRoot(config, request.build.orgRootCovenantId);
      if (!root) throwFail("HD genesis root record is missing", "RECONCILIATION_REQUIRED");
      if (!root.vaults.includes(manifest.vaultId)) {
        root.vaults.push(manifest.vaultId);
        await require("./wallet-requests-v7").saveOrgRoot(config, root);
      }
      const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
      if (receipt && (receipt.vaultId !== manifest.vaultId || receipt.action !== "createRootedHdVault" || receipt.proof?.outpoint !== `${request.txId}:${request.build.vaultOutputIndex}` || receipt.proof?.covenantId !== request.build.covenantId)) throwFail("HD genesis receipt belongs to another operation", "RECONCILIATION_REQUIRED");
      if (!receipt) await persistReceipt(config, { txId: request.txId, vaultId: manifest.vaultId, action: "createRootedHdVault", proof: { outpoint: `${request.txId}:${request.build.vaultOutputIndex}`, covenantId: request.build.covenantId } });
      if (!(await readAudit(config, { vaultId: manifest.vaultId, txId: request.txId, limit: 500 })).some((e) => e.action === "createRootedHdVault" && e.result === "CHAIN_VERIFIED")) await appendAudit(config, { vaultId: manifest.vaultId, action: "createRootedHdVault", actor: "funder", contractVersion: CONTRACT_VERSION_V7_HD, txId: request.txId, result: "CHAIN_VERIFIED", via: "org-roots/hd" });
      const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
      if (submission && (submission.vaultId !== manifest.vaultId || submission.action !== request.action)) throwFail("HD submission claim belongs to another operation", "CLAIM_CONFLICT");
      if (submission) await releaseSubmissionClaim(config, request.txId);
      request.state = RequestState.CHAIN_VERIFIED;
      await saveHdWalletRequest(config, request);
      return { ...request, authorityModel: AUTHORITY_MODEL_HD, status: "CANDIDATE" };
    }

    if (request.kind === "tokenDeposit") {
      const depositAddress = spkToAddress(config, request.build.frozen.outputs[0].scriptPublicKey);
      const depositValue = request.build.frozen.outputs[0].value.toString();
      let depositProof = null;
      for (let i = 0; i < 30 && !depositProof; i++) {
        const ref = await findOutpoint(rpc, depositAddress, request.txId, 0);
        if (ref && ref.amount.toString() === depositValue) depositProof = ref;
        if (!depositProof) await new Promise((r) => setTimeout(r, 2000));
      }
      if (!depositProof) {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        await saveHdWalletRequest(config, request);
        throw fail(`${request.txId} submitted but the deposit output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      const manifest = await loadManifestV7Hd(config, request.vaultId);
      const newTokenPosition = { outpoint: { transactionId: request.txId, index: 0 }, value: depositValue, scriptPublicKeyHex: request.build.frozen.outputs[0].scriptPublicKey.scriptHex, covenantId: request.build.frozen.outputs[0].covenant.covenantId, state: request.build.tokenNewStates[0] };
      await persistManifestV7Hd(config, { ...manifestToJsonV7Hd(manifest), live: { ...manifestToJsonV7Hd(manifest).live, tokenPosition: newTokenPosition }, latestTransitionTxId: request.txId, generation: (manifest.generation ?? 0) + 1 });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveHdWalletRequest(config, request);
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { outpoint: `${request.txId}:0`, reconciled: false } });
      await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "tokenOwner", contractVersion: CONTRACT_VERSION_V7_HD, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v7-hd" });
      return { ...request, authorityModel: AUTHORITY_MODEL_HD, status: "CANDIDATE" };
    }

    /* hdSpend / hdDelegation */
    const succIndex = request.build.frozen.outputs.findIndex((o) => o.covenant && o.covenant.covenantId === request.build.covenantId);
    const succAddress = spkToAddress(config, request.build.frozen.outputs[succIndex].scriptPublicKey);
    const succValue = request.build.frozen.outputs[succIndex].value.toString();
    let proof = null;
    for (let i = 0; i < 30 && !proof; i++) {
      const ref = await findOutpoint(rpc, succAddress, request.txId, succIndex);
      if (ref && ref.amount.toString() === succValue) proof = ref;
      if (!proof) await new Promise((r) => setTimeout(r, 2000));
    }
    if (!proof) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveHdWalletRequest(config, request);
      throw fail(`${request.txId} submitted but the vault successor was not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    const manifest = await loadManifestV7Hd(config, request.vaultId);
    const successorState = request.build.successorState;
    const stateId = computeStateIdV7Hd({ networkId: config.networkId, template: manifest.template, state: normalizeStateV7(successorState) });
    const currentJson = manifestToJsonV7Hd(manifest);
    const isSpend = request.kind === "hdSpend";
    /* the acting leaf's self token continuation lands at output 1 for a
     * spend; a delegation never touches the token domain at all */
    const newTokenPosition = isSpend
      ? { outpoint: { transactionId: request.txId, index: 1 }, value: request.build.frozen.outputs[1].value.toString(), scriptPublicKeyHex: request.build.frozen.outputs[1].scriptPublicKey.scriptHex, covenantId: request.build.frozen.outputs[1].covenant.covenantId, state: { ownerIdentifier: request.build.covenantId, identifierType: 2, amount: request.build.accounting.token.positionAfter, isMinter: false } }
      : currentJson.live.tokenPosition;
    /* advance the durable forest: the builder already proved the new
     * agentRoot via hd.nestedRefoldAfterSpend / nestedRefoldAfterDelegation
     * against the SAME forest this manifest carries — recompute the
     * updated forest by re-deriving it along the SAME path the request
     * used, splicing in the ONE changed leaf/child-root. */
    const advancedForest = isSpend
      ? advanceForestAfterSpend(manifest.forest, request.path, BigInt(request.build.accounting.token.spendAmount), request.build.ancestorChain.map((e) => BigInt(e.periodsElapsed)))
      : advanceForestAfterDelegation(manifest.forest, request.path, request.newChildTree ?? []);
    await persistManifestV7Hd(config, {
      ...currentJson,
      forest: advancedForest,
      live: { state: successorState, stateId, outpoint: { transactionId: request.txId, index: succIndex }, outpointValue: successorState.feeReserve, scriptSha256: request.build.successorScriptSha256, covenantId: request.build.covenantId, tokenPosition: newTokenPosition },
      latestTransitionTxId: request.txId, generation: (manifest.generation ?? 0) + 1
    });
    await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
    await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { successorOutpoint: `${request.txId}:${succIndex}`, reconciled: false } });
    await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "delegate", contractVersion: CONTRACT_VERSION_V7_HD, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v7-hd" });
    request.state = RequestState.CHAIN_VERIFIED;
    await saveHdWalletRequest(config, request);
    return { ...request, ...hdPresentation(request.build) };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/*
 * Advance the durable forest (JSON node shape { leaf: hdLeafToJson(...),
 * recipients, kids }) after a PROVEN spend: ONLY the acting leaf's OWN
 * period counters change (periodStartDaa / periodSpent), following the
 * SAME `path` (child indices) the request used. Every ancestor level's
 * leaf fields are untouched (their childRoot is always RECOMPUTED from
 * kids, never stored authoritatively — see core/model/hd-leaf-v7.js's
 * resolvedLeaf).
 */
function advanceForestAfterSpend(forestNodes, path, spendAmount, periodsElapsedByLevel) {
  /* EVERY ancestor on the spend path advances its OWN period counters, not
   * just the spending leaf — this mirrors core/model/hd-leaf-v7.js's
   * nestedRefoldAfterSpend exactly (a child can never outrun a parent
   * budget because the parent's counter also advances on each spend). If
   * only the deepest leaf were updated here, the locally recomputed forest
   * root would diverge from the covenant's successor agentRoot and every
   * post-spend persist of a multi-level vault would fail REGISTRY_ROOT_MISMATCH. */
  function walk(nodes, depth) {
    return nodes.map((node, i) => {
      if (i !== path[depth]) return node;
      const { periodStartDaa, periodSpent } = hd.advanceHdLeafPeriod(node.leaf, spendAmount, periodsElapsedByLevel[depth]);
      const advancedLeaf = hd.normalizeHdLeaf(leafInputFrom(node.leaf, { periodStartDaa: periodStartDaa.toString(), periodSpent: periodSpent.toString() }));
      if (depth === path.length - 1) {
        return { ...node, leaf: advancedLeaf };
      }
      return { ...node, leaf: advancedLeaf, kids: walk(node.kids, depth + 1) };
    });
  }
  return walk(forestNodes, 0);
}

/*
 * Advance the durable forest after a PROVEN delegation: the acting
 * level's node has its ENTIRE child subtree replaced by `newChildTree`
 * (the caller's proposed new children, verified consistent with the
 * signed newChildRoot at build time — see buildHdWalletRequest). The
 * leaf's own fields are unchanged.
 */
function advanceForestAfterDelegation(forestNodes, path, newChildTree) {
  function walk(nodes, depth) {
    return nodes.map((node, i) => {
      if (i !== path[depth]) return node;
      if (depth === path.length - 1) return { ...node, kids: newChildTree };
      return { ...node, kids: walk(node.kids, depth + 1) };
    });
  }
  return walk(forestNodes, 0);
}
function leafInputFrom(leaf, overrides = {}) {
  return {
    pk: leaf.pk, maxPerSpend: leaf.maxPerSpend.toString(), periodBudget: leaf.periodBudget.toString(),
    periodLengthDaa: leaf.periodLengthDaa.toString(), periodStartDaa: leaf.periodStartDaa.toString(), periodSpent: leaf.periodSpent.toString(),
    maxFeePerTx: leaf.maxFeePerTx.toString(), maxCarryKas: leaf.maxCarryKas.toString(), expiryDaa: leaf.expiryDaa.toString(),
    recipientRoot: leaf.recipientRoot, childRoot: leaf.childRoot, ...overrides
  };
}

/* ------------------------------------------------------------------ */
/* 5. REJECT                                                            */
/* ------------------------------------------------------------------ */

async function markHdWalletRejected(config, requestId) {
  const peek = await loadHdWalletRequest(config, requestId);
  if (!peek) return null;
  return withHdRequestLock(config, requestId, () => markHdWalletRejectedUnlocked(config, requestId));
}
async function markHdWalletRejectedUnlocked(config, requestId) {
  const request = await loadHdWalletRequest(config, requestId);
  if (request && request.state === RequestState.BUILT) {
    request.state = RequestState.WALLET_REJECTED;
    await saveHdWalletRequest(config, request);
  }
  return request;
}

module.exports = {
  V7_HD_WALLET_REQUEST_SCHEMA,
  AUTHORITY_MODEL_HD,
  RequestState,
  HD_ACTIONS,
  EXPIRY_STATEMENT,
  loadHdWalletRequest,
  saveHdWalletRequest,
  listHdWalletRequests,
  buildHdVaultGenesisRequest,
  buildHdWalletRequest,
  finalizeHdWalletRequest,
  submitHdWalletRequest,
  markHdWalletRejected,
  listRootedHdVaultsV7,
  hdPresentation
};
