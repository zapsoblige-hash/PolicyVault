"use strict";
const { verifySignedSafeJsonInputs, verifyFinalTransactionInputs } = require("./vm-preflight");
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV6 } = require("./contract-compiler-v6");

/*
 * PolicyVault v0.6 OPTIONAL-ATOMIC-COMPOSABILITY TOKEN CONTROLLER (FROZEN;
 * docs/postlaunch/v0.6-covenant-byte-freeze.md) — server-orchestrated
 * wallet-request pipeline (Wave 2 Track E; docs/postlaunch/
 * v0.7-app-surface-contract.md §6.1 "POST /wallet/v6/*"). Same discipline
 * as sdk/src/wallet-requests-v5.js (which this module closely mirrors):
 * intent -> build -> sign -> submit -> reconcile; builders never
 * broadcast; only PROVEN chain reconciliation advances a durable
 * manifest; `accounting.token` / `accounting.kas` are passed through
 * from the SDK build verbatim.
 *
 * WHAT IS NEW relative to v0.5: tokenAtomicSell / tokenAtomicBuy, gated
 * by the SAME single-owner authority as every other v0.6 action, and by
 * TWO additional server-side fail-closed checks the covenant itself does
 * NOT need (its swap-policy-leaf pin already prevents an unapproved pool)
 * but the app-surface contract requires for a clean, actionable refusal:
 *
 *   1. VENUE: this server recognizes exactly ONE venue — the PolicyVault
 *      pool FIXTURE (contracts/experiments/V6PoolFixture.sil, conformance
 *      evidence only; NOT a real DEX venue, NOT PolicyVault operating as
 *      a DEX — CLAUDE.md "PolicyVault MUST NOT become a DEX"). A request
 *      naming any other venue profile (by provenance sourceRelPath/
 *      sourceSha256) is refused VENUE_PROFILE_UNSUPPORTED BEFORE the SDK
 *      builder ever runs.
 *   2. FRESHNESS: `finalizeV6Transaction` requires the node-verified
 *      current DAA score and refuses a swap whose deadlineDaa has
 *      passed (DEADLINE_PASSED) — never a consensus expiry, a pre-sign
 *      freshness boundary the app-surface contract calls out explicitly.
 *      Because this server splits sign and submit into separate calls
 *      (unlike the "verify -> sign -> broadcast immediately" single-shot
 *      workflow the SDK doc comment describes), a swap's covenant call is
 *      finalized LAZILY at SUBMIT time (where a live RPC connection
 *      already exists to fetch the true current DAA score) rather than
 *      at the /signature call — see finalizeSignedSwapV6 below. The
 *      /signature call for a swap only validates and stores the raw
 *      signature; it does not yet produce final consensus bytes.
 *
 * Status: IMPLEMENTED (Wave 2 Track E). UNIT/API-TESTED by
 * sdk/test/wallet-v6-api.test.js.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { getStore, Categories } = require("./store");
const { assertVaultIdentityFree, withVaultIdentityLock, normalizeVaultId } = require("./vault-identity"); // RC33-ID-01 (2026-09-11): global vault-record uniqueness
const { assertOperationalNetwork, assertGenerationMainnetCreatable, assertGenerationMainnetOperable } = require("./config");
const { normalizeHex } = require("./vault-state");
const { kasToSompi } = require("./amounts");
/* RC35-REC-01 / legacy F4 (2026-09-11): shared submit-outcome settlement + observation-only genesis recovery primitives */
const { settleGenesisSubmitError, settleTransitionSubmitError, anyFrozenOutputObserved, frozenInputLive, ensureOwnSubmissionClaim, unobservedRecoveryDisposition, refreshUnobservedGenesis } = require("./genesis-recovery");
const { resolveAddressIdentity } = require("./address-identity");
const { connectVerified, getAddressUtxos, getVirtualDaaScore } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { claimTransition, claimSubmission, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
const { appendAudit, readAudit } = require("./audit");
const assets = require("../../core/assets");

const { CONTRACT_VERSION_V6, resolveV6Abi, normalizeStateV6, stateToJsonV6, computeStateIdV6, controllerValueV6 } = require("./vault-state-v6");
const { buildV6Transaction, buildCreateV6, finalizeV6Transaction, buildTokenDepositV6, finalizeTokenDepositV6, OWNER_CONTROL_ACTIONS, SPEND_ACTIONS, SWAP_ACTIONS } = require("./vault-builders-v6");
const { normalizeSwapVenueProfile } = require("./swap-policy-v6");
const { POOL_FIXTURE_REL } = require("./swap-pool-fixture-v6");
const { normalizeRegistry, normalizeSwapRegistry, registryEntryToJson, loadManifestV6, persistManifestV6, createManifestV6, manifestToJsonV6, MANIFEST_SCHEMA_V6 } = require("./manifest-v6");
const { VaultStatus } = require("./manifest");

const V6_WALLET_REQUEST_SCHEMA = "policyvault-wallet-request/v6";
const AUTHORITY_MODEL_V6 = "SINGLE_ON_CHAIN_OWNER";

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
  DEADLINE_PASSED: "DEADLINE_PASSED",
  STALE: "STALE",
  BUILD_FAILED: "BUILD_FAILED"
});

const TRANSITION_ACTIONS = new Set([...OWNER_CONTROL_ACTIONS, ...SPEND_ACTIONS, ...SWAP_ACTIONS, "ownerRecover"]);

function fail(message, code) {
  const e = new Error(`wallet-requests-v6: ${message}`);
  if (code) e.code = code;
  return e;
}
function throwFail(message, code) {
  throw fail(message, code);
}

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

async function loadWalletRequestV6(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  return r && r.schema === V6_WALLET_REQUEST_SCHEMA ? r : null;
}
async function saveWalletRequestV6(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function listWalletRequestsV6(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST);
  const out = all.filter((r) => r && r.schema === V6_WALLET_REQUEST_SCHEMA && (vaultId === undefined || r.vaultId === vaultId));
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

/*
 * VENUE FIXTURE GATE (see module header point 1). The ONLY venue profile
 * this server recognizes is the PolicyVault pool FIXTURE — identified by
 * its provenance pinning to the EXACT on-disk fixture source (never a
 * hardcoded hash: read fresh so a source edit is caught, not silently
 * trusted). A profile naming any other program fails closed BEFORE the
 * SDK builder (and its own, stricter, swap-policy-leaf pin check) runs.
 */
function assertFixtureVenue(config, venueProfileInput) {
  const profile = normalizeSwapVenueProfile(venueProfileInput);
  const sourcePath = path.join(config.repoRoot, POOL_FIXTURE_REL);
  let expectedSha256;
  try {
    expectedSha256 = crypto.createHash("sha256").update(fs.readFileSync(sourcePath, "utf8"), "utf8").digest("hex");
  } catch (e) {
    throwFail(`the PolicyVault pool fixture source could not be read to verify the venue (${e.message}) — failing closed`, "VENUE_PROFILE_UNSUPPORTED");
  }
  if (profile.provenance.sourceRelPath !== POOL_FIXTURE_REL || profile.provenance.sourceSha256 !== expectedSha256) {
    throwFail("the ONLY venue profile this server knows is the PolicyVault pool FIXTURE (conformance evidence) — no real DEX venue is supported; failing closed", "VENUE_PROFILE_UNSUPPORTED");
  }
  if (profile.networkId !== config.networkId) throwFail(`venue profile network ${profile.networkId} != ${config.networkId} — failing closed`, "VENUE_PROFILE_UNSUPPORTED");
  return profile;
}

function venuePresentation() {
  return { kind: "FIXTURE", supported: false, note: "no real DEX venue is supported — the PolicyVault pool fixture is conformance/testnet evidence only" };
}

/* Period-window advance shared by tokenAgentSpend / tokenAtomicSell /
 * tokenAtomicBuy: ONLY the acting agent's leaf changes, and ONLY its
 * tokenPeriodSpent (token domain) and/or kasPeriodSpent (KAS consideration
 * domain) — both windows share the SAME periodStartDaa/periodLengthDaa
 * clock (core/model/agent-merkle-v6.js's single-leaf schema), so a period
 * rollover resets both counters together. Mirrors wallet-requests-v7.js's
 * advanceRegistryAfterSpendV7 / wallet-requests-v5.js's -V5 sibling. */
function advanceRegistryV6(registry, build) {
  const agentPk = build.callExtra.agentPk;
  const periodsElapsed = BigInt(build.callExtra.periodsElapsed ?? "0");
  let tokenDelta = 0n;
  let kasDelta = 0n;
  if (SPEND_ACTIONS.has(build.action)) {
    tokenDelta = BigInt(build.payment.tokenAmount);
  } else if (build.swap) {
    if (build.swap.direction === "SELL") tokenDelta = BigInt(build.accounting.token.amountIn);
    else kasDelta = BigInt(build.accounting.kas.consideration);
  }
  return registry.map((e) => {
    if (e.agentPk !== agentPk) return e;
    let newStart = BigInt(e.periodStartDaa);
    let newTokenSpent = BigInt(e.tokenPeriodSpent) + tokenDelta;
    let newKasSpent = BigInt(e.kasPeriodSpent ?? "0") + kasDelta;
    if (periodsElapsed >= 1n) {
      newStart = BigInt(e.periodStartDaa) + periodsElapsed * BigInt(e.periodLengthDaa);
      newTokenSpent = tokenDelta;
      newKasSpent = kasDelta;
    }
    return { ...e, periodStartDaa: newStart.toString(), tokenPeriodSpent: newTokenSpent.toString(), kasPeriodSpent: newKasSpent.toString() };
  });
}

/* ------------------------------------------------------------------ */
/* 1. GENESIS — POST /wallet/v6/create                                  */
/* ------------------------------------------------------------------ */

async function buildCreateWalletRequestV6(args) {
  /* RC33-ID-01 (2026-09-11): the build (uniqueness check -> request write) is serialized per vault identity; a malformed
   * identity falls through and is refused exactly as before */
  let vaultId = null;
  try { vaultId = args.vaultId ? normalizeHex(args.vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex"); } catch { vaultId = null; }
  if (vaultId === null) return buildCreateWalletRequestV6Unlocked(args);
  return withVaultIdentityLock(vaultId, () => buildCreateWalletRequestV6Unlocked({ ...args, vaultId }));
}
async function buildCreateWalletRequestV6Unlocked({ config, label = "", descriptor, templateIndex = 0, initialAgents = [], initialSwapPolicies = [], feeReserveKas, swapPrincipalKas = "0", signerAddress, funding, vaultId }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V6);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const ownerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const { validated, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen } = templateFieldsFromDescriptor(descriptor, templateIndex);
  const { entries, tree } = normalizeRegistry(initialAgents);
  const { entries: swapEntries, tree: swapTree } = normalizeSwapRegistry(initialSwapPolicies);
  const initialRegistry = entries.map((e) => registryEntryToJson(e));
  const initialSwapRegistry = swapEntries.map((p) => require("./swap-policy-v6").swapPolicyToJsonV6(p));

  const vId = vaultId ? normalizeHex(vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex");
  await assertVaultIdentityFree(config, vId); // RC33-ID-01: an identity held by ANY generation's record or ANY request is refused before anything is built or written
  const template = { owner: ownerXOnly, vaultId: vId, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen };
  const feeReserveSompi = kasToSompi(feeReserveKas, "feeReserveKas");
  const swapPrincipalSompi = kasToSompi(swapPrincipalKas, "swapPrincipalKas");
  const initialState = { feeReserve: feeReserveSompi.toString(), swapPrincipal: swapPrincipalSompi.toString(), paused: "0", agentRoot: tree.root, swapRoot: swapTree.root, policyNonce: "0" };

  if (!Array.isArray(funding) || funding.length === 0) throwFail("funding (a non-empty array of the owner's ordinary UTXOs) is required", "BUILD_FAILED");

  let genesis;
  try {
    genesis = buildCreateV6({ config, templateInput: template, initialStateInput: initialState, funding, changeXOnly: ownerXOnly, descriptor: validated });
  } catch (e) {
    throw fail(`v0.6 genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  const request = {
    schema: V6_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "genesis",
    vaultId: vId,
    action: "createTokenController",
    contractVersion: CONTRACT_VERSION_V6,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly: ownerXOnly,
    label,
    descriptor: validated,
    templateIndex,
    initialRegistry,
    initialSwapRegistry,
    build: genesis,
    accounting: genesis.accounting,
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi,
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveWalletRequestV6(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 2. TRANSITIONS + SWAPS + TOKEN DEPOSIT — POST /wallet/v6/requests    */
/* ------------------------------------------------------------------ */

async function buildWalletRequestV6({ config, vaultId, action, params = {}, signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V6);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = await loadManifestV6(config, vaultId);
  if (!manifest) throwFail(`no v0.6 controller ${vaultId}`, "VAULT_NOT_FOUND");
  if (!manifest.live) throwFail(`vault is ${manifest.status} (closed) — read-only history`, "VAULT_TERMINAL");

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const changeXOnly = signerXOnly;

  if (action === "tokenDeposit") {
    if (manifest.live.tokenPosition !== null) {
      throwFail("this controller already holds a tracked token position — a second deposit would create an untracked same-family UTXO; failing closed", "TOKEN_POSITION_ALREADY_HELD");
    }
    const userPositionOutpoint = normalizeOutpoint(params.userPosition?.outpoint, "params.userPosition.outpoint");
    let build;
    try {
      build = buildTokenDepositV6({
        config,
        descriptor: manifest.asset.descriptor,
        templateIndex: manifest.asset.templateIndex,
        controller: { covenantId: manifest.live.covenantId, template: manifest.template },
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
      schema: V6_WALLET_REQUEST_SCHEMA,
      requestId,
      kind: "tokenDeposit",
      vaultId,
      action,
      contractVersion: CONTRACT_VERSION_V6,
      networkId: config.networkId,
      state: RequestState.BUILT,
      signerAddress,
      signerXOnly,
      predecessorOutpoint: userPositionOutpoint,
      build,
      accounting: build.accounting,
      txId: build.txId,
      transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
      requiredFeeSompi: build.requiredFeeSompi,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    await saveWalletRequestV6(config, request);
    return request;
  }

  if (!TRANSITION_ACTIONS.has(action)) throwFail(`unknown v0.6 action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const isSpend = SPEND_ACTIONS.has(action);
  const isSwap = SWAP_ACTIONS.has(action);
  if ((isSpend || isSwap) && manifest.status !== VaultStatus.ACTIVE) throwFail(`vault status is ${manifest.status} — this action needs ACTIVE`, "BUILD_FAILED");

  let venueProfile = null;
  if (isSwap) venueProfile = assertFixtureVenue(config, params.venueProfile);

  const sdkParams = { ...params };
  if (isSpend || isSwap) {
    sdkParams.agentPk = signerXOnly;
    if (sdkParams.spendAmount !== undefined) sdkParams.spendAmount = canonicalAmountParam(sdkParams.spendAmount, "spendAmount");
  }
  if (action === "ownerTopUpReserve" && sdkParams.topUpReserveAmountSompi !== undefined) sdkParams.topUpReserveAmountSompi = canonicalAmountParam(sdkParams.topUpReserveAmountSompi, "topUpReserveAmountSompi");
  if (action === "ownerFundSwapPrincipal" && sdkParams.fundSwapPrincipalSompi !== undefined) sdkParams.fundSwapPrincipalSompi = canonicalAmountParam(sdkParams.fundSwapPrincipalSompi, "fundSwapPrincipalSompi");

  const allowMalformedState = action === "ownerRecover" && params.allowMalformedState === true;
  const state = manifest.live.state;
  const chain = {
    predecessorOutpoint: manifest.live.outpoint,
    covenantId: manifest.live.covenantId,
    predecessorValue: controllerValueV6(state).toString(),
    ...(params.fuel && !isSwap ? { fuel: params.fuel } : {}),
    ...(params.tokenPosition ? { tokenPosition: params.tokenPosition } : {}),
    ...(params.pool ? { pool: params.pool } : {}),
    ...(params.poolNote ? { poolNote: params.poolNote } : {})
  };

  let build;
  try {
    build = buildV6Transaction({
      config,
      contractVersion: CONTRACT_VERSION_V6,
      templateInput: manifest.template,
      stateInput: stateToJsonV6(state),
      action,
      params: { ...sdkParams, allowMalformedState },
      chain,
      changeXOnly,
      descriptor: isSpend || isSwap || (action === "ownerRecover" && chain.tokenPosition) ? manifest.asset.descriptor : undefined,
      templateIndex: manifest.asset.templateIndex
    });
  } catch (e) {
    throw fail(`v0.6 ${action} build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const requestId = crypto.randomUUID();
  const request = {
    schema: V6_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: isSwap ? "swap" : "transition",
    vaultId,
    action,
    contractVersion: CONTRACT_VERSION_V6,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly,
    predecessorOutpoint: manifest.live.outpoint,
    predecessorStateId: manifest.live.stateId,
    build,
    accounting: build.accounting,
    venue: isSwap ? venuePresentation() : null,
    venueProfileHash: venueProfile ? build.swap.venueProfileHash : null,
    deadlineDaa: isSwap ? build.deadlineDaa : null,
    freshnessStatement: isSwap ? build.swap.freshness.statement : null,
    txId: build.txId,
    transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    requiredFeeSompi: build.requiredFeeSompi,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveWalletRequestV6(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 3. SIGN — POST /wallet/v6/requests/:id/signature                     */
/* ------------------------------------------------------------------ */

function assertImmutable(unsigned, signed) {
  const strip = (tx) => ({
    version: tx.version,
    lockTime: tx.lockTime,
    subnetworkId: tx.subnetworkId,
    gas: tx.gas,
    payload: tx.payload,
    inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })),
    outputs: tx.outputs
  });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throwFail("signed package mutated a consensus-visible field", "SIGNATURE_INVALID");
}

/* RC33-ID-01 review finding F1 (2026-09-11): the signature and the submission of a genesis are serialized PER VAULT IDENTITY inside the existing root / signer / request lock (lock order unchanged: root / signer / request first, identity inside), so the commit-phase identity check and the signature store / claim / broadcast that follow it form ONE critical section — a pre-correction pair of drafts naming one identity can never double-sign or double-broadcast under concurrency. A request whose identity cannot be normalized falls through to the unlocked body, which refuses it exactly as before. Only GENESIS requests carry a vault identity to serialize on. */
async function withGenesisIdentityLockV6(config, requestId, work) {
  const peek = await loadWalletRequestV6(config, requestId);
  let vaultId = null;
  try { vaultId = peek && peek.kind === "genesis" ? normalizeVaultId(peek.vaultId) : null; } catch { vaultId = null; }
  return vaultId === null ? work() : withVaultIdentityLock(vaultId, work);
}
async function submitSignatureV6(args) {
  return withGenesisIdentityLockV6(args.config, args.requestId, () => submitSignatureV6Unlocked(args));
}
async function submitSignatureV6Unlocked({ config, requestId, signedSafeJson }) {
  const request = await loadWalletRequestV6(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.BUILT) throwFail(`request is ${request.state}, not BUILT`, request.state);
  if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throwFail("signedSafeJson is required", "BAD_SIGNATURE");

  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    await saveWalletRequestV6(config, request);
    throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertImmutable(unsigned, signed);

  if (request.kind === "genesis") {
    await assertVaultIdentityFree(config, request.vaultId, { exceptRequestId: request.requestId, exceptTxId: request.txId, phase: "commit" }); // RC33-ID-01: refused before the signature is accepted; the request stays BUILT
    for (let i = 0; i < unsigned.inputs.length; i++) {
      if (!signed.inputs[i]?.signatureScript) {
        request.state = RequestState.WALLET_REJECTED;
        await saveWalletRequestV6(config, request);
        throwFail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
      }
    }
    /* Genesis inputs are ORDINARY (p2pk) funding UTXOs — Safe JSON, a
     * DIFFERENT shape from a finalized covenant-transition's
     * finalTransaction. Store the raw signed Safe JSON; submit
     * reconstructs the WASM transaction from unsigned Safe JSON + these
     * signature scripts (mirrors wallet-requests-v7.js's
     * broadcastSignedGenesis / wallet-requests-v5.js's own genesis path). */
    try {
      verifySignedSafeJsonInputs({ frozenCanonicalJson: request.build.frozenCanonicalJson, signedSafeJson }); // F-04: verify before SIGNED
    } catch (e) {
      throwFail(`genesis signature rejected: ${e.message}`, "SIGNATURE_INVALID");
    }
    request.signedSafeJson = signedSafeJson;
    request.state = RequestState.SIGNED;
    await saveWalletRequestV6(config, request);
    return request;
  }

  if (request.kind === "swap") {
    /* LAZY finalize (see module header point 2): store the raw covenant
     * signature now; finalizeV6Transaction (which enforces the pre-sign
     * deadline against the node-verified DAA score) runs at submit time. */
    const covenantSignatureHex = signed.inputs[0]?.signatureScript;
    if (!covenantSignatureHex) {
      request.state = RequestState.WALLET_REJECTED;
      await saveWalletRequestV6(config, request);
      throwFail("wallet did not sign the covenant input", "WALLET_REJECTED");
    }
    request.covenantSignatureHex = covenantSignatureHex;
    request.state = RequestState.SIGNED;
    await saveWalletRequestV6(config, request);
    return request;
  }

  try {
    let finalized;
    if (request.kind === "tokenDeposit") {
      const tokenOwnerSignatureHex = signed.inputs[0]?.signatureScript;
      const fuelSignatureScriptHex = signed.inputs[1]?.signatureScript;
      if (!tokenOwnerSignatureHex || !fuelSignatureScriptHex) throwFail("wallet did not sign every input", "WALLET_REJECTED");
      finalized = finalizeTokenDepositV6({ build: request.build, tokenOwnerSignatureHex, fuelSignatureScriptHex });
    } else {
      const covenantSignatureHex = signed.inputs[0]?.signatureScript;
      if (!covenantSignatureHex) throwFail("wallet did not sign the covenant input", "WALLET_REJECTED");
      const hasFuel = request.build.hasFuelInput === true;
      const fuelIndex = request.build.frozen.inputs.length - 1;
      const fuelSignatureScriptHex = hasFuel ? signed.inputs[fuelIndex]?.signatureScript : undefined;
      if (hasFuel && !fuelSignatureScriptHex) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
      ensureBuildDir({ config, buildDir: request.build.encoderBuildDir, recompile: () => compileExactStateV6({ config, template: request.build.template, state: request.build.stateJson, contractVersion: request.build.contractVersion }) }); // F-03
      finalized = finalizeV6Transaction({ build: request.build, covenantSignatureHex, fuelSignatureScriptHex });
    }
    verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
  } catch (e) {
    request.state = e.code === "WALLET_REJECTED" ? RequestState.WALLET_REJECTED : RequestState.SIGNATURE_INVALID;
    await saveWalletRequestV6(config, request);
    throw fail(`sign failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.state = RequestState.SIGNED;
  await saveWalletRequestV6(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 4. SUBMIT — POST /wallet/v6/requests/:id/submit                      */
/* ------------------------------------------------------------------ */

async function submitWalletRequestV6(args) {
  return withGenesisIdentityLockV6(args.config, args.requestId, () => submitWalletRequestV6Unlocked(args));
}
/* The EXACT controller output a v0.6 genesis declares (derived from the frozen transaction the funder signed). */
function genesisExpectedOutputV6(config, request) {
  const index = request.build.controllerOutputIndex;
  const out = request.build.frozen.outputs[index];
  return { address: spkToAddress(config, out.scriptPublicKey), txId: request.txId, index, value: String(out.value), covenantId: request.build.covenantId };
}
async function observeGenesisOutputV6(config, rpc, request, { pollAttempts = 30, pollDelayMs = 2000 } = {}) {
  const expected = genesisExpectedOutputV6(config, request);
  let proof = null;
  for (let i = 0; i < pollAttempts && !proof; i++) {
    const ref = await findOutpoint(rpc, expected.address, expected.txId, expected.index);
    if (ref && String(ref.covenantId ?? "").toLowerCase() === expected.covenantId && String(ref.amount) === expected.value) proof = ref;
    if (!proof && i + 1 < pollAttempts) await new Promise((r) => setTimeout(r, pollDelayMs));
  }
  return proof;
}
/* ONE replayable completion of a PROVEN v0.6 genesis (submit path and observation-only recovery alike). */
async function completeGenesisV6(config, request) {
  const state = normalizeStateV6(request.build.initialState);
  const stateId = computeStateIdV6({ networkId: config.networkId, template: request.build.template, state, contractVersion: CONTRACT_VERSION_V6 });
  /* RC33-ID-01: ATOMIC create-only completion (sdk/src/vault-identity.js) — never read-then-overwrite */
  let manifest;
  try {
    ({ manifest } = await createManifestV6(config, {
      schema: MANIFEST_SCHEMA_V6,
      contractVersion: CONTRACT_VERSION_V6,
      networkId: config.networkId,
      vaultId: request.build.template.vaultId,
      label: request.label ?? "",
      status: VaultStatus.ACTIVE,
      template: request.build.template,
      asset: { descriptor: request.descriptor, templateIndex: request.templateIndex ?? 0 },
      agentRegistry: request.initialRegistry ?? [],
      swapRegistry: request.initialSwapRegistry ?? [],
      live: { state: stateToJsonV6(state), stateId, outpoint: { transactionId: request.txId, index: request.build.controllerOutputIndex }, outpointValue: controllerValueV6(state).toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId, tokenPosition: null },
      creationTxId: request.txId,
      latestTransitionTxId: null
    }));
  } catch (e) {
    if (e.code !== "RECONCILIATION_REQUIRED") throw e;
    /* RC33-ID-01: the identity holds a DIFFERENT record (any generation) — that record is never replaced; the proven chain
     * effect stays on THIS request (signed bytes, txid, submission claim intact) as RECONCILIATION_REQUIRED */
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = `chain effect proven but the vault record could not be created: ${String(e.message).split("\n")[0]}`;
    await saveWalletRequestV6(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  const receipt = await getStore(config).read(Categories.RECEIPT, request.txId);
  if (receipt && (receipt.vaultId !== manifest.vaultId || receipt.action !== "createTokenController")) throwFail("a receipt for this transaction names another operation", "RECONCILIATION_REQUIRED");
  if (!receipt) await persistReceipt(config, { txId: request.txId, vaultId: manifest.vaultId, action: "createTokenController", proof: { outpoint: `${request.txId}:${request.build.controllerOutputIndex}`, covenantId: request.build.covenantId } });
  if (!(await readAudit(config, { vaultId: manifest.vaultId, txId: request.txId, limit: 500 })).some((e) => e.action === "createTokenController" && e.result === "CHAIN_VERIFIED")) {
    await appendAudit(config, { vaultId: manifest.vaultId, action: "createTokenController", actor: "owner", contractVersion: CONTRACT_VERSION_V6, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v6" });
  }
  /* the submission claim of a PROVEN genesis is released only when it is ours (never another operation's) */
  const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
  if (submission && (submission.vaultId !== request.vaultId || submission.action !== request.action)) throwFail("submission claim belongs to another operation", "CLAIM_CONFLICT");
  if (submission) await releaseSubmissionClaim(config, request.txId);
  request.state = RequestState.CHAIN_VERIFIED;
  request.error = undefined;
  request.chain = { successorOutpoint: `${request.txId}:${request.build.controllerOutputIndex}`, observedAt: request.chain?.observedAt ?? new Date().toISOString() };
  await saveWalletRequestV6(config, request);
  return request;
}
/* RC35 legacy F4 (2026-09-11): a genesis whose broadcast outcome is unresolved (SUBMITTING / SUBMITTED /
 * RECONCILIATION_REQUIRED) or that an earlier runtime persisted as SUBMISSION_REJECTED is recovered by OBSERVATION ONLY
 * through this SAME request: never rebuilt, never re-signed, never rebroadcast; the recovery belongs to the OPERABLE
 * set (it keeps working when new creation of this generation is disabled). */
const GENESIS_RECOVERY_STATES = new Set([RequestState.SUBMITTING, RequestState.SUBMITTED, RequestState.RECONCILIATION_REQUIRED, RequestState.SUBMISSION_REJECTED]);
async function recoverGenesisV6({ config, rpc, request, pollAttempts, pollDelayMs }) {
  const fromNegative = request.state === RequestState.SUBMISSION_REJECTED;
  const proof = await observeGenesisOutputV6(config, rpc, request, { pollAttempts, pollDelayMs });
  if (!proof) {
    const disposition = await refreshUnobservedGenesis({ config, rpc, request, claim: { txId: request.txId, vaultId: request.vaultId, action: request.action }, save: (q) => saveWalletRequestV6(config, q) });
    if (disposition.action === "KEEP_NEGATIVE") return request; // an ESTABLISHED negative: unchanged, nothing rebroadcast
    if (disposition.action === "PROTECT") await ensureOwnSubmissionClaim(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.state = RequestState.RECONCILIATION_REQUIRED;
    request.error = disposition.reason ?? `${request.txId} was broadcast but the controller output is not observed — reconcile (nothing is rebroadcast)`;
    await saveWalletRequestV6(config, request);
    throw fail(request.error, "RECONCILIATION_REQUIRED");
  }
  if (fromNegative) await ensureOwnSubmissionClaim(config, { txId: request.txId, vaultId: request.vaultId, action: request.action }); // the false negative released it; a conflicted completion must leave it in place
  return completeGenesisV6(config, request);
}
async function submitWalletRequestV6Unlocked({ config, requestId, rpc: providedRpc, pollAttempts = 30, pollDelayMs = 2000 }) {
  const request = await loadWalletRequestV6(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state === RequestState.CHAIN_VERIFIED) return request; // idempotent
  const recoveringGenesis = request.kind === "genesis" && GENESIS_RECOVERY_STATES.has(request.state);
  if (request.state !== RequestState.SIGNED && !recoveringGenesis) throwFail(`request is ${request.state}, not SIGNED`, request.state);

  try {
    assertOperationalNetwork(config);
    if (recoveringGenesis) assertGenerationMainnetOperable(config, CONTRACT_VERSION_V6); // observation of an existing attempt is not a new creation
    else assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V6);
  } catch (e) {
    throw fail(e.message, "NETWORK_MISMATCH");
  }

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    if (recoveringGenesis) return await recoverGenesisV6({ config, rpc, request, pollAttempts, pollDelayMs });

    if (request.kind === "swap" && !request.finalTransaction) {
      /* LAZY finalize — the freshness gate runs against the node's own
       * current DAA score, fetched right before broadcast. */
      const currentDaaScore = await getVirtualDaaScore(rpc);
      let finalized;
      try {
        ensureBuildDir({ config, buildDir: request.build.encoderBuildDir, recompile: () => compileExactStateV6({ config, template: request.build.template, state: request.build.stateJson, contractVersion: request.build.contractVersion }) }); // F-03
        finalized = finalizeV6Transaction({ build: request.build, covenantSignatureHex: request.covenantSignatureHex, fuelSignatureScriptHex: undefined, currentDaaScore });
      } catch (e) {
        request.state = e.code === "DEADLINE_PASSED" ? RequestState.DEADLINE_PASSED : RequestState.SIGNATURE_INVALID;
        request.error = e.message;
        await saveWalletRequestV6(config, request);
        throw fail(`swap finalize failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
      }
      verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
      await saveWalletRequestV6(config, request);
    }

    let transaction;
    if (request.kind === "genesis") {
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

    if (request.kind === "transition" || request.kind === "swap") {
      try {
        await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: request.txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected: { kind: "v6Successor", requestId: request.requestId, txId: request.txId } });
      } catch (e) {
        throw fail(e.message, "CLAIM_CONFLICT");
      }
    }
    if (request.kind === "genesis") await assertVaultIdentityFree(config, request.vaultId, { exceptRequestId: request.requestId, exceptTxId: request.txId, phase: "commit" }); // RC33-ID-01: before claims or broadcast
    await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.submitStartHash = await require("./submission-outcome-v7").readSubmissionStartHash(rpc);
    request.state = RequestState.SUBMITTING;
    await saveWalletRequestV6(config, request);

    let submitted;
    try {
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      /* RC35-REC-01: REJECTED / ALREADY_KNOWN / AMBIGUOUS through the shared classifier. A genesis settles its negative ONLY
       * with the controller output verified absent; a transition / swap / deposit only with its input still unspent AND
       * every frozen output absent; an already-known answer is observed like an accepted response; anything else keeps the claims. */
      const settled = request.kind === "genesis"
        ? await settleGenesisSubmitError({ config, request, rpc, message, txId: request.txId, expected: genesisExpectedOutputV6(config, request) })
        : await settleTransitionSubmitError({ config, rpc, request, message, txId: request.txId, predecessorLive: () => frozenInputLive(config, rpc, request.build.frozen, 0), effectAbsent: async () => !(await anyFrozenOutputObserved(config, rpc, request.build.frozen, request.txId)) });
      if (settled.decision === "REJECTED") {
        request.state = RequestState.SUBMISSION_REJECTED;
        request.submissionOutcome = { outcome: RequestState.SUBMISSION_REJECTED, reason: message, txId: request.txId, proof: settled.proof };
        await saveWalletRequestV6(config, request);
        if (request.kind === "transition" || request.kind === "swap") await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
        await releaseSubmissionClaim(config, request.txId);
        throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
      }
      if (settled.decision === "UNCERTAIN") {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        request.error = `${message} — ${settled.reason}`;
        await saveWalletRequestV6(config, request);
        throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
      }
      request.submissionResponse = { kind: "ALREADY_KNOWN", variant: settled.classification.variant, reason: message, at: new Date().toISOString() };
      submitted = { transactionId: request.txId };
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveWalletRequestV6(config, request);
      throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    await saveWalletRequestV6(config, request);

    if (request.kind === "genesis") {
      const proof = await observeGenesisOutputV6(config, rpc, request, { pollAttempts, pollDelayMs });
      if (!proof) {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        await saveWalletRequestV6(config, request);
        throw fail(`${request.txId} submitted but the controller output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      return await completeGenesisV6(config, request);
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
        await saveWalletRequestV6(config, request);
        throw fail(`${request.txId} submitted but the deposit output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      const manifest = await loadManifestV6(config, request.vaultId);
      const newTokenPosition = {
        outpoint: { transactionId: request.txId, index: 0 },
        value: depositValue,
        scriptPublicKeyHex: request.build.frozen.outputs[0].scriptPublicKey.scriptHex,
        covenantId: request.build.frozen.outputs[0].covenant.covenantId,
        state: request.build.tokenNewStates[0]
      };
      await persistManifestV6(config, { ...manifestToJsonV6(manifest), live: { ...manifestToJsonV6(manifest).live, tokenPosition: newTokenPosition }, latestTransitionTxId: request.txId });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveWalletRequestV6(config, request);
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { outpoint: `${request.txId}:0`, reconciled: false } });
      await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "tokenOwner", contractVersion: CONTRACT_VERSION_V6, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v6" });
      return request;
    }

    /* kind "transition" or "swap" */
    const terminal = request.action === "ownerRecover";
    if (terminal) {
      const manifest = await loadManifestV6(config, request.vaultId);
      await persistManifestV6(config, { ...manifestToJsonV6(manifest), status: VaultStatus.RECOVERED, live: null, latestTransitionTxId: request.txId });
      await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { recovered: true } });
      await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "owner", contractVersion: CONTRACT_VERSION_V6, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v6" });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveWalletRequestV6(config, request);
      return request;
    }

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
      await saveWalletRequestV6(config, request);
      throw fail(`${request.txId} submitted but the controller successor was not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    const manifest = await loadManifestV6(config, request.vaultId);
    const successorState = request.build.successorState;
    const stateId = computeStateIdV6({ networkId: config.networkId, template: manifest.template, state: normalizeStateV6(successorState), contractVersion: manifest.contractVersion });
    const isSpend = SPEND_ACTIONS.has(request.action);
    const isSwap = SWAP_ACTIONS.has(request.action);
    const currentJson = manifestToJsonV6(manifest);
    /* self continuation lands at output 1 for BOTH spend and swap shapes
     * (vault-builders-v6.js: [successor, ourNote/self, ...]) */
    const newTokenPosition = isSpend || isSwap
      ? { outpoint: { transactionId: request.txId, index: 1 }, value: request.build.frozen.outputs[1].value.toString(), scriptPublicKeyHex: request.build.frozen.outputs[1].scriptPublicKey.scriptHex, covenantId: request.build.frozen.outputs[1].covenant.covenantId, state: { ownerIdentifier: request.build.covenantId, identifierType: 2, amount: request.build.accounting.token.positionAfter, isMinter: false } }
      : currentJson.live.tokenPosition;
    const advancedRegistry = isSpend || isSwap ? advanceRegistryV6(currentJson.agentRegistry, request.build) : currentJson.agentRegistry;
    await persistManifestV6(config, {
      ...currentJson,
      agentRegistry: advancedRegistry,
      live: { state: successorState, stateId, outpoint: { transactionId: request.txId, index: succIndex }, outpointValue: controllerValueV6(normalizeStateV6(successorState)).toString(), scriptSha256: request.build.successorScriptSha256, covenantId: request.build.covenantId, tokenPosition: newTokenPosition },
      latestTransitionTxId: request.txId
    });
    await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
    await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { successorOutpoint: `${request.txId}:${succIndex}`, reconciled: false } });
    await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: isSpend || isSwap ? "agent" : "owner", contractVersion: CONTRACT_VERSION_V6, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v6" });
    request.state = RequestState.CHAIN_VERIFIED;
    await saveWalletRequestV6(config, request);
    return request;
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* ------------------------------------------------------------------ */
/* 5. REJECT                                                            */
/* ------------------------------------------------------------------ */

async function markWalletRejectedV6(config, requestId) {
  const request = await loadWalletRequestV6(config, requestId);
  if (request && request.state === RequestState.BUILT) {
    request.state = RequestState.WALLET_REJECTED;
    await saveWalletRequestV6(config, request);
  }
  return request;
}

module.exports = {
  V6_WALLET_REQUEST_SCHEMA,
  AUTHORITY_MODEL_V6,
  RequestState,
  TRANSITION_ACTIONS,
  loadWalletRequestV6,
  saveWalletRequestV6,
  listWalletRequestsV6,
  buildCreateWalletRequestV6,
  buildWalletRequestV6,
  submitSignatureV6,
  submitWalletRequestV6,
  markWalletRejectedV6,
  templateFieldsFromDescriptor,
  advanceRegistryV6,
  assertFixtureVenue,
  venuePresentation,
  spkToAddress,
  findOutpoint
};
