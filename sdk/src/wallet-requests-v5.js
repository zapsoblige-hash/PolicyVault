"use strict";
const { verifySignedSafeJsonInputs, verifyFinalTransactionInputs } = require("./vm-preflight");
const { ensureBuildDir } = require("./build-cache");
const { compileExactStateV5 } = require("./contract-compiler-v5");

/*
 * PolicyVault v0.5 TOKEN CONTROLLER (FROZEN; docs/postlaunch/
 * v0.5-covenant-byte-freeze.md) — server-orchestrated wallet-request
 * pipeline (Wave 2 Track E; docs/postlaunch/v0.7-app-surface-contract.md
 * §6.1 "POST /wallet/v5/*"). Mirrors the PROVEN v0.7 rooted-vault wallet
 * pattern (sdk/src/wallet-requests-v7.js §8 buildV7WalletRequest /
 * finalizeV7WalletRequest / submitV7WalletRequest): strict stages
 * intent -> build -> sign -> submit -> reconcile; builders never
 * broadcast; a submit result is never treated as success without exact
 * chain proof; durable transition + submission claims are created BEFORE
 * broadcast so a crash on either side is unambiguous; only PROVEN chain
 * reconciliation advances a durable manifest.
 *
 * EVERY funds-relevant decision stays in sdk/src/vault-builders-v5.js
 * (untouched by this file) and core/model/core/assets beneath it; this
 * module ONLY orchestrates durable records, signature collection,
 * submission, and short-poll chain proof (the deferred/crash-recovery
 * path is sdk/src/reconcile-v5.js). No server-only financial fact is
 * introduced: `accounting.token` / `accounting.kas` are passed through
 * from the SDK build verbatim, never recomputed here.
 *
 * ONE route family, THREE request kinds, sharing the SAME durable
 * BUILT -> SIGNED -> SUBMITTING -> SUBMITTED -> CHAIN_VERIFIED ladder
 * (unlike v0.4's separate genesis-submit route, v0.5 keeps the surface
 * narrow per the app-surface contract: create/requests/GET/{signature,
 * submit,reject} only):
 *   kind "genesis"      POST /wallet/v5/create      -> buildCreateV5
 *   kind "transition"   POST /wallet/v5/requests     -> buildV5Transaction
 *                        (tokenAgentSpend / ownerSetAgentRoot /
 *                        ownerTopUpReserve / ownerPause / ownerUnpause /
 *                        ownerRecover)
 *   kind "tokenDeposit" POST /wallet/v5/requests     -> buildTokenDepositV5
 *
 * SCOPE LIMITATION (recorded honestly, mirrors sdk/src/wallet-requests-
 * v7.js's own documented tokenDeposit limitation): a deposit into a
 * controller that ALREADY holds a tracked token position is refused
 * (TOKEN_POSITION_ALREADY_HELD) — buildTokenDepositV5 has no merge input,
 * so a second deposit would create a second, untracked same-family UTXO
 * this manifest's single tokenPosition field cannot represent.
 *
 * Status: IMPLEMENTED (Wave 2 Track E). UNIT/API-TESTED by
 * sdk/test/wallet-v5-api.test.js. Live: tools/testnet-v5-http-e2e.js.
 */

const crypto = require("crypto");

const { getStore, Categories } = require("./store");
const { assertOperationalNetwork, assertGenerationMainnetCreatable } = require("./config");
const { normalizeHex } = require("./vault-state");
const { parseSompi, sompiToKas, kasToSompi } = require("./amounts");
const { resolveAddressIdentity } = require("./address-identity");
const { connectVerified, getAddressUtxos } = require("./chain");
const { frozenToWasmTransaction } = require("./frozen-tx-v3");
const { claimTransition, claimSubmission, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { finalTxToWasm, isDefinitiveSubmitRejection } = require("./wallet-submit-v4");
const { appendAudit } = require("./audit");
const assets = require("../../core/assets");

const { CONTRACT_VERSION_V5, resolveV5Abi, normalizeTemplateV5, normalizeStateV5, stateToJsonV5, computeStateIdV5 } = require("./vault-state-v5");
const { buildV5Transaction, buildCreateV5, finalizeV5Transaction, buildTokenDepositV5, finalizeTokenDepositV5, OWNER_CONTROL_ACTIONS, SPEND_ACTIONS } = require("./vault-builders-v5");
const { normalizeRegistry, registryEntryToJson, loadManifestV5, persistManifestV5, manifestToJsonV5, MANIFEST_SCHEMA_V5 } = require("./manifest-v5");
const { VaultStatus } = require("./manifest");

const V5_WALLET_REQUEST_SCHEMA = "policyvault-wallet-request/v5";
const AUTHORITY_MODEL_V5 = "SINGLE_ON_CHAIN_OWNER";

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

/* actions handled by buildWalletRequestV5 (transitions + tokenDeposit) */
const TRANSITION_ACTIONS = new Set([...OWNER_CONTROL_ACTIONS, ...SPEND_ACTIONS, "ownerRecover"]);

function fail(message, code) {
  const e = new Error(`wallet-requests-v5: ${message}`);
  if (code) e.code = code;
  return e;
}
function throwFail(message, code) {
  throw fail(message, code);
}

/* Consensus amount params arrive over the API as untrusted JSON — accept
 * ONLY a bigint or a canonical base-10 string (CLAUDE.md numeric safety;
 * identical boundary hardening to wallet-requests-v4.js/-v7.js). */
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

async function loadWalletRequestV5(config, requestId) {
  const r = await getStore(config).read(Categories.REQUEST, requestId);
  return r && r.schema === V5_WALLET_REQUEST_SCHEMA ? r : null;
}
async function saveWalletRequestV5(config, request) {
  request.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.REQUEST, request.requestId, request);
  return request;
}
async function listWalletRequestsV5(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.REQUEST);
  const out = all.filter((r) => r && r.schema === V5_WALLET_REQUEST_SCHEMA && (vaultId === undefined || r.vaultId === vaultId));
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

/* The descriptor's accepted template, resolved into the exact template
 * pin fields buildCreateV5/buildV5Transaction require (mirrors
 * wallet-requests-v7.js's own private helper of the same name — a small
 * pure function, deliberately duplicated per version rather than shared
 * across covenant generations). */
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

/* The successor registry (JSON entries) after ONE tokenAgentSpend build:
 * advance ONLY the spending agent's leaf accounting, exactly the rule
 * manifest-v5.js's registry-root reconstruction pins (mirrors
 * wallet-requests-v7.js's advanceRegistryAfterSpendV7). */
function advanceRegistryAfterSpendV5(registry, build) {
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

/* ------------------------------------------------------------------ */
/* 1. GENESIS — POST /wallet/v5/create                                  */
/* ------------------------------------------------------------------ */

async function buildCreateWalletRequestV5({ config, label = "", descriptor, templateIndex = 0, initialAgents = [], feeReserveKas, signerAddress, funding, vaultId }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V5);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const ownerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const { validated, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen } = templateFieldsFromDescriptor(descriptor, templateIndex);
  const { entries, tree } = normalizeRegistry(initialAgents);
  const initialRegistry = entries.map((e) => registryEntryToJson(e));

  const vId = vaultId ? normalizeHex(vaultId, 32, "vaultId") : crypto.randomBytes(32).toString("hex");
  const template = { owner: ownerXOnly, vaultId: vId, descriptorHash, tokenCovenantId, templateVmHash, templatePrefixLen, templateStateLen, templateSuffixLen };
  const feeReserveSompi = kasToSompi(feeReserveKas, "feeReserveKas");
  const initialState = { feeReserve: feeReserveSompi.toString(), paused: "0", agentRoot: tree.root, policyNonce: "0" };

  if (!Array.isArray(funding) || funding.length === 0) throwFail("funding (a non-empty array of the owner's ordinary UTXOs) is required", "BUILD_FAILED");

  let genesis;
  try {
    genesis = buildCreateV5({ config, templateInput: template, initialStateInput: initialState, funding, changeXOnly: ownerXOnly, descriptor: validated });
  } catch (e) {
    throw fail(`v0.5 genesis build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, genesis.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();

  const requestId = crypto.randomUUID();
  const request = {
    schema: V5_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "genesis",
    vaultId: vId,
    action: "createTokenController",
    contractVersion: CONTRACT_VERSION_V5,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly: ownerXOnly,
    label,
    descriptor: validated,
    templateIndex,
    initialRegistry,
    build: genesis,
    accounting: genesis.accounting,
    txId: genesis.txId,
    requiredFeeSompi: genesis.requiredFeeSompi,
    transaction: { unsignedSafeJson, signInputs: genesis.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveWalletRequestV5(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 2. TRANSITIONS + TOKEN DEPOSIT — POST /wallet/v5/requests            */
/* ------------------------------------------------------------------ */

async function buildWalletRequestV5({ config, vaultId, action, params = {}, signerAddress }) {
  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V5);
  } catch (e) {
    throw fail(e.message, "BUILD_FAILED");
  }
  const manifest = await loadManifestV5(config, vaultId);
  if (!manifest) throwFail(`no v0.5 token controller ${vaultId}`, "VAULT_NOT_FOUND");
  if (!manifest.live) throwFail(`vault is ${manifest.status} (closed) — read-only history`, "VAULT_TERMINAL");

  const signerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
  const changeXOnly = signerXOnly;

  if (action === "tokenDeposit") {
    /* SCOPE LIMITATION (see module header): no merge input exists, so a
     * second deposit into an already-tracked position would create an
     * untracked same-family UTXO. Refuse closed. */
    if (manifest.live.tokenPosition !== null) {
      throwFail("this controller already holds a tracked token position — a second deposit would create an untracked same-family UTXO; failing closed", "TOKEN_POSITION_ALREADY_HELD");
    }
    const userPositionOutpoint = normalizeOutpoint(params.userPosition?.outpoint, "params.userPosition.outpoint");
    let build;
    try {
      build = buildTokenDepositV5({
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
      schema: V5_WALLET_REQUEST_SCHEMA,
      requestId,
      kind: "tokenDeposit",
      vaultId,
      action,
      contractVersion: CONTRACT_VERSION_V5,
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
    await saveWalletRequestV5(config, request);
    return request;
  }

  if (!TRANSITION_ACTIONS.has(action)) throwFail(`unknown v0.5 action ${JSON.stringify(action)} — failing closed`, "UNKNOWN_ACTION");
  const isSpend = SPEND_ACTIONS.has(action);
  if (isSpend && manifest.status !== VaultStatus.ACTIVE) throwFail(`vault status is ${manifest.status} — a delegate spend needs ACTIVE`, "BUILD_FAILED");

  const sdkParams = { ...params };
  if (isSpend) {
    sdkParams.agentPk = signerXOnly;
    if (sdkParams.spendAmount !== undefined) sdkParams.spendAmount = canonicalAmountParam(sdkParams.spendAmount, "spendAmount");
  }
  if (action === "ownerTopUpReserve" && sdkParams.topUpReserveAmountSompi !== undefined) {
    sdkParams.topUpReserveAmountSompi = canonicalAmountParam(sdkParams.topUpReserveAmountSompi, "topUpReserveAmountSompi");
  }

  const allowMalformedState = action === "ownerRecover" && params.allowMalformedState === true;
  const chain = {
    predecessorOutpoint: manifest.live.outpoint,
    covenantId: manifest.live.covenantId,
    predecessorValue: manifest.live.state.feeReserve.toString(),
    ...(params.fuel ? { fuel: params.fuel } : {}),
    ...(params.tokenPosition ? { tokenPosition: params.tokenPosition } : {})
  };

  let build;
  try {
    build = buildV5Transaction({
      config,
      contractVersion: CONTRACT_VERSION_V5,
      templateInput: manifest.template,
      stateInput: stateToJsonV5(manifest.live.state),
      action,
      params: { ...sdkParams, allowMalformedState },
      chain,
      changeXOnly,
      descriptor: isSpend || (action === "ownerRecover" && chain.tokenPosition) ? manifest.asset.descriptor : undefined,
      templateIndex: manifest.asset.templateIndex
    });
  } catch (e) {
    throw fail(`v0.5 ${action} build failed: ${e.message}`, e.code || "BUILD_FAILED");
  }

  const wtx = frozenToWasmTransaction(config, build.frozen);
  wtx.finalize();
  const unsignedSafeJson = wtx.serializeToSafeJSON();
  const requestId = crypto.randomUUID();
  const request = {
    schema: V5_WALLET_REQUEST_SCHEMA,
    requestId,
    kind: "transition",
    vaultId,
    action,
    contractVersion: CONTRACT_VERSION_V5,
    networkId: config.networkId,
    state: RequestState.BUILT,
    signerAddress,
    signerXOnly,
    predecessorOutpoint: manifest.live.outpoint,
    predecessorStateId: manifest.live.stateId,
    build,
    accounting: build.accounting,
    txId: build.txId,
    transaction: { unsignedSafeJson, signInputs: build.frozen.inputs.map((_, i) => ({ index: i, sighashType: 1 })) },
    requiredFeeSompi: build.requiredFeeSompi,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  await saveWalletRequestV5(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 3. SIGN — POST /wallet/v5/requests/:id/signature                     */
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

async function submitSignatureV5({ config, requestId, signedSafeJson }) {
  const request = await loadWalletRequestV5(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state !== RequestState.BUILT) throwFail(`request is ${request.state}, not BUILT`, request.state);
  if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throwFail("signedSafeJson is required", "BAD_SIGNATURE");

  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    await saveWalletRequestV5(config, request);
    throwFail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertImmutable(unsigned, signed);

  if (request.kind === "genesis") {
    for (let i = 0; i < unsigned.inputs.length; i++) {
      if (!signed.inputs[i]?.signatureScript) {
        request.state = RequestState.WALLET_REJECTED;
        await saveWalletRequestV5(config, request);
        throwFail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
      }
    }
    /* Genesis inputs are ORDINARY (p2pk) funding UTXOs — the wallet-signed
     * bytes are Safe JSON, a DIFFERENT shape from a finalized covenant-
     * transition's finalTransaction. Store the raw signed Safe JSON;
     * submitWalletRequestV5 reconstructs the WASM transaction from the
     * UNSIGNED Safe JSON + these signature scripts (mirrors
     * wallet-requests-v7.js's broadcastSignedGenesis). */
    /* F-04: VERIFY BEFORE SIGNED — every funding input executes on the real
     * engine against its spent UTXO (Schnorr over THIS transaction with the
     * key the UTXO script names). A bogus/foreign/replayed signature is a
     * pure refusal: the request stays BUILT for the legitimate signer. */
    try {
      verifySignedSafeJsonInputs({ frozenCanonicalJson: request.build.frozenCanonicalJson, signedSafeJson });
    } catch (e) {
      throwFail(`genesis signature rejected: ${e.message}`, "SIGNATURE_INVALID");
    }
    request.signedSafeJson = signedSafeJson;
    request.state = RequestState.SIGNED;
    await saveWalletRequestV5(config, request);
    return request;
  }

  try {
    let finalized;
    if (request.kind === "tokenDeposit") {
      const tokenOwnerSignatureHex = signed.inputs[0]?.signatureScript;
      const fuelSignatureScriptHex = signed.inputs[1]?.signatureScript;
      if (!tokenOwnerSignatureHex || !fuelSignatureScriptHex) throwFail("wallet did not sign every input", "WALLET_REJECTED");
      finalized = finalizeTokenDepositV5({ build: request.build, tokenOwnerSignatureHex, fuelSignatureScriptHex });
    } else {
      const covenantSignatureHex = signed.inputs[0]?.signatureScript;
      if (!covenantSignatureHex) throwFail("wallet did not sign the covenant input", "WALLET_REJECTED");
      const hasFuel = request.build.hasFuelInput === true;
      const fuelIndex = request.build.frozen.inputs.length - 1;
      const fuelSignatureScriptHex = hasFuel ? signed.inputs[fuelIndex]?.signatureScript : undefined;
      if (hasFuel && !fuelSignatureScriptHex) throwFail("wallet did not sign the fuel input", "WALLET_REJECTED");
      ensureBuildDir({ config, buildDir: request.build.encoderBuildDir, recompile: () => compileExactStateV5({ config, template: request.build.template, state: request.build.stateJson, contractVersion: request.build.contractVersion }) }); // F-03
      finalized = finalizeV5Transaction({ build: request.build, covenantSignatureHex, fuelSignatureScriptHex });
    }
    verifyFinalTransactionInputs(finalized.finalTransaction); // F-04: every input on the real VM before SIGNED
    request.finalTransaction = finalized.finalTransaction;
  } catch (e) {
    request.state = e.code === "WALLET_REJECTED" ? RequestState.WALLET_REJECTED : RequestState.SIGNATURE_INVALID;
    await saveWalletRequestV5(config, request);
    throw fail(`sign failed: ${e.message}`, e.code || "SIGNATURE_INVALID");
  }
  request.state = RequestState.SIGNED;
  await saveWalletRequestV5(config, request);
  return request;
}

/* ------------------------------------------------------------------ */
/* 4. SUBMIT — POST /wallet/v5/requests/:id/submit                      */
/* ------------------------------------------------------------------ */

async function submitWalletRequestV5({ config, requestId, rpc: providedRpc }) {
  const request = await loadWalletRequestV5(config, requestId);
  if (!request) throwFail(`no request ${requestId}`, "REQUEST_NOT_FOUND");
  if (request.state === RequestState.CHAIN_VERIFIED) return request; // idempotent
  if (request.state !== RequestState.SIGNED) throwFail(`request is ${request.state}, not SIGNED`, request.state);

  try {
    assertOperationalNetwork(config);
    assertGenerationMainnetCreatable(config, CONTRACT_VERSION_V5);
  } catch (e) {
    throw fail(e.message, "NETWORK_MISMATCH");
  }

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
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

    if (request.kind === "transition") {
      try {
        await claimTransition(config, { outpoint: request.predecessorOutpoint, action: request.action, txId: request.txId, vaultId: request.vaultId, stateId: request.predecessorStateId, expected: { kind: "v5Successor", requestId: request.requestId, txId: request.txId } });
      } catch (e) {
        throw fail(e.message, "CLAIM_CONFLICT");
      }
    }
    await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });
    request.state = RequestState.SUBMITTING;
    await saveWalletRequestV5(config, request);

    let submitted;
    try {
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        if (request.kind === "transition") await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
        await releaseSubmissionClaim(config, request.txId);
        request.state = RequestState.SUBMISSION_REJECTED;
        await saveWalletRequestV5(config, request);
        throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
      }
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveWalletRequestV5(config, request);
      throw fail(`submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      request.state = RequestState.RECONCILIATION_REQUIRED;
      await saveWalletRequestV5(config, request);
      throw fail(`node returned ${returnedTxId}, expected ${request.txId} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    await saveWalletRequestV5(config, request);

    if (request.kind === "genesis") {
      const address = spkToAddress(config, request.build.frozen.outputs[request.build.controllerOutputIndex].scriptPublicKey);
      let proof = null;
      for (let i = 0; i < 30 && !proof; i++) {
        const ref = await findOutpoint(rpc, address, request.txId, request.build.controllerOutputIndex);
        if (ref && String(ref.covenantId ?? "").toLowerCase() === request.build.covenantId) proof = ref;
        if (!proof) await new Promise((r) => setTimeout(r, 2000));
      }
      if (!proof) {
        request.state = RequestState.RECONCILIATION_REQUIRED;
        await saveWalletRequestV5(config, request);
        throw fail(`${request.txId} submitted but the controller output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      const state = normalizeStateV5(request.build.initialState);
      const stateId = computeStateIdV5({ networkId: config.networkId, template: request.build.template, state, contractVersion: CONTRACT_VERSION_V5 });
      const manifest = await persistManifestV5(config, {
        schema: MANIFEST_SCHEMA_V5,
        contractVersion: CONTRACT_VERSION_V5,
        networkId: config.networkId,
        vaultId: request.build.template.vaultId,
        label: request.label ?? "",
        status: VaultStatus.ACTIVE,
        template: request.build.template,
        asset: { descriptor: request.descriptor, templateIndex: request.templateIndex ?? 0 },
        agentRegistry: request.initialRegistry ?? [],
        live: { state: stateToJsonV5(state), stateId, outpoint: { transactionId: request.txId, index: request.build.controllerOutputIndex }, outpointValue: state.feeReserve.toString(), scriptSha256: request.build.scriptSha256, covenantId: request.build.covenantId, tokenPosition: null },
        creationTxId: request.txId,
        latestTransitionTxId: null
      });
      await persistReceipt(config, { txId: request.txId, vaultId: manifest.vaultId, action: "createTokenController", proof: { outpoint: `${request.txId}:${request.build.controllerOutputIndex}`, covenantId: request.build.covenantId } });
      await appendAudit(config, { vaultId: manifest.vaultId, action: "createTokenController", actor: "owner", contractVersion: CONTRACT_VERSION_V5, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v5" });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveWalletRequestV5(config, request);
      return request;
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
        await saveWalletRequestV5(config, request);
        throw fail(`${request.txId} submitted but the deposit output was not observed — reconcile`, "RECONCILIATION_REQUIRED");
      }
      const manifest = await loadManifestV5(config, request.vaultId);
      const newTokenPosition = {
        outpoint: { transactionId: request.txId, index: 0 },
        value: depositValue,
        scriptPublicKeyHex: request.build.frozen.outputs[0].scriptPublicKey.scriptHex,
        covenantId: request.build.frozen.outputs[0].covenant.covenantId,
        state: request.build.tokenNewStates[0]
      };
      await persistManifestV5(config, { ...manifestToJsonV5(manifest), live: { ...manifestToJsonV5(manifest).live, tokenPosition: newTokenPosition }, latestTransitionTxId: request.txId });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveWalletRequestV5(config, request);
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { outpoint: `${request.txId}:0`, reconciled: false } });
      await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "tokenOwner", contractVersion: CONTRACT_VERSION_V5, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v5" });
      return request;
    }

    /* kind === "transition" */
    const terminal = request.action === "ownerRecover";
    if (terminal) {
      const manifest = await loadManifestV5(config, request.vaultId);
      await persistManifestV5(config, { ...manifestToJsonV5(manifest), status: VaultStatus.RECOVERED, live: null, latestTransitionTxId: request.txId });
      await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
      await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { recovered: true } });
      await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: "owner", contractVersion: CONTRACT_VERSION_V5, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v5" });
      request.state = RequestState.CHAIN_VERIFIED;
      await saveWalletRequestV5(config, request);
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
      await saveWalletRequestV5(config, request);
      throw fail(`${request.txId} submitted but the controller successor was not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    const manifest = await loadManifestV5(config, request.vaultId);
    const successorState = request.build.successorState;
    const stateId = computeStateIdV5({ networkId: config.networkId, template: manifest.template, state: normalizeStateV5(successorState), contractVersion: manifest.contractVersion });
    const isSpend = SPEND_ACTIONS.has(request.action);
    /* a spend's SELF token continuation always lands at output 1 (see
     * vault-builders-v5.js's shapeFor: [successor, selfCarry, recipientCarry, change?]) */
    const currentJson = manifestToJsonV5(manifest);
    const newTokenPosition = isSpend
      ? { outpoint: { transactionId: request.txId, index: 1 }, value: request.build.frozen.outputs[1].value.toString(), scriptPublicKeyHex: request.build.frozen.outputs[1].scriptPublicKey.scriptHex, covenantId: request.build.frozen.outputs[1].covenant.covenantId, state: { ownerIdentifier: request.build.covenantId, identifierType: 2, amount: request.build.accounting.token.positionAfter, isMinter: false } }
      : currentJson.live.tokenPosition;
    const advancedRegistry = isSpend ? advanceRegistryAfterSpendV5(currentJson.agentRegistry, request.build) : currentJson.agentRegistry;
    await persistManifestV5(config, {
      ...currentJson,
      agentRegistry: advancedRegistry,
      live: { state: successorState, stateId, outpoint: { transactionId: request.txId, index: succIndex }, outpointValue: successorState.feeReserve, scriptSha256: request.build.successorScriptSha256, covenantId: request.build.covenantId, tokenPosition: newTokenPosition },
      latestTransitionTxId: request.txId
    });
    await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
    await persistReceipt(config, { txId: request.txId, vaultId: request.vaultId, action: request.action, proof: { successorOutpoint: `${request.txId}:${succIndex}`, reconciled: false } });
    await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: isSpend ? "agent" : "owner", contractVersion: CONTRACT_VERSION_V5, txId: request.txId, result: "CHAIN_VERIFIED", via: "wallet/v5" });
    request.state = RequestState.CHAIN_VERIFIED;
    await saveWalletRequestV5(config, request);
    return request;
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* ------------------------------------------------------------------ */
/* 5. REJECT                                                            */
/* ------------------------------------------------------------------ */

async function markWalletRejectedV5(config, requestId) {
  const request = await loadWalletRequestV5(config, requestId);
  if (request && request.state === RequestState.BUILT) {
    request.state = RequestState.WALLET_REJECTED;
    await saveWalletRequestV5(config, request);
  }
  return request;
}

module.exports = {
  V5_WALLET_REQUEST_SCHEMA,
  AUTHORITY_MODEL_V5,
  RequestState,
  TRANSITION_ACTIONS,
  loadWalletRequestV5,
  saveWalletRequestV5,
  listWalletRequestsV5,
  buildCreateWalletRequestV5,
  buildWalletRequestV5,
  submitSignatureV5,
  submitWalletRequestV5,
  markWalletRejectedV5,
  templateFieldsFromDescriptor,
  advanceRegistryAfterSpendV5,
  spkToAddress,
  findOutpoint
};
