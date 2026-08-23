"use strict";

/*
 * PolicyVault v0.4 LIVE submission + exact chain proof + atomic manifest/
 * registry advancement (Checkpoint H §H1–§H5).
 *
 * This is the ONLY place a v0.4 transaction is broadcast. It takes a
 * PREFLIGHT_VERIFIED request (produced by the Checkpoint-G offline pipeline,
 * with the exact finalized transaction, durable transition+submission claims,
 * and expected chain effect already recorded) and drives:
 *
 *   PREFLIGHT_VERIFIED -> SUBMITTING -> SUBMITTED -> CHAIN_VERIFIED
 *
 * Submission safety (H3): every precondition is re-checked BEFORE broadcast;
 * SUBMITTING is persisted BEFORE the node call; the node-returned txid MUST
 * equal the exact frozen txid (any other txid is ambiguous / reconcile). The
 * transaction is NEVER rebuilt or modified after signing.
 *
 * Exact chain proof (H4): CHAIN_VERIFIED requires the exact successor
 * outpoint at the exact successor covenant address carrying the exact value
 * and covenantId (successor script/state are re-derived from the request's
 * successor state, so the successor ADDRESS match proves the exact state,
 * incl. agentRoot). Only then does the manifest advance, ATOMICALLY with the
 * durable agent registry (H5); the advanced manifest is reloaded and its
 * registry independently reconstructs the successor agentRoot (fail closed).
 *
 * Definitive vs ambiguous submission outcomes are classified exactly as the
 * hardened v0.2 path: a DEFINITIVE node rejection (with the predecessor proven
 * still live and the expected effect absent) releases claims; anything
 * ambiguous keeps them for reconciliation. Uncertainty never releases a claim.
 *
 * Operational networks: testnet-10, and mainnet under the Gate R dual-flag
 * unlock (owner authorization 2026-08-22, docs/production-release.md §8).
 * Config, request, manifest, and the connected node must all agree on ONE
 * network; anything else is refused before any broadcast.
 */

const { CONTRACT_VERSION_V4, stateToJsonV4, normalizeStateV4, computeStateIdV4 } = require("./vault-state-v4");
const { compileExactStateV4 } = require("./contract-compiler-v4");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { loadManifestV4, persistManifestV4 } = require("./manifest-v4");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("./agent-merkle-v4");
const { buildRecipientTree } = require("./recipient-merkle-v3");
const {
  claimSubmission,
  releaseTransitionClaim,
  releaseSubmissionClaim,
  loadTransitionClaim,
  persistReceipt
} = require("./submission-claim");
const { appendAudit } = require("./audit");
const { VaultStatus } = require("./manifest");
const { RequestState, loadRequest, saveRequest } = require("./wallet-requests-v4");
const { assertOperationalNetwork } = require("./config");

function fail(message, code) {
  const error = new Error(`wallet-submit-v4: ${message}`);
  if (code) error.code = code;
  return error;
}

/*
 * Gate R network gate: the configured network must be operational
 * (testnet-10, or mainnet under the dual-flag unlock), and the request and
 * manifest must be stamped with EXACTLY that network — cross-network
 * material never broadcasts.
 */
function requireOperationalNetwork(config, request, manifest) {
  try {
    assertOperationalNetwork(config);
  } catch (e) {
    throw fail(`refusing to broadcast: ${e.message}`, "NETWORK_MISMATCH");
  }
  if (request && request.networkId !== config.networkId) throw fail(`request network ${request.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
  if (manifest && manifest.networkId !== config.networkId) throw fail(`manifest network ${manifest.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
}

// DEFINITIVE = the node evaluated the transaction and rejected it. rusty-kaspa
// formats every such rejection as "Rejected transaction {id}: {reason}"
// (rpc/core/src/error.rs:54, RpcError::RejectedTransaction) — this is also how a
// non-standard/sig-op rejection surfaces. The wRPC client may deliver it bare,
// behind the SDK's own "submit failed: " prefix, or WRAPPED by the transport as
// "RPC Server (remote error) -> Rejected transaction …" (rpc/core/src/error.rs:117)
// or the JS form "… message:`Rejected transaction …`". A word-boundary match on
// the exact "Rejected transaction " marker recognizes all of these while
// transport failures (timeout, dropped connection, "not connected", crash) —
// which never carry that marker — stay AMBIGUOUS. This is only a fast-path hint:
// the transition path still re-verifies predecessor-live + effect-absent by
// chain proof before releasing any claim (so a false positive cannot release a
// claim unsafely); genesis carries no covenant successor to endanger.
function isDefinitiveSubmitRejection(message) {
  return /\bRejected transaction /i.test(String(message ?? ""));
}

/* TEST-ONLY submission-error injection (refuses mainnet). */
function maybeInjectSubmitError(config, txId) {
  const mode = process.env.PV_TEST_WALLET_SUBMIT_ERROR;
  if (!mode) return;
  if (config.networkId === "mainnet") throw fail("PV_TEST_WALLET_SUBMIT_ERROR must never be armed on mainnet");
  if (mode === "definitive") throw new Error(`Rejected transaction ${txId}: TEST INJECTION (definitive)`);
  throw new Error("websocket connection dropped before response (TEST INJECTION)");
}

/* TEST-ONLY crash injection at a named durable boundary (refuses mainnet). */
function maybeCrash(config, point) {
  const armed = process.env.PV_TEST_CRASH_AT;
  if (!armed || armed !== point) return;
  if (config.networkId === "mainnet") throw fail("PV_TEST_CRASH_AT must never be armed on mainnet");
  const e = new Error(`TEST CRASH at ${point}`);
  e.code = "TEST_CRASH";
  throw e;
}

/* Build a submittable WASM Transaction from the stored final-transaction JSON
 * (inputs carry their signature scripts + spent UTXOs; outputs carry covenant
 * bindings). The v1 txId excludes signature scripts, so it equals the frozen
 * txId — asserted by the caller. */
function finalTxToWasm(config, finalTx) {
  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const { Transaction, CovenantBinding, Hash } = kaspa;
  const txObject = {
    version: 1,
    inputs: finalTx.inputs.map((input) => ({
      previousOutpoint: { transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index },
      signatureScript: input.signatureScript,
      sequence: BigInt(input.sequence),
      sigOpCount: 0,
      computeBudget: input.computeBudget,
      utxo: {
        outpoint: { transactionId: input.previousOutpoint.transactionId, index: input.previousOutpoint.index },
        amount: BigInt(input.utxo.amount),
        scriptPublicKey: { version: input.utxo.scriptPublicKey.version, script: input.utxo.scriptPublicKey.scriptHex },
        blockDaaScore: BigInt(input.utxo.blockDaaScore ?? 0),
        isCoinbase: false
      }
    })),
    outputs: finalTx.outputs.map((o) => ({ value: BigInt(o.value), scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex } })),
    lockTime: BigInt(finalTx.lockTime),
    subnetworkId: finalTx.subnetworkId,
    gas: BigInt(finalTx.gas),
    payload: finalTx.payload
  };
  const transaction = new Transaction(txObject);
  const outs = transaction.outputs;
  let bound = false;
  finalTx.outputs.forEach((o, i) => {
    if (o.covenant) {
      outs[i].covenant = new CovenantBinding(o.covenant.authorizingInput, new Hash(o.covenant.covenantId));
      bound = true;
    }
  });
  if (bound) transaction.outputs = outs;
  return transaction;
}

/* Re-derive the successor covenant address + script from the request's
 * successor state (for the exact chain proof). */
function successorAddressAndScript(config, template, successorState, contractVersion) {
  const state = normalizeStateV4(successorState);
  const compiled = compileExactStateV4({ config, template, state, contractVersion });
  return { address: covenantAddress(config, compiled.scriptBytes), scriptSha256: compiled.scriptSha256, state };
}

async function findOutpoint(rpc, address, txId, index) {
  const utxos = await getAddressUtxos(rpc, address);
  return utxos.find((u) => u.outpoint.transactionId === txId && Number(u.outpoint.index) === Number(index)) ?? null;
}

/*
 * SUBMIT a PREFLIGHT_VERIFIED v0.4 request to the live node, prove the exact
 * effect, and advance the manifest + registry atomically. testnet-10 only.
 */
async function submitWalletRequestV4({ config, requestId, rpc: providedRpc, pollAttempts = 30, pollDelayMs = 2000 }) {
  const request = loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.schema !== "policyvault-wallet-request/v4") throw fail("not a v0.4 request", "BUILD_FAILED");
  if (request.state !== RequestState.PREFLIGHT_VERIFIED) throw fail(`request ${requestId} is ${request.state}, not PREFLIGHT_VERIFIED`, request.state);
  if (request.kind === "genesis") throw fail("use submitCreateWalletRequestV4 for genesis", "BUILD_FAILED");

  const manifest = loadManifestV4(config, request.vaultId); // loader enforces registry root-equality
  if (!manifest || !manifest.live || manifest.live.stateId !== request.predecessorStateId) {
    request.state = RequestState.STALE;
    saveRequest(config, request);
    throw fail("vault advanced since this request was built — rebuild required", "STALE");
  }
  requireOperationalNetwork(config, request, manifest);

  // The transition claim must be held by THIS request+txid (created at G finalize).
  const claim = loadTransitionClaim(config, request.predecessorOutpoint);
  if (!claim || claim.txId !== request.txId) {
    throw fail("no transition claim held by this request — reconcile", "CLAIM_CONFLICT");
  }

  const terminal = request.sdkAction === "ownerRecover";
  const template = { owner: manifest.template.owner, vaultId: manifest.vaultId };
  const predecessor = successorAddressAndScript(config, template, stateToJsonV4(manifest.live.state), manifest.contractVersion);

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");

    // Predecessor must still be the live vault outpoint on chain.
    const liveRef = await findOutpoint(rpc, predecessor.address, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
    if (!liveRef) {
      request.state = RequestState.STALE;
      saveRequest(config, request);
      throw fail("manifest live outpoint not on chain — reconcile first", "STALE");
    }

    const transaction = finalTxToWasm(config, request.finalTransaction);
    const computedTxId = transaction.finalize().toString().toLowerCase();
    if (computedTxId !== request.txId) {
      throw fail(`reconstructed txid ${computedTxId} != frozen txid ${request.txId} — refusing to broadcast`, "TXID_MISMATCH");
    }

    // Submission claim keyed by the exact txid (idempotent).
    claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });

    // Persist SUBMITTING BEFORE the node call.
    request.state = RequestState.SUBMITTING;
    saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTING"); // crash-before-broadcast

    // Expected effect (re-derived; the successor address proves the state).
    const covIdx = request.finalTransaction.outputs.findIndex((o) => o.covenant !== null);
    const expected = terminal
      ? { kind: "recover", txId: request.txId, index: 0, valueSompi: request.build.accounting.terminalPayout, ownerAddress: request.signerAddress }
      : {
          kind: "successor",
          txId: request.txId,
          index: covIdx,
          valueSompi: (BigInt(request.build.successorState.protectedValue) + BigInt(request.build.successorState.feeReserve)).toString(),
          covenantId: request.covenantId,
          address: successorAddressAndScript(config, template, request.build.successorState, request.contractVersion).address,
          scriptSha256: request.build.successorScriptSha256,
          stateId: request.successorStateId
        };

    let submitted;
    try {
      maybeInjectSubmitError(config, request.txId);
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        // DEFINITIVE: confirm predecessor still live AND effect absent, then release.
        const stillLive = await findOutpoint(rpc, predecessor.address, manifest.live.outpoint.transactionId, manifest.live.outpoint.index).catch(() => null);
        const effect = await proveExpectedEffectV4(rpc, expected).catch(() => null);
        if (stillLive && !effect) {
          releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
          releaseSubmissionClaim(config, request.txId);
          appendAudit(config, { vaultId: request.vaultId, action: "submission_rejected_claims_released", actor: "system", txId: request.txId, result: "REJECTED_BY_NODE", oldStateId: request.predecessorStateId, detail: message });
          request.state = "SUBMISSION_REJECTED";
          saveRequest(config, request);
          throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
        }
      }
      request.state = "RECONCILIATION_REQUIRED";
      saveRequest(config, request);
      throw fail(`submit failed: ${message} — claims kept, reconcile required`, "RECONCILIATION_REQUIRED");
    }

    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      // Node acknowledged SOMETHING — ambiguous. Keep claims.
      request.state = "RECONCILIATION_REQUIRED";
      request.error = `node returned ${returnedTxId}, expected ${request.txId}`;
      saveRequest(config, request);
      throw fail(request.error + " — reconcile required", "RECONCILIATION_REQUIRED");
    }

    request.state = RequestState.SUBMITTED;
    saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTED"); // crash-after-broadcast (ambiguity)

    // Exact chain proof.
    let proof = null;
    for (let i = 0; i < pollAttempts && !proof; i++) {
      proof = await proveExpectedEffectV4(rpc, expected);
      if (!proof) await new Promise((r) => setTimeout(r, pollDelayMs));
    }
    if (!proof) {
      request.state = "RECONCILIATION_REQUIRED";
      saveRequest(config, request);
      throw fail(`submitted ${request.txId} but exact effect not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    maybeCrash(config, "AFTER_PROOF"); // crash after accept, before advance

    advanceManifestAndRegistryV4(config, manifest, request, expected);
    request.state = RequestState.CHAIN_VERIFIED;
    saveRequest(config, request);
    maybeCrash(config, "AFTER_ADVANCE"); // crash after advance, before claim release

    persistReceipt(config, {
      txId: request.txId,
      vaultId: request.vaultId,
      action: request.action,
      proof: { requestId, successorOutpoint: terminal ? null : `${request.txId}:${expected.index}`, value: expected.valueSompi, requiredFeeSompi: request.build.accounting.fee, actualFeeSompi: request.build.accounting.fee }
    });
    appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: request.signerRole, contractVersion: request.contractVersion, txId: request.txId, result: "CHAIN_VERIFIED", feeSompi: request.build.accounting.fee, oldStateId: request.predecessorStateId, newStateId: terminal ? null : request.successorStateId, via: "wallet" });

    return { request, txId: request.txId, expected };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/*
 * Prove the exact expected effect on chain (never treats predecessor absence
 * as proof). For a successor: the exact outpoint at the successor covenant
 * address with the exact value + covenantId. For recovery: the exact owner
 * payout outpoint with the exact value + no covenant.
 */
async function proveExpectedEffectV4(rpc, expected) {
  if (!expected || !expected.kind) return null;
  if (expected.kind === "successor") {
    const ref = await findOutpoint(rpc, expected.address, expected.txId, expected.index);
    if (!ref) return null;
    const valueOk = BigInt(ref.amount) === BigInt(expected.valueSompi);
    const covOk = String(ref.covenantId).toLowerCase() === String(expected.covenantId).toLowerCase();
    return valueOk && covOk ? ref : null;
  }
  if (expected.kind === "recover") {
    const ref = await findOutpoint(rpc, expected.ownerAddress, expected.txId, expected.index);
    if (!ref) return null;
    const valueOk = BigInt(ref.amount) === BigInt(expected.valueSompi);
    const ordinaryOk = ref.covenantId === undefined || ref.covenantId === null;
    return valueOk && ordinaryOk ? ref : null;
  }
  return null;
}

/*
 * Advance the manifest AND the durable agent registry ATOMICALLY (H5). For a
 * successor: the new manifest carries the successor state, outpoint, and the
 * registry recorded in the request (unchanged for spends/value ops; the new
 * set for agent-root ops). persistManifestV4 re-verifies registry
 * root-equality against the successor agentRoot (fail closed), and we reload
 * and reconstruct once more. For recovery: terminal, no successor.
 */
function advanceManifestAndRegistryV4(config, manifest, request, expected) {
  if (expected.kind === "recover") {
    persistManifestV4(config, {
      ...manifestToJson(manifest),
      status: VaultStatus.RECOVERED,
      live: null,
      latestTransitionTxId: expected.txId,
      lastTransition: { action: "ownerRecover", txId: expected.txId, oldStateId: request.predecessorStateId, newStateId: null, oldOutpoint: request.predecessorOutpoint, newOutpoint: null }
    });
    return;
  }
  // The successor registry: for ownerSetAgentRoot ops the request carries the
  // NEW registry; agentSpend advances the SPENDING agent's leaf accounting in
  // place; value/approver/pause ops leave the registry unchanged.
  const successorRegistry = deriveSuccessorRegistry(manifest, request);
  const successorState = request.build.successorState;
  const advanced = persistManifestV4(config, {
    ...manifestToJson(manifest),
    status: Number(successorState.paused) === 1 ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
    agentRegistry: successorRegistry,
    live: {
      state: successorState,
      stateId: expected.stateId,
      outpoint: { transactionId: expected.txId, index: Number(expected.index) },
      outpointValue: expected.valueSompi,
      scriptSha256: expected.scriptSha256,
      covenantId: expected.covenantId
    },
    latestTransitionTxId: expected.txId,
    lastTransition: { action: request.action, txId: expected.txId, oldStateId: request.predecessorStateId, newStateId: expected.stateId, oldOutpoint: request.predecessorOutpoint, newOutpoint: { transactionId: expected.txId, index: Number(expected.index) } }
  });
  // Independent re-verification: reload from disk and reconstruct the root.
  const reloaded = loadManifestV4(config, manifest.vaultId);
  if (!reloaded.live || reloaded.agentRegistryRoot !== reloaded.live.state.agentRoot) {
    throw fail("post-advance registry reconstruction does not match the successor agentRoot — SECURITY STOP", "REGISTRY_DRIFT");
  }
  void advanced;
}

/* The successor registry (JSON entries) for a manifest+request. */
function deriveSuccessorRegistry(manifest, request) {
  const current = manifest.agentRegistry.map((e) => registryEntryToJson(e));
  if (request.newRegistry) {
    // ownerSetAgentRoot family: the request carries the full new registry.
    return request.newRegistry;
  }
  if (request.sdkAction === "agentSpend") {
    // Advance ONLY the spending agent's leaf accounting; recompute its leaf.
    const agentPk = request.agentPk;
    const ce = request.build.callExtra;
    const periodsElapsed = BigInt(ce.periodsElapsed ?? "0");
    return current.map((e) => {
      if (e.agentPk !== agentPk) return e;
      const pay = BigInt(request.build.payment.value);
      let newStart = BigInt(e.periodStartDaa);
      let newSpent = BigInt(e.periodSpent) + pay;
      if (periodsElapsed >= 1n) {
        newStart = BigInt(e.periodStartDaa) + periodsElapsed * BigInt(e.periodLengthDaa);
        newSpent = pay;
      }
      return { ...e, periodStartDaa: newStart.toString(), periodSpent: newSpent.toString() };
    });
  }
  // value/approver/pause ops: registry unchanged.
  return current;
}

function registryEntryToJson(e) {
  const p = e.policy;
  return {
    agentPk: p.agentPk,
    maxPerSpend: p.maxPerSpend.toString(),
    periodBudget: p.periodBudget.toString(),
    periodLengthDaa: p.periodLengthDaa.toString(),
    periodStartDaa: p.periodStartDaa.toString(),
    periodSpent: p.periodSpent.toString(),
    approvalThreshold: p.approvalThreshold.toString(),
    agentMaxFeePerTx: p.agentMaxFeePerTx.toString(),
    agentRecipientRoot: p.agentRecipientRoot,
    recipients: [...e.recipients]
  };
}

/* Serialize a normalized manifest back to its JSON doc shape (for spreading
 * into persistManifestV4). */
function manifestToJson(manifest) {
  return {
    schema: manifest.schema,
    contractVersion: manifest.contractVersion,
    networkId: manifest.networkId,
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
    agentRegistry: manifest.agentRegistry.map((e) => registryEntryToJson(e)),
    live: manifest.live
      ? { state: stateToJsonV4(manifest.live.state), stateId: manifest.live.stateId, outpoint: manifest.live.outpoint, outpointValue: manifest.live.outpointValue.toString(), scriptSha256: manifest.live.scriptSha256, covenantId: manifest.live.covenantId }
      : null,
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    lastTransition: manifest.lastTransition
  };
}

/*
 * GENESIS live flow (H4): broadcast the funding transaction and prove the
 * exact covenant vault output on chain BEFORE creating the authoritative v0.4
 * manifest + initial registry. The manifest is created ONLY after the genesis
 * covenant outpoint is chain-proven. testnet-10 only.
 */
async function submitCreateWalletRequestV4({ config, requestId, signedSafeJson, rpc: providedRpc, pollAttempts = 30, pollDelayMs = 2000 }) {
  const request = loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.kind !== "genesis" || request.schema !== "policyvault-wallet-request/v4") throw fail("not a v0.4 genesis request", "BUILD_FAILED");
  if (request.state !== RequestState.BUILT) throw fail(`genesis request is ${request.state}, not BUILT`, request.state);
  requireOperationalNetwork(config, request, null);

  const { loadKaspa } = require("./chain");
  const kaspa = loadKaspa(config);
  const { Transaction } = kaspa;

  const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
  let signed;
  try {
    signed = JSON.parse(signedSafeJson);
  } catch {
    request.state = RequestState.SIGNATURE_INVALID;
    saveRequest(config, request);
    throw fail("signed Safe JSON is not valid JSON", "SIGNATURE_INVALID");
  }
  assertGenesisImmutable(unsigned, signed);

  // Rebuild the WASM tx from the unsigned form + wallet signatures (funding
  // inputs are ordinary P2PK; there is no covenant input at genesis).
  const transaction = Transaction.deserializeFromSafeJSON(request.transaction.unsignedSafeJson);
  const ins = transaction.inputs;
  for (let i = 0; i < ins.length; i++) {
    const sig = signed.inputs[i]?.signatureScript;
    if (!sig) {
      request.state = RequestState.WALLET_REJECTED;
      saveRequest(config, request);
      throw fail(`wallet did not sign funding input ${i}`, "WALLET_REJECTED");
    }
    ins[i].signatureScript = sig;
  }
  transaction.inputs = ins;

  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    const txId = transaction.finalize().toString().toLowerCase();
    if (txId !== request.txId) throw fail(`reconstructed genesis txid ${txId} != frozen ${request.txId}`, "TXID_MISMATCH");

    claimSubmission(config, { txId, vaultId: request.vaultId, action: "createVault" });
    request.state = RequestState.SUBMITTING;
    request.txId = txId;
    saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTING");

    // The vault covenant address (for the exact proof).
    const compiled = compileExactStateV4({ config, template: { owner: request.template.owner, vaultId: request.vaultId }, state: normalizeStateV4(request.initialState), contractVersion: request.contractVersion });
    const vaultAddress = covenantAddress(config, compiled.scriptBytes);
    const vaultValue = (BigInt(request.initialState.protectedValue) + BigInt(request.initialState.feeReserve)).toString();

    let submitted;
    try {
      maybeInjectSubmitError(config, txId);
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        releaseSubmissionClaim(config, txId); // genesis has no transition claim
        request.state = "SUBMISSION_REJECTED";
        saveRequest(config, request);
        throw fail(`node rejected genesis: ${message}`, "SUBMISSION_REJECTED");
      }
      request.state = "RECONCILIATION_REQUIRED";
      saveRequest(config, request);
      throw fail(`genesis submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    if (String(submitted.transactionId ?? submitted).toLowerCase() !== txId) {
      request.state = "RECONCILIATION_REQUIRED";
      saveRequest(config, request);
      throw fail("node returned an unexpected genesis txid — reconcile", "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTED");

    // Prove the exact covenant vault output.
    let proof = null;
    for (let i = 0; i < pollAttempts && !proof; i++) {
      const ref = await findOutpoint(rpc, vaultAddress, txId, request.vaultOutputIndex);
      if (ref && BigInt(ref.amount) === BigInt(vaultValue) && String(ref.covenantId).toLowerCase() === String(request.covenantId).toLowerCase()) proof = ref;
      if (!proof) await new Promise((r) => setTimeout(r, pollDelayMs));
    }
    if (!proof) {
      request.state = "RECONCILIATION_REQUIRED";
      saveRequest(config, request);
      throw fail(`genesis ${txId} submitted but covenant output not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    maybeCrash(config, "AFTER_PROOF");

    // NOW create the authoritative manifest + initial registry (proven).
    const state = normalizeStateV4(request.initialState);
    const stateId = computeStateIdV4({ networkId: config.networkId, template: { owner: request.template.owner, vaultId: request.vaultId }, state, contractVersion: request.contractVersion });
    persistManifestV4(config, {
      schema: "policyvault-vault-manifest/v4",
      contractVersion: request.contractVersion,
      networkId: config.networkId,
      vaultId: request.vaultId,
      label: request.label,
      status: VaultStatus.ACTIVE,
      template: { owner: request.template.owner, vaultId: request.vaultId },
      agentRegistry: request.initialRegistry,
      live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: txId, index: request.vaultOutputIndex }, outpointValue: vaultValue, scriptSha256: request.scriptSha256, covenantId: request.covenantId },
      creationTxId: txId,
      latestTransitionTxId: null,
      lastTransition: null
    });
    // Independent post-create root reconstruction.
    const reloaded = loadManifestV4(config, request.vaultId);
    if (!reloaded.live || reloaded.agentRegistryRoot !== reloaded.live.state.agentRoot) {
      throw fail("post-genesis registry reconstruction mismatch — SECURITY STOP", "REGISTRY_DRIFT");
    }
    persistReceipt(config, { txId, vaultId: request.vaultId, action: "createVault", proof: { requestId, outpoint: `${txId}:${request.vaultOutputIndex}`, covenantId: request.covenantId } });
    appendAudit(config, { vaultId: request.vaultId, action: "vault_created", actor: "owner", contractVersion: request.contractVersion, txId, result: "CHAIN_VERIFIED", newStateId: stateId, via: "wallet" });
    request.state = RequestState.CHAIN_VERIFIED;
    saveRequest(config, request);
    return { request, txId, vaultAddress };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

function assertGenesisImmutable(unsigned, signed) {
  const strip = (tx) => ({ version: tx.version, lockTime: tx.lockTime, subnetworkId: tx.subnetworkId, gas: tx.gas, payload: tx.payload, inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })), outputs: tx.outputs });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throw fail("signed genesis mutated a consensus-visible field", "SIGNATURE_INVALID");
}

module.exports = {
  submitWalletRequestV4,
  submitCreateWalletRequestV4,
  proveExpectedEffectV4,
  advanceManifestAndRegistryV4,
  finalTxToWasm,
  successorAddressAndScript,
  isDefinitiveSubmitRejection,
  registryEntryToJson,
  manifestToJson,
  deriveSuccessorRegistry
};
