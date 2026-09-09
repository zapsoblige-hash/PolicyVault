"use strict";
const path = require("path");
const fs = require("fs");

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

const { createHash } = require("node:crypto");
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
const { releaseReservationForRequest } = require("./budget-reservation");
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
  const request = await loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.schema !== "policyvault-wallet-request/v4") throw fail("not a v0.4 request", "BUILD_FAILED");
  if (request.state !== RequestState.PREFLIGHT_VERIFIED) throw fail(`request ${requestId} is ${request.state}, not PREFLIGHT_VERIFIED`, request.state);
  if (request.kind === "genesis") throw fail("use submitCreateWalletRequestV4 for genesis", "BUILD_FAILED");

  const manifest = await loadManifestV4(config, request.vaultId); // loader enforces registry root-equality
  if (!manifest || !manifest.live || manifest.live.stateId !== request.predecessorStateId) {
    request.state = RequestState.STALE;
    await saveRequest(config, request);
    await releaseReservationForRequest(config, request); // surface 15: a stale request frees its budget headroom
    throw fail("vault advanced since this request was built — rebuild required", "STALE");
  }
  requireOperationalNetwork(config, request, manifest);

  // The transition claim must be held by THIS request+txid (created at G finalize).
  const claim = await loadTransitionClaim(config, request.predecessorOutpoint);
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
      await saveRequest(config, request);
      await releaseReservationForRequest(config, request); // surface 15
      throw fail("manifest live outpoint not on chain — reconcile first", "STALE");
    }

    const transaction = finalTxToWasm(config, request.finalTransaction);
    const computedTxId = transaction.finalize().toString().toLowerCase();
    if (computedTxId !== request.txId) {
      throw fail(`reconstructed txid ${computedTxId} != frozen txid ${request.txId} — refusing to broadcast`, "TXID_MISMATCH");
    }

    // Submission claim keyed by the exact txid (idempotent).
    await claimSubmission(config, { txId: request.txId, vaultId: request.vaultId, action: request.action });

    // Persist SUBMITTING BEFORE the node call.
    request.state = RequestState.SUBMITTING;
    await saveRequest(config, request);
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
          await releaseTransitionClaim(config, { outpoint: request.predecessorOutpoint, txId: request.txId });
          await releaseSubmissionClaim(config, request.txId);
          await appendAudit(config, { vaultId: request.vaultId, action: "submission_rejected_claims_released", actor: "system", txId: request.txId, result: "REJECTED_BY_NODE", oldStateId: request.predecessorStateId, detail: message });
          request.state = "SUBMISSION_REJECTED";
          await saveRequest(config, request);
          await releaseReservationForRequest(config, request); // surface 15: mirrors the claim release (definitive rejection only)
          throw fail(`node rejected the transaction: ${message}`, "SUBMISSION_REJECTED");
        }
      }
      request.state = "RECONCILIATION_REQUIRED";
      await saveRequest(config, request);
      throw fail(`submit failed: ${message} — claims kept, reconcile required`, "RECONCILIATION_REQUIRED");
    }

    const returnedTxId = String(submitted.transactionId ?? submitted).toLowerCase();
    if (returnedTxId !== request.txId) {
      // Node acknowledged SOMETHING — ambiguous. Keep claims.
      request.state = "RECONCILIATION_REQUIRED";
      request.error = `node returned ${returnedTxId}, expected ${request.txId}`;
      await saveRequest(config, request);
      throw fail(request.error + " — reconcile required", "RECONCILIATION_REQUIRED");
    }

    request.state = RequestState.SUBMITTED;
    await saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTED"); // crash-after-broadcast (ambiguity)

    // Exact chain proof.
    let proof = null;
    for (let i = 0; i < pollAttempts && !proof; i++) {
      proof = await proveExpectedEffectV4(rpc, expected);
      if (!proof) await new Promise((r) => setTimeout(r, pollDelayMs));
    }
    if (!proof) {
      request.state = "RECONCILIATION_REQUIRED";
      await saveRequest(config, request);
      throw fail(`submitted ${request.txId} but exact effect not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    maybeCrash(config, "AFTER_PROOF"); // crash after accept, before advance

    await advanceManifestAndRegistryV4(config, manifest, request, expected);
    request.state = RequestState.CHAIN_VERIFIED;
    await saveRequest(config, request);
    // Surface 15: the manifest advanced — this spend's period accounting now
    // lives in the durable registry (periodSpent), so the reservation record
    // is complete and removed (the admission sweep would reclaim it anyway:
    // its predecessorStateId no longer matches the live state).
    await releaseReservationForRequest(config, request);
    maybeCrash(config, "AFTER_ADVANCE"); // crash after advance, before claim release

    await persistReceipt(config, {
      txId: request.txId,
      vaultId: request.vaultId,
      action: request.action,
      proof: { requestId, successorOutpoint: terminal ? null : `${request.txId}:${expected.index}`, value: expected.valueSompi, requiredFeeSompi: request.build.accounting.fee, actualFeeSompi: request.build.accounting.fee }
    });
    await appendAudit(config, { vaultId: request.vaultId, action: request.action, actor: request.signerRole, contractVersion: request.contractVersion, txId: request.txId, result: "CHAIN_VERIFIED", feeSompi: request.build.accounting.fee, oldStateId: request.predecessorStateId, newStateId: terminal ? null : request.successorStateId, via: "wallet" });

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
async function advanceManifestAndRegistryV4(config, manifest, request, expected) {
  if (expected.kind === "recover") {
    await persistManifestV4(config, {
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
  const advanced = await persistManifestV4(config, {
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
  const reloaded = await loadManifestV4(config, manifest.vaultId);
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
  const request = await loadRequest(config, requestId);
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
    await saveRequest(config, request);
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
      await saveRequest(config, request);
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

    await claimSubmission(config, { txId, vaultId: request.vaultId, action: "createVault" });
    request.state = RequestState.SUBMITTING;
    request.txId = txId;
    request.submittedAt = new Date().toISOString(); // UX-05: the durable submission clock for reconciliation
    // rc19 review R4-03: the selected-chain block the DAG stood at BEFORE the
    // broadcast — the start of the accepted-transaction window reconciliation
    // scans to PROVE this genesis was (or was never) accepted. Recorded before
    // the node call; a failure to read it leaves the field absent (then a
    // conflicted creation can only stay unresolved, never SUPERSEDED).
    try { const dag = await rpc.getBlockDagInfo(); request.submitStartHash = dag && dag.sink ? String(dag.sink).toLowerCase() : null; } catch { request.submitStartHash = null; }
    await saveRequest(config, request);
    maybeCrash(config, "AFTER_SUBMITTING");

    // The vault covenant address (for the exact proof).
    const { vaultAddress, vaultValue } = genesisTargetV4(config, request);

    let submitted;
    try {
      maybeInjectSubmitError(config, txId);
      submitted = await rpc.submitTransaction({ transaction, allowOrphan: false });
    } catch (e) {
      const message = String(e.message ?? e).split("\n")[0];
      request.error = message;
      if (isDefinitiveSubmitRejection(message)) {
        await releaseSubmissionClaim(config, txId); // genesis has no transition claim
        request.state = "SUBMISSION_REJECTED";
        await saveRequest(config, request);
        throw fail(`node rejected genesis: ${message}`, "SUBMISSION_REJECTED");
      }
      request.state = "RECONCILIATION_REQUIRED";
      await saveRequest(config, request);
      throw fail(`genesis submit failed: ${message} — reconcile`, "RECONCILIATION_REQUIRED");
    }
    if (String(submitted.transactionId ?? submitted).toLowerCase() !== txId) {
      request.state = "RECONCILIATION_REQUIRED";
      await saveRequest(config, request);
      throw fail("node returned an unexpected genesis txid — reconcile", "RECONCILIATION_REQUIRED");
    }
    request.state = RequestState.SUBMITTED;
    await saveRequest(config, request);
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
      await saveRequest(config, request);
      throw fail(`genesis ${txId} submitted but covenant output not observed — reconcile`, "RECONCILIATION_REQUIRED");
    }
    maybeCrash(config, "AFTER_PROOF");

    await completeGenesisV4(config, request, { txId, requestId });
    return { request, txId, vaultAddress };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

/* The vault covenant address + exact output value a genesis must create. */
function genesisTargetV4(config, request) {
  const compiled = compileExactStateV4({ config, template: { owner: request.template.owner, vaultId: request.vaultId }, state: normalizeStateV4(request.initialState), contractVersion: request.contractVersion });
  const vaultAddress = covenantAddress(config, compiled.scriptBytes);
  const vaultValue = (BigInt(request.initialState.protectedValue) + BigInt(request.initialState.feeReserve)).toString();
  return { vaultAddress, vaultValue };
}

/* The PROVEN completion of a genesis: called only after the exact covenant
 * output was observed on the DAG (by the submit path or by reconciliation). */
async function completeGenesisV4(config, request, { txId, requestId }) {
  const { vaultValue } = genesisTargetV4(config, request);
  // NOW create the authoritative manifest + initial registry (proven).
  const state = normalizeStateV4(request.initialState);
  const stateId = computeStateIdV4({ networkId: config.networkId, template: { owner: request.template.owner, vaultId: request.vaultId }, state, contractVersion: request.contractVersion });
  await persistManifestV4(config, {
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
  const reloaded = await loadManifestV4(config, request.vaultId);
  if (!reloaded.live || reloaded.agentRegistryRoot !== reloaded.live.state.agentRoot) {
    throw fail("post-genesis registry reconstruction mismatch — SECURITY STOP", "REGISTRY_DRIFT");
  }
  await persistReceipt(config, { txId, vaultId: request.vaultId, action: "createVault", proof: { requestId, outpoint: `${txId}:${request.vaultOutputIndex}`, covenantId: request.covenantId } });
  await appendAudit(config, { vaultId: request.vaultId, action: "vault_created", actor: "owner", contractVersion: request.contractVersion, txId, result: "CHAIN_VERIFIED", newStateId: stateId, via: "wallet" });
  request.state = RequestState.CHAIN_VERIFIED;
  await saveRequest(config, request);
  return request;
}

/*
 * UX-05 (Codex checkpoint 2): RECONCILE a genesis request whose submit
 * outcome is uncertain (SUBMITTING / SUBMITTED / RECONCILIATION_REQUIRED —
 * e.g. the HTTP response was lost after broadcast, the process crashed, or
 * the covenant output was not observed within the poll window). Outcomes:
 *   CHAIN_VERIFIED  — the exact covenant output IS on the DAG: completed
 *                     exactly as a successful submit (manifest, receipt, audit)
 *   NOT_BROADCAST   — proven not to have happened: every funding input is
 *                     still unspent, the transaction is not in the mempool,
 *                     and the submission is older than stalePendingMinimumMs;
 *                     the submission claim is released and the request closed
 *   PENDING         — anything else (fail closed: still unresolved; the
 *                     caller must NOT build a replacement)
 * A successful HTTP response, a status GET or the absence of a confirmation
 * never resolves a genesis — only this proof does.
 */
const UNRESOLVED_GENESIS_STATES = Object.freeze([RequestState.SUBMITTING, RequestState.SUBMITTED, "RECONCILIATION_REQUIRED"]);
const { transactionIdOfRpcBody, blockHashOfRpcHeader } = require("./tx-identity"); // Codex checkpoint 7 (UX-05): engine-recomputed identities for reconciliation evidence

/* Codex checkpoint 6 (UX-05) — response-shape and error-envelope discipline for the genesis reconciliation. */
const SPEND_SCAN_MAX_BATCHES = 1200; // getBlocks answers <= mergeset_size_limit + 1 blocks per call; ~300k blocks (hours at 10 BPS) before the scan gives up as UNCERTAIN
/* The node's exact miss for THIS transaction: rusty-kaspa RpcError::TransactionNotFound, bare or inside the WASM client's
 * remote-error envelope (probed on the live testnet-10 node 2026-09-05: two spaces before `message:`, backticks, `data:None`). */
function mempoolMissEnvelopes(txId) {
  return [`Transaction ${txId} not found`, `RPC Server (remote error) -> code:0  message:\`Transaction ${txId} not found\` data:None`];
}
function isExactMempoolMiss(err, txId) {
  const msg = String(err && err.message !== undefined ? err.message : err).trim().toLowerCase();
  return mempoolMissEnvelopes(String(txId).toLowerCase()).some((s) => s.toLowerCase() === msg);
}
/* PRESENT only for a well-formed entry whose transaction BODY recomputes (engine consensus id) to THIS transaction's id.
 * Codex checkpoint 7 (UX-05): an entry that merely carries a transaction object — or one that names this id without a body
 * that hashes to it — establishes nothing and is MALFORMED (an UNKNOWN answer: the claim is kept, nothing is displayed as
 * "in the mempool"). `identityOf(body)` is the engine recomputation (sdk/src/tx-identity transactionIdOfRpcBody). */
function classifyMempoolEntry(res, txId, identityOf) {
  if (typeof identityOf !== "function") throw fail("classifyMempoolEntry requires the engine identity function", "BUILD_FAILED");
  const entry = res && typeof res === "object" && !Array.isArray(res) ? (res.entry !== undefined ? res.entry : res.mempoolEntry) : null;
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return "MALFORMED";
  const tx = entry.transaction;
  if (!tx || typeof tx !== "object" || Array.isArray(tx)) return "MALFORMED";
  let id = null;
  try { id = identityOf(tx).transactionId; } catch { return "MALFORMED"; }
  if (typeof id !== "string" || id.toLowerCase() !== String(txId).toLowerCase()) return "MALFORMED";
  const declared = tx.verboseData && typeof tx.verboseData === "object" && tx.verboseData.transactionId !== undefined && tx.verboseData.transactionId !== null ? String(tx.verboseData.transactionId).toLowerCase() : null;
  if (declared !== null && declared !== id) return "MALFORMED"; // a label that disagrees with the body is an incoherent answer
  return "PRESENT";
}
/*
 * Codex checkpoint 8 (UX-05): ONE validation for every block either query returns, applied to EVERY record. A block is
 * accepted only when it is listed under its own verbose hash, its header hashes to that hash through the engine, and
 * EVERY transaction in it is a strictly readable body (sdk/src/tx-identity transactionIdOfRpcBody — no defaults, no
 * coerced fields) whose engine id equals the id it is labelled with and whose attribution names THIS block; two
 * transactions with one id in a block are incoherent. Nothing is skipped: not the records after a match, not a block
 * seen in an earlier batch. Any violation throws, which every caller reads as UNCERTAINTY — never as proof either way.
 * Codex checkpoint 9: the result carries `view`, the block's ordered engine transaction ids as a FROZEN COPY of
 * primitive strings (never a reference into the node's answer) — the immutable identity view compared across answers.
 */
function validateRpcBlock(block, listedHash, { identityOf, headerHashOf }) {
  const bh = String(listedHash).toLowerCase();
  if (!block || typeof block !== "object" || Array.isArray(block)) throw new Error("malformed block");
  if (!block.header || typeof block.header !== "object" || Array.isArray(block.header)) throw new Error("block without a header");
  if (!block.verboseData || typeof block.verboseData !== "object" || Array.isArray(block.verboseData)) throw new Error("block without verbose data");
  if (typeof block.verboseData.hash !== "string" || block.verboseData.hash.toLowerCase() !== bh) throw new Error("block listed under a hash that is not its own");
  if (headerHashOf(block.header) !== bh) throw new Error("block header does not hash to the listed block hash");
  if (!Array.isArray(block.transactions)) throw new Error("block without a transactions array");
  const transactions = [];
  const ids = new Set();
  for (let i = 0; i < block.transactions.length; i += 1) {
    const tx = block.transactions[i];
    if (!tx || typeof tx !== "object" || Array.isArray(tx)) throw new Error(`malformed transaction ${i}`);
    const parsed = identityOf(tx); // strict: throws on any missing, coerced or out-of-domain field
    const vd = tx.verboseData;
    if (!vd || typeof vd !== "object" || Array.isArray(vd)) throw new Error(`transaction ${i} without verbose data`);
    if (typeof vd.transactionId !== "string" || vd.transactionId.toLowerCase() !== parsed.transactionId) throw new Error(`transaction ${i} body does not hash to the id it is labelled with`);
    if (typeof vd.blockHash !== "string" || vd.blockHash.toLowerCase() !== bh) throw new Error(`transaction ${i} attributed to another block`);
    if (ids.has(parsed.transactionId)) throw new Error(`transaction ${parsed.transactionId} listed twice in one block`);
    ids.add(parsed.transactionId);
    transactions.push({ txId: parsed.transactionId, previousOutpoints: parsed.previousOutpoints });
  }
  return { hash: bh, isChainBlock: block.verboseData.isChainBlock === true, transactions, view: Object.freeze(transactions.map((t) => t.txId)) };
}
const outpointKey = (po) => `${String(po.transactionId).toLowerCase()}:${Number(po.index)}`;
/*
 * Codex checkpoint 9 (UX-05): CROSS-QUERY BLOCK-CONTENT CONSISTENCY. Whole-block validation (above) checks each answer on
 * its own; it cannot see that two answers describing ONE block hash disagree. Within one reconciliation attempt, every
 * representation of a block hash that the scan (lowHash overlap, repeated blocks) or the confirming query returns must
 * agree on the block's IMMUTABLE TRANSACTION-IDENTITY VIEW: the ORDERED engine ids of ALL its transactions (count +
 * order + identity, unrelated transactions included). Order is protocol-significant — rusty-kaspa commits the
 * transactions to the header through calc_hash_merkle_root(block.transactions.iter()) (consensus/core/src/merkle.rs;
 * consensus/src/pipeline/body_processor/body_validation_in_context.rs) and the RPC conversion preserves that order
 * (rpc/core/src/convert/block.rs: transactions.iter().map(RpcTransaction::from)) — so the view is compared element by
 * element, never as a set. Verbose metadata (isChainBlock, blueScore, children, per-transaction mass / blockTime …) is
 * NOT part of the view: it may legitimately differ between answers. The baseline is taken from the FIRST validated
 * representation and is never overwritten by a later answer, so a reused or mutated RPC object cannot move it: the scan
 * keeps, per block hash, the SHA-256 fingerprint of the ordered view (fixed-width 64-hex ids concatenated —
 * unambiguous) plus its transaction count, so its state stays as small as the hash set it replaces even on a maximal
 * walk; the located spender carries the FULL frozen view of its one block for the confirming comparison. A disagreement throws CONTRADICTORY_BLOCK_EVIDENCE, which the caller reads as UNCERTAINTY (claim kept, no
 * proof persisted, the reason says the answers disagreed — never that the creation was superseded). The comparison
 * state lives only in the attempt: a fresh, fully coherent attempt may still resolve on sufficient proof. This is
 * consistency between answers of the SAME node — it adds no Merkle proof and no second node.
 */
const HEX64_RE = /^[0-9a-f]{64}$/;
function sameIdentityView(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
const identityViewSha256 = (view) => createHash("sha256").update(view.join("")).digest("hex"); // fixed-width 64-hex ids: an unambiguous fingerprint of the ordered view
function contradictoryBlockEvidence(hash, baselineCount, seenCount) {
  const e = new Error(`contradictory contents for block ${hash}: the node's answers disagree (${baselineCount} vs ${seenCount} transactions; identity or order differs)`);
  e.code = "CONTRADICTORY_BLOCK_EVIDENCE";
  e.blockHash = hash;
  e.detail = `the node's answers disagreed on the contents of block ${hash} (${baselineCount} vs ${seenCount} transactions; identity or order differs) — contradictory observations of one block are never proof either way`;
  return e;
}

/*
 * Locate EVERY transaction that spends one of `outpoints` among the blocks between `lowHash` (the block recorded at
 * submission) and `sinkHash` (the sink the acceptance walk completed at), through getBlocks. rusty-kaspa
 * (rpc/service/src/service.rs get_blocks_call; consensus/src/processes/sync/mod.rs antipast_hashes_between) answers ONE
 * bounded batch per call: the requested lowHash PREPENDED, then the consensus-ordered mergesets of the chain blocks after
 * it (every block in the sink's past that is not in lowHash's past), the sink's anticone appended once the sink is
 * reached; chain blocks are marked isChainBlock. The next batch starts from the last CHAIN block of the previous one
 * (an ancestor of the sink, so the walk covers every later block); the scan is COMPLETE only once a batch contains
 * `sinkHash`.
 *
 * Codex checkpoint 7/8 (UX-05) — evidence discipline of the scan:
 *   • no early return: every batch is validated in full (validateRpcBlock on every block, every record, repeated
 *     blocks included) and the walk continues to the sink, so a matching transaction followed by malformed data, or an
 *     unaccepted spender followed by the accepted one, can never end the scan early;
 *   • every batch must start with the lowHash it was asked for (the node prepends it) and list each hash once;
 *   • every spender's id is the engine id of its body; a label or attribution that disagrees is incoherent;
 *   • any malformed or incoherent answer throws — the caller reads that as UNCERTAINTY, never as proof either way;
 *   • Codex checkpoint 9: every repeated block (the lowHash overlap included) is compared with the frozen identity view
 *     of its first representation BEFORE it is skipped; a disagreement throws CONTRADICTORY_BLOCK_EVIDENCE.
 * Returns { complete, spenders: [{ txId, blockHash, outpoint, blockView }], batches, blocks, repeats, views } (views: hash -> { sha256, count }).
 */
async function locateSpendingTransaction(rpc, { lowHash, sinkHash, outpoints, maxBatches = SPEND_SCAN_MAX_BATCHES, identityOf, headerHashOf }) {
  if (typeof identityOf !== "function" || typeof headerHashOf !== "function") throw new Error("locateSpendingTransaction requires the engine identity and header-hash functions");
  const HEX64 = /^[0-9a-f]{64}$/i;
  const wanted = new Map(outpoints.map((o) => [outpointKey(o), { transactionId: String(o.transactionId).toLowerCase(), index: Number(o.index) }]));
  let cursor = String(lowHash).toLowerCase();
  const sink = String(sinkHash).toLowerCase();
  let batches = 0, blocks = 0, repeats = 0, complete = false;
  const views = new Map(); // block hash -> { sha256, count } of its FIRST validated representation's ordered identity view (this attempt's baseline; bounded like the hash set it replaces)
  const spenders = new Map();
  while (batches < maxBatches && !complete) {
    const res = await rpc.getBlocks({ lowHash: cursor, includeBlocks: true, includeTransactions: true });
    batches += 1;
    const hashes = res && typeof res === "object" && Array.isArray(res.blockHashes) ? res.blockHashes.map((h) => (typeof h === "string" ? h.toLowerCase() : h)) : null;
    const list = res && typeof res === "object" && Array.isArray(res.blocks) ? res.blocks : null;
    if (!hashes || !list || hashes.length !== list.length || !hashes.every((h) => typeof h === "string" && HEX64.test(h))) throw new Error("malformed getBlocks answer");
    if (hashes.length === 0 || hashes[0] !== cursor) throw new Error("getBlocks answer does not start with the requested lowHash");
    if (new Set(hashes).size !== hashes.length) throw new Error("getBlocks answer lists a block hash twice");
    const validated = list.map((b, i) => validateRpcBlock(b, hashes[i], { identityOf, headerHashOf })); // EVERY block, before anything is read from the batch
    let lastChain = null;
    for (const vb of validated) {
      if (vb.isChainBlock) lastChain = vb.hash;
      const fingerprint = identityViewSha256(vb.view);
      const baseline = views.get(vb.hash);
      if (baseline) { // a repeated block: compared with the baseline BEFORE it is skipped; the baseline is never replaced
        if (baseline.sha256 !== fingerprint || baseline.count !== vb.view.length) throw contradictoryBlockEvidence(vb.hash, baseline.count, vb.view.length);
        repeats += 1;
        continue;
      }
      views.set(vb.hash, { sha256: fingerprint, count: vb.view.length });
      blocks += 1;
      for (const t of vb.transactions) {
        const hit = t.previousOutpoints.map(outpointKey).find((k) => wanted.has(k));
        if (hit && !spenders.has(t.txId)) spenders.set(t.txId, { txId: t.txId, blockHash: vb.hash, outpoint: wanted.get(hit), blockView: vb.view }); // the view the confirming query must reproduce
      }
    }
    if (hashes.includes(sink)) { complete = true; break; }
    if (!lastChain || lastChain === cursor) break; // no progress: never read as proof
    cursor = lastChain;
  }
  return { complete, spenders: [...spenders.values()], batches, blocks, repeats, views };
}

/*
 * Codex checkpoint 7/8 (UX-05): a conflicting spend located by the scan is CONFIRMED through a second, independent
 * query before it may close anything — getBlock(blockHash) must return a block that passes the SAME whole-block
 * validation as the scan (listed hash == verbose hash == engine header hash; every transaction strictly readable,
 * labelled with its own engine id, attributed to this block, no duplicate ids — remaining records included) and must
 * contain exactly one transaction whose engine id is the located id and which spends the outpoint. A body handed over
 * under another transaction's id, or a block whose remaining records are malformed, cannot survive this. Codex
 * checkpoint 9: the confirming block must also reproduce the COMPLETE identity view the scan recorded for this block
 * (`expectedView`, REQUIRED — missing scan evidence never bypasses the comparison), unrelated transactions and order
 * included; a disagreement throws CONTRADICTORY_BLOCK_EVIDENCE. Throws on any malformed answer (uncertainty);
 * returns true / false.
 */
async function confirmSpendingTransactionInBlock(rpc, { blockHash, txId, outpoint, expectedView, identityOf, headerHashOf }) {
  if (!Array.isArray(expectedView) || expectedView.length === 0 || !expectedView.every((id) => typeof id === "string" && HEX64_RE.test(id))) throw new Error("confirmation requires the scanned block's transaction-identity view");
  const res = await rpc.getBlock({ hash: blockHash, includeTransactions: true });
  const b = res && typeof res === "object" && !Array.isArray(res) ? (res.block !== undefined ? res.block : res) : null;
  const vb = validateRpcBlock(b, blockHash, { identityOf, headerHashOf });
  if (!sameIdentityView(expectedView, vb.view)) throw contradictoryBlockEvidence(vb.hash, expectedView.length, vb.view.length); // the WHOLE view, element by element, not just the candidate
  const key = outpointKey(outpoint);
  const match = vb.transactions.find((t) => t.txId === String(txId).toLowerCase());
  return !!match && match.previousOutpoints.some((po) => outpointKey(po) === key);
}
const SUBMITTER_WINDOW_MS = 90_000; // the submit path polls up to 60 s after broadcast; never race it
/* rc26 round-7 review R7-07: reconciliations of ONE request inside one SDK
 * process are SERIALIZED (the owner's strictly-serial rule for shared mutable
 * state — submissions, reconciliation). Two concurrent sessions fed
 * contradictory node answers could otherwise persist a vault manifest beside
 * a SUPERSEDED request; the server already serializes per signer
 * (withSignerLock), the SDK now serializes per request as well. The second
 * caller runs after the first completes and re-reads the DURABLE state, so it
 * sees CHAIN_VERIFIED / SUPERSEDED instead of re-deciding on its own answers.
 * Keyed by data root + request id; nothing is cached across processes. */
const RECONCILE_IN_FLIGHT = new Map();
/* Codex checkpoint 11 (R7-07) keyed this lock by a backing-store identity (resolved real path / pg host:port:db) + the
 * request id. Codex checkpoint 12 reproduced two residual bypasses of that identity: two accepted PostgreSQL
 * configurations naming ONE database as `localhost` and `127.0.0.1` obtained different locks, and a data root under a
 * SYMLINK PARENT changed from the normalized-path fallback to its real path when the directory appeared while an
 * earlier call was still active. The queue is therefore keyed by the REQUEST ID ALONE (`reconcileLockKey`): any two
 * callers inside one process that reconcile the same request are serialized however their configurations spell the
 * store — conservative in-process serialization that guarantees the exclusion without discovering host aliases. A
 * request id is a per-store UUID, so two unrelated stores that happen to share a queue only WAIT: the waiting call
 * re-reads ITS OWN durable state (reconcileCreateWalletRequestV4Unlocked loads the request fresh) and never inherits the
 * other's decision. `reconcileLockIdentity` remains as the STABLE diagnostic identity of the store, recorded on the
 * in-flight entry: the nearest EXISTING ancestor's real path joined with the not-yet-existing remainder for JSON (so it
 * does not change when the directory appears), and a lower-cased host with every loopback alias unified for postgres.
 * Cross-process protection is neither claimed nor provided here (the server serializes per signer). */
function stableRealPath(normalized) {
  let head = normalized;
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(head);
      return tail.length ? path.join(real, ...tail) : real;
    } catch (e) {
      if (!e || (e.code !== "ENOENT" && e.code !== "ENOTDIR")) throw e;
      const parent = path.dirname(head);
      if (parent === head) return normalized;
      tail.unshift(path.basename(head));
      head = parent;
    }
  }
}
function pgHostIdentity(host) {
  const h = String(host ?? "").trim().toLowerCase().replace(/\.$/, "").replace(/^\[(.*)\]$/, "$1");
  if (h === "" || h === "localhost" || h === "::1" || h === "0:0:0:0:0:0:0:1" || h === "::ffff:127.0.0.1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return "loopback";
  return h;
}
function reconcileLockIdentity(config) {
  if (config && config.persistenceBackend === "postgres" && config.pg) return `pg://${pgHostIdentity(config.pg.host)}:${Number(config.pg.port)}/${String(config.pg.database ?? "")}`;
  const raw = config && typeof config.dataRoot === "string" ? config.dataRoot : "";
  return `json://${stableRealPath(path.resolve(raw))}`;
}
function reconcileLockKey(requestId) {
  return `request::${String(requestId)}`;
}
async function reconcileCreateWalletRequestV4(args) {
  /* Codex checkpoint 13 (R7-07/A): the exclusion key is the raw request string, so the request id must be the CANONICAL
   * store key BEFORE any lock is taken or any record is read — "./<id>" and "<dir>/../<id>" (which the JSON store
   * used to resolve to the same file) are refused here and again at the store boundary (sdk/src/store.js). */
  require("./store").assertStoreKey(args ? args.requestId : undefined);
  const key = reconcileLockKey(args ? args.requestId : "");
  const prev = RECONCILE_IN_FLIGHT.get(key);
  const prevChain = prev ? prev.chain : Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const chain = prevChain.then(() => gate, () => gate);
  const entry = { chain, store: reconcileLockIdentity(args && args.config) };
  RECONCILE_IN_FLIGHT.set(key, entry);
  try {
    await prevChain.catch(() => {});
    return await reconcileCreateWalletRequestV4Unlocked(args);
  } finally {
    release();
    if (RECONCILE_IN_FLIGHT.get(key) === entry) RECONCILE_IN_FLIGHT.delete(key);
  }
}

async function reconcileCreateWalletRequestV4Unlocked({ config, requestId, rpc: providedRpc, stalePendingMinimumMs = 120_000, now = Date.now() }) {
  const request = await loadRequest(config, requestId);
  if (!request) throw fail(`no request ${requestId}`, "BUILD_FAILED");
  if (request.kind !== "genesis" || request.schema !== "policyvault-wallet-request/v4") throw fail("not a v0.4 genesis request", "NOT_A_GENESIS");
  if (request.state === RequestState.CHAIN_VERIFIED) return { request, outcome: "CHAIN_VERIFIED", detail: "already chain-verified" };
  if (!UNRESOLVED_GENESIS_STATES.includes(request.state)) return { request, outcome: request.state, detail: `request is ${request.state}; nothing to reconcile` };
  if (!request.txId) throw fail("unresolved genesis request carries no txId", "RECONCILIATION_REQUIRED");
  // A submitter that lost only its HTTP response may still be completing this
  // request (it polls up to 60 s): do not touch a young SUBMITTING/SUBMITTED
  // record — report PENDING; the durable state is re-read on the next call.
  const submittedMsEarly = request.submittedAt ? Date.parse(request.submittedAt) : NaN;
  if ((request.state === RequestState.SUBMITTING || request.state === RequestState.SUBMITTED) && Number.isFinite(submittedMsEarly) && now - submittedMsEarly < SUBMITTER_WINDOW_MS) {
    return { request, outcome: "PENDING", detail: `submitted ${Math.round((now - submittedMsEarly) / 1000)} s ago — the submitter may still be completing it; reconcile again after ${Math.round(SUBMITTER_WINDOW_MS / 1000)} s` };
  }
  requireOperationalNetwork(config, request, null);
  const owned = !providedRpc;
  const { rpc, serverInfo } = owned ? await connectVerified(config) : { rpc: providedRpc, serverInfo: { networkId: config.networkId } };
  try {
    if (serverInfo.networkId !== config.networkId) throw fail(`node network ${serverInfo.networkId} != configured ${config.networkId}`, "NETWORK_MISMATCH");
    const { vaultAddress, vaultValue } = genesisTargetV4(config, request);
    let ref = null;
    try { ref = await findOutpoint(rpc, vaultAddress, request.txId, request.vaultOutputIndex); } catch (e) {
      if (request.state !== "RECONCILIATION_REQUIRED") { request.state = "RECONCILIATION_REQUIRED"; await saveRequest(config, request); }
      return { request, outcome: "PENDING", detail: `the covenant-output query failed (${String(e && e.message || e).slice(0, 80)}) — uncertainty preserved (no claim released)` };
    }
    if (ref && BigInt(ref.amount) === BigInt(vaultValue) && String(ref.covenantId).toLowerCase() === String(request.covenantId).toLowerCase()) {
      await completeGenesisV4(config, request, { txId: request.txId, requestId });
      return { request, outcome: "CHAIN_VERIFIED", detail: `covenant output ${request.txId}:${request.vaultOutputIndex} observed on the DAG` };
    }
    // Not observed at the reviewed outpoint. A closed outcome needs COMPLETE
    // evidence (Codex checkpoint 3, UX-05; rc19 review R4-03/R4-04): a query
    // that FAILS preserves uncertainty — it is never read as "absent".
    //   NOT_BROADCAST: every funding input provably unspent, the transaction
    //     provably absent from the mempool (the node's exact "Transaction <id>
    //     not found" answer), submission older than the stale window.
    //   SUPERSEDED: the transaction is provably NOT among the transactions the
    //     selected chain accepted since the block recorded at submission, it
    //     is absent from the mempool, no UTXO carrying this creation's covenant
    //     id exists at the vault address, a funding input is spent and the
    //     submission is stale — so another transaction consumed the input and
    //     this genesis can never be mined.
    //   ADVANCED_UNRESOLVED (state RECONCILIATION_REQUIRED, claim kept): the
    //     creation WAS accepted (or its covenant id is observed on chain) but
    //     the reviewed outpoint is no longer unspent — the vault exists and was
    //     transitioned by another path; no live state is guessed.
    //   CONFLICTED_OR_CONSUMED (state RECONCILIATION_REQUIRED, claim kept): a
    //     funding input is spent but neither proof is available.
    // (1) MEMPOOL. Codex checkpoint 6 (UX-05): a successful answer is evidence only when it is the node's well-formed
    //     entry for THIS transaction (an empty `{}` or any other shape is an UNKNOWN answer, never an absence), and the
    //     node's miss is recognised only as the COMPLETE error text — the bare rusty-kaspa RpcError::TransactionNotFound
    //     or exactly the WASM client's remote-error envelope around it (both probed on the live node) — never as a
    //     substring of some other (transport / truncated) failure. Codex checkpoint 7: PRESENT requires the entry's
    //     transaction BODY to recompute (engine) to this id — presence is established by the bytes, not by a label.
    const identityOf = (body) => transactionIdOfRpcBody(config, body);
    const headerHashOf = (header) => blockHashOfRpcHeader(config, header);
    let mempoolKnown = true, inMempool = false, mempoolMalformed = false;
    try {
      const e = await rpc.getMempoolEntry({ transactionId: request.txId, includeOrphanPool: true, filterTransactionPool: false });
      if (classifyMempoolEntry(e, request.txId, identityOf) === "PRESENT") inMempool = true; else { mempoolKnown = false; mempoolMalformed = true; }
    } catch (e) {
      if (isExactMempoolMiss(e, request.txId)) inMempool = false; else mempoolKnown = false;
    }
    // (2) FUNDING INPUTS: every input provably unspent / some input spent — or the query failed (uncertainty).
    const unsigned = JSON.parse(request.transaction.unsignedSafeJson);
    const fundingOutpoints = unsigned.inputs.map((i) => ({ transactionId: String(i.transactionId).toLowerCase(), index: Number(i.index) }));
    let utxosKnown = true, allUnspent = false, anySpent = false;
    try {
      const funderUtxos = await getAddressUtxos(rpc, request.signerAddress);
      const present = fundingOutpoints.map((i) => funderUtxos.some((u) => u.outpoint.transactionId === i.transactionId && Number(u.outpoint.index) === i.index));
      allUnspent = present.every(Boolean);
      anySpent = present.some((p) => !p);
    } catch { utxosKnown = false; }
    // (3) VAULT ADDRESS, mined evidence (a): ANY unspent output at the vault address carrying this creation's covenant id.
    //     Codex checkpoint 6 (UX-05): a FAILED lookup is UNKNOWN — it never reads as "no such output".
    let covenantKnown = true, covenantObserved = null;
    try {
      const atVault = await getAddressUtxos(rpc, vaultAddress);
      covenantObserved = atVault.find((u) => String(u.covenantId || "").toLowerCase() === String(request.covenantId).toLowerCase()) || null;
    } catch { covenantKnown = false; covenantObserved = null; }
    //     Codex checkpoint 6 (UX-09): the ORIGINAL genesis output seen on this second lookup means the creation landed
    //     between the two queries — it IS the reviewed creation, completed exactly as the first lookup would have completed
    //     it; it is never described as "already transitioned".
    if (covenantObserved && covenantObserved.outpoint.transactionId === String(request.txId).toLowerCase() && Number(covenantObserved.outpoint.index) === Number(request.vaultOutputIndex) && BigInt(covenantObserved.amount) === BigInt(vaultValue)) {
      await completeGenesisV4(config, request, { txId: request.txId, requestId });
      return { request, outcome: "CHAIN_VERIFIED", detail: `covenant output ${request.txId}:${request.vaultOutputIndex} observed on the DAG (it landed while this reconciliation was querying)` };
    }
    // (4) mined / not-mined evidence (b): the accepted-transaction ids of the selected chain since the recorded submission
    // block. rc20 review R5-02: the node answers ONE bounded batch per call (no truncation flag), so the chain is WALKED —
    // from the recorded block, then from the last chain block each batch returned — until the last returned chain block
    // is the sink read in this same session. Anything short of a completed walk with at least one chain block (an error,
    // a hop cap, no progress, a malformed shape, an empty window while the chain is stale) is UNCERTAINTY, never proof.
    // Codex checkpoint 6 (UX-05): every returned chain block must carry ITS OWN acceptance entry (the node emits exactly
    // one per added chain block, in order) — chain blocks without acceptance entries are an incomplete answer.
    let acceptanceKnown = false, accepted = false, walkSink = null;
    const acceptedIds = new Set();
    if (request.submitStartHash && /^[0-9a-f]{64}$/i.test(String(request.submitStartHash))) {
      const HEX64 = /^[0-9a-f]{64}$/i;
      try {
        const readSink = async () => { const dag = await rpc.getBlockDagInfo(); const sk = dag && typeof dag.sink === "string" && HEX64.test(dag.sink) ? dag.sink.toLowerCase() : null; if (!sk) throw new Error("sink unavailable"); return sk; };
        let sink = await readSink();
        let cursor = String(request.submitStartHash).toLowerCase();
        let chainBlocks = 0, complete = false, hops = 0;
        // rc21 review R6-05: the sink may appear INSIDE a batch, and it may advance while we walk — completion is
        // "the walk covered the sink read in this session" (inside or at the end of a batch); an incomplete walk re-reads
        // the sink and continues, up to three rounds, before giving up (uncertainty).
        for (let round = 0; round < 3 && !complete; round += 1) {
          if (round > 0) sink = await readSink();
          for (; hops < 2000 && !complete; hops += 1) {
            const vc = await rpc.getVirtualChainFromBlock({ startHash: cursor, includeAcceptedTransactionIds: true });
            const added = vc && Array.isArray(vc.addedChainBlockHashes) ? vc.addedChainBlockHashes : null;
            const entries = vc && Array.isArray(vc.acceptedTransactionIds) ? vc.acceptedTransactionIds : null;
            if (!added || !entries || !added.every((h) => typeof h === "string" && HEX64.test(h))) throw new Error("malformed virtual-chain answer");
            if (entries.length !== added.length) throw new Error("acceptance entries do not cover the returned chain blocks");
            for (let k = 0; k < added.length; k += 1) {
              const en = entries[k];
              if (!en || typeof en !== "object" || typeof en.acceptingBlockHash !== "string" || en.acceptingBlockHash.toLowerCase() !== added[k].toLowerCase() || !Array.isArray(en.acceptedTransactionIds)) throw new Error("malformed accepted-transaction entry");
              for (const t of en.acceptedTransactionIds) { if (typeof t !== "string" || !HEX64.test(t)) throw new Error("malformed accepted transaction id"); acceptedIds.add(t.toLowerCase()); }
            }
            if (added.length === 0) { if (cursor === sink) complete = true; break; }
            chainBlocks += added.length;
            const lower = added.map((h) => h.toLowerCase());
            const last = lower[lower.length - 1];
            if (lower.includes(sink)) { complete = true; break; }
            if (last === cursor) break; // no progress: refuse to read it as proof
            cursor = last;
          }
        }
        acceptanceKnown = complete && chainBlocks > 0; // a completed walk over a chain that actually advanced since submission
        walkSink = acceptanceKnown ? sink : null;
      } catch { acceptanceKnown = false; acceptedIds.clear(); walkSink = null; }
    }
    accepted = acceptanceKnown && acceptedIds.has(String(request.txId).toLowerCase()); // an incomplete walk proves nothing either way
    const submittedMs = request.submittedAt ? Date.parse(request.submittedAt) : NaN;
    const ageMs = Number.isFinite(submittedMs) ? now - submittedMs : NaN;
    const stale = Number.isFinite(ageMs) && ageMs >= stalePendingMinimumMs;
    if (accepted || covenantObserved) {
      request.chainObservation = { at: new Date(now).toISOString(), accepted, observedOutpoint: covenantObserved ? { transactionId: covenantObserved.outpoint.transactionId, index: Number(covenantObserved.outpoint.index), amount: String(covenantObserved.amount) } : null };
      if (request.state !== "RECONCILIATION_REQUIRED") request.state = "RECONCILIATION_REQUIRED";
      await saveRequest(config, request);
      return { request, outcome: "ADVANCED_UNRESOLVED", detail: `the creation transaction ${request.txId} WAS accepted by the chain${covenantObserved ? ` (a covenant output with this creation's covenant id is unspent at ${covenantObserved.outpoint.transactionId}:${covenantObserved.outpoint.index})` : ""} but its output ${request.vaultOutputIndex} is no longer unspent at the reviewed outpoint — the vault exists under the reviewed rules and has already been transitioned by another path; PolicyVault records no guessed live state and keeps this creation unresolved (no claim released)` };
    }
    if (mempoolKnown && !inMempool && utxosKnown && allUnspent && covenantKnown && stale) { // Codex checkpoint 6: EVERY query must have answered (a failed vault lookup is uncertainty even with unspent inputs)
      await releaseSubmissionClaim(config, request.txId);
      request.state = "NOT_BROADCAST";
      request.error = `genesis ${request.txId} was never observed: funding inputs unspent, not in the mempool, ${Math.round(ageMs / 1000)} s after submission`;
      await saveRequest(config, request);
      return { request, outcome: "NOT_BROADCAST", detail: request.error };
    }
    // (5) AFFIRMATIVE CONFLICTING SPEND. Codex checkpoint 6 (UX-05): missing outputs + a spent input + a NEGATIVE
    //     acceptance history never establish a competing transaction on their own (the selected-chain history lags the
    //     virtual UTXO set — rusty-kaspa consensus/src/consensus/mod.rs get_virtual_chain_from_block is computed to the
    //     sink, excluding virtual). SUPERSEDED requires the conflicting transaction itself: a transaction OTHER than this
    //     creation, ACCEPTED by the selected chain since submission, that spends one of this creation's funding inputs.
    //     It is located by scanning the blocks between the recorded submission block and the walk's sink; a scan that
    //     cannot complete, or finds nothing, leaves the creation unresolved (claim kept).
    //     Codex checkpoint 7: the scan runs to COMPLETION (no early return), binds every located spender to its body
    //     (engine-recomputed id) and every block to its header, and the accepted conflict is CONFIRMED by an independent
    //     getBlock of its block before the claim may be released. Incoherent or incomplete evidence preserves uncertainty.
    //     Codex checkpoint 9: every answer describing one block (scan repeats, the confirming query) must agree on the
    //     block's ordered transaction-identity view; a contradiction is reported as such and keeps the claim.
    let conflict = null, conflictScan = null, scanProblem = null, selfInBlock = false, unacceptedSpender = null;
    if (mempoolKnown && !inMempool && utxosKnown && anySpent && covenantKnown && !covenantObserved && acceptanceKnown && !accepted && walkSink) {
      try {
        conflictScan = await locateSpendingTransaction(rpc, { lowHash: String(request.submitStartHash).toLowerCase(), sinkHash: walkSink, outpoints: fundingOutpoints, maxBatches: SPEND_SCAN_MAX_BATCHES, identityOf, headerHashOf });
        if (conflictScan.complete) {
          const me = String(request.txId).toLowerCase();
          selfInBlock = conflictScan.spenders.some((s) => s.txId === me);
          const acceptedSpenders = conflictScan.spenders.filter((s) => s.txId !== me && acceptedIds.has(s.txId));
          unacceptedSpender = conflictScan.spenders.find((s) => s.txId !== me && !acceptedIds.has(s.txId)) || null;
          if (acceptedSpenders.length > 0) {
            const candidate = acceptedSpenders[0];
            const confirmed = await confirmSpendingTransactionInBlock(rpc, { blockHash: candidate.blockHash, txId: candidate.txId, outpoint: candidate.outpoint, expectedView: candidate.blockView, identityOf, headerHashOf });
            if (confirmed) conflict = { ...candidate, accepted: true };
            else scanProblem = `the accepted spend ${candidate.txId} located by the scan was not found in block ${candidate.blockHash} on re-query`;
          }
        }
      } catch (e) { scanProblem = e && e.code === "CONTRADICTORY_BLOCK_EVIDENCE" ? e.detail : `the block scan for the conflicting spend failed (${String(e && e.message || e).slice(0, 80)})`; conflictScan = null; conflict = null; } // checkpoint 9: a contradiction is named as such — never as absence, never as supersession
    }
    if (conflict && conflict.accepted && conflict.txId !== String(request.txId).toLowerCase() && stale) {
      await releaseSubmissionClaim(config, request.txId);
      request.state = "SUPERSEDED";
      request.chainObservation = { at: new Date(now).toISOString(), accepted: false, observedOutpoint: null, conflictingTxId: conflict.txId, conflictingBlockHash: conflict.blockHash, spentOutpoint: conflict.outpoint, conflictingBlockTxCount: conflict.blockView.length, conflictingBlockViewSha256: identityViewSha256(conflict.blockView) }; // + the ordered identity view every answer agreed on (checkpoint 9)
      request.error = `genesis ${request.txId} can never be mined: funding input ${conflict.outpoint.transactionId}:${conflict.outpoint.index} was spent by transaction ${conflict.txId} (block ${conflict.blockHash}, body re-hashed and confirmed in that block, whose contents agreed across every answer), which the selected chain accepted since submission (from ${request.submitStartHash}); this creation is not among the accepted transactions, it is not in the mempool and no output with its covenant id exists, ${Math.round(ageMs / 1000)} s after submission`;
      await saveRequest(config, request);
      return { request, outcome: "SUPERSEDED", detail: request.error };
    }
    if (request.state !== "RECONCILIATION_REQUIRED") { request.state = "RECONCILIATION_REQUIRED"; await saveRequest(config, request); }
    if (utxosKnown && anySpent && mempoolKnown && !inMempool) {
      const why = !covenantKnown ? "the covenant-output lookup failed"
        : !acceptanceKnown ? "the accepted-transaction lookup since submission is not available"
        : !stale ? "the submission is not yet stale"
        : scanProblem ? scanProblem
        : conflictScan && conflictScan.complete && selfInBlock && !unacceptedSpender ? "this creation itself is in a block but not (yet) among the accepted transactions"
        : conflictScan && conflictScan.complete && unacceptedSpender ? `a spend of a funding input (${unacceptedSpender.txId}) is in a block but is not among the accepted transactions`
        : conflictScan && conflictScan.complete ? "no accepted transaction spending a funding input was located in the blocks since submission"
        : conflictScan ? `the block scan for the conflicting spend did not complete (${conflictScan.batches} batch(es), ${conflictScan.blocks} block(s))`
        : "the block scan for the conflicting spend could not run";
      return { request, outcome: "CONFLICTED_OR_CONSUMED", detail: `a funding input of ${request.txId} is spent and the covenant output was not observed, but ${why} — PolicyVault cannot tell whether this creation or another transaction consumed it; uncertainty preserved (no claim released)` };
    }
    return { request, outcome: "PENDING", detail: !mempoolKnown ? (mempoolMalformed ? "the mempool answered in an unrecognised shape (not the node's entry for this transaction) — uncertainty preserved (no claim released)" : "the mempool query failed — uncertainty preserved (no claim released)") : !utxosKnown ? "the funding-input query failed — uncertainty preserved (no claim released)" : !covenantKnown ? "the covenant-output lookup failed — uncertainty preserved (no claim released)" : inMempool ? `genesis ${request.txId} is in the mempool — awaiting acceptance` : `genesis ${request.txId} not observed yet (${Number.isFinite(ageMs) ? Math.round(ageMs / 1000) : "?"} s since submission; stale after ${Math.round(stalePendingMinimumMs / 1000)} s)` };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

function assertGenesisImmutable(unsigned, signed) {
  const strip = (tx) => ({ version: tx.version, lockTime: tx.lockTime, subnetworkId: tx.subnetworkId, gas: tx.gas, payload: tx.payload, inputs: tx.inputs.map((i) => ({ previousOutpoint: i.previousOutpoint, sequence: i.sequence, sigOpCount: i.sigOpCount, computeBudget: i.computeBudget })), outputs: tx.outputs });
  if (JSON.stringify(strip(unsigned)) !== JSON.stringify(strip(signed))) throw fail("signed genesis mutated a consensus-visible field", "SIGNATURE_INVALID");
}

module.exports = {
  reconcileLockIdentity,
  reconcileLockKey,
  stableRealPath,
  pgHostIdentity,
  submitWalletRequestV4,
  submitCreateWalletRequestV4,
  reconcileCreateWalletRequestV4,
  genesisTargetV4,
  UNRESOLVED_GENESIS_STATES,
  locateSpendingTransaction,
  confirmSpendingTransactionInBlock,
  validateRpcBlock,
  classifyMempoolEntry,
  isExactMempoolMiss,
  SPEND_SCAN_MAX_BATCHES,
  proveExpectedEffectV4,
  advanceManifestAndRegistryV4,
  finalTxToWasm,
  successorAddressAndScript,
  isDefinitiveSubmitRejection,
  registryEntryToJson,
  manifestToJson,
  deriveSuccessorRegistry
};
