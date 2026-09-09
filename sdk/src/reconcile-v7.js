"use strict";

/*
 * RECONCILE-ONLY mode for PolicyVault v0.7 ORGANIZATIONAL ROOTS + their
 * ROOTED VAULTS (docs/postlaunch/v0.7-app-surface-contract.md §2 "POST
 * /org-roots/:rootId/reconcile"). Mirrors the proven exact-proof-of-effect
 * standard of sdk/src/reconcile-v4.js: never broadcasts, never force-
 * unlocks, never overrides a stale timer, and NEVER mutates a durable
 * record to "match reality" on a divergent or absent chain fact.
 *
 * This module is the DEFERRED / crash-recovery path: sdk/src/wallet-
 * requests-v7.js already proves the exact effect inline at submit time
 * (short poll); this module is what a caller runs afterwards — after a
 * crash between broadcast and chain-proof, after an ambiguous submit
 * result (RECONCILIATION_REQUIRED), or simply as a periodic health check.
 *
 * Cases (identical taxonomy to reconcile-v4.js):
 *   A  root/vault live outpoint still on chain, no claim            -> CONSISTENT
 *   B  live outpoint on chain, a transition claim exists            -> CLAIM_PENDING
 *      (crash-before-broadcast, or the node has not yet re-indexed)
 *   C  exact attempt has a supported negative outcome (never age or
 *      a missing output alone), and its own claims are settled      -> CLAIM_RELEASED
 *   D  live outpoint GONE, a claim exists, and its EXACT expected
 *      effect IS observed                                           -> ADVANCED
 *   E  live outpoint GONE, no claim, or the expected effect cannot
 *      be proven (including a DIVERGENT successor)                  -> UNKNOWN
 *      (fail closed; the record is never guessed into a new shape)
 *   F  the node is unreachable / errors                             -> the error
 *      propagates; nothing is mutated (uncertainty never releases a claim)
 *
 * Codex checkpoint 12 (R7-02, durable completion): a LIVE root outpoint is
 * not proof that the transition which produced it finished its durable
 * records. Case A therefore first DISCOVERS unfinished work — the root's
 * pending pointer, and every rootAction request whose transaction IS the
 * live outpoint's transaction (legacy partial records with a cleared
 * pointer, BROADCAST / RECONCILIATION_REQUIRED, or a CHAIN_VERIFIED label
 * beside a stale vault) — verifies it locally, and replays the shared
 * completion for whatever is incomplete (reported as ADVANCED with a
 * `completion` list); only then is CONSISTENT reported.
 *
 * Status: IMPLEMENTED (Wave 2 Track B). UNIT/API-TESTED by
 * sdk/test/org-roots-api.test.js (mocked chain readback),
 * sdk/test/org-root-durable-completion-v7.test.js (fault injection),
 * sdk/test/hosted-pg-org-roots.test.js and
 * sdk/test/hosted-pg-durable-completion-v7.test.js.
 */

const { connectVerified, getAddressUtxos } = require("./chain");
const { assertOperationalNetwork } = require("./config");
const { loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { appendAudit } = require("./audit");
const { normalizeRootStateV7 } = require("../../core/model/vault-state-v7-root");
const { activeOwnerSlotsV7 } = require("../../core/model/owner-set-v7");
const { normalizeStateV7 } = require("../../core/model/vault-state-v7");
const { VaultStatus } = require("./manifest");
const { loadManifestV7 } = require("./manifest-v7");
const {
  loadOrgRoot,
  saveOrgRoot,
  loadOrgRootRequest,
  saveOrgRootRequest,
  listOrgRootRequests,
  RequestState
} = require("./wallet-requests-v7");
const { addressForXOnlyPubkey } = require("./address-identity");

const DEFAULT_STALE_PENDING_MINIMUM_MS = 120_000;

function fail(message, code) {
  const e = new Error(`reconcile-v7: ${message}`);
  if (code) e.code = code;
  throw e;
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

const DISCOVERABLE_STATES = new Set([RequestState.BROADCAST, RequestState.CHAIN_SEEN, RequestState.RECONCILIATION_REQUIRED, RequestState.CHAIN_VERIFIED]);

/*
 * Codex checkpoint 12 (R7-02): with the root's live outpoint OBSERVED on chain (`liveRef`), find every root action whose
 * durable records are still incomplete and replay the shared completion for it. Candidates: the root's pending pointer
 * (the incomplete-request guard) and every rootAction request whose transaction is the live outpoint's transaction in
 * a discoverable state. A candidate is replayed only when its frozen root output IS the observed outpoint (same index,
 * address and value — the chain evidence for this transition is the observation itself) and local verification says
 * something is missing. Returns the list of what was found (replayed or skipped, with reasons).
 */
async function completeDiscoveredRootActions(config, root, liveRef, rpc) {
  const wr = require("./wallet-requests-v7");
  const liveTx = String(root.live.outpoint.transactionId).toLowerCase();
  const candidates = new Map();
  if (root.pendingRequestId) {
    const pending = await loadOrgRootRequest(config, root.pendingRequestId);
    if (pending) candidates.set(pending.id, pending);
  }
  const records = await listOrgRootRequests(config, { rootCovenantId: root.rootCovenantId });
  const byTx = new Map();
  for (const q of records) {
    if (q.kind !== "rootAction" || typeof q.txId !== "string") continue;
    if (wr.neverEffective(q) || wr.sameEffectDuplicate(q, records)) continue; // a withdrawn / never-finalized / same-effect duplicate sharing the txid never hides the completed request (R8-01, R8-09)
    const tx = q.txId.toLowerCase(), prior = byTx.get(tx);
    // A second prebuilt request carrying the same transaction must not hide
    // the canonical completed request. Ambiguous legacy associations refuse.
    if (!byTx.has(tx)) byTx.set(tx, q);
    else if (await wr.hasBoundRootCompletionReceipt(config, q)) byTx.set(tx, q);
    else if (!prior || !await wr.hasBoundRootCompletionReceipt(config, prior)) byTx.set(tx, null);
  }
  // Reuse the existing scoped listing; bounded predecessor discovery also
  // finds an older partial request whose receipt is absent or misassociated.
  let cursor = liveTx;
  const seen = new Set();
  for (let i = 0; i < wr.COMPLETION_HISTORY_LIMIT && !seen.has(cursor); i++) {
    seen.add(cursor);
    const q = byTx.get(cursor);
    if (!q) break;
    if (DISCOVERABLE_STATES.has(q.state) || ["SIGNED", "SUBMISSION_REJECTED"].includes(q.state) && await wr.hasBoundRootCompletionReceipt(config, q)) candidates.set(q.id, q);
    cursor = String(q.manifest?.root?.outpoint?.transactionId ?? "").toLowerCase();
  }
  const found = [];
  for (const req of candidates.values()) {
    if (req.kind !== "rootAction" || !req.build || !req.manifest || typeof req.txId !== "string") continue; // e.g. the pending pointer names a request that is not yet submitted
    if (["SIGNED", "SUBMISSION_REJECTED"].includes(req.state) && !await wr.hasBoundRootCompletionReceipt(config, req)) continue;
    const target = wr.rootSuccessorTarget(config, req);
    const position = await wr.classifyRootRecord(config, root, req, target);
    const immediate = req.txId.toLowerCase() === liveTx && Number(target.rootOutIndex) === Number(root.live.outpoint.index) && target.rootAddress === root.live.address && String(liveRef.amount) === target.rootExpectedValue;
    const historical = position.position === "BEYOND" && String(liveRef.amount) === String(root.live.value);
    if (!immediate && !historical) {
      found.push({ requestId: req.id, txId: req.txId, replayed: false, skipped: "observed root is not this request's exact successor or a proven later transition" });
      continue;
    }
    const verified = await wr.verifyRootActionCompletion(config, req);
    if (verified.complete) continue;
    try {
      await wr.completeProvenRootAction(config, req, { rootOutIndex: target.rootOutIndex, rootAddress: target.rootAddress, rootExpectedValue: target.rootExpectedValue, rootBlockDaaScore: liveRef.blockDaaScore ? liveRef.blockDaaScore.toString() : null, vaultOutIndex: null, rpc, via: "reconcile" });
    } catch (e) {
      throw await wr.recordCompletionFailure(config, req, e);
    }
    found.push({ requestId: req.id, txId: req.txId, replayed: true, missingBefore: verified.missing });
  }
  return found;
}

/*
 * Reconcile ONE organizational root's own outpoint. Returns a status
 * object. Never advances the record on an unprovable or divergent
 * successor.
 */
async function reconcileRoot(config, rpc, rootRecord, { stalePendingMinimumMs, allowClaimRelease }) {
  let root = rootRecord;
  if (!root.live) return { status: "NO_LIVE_OUTPOINT", rootCovenantId: root.rootCovenantId };
  const liveAddress = root.live.address;
  const liveRef = await findOutpoint(rpc, liveAddress, root.live.outpoint.transactionId, root.live.outpoint.index);
  const claim = await loadTransitionClaim(config, root.live.outpoint);

  if (liveRef) {
    /* Codex checkpoint 12 (R7-02): unfinished durable work for the transition that PRODUCED this live outpoint is
     * discovered and completed first; the in-memory root is re-read afterwards (its pending pointer may have changed). */
    const completion = await completeDiscoveredRootActions(config, root, liveRef, rpc);
    if (completion.some((c) => c.replayed)) root = (await loadOrgRoot(config, root.rootCovenantId)) ?? root;
    const withCompletion = (result) => (completion.length ? { ...result, completion } : result);
    if (!claim && root.pendingRequestId) {
      const pending = await loadOrgRootRequest(config, root.pendingRequestId);
      if (pending?.submissionAttempt && pending.manifest?.root?.outpoint?.transactionId === root.live.outpoint.transactionId) {
        const result = await reconcileRootNegativeOutcome(config, rpc, root, pending, { stalePendingMinimumMs, allowClaimRelease });
        if (result) return withCompletion(result);
      }
    }
    if (!claim) {
      if (completion.some((c) => c.replayed)) return withCompletion({ status: "ADVANCED", rootCovenantId: root.rootCovenantId, txId: root.live.outpoint.transactionId, reason: "durable completion replayed for the transition that produced the live outpoint" });
      return withCompletion({ status: "CONSISTENT", rootCovenantId: root.rootCovenantId });
    }
    if (claim.expected?.kind === "orgRootRequest") {
      const request = await loadOrgRootRequest(config, claim.expected.requestId);
      const result = request ? await reconcileRootNegativeOutcome(config, rpc, root, request, { stalePendingMinimumMs, allowClaimRelease }) : null;
      if (result) return withCompletion(result);
    }
    return withCompletion({ status: "CLAIM_PENDING", rootCovenantId: root.rootCovenantId, claimTxId: claim.txId, reason: "claim outcome is unresolved; age and an unspent root alone cannot release it" });
  }

  /* live outpoint gone: advance ONLY on exact proof of the claimed effect */
  if (claim && claim.expected && claim.expected.kind === "orgRootRequest") {
    const req = await loadOrgRootRequest(config, claim.expected.requestId);
    if (req && req.txId) {
      const proven = await proveOrgRootSuccessor(config, rpc, root, req);
      if (proven) {
        /* Codex checkpoint 11 (R7-02, durable completion): the deferred path used to advance ONLY the root and then
         * release the claim against the already-replaced (successor) outpoint — the vault and its registry stayed
         * stale beside a CHAIN_VERIFIED request and the predecessor claim stayed held. It now runs the SAME ordered,
         * replayable completion the submit path runs (vault + registry first, root last, claims against the captured
         * predecessor outpoints, request CHAIN_VERIFIED only at the end). */
        if (req.kind === "rootAction" && req.build && req.manifest) {
          const wr = require("./wallet-requests-v7");
          try {
            await wr.completeProvenRootAction(config, req, { rootOutIndex: proven.index, rootAddress: proven.address, rootExpectedValue: String(proven.value), rootBlockDaaScore: proven.blockDaaScore, vaultOutIndex: null, rpc, via: "reconcile" });
          } catch (e) {
            /* Codex checkpoint 12 (R7-02): a failure mid-completion is recorded truthfully (RECONCILIATION_REQUIRED with
             * the failing step) and propagated — the next reconcile / retried submit discovers and replays the rest */
            throw await wr.recordCompletionFailure(config, req, e);
          }
          return { status: "ADVANCED", rootCovenantId: root.rootCovenantId, txId: req.txId };
        }
        /* a genesis-kind claim never reaches here (genesis has no predecessor root); any other kind fails closed */
        fail(`cannot reconcile: claim names a ${req.kind} request without a reviewable build/manifest — failing closed`, "RECONCILIATION_REQUIRED");
      }
    }
  }

  return { status: "UNKNOWN", rootCovenantId: root.rootCovenantId, reason: claim ? "claim present but the expected effect is not provable (or a divergent successor exists)" : "live outpoint gone, no claim" };
}

// Called only while public organization reconciliation holds the root queue.
// A missing successor/spent input is not itself a competing transaction.
async function reconcileRootNegativeOutcome(config, rpc, root, request, options) {
  const wr = require("./wallet-requests-v7"), { getStore, Categories } = require("./store");
  const pending = (reason) => ({ status: "CLAIM_PENDING", rootCovenantId: root.rootCovenantId, requestId: request.id, reason });
  if (!options.allowClaimRelease || request.kind !== "rootAction" || request.rootCovenantId !== root.rootCovenantId || request.state === "CHAIN_VERIFIED" || request.manifest?.root?.outpoint?.transactionId !== root.live.outpoint.transactionId || Number(request.manifest.root.outpoint.index) !== Number(root.live.outpoint.index)) return null;
  try {
    wr.assertFrozenRequestTransaction(config, request);
    const pointer = wr.completionReceiptPointer(request), saved = request.submissionOutcome;
    let outcome = saved && saved.txId === request.txId && Object.entries(pointer).every(([k, v]) => saved[k] === v) ? saved : null;
    if (!outcome && request.submissionAttempt?.phase === "PREPARING" && request.submissionAttempt.requestFingerprint === pointer.requestFingerprint) outcome = { outcome: "NOT_BROADCAST", reason: "durable root preparation never reached broadcast", proof: { attemptId: request.submissionAttempt.id } };
    if (!outcome) outcome = await require("./submission-outcome-v7").observeSubmissionOutcome(config, rpc, request, options);
    if (!["NOT_BROADCAST", "SUBMISSION_REJECTED", "SUPERSEDED"].includes(outcome?.outcome)) {
      if (outcome?.observationStartHash && !request.submitStartHash && !request.reconcileStartHash) {
        request.reconcileStartHash = outcome.observationStartHash; request.outcomeObservationAt = new Date().toISOString();
        await saveOrgRootRequest(config, request);
      }
      return pending(outcome?.reason ?? "no supported negative outcome");
    }
    const predecessors = [request.manifest.root.outpoint];
    if (request.vaultOperations?.length) predecessors.push(request.build.predecessorOutpoint);
    const claims = [];
    for (const outpoint of predecessors) {
      const claim = await loadTransitionClaim(config, outpoint);
      if (claim?.txId === request.txId && claim.expected?.requestId && claim.expected.requestId !== request.id) return pending("claim names another request");
      claims.push({ outpoint, claim });
    }
    const submission = await getStore(config).read(Categories.SUBMISSION_CLAIM, request.txId);
    if (submission && (submission.vaultId !== root.rootCovenantId || submission.action !== request.action)) return pending("submission claim belongs to another operation");
    request.submissionOutcome = { ...outcome, ...pointer, txId: request.txId };
    request.state = "RECONCILIATION_REQUIRED";
    await saveOrgRootRequest(config, request);
    for (const { outpoint, claim } of claims) if (claim?.txId === request.txId) await releaseTransitionClaim(config, { outpoint, txId: request.txId });
    if (submission) await releaseSubmissionClaim(config, request.txId);
    // Keep the pending pointer through the final request write; a failure at
    // either boundary is discoverable and retries only these local records.
    request.state = outcome.outcome;
    request.error = outcome.reason ?? outcome.outcome;
    await saveOrgRootRequest(config, request);
    const fresh = await loadOrgRoot(config, root.rootCovenantId);
    if (fresh.pendingRequestId === request.id) { fresh.pendingRequestId = null; await saveOrgRoot(config, fresh); }
    return { status: "CLAIM_RELEASED", rootCovenantId: root.rootCovenantId, requestId: request.id, outcome: outcome.outcome };
  } catch (e) { return pending(`outcome verification/settlement unavailable: ${e.message}`); }
}

/* Prove the org-root request's EXACT declared root successor on chain. */
async function proveOrgRootSuccessor(config, rpc, root, request) {
  if (!request.finalTransaction) return null;
  const isRootOnly = request.build && request.build.kind === "orgRootTransition";
  const outputs = request.finalTransaction.outputs;
  const rootOutIndex = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === root.rootCovenantId);
  if (rootOutIndex < 0) return null;
  const address = spkToAddress(config, outputs[rootOutIndex].scriptPublicKey);
  const expectedValue = outputs[rootOutIndex].value;
  const ref = await findOutpoint(rpc, address, request.txId, rootOutIndex);
  if (!ref || ref.amount.toString() !== String(expectedValue)) return null;
  void isRootOnly;
  return { txId: request.txId, index: rootOutIndex, address, value: expectedValue, blockDaaScore: ref.blockDaaScore ? ref.blockDaaScore.toString() : null };
}

/*
 * Reconcile ONE rooted vault's own outpoint (delegate spends / token
 * deposits / an owner-op that rode a root transition — any of these can
 * leave the vault side ambiguous even when the root side reconciled
 * cleanly, since they are two different UTXOs).
 */
async function reconcileVault(config, rpc, vaultId, options = {}) {
  const peek = await loadManifestV7(config, vaultId);
  if (!peek) return { status: "NOT_FOUND", vaultId };
  return require("./org-root-lock").withOrgRootLock(peek.orgRootCovenantId, () => reconcileVaultUnlocked(config, rpc, vaultId, options));
}
async function reconcileVaultUnlocked(config, rpc, vaultId, { stalePendingMinimumMs = DEFAULT_STALE_PENDING_MINIMUM_MS, allowClaimRelease = true } = {}) {
  const manifest = await loadManifestV7(config, vaultId);
  if (!manifest) return { status: "NOT_FOUND", vaultId };
  const delegate = await require("./wallet-requests-v7").reconcileDelegateRequests(config, rpc, manifest, { stalePendingMinimumMs, allowClaimRelease });
  if (delegate) return delegate;
  if (!manifest.live) return { status: "TERMINAL", vaultId, vaultStatus: manifest.status };

  const { compileExactStateV7 } = require("./contract-compiler-v7");
  const { stateToJsonV7 } = require("../../core/model/vault-state-v7");
  const { covenantAddress } = require("./chain");
  const compiled = compileExactStateV7({ config, template: manifest.template, state: stateToJsonV7(manifest.live.state), contractVersion: manifest.contractVersion });
  if (compiled.scriptSha256 !== manifest.live.scriptSha256) fail("compiled current vault state does not match the manifest script hash — failing closed");
  /* compiled.scriptHex is the RAW covenant redeem script (pre-P2SH) — wrap
   * it exactly as the builder did (p2shOf) before deriving an address;
   * spkToAddress is for an ALREADY-P2SH scriptPublicKey (e.g. a frozen
   * build's own outputs), a different shape from this compiler output. */
  const address = covenantAddress(config, Buffer.from(compiled.scriptHex, "hex"));

  const liveRef = await findOutpoint(rpc, address, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
  const claim = await loadTransitionClaim(config, manifest.live.outpoint);

  if (liveRef) {
    if (!claim) return { status: "CONSISTENT", vaultId };
    if (["orgRootRequest", "v7Successor"].includes(claim.expected?.kind)) return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, reason: "request-associated claim requires exact outcome reconciliation" };
    return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, reason: "an orphan claim requires a bound request and outcome proof; age alone cannot release it" };
  }


  return { status: "UNKNOWN", vaultId, reason: claim ? "claim present but expected effect not proven" : "live outpoint gone, no claim" };
}

/*
 * Reconcile ONE organizational root AND every rooted vault it lists
 * (docs/postlaunch/v0.7-app-surface-contract.md §2, POST
 * /org-roots/:rootId/reconcile: "exact readback of the root outpoint (and
 * each linked rooted vault)").
 */
async function reconcileOrgRootV7(config, rootCovenantId, options = {}) {
  return require("./org-root-lock").withOrgRootLock(rootCovenantId, () => reconcileOrgRootV7Unlocked(config, rootCovenantId, options));
}
async function reconcileOrgRootV7Unlocked(config, rootCovenantId, { rpc: providedRpc, stalePendingMinimumMs = DEFAULT_STALE_PENDING_MINIMUM_MS, allowClaimRelease = true } = {}) {
  const root = await loadOrgRoot(config, rootCovenantId);
  if (!root) fail(`no organizational root ${rootCovenantId}`, "ROOT_NOT_FOUND");
  assertOperationalNetwork(config);
  if (root.networkId !== config.networkId) fail(`root network ${root.networkId} != configured ${config.networkId} — refusing`);

  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc };
  try {
    // A later delegate/deposit may have advanced a vault before its final
    // request write. Repair that dependency before verifying older root
    // history. Keep the post-root pass: a later partial owner operation can
    // itself be the prerequisite for wallet-request recovery.
    const pre = new Map();
    for (const vaultId of root.vaults ?? []) {
      const vault = await loadManifestV7(config, vaultId);
      if (vault?.contractVersion === "policyvault-0.7-payment") pre.set(vaultId, await require("./wallet-requests-v7").reconcileDelegateRequests(config, rpc, vault, { stalePendingMinimumMs, allowClaimRelease }));
    }
    let rootResult, rootError;
    try { rootResult = await reconcileRoot(config, rpc, await loadOrgRoot(config, rootCovenantId), { stalePendingMinimumMs, allowClaimRelease }); }
    catch (e) { rootError = e; }
    const vaultResults = [];
    const freshRoot = (await loadOrgRoot(config, rootCovenantId)) ?? root;
    for (const vaultId of freshRoot.vaults ?? []) {
      const result = await reconcileVaultUnlocked(config, rpc, vaultId, { stalePendingMinimumMs, allowClaimRelease });
      vaultResults.push(result.status === "CONSISTENT" && ["ADVANCED", "CLAIM_RELEASED"].includes(pre.get(vaultId)?.status) ? pre.get(vaultId) : result);
    }
    if (rootError) {
      if (!vaultResults.some((v) => v.status === "ADVANCED")) throw rootError;
      rootResult = await reconcileRoot(config, rpc, await loadOrgRoot(config, rootCovenantId), { stalePendingMinimumMs, allowClaimRelease });
    }
    return { root: rootResult, vaults: vaultResults };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

module.exports = { reconcileOrgRootV7, reconcileVault, DEFAULT_STALE_PENDING_MINIMUM_MS };
