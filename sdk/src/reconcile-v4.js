"use strict";

/*
 * RECONCILE-ONLY mode for PolicyVault v0.4 vaults (Checkpoint H §H6) with an
 * EXACT proof-of-effect standard. Never broadcasts. No force unlock, no
 * manual claim deletion, no request-body override of stale timers or proof
 * requirements — identical philosophy to the hardened reconcile-v2.
 *
 * Cases (H6):
 *   A  exact expected successor proven      -> advance manifest+registry
 *   B  expected terminal recovery proven    -> mark RECOVERED
 *   C  predecessor still live + definitively rejected tx (aged, effect
 *      absent, fresh re-poll) -> release claims (usable again)
 *   D  predecessor live, not yet classifiable -> CLAIM_PENDING (locked)
 *   E  predecessor gone, expected successor unprovable -> UNKNOWN
 *      (TERMINATED_UNKNOWN, fail closed — never guess)
 *   F  chain shows a successor different from the expected frozen effect ->
 *      because advancement requires the EXACT expected outpoint+value+
 *      covenantId, a divergent successor is NOT adopted; it falls through to
 *      UNKNOWN (fail closed). We never mutate the manifest to "match reality."
 *   G  node unavailable / transport failure -> the RPC error propagates;
 *      claims are kept (uncertainty never releases a claim).
 *
 * A missing predecessor is NEVER treated as success on its own.
 */

const { compileExactStateV4 } = require("./contract-compiler-v4");
const { assertOperationalNetwork } = require("./config");
const { covenantAddress, connectVerified, getAddressUtxos } = require("./chain");
const { VaultStatus } = require("./manifest");
const { loadManifestV4 } = require("./manifest-v4");
const { CONTRACT_VERSION_V4, resolveV4Abi, stateToJsonV4 } = require("./vault-state-v4");
const { loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { listVaultRequests } = require("./wallet-requests-v4");
const { proveExpectedEffectV4, advanceManifestAndRegistryV4, successorAddressAndScript } = require("./wallet-submit-v4");
const { appendAudit } = require("./audit");

const DEFAULT_STALE_PENDING_MINIMUM_MS = 120_000;

function fail(message) {
  throw new Error(`reconcile-v4: ${message}`);
}

async function findOutpoint(rpc, address, txId, index) {
  const utxos = await getAddressUtxos(rpc, address);
  return utxos.find((u) => u.outpoint.transactionId === txId && Number(u.outpoint.index) === Number(index)) ?? null;
}

/* Rebuild the claim's expected record into the exact form the proof needs
 * (the successor address is re-derived from the claim's successor state). */
function expectedFromClaim(config, manifest, claim) {
  const e = claim.expected;
  if (!e || !e.kind) return null;
  if (e.kind === "recover") {
    return { kind: "recover", txId: e.txId, index: Number(e.index), valueSompi: e.valueSompi, ownerAddress: e.ownerAddress };
  }
  if (e.kind === "successor") {
    const template = { owner: manifest.template.owner, vaultId: manifest.vaultId };
    const { address } = successorAddressAndScript(config, template, e.state, manifest.contractVersion);
    return { kind: "successor", txId: e.txId, index: Number(e.index), valueSompi: e.valueSompi, covenantId: e.covenantId, address, scriptSha256: e.scriptSha256, stateId: e.stateId };
  }
  return null;
}

/* Advance the manifest for a proven successor, deriving the successor
 * registry from the request that produced this transaction (durable). */
function advanceFromClaim(config, manifest, claim, expected) {
  const request = listVaultRequests(config, manifest.vaultId).find((r) => r.txId === claim.txId);
  if (!request) fail(`no durable request found for claimed tx ${claim.txId} — cannot reconstruct the successor registry; failing closed`);
  advanceManifestAndRegistryV4(config, manifest, request, expected);
  return request;
}

/*
 * Reconcile one v0.4 vault against chain truth. Returns a status object.
 */
async function reconcileVaultV4(config, vaultId, { rpc: providedRpc, stalePendingMinimumMs = DEFAULT_STALE_PENDING_MINIMUM_MS, allowClaimRelease = true } = {}) {
  const manifest = loadManifestV4(config, vaultId); // loader enforces registry root-equality
  if (!manifest) fail(`no v0.4 manifest for vault ${vaultId}`);
  resolveV4Abi(manifest.contractVersion); // accepts the v0.4 family; fails closed otherwise
  if (!manifest.live) return { status: "TERMINAL", vaultStatus: manifest.status };
  assertOperationalNetwork(config); // Gate R: testnet-10 or unlocked mainnet
  if (manifest.networkId !== config.networkId) fail(`manifest network ${manifest.networkId} != configured ${config.networkId} — refusing`);

  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc };
  try {
    const template = { owner: manifest.template.owner, vaultId: manifest.vaultId };
    const current = successorAddressAndScript(config, template, stateToJsonV4(manifest.live.state), manifest.contractVersion);
    if (current.scriptSha256 !== manifest.live.scriptSha256) fail("compiled current state does not match the manifest script hash — failing closed");
    const currentAddress = current.address;
    const liveRef = await findOutpoint(rpc, currentAddress, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
    const claim = loadTransitionClaim(config, manifest.live.outpoint);

    if (liveRef) {
      if (!claim) return { status: "CONSISTENT", vaultId };
      // Predecessor still live but a claim exists: crash-before-broadcast or
      // a rejected tx. Case D/C.
      const expected = expectedFromClaim(config, manifest, claim);
      const effect = expected ? await proveExpectedEffectV4(rpc, expected) : null;
      if (effect) return { status: "CLAIM_PENDING", vaultId, reason: "effect observed but predecessor still indexed" };
      const ageMs = Date.now() - Date.parse(claim.createdAt ?? 0);
      if (!allowClaimRelease || !(ageMs >= stalePendingMinimumMs)) {
        return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, ageMs };
      }
      const stillLive = await findOutpoint(rpc, currentAddress, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
      const effectNow = expected ? await proveExpectedEffectV4(rpc, expected) : null;
      if (!stillLive || effectNow) return { status: "CLAIM_PENDING", vaultId, reason: "state changed during release check" };
      releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
      releaseSubmissionClaim(config, claim.txId);
      appendAudit(config, { vaultId, action: "stale_claim_released", actor: "system", txId: claim.txId, result: "RELEASED", oldStateId: manifest.live.stateId });
      return { status: "CLAIM_RELEASED", vaultId, claimTxId: claim.txId };
    }

    // Predecessor gone. Advance ONLY on exact proof of the claimed effect.
    if (claim && claim.expected) {
      const expected = expectedFromClaim(config, manifest, claim);
      const proven = expected ? await proveExpectedEffectV4(rpc, expected) : null;
      if (proven && expected.kind === "successor") {
        advanceFromClaim(config, manifest, claim, expected);
        // idempotent claim cleanup (guarded release checks the txId)
        releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
        releaseSubmissionClaim(config, claim.txId);
        persistReceipt(config, { txId: expected.txId, vaultId, action: claim.action, proof: { successorOutpoint: `${expected.txId}:${expected.index}`, value: expected.valueSompi, reconciled: true } });
        appendAudit(config, { vaultId, action: "reconciled_advanced", actor: "system", txId: expected.txId, result: "CHAIN_VERIFIED", oldStateId: manifest.live.stateId, newStateId: expected.stateId });
        return { status: "ADVANCED", to: claim.action, txId: expected.txId, stateId: expected.stateId };
      }
      if (proven && expected.kind === "recover") {
        advanceManifestAndRegistryV4(config, manifest, listVaultRequests(config, vaultId).find((r) => r.txId === claim.txId) ?? { predecessorOutpoint: manifest.live.outpoint, predecessorStateId: manifest.live.stateId, sdkAction: "ownerRecover", action: claim.action }, expected);
        releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
        releaseSubmissionClaim(config, claim.txId);
        persistReceipt(config, { txId: expected.txId, vaultId, action: "ownerRecover", proof: { consumedOutpoint: `${manifest.live.outpoint.transactionId}:${manifest.live.outpoint.index}`, recoveredValue: expected.valueSompi, reconciled: true } });
        appendAudit(config, { vaultId, action: "reconciled_recovered", actor: "system", txId: expected.txId, result: "CHAIN_VERIFIED", oldStateId: manifest.live.stateId });
        return { status: "ADVANCED", to: "RECOVERED", txId: expected.txId };
      }
    }

    // No claim / no expected / effect unprovable (Case E, and F falls here):
    // fail closed. Do NOT mutate the manifest to match a divergent reality.
    const { persistManifestV4 } = require("./manifest-v4");
    const { manifestToJson } = require("./wallet-submit-v4");
    persistManifestV4(config, { ...manifestToJson(manifest), status: VaultStatus.TERMINATED_UNKNOWN, live: null, latestTransitionTxId: claim?.txId ?? manifest.latestTransitionTxId, lastTransition: manifest.lastTransition });
    appendAudit(config, { vaultId, action: "reconciled_unknown", actor: "system", txId: claim?.txId, result: "FAIL_CLOSED", oldStateId: manifest.live.stateId });
    return { status: "UNKNOWN", reason: claim ? "claim present but expected effect not proven (or a divergent successor exists)" : "live outpoint gone, no claim" };
  } finally {
    if (owned) await rpc.disconnect();
  }
}

module.exports = { reconcileVaultV4, DEFAULT_STALE_PENDING_MINIMUM_MS };
