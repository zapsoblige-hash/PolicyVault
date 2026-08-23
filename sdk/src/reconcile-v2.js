"use strict";

/*
 * RECONCILE-ONLY mode for PolicyVault v0.2 vaults (mission §27) with an
 * EXACT proof-of-effect standard.
 *
 * Never broadcasts. A missing predecessor outpoint is NEVER treated as
 * success on its own: local state advances only when the transition
 * claim's recorded expected effect is proven on chain —
 *
 *   successor transitions: the exact successor outpoint {claim.txId, index}
 *   at the exact successor covenant address, carrying the exact protected
 *   value and the exact lineage covenantId (the successor script/stateId
 *   come from the claim's expected record, written before broadcast);
 *
 *   recovery: the predecessor consumed AND the exact owner payout outpoint
 *   {claim.txId, 0} with the full protected value at the owner address.
 *
 * Anything else fails closed to TERMINATED_UNKNOWN (funds state must be
 * resolved by inspection, never guessed).
 *
 * Pending-claim handling (crash BEFORE broadcast, or node rejection): if
 * the predecessor outpoint is STILL live and the expected effect is absent,
 * the claimed transaction may or may not still be in the mempool, so the
 * claim is only released after `stalePendingMinimumMs` has passed since the
 * claim was created AND a fresh poll still shows the predecessor live and
 * the effect absent. Until then the vault reports CLAIM_PENDING and no
 * operation may reuse the outpoint.
 */

const { compileExactStateV2 } = require("./contract-compiler-v2");
const { covenantAddress, connectVerified } = require("./chain");
const { VaultStatus } = require("./manifest");
const { loadManifestV2, persistManifestV2 } = require("./manifest-v2");
const { CONTRACT_VERSION_V2 } = require("./vault-state-v2");
const { loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { appendAudit } = require("./audit");

const DEFAULT_STALE_PENDING_MINIMUM_MS = 120_000;

function fail(message) {
  throw new Error(`reconcile-v2: ${message}`);
}

async function findOutpoint(rpc, address, txId, index) {
  const resp = await rpc.getUtxosByAddresses({ addresses: [address] });
  return (
    (resp.entries ?? []).find((e) => {
      const o = e.outpoint ?? e.entry?.outpoint;
      return String(o.transactionId).toLowerCase() === txId && Number(o.index) === Number(index);
    }) ?? null
  );
}

/*
 * Reconcile one v0.2 vault. Returns one of:
 *   { status: "TERMINAL" }         manifest already terminal
 *   { status: "CONSISTENT" }       live outpoint present, no claim
 *   { status: "CLAIM_PENDING" }    outpoint live but a claim exists and is
 *                                  too fresh to release (or releases are
 *                                  disabled) — fail closed, do not retry
 *   { status: "CLAIM_RELEASED" }   stale never-confirmed claim removed;
 *                                  the vault is usable again
 *   { status: "ADVANCED", ... }    the claimed effect was proven exactly
 *   { status: "UNKNOWN" }          outpoint gone without exact proof —
 *                                  manifest fail-closed TERMINATED_UNKNOWN
 */
async function reconcileVaultV2(
  config,
  vaultId,
  { rpc: providedRpc, stalePendingMinimumMs = DEFAULT_STALE_PENDING_MINIMUM_MS, allowClaimRelease = true } = {}
) {
  const manifest = loadManifestV2(config, vaultId);
  if (!manifest) {
    fail(`no v0.2 manifest for vault ${vaultId}`);
  }
  if (manifest.contractVersion !== CONTRACT_VERSION_V2) {
    fail(`unexpected contract version ${manifest.contractVersion} — failing closed`);
  }
  if (!manifest.live) {
    return { status: "TERMINAL", vaultStatus: manifest.status };
  }

  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc };
  try {
    const current = compileExactStateV2({ config, template: manifest.template, state: manifest.live.state });
    if (current.scriptSha256 !== manifest.live.scriptSha256) {
      fail("compiled current state does not match the manifest script hash — failing closed");
    }
    const currentAddress = covenantAddress(config, current.scriptBytes);
    const liveRef = await findOutpoint(rpc, currentAddress, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
    const claim = loadTransitionClaim(config, manifest.live.outpoint);

    if (liveRef) {
      if (!claim) {
        return { status: "CONSISTENT", vaultId };
      }
      /*
       * Predecessor still live but a claim exists: crash before broadcast,
       * or the claimed transaction was rejected. Prove the expected effect
       * is absent, then release only after the minimum age (a still-pending
       * mempool transaction would confirm within seconds on testnet-10; the
       * age window makes the release deterministic and conservative).
       */
      const effect = await proveExpectedEffect(rpc, claim);
      if (effect) {
        /*
         * Effect proven while the predecessor still shows live: the UTXO
         * index is mid-update. Treat as pending; a later run advances.
         */
        return { status: "CLAIM_PENDING", vaultId, reason: "effect observed but predecessor still indexed" };
      }
      const ageMs = Date.now() - Date.parse(claim.createdAt ?? 0);
      if (!allowClaimRelease || !(ageMs >= stalePendingMinimumMs)) {
        return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, ageMs };
      }
      // Fresh re-poll immediately before release.
      const stillLive = await findOutpoint(rpc, currentAddress, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
      const effectNow = await proveExpectedEffect(rpc, claim);
      if (!stillLive || effectNow) {
        return { status: "CLAIM_PENDING", vaultId, reason: "state changed during release check" };
      }
      releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
      releaseSubmissionClaim(config, claim.txId);
      appendAudit(config, {
        vaultId,
        action: "stale_claim_released",
        actor: "system",
        txId: claim.txId,
        result: "RELEASED",
        oldStateId: manifest.live.stateId
      });
      return { status: "CLAIM_RELEASED", vaultId, claimTxId: claim.txId };
    }

    /* Predecessor gone. Advance ONLY on exact proof of the claimed effect. */
    if (claim && claim.expected) {
      const proven = await proveExpectedEffect(rpc, claim);
      if (proven && claim.expected.kind === "successor") {
        const e = claim.expected;
        persistManifestV2(config, {
          ...manifest,
          status: Number(e.state.paused) === 1 ? VaultStatus.PAUSED : VaultStatus.ACTIVE,
          template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
          live: {
            state: e.state,
            stateId: e.stateId,
            outpoint: { transactionId: e.txId, index: Number(e.index) },
            outpointValue: e.valueSompi,
            scriptSha256: e.scriptSha256,
            covenantId: e.covenantId
          },
          creationTxId: manifest.creationTxId,
          latestTransitionTxId: e.txId,
          lastTransition: {
            action: claim.action,
            txId: e.txId,
            oldStateId: manifest.live.stateId,
            newStateId: e.stateId,
            oldOutpoint: manifest.live.outpoint,
            newOutpoint: { transactionId: e.txId, index: Number(e.index) }
          }
        });
        persistReceipt(config, {
          txId: e.txId,
          vaultId,
          action: claim.action,
          proof: { successorOutpoint: `${e.txId}:${e.index}`, value: e.valueSompi, reconciled: true }
        });
        appendAudit(config, {
          vaultId,
          action: "reconciled_advanced",
          actor: "system",
          txId: e.txId,
          result: "CHAIN_VERIFIED",
          oldStateId: manifest.live.stateId,
          newStateId: e.stateId
        });
        return { status: "ADVANCED", to: claim.action, txId: e.txId, stateId: e.stateId };
      }
      if (proven && claim.expected.kind === "recover") {
        const e = claim.expected;
        persistManifestV2(config, {
          ...manifest,
          status: VaultStatus.RECOVERED,
          template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
          live: null,
          creationTxId: manifest.creationTxId,
          latestTransitionTxId: e.txId,
          lastTransition: {
            action: "ownerRecover",
            txId: e.txId,
            oldStateId: manifest.live.stateId,
            newStateId: null,
            oldOutpoint: manifest.live.outpoint,
            newOutpoint: null
          }
        });
        persistReceipt(config, {
          txId: e.txId,
          vaultId,
          action: "ownerRecover",
          proof: { consumedOutpoint: `${manifest.live.outpoint.transactionId}:${manifest.live.outpoint.index}`, recoveredValue: e.valueSompi, reconciled: true }
        });
        appendAudit(config, {
          vaultId,
          action: "reconciled_recovered",
          actor: "system",
          txId: e.txId,
          result: "CHAIN_VERIFIED",
          oldStateId: manifest.live.stateId
        });
        return { status: "ADVANCED", to: "RECOVERED", txId: e.txId };
      }
    }

    /* No claim, no expected record, or effect unproven: fail closed. */
    persistManifestV2(config, {
      ...manifest,
      status: VaultStatus.TERMINATED_UNKNOWN,
      template: { owner: manifest.template.owner, vaultId: manifest.template.vaultId },
      live: null,
      creationTxId: manifest.creationTxId,
      latestTransitionTxId: claim?.txId ?? manifest.latestTransitionTxId,
      lastTransition: manifest.lastTransition
    });
    appendAudit(config, {
      vaultId,
      action: "reconciled_unknown",
      actor: "system",
      txId: claim?.txId,
      result: "FAIL_CLOSED",
      oldStateId: manifest.live.stateId
    });
    return {
      status: "UNKNOWN",
      reason: claim ? "claim present but expected effect not proven" : "live outpoint gone, no claim"
    };
  } finally {
    if (owned) {
      await rpc.disconnect();
    }
  }
}

/*
 * Prove a claim's exact expected effect on chain. Returns the found UTXO
 * reference or null. Never treats absence of the predecessor as proof.
 */
async function proveExpectedEffect(rpc, claim) {
  const e = claim.expected;
  if (!e || !e.kind) {
    return null;
  }
  if (e.kind === "successor") {
    const ref = await findOutpoint(rpc, e.address, e.txId, e.index);
    if (!ref) {
      return null;
    }
    const utxo = ref.utxoEntry ?? ref.entry ?? ref;
    const valueOk = BigInt(utxo.amount) === BigInt(e.valueSompi);
    const covenantOk = String(utxo.covenantId).toLowerCase() === String(e.covenantId).toLowerCase();
    return valueOk && covenantOk ? ref : null;
  }
  if (e.kind === "recover") {
    const ref = await findOutpoint(rpc, e.ownerAddress, e.txId, e.index);
    if (!ref) {
      return null;
    }
    const utxo = ref.utxoEntry ?? ref.entry ?? ref;
    const valueOk = BigInt(utxo.amount) === BigInt(e.valueSompi);
    const ordinaryOk = utxo.covenantId === undefined || utxo.covenantId === null;
    return valueOk && ordinaryOk ? ref : null;
  }
  return null; // unknown effect kind: fail closed
}

module.exports = { reconcileVaultV2, proveExpectedEffect, DEFAULT_STALE_PENDING_MINIMUM_MS };
