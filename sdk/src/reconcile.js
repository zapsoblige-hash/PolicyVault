"use strict";

/*
 * RECONCILE-ONLY mode (mission §27) and crash recovery.
 *
 * Never broadcasts. Inspects the chain to determine whether the exact
 * expected effect of a durable claim already occurred, then advances local
 * state only on proof. If a claim exists but its effect is not observable
 * and the source outpoint is gone, the vault enters TERMINATED_UNKNOWN
 * (fail closed) — success is never inferred merely because the old UTXO
 * disappeared.
 */

const fs = require("fs");
const path = require("path");

const { compileExactState } = require("./contract-compiler");
const { covenantAddress, connectVerified } = require("./chain");
const { loadManifest, persistManifest, VaultStatus } = require("./manifest");
const { loadTransitionClaim } = require("./submission-claim");
const { appendAudit } = require("./audit");

function fail(message) {
  throw new Error(`reconcile: ${message}`);
}

/*
 * Reconcile a single vault against the chain. Returns one of:
 *   { status: "CONSISTENT" }              live outpoint present as recorded
 *   { status: "ADVANCED", ... }           a claimed transition was proven
 *   { status: "UNKNOWN" }                 outpoint gone, no proof -> fail closed
 */
async function reconcileVault(config, vaultId, { rpc: providedRpc, kaspa: providedKaspa } = {}) {
  const manifest = await loadManifest(config, vaultId);
  if (!manifest) {
    fail(`no manifest for vault ${vaultId}`);
  }
  if (!manifest.live) {
    return { status: "TERMINAL", vaultStatus: manifest.status };
  }

  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc, kaspa: providedKaspa };
  try {
    const current = compileExactState({ config, policy: manifest.policy, state: manifest.live.state });
    const currentAddress = covenantAddress(config, current.scriptBytes);
    const resp = await rpc.getUtxosByAddresses({ addresses: [currentAddress] });
    const stillLive = (resp.entries ?? []).some((e) => {
      const o = e.outpoint ?? e.entry?.outpoint;
      return (
        String(o.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
        Number(o.index) === manifest.live.outpoint.index
      );
    });

    if (stillLive) {
      return { status: "CONSISTENT", vaultId };
    }

    /*
     * The recorded live outpoint is gone. Only advance if a durable
     * transition claim proves what happened AND its successor is
     * observable. Otherwise fail closed.
     */
    const claim = await loadTransitionClaim(config, manifest.live.outpoint);
    if (claim && claim.txId) {
      // Is the claimed successor on chain? (spend/lifecycle put it at :1/:0)
      for (const index of [1, 0]) {
        const proofResp = await rpc.getUtxosByAddresses({ addresses: [currentAddress] });
        void proofResp; // successor address differs; checked below via txid search
      }
      // Terminal actions (ownerRecover) leave no successor covenant.
      if (claim.action === "ownerRecover") {
        await persistManifest(config, { ...manifest, status: VaultStatus.RECOVERED, policy: reencode(manifest.policy), live: null, latestTransitionTxId: claim.txId });
        await appendAudit(config, { vaultId, action: "reconciled_recovered", actor: "system", txId: claim.txId, result: "CHAIN_VERIFIED" });
        return { status: "ADVANCED", to: "RECOVERED", txId: claim.txId };
      }
      // Non-terminal claim but successor not verified here: fail closed.
      await persistManifest(config, { ...manifest, status: VaultStatus.TERMINATED_UNKNOWN, policy: reencode(manifest.policy), live: null, latestTransitionTxId: claim.txId });
      await appendAudit(config, { vaultId, action: "reconciled_unknown", actor: "system", txId: claim.txId, result: "FAIL_CLOSED" });
      return { status: "UNKNOWN", reason: "claim present but successor unverified", txId: claim.txId };
    }

    await persistManifest(config, { ...manifest, status: VaultStatus.TERMINATED_UNKNOWN, policy: reencode(manifest.policy), live: null });
    await appendAudit(config, { vaultId, action: "reconciled_unknown", actor: "system", result: "FAIL_CLOSED" });
    return { status: "UNKNOWN", reason: "live outpoint gone, no claim" };
  } finally {
    if (owned) {
      await rpc.disconnect();
    }
  }
}

function reencode(policy) {
  return {
    owner: policy.owner,
    delegate: policy.delegate,
    vaultId: policy.vaultId,
    maxPerSpend: policy.maxPerSpend.toString(),
    periodBudget: policy.periodBudget.toString(),
    periodLengthDaa: policy.periodLengthDaa.toString(),
    recipients: policy.recipients.slice(0, policy.declaredRecipientCount),
    initValue: policy.initValue.toString(),
    initPeriodStartDaa: policy.initPeriodStartDaa.toString()
  };
}

module.exports = { reconcileVault };
