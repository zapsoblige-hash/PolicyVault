"use strict";

/*
 * RECONCILE-ONLY mode for a PolicyVault v0.6 OPTIONAL-ATOMIC-COMPOSABILITY
 * TOKEN CONTROLLER (Wave 2 Track E). Mirrors sdk/src/reconcile-v5.js /
 * reconcile-v7.js's reconcileVault: never broadcasts, never force-
 * unlocks, never overrides a stale timer, NEVER mutates a durable
 * manifest to "match reality" on a divergent or absent chain fact. This
 * is the DEFERRED / crash-recovery path — sdk/src/wallet-requests-v6.js
 * already proves the exact effect inline at submit time (short poll).
 *
 * Status: IMPLEMENTED (Wave 2 Track E). UNIT/API-TESTED by
 * sdk/test/wallet-v6-api.test.js.
 */

const { connectVerified, getAddressUtxos } = require("./chain");
const { assertOperationalNetwork } = require("./config");
const { loadTransitionClaim, releaseTransitionClaim, releaseSubmissionClaim, persistReceipt } = require("./submission-claim");
const { appendAudit } = require("./audit");
const { VaultStatus } = require("./manifest");
const { loadManifestV6, persistManifestV6, manifestToJsonV6 } = require("./manifest-v6");
const { resolveV6Abi, normalizeStateV6, controllerValueV6 } = require("./vault-state-v6");
const { SPEND_ACTIONS, SWAP_ACTIONS } = require("./vault-builders-v6");

const DEFAULT_STALE_PENDING_MINIMUM_MS = 120_000;

function fail(message, code) {
  const e = new Error(`reconcile-v6: ${message}`);
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

async function reconcileVaultV6(config, rpc, vaultId, { stalePendingMinimumMs, allowClaimRelease }) {
  const manifest = await loadManifestV6(config, vaultId);
  if (!manifest) return { status: "NOT_FOUND", vaultId };
  if (!manifest.live) return { status: "TERMINAL", vaultId, vaultStatus: manifest.status };
  resolveV6Abi(manifest.contractVersion);

  const { compileExactStateV6 } = require("./contract-compiler-v6");
  const { stateToJsonV6 } = require("./vault-state-v6");
  const { covenantAddress } = require("./chain");
  const compiled = compileExactStateV6({ config, template: manifest.template, state: stateToJsonV6(manifest.live.state), contractVersion: manifest.contractVersion });
  if (compiled.scriptSha256 !== manifest.live.scriptSha256) fail("compiled current controller state does not match the manifest script hash — failing closed");
  const address = covenantAddress(config, Buffer.from(compiled.scriptHex, "hex"));

  const liveRef = await findOutpoint(rpc, address, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
  const claim = await loadTransitionClaim(config, manifest.live.outpoint);

  if (liveRef) {
    if (!claim) return { status: "CONSISTENT", vaultId };
    const ageMs = Date.now() - Date.parse(claim.createdAt ?? 0);
    if (!allowClaimRelease || !(ageMs >= stalePendingMinimumMs)) return { status: "CLAIM_PENDING", vaultId, claimTxId: claim.txId, ageMs };
    const stillLive = await findOutpoint(rpc, address, manifest.live.outpoint.transactionId, manifest.live.outpoint.index);
    if (!stillLive) return { status: "CLAIM_PENDING", vaultId, reason: "state changed during release check" };
    await releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
    await releaseSubmissionClaim(config, claim.txId);
    await appendAudit(config, { vaultId, action: "stale_claim_released", actor: "system", txId: claim.txId, result: "RELEASED" });
    return { status: "CLAIM_RELEASED", vaultId, claimTxId: claim.txId };
  }

  if (claim && claim.expected && claim.expected.kind === "v6Successor") {
    const wr6 = require("./wallet-requests-v6");
    const request = await wr6.loadWalletRequestV6(config, claim.expected.requestId ?? "").catch(() => null);
    const outputs = request && request.finalTransaction ? request.finalTransaction.outputs : null;
    if (outputs) {
      const terminal = request.action === "ownerRecover";
      if (terminal) {
        await persistManifestV6(config, { ...manifestToJsonV6(manifest), status: VaultStatus.RECOVERED, live: null, latestTransitionTxId: claim.txId });
        await releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
        await releaseSubmissionClaim(config, claim.txId);
        await persistReceipt(config, { txId: claim.txId, vaultId, action: claim.action, proof: { recovered: true, reconciled: true } });
        await appendAudit(config, { vaultId, action: claim.action, actor: "system", txId: claim.txId, result: "CHAIN_VERIFIED", via: "reconcile" });
        return { status: "ADVANCED", vaultId, txId: claim.txId };
      }
      const idx = outputs.findIndex((o) => o.covenant && o.covenant.covenantId === manifest.live.covenantId);
      if (idx >= 0) {
        const succAddress = spkToAddress(config, outputs[idx].scriptPublicKey);
        const ref = await findOutpoint(rpc, succAddress, claim.txId, idx);
        if (ref && ref.amount.toString() === String(outputs[idx].value)) {
          const isSpend = SPEND_ACTIONS.has(request.action);
          const isSwap = SWAP_ACTIONS.has(request.action);
          const currentJson = manifestToJsonV6(manifest);
          const newTokenPosition = isSpend || isSwap
            ? { outpoint: { transactionId: claim.txId, index: 1 }, value: outputs[1].value.toString(), scriptPublicKeyHex: outputs[1].scriptPublicKey.scriptHex, covenantId: outputs[1].covenant.covenantId, state: { ownerIdentifier: manifest.live.covenantId, identifierType: 2, amount: request.build.accounting.token.positionAfter, isMinter: false } }
            : currentJson.live.tokenPosition;
          const advancedRegistry = isSpend || isSwap ? require("./wallet-requests-v6").advanceRegistryV6(currentJson.agentRegistry, request.build) : currentJson.agentRegistry;
          await persistManifestV6(config, {
            ...currentJson,
            agentRegistry: advancedRegistry,
            live: { state: request.build.successorState, outpoint: { transactionId: claim.txId, index: idx }, outpointValue: controllerValueV6(normalizeStateV6(request.build.successorState)).toString(), scriptSha256: request.build.successorScriptSha256, covenantId: manifest.live.covenantId, tokenPosition: newTokenPosition },
            latestTransitionTxId: claim.txId
          });
          await releaseTransitionClaim(config, { outpoint: manifest.live.outpoint, txId: claim.txId });
          await releaseSubmissionClaim(config, claim.txId);
          await persistReceipt(config, { txId: claim.txId, vaultId, action: claim.action, proof: { successorOutpoint: `${claim.txId}:${idx}`, reconciled: true } });
          await appendAudit(config, { vaultId, action: claim.action, actor: "system", txId: claim.txId, result: "CHAIN_VERIFIED", via: "reconcile" });
          return { status: "ADVANCED", vaultId, txId: claim.txId };
        }
      }
    }
  }

  return { status: "UNKNOWN", vaultId, reason: claim ? "claim present but expected effect not proven" : "live outpoint gone, no claim" };
}

async function reconcileV6(config, vaultId, { rpc: providedRpc, stalePendingMinimumMs = DEFAULT_STALE_PENDING_MINIMUM_MS, allowClaimRelease = true } = {}) {
  assertOperationalNetwork(config);
  const owned = !providedRpc;
  const { rpc } = owned ? await connectVerified(config) : { rpc: providedRpc };
  try {
    return await reconcileVaultV6(config, rpc, vaultId, { stalePendingMinimumMs, allowClaimRelease });
  } finally {
    if (owned) await rpc.disconnect();
  }
}

module.exports = { reconcileV6, reconcileVaultV6, DEFAULT_STALE_PENDING_MINIMUM_MS };
