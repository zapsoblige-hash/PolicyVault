"use strict";

/*
 * Network identity (spec §2.1, §7.1 step 1; OQ-F3 RESOLVED). The
 * identifier string is NEVER chain evidence: the bound network's kaspad
 * identity must be reported by the node on EVERY observation, together
 * with isSynced and hasUtxoIndex, or the request is RETRY-classed (never
 * a validity judgement).
 */

const { NETWORKS } = require("./constants");
const { refuse } = require("./codes");

/* Byte-exact lookup: no trimming, case folding, aliasing, or prefix match. */
function networkByIdentifier(identifier) {
  if (typeof identifier !== "string") return null;
  return Object.prototype.hasOwnProperty.call(NETWORKS, identifier) ? NETWORKS[identifier] : null;
}

/* Deployment binding: exactly one frozen identifier. Throws a plain Error
 * (configuration, not a request refusal). */
function bindNetwork(identifier) {
  const bound = networkByIdentifier(identifier);
  if (!bound) {
    throw new Error(
      `x402-facilitator: unknown network identifier ${JSON.stringify(identifier)} — only ${Object.keys(NETWORKS).join(", ")} are frozen for pv-x402-kaspa-exact-upfront/1 (fail closed)`
    );
  }
  return bound;
}

/* Request gate: the requirement's network must byte-equal the bound one. */
function requireBoundNetwork(bound, requested) {
  if (typeof requested !== "string" || requested !== bound.identifier) {
    refuse("NETWORK_MISMATCH", `requested ${JSON.stringify(typeof requested === "string" ? requested.slice(0, 64) : requested)}, bound ${bound.identifier}`);
  }
  return bound;
}

/*
 * Node identity gate on a getServerInfo() answer: exact kaspad networkId
 * (testnet-10 by explicit netsuffix), synced, UTXO-indexed. Every failure
 * is RETRY-classed — it says nothing about the payment.
 */
function verifyNodeIdentity(bound, serverInfo) {
  if (!serverInfo || typeof serverInfo !== "object") refuse("RPC_MALFORMED", "getServerInfo returned no object");
  if (typeof serverInfo.networkId !== "string") refuse("RPC_MALFORMED", "getServerInfo.networkId missing");
  if (serverInfo.networkId !== bound.kaspadNetworkId) {
    refuse("NODE_UNAVAILABLE", `node reports network ${JSON.stringify(serverInfo.networkId)} but this facilitator is bound to ${bound.identifier} (${bound.kaspadNetworkId}) — refusing to judge against the wrong network`);
  }
  if (serverInfo.isSynced !== true) refuse("NODE_UNSYNCED");
  if (serverInfo.hasUtxoIndex !== true) refuse("UTXO_INDEX_UNAVAILABLE");
  return Object.freeze({
    networkId: serverInfo.networkId,
    serverVersion: typeof serverInfo.serverVersion === "string" ? serverInfo.serverVersion : null,
    isSynced: true,
    hasUtxoIndex: true
  });
}

module.exports = { networkByIdentifier, bindNetwork, requireBoundNetwork, verifyNodeIdentity };
