"use strict";

/*
 * The adapters' ONLY doorway into PolicyVault: the packaged SDK HTTP
 * client (`sdk/src/http-client.js`, transport-only by its own contract),
 * authenticated with a scoped MACHINE credential. The adapter process has
 * no in-process handle to buildV4Transaction, the store, the signer, or
 * the node — it is a scoped API client and nothing else, which is what
 * makes the specs' §5 prohibitions structural rather than promises.
 *
 * The six-scope contract (x402 spec §4.2 == ap2 spec §4.2): the machine
 * credential the operator mints for an adapter carries EXACTLY
 *   read:network, read:vaults, read:requests, read:manifests,
 *   request:build, request:submit
 * — and nothing else. This module exports the list so conformance tests
 * and provisioning tooling share one constant; it cannot mint or widen a
 * credential itself (/identities* is wallet-session-only, structurally).
 *
 * Network verification (CLAUDE.md network safety), two checkpoints:
 *  - verifyServerNetwork(): GET /capabilities — the Agent API's reported
 *    networkId (live-config truth, no node dial) must equal the adapter's
 *    configured network. Checked before ANY per-attempt pipeline call.
 *  - verifyLiveNetwork(): GET /network/status — networkId + isSynced +
 *    hasUtxoIndex from the real node. REQUIRED before the submit stage
 *    (the one live operation the adapter performs). Never assume sync.
 * Both fail closed on mismatch or unavailability.
 */

const { PolicyVaultClient, PolicyVaultApiError, PolicyVaultNetworkError } = require("../../sdk/src/http-client");

const ADAPTER_SCOPES = Object.freeze([
  "read:network",
  "read:vaults",
  "read:requests",
  "read:manifests",
  "request:build",
  "request:submit"
]);

class NetworkGateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "NetworkGateError";
    this.code = code;
  }
}

function createPolicyVaultClient({ baseUrl, token }) {
  if (typeof token !== "string" || !token) {
    throw new Error("createPolicyVaultClient: a machine credential is required (pass the pvmk_ token via the configured environment variable — never in a config file)");
  }
  return new PolicyVaultClient({ baseUrl, token });
}

/* Agent-API-reported network (config truth) == adapter-configured network,
 * else refuse. Returns the capabilities document for feature checks. */
async function verifyServerNetwork(client, networkId) {
  let caps;
  try {
    caps = await client.capabilities();
  } catch (error) {
    throw new NetworkGateError("UPSTREAM_UNAVAILABLE", `PolicyVault capabilities unavailable — failing closed (${error.message})`);
  }
  if (!caps || caps.networkId !== networkId) {
    throw new NetworkGateError("NETWORK_MISMATCH", `Agent API reports networkId ${JSON.stringify(caps ? caps.networkId : null)} but this adapter is configured for ${JSON.stringify(networkId)} — refusing (never silently switch network)`);
  }
  return caps;
}

/* Live-node gate before the submit stage: exact networkId, synced, UTXO
 * index. submitTransaction() returning is not success and a build is not
 * a broadcast — this gate protects the ONE live operation. */
async function verifyLiveNetwork(client, networkId) {
  let status;
  try {
    status = await client.networkStatus();
  } catch (error) {
    throw new NetworkGateError("NODE_UNAVAILABLE", `node status unavailable — refusing to submit (${error.message})`);
  }
  if (!status || status.networkId !== networkId) {
    throw new NetworkGateError("NETWORK_MISMATCH", `node reports networkId ${JSON.stringify(status ? status.networkId : null)}, adapter configured for ${JSON.stringify(networkId)} — refusing`);
  }
  if (status.isSynced !== true) throw new NetworkGateError("NODE_NOT_SYNCED", "node is not synced — refusing to submit (never assume sync)");
  if (status.hasUtxoIndex !== true) throw new NetworkGateError("NODE_NO_UTXO_INDEX", "node has no UTXO index — refusing to submit");
  return status;
}

module.exports = {
  ADAPTER_SCOPES,
  NetworkGateError,
  createPolicyVaultClient,
  verifyServerNetwork,
  verifyLiveNetwork,
  PolicyVaultApiError,
  PolicyVaultNetworkError
};
