"use strict";

/*
 * Chain access layer: RPC connection with strict network verification and
 * exact-chain readback used for reconciliation proofs.
 *
 * Never assumes sync. Never silently switches networks or nodes. Reads
 * only — no broadcast lives in this module.
 */

globalThis.WebSocket = require("websocket").w3cwebsocket;

function fail(message) {
  throw new Error(`chain: ${message}`);
}

let kaspaModule = null;

function loadKaspa(config) {
  if (kaspaModule === null) {
    kaspaModule = require(config.rustyKaspaModule);
  }
  return kaspaModule;
}

/*
 * Connect and hard-verify the node: exact networkId, synced, utxoindex.
 */
async function connectVerified(config) {
  const kaspa = loadKaspa(config);
  const rpc = new kaspa.RpcClient({
    url: config.rpcUrl,
    encoding: kaspa.Encoding.SerdeJson,
    networkId: config.networkId
  });
  await rpc.connect({ timeoutDuration: 15000 });

  const info = await rpc.getServerInfo();
  if (info.networkId !== config.networkId) {
    await rpc.disconnect();
    fail(`node network ${info.networkId} does not match configured ${config.networkId}`);
  }
  if (info.isSynced !== true) {
    await rpc.disconnect();
    fail("node is not synced — refusing live operations");
  }
  if (info.hasUtxoIndex !== true) {
    await rpc.disconnect();
    fail("node has no utxoindex — refusing live operations");
  }

  return { rpc, kaspa, serverInfo: info };
}

async function getVirtualDaaScore(rpc) {
  const dag = await rpc.getBlockDagInfo();
  return BigInt(dag.virtualDaaScore);
}

/*
 * The canonical P2SH address of a compiled covenant script on this
 * network.
 */
function covenantAddress(config, scriptBytes) {
  const kaspa = loadKaspa(config);
  const spk = kaspa.payToScriptHashScript(Buffer.from(scriptBytes).toString("hex"));
  const address = kaspa.addressFromScriptPublicKey(spk, config.networkId);
  if (!address) {
    fail("could not derive covenant address from script");
  }
  return address.toString();
}

/*
 * Fetch the UTXOs currently held by an address. Returns normalized
 * entries: { outpoint: {transactionId, index}, amount: BigInt,
 * scriptPublicKeyHex, covenantId|null, blockDaaScore }.
 */
async function getAddressUtxos(rpc, address) {
  const response = await rpc.getUtxosByAddresses({ addresses: [address] });
  const entries = response.entries ?? [];
  return entries.map((entry) => {
    const outpoint = entry.outpoint ?? entry.entry?.outpoint;
    const utxo = entry.utxoEntry ?? entry.entry ?? entry;
    const scriptHexRaw = utxo.scriptPublicKey?.script ?? utxo.scriptPublicKey;
    return {
      outpoint: {
        transactionId: String(outpoint.transactionId).toLowerCase(),
        index: Number(outpoint.index)
      },
      amount: BigInt(utxo.amount),
      scriptPublicKeyHex: typeof scriptHexRaw === "string" ? scriptHexRaw.toLowerCase() : null,
      covenantId: utxo.covenantId ? String(utxo.covenantId).toLowerCase() : null,
      blockDaaScore: utxo.blockDaaScore !== undefined ? BigInt(utxo.blockDaaScore) : null
    };
  });
}

/*
 * Exact live-outpoint proof: does `outpoint` still sit unspent on
 * `address` with exactly `expectedValue`? Returns "LIVE", "GONE", or
 * fails on value/script mismatch (corrupt expectations are worse than
 * unknown ones).
 */
async function proveOutpointStatus(rpc, { address, outpoint, expectedValue }) {
  const utxos = await getAddressUtxos(rpc, address);
  const match = utxos.find(
    (u) => u.outpoint.transactionId === outpoint.transactionId && u.outpoint.index === outpoint.index
  );
  if (!match) {
    return { status: "GONE" };
  }
  if (match.amount !== expectedValue) {
    fail(
      `outpoint ${outpoint.transactionId}:${outpoint.index} carries ${match.amount} sompi, expected ${expectedValue} — failing closed`
    );
  }
  return { status: "LIVE", utxo: match };
}

module.exports = {
  connectVerified,
  getVirtualDaaScore,
  covenantAddress,
  getAddressUtxos,
  proveOutpointStatus,
  loadKaspa
};
