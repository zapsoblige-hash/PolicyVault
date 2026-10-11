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
 * RC45 R1-05 (ST-02; plan R1 revision 2 C4, K1): the node's raw
 * blockDaaScore as a BigInt when it is canonical, else null. Canonical is
 * exactly one of: a non-negative bigint (the rusty-kaspa v2.0.1 WASM getter
 * encoding of the u64 field, consensus/client/src/utxo.rs:72, :188), a
 * non-negative safe integer, or a string matching /^[0-9]+$/. Anything else
 * (missing, empty, hex, signed, fractional, padded, any other type) is null.
 * Never throws. A depth judge refuses null for the entries it judges and
 * never looks at the others.
 */
function canonicalDaaScore(raw) {
  if (typeof raw === "bigint") return raw >= 0n ? raw : null;
  if (typeof raw === "number") return Number.isSafeInteger(raw) && raw >= 0 ? BigInt(raw) : null;
  if (typeof raw === "string") return /^[0-9]+$/.test(raw) ? BigInt(raw) : null;
  return null;
}

/* The informational coercion (unchanged for every value BigInt accepts; null
 * when absent) that never throws: a value BigInt refuses is null instead of
 * failing the whole read, so an output nobody judges never decides an answer
 * (RC45 R1-05, RC1-12). */
function coercedDaaScore(raw) {
  if (raw === undefined) return null;
  try { return BigInt(raw); } catch { return null; }
}

/*
 * Fetch the UTXOs currently held by an address. Returns normalized
 * entries: { outpoint: {transactionId, index}, amount: BigInt,
 * scriptPublicKeyHex, scriptPublicKeyVersion|null, covenantId|null, blockDaaScore|null,
 * blockDaaScoreRaw, isCoinbase }.
 * `isCoinbase` is the node's boolean when present and null when the RPC
 * entry does not carry it (consumers that need it fail closed on null).
 * `blockDaaScoreRaw` is the node's value as answered, read only by the depth
 * judges through canonicalDaaScore (RC45 R1-05); it is never part of a
 * transaction.
 */
async function getAddressUtxos(rpc, address) {
  const response = await rpc.getUtxosByAddresses({ addresses: [address] });
  if (!response || response.error != null || !Array.isArray(response.entries)) {
    throw new Error("getUtxosByAddresses returned an error or malformed entries; observation unavailable");
  }
  const entries = response.entries;
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
      scriptPublicKeyVersion: Number.isInteger(utxo.scriptPublicKey?.version) ? utxo.scriptPublicKey.version : null,
      covenantId: utxo.covenantId ? String(utxo.covenantId).toLowerCase() : null,
      blockDaaScore: coercedDaaScore(utxo.blockDaaScore),
      blockDaaScoreRaw: utxo.blockDaaScore,
      isCoinbase: typeof utxo.isCoinbase === "boolean" ? utxo.isCoinbase : null
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

/*
 * RC45 delegate period-start rule: the network position a new or changed
 * delegate's budget period is anchored to, and the position its freshness is
 * judged against. Only a canonical virtual DAA score (canonicalDaaScore above)
 * is ever answered; a read that fails or a value that is not canonical throws
 * PERIOD_START_REQUIRED naming the cause, so a guess never anchors a start.
 * getVirtualDaaScore stays unchanged for its existing readers.
 */
function periodStartRequired(message) {
  const error = new Error(`chain: ${message}`);
  error.code = "PERIOD_START_REQUIRED";
  return error;
}

function describeDaaAnswer(raw) {
  if (typeof raw === "string") return JSON.stringify(raw.length > 40 ? `${raw.slice(0, 40)}…` : raw);
  if (typeof raw === "bigint" || typeof raw === "number" || typeof raw === "boolean") return String(raw);
  if (raw === null) return "null";
  if (raw === undefined) return "no value";
  return Array.isArray(raw) ? "an array" : `a value of type ${typeof raw}`;
}

/* The canonical virtual DAA score of an open, verified node connection. */
async function readCanonicalVirtualDaaScore(rpc) {
  let dag;
  try {
    dag = await rpc.getBlockDagInfo();
  } catch (error) {
    throw periodStartRequired(`the node's current network position (virtual DAA score) could not be read: ${error?.message ?? String(error)}`);
  }
  const raw = dag && typeof dag === "object" ? dag.virtualDaaScore : undefined;
  const score = canonicalDaaScore(raw);
  if (score === null) {
    throw periodStartRequired(`the node answered a virtual DAA score that is not a canonical non-negative integer (${describeDaaAnswer(raw)}) — refusing to anchor a delegate's budget period to it`);
  }
  return score;
}

/*
 * One read of the configured node: connectVerified (exact network, synced,
 * utxoindex), the canonical virtual DAA score, disconnect. Any connect or gate
 * failure is rethrown as PERIOD_START_REQUIRED with its message appended.
 * Callers reach this as require("./chain").readAnchorDaa at call time.
 */
async function readAnchorDaa(config) {
  let rpc;
  try {
    ({ rpc } = await connectVerified(config));
  } catch (error) {
    throw periodStartRequired(`the configured node could not be used to read the current network position: ${error?.message ?? String(error)}`);
  }
  try {
    return await readCanonicalVirtualDaaScore(rpc);
  } finally {
    await rpc.disconnect();
  }
}

module.exports = {
  connectVerified,
  getVirtualDaaScore,
  covenantAddress,
  getAddressUtxos,
  canonicalDaaScore,
  readCanonicalVirtualDaaScore,
  readAnchorDaa,
  proveOutpointStatus,
  loadKaspa
};
