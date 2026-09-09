"use strict";
// Read-only outcome arbitration for a frozen v7 transaction. Reuses UX-05's
// strict mempool and block/body identity checks; no claim or request writes.
const { getAddressUtxos, loadKaspa } = require("./chain");
const { isExactMempoolMiss, classifyMempoolEntry, locateSpendingTransaction, confirmSpendingTransactionInBlock } = require("./wallet-submit-v4");
const { transactionIdOfRpcBody, blockHashOfRpcHeader } = require("./tx-identity");
const HEX = /^[0-9a-f]{64}$/;
const same = (a, b) => a?.transactionId === b?.transactionId && Number(a?.index) === Number(b?.index);
const unknown = (reason, extra = {}) => ({ outcome: "UNKNOWN", reason, ...extra });
async function readSubmissionStartHash(rpc) {
  try { const { sink } = await rpc.getBlockDagInfo(); return typeof sink === "string" && HEX.test(sink) ? sink : null; }
  catch { return null; }
}
function isBoundRejection(error, txId) {
  let message = String(error?.message ?? error).trim();
  const remote = /^RPC Server \(remote error\) -> code:0  message:`([^`]+)` data:None$/.exec(message);
  if (remote) message = remote[1];
  return HEX.test(txId) && message.startsWith(`Rejected transaction ${txId}: `) && !/already|duplicate|known|mempool|orphan/i.test(message);
}
async function acceptanceWindow(rpc, start, txId, allowRejectedAnchorReorg = false) {
  const sink = await readSubmissionStartHash(rpc);
  if (!sink || !HEX.test(start ?? "")) return { complete: false, sink, accepted: false };
  const acceptedIds = new Set(), visited = new Set(), chainHashes = new Set();
  let cursor = start, count = 0, initialAnchorReorg = false;
  for (let hop = 0; hop < 2000 && !visited.has(cursor); hop++) {
    visited.add(cursor);
    const r = await rpc.getVirtualChainFromBlock({ startHash: cursor, includeAcceptedTransactionIds: true });
    const added = r?.addedChainBlockHashes, entries = r?.acceptedTransactionIds, removed = r?.removedChainBlockHashes;
    if (!Array.isArray(added) || !Array.isArray(entries) || added.length !== entries.length || !added.every((h) => typeof h === "string" && HEX.test(h)) || new Set(added).size !== added.length || !Array.isArray(removed) || !removed.every((h) => typeof h === "string" && HEX.test(h)) || new Set(removed).size !== removed.length) throw Error("incomplete, reorged or malformed acceptance window");
    // RPC removes the initial non-selected path back to the common ancestor.
    // Only a bound first rejection can use that replacement window: it cannot
    // prove a negative outcome for an ambiguous or previously accepted attempt.
    if (removed.length) {
      if (!allowRejectedAnchorReorg || hop !== 0 || removed[0] !== start) throw Error("unresolved acceptance-window reorganization");
      initialAnchorReorg = true;
      for (const hash of removed) chainHashes.add(hash);
    }
    for (const hash of added) {
      if (hash === start || chainHashes.has(hash)) throw Error("overlapping acceptance-window paths");
      chainHashes.add(hash);
    }
    for (let i = 0; i < added.length; i++) {
      const e = entries[i];
      if (e?.acceptingBlockHash !== added[i] || !Array.isArray(e.acceptedTransactionIds) || !e.acceptedTransactionIds.every((id) => typeof id === "string" && HEX.test(id))) throw Error("incomplete acceptance entry");
      for (const id of e.acceptedTransactionIds) acceptedIds.add(id);
    }
    count += added.length;
    if (added.includes(sink) || !added.length && cursor === sink) return { complete: count > 0, sink, acceptedIds, accepted: acceptedIds.has(txId), blocks: count, initialAnchorReorg };
    if (!added.length) break;
    cursor = added.at(-1);
  }
  return { complete: false, sink, accepted: acceptedIds.has(txId), initialAnchorReorg };
}
async function observeSubmissionOutcome(config, rpc, request, { stalePendingMinimumMs = 120000, now = Date.now() } = {}) {
  const txId = request.txId, frozen = request.build.frozen;
  const identityOf = (body) => transactionIdOfRpcBody(config, body), headerHashOf = (header) => blockHashOfRpcHeader(config, header);
  const address = (spk) => loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
  async function outputsAbsent() {
    for (let i = 0; i < frozen.outputs.length; i++) {
      const refs = await getAddressUtxos(rpc, address(frozen.outputs[i].scriptPublicKey));
      // Even a mismatching output reported under this txid contradicts a
      // negative verdict. The positive completion path validates its bytes.
      if (refs.some((u) => u.outpoint.transactionId === txId)) return false;
    }
    return true;
  }
  async function inputs() {
    const present = [];
    for (const i of frozen.inputs) {
      const matches = (await getAddressUtxos(rpc, address(i.utxo.scriptPublicKey))).filter((u) => same(u.outpoint, i.previousOutpoint));
      if (matches.length > 1) throw Error("duplicate input observation");
      if (matches.length && (String(matches[0].amount) !== String(i.utxo.amount) || (matches[0].covenantId ?? null) !== (i.utxo.covenantId ?? null) || matches[0].scriptPublicKeyHex != null && matches[0].scriptPublicKeyHex !== i.utxo.scriptPublicKey.scriptHex)) throw Error("input observation differs from frozen funding evidence");
      present.push(matches.length === 1);
    }
    return present;
  }
  async function mempoolAbsent() {
    try {
      const entry = await rpc.getMempoolEntry({ transactionId: txId, includeOrphanPool: true, filterTransactionPool: false });
      if (classifyMempoolEntry(entry, txId, identityOf) === "PRESENT") return false;
      throw Error("malformed mempool answer");
    } catch (e) { if (isExactMempoolMiss(e, txId)) return true; throw e; }
  }
  try {
    if (!await outputsAbsent()) return { outcome: "ACCEPTED_OR_CONTRADICTORY", reason: "an output under this transaction ID was observed" };
    if (!await mempoolAbsent()) return unknown("transaction is present in the mempool");
    const first = await inputs();
    // Resolve the settlement/query race before considering a negative outcome.
    if (!await outputsAbsent()) return { outcome: "ACCEPTED_OR_CONTRADICTORY", reason: "transaction appeared during the funding queries" };
    const start = request.submitStartHash ?? request.reconcileStartHash;
    const rejectedFirstAttempt = request.submissionAttempt?.phase === "REJECTED_RESPONSE" && isBoundRejection(request.submissionAttempt.error, txId);
    const boundRejectedRequest = rejectedFirstAttempt && request.submissionAttempt.requestFingerprint === require("./wallet-requests-v7").completionReceiptPointer(request).requestFingerprint;
    const window = await acceptanceWindow(rpc, start, txId, boundRejectedRequest);
    if (window.accepted) return { outcome: "ACCEPTED_OR_CONTRADICTORY", reason: "the acceptance window includes this transaction" };
    if (window.initialAnchorReorg && !window.complete) return unknown("removed initial anchor requires complete replacement acceptance coverage");
    const at = Date.parse(request.submittedAt ?? request.outcomeObservationAt ?? "");
    const stale = Number.isFinite(at) && now - at >= stalePendingMinimumMs;
    if (!rejectedFirstAttempt && (!window.complete || !stale)) return unknown("no complete, aged negative outcome proof", { observationStartHash: start ? null : window.sink });
    const second = await inputs();
    if (!await outputsAbsent() || !await mempoolAbsent()) return unknown("transaction appeared or observations changed during arbitration");
    if (first.every(Boolean) && second.every(Boolean)) return {
      outcome: rejectedFirstAttempt ? "SUBMISSION_REJECTED" : "NOT_BROADCAST",
      proof: { txId, allInputsUnspent: true, repeatedFundingQueries: true, exactMempoolMiss: true, outputsAbsent: true, startHash: start ?? null, sink: window.sink, completeAcceptanceWindow: window.complete, rejectedFirstAttempt, initialAnchorReorg: window.initialAnchorReorg === true, at: new Date(now).toISOString() }
    };
    if (window.initialAnchorReorg) return unknown("removed initial anchor cannot establish a competing transaction outcome");
    if (!window.complete || !stale || !window.acceptedIds) return unknown("spent inputs require affirmative accepted conflict evidence");
    const scan = await locateSpendingTransaction(rpc, { lowHash: start, sinkHash: window.sink, outpoints: frozen.inputs.map((i) => i.previousOutpoint), identityOf, headerHashOf });
    if (!scan.complete) return unknown("conflict scan did not cover the acceptance window");
    if (scan.spenders.some((s) => s.txId === txId)) return unknown("the original transaction also appears in the block scan");
    for (const spender of scan.spenders) {
      if (spender.txId === txId || !window.acceptedIds.has(spender.txId)) continue;
      const i = frozen.inputs.findIndex((input) => same(input.previousOutpoint, spender.outpoint));
      if (i < 0 || first[i] || second[i]) continue;
      if (await confirmSpendingTransactionInBlock(rpc, { ...spender, expectedView: spender.blockView, identityOf, headerHashOf }) && await outputsAbsent() && await mempoolAbsent()) return {
        outcome: "SUPERSEDED", proof: { txId, acceptedConflictingTxId: spender.txId, spentOutpoint: spender.outpoint, blockHash: spender.blockHash, startHash: start, sink: window.sink, at: new Date(now).toISOString() }
      };
    }
    return unknown("no coherent accepted competing transaction was proved");
  } catch (e) { return unknown(`outcome verification unavailable or contradictory: ${e.message}`); }
}
module.exports = { readSubmissionStartHash, isBoundRejection, observeSubmissionOutcome };
