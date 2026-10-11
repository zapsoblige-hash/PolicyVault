"use strict";
// Stub RPC with engine-computed transaction and block identities. It never connects.
const { dep, fx } = require("./rc27f-fixtures");
const { transactionIdOfRpcBody, blockHashOfRpcHeader } = dep("sdk/src/tx-identity");
function seedInputs(x) {
  const addresses = new Set(x.q.build.frozen.inputs.map((i) => fx.spkAddress(x.config, i.utxo.scriptPublicKey)));
  for (const a of addresses) x.rpc.clear(a);
  for (const i of x.q.build.frozen.inputs) {
    const a = fx.spkAddress(x.config, i.utxo.scriptPublicKey);
    x.rpc.seed(a, { ...fx.utxo(a, i.previousOutpoint.transactionId, i.previousOutpoint.index, i.utxo.amount, i.utxo.covenantId), scriptPublicKey: i.utxo.scriptPublicKey.scriptHex });
  }
}
function outcomeRpc(x, { rejection = false, conflict = false, defect = null } = {}) {
  seedInputs(x);
  const header = (nonce) => ({ version: 1, parentsByLevel: [[fx.H(0)]], hashMerkleRoot: fx.H(0), acceptedIdMerkleRoot: fx.H(0), utxoCommitment: fx.H(0), timestamp: 0n, bits: 0, daaScore: 0n, blueWork: 0n, blueScore: 0n, pruningPoint: fx.H(0), nonce });
  const hs = [header(100n), header(101n)], hashes = hs.map((h) => blockHashOfRpcHeader(x.config, h));
  const consumed = x.q.build.frozen.inputs.at(-1).previousOutpoint;
  const body = { version: 1, inputs: [{ previousOutpoint: consumed, signatureScript: "", sequence: "0", sigOpCount: 0, computeBudget: 0 }], outputs: [{ value: "1", scriptPublicKey: { version: 0, script: `20${fx.XO(x.config, x.o.fuelKey)}ac` } }], lockTime: "0", subnetworkId: "00".repeat(20), gas: "0", payload: "" };
  const conflictId = transactionIdOfRpcBody(x.config, body).transactionId;
  let attempted = false;
  const submit = x.rpc.submitTransaction.bind(x.rpc);
  x.rpc.submitTransaction = async (args) => {
    attempted = true; await submit(args);
    if (conflict) x.rpc.clear(fx.spkAddress(x.config, x.q.build.frozen.inputs.at(-1).utxo.scriptPublicKey));
    throw Error(rejection ? `Rejected transaction ${x.q.txId}: test consensus refusal` : "STUB response lost; outcome unknown");
  };
  x.rpc.getBlockDagInfo = async () => ({ sink: hashes[attempted ? 1 : 0] });
  x.rpc.getMempoolEntry = async ({ transactionId }) => { throw Error(`Transaction ${transactionId} not found`); };
  /* R3N-B1a inventory: x.rpc carries the seam's selected-chain walk (sdk/testutil/guard-node.js chainWalk, installed by
   * the case); the B1 runtime records the submit start as the sink's 20th selected parent (A_s) instead of the sink, so
   * the window and the block scan modelled FROM hashes[0] (the submit-time sink) are answered from any start on
   * hashes[0]'s walk too: the walk blocks above that start (they accept nothing), hashes[0], then hashes[0]'s window. */
  const walk = require("./guard-node").chainWalkOf(x.rpc);
  const above0 = (start) => { const s0 = String(start).toLowerCase(); if (s0 === hashes[0]) return []; const p = walk ? walk.pathAbove(s0) : null; return p && p.head === hashes[0] ? p.blocks : null; };
  x.rpc.getVirtualChainFromBlock = async ({ startHash }) => { const pre = above0(startHash); return { removedChainBlockHashes: [], addedChainBlockHashes: pre !== null ? [...pre, hashes[1]] : [], acceptedTransactionIds: pre !== null ? [...pre.map((h) => ({ acceptingBlockHash: h, acceptedTransactionIds: [] })), { acceptingBlockHash: hashes[1], acceptedTransactionIds: conflict && defect !== "unaccepted" ? [conflictId] : [] }] : [] }; };
  const block = (index, confirmation = false) => {
    const transactions = index && conflict ? [{ ...structuredClone(body), verboseData: { transactionId: conflictId, blockHash: hashes[1] } }] : [];
    if (transactions.length) {
      if (defect === "body") transactions[0].outputs[0].value = "2";
      if (defect === "incomplete") delete transactions[0].lockTime;
      if (defect === "confirmation" && confirmation) transactions.length = 0;
      if (defect === "trailing") transactions.push(null);
    }
    return { header: defect === "header" && index ? header(199n) : hs[index], verboseData: { hash: hashes[index], isChainBlock: true }, transactions };
  };
  x.rpc.getBlocks = async ({ lowHash } = {}) => {
    const pre = lowHash === undefined ? null : above0(lowHash);
    if (pre === null || pre.length === 0) return { blockHashes: hashes, blocks: [block(0), block(1)] };
    const low = String(lowHash).toLowerCase(), seam = [low, ...pre.slice(0, -1)];
    return { blockHashes: [...seam, ...hashes], blocks: [...seam.map((h) => walk.view(h)), block(0), block(1)] };
  };
  x.rpc.getBlock = async ({ hash }) => ({ block: block(hashes.indexOf(hash), true) });
  return { conflictId, hashes };
}
module.exports = { seedInputs, outcomeRpc };
