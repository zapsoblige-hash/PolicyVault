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
  x.rpc.getVirtualChainFromBlock = async ({ startHash }) => ({ removedChainBlockHashes: [], addedChainBlockHashes: startHash === hashes[0] ? [hashes[1]] : [], acceptedTransactionIds: startHash === hashes[0] ? [{ acceptingBlockHash: hashes[1], acceptedTransactionIds: conflict && defect !== "unaccepted" ? [conflictId] : [] }] : [] });
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
  x.rpc.getBlocks = async () => ({ blockHashes: hashes, blocks: [block(0), block(1)] });
  x.rpc.getBlock = async ({ hash }) => ({ block: block(hashes.indexOf(hash), true) });
  return { conflictId, hashes };
}
module.exports = { seedInputs, outcomeRpc };
