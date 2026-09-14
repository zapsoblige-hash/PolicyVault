"use strict";
// Dedicated bounded fixtures for RC36 negative-proof review. Only explicit
// immutable funding metadata is returned; no generic [] success shortcut.
const crypto = require("crypto");
const { loadKaspa } = require("../../src/chain");
const { frozenToWasmTransaction, normalizeFrozenTxV3 } = require("../../src/frozen-tx-v3");
const START = "31".repeat(32), SINK = "32".repeat(32), OTHER = "33".repeat(32);
const address = (config, spk) => loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
function fundingRequest(config, overrides = {}) {
  const kaspa = loadKaspa(config);
  const xo = new kaspa.PrivateKey("71".repeat(32)).toPublicKey().toXOnlyPublicKey().toString();
  const frozen = { version: 1, lockTime: "0", subnetworkId: "0".repeat(40), gas: "0", payload: "",
    inputs: [{ previousOutpoint: { transactionId: "45".repeat(32), index: 0 }, sequence: "0", computeBudget: 0,
      utxo: { amount: "100000000", blockDaaScore: "1", covenantId: null, scriptPublicKey: { version: 0, scriptHex: `20${xo}ac` } } }],
    outputs: [{ value: "99000000", scriptPublicKey: { version: 0, scriptHex: `20${xo}ac` } }] };
  const txId = frozenToWasmTransaction(config, normalizeFrozenTxV3(frozen)).finalize().toString().toLowerCase();
  return { schema: "policyvault-wallet-request/v7-kas", requestId: crypto.randomUUID(), kind: "kasGenesis", vaultId: crypto.randomBytes(32).toString("hex"),
    state: "SUBMISSION_REJECTED", networkId: config.networkId, txId, submitStartHash: START, build: { frozen }, ...overrides };
}
function negativeRpc(config, request, { baseRpc = null, captureAtSubmission = false } = {}) {
  const state = { dagReads: 0, fundingReads: 0, outputReads: 0, mempoolReads: 0, windows: [], mode: "honest", accepted: false, submitted: !captureAtSubmission, start: request?.submitStartHash ?? START };
  const funding = [], outputAddresses = [];
  function configure(r) {
    request = r;
    funding.splice(0, funding.length, ...request.build.frozen.inputs.map((i) => ({ address: address(config, i.utxo.scriptPublicKey), outpoint: { ...i.previousOutpoint },
    amount: String(i.utxo.amount), covenantId: i.utxo.covenantId ?? null, scriptPublicKey: { version: i.utxo.scriptPublicKey.version, script: i.utxo.scriptPublicKey.scriptHex }, blockDaaScore: "1", isCoinbase: false })));
    outputAddresses.splice(0, outputAddresses.length, ...request.build.frozen.outputs.map((o) => address(config, o.scriptPublicKey)));
  }
  if (request) configure(request);
  const rpc = {
    ...(baseRpc ?? {}),
    async submitTransaction(args) {
      state.submitted = true; // anchor A advances to B only on the mock attempt
      if (!request) {
        const tx = JSON.parse(args.transaction.serializeToSafeJSON());
        const actual = args.transaction;
        const script = (s) => ({ version: s.version, scriptHex: s.script });
        configure({ txId: args.transaction.finalize().toString().toLowerCase(), build: { frozen: { ...tx,
          inputs: tx.inputs.map((i, index) => ({ ...i, utxo: { ...i.utxo, scriptPublicKey: script(actual.inputs[index].utxo.scriptPublicKey) } })),
          outputs: tx.outputs.map((o, index) => ({ ...o, scriptPublicKey: script(actual.outputs[index].scriptPublicKey) })) } } });
      }
      if (!baseRpc?.submitTransaction) throw Error("TEST fixture has no submit implementation");
      return baseRpc.submitTransaction(args);
    },
    async getBlockDagInfo() {
      state.dagReads += 1;
      if (state.mode === "dag-error") throw Error("TEST node disconnected");
      if (state.mode === "dag-error-field") return { sink: SINK, error: { message: "TEST stale tip from unavailable node" } };
      if (!state.submitted) return { sink: state.start };
      const postWindow = state.dagReads > (captureAtSubmission ? 2 : 1);
      return { sink: state.mode === "tip-moved" && postWindow ? OTHER : SINK };
    },
    async getVirtualChainFromBlock(args) {
      state.windows.push(args);
      if (state.mode === "window-error") throw Error("TEST acceptance RPC unavailable");
      if (state.mode === "window-error-field") return { error: { message: "TEST unavailable history" }, addedChainBlockHashes: [SINK], acceptedTransactionIds: [{ acceptingBlockHash: SINK, acceptedTransactionIds: [] }], removedChainBlockHashes: [] };
      if (state.mode === "window-malformed") return { addedChainBlockHashes: [SINK], acceptedTransactionIds: [], removedChainBlockHashes: [] };
      if (state.mode === "window-incomplete") return { addedChainBlockHashes: [], acceptedTransactionIds: [], removedChainBlockHashes: [] };
      return { addedChainBlockHashes: [SINK], acceptedTransactionIds: [{ acceptingBlockHash: SINK, acceptedTransactionIds: state.accepted ? [request.txId] : [] }],
        removedChainBlockHashes: state.mode === "anchor-reorg" ? [state.start] : [] };
    },
    async getMempoolEntry(args) {
      state.mempoolReads += 1;
      if (state.mode === "mempool-error") throw Error("TEST mempool service unavailable");
      if (state.mode === "mempool-wrong-id") throw Error(`Transaction ${OTHER} not found`);
      if (state.mode === "mempool-malformed") return {};
      if (args.transactionId !== request.txId || args.includeOrphanPool !== true || args.filterTransactionPool !== false) throw Error("TEST mempool query is not bound to complete pools");
      throw Error(`Transaction ${request.txId} not found`);
    },
    async getUtxosByAddresses(args) {
      if (state.mode === "utxo-error") throw Error("TEST UTXO query failed");
      if (state.mode === "utxo-error-field") return { entries: [], error: { message: "TEST failed" } };
      if (state.mode === "utxo-malformed") return {};
      const requested = new Set(args.addresses);
      const expectedFunding = funding.filter((u) => requested.has(u.address));
      if (expectedFunding.length) state.fundingReads += 1;
      if (outputAddresses.some((a) => requested.has(a))) state.outputReads += 1;
      const result = baseRpc ? await baseRpc.getUtxosByAddresses(args) : { entries: [] };
      let entries = result.entries.filter((u) => !expectedFunding.some((f) => f.outpoint.transactionId === u.outpoint.transactionId && f.outpoint.index === u.outpoint.index));
      if (state.mode !== "funding-spent" && !(state.mode === "funding-disappears" && state.fundingReads > 1)) entries.push(...expectedFunding.map((u) => ({ ...u,
        ...(state.mode === "funding-amount" ? { amount: String(BigInt(u.amount) + 1n) } : {}),
        ...(state.mode === "funding-script" ? { scriptPublicKey: { version: 0, script: "51" } } : {}),
        ...(state.mode === "funding-covenant" ? { covenantId: OTHER } : {}) })));
      if (state.mode === "funding-duplicate") entries.push(...expectedFunding);
      if (state.mode === "output-observed" && requested.has(outputAddresses[0])) entries.push({ outpoint: { transactionId: request.txId, index: 0 }, amount: request.build.frozen.outputs[0].value, scriptPublicKey: { version: 0, script: request.build.frozen.outputs[0].scriptPublicKey.scriptHex } });
      return { entries };
    }
  };
  return { rpc, state, funding };
}
async function provenNegative(config, record) {
  const { settleGenesisSubmitError } = require("../../src/genesis-recovery");
  const { rpc } = negativeRpc(config, record);
  const message = `Rejected transaction ${record.txId}: transaction is not standard: TEST policy rejection`;
  const result = await settleGenesisSubmitError({ config, rpc, request: record, txId: record.txId, message });
  if (result.decision !== "REJECTED") throw Error(`TEST fixture failed to prove negative: ${result.reason}`);
  return { ...record, state: "SUBMISSION_REJECTED", error: message, submissionOutcome: { outcome: "SUBMISSION_REJECTED", txId: record.txId, proof: result.proof } };
}
module.exports = { START, SINK, OTHER, fundingRequest, negativeRpc, provenNegative };
