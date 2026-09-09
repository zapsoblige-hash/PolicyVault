"use strict";
/*
 * UX-05 (Codex checkpoint 2) — a vault creation whose submit outcome is
 * uncertain is a DURABLE unresolved request:
 *   • POST /wallet/v4/create refuses (409 CREATION_UNRESOLVED) for the same
 *     signer while such a request exists (SUBMITTING / SUBMITTED /
 *     RECONCILIATION_REQUIRED); a BUILT (unsigned) draft never blocks;
 *   • GET /wallet/v4/requests?unresolved=1 lists it (reload-restore);
 *   • reconcileCreateWalletRequestV4 resolves ONLY by chain proof:
 *     covenant output observed -> CHAIN_VERIFIED (manifest persisted exactly
 *     as a successful submit); funding unspent + not in mempool + stale ->
 *     NOT_BROADCAST (claim released, creation allowed again); anything else
 *     -> PENDING (fail closed, still blocked).
 * Offline: canonical create schema; the node is a fake RPC.
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const wr4 = require("../src/wallet-requests-v4");
const submit4 = require("../src/wallet-submit-v4");
const { loadManifestV4 } = require("../src/manifest-v4");
const { CONTRACT_VERSION_V4_1 } = require("../../core/model/vault-state-v4.js");

const config = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ux05-")) });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (v) => KEY(v).toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (v) => KEY(v).toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;
const OWNER = 5, AGENT = 0x2f, RECIP = 0x39, OTHER = 6;
const p2pk = (x) => `20${x}ac`;
/* Codex checkpoint 7 (UX-05): the fake node speaks REAL identities — every block hash is the engine hash of a real header
 * (Header.finalize) and every spending transaction is a real BODY whose engine id (transactionIdOfRpcBody) is what the
 * acceptance history names. Tests keep writing LABELS ("d1"*32, "a1"*32); the fake maps labels to real identities. */
const { transactionIdOfRpcBody, blockHashOfRpcHeader } = require("../src/tx-identity");
const HEADER_BASE = { version: 1, parentsByLevel: [["00".repeat(32)]], hashMerkleRoot: "00".repeat(32), acceptedIdMerkleRoot: "00".repeat(32), utxoCommitment: "00".repeat(32), timestamp: 0n, bits: 0, daaScore: 0n, blueWork: 0n, blueScore: 0n, pruningPoint: "00".repeat(32) };
const headerFor = (label) => ({ ...HEADER_BASE, nonce: BigInt("0x" + require("node:crypto").createHash("sha256").update(String(label)).digest("hex").slice(0, 16)) }); // a distinct real header per label
const HB = (label) => blockHashOfRpcHeader(config, headerFor(label)); // the REAL hash a labelled block has
const bodyFor = (outpoint, label) => ({ version: 1, inputs: [{ previousOutpoint: { transactionId: outpoint.transactionId, index: outpoint.index }, signatureScript: "", sequence: "0", sigOpCount: 0, computeBudget: 0 }], outputs: [{ value: "1", scriptPublicKey: { version: 0, script: p2pk(String(label).slice(0, 2).repeat(32)) } }], lockTime: "0", subnetworkId: "00".repeat(20), gas: "0", payload: "" });
/* the creation's own body, as the node would return it (from the request's unsigned safe JSON) */
const rpcBodyFromSafeJson = (text) => { const t = JSON.parse(text); return { version: t.version, inputs: t.inputs.map((i) => ({ previousOutpoint: { transactionId: i.transactionId, index: i.index }, signatureScript: i.signatureScript || "", sequence: String(i.sequence), sigOpCount: i.sigOpCount || 0, computeBudget: i.computeBudget || 0 })), outputs: t.outputs.map((o) => ({ value: String(o.value), scriptPublicKey: o.scriptPublicKey, ...(o.covenant ? { covenant: o.covenant } : {}) })), lockTime: String(t.lockTime), subnetworkId: t.subnetworkId, gas: String(t.gas), payload: t.payload || "" }; };
let BASE = null, server;
const post = async (url, body) => { const r = await fetch(BASE + url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }); return { status: r.status, j: await r.json() }; };
const get = async (url) => { const r = await fetch(BASE + url); return { status: r.status, j: await r.json() }; };
before(async () => { server = createServer(config); await new Promise((r) => server.listen(0, "127.0.0.1", r)); BASE = `http://127.0.0.1:${server.address().port}/api/v1`; });
after(() => server && server.close());

const FUNDING_TX = "6a".repeat(32);
function createBody(vaultId, signer = OWNER, fundingTx = FUNDING_TX) {
  return {
    templateInput: { owner: XO(signer), vaultId },
    initialAgents: [{ agentPk: XO(AGENT), maxPerSpend: (2n * KAS).toString(), periodBudget: (10n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (1n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), recipients: [XO(RECIP)] }],
    initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" },
    signerAddress: ADDR(signer),
    funding: [{ outpoint: { transactionId: fundingTx, index: 0 }, amount: (200n * KAS).toString(), scriptPublicKeyHex: p2pk(XO(signer)) }],
    label: "ux05", contractVersion: CONTRACT_VERSION_V4_1
  };
}
/* accepted = the transaction ids the selected chain accepted since the recorded submission block (rc19 review R4-03);
 * vcFail = the accepted-transaction lookup fails (uncertainty). The mempool miss is the node's EXACT text (R4-04). */
/* batches (rc20 review R5-02): the node answers ONE bounded batch per call; a fake may hand out several — each
 * { added: [chain block hashes], accepted: [txids] } — keyed by the start hash ("cc"*32 first, then the last added hash);
 * the sink reported by getBlockDagInfo is the last added hash of the last batch (or the start hash when there are none). */
function fakeRpc({ vaultUtxo = null, vaultCalls = null, funderUtxos = [], mempool = false, mempoolAnswer = undefined, mempoolBody = null, accepted = [], vcFail = false, batches = null, sink = null, sinks = null, malformed = null, spends = [], blocksFail = false, blockHashMismatch = false, headerMismatch = false, trailingMalformed = false, dropLowHash = false, confirmMismatch = false, blockFail = false, confirmMislabel = false, confirmWrongBlock = false, confirmTrailing = undefined, scanTrailing = undefined, bodyDefect = null, scanAnswers = null, confirmEdit = null, reuseBlockObjects = false } = {}) {
  const START = "cc".repeat(32);
  const plan = batches || [{ added: ["dd".repeat(32)], accepted }];
  const byStart = new Map(); let cur = START;
  for (const b of plan) { byStart.set(cur, b); if (b.added.length) cur = b.added[b.added.length - 1]; }
  const SINK = sink || cur;
  const sinkSeq = Array.isArray(sinks) ? [...sinks] : null; // rc21 review R6-05: the sink reported per getBlockDagInfo call (advances mid-walk)
  const vaultQueue = Array.isArray(vaultCalls) ? [...vaultCalls] : null; // Codex checkpoint 6: per-call answers for the VAULT address (null = empty, "FAIL" = throw, utxo = present)
  const entryFor = (u) => ({ outpoint: u.outpoint, utxoEntry: { amount: u.amount, scriptPublicKey: { script: "aa" }, covenantId: u.covenantId, blockDaaScore: "1", isCoinbase: false } });
  const chainHashes = [START, ...plan.flatMap((b) => b.added)];
  /* label <-> real identity maps (Codex checkpoint 7) */
  const realOf = new Map(), labelOf = new Map();
  const R = (label) => { const l = String(label).toLowerCase(); if (!realOf.has(l)) { const h = HB(l); realOf.set(l, h); labelOf.set(h, l); } return realOf.get(l); };
  const L = (hash) => { const h = String(hash).toLowerCase(); if (labelOf.has(h)) return labelOf.get(h); return h; };
  for (const h of [...chainHashes, SINK, ...(sinkSeq || [])]) R(h);
  /* spending transactions: a real body per spend (or the caller's body); its ENGINE id is what "txId" labels map to */
  const spendBodies = spends.map((sp) => { const body = sp.body || bodyFor(sp.outpoint, sp.txId); const id = transactionIdOfRpcBody(config, body).transactionId; return { ...sp, body, id }; });
  const T = (label) => { const l = String(label).toLowerCase(); const sp = spendBodies.find((s) => String(s.txId).toLowerCase() === l); return sp ? sp.id : l; };
  /* Codex checkpoint 8: a body defect the node might hand over — fields missing / null / incomplete — applied to the emitted body only
   * (the spend's id was computed from the COMPLETE body, so the label stays "right" while the bytes are unreadable). */
  const defected = (body) => { const b = JSON.parse(JSON.stringify(body)); if (bodyDefect === "noLockTime") delete b.lockTime; else if (bodyDefect === "nullIndex") b.inputs[0].previousOutpoint.index = null; else if (bodyDefect === "halfCovenant") b.outputs[0].covenant = { authorizingInput: 0 }; else if (bodyDefect === "noPayload") delete b.payload; else if (bodyDefect === "unsafeValue") b.outputs[0].value = 9007199254740993; return b; };
  const txOf = (sp, blockLabel, { inConfirm = false } = {}) => ({ ...defected(sp.body), verboseData: { transactionId: sp.mislabel || (inConfirm && confirmMislabel) ? "a1".repeat(32) : sp.id, hash: sp.id, blockHash: inConfirm && confirmWrongBlock ? R(blockLabel + "z") : R(blockLabel) } });
  const blockOfFresh = (label, { inConfirm = false } = {}) => { const transactions = spendBodies.filter((sp) => String(sp.blockHash).toLowerCase() === String(label).toLowerCase()).map((sp) => txOf(sp, label, { inConfirm })); if (transactions.length) { if (inConfirm && confirmTrailing !== undefined) transactions.push(confirmTrailing === "DUP" ? JSON.parse(JSON.stringify(transactions[0])) : confirmTrailing); if (!inConfirm && scanTrailing !== undefined) transactions.push(scanTrailing); } return { header: headerFor(headerMismatch ? label + "x" : label), verboseData: { hash: blockHashMismatch ? R(label + "y") : R(label), isChainBlock: true, selectedParentHash: "00".repeat(32) }, transactions }; };
  /* Codex checkpoint 9 (UX-05): `reuseBlockObjects` hands over the SAME block object on every later answer (an adapter that
   * caches / mutates its objects); `scanAnswers` scripts getBlocks per call ({ labels, edits: { [label]: (block, mk) => block } });
   * `confirmEdit(block, mk)` edits the confirming getBlock answer. `mk(label).tx(txLabel, outpoint)` builds a COMPLETE,
   * correctly identified and attributed transaction for that block. */
  const blockCache = new Map();
  const blockOf = (label, opts = {}) => { if (!reuseBlockObjects) return blockOfFresh(label, opts); const k = String(label).toLowerCase(); if (!blockCache.has(k)) blockCache.set(k, blockOfFresh(label, opts)); return blockCache.get(k); };
  const mk = (blockLabel) => ({ tx: (txLabel, outpoint) => { const body = bodyFor(outpoint, txLabel); const id = transactionIdOfRpcBody(config, body).transactionId; return { ...body, verboseData: { transactionId: id, hash: id, blockHash: R(blockLabel) } }; }, idOf: T, hashOf: R });
  const calls = { getBlocks: 0, getBlock: 0 };
  const rpc = {
    getUtxosByAddresses: async ({ addresses }) => {
      const a = addresses[0];
      if (funderUtxos.address === a) return { entries: funderUtxos.list.map((o) => ({ outpoint: o, utxoEntry: { amount: "20000000000", scriptPublicKey: { script: p2pk(XO(OWNER)) }, covenantId: null, blockDaaScore: "1", isCoinbase: false } })) };
      if (vaultQueue && (vaultUtxo === null || a === vaultUtxo.address)) {
        const next = vaultQueue.length > 1 ? vaultQueue.shift() : vaultQueue[0];
        if (next === "FAIL") throw new Error("connection reset");
        return { entries: next ? [entryFor(next)] : [] };
      }
      if (vaultUtxo && a === vaultUtxo.address) return { entries: [entryFor(vaultUtxo)] };
      return { entries: [] };
    },
    getMempoolEntry: async ({ transactionId }) => { if (mempoolAnswer !== undefined) return mempoolAnswer; if (mempoolBody) return { mempoolEntry: { fee: 1n, transaction: mempoolBody, is_orphan: false } }; if (mempool) return { entry: { transaction: {} } }; throw new Error(`RPC Server (remote error) -> code:0  message:\`Transaction ${transactionId} not found\` data:None`); },
    getBlockDagInfo: async () => ({ sink: R(sinkSeq && sinkSeq.length ? (sinkSeq.length > 1 ? sinkSeq.shift() : sinkSeq[0]) : SINK), virtualDaaScore: "1" }),
    getVirtualChainFromBlock: async ({ startHash }) => {
      if (vcFail) throw new Error("block not found");
      if (malformed) return malformed;
      const b = byStart.get(L(startHash));
      if (!b) return { removedChainBlockHashes: [], addedChainBlockHashes: [], acceptedTransactionIds: [] };
      return { removedChainBlockHashes: [], addedChainBlockHashes: b.added.map(R), acceptedTransactionIds: b.added.map((h, i) => ({ acceptingBlockHash: R(h), acceptedTransactionIds: i === b.added.length - 1 ? b.accepted.map(T) : [] })) };
    },
    /* Codex checkpoint 6/7 (UX-05): the block scan for the AFFIRMATIVE conflicting spend — one batch: lowHash inclusive (prepended, as
     * rusty-kaspa does), every chain block of the plan (marked isChainBlock) up to and including the sink; blocks carry real headers. */
    getBlocks: async ({ lowHash }) => {
      if (blocksFail) throw new Error("block not found");
      calls.getBlocks += 1;
      if (scanAnswers) {
        const plan = scanAnswers[calls.getBlocks - 1];
        if (!plan) throw new Error(`fake node: no scripted scan answer #${calls.getBlocks}`);
        const blocks = plan.labels.map((label) => { const b = blockOf(label); const edit = plan.edits && plan.edits[label]; return edit ? edit(b, mk(label)) : b; });
        return { blockHashes: plan.labels.map(R), blocks };
      }
      const low = L(lowHash);
      const from = chainHashes.indexOf(low);
      const labels = [...new Set([...(from >= 0 ? chainHashes.slice(from) : [low]), SINK])];
      const emitted = dropLowHash ? labels.slice(1) : labels;
      const blocks = emitted.map(blockOf);
      if (trailingMalformed) blocks[blocks.length - 1] = { header: {}, transactions: "nope" };
      return { blockHashes: emitted.map(R), blocks };
    },
    getBlock: async ({ hash }) => {
      if (blockFail) throw new Error("block not found");
      const label = L(hash);
      calls.getBlock += 1;
      let block = blockOf(label, { inConfirm: true });
      if (confirmMismatch) block.transactions = [];
      if (confirmEdit) block = confirmEdit(block, mk(label));
      return { block };
    },
    submitTransaction: async () => { throw new Error("fake rpc never broadcasts"); },
    disconnect: async () => {},
    /* helpers for assertions */
    hashOf: R, txIdOf: T, calls
  };
  return rpc;
}

test("a BUILT (unsigned) draft never blocks a new creation; an UNRESOLVED submit does (409 CREATION_UNRESOLVED) and is listed by unresolved=1; NOT_BROADCAST reconciliation unblocks", async () => {
  const a = await post("/wallet/v4/create", createBody("a1".repeat(32)));
  assert.equal(a.status, 201, JSON.stringify(a.j).slice(0, 200));
  const b = await post("/wallet/v4/create", createBody("a2".repeat(32), OWNER, "6b".repeat(32)));
  assert.equal(b.status, 201, "a BUILT draft is cleanup, not an unresolved creation");
  // the first creation's submit outcome becomes uncertain (as if the response was lost after broadcast)
  const rec = await wr4.loadRequest(config, a.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId || rec.txId || "5d".repeat(32); rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  await wr4.saveRequest(config, rec);
  const c = await post("/wallet/v4/create", createBody("a3".repeat(32), OWNER, "6c".repeat(32)));
  assert.equal(c.status, 409);
  assert.equal(c.j.error.code, "CREATION_UNRESOLVED");
  assert.equal(c.j.error.requestId ?? c.j.error.details?.requestId ?? c.j.error.extra?.requestId ?? (JSON.stringify(c.j).includes(rec.requestId) ? rec.requestId : null), rec.requestId, JSON.stringify(c.j));
  const other = await post("/wallet/v4/create", createBody("a4".repeat(32), OTHER, "6d".repeat(32)));
  assert.equal(other.status, 201, "another wallet's creation is not blocked by this signer's unresolved one");
  const listed = await get("/wallet/v4/requests?unresolved=1");
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.j.requests.map((r) => r.requestId), [rec.requestId]);
  // CONFLICTED_OR_CONSUMED (unresolved): funding input spent (not in the funder's UTXO set) but the covenant output not observed and no proof either way -> still blocked, claim kept
  const pending = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] } }), stalePendingMinimumMs: 60 * 60 * 1000 });
  assert.equal(pending.outcome, "CONFLICTED_OR_CONSUMED");
  assert.equal(pending.request.state, "RECONCILIATION_REQUIRED");
  assert.equal((await post("/wallet/v4/create", createBody("a5".repeat(32), OWNER, "6e".repeat(32)))).status, 409, "still blocked while PENDING");
  // PENDING: in the mempool -> still blocked even though funding looks unspent. Codex checkpoint 7: PRESENT is established by the
  // entry's BODY recomputing to this id (the creation's own body); a bare `{ entry: { transaction: {} } }` is an UNRECOGNISED answer
  // (still PENDING, claim kept) and is never displayed as "in the mempool"
  const inMempool = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: FUNDING_TX, index: 0 }] }, mempoolBody: rpcBodyFromSafeJson(rec.transaction.unsignedSafeJson) }), stalePendingMinimumMs: 1000 });
  assert.equal(inMempool.outcome, "PENDING"); assert.match(inMempool.detail, /is in the mempool/);
  assert.equal(transactionIdOfRpcBody(config, rpcBodyFromSafeJson(rec.transaction.unsignedSafeJson)).transactionId, rec.txId, "sanity: the creation body recomputes to the recorded txId");
  const bareEntry = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: FUNDING_TX, index: 0 }] }, mempool: true }), stalePendingMinimumMs: 1000 });
  assert.equal(bareEntry.outcome, "PENDING"); assert.match(bareEntry.detail, /unrecognised shape/); assert.doesNotMatch(bareEntry.detail, /is in the mempool/);
  const otherBody = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: FUNDING_TX, index: 0 }] }, mempoolBody: bodyFor({ transactionId: FUNDING_TX, index: 0 }, "e9".repeat(32)) }), stalePendingMinimumMs: 1000 });
  assert.equal(otherBody.outcome, "PENDING"); assert.match(otherBody.detail, /unrecognised shape/, "a body that does not recompute to this id establishes nothing");
  // PENDING: not yet stale -> still blocked
  const young = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: FUNDING_TX, index: 0 }] } }), stalePendingMinimumMs: 60 * 60 * 1000 });
  assert.equal(young.outcome, "PENDING");
  // NOT_BROADCAST: funding unspent, not in mempool, stale -> closed, claim released, creation allowed again
  const nb = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: FUNDING_TX, index: 0 }] } }), stalePendingMinimumMs: 1000 });
  assert.equal(nb.outcome, "NOT_BROADCAST");
  assert.equal(nb.request.state, "NOT_BROADCAST");
  assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0);
  assert.equal((await post("/wallet/v4/create", createBody("a6".repeat(32), OWNER, "6f".repeat(32)))).status, 201, "unblocked after a proven NOT_BROADCAST");
});

test("CHAIN_VERIFIED reconciliation: the covenant output observed on the DAG completes the genesis exactly like a successful submit (manifest persisted, request CHAIN_VERIFIED)", async () => {
  const r = await post("/wallet/v4/create", createBody("b1".repeat(32), OWNER, "7a".repeat(32)));
  assert.equal(r.status, 201);
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  const txId = rec.build.txId;
  rec.state = "SUBMITTING"; rec.txId = txId; rec.submittedAt = new Date().toISOString();
  await wr4.saveRequest(config, rec);
  // a YOUNG submission is never touched (the submitter may still be completing it) — even if the output were observed
  const young = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc() });
  assert.equal(young.outcome, "PENDING"); assert.match(young.detail, /submitter may still be completing/);
  rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  await wr4.saveRequest(config, rec);
  // the vault covenant address the SDK would poll
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { covenantAddress } = require("../src/chain");
  const { normalizeStateV4 } = require("../../core/model/vault-state-v4.js");
  const compiled = compileExactStateV4({ config, template: rec.template, state: normalizeStateV4(rec.initialState), contractVersion: rec.contractVersion });
  const vaultAddress = covenantAddress(config, compiled.scriptBytes);
  const vaultValue = (BigInt(rec.initialState.protectedValue) + BigInt(rec.initialState.feeReserve)).toString();
  const out = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ vaultUtxo: { address: vaultAddress, outpoint: { transactionId: txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId } }) });
  assert.equal(out.outcome, "CHAIN_VERIFIED");
  assert.equal(out.request.state, "CHAIN_VERIFIED");
  const manifest = await loadManifestV4(config, rec.vaultId);
  assert.ok(manifest && manifest.live && manifest.live.outpoint.transactionId === txId, "manifest persisted from the reconciled proof");
  assert.equal(manifest.creationTxId, txId);
  // a chain-verified request is not "unresolved"; creation is allowed
  assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0);
  // reconciling again is idempotent
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc() })).outcome, "CHAIN_VERIFIED");
});

test("Codex checkpoint 3 (UX-05): a FAILED chain query preserves uncertainty (no claim released, PENDING); a funding input spent by another transaction closes as SUPERSEDED only with acceptance proof (rc19 R4-03); a re-spelled signer address is the same wallet for the 409 guard", async () => {
  const r = await post("/wallet/v4/create", createBody("c1".repeat(32), OWNER, "8a".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  await wr4.saveRequest(config, rec);
  const { loadTransitionClaim } = require("../src/submission-claim");
  void loadTransitionClaim;
  // (a) mempool RPC failure (timeout) with unspent inputs and a stale submission -> PENDING, never NOT_BROADCAST
  const mempoolTimeout = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
  mempoolTimeout.getMempoolEntry = async () => { throw new Error("request timed out"); };
  const t1 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: mempoolTimeout, stalePendingMinimumMs: 1000 });
  assert.equal(t1.outcome, "PENDING"); assert.match(t1.detail, /mempool query failed — uncertainty preserved/);
  assert.equal((await wr4.loadRequest(config, rec.requestId)).state, "RECONCILIATION_REQUIRED");
  // (a') Codex checkpoint 6: a SUCCESSFUL answer of an unrecognised shape (`{}`, an entry for ANOTHER transaction, a bare entry) is
  //      UNKNOWN — never an absence — so a stale creation with unspent inputs stays PENDING instead of closing NOT_BROADCAST
  for (const [label, answer] of [["empty object", {}], ["null", null], ["entry without a transaction", { entry: {} }], ["entry for another transaction", { entry: { transaction: { verboseData: { transactionId: "9f".repeat(32) } } } }], ["array", []]]) {
    const odd = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] }, mempoolAnswer: answer });
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: odd, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "PENDING", label); assert.match(o.detail, /unrecognised shape/, label);
  }
  // (b) funding-input UTXO query failure (the covenant-output query answers) -> PENDING, uncertainty preserved
  const utxoFail = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
  const utxoOk = utxoFail.getUtxosByAddresses;
  utxoFail.getUtxosByAddresses = async (args) => { if (args.addresses[0] === ADDR(OWNER)) throw new Error("connection reset"); return utxoOk(args); };
  const t2 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: utxoFail, stalePendingMinimumMs: 1000 });
  assert.equal(t2.outcome, "PENDING"); assert.match(t2.detail, /funding-input query failed/);
  // (b') the covenant-output query itself failing is ALSO uncertainty (never NOT_BROADCAST / SUPERSEDED / CHAIN_VERIFIED)
  const allFail = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] } });
  allFail.getUtxosByAddresses = async () => { throw new Error("connection reset"); };
  const t2b = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: allFail, stalePendingMinimumMs: 1000 });
  assert.equal(t2b.outcome, "PENDING"); assert.match(t2b.detail, /covenant-output query failed .*uncertainty preserved/);
  assert.equal((await wr4.loadRequest(config, rec.requestId)).state, "RECONCILIATION_REQUIRED");
  // (b'') Codex checkpoint 6: the SECOND vault lookup failing (the first answered empty) with unspent inputs and a stale submission
  //       is still uncertainty — never NOT_BROADCAST while any query is unanswered
  const secondFails = fakeRpc({ vaultCalls: [null, "FAIL"], funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
  const t2c = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: secondFails, stalePendingMinimumMs: 1000 });
  assert.equal(t2c.outcome, "PENDING"); assert.match(t2c.detail, /covenant-output lookup failed/);
  // (c) the node's EXACT "Transaction <id> not found" answer IS an absence (the closed NOT_BROADCAST path stays reachable) —
  //     rc19 review R4-04 / Codex checkpoint 6: any OTHER text — including a transport failure that merely CONTAINS the node's
  //     envelope — is a failed query
  for (const txt of ["WebSocket connection is missing", "unknown websocket state", "transaction not found in mempool", `Transaction ${"9f".repeat(32)} not found`, `socket closed while awaiting: Transaction ${rec.txId} not found (retrying)`, `WebSocket closed while reading: RPC Server (remote error) -> code:0  message:\`Transaction ${rec.txId} not found\` data:None`, `RPC Server (remote error) -> code:0  message:\`Transaction ${rec.txId} not found\` data:None (truncated)`, `code:0  message:\`Transaction ${rec.txId} not found\``]) {
    const vague = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
    vague.getMempoolEntry = async () => { throw new Error(txt); };
    const v = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: vague, stalePendingMinimumMs: 1000 });
    assert.equal(v.outcome, "PENDING", txt); assert.match(v.detail, /mempool query failed/, txt);
  }
  const bare = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
  bare.getMempoolEntry = async () => { throw new Error(`Transaction ${rec.txId} not found`); }; // the bare rusty-kaspa error is the other exact form
  const notFound = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [{ transactionId: "8a".repeat(32), index: 0 }] } });
  assert.equal((await post("/wallet/v4/create", createBody("c2".repeat(32), OWNER, "8b".repeat(32)))).status, 409, "still blocked while PENDING");
  // re-spelled signer (trailing space / uppercase) is the SAME wallet (rc18 review R3-05)
  const respelled = createBody("c3".repeat(32), OWNER, "8c".repeat(32)); respelled.signerAddress = " " + ADDR(OWNER).toUpperCase() + " ";
  const rr = await post("/wallet/v4/create", respelled);
  assert.ok(rr.status === 409 || rr.status === 400, `re-spelled signer must not bypass the guard: ${rr.status} ${JSON.stringify(rr.j).slice(0, 120)}`);
  const nbBare = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: bare, stalePendingMinimumMs: 1000 });
  assert.equal(nbBare.outcome, "NOT_BROADCAST", "the bare exact miss is an absence");
  { const again = await wr4.loadRequest(config, rec.requestId); again.state = "SUBMITTED"; again.error = undefined; await wr4.saveRequest(config, again); }
  const nb = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: notFound, stalePendingMinimumMs: 1000 });
  assert.equal(nb.outcome, "NOT_BROADCAST");
  // (d) SUPERSEDED: a funding input spent elsewhere, output never observed, stale -> closed, creation allowed again
  const r2 = await post("/wallet/v4/create", createBody("c4".repeat(32), OWNER, "8d".repeat(32)));
  assert.equal(r2.status, 201, JSON.stringify(r2.j).slice(0, 200));
  const rec2 = await wr4.loadRequest(config, r2.j.request.requestId);
  rec2.state = "SUBMITTED"; rec2.txId = rec2.build.txId; rec2.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  await wr4.saveRequest(config, rec2);
  const FUND2 = { transactionId: "8d".repeat(32), index: 0 };
  // rc19 review R4-03: SUPERSEDED needs PROOF that this genesis was never accepted — the accepted-transaction ids of the
  // selected chain since the block recorded at submission. Without the recorded block (or with a failed lookup) a
  // consumed funding input stays CONFLICTED_OR_CONSUMED (unresolved, claim kept); a mined-then-spent genesis is
  // ADVANCED_UNRESOLVED (claim kept), never SUPERSEDED.
  const spentNoProof = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] } });
  const np = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: spentNoProof, stalePendingMinimumMs: 1000 });
  assert.equal(np.outcome, "CONFLICTED_OR_CONSUMED", "no submission block recorded -> no proof -> unresolved"); assert.equal(np.request.state, "RECONCILIATION_REQUIRED");
  assert.equal((await post("/wallet/v4/create", createBody("c6".repeat(32), OWNER, "8f".repeat(32)))).status, 409, "still blocked without proof");
  rec2.submitStartHash = HB("cc".repeat(32)); await wr4.saveRequest(config, rec2);
  const lookupFails = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, vcFail: true });
  const lf = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: lookupFails, stalePendingMinimumMs: 1000 });
  assert.equal(lf.outcome, "CONFLICTED_OR_CONSUMED", "a failed accepted-transaction lookup is uncertainty");
  const minedThenSpent = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, accepted: [rec2.txId] });
  const mts = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: minedThenSpent, stalePendingMinimumMs: 1000 });
  assert.equal(mts.outcome, "ADVANCED_UNRESOLVED", "accepted by the chain but the reviewed outpoint is gone: the vault exists — never SUPERSEDED"); assert.equal(mts.request.state, "RECONCILIATION_REQUIRED"); assert.equal(mts.request.chainObservation.accepted, true);
  assert.equal((await post("/wallet/v4/create", createBody("c7".repeat(32), OWNER, "8f".repeat(32)))).status, 409, "a mined-then-spent creation keeps the claim");
  const { vaultAddress: va2 } = submit4.genesisTargetV4(config, rec2);
  const covSeen = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, vaultUtxo: { address: va2, outpoint: { transactionId: "e1".repeat(32), index: 0 }, amount: "1", covenantId: rec2.covenantId } });
  const cs = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: covSeen, stalePendingMinimumMs: 1000 });
  assert.equal(cs.outcome, "ADVANCED_UNRESOLVED", "a UTXO carrying this creation's covenant id at another outpoint proves the genesis was mined"); assert.equal(cs.request.chainObservation.observedOutpoint.transactionId, "e1".repeat(32));
  // rc20 review R5-02: the walk must reach the SINK — a truncated first batch with the genesis accepted in the SECOND batch is a
  // mined-then-spent creation (ADVANCED_UNRESOLVED), never SUPERSEDED; an empty window, no progress, or a malformed answer is uncertainty
  const truncated = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: [rec2.txId] }] });
  const tr = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: truncated, stalePendingMinimumMs: 1000 });
  assert.equal(tr.outcome, "ADVANCED_UNRESOLVED", "the genesis accepted beyond the first batch is found by walking to the sink — never SUPERSEDED");
  const emptyWindow = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: [], accepted: [] }] });
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: emptyWindow, stalePendingMinimumMs: 1000 })).outcome, "CONFLICTED_OR_CONSUMED", "an empty window while stale is not proof");
  const unfinished = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: [] }], sink: "d9".repeat(32) });
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: unfinished, stalePendingMinimumMs: 1000 })).outcome, "CONFLICTED_OR_CONSUMED", "a walk that never reaches the sink is not proof");
  const badShape = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, malformed: { addedChainBlockHashes: ["d1".repeat(32)], acceptedTransactionIds: [{ acceptingBlockHash: "d1".repeat(32), acceptedTransactionIds: "not-an-array" }] } });
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: badShape, stalePendingMinimumMs: 1000 })).outcome, "CONFLICTED_OR_CONSUMED", "a malformed accepted-id entry is unknown, never 'not accepted'");
  // Codex checkpoint 6 (UX-05): chain blocks returned WITHOUT their acceptance entries (or with entries for other blocks) are an
  // incomplete answer — never complete negative evidence
  const uncovered = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, malformed: { addedChainBlockHashes: ["d1".repeat(32), "d2".repeat(32)], acceptedTransactionIds: [{ acceptingBlockHash: "d1".repeat(32), acceptedTransactionIds: [] }] } });
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: uncovered, stalePendingMinimumMs: 1000 })).outcome, "CONFLICTED_OR_CONSUMED", "a chain block without its acceptance entry is not negative evidence");
  const misattributed = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, malformed: { addedChainBlockHashes: ["d1".repeat(32)], acceptedTransactionIds: [{ acceptingBlockHash: "d7".repeat(32), acceptedTransactionIds: [] }] } });
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: misattributed, stalePendingMinimumMs: 1000 })).outcome, "CONFLICTED_OR_CONSUMED", "an acceptance entry for a block that was not returned is malformed");
  // Codex checkpoint 6 (UX-05): a NEGATIVE walk + a spent input is NOT a competing transaction. SUPERSEDED needs the AFFIRMATIVE
  // conflicting spend: a transaction other than this creation, accepted since submission, spending a funding input.
  const negativeOnly = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }] });
  const neg = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: negativeOnly, stalePendingMinimumMs: 1000 });
  assert.equal(neg.outcome, "CONFLICTED_OR_CONSUMED", "negative history alone never releases the claim"); assert.match(neg.detail, /no accepted transaction spending a funding input was located/);
  assert.equal((await post("/wallet/v4/create", createBody("c8".repeat(32), OWNER, "8f".repeat(32)))).status, 409, "still blocked: no affirmative conflict");
  const scanFails = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: ["a0".repeat(32)] }], blocksFail: true });
  const sf = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: scanFails, stalePendingMinimumMs: 1000 });
  assert.equal(sf.outcome, "CONFLICTED_OR_CONSUMED", "a failed block scan is uncertainty"); assert.match(sf.detail, /block scan for the conflicting spend failed \(block not found\)/);
  const notAccepted = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: ["a0".repeat(32)] }], spends: [{ txId: "b7".repeat(32), blockHash: "d1".repeat(32), outpoint: FUND2 }] });
  const na = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: notAccepted, stalePendingMinimumMs: 1000 });
  assert.equal(na.outcome, "CONFLICTED_OR_CONSUMED", "a spend found in a block but NOT accepted by the selected chain is not proof"); assert.match(na.detail, /is not among the accepted transactions/);
  const ownInBlock = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: [rec2.txId] }], spends: [{ txId: rec2.txId, blockHash: "d1".repeat(32), outpoint: FUND2, body: rpcBodyFromSafeJson(rec2.transaction.unsignedSafeJson) }] });
  assert.equal(ownInBlock.txIdOf(rec2.txId), rec2.txId, "sanity: the creation's own body recomputes to its txId");
  assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: ownInBlock, stalePendingMinimumMs: 1000 })).outcome, "ADVANCED_UNRESOLVED", "the spender being THIS creation (accepted) is a mined creation — never SUPERSEDED");
  const spentElsewhere = fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }], spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND2 }] });
  const young = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: spentElsewhere, stalePendingMinimumMs: 60 * 60 * 1000 });
  assert.equal(young.outcome, "CONFLICTED_OR_CONSUMED", "not stale yet: uncertainty preserved");
  const sup = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: spentElsewhere, stalePendingMinimumMs: 1000 });
  assert.equal(sup.outcome, "SUPERSEDED", "proven: an ACCEPTED transaction other than this creation spent a funding input; this creation is not accepted, not in the mempool, no covenant output, stale"); assert.equal(sup.request.state, "SUPERSEDED");
  assert.equal(sup.request.chainObservation.conflictingTxId, spentElsewhere.txIdOf("a1".repeat(32)), "the recorded conflict is the ENGINE id of the spending body"); assert.notEqual(sup.request.chainObservation.conflictingTxId, "a1".repeat(32)); assert.equal(sup.request.chainObservation.conflictingBlockHash, spentElsewhere.hashOf("d3".repeat(32))); assert.deepEqual(sup.request.chainObservation.spentOutpoint, FUND2); assert.match(sup.detail, new RegExp(`spent by transaction ${spentElsewhere.txIdOf("a1".repeat(32))}`)); assert.match(sup.detail, /body re-hashed and confirmed in that block/);
  // rc21 review R6-05 (each on a re-opened SUBMITTED record): the sink INSIDE a batch completes the walk; a sink that advanced mid-walk is re-read and the walk continues
  for (const [label, rpcX] of [
    ["the sink inside the batch completes the walk", fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32), "d2".repeat(32), "d3".repeat(32)], accepted: ["a0".repeat(32)] }], sink: "d2".repeat(32), spends: [{ txId: "a0".repeat(32), blockHash: "d1".repeat(32), outpoint: FUND2 }] })],
    ["an advanced sink is re-read and the walk completes on the next round", fakeRpc({ funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: [] }, { added: ["d2".repeat(32)], accepted: ["a0".repeat(32)] }], sinks: ["d9".repeat(32), "d2".repeat(32)], spends: [{ txId: "a0".repeat(32), blockHash: "d2".repeat(32), outpoint: FUND2 }] })]
  ]) {
    const reopened = await wr4.loadRequest(config, rec2.requestId); reopened.state = "SUBMITTED"; reopened.error = undefined; await wr4.saveRequest(config, reopened);
    assert.equal((await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec2.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 })).outcome, "SUPERSEDED", label);
  }
  assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0);
  assert.equal((await post("/wallet/v4/create", createBody("c5".repeat(32), OWNER, "8e".repeat(32)))).status, 201);
});

test("Codex checkpoint 6 (UX-05 / UX-09): the LANDING RACE — the creation lands between the first output lookup and the funding-input check; a failed second lookup keeps the claim, a successful one completes THIS creation (never 'already transitioned'); reload then completes it; the claim is never released to a replacement", async () => {
  const r = await post("/wallet/v4/create", createBody("f1".repeat(32), OWNER, "9c".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec);
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(config, rec);
  const original = { address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId };
  // race 1: first lookup empty (not landed yet), funding input then observed SPENT (it landed), the SECOND vault lookup FAILS,
  //         the selected-chain history has not recorded it (negative, complete walk) -> uncertainty, claim kept, replacement refused
  const race1 = fakeRpc({ vaultUtxo: original, vaultCalls: [null, "FAIL"], funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: ["a0".repeat(32)] }] });
  const o1 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: race1, stalePendingMinimumMs: 1000 });
  assert.equal(o1.outcome, "CONFLICTED_OR_CONSUMED", "a failed second lookup + negative history is UNCERTAINTY, never SUPERSEDED"); assert.match(o1.detail, /covenant-output lookup failed/);
  assert.equal((await wr4.loadRequest(config, rec.requestId)).state, "RECONCILIATION_REQUIRED");
  assert.equal((await post("/wallet/v4/create", createBody("f2".repeat(32), OWNER, "9d".repeat(32)))).status, 409, "no replacement funding while the original may have landed");
  // reload: the next reconciliation sees the original output on its first lookup and completes THIS creation
  const reload = fakeRpc({ vaultUtxo: original, funderUtxos: { address: ADDR(OWNER), list: [] } });
  const o2 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: reload, stalePendingMinimumMs: 1000 });
  assert.equal(o2.outcome, "CHAIN_VERIFIED"); assert.equal(o2.request.state, "CHAIN_VERIFIED");
  const manifest = await loadManifestV4(config, rec.vaultId);
  assert.ok(manifest && manifest.live && manifest.live.outpoint.transactionId === rec.txId, "the ORIGINAL creation is tracked — not a replacement");
  assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0);
  // race 2: first lookup empty, the SECOND lookup observes the ORIGINAL output -> the creation itself is completed at once
  //         (Codex checkpoint 6, UX-09: never described as 'already transitioned' / ADVANCED_UNRESOLVED)
  const r3 = await post("/wallet/v4/create", createBody("f3".repeat(32), OWNER, "9e".repeat(32)));
  assert.equal(r3.status, 201, JSON.stringify(r3.j).slice(0, 200));
  const rec3 = await wr4.loadRequest(config, r3.j.request.requestId);
  rec3.state = "SUBMITTED"; rec3.txId = rec3.build.txId; rec3.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec3.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec3);
  const t3 = submit4.genesisTargetV4(config, rec3);
  const original3 = { address: t3.vaultAddress, outpoint: { transactionId: rec3.txId, index: rec3.vaultOutputIndex }, amount: t3.vaultValue, covenantId: rec3.covenantId };
  const race2 = fakeRpc({ vaultUtxo: original3, vaultCalls: [null, original3], funderUtxos: { address: ADDR(OWNER), list: [] }, batches: [{ added: ["d1".repeat(32)], accepted: ["a0".repeat(32)] }] });
  const o3 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec3.requestId, rpc: race2, stalePendingMinimumMs: 1000 });
  assert.equal(o3.outcome, "CHAIN_VERIFIED", "the ORIGINAL output observed on the second lookup completes this creation"); assert.match(o3.detail, /landed while this reconciliation was querying/); assert.doesNotMatch(o3.detail, /already been transitioned/);
  assert.equal((await loadManifestV4(config, rec3.vaultId)).creationTxId, rec3.txId);
  // a genuinely ADVANCED vault (the covenant id observed at ANOTHER outpoint) keeps the "transitioned by another path" description
  const r4 = await post("/wallet/v4/create", createBody("f4".repeat(32), OWNER, "9f".repeat(32)));
  assert.equal(r4.status, 201);
  const rec4 = await wr4.loadRequest(config, r4.j.request.requestId);
  rec4.state = "SUBMITTED"; rec4.txId = rec4.build.txId; rec4.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec4.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec4);
  const t4 = submit4.genesisTargetV4(config, rec4);
  const advanced = fakeRpc({ vaultUtxo: { address: t4.vaultAddress, outpoint: { transactionId: "e4".repeat(32), index: 0 }, amount: "1", covenantId: rec4.covenantId }, vaultCalls: [null, { address: t4.vaultAddress, outpoint: { transactionId: "e4".repeat(32), index: 0 }, amount: "1", covenantId: rec4.covenantId }], funderUtxos: { address: ADDR(OWNER), list: [] } });
  const o4 = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec4.requestId, rpc: advanced, stalePendingMinimumMs: 1000 });
  assert.equal(o4.outcome, "ADVANCED_UNRESOLVED"); assert.match(o4.detail, /already been transitioned by another path/);
  { const done = await wr4.loadRequest(config, rec4.requestId); done.state = "NOT_BROADCAST"; await wr4.saveRequest(config, done); } // clear the fixture's claim for the next test
});

test("Codex checkpoint 3 (UX-05): the invariant holds at SUBMISSION — a request built earlier cannot be genesis-submitted while another creation of the same wallet is unresolved (409), and concurrent creates are serialized per signer", async () => {
  const early = await post("/wallet/v4/create", createBody("d1".repeat(32), OWNER, "9a".repeat(32)));
  assert.equal(early.status, 201);
  const later = await post("/wallet/v4/create", createBody("d2".repeat(32), OWNER, "9b".repeat(32)));
  assert.equal(later.status, 201);
  const laterRec = await wr4.loadRequest(config, later.j.request.requestId);
  laterRec.state = "SUBMITTED"; laterRec.txId = laterRec.build.txId; laterRec.submittedAt = new Date().toISOString();
  await wr4.saveRequest(config, laterRec);
  // the EARLIER (prebuilt, unsigned) request must not reach submission
  const sub = await post(`/wallet/v4/requests/${early.j.request.requestId}/genesis-submit`, { signedSafeJson: early.j.request.transaction.unsignedSafeJson });
  assert.equal(sub.status, 409, JSON.stringify(sub.j).slice(0, 200));
  assert.equal(sub.j.error.code, "CREATION_UNRESOLVED");
  assert.equal((await wr4.loadRequest(config, early.j.request.requestId)).state, "BUILT", "the prebuilt request is untouched");
  // resolve, then concurrency: N simultaneous creates for the same signer are serialized (all may build — they are BUILT drafts, never unresolved)
  laterRec.state = "NOT_BROADCAST"; await wr4.saveRequest(config, laterRec);
  const results = await Promise.all([1, 2, 3].map((i) => post("/wallet/v4/create", createBody(("e" + i).repeat(32), OWNER, ("9" + i).repeat(32)))));
  assert.deepEqual(results.map((x) => x.status), [201, 201, 201]);
});

test("Codex checkpoint 7 (UX-05): conflict proof is BOUND to the spending body and its block — a body labelled with another (accepted) id, an unbound block hash / header, malformed data after a match, an answer without the requested boundary, or a failed re-query never release the claim; an unaccepted spender before the accepted one is not missed; reload and the replacement guard hold", async () => {
  const r = await post("/wallet/v4/create", createBody("c9".repeat(32), OWNER, "7b".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec);
  const FUND = { transactionId: "7b".repeat(32), index: 0 };
  const spent = { address: ADDR(OWNER), list: [] };
  const history = [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }];
  const expectUnresolved = async (label, rpcX, re) => {
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "CONFLICTED_OR_CONSUMED", `${label}: ${o.outcome} — ${o.detail}`);
    if (re) assert.match(o.detail, re, label);
    const again = await wr4.loadRequest(config, rec.requestId);
    assert.equal(again.state, "RECONCILIATION_REQUIRED", `${label}: durable unresolved state preserved`);
    assert.equal(again.chainObservation && again.chainObservation.conflictingTxId, undefined, `${label}: no conflict recorded`);
    assert.equal((await post("/wallet/v4/create", createBody("ca".repeat(32), OWNER, "7c".repeat(32)))).status, 409, `${label}: replacement creation still refused after reload`);
    assert.deepEqual((await get("/wallet/v4/requests?unresolved=1")).j.requests.map((x) => x.requestId), [rec.requestId], `${label}: still listed as unresolved`);
  };
  /* (1) Codex's reproduction: history accepted Y ("a1"); getBlocks returns body Z (spends the funding input) LABELLED with Y's id.
   *     The body recomputes to Z != Y: an incoherent answer -> uncertainty; NEVER SUPERSEDED. */
  await expectUnresolved("body Z labelled with accepted id Y", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND, mislabel: true }] }), /block scan for the conflicting spend failed/);
  /* (1') the same body Z without any label: its engine id is simply not among the accepted ids -> an unaccepted spender, uncertainty */
  {
    const rpcX = fakeRpc({ funderUtxos: spent, batches: [{ added: ["d1".repeat(32)], accepted: ["a1".repeat(32)] }], spends: [{ txId: "ee".repeat(32), blockHash: "d1".repeat(32), outpoint: FUND }] });
    await expectUnresolved("unlabelled body whose engine id is not accepted", rpcX, /is not among the accepted transactions/);
  }
  /* (2) a block listed under a hash that is not its verbose hash / whose header does not hash to it */
  await expectUnresolved("block-array hash disagrees with the block's verbose hash", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }], blockHashMismatch: true }), /block scan for the conflicting spend failed/);
  await expectUnresolved("block header does not hash to the listed block hash", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }], headerMismatch: true }), /block scan for the conflicting spend failed/);
  /* (3) a matching (accepted) spend followed by malformed block data in the same answer: no early return, uncertainty */
  await expectUnresolved("accepted spend followed by malformed remaining block data", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d1".repeat(32), outpoint: FUND }], trailingMalformed: true }), /block scan for the conflicting spend failed/);
  /* (4) an answer that does not start with the requested lowHash is not an answer to the question */
  await expectUnresolved("answer without the requested scan boundary", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }], dropLowHash: true }), /block scan for the conflicting spend failed/);
  /* (5) the located accepted spend is not found in its block on re-query (getBlock) -> not confirmed, uncertainty */
  /*     Codex checkpoint 9 re-pin (STALE ASSUMPTION — reason text only; outcome, durable state, no-proof, 409 and unresolved-listing assertions
   *     unchanged): an EMPTY confirming block is now detected as a CONTRADICTION of the scanned block's contents (1 vs 0 transactions)
   *     before the candidate lookup, so the reason names the disagreement instead of "not found on re-query". */
  await expectUnresolved("accepted spend not confirmed by getBlock", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }], confirmMismatch: true }), /answers disagreed on the contents of block [0-9a-f]{64} \(1 vs 0 transactions/);
  await expectUnresolved("getBlock re-query fails", fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }], blockFail: true }), /block scan for the conflicting spend failed/);
  /* (6) an UNACCEPTED spender earlier in the same answer must not hide the accepted one later in it (Low extension) */
  {
    const rpcX = fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "b7".repeat(32), blockHash: "d1".repeat(32), outpoint: FUND }, { txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }] });
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "SUPERSEDED", `unaccepted-first / accepted-later: ${o.detail}`);
    assert.equal(o.request.chainObservation.conflictingTxId, rpcX.txIdOf("a1".repeat(32)));
    assert.equal(o.request.chainObservation.conflictingBlockHash, rpcX.hashOf("d3".repeat(32)));
    assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0);
    assert.equal((await post("/wallet/v4/create", createBody("cb".repeat(32), OWNER, "7d".repeat(32)))).status, 201, "a PROVEN supersession releases the claim");
  }
  /* (7) positive control on a re-opened record: a consistent accepted conflicting body (engine id == accepted id, block bound,
   *     confirmed by getBlock) closes SUPERSEDED — the scan's coverage and bindings do not break the genuine case */
  {
    const reopened = await wr4.loadRequest(config, rec.requestId); reopened.state = "SUBMITTED"; reopened.error = undefined; reopened.chainObservation = undefined; await wr4.saveRequest(config, reopened);
    const rpcX = fakeRpc({ funderUtxos: spent, batches: history, spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }] });
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "SUPERSEDED", o.detail);
    assert.match(o.detail, /body re-hashed and confirmed in that block/);
  }
});

test("Codex checkpoint 8 (UX-05): the CONFIRMING query and the scan validate EVERY record and the supplied metadata — a confirmation body with a contradictory verbose id, one naming another block, a matching body followed by null, a scan match followed by a stub, and bodies with missing / null / incomplete / unsafe identity fields in either query never release the claim (reload + replacement guard hold); such bodies are never 'in the mempool'; the genuine accepted conflict still resolves", async () => {
  const r = await post("/wallet/v4/create", createBody("cc".repeat(32), OWNER, "7e".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec);
  const FUND = { transactionId: "7e".repeat(32), index: 0 };
  const spent = { address: ADDR(OWNER), list: [] };
  const history = [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }];
  const conflict = [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }];
  const expectUnresolved = async (label, rpcX, re) => {
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "CONFLICTED_OR_CONSUMED", `${label}: ${o.outcome} — ${o.detail}`);
    if (re) assert.match(o.detail, re, label);
    const again = await wr4.loadRequest(config, rec.requestId);
    assert.equal(again.state, "RECONCILIATION_REQUIRED", `${label}: durable unresolved state preserved after reload`);
    assert.equal(again.chainObservation && again.chainObservation.conflictingTxId, undefined, `${label}: no conflict recorded`);
    assert.equal((await post("/wallet/v4/create", createBody("cd".repeat(32), OWNER, "7f".repeat(32)))).status, 409, `${label}: replacement creation still refused`);
    assert.deepEqual((await get("/wallet/v4/requests?unresolved=1")).j.requests.map((x) => x.requestId), [rec.requestId], `${label}: still listed as unresolved`);
  };
  /* A. confirmation validation */
  await expectUnresolved("confirmation body carries a contradictory verbose transaction id", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, confirmMislabel: true }), /block scan for the conflicting spend failed/);
  await expectUnresolved("confirmation body names another block", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, confirmWrongBlock: true }), /block scan for the conflicting spend failed/);
  await expectUnresolved("confirmation: matching body followed by null", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, confirmTrailing: null }), /block scan for the conflicting spend failed/);
  await expectUnresolved("confirmation: matching body followed by a stub { inputs: [] }", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, confirmTrailing: { inputs: [] } }), /block scan for the conflicting spend failed/);
  await expectUnresolved("confirmation: matching body followed by a duplicate of itself", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, confirmTrailing: "DUP" }), /block scan for the conflicting spend failed/);
  /* the scan: a match followed by a stub with the remaining body absent */
  await expectUnresolved("scan: matching body followed by a stub { inputs: [] }", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, scanTrailing: { inputs: [] } }), /block scan for the conflicting spend failed/);
  await expectUnresolved("scan: matching body followed by null", fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, scanTrailing: null }), /block scan for the conflicting spend failed/);
  /* B. strict body reading in both queries: missing lockTime / payload, null input index, incomplete covenant, unsafe JS number */
  for (const defect of ["noLockTime", "noPayload", "nullIndex", "halfCovenant", "unsafeValue"]) {
    await expectUnresolved(`body defect ${defect} in the scan and confirmation bodies`, fakeRpc({ funderUtxos: spent, batches: history, spends: conflict, bodyDefect: defect }), /block scan for the conflicting spend failed/);
  }
  /* mempool: otherwise matching bodies with those defects are UNRECOGNISED, never "is in the mempool" */
  {
    const own = rpcBodyFromSafeJson(rec.transaction.unsignedSafeJson);
    const unspent = { address: ADDR(OWNER), list: [{ transactionId: "7e".repeat(32), index: 0 }] };
    const present = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: unspent, mempoolBody: own }), stalePendingMinimumMs: 1000 });
    assert.equal(present.outcome, "PENDING"); assert.match(present.detail, /is in the mempool/, "control: the complete own body IS present");
    for (const [label, mutate] of [["missing lockTime", (b) => { delete b.lockTime; }], ["null input index", (b) => { b.inputs[0].previousOutpoint.index = null; }], ["incomplete covenant", (b) => { b.outputs[0].covenant = { authorizingInput: 0 }; }], ["missing payload", (b) => { delete b.payload; }], ["missing gas", (b) => { delete b.gas; }]]) {
      const body = JSON.parse(JSON.stringify(own)); mutate(body);
      const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: fakeRpc({ funderUtxos: unspent, mempoolBody: body }), stalePendingMinimumMs: 1000 });
      assert.equal(o.outcome, "PENDING", label); assert.match(o.detail, /unrecognised shape/, label); assert.doesNotMatch(o.detail, /is in the mempool/, label);
    }
  }
  /* positive control on the same record: the genuine accepted conflict (complete bodies, coherent labels) still resolves */
  {
    const rpcX = fakeRpc({ funderUtxos: spent, batches: history, spends: conflict });
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "SUPERSEDED", o.detail);
    assert.equal(o.request.chainObservation.conflictingTxId, rpcX.txIdOf("a1".repeat(32)));
    assert.equal((await post("/wallet/v4/create", createBody("ce".repeat(32), OWNER, "80".repeat(32)))).status, 201, "a PROVEN supersession releases the claim");
  }
});

test("Codex checkpoint 9 (UX-05): CROSS-QUERY BLOCK-CONTENT CONSISTENCY — every representation of one block hash that the scan (lowHash overlap / repeats) and the confirming query return must agree on the block's ORDERED engine transaction-id view; a substituted, added, removed or reordered transaction, a reused object mutated between answers, or a later answer that 'restores' the original never releases the claim (0 releases, no conflict proof, unresolved listing + replacement and prebuilt refusal after reload); identical overlap with changed verbose metadata still resolves; a fresh coherent retry resolves", async () => {
  const r = await post("/wallet/v4/create", createBody("e4".repeat(32), OWNER, "82".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const prebuilt = await post("/wallet/v4/create", createBody("e5".repeat(32), OWNER, "83".repeat(32))); // a BUILT draft of the same wallet: must stay refused at submission while the creation is unresolved
  assert.equal(prebuilt.status, 201, JSON.stringify(prebuilt.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString(); rec.submitStartHash = HB("cc".repeat(32));
  await wr4.saveRequest(config, rec);
  const { claimSubmission } = require("../src/submission-claim");
  const { getStore, Categories } = require("../src/store");
  const claimHeld = async () => !!(await getStore(config).read(Categories.SUBMISSION_CLAIM, rec.txId));
  const holdClaim = async () => { if (!(await claimHeld())) await claimSubmission(config, { txId: rec.txId, vaultId: rec.vaultId, action: "createVault" }); };
  await holdClaim(); // the durable claim a real submit creates before broadcast — a release is observable ONLY as its removal
  const reopen = async () => { await holdClaim(); const x = await wr4.loadRequest(config, rec.requestId); x.state = "SUBMITTED"; x.error = undefined; x.chainObservation = undefined; await wr4.saveRequest(config, x); };
  const FUND = { transactionId: "82".repeat(32), index: 0 };
  const UNREL = { transactionId: "ab".repeat(32), index: 1 }; // an outpoint unrelated to this creation
  const spent = { address: ADDR(OWNER), list: [] };
  const START = "cc".repeat(32), D1 = "d1".repeat(32), B = "d2".repeat(32), D3 = "d3".repeat(32), D4 = "d4".repeat(32);
  const history = [{ added: [D1, B], accepted: ["a1".repeat(32)] }, { added: [D3], accepted: ["a0".repeat(32)] }]; // C ("a1") is accepted; the sink is d3
  const C = { txId: "a1".repeat(32), blockHash: B, outpoint: FUND }; // the accepted conflicting spend, in block B
  const U = { txId: "f1".repeat(32), blockHash: B, outpoint: UNREL }; // an unrelated transaction in the same block
  const overlap = (edits = null) => [{ labels: [START, D1, B] }, { labels: [B, D3], ...(edits ? { edits } : {}) }]; // legitimate lowHash overlap: batch 2 starts at B, the last chain block of batch 1
  const replaceWith = (label) => (b, mk) => { b.transactions = [mk.tx(label, UNREL)]; return b; };
  const expectRefused = async (label, rpcX, re = /answers disagreed on the contents of block/) => {
    assert.equal(await claimHeld(), true, `${label}: precondition — the claim is held`);
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "CONFLICTED_OR_CONSUMED", `${label}: ${o.outcome} — ${o.detail}`);
    assert.match(o.detail, re, label);
    assert.doesNotMatch(o.detail, /can never be mined|superseded/i, `${label}: never described as superseded`);
    assert.match(o.detail, /uncertainty preserved \(no claim released\)/, label);
    assert.equal(await claimHeld(), true, `${label}: ZERO releases — the durable submission claim is still held`);
    const again = await wr4.loadRequest(config, rec.requestId);
    assert.equal(again.state, "RECONCILIATION_REQUIRED", `${label}: durable unresolved state after reload`);
    assert.equal(again.chainObservation && again.chainObservation.conflictingTxId, undefined, `${label}: no conflict proof persisted`);
    assert.deepEqual((await get("/wallet/v4/requests?unresolved=1")).j.requests.map((x) => x.requestId), [rec.requestId], `${label}: listed unresolved after reload`);
    assert.equal((await post("/wallet/v4/create", createBody("e6".repeat(32), OWNER, "84".repeat(32)))).status, 409, `${label}: replacement creation refused`);
    const sub = await post(`/wallet/v4/requests/${prebuilt.j.request.requestId}/genesis-submit`, { signedSafeJson: prebuilt.j.request.transaction.unsignedSafeJson });
    assert.equal(sub.status, 409, `${label}: prebuilt request refused at submission (${JSON.stringify(sub.j).slice(0, 120)})`); assert.equal(sub.j.error.code, "CREATION_UNRESOLVED", label);
  };
  const expectResolved = async (label, rpcX, txCount) => {
    await reopen();
    const o = await submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcX, stalePendingMinimumMs: 1000 });
    assert.equal(o.outcome, "SUPERSEDED", `${label}: ${o.outcome} — ${o.detail}`);
    assert.equal(await claimHeld(), false, `${label}: exactly one release — the claim is gone`);
    assert.equal(o.request.chainObservation.conflictingTxId, rpcX.txIdOf(C.txId), label);
    assert.equal(o.request.chainObservation.conflictingBlockHash, rpcX.hashOf(B), label);
    assert.equal(o.request.chainObservation.conflictingBlockTxCount, txCount, `${label}: the compared view's transaction count is recorded`);
    assert.match(String(o.request.chainObservation.conflictingBlockViewSha256), /^[0-9a-f]{64}$/, `${label}: the compared ordered view's fingerprint is recorded`);
    assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0, label);
  };
  /* 1. Codex's reproduction: batch 1 [start, d1, B] with C in B; batch 2 [B, d3] (lowHash overlap) hands over B under the SAME header/hash with another
   *    complete, correctly identified and attributed transaction in place of C; the confirming getBlock(B) returns the first representation again */
  await expectRefused("repeat of B substitutes another transaction for C; the confirmation restores C", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap({ [B]: replaceWith("f0".repeat(32)) }) }));
  /* 2. the confirming query keeps C but drops the unrelated transaction the scan saw in B */
  await expectRefused("confirmation keeps C but removes an unrelated transaction", fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap(), confirmEdit: (b, mk) => { b.transactions = b.transactions.filter((t) => t.verboseData.transactionId === mk.idOf(C.txId)); return b; } }));
  /* 3. an unrelated transaction ADDED or SUBSTITUTED under the same hash — by the repeat, or by the confirmation */
  await expectRefused("repeat of B adds an unrelated transaction", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap({ [B]: (b, mk) => { b.transactions.push(mk.tx("f2".repeat(32), UNREL)); return b; } }) }));
  await expectRefused("confirmation adds an unrelated transaction", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap(), confirmEdit: (b, mk) => { b.transactions.push(mk.tx("f2".repeat(32), UNREL)); return b; } }));
  await expectRefused("confirmation substitutes the unrelated transaction while keeping C", fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap(), confirmEdit: (b, mk) => { b.transactions = b.transactions.map((t) => (t.verboseData.transactionId === mk.idOf(C.txId) ? t : mk.tx("f3".repeat(32), UNREL))); return b; } }));
  /* 4. the same transactions in another ORDER — order is committed by the header's merkle root; set equality is not enough */
  await expectRefused("repeat of B reorders its transactions", fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap({ [B]: (b) => { b.transactions.reverse(); return b; } }) }));
  await expectRefused("confirmation reorders the block's transactions", fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap(), confirmEdit: (b) => { b.transactions.reverse(); return b; } }));
  /* 5. a contradiction in the middle of a longer walk after which every later answer (batch 3, the confirmation) agrees with the FIRST representation:
   *    the earlier contradiction is not erased within the attempt */
  await expectRefused("contradictory B in batch 2; batch 3 and the confirmation restore the original contents", fakeRpc({ funderUtxos: spent, batches: [{ added: [D1, B], accepted: ["a1".repeat(32)] }, { added: [D3, D4], accepted: ["a0".repeat(32)] }], spends: [C], scanAnswers: [{ labels: [START, D1, B] }, { labels: [B, D3], edits: { [B]: replaceWith("f0".repeat(32)) } }, { labels: [D3, D4] }] }));
  /* 6. snapshot isolation: the adapter hands over the SAME block object again, mutated in place between the answers — the baseline must be a copy, never a reference into the node's answer */
  await expectRefused("reused block object mutated in place between answers", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], reuseBlockObjects: true, scanAnswers: overlap({ [B]: (b, mk) => { b.transactions.splice(0, b.transactions.length, mk.tx("f0".repeat(32), UNREL)); return b; } }) }));
  /* 7. malformed / duplicate records in the REPEATED block stay refused by whole-block validation (before any comparison) */
  await expectRefused("repeat of B lists C twice", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap({ [B]: (b) => { b.transactions.push(JSON.parse(JSON.stringify(b.transactions[0]))); return b; } }) }), /block scan for the conflicting spend failed/);
  await expectRefused("repeat of B carries a stub record", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap({ [B]: (b) => { b.transactions.push({ inputs: [] }); return b; } }) }), /block scan for the conflicting spend failed/);
  /* positive controls on the same record (re-opened, claim re-held): coherent overlap resolves with exactly one release */
  const coherent = () => fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap() });
  await expectResolved("identical lowHash overlap, complete matching confirmation", coherent(), 2);
  const meta = (tag) => (b) => { b.verboseData = { ...b.verboseData, blueScore: tag, childrenHashes: ["ee".repeat(32)], mergeSetBluesHashes: [], isChainBlock: true }; b.transactions = b.transactions.map((t) => ({ ...t, verboseData: { ...t.verboseData, mass: tag, blockTime: "99", computeMass: "5" } })); return b; };
  await expectResolved("identical overlap with changed nonessential verbose metadata (block and per-transaction)", fakeRpc({ funderUtxos: spent, batches: history, spends: [C, U], scanAnswers: overlap({ [B]: meta("77") }), confirmEdit: meta("78") }), 2);
  await expectResolved("the same (unmutated) block object handed over three times", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], reuseBlockObjects: true, scanAnswers: overlap() }), 1);
  /* 8. a fresh, fully coherent attempt after a refused contradictory attempt still resolves — the request is not poisoned */
  await reopen();
  await expectRefused("contradictory attempt (again, on the re-opened record)", fakeRpc({ funderUtxos: spent, batches: history, spends: [C], scanAnswers: overlap({ [B]: replaceWith("f0".repeat(32)) }) }));
  await expectResolved("fresh coherent retry after the refused contradictory attempt", coherent(), 2);
  assert.equal((await post("/wallet/v4/create", createBody("e7".repeat(32), OWNER, "85".repeat(32)))).status, 201, "a PROVEN supersession releases the claim");
});

/* ------------------------------------------------------------------ *
 * rc26 round-7 internal review R7-07: two CONCURRENT reconciliations of ONE
 * request inside one SDK process must be SERIALIZED. Without a request-level
 * lock, a node that answers the two sessions contradictorily (the vault
 * outpoint to one, a proven conflicting spend to the other — impossible for
 * one honest node, but exactly the shape the UX-05 work refuses everywhere
 * else) left a VAULT MANIFEST persisted beside a SUPERSEDED request. The
 * server's withSignerLock already serializes the API; the SDK now serializes
 * per request as well (the owner's strictly-serial rule for shared mutable
 * state). RED on cf4e644 (outcomes CHAIN_VERIFIED / SUPERSEDED, manifest
 * beside SUPERSEDED); GREEN when the second call runs after the first and
 * sees the durable CHAIN_VERIFIED.
 * ------------------------------------------------------------------ */
test("rc26 round-7 R7-07: concurrent SDK reconciliations of one request are serialized — the second sees the first's durable outcome; no manifest ever lands beside a SUPERSEDED request", async () => {
  const r = await post("/wallet/v4/create", createBody("d7".repeat(32), OWNER, "9d".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  rec.chainObservation = { sink: "cc".repeat(32) };
  await wr4.saveRequest(config, rec);
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(config, rec);
  const FUND = { transactionId: "9d".repeat(32), index: 0 };
  const vaultUtxo = { address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId };
  /* ONE rpc object shared by both sessions: the vault query answers the outpoint ONCE (first caller), then nothing;
   * the chain answers with a proven conflicting spend of the funding input (SUPERSEDED evidence) to whoever asks. */
  const rpc = fakeRpc({
    vaultUtxo, vaultCalls: [vaultUtxo, null],
    funderUtxos: { address: ADDR(OWNER), list: [] },
    batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }],
    spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }]
  });
  const [a, b] = await Promise.all([
    submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }),
    submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 })
  ]);
  const outcomes = [a.outcome, b.outcome].sort();
  const durable = (await wr4.loadRequest(config, rec.requestId)).state;
  const manifest = await loadManifestV4(config, rec.vaultId);
  assert.deepEqual(outcomes, ["CHAIN_VERIFIED", "CHAIN_VERIFIED"], `serialized: the second session must see the first's durable outcome (got ${a.outcome} / ${b.outcome})`);
  assert.equal(durable, "CHAIN_VERIFIED");
  assert.ok(manifest && manifest.creationTxId === rec.txId, "the vault manifest exists for the CHAIN_VERIFIED creation");
  assert.ok([a.detail, b.detail].some((d) => /already chain-verified/.test(String(d))), "one of the two returned the durable state without re-querying");
});

/* rc26 round-7 review R7-07 — Codex checkpoint 11: the per-request reconcile lock was keyed by the LITERAL configured
 * data-root string, so two configs naming the SAME backing store through equivalent paths ("/x/store" vs "/x/store/",
 * a relative spelling, a symlink) got different locks and reconciled concurrently. The key is now the backing-store
 * IDENTITY (the resolved real path for JSON; host/port/database for postgres) + the request id. RED on 109c5b9. */
test("rc26 round-7 R7-07 (checkpoint 11): equivalent data-root spellings of ONE backing store share the reconcile lock — no concurrent reconciliation through an alias", async () => {
  const r = await post("/wallet/v4/create", createBody("d8".repeat(32), OWNER, "9e".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  rec.chainObservation = { sink: "cc".repeat(32) };
  await wr4.saveRequest(config, rec);
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(config, rec);
  const FUND = { transactionId: "9e".repeat(32), index: 0 };
  const vaultUtxo = { address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId };
  const rpc = fakeRpc({
    vaultUtxo, vaultCalls: [vaultUtxo, null],
    funderUtxos: { address: ADDR(OWNER), list: [] },
    batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }],
    spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }]
  });
  /* three ALIASES of the same store: trailing slash, a "./" segment, and a symlink to the data root */
  const link = path.join(os.tmpdir(), `pv-ux05-link-${process.pid}-${Date.now()}`);
  fs.symlinkSync(config.dataRoot, link);
  const aliases = [config.dataRoot + "/", path.join(config.dataRoot, ".", "."), link].map((d) => require("../src/config").loadConfig({ dataRoot: d }));
  const { reconcileLockIdentity } = submit4;
  assert.ok(aliases.some((a) => a.dataRoot !== config.dataRoot), "at least one alias spells the root differently (config keeps the caller's spelling)");
  for (const alias of aliases) assert.equal(reconcileLockIdentity(alias), reconcileLockIdentity(config), `alias ${alias.dataRoot} resolves to the same backing-store identity`);
  assert.notEqual(reconcileLockIdentity(loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ux05-other-")) })), reconcileLockIdentity(config), "a DIFFERENT store gets a different identity");
  const outcomes = await Promise.all([
    submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }),
    ...aliases.map((alias) => submit4.reconcileCreateWalletRequestV4({ config: alias, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }))
  ]);
  fs.unlinkSync(link);
  assert.deepEqual(outcomes.map((o) => o.outcome), ["CHAIN_VERIFIED", "CHAIN_VERIFIED", "CHAIN_VERIFIED", "CHAIN_VERIFIED"], `every alias serialized behind the first: ${outcomes.map((o) => o.outcome).join(" / ")}`);
  assert.equal((await wr4.loadRequest(config, rec.requestId)).state, "CHAIN_VERIFIED");
  const manifest = await loadManifestV4(config, rec.vaultId);
  assert.ok(manifest && manifest.creationTxId === rec.txId);
});

/* ------------------------------------------------------------------ *
 * rc26 round-7 review R7-07 — Codex checkpoint 12: two RESIDUAL bypasses of
 * the checkpoint-11 backing-store identity were reproduced — (1) PostgreSQL
 * host aliases of ONE database (`localhost` / `127.0.0.1`) got different
 * locks; (2) a data root under a SYMLINK PARENT changed from the normalized
 * fallback to its real path when the directory appeared while an earlier
 * call was active. Corrected: the queue is keyed by the REQUEST ID ALONE
 * (`reconcileLockKey` — conservative in-process serialization, guaranteed
 * regardless of the store's spelling), and `reconcileLockIdentity` is STABLE
 * (nearest existing ancestor's real path; loopback aliases unified). The
 * live-PostgreSQL version of the alias case is hosted-pg-reconcile-lock.test.js.
 * RED on 9da991f (identity changes when the directory appears; pg aliases differ).
 * ------------------------------------------------------------------ */
test("R7-07 (checkpoint 12): the store identity is STABLE across a directory appearing under a symlink parent, and unifies PostgreSQL loopback aliases; the queue key depends on the request id only", async () => {
  const real = fs.mkdtempSync(path.join(os.tmpdir(), "pv-r707-real-"));
  const link = path.join(os.tmpdir(), `pv-r707-link-${process.pid}-${Date.now()}`);
  fs.symlinkSync(real, link);
  try {
    const viaLinkNotYet = loadConfig({ dataRoot: path.join(link, "store") }); // the directory does NOT exist yet
    const before = submit4.reconcileLockIdentity(viaLinkNotYet);
    assert.equal(before, `json://${path.join(real, "store")}`, "resolved through the EXISTING symlink parent before the directory exists");
    fs.mkdirSync(path.join(link, "store"));
    assert.equal(submit4.reconcileLockIdentity(viaLinkNotYet), before, "unchanged after the directory appears");
    assert.equal(submit4.reconcileLockIdentity(loadConfig({ dataRoot: path.join(real, "store") })), before, "the real spelling names the same store");
    assert.equal(submit4.reconcileLockIdentity(loadConfig({ dataRoot: path.join(link, "store", ".", "") })), before, "dot/trailing spellings too");
    assert.equal(submit4.stableRealPath(path.join(link, "store", "deeper", "still-missing")), path.join(real, "store", "deeper", "still-missing"), "a deeper missing remainder is joined onto the nearest existing ancestor's real path");
  } finally {
    fs.unlinkSync(link);
  }
  const pg = (host, extra = {}) => loadConfig({ persistenceBackend: "postgres", pgHost: host, pgPort: 5432, pgUser: "u", pgDatabase: "db", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot: os.tmpdir(), ...extra });
  const canonical = submit4.reconcileLockIdentity(pg("127.0.0.1"));
  for (const alias of ["localhost", "LOCALHOST", "localhost.", "::1", "[::1]", "127.0.0.2", "0:0:0:0:0:0:0:1"]) assert.equal(submit4.reconcileLockIdentity(pg(alias)), canonical, `pg host alias ${alias} names the same backing database`);
  assert.notEqual(submit4.reconcileLockIdentity(pg("127.0.0.1", { pgDatabase: "other" })), canonical, "a different database is a different store");
  assert.notEqual(submit4.reconcileLockIdentity(pg("127.0.0.1", { pgPort: 5433 })), canonical, "a different port is a different store");
  assert.notEqual(submit4.reconcileLockIdentity(pg("db.internal")), canonical, "a non-loopback host is not unified (no hostname discovery)");
  assert.equal(submit4.reconcileLockKey("abc"), submit4.reconcileLockKey("abc"));
  assert.notEqual(submit4.reconcileLockKey("abc"), submit4.reconcileLockKey("abd"));
});

test("R7-07 (checkpoint 12): a data root under a symlink parent whose identity would have CHANGED mid-operation (directory-appearance race, filesystem timing stubbed) still serializes — both callers CHAIN_VERIFIED, one manifest, no unresolved request beside it", async () => {
  const r = await post("/wallet/v4/create", createBody("d9".repeat(32), OWNER, "9f".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  rec.chainObservation = { sink: "cc".repeat(32) };
  await wr4.saveRequest(config, rec);
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(config, rec);
  const FUND = { transactionId: "9f".repeat(32), index: 0 };
  const vaultUtxo = { address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId };
  const rpc = fakeRpc({
    vaultUtxo, vaultCalls: [vaultUtxo, null],
    funderUtxos: { address: ADDR(OWNER), list: [] },
    batches: [{ added: ["d1".repeat(32), "d2".repeat(32)], accepted: ["a0".repeat(32)] }, { added: ["d3".repeat(32)], accepted: ["a1".repeat(32)] }],
    spends: [{ txId: "a1".repeat(32), blockHash: "d3".repeat(32), outpoint: FUND }]
  });
  /* the SAME store spelled through a symlink parent; the first identity computation is made to see the directory as
   * absent (ENOENT — the reviewer's stubbed race), the second sees it present */
  const parentLink = path.join(os.tmpdir(), `pv-r707-parent-${process.pid}-${Date.now()}`);
  fs.symlinkSync(path.dirname(config.dataRoot), parentLink);
  const viaParent = loadConfig({ dataRoot: path.join(parentLink, path.basename(config.dataRoot)) });
  const realNative = fs.realpathSync.native;
  let stubbed = 0;
  fs.realpathSync.native = function (p, ...rest) { if (stubbed === 0 && String(p) === path.resolve(viaParent.dataRoot)) { stubbed += 1; const e = new Error("ENOENT (stubbed race)"); e.code = "ENOENT"; throw e; } return realNative.call(fs, p, ...rest); };
  let outcomes;
  try {
    outcomes = await Promise.all([
      submit4.reconcileCreateWalletRequestV4({ config: viaParent, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }),
      submit4.reconcileCreateWalletRequestV4({ config: viaParent, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 }),
      submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc, stalePendingMinimumMs: 1000 })
    ]);
  } finally {
    fs.realpathSync.native = realNative;
    fs.unlinkSync(parentLink);
  }
  assert.equal(stubbed, 1, "the stubbed race fired for the first identity computation");
  assert.deepEqual(outcomes.map((o) => o.outcome), ["CHAIN_VERIFIED", "CHAIN_VERIFIED", "CHAIN_VERIFIED"], `serialized: ${outcomes.map((o) => o.outcome).join(" / ")}`);
  assert.equal((await wr4.loadRequest(config, rec.requestId)).state, "CHAIN_VERIFIED");
  const manifest = await loadManifestV4(config, rec.vaultId);
  assert.ok(manifest && manifest.creationTxId === rec.txId);
  assert.equal((await get("/wallet/v4/requests?unresolved=1")).j.requests.length, 0, "no unresolved request beside the installed manifest");
});

test("R7-07 (checkpoint 12): two DIFFERENT stores that share a queue entry (same request id) keep their OWN state — the waiting store decides on its own durable state and evidence, never inheriting the other's outcome", async () => {
  const r = await post("/wallet/v4/create", createBody("da".repeat(32), OWNER, "a0".repeat(32)));
  assert.equal(r.status, 201, JSON.stringify(r.j).slice(0, 200));
  const rec = await wr4.loadRequest(config, r.j.request.requestId);
  rec.state = "SUBMITTED"; rec.txId = rec.build.txId; rec.submittedAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  rec.chainObservation = { sink: "cc".repeat(32) };
  await wr4.saveRequest(config, rec);
  /* store B: a different data root holding a COPY of the same request record (same id) */
  const other = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-r707-other-")) });
  await wr4.saveRequest(other, JSON.parse(JSON.stringify(rec)));
  const { vaultAddress, vaultValue } = submit4.genesisTargetV4(config, rec);
  const vaultUtxo = { address: vaultAddress, outpoint: { transactionId: rec.txId, index: rec.vaultOutputIndex }, amount: vaultValue, covenantId: rec.covenantId };
  const rpcA = fakeRpc({ vaultUtxo, funderUtxos: { address: ADDR(OWNER), list: [] } });
  const rpcB = { getUtxosByAddresses: async () => { throw new Error("store B's node is unreachable"); }, getMempoolEntry: async () => { throw new Error("unreachable"); }, getBlockDagInfo: async () => { throw new Error("unreachable"); }, disconnect: async () => {} };
  assert.equal(submit4.reconcileLockKey(rec.requestId), submit4.reconcileLockKey(rec.requestId), "the two calls share the queue entry");
  const [a, b] = await Promise.all([
    submit4.reconcileCreateWalletRequestV4({ config, requestId: rec.requestId, rpc: rpcA, stalePendingMinimumMs: 1000 }),
    submit4.reconcileCreateWalletRequestV4({ config: other, requestId: rec.requestId, rpc: rpcB, stalePendingMinimumMs: 1000 })
  ]);
  assert.equal(a.outcome, "CHAIN_VERIFIED", "store A resolves on its own evidence");
  assert.notEqual(b.outcome, "CHAIN_VERIFIED", `store B does NOT inherit A's outcome (got ${b.outcome}: ${b.detail})`);
  assert.equal((await wr4.loadRequest(other, rec.requestId)).state === "CHAIN_VERIFIED", false, "store B's durable record is its own");
  assert.equal(await loadManifestV4(other, rec.vaultId), null, "no manifest was installed in store B");
  assert.ok((await loadManifestV4(config, rec.vaultId)) && (await loadManifestV4(config, rec.vaultId)).creationTxId === rec.txId, "store A's manifest exists");
});
