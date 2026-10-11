"use strict";
/*
 * RC45 R3N-B1 (contract rc45-l201-contract-03, addendum v2b revision 3 §7 + writer amendment A1) — THE
 * ARBITRATION-CAPABLE MOCK CHAIN of the B1 legs. Internal RED-first regression material for the RC45 candidate; not an
 * external engagement of any kind.
 *
 * It sits on top of a case's kit node (sdk/testutil/rc45-r2-kas-kit.js chainNode: the UTXO table IS the node's UTXO
 * index) and adds the chain surface a B1 runtime reads, modelled on rusty-kaspa (rk) v2.0.1:
 *   - an engine-hashed SELECTED-PARENT CHAIN: every block carries a real header (kaspa.Header(...).finalize() is its
 *     hash, as sdk/src/tx-identity blockHashOfRpcHeader recomputes), a header daaScore that strictly grows along the
 *     chain, verboseData { hash, selectedParentHash, isChainBlock }; isChainBlock means "on the current selected chain"
 *     (rk consensus/mod.rs:1500-1502);
 *   - getBlockDagInfo { virtualDaaScore, sink }: the virtual DAA score is the kit node's state.daa; unless frozen, the
 *     chain is extended lazily so that the sink sits 1 DAA below the virtual and the 20th selected parent of the sink
 *     sits 37 DAA below it when the virtual moved far enough (the "20-deep ancestor 27–47 DAA below the virtual" of the
 *     contract's measured basis);
 *   - getVirtualChainFromBlock({ startHash, includeAcceptedTransactionIds }) with added / removed chain blocks and the
 *     accepted transaction ids per added chain block (rk service.rs:724-768); a pruned start answers the retention
 *     error, an unknown start "not found";
 *   - getBlocks({ lowHash }) in rk's shape (lowHash prepended, then past(sink) \ past(lowHash) in consensus order:
 *     each chain block's merged blocks, then the chain block; the sink's anticone appended once the sink is reached,
 *     unless anticone: "omit"), batched (batchLimit, default 249 = mergeset_size_limit + 1 at 10 BPS);
 *   - getBlock({ hash, includeTransactions }) returning engine-identity bodies (sdk/src/tx-identity
 *     transactionIdOfRpcBody recomputes every listed id; verboseData { transactionId, blockHash });
 *   - getMempoolEntry: rk's exact miss "Transaction <id> not found" (ws4 isExactMempoolMiss), or PRESENT
 *     { mempoolEntry: { fee, transaction, isOrphan } } (rk rpc/core/src/model/mempool.rs:7-11);
 *   - submitTransaction: an input missing from the index answers rk's disallowed-orphan rejection; otherwise the
 *     transaction is accepted by a new chain block (its effect: frozen inputs spent, frozen outputs created and stamped
 *     with that block's DAA, as rk stamps every output of one accepted transaction with the processing block's DAA,
 *     consensus/core/src/utxo/utxo_diff.rs:224-241), or held in the mempool, or answered "already accepted" / lost;
 *   - the kit's getUtxosByAddresses (the index) and its afterRead hooks, plus hooks and faults on EVERY method and a
 *     call log of every method (read-order and zero-call legs).
 *
 * Transactions are registered as EFFECTS (inputs spent / outputs created on the index) and are applied only when a
 * chain block (or the virtual) accepts them; a reorganization reverts the effects of the transactions its removed
 * chain blocks accepted. Nothing dials a node: every config names ws://127.0.0.1:1. TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");

const SDK_SRC = path.join(__dirname, "..", "src");
const sdk = (name) => require(path.join(SDK_SRC, name));
const H32 = (b) => b.toString(16).padStart(2, "0").repeat(32);
const HEX64 = /^[0-9a-f]{64}$/;
const lower = (s) => String(s).toLowerCase();
const sameOp = (a, b) => Boolean(a && b) && lower(a.transactionId) === lower(b.transactionId) && Number(a.index) === Number(b.index);
const opKey = (o) => `${lower(o.transactionId)}:${Number(o.index)}`;
const ZERO_SUBNET = "00".repeat(20);

function spkAddress(config, spk) {
  return sdk("chain.js").loadKaspa(config).addressFromScriptPublicKey({ version: spk.version, script: spk.scriptHex }, config.networkId).toString();
}
/* The node's RPC transaction body of a frozen (unsigned) transaction: its engine id is the request's txId (the id
 * excludes signature scripts, rk consensus/core/src/hashing/tx.rs). */
function rpcBodyOfFrozen(frozen) {
  return {
    version: Number(frozen.version),
    inputs: frozen.inputs.map((i) => ({ previousOutpoint: { transactionId: lower(i.previousOutpoint.transactionId), index: Number(i.previousOutpoint.index) }, signatureScript: "", sequence: String(i.sequence ?? 0), sigOpCount: Number(i.sigOpCount ?? 1), computeBudget: Number(i.computeBudget ?? 0) })),
    outputs: frozen.outputs.map((o) => ({ value: String(o.value), scriptPublicKey: { version: Number(o.scriptPublicKey.version), script: o.scriptPublicKey.scriptHex }, ...(o.covenant ? { covenant: { authorizingInput: Number(o.covenant.authorizingInput), covenantId: lower(o.covenant.covenantId) } } : {}) })),
    lockTime: String(frozen.lockTime ?? 0),
    subnetworkId: frozen.subnetworkId ?? ZERO_SUBNET,
    gas: String(frozen.gas ?? 0),
    payload: frozen.payload ?? ""
  };
}

/*
 * b1Chain(x, opts) — x is a kit case ({ config, node, ... }); x.node.state.daa is the virtual DAA score.
 *   opts.hops         the selected-parent depth the pattern is laid out for (20);
 *   opts.batchLimit   getBlocks batch size (249);
 *   opts.anticone     "include" (rk: appended once the batch reaches the sink) | "omit" (a final batch truncated
 *                     without the anticone);
 *   opts.submit       "accept" (default) | "mempool" (held, never mined) | "orphan" (always refused as an orphan) |
 *                     "alreadyAccepted" | "lost"
 */
function b1Chain(x, { hops = 20, batchLimit = 249, anticone = "include", submit = "accept" } = {}) {
  const config = x.config, node = x.node;
  const { blockHashOfRpcHeader, transactionIdOfRpcBody } = sdk("tx-identity.js");
  const st = {
    blocks: new Map(), // hash -> block
    chain: [], // selected chain, oldest first
    floating: [], // blocks merged by no chain block yet (the sink's anticone / the virtual's own mergeset)
    effects: new Map(), // txId -> { body, spend: [outpoints], create: [{ address, entry }], applied: null | { daa, removed: [{address, entry}] } }
    acceptedBy: new Map(), // txId -> accepting block hash ("virtual" for the virtual's own mergeset)
    mempool: new Map(), // txId -> { body, isOrphan }
    pruned: new Set(),
    serial: 0,
    frozen: false,
    calls: [],
    hooks: [],
    faults: [],
    overrides: new Map(),
    opts: { batchLimit, anticone, submit }
  };

  /* ---------------- blocks ---------------- */
  function header(daa, parent) {
    st.serial += 1;
    return { version: 1, parentsByLevel: [[parent ?? H32(0)]], hashMerkleRoot: H32(0), acceptedIdMerkleRoot: H32(0), utxoCommitment: H32(0), timestamp: BigInt(st.serial), bits: 0, daaScore: BigInt(daa), blueWork: BigInt(st.serial), blueScore: BigInt(st.serial), pruningPoint: H32(0), nonce: BigInt(st.serial) };
  }
  function newBlock(daa, parent, { txs = [] } = {}) {
    const h = header(daa, parent);
    const hash = blockHashOfRpcHeader(config, h);
    const block = { hash, header: h, daa: BigInt(daa), parent: parent ?? null, merged: [], txs: [], accepted: [] };
    st.blocks.set(hash, block);
    for (const body of txs) include(block, body);
    return block;
  }
  function include(block, body) {
    const id = transactionIdOfRpcBody(config, body).transactionId;
    block.txs.push({ ...structuredClone(body), verboseData: { transactionId: id, blockHash: block.hash } });
    return id;
  }
  const sink = () => st.blocks.get(st.chain.at(-1));
  const onChain = (hash) => st.chain.includes(hash);
  const v = () => BigInt(node.state.daa);

  /* ---------------- effects ---------------- */
  function applyEffect(id, daa) {
    const fx = st.effects.get(id);
    if (!fx || fx.applied) return false;
    const removed = [];
    for (const op of fx.spend) {
      const at = node.entryAt(op);
      if (at) removed.push(at);
      node.spendOutpoint(op);
    }
    for (const c of fx.create) node.putEntry(c.address, { ...c.entry, outpoint: { ...c.entry.outpoint }, daaStamp: String(daa) });
    fx.applied = { daa: BigInt(daa), removed };
    return true;
  }
  function revertEffect(id) {
    const fx = st.effects.get(id);
    if (!fx || !fx.applied) return;
    for (const c of fx.create) node.spendOutpoint(c.entry.outpoint);
    for (const r of fx.applied.removed) node.putEntry(r.address, { ...r.entry, outpoint: { ...r.entry.outpoint } });
    fx.applied = null;
    st.acceptedBy.delete(id);
  }
  const inputsLive = (id) => st.effects.get(id).spend.every((op) => node.entryAt(op) !== null);

  /* ---------------- the chain ---------------- */
  function appendChain(block) {
    assert.ok(block.daa > sink().daa, `TEST chain: chain DAA strictly grows (${block.daa} after ${sink().daa})`);
    st.chain.push(block.hash);
    if (v() <= block.daa) node.state.daa = block.daa + 1n;
  }
  /* lay out the pattern below the virtual: blocks at v-1-floor(36k/20) for k = hops..0 above the sink */
  function sync() {
    if (st.frozen) return;
    const target = v() - 1n;
    if (sink().daa >= target) return;
    for (let k = hops; k >= 0; k--) {
      const d = target - BigInt(Math.floor((36 * k) / hops));
      if (d <= sink().daa) continue;
      const b = newBlock(d, sink().hash);
      st.chain.push(b.hash);
    }
  }
  /* the genesis of the mock: a base block 2,000 DAA below the virtual, then the pattern */
  {
    const base = newBlock(v() - 2000n, null);
    st.chain.push(base.hash);
    for (let i = 1; i <= 40; i++) { const b = newBlock(v() - 2000n + BigInt(i * 20), sink().hash); st.chain.push(b.hash); }
    sync();
  }
  function ancestor(n, from = null) {
    let h = from ?? sink().hash;
    for (let i = 0; i < n; i++) h = st.blocks.get(h).parent;
    return st.blocks.get(h);
  }

  /*
   * mine({ daa, txs, merge, accept }) — append ONE chain block on the sink:
   *   txs      transaction bodies (or registered ids) included in it;
   *   merge    floating block hashes it merges (their transactions become acceptable here);
   *   accept   "all" (default: every included / merged registered transaction whose inputs are still unspent, in
   *            order) | [txIds] | [] (merges without accepting);
   * applies the effects of the accepted transactions (outputs stamped with this block's DAA) and returns the block.
   */
  function mine({ daa = null, txs = [], merge = [], accept = "all" } = {}) {
    sync();
    const d = daa === null ? sink().daa + 1n : BigInt(daa);
    const b = newBlock(d, sink().hash);
    for (const t of txs) include(b, typeof t === "string" ? st.effects.get(t).body : t);
    for (const h of merge) {
      assert.ok(st.blocks.has(h), "TEST chain: merge names a known block");
      b.merged.push(h);
      st.floating = st.floating.filter((f) => f !== h);
    }
    appendChain(b);
    const candidates = [...b.merged.flatMap((h) => st.blocks.get(h).txs.map((t) => t.verboseData.transactionId)), ...b.txs.map((t) => t.verboseData.transactionId)];
    const wanted = accept === "all" ? candidates : accept;
    for (const id of wanted) {
      if (!st.effects.has(id)) { b.accepted.push(id); continue; }
      const fx = st.effects.get(id);
      if (st.acceptedBy.get(id) === "virtual") { st.acceptedBy.set(id, b.hash); b.accepted.push(id); continue; }
      if (fx.applied) continue;
      if (accept === "all" && !inputsLive(id)) continue; // a double spend is merged, not accepted
      applyEffect(id, d);
      st.acceptedBy.set(id, b.hash);
      b.accepted.push(id);
      st.mempool.delete(id);
    }
    return b;
  }
  /* a block outside the selected chain (merged later, or never: the anticone) carrying `txs` */
  function sideBlock({ txs = [], daa = null } = {}) {
    sync();
    const b = newBlock(daa === null ? sink().daa : BigInt(daa), sink().parent ?? sink().hash);
    for (const t of txs) include(b, typeof t === "string" ? st.effects.get(t).body : t);
    st.floating.push(b.hash);
    return b;
  }
  /* a transaction accepted ONLY by the virtual block's own mergeset (rk: utxo_validation.rs:75-76 "this can also be the
   * virtual block"): its block is a tip no chain block merges yet; the index applies it (stamped with the virtual DAA). */
  function acceptByVirtual(id) {
    const b = sideBlock({ txs: [id] });
    applyEffect(id, v());
    st.acceptedBy.set(id, "virtual");
    st.mempool.delete(id);
    return b;
  }
  /*
   * reorg({ depth, blocks }) — the top `depth` chain blocks leave the selected chain (they stay readable, isChainBlock
   * false); the effects of the transactions they accepted are reverted (newest first); then each spec of `blocks`
   * (mine() options) is mined on the fork point. A removed block's transactions can be merged by a new block (merge).
   */
  function reorg({ depth, blocks = [{}] }) {
    assert.ok(depth >= 1 && depth < st.chain.length, "TEST chain: reorg depth");
    const removed = st.chain.splice(st.chain.length - depth, depth);
    for (const h of [...removed].reverse()) {
      const b = st.blocks.get(h);
      for (const id of [...b.accepted].reverse()) if (st.acceptedBy.get(id) === h) revertEffect(id);
    }
    const out = [];
    const wasFrozen = st.frozen;
    st.frozen = true;
    try {
      for (const spec of blocks) {
        const daa = spec.daa ?? null;
        const b = newBlock(daa === null ? sink().daa + 1n : BigInt(daa), sink().hash);
        for (const t of spec.txs ?? []) include(b, typeof t === "string" ? st.effects.get(t).body : t);
        for (const hh of spec.merge ?? []) { b.merged.push(hh); st.floating = st.floating.filter((f) => f !== hh); }
        appendChain(b);
        const candidates = [...b.merged.flatMap((hh) => st.blocks.get(hh).txs.map((t) => t.verboseData.transactionId)), ...b.txs.map((t) => t.verboseData.transactionId)];
        const wanted = (spec.accept ?? "all") === "all" ? candidates : spec.accept;
        for (const id of wanted) {
          if (!st.effects.has(id)) { b.accepted.push(id); continue; }
          if (st.effects.get(id).applied) continue;
          if ((spec.accept ?? "all") === "all" && !inputsLive(id)) continue;
          applyEffect(id, b.daa);
          st.acceptedBy.set(id, b.hash);
          b.accepted.push(id);
        }
        out.push(b);
      }
    } finally { st.frozen = wasFrozen; }
    return { removed, added: out };
  }

  /* ---------------- transactions ---------------- */
  /* register a frozen transaction (a request's own transaction X, or any SDK-built transaction) as an effect */
  function registerFrozen(frozen, txId) {
    const body = rpcBodyOfFrozen(frozen);
    const id = transactionIdOfRpcBody(config, body).transactionId;
    assert.equal(id, lower(txId), "TEST chain: the frozen body recomputes to the request's txId");
    if (!st.effects.has(id)) st.effects.set(id, {
      body,
      spend: frozen.inputs.map((i) => ({ transactionId: lower(i.previousOutpoint.transactionId), index: Number(i.previousOutpoint.index) })),
      create: frozen.outputs.map((o, i) => ({ address: spkAddress(config, o.scriptPublicKey), entry: { outpoint: { transactionId: id, index: i }, amount: BigInt(o.value), covenantId: o.covenant ? lower(o.covenant.covenantId) : null, scriptPublicKey: { version: o.scriptPublicKey.version, script: o.scriptPublicKey.scriptHex } } })),
      applied: null
    });
    return id;
  }
  const registerRequest = (rec) => registerFrozen(rec.build.frozen, rec.txId);
  /*
   * A synthetic transaction (engine identity; signatures are not validated by the node model): it spends `spend`
   * (outpoints; when empty, a unique TEST outpoint that no index entry carries, as an already-final funding input
   * would) and pays `outputs` [{ wallet | xonly | spk, amountSompi, covenantId? }] (default: one P2PK output to 0x99's
   * key). Returns { id, body, outpoints } (outpoints: the created outputs).
   */
  function syntheticTx({ spend = [], outputs = null, tag = "spend" } = {}) {
    st.serial += 1;
    const ins = spend.length ? spend : [{ transactionId: require("node:crypto").createHash("sha256").update(`rc45-b1-chain-${tag}-${st.serial}`).digest("hex"), index: 0 }];
    const outs = (outputs ?? [{ xonly: "99".repeat(32), amountSompi: 100000000n }]).map((o) => {
      const script = o.spk ? o.spk.script : `20${o.wallet ? o.wallet.xonly : o.xonly}ac`;
      return { value: String(o.amountSompi), scriptPublicKey: { version: o.spk ? o.spk.version : 0, script }, ...(o.covenantId ? { covenant: { authorizingInput: 0, covenantId: lower(o.covenantId) } } : {}) };
    });
    const body = { version: 1, inputs: ins.map((op) => ({ previousOutpoint: { transactionId: lower(op.transactionId), index: Number(op.index) }, signatureScript: "", sequence: String(st.serial), sigOpCount: 1, computeBudget: 0 })), outputs: outs, lockTime: "0", subnetworkId: ZERO_SUBNET, gas: "0", payload: "" };
    const id = transactionIdOfRpcBody(config, body).transactionId;
    const kaspa = sdk("chain.js").loadKaspa(config);
    st.effects.set(id, {
      body,
      spend: spend.map((op) => ({ transactionId: lower(op.transactionId), index: Number(op.index) })),
      create: outs.map((o, i) => ({ address: kaspa.addressFromScriptPublicKey({ version: o.scriptPublicKey.version, script: o.scriptPublicKey.script }, config.networkId).toString(), entry: { outpoint: { transactionId: id, index: i }, amount: BigInt(o.value), covenantId: o.covenant ? o.covenant.covenantId : null, scriptPublicKey: { ...o.scriptPublicKey } } })),
      applied: null
    });
    return { id, body, outpoints: outs.map((_, i) => ({ transactionId: id, index: i })) };
  }
  /* the transaction spending `outpoints` (another party's conflicting spend C), accepted by a new chain block */
  function conflictingSpend(outpoints, { tag = "conflict", payTo = "99".repeat(32), accept = true } = {}) {
    const t = syntheticTx({ spend: outpoints, outputs: [{ xonly: payTo, amountSompi: 1000n }], tag });
    const block = accept ? mine({ txs: [t.id] }) : null;
    return { ...t, block };
  }
  /* a creating transaction F paying `wallet` (an ordinary P2PK output), accepted by a new chain block K' */
  function fund(wallet, amountSompi, { tag = "fund", extra = [], accept = true } = {}) {
    const t = syntheticTx({ outputs: [{ wallet, amountSompi: BigInt(amountSompi) }, ...extra], tag });
    const block = accept ? mine({ txs: [t.id] }) : null;
    return { ...t, block, outpoint: t.outpoints[0], fuel: { outpoint: { ...t.outpoints[0] }, amount: String(amountSompi), scriptPublicKeyHex: `20${wallet.xonly}ac` } };
  }

  /* ---------------- hooks, faults, overrides ---------------- */
  function record(method, args) {
    const call = { method, args: args === undefined ? null : structuredClone(args) };
    st.calls.push(call);
    for (const f of st.faults) {
      if (f.method !== method || !f.pred(call)) continue;
      f.count += 1;
      if (f.always ? f.count >= f.nth : f.count === f.nth) throw new Error(f.message);
    }
    return async () => {
      for (const h of st.hooks) {
        if (h.done || h.method !== method || !h.pred(call)) continue;
        h.count += 1;
        if (h.count === h.nth) { h.done = true; await h.fn(call); }
      }
    };
  }
  /* the call is recorded (faults fire), its answer computed (or thrown), then the matching hooks run (awaited) before it
   * returns or rethrows */
  async function run(method, args, answer) {
    const after = record(method, args);
    const ov = st.overrides.get(method);
    let out;
    try { out = ov ? await ov(args, answer) : await answer(); } finally { await after(); } // hooks run after a thrown answer too
    return out;
  }

  /* ---------------- the rpc ---------------- */
  const blockView = (b, includeTransactions) => ({
    header: { ...b.header },
    transactions: includeTransactions ? b.txs.map((t) => structuredClone(t)) : [],
    verboseData: { hash: b.hash, selectedParentHash: b.parent ?? H32(0), isChainBlock: onChain(b.hash), blueScore: b.header.blueScore, mergeSetBluesHashes: [...b.merged], childrenHashes: [] }
  });
  const rpc = {
    async getBlockDagInfo() {
      return run("getBlockDagInfo", undefined, async () => { sync(); return { networkName: "kaspa-testnet-10", virtualDaaScore: v().toString(), sink: sink().hash, tipHashes: [sink().hash, ...st.floating] }; });
    },
    async getUtxosByAddresses(args) {
      return run("getUtxosByAddresses", args, async () => node.rpc.getUtxosByAddresses(args));
    },
    async getBlock(args) {
      return run("getBlock", args, async () => {
        const hash = lower(args && args.hash);
        if (st.pruned.has(hash) || !st.blocks.has(hash)) throw new Error(`Block ${hash} not found`);
        return { block: blockView(st.blocks.get(hash), args.includeTransactions === true) };
      });
    },
    async getVirtualChainFromBlock(args) {
      return run("getVirtualChainFromBlock", args, async () => {
        sync();
        const start = lower(args && args.startHash);
        if (st.pruned.has(start)) throw new Error(`cannot use block ${start} as a start: it is below the retention root (the chain path lacks the retention root)`);
        if (!st.blocks.has(start)) throw new Error(`Block ${start} not found`);
        const removed = [];
        let fork = start;
        while (!onChain(fork)) { removed.push(fork); fork = st.blocks.get(fork).parent; assert.ok(fork, "TEST chain: a removed block descends from the chain"); }
        const added = st.chain.slice(st.chain.indexOf(fork) + 1);
        return {
          removedChainBlockHashes: removed,
          addedChainBlockHashes: added,
          acceptedTransactionIds: args.includeAcceptedTransactionIds ? added.map((h) => ({ acceptingBlockHash: h, acceptedTransactionIds: [...st.blocks.get(h).accepted] })) : []
        };
      });
    },
    async getBlocks(args) {
      return run("getBlocks", args, async () => {
        sync();
        const low = lower(args && args.lowHash);
        if (!st.blocks.has(low)) throw new Error(`Block ${low} not found`);
        assert.ok(onChain(low), "TEST chain: getBlocks is answered from a selected-chain lowHash");
        const order = [];
        for (const h of st.chain.slice(st.chain.indexOf(low) + 1)) { for (const m of st.blocks.get(h).merged) order.push(m); order.push(h); }
        const list = [low, ...order.slice(0, st.opts.batchLimit - 1)];
        if (list.includes(sink().hash) && st.opts.anticone === "include") for (const f of st.floating) if (!list.includes(f)) list.push(f);
        return { blockHashes: list, blocks: list.map((h) => blockView(st.blocks.get(h), args.includeTransactions === true)) };
      });
    },
    async getMempoolEntry(args) {
      return run("getMempoolEntry", args, async () => {
        const id = lower(args && args.transactionId);
        const e = st.mempool.get(id);
        if (!e || (e.isOrphan && args.includeOrphanPool !== true)) throw new Error(`Transaction ${id} not found`);
        return { mempoolEntry: { fee: 0n, transaction: structuredClone(e.body), isOrphan: e.isOrphan } };
      });
    },
    async submitTransaction(args) {
      return run("submitTransaction", { allowOrphan: args.allowOrphan }, async () => {
        const id = lower(args.transaction.finalize().toString());
        node.state.broadcasts.push(id);
        const mode = st.opts.submit;
        if (mode === "lost") throw new Error("TEST node: the submit response was lost (connection reset); outcome unknown");
        if (mode === "alreadyAccepted") throw new Error(`Rejected transaction ${id}: transaction ${id} was already accepted by the consensus`);
        const fx = st.effects.get(id);
        /* rusty-kaspa mempool answers (mining/errors/src/mempool.rs), wrapped "Rejected transaction <id>: ..." (rpc/core/src/error.rs) */
        if (mode === "orphan") throw new Error(`Rejected transaction ${id}: transaction ${id} is an orphan where orphan is disallowed`);
        if (fx && fx.applied) throw new Error(`Rejected transaction ${id}: transaction ${id} was already accepted by the consensus`);
        if (st.mempool.has(id) && !st.mempool.get(id).isOrphan) throw new Error(`Rejected transaction ${id}: transaction ${id} is already in the mempool`);
        if (fx) for (const [other, e] of st.mempool) {
          if (other === id || e.isOrphan) continue;
          const spent = new Set(e.body.inputs.map((i) => `${lower(i.previousOutpoint.transactionId)}:${Number(i.previousOutpoint.index)}`));
          const clash = fx.spend.find((op) => spent.has(opKey(op)));
          if (clash) throw new Error(`Rejected transaction ${id}: transaction ${id} is a double spend of an outpoint ${opKey(clash)} already spent by transaction ${other} in the mempool`);
        }
        if (!fx || !inputsLive(id)) throw new Error(`Rejected transaction ${id}: transaction ${id} is an orphan where orphan is disallowed`);
        if (mode === "mempool") { st.mempool.set(id, { body: fx.body, isOrphan: false }); return { transactionId: id }; }
        mine({ txs: [id] });
        return { transactionId: id };
      });
    },
    async disconnect() { st.calls.push({ method: "disconnect", args: null }); }
  };

  return {
    rpc,
    state: st,
    /* ---- reading the model ---- */
    sink, ancestor, onChain, v,
    block: (hash) => st.blocks.get(lower(hash)),
    blockOfTx: (id) => { const h = st.acceptedBy.get(lower(id)); return h && h !== "virtual" ? st.blocks.get(h) : null; },
    acceptedBy: (id) => st.acceptedBy.get(lower(id)) ?? null,
    calls: () => st.calls.map((c) => ({ method: c.method, args: c.args })),
    callCount: (method) => st.calls.filter((c) => c.method === method).length,
    resetCalls: () => { st.calls.length = 0; },
    /* ---- changing the model ---- */
    sync, mine, sideBlock, acceptByVirtual, reorg,
    freeze() { st.frozen = true; }, thaw() { st.frozen = false; },
    prune(hash) { st.pruned.add(lower(hash)); },
    /* advance the virtual by `daa` (the chain follows lazily) */
    advance(daa) { node.state.daa = v() + BigInt(daa); sync(); return v(); },
    registerFrozen, registerRequest, syntheticTx, conflictingSpend, fund,
    accept(id, opts = {}) { return mine({ txs: [id], ...opts }); },
    toMempool(id, { isOrphan = false } = {}) { st.mempool.set(lower(id), { body: st.effects.get(lower(id)).body, isOrphan }); },
    dropMempool(id) { st.mempool.delete(lower(id)); },
    setSubmit(mode) { st.opts.submit = mode; },
    setAnticone(mode) { st.opts.anticone = mode; },
    setBatchLimit(n) { st.opts.batchLimit = n; },
    /* after the nth call of `method` with pred(call) true has computed its answer, fn(call) runs once */
    after(method, pred, nth, fn) { st.hooks.push({ method, pred: pred ?? (() => true), nth, fn, count: 0, done: false }); },
    /* the nth (or, with always, every from the nth on) call of `method` with pred(call) true throws `message` */
    fault(method, { pred = () => true, nth = 1, always = false, message = `TEST node: ${method} failed (connection reset)` } = {}) { st.faults.push({ method, pred, nth, always, message, count: 0 }); },
    clearFaults() { st.faults.length = 0; },
    /* replace the answer of `method`: fn(args, real) where real() computes the model's answer */
    override(method, fn) { if (fn) st.overrides.set(method, fn); else st.overrides.delete(method); },
    rpcBodyOfFrozen
  };
}

module.exports = { b1Chain, rpcBodyOfFrozen, spkAddress, H32, HEX64, sameOp, opKey, lower };
