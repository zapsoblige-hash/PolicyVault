"use strict";
/*
 * TEST SEAM (not a test file): the BUILD-TIME NODE of a fixture's hosted root builds — RC45 L2-01 guard inventory
 * (mock seeding). Internal test support; not an external engagement of any kind.
 *
 * A root build now reads the configured synced node once (the build-time liveness check of every frozen root and
 * v0.7-kas treasury input), so a fixture that builds a root request against its own mock UTXO table must let that
 * read reach the table — exactly as its submits and reconciles already do through an explicit rpc. Nothing else of
 * the fixture changes: its table carries the outputs the real chain would carry.
 *
 *   registerFixtureNode(config, rpc)    the mock rpc answering for the data root of `config` (a reloaded or cloned
 *                                       config of the same data root finds it; a clone registers its own);
 *   fixtureNodeFor(config)              the registered rpc (or null);
 *   withFixtureNode(config, rpc, fn)    runs fn with the configured node answering from `rpc` (default: the rpc
 *                                       registered for config): during fn, the rusty-kaspa RpcClient constructor that
 *                                       chain.connectVerified uses answers a TEST client — connect, getServerInfo
 *                                       (synced, UTXO-indexed, config.networkId), getUtxosByAddresses and
 *                                       getBlockDagInfo delegated to `rpc`, disconnect — and is restored afterwards.
 *                                       A test that installed its own route-level node (the R2 kit's NODE().with)
 *                                       keeps it: this seam only replaces the client the real connect constructs.
 *
 * RC45 R3N-B1a inventory (contract rc45-l201-contract-03 §8 + clarification 01 item 2 (a); mock capabilities only —
 * nothing here changes an assertion): the B1 runtime also reads, on the same configured node, the 20-hop selected-chain
 * walk from the sink (getBlockDagInfo's sink, then getBlock with verboseData.selectedParentHash / isChainBlock and a
 * header that hashes to the anchor), and E3's getVirtualChainFromBlock. So:
 *   - the TEST client also delegates getBlock, getBlocks, getVirtualChainFromBlock and getMempoolEntry to `rpc` (a
 *     fixture that models none of them answers as a node lacking the data: an error naming the call);
 *   - chainWalk(rpc, config, { daa })   gives a fixture rpc the walk (in place, idempotent; see below);
 *   - registerFixtureNode gives the registered rpc the walk (and FIXTURE_DAA as its virtual DAA when it answers none);
 *   - seedFixtureFuel / spendFixtureFuel put a supplied fee UTXO on a flat-table fixture node before the build and spend
 *     it when the fixture models the transaction's acceptance;
 *   - registerFixtureNode / chainWalk also make a node connection opened OUTSIDE a fixture node fail at once
 *     ("connection refused") instead of never returning: in the test namespaces the real client's connect to the
 *     loopback config (ws://127.0.0.1:1) does not return (probe: more than 200 s), so no passing test can rely on one.
 *     The B1 runtime's fail-soft K1' existence refresh at the slot-request / slot-signature / finalize saves (writer
 *     amendment A1-2) opens such a connection; where a fixture does not serve those saves it records nothing, as A1-2
 *     allows for a failed evaluation.
 *
 * Nothing dials a node; TEST keys only.
 */
const path = require("node:path");
const crypto = require("node:crypto");

const byDataRoot = new Map();
const UNREACHABLE = Symbol.for("policyvault.test.unreachableNodeClient");
const WALK = Symbol.for("policyvault.test.chainWalk");
const HEX64 = /^[0-9a-f]{64}$/;
const lower = (s) => String(s).toLowerCase();
/* the virtual DAA a fixture node that models none answers (R3N-B1a inventory) */
const FIXTURE_DAA = 1_000_000n;

/* A node connection opened outside a fixture node fails at once (see above). Process-wide, installed once. */
function guardUnconfiguredNode(config) {
  const chain = require(path.join(__dirname, "..", "src", "chain.js"));
  const kaspa = chain.loadKaspa(config);
  if (kaspa.RpcClient && kaspa.RpcClient[UNREACHABLE]) return;
  if (kaspa.RpcClient && kaspa.RpcClient.name !== "RpcClient") return; // another TEST client is installed: leave it
  class UnreachableNodeClient {
    constructor(options) { this.options = options; }
    async connect() { throw new Error(`TEST environment: no node answers at ${this.options && this.options.url} outside a fixture node (connection refused)`); }
    async disconnect() { /* nothing to close */ }
  }
  UnreachableNodeClient[UNREACHABLE] = true;
  kaspa.RpcClient = UnreachableNodeClient;
}

/*
 * chainWalk(rpc, config, { daa = null, hops = 20 }) -> handle. Gives a fixture rpc the selected-chain surface the B1
 * runtime reads, in place (idempotent; returns the existing handle when installed). The fixture's own answers stay the
 * answers: a getBlockDagInfo or getBlock the fixture defines (before or after this call — an assignment replaces the
 * fixture's answer, not the seam) is still asked first.
 *   getBlockDagInfo  the fixture's answer, plus `sink` when it names no 64-hex sink (a seam block) and plus
 *                    `virtualDaaScore` (String(daa), daa a value or a function) when it names no canonical one and
 *                    `daa` is given; a fixture without getBlockDagInfo answers only when `daa` is given;
 *   getBlock         every sink the node has answered is the head of a walk of `hops` seam blocks below it (one walk
 *                    per sink and virtual DAA read, created on first read): the sink's own block (the fixture's
 *                    getBlock answer when it has one, else an empty block) gains verboseData { hash,
 *                    selectedParentHash: the walk's first block, isChainBlock: true }; each seam block has an
 *                    engine-hashed header (sdk/src/tx-identity
 *                    blockHashOfRpcHeader recomputes its hash), no transactions, isChainBlock true and a header DAA
 *                    that strictly decreases down the walk: the k-th selected parent of the sink sits
 *                    1 + floor(36k / hops) DAA below the virtual read before the walk (the 20th 37 below, the measured
 *                    20-deep spacing of contract-03's constants table), never below 0; any other hash: the fixture's
 *                    getBlock, else rusty-kaspa's "Block <hash> not found".
 * Nothing else is added: a fixture that models no getVirtualChainFromBlock or getBlocks keeps answering none (its
 * acceptance windows stay unavailable, as before). handle.pathAbove(start) = { head, blocks } (the seam blocks above
 * `start` up to and including the head; start excluded) or null; handle.view(hash, includeTransactions) the RPC block
 * of a seam block; handle.isWalkBlock(hash); handle.walks() every walk made ({ head, v, anchor }).
 */
function chainWalk(rpc, config, { daa = null, hops = 20 } = {}) {
  if (!rpc || typeof rpc !== "object") throw new TypeError("chainWalk: a fixture rpc object is required");
  if (!config || typeof config.networkId !== "string") throw new TypeError("chainWalk: a config is required");
  if (rpc[WALK]) return rpc[WALK];
  guardUnconfiguredNode(config);
  const { blockHashOfRpcHeader } = require(path.join(__dirname, "..", "src", "tx-identity.js"));
  const { canonicalDaaScore } = require(path.join(__dirname, "..", "src", "chain.js"));
  const H32 = (b) => b.toString(16).padStart(2, "0").repeat(32);
  const salt = BigInt(`0x${crypto.randomBytes(4).toString("hex")}`);
  const st = { blocks: new Map(), walks: new Map(), sinks: new Set(), lastV: null, serial: 0n, seamSink: null };
  const daaNow = () => (typeof daa === "function" ? daa() : daa);
  function header(d, parent) {
    st.serial += 1n;
    return { version: 1, parentsByLevel: [[parent ?? H32(0)]], hashMerkleRoot: H32(0), acceptedIdMerkleRoot: H32(0), utxoCommitment: H32(0), timestamp: salt * 1000000n + st.serial, bits: 0, daaScore: d, blueWork: st.serial, blueScore: st.serial, pruningPoint: H32(0), nonce: salt + st.serial };
  }
  function seamBlock(d, parent) {
    const h = header(d < 0n ? 0n : d, parent);
    const hash = blockHashOfRpcHeader(config, h);
    const b = { hash, header: h, parent, walk: null };
    st.blocks.set(hash, b);
    return b;
  }
  /* one walk per (sink, virtual DAA) read: a fixture whose sink hash stays constant while its virtual DAA moves gets
   * the 20-deep ancestor that moves with the virtual, as on a real chain */
  function walkFor(head) {
    const v = st.lastV ?? 0n;
    const key = `${head}@${v}`;
    if (st.walks.has(key)) return st.walks.get(key);
    const chain = []; // oldest (the anchor) first
    let parent = null;
    for (let k = hops; k >= 1; k--) {
      const b = seamBlock(v - 1n - BigInt(Math.floor((36 * k) / hops)), parent);
      chain.push(b.hash);
      parent = b.hash;
    }
    const w = { head, chain, v };
    for (const h of chain) st.blocks.get(h).walk = w;
    st.walks.set(key, w);
    return w;
  }
  const view = (hash, includeTransactions = false) => {
    const b = st.blocks.get(lower(hash));
    if (!b) return null;
    void includeTransactions;
    return { header: { ...b.header }, transactions: [], verboseData: { hash: b.hash, selectedParentHash: b.parent ?? H32(0), isChainBlock: true } };
  };
  /* the fixture's own answers, captured now and on every later assignment */
  const own = { getBlockDagInfo: null, getBlock: null };
  const seam = {
    async getBlockDagInfo(args) {
      let answer;
      if (own.getBlockDagInfo) answer = await own.getBlockDagInfo.call(rpc, args);
      else if (daaNow() !== null) answer = {};
      else throw new Error("TEST fixture node: this fixture's table answers no DAA score");
      if (!answer || typeof answer !== "object" || answer.error != null) return answer;
      const out = { ...answer };
      if (canonicalDaaScore(out.virtualDaaScore) === null && daaNow() !== null) out.virtualDaaScore = String(daaNow());
      const v = canonicalDaaScore(out.virtualDaaScore);
      if (v !== null) st.lastV = v;
      if (typeof out.sink !== "string" || !HEX64.test(lower(out.sink))) {
        if (!st.seamSink) st.seamSink = seamBlock((v ?? 0n) - 1n, null).hash;
        out.sink = st.seamSink;
      }
      st.sinks.add(lower(out.sink));
      return out;
    },
    async getBlock(args) {
      const h = lower(args && args.hash);
      if (st.blocks.has(h) && st.blocks.get(h).walk) return { block: view(h, args && args.includeTransactions === true) };
      if (st.sinks.has(h)) {
        const w = walkFor(h);
        let base = null;
        if (own.getBlock) { try { base = await own.getBlock.call(rpc, args); } catch { base = null; } }
        const blk = base && typeof base === "object" && !Array.isArray(base) ? (base.block !== undefined ? base.block : base) : null;
        const sb = st.blocks.get(h);
        return { block: { ...(blk ?? {}), header: blk && blk.header ? blk.header : sb ? { ...sb.header } : null, transactions: blk && Array.isArray(blk.transactions) ? blk.transactions : [], verboseData: { ...((blk && blk.verboseData) || {}), hash: h, selectedParentHash: w.chain[w.chain.length - 1], isChainBlock: true } } };
      }
      if (own.getBlock) return own.getBlock.call(rpc, args);
      throw new Error(`Block ${h} not found`);
    }
  };
  for (const m of Object.keys(seam)) {
    own[m] = typeof rpc[m] === "function" ? rpc[m] : null;
    Object.defineProperty(rpc, m, { configurable: true, enumerable: true, get: () => seam[m], set: (fn) => { own[m] = typeof fn === "function" ? fn : null; } });
  }
  const handle = {
    isWalkBlock: (hash) => Boolean(st.blocks.get(lower(hash)) && st.blocks.get(lower(hash)).walk),
    view,
    pathAbove(start) {
      const b = st.blocks.get(lower(start));
      if (!b || !b.walk) return null;
      const i = b.walk.chain.indexOf(b.hash);
      return { head: b.walk.head, blocks: [...b.walk.chain.slice(i + 1), b.walk.head] };
    },
    walks: () => [...st.walks.values()].map((w) => ({ head: w.head, v: w.v, anchor: w.chain[0] })),
    /* the fixture's virtual DAA: the `daa` option, else the last canonical virtual DAA the node answered (or null) */
    daa: () => { const d = daaNow(); return d !== null ? BigInt(d) : st.lastV; }
  };
  Object.defineProperty(rpc, WALK, { value: handle, enumerable: false });
  return handle;
}

function registerFixtureNode(config, rpc) {
  if (!config || typeof config.dataRoot !== "string") throw new TypeError("registerFixtureNode: a config with a dataRoot is required");
  guardUnconfiguredNode(config);
  /* R3N-B1a inventory: a registered fixture node is the configured node, which the B1 runtime asks for its virtual DAA,
   * sink and 20-hop walk: it gets the seam's walk, and a fixture that answers no DAA score at all answers FIXTURE_DAA */
  if (rpc && typeof rpc === "object" && !chainWalkOf(rpc)) chainWalk(rpc, config, { daa: typeof rpc.getBlockDagInfo === "function" ? null : FIXTURE_DAA });
  byDataRoot.set(path.resolve(config.dataRoot), rpc);
  return rpc;
}
function fixtureNodeFor(config) {
  return config && typeof config.dataRoot === "string" ? byDataRoot.get(path.resolve(config.dataRoot)) ?? null : null;
}
function withFixtureNode(config, rpcOrFn, maybeFn) {
  const fn = typeof rpcOrFn === "function" ? rpcOrFn : maybeFn;
  const rpc = typeof rpcOrFn === "function" ? fixtureNodeFor(config) : rpcOrFn;
  if (typeof fn !== "function") throw new TypeError("withFixtureNode: a function is required");
  if (!rpc) return fn();
  const chain = require(path.join(__dirname, "..", "src", "chain.js"));
  const kaspa = chain.loadKaspa(config);
  const Real = kaspa.RpcClient;
  class FixtureNodeClient {
    constructor(options) { this.options = options; }
    async connect() { /* the fixture's table is the node */ }
    async getServerInfo() { return { networkId: config.networkId, isSynced: true, hasUtxoIndex: true }; }
    async getUtxosByAddresses(args) { return rpc.getUtxosByAddresses(args); }
    async getBlockDagInfo(args) {
      if (typeof rpc.getBlockDagInfo !== "function") throw new Error("TEST fixture node: this fixture's table answers no DAA score");
      return rpc.getBlockDagInfo(args);
    }
    async disconnect() { /* nothing to close */ }
  }
  /* R3N-B1a inventory: the B1 runtime's further reads on the configured node reach the fixture too */
  for (const name of ["getBlock", "getBlocks", "getVirtualChainFromBlock", "getMempoolEntry"]) {
    FixtureNodeClient.prototype[name] = async function delegated(args) {
      if (typeof rpc[name] !== "function") throw new Error(`TEST fixture node: this fixture models no ${name}`);
      return rpc[name](args);
    };
  }
  kaspa.RpcClient = FixtureNodeClient;
  const restore = () => { kaspa.RpcClient = Real; };
  let out;
  try { out = fn(); } catch (e) { restore(); throw e; }
  if (out && typeof out.then === "function") return out.finally(restore);
  restore();
  return out;
}

/* The chainWalk handle of a fixture rpc (or null). */
const chainWalkOf = (rpc) => (rpc && rpc[WALK]) || null;

/*
 * seedFixtureFuel(config, fuel, { rpc = null, depth = 100000n }) -> fuel. The B1 build observes every non-root frozen
 * input live and exact on the configured node (contract-03 §1.2 D6b), so a fee UTXO a fixture supplies as params.fuel
 * must be in the fixture node's table when the build reads it, as the real chain carries the fee payer's UTXO. For the
 * flat-table fixture nodes (rpc.seed(address, entry): the org-root durable fixture, the v0.7-kas mock harness and their
 * inline copies) this puts exactly that UTXO at its address — its outpoint, amount, P2PK script, no covenant id — with
 * an accepting DAA `depth` below the fixture's virtual DAA (an ordinary wallet UTXO older than 1,000 DAA; no DAA when
 * the fixture has none). The node is `rpc`, else the one registered for config's data root.
 */
const seededFuel = new WeakMap(); // fixture node -> { live: Set(outpoint keys seedFixtureFuel put), spent: Set(keys spendFixtureFuel spent) }
function fuelBook(node) {
  if (seededFuel.has(node)) return seededFuel.get(node);
  const book = { live: new Set(), spent: new Set() };
  seededFuel.set(node, book);
  /* the node's index no longer reports a seeded fee UTXO once spendFixtureFuel spent it (its other entries unchanged);
   * a later assignment of getUtxosByAddresses is filtered the same way */
  let own = node.getUtxosByAddresses;
  const keyOf = (e) => { const op = e && (e.outpoint ?? (e.entry && e.entry.outpoint)); return op ? `${String(op.transactionId).toLowerCase()}:${Number(op.index)}` : null; };
  const filtered = async function getUtxosByAddresses(args) {
    const answer = await own.call(node, args);
    if (!book.spent.size || !answer || !Array.isArray(answer.entries)) return answer;
    return { ...answer, entries: answer.entries.filter((e) => !book.spent.has(keyOf(e))) };
  };
  Object.defineProperty(node, "getUtxosByAddresses", { configurable: true, enumerable: true, get: () => filtered, set: (fn) => { own = fn; } });
  return book;
}
function seedFixtureFuel(config, fuel, { rpc = null, depth = 100000n } = {}) {
  const node = rpc ?? fixtureNodeFor(config);
  if (!node || typeof node.seed !== "function") throw new Error("seedFixtureFuel: a flat-table fixture node (rpc.seed) is required");
  const script = String(fuel.scriptPublicKeyHex).toLowerCase();
  const kaspa = require(path.join(__dirname, "..", "src", "chain.js")).loadKaspa(config);
  const address = kaspa.addressFromScriptPublicKey({ version: 0, script }, config.networkId).toString();
  const handle = chainWalkOf(node), v = handle ? handle.daa() : null;
  const entry = { address, outpoint: { transactionId: String(fuel.outpoint.transactionId).toLowerCase(), index: Number(fuel.outpoint.index) }, amount: BigInt(fuel.amount), covenantId: null, scriptPublicKey: script };
  if (v !== null) entry.blockDaaScore = String(v > BigInt(depth) ? v - BigInt(depth) : 0n);
  const book = fuelBook(node);
  const key = `${entry.outpoint.transactionId}:${entry.outpoint.index}`;
  if (!book.live.has(key) && !book.spent.has(key)) { node.seed(address, entry); book.live.add(key); }
  return fuel;
}
/*
 * spendFixtureFuel(config, frozen, { rpc = null }) — the fixture models the acceptance of a transaction whose frozen
 * inputs include a fee UTXO seedFixtureFuel put: from then on the node no longer reports exactly that UTXO (the
 * address's other entries stay), as an accepted transaction spends every input it consumes (the C3 completion checks
 * every consumed input absent, wr7 assertConsumedInputsAbsent). Entries the seam did not seed are untouched. Synchronous.
 */
function spendFixtureFuel(config, frozen, { rpc = null } = {}) {
  const node = rpc ?? fixtureNodeFor(config);
  const book = node ? seededFuel.get(node) : null;
  if (!book) return;
  for (const input of frozen.inputs) {
    const key = `${String(input.previousOutpoint.transactionId).toLowerCase()}:${Number(input.previousOutpoint.index)}`;
    if (book.live.delete(key)) book.spent.add(key);
  }
}

module.exports = { FIXTURE_DAA, registerFixtureNode, fixtureNodeFor, withFixtureNode, chainWalk, chainWalkOf, guardUnconfiguredNode, seedFixtureFuel, spendFixtureFuel };
