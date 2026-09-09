"use strict";

/*
 * Node session — the facilitator's ONLY outbound dependency: read-only
 * kaspad RPC through the sanctioned SDK chain helpers (connectVerified /
 * getVirtualDaaScore / getAddressUtxos). Every observation re-verifies
 * the node identity (network, synced, UTXO index) BEFORE any chain field
 * is read (spec §6, §7.1 step 1). Nothing here submits, signs, or reads
 * the mempool. Failures are RETRY-classed refusals (never a judgement)
 * and drop the connection so the next request reconnects.
 */

const chain = require("../../sdk/src/chain");
const { verifyNodeIdentity } = require("./network");
const { refuse, FacilitatorRefusal } = require("./codes");

function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} exceeded ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

class NodeSession {
  /* config: { networkId (kaspad id), rpcUrl, rustyKaspaModule }; bound: frozen network record. */
  constructor({ config, bound, timeoutMs = 15000 }) {
    this.config = config;
    this.bound = bound;
    this.timeoutMs = timeoutMs;
    this.session = null;
    this.connecting = null;
  }

  async _connect() {
    if (this.session) return this.session;
    if (!this.connecting) {
      this.connecting = chain
        .connectVerified(this.config)
        .then((s) => {
          this.session = s;
          this.connecting = null;
          return s;
        })
        .catch((e) => {
          this.connecting = null;
          throw e;
        });
    }
    return this.connecting;
  }

  async _drop() {
    const s = this.session;
    this.session = null;
    if (s && s.rpc) {
      try {
        await s.rpc.disconnect();
      } catch {
        /* already gone */
      }
    }
  }

  /*
   * One observation batch: node identity → virtual DAA score → UTXO
   * entries of each address. Returns
   *   { node: { networkId, serverVersion, isSynced, hasUtxoIndex },
   *     virtualDaaScore: BigInt, entries: Map<address, normalizedEntry[]>,
   *     observedAt }.
   */
  async observe(addresses, { budgetMs } = {}) {
    const ms = Math.max(1000, Math.min(this.timeoutMs, budgetMs ?? this.timeoutMs));
    let session;
    try {
      session = await withTimeout(this._connect(), ms, "node connect");
    } catch (e) {
      await this._drop();
      refuse("NODE_UNAVAILABLE", String(e && e.message ? e.message : e).slice(0, 160));
    }
    try {
      const serverInfo = await withTimeout(session.rpc.getServerInfo(), ms, "getServerInfo");
      const node = verifyNodeIdentity(this.bound, serverInfo); // RETRY-classed refusals
      const virtualDaaScore = await withTimeout(chain.getVirtualDaaScore(session.rpc), ms, "getBlockDagInfo");
      if (typeof virtualDaaScore !== "bigint" || virtualDaaScore < 0n) refuse("RPC_MALFORMED", "virtualDaaScore");
      const entries = new Map();
      for (const address of addresses) {
        const list = await withTimeout(chain.getAddressUtxos(session.rpc, address), ms, "getUtxosByAddresses");
        entries.set(address, list.map(normalizeEntry));
      }
      return Object.freeze({ node, virtualDaaScore, entries, observedAt: new Date().toISOString() });
    } catch (e) {
      if (e instanceof FacilitatorRefusal) {
        if (e.code === "NODE_UNAVAILABLE" || e.code === "NODE_UNSYNCED" || e.code === "UTXO_INDEX_UNAVAILABLE") await this._drop();
        throw e;
      }
      await this._drop();
      refuse("NODE_UNAVAILABLE", String(e && e.message ? e.message : e).slice(0, 160));
    }
  }

  async close() {
    await this._drop();
  }
}

/* Every chain field the facilitator uses must be present and well-formed;
 * a malformed entry is refused (RPC_MALFORMED) rather than partially trusted. */
function normalizeEntry(u) {
  if (!u || !u.outpoint || typeof u.outpoint.transactionId !== "string" || !/^[0-9a-f]{64}$/.test(u.outpoint.transactionId) || !Number.isInteger(u.outpoint.index) || u.outpoint.index < 0) {
    refuse("RPC_MALFORMED", "utxo entry outpoint");
  }
  if (typeof u.amount !== "bigint" || u.amount < 0n) refuse("RPC_MALFORMED", "utxo entry amount");
  if (typeof u.scriptPublicKeyHex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(u.scriptPublicKeyHex)) refuse("RPC_MALFORMED", "utxo entry scriptPublicKey");
  if (u.covenantId !== null && !(typeof u.covenantId === "string" && /^[0-9a-f]{64}$/.test(u.covenantId))) refuse("RPC_MALFORMED", "utxo entry covenantId");
  if (typeof u.blockDaaScore !== "bigint") refuse("RPC_MALFORMED", "utxo entry blockDaaScore");
  if (typeof u.isCoinbase !== "boolean") refuse("RPC_MALFORMED", "utxo entry isCoinbase");
  return Object.freeze({
    transactionId: u.outpoint.transactionId,
    index: u.outpoint.index,
    amount: u.amount,
    scriptPublicKeyHex: u.scriptPublicKeyHex,
    covenantId: u.covenantId,
    blockDaaScore: u.blockDaaScore,
    isCoinbase: u.isCoinbase
  });
}

module.exports = { NodeSession, normalizeEntry };
