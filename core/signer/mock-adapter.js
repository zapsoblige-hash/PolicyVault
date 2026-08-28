"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — in-memory mock adapter.
 *
 * A fully conformant TEST adapter (kind "mock"): it exercises every
 * contract surface — capability descriptor, identity/network reporting,
 * message + transaction signing, events, and the asynchronous-approval
 * lifecycle — without any provider, network, or key material.
 *
 * The "signatures" it returns are DETERMINISTIC PLACEHOLDERS (sha512 of
 * request fields), shaped exactly like the real contract (128-hex for
 * schnorr). They are NOT cryptographic signatures and verify against
 * nothing; the mock exists to prove interface conformance, never to
 * stand in for a real signer on any funds path. No private keys exist
 * anywhere in this module — structurally none are needed, which is the
 * point of the interface.
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from
 * server/ or sdk/.
 */

const crypto = require("crypto");
const { SIGNER_INTERFACE_VERSION } = require("./errors");

const DEFAULT_ACCOUNTS = Object.freeze([
  Object.freeze({ address: "kaspatest:mocksigneraccount0", publicKey: "02" + "ab".repeat(32) }),
  Object.freeze({ address: "kaspatest:mocksigneraccount1", publicKey: "03" + "cd".repeat(32) })
]);

function deterministicHex128(parts) {
  return crypto.createHash("sha512").update(parts.join("|"), "utf8").digest("hex"); // 64 bytes -> 128 hex
}

/*
 * createMockSignerAdapter(options):
 *   provider, label            — descriptor identity (defaults "mock" / "Mock signer")
 *   schemes                    — declared schemes (default ["schnorr"])
 *   networks                   — declared networks (default ["testnet-10"])
 *   network                    — initial live network (default networks[0])
 *   features                   — feature overrides merged over the defaults
 *   accounts                   — [{ address, publicKey }] (defaults provided)
 *   asyncApproval: true        — signing calls stay PENDING until
 *                                control.approve/reject/cancelSigning settles them
 *
 * Returns a PLAIN OBJECT adapter (methods close over internal state, so
 * tests may spread/override/delete members to build broken-contract
 * variants) plus a `control` test surface:
 *   control.approve(requestId) / control.reject(requestId)
 *   control.listPending()      — pending async requestIds
 *   control.cancelled          — requestIds cancelled via cancelSigning
 *   control.invocations        — sign calls that reached the provider
 *   control.setActiveAccount(address) / control.setNetwork(network)
 *   control.lock() / control.unlock()
 *   control.failNextSignWith(errorLike)
 *   control.duringSign = (request) => {}  — hook run when a sign call starts
 */
function createMockSignerAdapter(options = {}) {
  const providerId = options.provider || "mock";
  const label = options.label || "Mock signer";
  const schemes = Object.freeze([...(options.schemes || ["schnorr"])]);
  const networks = Object.freeze([...(options.networks || ["testnet-10"])]);
  const accounts = Object.freeze([...(options.accounts || DEFAULT_ACCOUNTS)]);
  const asyncApproval = options.asyncApproval === true;

  const features = Object.freeze({
    messageSigning: true,
    transactionSigning: true,
    specificInputSigning: true,
    multiAccount: accounts.length > 1,
    networkSwitching: true,
    accountEvents: true,
    asynchronousApproval: asyncApproval,
    airGapped: false,
    hardwareDisplay: false,
    ...(options.features || {})
  });

  const state = {
    connected: false,
    activeIndex: 0,
    network: options.network || networks[0],
    locked: false,
    failNext: null,
    listeners: { accountChanged: [], networkChanged: [] },
    pending: new Map() // requestId -> { request, resolve, reject }
  };

  const control = {
    cancelled: [],
    invocations: 0,
    duringSign: null,
    listPending() {
      return [...state.pending.keys()];
    },
    approve(requestId) {
      const entry = state.pending.get(requestId);
      if (!entry) throw new Error(`mock: no pending signing request ${requestId}`);
      state.pending.delete(requestId);
      entry.resolve(resultFor(entry.request));
    },
    reject(requestId) {
      const entry = state.pending.get(requestId);
      if (!entry) throw new Error(`mock: no pending signing request ${requestId}`);
      state.pending.delete(requestId);
      entry.reject({ signerCode: "USER_REJECTED", message: "the signer's holder declined the request" });
    },
    setActiveAccount(address) {
      const idx = accounts.findIndex((a) => a.address === address);
      if (idx === -1) throw new Error(`mock: unknown account ${address}`);
      state.activeIndex = idx;
      for (const cb of state.listeners.accountChanged) cb(address);
    },
    setNetwork(network) {
      state.network = network;
      for (const cb of state.listeners.networkChanged) cb(network);
    },
    lock() {
      state.locked = true;
    },
    unlock() {
      state.locked = false;
    },
    failNextSignWith(errorLike) {
      state.failNext = errorLike;
    }
  };

  function active() {
    return accounts[state.activeIndex];
  }

  function resultFor(request) {
    if (request.kind === "sign-message") {
      return deterministicHex128(["mock-personal-message", providerId, active().address, request.scheme, request.message]);
    }
    /* sign-transaction: a non-empty string simulating the signed Safe
     * JSON serialization (base bytes echoed VERBATIM — the mock never
     * rewrites the frozen serialization it was handed). */
    return JSON.stringify({
      mockSigned: true,
      requestId: request.requestId,
      signedBy: active().address,
      signInputs: request.signInputs,
      base: request.unsignedSafeJson
    });
  }

  function startSign(request) {
    if (state.locked) {
      throw { signerCode: "SIGNER_LOCKED", message: "mock signer is locked" };
    }
    if (state.failNext) {
      const failure = state.failNext;
      state.failNext = null;
      throw failure;
    }
    control.invocations += 1;
    if (typeof control.duringSign === "function") control.duringSign(request);
    if (!asyncApproval) {
      return Promise.resolve(resultFor(request));
    }
    return new Promise((resolve, reject) => {
      state.pending.set(request.requestId, { request, resolve, reject });
    });
  }

  const adapter = {
    control,

    describe() {
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION,
        provider: providerId,
        label,
        kind: "mock",
        schemes: [...schemes],
        networks: [...networks],
        features: { ...features }
      };
    },

    detect() {
      return true;
    },

    async connect() {
      state.connected = true;
      return { address: active().address, network: state.network };
    },

    async disconnect() {
      state.connected = false;
    },

    async getActiveAccount() {
      return state.connected ? { address: active().address } : null;
    },

    async getNetwork() {
      return state.network;
    },

    async getPublicKey() {
      if (!state.connected) {
        throw { signerCode: "SIGNER_DISCONNECTED", message: "mock signer is not connected" };
      }
      return active().publicKey;
    },

    on(event, cb) {
      if (state.listeners[event]) state.listeners[event].push(cb);
    },

    async signMessage(request) {
      return startSign(request);
    },

    async signTransaction(request) {
      return startSign(request);
    },

    async cancelSigning(requestId) {
      const entry = state.pending.get(requestId);
      control.cancelled.push(requestId);
      if (entry) {
        state.pending.delete(requestId);
        entry.reject(new Error("mock: signing request cancelled")); // discarded by the core after timeout settlement
      }
    }
  };

  return adapter;
}

module.exports = { createMockSignerAdapter, DEFAULT_ACCOUNTS };
