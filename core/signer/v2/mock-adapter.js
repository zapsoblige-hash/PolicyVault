"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — in-memory mock adapter.
 *
 * A fully conformant TEST adapter (kind "mock") for the v2 contract:
 * capability descriptor + PROBE, identity/network claims, message and
 * transaction signing through BOUND RESPONSE ENVELOPES, events, and the
 * asynchronous-approval lifecycle — with no provider, no network, and no
 * key material anywhere.
 *
 * The "signatures" it returns are DETERMINISTIC PLACEHOLDERS (sha256 of
 * request fields, shaped like the real contract: 128 hex for schnorr).
 * They are NOT cryptographic signatures and verify against nothing. The
 * mock exists to prove interface conformance and to let hostile tests
 * drive every misbehaviour a real signer could exhibit; it must never
 * stand in for a real signer on any funds path.
 *
 * Pure CommonJS, browser-portable. Zero external dependencies.
 */

const crypto = require("crypto");
const { SIGNER_INTERFACE_VERSION_V2 } = require("./errors");
const { SIGHASH_ALL, TRANSACTION_FORMATS, buildResponseEnvelope } = require("./interface");

const DEFAULT_ACCOUNTS = Object.freeze([
  Object.freeze({ address: "kaspatest:mockv2signeraccount0", publicKey: "02" + "ab".repeat(32) }),
  Object.freeze({ address: "kaspatest:mockv2signeraccount1", publicKey: "03" + "cd".repeat(32) })
]);

function hex128(parts) {
  const a = crypto.createHash("sha256").update(parts.join("|"), "utf8").digest("hex");
  const b = crypto.createHash("sha256").update(`${a}|2`, "utf8").digest("hex");
  return a + b; /* 128 hex — the SHAPE of a 64-byte BIP-340 signature */
}

/*
 * createMockSignerAdapterV2(options)
 *
 * Descriptor knobs: provider, label, kind, schemes, networks, features,
 * sighash, pskt, transactionFormats, userPresence, transport,
 * cancellation, maxTimeoutMs.
 *
 * Behaviour knobs:
 *   asyncApproval: true       — sign calls stay pending until control
 *                               approve/reject/cancel settles them
 *   probe                     — the probe report to return (default: a
 *                               truthful report derived from the
 *                               descriptor); `probe: null` reports
 *                               probed:false with a reason
 *
 * control (test surface):
 *   approve(id) / reject(id) / listPending()
 *   setActiveAccount(address) / setNetwork(network) / lock() / unlock()
 *   failNextSignWith(errorLike)
 *   duringSign = (request) => {}          hook run when a sign starts
 *   mutateEnvelope = (env, request) => e  last-chance envelope rewrite
 *                                         (how hostile tests simulate a
 *                                         lying or substituting signer)
 *   signedPayloadFor = (request) => str   what the "signed" transaction
 *                                         serialization contains
 *   invocations / cancelled
 */
function createMockSignerAdapterV2(options = {}) {
  const providerId = options.provider || "mockv2";
  const label = options.label || "Mock signer v2";
  const kind = options.kind || "mock";
  const schemes = Object.freeze([...(options.schemes || ["schnorr"])]);
  const networks = Object.freeze([...(options.networks || ["testnet-10"])]);
  const accounts = Object.freeze([...(options.accounts || DEFAULT_ACCOUNTS)]);
  const asyncApproval = options.asyncApproval === true;

  const features = Object.freeze({
    messageSigning: true,
    transactionSigning: true,
    specificInputSigning: true,
    multiAccount: accounts.length > 1,
    networkSwitching: false,
    accountEvents: true,
    asynchronousApproval: asyncApproval,
    airGapped: false,
    hardwareDisplay: false,
    ...(options.features || {})
  });

  const sighash = Object.freeze({ all: true, none: false, single: false, anyoneCanPay: false, ...(options.sighash || {}) });
  const pskt = Object.freeze(options.pskt ? { supported: options.pskt.supported, roles: [...(options.pskt.roles || [])] } : { supported: false, roles: [] });
  const transactionFormats = Object.freeze([...(options.transactionFormats || (features.transactionSigning ? [TRANSACTION_FORMATS[0]] : []))]);
  const userPresence = options.userPresence || "required";
  const transport = options.transport || "in-page";
  const cancellation = options.cancellation || (asyncApproval ? "supported" : "unsupported");
  const maxTimeoutMs = Number.isInteger(options.maxTimeoutMs) ? options.maxTimeoutMs : 600000;

  const state = {
    connected: true,
    activeIndex: 0,
    network: options.network || networks[0],
    locked: false,
    failNext: null,
    listeners: { accountChanged: [], networkChanged: [] },
    pending: new Map()
  };

  const control = {
    cancelled: [],
    invocations: 0,
    duringSign: null,
    mutateEnvelope: null,
    signedPayloadFor: null,
    listPending() {
      return [...state.pending.keys()];
    },
    approve(requestId) {
      const entry = state.pending.get(requestId);
      if (!entry) throw new Error(`mockv2: no pending signing request ${requestId}`);
      state.pending.delete(requestId);
      entry.resolve(envelopeFor(entry.request));
    },
    reject(requestId) {
      const entry = state.pending.get(requestId);
      if (!entry) throw new Error(`mockv2: no pending signing request ${requestId}`);
      state.pending.delete(requestId);
      entry.reject({ signerCode: "USER_REJECTED", message: "the signer's holder declined the request" });
    },
    setActiveAccount(address) {
      const idx = accounts.findIndex((a) => a.address === address);
      if (idx === -1) throw new Error(`mockv2: unknown account ${address}`);
      state.activeIndex = idx;
      for (const cb of state.listeners.accountChanged) cb(address);
    },
    setNetwork(network) {
      state.network = network;
      for (const cb of state.listeners.networkChanged) cb(network);
    },
    setConnected(connected) {
      state.connected = connected === true;
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

  function envelopeFor(request) {
    let result;
    if (request.kind === "sign-message") {
      result = { signature: hex128(["mockv2-personal-message", providerId, active().address, request.scheme, request.message]) };
    } else {
      const signed =
        typeof control.signedPayloadFor === "function"
          ? control.signedPayloadFor(request)
          : JSON.stringify({ mockSigned: true, base: request.unsignedSafeJson, signInputs: request.signInputs.map((si) => ({ ...si })) });
      result = { signedSafeJson: signed };
    }
    const envelope = buildResponseEnvelope(request, result, { signerAddress: active().address });
    if (typeof control.mutateEnvelope === "function") {
      const mutated = control.mutateEnvelope({ ...envelope, result: { ...result } }, request);
      return mutated === undefined ? envelope : mutated;
    }
    return envelope;
  }

  function startSign(request) {
    if (state.locked) throw { signerCode: "SIGNER_LOCKED", message: "mockv2 signer is locked" };
    if (state.failNext) {
      const failure = state.failNext;
      state.failNext = null;
      throw failure;
    }
    control.invocations += 1;
    if (typeof control.duringSign === "function") control.duringSign(request);
    if (!asyncApproval) return Promise.resolve(envelopeFor(request));
    return new Promise((resolve, reject) => {
      state.pending.set(request.requestId, { request, resolve, reject });
    });
  }

  const adapter = {
    control,

    describe() {
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
        provider: providerId,
        label,
        kind,
        schemes: [...schemes],
        networks: [...networks],
        features: { ...features },
        sighash: { ...sighash },
        pskt: { supported: pskt.supported, roles: [...pskt.roles] },
        transactionFormats: [...transactionFormats],
        userPresence,
        transport,
        cancellation,
        maxTimeoutMs
      };
    },

    /* A truthful probe by default: exactly what this mock implements. */
    probeCapabilities() {
      if (options.probe === null) {
        return { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: false, reason: "mockv2 configured as unprobeable" };
      }
      if (options.probe !== undefined) return options.probe;
      const methods = ["signMessage", "signTransaction", "getNetwork", "getActiveAccount", "getPublicKey"];
      if (typeof adapter.cancelSigning === "function") methods.push("cancelSigning");
      if (typeof adapter.on === "function") methods.push("on");
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
        probed: true,
        methods,
        sighash: { ...sighash },
        pskt: { supported: pskt.supported, roles: [...pskt.roles] },
        transactionFormats: [...transactionFormats],
        network: state.network
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
      if (!state.connected) throw { signerCode: "SIGNER_DISCONNECTED", message: "mockv2 signer is not connected" };
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
      control.cancelled.push(requestId);
      const entry = state.pending.get(requestId);
      if (entry) {
        state.pending.delete(requestId);
        entry.reject(new Error("mockv2: signing request cancelled"));
      }
    }
  };

  if (cancellation !== "supported" && features.asynchronousApproval !== true) {
    /* a synchronous signer with no revocation channel must not pretend to
     * have one: remove the method so validateAdapterV2 sees the truth */
    delete adapter.cancelSigning;
  }

  return adapter;
}

module.exports = { createMockSignerAdapterV2, DEFAULT_ACCOUNTS, SIGHASH_ALL };
