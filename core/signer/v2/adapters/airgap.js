"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — AIR-GAP TRANSPORT adapter
 * (QR / file / clipboard shuttle to the offline CLI keyfile signer).
 *
 * WHAT THIS IS. A new TRANSPORT, not new cryptography and not a new
 * document format — the same decision the mobile architecture already
 * fixed (docs/postlaunch/mobile-architecture-decision.md §4.1, implemented
 * in mobile/www/js/portable/airgap.js). The signer on the other side of
 * the gap is the EXISTING offline signer, `core/signer/adapters/cli`,
 * driven through its OWN closed document schemas:
 *
 *   request  (transactions): policyvault-cli-signing-request/1
 *                            keys ["format","kind","network",
 *                                  "expectedSignerAddress",
 *                                  "unsignedSafeJson","signInputs"]
 *   request  (messages):     the message's exact UTF-8 bytes (the CLI's
 *                            `sign-message --message-file` input) — no
 *                            new format is invented for this direction.
 *   response (transactions): policyvault-cli-signer-signed-transaction/1
 *   response (messages):     policyvault-cli-signer-signature/1
 *
 * Nothing here re-implements signing, hashing of transactions, or
 * verification. The adapter frames, hands over, parses, and BINDS.
 *
 * ------------------------------------------------------------------
 * CAPABILITY LIMITATIONS — stated, exported, and testable
 * ------------------------------------------------------------------
 * These are exposed as `adapter.limitations` (a non-interface property;
 * consumers still gate on the DECLARED descriptor) and as the exported
 * AIRGAP_LIMITATIONS constant, so a UI can render them verbatim instead
 * of a developer discovering them later:
 *
 *  L1  NO NONCE CROSSES THE GAP. The frozen CLI request schema carries no
 *      request id and no nonce, and a frozen schema is never mutated in
 *      place. The v2 nonce is therefore a LOCAL single-use token only
 *      (enforced by the core's replay guard), and the `requestId` the CLI
 *      prints in its response is the OFFLINE SIGNER'S OWN id, unrelated
 *      to this request — so this adapter deliberately does NOT treat it
 *      as a binding. Carrying the v2 nonce across the gap requires a NEW
 *      document version (policyvault-cli-signing-request/3), which is an
 *      additive change with its own review, not a silent extension here.
 *
 *  L2  BINDING IS BY PAYLOAD IDENTITY, NOT BY REQUEST IDENTITY. A message
 *      response is bound by `messageSha256` (which the CLI already emits)
 *      equalling the request's payload digest; a transaction response is
 *      bound by the returned serialization re-deriving the SAME
 *      transaction id as the unsigned bytes (Kaspa txids exclude
 *      signature scripts), which the v2 core performs through the
 *      injected `deriveTransactionId`. CONSEQUENCE: a genuine response to
 *      an EARLIER, BYTE-IDENTICAL request cannot be distinguished from a
 *      fresh one at this boundary. Because every PolicyVault transaction
 *      spends specific UTXOs, a replayed signature is for a transaction
 *      that is either already accepted or already dead on the DAG — but
 *      this adapter does not claim to detect it, and L1's document
 *      version is the fix.
 *
 *  L3  NO PRE-FLIGHT PROBE. An offline signer cannot be interrogated
 *      before the document crosses the gap, so `probeCapabilities()`
 *      honestly returns `probed: false` with a reason. A consumer passing
 *      `requireProbedCapabilities: true` therefore refuses this adapter —
 *      which is the correct outcome, not a bug.
 *
 *  L4  NO LOCAL SIGNATURE VERIFICATION. This module verifies no Schnorr
 *      bytes and derives no sighash (the core holds no cryptography by
 *      design). Authority remains where it already is: the server's
 *      finalizer re-derives the frozen txid and runs a VM preflight before
 *      broadcast, and the covenant is the security boundary.
 *
 * Pure CommonJS, browser-portable. Zero external dependencies. All I/O is
 * INJECTED (`exchange`) — this module never opens a camera, a file, or a
 * socket.
 */

const { SIGNER_INTERFACE_VERSION_V2, SignerErrorCodesV2, signerErrorV2 } = require("../errors");
const { SIGHASH_ALL, TRANSACTION_FORMATS, SIGNER_NETWORKS, buildResponseEnvelope, sha256Hex } = require("../interface");

/* The CLI signer's OWN frozen document formats — restated, never
 * redefined. Any mismatch fails closed (unknown versions never route to a
 * default). */
const SIGNING_REQUEST_FORMAT = "policyvault-cli-signing-request/1";
const SIGNING_REQUEST_KEYS = Object.freeze(["format", "kind", "network", "expectedSignerAddress", "unsignedSafeJson", "signInputs"]);
const SIGNED_TX_FORMAT = "policyvault-cli-signer-signed-transaction/1";
const SIGNED_TX_KEYS = Object.freeze(["format", "requestId", "kind", "network", "address", "signedSafeJson"]);
const SIGNATURE_FORMAT = "policyvault-cli-signer-signature/1";
const SIGNATURE_KEYS = Object.freeze(["format", "requestId", "kind", "network", "address", "publicKey", "scheme", "messageSha256", "signature"]);

const MAX_RESPONSE_CHARS = 2097152;

const AIRGAP_LIMITATIONS = Object.freeze([
  Object.freeze({
    id: "no-nonce-across-the-gap",
    summary: "The frozen offline-signer document schema carries no request id or nonce, so the v2 nonce is a LOCAL single-use token only and the requestId the signer prints is its own, not this request's.",
    consequence: "Request-identity binding stops at this device; payload-identity binding (below) is what crosses the gap.",
    fix: "A new additive document version (policyvault-cli-signing-request/3) carrying the request id and nonce."
  }),
  Object.freeze({
    id: "payload-identity-binding-only",
    summary: "Responses are bound by payload identity — messageSha256 for messages, re-derived transaction id for transactions — not by request identity.",
    consequence: "A genuine response to an earlier, byte-identical request is indistinguishable from a fresh one at this boundary.",
    fix: "Same as above; until then the local replay guard refuses duplicate settlement within a session, and every PolicyVault transaction spends specific UTXOs."
  }),
  Object.freeze({
    id: "no-preflight-probe",
    summary: "An offline signer cannot be interrogated before the document crosses the gap.",
    consequence: 'probeCapabilities() reports probed:false with a reason; a consumer requiring probed capabilities refuses this adapter.',
    fix: "None available for a genuinely offline signer — the refusal is the correct behaviour."
  }),
  Object.freeze({
    id: "no-local-signature-verification",
    summary: "This adapter verifies no signature bytes and derives no sighash.",
    consequence: "Acceptance of the signature rests on the downstream finalizer's frozen-txid re-derivation and VM preflight, and on consensus.",
    fix: "Unchanged by design: the core holds no cryptography."
  })
]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function invalid(message) {
  return signerErrorV2(SignerErrorCodesV2.REQUEST_INVALID, message);
}

function transportFault(message, cause) {
  return signerErrorV2(SignerErrorCodesV2.PROVIDER_ERROR, `air-gap transport: ${message}`, cause === undefined ? undefined : { cause });
}

function bindingMismatch(message, details) {
  return signerErrorV2(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, `air-gap response: ${message}`, details ? { details } : undefined);
}

/* Deterministic, closed-key document emission — same key order every
 * time, so the framed bytes are reproducible and reviewable. */
function emitDocument(keys, values) {
  const doc = {};
  for (const key of keys) doc[key] = values[key];
  return doc;
}

/*
 * Build the offline signer's transaction request document from a v2
 * request. The signInputs are COPIED from the request (already asserted
 * canonical by the v2 core) — never rebuilt, never trimmed.
 */
function buildSigningRequestDocument(request) {
  if (!isPlainObject(request) || request.kind !== "sign-transaction") {
    throw invalid("air-gap signing-request documents are built from sign-transaction requests only");
  }
  return emitDocument(SIGNING_REQUEST_KEYS, {
    format: SIGNING_REQUEST_FORMAT,
    kind: "sign-transaction",
    network: request.network,
    expectedSignerAddress: request.expectedSignerAddress,
    unsignedSafeJson: request.unsignedSafeJson,
    signInputs: request.signInputs.map((si) => ({ index: si.index, sighashType: si.sighashType }))
  });
}

function parseResponseText(text) {
  if (typeof text !== "string" || !text.trim()) throw transportFault("the shuttle returned nothing");
  if (text.length > MAX_RESPONSE_CHARS) throw transportFault(`the shuttle returned ${text.length} characters, above the ${MAX_RESPONSE_CHARS} limit`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw transportFault("the scanned/loaded response is not valid JSON", e);
  }
  if (!isPlainObject(parsed)) throw transportFault("the response document must be a JSON object");
  return parsed;
}

function assertClosedKeys(doc, keys, what) {
  for (const key of Object.keys(doc)) {
    if (!keys.includes(key)) throw bindingMismatch(`${what} carries unknown key ${JSON.stringify(key)} — the schema is closed; refusing`);
  }
  for (const key of keys) {
    if (!(key in doc)) throw bindingMismatch(`${what} is missing required key ${JSON.stringify(key)}`);
  }
}

/*
 * Validate the offline signer's SIGNED-TRANSACTION document against the
 * request it is supposed to answer, and return the v2 result payload.
 * Note what is deliberately NOT checked: doc.requestId (see L1).
 */
function validateSignedTransactionDocument(request, doc) {
  assertClosedKeys(doc, SIGNED_TX_KEYS, "signed-transaction response");
  if (doc.format !== SIGNED_TX_FORMAT) {
    throw bindingMismatch(`format ${JSON.stringify(String(doc.format).slice(0, 64))} is not ${JSON.stringify(SIGNED_TX_FORMAT)} — unknown versions fail closed`);
  }
  if (doc.kind !== "sign-transaction") throw bindingMismatch(`kind ${JSON.stringify(String(doc.kind).slice(0, 32))} does not answer a sign-transaction request`);
  if (doc.network !== request.network) {
    throw signerErrorV2(
      SignerErrorCodesV2.WRONG_NETWORK,
      `air-gap response: the offline signer reports network ${JSON.stringify(String(doc.network).slice(0, 32))}, request is bound to ${JSON.stringify(request.network)} — refusing`
    );
  }
  if (doc.address !== request.expectedSignerAddress) {
    throw signerErrorV2(
      SignerErrorCodesV2.ACCOUNT_CHANGED,
      "air-gap response: the offline signer's address is not the identity this request is bound to — discarding the signature"
    );
  }
  if (typeof doc.signedSafeJson !== "string" || !doc.signedSafeJson.trim()) {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "air-gap response: no signed transaction serialization");
  }
  return { signedSafeJson: doc.signedSafeJson };
}

/*
 * Validate the offline signer's SIGNATURE document. `messageSha256` is
 * the load-bearing binding here: it is the digest of the exact bytes the
 * signer says it signed, and it must equal the digest of the exact bytes
 * this request carries.
 */
function validateSignatureDocument(request, doc) {
  assertClosedKeys(doc, SIGNATURE_KEYS, "signature response");
  if (doc.format !== SIGNATURE_FORMAT) {
    throw bindingMismatch(`format ${JSON.stringify(String(doc.format).slice(0, 64))} is not ${JSON.stringify(SIGNATURE_FORMAT)} — unknown versions fail closed`);
  }
  if (doc.kind !== "sign-message") throw bindingMismatch(`kind ${JSON.stringify(String(doc.kind).slice(0, 32))} does not answer a sign-message request`);
  if (request.network !== undefined && doc.network !== request.network) {
    throw signerErrorV2(
      SignerErrorCodesV2.WRONG_NETWORK,
      `air-gap response: the offline signer reports network ${JSON.stringify(String(doc.network).slice(0, 32))}, request is bound to ${JSON.stringify(request.network)} — refusing`
    );
  }
  if (request.expectedSignerAddress !== undefined && doc.address !== request.expectedSignerAddress) {
    throw signerErrorV2(SignerErrorCodesV2.ACCOUNT_CHANGED, "air-gap response: the offline signer's address is not the identity this request is bound to — discarding the signature");
  }
  if (doc.scheme !== request.scheme) {
    throw signerErrorV2(
      SignerErrorCodesV2.UNSUPPORTED_SCHEME,
      `air-gap response: the offline signer used scheme ${JSON.stringify(String(doc.scheme).slice(0, 32))}, request pinned ${JSON.stringify(request.scheme)} — refusing`
    );
  }
  if (doc.messageSha256 !== request.payloadSha256) {
    throw signerErrorV2(
      SignerErrorCodesV2.PAYLOAD_MUTATED,
      "air-gap response: the offline signer signed a message whose digest differs from the message this request carries — the signature is not over the verified bytes; discarding it",
      { details: { expectedSha256: request.payloadSha256, reportedSha256: String(doc.messageSha256).slice(0, 64) } }
    );
  }
  if (typeof doc.signature !== "string") {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "air-gap response: no signature");
  }
  return { signature: doc.signature };
}

/*
 * createAirGapSignerAdapter(options)
 *
 *   provider, label     descriptor identity (defaults "airgap-cli")
 *   transport           "qr-airgap" (default) or "file"
 *   network             the ONE network this shuttle operates on
 *   signerAddress       the offline signer's address CLAIM (the operator
 *                       states which signer is on the other side; the
 *                       core binds every request to it and the response
 *                       document must carry it back)
 *   publicKey           optional public-key CLAIM
 *   exchange            REQUIRED async ({ documentText, document, request })
 *                       -> response text. This is the ONLY I/O seam: the
 *                       platform layer frames it as QR, writes it to a
 *                       file, or shows it for copy/paste.
 *   maxTimeoutMs        longest deadline this shuttle claims (default 30m)
 *   probe               optional probe report override (default: an
 *                       honest probed:false, see L3)
 */
function createAirGapSignerAdapter(options = {}) {
  if (!isPlainObject(options)) throw invalid("createAirGapSignerAdapter options must be a plain object");
  const ALLOWED = ["provider", "label", "transport", "network", "signerAddress", "publicKey", "exchange", "maxTimeoutMs", "probe"];
  for (const key of Object.keys(options)) {
    if (!ALLOWED.includes(key)) throw invalid(`unknown createAirGapSignerAdapter option ${JSON.stringify(key)} — failing closed`);
  }
  const providerId = options.provider === undefined ? "airgap-cli" : options.provider;
  const label = options.label === undefined ? "Offline signer over an air gap" : options.label;
  const transport = options.transport === undefined ? "qr-airgap" : options.transport;
  if (transport !== "qr-airgap" && transport !== "file") {
    throw invalid('air-gap adapters use the "qr-airgap" or "file" transport only — failing closed');
  }
  const network = options.network;
  if (typeof network !== "string" || !SIGNER_NETWORKS.includes(network)) {
    throw invalid(`air-gap adapter requires an operational network (${JSON.stringify(SIGNER_NETWORKS)}) — failing closed`);
  }
  const signerAddress = options.signerAddress;
  if (typeof signerAddress !== "string" || !signerAddress.trim() || signerAddress.length > 256) {
    throw invalid("air-gap adapter requires the offline signer's address — a shuttle must name the signer it is for");
  }
  if (typeof options.exchange !== "function") {
    throw invalid("air-gap adapter requires an exchange({ documentText, document, request }) transport function");
  }
  const maxTimeoutMs = Number.isInteger(options.maxTimeoutMs) ? options.maxTimeoutMs : 1800000; /* 30 minutes */

  const state = { connected: false, abandoned: new Set() };

  function assertNotAbandoned(requestId) {
    if (state.abandoned.has(requestId)) {
      throw signerErrorV2(
        SignerErrorCodesV2.REQUEST_CANCELLED,
        `air-gap exchange ${requestId} was abandoned before the response arrived — refusing to accept a document for a cancelled shuttle`
      );
    }
  }

  const adapter = {
    limitations: AIRGAP_LIMITATIONS,

    describe() {
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
        provider: providerId,
        label,
        kind: "air-gapped",
        schemes: ["schnorr"],
        networks: [network],
        features: {
          messageSigning: true,
          transactionSigning: true,
          specificInputSigning: true,
          multiAccount: false,
          networkSwitching: false,
          accountEvents: false,
          asynchronousApproval: true,
          airGapped: true,
          hardwareDisplay: false
        },
        sighash: { all: true, none: false, single: false, anyoneCanPay: false },
        pskt: { supported: false, roles: [] },
        transactionFormats: [TRANSACTION_FORMATS[0]],
        userPresence: "required",
        transport,
        cancellation: "supported",
        maxTimeoutMs
      };
    },

    /* L3: honest refusal to claim an observation that cannot be made. */
    probeCapabilities() {
      if (options.probe !== undefined) return options.probe;
      return {
        interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
        probed: false,
        reason: "an offline signer cannot be interrogated before the document crosses the gap — capabilities are declared, not observed"
      };
    },

    detect() {
      return typeof options.exchange === "function";
    },

    async connect() {
      state.connected = true;
      return { address: signerAddress, network };
    },

    async disconnect() {
      state.connected = false;
    },

    async getActiveAccount() {
      return state.connected ? { address: signerAddress } : null;
    },

    async getNetwork() {
      return network; /* configured CLAIM — the consumer binds and refuses on mismatch */
    },

    async getPublicKey() {
      if (typeof options.publicKey !== "string" || !options.publicKey.trim()) {
        throw signerErrorV2(
          SignerErrorCodesV2.INVALID_PUBLIC_KEY,
          "no public key is configured for this offline signer — read it from the signer's `identity` command and configure it"
        );
      }
      return options.publicKey;
    },

    async signMessage(request) {
      assertNotAbandoned(request.requestId);
      /* the CLI's message input IS the raw message bytes — no new format */
      const documentText = request.message;
      let responseText;
      try {
        responseText = await options.exchange({ documentText, document: null, request });
      } catch (e) {
        if (e && typeof e.signerCode === "string") throw e;
        throw transportFault((e && e.message) || "the shuttle failed", e);
      }
      assertNotAbandoned(request.requestId);
      const doc = parseResponseText(responseText);
      const result = validateSignatureDocument(request, doc);
      return buildResponseEnvelope(request, result, { signerAddress: doc.address });
    },

    async signTransaction(request) {
      assertNotAbandoned(request.requestId);
      const document = buildSigningRequestDocument(request);
      const documentText = JSON.stringify(document);
      let responseText;
      try {
        responseText = await options.exchange({ documentText, document, request });
      } catch (e) {
        if (e && typeof e.signerCode === "string") throw e;
        throw transportFault((e && e.message) || "the shuttle failed", e);
      }
      assertNotAbandoned(request.requestId);
      const doc = parseResponseText(responseText);
      const result = validateSignedTransactionDocument(request, doc);
      return buildResponseEnvelope(request, result, { signerAddress: doc.address });
    },

    /* Abandoning the shuttle: a response arriving afterwards is refused,
     * which is the only revocation an offline exchange can offer. */
    async cancelSigning(requestId) {
      state.abandoned.add(requestId);
    }
  };

  return adapter;
}

module.exports = {
  createAirGapSignerAdapter,
  buildSigningRequestDocument,
  validateSignedTransactionDocument,
  validateSignatureDocument,
  AIRGAP_LIMITATIONS,
  SIGNING_REQUEST_FORMAT,
  SIGNING_REQUEST_KEYS,
  SIGNED_TX_FORMAT,
  SIGNED_TX_KEYS,
  SIGNATURE_FORMAT,
  SIGNATURE_KEYS,
  SIGHASH_ALL,
  sha256Hex
};
