"use strict";

/*
 * PolicyVault Universal Signer Interface — LIFT: run an existing,
 * conformant interface-v1 adapter behind the v2 contract.
 *
 * WHY A LIFT RATHER THAN A REWRITE. v1 adapters (the production KasWare
 * browser adapter, the offline CLI keyfile signer) are reviewed, tested
 * code whose provider calls are byte-exact reproductions of the shipped
 * flow. Rewriting them for v2 would put every one of those bytes back on
 * the table. The lift instead keeps the v1 adapter EXACTLY as it is and
 * adds, around it, only what v2 introduces:
 *
 *   - a v2 capability descriptor, whose EXTRA declarations the caller
 *     must state EXPLICITLY (sighash, pskt, transaction formats, user
 *     presence, transport, cancellation, maxTimeoutMs). Nothing is
 *     inferred: a lift that guessed "probably SIGHASH_ALL" would be
 *     exactly the silent capability assumption v2 exists to abolish. The
 *     v1 half of the descriptor (provider, label, kind, schemes,
 *     networks, features) is carried over VERBATIM from the v1
 *     descriptor, which the lift re-validates through v1 first.
 *   - a capability PROBE (caller-supplied; a lift cannot invent one).
 *   - v2 -> v1 request translation, and v1 -> v2 response ENVELOPE
 *     construction.
 *
 * HONEST LIMITATION OF A LIFTED ADAPTER (stated here and in the spec).
 * A v1 adapter returns a BARE signature/serialization: it has no
 * vocabulary for the binding fields. The envelope is therefore assembled
 * by the LIFT from the request plus the adapter's own live
 * getActiveAccount() answer. Consequently:
 *
 *   - envelope binding (requestId, nonce, kind, network, scheme, payload
 *     digest) proves the transport between the LIFT and the consumer,
 *     NOT the segment between the lift and the signer;
 *   - `signerAddress` IS a live claim (read from the adapter after the
 *     signature returns) and is genuinely checked;
 *   - detection of "the signer signed a DIFFERENT transaction" therefore
 *     rests on the injected transaction-identity re-derivation
 *     (`deriveTransactionId`) and on the downstream SDK finalizer's
 *     frozen-txid refusal — both of which read the RETURNED bytes and
 *     are unaffected by the lift.
 *
 * A signer that natively speaks v2 (returning its own envelope) gets the
 * stronger property; a lifted v1 signer gets exactly what v1 could
 * prove, plus the new pre-signing gates. Neither is silently upgraded.
 *
 * Pure CommonJS, browser-portable. Zero external dependencies.
 */

const v1 = require("../../interface");
const { SIGNER_INTERFACE_VERSION_V2, SignerErrorCodesV2, signerErrorV2 } = require("../errors");
const {
  SIGHASH_FLAGS,
  TRANSACTION_FORMATS,
  PSKT_ROLES,
  TRANSPORT_KINDS,
  USER_PRESENCE_MODES,
  CANCELLATION_MODES,
  validateCapabilityDescriptorV2,
  buildResponseEnvelope
} = require("../interface");

const V2_ONLY_DECLARATIONS = Object.freeze(["sighash", "pskt", "transactionFormats", "userPresence", "transport", "cancellation", "maxTimeoutMs"]);

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function invalid(message) {
  return signerErrorV2(SignerErrorCodesV2.REQUEST_INVALID, message);
}

/*
 * Translate a v2 request into the v1 request shape the underlying
 * adapter was written against. The requestId is carried over unchanged
 * (both versions use the same 32-hex form) so adapter-side diagnostics
 * and cancellation keep referring to the same request. v2-only fields
 * (nonce, payloadSha256, expiresAtMs, transactionFormat, sighash) are
 * NOT passed down: a v1 adapter's closed request schema would refuse
 * them, and they are enforced by the v2 core on both sides of the call.
 */
function toV1Request(request) {
  if (request.kind === "sign-message") {
    return Object.freeze({
      interfaceVersion: v1.SIGNER_INTERFACE_VERSION,
      requestId: request.requestId,
      kind: "sign-message",
      message: request.message,
      scheme: request.scheme,
      network: request.network,
      expectedSignerAddress: request.expectedSignerAddress,
      createdAtMs: request.createdAtMs
    });
  }
  return Object.freeze({
    interfaceVersion: v1.SIGNER_INTERFACE_VERSION,
    requestId: request.requestId,
    kind: "sign-transaction",
    unsignedSafeJson: request.unsignedSafeJson,
    signInputs: request.signInputs.map((si) => Object.freeze({ index: si.index, sighashType: si.sighashType })),
    network: request.network,
    expectedSignerAddress: request.expectedSignerAddress,
    scheme: request.scheme,
    createdAtMs: request.createdAtMs
  });
}

/*
 * liftV1Adapter(v1Adapter, declarations)
 *
 * `declarations` MUST contain every v2-only field plus `probeCapabilities`
 * (a function returning the probe report for this provider). Unknown keys
 * are refused; missing keys are refused. The result is a v2 adapter that
 * passes validateAdapterV2.
 */
function liftV1Adapter(v1Adapter, declarations) {
  const registration = v1.validateAdapter(v1Adapter); /* the v1 contract still holds */
  const v1Descriptor = registration.descriptor;

  if (!isPlainObject(declarations)) throw invalid("liftV1Adapter requires a declarations object");
  const ALLOWED = [...V2_ONLY_DECLARATIONS, "probeCapabilities", "provider", "label"];
  for (const key of Object.keys(declarations)) {
    if (!ALLOWED.includes(key)) throw invalid(`unknown lift declaration ${JSON.stringify(key)} — failing closed`);
  }
  for (const key of V2_ONLY_DECLARATIONS) {
    if (!(key in declarations)) {
      throw invalid(`lift declaration ${JSON.stringify(key)} is required — a lift never infers a v2 capability from a v1 adapter`);
    }
  }
  if (typeof declarations.probeCapabilities !== "function") {
    throw invalid("lift declaration probeCapabilities must be a function — a lifted adapter must still be probeable (or report probed:false with a reason)");
  }
  /* shape pre-checks with lift-local messages; validateCapabilityDescriptorV2
   * is the authority and runs on the assembled descriptor below */
  if (!isPlainObject(declarations.sighash) || SIGHASH_FLAGS.some((f) => typeof declarations.sighash[f] !== "boolean")) {
    throw invalid(`lift declaration sighash must declare every flag of ${JSON.stringify(SIGHASH_FLAGS)} as a strict boolean`);
  }
  if (!isPlainObject(declarations.pskt) || typeof declarations.pskt.supported !== "boolean" || !Array.isArray(declarations.pskt.roles)) {
    throw invalid(`lift declaration pskt must be { supported: boolean, roles: [...] } (roles from ${JSON.stringify(PSKT_ROLES)})`);
  }
  if (!Array.isArray(declarations.transactionFormats)) {
    throw invalid(`lift declaration transactionFormats must be an array (known: ${JSON.stringify(TRANSACTION_FORMATS)})`);
  }
  if (!USER_PRESENCE_MODES.includes(declarations.userPresence)) {
    throw invalid(`lift declaration userPresence must be one of ${JSON.stringify(USER_PRESENCE_MODES)}`);
  }
  if (!TRANSPORT_KINDS.includes(declarations.transport)) {
    throw invalid(`lift declaration transport must be one of ${JSON.stringify(TRANSPORT_KINDS)}`);
  }
  if (!CANCELLATION_MODES.includes(declarations.cancellation)) {
    throw invalid(`lift declaration cancellation must be one of ${JSON.stringify(CANCELLATION_MODES)}`);
  }

  const descriptor = validateCapabilityDescriptorV2({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    provider: declarations.provider === undefined ? v1Descriptor.provider : declarations.provider,
    label: declarations.label === undefined ? v1Descriptor.label : declarations.label,
    kind: v1Descriptor.kind,
    schemes: [...v1Descriptor.schemes],
    networks: [...v1Descriptor.networks],
    features: { ...v1Descriptor.features },
    sighash: { ...declarations.sighash },
    pskt: { supported: declarations.pskt.supported, roles: [...declarations.pskt.roles] },
    transactionFormats: [...declarations.transactionFormats],
    userPresence: declarations.userPresence,
    transport: declarations.transport,
    cancellation: declarations.cancellation,
    maxTimeoutMs: declarations.maxTimeoutMs
  });

  async function liveSignerAddress() {
    try {
      const account = await v1Adapter.getActiveAccount();
      if (isPlainObject(account) && typeof account.address === "string" && account.address.trim()) return account.address.trim();
    } catch {
      /* the v2 core re-reads the identity itself; a failure here must not
       * masquerade as a successful signature, so fall through to null */
    }
    return null;
  }

  async function sign(request) {
    const downstream = toV1Request(request);
    const raw = request.kind === "sign-message" ? await v1Adapter.signMessage(downstream) : await v1Adapter.signTransaction(downstream);
    const result = request.kind === "sign-message" ? { signature: raw } : { signedSafeJson: raw };
    const signerAddress = await liveSignerAddress();
    return buildResponseEnvelope(request, result, {
      signerAddress: signerAddress === null ? request.expectedSignerAddress === undefined ? null : request.expectedSignerAddress : signerAddress
    });
  }

  const lifted = {
    /* the lifted v1 adapter, exposed for diagnostics and for consumers
     * that still drive the v1 pipeline (both versions stay usable) */
    v1Adapter,
    v1Descriptor,

    describe() {
      return {
        interfaceVersion: descriptor.interfaceVersion,
        provider: descriptor.provider,
        label: descriptor.label,
        kind: descriptor.kind,
        schemes: [...descriptor.schemes],
        networks: [...descriptor.networks],
        features: { ...descriptor.features },
        sighash: { ...descriptor.sighash },
        pskt: { supported: descriptor.pskt.supported, roles: [...descriptor.pskt.roles] },
        transactionFormats: [...descriptor.transactionFormats],
        userPresence: descriptor.userPresence,
        transport: descriptor.transport,
        cancellation: descriptor.cancellation,
        maxTimeoutMs: descriptor.maxTimeoutMs
      };
    },

    probeCapabilities() {
      return declarations.probeCapabilities();
    },

    detect() {
      return v1Adapter.detect();
    },
    connect() {
      return v1Adapter.connect();
    },
    disconnect() {
      return v1Adapter.disconnect();
    },
    getActiveAccount() {
      return v1Adapter.getActiveAccount();
    },
    getNetwork() {
      return v1Adapter.getNetwork();
    },
    getPublicKey() {
      return v1Adapter.getPublicKey();
    }
  };

  if (descriptor.features.messageSigning) lifted.signMessage = (request) => sign(request);
  if (descriptor.features.transactionSigning) lifted.signTransaction = (request) => sign(request);
  if (descriptor.features.accountEvents) lifted.on = (event, cb) => v1Adapter.on(event, cb);
  if (descriptor.cancellation === "supported" || descriptor.features.asynchronousApproval) {
    lifted.cancelSigning = (requestId) => {
      if (typeof v1Adapter.cancelSigning === "function") return v1Adapter.cancelSigning(requestId);
      return undefined; /* nothing to revoke downstream; the v2 core still discards late settlements */
    };
  }

  return lifted;
}

module.exports = { liftV1Adapter, toV1Request, V2_ONLY_DECLARATIONS };
