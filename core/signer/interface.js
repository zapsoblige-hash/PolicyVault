"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — the adapter contract.
 *
 * PolicyVault is NOT a wallet and never becomes one: private keys live
 * inside EXTERNAL signers (browser extensions, mobile wallets, hardware
 * devices, HSMs, MPC quorums, institutional platforms, agent runtimes).
 * This module defines the one stable boundary through which PolicyVault
 * talks to any of them:
 *
 *   frozen bytes / server-issued message  ->  external signer  ->  signature
 *
 * Structural non-custody: the vocabulary below contains NO capability, no
 * request field and no response field through which secret material (seed
 * phrase, private key, wallet backup) could be requested, declared, or
 * returned. Responses are validated to their exact expected shape; an
 * adapter has nowhere to put a secret even if it tried.
 *
 * Fail-closed rules (interface-wide):
 *   - unknown interface version        -> INTERFACE_VERSION_UNSUPPORTED
 *   - unknown capability value/key     -> registration REFUSED (PROTOCOL_VIOLATION)
 *   - unknown error code from adapter  -> PROTOCOL_VIOLATION (errors.js)
 *   - unknown request kind / scheme    -> REQUEST_INVALID / UNSUPPORTED_SCHEME
 *   - live network mismatch            -> WRONG_NETWORK
 *   - identity change around signing   -> ACCOUNT_CHANGED
 * Nothing unknown is ever routed to a default.
 *
 * Identity boundary (standing project rule): everything an adapter reports
 * about identity (address, public key, network) is a CLAIM. Proof is
 * established only by cryptographic verification of a signature over a
 * core/server-issued challenge, performed by the consumer that holds the
 * verifier (kaspa-wasm in the SDK/server — reference implementation:
 * server/src/auth.js HostedAuthService.verify). This module transports
 * claims and validates shapes; it deliberately contains NO cryptography.
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from
 * server/ or sdk/ (only node:crypto for request-id entropy).
 */

const crypto = require("crypto");
const {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  SignerError,
  signerError,
  normalizeAdapterFailure
} = require("./errors");

/* ------------------------------------------------------------------ */
/* v1 closed vocabularies                                              */
/* ------------------------------------------------------------------ */

/* Signature schemes an adapter may OFFER. `schnorr` (BIP-340, 64-byte
 * signatures) is the only scheme with a defined v1 response contract —
 * matching Kaspa PubKey accounts and the hosted auth v1 posture. `ecdsa`
 * exists in the vocabulary so Tangem-class adapters can DECLARE it
 * truthfully and consumers can REFUSE it fail-closed; v1 defines no
 * verified ECDSA response contract (see validateSignatureResponse). */
const SIGNATURE_SCHEMES = Object.freeze(["schnorr", "ecdsa"]);

/* Networks the interface can express (mirrors sdk/src/address-identity.js
 * PREFIX_BY_NETWORK — the Gate R operational set). New networks require a
 * new interface version; unknown values are refused. */
const SIGNER_NETWORKS = Object.freeze(["mainnet", "testnet-10"]);

/* Adapter deployment kinds (target catalogue of the v1 spec). */
const ADAPTER_KINDS = Object.freeze([
  "browser-extension", // e.g. KasWare
  "mobile", // deep-link / relay wallet apps
  "hardware", // device-held keys with on-device display
  "air-gapped", // offline request/response shuttle
  "cli", // operator command-line signer
  "hsm", // organization-controlled hardware security module
  "mpc", // multi-party-computation / threshold quorum
  "institutional", // custody-platform policy-engine approval
  "agent", // automated agent runtime holding its own delegate key
  "mock" // in-memory conformance/test adapter
]);

/* Capability feature flags. EVERY key must be declared explicitly with a
 * boolean — no defaults, no omissions, no extras (fail closed both ways).
 * Only some features bind required methods in v1 (see REQUIRED_METHODS /
 * FEATURE_METHODS); the rest are declarative negotiation/UX facts. */
const CAPABILITY_FEATURES = Object.freeze([
  "messageSigning", // can sign personal messages (auth challenges)
  "transactionSigning", // can sign transactions
  "specificInputSigning", // can sign exactly the named inputs (v1 tx requests REQUIRE this)
  "multiAccount", // exposes/switches multiple accounts
  "networkSwitching", // can switch networks (declarative in v1 — no method bound yet)
  "accountEvents", // emits accountChanged / networkChanged events
  "asynchronousApproval", // approval settles out-of-band (mobile push, device button, quorum, policy engine)
  "airGapped", // request/response cross an offline boundary
  "hardwareDisplay" // the signer shows the payload on trusted hardware
]);

/* Signing-request kinds. */
const REQUEST_KINDS = Object.freeze(["sign-message", "sign-transaction"]);

/* Signing lifecycle states emitted through executeSigning's onTransition.
 * CREATED is implicit at request creation; exactly one terminal state is
 * ever emitted per execution (late provider settlements are discarded). */
const SIGNING_STATES = Object.freeze([
  "REFUSED", // terminal — a fail-closed gate refused before the signer was invoked
  "SUBMITTED", // the external signer has been invoked; approval pending
  "APPROVED", // terminal — signature returned and validated
  "REJECTED", // terminal — the signer's holder declined
  "TIMED_OUT", // terminal — the approval deadline elapsed; cancelled fail-closed
  "FAILED" // terminal — provider/protocol/validation failure
]);

/* The ONLY sighash type this application ever emits (SIG_HASH_ALL) —
 * mirrors web/app-v4.js assertCanonicalSignInputs and the frozen request
 * contract. */
const SIGHASH_ALL = 1;

/* Adapter methods required unconditionally. */
const REQUIRED_METHODS = Object.freeze([
  "describe",
  "detect",
  "connect",
  "disconnect",
  "getActiveAccount",
  "getNetwork",
  "getPublicKey"
]);

/* Feature -> additionally-required method(s). A declared feature without
 * its backing method is a contract breach and the adapter is refused. */
const FEATURE_METHODS = Object.freeze({
  messageSigning: Object.freeze(["signMessage"]),
  transactionSigning: Object.freeze(["signTransaction"]),
  asynchronousApproval: Object.freeze(["cancelSigning"]),
  accountEvents: Object.freeze(["on"])
});

const PROVIDER_ID_RE = /^[a-z][a-z0-9-]{1,31}$/;
const SCHNORR_SIG_RE = /^[0-9a-f]{128}$/; // 64-byte BIP-340 — same gate as server/src/auth.js SCHNORR_SIG_HEX
const MAX_MESSAGE_CHARS = 16384;
const MAX_SAFE_JSON_CHARS = 1048576;

function violation(message, details) {
  return signerError(SignerErrorCodes.PROTOCOL_VIOLATION, message, details ? { details } : undefined);
}

function invalidRequest(message, details) {
  return signerError(SignerErrorCodes.REQUEST_INVALID, message, details ? { details } : undefined);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function uniqueKnownList(value, allowed, what) {
  if (!Array.isArray(value) || value.length === 0) {
    throw violation(`capability descriptor ${what} must be a non-empty array`);
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw violation(`capability descriptor ${what} contains unknown value ${JSON.stringify(item)} — not in the ${SIGNER_INTERFACE_VERSION} vocabulary; refusing`, { unknownValue: String(item) });
    }
    if (seen.has(item)) throw violation(`capability descriptor ${what} lists ${JSON.stringify(item)} more than once`);
    seen.add(item);
  }
  return Object.freeze([...value]);
}

/* ------------------------------------------------------------------ */
/* Capability descriptor validation                                    */
/* ------------------------------------------------------------------ */

/*
 * Validates an adapter-provided capability descriptor against the v1
 * schema and returns a deep-frozen normalized copy. ANY unknown key,
 * unknown value, missing field, or wrong type refuses the descriptor —
 * unknown capabilities are never ignored and never defaulted.
 */
function validateCapabilityDescriptor(desc) {
  if (!isPlainObject(desc)) throw violation("capability descriptor must be a plain object");

  if (desc.interfaceVersion !== SIGNER_INTERFACE_VERSION) {
    throw signerError(
      SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
      `capability descriptor declares interface version ${JSON.stringify(desc.interfaceVersion)}; this core implements exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION)} — failing closed (no downgrade, no guessing)`
    );
  }

  const EXPECTED_KEYS = ["interfaceVersion", "provider", "label", "kind", "schemes", "networks", "features"];
  for (const key of Object.keys(desc)) {
    if (!EXPECTED_KEYS.includes(key)) {
      throw violation(`capability descriptor carries unknown key ${JSON.stringify(key)} — refusing (closed schema)`);
    }
  }
  for (const key of EXPECTED_KEYS) {
    if (!(key in desc)) throw violation(`capability descriptor is missing required key ${JSON.stringify(key)}`);
  }

  if (typeof desc.provider !== "string" || !PROVIDER_ID_RE.test(desc.provider)) {
    throw violation("capability descriptor provider must match /^[a-z][a-z0-9-]{1,31}$/");
  }
  if (typeof desc.label !== "string" || !desc.label.trim() || desc.label.length > 64) {
    throw violation("capability descriptor label must be a non-empty string of at most 64 characters");
  }
  if (typeof desc.kind !== "string" || !ADAPTER_KINDS.includes(desc.kind)) {
    throw violation(`capability descriptor kind ${JSON.stringify(desc.kind)} is not a known adapter kind — refusing`, { unknownValue: String(desc.kind) });
  }

  const schemes = uniqueKnownList(desc.schemes, SIGNATURE_SCHEMES, "schemes");
  const networks = uniqueKnownList(desc.networks, SIGNER_NETWORKS, "networks");

  if (!isPlainObject(desc.features)) throw violation("capability descriptor features must be a plain object");
  for (const key of Object.keys(desc.features)) {
    if (!CAPABILITY_FEATURES.includes(key)) {
      throw violation(`capability descriptor features carry unknown feature ${JSON.stringify(key)} — refusing (unknown capabilities are never ignored)`, { unknownValue: key });
    }
  }
  const features = {};
  for (const key of CAPABILITY_FEATURES) {
    if (!(key in desc.features)) {
      throw violation(`capability descriptor features must declare ${JSON.stringify(key)} explicitly (no defaults)`);
    }
    if (typeof desc.features[key] !== "boolean") {
      throw violation(`capability descriptor feature ${JSON.stringify(key)} must be strictly boolean`);
    }
    features[key] = desc.features[key];
  }

  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION,
    provider: desc.provider,
    label: desc.label,
    kind: desc.kind,
    schemes,
    networks,
    features: Object.freeze(features)
  });
}

/* ------------------------------------------------------------------ */
/* Adapter validation + registry                                       */
/* ------------------------------------------------------------------ */

/*
 * Validates an adapter object: its describe() must yield a valid v1
 * capability descriptor, every unconditional method must be present, and
 * every method a declared feature binds must be present. Returns a frozen
 * registration record { adapter, descriptor }. Refusal is structured —
 * an adapter missing required methods or declaring unknown capabilities
 * is REFUSED, never partially accepted.
 */
function validateAdapter(adapter) {
  if (!isPlainObject(adapter) && typeof adapter !== "object") {
    throw violation("adapter must be an object");
  }
  if (adapter === null || typeof adapter.describe !== "function") {
    throw violation("adapter must implement describe()");
  }
  let rawDescriptor;
  try {
    rawDescriptor = adapter.describe();
  } catch (e) {
    throw normalizeAdapterFailure(e, "describe");
  }
  const descriptor = validateCapabilityDescriptor(rawDescriptor);

  const missing = [];
  for (const name of REQUIRED_METHODS) {
    if (typeof adapter[name] !== "function") missing.push(name);
  }
  for (const [feature, methods] of Object.entries(FEATURE_METHODS)) {
    if (descriptor.features[feature]) {
      for (const name of methods) {
        if (typeof adapter[name] !== "function") missing.push(`${name} (required by feature ${feature})`);
      }
    }
  }
  if (missing.length > 0) {
    throw violation(`adapter ${descriptor.provider} is missing required method(s): ${missing.join(", ")} — refusing registration`, { missing });
  }
  return Object.freeze({ adapter, descriptor });
}

/*
 * Registry of validated adapters, keyed by provider id. Registration
 * refuses duplicates; lookup of an unregistered provider fails closed.
 */
class SignerRegistry {
  constructor() {
    this._records = new Map();
  }

  register(adapter) {
    const record = validateAdapter(adapter);
    if (this._records.has(record.descriptor.provider)) {
      throw violation(`a signer adapter with provider id ${JSON.stringify(record.descriptor.provider)} is already registered — refusing duplicate registration`);
    }
    this._records.set(record.descriptor.provider, record);
    return record.descriptor;
  }

  has(providerId) {
    return this._records.has(providerId);
  }

  get(providerId) {
    const record = this._records.get(providerId);
    if (!record) {
      throw signerError(SignerErrorCodes.SIGNER_NOT_FOUND, `no signer adapter registered under provider id ${JSON.stringify(providerId)}`);
    }
    return record;
  }

  list() {
    return Object.freeze([...this._records.values()].map((r) => r.descriptor));
  }
}

/* ------------------------------------------------------------------ */
/* Capability negotiation                                              */
/* ------------------------------------------------------------------ */

/*
 * Consumer-side negotiation: does this descriptor satisfy my
 * requirements? Requirements themselves are validated against the closed
 * vocabularies FIRST — a consumer asking for an unknown scheme, feature,
 * network, or requirement key gets REQUEST_INVALID (thrown), because
 * silently "not matching" an unknown requirement could pass an adapter
 * the consumer meant to constrain.
 *
 * Returns a frozen result:
 *   { ok: true, provider }                       — satisfied
 *   { ok: false, provider, code, missing: [..] } — structured refusal
 * Refusal codes: UNSUPPORTED_SCHEME | UNSUPPORTED_CAPABILITY | WRONG_NETWORK.
 */
function negotiateCapabilities(descriptor, requirements) {
  const desc = validateCapabilityDescriptor(descriptor); // never trust an unvalidated descriptor
  if (!isPlainObject(requirements)) throw invalidRequest("requirements must be a plain object");
  const ALLOWED = ["schemes", "features", "network"];
  for (const key of Object.keys(requirements)) {
    if (!ALLOWED.includes(key)) {
      throw invalidRequest(`unknown requirement key ${JSON.stringify(key)} — the ${SIGNER_INTERFACE_VERSION} negotiation vocabulary is closed; failing closed`);
    }
  }

  const refuse = (code, missing) => Object.freeze({ ok: false, provider: desc.provider, code, missing: Object.freeze([...missing]) });

  if (requirements.schemes !== undefined) {
    const wanted = uniqueRequirementList(requirements.schemes, SIGNATURE_SCHEMES, "schemes");
    const missing = wanted.filter((s) => !desc.schemes.includes(s));
    if (missing.length > 0) return refuse(SignerErrorCodes.UNSUPPORTED_SCHEME, missing);
  }
  if (requirements.features !== undefined) {
    const wanted = uniqueRequirementList(requirements.features, CAPABILITY_FEATURES, "features");
    const missing = wanted.filter((f) => desc.features[f] !== true);
    if (missing.length > 0) return refuse(SignerErrorCodes.UNSUPPORTED_CAPABILITY, missing);
  }
  if (requirements.network !== undefined) {
    if (typeof requirements.network !== "string" || !SIGNER_NETWORKS.includes(requirements.network)) {
      throw invalidRequest(`unknown required network ${JSON.stringify(requirements.network)} — failing closed`);
    }
    if (!desc.networks.includes(requirements.network)) {
      return refuse(SignerErrorCodes.WRONG_NETWORK, [requirements.network]);
    }
  }
  return Object.freeze({ ok: true, provider: desc.provider });
}

function uniqueRequirementList(value, allowed, what) {
  if (!Array.isArray(value) || value.length === 0) {
    throw invalidRequest(`requirement ${what} must be a non-empty array`);
  }
  const out = [];
  for (const item of value) {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw invalidRequest(`requirement ${what} contains unknown value ${JSON.stringify(item)} — failing closed`);
    }
    if (!out.includes(item)) out.push(item);
  }
  return out;
}

/* Throwing variant for consumers that treat an unsatisfied requirement as
 * a hard refusal. */
function requireCapabilities(descriptor, requirements) {
  const result = negotiateCapabilities(descriptor, requirements);
  if (!result.ok) {
    throw signerError(result.code, `adapter ${result.provider} does not satisfy required capabilities: ${result.missing.join(", ")}`, {
      details: { missing: [...result.missing] }
    });
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* Provider public-key normalization                                   */
/* ------------------------------------------------------------------ */

/*
 * Canonical provider-pubkey normalization — the exact rules of
 * web/wallet.js normalizePublicKeyToXOnly, restated here so every future
 * adapter host (browser, CLI, server-side agent) shares ONE
 * implementation. Exactly two provider encodings are accepted:
 *   - 64-hex x-only (BIP-340)                -> canonicalized (trim, lowercase)
 *   - 66-hex compressed secp256k1 (02/03+X)  -> X
 * Everything else fails closed with INVALID_PUBLIC_KEY (including 65-byte
 * uncompressed 04-keys). Error messages carry only the value's SHAPE,
 * never the raw malformed string. NOTE: the result is still a CLAIM —
 * identity proof requires signature verification by the consumer.
 */
function normalizePublicKeyToXOnly(value, source) {
  const label = source || "signer provider";
  if (typeof value !== "string" || !value.trim()) {
    throw signerError(SignerErrorCodes.INVALID_PUBLIC_KEY, `${label} returned no public key`);
  }
  const hex = value.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hex)) return hex;
  if (/^0[23][0-9a-f]{64}$/.test(hex)) return hex.slice(2);
  if (/^04[0-9a-f]{128}$/.test(hex)) {
    throw signerError(SignerErrorCodes.INVALID_PUBLIC_KEY, `${label} returned an uncompressed 65-byte secp256k1 public key — unsupported encoding`);
  }
  const shape = /^[0-9a-f]+$/.test(hex) ? `${hex.length}-char hex` : "non-hex data";
  throw signerError(
    SignerErrorCodes.INVALID_PUBLIC_KEY,
    `${label} returned an unsupported public key (${shape}); expected 64-hex x-only or 66-hex compressed (02/03 prefix)`
  );
}

/* ------------------------------------------------------------------ */
/* Signing requests (frozen, core-created)                             */
/* ------------------------------------------------------------------ */

function newRequestId() {
  return crypto.randomBytes(16).toString("hex");
}

function assertNetworkValue(network, required) {
  if (network === undefined) {
    if (required) throw invalidRequest("network is required for this request kind");
    return undefined;
  }
  if (typeof network !== "string" || !SIGNER_NETWORKS.includes(network)) {
    throw invalidRequest(`unknown network ${JSON.stringify(network)} — the ${SIGNER_INTERFACE_VERSION} network vocabulary is closed; failing closed`);
  }
  return network;
}

function assertOptionalScheme(scheme, required) {
  if (scheme === undefined) {
    if (required) throw invalidRequest("scheme must be explicit — the interface never defaults or auto-selects a signature scheme");
    return undefined;
  }
  if (typeof scheme !== "string" || !SIGNATURE_SCHEMES.includes(scheme)) {
    throw invalidRequest(`unknown signature scheme ${JSON.stringify(scheme)} — failing closed`);
  }
  return scheme;
}

function assertOptionalAddress(address, required, what) {
  if (address === undefined) {
    if (required) throw invalidRequest(`${what} is required for this request kind`);
    return undefined;
  }
  if (typeof address !== "string" || !address.trim() || address.length > 256) {
    throw invalidRequest(`${what} must be a non-empty address string`);
  }
  return address.trim();
}

/*
 * Personal-message signing request (authentication challenges). The
 * message is signed VERBATIM by the external signer, which displays it to
 * its holder; per Kaspa semantics it lives in the
 * PersonalMessageSigningHash domain and can never validate as a
 * transaction signature. The scheme is ALWAYS explicit (never "auto" —
 * auto could silently change the cryptographic scheme on Tangem-class
 * accounts; see web/wallet.js signAuthMessage).
 */
function createMessageSigningRequest({ message, scheme, network, expectedSignerAddress } = {}) {
  if (typeof message !== "string" || message.length === 0) {
    throw invalidRequest("message must be a non-empty string");
  }
  if (message.length > MAX_MESSAGE_CHARS) {
    throw invalidRequest(`message exceeds ${MAX_MESSAGE_CHARS} characters`);
  }
  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION,
    requestId: newRequestId(),
    kind: "sign-message",
    message,
    scheme: assertOptionalScheme(scheme, true),
    network: assertNetworkValue(network, false),
    expectedSignerAddress: assertOptionalAddress(expectedSignerAddress, false, "expectedSignerAddress"),
    createdAtMs: Date.now()
  });
}

/*
 * Canonical frozen signing metadata — the exact rule of web/app-v4.js
 * assertCanonicalSignInputs: every entry is { index: integer >= 0,
 * sighashType: 1 } and NOTHING else. The browser/core never invents or
 * trims signing semantics (real-KasWare incident: a reconstructed entry
 * without sighashType panicked kaspa-wasm AFTER the human clicked Sign).
 */
function assertCanonicalSignInputs(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw invalidRequest("signing metadata missing — refusing to invoke the signer");
  }
  const out = [];
  for (const si of list) {
    if (!isPlainObject(si) || !Number.isInteger(si.index) || si.index < 0 || si.sighashType !== SIGHASH_ALL) {
      throw invalidRequest(`signing entry ${JSON.stringify(si)} is not the canonical frozen { index, sighashType: ${SIGHASH_ALL} } — refusing to invoke the signer`);
    }
    const extras = Object.keys(si).filter((k) => k !== "index" && k !== "sighashType");
    if (extras.length > 0) {
      throw invalidRequest(`signing entry carries unknown key(s) ${JSON.stringify(extras)} — refusing (closed shape)`);
    }
    out.push(Object.freeze({ index: si.index, sighashType: SIGHASH_ALL }));
  }
  return Object.freeze(out);
}

/*
 * Transaction signing request: FROZEN BYTES IN, SIGNATURE OUT.
 * `unsignedSafeJson` is the exact frozen serialized transaction produced
 * by the SDK builders — this module never parses, rebuilds, or edits it
 * (it has no transaction code at all, by design). The signer adds
 * signatures for exactly the named inputs and returns the signed
 * serialization; the downstream SDK finalizer independently re-derives
 * the frozen txid and refuses any byte drift (sdk/src/wallet-submit-v4.js
 * TXID_MISMATCH). network and expectedSignerAddress are REQUIRED: a
 * funds-path signature is always bound to one network and one expected
 * identity, fail closed.
 */
function createTransactionSigningRequest({ unsignedSafeJson, signInputs, network, expectedSignerAddress, scheme } = {}) {
  if (typeof unsignedSafeJson !== "string" || unsignedSafeJson.length === 0) {
    throw invalidRequest("unsignedSafeJson must be the non-empty frozen serialized transaction string");
  }
  if (unsignedSafeJson.length > MAX_SAFE_JSON_CHARS) {
    throw invalidRequest(`unsignedSafeJson exceeds ${MAX_SAFE_JSON_CHARS} characters`);
  }
  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION,
    requestId: newRequestId(),
    kind: "sign-transaction",
    unsignedSafeJson,
    signInputs: assertCanonicalSignInputs(signInputs),
    network: assertNetworkValue(network, true),
    expectedSignerAddress: assertOptionalAddress(expectedSignerAddress, true, "expectedSignerAddress"),
    scheme: assertOptionalScheme(scheme, false),
    createdAtMs: Date.now()
  });
}

/* Structural re-validation of a request object (defense in depth inside
 * executeSigning — requests are re-checked, not trusted by marker). */
function assertSigningRequest(request) {
  if (!isPlainObject(request)) throw invalidRequest("signing request must be a plain object");
  if (request.interfaceVersion !== SIGNER_INTERFACE_VERSION) {
    throw signerError(
      SignerErrorCodes.INTERFACE_VERSION_UNSUPPORTED,
      `signing request declares interface version ${JSON.stringify(request.interfaceVersion)}; this core implements exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION)} — failing closed`
    );
  }
  if (typeof request.requestId !== "string" || !/^[0-9a-f]{32}$/.test(request.requestId)) {
    throw invalidRequest("signing request requestId must be 32-hex");
  }
  if (request.kind === "sign-message") {
    if (typeof request.message !== "string" || !request.message || request.message.length > MAX_MESSAGE_CHARS) {
      throw invalidRequest("sign-message request message is malformed");
    }
    assertOptionalScheme(request.scheme, true);
    assertNetworkValue(request.network, false);
    assertOptionalAddress(request.expectedSignerAddress, false, "expectedSignerAddress");
    return request;
  }
  if (request.kind === "sign-transaction") {
    if (typeof request.unsignedSafeJson !== "string" || !request.unsignedSafeJson || request.unsignedSafeJson.length > MAX_SAFE_JSON_CHARS) {
      throw invalidRequest("sign-transaction request unsignedSafeJson is malformed");
    }
    assertCanonicalSignInputs(request.signInputs);
    assertNetworkValue(request.network, true);
    assertOptionalAddress(request.expectedSignerAddress, true, "expectedSignerAddress");
    assertOptionalScheme(request.scheme, false);
    return request;
  }
  throw invalidRequest(`unknown signing request kind ${JSON.stringify(request.kind)} — failing closed`);
}

/* ------------------------------------------------------------------ */
/* Response validation                                                 */
/* ------------------------------------------------------------------ */

/*
 * Personal-message signature response contract.
 *   schnorr: exactly 128 lowercase hex chars (64-byte BIP-340) after
 *            trim+lowercase — identical to web/wallet.js signAuthMessage
 *            and server/src/auth.js SCHNORR_SIG_HEX.
 *   ecdsa:   NO verified v1 contract — REFUSED (UNSUPPORTED_SCHEME).
 *            The scheme is expressible so negotiation can refuse it; a
 *            response contract will only be added with source-backed
 *            evidence of the exact byte format, never guessed.
 */
function validateSignatureResponse(request, raw) {
  if (request.scheme === "schnorr") {
    if (typeof raw !== "string" || !SCHNORR_SIG_RE.test(raw.trim().toLowerCase())) {
      throw signerError(SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, "signer returned an unexpected personal-message signature format (expected 128-hex Schnorr)");
    }
    return raw.trim().toLowerCase();
  }
  if (request.scheme === "ecdsa") {
    throw signerError(
      SignerErrorCodes.UNSUPPORTED_SCHEME,
      "interface v1 defines no verified ECDSA personal-message response contract — failing closed (hosted auth v1 refuses ECDSA/Tangem accounts)"
    );
  }
  throw invalidRequest(`unknown signature scheme ${JSON.stringify(request.scheme)} — failing closed`);
}

/*
 * Signed-transaction response contract: a non-empty string (the signed
 * Safe JSON serialization). Returned VERBATIM — this module never trims,
 * re-encodes, or parses bytes that a downstream validator will check
 * against the frozen txid.
 */
function validateSignedTransactionResponse(raw) {
  if (typeof raw !== "string" || !raw.trim()) {
    throw signerError(SignerErrorCodes.INVALID_SIGNATURE_RESPONSE, "signer returned no signed transaction serialization");
  }
  return raw;
}

/* ------------------------------------------------------------------ */
/* Signing execution + approval lifecycle                              */
/* ------------------------------------------------------------------ */

function emitTransition(onTransition, requestId, state, extra) {
  if (typeof onTransition !== "function") return;
  try {
    onTransition(Object.freeze({ requestId, state, atMs: Date.now(), ...(extra || {}) }));
  } catch {
    /* observers must never alter signing outcomes */
  }
}

async function activeAccountAddress(adapter) {
  const account = await adapter.getActiveAccount();
  if (account === null || account === undefined) return null;
  if (isPlainObject(account) && typeof account.address === "string" && account.address.trim()) {
    return account.address.trim();
  }
  throw violation("adapter getActiveAccount() must return null or { address: <non-empty string> }");
}

/*
 * Drives one signing request through a validated adapter with every
 * fail-closed gate of the existing production flow (web/app-v4.js
 * walletSign stages, generalized):
 *
 *   gates (may emit terminal REFUSED):
 *     capability gate     — request kind vs declared features
 *     scheme gate         — request scheme vs declared schemes
 *     network gate        — declared networks AND the LIVE adapter network
 *     identity gate (pre) — active account === expectedSignerAddress
 *     async deadline gate — asynchronousApproval adapters require an
 *                           explicit timeoutMs (approval may settle
 *                           out-of-band; an unbounded wait is refused)
 *   SUBMITTED             — the external signer is invoked (it displays /
 *                           holds; approval happens INSIDE the signer)
 *   terminal:
 *     APPROVED  — response validated; identity re-verified post-approval
 *     REJECTED  — the signer's holder declined (USER_REJECTED)
 *     TIMED_OUT — deadline elapsed; cancelSigning() best-effort; any late
 *                 provider settlement is DISCARDED (never delivered)
 *     FAILED    — provider/protocol/validation failure (structured)
 *
 * Returns frozen { requestId, status: "approved", result } on approval;
 * throws a SignerError otherwise. Exactly one terminal transition is
 * emitted per execution.
 */
async function executeSigning(adapterOrRegistration, request, options = {}) {
  const registration =
    isPlainObject(adapterOrRegistration) && adapterOrRegistration.adapter && adapterOrRegistration.descriptor
      ? Object.freeze({ adapter: adapterOrRegistration.adapter, descriptor: validateCapabilityDescriptor(adapterOrRegistration.descriptor) })
      : validateAdapter(adapterOrRegistration);
  const { adapter, descriptor } = registration;

  if (!isPlainObject(options)) throw invalidRequest("options must be a plain object");
  const { timeoutMs, onTransition } = options;
  for (const key of Object.keys(options)) {
    if (key !== "timeoutMs" && key !== "onTransition") {
      throw invalidRequest(`unknown executeSigning option ${JSON.stringify(key)} — failing closed`);
    }
  }
  if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs <= 0)) {
    throw invalidRequest("timeoutMs must be a positive integer when provided");
  }

  assertSigningRequest(request);
  const refuse = (err) => {
    emitTransition(onTransition, request.requestId, "REFUSED", { code: err.signerCode });
    throw err;
  };

  /* capability + scheme gates (before any provider contact) */
  if (request.kind === "sign-message" && descriptor.features.messageSigning !== true) {
    refuse(signerError(SignerErrorCodes.UNSUPPORTED_CAPABILITY, `adapter ${descriptor.provider} does not offer messageSigning`));
  }
  if (request.kind === "sign-transaction") {
    if (descriptor.features.transactionSigning !== true) {
      refuse(signerError(SignerErrorCodes.UNSUPPORTED_CAPABILITY, `adapter ${descriptor.provider} does not offer transactionSigning`));
    }
    if (descriptor.features.specificInputSigning !== true) {
      refuse(
        signerError(
          SignerErrorCodes.UNSUPPORTED_CAPABILITY,
          `adapter ${descriptor.provider} cannot sign exactly the named inputs (specificInputSigning) — v1 transaction requests always carry canonical per-input signing entries; refusing`
        )
      );
    }
  }
  if (request.scheme !== undefined && !descriptor.schemes.includes(request.scheme)) {
    refuse(signerError(SignerErrorCodes.UNSUPPORTED_SCHEME, `adapter ${descriptor.provider} does not offer scheme ${JSON.stringify(request.scheme)}`));
  }
  if (request.kind === "sign-message") {
    /* fail closed NOW if the scheme has no v1 response contract — never
     * open a signer prompt whose result cannot be accepted. */
    if (request.scheme !== "schnorr") {
      refuse(
        signerError(
          SignerErrorCodes.UNSUPPORTED_SCHEME,
          `interface v1 defines a verified response contract only for schnorr personal-message signatures; refusing scheme ${JSON.stringify(request.scheme)} before invoking the signer`
        )
      );
    }
  }
  if (descriptor.features.asynchronousApproval === true && timeoutMs === undefined) {
    refuse(
      signerError(
        SignerErrorCodes.REQUEST_INVALID,
        `adapter ${descriptor.provider} settles approvals asynchronously — an explicit timeoutMs is required (an unbounded wait is refused, fail closed)`
      )
    );
  }

  /* network gate: declared + LIVE (network mismatches fail closed) */
  if (request.network !== undefined) {
    if (!descriptor.networks.includes(request.network)) {
      refuse(signerError(SignerErrorCodes.WRONG_NETWORK, `adapter ${descriptor.provider} does not declare network ${JSON.stringify(request.network)}`));
    }
    let liveNetwork;
    try {
      liveNetwork = await adapter.getNetwork();
    } catch (e) {
      refuse(normalizeAdapterFailure(e, "getNetwork"));
    }
    if (liveNetwork !== request.network) {
      refuse(
        signerError(
          SignerErrorCodes.WRONG_NETWORK,
          `signer reports network ${JSON.stringify(liveNetwork ?? null)}, required ${JSON.stringify(request.network)} — failing closed`
        )
      );
    }
  }

  /* identity gate (pre-invocation) */
  if (request.expectedSignerAddress !== undefined) {
    let before;
    try {
      before = await activeAccountAddress(adapter);
    } catch (e) {
      refuse(normalizeAdapterFailure(e, "getActiveAccount"));
    }
    if (before === null) {
      refuse(signerError(SignerErrorCodes.SIGNER_DISCONNECTED, "no active signer account — connect the signer first"));
    }
    if (before !== request.expectedSignerAddress) {
      refuse(
        signerError(
          SignerErrorCodes.ACCOUNT_CHANGED,
          "the active signer account is not the expected signer — refusing to request a signature from a different identity"
        )
      );
    }
  }

  /* invoke the external signer — approval happens INSIDE it */
  emitTransition(onTransition, request.requestId, "SUBMITTED");
  const invoke = request.kind === "sign-message" ? () => adapter.signMessage(request) : () => adapter.signTransaction(request);
  const providerPromise = Promise.resolve().then(invoke);
  providerPromise.catch(() => {}); /* outcome consumed via the settlement race — never unhandled */

  let timer = null;
  let outcome;
  try {
    outcome = await new Promise((resolve) => {
      if (timeoutMs !== undefined) {
        timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
      }
      providerPromise.then(
        (value) => resolve({ value }),
        (error) => resolve({ error })
      );
    });
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (outcome.timedOut) {
    /* fail closed: cancel best-effort; any late settlement of the
     * provider promise is DISCARDED (the settlement race above has
     * already resolved — nothing can deliver a late result). */
    if (typeof adapter.cancelSigning === "function") {
      try {
        await adapter.cancelSigning(request.requestId);
      } catch {
        /* best-effort cancellation must not mask the timeout */
      }
    }
    emitTransition(onTransition, request.requestId, "TIMED_OUT");
    throw signerError(SignerErrorCodes.SIGNER_TIMEOUT, `signing request ${request.requestId} was not approved within ${timeoutMs}ms — cancelled fail-closed`);
  }

  if (outcome.error !== undefined) {
    const err = normalizeAdapterFailure(outcome.error, request.kind);
    emitTransition(onTransition, request.requestId, err.signerCode === SignerErrorCodes.USER_REJECTED ? "REJECTED" : "FAILED", { code: err.signerCode });
    throw err;
  }

  /* response shape first, then post-approval identity re-verification
   * (mirrors web/app-v4.js walletSign stages F/G then I). */
  let result;
  try {
    result =
      request.kind === "sign-message"
        ? Object.freeze({ signature: validateSignatureResponse(request, outcome.value) })
        : Object.freeze({ signedSafeJson: validateSignedTransactionResponse(outcome.value) });
  } catch (e) {
    const err = normalizeAdapterFailure(e, request.kind);
    emitTransition(onTransition, request.requestId, "FAILED", { code: err.signerCode });
    throw err;
  }

  if (request.expectedSignerAddress !== undefined) {
    let after = null;
    try {
      after = await activeAccountAddress(adapter);
    } catch (e) {
      const err = normalizeAdapterFailure(e, "getActiveAccount");
      emitTransition(onTransition, request.requestId, "FAILED", { code: err.signerCode });
      throw err;
    }
    if (after !== request.expectedSignerAddress) {
      const err = signerError(
        SignerErrorCodes.ACCOUNT_CHANGED,
        "signer account/network changed during signing — refusing to accept a signature from a different identity"
      );
      emitTransition(onTransition, request.requestId, "FAILED", { code: err.signerCode });
      throw err;
    }
  }

  emitTransition(onTransition, request.requestId, "APPROVED");
  return Object.freeze({ requestId: request.requestId, status: "approved", result });
}

module.exports = {
  SIGNER_INTERFACE_VERSION,
  SIGNATURE_SCHEMES,
  SIGNER_NETWORKS,
  ADAPTER_KINDS,
  CAPABILITY_FEATURES,
  REQUEST_KINDS,
  SIGNING_STATES,
  SIGHASH_ALL,
  REQUIRED_METHODS,
  FEATURE_METHODS,
  validateCapabilityDescriptor,
  validateAdapter,
  SignerRegistry,
  negotiateCapabilities,
  requireCapabilities,
  normalizePublicKeyToXOnly,
  assertCanonicalSignInputs,
  createMessageSigningRequest,
  createTransactionSigningRequest,
  assertSigningRequest,
  validateSignatureResponse,
  validateSignedTransactionResponse,
  executeSigning
};
