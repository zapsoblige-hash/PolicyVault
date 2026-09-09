"use strict";

/*
 * PolicyVault Universal Signer Interface v2 — the adapter contract.
 *
 * Spec: docs/postlaunch/signer-interface-v2-spec.md
 * v1 (frozen, still exported and still supported): core/signer/
 *
 * WHY A NEW VERSION RATHER THAN AN AMENDMENT. Interface v1's vocabularies
 * are CLOSED and FROZEN — the same discipline the covenant versions
 * follow. Every capability v1 could not express is therefore added HERE,
 * additively, leaving `policyvault-signer/1` byte-for-byte untouched and
 * fully operational. Version strings are matched by EXACT EQUALITY in
 * both directions: a v1 descriptor is refused by v2 and a v2 descriptor
 * is refused by v1, both with INTERFACE_VERSION_UNSUPPORTED. There is no
 * range matching, no downgrade, no "compatible enough".
 *
 * WHAT v2 ADDS (all declared explicitly, all negotiated, all fail-closed):
 *
 *   sighash            which sighash behaviours the signer will commit to.
 *                      PolicyVault emits SIGHASH_ALL ONLY; a signer that
 *                      does not declare `all` cannot sign for it.
 *   transactionFormat  the exact serialization the signer speaks
 *                      ("kaspa-safe-json/1" — what the SDK builders emit
 *                      and what the finalizer re-derives the frozen txid
 *                      from). Pinned per request.
 *   pskt               BIP-370-style partially-signed-transaction support,
 *                      DECLARED ONLY. v2 defines no PSKT response contract
 *                      (see §PSKT below) — declaring it lets consumers
 *                      route/refuse; it never changes what is signed.
 *   userPresence       whether a human is at the signer for each request.
 *   transport          how request and response physically travel
 *                      (in-page / deep-link / qr-airgap / file / cli).
 *   cancellation       whether a submitted request can be revoked.
 *   maxTimeoutMs       the longest deadline the signer can honour.
 *   probeCapabilities  a REQUIRED method returning what the live provider
 *                      actually exposes, so a descriptor that claims more
 *                      than the provider can do is refused (CAPABILITY_MISMATCH)
 *                      instead of failing after a human clicks Sign.
 *   request binding    every request carries a CSPRNG nonce, an explicit
 *                      expiry, and the sha256 of the exact bytes to be
 *                      signed; every response is an ENVELOPE that must
 *                      echo them. v1 responses were bare strings, so
 *                      mis-binding, replay and duplicate settlement were
 *                      structurally undetectable.
 *
 * NON-CUSTODIAL INVARIANT (unchanged, structural): there is NO capability,
 * NO request field and NO response field through which a seed phrase,
 * private key or wallet backup could be requested, declared or returned.
 * The vocabularies below are closed; a custody capability cannot even be
 * spelled. PolicyVault is not a wallet and never becomes one.
 *
 * NO CRYPTOGRAPHY IN THE CORE (unchanged): this module hashes payloads
 * with sha256 for BINDING only. It never verifies a signature, never
 * derives a sighash, and never parses a transaction. Transaction-identity
 * re-derivation is performed by an INJECTED function
 * (`options.deriveTransactionId`) supplied by a consumer that already
 * holds the authoritative kaspa-wasm module; without it the check is
 * reported as NOT performed (`txIdVerified: false`) and the downstream
 * SDK finalizer's TXID_MISMATCH refusal remains the authority. Consensus
 * is the security boundary; this interface transports authorization
 * material only.
 *
 * PSKT — WHY DECLARED ONLY. rusty-kaspa ships a real PSKT implementation
 * (`wallet/pskt`, roles enumerated in `wallet/pskt/src/role.rs`: Creator,
 * Constructor, Updater, Signer, Combiner, Finalizer, Extractor; WASM class
 * `PSKT` in `wasm/nodejs/kaspa/kaspa.d.ts`). PolicyVault does NOT use it:
 * the production browser signer's method is *named* `signPskt` but its
 * payload is `{ txJsonString, options: { signInputs } }` and its result is
 * a Kaspa **Safe JSON** transaction serialization (web/wallet.js,
 * sdk/src/signer-dev.js, sdk/src/wallet-requests-v4.js) — not a PSKT
 * bundle. v2 therefore lets an adapter DECLARE pskt support with the exact
 * roles it implements, so consumers can route future multi-party flows,
 * and defines NO pskt response contract: adding one requires source-backed
 * evidence of the exact serialization, never a guess.
 *
 * Pure CommonJS, browser-portable through web/core-bundle.js. Zero
 * external dependencies; the only Node builtin is `crypto`, used for
 * `randomBytes` (nonces/ids) and `createHash("sha256")` (payload binding)
 * — exactly the two surfaces the browser crypto shim implements. BigInt
 * safe: this module performs no arithmetic on money.
 */

const crypto = require("crypto");
const v1 = require("../interface");
const {
  SIGNER_INTERFACE_VERSION_V2,
  SignerErrorCodesV2,
  signerErrorV2,
  normalizeAdapterFailureV2
} = require("./errors");

/* ------------------------------------------------------------------ */
/* v2 closed vocabularies                                              */
/* ------------------------------------------------------------------ */

/* Re-exported from v1 UNCHANGED — these sets are shared, not forked. A
 * new scheme/network/kind/feature is a change to BOTH versions' meaning
 * and is therefore never made silently here. */
const SIGNATURE_SCHEMES = v1.SIGNATURE_SCHEMES;
const SIGNER_NETWORKS = v1.SIGNER_NETWORKS;
const ADAPTER_KINDS = v1.ADAPTER_KINDS;
const CAPABILITY_FEATURES = v1.CAPABILITY_FEATURES;
const REQUEST_KINDS = v1.REQUEST_KINDS;
const SIGHASH_ALL = v1.SIGHASH_ALL; /* 1 */

/* Sighash behaviours a signer can declare. PolicyVault REQUIRES `all`
 * and emits nothing else; the other three exist so a signer describes
 * itself truthfully and a consumer can refuse it on the exact reason. */
const SIGHASH_FLAGS = Object.freeze(["all", "none", "single", "anyoneCanPay"]);

/* Transaction serialization formats. Exactly one is defined: the Kaspa
 * Safe JSON serialization produced by `Transaction.serializeToSafeJSON()`
 * and consumed by `Transaction.deserializeFromSafeJSON()` — the format
 * every PolicyVault builder emits and every finalizer re-derives the
 * frozen txid from. A PSKT bundle format would be a NEW entry added with
 * source-backed evidence, never a re-interpretation of this one. */
const TRANSACTION_FORMATS = Object.freeze(["kaspa-safe-json/1"]);

/* BIP-370 PSKT roles, mirroring rusty-kaspa `wallet/pskt/src/role.rs`
 * exactly (the upstream enum, in upstream order). Declaration vocabulary
 * only — v2 defines no PSKT wire contract. */
const PSKT_ROLES = Object.freeze([
  "creator",
  "constructor",
  "updater",
  "signer",
  "combiner",
  "finalizer",
  "extractor"
]);

/* How a request and its response physically travel. This is a SECURITY
 * fact, not a UX fact: a qr-airgap or file transport crosses a boundary
 * where an attacker may substitute or replay a document, which is why
 * every v2 response is a bound envelope. */
const TRANSPORT_KINDS = Object.freeze([
  "in-page", // injected provider inside the same page (browser extension)
  "deep-link", // OS URL handoff to a wallet app and a callback back
  "qr-airgap", // optical shuttle across an offline gap
  "file", // file/share-sheet shuttle across an offline gap
  "cli" // local process invocation (no transport hop at all)
]);

/* Whether a human is present at the signer for each request. Two values
 * only: an "unknown" state would be a hole a consumer could accidentally
 * accept, so an adapter that cannot honestly claim presence declares
 * "not-required" and a presence-requiring consumer refuses it. */
const USER_PRESENCE_MODES = Object.freeze(["required", "not-required"]);

/* Whether a SUBMITTED request can be revoked before it settles. */
const CANCELLATION_MODES = Object.freeze(["supported", "unsupported"]);

/* v2 lifecycle states. CREATED is implicit at request creation; exactly
 * ONE terminal state is emitted per execution. CANCELLED and EXPIRED are
 * new: v1 could only express them as SIGNER_TIMEOUT. */
const SIGNING_STATES_V2 = Object.freeze([
  "REFUSED", // terminal — a fail-closed gate refused before the signer was invoked
  "SUBMITTED", // the external signer holds the request
  "APPROVED", // terminal — envelope validated and bound
  "REJECTED", // terminal — the signer's holder declined
  "TIMED_OUT", // terminal — the consumer's deadline elapsed
  "EXPIRED", // terminal — the REQUEST's own expiry elapsed
  "CANCELLED", // terminal — the consumer revoked the request
  "FAILED" // terminal — provider/protocol/validation/binding failure
]);

/* Adapter methods required unconditionally in v2 = v1's seven plus the
 * capability probe. */
const REQUIRED_METHODS_V2 = Object.freeze([...v1.REQUIRED_METHODS, "probeCapabilities"]);

/* Feature -> additionally-required method(s), inherited from v1. */
const FEATURE_METHODS_V2 = v1.FEATURE_METHODS;

const PROVIDER_ID_RE = /^[a-z][a-z0-9-]{1,31}$/;
const SCHNORR_SIG_RE = /^[0-9a-f]{128}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const MAX_MESSAGE_CHARS = 16384;
const MAX_SAFE_JSON_CHARS = 1048576;

/* Request time-to-live bounds. A request with no expiry is refused: a
 * signing authorization that never goes stale is a replayable bearer
 * token. The upper bound accommodates institutional/MPC approvals that
 * legitimately take days. */
const MIN_TTL_MS = 1000;
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; /* 30 days */

/* Longest deadline an adapter may declare it can honour. */
const MAX_DECLARABLE_TIMEOUT_MS = MAX_TTL_MS;

function violation(message, details) {
  return signerErrorV2(SignerErrorCodesV2.PROTOCOL_VIOLATION, message, details ? { details } : undefined);
}

function invalidRequest(message, details) {
  return signerErrorV2(SignerErrorCodesV2.REQUEST_INVALID, message, details ? { details } : undefined);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function uniqueKnownList(value, allowed, what, makeError) {
  if (!Array.isArray(value)) {
    throw makeError(`${what} must be an array`);
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string" || !allowed.includes(item)) {
      throw makeError(
        `${what} contains unknown value ${JSON.stringify(String(item))} — the ${SIGNER_INTERFACE_VERSION_V2} vocabulary is closed; refusing`,
        { unknownValue: String(item) }
      );
    }
    if (seen.has(item)) throw makeError(`${what} lists ${JSON.stringify(item)} more than once`);
    seen.add(item);
  }
  return Object.freeze([...value]);
}

/* ------------------------------------------------------------------ */
/* Capability descriptor (v2)                                          */
/* ------------------------------------------------------------------ */

const DESCRIPTOR_KEYS_V2 = Object.freeze([
  "interfaceVersion",
  "provider",
  "label",
  "kind",
  "schemes",
  "networks",
  "features",
  "sighash",
  "pskt",
  "transactionFormats",
  "userPresence",
  "transport",
  "cancellation",
  "maxTimeoutMs"
]);

/*
 * Validates an adapter-provided v2 capability descriptor and returns a
 * deep-frozen normalized copy. EVERY key is required and EVERY value is
 * checked against a closed vocabulary: unknown keys, missing keys,
 * unknown values, wrong types and internally inconsistent declarations
 * are REFUSED. Nothing is defaulted and nothing unknown is ignored.
 *
 * Internal-consistency rules (a descriptor that contradicts itself is a
 * contract breach, not a preference):
 *   - a signer that settles approvals out-of-band MUST support
 *     cancellation (an unrevocable pending authorization is refused);
 *   - a signer that declares transactionSigning MUST declare at least
 *     one transaction format and at least one sighash behaviour;
 *   - `pskt.roles` is non-empty exactly when `pskt.supported` is true;
 *   - an air-gapped adapter cannot claim an "in-page" transport;
 *   - `maxTimeoutMs` is a positive integer within the declarable bound.
 */
function validateCapabilityDescriptorV2(desc) {
  if (!isPlainObject(desc)) throw violation("capability descriptor must be a plain object");

  if (desc.interfaceVersion !== SIGNER_INTERFACE_VERSION_V2) {
    throw signerErrorV2(
      SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      `capability descriptor declares interface version ${JSON.stringify(desc.interfaceVersion)}; this core implements exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION_V2)} — failing closed (no downgrade, no guessing)`
    );
  }

  for (const key of Object.keys(desc)) {
    if (!DESCRIPTOR_KEYS_V2.includes(key)) {
      throw violation(`capability descriptor carries unknown key ${JSON.stringify(key)} — refusing (closed schema)`);
    }
  }
  for (const key of DESCRIPTOR_KEYS_V2) {
    if (!(key in desc)) throw violation(`capability descriptor is missing required key ${JSON.stringify(key)}`);
  }

  if (typeof desc.provider !== "string" || !PROVIDER_ID_RE.test(desc.provider)) {
    throw violation("capability descriptor provider must match /^[a-z][a-z0-9-]{1,31}$/");
  }
  if (typeof desc.label !== "string" || !desc.label.trim() || desc.label.length > 64) {
    throw violation("capability descriptor label must be a non-empty string of at most 64 characters");
  }
  if (typeof desc.kind !== "string" || !ADAPTER_KINDS.includes(desc.kind)) {
    throw violation(`capability descriptor kind ${JSON.stringify(String(desc.kind))} is not a known adapter kind — refusing`, {
      unknownValue: String(desc.kind)
    });
  }

  const schemes = uniqueKnownList(desc.schemes, SIGNATURE_SCHEMES, "capability descriptor schemes", violation);
  if (schemes.length === 0) throw violation("capability descriptor schemes must be non-empty");
  const networks = uniqueKnownList(desc.networks, SIGNER_NETWORKS, "capability descriptor networks", violation);
  if (networks.length === 0) throw violation("capability descriptor networks must be non-empty");

  /* features: the v1 nine, still every key explicit and strictly boolean */
  if (!isPlainObject(desc.features)) throw violation("capability descriptor features must be a plain object");
  for (const key of Object.keys(desc.features)) {
    if (!CAPABILITY_FEATURES.includes(key)) {
      throw violation(`capability descriptor features carry unknown feature ${JSON.stringify(key)} — refusing (unknown capabilities are never ignored)`, {
        unknownValue: key
      });
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

  /* sighash: every flag explicit and strictly boolean */
  if (!isPlainObject(desc.sighash)) throw violation("capability descriptor sighash must be a plain object");
  for (const key of Object.keys(desc.sighash)) {
    if (!SIGHASH_FLAGS.includes(key)) {
      throw violation(`capability descriptor sighash carries unknown flag ${JSON.stringify(key)} — refusing`, { unknownValue: key });
    }
  }
  const sighash = {};
  for (const key of SIGHASH_FLAGS) {
    if (!(key in desc.sighash)) {
      throw violation(`capability descriptor sighash must declare ${JSON.stringify(key)} explicitly (no defaults)`);
    }
    if (typeof desc.sighash[key] !== "boolean") {
      throw violation(`capability descriptor sighash flag ${JSON.stringify(key)} must be strictly boolean`);
    }
    sighash[key] = desc.sighash[key];
  }

  /* pskt: declaration only */
  if (!isPlainObject(desc.pskt)) throw violation("capability descriptor pskt must be a plain object");
  for (const key of Object.keys(desc.pskt)) {
    if (key !== "supported" && key !== "roles") {
      throw violation(`capability descriptor pskt carries unknown key ${JSON.stringify(key)} — refusing (closed schema)`);
    }
  }
  if (typeof desc.pskt.supported !== "boolean") throw violation("capability descriptor pskt.supported must be strictly boolean");
  const psktRoles = uniqueKnownList(desc.pskt.roles, PSKT_ROLES, "capability descriptor pskt.roles", violation);
  if (desc.pskt.supported === true && psktRoles.length === 0) {
    throw violation("capability descriptor declares pskt.supported without naming a single PSKT role — refusing (a support claim must say what it supports)");
  }
  if (desc.pskt.supported === false && psktRoles.length > 0) {
    throw violation("capability descriptor names PSKT roles while declaring pskt.supported: false — refusing (self-contradictory declaration)");
  }

  const transactionFormats = uniqueKnownList(desc.transactionFormats, TRANSACTION_FORMATS, "capability descriptor transactionFormats", violation);

  if (typeof desc.userPresence !== "string" || !USER_PRESENCE_MODES.includes(desc.userPresence)) {
    throw violation(`capability descriptor userPresence ${JSON.stringify(String(desc.userPresence))} is not one of ${JSON.stringify(USER_PRESENCE_MODES)} — refusing`);
  }
  if (typeof desc.transport !== "string" || !TRANSPORT_KINDS.includes(desc.transport)) {
    throw violation(`capability descriptor transport ${JSON.stringify(String(desc.transport))} is not a known transport kind — refusing`, {
      unknownValue: String(desc.transport)
    });
  }
  if (typeof desc.cancellation !== "string" || !CANCELLATION_MODES.includes(desc.cancellation)) {
    throw violation(`capability descriptor cancellation ${JSON.stringify(String(desc.cancellation))} is not one of ${JSON.stringify(CANCELLATION_MODES)} — refusing`);
  }
  if (!Number.isInteger(desc.maxTimeoutMs) || desc.maxTimeoutMs <= 0 || desc.maxTimeoutMs > MAX_DECLARABLE_TIMEOUT_MS) {
    throw violation(`capability descriptor maxTimeoutMs must be a positive integer of at most ${MAX_DECLARABLE_TIMEOUT_MS} — refusing`);
  }

  /* ---- internal consistency ---- */
  if (features.asynchronousApproval === true && desc.cancellation !== "supported") {
    throw violation(
      "capability descriptor declares asynchronousApproval without cancellation support — refusing (an out-of-band approval that can never be revoked is not an acceptable authorization)"
    );
  }
  if (features.transactionSigning === true) {
    if (transactionFormats.length === 0) {
      throw violation("capability descriptor declares transactionSigning without a single transaction format — refusing");
    }
    if (!SIGHASH_FLAGS.some((f) => sighash[f] === true)) {
      throw violation("capability descriptor declares transactionSigning without a single sighash behaviour — refusing");
    }
  }
  if (features.transactionSigning === false && transactionFormats.length > 0) {
    throw violation("capability descriptor names transaction formats while declaring transactionSigning: false — refusing (self-contradictory declaration)");
  }
  if (features.airGapped === true && desc.transport === "in-page") {
    throw violation('capability descriptor declares airGapped with an "in-page" transport — refusing (self-contradictory declaration)');
  }

  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    provider: desc.provider,
    label: desc.label,
    kind: desc.kind,
    schemes,
    networks,
    features: Object.freeze(features),
    sighash: Object.freeze(sighash),
    pskt: Object.freeze({ supported: desc.pskt.supported, roles: psktRoles }),
    transactionFormats,
    userPresence: desc.userPresence,
    transport: desc.transport,
    cancellation: desc.cancellation,
    maxTimeoutMs: desc.maxTimeoutMs
  });
}

/* ------------------------------------------------------------------ */
/* Capability PROBE — declaration vs observed reality                  */
/* ------------------------------------------------------------------ */

const PROBE_KEYS = Object.freeze([
  "interfaceVersion",
  "probed",
  "reason",
  "methods",
  "sighash",
  "pskt",
  "transactionFormats",
  "network"
]);

/*
 * Validates a probe report. `probed: false` is an HONEST answer (an
 * air-gapped signer cannot be interrogated before the shuttle) and MUST
 * carry a reason; consumers that require probed capabilities refuse such
 * an adapter rather than assuming.
 */
function validateProbeReport(report) {
  if (!isPlainObject(report)) throw violation("capability probe report must be a plain object");
  if (report.interfaceVersion !== SIGNER_INTERFACE_VERSION_V2) {
    throw signerErrorV2(
      SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      `capability probe report declares interface version ${JSON.stringify(report.interfaceVersion)}; expected exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION_V2)} — failing closed`
    );
  }
  for (const key of Object.keys(report)) {
    if (!PROBE_KEYS.includes(key)) throw violation(`capability probe report carries unknown key ${JSON.stringify(key)} — refusing (closed schema)`);
  }
  if (typeof report.probed !== "boolean") throw violation("capability probe report must declare probed as a strict boolean");

  if (report.probed === false) {
    if (typeof report.reason !== "string" || !report.reason.trim() || report.reason.length > 256) {
      throw violation("an unprobed capability report must carry a short non-empty reason — refusing (silence is not an answer)");
    }
    return Object.freeze({ interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: false, reason: report.reason });
  }

  const out = { interfaceVersion: SIGNER_INTERFACE_VERSION_V2, probed: true };
  if ("reason" in report && report.reason !== undefined) {
    if (typeof report.reason !== "string" || report.reason.length > 256) throw violation("capability probe reason must be a short string when present");
    out.reason = report.reason;
  }
  if ("methods" in report && report.methods !== undefined) {
    if (!Array.isArray(report.methods)) throw violation("capability probe methods must be an array of method names");
    const methods = [];
    for (const m of report.methods) {
      if (typeof m !== "string" || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(m)) {
        throw violation("capability probe methods must be plain method-name strings — refusing");
      }
      if (!methods.includes(m)) methods.push(m);
    }
    out.methods = Object.freeze(methods);
  }
  if ("sighash" in report && report.sighash !== undefined) {
    if (!isPlainObject(report.sighash)) throw violation("capability probe sighash must be a plain object");
    const sh = {};
    for (const key of Object.keys(report.sighash)) {
      if (!SIGHASH_FLAGS.includes(key)) throw violation(`capability probe sighash carries unknown flag ${JSON.stringify(key)} — refusing`);
      if (typeof report.sighash[key] !== "boolean") throw violation("capability probe sighash flags must be strictly boolean");
      sh[key] = report.sighash[key];
    }
    out.sighash = Object.freeze(sh);
  }
  if ("pskt" in report && report.pskt !== undefined) {
    if (!isPlainObject(report.pskt)) throw violation("capability probe pskt must be a plain object");
    for (const key of Object.keys(report.pskt)) {
      if (key !== "supported" && key !== "roles") throw violation(`capability probe pskt carries unknown key ${JSON.stringify(key)} — refusing`);
    }
    if (typeof report.pskt.supported !== "boolean") throw violation("capability probe pskt.supported must be strictly boolean");
    const roles = report.pskt.roles === undefined ? [] : uniqueKnownList(report.pskt.roles, PSKT_ROLES, "capability probe pskt.roles", violation);
    out.pskt = Object.freeze({ supported: report.pskt.supported, roles });
  }
  if ("transactionFormats" in report && report.transactionFormats !== undefined) {
    out.transactionFormats = uniqueKnownList(report.transactionFormats, TRANSACTION_FORMATS, "capability probe transactionFormats", violation);
  }
  if ("network" in report && report.network !== undefined && report.network !== null) {
    if (typeof report.network !== "string" || !SIGNER_NETWORKS.includes(report.network)) {
      throw violation(`capability probe network ${JSON.stringify(String(report.network))} is not a known network — refusing`);
    }
    out.network = report.network;
  }
  return Object.freeze(out);
}

/*
 * Cross-checks a DECLARED descriptor against a PROBED report.
 *
 * The asymmetry is deliberate and is the whole point: an adapter may
 * offer upward LESS than its provider can do (the v1 rule — a descriptor
 * describes what the ADAPTER offers, e.g. KasWare's adapter declares
 * schnorr only although the extension can emit ECDSA for Tangem cards).
 * It may never offer MORE. Every declaration the probe contradicts is a
 * CAPABILITY_MISMATCH and the adapter is refused before any signing.
 *
 * Returns a frozen { ok: true, probed } or throws. `probed: false`
 * reports are accepted here (nothing was contradicted) and surfaced to
 * the caller so a consumer requiring a live probe can refuse.
 */
function verifyDeclaredCapabilities(descriptor, report) {
  const desc = validateCapabilityDescriptorV2(descriptor);
  const probe = validateProbeReport(report);
  if (probe.probed === false) {
    return Object.freeze({ ok: true, provider: desc.provider, probed: false, reason: probe.reason });
  }

  const mismatches = [];

  if (probe.methods !== undefined) {
    /* method-bound features only: a declared feature whose backing
     * provider method the probe did NOT observe is over-declaration. */
    for (const [feature, methods] of Object.entries(FEATURE_METHODS_V2)) {
      if (desc.features[feature] !== true) continue;
      for (const m of methods) {
        if (!probe.methods.includes(m)) mismatches.push(`feature ${feature} declared but the provider exposes no ${m}()`);
      }
    }
  }
  if (probe.sighash !== undefined) {
    for (const flag of SIGHASH_FLAGS) {
      if (desc.sighash[flag] === true && probe.sighash[flag] === false) {
        mismatches.push(`sighash.${flag} declared but the provider does not support it`);
      }
    }
  }
  if (probe.pskt !== undefined) {
    if (desc.pskt.supported === true && probe.pskt.supported === false) {
      mismatches.push("pskt.supported declared but the provider exposes no PSKT surface");
    }
    if (desc.pskt.supported === true && probe.pskt.supported === true) {
      for (const role of desc.pskt.roles) {
        if (!probe.pskt.roles.includes(role)) mismatches.push(`pskt role ${role} declared but not offered by the provider`);
      }
    }
  }
  if (probe.transactionFormats !== undefined) {
    for (const fmt of desc.transactionFormats) {
      if (!probe.transactionFormats.includes(fmt)) mismatches.push(`transaction format ${fmt} declared but not spoken by the provider`);
    }
  }
  if (probe.network !== undefined && !desc.networks.includes(probe.network)) {
    mismatches.push(`the provider reports network ${probe.network}, which this adapter does not declare`);
  }

  if (mismatches.length > 0) {
    throw signerErrorV2(
      SignerErrorCodesV2.CAPABILITY_MISMATCH,
      `adapter ${desc.provider} declares capabilities its provider does not have: ${mismatches.join("; ")} — refusing (an adapter may offer LESS than its provider, never more)`,
      { details: { mismatches } }
    );
  }
  return Object.freeze({ ok: true, provider: desc.provider, probed: true });
}

/* ------------------------------------------------------------------ */
/* Adapter validation + registry (v2)                                  */
/* ------------------------------------------------------------------ */

/*
 * Validates a v2 adapter: describe() must yield a valid v2 descriptor,
 * every unconditional method (including probeCapabilities) must exist,
 * every feature-bound method must exist, and an adapter declaring
 * cancellation support must implement cancelSigning. Returns a frozen
 * { adapter, descriptor }. Partial acceptance does not exist.
 */
function validateAdapterV2(adapter) {
  if (adapter === null || typeof adapter !== "object" || typeof adapter.describe !== "function") {
    throw violation("adapter must be an object implementing describe()");
  }
  let raw;
  try {
    raw = adapter.describe();
  } catch (e) {
    throw normalizeAdapterFailureV2(e, "describe");
  }
  const descriptor = validateCapabilityDescriptorV2(raw);

  const missing = [];
  for (const name of REQUIRED_METHODS_V2) {
    if (typeof adapter[name] !== "function") missing.push(name);
  }
  for (const [feature, methods] of Object.entries(FEATURE_METHODS_V2)) {
    if (descriptor.features[feature]) {
      for (const name of methods) {
        if (typeof adapter[name] !== "function") missing.push(`${name} (required by feature ${feature})`);
      }
    }
  }
  if (descriptor.cancellation === "supported" && typeof adapter.cancelSigning !== "function") {
    missing.push('cancelSigning (required by cancellation: "supported")');
  }
  if (missing.length > 0) {
    throw violation(`adapter ${descriptor.provider} is missing required method(s): ${missing.join(", ")} — refusing registration`, { missing });
  }
  return Object.freeze({ adapter, descriptor });
}

/* Registry of validated v2 adapters, keyed by provider id. Kept separate
 * from the v1 registry: mixing versions in one namespace would invite a
 * consumer to hand a v2 request to a v1 adapter. */
class SignerRegistryV2 {
  constructor() {
    this._records = new Map();
  }

  register(adapter) {
    const record = validateAdapterV2(adapter);
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
      throw signerErrorV2(SignerErrorCodesV2.SIGNER_NOT_FOUND, `no signer adapter registered under provider id ${JSON.stringify(providerId)}`);
    }
    return record;
  }

  list() {
    return Object.freeze([...this._records.values()].map((r) => r.descriptor));
  }
}

/* ------------------------------------------------------------------ */
/* Capability negotiation (v2)                                         */
/* ------------------------------------------------------------------ */

const REQUIREMENT_KEYS_V2 = Object.freeze([
  "schemes",
  "features",
  "network",
  "sighash",
  "transactionFormat",
  "transports",
  "userPresence",
  "pskt",
  "cancellation",
  "minTimeoutMs"
]);

/*
 * Consumer-side negotiation. Requirements are validated against the
 * closed vocabularies FIRST: a consumer asking for something the
 * vocabulary cannot express gets REQUEST_INVALID, because silently "not
 * matching" an unknown requirement could pass an adapter the consumer
 * meant to constrain.
 *
 * Returns frozen { ok: true, provider } or a structured refusal
 * { ok: false, provider, code, missing }.
 */
function negotiateCapabilitiesV2(descriptor, requirements) {
  const desc = validateCapabilityDescriptorV2(descriptor);
  if (!isPlainObject(requirements)) throw invalidRequest("requirements must be a plain object");
  for (const key of Object.keys(requirements)) {
    if (!REQUIREMENT_KEYS_V2.includes(key)) {
      throw invalidRequest(`unknown requirement key ${JSON.stringify(key)} — the ${SIGNER_INTERFACE_VERSION_V2} negotiation vocabulary is closed; failing closed`);
    }
  }

  const refuse = (code, missing) => Object.freeze({ ok: false, provider: desc.provider, code, missing: Object.freeze([...missing]) });

  if (requirements.schemes !== undefined) {
    const wanted = uniqueKnownList(requirements.schemes, SIGNATURE_SCHEMES, "requirement schemes", invalidRequest);
    if (wanted.length === 0) throw invalidRequest("requirement schemes must be non-empty");
    const missing = wanted.filter((s) => !desc.schemes.includes(s));
    if (missing.length > 0) return refuse(SignerErrorCodesV2.UNSUPPORTED_SCHEME, missing);
  }
  if (requirements.features !== undefined) {
    const wanted = uniqueKnownList(requirements.features, CAPABILITY_FEATURES, "requirement features", invalidRequest);
    if (wanted.length === 0) throw invalidRequest("requirement features must be non-empty");
    const missing = wanted.filter((f) => desc.features[f] !== true);
    if (missing.length > 0) return refuse(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, missing);
  }
  if (requirements.network !== undefined) {
    if (typeof requirements.network !== "string" || !SIGNER_NETWORKS.includes(requirements.network)) {
      throw invalidRequest(`unknown required network ${JSON.stringify(String(requirements.network))} — failing closed`);
    }
    if (!desc.networks.includes(requirements.network)) return refuse(SignerErrorCodesV2.WRONG_NETWORK, [requirements.network]);
  }
  if (requirements.sighash !== undefined) {
    const wanted = uniqueKnownList(requirements.sighash, SIGHASH_FLAGS, "requirement sighash", invalidRequest);
    if (wanted.length === 0) throw invalidRequest("requirement sighash must be non-empty");
    const missing = wanted.filter((f) => desc.sighash[f] !== true);
    if (missing.length > 0) return refuse(SignerErrorCodesV2.UNSUPPORTED_SIGHASH, missing);
  }
  if (requirements.transactionFormat !== undefined) {
    if (typeof requirements.transactionFormat !== "string" || !TRANSACTION_FORMATS.includes(requirements.transactionFormat)) {
      throw invalidRequest(`unknown required transaction format ${JSON.stringify(String(requirements.transactionFormat))} — failing closed`);
    }
    if (!desc.transactionFormats.includes(requirements.transactionFormat)) {
      return refuse(SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT, [requirements.transactionFormat]);
    }
  }
  if (requirements.transports !== undefined) {
    const allowed = uniqueKnownList(requirements.transports, TRANSPORT_KINDS, "requirement transports", invalidRequest);
    if (allowed.length === 0) throw invalidRequest("requirement transports must be non-empty");
    if (!allowed.includes(desc.transport)) return refuse(SignerErrorCodesV2.TRANSPORT_UNSUPPORTED, [desc.transport]);
  }
  if (requirements.userPresence !== undefined) {
    if (typeof requirements.userPresence !== "string" || !USER_PRESENCE_MODES.includes(requirements.userPresence)) {
      throw invalidRequest(`unknown required userPresence ${JSON.stringify(String(requirements.userPresence))} — failing closed`);
    }
    if (requirements.userPresence === "required" && desc.userPresence !== "required") {
      return refuse(SignerErrorCodesV2.USER_PRESENCE_REQUIRED, ["userPresence:required"]);
    }
  }
  if (requirements.pskt !== undefined) {
    const wanted = uniqueKnownList(requirements.pskt, PSKT_ROLES, "requirement pskt", invalidRequest);
    if (wanted.length === 0) throw invalidRequest("requirement pskt must be non-empty");
    const missing = desc.pskt.supported === true ? wanted.filter((r) => !desc.pskt.roles.includes(r)) : wanted;
    if (missing.length > 0) return refuse(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, missing.map((r) => `pskt:${r}`));
  }
  if (requirements.cancellation !== undefined) {
    if (typeof requirements.cancellation !== "string" || !CANCELLATION_MODES.includes(requirements.cancellation)) {
      throw invalidRequest(`unknown required cancellation mode ${JSON.stringify(String(requirements.cancellation))} — failing closed`);
    }
    if (requirements.cancellation === "supported" && desc.cancellation !== "supported") {
      return refuse(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, ["cancellation:supported"]);
    }
  }
  if (requirements.minTimeoutMs !== undefined) {
    if (!Number.isInteger(requirements.minTimeoutMs) || requirements.minTimeoutMs <= 0) {
      throw invalidRequest("requirement minTimeoutMs must be a positive integer");
    }
    if (desc.maxTimeoutMs < requirements.minTimeoutMs) {
      return refuse(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, [`maxTimeoutMs:${desc.maxTimeoutMs}`]);
    }
  }
  return Object.freeze({ ok: true, provider: desc.provider });
}

/* Throwing variant. */
function requireCapabilitiesV2(descriptor, requirements) {
  const result = negotiateCapabilitiesV2(descriptor, requirements);
  if (!result.ok) {
    throw signerErrorV2(result.code, `adapter ${result.provider} does not satisfy required capabilities: ${result.missing.join(", ")}`, {
      details: { missing: [...result.missing] }
    });
  }
  return result;
}

/*
 * The canonical PolicyVault consumer requirement set for a FUNDS-PATH
 * transaction signature. Restated as a constant so no consumer has to
 * remember it and no consumer can quietly relax it: BIP-340 Schnorr,
 * transaction signing of exactly the named inputs, SIGHASH_ALL, and the
 * Kaspa Safe JSON serialization the finalizer re-derives the frozen txid
 * from.
 */
const POLICYVAULT_TRANSACTION_REQUIREMENTS = Object.freeze({
  schemes: Object.freeze(["schnorr"]),
  features: Object.freeze(["transactionSigning", "specificInputSigning"]),
  sighash: Object.freeze(["all"]),
  transactionFormat: "kaspa-safe-json/1"
});

/* ------------------------------------------------------------------ */
/* Signing requests (v2): bound, nonced, expiring                      */
/* ------------------------------------------------------------------ */

function newRequestId() {
  return crypto.randomBytes(16).toString("hex"); /* 32 hex */
}

function newNonce() {
  return crypto.randomBytes(32).toString("hex"); /* 64 hex */
}

function assertNetworkValue(network, required) {
  if (network === undefined) {
    if (required) throw invalidRequest("network is required for this request kind");
    return undefined;
  }
  if (typeof network !== "string" || !SIGNER_NETWORKS.includes(network)) {
    throw invalidRequest(`unknown network ${JSON.stringify(String(network))} — the ${SIGNER_INTERFACE_VERSION_V2} network vocabulary is closed; failing closed`);
  }
  return network;
}

function assertScheme(scheme) {
  if (typeof scheme !== "string" || !SIGNATURE_SCHEMES.includes(scheme)) {
    throw invalidRequest("scheme must be explicit and known — the interface never defaults or auto-selects a signature scheme");
  }
  return scheme;
}

function assertAddress(address, required, what) {
  if (address === undefined) {
    if (required) throw invalidRequest(`${what} is required for this request kind`);
    return undefined;
  }
  if (typeof address !== "string" || !address.trim() || address.length > 256) {
    throw invalidRequest(`${what} must be a non-empty address string`);
  }
  return address.trim();
}

function assertTtl(ttlMs) {
  if (!Number.isInteger(ttlMs) || ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
    throw invalidRequest(
      `ttlMs must be an integer between ${MIN_TTL_MS} and ${MAX_TTL_MS} — every v2 request expires (an authorization that never goes stale is a replayable bearer token)`
    );
  }
  return ttlMs;
}

/*
 * Canonical frozen signing metadata (v2). Identical to the v1 rule —
 * every entry is exactly { index: integer >= 0, sighashType: 1 } and
 * nothing else — but v2 gives the refusal its own code
 * (UNSUPPORTED_SIGHASH) when the sighash type is the thing that is
 * wrong, rather than folding it into a generic malformed-request error.
 */
function assertCanonicalSignInputsV2(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw invalidRequest("signing metadata missing — refusing to invoke the signer");
  }
  const out = [];
  for (const si of list) {
    if (!isPlainObject(si)) throw invalidRequest("each signing entry must be a plain object — refusing");
    const extras = Object.keys(si).filter((k) => k !== "index" && k !== "sighashType");
    if (extras.length > 0) {
      throw invalidRequest(`signing entry carries unknown key(s) ${JSON.stringify(extras)} — refusing (closed shape)`);
    }
    if (!Number.isInteger(si.index) || si.index < 0) {
      throw invalidRequest("signing entry index must be an integer >= 0 — refusing");
    }
    if (si.sighashType !== SIGHASH_ALL) {
      throw signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_SIGHASH,
        `signing entry declares sighashType ${JSON.stringify(si.sighashType)}; PolicyVault emits SIGHASH_ALL (${SIGHASH_ALL}) only — refusing before the signer is invoked`,
        { details: { index: si.index } }
      );
    }
    out.push(Object.freeze({ index: si.index, sighashType: SIGHASH_ALL }));
  }
  return Object.freeze(out);
}

/*
 * Personal-message signing request (authentication challenges).
 * `ttlMs` is REQUIRED: a challenge signature request is an authorization
 * and expires like one.
 */
function createMessageSigningRequestV2({ message, scheme, network, expectedSignerAddress, ttlMs, nowMs } = {}) {
  if (typeof message !== "string" || message.length === 0) throw invalidRequest("message must be a non-empty string");
  if (message.length > MAX_MESSAGE_CHARS) throw invalidRequest(`message exceeds ${MAX_MESSAGE_CHARS} characters`);
  const created = Number.isInteger(nowMs) ? nowMs : Date.now();
  const ttl = assertTtl(ttlMs);
  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    requestId: newRequestId(),
    nonce: newNonce(),
    kind: "sign-message",
    message,
    payloadSha256: sha256Hex(message),
    scheme: assertScheme(scheme),
    network: assertNetworkValue(network, false),
    expectedSignerAddress: assertAddress(expectedSignerAddress, false, "expectedSignerAddress"),
    createdAtMs: created,
    expiresAtMs: created + ttl
  });
}

/*
 * Transaction signing request: FROZEN BYTES IN, BOUND ENVELOPE OUT.
 * `unsignedSafeJson` is the EXACT frozen serialization from the SDK
 * builders; this module never parses, rebuilds, edits, trims, or
 * re-encodes it. `payloadSha256` is the fingerprint of those exact bytes
 * — the anchor every later binding check is measured against.
 */
function createTransactionSigningRequestV2({
  unsignedSafeJson,
  signInputs,
  network,
  expectedSignerAddress,
  scheme,
  transactionFormat,
  ttlMs,
  nowMs
} = {}) {
  if (typeof unsignedSafeJson !== "string" || unsignedSafeJson.length === 0) {
    throw invalidRequest("unsignedSafeJson must be the non-empty frozen serialized transaction string");
  }
  if (unsignedSafeJson.length > MAX_SAFE_JSON_CHARS) {
    throw invalidRequest(`unsignedSafeJson exceeds ${MAX_SAFE_JSON_CHARS} characters`);
  }
  const fmt = transactionFormat === undefined ? TRANSACTION_FORMATS[0] : transactionFormat;
  if (typeof fmt !== "string" || !TRANSACTION_FORMATS.includes(fmt)) {
    throw invalidRequest(`unknown transaction format ${JSON.stringify(String(transactionFormat))} — failing closed`);
  }
  const created = Number.isInteger(nowMs) ? nowMs : Date.now();
  const ttl = assertTtl(ttlMs);
  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    requestId: newRequestId(),
    nonce: newNonce(),
    kind: "sign-transaction",
    unsignedSafeJson,
    payloadSha256: sha256Hex(unsignedSafeJson),
    signInputs: assertCanonicalSignInputsV2(signInputs),
    transactionFormat: fmt,
    /* what this request REQUIRES of the signer's sighash behaviour */
    sighash: Object.freeze({ all: true, none: false, single: false, anyoneCanPay: false }),
    network: assertNetworkValue(network, true),
    expectedSignerAddress: assertAddress(expectedSignerAddress, true, "expectedSignerAddress"),
    scheme: scheme === undefined ? undefined : assertScheme(scheme),
    createdAtMs: created,
    expiresAtMs: created + ttl
  });
}

/* Structural re-validation of a v2 request (defense in depth inside
 * executeSigningV2 — requests are re-checked, never trusted by marker).
 * The payload digest is RECOMPUTED: a request whose digest does not match
 * its own payload has been tampered with between creation and use. */
function assertSigningRequestV2(request) {
  if (!isPlainObject(request)) throw invalidRequest("signing request must be a plain object");
  if (request.interfaceVersion !== SIGNER_INTERFACE_VERSION_V2) {
    throw signerErrorV2(
      SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      `signing request declares interface version ${JSON.stringify(request.interfaceVersion)}; this core implements exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION_V2)} — failing closed`
    );
  }
  if (typeof request.requestId !== "string" || !HEX32_RE.test(request.requestId)) throw invalidRequest("signing request requestId must be 32-hex");
  if (typeof request.nonce !== "string" || !HEX64_RE.test(request.nonce)) throw invalidRequest("signing request nonce must be 64-hex (32 CSPRNG bytes)");
  if (!Number.isInteger(request.createdAtMs) || !Number.isInteger(request.expiresAtMs) || request.expiresAtMs <= request.createdAtMs) {
    throw invalidRequest("signing request must carry integer createdAtMs and a strictly later expiresAtMs");
  }
  if (request.expiresAtMs - request.createdAtMs > MAX_TTL_MS) {
    throw invalidRequest(`signing request lifetime exceeds ${MAX_TTL_MS}ms — refusing`);
  }

  if (request.kind === "sign-message") {
    if (typeof request.message !== "string" || !request.message || request.message.length > MAX_MESSAGE_CHARS) {
      throw invalidRequest("sign-message request message is malformed");
    }
    if (request.payloadSha256 !== sha256Hex(request.message)) {
      throw signerErrorV2(
        SignerErrorCodesV2.PAYLOAD_MUTATED,
        "sign-message request payload digest does not match its own message — the request was altered after creation; refusing"
      );
    }
    assertScheme(request.scheme);
    assertNetworkValue(request.network, false);
    assertAddress(request.expectedSignerAddress, false, "expectedSignerAddress");
    return request;
  }
  if (request.kind === "sign-transaction") {
    if (typeof request.unsignedSafeJson !== "string" || !request.unsignedSafeJson || request.unsignedSafeJson.length > MAX_SAFE_JSON_CHARS) {
      throw invalidRequest("sign-transaction request unsignedSafeJson is malformed");
    }
    if (request.payloadSha256 !== sha256Hex(request.unsignedSafeJson)) {
      throw signerErrorV2(
        SignerErrorCodesV2.PAYLOAD_MUTATED,
        "sign-transaction request payload digest does not match its own unsignedSafeJson — the frozen bytes were altered after the request was created; refusing before the signer is invoked"
      );
    }
    assertCanonicalSignInputsV2(request.signInputs);
    if (typeof request.transactionFormat !== "string" || !TRANSACTION_FORMATS.includes(request.transactionFormat)) {
      throw signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT,
        `signing request pins unknown transaction format ${JSON.stringify(String(request.transactionFormat))} — failing closed`
      );
    }
    if (!isPlainObject(request.sighash) || request.sighash.all !== true) {
      throw signerErrorV2(SignerErrorCodesV2.UNSUPPORTED_SIGHASH, "sign-transaction request must require sighash.all — refusing");
    }
    assertNetworkValue(request.network, true);
    assertAddress(request.expectedSignerAddress, true, "expectedSignerAddress");
    if (request.scheme !== undefined) assertScheme(request.scheme);
    return request;
  }
  throw invalidRequest(`unknown signing request kind ${JSON.stringify(String(request.kind))} — failing closed`);
}

/* ------------------------------------------------------------------ */
/* Response envelopes (v2)                                             */
/* ------------------------------------------------------------------ */

const ENVELOPE_KEYS = Object.freeze([
  "interfaceVersion",
  "requestId",
  "nonce",
  "kind",
  "network",
  "signerAddress",
  "scheme",
  "payloadSha256",
  "sighashType",
  "transactionFormat",
  "signedTxId",
  "result"
]);

/*
 * Builds the response envelope an adapter returns. Provided so adapters
 * never hand-assemble the binding fields (and so the shape has exactly
 * one producer). The adapter supplies the signing RESULT; every binding
 * field is copied from the REQUEST, which is why a mis-bound envelope can
 * only come from a transport substitution, a replay, or a signer that
 * answered a different request — precisely the cases v2 detects.
 */
function buildResponseEnvelope(request, result, extra = {}) {
  if (!isPlainObject(request)) throw invalidRequest("buildResponseEnvelope requires the signing request");
  if (!isPlainObject(extra)) throw invalidRequest("buildResponseEnvelope extras must be a plain object");
  for (const key of Object.keys(extra)) {
    if (key !== "signerAddress" && key !== "signedTxId") {
      throw invalidRequest(`unknown buildResponseEnvelope extra ${JSON.stringify(key)} — failing closed`);
    }
  }
  const envelope = {
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    requestId: request.requestId,
    nonce: request.nonce,
    kind: request.kind,
    network: request.network === undefined ? null : request.network,
    signerAddress: extra.signerAddress !== undefined ? extra.signerAddress : request.expectedSignerAddress === undefined ? null : request.expectedSignerAddress,
    scheme: request.scheme === undefined ? null : request.scheme,
    payloadSha256: request.payloadSha256,
    sighashType: request.kind === "sign-transaction" ? SIGHASH_ALL : null,
    transactionFormat: request.kind === "sign-transaction" ? request.transactionFormat : null,
    result
  };
  if (extra.signedTxId !== undefined) envelope.signedTxId = extra.signedTxId;
  return Object.freeze(envelope);
}

/*
 * Validates a response envelope AGAINST its request. Every mismatch is a
 * distinct, structured refusal — this function is the reason a v2
 * consumer can tell "the holder declined" from "the transport handed me
 * somebody else's signature".
 *
 * Order matters: version -> shape -> binding -> sighash/format ->
 * payload identity -> result shape. The cheapest, most fundamental
 * refusals happen first, and no signature material is examined until the
 * envelope is proven to belong to this request.
 */
function validateResponseEnvelope(request, envelope) {
  if (!isPlainObject(envelope)) {
    throw signerErrorV2(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, "signer returned no response envelope — v2 responses are bound envelopes, never bare values");
  }
  if (envelope.interfaceVersion !== SIGNER_INTERFACE_VERSION_V2) {
    throw signerErrorV2(
      SignerErrorCodesV2.INTERFACE_VERSION_UNSUPPORTED,
      `response envelope declares interface version ${JSON.stringify(envelope.interfaceVersion)}; expected exactly ${JSON.stringify(SIGNER_INTERFACE_VERSION_V2)} — failing closed`
    );
  }
  for (const key of Object.keys(envelope)) {
    if (!ENVELOPE_KEYS.includes(key)) {
      throw violation(`response envelope carries unknown key ${JSON.stringify(key)} — refusing (closed schema)`);
    }
  }

  const bindingMismatch = (what, expected, got) =>
    signerErrorV2(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, `response envelope ${what} does not match the request (expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)}) — refusing`, {
      details: { field: what }
    });

  if (envelope.requestId !== request.requestId) throw bindingMismatch("requestId", request.requestId, envelope.requestId);
  if (envelope.nonce !== request.nonce) throw bindingMismatch("nonce", request.nonce, envelope.nonce);
  if (envelope.kind !== request.kind) throw bindingMismatch("kind", request.kind, envelope.kind);

  const expectedNetwork = request.network === undefined ? null : request.network;
  if (envelope.network !== expectedNetwork) {
    /* a signature produced under a different network identity is a
     * WRONG_NETWORK condition, not a generic binding slip */
    throw signerErrorV2(
      SignerErrorCodesV2.WRONG_NETWORK,
      `response envelope reports network ${JSON.stringify(envelope.network)}, request is bound to ${JSON.stringify(expectedNetwork)} — refusing`
    );
  }
  if (request.expectedSignerAddress !== undefined && envelope.signerAddress !== request.expectedSignerAddress) {
    throw signerErrorV2(
      SignerErrorCodesV2.ACCOUNT_CHANGED,
      "response envelope was signed by a different identity than the request is bound to — discarding the signature"
    );
  }
  const expectedScheme = request.scheme === undefined ? null : request.scheme;
  if (envelope.scheme !== expectedScheme) {
    throw signerErrorV2(
      SignerErrorCodesV2.UNSUPPORTED_SCHEME,
      `response envelope declares scheme ${JSON.stringify(envelope.scheme)}, request pinned ${JSON.stringify(expectedScheme)} — refusing (the scheme is never re-negotiated by the signer)`
    );
  }

  if (request.kind === "sign-transaction") {
    if (envelope.sighashType !== SIGHASH_ALL) {
      throw signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_SIGHASH,
        `response envelope reports sighashType ${JSON.stringify(envelope.sighashType)}; PolicyVault accepts SIGHASH_ALL (${SIGHASH_ALL}) only — discarding the signature`
      );
    }
    if (envelope.transactionFormat !== request.transactionFormat) {
      throw signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT,
        `response envelope reports transaction format ${JSON.stringify(envelope.transactionFormat)}, request pinned ${JSON.stringify(request.transactionFormat)} — refusing`
      );
    }
  } else {
    if (envelope.sighashType !== null) throw bindingMismatch("sighashType", null, envelope.sighashType);
    if (envelope.transactionFormat !== null) throw bindingMismatch("transactionFormat", null, envelope.transactionFormat);
  }

  if (envelope.payloadSha256 !== request.payloadSha256) {
    throw signerErrorV2(
      SignerErrorCodesV2.PAYLOAD_MUTATED,
      "response envelope reports a different payload digest than the bytes PolicyVault verified and sent — the signature is not over the verified bytes; discarding it",
      { details: { expectedSha256: request.payloadSha256, reportedSha256: String(envelope.payloadSha256).slice(0, 64) } }
    );
  }

  if (!isPlainObject(envelope.result)) {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "response envelope carries no result object");
  }
  if (request.kind === "sign-message") {
    const keys = Object.keys(envelope.result);
    if (keys.length !== 1 || keys[0] !== "signature") {
      throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, 'sign-message result must carry exactly { signature } — refusing (closed shape)');
    }
    if (request.scheme === "ecdsa") {
      throw signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_SCHEME,
        "interface v2 defines no verified ECDSA personal-message response contract — failing closed (hosted auth refuses ECDSA/Tangem accounts)"
      );
    }
    const raw = envelope.result.signature;
    if (typeof raw !== "string" || !SCHNORR_SIG_RE.test(raw.trim().toLowerCase())) {
      throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "signer returned an unexpected personal-message signature format (expected 128-hex Schnorr)");
    }
    return Object.freeze({ signature: raw.trim().toLowerCase() });
  }

  const keys = Object.keys(envelope.result);
  if (keys.length !== 1 || keys[0] !== "signedSafeJson") {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "sign-transaction result must carry exactly { signedSafeJson } — refusing (closed shape)");
  }
  const signed = envelope.result.signedSafeJson;
  if (typeof signed !== "string" || !signed.trim()) {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, "signer returned no signed transaction serialization");
  }
  if (signed.length > MAX_SAFE_JSON_CHARS) {
    throw signerErrorV2(SignerErrorCodesV2.INVALID_SIGNATURE_RESPONSE, `signed serialization exceeds ${MAX_SAFE_JSON_CHARS} characters — refusing`);
  }
  /* returned VERBATIM — never trimmed, never re-encoded: a downstream
   * validator will check these exact bytes against the frozen txid. */
  return Object.freeze({ signedSafeJson: signed });
}

/* ------------------------------------------------------------------ */
/* Replay guard + cancellation token                                   */
/* ------------------------------------------------------------------ */

/*
 * Session-scoped single-use ledger for requestIds and nonces.
 *
 * WHY: a transport that can deliver a response can usually deliver it
 * TWICE (a duplicate deep-link callback, a QR frame scanned again, a
 * relay retry), and an attacker who captured a valid response can hand
 * it back at a later request. Envelope binding already refuses the
 * second case when the new request has a new nonce; the guard makes the
 * refusal explicit, ordered, and independent of whether the attacker
 * happened to keep the old request around.
 *
 * `open(request)` claims the pair; `consume(request)` spends it exactly
 * once. A second consume is DUPLICATE_SETTLEMENT; a nonce or requestId
 * seen before under a DIFFERENT request is REPLAY_DETECTED.
 */
function createReplayGuard() {
  const openRequests = new Map(); /* requestId -> nonce */
  const seenNonces = new Map(); /* nonce -> requestId */
  const settled = new Set(); /* requestIds already consumed */

  return Object.freeze({
    open(request) {
      const { requestId, nonce } = request;
      if (settled.has(requestId)) {
        throw signerErrorV2(SignerErrorCodesV2.DUPLICATE_SETTLEMENT, `signing request ${requestId} already reached a terminal state — refusing to re-open it`);
      }
      const priorNonceOwner = seenNonces.get(nonce);
      if (priorNonceOwner !== undefined && priorNonceOwner !== requestId) {
        throw signerErrorV2(SignerErrorCodesV2.REPLAY_DETECTED, "signing request reuses a nonce already issued to a different request — refusing (nonces are single-use)");
      }
      const priorNonce = openRequests.get(requestId);
      if (priorNonce !== undefined && priorNonce !== nonce) {
        throw signerErrorV2(SignerErrorCodesV2.REPLAY_DETECTED, `signing request id ${requestId} was already issued with a different nonce — refusing`);
      }
      openRequests.set(requestId, nonce);
      seenNonces.set(nonce, requestId);
      return true;
    },
    consume(request) {
      const { requestId, nonce } = request;
      if (settled.has(requestId)) {
        throw signerErrorV2(SignerErrorCodesV2.DUPLICATE_SETTLEMENT, `a settlement for signing request ${requestId} was already accepted — refusing the duplicate`);
      }
      const openNonce = openRequests.get(requestId);
      if (openNonce === undefined) {
        throw signerErrorV2(SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH, `no open signing request ${requestId} — refusing a settlement for a request this session never issued`);
      }
      if (openNonce !== nonce) {
        throw signerErrorV2(SignerErrorCodesV2.REPLAY_DETECTED, "settlement nonce does not match the nonce this request was issued with — refusing");
      }
      settled.add(requestId);
      openRequests.delete(requestId);
      return true;
    },
    isSettled(requestId) {
      return settled.has(requestId);
    },
    /* diagnostics only (counts, never material) */
    stats() {
      return Object.freeze({ open: openRequests.size, settled: settled.size, noncesSeen: seenNonces.size });
    }
  });
}

/*
 * A minimal cancellation token. Deliberately not AbortController: this
 * module must behave identically in Node and in the browser bundle with
 * no ambient-global assumptions, and the token carries a REASON the
 * lifecycle can report.
 */
function createCancellationToken() {
  const state = { cancelled: false, reason: null, listeners: [] };
  return Object.freeze({
    get cancelled() {
      return state.cancelled;
    },
    get reason() {
      return state.reason;
    },
    cancel(reason) {
      if (state.cancelled) return false;
      state.cancelled = true;
      state.reason = typeof reason === "string" && reason.trim() ? reason.slice(0, 256) : "cancelled by the consumer";
      const listeners = state.listeners.splice(0, state.listeners.length);
      for (const cb of listeners) {
        try {
          cb(state.reason);
        } catch {
          /* a cancellation observer must never alter the outcome */
        }
      }
      return true;
    },
    onCancel(cb) {
      if (typeof cb !== "function") return;
      if (state.cancelled) {
        try {
          cb(state.reason);
        } catch {
          /* isolated */
        }
        return;
      }
      state.listeners.push(cb);
    }
  });
}

/* ------------------------------------------------------------------ */
/* Signing execution + approval lifecycle (v2)                         */
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
  if (isPlainObject(account) && typeof account.address === "string" && account.address.trim()) return account.address.trim();
  throw violation("adapter getActiveAccount() must return null or { address: <non-empty string> }");
}

const EXECUTE_OPTIONS_V2 = Object.freeze([
  "timeoutMs",
  "onTransition",
  "nowMs",
  "replayGuard",
  "cancellation",
  "deriveTransactionId",
  "requireUserPresence",
  "allowedTransports",
  "requireProbedCapabilities"
]);

/*
 * Drives one v2 request through a validated adapter with every
 * fail-closed gate, in this order (nothing reaches the signer until all
 * pre-gates pass):
 *
 *   0. request re-validation (incl. payload-digest recomputation)
 *   1. replay guard: claim requestId + nonce (single use)
 *   2. expiry: the request must not already be stale
 *   3. capability probe: declaration vs observed provider reality
 *   4. capability / scheme gates
 *   5. sighash gate       (SIGHASH_ALL declared by the signer)
 *   6. transaction-format gate (exact pin)
 *   7. transport gate     (consumer's allowed set)
 *   8. user-presence gate (consumer's requirement)
 *   9. deadline gate      (async signers require an explicit timeoutMs;
 *                          the deadline is clamped to the request expiry
 *                          and to the signer's declared maxTimeoutMs)
 *  10. network gate       (declared AND live; unknown/null fails closed)
 *  11. identity gate      (live active account === expectedSignerAddress)
 *
 * then SUBMITTED -> settlement race (provider / timeout / expiry /
 * cancellation) -> envelope binding validation -> single-use consume ->
 * transaction-identity re-derivation (when a deriver is injected) ->
 * post-approval identity re-check -> APPROVED.
 *
 * Exactly ONE terminal transition is emitted; late provider settlements
 * are DISCARDED and can never deliver a signature.
 */
async function executeSigningV2(adapterOrRegistration, request, options = {}) {
  if (!isPlainObject(options)) throw invalidRequest("options must be a plain object");
  for (const key of Object.keys(options)) {
    if (!EXECUTE_OPTIONS_V2.includes(key)) {
      throw invalidRequest(`unknown executeSigning option ${JSON.stringify(key)} — failing closed`);
    }
  }
  const {
    timeoutMs,
    onTransition,
    nowMs,
    replayGuard,
    cancellation,
    deriveTransactionId,
    requireUserPresence,
    allowedTransports,
    requireProbedCapabilities
  } = options;

  if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs <= 0)) {
    throw invalidRequest("timeoutMs must be a positive integer when provided");
  }
  if (deriveTransactionId !== undefined && typeof deriveTransactionId !== "function") {
    throw invalidRequest("deriveTransactionId must be a function when provided");
  }
  if (requireUserPresence !== undefined && typeof requireUserPresence !== "boolean") {
    throw invalidRequest("requireUserPresence must be a boolean when provided");
  }
  if (requireProbedCapabilities !== undefined && typeof requireProbedCapabilities !== "boolean") {
    throw invalidRequest("requireProbedCapabilities must be a boolean when provided");
  }
  const now = () => (Number.isInteger(nowMs) ? nowMs : Date.now());

  const registration =
    isPlainObject(adapterOrRegistration) && adapterOrRegistration.adapter && adapterOrRegistration.descriptor
      ? Object.freeze({ adapter: adapterOrRegistration.adapter, descriptor: validateCapabilityDescriptorV2(adapterOrRegistration.descriptor) })
      : validateAdapterV2(adapterOrRegistration);
  const { adapter, descriptor } = registration;

  assertSigningRequestV2(request);

  const refuse = (err) => {
    emitTransition(onTransition, request.requestId, "REFUSED", { code: err.signerCode });
    throw err;
  };

  /* 1. replay guard — single-use requestId/nonce for this session */
  const guard = replayGuard === undefined ? createReplayGuard() : replayGuard;
  if (!isPlainObject(guard) || typeof guard.open !== "function" || typeof guard.consume !== "function") {
    throw invalidRequest("replayGuard must be a createReplayGuard() token when provided");
  }
  try {
    guard.open(request);
  } catch (e) {
    refuse(normalizeAdapterFailureV2(e, "replayGuard"));
  }

  /* 2. expiry (stale request) */
  if (now() >= request.expiresAtMs) {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.REQUEST_EXPIRED,
        `signing request ${request.requestId} expired at ${request.expiresAtMs} — refusing to present a stale authorization to the signer`
      )
    );
  }

  /* 3. capability probe — declaration vs observed reality */
  let probeResult;
  try {
    probeResult = verifyDeclaredCapabilities(descriptor, await adapter.probeCapabilities());
  } catch (e) {
    refuse(normalizeAdapterFailureV2(e, "probeCapabilities"));
  }
  if (requireProbedCapabilities === true && probeResult.probed !== true) {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.CAPABILITY_MISMATCH,
        `adapter ${descriptor.provider} could not be probed (${probeResult.reason || "no reason given"}) and this consumer requires probed capabilities — refusing`
      )
    );
  }

  /* 4. capability + scheme gates */
  if (request.kind === "sign-message" && descriptor.features.messageSigning !== true) {
    refuse(signerErrorV2(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, `adapter ${descriptor.provider} does not offer messageSigning`));
  }
  if (request.kind === "sign-transaction") {
    if (descriptor.features.transactionSigning !== true) {
      refuse(signerErrorV2(SignerErrorCodesV2.UNSUPPORTED_CAPABILITY, `adapter ${descriptor.provider} does not offer transactionSigning`));
    }
    if (descriptor.features.specificInputSigning !== true) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.UNSUPPORTED_CAPABILITY,
          `adapter ${descriptor.provider} cannot sign exactly the named inputs (specificInputSigning) — v2 transaction requests always carry canonical per-input signing entries; refusing`
        )
      );
    }
    /* 5. sighash gate */
    if (descriptor.sighash.all !== true) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.UNSUPPORTED_SIGHASH,
          `adapter ${descriptor.provider} does not declare SIGHASH_ALL — PolicyVault signs with SIGHASH_ALL only; refusing before the signer is invoked`
        )
      );
    }
    /* 6. transaction-format gate (exact pin) */
    if (!descriptor.transactionFormats.includes(request.transactionFormat)) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.UNSUPPORTED_TRANSACTION_FORMAT,
          `adapter ${descriptor.provider} does not speak transaction format ${JSON.stringify(request.transactionFormat)} — refusing`
        )
      );
    }
  }
  if (request.scheme !== undefined && !descriptor.schemes.includes(request.scheme)) {
    refuse(signerErrorV2(SignerErrorCodesV2.UNSUPPORTED_SCHEME, `adapter ${descriptor.provider} does not offer scheme ${JSON.stringify(request.scheme)}`));
  }
  if (request.kind === "sign-message" && request.scheme !== "schnorr") {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.UNSUPPORTED_SCHEME,
        `interface v2 defines a verified response contract only for schnorr personal-message signatures; refusing scheme ${JSON.stringify(request.scheme)} before invoking the signer`
      )
    );
  }

  /* 7. transport gate */
  if (allowedTransports !== undefined) {
    let allowed;
    try {
      allowed = uniqueKnownList(allowedTransports, TRANSPORT_KINDS, "allowedTransports", invalidRequest);
    } catch (e) {
      refuse(normalizeAdapterFailureV2(e, "allowedTransports"));
    }
    if (allowed.length === 0) refuse(invalidRequest("allowedTransports must be non-empty when provided"));
    if (!allowed.includes(descriptor.transport)) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.TRANSPORT_UNSUPPORTED,
          `adapter ${descriptor.provider} uses the ${descriptor.transport} transport, which this consumer does not accept for this request — refusing`
        )
      );
    }
  }

  /* 8. user-presence gate */
  if (requireUserPresence === true && descriptor.userPresence !== "required") {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.USER_PRESENCE_REQUIRED,
        `adapter ${descriptor.provider} declares userPresence ${JSON.stringify(descriptor.userPresence)} but this request requires a human present at the signer — refusing`
      )
    );
  }

  /* 9. deadline gate */
  if (descriptor.features.asynchronousApproval === true && timeoutMs === undefined) {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.REQUEST_INVALID,
        `adapter ${descriptor.provider} settles approvals asynchronously — an explicit timeoutMs is required (an unbounded wait is refused, fail closed)`
      )
    );
  }
  if (timeoutMs !== undefined && timeoutMs > descriptor.maxTimeoutMs) {
    refuse(
      signerErrorV2(
        SignerErrorCodesV2.REQUEST_INVALID,
        `timeoutMs ${timeoutMs} exceeds the deadline adapter ${descriptor.provider} declares it can honour (${descriptor.maxTimeoutMs}) — refusing rather than waiting past the signer's own limit`
      )
    );
  }

  /* 10. network gate — declared AND live */
  if (request.network !== undefined) {
    if (!descriptor.networks.includes(request.network)) {
      refuse(signerErrorV2(SignerErrorCodesV2.WRONG_NETWORK, `adapter ${descriptor.provider} does not declare network ${JSON.stringify(request.network)}`));
    }
    let liveNetwork;
    try {
      liveNetwork = await adapter.getNetwork();
    } catch (e) {
      refuse(normalizeAdapterFailureV2(e, "getNetwork"));
    }
    if (liveNetwork !== request.network) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.WRONG_NETWORK,
          `signer reports network ${JSON.stringify(liveNetwork === undefined ? null : liveNetwork)}, required ${JSON.stringify(request.network)} — failing closed`
        )
      );
    }
  }

  /* 11. identity gate (pre-invocation) */
  if (request.expectedSignerAddress !== undefined) {
    let before;
    try {
      before = await activeAccountAddress(adapter);
    } catch (e) {
      refuse(normalizeAdapterFailureV2(e, "getActiveAccount"));
    }
    if (before === null) refuse(signerErrorV2(SignerErrorCodesV2.SIGNER_DISCONNECTED, "no active signer account — connect the signer first"));
    if (before !== request.expectedSignerAddress) {
      refuse(
        signerErrorV2(
          SignerErrorCodesV2.ACCOUNT_CHANGED,
          "the active signer account is not the expected signer — refusing to request a signature from a different identity"
        )
      );
    }
  }

  /* ---- invoke the external signer ---- */
  emitTransition(onTransition, request.requestId, "SUBMITTED");
  const invoke = request.kind === "sign-message" ? () => adapter.signMessage(request) : () => adapter.signTransaction(request);
  const providerPromise = Promise.resolve().then(invoke);
  providerPromise.catch(() => {}); /* consumed through the settlement race — never unhandled */

  /* the effective deadline is the EARLIEST of: the consumer's timeout and
   * the request's own expiry. A signer is never given more time than the
   * authorization itself is valid for. */
  const deadlines = [];
  if (timeoutMs !== undefined) deadlines.push({ at: now() + timeoutMs, kind: "timeout" });
  deadlines.push({ at: request.expiresAtMs, kind: "expiry" });
  deadlines.sort((a, b) => a.at - b.at);
  const deadline = deadlines[0];
  const waitMs = Math.max(0, deadline.at - now());

  let timer = null;
  let outcome;
  try {
    outcome = await new Promise((resolve) => {
      /* NOT unref'd: the deadline is the thing that must keep the runtime
       * alive while an out-of-band approval is outstanding. It is always
       * cleared in the finally below, so it can never leak. */
      timer = setTimeout(() => resolve({ deadline: deadline.kind }), waitMs);
      if (isPlainObject(cancellation) && typeof cancellation.onCancel === "function") {
        if (cancellation.cancelled === true) resolve({ cancelled: cancellation.reason });
        else cancellation.onCancel((reason) => resolve({ cancelled: reason }));
      }
      providerPromise.then(
        (value) => resolve({ value }),
        (error) => resolve({ error })
      );
    });
  } finally {
    if (timer) clearTimeout(timer);
  }

  /* best-effort revocation shared by the timeout / expiry / cancel paths.
   * A cancellation failure never masks the terminal condition. */
  const bestEffortCancel = async () => {
    if (typeof adapter.cancelSigning !== "function") return;
    try {
      await adapter.cancelSigning(request.requestId);
    } catch {
      /* best-effort */
    }
  };

  if (outcome.cancelled !== undefined) {
    await bestEffortCancel();
    emitTransition(onTransition, request.requestId, "CANCELLED");
    throw signerErrorV2(
      SignerErrorCodesV2.REQUEST_CANCELLED,
      `signing request ${request.requestId} was cancelled by the consumer (${outcome.cancelled}) — any later settlement is discarded`
    );
  }
  if (outcome.deadline !== undefined) {
    await bestEffortCancel();
    if (outcome.deadline === "expiry") {
      emitTransition(onTransition, request.requestId, "EXPIRED");
      throw signerErrorV2(
        SignerErrorCodesV2.REQUEST_EXPIRED,
        `signing request ${request.requestId} expired before the signer settled — cancelled fail-closed; any later settlement is discarded`
      );
    }
    emitTransition(onTransition, request.requestId, "TIMED_OUT");
    throw signerErrorV2(SignerErrorCodesV2.SIGNER_TIMEOUT, `signing request ${request.requestId} was not approved within ${timeoutMs}ms — cancelled fail-closed`);
  }

  if (outcome.error !== undefined) {
    const err = normalizeAdapterFailureV2(outcome.error, request.kind);
    emitTransition(onTransition, request.requestId, err.signerCode === SignerErrorCodesV2.USER_REJECTED ? "REJECTED" : "FAILED", { code: err.signerCode });
    throw err;
  }

  /* A settlement that arrives after the request's own expiry is stale
   * even if the race resolved first (clock advanced during validation). */
  const fail = (err) => {
    emitTransition(onTransition, request.requestId, "FAILED", { code: err.signerCode });
    throw err;
  };

  let result;
  try {
    result = validateResponseEnvelope(request, outcome.value);
  } catch (e) {
    fail(normalizeAdapterFailureV2(e, request.kind));
  }

  /* single-use settlement: a duplicate callback or a replayed envelope
   * cannot be accepted twice */
  try {
    guard.consume(request);
  } catch (e) {
    fail(normalizeAdapterFailureV2(e, "settlement"));
  }

  /* transaction-identity re-derivation (injected; the core holds no
   * transaction code). Kaspa txids EXCLUDE signature scripts, so a
   * correctly signed transaction has the SAME id as the unsigned one —
   * a different id means different consensus-visible bytes were signed. */
  let txIdVerified = false;
  let transactionId = null;
  if (request.kind === "sign-transaction" && deriveTransactionId !== undefined) {
    let unsignedId;
    let signedId;
    try {
      unsignedId = deriveTransactionId(request.unsignedSafeJson);
      signedId = deriveTransactionId(result.signedSafeJson);
    } catch (e) {
      fail(
        signerErrorV2(SignerErrorCodesV2.PAYLOAD_MUTATED, "the signed serialization could not be parsed to re-derive its transaction id — refusing to accept unverifiable bytes", {
          cause: e
        })
      );
    }
    if (typeof unsignedId !== "string" || !unsignedId || typeof signedId !== "string" || !signedId) {
      fail(violation("deriveTransactionId must return a non-empty transaction id string — refusing"));
    }
    if (unsignedId !== signedId) {
      fail(
        signerErrorV2(
          SignerErrorCodesV2.PAYLOAD_MUTATED,
          "the signer returned a DIFFERENT transaction than the one PolicyVault verified and sent (transaction id drift) — discarding the signature",
          { details: { expectedTxId: unsignedId, returnedTxId: signedId } }
        )
      );
    }
    if (isPlainObject(outcome.value) && outcome.value.signedTxId !== undefined && outcome.value.signedTxId !== signedId) {
      fail(
        signerErrorV2(
          SignerErrorCodesV2.RESPONSE_BINDING_MISMATCH,
          "the response envelope claims a transaction id that the signed bytes do not produce — refusing",
          { details: { claimed: String(outcome.value.signedTxId).slice(0, 128), derived: signedId } }
        )
      );
    }
    txIdVerified = true;
    transactionId = signedId;
  }

  /* post-approval identity re-check: a mid-prompt account switch discards
   * the signature (v1 parity, mirroring web/app-v4.js walletSign I). */
  if (request.expectedSignerAddress !== undefined) {
    let after = null;
    try {
      after = await activeAccountAddress(adapter);
    } catch (e) {
      fail(normalizeAdapterFailureV2(e, "getActiveAccount"));
    }
    if (after !== request.expectedSignerAddress) {
      fail(
        signerErrorV2(
          SignerErrorCodesV2.ACCOUNT_CHANGED,
          "signer account changed during signing — refusing to accept a signature from a different identity"
        )
      );
    }
  }

  emitTransition(onTransition, request.requestId, "APPROVED");
  return Object.freeze({
    interfaceVersion: SIGNER_INTERFACE_VERSION_V2,
    requestId: request.requestId,
    status: "approved",
    provider: descriptor.provider,
    transport: descriptor.transport,
    capabilitiesProbed: probeResult.probed === true,
    txIdVerified,
    transactionId,
    result
  });
}

module.exports = {
  SIGNER_INTERFACE_VERSION_V2,
  SIGNATURE_SCHEMES,
  SIGNER_NETWORKS,
  ADAPTER_KINDS,
  CAPABILITY_FEATURES,
  REQUEST_KINDS,
  SIGHASH_ALL,
  SIGHASH_FLAGS,
  TRANSACTION_FORMATS,
  PSKT_ROLES,
  TRANSPORT_KINDS,
  USER_PRESENCE_MODES,
  CANCELLATION_MODES,
  SIGNING_STATES_V2,
  REQUIRED_METHODS_V2,
  FEATURE_METHODS_V2,
  DESCRIPTOR_KEYS_V2,
  REQUIREMENT_KEYS_V2,
  ENVELOPE_KEYS,
  MIN_TTL_MS,
  MAX_TTL_MS,
  POLICYVAULT_TRANSACTION_REQUIREMENTS,
  validateCapabilityDescriptorV2,
  validateProbeReport,
  verifyDeclaredCapabilities,
  validateAdapterV2,
  SignerRegistryV2,
  negotiateCapabilitiesV2,
  requireCapabilitiesV2,
  normalizePublicKeyToXOnly: v1.normalizePublicKeyToXOnly,
  assertCanonicalSignInputsV2,
  createMessageSigningRequestV2,
  createTransactionSigningRequestV2,
  assertSigningRequestV2,
  buildResponseEnvelope,
  validateResponseEnvelope,
  createReplayGuard,
  createCancellationToken,
  executeSigningV2,
  sha256Hex
};
