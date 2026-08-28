/*
 * PolicyVault browser core bundle — GENERATED FILE, do not edit by hand.
 * Generator: web/tools/build-core-bundle.js (committed; deterministic:
 * same input bytes => same bundle bytes; regenerate + byte-compare with
 * `node web/tools/build-core-bundle.js --check`).
 *
 * Embedded portable shared-core sources, VERBATIM (sha256 of each):
 *   core/intent/canonical.js  sha256:158d5a2663c1c49e7c9a43853d3c8f303185106011099bf71340195bde549b8d
 *   core/intent/manifest.js  sha256:e7dab437f4f413792b6a7c00df06a01213997fa194c749813554e43e4b9a5955
 *   core/intent/verify.js  sha256:0a1b0e685fc74e16559b1f6361da72b59e06203f8d55b41538e0c15588b98985
 *   core/intent/index.js  sha256:75aea5b60fe2e8eb12838d1b2f994b156eddabeb5cc5faa7959b3523e7737d4e
 *   core/explain/kas.js  sha256:2906726fa5ed5f13703e5f806dba654e17b64c04979d3f5597836d155f241b0b
 *   core/explain/intent-explain.js  sha256:f49c7cb836f1c6a148b46bb58adb83a98e9fa5ac8e1f0e949be6c04bd58d4ad4
 *   core/signer/errors.js  sha256:30210486548ff12a3a1ac9d697ec8094e2b1fa99823f37ca6c2f6768165bb195
 *   core/signer/interface.js  sha256:4f8f0fc31da573d06bbe3ccb4374fbe02c5c94c15977c68f1bdcb2cf79d6a291
 *   core/model/amounts.js  sha256:a7bcc3c928ce0fe96e77ce33d1a2036087c777509f433c2799bed6f4dfdbc107
 *   core/model/contract-version.js  sha256:6e29edc3c29746f9b953bc5456c179f3e7cf54bb26331ffe4949adf5610aacac
 *   core/model/vault-state.js  sha256:bfcdacab6b22de5d1ecc442d73610fa7fb7ac34ffa7a3f3e76a9a56eac5fc98b
 *   core/model/recipient-merkle-v3.js  sha256:87b9da1560896bc383f749b594763e26c507f29d73cc38d0ae0606c120134b73
 *   core/model/agent-merkle-v4.js  sha256:8fb098c7657adb6ba5de1d377a1929d1adf5b2934d28d2b366d7badd98fe9d7c
 *   core/model/compute-budget-v3.js  sha256:5a8d7588a837a36d689c11474b4a96f690e22f8f0509ca486fdedea267b7b188
 *   core/model/compute-budget-v4.js  sha256:81f71aba783ccbded39ad076dbbf4431ee9e0a9c14dbbdf9b4b26f8b37e5cb64
 *   core/model/fee-mass.js  sha256:c1eb9277d018cc5fd7dcba96e9f6718e22e270aa0a01f58dc81559d3150e2e4c
 *   core/model/frozen-tx-v3.js  sha256:01571212821a9ff9e0a7befcc92d409bdf84c0f60e61e70b361b039bd9ea7567
 *   core/model/vault-state-v4.js  sha256:27dfae8761a4ecdf0d986e0daaf637a90f69d60fd1abe21a4b61849d46659eb9
 *   core/model/vault-transitions-v4.js  sha256:5f3ee089848488e1c22dbd96c09c0199da830c247cd79d9c4542c27d535c5655
 *   core/governance/canonical.js  sha256:f4efbfdb97d3b279beedcb1094d220bacb40dc605b2e3e28671ec8b7b08087c6
 *   core/governance/authority-delta.js  sha256:d9e452d02e4d64cc5d92f6b2485b75e3b60076d291365ebbada27f56fe9a9f55
 *   core/governance/index.js  sha256:3a4480b6488c5d17596a60f3993284b987ec87ca2987df909becba8fed24104c
 *   core/explain/governance-explain.js  sha256:546e3e8a8d33f5bb0433e1874e9cd823f7c066a54d5db61010fa130fe88b3679
 *   core/explain/risk-explain.js  sha256:d4af12eddc339a3c2b4c176d86b058526aa6b825f778c9dc1e5acbb04b1fe43b
 *   <crypto shim>  sha256:18c64bc952c83297a0abe5b25e4a70a28740875eeac9b60335df40a984aeb681
 */
(function (globalScope) {
  "use strict";
  var factories = {};
  var cache = {};

  function define(id, factory) { factories[id] = factory; }

  /* Resolve a require request against the requesting module id.
   * CLOSED module set: anything unresolvable throws (fail closed). */
  function resolveId(fromId, request) {
    if (request === "crypto" || request === "node:crypto") return "crypto";
    var base = request.charAt(0) === "." ? fromId.split("/").slice(0, -1) : [];
    var segments = base.concat(request.split("/"));
    var out = [];
    for (var i = 0; i < segments.length; i++) {
      var seg = segments[i];
      if (seg === "" || seg === ".") continue;
      if (seg === "..") { if (out.length === 0) throw new Error("core-bundle: path escape in require " + JSON.stringify(request)); out.pop(); continue; }
      out.push(seg);
    }
    var id = out.join("/").replace(/\.js$/, "");
    if (factories[id]) return id;
    if (factories[id + "/index"]) return id + "/index";
    throw new Error("core-bundle: module " + JSON.stringify(request) + " (from " + fromId + ") is not in the bundled module set — failing closed");
  }

  function load(id) {
    if (cache[id]) return cache[id].exports;
    var module = { exports: {} };
    cache[id] = module;
    factories[id](module, module.exports, function (request) { return load(resolveId(id, request)); });
    return module.exports;
  }

  define("crypto", function (module, exports, require) {
"use strict";
/* browser crypto shim — sha256 (sync, pure JS) + randomBytes only; fail closed elsewhere */
var K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
function utf8Bytes(text) {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
  /* minimal UTF-8 encoder fallback (correct for all code points incl. surrogate pairs) */
  var out = [];
  for (var i = 0; i < text.length; i++) {
    var c = text.codePointAt(i);
    if (c > 0xffff) i++;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}
function sha256Bytes(msg) {
  var len = msg.length;
  var bitLenHi = Math.floor(len / 0x20000000);
  var bitLenLo = (len << 3) >>> 0;
  var padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  var dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLenHi);
  dv.setUint32(padded.length - 4, bitLenLo);
  var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
      h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  var w = new Int32Array(64);
  for (var off = 0; off < padded.length; off += 64) {
    var i;
    for (i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (i = 16; i < 64; i++) {
      var w15 = w[i - 15], w2 = w[i - 2];
      var s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      var s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
  }
  var out = new Uint8Array(32);
  var dvOut = new DataView(out.buffer);
  var hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (var j = 0; j < 8; j++) dvOut.setUint32(j * 4, hs[j] >>> 0);
  return out;
}
function hexOfBytes(bytes) {
  var hex = "";
  for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}
function shimFail(message) { throw new Error("core-bundle crypto shim: " + message + " — failing closed"); }
module.exports = {
  createHash: function (algorithm) {
    if (algorithm !== "sha256") shimFail("unsupported hash algorithm " + JSON.stringify(algorithm));
    var parts = [];
    var digested = false;
    return {
      update: function (data, encoding) {
        if (typeof data === "string") {
          if (encoding !== undefined && encoding !== "utf8" && encoding !== "utf-8") shimFail("unsupported update encoding " + JSON.stringify(encoding));
          if (digested) shimFail("update after digest");
          parts.push({ s: data });
          return this;
        }
        /* Uint8Array check is realm-safe: instanceof for the common
         * single-realm case, plus the unspoofable ArrayBuffer.isView brand
         * + constructor name for byte arrays from another realm (vm test
         * harnesses; an embedding page's iframes). Everything else still
         * fails closed. */
        if (data instanceof Uint8Array || (ArrayBuffer.isView(data) && data.constructor && data.constructor.name === "Uint8Array")) {
          if (encoding !== undefined) shimFail("byte updates take no encoding");
          if (digested) shimFail("update after digest");
          parts.push({ b: data });
          return this;
        }
        shimFail("createHash update supports UTF-8 strings and Uint8Array bytes only in the browser");
      },
      digest: function (format) {
        if (format !== undefined && format !== "hex") shimFail("unsupported digest format " + JSON.stringify(format));
        if (digested) shimFail("digest called twice");
        digested = true;
        /* Adjacent string parts are JOINED BEFORE UTF-8 encoding — exactly
         * the pre-extension all-string behavior; byte parts concatenate
         * verbatim in call order. */
        var chunks = [];
        var run = null;
        for (var i = 0; i < parts.length; i++) {
          if (parts[i].s !== undefined) {
            run = run === null ? parts[i].s : run + parts[i].s;
          } else {
            if (run !== null) { chunks.push(utf8Bytes(run)); run = null; }
            chunks.push(parts[i].b);
          }
        }
        if (run !== null) chunks.push(utf8Bytes(run));
        var total = 0;
        for (var c = 0; c < chunks.length; c++) total += chunks[c].length;
        var msg = new Uint8Array(total);
        var off = 0;
        for (var m = 0; m < chunks.length; m++) { msg.set(chunks[m], off); off += chunks[m].length; }
        var digestBytes = sha256Bytes(msg);
        return format === "hex" ? hexOfBytes(digestBytes) : digestBytes;
      }
    };
  },
  randomBytes: function (size) {
    if (!Number.isInteger(size) || size <= 0 || size > 65536) shimFail("randomBytes size out of range");
    var g = typeof globalThis !== "undefined" ? globalThis.crypto : undefined;
    if (!g || typeof g.getRandomValues !== "function") shimFail("no secure random source available");
    var bytes = new Uint8Array(size);
    g.getRandomValues(bytes);
    return {
      toString: function (format) {
        if (format !== "hex") shimFail("randomBytes toString supports hex only");
        var hex = "";
        for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
        return hex;
      }
    };
  }
};
  });

  define("core/intent/canonical", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Transaction Intent Manifest — canonical JSON + manifest hash.
 *
 * PORTABLE SHARED CORE (core/intent): pure Node (CommonJS), zero external
 * dependencies, no server/SDK imports. Runnable later in browser / mobile /
 * CLI / server contexts (the only Node builtin used is node:crypto sha256,
 * isolated behind sha256Hex for future substitution by WebCrypto).
 *
 * The canonical serialization here MIRRORS THE SEMANTICS of
 * sdk/src/canonical-json.js (the Phase G defect G-2 remediation) without
 * importing it — the manifest hash MUST be representation-independent:
 * PostgreSQL jsonb canonicalizes object key order (a real production
 * incident: an approval-package commitment preimage that was
 * JSON-key-order-sensitive recomputed differently after a postgres round
 * trip with every value byte-intact, voiding collected approvals).
 *
 * Rules (identical to sdk/src/canonical-json.js):
 *   - arrays keep element order (order is consensus-meaningful: inputs,
 *     outputs, approver slots, Merkle siblings);
 *   - object keys serialize in lexicographic (UTF-16 code unit) order;
 *   - primitives serialize exactly as JSON.stringify does;
 *   - anything not plainly JSON fails CLOSED instead of serializing
 *     surprisingly: undefined values, functions, symbols, BigInt,
 *     non-finite numbers, and non-plain objects (Date, Map, class
 *     instances) all throw. A manifest hash preimage must never silently
 *     omit or coerce a field the way bare JSON.stringify would.
 */

const crypto = require("crypto");

/*
 * Hash-domain separation: this exact prefix keeps intent-manifest hashes
 * from ever colliding with any other sha256(canonical-json) commitment in
 * the PolicyVault codebase (approval-package commitments, frozen-tx
 * commitments, state IDs). Version-bound: a future manifest version defines
 * its own domain string; it never reuses this one.
 */
const MANIFEST_HASH_DOMAIN_V1 = "policyvault-intent-manifest-hash/1\n";

function fail(message) {
  const e = new Error(`intent-canonical: ${message}`);
  e.code = "CANONICAL_JSON_INVALID";
  throw e;
}

function serialize(value, path) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) fail(`non-finite number at ${path} — failing closed`);
    return JSON.stringify(value);
  }
  if (t === "bigint") fail(`BigInt at ${path} — consensus integers must be committed as decimal strings`);
  if (t === "undefined") fail(`undefined at ${path} — a manifest field may not be silently omitted`);
  if (t === "function" || t === "symbol") fail(`${t} at ${path} — not JSON`);
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => serialize(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      fail(`non-plain object at ${path} — refusing to canonicalize`);
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      parts.push(`${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`)}`);
    }
    return `{${parts.join(",")}}`;
  }
  fail(`unsupported type ${t} at ${path}`);
}

/* Deterministic, storage-representation-independent JSON serialization. */
function canonicalJsonStringify(value) {
  return serialize(value, "$");
}

/* sha256 hex of a UTF-8 string (the one Node-builtin dependency). */
function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/*
 * The v1 manifest hash: sha256 over the domain prefix + the canonical JSON
 * of the manifest BODY. The body is the manifest document with the
 * `manifestHash` key itself removed (a hash cannot cover itself). There is
 * deliberately NO timestamp anywhere in the hashed body: identical
 * transaction facts must always produce the identical manifest hash, on
 * any machine, at any time, through any storage backend.
 */
function computeManifestHashV1(manifestBody) {
  if (manifestBody === null || typeof manifestBody !== "object" || Array.isArray(manifestBody)) {
    fail("manifest body must be a plain object");
  }
  if (Object.prototype.hasOwnProperty.call(manifestBody, "manifestHash")) {
    fail("manifest body must not contain manifestHash — strip it before hashing");
  }
  return sha256Hex(MANIFEST_HASH_DOMAIN_V1 + canonicalJsonStringify(manifestBody));
}

/*
 * Value equality under the canonical serialization: true iff two documents
 * carry the identical VALUES, regardless of key order or storage
 * representation. Throws (fails closed) if either side is not canonically
 * serializable.
 */
function canonicalEqual(a, b) {
  return canonicalJsonStringify(a) === canonicalJsonStringify(b);
}

module.exports = {
  MANIFEST_HASH_DOMAIN_V1,
  canonicalJsonStringify,
  sha256Hex,
  computeManifestHashV1,
  canonicalEqual
};
  });

  define("core/intent/manifest", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Transaction Intent Manifest v1 — schema + validation + build.
 *
 * A manifest is a deterministic, portable JSON description of what ONE
 * proposed PolicyVault transaction ACTUALLY does: identity, decoded
 * transaction facts, state before/after, exact value accounting, limits,
 * approvals, allowlist evaluation, and the explicit policy-mutation diff.
 * The companion verifier (verify.js) compares a manifest against the
 * structured requested intent and the structured decoded transaction and
 * emits its verified statement ONLY when every fail-closed detector passes.
 *
 * Field shapes MIRROR the real SDK structures (never invented):
 *   - state tuple           -> sdk/src/vault-state-v4.js  stateToJsonV4
 *   - agent policy leaf     -> sdk/src/agent-merkle-v4.js normalizeAgentPolicyV4
 *   - decoded transaction   -> sdk/src/frozen-tx-v3.js    canonicalFrozenTxJson
 *   - accounting (11 keys)  -> sdk/src/vault-builders-v4.js build.accounting
 *   - action/role table     -> sdk/src/wallet-requests-v4.js ROLE_BY_ACTION
 *   - nonce + mutable-field -> sdk/src/vault-transitions-v4.js
 *   - amount discipline     -> sdk/src/amounts.js (integer sompi only)
 *
 * HARD RULES (fail closed, never a default route):
 *   - unknown manifest versions, intent versions, covenant versions, and
 *     actions are refused with a specific code;
 *   - every schema is CLOSED: unknown keys are refused (a hidden field is
 *     a hidden effect);
 *   - all consensus/accounting quantities are CANONICAL base-10 digit
 *     strings ("0" or no leading zero) parsed to BigInt — JS numbers are
 *     refused on every amount path (one value = one encoding = one hash);
 *   - hex is exact-width lowercase only (one value = one encoding);
 *   - the manifest hash is representation-independent (canonical.js).
 *
 * Portable shared core: pure CommonJS, zero external deps, no SDK/server
 * imports.
 */

const { canonicalJsonStringify, computeManifestHashV1 } = require("./canonical");

const MANIFEST_VERSION_1 = "policyvault-intent-manifest/1";
const REQUESTED_INTENT_VERSION_1 = "policyvault-requested-intent/1";

/* Covenant versions manifest v1 can DESCRIBE AND VERIFY (the v0.4 family,
 * mirroring sdk/src/vault-state-v4.js V4_ABIS). Anything else — unknown OR
 * simply not covered by manifest v1 (e.g. policyvault-0.3) — is refused;
 * a future manifest version extends coverage additively. */
const SUPPORTED_COVENANT_VERSIONS = Object.freeze(["policyvault-0.4", "policyvault-0.4.1"]);

/* Integer sompi domain — mirrors sdk/src/amounts.js. */
const SOMPI_PER_KAS = 100000000n;
const MAX_SOMPI = 29000000000n * SOMPI_PER_KAS;

const MAX_APPROVERS = 10;
const APPROVER_SENTINEL = "00".repeat(32);
const NATIVE_SUBNETWORK = "00".repeat(20);
const MAX_POLICY_NONCE = 1000000000n; // vault-state-v4 policyNonce bound
const MAX_PERIODS_ELAPSED = 1000n; // covenant: require(periodsElapsed <= 1000)

/*
 * Per-action metadata — mirrors ROLE_BY_ACTION (wallet-requests-v4.js),
 * the per-entrypoint mutable-field matrix and the exact policyNonce rule
 * (vault-transitions-v4.js), plus genesis. Unknown actions FAIL CLOSED.
 *   nonce "preserve":  agentSpend, ownerTopUp, ownerTopUpReserve,
 *                      ownerPause, ownerUnpause
 *   nonce "increment": ownerSetAgentRoot, ownerSetApprovers
 */
const ACTIONS = Object.freeze({
  agentSpend: Object.freeze({ role: "agent", genesis: false, terminal: false, mutable: Object.freeze(["protectedValue", "feeReserve", "agentRoot"]), nonce: "preserve" }),
  ownerSetAgentRoot: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["agentRoot"]), nonce: "increment" }),
  ownerSetApprovers: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["approverSlots", "approvalM"]), nonce: "increment" }),
  ownerTopUp: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["protectedValue"]), nonce: "preserve" }),
  ownerTopUpReserve: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["feeReserve"]), nonce: "preserve" }),
  ownerPause: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["paused"]), nonce: "preserve" }),
  ownerUnpause: Object.freeze({ role: "owner", genesis: false, terminal: false, mutable: Object.freeze(["paused"]), nonce: "preserve" }),
  ownerRecover: Object.freeze({ role: "owner", genesis: false, terminal: true, mutable: Object.freeze([]), nonce: null }),
  createVault: Object.freeze({ role: "owner", genesis: true, terminal: false, mutable: Object.freeze([]), nonce: null })
});

/* High-level owner agent-lifecycle actions map to ownerSetAgentRoot at the
 * SDK layer (wallet-requests-v4.js planV4); the manifest records both. */
const HIGH_LEVEL_TO_SDK = Object.freeze({
  addAgent: "ownerSetAgentRoot",
  removeAgent: "ownerSetAgentRoot",
  rotateAgent: "ownerSetAgentRoot",
  rePolicyAgent: "ownerSetAgentRoot"
});

/* v0.4-family state tuple field names in canonical order (stateToJsonV4). */
const STATE_FIELDS = Object.freeze(["protectedValue", "feeReserve", "paused", "agentRoot", "approverSlots", "approvalM", "policyNonce"]);

/* v0.4 agent policy leaf field names (agent-merkle-v4.js). */
const AGENT_POLICY_FIELDS = Object.freeze([
  "agentPk",
  "maxPerSpend",
  "periodBudget",
  "periodLengthDaa",
  "periodStartDaa",
  "periodSpent",
  "approvalThreshold",
  "agentMaxFeePerTx",
  "agentRecipientRoot"
]);

/* Builder accounting field names (vault-builders-v4.js build.accounting). */
const ACCOUNTING_FIELDS = Object.freeze([
  "predecessorProtected",
  "predecessorFeeReserve",
  "payAmount",
  "reserveConsumed",
  "externalIn",
  "externalOut",
  "fee",
  "successorProtected",
  "successorFeeReserve",
  "successorTotal",
  "terminalPayout"
]);

const INPUT_KINDS = Object.freeze(["covenant", "external"]);
const OUTPUT_KINDS = Object.freeze(["successor", "payment", "change", "recoverPayout", "genesisVault", "agentFuel"]);

/* ------------------------------------------------------------------ */
/* refusal + guards                                                    */
/* ------------------------------------------------------------------ */

function refuse(code, message) {
  const e = new Error(`intent-manifest: ${message}`);
  e.code = code;
  throw e;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function requireObject(v, path) {
  if (!isPlainObject(v)) refuse("SCHEMA_INVALID", `${path} must be a plain object`);
  return v;
}

/* CLOSED schema: exactly these keys — unknown keys are hidden effects. */
function requireExactKeys(obj, keys, path) {
  requireObject(obj, path);
  for (const k of Object.keys(obj)) {
    if (!keys.includes(k)) refuse("SCHEMA_INVALID", `${path} carries unknown key ${JSON.stringify(k)} — failing closed`);
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) refuse("SCHEMA_INVALID", `${path}.${k} is required`);
  }
  return obj;
}

const CANONICAL_DIGITS_RE = /^(0|[1-9][0-9]*)$/;

/*
 * Canonical integer-sompi guard (STRICTER than sdk/src/amounts.js
 * parseSompi, which accepts leading zeros): a manifest quantity must have
 * exactly one encoding, because the manifest hash is a function of the
 * encoding of values. Rejects everything that is not a canonical base-10
 * digit string: numbers (floating-point risk: NaN/Infinity/negatives/
 * unsafe integers all arrive as numbers), BigInt (not JSON), signs,
 * decimals, exponents, whitespace, leading zeros, non-ASCII digits.
 */
function parseAmount(value, field, { min = 0n, max = MAX_SOMPI } = {}) {
  if (typeof value !== "string") {
    refuse("VALUE_INVALID", `${field} must be a canonical base-10 digit string, got ${typeof value}`);
  }
  if (!CANONICAL_DIGITS_RE.test(value)) {
    refuse("VALUE_INVALID", `${field} is not a canonical base-10 digit string: ${JSON.stringify(value)}`);
  }
  const amount = BigInt(value);
  if (amount < min) refuse("VALUE_INVALID", `${field} must be >= ${min}`);
  if (amount > max) refuse("VALUE_INVALID", `${field} exceeds the maximum representable value (${max})`);
  return amount;
}

function parsePositiveAmount(value, field, opts = {}) {
  return parseAmount(value, field, { ...opts, min: 1n });
}

/* Structural JS integers (indexes, computeBudget, script version) — the
 * only place JS numbers are accepted, mirroring frozen-tx-v3.js. */
function requireInt(value, field, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    refuse("VALUE_INVALID", `${field} must be a safe integer, got ${typeof value === "number" ? String(value) : typeof value}`);
  }
  if (value < min || value > max) refuse("VALUE_INVALID", `${field} out of range [${min}, ${max}]`);
  return value;
}

/* Exact-width LOWERCASE hex only — one value, one encoding, one hash.
 * (sdk normalizeHex lowercases; a manifest must already be canonical.) */
function requireHex(value, bytes, field) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    refuse("VALUE_INVALID", `${field} must be ${bytes}-byte lowercase hex`);
  }
  return value;
}

function requireEvenHex(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be non-empty even-length lowercase hex`);
  }
  return value;
}

function requireBool(value, field) {
  if (typeof value !== "boolean") refuse("VALUE_INVALID", `${field} must be a boolean`);
  return value;
}

function requireNetworkId(value, field) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be a lowercase network id (e.g. "mainnet", "testnet-10")`);
  }
  return value;
}

function requireCode(value, field) {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(value)) {
    refuse("VALUE_INVALID", `${field} must be an UPPER_SNAKE code`);
  }
  return value;
}

function requireDetail(value, field) {
  if (typeof value !== "string" || value.length > 2000) {
    refuse("VALUE_INVALID", `${field} must be a string of at most 2000 characters`);
  }
  return value;
}

/* Kaspa standard P2PK script for an x-only key: OP_DATA_32 <key>
 * OP_CHECKSIG — mirrors sdk p2pkScriptHex (approval-package-v3.js). */
function p2pkScriptHex(xOnly) {
  return `20${xOnly}ac`;
}

/* ------------------------------------------------------------------ */
/* component schemas                                                   */
/* ------------------------------------------------------------------ */

/* v0.4-family state tuple — exact stateToJsonV4 shape. Returns a parsed
 * BigInt view; the input document is left untouched. */
function validateStateShape(state, path) {
  requireExactKeys(state, STATE_FIELDS, path);
  const protectedValue = parsePositiveAmount(state.protectedValue, `${path}.protectedValue`);
  const feeReserve = parseAmount(state.feeReserve, `${path}.feeReserve`);
  const paused = parseAmount(state.paused, `${path}.paused`, { max: 1n });
  const agentRoot = requireHex(state.agentRoot, 32, `${path}.agentRoot`);
  if (!Array.isArray(state.approverSlots) || state.approverSlots.length !== MAX_APPROVERS) {
    refuse("SCHEMA_INVALID", `${path}.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
  }
  const seen = new Set();
  let activeCount = 0;
  state.approverSlots.forEach((k, i) => {
    const key = requireHex(k, 32, `${path}.approverSlots[${i}]`);
    if (key !== APPROVER_SENTINEL) {
      if (seen.has(key)) refuse("SCHEMA_INVALID", `${path}.approverSlots[${i}] duplicates an earlier active approver key`);
      seen.add(key);
      activeCount += 1;
    }
  });
  const approvalM = parseAmount(state.approvalM, `${path}.approvalM`, { max: BigInt(MAX_APPROVERS) });
  if (activeCount === 0) {
    if (approvalM !== 0n) refuse("SCHEMA_INVALID", `${path}.approvalM must be 0 when there are no active approvers`);
  } else {
    if (approvalM < 1n) refuse("SCHEMA_INVALID", `${path}.approvalM must be >= 1 when approvers are configured`);
    if (approvalM > BigInt(activeCount)) refuse("SCHEMA_INVALID", `${path}.approvalM exceeds the active approver count (${activeCount})`);
  }
  const policyNonce = parseAmount(state.policyNonce, `${path}.policyNonce`, { max: MAX_POLICY_NONCE });
  return { protectedValue, feeReserve, paused, agentRoot, approverSlots: state.approverSlots.slice(), activeCount, approvalM, policyNonce };
}

/* v0.4 agent policy leaf — exact agent-merkle-v4 field set. */
function validateAgentPolicyShape(policy, path) {
  requireExactKeys(policy, AGENT_POLICY_FIELDS, path);
  return {
    agentPk: requireHex(policy.agentPk, 32, `${path}.agentPk`),
    maxPerSpend: parsePositiveAmount(policy.maxPerSpend, `${path}.maxPerSpend`),
    periodBudget: parsePositiveAmount(policy.periodBudget, `${path}.periodBudget`),
    periodLengthDaa: parsePositiveAmount(policy.periodLengthDaa, `${path}.periodLengthDaa`),
    periodStartDaa: parseAmount(policy.periodStartDaa, `${path}.periodStartDaa`),
    periodSpent: parseAmount(policy.periodSpent, `${path}.periodSpent`),
    approvalThreshold: parseAmount(policy.approvalThreshold, `${path}.approvalThreshold`),
    agentMaxFeePerTx: parseAmount(policy.agentMaxFeePerTx, `${path}.agentMaxFeePerTx`),
    agentRecipientRoot: requireHex(policy.agentRecipientRoot, 32, `${path}.agentRecipientRoot`)
  };
}

function validateOutpoint(op, path) {
  requireExactKeys(op, ["transactionId", "index"], path);
  return {
    transactionId: requireHex(op.transactionId, 32, `${path}.transactionId`),
    index: requireInt(op.index, `${path}.index`, { max: 0xffffffff })
  };
}

/* ------------------------------------------------------------------ */
/* requested intent v1                                                 */
/* ------------------------------------------------------------------ */

/* Per-action closed parameter schemas. Every quantity a canonical digit
 * string; every key a 32-byte lowercase hex x-only pubkey / root. */
function validateRequestedIntent(intent) {
  requireObject(intent, "requestedIntent");
  if (intent.intentVersion !== REQUESTED_INTENT_VERSION_1) {
    refuse("UNKNOWN_INTENT_VERSION", `unknown requested-intent version ${JSON.stringify(intent.intentVersion)} — failing closed`);
  }
  requireExactKeys(intent, ["intentVersion", "networkId", "vaultId", "covenantVersion", "action", "params", "maxFeeSompi"], "requestedIntent");
  requireNetworkId(intent.networkId, "requestedIntent.networkId");
  requireHex(intent.vaultId, 32, "requestedIntent.vaultId");
  if (!SUPPORTED_COVENANT_VERSIONS.includes(intent.covenantVersion)) {
    refuse("UNSUPPORTED_COVENANT_VERSION", `covenant version ${JSON.stringify(intent.covenantVersion)} is not supported by manifest v1 — failing closed`);
  }
  const requestedAction = intent.action;
  const highLevelAction = Object.prototype.hasOwnProperty.call(HIGH_LEVEL_TO_SDK, requestedAction) ? requestedAction : null;
  const sdkAction = highLevelAction ? HIGH_LEVEL_TO_SDK[requestedAction] : requestedAction;
  if (!Object.prototype.hasOwnProperty.call(ACTIONS, sdkAction)) {
    refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(requestedAction)} — failing closed`);
  }
  if (intent.maxFeeSompi !== null) parsePositiveAmount(intent.maxFeeSompi, "requestedIntent.maxFeeSompi");

  const p = intent.params;
  const path = "requestedIntent.params";
  switch (sdkAction) {
    case "agentSpend": {
      requireExactKeys(p, ["agentPk", "recipient", "payAmountSompi", "periodsElapsed", "reserveConsumedSompi"], path);
      requireHex(p.agentPk, 32, `${path}.agentPk`);
      requireHex(p.recipient, 32, `${path}.recipient`);
      parsePositiveAmount(p.payAmountSompi, `${path}.payAmountSompi`);
      parseAmount(p.periodsElapsed, `${path}.periodsElapsed`, { max: MAX_PERIODS_ELAPSED });
      parseAmount(p.reserveConsumedSompi, `${path}.reserveConsumedSompi`);
      break;
    }
    case "ownerSetAgentRoot": {
      /* High-level lifecycle intents (addAgent / removeAgent / rotateAgent
       * / rePolicyAgent) must still pin the RESOLVED newAgentRoot — the
       * requested-vs-built binding is on the exact root commitment. */
      requireExactKeys(p, ["newAgentRoot"], path);
      requireHex(p.newAgentRoot, 32, `${path}.newAgentRoot`);
      break;
    }
    case "ownerSetApprovers": {
      requireExactKeys(p, ["newApproverSlots", "newApprovalM"], path);
      if (!Array.isArray(p.newApproverSlots) || p.newApproverSlots.length !== MAX_APPROVERS) {
        refuse("SCHEMA_INVALID", `${path}.newApproverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
      }
      p.newApproverSlots.forEach((k, i) => requireHex(k, 32, `${path}.newApproverSlots[${i}]`));
      parseAmount(p.newApprovalM, `${path}.newApprovalM`, { max: BigInt(MAX_APPROVERS) });
      break;
    }
    case "ownerTopUp": {
      requireExactKeys(p, ["topUpAmountSompi"], path);
      parsePositiveAmount(p.topUpAmountSompi, `${path}.topUpAmountSompi`);
      break;
    }
    case "ownerTopUpReserve": {
      requireExactKeys(p, ["topUpReserveAmountSompi"], path);
      parsePositiveAmount(p.topUpReserveAmountSompi, `${path}.topUpReserveAmountSompi`);
      break;
    }
    case "ownerPause":
    case "ownerUnpause":
    case "ownerRecover": {
      requireExactKeys(p, [], path);
      break;
    }
    case "createVault": {
      requireExactKeys(p, ["owner", "initialState", "agentFuel"], path);
      requireHex(p.owner, 32, `${path}.owner`);
      const st = validateStateShape(p.initialState, `${path}.initialState`);
      if (st.policyNonce !== 0n) refuse("SCHEMA_INVALID", `${path}.initialState.policyNonce must be "0" at genesis`);
      if (st.paused !== 0n) refuse("SCHEMA_INVALID", `${path}.initialState must start unpaused`);
      if (p.agentFuel !== null) {
        requireExactKeys(p.agentFuel, ["xOnly", "amountSompi"], `${path}.agentFuel`);
        requireHex(p.agentFuel.xOnly, 32, `${path}.agentFuel.xOnly`);
        parsePositiveAmount(p.agentFuel.amountSompi, `${path}.agentFuel.amountSompi`);
      }
      break;
    }
    default:
      refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(sdkAction)} — failing closed`);
  }
  return { requestedAction, highLevelAction, sdkAction, info: ACTIONS[sdkAction] };
}

/* ------------------------------------------------------------------ */
/* decoded transaction                                                 */
/* ------------------------------------------------------------------ */

/*
 * Decoded (frozen, unsigned) transaction document: exactly the
 * canonicalFrozenTxJson field set from sdk/src/frozen-tx-v3.js, plus txId.
 * The frozen form is the security object: for version-1 Kaspa transactions
 * the txId excludes signature scripts, so this txId equals the final
 * broadcast txId.
 */
function validateTransactionShape(tx, path) {
  requireExactKeys(tx, ["txId", "version", "inputs", "outputs", "lockTime", "subnetworkId", "gas", "payload"], path);
  requireHex(tx.txId, 32, `${path}.txId`);
  if (tx.version !== 1) refuse("SCHEMA_INVALID", `${path}.version must be 1 (Toccata)`);
  parseAmount(tx.lockTime, `${path}.lockTime`, { max: (1n << 64n) - 1n });
  if (tx.subnetworkId !== NATIVE_SUBNETWORK) refuse("SCHEMA_INVALID", `${path}.subnetworkId must be the native subnetwork`);
  if (tx.gas !== "0") refuse("SCHEMA_INVALID", `${path}.gas must be "0"`);
  if (tx.payload !== "") refuse("SCHEMA_INVALID", `${path}.payload must be empty`);
  if (!Array.isArray(tx.inputs) || tx.inputs.length === 0) refuse("SCHEMA_INVALID", `${path}.inputs must be a non-empty array`);
  if (!Array.isArray(tx.outputs) || tx.outputs.length === 0) refuse("SCHEMA_INVALID", `${path}.outputs must be a non-empty array`);

  const inputs = tx.inputs.map((input, i) => {
    const ip = `${path}.inputs[${i}]`;
    requireExactKeys(input, ["previousOutpoint", "sequence", "computeBudget", "utxo"], ip);
    const previousOutpoint = validateOutpoint(input.previousOutpoint, `${ip}.previousOutpoint`);
    const sequence = parseAmount(input.sequence, `${ip}.sequence`, { max: (1n << 64n) - 1n });
    const computeBudget = requireInt(input.computeBudget, `${ip}.computeBudget`, { max: 0xffff });
    requireExactKeys(input.utxo, ["amount", "scriptPublicKey", "covenantId", "blockDaaScore"], `${ip}.utxo`);
    requireExactKeys(input.utxo.scriptPublicKey, ["version", "scriptHex"], `${ip}.utxo.scriptPublicKey`);
    const utxo = {
      amount: parsePositiveAmount(input.utxo.amount, `${ip}.utxo.amount`),
      scriptVersion: requireInt(input.utxo.scriptPublicKey.version, `${ip}.utxo.scriptPublicKey.version`, { max: 0xffff }),
      scriptHex: requireEvenHex(input.utxo.scriptPublicKey.scriptHex, `${ip}.utxo.scriptPublicKey.scriptHex`),
      covenantId: input.utxo.covenantId === null ? null : requireHex(input.utxo.covenantId, 32, `${ip}.utxo.covenantId`),
      blockDaaScore: parseAmount(input.utxo.blockDaaScore, `${ip}.utxo.blockDaaScore`)
    };
    return { previousOutpoint, sequence, computeBudget, utxo };
  });

  const outputs = tx.outputs.map((output, i) => {
    const op = `${path}.outputs[${i}]`;
    requireExactKeys(output, ["value", "scriptPublicKey", "covenant"], op);
    requireExactKeys(output.scriptPublicKey, ["version", "scriptHex"], `${op}.scriptPublicKey`);
    let covenant = null;
    if (output.covenant !== null) {
      requireExactKeys(output.covenant, ["authorizingInput", "covenantId"], `${op}.covenant`);
      covenant = {
        authorizingInput: requireInt(output.covenant.authorizingInput, `${op}.covenant.authorizingInput`, { max: 0xffff }),
        covenantId: requireHex(output.covenant.covenantId, 32, `${op}.covenant.covenantId`)
      };
    }
    return {
      value: parsePositiveAmount(output.value, `${op}.value`),
      scriptVersion: requireInt(output.scriptPublicKey.version, `${op}.scriptPublicKey.version`, { max: 0xffff }),
      scriptHex: requireEvenHex(output.scriptPublicKey.scriptHex, `${op}.scriptPublicKey.scriptHex`),
      covenant
    };
  });

  return { txId: tx.txId, lockTime: parseAmount(tx.lockTime, `${path}.lockTime`), inputs, outputs };
}

/* effects: one classification entry per transaction input/output, in
 * order. Covenant-bearing consistency is structural: an input is
 * "covenant" iff its UTXO carries a covenantId; an output is
 * "successor"/"genesisVault" iff it carries a covenant binding. */
function validateEffects(effects, txView, path) {
  requireExactKeys(effects, ["inputs", "outputs"], path);
  if (!Array.isArray(effects.inputs) || effects.inputs.length !== txView.inputs.length) {
    refuse("SCHEMA_INVALID", `${path}.inputs must classify every transaction input exactly once`);
  }
  if (!Array.isArray(effects.outputs) || effects.outputs.length !== txView.outputs.length) {
    refuse("SCHEMA_INVALID", `${path}.outputs must classify every transaction output exactly once`);
  }
  effects.inputs.forEach((entry, i) => {
    requireExactKeys(entry, ["index", "kind"], `${path}.inputs[${i}]`);
    if (entry.index !== i) refuse("SCHEMA_INVALID", `${path}.inputs[${i}].index must be ${i} (in order)`);
    if (!INPUT_KINDS.includes(entry.kind)) refuse("SCHEMA_INVALID", `${path}.inputs[${i}].kind must be one of ${INPUT_KINDS.join("/")}`);
    const hasCovenantId = txView.inputs[i].utxo.covenantId !== null;
    if ((entry.kind === "covenant") !== hasCovenantId) {
      refuse("SCHEMA_INVALID", `${path}.inputs[${i}] kind ${entry.kind} contradicts the input's covenantId presence`);
    }
  });
  effects.outputs.forEach((entry, i) => {
    requireExactKeys(entry, ["index", "kind"], `${path}.outputs[${i}]`);
    if (entry.index !== i) refuse("SCHEMA_INVALID", `${path}.outputs[${i}].index must be ${i} (in order)`);
    if (!OUTPUT_KINDS.includes(entry.kind)) refuse("SCHEMA_INVALID", `${path}.outputs[${i}].kind must be one of ${OUTPUT_KINDS.join("/")}`);
    const bound = txView.outputs[i].covenant !== null;
    const boundKind = entry.kind === "successor" || entry.kind === "genesisVault";
    if (boundKind !== bound) {
      refuse("SCHEMA_INVALID", `${path}.outputs[${i}] kind ${entry.kind} contradicts the output's covenant binding`);
    }
  });
  return {
    inputKinds: effects.inputs.map((e) => e.kind),
    outputKinds: effects.outputs.map((e) => e.kind)
  };
}

function validateNotes(list, path) {
  if (!Array.isArray(list)) refuse("SCHEMA_INVALID", `${path} must be an array`);
  list.forEach((entry, i) => {
    requireExactKeys(entry, ["code", "detail"], `${path}[${i}]`);
    requireCode(entry.code, `${path}[${i}].code`);
    requireDetail(entry.detail, `${path}[${i}].detail`);
  });
}

/* ------------------------------------------------------------------ */
/* full manifest validation                                            */
/* ------------------------------------------------------------------ */

const MANIFEST_KEYS = Object.freeze([
  "manifestVersion",
  "network",
  "vault",
  "action",
  "actor",
  "requested",
  "transaction",
  "effects",
  "stateBefore",
  "stateAfter",
  "accounting",
  "payment",
  "allowlist",
  "approvals",
  "limits",
  "policyMutations",
  "warnings",
  "unexpectedEffects",
  "manifestHash"
]);

/*
 * STRICT fail-closed validation of a complete manifest document.
 * Shape, domains, closed key sets, identity cross-references, and the
 * representation-independent hash. Value EQUATIONS (state transitions,
 * conservation, request binding, detectors) live in verify.js.
 *
 * Returns a parsed context view for the verifier. Throws coded errors:
 * UNKNOWN_MANIFEST_VERSION / UNSUPPORTED_COVENANT_VERSION /
 * UNKNOWN_ACTION / UNKNOWN_INTENT_VERSION / SCHEMA_INVALID /
 * VALUE_INVALID / MANIFEST_HASH_MISMATCH.
 */
function validateManifest(manifest) {
  requireObject(manifest, "manifest");
  /* Version FIRST: an unknown version must refuse with its own code before
   * any structural assumption is applied — never route to a default. */
  if (manifest.manifestVersion !== MANIFEST_VERSION_1) {
    refuse("UNKNOWN_MANIFEST_VERSION", `unknown manifest version ${JSON.stringify(manifest.manifestVersion)} — failing closed`);
  }
  requireExactKeys(manifest, MANIFEST_KEYS, "manifest");

  /* network / vault */
  requireExactKeys(manifest.network, ["networkId"], "manifest.network");
  requireNetworkId(manifest.network.networkId, "manifest.network.networkId");
  requireExactKeys(manifest.vault, ["vaultId", "owner", "covenantVersion", "covenantId"], "manifest.vault");
  requireHex(manifest.vault.vaultId, 32, "manifest.vault.vaultId");
  requireHex(manifest.vault.owner, 32, "manifest.vault.owner");
  if (!SUPPORTED_COVENANT_VERSIONS.includes(manifest.vault.covenantVersion)) {
    refuse("UNSUPPORTED_COVENANT_VERSION", `covenant version ${JSON.stringify(manifest.vault.covenantVersion)} is not supported by manifest v1 — failing closed`);
  }
  requireHex(manifest.vault.covenantId, 32, "manifest.vault.covenantId");

  /* action — unknown actions refuse with their own code before the walk. */
  requireObject(manifest.action, "manifest.action");
  const sdkAction = manifest.action.sdkAction;
  if (typeof sdkAction !== "string" || !Object.prototype.hasOwnProperty.call(ACTIONS, sdkAction)) {
    refuse("UNKNOWN_ACTION", `unknown action ${JSON.stringify(sdkAction)} — failing closed`);
  }
  const info = ACTIONS[sdkAction];
  requireExactKeys(manifest.action, ["sdkAction", "highLevelAction", "role", "genesis", "terminal", "aboveThreshold"], "manifest.action");
  const highLevel = manifest.action.highLevelAction;
  if (highLevel !== null) {
    if (!Object.prototype.hasOwnProperty.call(HIGH_LEVEL_TO_SDK, highLevel) || HIGH_LEVEL_TO_SDK[highLevel] !== sdkAction) {
      refuse("SCHEMA_INVALID", `manifest.action.highLevelAction ${JSON.stringify(highLevel)} does not map to ${sdkAction}`);
    }
  }
  if (manifest.action.role !== info.role) refuse("SCHEMA_INVALID", `manifest.action.role must be ${JSON.stringify(info.role)} for ${sdkAction}`);
  if (requireBool(manifest.action.genesis, "manifest.action.genesis") !== info.genesis) {
    refuse("SCHEMA_INVALID", `manifest.action.genesis must be ${info.genesis} for ${sdkAction}`);
  }
  if (requireBool(manifest.action.terminal, "manifest.action.terminal") !== info.terminal) {
    refuse("SCHEMA_INVALID", `manifest.action.terminal must be ${info.terminal} for ${sdkAction}`);
  }
  requireBool(manifest.action.aboveThreshold, "manifest.action.aboveThreshold");
  if (manifest.action.aboveThreshold && sdkAction !== "agentSpend") {
    refuse("SCHEMA_INVALID", "manifest.action.aboveThreshold can be true only for agentSpend");
  }

  /* actor — canonical identity is the x-only pubkey (never an address). */
  requireExactKeys(manifest.actor, ["role", "signerXOnly", "agentPk"], "manifest.actor");
  if (manifest.actor.role !== info.role) refuse("SCHEMA_INVALID", `manifest.actor.role must be ${JSON.stringify(info.role)} for ${sdkAction}`);
  requireHex(manifest.actor.signerXOnly, 32, "manifest.actor.signerXOnly");
  if (sdkAction === "agentSpend") {
    requireHex(manifest.actor.agentPk, 32, "manifest.actor.agentPk");
    if (manifest.actor.agentPk !== manifest.actor.signerXOnly) {
      refuse("SCHEMA_INVALID", "manifest.actor.agentPk must equal manifest.actor.signerXOnly for agentSpend (the acting agent signs)");
    }
  } else {
    if (manifest.actor.agentPk !== null) refuse("SCHEMA_INVALID", "manifest.actor.agentPk must be null for owner actions");
    if (manifest.actor.signerXOnly !== manifest.vault.owner) {
      refuse("SCHEMA_INVALID", `${sdkAction} is an owner operation — manifest.actor.signerXOnly must equal manifest.vault.owner`);
    }
  }

  /* requested intent — embedded, and identity-bound to this manifest. */
  const requested = validateRequestedIntent(manifest.requested);
  if (requested.sdkAction !== sdkAction) {
    refuse("SCHEMA_INVALID", `manifest.requested action resolves to ${requested.sdkAction}, but manifest.action.sdkAction is ${sdkAction}`);
  }
  if (requested.highLevelAction !== highLevel) {
    refuse("SCHEMA_INVALID", "manifest.action.highLevelAction must equal the requested high-level action (or null)");
  }
  if (manifest.requested.networkId !== manifest.network.networkId) {
    refuse("SCHEMA_INVALID", "manifest.requested.networkId differs from manifest.network.networkId");
  }
  if (manifest.requested.vaultId !== manifest.vault.vaultId) {
    refuse("SCHEMA_INVALID", "manifest.requested.vaultId differs from manifest.vault.vaultId");
  }
  if (manifest.requested.covenantVersion !== manifest.vault.covenantVersion) {
    refuse("SCHEMA_INVALID", "manifest.requested.covenantVersion differs from manifest.vault.covenantVersion");
  }

  /* transaction + effects */
  const txView = validateTransactionShape(manifest.transaction, "manifest.transaction");
  const effects = validateEffects(manifest.effects, txView, "manifest.effects");

  /* stateBefore / stateAfter null-ness matrix */
  let stateBefore = null;
  if (info.genesis) {
    if (manifest.stateBefore !== null) refuse("SCHEMA_INVALID", "manifest.stateBefore must be null for genesis (createVault)");
  } else {
    requireExactKeys(manifest.stateBefore, ["outpoint", "stateId", "state"], "manifest.stateBefore");
    stateBefore = {
      outpoint: validateOutpoint(manifest.stateBefore.outpoint, "manifest.stateBefore.outpoint"),
      stateId: requireHex(manifest.stateBefore.stateId, 32, "manifest.stateBefore.stateId"),
      state: validateStateShape(manifest.stateBefore.state, "manifest.stateBefore.state")
    };
  }
  let stateAfter = null;
  if (info.terminal) {
    if (manifest.stateAfter !== null) refuse("SCHEMA_INVALID", "manifest.stateAfter must be null for the terminal action (ownerRecover)");
  } else {
    requireExactKeys(manifest.stateAfter, ["stateId", "state", "expectedOutpoint"], "manifest.stateAfter");
    stateAfter = {
      stateId: requireHex(manifest.stateAfter.stateId, 32, "manifest.stateAfter.stateId"),
      state: validateStateShape(manifest.stateAfter.state, "manifest.stateAfter.state"),
      expectedOutpoint: validateOutpoint(manifest.stateAfter.expectedOutpoint, "manifest.stateAfter.expectedOutpoint")
    };
  }

  /* accounting — the exact 11 builder fields, all canonical amounts. */
  requireExactKeys(manifest.accounting, ACCOUNTING_FIELDS, "manifest.accounting");
  const accounting = {};
  for (const field of ACCOUNTING_FIELDS) {
    accounting[field] = parseAmount(manifest.accounting[field], `manifest.accounting.${field}`);
  }

  /* agentSpend-only sections (null-ness matrix). */
  const isSpend = sdkAction === "agentSpend";
  let payment = null;
  let allowlist = null;
  let approvals = null;
  let limits = null;
  if (isSpend) {
    requireExactKeys(manifest.payment, ["recipientXOnly", "amountSompi", "outputIndex"], "manifest.payment");
    payment = {
      recipientXOnly: requireHex(manifest.payment.recipientXOnly, 32, "manifest.payment.recipientXOnly"),
      amountSompi: parsePositiveAmount(manifest.payment.amountSompi, "manifest.payment.amountSompi"),
      outputIndex: requireInt(manifest.payment.outputIndex, "manifest.payment.outputIndex", { max: txView.outputs.length - 1 })
    };
    requireExactKeys(manifest.allowlist, ["agentRecipientRoot", "recipientAllowlisted", "proofSupplied"], "manifest.allowlist");
    allowlist = {
      agentRecipientRoot: requireHex(manifest.allowlist.agentRecipientRoot, 32, "manifest.allowlist.agentRecipientRoot"),
      recipientAllowlisted: requireBool(manifest.allowlist.recipientAllowlisted, "manifest.allowlist.recipientAllowlisted"),
      proofSupplied: requireBool(manifest.allowlist.proofSupplied, "manifest.allowlist.proofSupplied")
    };
    requireExactKeys(manifest.approvals, ["aboveThreshold", "approvalThreshold", "requiredM"], "manifest.approvals");
    approvals = {
      aboveThreshold: requireBool(manifest.approvals.aboveThreshold, "manifest.approvals.aboveThreshold"),
      approvalThreshold: parseAmount(manifest.approvals.approvalThreshold, "manifest.approvals.approvalThreshold"),
      requiredM: parseAmount(manifest.approvals.requiredM, "manifest.approvals.requiredM", { max: BigInt(MAX_APPROVERS) })
    };
    if (approvals.aboveThreshold !== manifest.action.aboveThreshold) {
      refuse("SCHEMA_INVALID", "manifest.approvals.aboveThreshold must equal manifest.action.aboveThreshold");
    }
    requireExactKeys(manifest.limits, ["policyBefore", "policyAfter", "periodsElapsed"], "manifest.limits");
    limits = {
      policyBefore: validateAgentPolicyShape(manifest.limits.policyBefore, "manifest.limits.policyBefore"),
      policyAfter: validateAgentPolicyShape(manifest.limits.policyAfter, "manifest.limits.policyAfter"),
      periodsElapsed: parseAmount(manifest.limits.periodsElapsed, "manifest.limits.periodsElapsed", { max: MAX_PERIODS_ELAPSED })
    };
  } else {
    if (manifest.payment !== null) refuse("SCHEMA_INVALID", `manifest.payment must be null for ${sdkAction}`);
    if (manifest.allowlist !== null) refuse("SCHEMA_INVALID", `manifest.allowlist must be null for ${sdkAction}`);
    if (manifest.approvals !== null) refuse("SCHEMA_INVALID", `manifest.approvals must be null for ${sdkAction}`);
    if (manifest.limits !== null) refuse("SCHEMA_INVALID", `manifest.limits must be null for ${sdkAction}`);
  }

  /* policyMutations — the explicit state-diff declaration. */
  if (!Array.isArray(manifest.policyMutations)) refuse("SCHEMA_INVALID", "manifest.policyMutations must be an array");
  if ((info.genesis || info.terminal) && manifest.policyMutations.length !== 0) {
    refuse("SCHEMA_INVALID", "manifest.policyMutations must be empty for genesis/terminal actions (no predecessor/successor pair to diff)");
  }
  const seenFields = new Set();
  manifest.policyMutations.forEach((entry, i) => {
    requireExactKeys(entry, ["field", "before", "after"], `manifest.policyMutations[${i}]`);
    if (!STATE_FIELDS.includes(entry.field)) {
      refuse("SCHEMA_INVALID", `manifest.policyMutations[${i}].field ${JSON.stringify(entry.field)} is not a state field`);
    }
    if (seenFields.has(entry.field)) refuse("SCHEMA_INVALID", `manifest.policyMutations declares ${entry.field} twice`);
    seenFields.add(entry.field);
    const checkSide = (side, label) => {
      if (entry.field === "approverSlots") {
        if (!Array.isArray(side) || side.length !== MAX_APPROVERS) {
          refuse("SCHEMA_INVALID", `manifest.policyMutations[${i}].${label} must be a ${MAX_APPROVERS}-slot array for approverSlots`);
        }
        side.forEach((k, j) => requireHex(k, 32, `manifest.policyMutations[${i}].${label}[${j}]`));
      } else if (entry.field === "agentRoot") {
        requireHex(side, 32, `manifest.policyMutations[${i}].${label}`);
      } else {
        parseAmount(side, `manifest.policyMutations[${i}].${label}`);
      }
    };
    checkSide(entry.before, "before");
    checkSide(entry.after, "after");
  });

  /* warnings + unexpectedEffects. The unexpectedEffects FIELD exists so an
   * upstream builder that detects something unexplained can RECORD it —
   * verify.js refuses any manifest where it is non-empty. */
  validateNotes(manifest.warnings, "manifest.warnings");
  validateNotes(manifest.unexpectedEffects, "manifest.unexpectedEffects");

  /* manifest hash LAST (over the structurally valid body). */
  requireHex(manifest.manifestHash, 32, "manifest.manifestHash");
  const body = {};
  for (const k of MANIFEST_KEYS) {
    if (k !== "manifestHash") body[k] = manifest[k];
  }
  const recomputed = computeManifestHashV1(body);
  if (recomputed !== manifest.manifestHash) {
    refuse(
      "MANIFEST_HASH_MISMATCH",
      "manifest hash does not match a recomputation over the canonical serialization — the manifest was mutated after it was built (or was built with a non-canonical hasher)"
    );
  }

  return {
    manifest,
    sdkAction,
    info,
    txView,
    effects,
    stateBefore,
    stateAfter,
    accounting,
    payment,
    allowlist,
    approvals,
    limits
  };
}

/* ------------------------------------------------------------------ */
/* deterministic state diff                                            */
/* ------------------------------------------------------------------ */

/*
 * The canonical policy-mutation diff between two state documents (JSON
 * form), in fixed STATE_FIELDS order. Deterministic: same states -> same
 * diff array, always.
 */
function diffStates(beforeState, afterState) {
  const diff = [];
  for (const field of STATE_FIELDS) {
    const b = beforeState[field];
    const a = afterState[field];
    const equal = field === "approverSlots" ? canonicalJsonStringify(b) === canonicalJsonStringify(a) : b === a;
    if (!equal) {
      diff.push({
        field,
        before: field === "approverSlots" ? b.slice() : b,
        after: field === "approverSlots" ? a.slice() : a
      });
    }
  }
  return diff;
}

/* ------------------------------------------------------------------ */
/* build                                                               */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

/*
 * Assemble a v1 manifest from structured inputs (in a real integration:
 * the requested intent, the SDK build output bridged to JSON — frozen tx
 * via canonicalFrozenTxJson + txId, states via stateToJsonV4, the builder
 * accounting object — and the effect classification). The builder DERIVES
 * action metadata, the policy-mutation diff, the expected successor
 * outpoint, and the manifest hash; it accepts NO caller-supplied verdict.
 * The result is re-validated through the full strict schema before it is
 * returned — buildIntentManifest can never emit an invalid manifest — and
 * the caller is expected to run verifyIntentManifest before trusting it.
 */
function buildIntentManifest(inputs) {
  requireObject(inputs, "inputs");
  requireExactKeys(
    inputs,
    [
      "requestedIntent",
      "network",
      "vault",
      "signerXOnly",
      "transaction",
      "effects",
      "stateBefore",
      "stateAfter",
      "accounting",
      "payment",
      "allowlist",
      "approvals",
      "limits",
      "warnings",
      "unexpectedEffects"
    ],
    "inputs"
  );

  const requested = validateRequestedIntent(inputs.requestedIntent);
  const info = requested.info;

  /* effects: accept plain kind-string arrays; expand to {index, kind}. */
  requireExactKeys(inputs.effects, ["inputs", "outputs"], "inputs.effects");
  if (!Array.isArray(inputs.effects.inputs) || !Array.isArray(inputs.effects.outputs)) {
    refuse("SCHEMA_INVALID", "inputs.effects.inputs/outputs must be arrays of kind strings");
  }
  const effects = {
    inputs: inputs.effects.inputs.map((kind, index) => ({ index, kind })),
    outputs: inputs.effects.outputs.map((kind, index) => ({ index, kind }))
  };

  /* Derived action metadata — the builder computes it; callers cannot
   * claim a role/genesis/terminal combination the action table refutes. */
  const aboveThreshold = requested.sdkAction === "agentSpend" ? requireBool(requireObject(inputs.approvals, "inputs.approvals").aboveThreshold, "inputs.approvals.aboveThreshold") : false;
  const action = {
    sdkAction: requested.sdkAction,
    highLevelAction: requested.highLevelAction,
    role: info.role,
    genesis: info.genesis,
    terminal: info.terminal,
    aboveThreshold
  };
  const actor = {
    role: info.role,
    signerXOnly: requireHex(inputs.signerXOnly, 32, "inputs.signerXOnly"),
    agentPk: requested.sdkAction === "agentSpend" ? requireHex(inputs.signerXOnly, 32, "inputs.signerXOnly") : null
  };

  /* stateAfter.expectedOutpoint: DERIVED — txId of this transaction plus
   * the index of its covenant-bound (successor / genesisVault) output. */
  let stateAfter = null;
  if (!info.terminal) {
    requireObject(inputs.stateAfter, "inputs.stateAfter");
    requireExactKeys(inputs.stateAfter, ["stateId", "state"], "inputs.stateAfter");
    const txDoc = requireObject(inputs.transaction, "inputs.transaction");
    const boundIndex = effects.outputs.findIndex((e) => e.kind === "successor" || e.kind === "genesisVault");
    if (boundIndex < 0) refuse("SCHEMA_INVALID", "a non-terminal manifest requires a successor/genesisVault output classification");
    stateAfter = {
      stateId: inputs.stateAfter.stateId,
      state: inputs.stateAfter.state,
      expectedOutpoint: { transactionId: txDoc.txId, index: boundIndex }
    };
  } else if (inputs.stateAfter !== null) {
    refuse("SCHEMA_INVALID", "inputs.stateAfter must be null for the terminal action");
  }

  /* policyMutations: DERIVED deterministic diff — never caller-supplied. */
  let policyMutations = [];
  if (!info.genesis && !info.terminal) {
    const beforeDoc = requireObject(inputs.stateBefore, "inputs.stateBefore");
    requireExactKeys(beforeDoc, ["outpoint", "stateId", "state"], "inputs.stateBefore");
    validateStateShape(beforeDoc.state, "inputs.stateBefore.state");
    validateStateShape(stateAfter.state, "inputs.stateAfter.state");
    policyMutations = diffStates(beforeDoc.state, stateAfter.state);
  }

  const body = {
    manifestVersion: MANIFEST_VERSION_1,
    network: inputs.network,
    vault: inputs.vault,
    action,
    actor,
    requested: inputs.requestedIntent,
    transaction: inputs.transaction,
    effects,
    stateBefore: info.genesis ? null : inputs.stateBefore,
    stateAfter,
    accounting: inputs.accounting,
    payment: inputs.payment,
    allowlist: inputs.allowlist,
    approvals: inputs.approvals,
    limits: inputs.limits,
    policyMutations,
    warnings: inputs.warnings ?? [],
    unexpectedEffects: inputs.unexpectedEffects ?? []
  };
  const manifest = { ...body, manifestHash: computeManifestHashV1(body) };

  /* Self-check: the builder can never return an invalid manifest. */
  validateManifest(manifest);
  return deepFreeze(manifest);
}

module.exports = {
  MANIFEST_VERSION_1,
  REQUESTED_INTENT_VERSION_1,
  SUPPORTED_COVENANT_VERSIONS,
  SOMPI_PER_KAS,
  MAX_SOMPI,
  MAX_APPROVERS,
  APPROVER_SENTINEL,
  NATIVE_SUBNETWORK,
  MAX_POLICY_NONCE,
  MAX_PERIODS_ELAPSED,
  ACTIONS,
  HIGH_LEVEL_TO_SDK,
  STATE_FIELDS,
  AGENT_POLICY_FIELDS,
  ACCOUNTING_FIELDS,
  INPUT_KINDS,
  OUTPUT_KINDS,
  refuse,
  parseAmount,
  parsePositiveAmount,
  requireInt,
  requireHex,
  requireEvenHex,
  p2pkScriptHex,
  validateStateShape,
  validateAgentPolicyShape,
  validateRequestedIntent,
  validateTransactionShape,
  validateManifest,
  diffStates,
  buildIntentManifest
};
  });

  define("core/intent/verify", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Transaction Intent Manifest v1 — fail-closed verification.
 *
 * verifyIntentManifest compares a manifest against the structured
 * REQUESTED INTENT and the structured DECODED TRANSACTION and runs the
 * complete detector catalogue. Every detector returns structured
 * failures; the overall verdict is VERIFIED_EXACT — and the verified
 * statement is emitted — ONLY when every detector passes. Anything
 * unknown, missing, ambiguous, or unexplained REFUSES.
 *
 * Detector catalogue (spec §7):
 *   manifest-valid            schema/version/action/hash (validateManifest)
 *   intent-binding            supplied intent ≡ embedded intent
 *   transaction-binding       supplied decoded tx ≡ embedded transaction
 *   tx-shape                  requested action ⇒ exact transaction shape
 *   predecessor               covenant input = the exact predecessor UTXO
 *   successor                 covenant output = the exact declared successor
 *   outputs-explained         every output's script+value justified
 *   value-conservation        exact sompi ledger identities
 *   fee                       positive fee, bounded by the requested cap
 *   request-equations         requested parameters = manifest values
 *   state-transition          per-action state equations, authorized fields
 *   nonce-rule                exact per-action policyNonce rule
 *   policy-mutations-declared declared diff = recomputed diff
 *   limits                    agent policy arithmetic (v0.4 covenant rules)
 *   authority                 no unexplained authority expansion
 *   unexpected-effects        recorded unexplained effects refuse
 *
 * The equations mirror sdk/src/vault-transitions-v4.js and
 * sdk/src/vault-builders-v4.js exactly. What this verifier deliberately
 * does NOT re-implement (delegated to the layers that already prove it
 * with real consensus code): consensus hashing (txId/sighash come from
 * rusty-kaspa via pv_tx_probe), Schnorr signature verification, Merkle
 * fold recomputation, covenant script compilation, and VM execution.
 * The manifest pins those layers' outputs; this verifier proves the
 * transaction's declared meaning is EXACTLY the requested meaning.
 */

const { canonicalJsonStringify } = require("./canonical");
const { ACTIONS, validateManifest, diffStates, p2pkScriptHex } = require("./manifest");

const VERIFIED_STATEMENT = "THIS TRANSACTION DOES EXACTLY WHAT WAS REQUESTED AND NOTHING ELSE.";

const VERDICTS = Object.freeze({
  VERIFIED_EXACT: "VERIFIED_EXACT",
  REFUSED: "REFUSED"
});

function failure(code, detail) {
  return { code, detail };
}

function canonicalEqualSafe(a, b) {
  try {
    return canonicalJsonStringify(a) === canonicalJsonStringify(b);
  } catch {
    return false; // not canonically serializable -> never equal, fail closed
  }
}

/* ------------------------------------------------------------------ */
/* per-action transaction shapes (mirrors vault-builders-v4.js)        */
/* ------------------------------------------------------------------ */

const OWNER_MUTATION_ACTIONS = Object.freeze([
  "ownerSetAgentRoot",
  "ownerSetApprovers",
  "ownerTopUp",
  "ownerTopUpReserve",
  "ownerPause",
  "ownerUnpause"
]);

function allowedShapes(sdkAction) {
  if (sdkAction === "agentSpend") {
    return {
      inputs: [["covenant"], ["covenant", "external"]],
      /* The REAL SDK builder (sdk/src/vault-builders-v4.js agentSpend)
       * emits outputs in the order [payment, successor(, change)] — the
       * P2PK payment is output 0 and the covenant-bound successor is output
       * 1 (VM-proven by tests/vm/tests/v4_sdk_integration.rs, and every
       * §E11 negative vector mutates outputs[0]=payment / outputs[1]=
       * successor). The shape table MUST mirror the builder exactly, or the
       * verifier rejects every real agent spend (fail closed on a valid
       * transaction). All value/recipient/successor detectors locate
       * outputs by classification, not position, so this order change
       * weakens nothing. */
      outputs: [["payment", "successor"], ["payment", "successor", "change"]],
      /* fee fuel present <=> change present (vault-builders-v4 agentSpend) */
      coupled: true
    };
  }
  if (OWNER_MUTATION_ACTIONS.includes(sdkAction)) {
    return { inputs: [["covenant", "external"]], outputs: [["successor", "change"]], coupled: false };
  }
  if (sdkAction === "ownerRecover") {
    return { inputs: [["covenant", "external"]], outputs: [["recoverPayout", "change"]], coupled: false };
  }
  if (sdkAction === "createVault") {
    return {
      inputs: null, // any count >= 1, all external
      outputs: [["genesisVault", "change"], ["genesisVault", "agentFuel", "change"]],
      coupled: false
    };
  }
  return null; // unreachable after validateManifest; treated as refusal
}

function sequenceMatches(sequence, patterns) {
  return patterns.some((p) => p.length === sequence.length && p.every((k, i) => k === sequence[i]));
}

/* ------------------------------------------------------------------ */
/* detectors — each takes the validated context, returns failures      */
/* ------------------------------------------------------------------ */

function checkTxShape(ctx) {
  const { sdkAction, effects } = ctx;
  const failures = [];
  const shapes = allowedShapes(sdkAction);
  if (!shapes) {
    failures.push(failure("ACTION_TX_SHAPE_MISMATCH", `no transaction shape is defined for ${sdkAction} — failing closed`));
    return failures;
  }
  if (shapes.inputs === null) {
    if (!effects.inputKinds.every((k) => k === "external")) {
      failures.push(failure("ACTION_TX_SHAPE_MISMATCH", "createVault must be funded only by ordinary external inputs (no covenant input at genesis)"));
    }
  } else if (!sequenceMatches(effects.inputKinds, shapes.inputs)) {
    failures.push(
      failure(
        "ACTION_TX_SHAPE_MISMATCH",
        `${sdkAction} requires inputs ${JSON.stringify(shapes.inputs)}; the transaction carries ${JSON.stringify(effects.inputKinds)}`
      )
    );
  }
  if (!sequenceMatches(effects.outputKinds, shapes.outputs)) {
    const maxLen = Math.max(...shapes.outputs.map((p) => p.length));
    const code = effects.outputKinds.length > maxLen ? "UNEXPECTED_OUTPUT" : "ACTION_TX_SHAPE_MISMATCH";
    failures.push(
      failure(code, `${sdkAction} permits outputs ${JSON.stringify(shapes.outputs)}; the transaction carries ${JSON.stringify(effects.outputKinds)}`)
    );
  }
  if (shapes.coupled) {
    const hasFuel = effects.inputKinds.includes("external");
    const hasChange = effects.outputKinds.includes("change");
    if (hasFuel !== hasChange) {
      failures.push(failure("ACTION_TX_SHAPE_MISMATCH", "agentSpend: a fee-fuel input requires a change output and vice versa"));
    }
  }
  return failures;
}

function checkPredecessor(ctx) {
  const { manifest, info, txView, effects, stateBefore, accounting } = ctx;
  const failures = [];
  if (info.genesis) {
    if (accounting.predecessorProtected !== 0n || accounting.predecessorFeeReserve !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "genesis accounting must declare zero predecessor value"));
    }
    return failures;
  }
  const covenantIndex = effects.inputKinds.indexOf("covenant");
  if (covenantIndex !== 0) {
    failures.push(failure("PREDECESSOR_MISMATCH", "the covenant predecessor must be input 0"));
    return failures;
  }
  const input = txView.inputs[0];
  const op = stateBefore ? ctx.manifest.stateBefore.outpoint : null;
  if (!op || input.previousOutpoint.transactionId !== op.transactionId || input.previousOutpoint.index !== op.index) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 does not spend the declared predecessor outpoint"));
  }
  if (input.utxo.covenantId !== manifest.vault.covenantId) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 covenantId differs from the vault covenantId"));
  }
  const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
  if (input.utxo.amount !== predTotal) {
    failures.push(failure("PREDECESSOR_MISMATCH", "input 0 value differs from predecessor protectedValue + feeReserve"));
  }
  if (stateBefore && (accounting.predecessorProtected !== stateBefore.state.protectedValue || accounting.predecessorFeeReserve !== stateBefore.state.feeReserve)) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting predecessor values differ from stateBefore"));
  }
  return failures;
}

function checkSuccessor(ctx) {
  const { manifest, info, txView, effects, stateAfter, accounting } = ctx;
  const failures = [];
  if (info.terminal) {
    if (accounting.successorProtected !== 0n || accounting.successorFeeReserve !== 0n || accounting.successorTotal !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "terminal accounting must declare zero successor value"));
    }
    return failures;
  }
  const boundIndexes = effects.outputKinds
    .map((k, i) => (k === "successor" || k === "genesisVault" ? i : -1))
    .filter((i) => i >= 0);
  if (boundIndexes.length !== 1) {
    failures.push(failure("WRONG_SUCCESSOR", `exactly one covenant-bound output is required; found ${boundIndexes.length}`));
    return failures;
  }
  const index = boundIndexes[0];
  const output = txView.outputs[index];
  if (output.covenant.covenantId !== manifest.vault.covenantId) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output carries a different covenantId than the vault"));
  }
  if (output.covenant.authorizingInput !== 0) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output must be authorized by input 0"));
  }
  if (output.scriptVersion !== 0) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output must use script version 0"));
  }
  const declaredTotal = stateAfter.state.protectedValue + stateAfter.state.feeReserve;
  if (accounting.successorTotal !== declaredTotal) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.successorTotal differs from stateAfter protectedValue + feeReserve"));
  }
  if (accounting.successorProtected !== stateAfter.state.protectedValue || accounting.successorFeeReserve !== stateAfter.state.feeReserve) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting successor values differ from stateAfter"));
  }
  if (output.value !== declaredTotal) {
    failures.push(failure("WRONG_SUCCESSOR", "the covenant-bound output value differs from the declared successor protectedValue + feeReserve"));
  }
  const expected = stateAfter.expectedOutpoint;
  if (expected.transactionId !== txView.txId || expected.index !== index) {
    failures.push(failure("WRONG_SUCCESSOR", "stateAfter.expectedOutpoint does not name this transaction's covenant-bound output"));
  }
  return failures;
}

function checkOutputsExplained(ctx) {
  const { manifest, txView, effects, payment, accounting } = ctx;
  const failures = [];
  effects.outputKinds.forEach((kind, i) => {
    const output = txView.outputs[i];
    if (kind === "payment") {
      if (!payment) {
        failures.push(failure("UNEXPECTED_OUTPUT", `output ${i} is classified payment but the manifest declares no payment`));
        return;
      }
      if (payment.outputIndex !== i) {
        failures.push(failure("UNEXPECTED_OUTPUT", `manifest.payment.outputIndex ${payment.outputIndex} does not name output ${i}`));
      }
      if (output.value !== payment.amountSompi) {
        failures.push(failure("HIDDEN_RECIPIENT", `payment output ${i} value differs from the declared payment amount`));
      }
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(payment.recipientXOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `payment output ${i} does not pay the declared recipient key`));
      }
    } else if (kind === "change") {
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(manifest.actor.signerXOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `change output ${i} does not return to the signing wallet — value would leave through "change"`));
      }
    } else if (kind === "recoverPayout") {
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(manifest.vault.owner)) {
        failures.push(failure("HIDDEN_RECIPIENT", `recovery payout output ${i} does not pay the vault owner`));
      }
      if (output.value !== accounting.terminalPayout) {
        failures.push(failure("TERMINAL_PAYOUT_MISMATCH", `recovery payout output ${i} value differs from accounting.terminalPayout`));
      }
    } else if (kind === "agentFuel") {
      const fuel = manifest.requested.params.agentFuel ?? null;
      if (!fuel) {
        failures.push(failure("UNEXPECTED_OUTPUT", `output ${i} is classified agentFuel but the requested intent declares none`));
        return;
      }
      if (output.scriptVersion !== 0 || output.scriptHex !== p2pkScriptHex(fuel.xOnly)) {
        failures.push(failure("HIDDEN_RECIPIENT", `agent fuel output ${i} does not pay the requested agent key`));
      }
      if (output.value.toString() !== fuel.amountSompi) {
        failures.push(failure("REQUEST_MISMATCH", `agent fuel output ${i} value differs from the requested amount`));
      }
    }
    /* successor / genesisVault are fully checked by checkSuccessor. */
  });
  if (payment) {
    const kindAt = effects.outputKinds[payment.outputIndex];
    if (kindAt !== "payment") {
      failures.push(failure("HIDDEN_RECIPIENT", `manifest.payment.outputIndex ${payment.outputIndex} is classified ${kindAt}, not payment`));
    }
  }
  return failures;
}

function checkValueConservation(ctx) {
  const { info, sdkAction, txView, effects, accounting } = ctx;
  const failures = [];
  const totalIn = txView.inputs.reduce((s, i) => s + i.utxo.amount, 0n);
  const totalOut = txView.outputs.reduce((s, o) => s + o.value, 0n);
  if (totalIn - totalOut !== accounting.fee) {
    failures.push(
      failure("VALUE_CONSERVATION_VIOLATION", `inputs (${totalIn}) − outputs (${totalOut}) = ${totalIn - totalOut} sompi, but accounting.fee declares ${accounting.fee}`)
    );
  }
  let externalIn = 0n;
  txView.inputs.forEach((input, i) => {
    if (effects.inputKinds[i] === "external") externalIn += input.utxo.amount;
  });
  if (externalIn !== accounting.externalIn) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.externalIn differs from the sum of external input values"));
  }
  let externalOut = 0n;
  let paymentOut = 0n;
  let payoutOut = 0n;
  txView.outputs.forEach((output, i) => {
    const kind = effects.outputKinds[i];
    if (kind === "change" || kind === "agentFuel") externalOut += output.value;
    if (kind === "payment") paymentOut += output.value;
    if (kind === "recoverPayout") payoutOut += output.value;
  });
  if (externalOut !== accounting.externalOut) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.externalOut differs from the sum of change/agent-fuel output values"));
  }
  if (paymentOut !== accounting.payAmount) {
    failures.push(failure("ACCOUNTING_MISMATCH", "accounting.payAmount differs from the payment output value"));
  }
  if (info.terminal) {
    if (payoutOut !== accounting.terminalPayout) {
      failures.push(failure("ACCOUNTING_MISMATCH", "accounting.terminalPayout differs from the recovery payout output value"));
    }
    const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
    if (accounting.terminalPayout !== predTotal) {
      failures.push(failure("TERMINAL_PAYOUT_MISMATCH", "the covenant requires the terminal payout to equal protectedValue + feeReserve exactly"));
    }
    if (accounting.reserveConsumed !== 0n || accounting.payAmount !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "terminal accounting must declare zero payAmount and reserveConsumed"));
    }
    if (accounting.fee !== accounting.externalIn - accounting.externalOut) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "terminal fee must equal external fuel in minus change out"));
    }
  } else if (info.genesis) {
    if (accounting.reserveConsumed !== 0n || accounting.payAmount !== 0n || accounting.terminalPayout !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "genesis accounting must declare zero payAmount, reserveConsumed, and terminalPayout"));
    }
    if (accounting.fee !== accounting.externalIn - accounting.successorTotal - accounting.externalOut) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "genesis fee must equal funding in minus vault value minus change out"));
    }
  } else {
    if (accounting.terminalPayout !== 0n) {
      failures.push(failure("ACCOUNTING_MISMATCH", "a non-terminal transition must declare terminalPayout 0"));
    }
    if (sdkAction !== "agentSpend" && (accounting.payAmount !== 0n || accounting.reserveConsumed !== 0n)) {
      failures.push(failure("ACCOUNTING_MISMATCH", `${sdkAction} must declare zero payAmount and reserveConsumed`));
    }
    /* General non-terminal ledger identity: what left the covenant
     * (predTotal − succTotal, negative for top-ups) minus the payment,
     * plus the net external fuel contribution, is exactly the fee. */
    const predTotal = accounting.predecessorProtected + accounting.predecessorFeeReserve;
    if (accounting.fee !== predTotal - accounting.successorTotal - accounting.payAmount + accounting.externalIn - accounting.externalOut) {
      failures.push(
        failure("VALUE_CONSERVATION_VIOLATION", "fee must equal (predecessor total − successor total) − payAmount + externalIn − externalOut exactly")
      );
    }
    /* agentSpend: the covenant drawdown decomposes exactly into the
     * payment plus the reserve-funded fee portion — nothing else. */
    if (sdkAction === "agentSpend" && predTotal - accounting.successorTotal !== accounting.payAmount + accounting.reserveConsumed) {
      failures.push(failure("VALUE_CONSERVATION_VIOLATION", "an agent spend must draw down the covenant by exactly payAmount + reserveConsumed"));
    }
  }
  return failures;
}

function checkFee(ctx) {
  const { manifest, accounting } = ctx;
  const failures = [];
  if (accounting.fee < 1n) {
    failures.push(failure("VALUE_CONSERVATION_VIOLATION", "a real transaction pays a positive network fee"));
  }
  const maxFee = manifest.requested.maxFeeSompi;
  if (maxFee !== null && accounting.fee > BigInt(maxFee)) {
    failures.push(failure("EXCESSIVE_FEE", `accounting.fee ${accounting.fee} exceeds the requested maxFeeSompi ${maxFee}`));
  }
  return failures;
}

function checkRequestEquations(ctx) {
  const { manifest, sdkAction, stateBefore, stateAfter, accounting, payment, limits } = ctx;
  const failures = [];
  const params = manifest.requested.params;
  const miss = (detail) => failures.push(failure("REQUEST_MISMATCH", detail));
  switch (sdkAction) {
    case "agentSpend": {
      if (manifest.actor.agentPk !== params.agentPk) miss("the acting agent differs from the requested agentPk");
      if (payment.recipientXOnly !== params.recipient) miss("the payment recipient differs from the requested recipient");
      if (payment.amountSompi.toString() !== params.payAmountSompi) miss("the payment amount differs from the requested payAmountSompi");
      if (limits.periodsElapsed.toString() !== params.periodsElapsed) miss("limits.periodsElapsed differs from the requested periodsElapsed");
      if (accounting.reserveConsumed.toString() !== params.reserveConsumedSompi) miss("accounting.reserveConsumed differs from the requested reserveConsumedSompi");
      break;
    }
    case "ownerSetAgentRoot": {
      if (stateAfter.state.agentRoot !== params.newAgentRoot) miss("the successor agentRoot differs from the requested newAgentRoot");
      break;
    }
    case "ownerSetApprovers": {
      if (!canonicalEqualSafe(manifest.stateAfter.state.approverSlots, params.newApproverSlots)) {
        miss("the successor approver slots differ from the requested newApproverSlots");
      }
      if (stateAfter.state.approvalM.toString() !== params.newApprovalM) miss("the successor approvalM differs from the requested newApprovalM");
      break;
    }
    case "ownerTopUp": {
      const delta = stateAfter.state.protectedValue - stateBefore.state.protectedValue;
      if (delta.toString() !== params.topUpAmountSompi) miss("the protectedValue increase differs from the requested topUpAmountSompi");
      break;
    }
    case "ownerTopUpReserve": {
      const delta = stateAfter.state.feeReserve - stateBefore.state.feeReserve;
      if (delta.toString() !== params.topUpReserveAmountSompi) miss("the feeReserve increase differs from the requested topUpReserveAmountSompi");
      break;
    }
    case "ownerPause":
    case "ownerUnpause":
    case "ownerRecover":
      break; // parameterless; the transition itself is the request
    case "createVault": {
      if (manifest.vault.owner !== params.owner) miss("the vault owner differs from the requested owner");
      if (!canonicalEqualSafe(manifest.stateAfter.state, params.initialState)) {
        miss("the genesis state differs from the requested initialState");
      }
      break;
    }
    default:
      failures.push(failure("UNKNOWN_ACTION", `no request equations for ${sdkAction} — failing closed`));
  }
  return failures;
}

function checkStateTransition(ctx) {
  const { manifest, sdkAction, info, stateBefore, stateAfter, accounting } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state;
  const after = stateAfter.state;

  /* Frozen per-entrypoint field-preservation matrix: any field outside the
   * action's authorized-change set MUST be preserved (policyNonce has its
   * own detector). A violation is a hidden policy mutation. */
  const preserved = {
    protectedValue: before.protectedValue === after.protectedValue,
    feeReserve: before.feeReserve === after.feeReserve,
    paused: before.paused === after.paused,
    agentRoot: before.agentRoot === after.agentRoot,
    approverSlots: canonicalEqualSafe(manifest.stateBefore.state.approverSlots, manifest.stateAfter.state.approverSlots),
    approvalM: before.approvalM === after.approvalM
  };
  for (const [field, same] of Object.entries(preserved)) {
    if (!same && !info.mutable.includes(field)) {
      failures.push(failure("HIDDEN_POLICY_MUTATION", `${sdkAction} is not authorized to change ${field}, but the successor state changes it`));
    }
  }

  switch (sdkAction) {
    case "agentSpend": {
      if (before.paused !== 0n) failures.push(failure("STATE_MISMATCH", "agentSpend requires an unpaused predecessor"));
      if (after.protectedValue !== before.protectedValue - accounting.payAmount) {
        failures.push(failure("STATE_MISMATCH", "successor protectedValue must decrease by exactly the payment amount"));
      }
      if (after.feeReserve !== before.feeReserve - accounting.reserveConsumed) {
        failures.push(failure("STATE_MISMATCH", "successor feeReserve must decrease by exactly reserveConsumed"));
      }
      if (after.agentRoot === before.agentRoot) {
        failures.push(failure("STATE_MISMATCH", "an agent spend always advances the agent's period accounting — the successor agentRoot cannot equal the predecessor root"));
      }
      break;
    }
    case "ownerTopUp": {
      if (after.protectedValue <= before.protectedValue) {
        failures.push(failure("STATE_MISMATCH", "ownerTopUp must strictly increase protectedValue"));
      }
      break;
    }
    case "ownerTopUpReserve": {
      if (after.feeReserve <= before.feeReserve) {
        failures.push(failure("STATE_MISMATCH", "ownerTopUpReserve must strictly increase feeReserve"));
      }
      break;
    }
    case "ownerPause": {
      if (before.paused !== 0n || after.paused !== 1n) {
        failures.push(failure("STATE_MISMATCH", "ownerPause must transition paused 0 -> 1"));
      }
      break;
    }
    case "ownerUnpause": {
      if (before.paused !== 1n || after.paused !== 0n) {
        failures.push(failure("STATE_MISMATCH", "ownerUnpause must transition paused 1 -> 0"));
      }
      break;
    }
    case "ownerSetApprovers": {
      if (after.activeCount < 1 || after.approvalM < 1n) {
        failures.push(failure("STATE_MISMATCH", "the covenant cannot transition to a zero-approver configuration (ownerSetApprovers requires 1 <= approvalM <= activeCount)"));
      }
      break;
    }
    case "ownerSetAgentRoot":
      break; // the root equality with the request is checked in request-equations
    default:
      failures.push(failure("UNKNOWN_ACTION", `no state-transition equations for ${sdkAction} — failing closed`));
  }
  return failures;
}

function checkNonceRule(ctx) {
  const { info, stateBefore, stateAfter } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state.policyNonce;
  const after = stateAfter.state.policyNonce;
  const expected = info.nonce === "increment" ? before + 1n : before;
  if (after !== expected) {
    failures.push(
      failure(
        "NONCE_RULE_VIOLATION",
        `policyNonce must be ${info.nonce === "increment" ? "incremented by exactly 1" : "preserved"} (expected ${expected}, successor declares ${after})`
      )
    );
  }
  return failures;
}

function checkPolicyMutationsDeclared(ctx) {
  const { manifest, info } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures; // schema enforces []
  const recomputed = diffStates(manifest.stateBefore.state, manifest.stateAfter.state);
  if (!canonicalEqualSafe(recomputed, manifest.policyMutations)) {
    failures.push(
      failure("POLICY_MUTATION_MISDECLARED", "manifest.policyMutations does not equal the recomputed stateBefore→stateAfter diff — declared and actual mutations diverge")
    );
  }
  return failures;
}

function checkLimits(ctx) {
  const { manifest, sdkAction, txView, stateBefore, accounting, payment, allowlist, approvals, limits } = ctx;
  const failures = [];
  if (sdkAction !== "agentSpend") return failures;
  const pb = limits.policyBefore;
  const pa = limits.policyAfter;
  const pay = payment.amountSompi;

  if (pb.agentPk !== manifest.actor.agentPk) {
    failures.push(failure("AGENT_POLICY_MISMATCH", "limits.policyBefore.agentPk differs from the acting agent"));
  }
  if (pa.agentPk !== pb.agentPk) {
    failures.push(failure("AGENT_POLICY_MISMATCH", "an agent spend never changes the agent key"));
  }
  if (pay > pb.maxPerSpend) {
    failures.push(failure("LIMIT_VIOLATION", "payAmount exceeds this agent's maxPerSpend"));
  }

  /* Exact covenant rollover arithmetic (vault-transitions-v4 agentSpend). */
  const periods = limits.periodsElapsed;
  let newStart = pb.periodStartDaa;
  let newSpent = pb.periodSpent + pay;
  let requiredLockTime = 0n;
  if (periods >= 1n) {
    newStart = pb.periodStartDaa + periods * pb.periodLengthDaa;
    newSpent = pay;
    requiredLockTime = newStart; // covenant CLTV: lockTime >= newStart; the builder pins equality
  }
  if (newSpent > pb.periodBudget) {
    failures.push(failure("LIMIT_VIOLATION", "the spend exceeds this agent's remaining period budget"));
  }
  if (txView.lockTime !== requiredLockTime) {
    failures.push(failure("LOCKTIME_RULE_VIOLATION", `transaction lockTime must be ${requiredLockTime} for periodsElapsed ${periods}`));
  }
  const expectedAfter = { ...pb, periodStartDaa: newStart, periodSpent: newSpent };
  for (const field of Object.keys(expectedAfter)) {
    if (pa[field] !== expectedAfter[field]) {
      failures.push(failure("AGENT_POLICY_MISMATCH", `limits.policyAfter.${field} does not follow the covenant's single-leaf update arithmetic`));
    }
  }

  if (accounting.reserveConsumed > pb.agentMaxFeePerTx) {
    failures.push(failure("RESERVE_RULE_VIOLATION", "reserveConsumed exceeds this agent's agentMaxFeePerTx"));
  }
  if (accounting.reserveConsumed > accounting.predecessorFeeReserve) {
    failures.push(failure("RESERVE_RULE_VIOLATION", "reserveConsumed exceeds the available fee reserve"));
  }

  const shouldBeAbove = pay > pb.approvalThreshold;
  if (approvals.aboveThreshold !== shouldBeAbove) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", `payAmount ${pay} vs approvalThreshold ${pb.approvalThreshold}: aboveThreshold must be ${shouldBeAbove}`));
  }
  if (approvals.approvalThreshold !== pb.approvalThreshold) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "approvals.approvalThreshold differs from the agent policy's approvalThreshold"));
  }
  if (approvals.requiredM !== stateBefore.state.approvalM) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "approvals.requiredM differs from the vault's approvalM"));
  }
  if (shouldBeAbove && stateBefore.state.approvalM < 1n) {
    failures.push(failure("APPROVAL_TIER_MISMATCH", "an above-threshold spend requires an approver configuration (approvalM >= 1)"));
  }

  if (allowlist.agentRecipientRoot !== pb.agentRecipientRoot) {
    failures.push(failure("ALLOWLIST_MISMATCH", "allowlist.agentRecipientRoot differs from the agent policy's agentRecipientRoot"));
  }
  if (allowlist.recipientAllowlisted !== true || allowlist.proofSupplied !== true) {
    failures.push(failure("ALLOWLIST_NOT_PROVEN", "the recipient's allowlist membership is not recorded as proven — refusing"));
  }
  return failures;
}

function checkAuthority(ctx) {
  const { manifest, sdkAction, info, stateBefore, stateAfter } = ctx;
  const failures = [];
  if (info.genesis || info.terminal) return failures;
  const before = stateBefore.state;
  const after = stateAfter.state;
  const expand = (detail) => failures.push(failure("AUTHORITY_EXPANSION", detail));

  const approversChanged =
    before.approvalM !== after.approvalM ||
    !canonicalEqualSafe(manifest.stateBefore.state.approverSlots, manifest.stateAfter.state.approverSlots);
  if (approversChanged && sdkAction !== "ownerSetApprovers") {
    expand(`${sdkAction} changes the approval configuration — only ownerSetApprovers may`);
  }
  if (after.agentRoot !== before.agentRoot && sdkAction !== "agentSpend" && sdkAction !== "ownerSetAgentRoot") {
    expand(`${sdkAction} changes the agent registry root — only agentSpend (single-leaf accounting) or ownerSetAgentRoot may`);
  }
  if (before.paused === 1n && after.paused === 0n && sdkAction !== "ownerUnpause") {
    expand(`${sdkAction} silently unpauses the vault — only ownerUnpause may`);
  }
  if (after.policyNonce > before.policyNonce && info.nonce !== "increment") {
    expand(`${sdkAction} advances the policyNonce without being a policy-mutation entrypoint`);
  }
  if (after.protectedValue < before.protectedValue && sdkAction !== "agentSpend") {
    expand(`${sdkAction} moves protected value out of the vault — only agentSpend may`);
  }
  if (after.feeReserve < before.feeReserve && sdkAction !== "agentSpend") {
    expand(`${sdkAction} consumes the fee reserve — only agentSpend may`);
  }
  return failures;
}

function checkUnexpectedEffects(ctx) {
  const list = ctx.manifest.unexpectedEffects;
  if (list.length === 0) return [];
  return list.map((e) => failure("UNEXPECTED_EFFECTS_PRESENT", `recorded unexplained effect ${e.code}: ${e.detail}`));
}

/* ------------------------------------------------------------------ */
/* the verifier                                                        */
/* ------------------------------------------------------------------ */

const DETECTORS = Object.freeze([
  ["tx-shape", checkTxShape],
  ["predecessor", checkPredecessor],
  ["successor", checkSuccessor],
  ["outputs-explained", checkOutputsExplained],
  ["value-conservation", checkValueConservation],
  ["fee", checkFee],
  ["request-equations", checkRequestEquations],
  ["state-transition", checkStateTransition],
  ["nonce-rule", checkNonceRule],
  ["policy-mutations-declared", checkPolicyMutationsDeclared],
  ["limits", checkLimits],
  ["authority", checkAuthority],
  ["unexpected-effects", checkUnexpectedEffects]
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function refusedResult(checks, failures, manifestHash) {
  return deepFreeze({
    ok: false,
    verdict: VERDICTS.REFUSED,
    statement: null,
    manifestHash: manifestHash ?? null,
    txId: null,
    checks,
    failures
  });
}

/*
 * Verify a manifest against the structured requested intent and the
 * structured decoded transaction.
 *
 *   verifyIntentManifest({ manifest, requestedIntent, decodedTransaction })
 *
 * `requestedIntent` and `decodedTransaction` are the caller's independent
 * copies (from the user/agent request and from an independent decode of
 * the frozen transaction). When supplied they must be canonically
 * IDENTICAL to the manifest's embedded copies; omit a side (undefined) to
 * verify a self-contained manifest against its own embedded copies.
 *
 * Returns a structured, deep-frozen result:
 *   { ok, verdict, statement, manifestHash, txId, checks, failures }
 * ok=true and verdict=VERIFIED_EXACT ONLY when every detector passed —
 * then, and only then, `statement` carries the verified claim. Any
 * failure — including an internal verifier error — refuses.
 */
function verifyIntentManifest({ manifest, requestedIntent, decodedTransaction } = {}) {
  const checks = [];
  const allFailures = [];

  /* 1. Strict validation (schema, versions, actions, hash). A manifest
   * that fails validation is hard-refused immediately: no later detector
   * may run over an untrusted structure. */
  let ctx;
  try {
    ctx = validateManifest(manifest);
  } catch (e) {
    const f = failure(e.code ?? "SCHEMA_INVALID", e.message);
    checks.push({ id: "manifest-valid", ok: false, failures: [f] });
    return refusedResult(checks, [f], null);
  }
  checks.push({ id: "manifest-valid", ok: true, failures: [] });

  /* 2. Binding to the caller's independent copies. */
  if (requestedIntent !== undefined) {
    const ok = canonicalEqualSafe(requestedIntent, ctx.manifest.requested);
    const f = ok ? [] : [failure("REQUEST_MISMATCH", "the supplied requested intent differs from the manifest's embedded intent")];
    checks.push({ id: "intent-binding", ok, failures: f });
    allFailures.push(...f);
  }
  if (decodedTransaction !== undefined) {
    const ok = canonicalEqualSafe(decodedTransaction, ctx.manifest.transaction);
    const f = ok ? [] : [failure("TX_MISMATCH", "the supplied decoded transaction differs from the manifest's embedded transaction — the manifest does not describe this transaction")];
    checks.push({ id: "transaction-binding", ok, failures: f });
    allFailures.push(...f);
  }

  /* 3. The detector catalogue. An unexpected internal error in any
   * detector REFUSES (fail closed) — it never skips. */
  for (const [id, detector] of DETECTORS) {
    let failuresHere;
    try {
      failuresHere = detector(ctx);
    } catch (e) {
      failuresHere = [failure("VERIFIER_INTERNAL", `${id}: ${e.message} — failing closed`)];
    }
    checks.push({ id, ok: failuresHere.length === 0, failures: failuresHere });
    allFailures.push(...failuresHere);
  }

  const ok = allFailures.length === 0;
  return deepFreeze({
    ok,
    verdict: ok ? VERDICTS.VERIFIED_EXACT : VERDICTS.REFUSED,
    statement: ok ? VERIFIED_STATEMENT : null,
    manifestHash: ctx.manifest.manifestHash,
    txId: ctx.manifest.transaction.txId,
    checks,
    failures: allFailures
  });
}

module.exports = {
  VERIFIED_STATEMENT,
  VERDICTS,
  ACTIONS,
  verifyIntentManifest
};
  });

  define("core/intent/index", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Transaction Intent Manifest — portable core, v1.
 *
 * Spec: docs/postlaunch/intent-manifest-spec.md
 * Status: IMPLEMENTED + UNIT-TESTED (core/intent/test). Pure CommonJS,
 * zero external dependencies, no server/SDK imports.
 */

const canonical = require("./canonical");
const manifest = require("./manifest");
const verify = require("./verify");

module.exports = {
  /* canonical serialization + representation-independent hashing */
  MANIFEST_HASH_DOMAIN_V1: canonical.MANIFEST_HASH_DOMAIN_V1,
  canonicalJsonStringify: canonical.canonicalJsonStringify,
  sha256Hex: canonical.sha256Hex,
  computeManifestHashV1: canonical.computeManifestHashV1,
  canonicalEqual: canonical.canonicalEqual,

  /* schema + validation + build */
  MANIFEST_VERSION_1: manifest.MANIFEST_VERSION_1,
  REQUESTED_INTENT_VERSION_1: manifest.REQUESTED_INTENT_VERSION_1,
  SUPPORTED_COVENANT_VERSIONS: manifest.SUPPORTED_COVENANT_VERSIONS,
  ACTIONS: manifest.ACTIONS,
  HIGH_LEVEL_TO_SDK: manifest.HIGH_LEVEL_TO_SDK,
  STATE_FIELDS: manifest.STATE_FIELDS,
  AGENT_POLICY_FIELDS: manifest.AGENT_POLICY_FIELDS,
  ACCOUNTING_FIELDS: manifest.ACCOUNTING_FIELDS,
  parseAmount: manifest.parseAmount,
  parsePositiveAmount: manifest.parsePositiveAmount,
  requireInt: manifest.requireInt,
  requireHex: manifest.requireHex,
  p2pkScriptHex: manifest.p2pkScriptHex,
  validateStateShape: manifest.validateStateShape,
  validateAgentPolicyShape: manifest.validateAgentPolicyShape,
  validateRequestedIntent: manifest.validateRequestedIntent,
  validateTransactionShape: manifest.validateTransactionShape,
  validateManifest: manifest.validateManifest,
  diffStates: manifest.diffStates,
  buildIntentManifest: manifest.buildIntentManifest,

  /* fail-closed verification */
  VERIFIED_STATEMENT: verify.VERIFIED_STATEMENT,
  VERDICTS: verify.VERDICTS,
  verifyIntentManifest: verify.verifyIntentManifest
};
  });

  define("core/explain/kas", function (module, exports, require) {
"use strict";

/*
 * Exact integer sompi -> KAS decimal rendering for the explanation layer.
 *
 * MIRRORS the semantics of sdk/src/amounts.js `sompiToKas` (whole =
 * amount / 1e8; fraction = amount % 1e8 zero-padded to 8 digits with
 * trailing zeros trimmed; no fraction part when it is zero) WITHOUT
 * importing it: core/explain is a portable shared-core module with zero
 * SDK/server imports. sdk/src/amounts.js is itself pure (BigInt-only
 * integer math, no I/O), so the coordinator MAY later wire the SDK
 * implementation in its place inside SDK-resident code paths; the
 * rendered strings are identical over the shared domain by construction
 * (asserted by golden vectors in core/explain/test/kas.test.js).
 *
 * Differences from the SDK helper, both deliberate and both STRICTER or
 * WIDER in a fail-closed-compatible way:
 *   - INPUT is canonical only: a BigInt, or a base-10 digit string with
 *     no leading zeros ("0" or [1-9][0-9]*). The SDK parser tolerates
 *     leading zeros; explanation inputs come from manifests/delta
 *     results where one value has exactly one encoding, so a
 *     non-canonical encoding here is evidence of tampering or a wrong
 *     pipeline and REFUSES.
 *   - DOMAIN is 0..I64_MAX (2^63-1), the num8 consensus encoding bound
 *     used by core/governance, which is a superset of the SDK's
 *     MAX_SOMPI supply ceiling (2.9e18 < 2^63-1). Intent-manifest
 *     amounts are already bounded to MAX_SOMPI upstream by
 *     core/intent validateManifest; governance delta values may
 *     legitimately reach the i64 bound.
 *
 * NUMERIC SAFETY: BigInt integer math only. JS numbers are refused on
 * every path (floating point can silently corrupt a funds display —
 * a display defect on a signing screen is a funds-safety defect).
 */

const SOMPI_PER_KAS = 100000000n;
const I64_MAX = 2n ** 63n - 1n; // num8 encoding domain (core/governance)

const CANONICAL_DIGITS_RE = /^(0|[1-9][0-9]*)$/;

function refuse(code, message) {
  const e = new Error(`explain-kas: ${message}`);
  e.code = code;
  throw e;
}

/*
 * Parse a canonical sompi quantity (BigInt or canonical base-10 digit
 * string) into BigInt. Refuses JS numbers, signs, decimals, exponents,
 * whitespace, leading zeros, empty strings, negatives, and values above
 * I64_MAX. Fail closed: an unrenderable amount is never approximated.
 */
function parseCanonicalSompi(value, field = "amount") {
  let amount;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_DIGITS_RE.test(value)) {
      refuse("VALUE_INVALID", `${field} is not a canonical base-10 digit string: ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    refuse(
      "VALUE_INVALID",
      `${field} must be a BigInt or canonical digit string (JS numbers are refused: floating point is unsafe for funds display), got ${typeof value}`
    );
  }
  if (amount < 0n) refuse("VALUE_INVALID", `${field} must not be negative`);
  if (amount > I64_MAX) refuse("VALUE_INVALID", `${field} exceeds the i64 encoding domain`);
  return amount;
}

/*
 * Render sompi as an exact KAS decimal string. Pure integer/string math;
 * exact 8-decimal handling; trailing fraction zeros trimmed; NEVER
 * rounded, truncated, or approximated ("1000000000" -> "10",
 * "125000000" -> "1.25", "1" -> "0.00000001").
 */
function sompiToKasString(value, field = "amount") {
  const amount = parseCanonicalSompi(value, field);
  const whole = amount / SOMPI_PER_KAS;
  const frac = amount % SOMPI_PER_KAS;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

/* The {sompi, kas} display pair used throughout structured explanations:
 * the exact integer AND its exact KAS rendering, so no consumer ever
 * needs to re-derive one from the other. */
function kasAmount(value, field = "amount") {
  const amount = parseCanonicalSompi(value, field);
  return { sompi: amount.toString(), kas: sompiToKasString(amount, field) };
}

module.exports = {
  SOMPI_PER_KAS,
  I64_MAX,
  parseCanonicalSompi,
  sompiToKasString,
  kasAmount
};
  });

  define("core/explain/intent-explain", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Transaction Intent Manifest — EXPLANATIONS (v1).
 *
 * Turns a VERIFIED v1 Transaction Intent Manifest plus its verification
 * result into:
 *
 *   structured({ manifest, verification })
 *     -> a stable, versioned, JSON-safe explanation document
 *        ("policyvault-intent-explanation/1") for APIs and agent
 *        workflows;
 *
 *   humanReadable({ manifest, verification })
 *     -> deterministic English lines a signer UI shows BEFORE signing.
 *
 * BINDING RULES (fail closed, no default route):
 *   - Explanations are derived ONLY from the verified manifest — never
 *     from unverified request data. The manifest is independently
 *     re-validated here (schema + hash), the supplied verification
 *     result must BIND to this exact manifest (same manifestHash and
 *     txId) and be a full pass, AND the manifest is independently
 *     RE-VERIFIED in-process through core/intent verifyIntentManifest.
 *     A fabricated { ok: true } verification object therefore cannot
 *     make an unverified manifest render normally.
 *   - Any manifest whose verification is not a full pass produces a
 *     prominent REFUSAL explanation listing the detector codes — never
 *     a normal rendering, and never any amount/recipient/state block.
 *   - Unknown manifest/intent/covenant versions and unknown actions
 *     refuse (the underlying validator's own codes are surfaced).
 *   - NO truncation of addresses/amounts that could hide a
 *     substitution: every key, root, id, and amount is rendered IN
 *     FULL. (A UI may add a shortened display form ONLY alongside the
 *     full value; this module never emits a shortened form.)
 *   - Identity note: the manifest's canonical identities are x-only
 *     public keys (never addresses); lines render the full 64-hex key.
 *     A UI layer that owns the address codec may append the bech32
 *     address form alongside — the key remains the verified value.
 *
 * Both entry points are TOTAL: they never throw. Malformed inputs and
 * internal errors produce a REFUSAL explanation (an error is never a
 * pass, and a signer UI always gets something safe to display).
 *
 * Portable shared core: pure CommonJS, zero external dependencies, no
 * SDK/server imports; the only module dependencies are the public
 * exports of core/intent and the local KAS renderer.
 */

const { validateManifest, verifyIntentManifest, VERIFIED_STATEMENT } = require("../intent");
const { kasAmount, sompiToKasString } = require("./kas");

const INTENT_EXPLANATION_VERSION_1 = "policyvault-intent-explanation/1";

// Failure/warning details are untrusted text (they originate from server- or
// manifest-supplied strings). When interpolated into a rendered line they
// must NOT be able to forge a structural or verdict line: a crafted detail
// carrying newlines could otherwise inject a fake "Verification: PASSED" into
// a DO-NOT-SIGN rendering, or false Fee/Payment lines into a VERIFIED one, and
// bidi/RTL controls could visually reorder the display. Collapse every control
// and bidi-override character to a single space and cap the length. The
// STRUCTURED output keeps the raw detail (it is data, not a rendered line);
// only line rendering is sanitized. (Hostile-AI review H-1.)
function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}

const EXPLANATION_VERDICTS = Object.freeze({
  VERIFIED_EXACT: "VERIFIED_EXACT",
  REFUSED: "REFUSED"
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function isHex32(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function failureEntry(code, detail) {
  return { code: String(code), detail: String(detail) };
}

/* The closed top-level key set of every explanation document — identical
 * for both verdicts (refusals carry null rendering blocks), so API
 * consumers get ONE stable shape. */
function baseDocument() {
  return {
    explanationVersion: INTENT_EXPLANATION_VERSION_1,
    verdict: null,
    statement: null,
    refusal: null,
    context: null,
    manifestHash: null,
    txId: null,
    network: null,
    vault: null,
    action: null,
    actor: null,
    fee: null,
    outputs: null,
    payment: null,
    accounting: null,
    balances: null,
    policyChanges: null,
    policyNonce: null,
    approvals: null,
    limits: null,
    warnings: null,
    verification: null
  };
}

/*
 * REFUSAL document. `failures` is [{code, detail}]; `context` (optional)
 * is the minimal identity block extractable from a manifest that at
 * least VALIDATED structurally — explicitly labeled unverified, and the
 * only manifest-derived content a refusal may carry. No amounts, no
 * recipients, no state: unverified values are never rendered.
 */
function refusalDocument({ reason, failures, context = null, manifestHash = null, txId = null, verificationSummary = null }) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  const doc = baseDocument();
  doc.verdict = EXPLANATION_VERDICTS.REFUSED;
  doc.refusal = {
    reason: String(reason),
    codes,
    failures: failures.map((f) => failureEntry(f.code, f.detail))
  };
  doc.context = context;
  doc.manifestHash = manifestHash;
  doc.txId = txId;
  doc.verification = verificationSummary;
  return deepFreeze(doc);
}

/* Strict shape check of a caller-supplied verification result (the
 * deep-frozen object produced by core/intent verifyIntentManifest).
 * Returns null when valid, else the refusal detail string. */
function verificationShapeProblem(verification) {
  if (!isPlainObject(verification) && !(verification && typeof verification === "object" && !Array.isArray(verification))) {
    return "verification result must be the object returned by verifyIntentManifest";
  }
  if (typeof verification.ok !== "boolean") return "verification.ok must be a boolean";
  if (verification.verdict !== "VERIFIED_EXACT" && verification.verdict !== "REFUSED") {
    return `verification.verdict ${JSON.stringify(verification.verdict)} is unknown — failing closed`;
  }
  if (!Array.isArray(verification.checks)) return "verification.checks must be an array";
  for (const c of verification.checks) {
    if (!c || typeof c.id !== "string" || typeof c.ok !== "boolean" || !Array.isArray(c.failures)) {
      return "verification.checks entries must be { id, ok, failures[] }";
    }
  }
  if (!Array.isArray(verification.failures)) return "verification.failures must be an array";
  for (const f of verification.failures) {
    if (!f || typeof f.code !== "string") return "verification.failures entries must carry a code";
  }
  if (verification.ok === true) {
    if (verification.verdict !== "VERIFIED_EXACT") return "verification.ok=true requires verdict VERIFIED_EXACT";
    if (verification.statement !== VERIFIED_STATEMENT) return "verification.statement is not the canonical verified statement";
    if (!isHex32(verification.manifestHash)) return "verification.manifestHash must be 32-byte lowercase hex";
    if (!isHex32(verification.txId)) return "verification.txId must be 32-byte lowercase hex";
    if (verification.failures.length !== 0) return "verification.ok=true cannot carry failures";
  }
  return null;
}

function verificationSummaryOf(verification) {
  return {
    verdict: verification.verdict,
    ok: verification.ok,
    checks: verification.checks.map((c) => ({ id: c.id, ok: c.ok })),
    failureCodes: [...new Set(verification.failures.map((f) => f.code))].sort()
  };
}

/* ------------------------------------------------------------------ */
/* rendering helpers (VERIFIED manifests only)                         */
/* ------------------------------------------------------------------ */

const OUTPUT_DESTINATIONS = Object.freeze({
  successor: "vault-successor",
  genesisVault: "vault-genesis",
  payment: "recipient",
  change: "signer-change",
  recoverPayout: "owner-payout",
  agentFuel: "agent-fuel"
});

function destinationXOnlyFor(kind, ctx) {
  const m = ctx.manifest;
  if (kind === "payment") return m.payment.recipientXOnly;
  if (kind === "change") return m.actor.signerXOnly;
  if (kind === "recoverPayout") return m.vault.owner;
  if (kind === "agentFuel") return m.requested.params.agentFuel.xOnly;
  return null; // successor / genesisVault: the vault covenant itself
}

function outputDescription(kind, valueKas, destinationXOnly) {
  switch (kind) {
    case "successor":
      return `Vault covenant successor holding the vault's protected value + fee reserve (${valueKas} KAS).`;
    case "genesisVault":
      return `New vault covenant output holding the initial protected value + fee reserve (${valueKas} KAS).`;
    case "payment":
      return `Payment of exactly ${valueKas} KAS to recipient public key ${destinationXOnly}.`;
    case "change":
      return `Change of ${valueKas} KAS returning to the signing wallet public key ${destinationXOnly}.`;
    case "recoverPayout":
      return `Terminal recovery payout of ${valueKas} KAS to the vault owner public key ${destinationXOnly}.`;
    case "agentFuel":
      return `Agent fee-fuel of ${valueKas} KAS to agent public key ${destinationXOnly}.`;
    default:
      return `Output of ${valueKas} KAS.`; // unreachable after validation
  }
}

/* JSON-safe rendering of a parsed (BigInt-view) state tuple. */
function stateBlock(state, stateId) {
  return {
    stateId,
    protectedValue: kasAmount(state.protectedValue, "state.protectedValue"),
    feeReserve: kasAmount(state.feeReserve, "state.feeReserve"),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    approverSlots: state.approverSlots.slice(),
    activeApproverCount: state.activeCount,
    approvalM: state.approvalM.toString(),
    policyNonce: state.policyNonce.toString()
  };
}

function copyOutpoint(op) {
  return { transactionId: op.transactionId, index: op.index };
}

function actionSummary(ctx) {
  const m = ctx.manifest;
  const vaultId = m.vault.vaultId;
  switch (ctx.sdkAction) {
    case "agentSpend": {
      const pay = sompiToKasString(ctx.payment.amountSompi, "payment.amountSompi");
      return `Send exactly ${pay} KAS to recipient public key ${m.payment.recipientXOnly} from vault ${vaultId}.`;
    }
    case "ownerTopUp": {
      const delta = ctx.stateAfter.state.protectedValue - ctx.stateBefore.state.protectedValue;
      return `Add exactly ${sompiToKasString(delta, "topUpDelta")} KAS to the protected value of vault ${vaultId}.`;
    }
    case "ownerTopUpReserve": {
      const delta = ctx.stateAfter.state.feeReserve - ctx.stateBefore.state.feeReserve;
      return `Add exactly ${sompiToKasString(delta, "topUpReserveDelta")} KAS to the fee reserve of vault ${vaultId}.`;
    }
    case "ownerPause":
      return `Freeze vault ${vaultId} (emergency pause — agent spending stops until the owner unpauses).`;
    case "ownerUnpause":
      return `Unfreeze vault ${vaultId} (agent spending resumes under the existing policy).`;
    case "ownerSetAgentRoot": {
      const root = m.stateAfter.state.agentRoot;
      switch (m.action.highLevelAction) {
        case "addAgent":
          return `Add an agent to vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "removeAgent":
          return `Remove an agent from vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "rotateAgent":
          return `Rotate an agent key on vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        case "rePolicyAgent":
          return `Update an agent's policy on vault ${vaultId} — the agent registry commitment becomes ${root}.`;
        default:
          return `Replace the agent registry commitment of vault ${vaultId} with ${root}.`;
      }
    }
    case "ownerSetApprovers": {
      const after = ctx.stateAfter.state;
      return `Replace the approver configuration of vault ${vaultId}: ${after.approvalM} of ${after.activeCount} listed approver key(s) must co-sign above-threshold spends.`;
    }
    case "ownerRecover": {
      const payout = sompiToKasString(ctx.accounting.terminalPayout, "accounting.terminalPayout");
      return `CLOSE vault ${vaultId}: pay its entire protected value + fee reserve (${payout} KAS) to the vault owner public key ${m.vault.owner}. This is terminal — the vault ends.`;
    }
    case "createVault": {
      const prot = sompiToKasString(ctx.accounting.successorProtected, "accounting.successorProtected");
      const res = sompiToKasString(ctx.accounting.successorFeeReserve, "accounting.successorFeeReserve");
      return `Create vault ${vaultId} with ${prot} KAS protected value and ${res} KAS fee reserve, owned by public key ${m.vault.owner}.`;
    }
    default:
      return `Unknown action.`; // unreachable: validateManifest refuses unknown actions
  }
}

/* Policy-mutation rendering. Category:
 *   funding    — protectedValue / feeReserve movement;
 *   accounting — execution-managed values (spend period accounting,
 *                policyNonce advancement);
 *   policy     — the governed policy surface (paused, approver
 *                configuration, owner agent-registry replacement). */
function policyChangeEntries(ctx) {
  const entries = [];
  for (const mut of ctx.manifest.policyMutations) {
    const { field, before, after } = mut;
    if (field === "protectedValue" || field === "feeReserve") {
      const label = field === "protectedValue" ? "Protected value" : "Fee reserve";
      entries.push({
        field,
        category: "funding",
        before,
        after,
        beforeKas: sompiToKasString(before, field),
        afterKas: sompiToKasString(after, field),
        description: `${label}: ${sompiToKasString(before, field)} KAS -> ${sompiToKasString(after, field)} KAS.`
      });
    } else if (field === "agentRoot") {
      const spend = ctx.sdkAction === "agentSpend";
      entries.push({
        field,
        category: spend ? "accounting" : "policy",
        before,
        after,
        description: spend
          ? `Agent registry commitment advances for this spend's period accounting: ${before} -> ${after}.`
          : `Agent registry commitment replaced: ${before} -> ${after}.`
      });
    } else if (field === "paused") {
      entries.push({
        field,
        category: "policy",
        before,
        after,
        description: after === "1" ? "Vault paused (spending frozen)." : "Vault unpaused (spending resumes)."
      });
    } else if (field === "approverSlots") {
      entries.push({
        field,
        category: "policy",
        before: before.slice(),
        after: after.slice(),
        description: "Approver key slots replaced (full before/after slot lists carried in this entry)."
      });
    } else if (field === "approvalM") {
      entries.push({
        field,
        category: "policy",
        before,
        after,
        description: `Approval quorum: ${before} -> ${after} required approval(s).`
      });
    } else if (field === "policyNonce") {
      entries.push({
        field,
        category: "accounting",
        before,
        after,
        description: `Policy nonce advances ${before} -> ${after} (policy-defining operation).`
      });
    } else {
      /* Unreachable after validateManifest (closed STATE_FIELDS set);
       * still rendered honestly rather than dropped. */
      entries.push({ field, category: "policy", before, after, description: `${field}: ${JSON.stringify(before)} -> ${JSON.stringify(after)}.` });
    }
  }
  return entries;
}

/* ------------------------------------------------------------------ */
/* structured explanation                                              */
/* ------------------------------------------------------------------ */

/*
 * Build the structured explanation for a manifest + verification result.
 * TOTAL: always returns an explanation document; refusal on any doubt.
 */
function structured(input) {
  // TOTAL contract: never throw. A null/non-object argument (not just a
  // missing one) must still produce a refusal, not a TypeError from
  // destructuring. (Hostile-AI review H-4.)
  const { manifest, verification } = (input && typeof input === "object") ? input : {};
  try {
    /* 1. Independent strict validation of the manifest itself (schema,
     * versions, actions, representation-independent hash). A manifest
     * that fails validation gets a refusal carrying ONLY the local
     * validation error — nothing from an unvalidated document is
     * rendered, not even identity context. */
    let ctx;
    try {
      ctx = validateManifest(manifest);
    } catch (e) {
      return refusalDocument({
        reason: "The manifest failed strict validation and cannot be rendered.",
        failures: [failureEntry(e.code ?? "SCHEMA_INVALID", e.message)]
      });
    }
    const context = {
      networkId: ctx.manifest.network.networkId,
      vaultId: ctx.manifest.vault.vaultId,
      covenantVersion: ctx.manifest.vault.covenantVersion,
      sdkAction: ctx.sdkAction,
      highLevelAction: ctx.manifest.action.highLevelAction
    };
    const manifestHash = ctx.manifest.manifestHash;
    const txId = ctx.manifest.transaction.txId;

    /* 2. The verification result is REQUIRED and must be well-formed. */
    if (verification === undefined || verification === null) {
      return refusalDocument({
        reason: "No verification result was supplied — an unverified manifest is never rendered as a normal transaction summary.",
        failures: [failureEntry("MISSING_VERIFICATION", "explanations require the verifyIntentManifest result for this exact manifest")],
        context,
        manifestHash,
        txId
      });
    }
    const shapeProblem = verificationShapeProblem(verification);
    if (shapeProblem) {
      return refusalDocument({
        reason: "The supplied verification result is malformed — failing closed.",
        failures: [failureEntry("VERIFICATION_MALFORMED", shapeProblem)],
        context,
        manifestHash,
        txId
      });
    }

    /* 3. A non-full-pass verification produces the REFUSAL rendering,
     * prominently listing every detector code. */
    if (verification.ok !== true) {
      const failures = verification.failures.map((f) => failureEntry(f.code, f.detail ?? ""));
      return refusalDocument({
        reason: "Verification REFUSED this manifest — the transaction must not be signed.",
        failures: failures.length ? failures : [failureEntry("REFUSED", "verification refused without detail")],
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(verification)
      });
    }

    /* 4. The verification result must BIND to THIS manifest. */
    if (verification.manifestHash !== manifestHash || verification.txId !== txId) {
      return refusalDocument({
        reason: "The supplied verification result is for a DIFFERENT manifest/transaction — failing closed.",
        failures: [
          failureEntry(
            "VERIFICATION_BINDING_MISMATCH",
            `verification is bound to manifestHash ${verification.manifestHash} / txId ${verification.txId}, not this manifest`
          )
        ],
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(verification)
      });
    }

    /* 5. Independent in-process RE-VERIFICATION (self-contained). A
     * fabricated ok:true object cannot make an unverified manifest
     * render: the explanation layer re-proves the verdict itself. */
    const reverified = verifyIntentManifest({ manifest });
    if (reverified.ok !== true) {
      const failures = [
        failureEntry("EXPLAIN_REVERIFY_REFUSED", "independent re-verification refused this manifest despite the supplied passing result"),
        ...reverified.failures.map((f) => failureEntry(f.code, f.detail ?? ""))
      ];
      return refusalDocument({
        reason: "Independent re-verification REFUSED this manifest — the supplied verification result is not trustworthy.",
        failures,
        context,
        manifestHash,
        txId,
        verificationSummary: verificationSummaryOf(reverified)
      });
    }

    /* 6. VERIFIED — build the normal rendering, from the verified
     * manifest only. */
    const m = ctx.manifest;
    const doc = baseDocument();
    doc.verdict = EXPLANATION_VERDICTS.VERIFIED_EXACT;
    doc.statement = VERIFIED_STATEMENT;
    doc.manifestHash = manifestHash;
    doc.txId = txId;
    doc.network = { networkId: m.network.networkId };
    doc.vault = {
      vaultId: m.vault.vaultId,
      owner: m.vault.owner,
      covenantVersion: m.vault.covenantVersion,
      covenantId: m.vault.covenantId
    };
    doc.action = {
      sdkAction: ctx.sdkAction,
      highLevelAction: m.action.highLevelAction,
      role: m.action.role,
      genesis: m.action.genesis,
      terminal: m.action.terminal,
      aboveThreshold: m.action.aboveThreshold,
      summary: actionSummary(ctx)
    };
    doc.actor = { role: m.actor.role, signerXOnly: m.actor.signerXOnly, agentPk: m.actor.agentPk };

    doc.fee = {
      fee: kasAmount(ctx.accounting.fee, "accounting.fee"),
      maxFee: m.requested.maxFeeSompi === null ? null : kasAmount(m.requested.maxFeeSompi, "requested.maxFeeSompi"),
      withinRequestedCap: m.requested.maxFeeSompi === null ? null : true
    };

    doc.outputs = ctx.txView.outputs.map((output, index) => {
      const kind = ctx.effects.outputKinds[index];
      const value = kasAmount(output.value, `outputs[${index}].value`);
      const destinationXOnly = destinationXOnlyFor(kind, ctx);
      return {
        index,
        kind,
        destinationKind: OUTPUT_DESTINATIONS[kind],
        destinationXOnly,
        value,
        description: outputDescription(kind, value.kas, destinationXOnly)
      };
    });

    doc.payment =
      ctx.payment === null
        ? null
        : {
            recipientXOnly: m.payment.recipientXOnly,
            amount: kasAmount(ctx.payment.amountSompi, "payment.amountSompi"),
            outputIndex: m.payment.outputIndex
          };

    doc.accounting = {};
    for (const field of Object.keys(ctx.accounting)) {
      doc.accounting[field] = kasAmount(ctx.accounting[field], `accounting.${field}`);
    }

    doc.balances = {
      before: ctx.stateBefore === null ? null : stateBlock(ctx.stateBefore.state, ctx.stateBefore.stateId),
      after: ctx.stateAfter === null ? null : stateBlock(ctx.stateAfter.state, ctx.stateAfter.stateId)
    };
    if (doc.balances.before !== null) {
      doc.balances.before.outpoint = copyOutpoint(m.stateBefore.outpoint);
    }
    if (doc.balances.after !== null) {
      doc.balances.after.expectedOutpoint = copyOutpoint(m.stateAfter.expectedOutpoint);
    }

    doc.policyChanges = policyChangeEntries(ctx);

    doc.policyNonce =
      ctx.stateBefore === null || ctx.stateAfter === null
        ? null
        : {
            before: m.stateBefore.state.policyNonce,
            after: m.stateAfter.state.policyNonce,
            rule: ctx.info.nonce
          };

    if (ctx.sdkAction === "agentSpend") {
      doc.approvals = {
        aboveThreshold: m.approvals.aboveThreshold,
        approvalThreshold: kasAmount(ctx.approvals.approvalThreshold, "approvals.approvalThreshold"),
        requiredM: ctx.approvals.requiredM.toString()
      };
      const pb = ctx.limits.policyBefore;
      const pa = ctx.limits.policyAfter;
      const rollover = ctx.limits.periodsElapsed >= 1n;
      doc.limits = {
        agentPk: m.limits.policyBefore.agentPk,
        maxPerSpend: kasAmount(pb.maxPerSpend, "policy.maxPerSpend"),
        periodBudget: kasAmount(pb.periodBudget, "policy.periodBudget"),
        periodSpentBefore: kasAmount(pb.periodSpent, "policy.periodSpent"),
        periodSpentAfter: kasAmount(pa.periodSpent, "policy.periodSpentAfter"),
        remainingAfter: kasAmount(pa.periodBudget - pa.periodSpent, "policy.remainingAfter"),
        periodLengthDaa: pb.periodLengthDaa.toString(),
        periodsElapsed: ctx.limits.periodsElapsed.toString(),
        rollover,
        periodStartAfterDaa: pa.periodStartDaa.toString(),
        lockTime: ctx.txView.lockTime.toString(),
        agentMaxFeePerTx: kasAmount(pb.agentMaxFeePerTx, "policy.agentMaxFeePerTx"),
        reserveConsumed: kasAmount(ctx.accounting.reserveConsumed, "accounting.reserveConsumed"),
        agentRecipientRoot: m.allowlist.agentRecipientRoot,
        recipientAllowlisted: m.allowlist.recipientAllowlisted,
        allowlistProofSupplied: m.allowlist.proofSupplied
      };
    }

    doc.warnings = m.warnings.map((w) => ({ code: w.code, detail: w.detail }));
    doc.verification = verificationSummaryOf(verification);
    return deepFreeze(doc);
  } catch (e) {
    /* An internal error is never a pass — refuse. */
    return refusalDocument({
      reason: "The explanation engine failed internally — failing closed.",
      failures: [failureEntry("EXPLAIN_INTERNAL", `${e.message}`)]
    });
  }
}

/* ------------------------------------------------------------------ */
/* human-readable lines                                                */
/* ------------------------------------------------------------------ */

function refusalLines(doc) {
  const lines = [];
  lines.push("!! DO NOT SIGN !!");
  lines.push("VERIFICATION REFUSED — this transaction description FAILED verification and must not be signed.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  if (doc.context !== null) {
    const c = doc.context;
    const action = c.highLevelAction === null ? c.sdkAction : `${c.highLevelAction} (${c.sdkAction})`;
    lines.push(
      `Context (from the manifest, NOT verified): action ${action}, vault ${c.vaultId}, network ${c.networkId}, covenant ${c.covenantVersion}.`
    );
  }
  if (doc.txId !== null) lines.push(`Transaction id (NOT verified): ${doc.txId}.`);
  if (doc.manifestHash !== null) lines.push(`Manifest hash: ${doc.manifestHash}.`);
  lines.push("A refused manifest is never rendered as a normal transaction summary. Rebuild the request and verify again.");
  return lines;
}

function verifiedLines(doc) {
  const lines = [];
  lines.push(doc.action.summary);

  /* Every output the transaction creates, in order, with full values. */
  for (const output of doc.outputs) {
    lines.push(`Output ${output.index}: ${output.description}`);
  }

  const cap = doc.fee.maxFee === null ? "" : ` (within the requested cap of ${doc.fee.maxFee.kas} KAS)`;
  lines.push(`Fee: ${doc.fee.fee.kas} KAS${cap}.`);

  if (doc.balances.after !== null) {
    const afterProt = doc.balances.after.protectedValue.kas;
    const afterRes = doc.balances.after.feeReserve.kas;
    if (doc.balances.before !== null) {
      lines.push(
        `Protected value after: ${afterProt} KAS (was ${doc.balances.before.protectedValue.kas} KAS). Fee reserve after: ${afterRes} KAS (was ${doc.balances.before.feeReserve.kas} KAS).`
      );
    } else {
      lines.push(`Protected value: ${afterProt} KAS. Fee reserve: ${afterRes} KAS.`);
    }
  } else if (doc.action.terminal) {
    lines.push("The vault is CLOSED by this transaction — no successor state remains.");
  }

  if (doc.limits !== null) {
    lines.push(
      `Budget after: ${doc.limits.periodSpentAfter.kas} KAS of the ${doc.limits.periodBudget.kas} KAS period budget used (${doc.limits.remainingAfter.kas} KAS remaining). Per-spend cap: ${doc.limits.maxPerSpend.kas} KAS.`
    );
    if (doc.limits.rollover) {
      lines.push(
        `A new budget period starts with this spend (periods elapsed: ${doc.limits.periodsElapsed}); the transaction is not valid before DAA score ${doc.limits.lockTime}.`
      );
    }
    lines.push(`Network fee is paid from the vault fee reserve: ${doc.limits.reserveConsumed.kas} KAS (agent per-transaction fee cap ${doc.limits.agentMaxFeePerTx.kas} KAS).`);
    lines.push(`Recipient is authorized by this agent's recipient allowlist (root ${doc.limits.agentRecipientRoot}); membership proof verified upstream.`);
  }

  if (doc.approvals !== null) {
    if (doc.approvals.aboveThreshold) {
      lines.push(
        `This spend is ABOVE the approval threshold (${doc.approvals.approvalThreshold.kas} KAS): ${doc.approvals.requiredM} approver signature(s) are required by the covenant.`
      );
    } else {
      lines.push(`This spend is at or below the approval threshold (${doc.approvals.approvalThreshold.kas} KAS): no approver signatures are required.`);
    }
  }

  const policyEntries = doc.policyChanges === null ? [] : doc.policyChanges.filter((e) => e.category === "policy");
  if (doc.action.genesis) {
    lines.push("This transaction creates the vault's initial policy state.");
  } else if (doc.action.terminal) {
    lines.push("All policy for this vault ends with the vault.");
  } else if (policyEntries.length === 0) {
    const qualifier = doc.action.sdkAction === "agentSpend" ? "spend and period accounting only" : "funding only";
    lines.push(`No policy changes — ${qualifier}.`);
  } else {
    for (const e of policyEntries) {
      lines.push(`Policy change: ${e.description}`);
    }
  }
  if (doc.policyNonce !== null && doc.policyNonce.rule === "increment") {
    lines.push(`Policy nonce advances ${doc.policyNonce.before} -> ${doc.policyNonce.after}.`);
  }

  for (const w of doc.warnings) {
    lines.push(`Warning ${w.code}: ${sanitizeDetail(w.detail)}`);
  }

  lines.push(`Vault: ${doc.vault.vaultId} (network ${doc.network.networkId}, covenant ${doc.vault.covenantVersion}).`);
  lines.push(`Signer: ${doc.actor.role} public key ${doc.actor.signerXOnly}.`);
  lines.push(`Transaction id: ${doc.txId}. Manifest hash: ${doc.manifestHash}.`);
  lines.push(`Verification: PASSED — ${doc.statement}`);
  return lines;
}

/*
 * Deterministic English lines for a signer UI. TOTAL: never throws;
 * refusals render as prominent DO-NOT-SIGN lines. Same input ->
 * byte-identical output.
 */
function humanReadable(input) {
  // TOTAL contract (H-4): tolerate a null/non-object argument.
  const { manifest, verification } = (input && typeof input === "object") ? input : {};
  const doc = structured({ manifest, verification });
  const lines = doc.verdict === EXPLANATION_VERDICTS.VERIFIED_EXACT ? verifiedLines(doc) : refusalLines(doc);
  return deepFreeze(lines);
}

module.exports = {
  INTENT_EXPLANATION_VERSION_1,
  EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
  });

  define("core/signer/errors", function (module, exports, require) {
"use strict";

/*
 * PolicyVault Universal Signer Interface v1 — structured error taxonomy.
 *
 * Every failure that crosses the signer-adapter boundary is expressed as a
 * SignerError carrying a code from the CLOSED vocabulary below. The
 * vocabulary is frozen for interface v1: an adapter (or consumer) that
 * emits a code outside this set is treated as having BROKEN the interface
 * contract and its failure is mapped, fail closed, to PROTOCOL_VIOLATION —
 * never passed through, never guessed into a "similar" meaning, never
 * routed to a benign default.
 *
 * Design lineage (read-only reference, not imported):
 *   - web/wallet.js `WalletError` — the existing browser adapter categories
 *     (WALLET_NOT_FOUND, USER_REJECTED, WRONG_NETWORK, SIGNING_UNSUPPORTED,
 *     INVALID_SIGNATURE_RESPONSE, INVALID_PUBLIC_KEY, PROVIDER_ERROR, ...).
 *   - server/src/auth.js `AuthErrorCodes` — the hosted challenge/verify
 *     codes (server side; NOT duplicated here — authentication decisions
 *     stay server-side, this module only classifies signer-side failures).
 *
 * Pure Node CommonJS. Zero external dependencies. No imports from
 * server/ or sdk/.
 */

const SIGNER_INTERFACE_VERSION = "policyvault-signer/1";

/* CLOSED error-code vocabulary for interface v1. */
const SignerErrorCodes = Object.freeze({
  /* Presence / session */
  SIGNER_NOT_FOUND: "SIGNER_NOT_FOUND", // provider not installed / not reachable
  SIGNER_DISCONNECTED: "SIGNER_DISCONNECTED", // no connected/active account
  SIGNER_LOCKED: "SIGNER_LOCKED", // provider present but locked; user action needed

  /* Human / policy decisions */
  USER_REJECTED: "USER_REJECTED", // the signer's holder declined the request

  /* Identity / environment binding (fail-closed identity boundary) */
  WRONG_NETWORK: "WRONG_NETWORK", // live or declared network != required network
  ACCOUNT_CHANGED: "ACCOUNT_CHANGED", // active identity changed before/during/after signing

  /* Capability negotiation */
  UNSUPPORTED_CAPABILITY: "UNSUPPORTED_CAPABILITY", // adapter does not offer a required feature
  UNSUPPORTED_SCHEME: "UNSUPPORTED_SCHEME", // required signature scheme not offered / not contract-defined

  /* Material validation */
  INVALID_PUBLIC_KEY: "INVALID_PUBLIC_KEY", // provider public key claim malformed / unsupported encoding
  INVALID_SIGNATURE_RESPONSE: "INVALID_SIGNATURE_RESPONSE", // signing result malformed for the requested scheme/kind

  /* Lifecycle */
  SIGNER_TIMEOUT: "SIGNER_TIMEOUT", // approval deadline elapsed; request cancelled fail-closed

  /* Faults */
  PROVIDER_ERROR: "PROVIDER_ERROR", // unclassified provider/transport exception (cause preserved)
  PROTOCOL_VIOLATION: "PROTOCOL_VIOLATION", // adapter/consumer broke the interface contract (incl. unknown codes)
  INTERFACE_VERSION_UNSUPPORTED: "INTERFACE_VERSION_UNSUPPORTED", // version mismatch — fail closed, no downgrade
  REQUEST_INVALID: "REQUEST_INVALID" // malformed signing request / options refused before the signer is invoked
});

const KNOWN_CODES = Object.freeze(new Set(Object.values(SignerErrorCodes)));

/*
 * Throws when `code` is not part of the v1 vocabulary. Used both by the
 * SignerError constructor (a PolicyVault component must never mint an
 * unknown code) and by adapter-failure normalization (an adapter claiming
 * an unknown code is a contract breach).
 */
function assertKnownErrorCode(code) {
  if (typeof code !== "string" || !KNOWN_CODES.has(code)) {
    const shown = typeof code === "string" ? JSON.stringify(code) : typeof code;
    const err = new Error(`unknown signer error code ${shown} — not in the ${SIGNER_INTERFACE_VERSION} vocabulary; failing closed`);
    err.signerCode = SignerErrorCodes.PROTOCOL_VIOLATION;
    throw err;
  }
  return code;
}

function isKnownErrorCode(code) {
  return typeof code === "string" && KNOWN_CODES.has(code);
}

/*
 * The one structured error type of the interface. `signerCode` is the
 * machine-readable classification; `details` is an optional plain object of
 * NON-SECRET diagnostic fields (never key material, never seed phrases,
 * never raw provider payload dumps). `cause` preserves the original
 * exception for diagnostics without altering classification.
 */
class SignerError extends Error {
  constructor(code, message, { details, cause } = {}) {
    assertKnownErrorCode(code);
    super(message || code);
    this.name = "SignerError";
    this.signerCode = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

function signerError(code, message, extra) {
  return new SignerError(code, message, extra);
}

function isSignerError(e) {
  return e instanceof SignerError;
}

/*
 * Fail-closed normalization of ANYTHING thrown across the adapter
 * boundary into a SignerError:
 *
 *   1. A SignerError passes through unchanged (already classified by this
 *      module — its constructor enforced a known code).
 *   2. An error-like value carrying a KNOWN `signerCode` is the sanctioned
 *      way for adapters to classify their own failures (mirrors
 *      web/wallet.js `walletCategory`): it is wrapped preserving code,
 *      message, and the original as `cause`.
 *   3. An error-like value carrying an UNKNOWN `signerCode` broke the
 *      contract: mapped to PROTOCOL_VIOLATION with the claimed code
 *      recorded in details. NEVER passed through, NEVER guessed.
 *   4. Anything else (plain Error, string, undefined, ...) is an
 *      unclassified provider fault: PROVIDER_ERROR with cause preserved.
 *
 * `context` is a short human label ("signMessage", "getNetwork", ...)
 * prefixed into the message for diagnosability.
 */
function normalizeAdapterFailure(raw, context) {
  const where = context ? `${context}: ` : "";
  if (isSignerError(raw)) return raw;
  const claimed = raw && typeof raw === "object" ? raw.signerCode : undefined;
  if (claimed !== undefined) {
    if (isKnownErrorCode(claimed)) {
      return new SignerError(claimed, `${where}${raw.message || claimed}`, { cause: raw });
    }
    return new SignerError(
      SignerErrorCodes.PROTOCOL_VIOLATION,
      `${where}adapter emitted unknown error code ${JSON.stringify(String(claimed))} — outside the ${SIGNER_INTERFACE_VERSION} vocabulary; failing closed`,
      { details: { claimedCode: String(claimed) }, cause: raw }
    );
  }
  const message = raw && typeof raw === "object" && typeof raw.message === "string" && raw.message ? raw.message : String(raw);
  return new SignerError(SignerErrorCodes.PROVIDER_ERROR, `${where}${message}`, { cause: raw });
}

module.exports = {
  SIGNER_INTERFACE_VERSION,
  SignerErrorCodes,
  SignerError,
  signerError,
  isSignerError,
  isKnownErrorCode,
  assertKnownErrorCode,
  normalizeAdapterFailure
};
  });

  define("core/signer/interface", function (module, exports, require) {
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
  });

  define("core/model/amounts", function (module, exports, require) {
"use strict";

/*
 * Canonical KAS <-> sompi conversion.
 *
 * All consensus/accounting values are BigInt sompi. Floating point is
 * forbidden on every funds path. Parsers fail closed on anything that is
 * not an exact, in-range, well-formed amount.
 */

const SOMPI_PER_KAS = 100_000_000n;

/* Kaspa max supply ~28.7B KAS; use a generous hard ceiling for sanity. */
const MAX_SOMPI = 29_000_000_000n * SOMPI_PER_KAS;

function fail(message) {
  throw new Error(`amounts: ${message}`);
}

/*
 * Parse a decimal-string sompi amount into BigInt.
 * Accepts BigInt directly. Rejects numbers (floating-point risk).
 */
function parseSompi(value, field = "amount") {
  let amount;

  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!/^\d+$/.test(value)) {
      fail(`${field} must be a base-10 digit string, got ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    fail(`${field} must be a BigInt or decimal string, got ${typeof value}`);
  }

  if (amount < 0n) {
    fail(`${field} must not be negative`);
  }
  if (amount > MAX_SOMPI) {
    fail(`${field} exceeds maximum representable sompi`);
  }

  return amount;
}

function parsePositiveSompi(value, field = "amount") {
  const amount = parseSompi(value, field);
  if (amount === 0n) {
    fail(`${field} must be greater than zero`);
  }
  return amount;
}

/*
 * Parse a human KAS decimal string ("12", "0.5", "1.23456789") into
 * BigInt sompi. Max 8 fractional digits, no exponents, no signs, no
 * floats.
 */
function kasToSompi(value, field = "amount") {
  if (typeof value !== "string") {
    fail(`${field} must be a string KAS amount, got ${typeof value}`);
  }
  const match = /^(\d+)(?:\.(\d{1,8}))?$/.exec(value.trim());
  if (!match) {
    fail(`${field} is not a valid KAS decimal string: ${JSON.stringify(value)}`);
  }
  const whole = BigInt(match[1]);
  const fracDigits = match[2] ?? "";
  const frac = BigInt(fracDigits.padEnd(8, "0") || "0");
  const amount = whole * SOMPI_PER_KAS + frac;
  if (amount > MAX_SOMPI) {
    fail(`${field} exceeds maximum representable sompi`);
  }
  return amount;
}

/*
 * Render BigInt sompi as a canonical KAS decimal string with trailing
 * zeros trimmed ("1.5", "0.00000001", "12").
 */
function sompiToKas(value, field = "amount") {
  const amount = parseSompi(value, field);
  const whole = amount / SOMPI_PER_KAS;
  const frac = amount % SOMPI_PER_KAS;
  if (frac === 0n) {
    return whole.toString();
  }
  const fracStr = frac.toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole}.${fracStr}`;
}

module.exports = {
  SOMPI_PER_KAS,
  MAX_SOMPI,
  parseSompi,
  parsePositiveSompi,
  kasToSompi,
  sompiToKas
};
  });

  define("core/model/contract-version", function (module, exports, require) {
"use strict";

/*
 * Frozen protocol-identity constant, severed from sdk/src/config.js during
 * shared-core extraction step 1 — the ONLY value vault-state.js needed from
 * the impure config module (config reads process.env / fs and must not
 * enter the portable core).
 *
 * CONTRACT_VERSION participates in every v1 state-ID preimage
 * ("contract:<version>" line in computeStateId), so it is frozen
 * application identity, NOT deployment configuration: changing it would
 * re-identify every existing v1 vault state. Since extraction step 2,
 * sdk/src/config.js consumes THIS module (no duplicate literal exists);
 * core/model/test/contract-version-sync.test.js proves the single
 * sourcing and pins the frozen tag.
 */

const CONTRACT_VERSION = "policyvault-0.1-beta";

module.exports = { CONTRACT_VERSION };
  });

  define("core/model/vault-state", function (module, exports, require) {
"use strict";

/*
 * Exact live-state model for a PolicyVault vault.
 *
 * A vault's full identity = immutable policy (constructor params, part of
 * the compiled template) + mutable state fields + contract version +
 * network. There is exactly one current live state; its deterministic
 * state ID names build artifacts and binds requests.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { CONTRACT_VERSION } = require("./contract-version");

function fail(message) {
  throw new Error(`vault-state: ${message}`);
}

function normalizeHex(value, bytes, field) {
  if (typeof value !== "string") {
    fail(`${field} must be a hex string`);
  }
  const normalized = value.trim().toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(normalized)) {
    fail(`${field} must be ${bytes}-byte lowercase hex`);
  }
  return normalized;
}

function normalizeXOnlyPubkey(value, field) {
  return normalizeHex(value, 32, field);
}

function normalizeDaa(value, field) {
  const daa = parseSompi(value, field); // same digit-string/BigInt rules
  /*
   * DAA-score locks must stay below LOCK_TIME_THRESHOLD (5e11) so
   * tx.time comparisons keep DAA semantics (rusty-kaspa constants.rs).
   */
  if (daa >= 500_000_000_000n) {
    fail(`${field} must be below the DAA lock-time threshold`);
  }
  return daa;
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

/*
 * Immutable policy. recipients: array of 1..3 x-only pubkey hex strings;
 * unused slots repeat the first recipient so the compiled template stays
 * shaped for exactly 3.
 */
function normalizePolicy(input) {
  if (!input || typeof input !== "object") {
    fail("policy object is required");
  }

  const recipientsIn = input.recipients;
  if (!Array.isArray(recipientsIn) || recipientsIn.length < 1 || recipientsIn.length > 3) {
    fail("policy.recipients must contain 1 to 3 recipients");
  }
  const recipients = recipientsIn.map((r, i) => normalizeXOnlyPubkey(r, `policy.recipients[${i}]`));
  const padded = [recipients[0], recipients[1] ?? recipients[0], recipients[2] ?? recipients[1] ?? recipients[0]];

  const maxPerSpend = parsePositiveSompi(input.maxPerSpend, "policy.maxPerSpend");
  const periodBudget = parsePositiveSompi(input.periodBudget, "policy.periodBudget");
  if (periodBudget < maxPerSpend) {
    fail("policy.periodBudget must be >= policy.maxPerSpend");
  }

  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "policy.owner"),
    delegate: normalizeXOnlyPubkey(input.delegate, "policy.delegate"),
    vaultId: normalizeHex(input.vaultId, 32, "policy.vaultId"),
    maxPerSpend,
    periodBudget,
    periodLengthDaa: normalizeSmallInt(input.periodLengthDaa, "policy.periodLengthDaa", {
      min: 1n,
      max: 500_000_000_000n
    }),
    recipients: Object.freeze(padded),
    declaredRecipientCount: recipients.length,
    initValue: parsePositiveSompi(input.initValue, "policy.initValue"),
    initPeriodStartDaa: normalizeDaa(input.initPeriodStartDaa, "policy.initPeriodStartDaa")
  });
}

/* Mutable state fields. */
function normalizeState(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const protectedValue = parsePositiveSompi(input.protectedValue, "state.protectedValue");
  const periodSpent = parseSompi(input.periodSpent, "state.periodSpent");
  const paused = normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n });
  return Object.freeze({
    protectedValue,
    periodStartDaa: normalizeDaa(input.periodStartDaa, "state.periodStartDaa"),
    periodSpent,
    paused
  });
}

/*
 * Deterministic application-level state ID: sha256 over a canonical,
 * versioned, field-tagged encoding. (Application identity only — never a
 * consensus value.)
 */
function computeStateId({ networkId, policy, state }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  const canonical = [
    "policyvault-state/v1",
    `network:${networkId}`,
    `contract:${CONTRACT_VERSION}`,
    `owner:${policy.owner}`,
    `delegate:${policy.delegate}`,
    `vaultId:${policy.vaultId}`,
    `maxPerSpend:${policy.maxPerSpend}`,
    `periodBudget:${policy.periodBudget}`,
    `periodLengthDaa:${policy.periodLengthDaa}`,
    `recipients:${policy.recipients.join(",")}`,
    `initValue:${policy.initValue}`,
    `initPeriodStartDaa:${policy.initPeriodStartDaa}`,
    `protectedValue:${state.protectedValue}`,
    `periodStartDaa:${state.periodStartDaa}`,
    `periodSpent:${state.periodSpent}`,
    `paused:${state.paused}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/* The exact successor state for a within-period delegate spend. */
function spendSuccessor(state, payAmount) {
  const pay = parsePositiveSompi(payAmount, "payAmount");
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return Object.freeze({
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa,
    periodSpent: state.periodSpent + pay,
    paused: 0n
  });
}

/* The exact successor state for a rollover-and-spend. */
function rolloverSuccessor(policy, state, payAmount, periodsElapsed) {
  const pay = parsePositiveSompi(payAmount, "payAmount");
  const periods = normalizeSmallInt(periodsElapsed, "periodsElapsed", { min: 1n, max: 1000n });
  if (pay >= state.protectedValue) {
    fail("spend would not leave a positive successor value");
  }
  return Object.freeze({
    protectedValue: state.protectedValue - pay,
    periodStartDaa: state.periodStartDaa + periods * policy.periodLengthDaa,
    periodSpent: pay,
    paused: 0n
  });
}

module.exports = {
  normalizePolicy,
  normalizeState,
  computeStateId,
  spendSuccessor,
  rolloverSuccessor,
  normalizeHex,
  normalizeXOnlyPubkey
};
  });

  define("core/model/recipient-merkle-v3", function (module, exports, require) {
"use strict";

/*
 * PolicyVault v0.3 canonical recipient Merkle tree / proof SDK.
 *
 * This is the ONE tree builder + proof generator + verifier for the v0.3
 * recipient allowlist (docs/v03-recipient-auth-design.md). The covenant is
 * the authority; this module must produce exactly the bytes the PRODUCTION
 * covenant accepts (proven by tests/vm/tests/v3_sdk_integration.rs, which
 * drives SDK-generated proofs through the real pv_call_encoder binary and
 * the production PolicyVault.v0.3.sil on the real TxScriptEngine).
 *
 * Canonical construction (all source-checked against the covenant):
 *   leaf  = SHA256(0x50 0x56 0x33 0x01 || recipient_xonly_pubkey)
 *           (36-byte preimage; the covenant ALWAYS recomputes the leaf
 *            from recipientPk, never accepts a preformed leaf)
 *   node  = SHA256(left || right)   (64-byte preimage — cannot collide
 *            with the 36-byte leaf preimage)
 *   depth <= 16 (siblings.length <= 512 and multiple of 32; pathBits in
 *            [0, 65536) and fully consumed after the walk)
 *
 * Determinism rules:
 *   - active recipient x-only keys are DE-DUPLICATED and sorted ascending
 *     (fixed-width lowercase hex sorts identically to byte order), so one
 *     recipient set has exactly one root;
 *   - non-power-of-two leaf counts are padded by DUPLICATING THE LAST NODE
 *     at each level (matching the VM test fixture semantics: padding
 *     happens at the leaf level up to the next power of two);
 *   - a single recipient is depth 0: empty siblings, pathBits 0, and
 *     root == leaf (VM-proven);
 *   - zero recipients is DISALLOWED (a vault that can pay nobody is a
 *     policy error; fail closed).
 *
 * Known benign property of duplicate-padding: where a node equals its own
 * sibling (a padded level), SHA256(node||sib) == SHA256(sib||node), so
 * that level's path bit is not significant — two encodings prove the SAME
 * recipient under the SAME root. Membership and exact output binding are
 * unaffected; this is proof-encoding malleability only, never an
 * authorization change.
 *
 * pathBits convention (exactly the covenant's): bit i (LSB-first) is 1
 * when the running node is the RIGHT child at level i, i.e. the sibling is
 * hashed on the LEFT: node = SHA256(sib || node). Bit 0 => sibling on the
 * right: node = SHA256(node || sib).
 *
 * All identities are 32-byte x-only pubkeys (lowercase hex). Wallet
 * addresses must be resolved through the shared address-identity boundary
 * (sdk/src/address-identity.js) BEFORE reaching this module — this module
 * never parses addresses.
 *
 * BROWSER-PORTABLE (F1 byte-native refactor): all byte plumbing is
 * Uint8Array-native — no Buffer dependency — so this module runs
 * byte-identically in Node and inside the browser core bundle
 * (web/core-bundle.js crypto shim: update(<Uint8Array>) / digest()).
 * Byte identity with the pre-refactor Buffer implementation is pinned by
 * core/model/test/golden-f1-merkle.test.js (fixture captured from the
 * ORIGINAL code). In Node, hash outputs (leafHash, tree levels) are the
 * node:crypto digest objects (Buffer IS a Uint8Array) exactly as before.
 */

const crypto = require("crypto");
const { normalizeXOnlyPubkey } = require("./vault-state");

const LEAF_DOMAIN = Uint8Array.of(0x50, 0x56, 0x33, 0x01);
const MAX_DEPTH = 16;
const MAX_RECIPIENTS = 1 << MAX_DEPTH; // 65,536

function fail(message) {
  throw new Error(`recipient-merkle-v3: ${message}`);
}

/* ---- portable byte helpers (inputs validated upstream) ---- */

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

/* Canonical leaf hash for one recipient x-only pubkey (hex in, bytes out). */
function leafHash(recipientXOnlyHex) {
  const key = normalizeXOnlyPubkey(recipientXOnlyHex, "recipient");
  return sha256(concatBytes([LEAF_DOMAIN, hexToBytes(key)]));
}

/*
 * Build the canonical recipient tree.
 *
 * recipients: array of x-only pubkey hex strings (>= 1). Duplicates are
 * collapsed; the active set is sorted ascending. Returns a frozen object:
 *   { root, recipients, leafCount, depth, levels }
 * where `root` is 64-hex, `recipients` is the sorted de-duplicated key
 * list, `depth` is the proof depth every generated proof will have, and
 * `levels` holds the raw byte levels for proof generation.
 */
function buildRecipientTree(recipientsInput) {
  if (!Array.isArray(recipientsInput) || recipientsInput.length === 0) {
    fail("recipients must be a non-empty array — a vault with no recipients cannot spend");
  }
  const seen = new Set();
  const keys = [];
  recipientsInput.forEach((r, i) => {
    const key = normalizeXOnlyPubkey(r, `recipients[${i}]`);
    if (!seen.has(key)) {
      seen.add(key);
      keys.push(key);
    }
  });
  keys.sort();
  if (keys.length > MAX_RECIPIENTS) {
    fail(`recipient count ${keys.length} exceeds the maximum ${MAX_RECIPIENTS} (depth ${MAX_DEPTH})`);
  }

  /* Pad the LEAF level to the next power of two by duplicating the last
   * leaf, then hash pairwise up. This matches the production VM fixtures
   * (tests/vm: `while level.len().count_ones() != 1 { push(last) }` at the
   * leaf level). */
  let level = keys.map((k) => leafHash(k));
  while ((level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(concatBytes([level[i], level[i + 1]])));
    }
    levels.push(next);
    level = next;
  }

  const depth = levels.length - 1;
  if (depth > MAX_DEPTH) {
    fail(`tree depth ${depth} exceeds the covenant maximum ${MAX_DEPTH}`);
  }

  return Object.freeze({
    root: bytesToHex(levels[levels.length - 1][0]),
    recipients: Object.freeze(keys.slice()),
    leafCount: levels[0].length,
    depth,
    levels
  });
}

/*
 * Generate the canonical membership proof for one recipient.
 * Returns { recipient, root, siblingsHex, pathBits, depth }:
 *   siblingsHex — depth * 32 bytes, leaf-to-root sibling order;
 *   pathBits    — BigInt; bit i set <=> node is the RIGHT child at level i.
 * Fails closed if the recipient is not in the tree.
 */
function generateRecipientProof(tree, recipientXOnlyHex) {
  const key = normalizeXOnlyPubkey(recipientXOnlyHex, "recipient");
  const index = tree.recipients.indexOf(key);
  if (index < 0) {
    fail(`recipient ${key} is not in this tree — refusing to fabricate a proof`);
  }
  let idx = index;
  const siblings = [];
  let pathBits = 0n;
  for (let levelIdx = 0; levelIdx < tree.depth; levelIdx++) {
    const level = tree.levels[levelIdx];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(level[siblingIdx]);
    if (idx % 2 === 1) {
      pathBits |= 1n << BigInt(levelIdx);
    }
    idx = Math.floor(idx / 2);
  }
  return Object.freeze({
    recipient: key,
    root: tree.root,
    siblingsHex: bytesToHex(concatBytes(siblings)),
    pathBits,
    depth: tree.depth
  });
}

/*
 * SDK-side proof verification: the exact covenant walk. This is a local
 * pre-check ONLY — the production covenant remains the authority. Returns
 * true/false for well-formed inputs; throws on malformed inputs (odd hex,
 * bad widths, depth > 16, pathBits out of range) exactly where the
 * covenant would abort.
 */
function verifyRecipientProof({ root, recipient, siblingsHex, pathBits }) {
  const rootHex = normalizeXOnlyPubkey(root, "root"); // 32-byte hex, same shape rule
  const key = normalizeXOnlyPubkey(recipient, "recipient");
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) {
    fail("siblingsHex must be lowercase hex");
  }
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) {
    fail("siblings length must be a multiple of 32 bytes");
  }
  if (siblings.length > 32 * MAX_DEPTH) {
    fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${MAX_DEPTH}`);
  }
  const depth = siblings.length / 32;
  let bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= 65536n) {
    fail("pathBits out of range [0, 65536)");
  }
  let node = sha256(concatBytes([LEAF_DOMAIN, hexToBytes(key)]));
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    if (bits % 2n === 1n) {
      node = sha256(concatBytes([sib, node]));
    } else {
      node = sha256(concatBytes([node, sib]));
    }
    bits /= 2n;
  }
  if (bits !== 0n) {
    return false; // excess path bits — the covenant requires bits == 0
  }
  return bytesToHex(node) === rootHex;
}

module.exports = {
  MAX_DEPTH,
  MAX_RECIPIENTS,
  LEAF_DOMAIN,
  leafHash,
  buildRecipientTree,
  generateRecipientProof,
  verifyRecipientProof
};
  });

  define("core/model/agent-merkle-v4", function (module, exports, require) {
"use strict";

/*
 * PolicyVault v0.4 canonical agent-policy Merkle tree / proof SDK
 * (Checkpoint E §E1).
 *
 * This is the ONE tree builder + proof generator + verifier for the v0.4
 * agent authenticated set (docs/covenant-spec-v0.4.md §2/§3 — FROZEN ABI).
 * The production covenant is the authority; this module must produce
 * exactly the bytes the PRODUCTION covenant accepts (proven by
 * tests/vm/tests/v4_sdk_integration.rs, which drives SDK-generated proofs
 * through the real pv_call_encoder binary and the production
 * PolicyVault.v0.4.sil on the real TxScriptEngine).
 *
 * Canonical construction (frozen, byte-exact):
 *   leaf  = SHA256(0x50 0x56 0x34 0x01 || agentPk
 *                  || num8(maxPerSpend)      || num8(periodBudget)
 *                  || num8(periodLengthDaa)  || num8(periodStartDaa)
 *                  || num8(periodSpent)      || num8(approvalThreshold)
 *                  || num8(agentMaxFeePerTx) || agentRecipientRoot)
 *           (124-byte preimage; the covenant ALWAYS recomputes the leaf
 *            from typed call arguments, never accepts a preformed leaf)
 *   num8(v) = 8-byte little-endian (consensus OpNum2Bin(v,8) /
 *            serialize_i64 — injective over 0 <= v < 2^63; this module's
 *            numeric domain [0, MAX_SOMPI] sits strictly inside it)
 *   node  = SHA256(left || right)   (64-byte preimage — cannot collide
 *            with the 124-byte agent-leaf or 36-byte recipient-leaf
 *            preimages: three distinct lengths)
 *   depth <= 12 (siblings.length <= 384 and a multiple of 32; pathBits in
 *            [0, 4096) and fully consumed after the walk)
 *
 * Determinism / identity rules:
 *   - the agent x-only key is the UNIQUE identity inside one tree: two
 *     leaves with the same agentPk are REJECTED (they would be two
 *     independent budget lanes for one key — a policy-dilution hole);
 *   - real agent leaves are sorted ascending by agentPk (fixed-width
 *     lowercase hex sorts identically to byte order), so one logical
 *     agent set has exactly ONE root regardless of caller insertion order;
 *   - the leaf level is padded to the next power of two with the
 *     STRUCTURALLY UNSPENDABLE padding leaf (below) — never by
 *     duplicating a real leaf;
 *   - an EMPTY agent set is allowed and canonical: root = the padding
 *     leaf itself (depth 0). No agent can ever spend from it; the owner
 *     uses it to suspend all agent activity via ownerSetAgentRoot.
 *
 * SECURITY — WHY DUPLICATE-LAST PADDING IS FORBIDDEN HERE (Checkpoint E
 * finding). The v0.3 RECIPIENT tree pads by duplicating the last leaf,
 * which is benign there because recipient trees are static membership
 * sets. The v0.4 AGENT tree is DYNAMIC: every agentSpend advances the
 * target leaf's period accounting in place (single-leaf Merkle update).
 * If the last real agent's leaf were duplicated as padding, EACH padded
 * copy would itself be a valid, spendable member of the same root
 * carrying an independent copy of that agent's period accounting — one
 * extra full periodBudget lane per copy, consensus-accepted (verified
 * hostile on the real VM: v4_sdk_integration.rs
 * `v4_sdk_duplicate_padding_budget_lane_is_real_and_padding_is_unspendable`).
 * Padding therefore uses a constant leaf that can never satisfy
 * membership for ANY typed agent-policy preimage:
 *
 *   PADDING_LEAF = SHA256(0x50 0x56 0x34 0x00)
 *
 * (4-byte domain-separated preimage, recordType 0 = padding). Spending
 * through a padding slot would require exhibiting 124-byte agent-policy
 * arguments whose SHA256 equals PADDING_LEAF — a SHA-256 preimage.
 *
 * pathBits convention (exactly the covenant's): bit i (LSB-first) is 1
 * when the running node is the RIGHT child at level i, i.e. the sibling
 * is hashed on the LEFT: node = SHA256(sib || node).
 *
 * All identities are 32-byte x-only pubkeys (lowercase hex). Wallet
 * addresses must be resolved through the shared address-identity boundary
 * (sdk/src/address-identity.js) BEFORE reaching this module.
 *
 * BROWSER-PORTABLE (F1 byte-native refactor): all byte plumbing is
 * Uint8Array-native — no Buffer dependency — so this module runs
 * byte-identically in Node and inside the browser core bundle
 * (web/core-bundle.js crypto shim: update(<Uint8Array>) / digest()).
 * Byte identity with the pre-refactor Buffer implementation is pinned by
 * core/model/test/golden-f1-merkle.test.js (fixture captured from the
 * ORIGINAL code). In Node, hash outputs (agentLeafHash, tree levels) are
 * the node:crypto digest objects (Buffer IS a Uint8Array) exactly as
 * before; foldLeafV4 accepts any 32-byte Uint8Array (a Buffer still
 * qualifies — its reject message text is kept verbatim from the frozen
 * behavior fixture).
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey, normalizeHex } = require("./vault-state");

const AGENT_LEAF_DOMAIN = Uint8Array.of(0x50, 0x56, 0x34, 0x01);
const AGENT_PADDING_DOMAIN = Uint8Array.of(0x50, 0x56, 0x34, 0x00);
const MAX_AGENT_DEPTH = 12;
const MAX_AGENTS = 1 << MAX_AGENT_DEPTH; // 4,096

function fail(message, code) {
  const error = new Error(`agent-merkle-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

/* ---- portable byte helpers (inputs validated upstream) ---- */

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

const PADDING_LEAF = sha256(AGENT_PADDING_DOMAIN);
const PADDING_LEAF_HEX = bytesToHex(PADDING_LEAF);

/* Consensus-canonical num8: 8-byte little-endian, injective over the
 * module's whole numeric domain (0 <= v <= MAX_SOMPI < 2^63). */
function num8(value, field) {
  const v = parseSompi(value, field);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

/*
 * Normalize one agent policy (the full frozen leaf tuple). Strict
 * fail-closed validation; every quantity BigInt. periodSpent above
 * periodBudget is structurally representable (it simply cannot spend
 * until rollover) and is NOT rejected here — the covenant is the
 * authority on spendability, this module on byte shape.
 */
function normalizeAgentPolicyV4(input) {
  if (!input || typeof input !== "object") {
    fail("agent policy object is required");
  }
  return Object.freeze({
    agentPk: normalizeXOnlyPubkey(input.agentPk, "agentPolicy.agentPk"),
    maxPerSpend: parsePositiveSompi(input.maxPerSpend, "agentPolicy.maxPerSpend"),
    periodBudget: parsePositiveSompi(input.periodBudget, "agentPolicy.periodBudget"),
    periodLengthDaa: parsePositiveSompi(input.periodLengthDaa, "agentPolicy.periodLengthDaa"),
    periodStartDaa: parseSompi(input.periodStartDaa, "agentPolicy.periodStartDaa"),
    periodSpent: parseSompi(input.periodSpent, "agentPolicy.periodSpent"),
    approvalThreshold: parseSompi(input.approvalThreshold, "agentPolicy.approvalThreshold"),
    agentMaxFeePerTx: parseSompi(input.agentMaxFeePerTx, "agentPolicy.agentMaxFeePerTx"),
    agentRecipientRoot: normalizeHex(input.agentRecipientRoot, 32, "agentPolicy.agentRecipientRoot")
  });
}

/* The exact frozen 124-byte leaf preimage. */
function agentLeafPreimage(policyInput) {
  const p = normalizeAgentPolicyV4(policyInput);
  const preimage = concatBytes([
    AGENT_LEAF_DOMAIN,
    hexToBytes(p.agentPk),
    num8(p.maxPerSpend, "maxPerSpend"),
    num8(p.periodBudget, "periodBudget"),
    num8(p.periodLengthDaa, "periodLengthDaa"),
    num8(p.periodStartDaa, "periodStartDaa"),
    num8(p.periodSpent, "periodSpent"),
    num8(p.approvalThreshold, "approvalThreshold"),
    num8(p.agentMaxFeePerTx, "agentMaxFeePerTx"),
    hexToBytes(p.agentRecipientRoot)
  ]);
  if (preimage.length !== 124) {
    fail(`internal: agent-leaf preimage is ${preimage.length} bytes, not 124`);
  }
  return preimage;
}

/* Canonical agent-leaf hash (32 bytes). */
function agentLeafHash(policyInput) {
  return sha256(agentLeafPreimage(policyInput));
}

/*
 * Build the canonical agent tree from an array of agent policies
 * (0..4096 entries). Returns a frozen object:
 *   { root, agents, realCount, leafCount, depth, levels }
 * where `agents` is the sorted (by agentPk) normalized policy list,
 * `leafCount` includes unspendable padding, and `levels` holds the raw
 * byte levels for proof generation.
 */
function buildAgentTreeV4(agentsInput) {
  if (!Array.isArray(agentsInput)) {
    fail("agents must be an array of agent-policy objects (may be empty)");
  }
  const agents = agentsInput.map((a, i) => {
    try {
      return normalizeAgentPolicyV4(a);
    } catch (error) {
      fail(`agents[${i}]: ${error.message}`);
    }
  });
  const seen = new Set();
  for (const a of agents) {
    if (seen.has(a.agentPk)) {
      fail(`duplicate agentPk ${a.agentPk} — one key may hold exactly one policy leaf (duplicate leaves would be independent budget lanes)`, "DUPLICATE_AGENT");
    }
    seen.add(a.agentPk);
  }
  if (agents.length > MAX_AGENTS) {
    fail(`agent count ${agents.length} exceeds the maximum ${MAX_AGENTS} (depth ${MAX_AGENT_DEPTH})`);
  }
  agents.sort((x, y) => (x.agentPk < y.agentPk ? -1 : x.agentPk > y.agentPk ? 1 : 0));

  /* Leaf level: real leaves then UNSPENDABLE padding to the next power of
   * two (see the module header for why duplicate-last is forbidden). */
  let level = agents.map((a) => agentLeafHash(a));
  if (level.length === 0) {
    level = [PADDING_LEAF];
  }
  while ((level.length & (level.length - 1)) !== 0) {
    level.push(PADDING_LEAF);
  }
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(concatBytes([level[i], level[i + 1]])));
    }
    levels.push(next);
    level = next;
  }

  const depth = levels.length - 1;
  if (depth > MAX_AGENT_DEPTH) {
    fail(`tree depth ${depth} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  }

  return Object.freeze({
    root: bytesToHex(levels[levels.length - 1][0]),
    agents: Object.freeze(agents),
    realCount: agents.length,
    leafCount: levels[0].length,
    depth,
    levels
  });
}

function agentIndex(tree, agentPkHex, label) {
  const key = normalizeXOnlyPubkey(agentPkHex, label ?? "agentPk");
  const index = tree.agents.findIndex((a) => a.agentPk === key);
  return { key, index };
}

/*
 * Generate the canonical membership proof for one agent. Returns
 * { agentPk, policy, root, siblingsHex, pathBits, depth }:
 *   siblingsHex — depth * 32 bytes, leaf-to-root sibling order;
 *   pathBits    — BigInt; bit i set <=> node is the RIGHT child at level i.
 * Fails closed if the agent is not in the tree (padding slots are not
 * agents and can never be proven).
 */
function generateAgentProofV4(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — refusing to fabricate a proof`);
  }
  let idx = index;
  const siblings = [];
  let pathBits = 0n;
  for (let levelIdx = 0; levelIdx < tree.depth; levelIdx++) {
    const level = tree.levels[levelIdx];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(level[siblingIdx]);
    if (idx % 2 === 1) {
      pathBits |= 1n << BigInt(levelIdx);
    }
    idx = Math.floor(idx / 2);
  }
  return Object.freeze({
    agentPk: key,
    policy: tree.agents[index],
    root: tree.root,
    siblingsHex: bytesToHex(concatBytes(siblings)),
    pathBits,
    depth: tree.depth
  });
}

function normalizeSiblings(siblingsHex) {
  if (typeof siblingsHex !== "string" || !/^[0-9a-f]*$/.test(siblingsHex) || siblingsHex.length % 2 !== 0) {
    fail("siblingsHex must be lowercase hex");
  }
  const siblings = hexToBytes(siblingsHex);
  if (siblings.length % 32 !== 0) {
    fail("siblings length must be a multiple of 32 bytes");
  }
  if (siblings.length > 32 * MAX_AGENT_DEPTH) {
    fail(`proof depth ${siblings.length / 32} exceeds the covenant maximum ${MAX_AGENT_DEPTH}`);
  }
  return siblings;
}

function normalizePathBits(pathBits) {
  const bits = typeof pathBits === "bigint" ? pathBits : BigInt(pathBits);
  if (bits < 0n || bits >= BigInt(MAX_AGENTS)) {
    fail(`pathBits out of range [0, ${MAX_AGENTS})`);
  }
  return bits;
}

/*
 * Fold a leaf hash up a co-path — the exact covenant computeMerkleRoot
 * walk. Throws on malformed inputs exactly where the covenant would
 * abort; returns null when pathBits are not fully consumed (the covenant
 * requires bits == 0 after the walk).
 */
function foldLeafV4(leafBuffer, siblingsHex, pathBits) {
  if (!(leafBuffer instanceof Uint8Array) || leafBuffer.length !== 32) {
    fail("leaf must be a 32-byte Buffer");
  }
  const siblings = normalizeSiblings(siblingsHex);
  let bits = normalizePathBits(pathBits);
  const depth = siblings.length / 32;
  let node = leafBuffer;
  for (let level = 0; level < depth; level++) {
    const sib = siblings.subarray(level * 32, level * 32 + 32);
    if (bits % 2n === 1n) {
      node = sha256(concatBytes([sib, node]));
    } else {
      node = sha256(concatBytes([node, sib]));
    }
    bits /= 2n;
  }
  if (bits !== 0n) {
    return null; // excess path bits — the covenant rejects
  }
  return bytesToHex(node);
}

/* Fold a full agent policy up a co-path (successor-root derivation). */
function foldAgentPolicyV4(policyInput, siblingsHex, pathBits) {
  return foldLeafV4(agentLeafHash(policyInput), siblingsHex, pathBits);
}

/*
 * SDK-side proof verification: the exact covenant walk over the leaf
 * recomputed from the full policy. Local pre-check ONLY — the production
 * covenant remains the authority. Returns true/false for well-formed
 * inputs; throws on malformed inputs (odd hex, bad widths, depth > 12,
 * pathBits out of range) exactly where the covenant would abort.
 */
function verifyAgentProofV4({ root, policy, siblingsHex, pathBits }) {
  const rootHex = normalizeHex(root, 32, "root");
  const computed = foldAgentPolicyV4(policy, siblingsHex, pathBits);
  return computed !== null && computed === rootHex;
}

/* ---------------- canonical tree edits (owner lifecycle) ----------------
 * ownerSetAgentRoot replaces the committed root wholesale, so every edit
 * is a canonical REBUILD of the modified agent set: deterministic,
 * insertion-order-free, and re-validated from scratch. Each returns a NEW
 * tree; the input tree is never mutated. */

function addAgentV4(tree, policyInput) {
  const policy = normalizeAgentPolicyV4(policyInput);
  const { index } = agentIndex(tree, policy.agentPk, "new agentPk");
  if (index >= 0) {
    fail(`agent ${policy.agentPk} already exists — use updateAgentPolicyV4/rotateAgentV4`, "DUPLICATE_AGENT");
  }
  return buildAgentTreeV4([...tree.agents, policy]);
}

function removeAgentV4(tree, agentPkHex) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — nothing to remove`);
  }
  return buildAgentTreeV4(tree.agents.filter((a) => a.agentPk !== key));
}

/* Replace one agent's policy IN PLACE (same key, new limits/roots). */
function updateAgentPolicyV4(tree, policyInput) {
  const policy = normalizeAgentPolicyV4(policyInput);
  const { index } = agentIndex(tree, policy.agentPk, "agentPk");
  if (index < 0) {
    fail(`agent ${policy.agentPk} is not in this tree — use addAgentV4`);
  }
  return buildAgentTreeV4(tree.agents.map((a) => (a.agentPk === policy.agentPk ? policy : a)));
}

/* Rotate an agent key: remove the old key's leaf, add the full new
 * policy under the new key (the caller decides whether accounting resets
 * — a rotation is a NEW leaf, so it carries whatever the new policy
 * states; there is no implicit carry-over). */
function rotateAgentV4(tree, currentPkHex, newPolicyInput) {
  const { key, index } = agentIndex(tree, currentPkHex, "currentPk");
  if (index < 0) {
    fail(`agent ${key} is not in this tree — cannot rotate`);
  }
  const newPolicy = normalizeAgentPolicyV4(newPolicyInput);
  if (newPolicy.agentPk === key) {
    fail("rotation requires a NEW agent key — use updateAgentPolicyV4 to re-policy the same key");
  }
  const without = tree.agents.filter((a) => a.agentPk !== key);
  return buildAgentTreeV4([...without, newPolicy]);
}

/*
 * Apply an agentSpend accounting advance to the tree: ONLY the spending
 * agent's periodStartDaa/periodSpent change; every other leaf (and all
 * padding) is untouched. Returns { tree, previousPolicy, newPolicy }.
 *
 * INVARIANT (asserted, fail-closed): with unspendable padding the
 * canonical rebuild of the updated set equals the covenant's single-leaf
 * fold of the new leaf up the old co-path — i.e. the SDK's successor
 * tree is byte-identical to the successor root consensus enforces.
 */
function applyAgentSpendV4(tree, agentPkHex, { newPeriodStartDaa, newPeriodSpent }) {
  const { key, index } = agentIndex(tree, agentPkHex);
  if (index < 0) {
    fail(`agent ${key} is not in this tree — cannot advance accounting`);
  }
  const previousPolicy = tree.agents[index];
  const newPolicy = normalizeAgentPolicyV4({
    ...previousPolicy,
    periodStartDaa: parseSompi(newPeriodStartDaa, "newPeriodStartDaa"),
    periodSpent: parseSompi(newPeriodSpent, "newPeriodSpent")
  });
  const proof = generateAgentProofV4(tree, key);
  const foldedRoot = foldAgentPolicyV4(newPolicy, proof.siblingsHex, proof.pathBits);
  const rebuilt = buildAgentTreeV4(tree.agents.map((a) => (a.agentPk === key ? newPolicy : a)));
  if (rebuilt.root !== foldedRoot) {
    fail(
      `internal invariant violated: canonical rebuild root ${rebuilt.root} != single-leaf fold root ${foldedRoot} — refusing to emit a successor tree that disagrees with consensus`
    );
  }
  return Object.freeze({ tree: rebuilt, previousPolicy, newPolicy });
}

module.exports = {
  AGENT_LEAF_DOMAIN,
  AGENT_PADDING_DOMAIN,
  PADDING_LEAF_HEX,
  MAX_AGENT_DEPTH,
  MAX_AGENTS,
  normalizeAgentPolicyV4,
  agentLeafPreimage,
  agentLeafHash,
  buildAgentTreeV4,
  generateAgentProofV4,
  verifyAgentProofV4,
  foldLeafV4,
  foldAgentPolicyV4,
  addAgentV4,
  removeAgentV4,
  updateAgentPolicyV4,
  rotateAgentV4,
  applyAgentSpendV4
};
  });

  define("core/model/compute-budget-v3", function (module, exports, require) {
"use strict";

/*
 * Centralized v0.3 covenant compute-budget selection (Phase 4H §14).
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. The values below are PROVEN-SAFE tiers backed
 * by direct measurement of the PRODUCTION covenant under production
 * sig-op pricing (Gram(1000) = 100,000 script units per checkSig;
 * tests/vm/tests/v3_encoder_integration.rs enc3_measure_* and the Phase
 * 4H SDK-shape proofs in v3_sdk_integration.rs):
 *
 *   delegate spend, depth 0,  no approvals:   282,320 units -> budget 29
 *   delegate spend, depth 16, no approvals:   305,505 units -> budget 31
 *   approved spend, 2-of-3 (depth 8):         609,529 units -> budget 61
 *   approved spend, 10-of-10 (depth 8):     1,334,175 units -> budget 134
 *   WORST: depth 16 + 10-of-10:             1,349,839 units -> budget 135
 *   owner op (incl. setApprovers):          ~231k-286k     -> budget 29
 *   ownerRecover (terminal):                  157,203 units -> budget 16
 *
 * Tier policy (documented conservative proven-safe, §14): commit the tier
 * ceiling rather than a per-shape estimate. This is FEE-NEUTRAL for every
 * v0.3 shape because v0.3 fees are transient-mass-dominated (the ~28 KB
 * redeem script sets the fee; compute mass at budget 135 is 13,500 grams,
 * far below the ~60k normalized transient mass — asserted by tests), and
 * it removes all under-commit risk from shape-estimation drift.
 *
 * Callers may NEVER lower the committed budget below the tier value.
 */

const V3_BUDGET = Object.freeze({
  /* Any spend at or below approvalThresholdAmount, any Merkle depth 0..16
   * (proven ceiling: depth 16 = 305,505 units -> 31). */
  SPEND_DELEGATE_ONLY: 31,
  /* Any spend above approvalThresholdAmount, any depth, any approver
   * configuration up to 10-of-10 (proven ceiling: depth16 + 10-of-10 =
   * 1,349,839 units -> 135). */
  SPEND_WITH_APPROVALS: 135,
  /* Every owner state transition (pause/unpause/revoke/rotate/topUp/
   * migrate/setRecipientRoot/setApprovers). */
  OWNER_OP: 29,
  /* Terminal ownerRecover. */
  RECOVER: 16,
  /* Ordinary (non-covenant) fee/fuel inputs. */
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v3: ${message}`);
}

/*
 * Select the committed covenant-input compute budget for a v0.3 operation.
 *   operation: one of the 11 production entrypoint names or "createVault".
 *   aboveThreshold: REQUIRED for spend operations (payAmount >
 *   approvalThresholdAmount on the PREDECESSOR state).
 * Unknown operations fail closed.
 */
function selectComputeBudgetV3({ operation, aboveThreshold }) {
  switch (operation) {
    case "delegateSpend":
    case "rolloverAndSpend":
      if (typeof aboveThreshold !== "boolean") {
        fail(`${operation} budget selection requires aboveThreshold (boolean)`);
      }
      return aboveThreshold ? V3_BUDGET.SPEND_WITH_APPROVALS : V3_BUDGET.SPEND_DELEGATE_ONLY;
    case "ownerPause":
    case "ownerUnpause":
    case "revokeDelegate":
    case "rotateDelegate":
    case "ownerTopUp":
    case "migratePolicy":
    case "ownerSetRecipientRoot":
    case "ownerSetApprovers":
      return V3_BUDGET.OWNER_OP;
    case "ownerRecover":
      return V3_BUDGET.RECOVER;
    default:
      fail(`unknown v0.3 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/* Reject any attempt to commit less than the proven tier value. */
function assertBudgetSufficient({ operation, aboveThreshold, committed }) {
  const required = selectComputeBudgetV3({ operation, aboveThreshold });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = { V3_BUDGET, selectComputeBudgetV3, assertBudgetSufficient };
  });

  define("core/model/compute-budget-v4", function (module, exports, require) {
"use strict";

/*
 * Centralized v0.4 covenant compute-budget selection (Checkpoint E §E5).
 *
 * The committed budget is CONSENSUS-CRITICAL for usability: an
 * under-committed budget makes an otherwise-valid transaction fail script
 * execution on a live node. The values below are PROVEN-SAFE tiers backed
 * by direct measurement of the PRODUCTION v0.4 covenant under production
 * sig-op pricing (Gram(1000) = 100,000 script units per checkSig;
 * tests/vm/tests/v4_production.rs v4p_measure_production_budgets,
 * re-verified at Checkpoint D, and the Checkpoint-E SDK-shape proofs in
 * v4_sdk_integration.rs):
 *
 *   agent spend, agent depth 0,  recip depth 0,  below threshold:
 *                                              222,758 units -> budget 23
 *   agent spend, agent depth 12, recip depth 0, below threshold:
 *                                              251,768 units -> budget 26
 *   agent spend, agent depth 0,  recip depth 16, below threshold:
 *                                              245,943 units -> budget 25
 *   WORST: agent depth 12 + recip depth 16 + 10-of-10 + reserve:
 *                                            1,318,131 units -> budget 132
 *   ownerSetAgentRoot:                         219,115 units -> budget 22
 *   ownerRecover (terminal):                   137,927 units -> budget 14
 *
 * Tier policy (same documented conservative proven-safe scheme as v0.3):
 * commit the tier CEILING rather than a per-shape estimate, with explicit
 * headroom above the measured points for the shape dimensions the
 * measurements did not enumerate (combined agent+recipient depth below
 * threshold; extra external fee inputs/outputs adding txFee() loop
 * iterations; ownerSetApprovers' 45-pair distinctness block, which the
 * owner-op measurement above does not include). This is FEE-NEUTRAL for
 * every v0.4 shape because v0.4 fees are transient-mass-dominated: the
 * ~19-21 KB redeem script sets the fee (normalized transient ~40k grams),
 * while compute mass even at budget 134 is 13,400 grams — asserted by the
 * fee golden vectors. Over-commit costs nothing; under-commit strands a
 * valid transaction. The production-byte integration suite executes every
 * SDK-built accept vector under PRODUCTION pricing with the SDK's OWN
 * committed budget and asserts sufficiency per exact shape.
 *
 * Callers may NEVER lower the committed budget below the tier value.
 */

const V4_BUDGET = Object.freeze({
  /* Any agent spend at or below the leaf's approvalThreshold, any agent
   * depth 0..12, any recipient depth 0..16 (measured single-dimension
   * ceilings 23/26/25; combined-depth additive bound ~28; headroom to 32,
   * VM-asserted at agent depth 12 + recipient depth 16). */
  SPEND_NO_APPROVALS: 32,
  /* Any agent spend above the leaf's approvalThreshold, any depths, any
   * approver configuration up to 10-of-10 (measured worst 1,318,131 units
   * -> 132 for the 1-input/2-output shape; +2 headroom for external
   * fee-input/change txFee() iterations). */
  SPEND_WITH_APPROVALS: 134,
  /* Every owner state transition (setAgentRoot/setApprovers/topUp/
   * topUpReserve/pause/unpause). setAgentRoot measured 22; setApprovers
   * adds the 45-pair distinctness + active-count block (v0.3's analogous
   * op measured ~286k -> 29 on a LARGER script); 30 covers it,
   * VM-asserted per shape. */
  OWNER_OP: 30,
  /* Terminal ownerRecover (measured 137,927 -> 14; +1 headroom). */
  RECOVER: 15,
  /* Ordinary (non-covenant) fee/fuel inputs. */
  ORDINARY_INPUT: 10
});

function fail(message) {
  throw new Error(`compute-budget-v4: ${message}`);
}

/*
 * Select the committed covenant-input compute budget for a v0.4 operation.
 *   operation: one of the 8 production entrypoint names.
 *   aboveThreshold: REQUIRED for agentSpend (payAmount > the spending
 *   agent LEAF's approvalThreshold).
 * Unknown operations fail closed.
 */
function selectComputeBudgetV4({ operation, aboveThreshold }) {
  switch (operation) {
    case "agentSpend":
      if (typeof aboveThreshold !== "boolean") {
        fail("agentSpend budget selection requires aboveThreshold (boolean)");
      }
      return aboveThreshold ? V4_BUDGET.SPEND_WITH_APPROVALS : V4_BUDGET.SPEND_NO_APPROVALS;
    case "ownerSetAgentRoot":
    case "ownerSetApprovers":
    case "ownerTopUp":
    case "ownerTopUpReserve":
    case "ownerPause":
    case "ownerUnpause":
      return V4_BUDGET.OWNER_OP;
    case "ownerRecover":
      return V4_BUDGET.RECOVER;
    default:
      fail(`unknown v0.4 operation ${JSON.stringify(operation)} — failing closed`);
  }
}

/* Reject any attempt to commit less than the proven tier value. */
function assertBudgetSufficientV4({ operation, aboveThreshold, committed }) {
  const required = selectComputeBudgetV4({ operation, aboveThreshold });
  if (!Number.isInteger(committed) || committed < required) {
    fail(`committed compute budget ${committed} is below the proven-safe minimum ${required} for ${operation}`);
  }
  return committed;
}

module.exports = { V4_BUDGET, selectComputeBudgetV4, assertBudgetSufficientV4 };
  });

  define("core/model/fee-mass", function (module, exports, require) {
"use strict";

/*
 * Authoritative Toccata transaction-v1 fee/mass accounting for PolicyVault.
 *
 * Source-backed reimplementation of rusty-kaspa's mass and minimum-relay-fee
 * rules (see docs/fee-mass-spec.md for the exact source citations). The WASM
 * helpers undercount covenant + v1 transactions, so funds paths use this
 * module instead and never trust the WASM recalculators.
 *
 * All arithmetic is BigInt. No floating point on the fee path (the single
 * rational cofactor is applied exactly as an integer ratio). Fails closed.
 */

// --- consensus constants (rusty-kaspa v2.0.1, testnet-10) ---
const MASS_PER_TX_BYTE = 1n;
const MASS_PER_SCRIPT_PUB_KEY_BYTE = 10n;
const GRAMS_PER_COMPUTE_BUDGET_UNIT = 100n;
const TRANSIENT_BYTE_TO_MASS_FACTOR = 4n;
const MINIMUM_RELAY_TRANSACTION_FEE = 100_000n; // sompi/kg
const RELAY_FEE_DIVISOR = 1000n;

// Post-Toccata block mass limits → transient cofactor = compute/transient.
const BLOCK_COMPUTE_LIMIT = 500_000n;
const BLOCK_TRANSIENT_LIMIT = 1_000_000n;
const STANDARD_MASS_CAP = 500_000n;

// Serialized-size fixed widths.
const OUTPOINT_SIZE = 36n; // 32 txid + 4 index
const SUBNETWORK_ID_SIZE = 20n;
const HASH_SIZE = 32n;

function fail(message) {
  throw new Error(`fee-mass: ${message}`);
}

function ceilDiv(a, b) {
  return (a + b - 1n) / b;
}

function hexLen(hex) {
  if (hex === undefined || hex === null || hex === "") {
    return 0n;
  }
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    fail(`expected an even-length hex string, got ${JSON.stringify(hex).slice(0, 40)}`);
  }
  return BigInt(hex.length / 2);
}

/*
 * A minimal transaction shape descriptor, read from a WASM Transaction or
 * built directly:
 *   { version, inputs: [{ signatureScriptHex, computeBudget }],
 *     outputs: [{ scriptHex, hasCovenant }], payloadHex }
 */
function estimatedSerializedSize(tx) {
  if (tx.version < 1) {
    fail("this module is for transaction version >= 1 (Toccata)");
  }
  let size = 2n; // version u16
  size += 8n; // input count u64
  for (const input of tx.inputs) {
    size += OUTPOINT_SIZE;
    size += 8n + hexLen(input.signatureScriptHex); // sig-script len prefix + bytes
    size += 8n; // sequence u64
    size += 2n; // compute_budget u16 (v >= 1)
  }
  size += 8n; // output count u64
  for (const output of tx.outputs) {
    size += 8n; // value u64
    size += 2n; // spk version u16
    size += 8n + hexLen(output.scriptHex); // spk len prefix + bytes
    if (output.hasCovenant) {
      size += 2n + HASH_SIZE; // authorizing_input u16 + covenant_id
    }
  }
  size += 8n; // lock time u64
  size += SUBNETWORK_ID_SIZE;
  size += 8n; // gas u64
  size += HASH_SIZE; // payload hash
  size += 8n + hexLen(tx.payloadHex); // payload len prefix + bytes
  return size;
}

function computeMass(tx) {
  const size = estimatedSerializedSize(tx);
  const sizeMass = size * MASS_PER_TX_BYTE;

  let totalSpkSize = 0n;
  for (const output of tx.outputs) {
    totalSpkSize += 2n + hexLen(output.scriptHex); // spk version u16 + script bytes
  }
  const spkMass = totalSpkSize * MASS_PER_SCRIPT_PUB_KEY_BYTE;

  let totalComputeBudget = 0n;
  for (const input of tx.inputs) {
    if (input.computeBudget === undefined || input.computeBudget === null) {
      fail("v1 input is missing computeBudget");
    }
    totalComputeBudget += BigInt(input.computeBudget);
  }
  const scriptMass = totalComputeBudget * GRAMS_PER_COMPUTE_BUDGET_UNIT;

  return { size, computeMass: sizeMass + spkMass + scriptMass };
}

/*
 * fee_mass = max(compute_mass, normalized_transient), where
 * normalized_transient = ceil(transient_mass * (L_compute / L_transient)).
 * Applied as an exact integer ratio (no floats).
 */
function feeMass(tx) {
  const { size, computeMass: cm } = computeMass(tx);
  const transientMass = size * TRANSIENT_BYTE_TO_MASS_FACTOR;
  const normalizedTransient = ceilDiv(transientMass * BLOCK_COMPUTE_LIMIT, BLOCK_TRANSIENT_LIMIT);
  const fm = cm > normalizedTransient ? cm : normalizedTransient;
  return { size, computeMass: cm, transientMass, normalizedTransient, feeMass: fm };
}

/*
 * The exact minimum consensus relay fee, in sompi:
 *   minimum_fee = (fee_mass * MINIMUM_RELAY_TRANSACTION_FEE) / 1000
 * with the node's `if minimum_fee == 0 { minimum_fee = relay_fee }` floor.
 */
function calculateRequiredFee(tx) {
  const m = feeMass(tx);
  if (m.feeMass > STANDARD_MASS_CAP) {
    fail(`fee_mass ${m.feeMass} exceeds the standard mass cap ${STANDARD_MASS_CAP}`);
  }
  let minimumFee = (m.feeMass * MINIMUM_RELAY_TRANSACTION_FEE) / RELAY_FEE_DIVISOR;
  if (minimumFee === 0n) {
    minimumFee = MINIMUM_RELAY_TRANSACTION_FEE;
  }
  return { ...m, minimumRequiredFee: minimumFee };
}

/*
 * Read a WASM Transaction object into the descriptor this module needs.
 * Reads only structural fields; never trusts WASM mass/fee helpers.
 */
function describeWasmTransaction(transaction) {
  return {
    version: Number(transaction.version),
    payloadHex: transaction.payload || "",
    inputs: transaction.inputs.map((input) => ({
      signatureScriptHex: input.signatureScript || "",
      computeBudget: input.computeBudget
    })),
    outputs: transaction.outputs.map((output) => {
      const spk = output.scriptPublicKey;
      const scriptHex = typeof spk === "string" ? spk : spk.script;
      return { scriptHex, hasCovenant: output.covenant !== undefined && output.covenant !== null };
    })
  };
}

/*
 * Validate a covenant-input compute budget against the expected value
 * (PolicyVault uses 100 for the covenant input, 10 for ordinary inputs).
 */
function validateComputeBudget(value, expected, label) {
  if (Number(value) !== Number(expected)) {
    fail(`${label} compute budget is ${value}, expected ${expected}`);
  }
}

/*
 * Finalize a covenant-spending transaction with the EXACT minimum fee plus
 * an optional, clearly-separated relay margin.
 *
 * Convergence: signature-script lengths do not depend on output *values*
 * (Schnorr signatures are fixed-width; covenant call fields are
 * fixed-width). So we (1) fully sign with a placeholder change, (2) measure
 * the exact required fee, (3) set change = totalFuel - selectedFee,
 * (4) re-sign once, (5) assert sig-script lengths are unchanged (=> mass
 * unchanged => fee still exact) and the realized fee meets the requirement.
 * One re-sign always suffices; there is no unbounded retry loop.
 *
 * signAll(transaction) must re-attach every signature/covenant call to the
 * transaction in place and return it. changeIndex is the ordinary change
 * output whose value absorbs the fee. totalInputValue is the sum of ALL
 * input UTXO values. The fee is, by definition, totalInputs − totalOutputs;
 * only the change output moves, so the extra fee comes from ordinary fuel
 * and never from protected principal (the covenant-funded payment and
 * successor outputs are left untouched). relayMargin is an optional extra
 * fee (default 0).
 */
function finalizeWithExactFee({ transaction, signAll, changeIndex, totalInputValue, relayMargin = 0n }) {
  const totalInput = BigInt(totalInputValue);
  const margin = BigInt(relayMargin);

  signAll(transaction);
  const lengths1 = transaction.inputs.map((i) => hexLen(i.signatureScript || ""));
  const required1 = calculateRequiredFee(describeWasmTransaction(transaction)).minimumRequiredFee;

  const selectedFee = required1 + margin;
  const outputsSum = transaction.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  const nonChangeOutputs = outputsSum - BigInt(transaction.outputs[changeIndex].value);
  // fee = totalInput − (nonChangeOutputs + change)  ⇒  change = totalInput − nonChangeOutputs − fee
  const newChange = totalInput - nonChangeOutputs - selectedFee;
  if (newChange <= 0n) {
    fail(`inputs ${totalInput} cannot cover outputs ${nonChangeOutputs} + fee ${selectedFee}`);
  }

  const adjusted = transaction.outputs;
  adjusted[changeIndex].value = newChange;
  transaction.outputs = adjusted;

  signAll(transaction);
  const lengths2 = transaction.inputs.map((i) => hexLen(i.signatureScript || ""));

  // Sig-script lengths must be stable, else mass (and the fee) would drift.
  for (let i = 0; i < lengths1.length; i++) {
    if (lengths1[i] !== lengths2[i]) {
      fail(`signature-script length for input ${i} changed on re-sign (${lengths1[i]} -> ${lengths2[i]}); fee did not converge`);
    }
  }

  const required2 = calculateRequiredFee(describeWasmTransaction(transaction)).minimumRequiredFee;
  const actualFee = totalInput - transaction.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  if (required2 !== required1) {
    fail(`required fee drifted (${required1} -> ${required2})`);
  }
  if (actualFee < required2) {
    fail(`finalized fee ${actualFee} is below the required minimum ${required2}`);
  }

  return { requiredFee: required2, actualFee, change: newChange };
}

module.exports = {
  MINIMUM_RELAY_TRANSACTION_FEE,
  STANDARD_MASS_CAP,
  estimatedSerializedSize,
  computeMass,
  feeMass,
  calculateRequiredFee,
  describeWasmTransaction,
  validateComputeBudget,
  finalizeWithExactFee
};
  });

  define("core/model/frozen-tx-v3", function (module, exports, require) {
"use strict";

/*
 * Canonical FROZEN (unsigned) transaction representation for PolicyVault
 * v0.3+ approval collection (Phase 4H §7/§8) — PURE MODEL CORE.
 *
 * Shared-core extraction step 3 (interface split): this module carries the
 * deterministic members of sdk/src/frozen-tx-v3.js — normalization, the
 * canonical serialization, the local sha256 commitment, and the fee
 * descriptor. The AUTHORITATIVE consensus computations (txId, per-input
 * SIG_HASH_ALL sighash, approval-signature verification via the real
 * rusty-kaspa pv_tx_probe binary) and the WASM transaction builder are
 * IMPURE (child_process/fs/WASM) and live in sdk/src/frozen-tx-v3.js,
 * which composes this module. Member bodies are verbatim from the
 * pre-split sdk implementation.
 *
 * The frozen form is the security object approvers sign against: once a
 * transaction is frozen, every consensus/sighash-visible field is
 * immutable. It deliberately carries NO signature scripts — for
 * version-1 Kaspa transactions neither the transaction ID nor the
 * SIG_HASH_ALL sighash commits signature scripts, so signatures can be
 * collected in any order against the frozen form and the txId computed
 * from it equals the final broadcast txId
 * (source: rusty-kaspa consensus/core/src/hashing/{tx.rs,sighash.rs}).
 *
 * SIG_HASH_ALL (v1) COMMITS: tx version; every input's outpoint and
 * sequence; the signed input's spent-UTXO script + amount (which pins the
 * exact predecessor covenant state script); every output's value, script,
 * and covenant binding (authorizingInput + covenantId); lockTime;
 * subnetworkId; gas; payload; and the sighash-type byte.
 *
 * SIG_HASH_ALL (v1) DOES NOT COMMIT: signature scripts, and each input's
 * committed COMPUTE BUDGET. The budget is therefore frozen here as an
 * APPLICATION-INTEGRITY rule (covered by the canonical commitment), not a
 * consensus binding: consensus tolerates budget malleation, which can only
 * make the transaction non-viable (fee shortfall / execution abort), never
 * change where funds go.
 */

const crypto = require("crypto");

const { parseSompi } = require("./amounts");
const { normalizeHex } = require("./vault-state");

const NATIVE_SUBNETWORK = "00".repeat(20);

function fail(message) {
  throw new Error(`frozen-tx-v3: ${message}`);
}

function normalizeTxId(value, field) {
  return normalizeHex(value, 32, field);
}

function normalizeSpk(input, label) {
  if (!input || typeof input !== "object") {
    fail(`${label} must be a { version, scriptHex } object`);
  }
  const version = Number(input.version ?? 0);
  if (!Number.isInteger(version) || version < 0 || version > 0xffff) {
    fail(`${label}.version out of range`);
  }
  const scriptHex = String(input.scriptHex ?? "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(scriptHex) || scriptHex.length % 2 !== 0) {
    fail(`${label}.scriptHex must be even-length hex`);
  }
  return Object.freeze({ version, scriptHex });
}

/*
 * Normalize + deep-freeze an unsigned transaction descriptor. Fails closed
 * on anything missing, malformed, or carrying a signature script.
 */
function normalizeFrozenTxV3(input) {
  if (!input || typeof input !== "object") {
    fail("transaction descriptor is required");
  }
  if (Number(input.version) !== 1) {
    fail("frozen transactions must be version 1 (Toccata)");
  }
  if (!Array.isArray(input.inputs) || input.inputs.length === 0) {
    fail("at least one input is required");
  }
  if (!Array.isArray(input.outputs) || input.outputs.length === 0) {
    fail("at least one output is required");
  }
  const inputs = input.inputs.map((entry, i) => {
    if (entry.signatureScript !== undefined && entry.signatureScript !== "") {
      fail(`inputs[${i}] must not carry a signatureScript — the frozen form is unsigned`);
    }
    const op = entry.previousOutpoint;
    if (!op || typeof op !== "object") {
      fail(`inputs[${i}].previousOutpoint is required`);
    }
    const index = Number(op.index);
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
      fail(`inputs[${i}].previousOutpoint.index out of range`);
    }
    const computeBudget = Number(entry.computeBudget);
    if (!Number.isInteger(computeBudget) || computeBudget < 0 || computeBudget > 0xffff) {
      fail(`inputs[${i}].computeBudget out of u16 range`);
    }
    const utxo = entry.utxo;
    if (!utxo || typeof utxo !== "object") {
      fail(`inputs[${i}].utxo is required (amount + scriptPublicKey + covenantId)`);
    }
    return Object.freeze({
      previousOutpoint: Object.freeze({
        transactionId: normalizeTxId(op.transactionId, `inputs[${i}].previousOutpoint.transactionId`),
        index
      }),
      sequence: parseSompi(entry.sequence ?? 0n, `inputs[${i}].sequence`),
      computeBudget,
      utxo: Object.freeze({
        amount: parseSompi(utxo.amount, `inputs[${i}].utxo.amount`),
        scriptPublicKey: normalizeSpk(utxo.scriptPublicKey, `inputs[${i}].utxo.scriptPublicKey`),
        covenantId: utxo.covenantId == null ? null : normalizeHex(utxo.covenantId, 32, `inputs[${i}].utxo.covenantId`),
        blockDaaScore: parseSompi(utxo.blockDaaScore ?? 0n, `inputs[${i}].utxo.blockDaaScore`)
      })
    });
  });
  const outputs = input.outputs.map((entry, i) => {
    const covenant = entry.covenant == null
      ? null
      : Object.freeze({
          authorizingInput: (() => {
            const a = Number(entry.covenant.authorizingInput);
            if (!Number.isInteger(a) || a < 0 || a > 0xffff) {
              fail(`outputs[${i}].covenant.authorizingInput out of range`);
            }
            return a;
          })(),
          covenantId: normalizeHex(entry.covenant.covenantId, 32, `outputs[${i}].covenant.covenantId`)
        });
    return Object.freeze({
      value: parseSompi(entry.value, `outputs[${i}].value`),
      scriptPublicKey: normalizeSpk(entry.scriptPublicKey, `outputs[${i}].scriptPublicKey`),
      covenant
    });
  });
  const subnetworkId = String(input.subnetworkId ?? NATIVE_SUBNETWORK).toLowerCase();
  if (subnetworkId !== NATIVE_SUBNETWORK) {
    fail("frozen transactions must use the native subnetwork");
  }
  const gas = parseSompi(input.gas ?? 0n, "gas");
  if (gas !== 0n) {
    fail("frozen transactions must carry gas 0");
  }
  const payload = String(input.payload ?? "").toLowerCase();
  if (payload !== "") {
    fail("frozen transactions must carry an empty payload");
  }
  return Object.freeze({
    version: 1,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    lockTime: parseSompi(input.lockTime ?? 0n, "lockTime"),
    subnetworkId,
    gas: 0n,
    payload: ""
  });
}

/*
 * The canonical serialization: fixed field order, digit strings for every
 * 64-bit quantity. One frozen transaction has exactly one canonical JSON
 * string; the local package commitment hashes this string.
 */
function canonicalFrozenTxJson(frozen) {
  const doc = {
    version: frozen.version,
    inputs: frozen.inputs.map((i) => ({
      previousOutpoint: { transactionId: i.previousOutpoint.transactionId, index: i.previousOutpoint.index },
      sequence: i.sequence.toString(),
      computeBudget: i.computeBudget,
      utxo: {
        amount: i.utxo.amount.toString(),
        scriptPublicKey: { version: i.utxo.scriptPublicKey.version, scriptHex: i.utxo.scriptPublicKey.scriptHex },
        covenantId: i.utxo.covenantId,
        blockDaaScore: i.utxo.blockDaaScore.toString()
      }
    })),
    outputs: frozen.outputs.map((o) => ({
      value: o.value.toString(),
      scriptPublicKey: { version: o.scriptPublicKey.version, scriptHex: o.scriptPublicKey.scriptHex },
      covenant: o.covenant ? { authorizingInput: o.covenant.authorizingInput, covenantId: o.covenant.covenantId } : null
    })),
    lockTime: frozen.lockTime.toString(),
    subnetworkId: frozen.subnetworkId,
    gas: frozen.gas.toString(),
    payload: frozen.payload
  };
  return JSON.stringify(doc);
}

/* sha256 of the canonical serialization — the LOCAL integrity commitment.
 * NEVER a signing digest: approver authority is the Kaspa Schnorr
 * signature over the real transaction sighash (pv_tx_probe), only. */
function frozenTxCommitment(frozen) {
  return crypto.createHash("sha256").update(canonicalFrozenTxJson(frozen), "utf8").digest("hex");
}

/*
 * Fee/mass descriptor for the frozen transaction with the KNOWN final
 * signature-script lengths supplied per input (the frozen form itself is
 * unsigned). Feeds core/model/fee-mass.js calculateRequiredFee.
 */
function feeDescriptorFromFrozen(frozen, sigScriptLengths) {
  if (!Array.isArray(sigScriptLengths) || sigScriptLengths.length !== frozen.inputs.length) {
    fail("feeDescriptorFromFrozen needs one final sig-script length per input");
  }
  return {
    version: frozen.version,
    payloadHex: frozen.payload,
    inputs: frozen.inputs.map((input, i) => {
      const len = sigScriptLengths[i];
      if (!Number.isInteger(len) || len < 0) {
        fail(`sigScriptLengths[${i}] must be a non-negative integer`);
      }
      return { signatureScriptHex: "00".repeat(len), computeBudget: input.computeBudget };
    }),
    outputs: frozen.outputs.map((o) => ({ scriptHex: o.scriptPublicKey.scriptHex, hasCovenant: o.covenant !== null }))
  };
}

module.exports = {
  fail,
  normalizeFrozenTxV3,
  canonicalFrozenTxJson,
  frozenTxCommitment,
  feeDescriptorFromFrozen
};
  });

  define("core/model/vault-state-v4", function (module, exports, require) {
"use strict";

/*
 * Exact live-state model for a PolicyVault v0.4 vault (FROZEN ABI,
 * docs/covenant-spec-v0.4.md). Low-level normalization + exact serialization
 * only — NO transaction builders (that is a later phase, deliberately not
 * implemented in Checkpoint C).
 *
 * v0.4 identity = immutable template (owner, vaultId) + 17 mutable state
 * fields. The single v0.3 delegate and its per-delegate policy move INTO the
 * per-agent authenticated leaf (agentRoot commitment), so fixed state holds
 * only: boundVaultId, protectedValue, feeReserve, paused, agentRoot,
 * approver1..10, approvalM, policyNonce. The covenant UTXO holds
 * protectedValue + feeReserve. All quantities are BigInt sompi / integers.
 */

const crypto = require("crypto");
const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeHex, normalizeXOnlyPubkey } = require("./vault-state");

const CONTRACT_VERSION_V4 = "policyvault-0.4";
// v0.4.1 STANDARDNESS REDESIGN: byte-identical state ABI to v0.4, but the six
// owner operations are consolidated behind ownerControl + opSelector so the
// redeem script carries 13 (<=15) static sig-ops and relays on a default node.
const CONTRACT_VERSION_V4_1 = "policyvault-0.4.1";
const MAX_APPROVERS = 10;

/*
 * Version-ABI descriptors. Everything about v0.4 and v0.4.1 is identical EXCEPT
 * the version tag, the on-disk covenant path, the artifact build subdir (kept
 * separate so identical state never reads the wrong version's cached script),
 * and — for owner operations only — the encoder call shape. Unknown versions
 * FAIL CLOSED; there is no cross-version fallback.
 */
const V4_ABIS = Object.freeze({
  [CONTRACT_VERSION_V4]: Object.freeze({
    version: CONTRACT_VERSION_V4,
    contractRelPath: "contracts/PolicyVault.v0.4.sil",
    buildSubdir: "build-v4",
    // v0.4: each owner op is its own covenant entrypoint (no opSelector).
    consolidatedOwner: false
  }),
  [CONTRACT_VERSION_V4_1]: Object.freeze({
    version: CONTRACT_VERSION_V4_1,
    contractRelPath: "contracts/PolicyVault.v0.4.1.sil",
    buildSubdir: "build-v4_1",
    // v0.4.1: owner ops are ONE ownerControl entrypoint + opSelector.
    consolidatedOwner: true
  })
});

// v0.4.1 owner sdkAction -> ownerControl opSelector (mutually exclusive branches).
const OWNER_OP_SELECTOR_V4_1 = Object.freeze({
  ownerSetAgentRoot: 0,
  ownerSetApprovers: 1,
  ownerTopUp: 2,
  ownerTopUpReserve: 3,
  ownerPause: 4,
  ownerUnpause: 5
});

function resolveV4Abi(contractVersion) {
  const abi = V4_ABIS[contractVersion ?? CONTRACT_VERSION_V4];
  if (!abi) {
    fail(`unknown contract version ${JSON.stringify(contractVersion)} for the v0.4 family — failing closed (no cross-version fallback)`);
  }
  return abi;
}
const APPROVER_SENTINEL = "00".repeat(32);

function fail(message) {
  throw new Error(`vault-state-v4: ${message}`);
}

function normalizeSmallInt(value, field, { min, max }) {
  const n = parseSompi(value, field);
  if (n < min || n > max) {
    fail(`${field} out of range [${min}, ${max}]`);
  }
  return n;
}

/* v0.4 immutable template constants. */
function normalizeTemplateV4(input) {
  if (!input || typeof input !== "object") {
    fail("template object is required");
  }
  return Object.freeze({
    owner: normalizeXOnlyPubkey(input.owner, "template.owner"),
    vaultId: normalizeHex(input.vaultId, 32, "template.vaultId")
  });
}

/*
 * Approver slots. Two accepted input forms (mirrors v0.3): `approvers`
 * (0..10 active x-only keys, canonicalized: sorted + padded) or
 * `approverSlots` (exact 10-slot layout, preserved verbatim). Fails closed
 * on: too many, malformed key, sentinel as an active key, or duplicate
 * active key.
 */
function normalizeApprovers(input) {
  if (input.approverSlots !== undefined) {
    const slots = input.approverSlots;
    if (!Array.isArray(slots) || slots.length !== MAX_APPROVERS) {
      fail(`state.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
    }
    const seen = new Set();
    let activeCount = 0;
    const normalized = slots.map((k, i) => {
      const key = normalizeHex(k, 32, `state.approverSlots[${i}]`);
      if (key !== APPROVER_SENTINEL) {
        if (seen.has(key)) {
          fail(`state.approverSlots[${i}] duplicates an earlier active approver key — active approver keys must be distinct`);
        }
        seen.add(key);
        activeCount += 1;
      }
      return key;
    });
    return { approvers: Object.freeze(normalized), activeCount };
  }
  const raw = input.approvers;
  if (!Array.isArray(raw)) {
    fail("state.approvers must be an array (0..10 x-only pubkeys) or state.approverSlots an exact 10-slot layout");
  }
  if (raw.length > MAX_APPROVERS) {
    fail(`state.approvers has ${raw.length} entries; max is ${MAX_APPROVERS}`);
  }
  const active = [];
  const seen = new Set();
  raw.forEach((k, i) => {
    const key = normalizeXOnlyPubkey(k, `state.approvers[${i}]`);
    if (key === APPROVER_SENTINEL) {
      fail(`state.approvers[${i}] is the all-zero sentinel; pass only active approver keys`);
    }
    if (seen.has(key)) {
      fail(`state.approvers[${i}] duplicates an earlier approver key — active approver keys must be distinct`);
    }
    seen.add(key);
    active.push(key);
  });
  active.sort();
  const padded = active.slice();
  while (padded.length < MAX_APPROVERS) {
    padded.push(APPROVER_SENTINEL);
  }
  return { approvers: Object.freeze(padded), activeCount: active.length };
}

/*
 * v0.4 mutable state. Every field strictly validated; approver policy
 * cross-checked against the active approver count (a vault MAY have zero
 * approvers and approvalM 0 — an all-agent-below-their-own-threshold vault;
 * when approvers are configured, 1 <= approvalM <= activeCount).
 */
function normalizeStateV4(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const { approvers, activeCount } = normalizeApprovers(input);
  const approvalM = normalizeSmallInt(input.approvalM, "state.approvalM", { min: 0n, max: BigInt(MAX_APPROVERS) });
  if (activeCount === 0) {
    if (approvalM !== 0n) {
      fail("state.approvalM must be 0 when there are no active approvers");
    }
  } else {
    if (approvalM < 1n) {
      fail("state.approvalM must be >= 1 when approvers are configured");
    }
    if (approvalM > BigInt(activeCount)) {
      fail(`state.approvalM (${approvalM}) exceeds the active approver count (${activeCount})`);
    }
  }
  return Object.freeze({
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: normalizeSmallInt(input.paused, "state.paused", { min: 0n, max: 1n }),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    approvers,
    activeApproverCount: activeCount,
    approvalM,
    policyNonce: normalizeSmallInt(input.policyNonce, "state.policyNonce", { min: 0n, max: 1_000_000_000n })
  });
}

/*
 * BREAK-GLASS shape-only parse for ownerRecover (Checkpoint E; mirrors
 * v0.3's normalizeStateV3ForRecovery). Consensus does not validate genesis
 * state, so a manually-baked v0.4 UTXO can carry duplicate approver keys,
 * an inconsistent approvalM, paused=1, or a garbage agentRoot — and the
 * covenant still allows ownerRecover from it. This parse enforces ONLY
 * widths and representable integer domains (the compiled template
 * substitutes the exact values); it is quarantined to ownerRecover by the
 * `recoveryParse: true` marker, which every ordinary transition rejects.
 */
function normalizeStateV4ForRecovery(input) {
  if (!input || typeof input !== "object") {
    fail("state object is required");
  }
  const slotsIn = input.approverSlots ?? input.approvers;
  if (!Array.isArray(slotsIn) || slotsIn.length > MAX_APPROVERS) {
    fail(`recovery parse requires an approver slot array of at most ${MAX_APPROVERS} entries`);
  }
  const slots = slotsIn.map((k, i) => normalizeHex(k, 32, `state.approverSlots[${i}]`));
  while (slots.length < MAX_APPROVERS) {
    slots.push(APPROVER_SENTINEL);
  }
  let activeCount = 0;
  for (const s of slots) {
    if (s !== APPROVER_SENTINEL) activeCount += 1;
  }
  return Object.freeze({
    recoveryParse: true,
    protectedValue: parsePositiveSompi(input.protectedValue, "state.protectedValue"),
    feeReserve: parseSompi(input.feeReserve, "state.feeReserve"),
    paused: parseSompi(input.paused, "state.paused"),
    agentRoot: normalizeHex(input.agentRoot, 32, "state.agentRoot"),
    approvers: Object.freeze(slots),
    activeApproverCount: activeCount,
    approvalM: parseSompi(input.approvalM, "state.approvalM"),
    policyNonce: parseSompi(input.policyNonce, "state.policyNonce")
  });
}

/* Deterministic v0.4 state ID (application identity; never a consensus value). */
function computeStateIdV4({ networkId, template, state, contractVersion }) {
  if (typeof networkId !== "string" || networkId.length === 0) {
    fail("networkId is required for the state ID");
  }
  // The version is part of the identity so a v0.4 and a v0.4.1 vault with the
  // same owner/vaultId/state never collide (distinct stateId -> distinct build
  // dir and manifest). Default preserves every existing v0.4 stateId exactly.
  const version = contractVersion ?? CONTRACT_VERSION_V4;
  const canonical = [
    "policyvault-state/v4",
    `network:${networkId}`,
    `contract:${version}`,
    `owner:${template.owner}`,
    `vaultId:${template.vaultId}`,
    `protectedValue:${state.protectedValue}`,
    `feeReserve:${state.feeReserve}`,
    `paused:${state.paused}`,
    `agentRoot:${state.agentRoot}`,
    `approvers:${state.approvers.join(",")}`,
    `approvalM:${state.approvalM}`,
    `policyNonce:${requireNonce(state)}`
  ].join("\n");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function requireNonce(state) {
  if (typeof state.policyNonce !== "bigint") {
    fail("state.policyNonce is required (BigInt) — refusing an implicit default for a consensus-visible value");
  }
  return state.policyNonce;
}

/* JSON-safe encoding (BigInt -> digit strings) for manifests/receipts. */
function stateToJsonV4(state) {
  return {
    protectedValue: state.protectedValue.toString(),
    feeReserve: state.feeReserve.toString(),
    paused: state.paused.toString(),
    agentRoot: state.agentRoot,
    approverSlots: [...state.approvers],
    approvalM: state.approvalM.toString(),
    policyNonce: requireNonce(state).toString()
  };
}

module.exports = {
  CONTRACT_VERSION_V4,
  CONTRACT_VERSION_V4_1,
  V4_ABIS,
  OWNER_OP_SELECTOR_V4_1,
  resolveV4Abi,
  MAX_APPROVERS,
  APPROVER_SENTINEL,
  normalizeTemplateV4,
  normalizeStateV4,
  normalizeStateV4ForRecovery,
  normalizeApprovers,
  computeStateIdV4,
  stateToJsonV4
};
  });

  define("core/model/vault-transitions-v4", function (module, exports, require) {
"use strict";

/*
 * Canonical v0.4 state-transition derivation (Checkpoint E §E3).
 *
 * One canonical successor builder per non-terminal production entrypoint
 * (FROZEN ABI, docs/covenant-spec-v0.4.md §4). Callers NEVER supply
 * successor state — every builder derives the single covenant-permitted
 * successor from the normalized predecessor, changes ONLY the fields that
 * entrypoint authorizes, preserves everything else, and applies the exact
 * production policyNonce rule:
 *
 *   nonce PRESERVED: agentSpend, ownerTopUp, ownerTopUpReserve,
 *                    ownerPause, ownerUnpause
 *   nonce +1:        ownerSetAgentRoot, ownerSetApprovers
 *
 * The frozen per-entrypoint field-preservation matrix (spec §4) is
 * enforced structurally: each builder spreads the predecessor and touches
 * only its authorized fields, then re-normalizes through the STRICT v0.4
 * normalizer (exact approver-slot layout preserved) so an ill-formed
 * successor can never leave this module.
 *
 * agentSpend mirrors the covenant's exact rules (gen_v4.js / the compiled
 * production covenant is the authority):
 *   paused == 0; payAmount > 0; payAmount <= leaf.maxPerSpend;
 *   0 <= periodsElapsed <= 1000; rollover advances periodStartDaa by
 *   periodsElapsed * periodLengthDaa and resets periodSpent to payAmount
 *   (lockTime must be >= newStart — CLTV); newSpent <= periodBudget;
 *   newProtected = protected - pay > 0; newReserve = reserve -
 *   reserveConsumed >= 0; 0 <= reserveConsumed <= leaf.agentMaxFeePerTx;
 *   successor agentRoot = fold(newLeaf) up the SAME co-path that proved
 *   the old leaf (single-leaf update: every unrelated leaf preserved).
 *
 * Recovery-mode predecessor parses (normalizeStateV4ForRecovery) are
 * rejected by every function here — they exist only for ownerRecover
 * construction (recoverPlanV4 accepts both parse modes).
 *
 * Owner recovery is TERMINAL: recoverPlanV4 returns exact payout facts
 * (protectedValue + feeReserve to the owner) and never fabricates a
 * covenant successor.
 */

const { parseSompi, parsePositiveSompi } = require("./amounts");
const { normalizeXOnlyPubkey, normalizeHex } = require("./vault-state");
const { normalizeStateV4, stateToJsonV4, MAX_APPROVERS } = require("./vault-state-v4");
const { normalizeAgentPolicyV4, verifyAgentProofV4, foldAgentPolicyV4 } = require("./agent-merkle-v4");

const MAX_PERIODS_ELAPSED = 1000n; // covenant: require(periodsElapsed <= 1000)

function fail(message, code) {
  const error = new Error(`vault-transitions-v4: ${message}`);
  if (code) error.code = code;
  throw error;
}

function requireContinuingState(state, label) {
  if (!state || typeof state !== "object") {
    fail(`${label}: normalized predecessor state is required`);
  }
  if (state.recoveryParse === true) {
    fail(`${label}: a recovery-mode state parse can only be used for ownerRecover — refusing ordinary transition`);
  }
  if (typeof state.policyNonce !== "bigint") {
    fail(`${label}: predecessor state is missing policyNonce`);
  }
}

/*
 * Re-normalize a derived successor through the strict normalizer with the
 * EXACT slot layout preserved — asserts the successor is a well-formed
 * continuing state; a canonical builder can never emit a state the strict
 * normalizer rejects.
 */
function normalizeSuccessor(successor) {
  return normalizeStateV4(stateToJsonV4(successor));
}

function withChanges(state, changes) {
  return normalizeSuccessor(Object.freeze({ ...state, ...changes }));
}

/*
 * agentSpend: the one agent path (both approval tiers + rollover).
 * Derives the FULL spend transition:
 *   - authenticates the agent policy against the live agentRoot,
 *   - advances the agent's period accounting exactly as the covenant will,
 *   - derives the successor agentRoot by the single-leaf fold,
 *   - moves protectedValue by exactly payAmount and feeReserve by exactly
 *     reserveConsumed.
 * Returns { successor, previousPolicy, newPolicy, newStart, newSpent,
 *           lockTime, aboveThreshold, payAmount, reserveConsumed }.
 */
function agentSpendSuccessorV4(state, { agentPolicy, agentProof, payAmount, periodsElapsed, reserveConsumed }) {
  requireContinuingState(state, "agentSpend");
  if (state.paused !== 0n) {
    fail("agentSpend: vault is paused");
  }
  const policy = normalizeAgentPolicyV4(agentPolicy);
  if (!agentProof || typeof agentProof !== "object") {
    fail("agentSpend: agentProof { siblingsHex, pathBits } is required");
  }
  const proof = {
    siblingsHex: String(agentProof.siblingsHex ?? "").toLowerCase(),
    pathBits: typeof agentProof.pathBits === "bigint" ? agentProof.pathBits : BigInt(agentProof.pathBits)
  };
  if (!verifyAgentProofV4({ root: state.agentRoot, policy, siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })) {
    fail("agentSpend: the agent policy proof does not verify against the live agentRoot — stale tree or forged policy", "AGENT_PROOF_INVALID");
  }

  const pay = parsePositiveSompi(payAmount, "payAmount");
  if (pay > policy.maxPerSpend) {
    fail("agentSpend: payAmount exceeds this agent's maxPerSpend");
  }
  const periods = parseSompi(periodsElapsed ?? 0n, "periodsElapsed");
  if (periods > MAX_PERIODS_ELAPSED) {
    fail(`agentSpend: periodsElapsed out of range [0, ${MAX_PERIODS_ELAPSED}]`);
  }
  let newStart = policy.periodStartDaa;
  let newSpent = policy.periodSpent + pay;
  let lockTime = 0n;
  if (periods >= 1n) {
    newStart = policy.periodStartDaa + periods * policy.periodLengthDaa;
    newSpent = pay;
    lockTime = newStart; // covenant CLTV: tx lockTime must be >= newStart
  }
  if (newSpent > policy.periodBudget) {
    fail("agentSpend: spend exceeds this agent's remaining period budget");
  }

  if (pay >= state.protectedValue) {
    fail("agentSpend: spend would not leave a positive successor protectedValue (covenant requires newProtected > 0)");
  }
  const consumed = parseSompi(reserveConsumed ?? 0n, "reserveConsumed");
  if (consumed > policy.agentMaxFeePerTx) {
    fail("agentSpend: reserveConsumed exceeds this agent's agentMaxFeePerTx", "OVER_AGENT_FEE_CAP");
  }
  if (consumed > state.feeReserve) {
    fail("agentSpend: reserveConsumed exceeds the available fee reserve", "INSUFFICIENT_RESERVE");
  }

  const newPolicy = normalizeAgentPolicyV4({ ...policy, periodStartDaa: newStart, periodSpent: newSpent });
  const newRoot = foldAgentPolicyV4(newPolicy, proof.siblingsHex, proof.pathBits);
  if (newRoot === null) {
    fail("agentSpend: internal — successor-root fold left unconsumed path bits");
  }

  const successor = withChanges(state, {
    protectedValue: state.protectedValue - pay,
    feeReserve: state.feeReserve - consumed,
    agentRoot: newRoot
  });

  const aboveThreshold = pay > policy.approvalThreshold;
  if (aboveThreshold && state.approvalM < 1n) {
    fail(
      "agentSpend: payAmount exceeds this agent's approvalThreshold but the vault has no approver configuration (approvalM 0) — the covenant rejects this spend; the owner must ownerSetApprovers or re-policy the agent first",
      "NO_APPROVER_TIER"
    );
  }

  return Object.freeze({
    successor,
    previousPolicy: policy,
    newPolicy,
    newStart,
    newSpent,
    lockTime,
    aboveThreshold,
    payAmount: pay,
    reserveConsumed: consumed,
    agentProof: Object.freeze({ siblingsHex: proof.siblingsHex, pathBits: proof.pathBits })
  });
}

/* ownerSetAgentRoot: root replaced wholesale; policyNonce += 1. All agent
 * lifecycle (add/remove/rotate/re-policy/per-agent pause) reduces to an
 * SDK tree edit + this root swap. */
function setAgentRootSuccessorV4(state, newAgentRoot) {
  requireContinuingState(state, "setAgentRoot");
  const agentRoot = normalizeHex(newAgentRoot, 32, "newAgentRoot");
  return withChanges(state, { agentRoot, policyNonce: state.policyNonce + 1n });
}

/*
 * ownerSetApprovers: approver slots + approvalM replaced atomically;
 * policyNonce += 1. The new configuration must be a covenant-valid
 * transition target: >= 1 active approver, distinct active keys,
 * 1 <= M <= activeCount (the zero-approver configuration is GENESIS-ONLY
 * — the covenant requires newApprovalM >= 1 on this path).
 */
function setApproversSuccessorV4(state, { approvers, approverSlots, approvalM }) {
  requireContinuingState(state, "setApprovers");
  if (approvers === undefined && approverSlots === undefined) {
    fail("setApprovers requires the new approver set (approvers or approverSlots)");
  }
  if (approvalM === undefined) {
    fail("setApprovers requires approvalM");
  }
  const json = stateToJsonV4(state);
  delete json.approverSlots;
  const successor = normalizeStateV4({
    ...json,
    ...(approvers !== undefined ? { approvers } : {}),
    ...(approverSlots !== undefined ? { approverSlots } : {}),
    approvalM,
    policyNonce: (state.policyNonce + 1n).toString()
  });
  if (successor.activeApproverCount < 1 || successor.approvalM < 1n) {
    fail(
      "the covenant cannot transition to a zero-approver configuration (ownerSetApprovers requires 1 <= approvalM <= activeCount); the zero-approver tier exists only at genesis"
    );
  }
  return successor;
}

/* ownerTopUp: protectedValue increases by exactly the top-up amount. */
function topUpSuccessorV4(state, topUpAmount) {
  requireContinuingState(state, "topUp");
  const amount = parsePositiveSompi(topUpAmount, "topUpAmount");
  return withChanges(state, { protectedValue: state.protectedValue + amount });
}

/* ownerTopUpReserve: feeReserve increases by exactly the top-up amount. */
function topUpReserveSuccessorV4(state, topUpAmount) {
  requireContinuingState(state, "topUpReserve");
  const amount = parsePositiveSompi(topUpAmount, "topUpReserveAmount");
  return withChanges(state, { feeReserve: state.feeReserve + amount });
}

/* ownerPause / ownerUnpause: only `paused` flips. */
function pauseSuccessorV4(state, pause) {
  requireContinuingState(state, pause ? "pause" : "unpause");
  const target = pause ? 1n : 0n;
  if (state.paused === target) {
    fail(`vault is already ${pause ? "paused" : "active"}`);
  }
  return withChanges(state, { paused: target });
}

/*
 * ownerRecover planning (terminal): no successor exists. Returns the
 * exact covenant-required payout facts: output 0 = P2PK(owner) with value
 * exactly protectedValue + feeReserve. Accepts BOTH strict and
 * recovery-mode predecessor parses — recovery is the break-glass path and
 * must remain possible with an empty fee reserve and malformed policy.
 */
function recoverPlanV4(state, ownerXOnly) {
  if (
    !state ||
    typeof state !== "object" ||
    typeof state.protectedValue !== "bigint" ||
    typeof state.feeReserve !== "bigint"
  ) {
    fail("recover: normalized predecessor state is required");
  }
  const owner = normalizeXOnlyPubkey(ownerXOnly, "owner");
  return Object.freeze({
    terminal: true,
    payoutXOnly: owner,
    payoutValue: state.protectedValue + state.feeReserve
  });
}

module.exports = {
  MAX_PERIODS_ELAPSED,
  agentSpendSuccessorV4,
  setAgentRootSuccessorV4,
  setApproversSuccessorV4,
  topUpSuccessorV4,
  topUpReserveSuccessorV4,
  pauseSuccessorV4,
  recoverPlanV4,
  MAX_APPROVERS
};
  });

  define("core/governance/canonical", function (module, exports, require) {
"use strict";

/*
 * PolicyVault post-launch governance — canonical proposal encoding.
 *
 * Deterministic, storage-representation-independent serialization for
 * GOVERNANCE PROPOSAL commitment preimages. Semantics intentionally match
 * `sdk/src/canonical-json.js` (the Phase G-2 standing rule: any integrity
 * commitment over structured data must be representation-independent —
 * PostgreSQL jsonb reorders object keys, the JSON-file backend preserves
 * insertion order, and identical VALUES must hash identically on both).
 * This module is deliberately self-contained (core/ has no runtime
 * dependency on sdk/); any divergence from the sdk serializer's semantics
 * is a defect.
 *
 * Rules:
 *   - arrays keep element order (order can be meaningful: approver slots,
 *     recipient lists, per-agent registries);
 *   - object keys serialize in lexicographic (UTF-16 code unit) order;
 *   - primitives serialize exactly as JSON.stringify does;
 *   - anything not plainly JSON fails CLOSED: undefined, functions,
 *     symbols, BigInt (consensus integers must already be decimal
 *     strings), non-finite numbers, and non-plain objects all throw.
 *
 * The proposal digest is domain-separated and schema-versioned:
 * unknown proposal schemas REFUSE (fail closed) — they are never routed
 * to a default encoding.
 */

const crypto = require("crypto");

const GOVERNANCE_PROPOSAL_SCHEMA = "policyvault-governance-proposal/v1";
const GOVERNANCE_PROPOSAL_DOMAIN = "policyvault-governance-proposal-digest/v1";

class CanonicalEncodingRefusal extends Error {
  constructor(code, message) {
    super(`governance-canonical: ${message}`);
    this.name = "CanonicalEncodingRefusal";
    this.code = code;
  }
}

function fail(code, message) {
  throw new CanonicalEncodingRefusal(code, message);
}

function serialize(value, path) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      fail("CANONICAL_JSON_INVALID", `non-finite number at ${path} — failing closed`);
    }
    return JSON.stringify(value);
  }
  if (t === "bigint") {
    fail("CANONICAL_JSON_INVALID", `BigInt at ${path} — consensus integers must be committed as decimal strings`);
  }
  if (t === "undefined") {
    fail("CANONICAL_JSON_INVALID", `undefined at ${path} — a commitment field may not be silently omitted`);
  }
  if (t === "function" || t === "symbol") {
    fail("CANONICAL_JSON_INVALID", `${t} at ${path} — not JSON`);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => serialize(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      fail("CANONICAL_JSON_INVALID", `non-plain object at ${path} — refusing to canonicalize`);
    }
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      parts.push(`${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`)}`);
    }
    return `{${parts.join(",")}}`;
  }
  fail("CANONICAL_JSON_INVALID", `unsupported type ${t} at ${path}`);
}

/* Deterministic, key-order-independent JSON serialization (string out). */
function canonicalJsonStringify(value) {
  return serialize(value, "$");
}

/*
 * Canonical byte encoding of ONE governance proposal. The proposal object
 * must be a plain JSON-safe object carrying exactly the supported schema
 * tag; every signature ever collected for a proposal is a signature over
 * these bytes (wallet personal-message signing — a domain permanently
 * distinct from transaction signing), so a stored proposal that is
 * tampered with in the database no longer verifies against any of its
 * collected signatures.
 */
function encodeGovernanceProposal(proposal) {
  if (proposal === null || typeof proposal !== "object" || Array.isArray(proposal)) {
    fail("PROPOSAL_INVALID", "proposal must be a plain object");
  }
  if (proposal.schema !== GOVERNANCE_PROPOSAL_SCHEMA) {
    fail(
      "GOVERNANCE_SCHEMA_UNKNOWN",
      `unknown proposal schema ${JSON.stringify(proposal.schema)} — only ${GOVERNANCE_PROPOSAL_SCHEMA} is supported; unknown schemas fail closed`
    );
  }
  return Buffer.from(canonicalJsonStringify(proposal), "utf8");
}

/* SHA-256 digest (lowercase hex) over domain || "\n" || canonical bytes. */
function governanceProposalDigest(proposal) {
  const bytes = encodeGovernanceProposal(proposal);
  return crypto
    .createHash("sha256")
    .update(GOVERNANCE_PROPOSAL_DOMAIN, "utf8")
    .update("\n", "utf8")
    .update(bytes)
    .digest("hex");
}

module.exports = {
  GOVERNANCE_PROPOSAL_SCHEMA,
  GOVERNANCE_PROPOSAL_DOMAIN,
  CanonicalEncodingRefusal,
  canonicalJsonStringify,
  encodeGovernanceProposal,
  governanceProposalDigest
};
  });

  define("core/governance/authority-delta", function (module, exports, require) {
"use strict";

/*
 * PolicyVault post-launch governance — AUTHORITY-DELTA CLASSIFIER.
 *
 * Pure classification of a proposed policy change:
 *
 *   classifyPolicyDelta({ covenantVersion, before, after })
 *     -> { classification: "REDUCTION" | "EXPANSION", covenantVersion,
 *          perField: [...], codes: [...] }
 *
 * The classifier decides ONLY how much governance ceremony a proposal
 * gets (lighter for safely-restrictive changes, strongest for authority
 * expansions). It grants nothing: every covenant policy transition still
 * requires the vault owner's BIP-340 wallet signature over the exact
 * frozen transaction bytes, verified by Kaspa consensus. A hosted
 * administrator or database writer who tampers with stored tuples or a
 * stored classification label changes what the app DISPLAYS, never what
 * the covenant ACCEPTS (docs/hosted-threat-model.md §3: a fully
 * compromised server steals nothing unilaterally; the database cannot
 * sign). Consumers therefore RECOMPUTE this classification from the
 * proposal's before/after tuples at every decision point and never trust
 * a stored label.
 *
 * Fail-closed rules (docs/postlaunch/governance-spec.md §5):
 *   - unknown covenant versions REFUSE (never routed to a default);
 *   - unknown / missing / malformed fields REFUSE;
 *   - a change whose direction cannot be proven restrictive is
 *     EXPANSION (opaque commitment swaps, period-phase changes, mixed
 *     reduction+expansion proposals);
 *   - identical before/after REFUSES (NO_CHANGE) — a no-op is not a
 *     governable change;
 *   - numeric safety: BigInt or base-10 digit strings only, bounded to
 *     the i64 num8 encoding domain; JS numbers, floats, NaN, negatives,
 *     and overflow all REFUSE.
 *
 * Field names below are the REAL covenant/SDK field names, taken from
 * contracts/PolicyVault.v0.{2,3,4,4.1}.sil and
 * sdk/src/{vault-state-v2,vault-state-v3,vault-state-v4,agent-merkle-v4}.js.
 */

const CLASSIFICATION_REDUCTION = "REDUCTION";
const CLASSIFICATION_EXPANSION = "EXPANSION";
const CLASSIFICATIONS = Object.freeze([CLASSIFICATION_REDUCTION, CLASSIFICATION_EXPANSION]);
const DIRECTION_NEUTRAL = "NEUTRAL";
const DIRECTIONS = Object.freeze([CLASSIFICATION_REDUCTION, CLASSIFICATION_EXPANSION, DIRECTION_NEUTRAL]);

/* num8 = OpNum2Bin(v, 8) is injective over i64; 0 <= v < 2^63 covers every
 * consensus-encodable sompi/DAA quantity in the frozen ABIs. */
const I64_MAX = 2n ** 63n - 1n;

const APPROVER_SENTINEL = "00".repeat(32);
const MAX_APPROVERS = 10;

const VERSION_V2 = "policyvault-0.2";
const VERSION_V3 = "policyvault-0.3";
const VERSION_V4 = "policyvault-0.4";
const VERSION_V4_1 = "policyvault-0.4.1";

class GovernanceRefusal extends Error {
  constructor(code, message) {
    super(`authority-delta: ${message}`);
    this.name = "GovernanceRefusal";
    this.code = code;
    this.failClosed = true;
  }
}

function refuse(code, message) {
  throw new GovernanceRefusal(code, message);
}

/* ------------------------------------------------------------------ */
/* Strict primitives (numeric safety, hex identity)                    */
/* ------------------------------------------------------------------ */

/* BigInt or CANONICAL base-10 digit string only ("0" or no leading zero);
 * 0 <= v <= I64_MAX. JS numbers are refused entirely (floating-point risk
 * on funds-relevant quantities). Leading-zero forms ("010") are refused —
 * hardening from the core-v1 falsification pass: the governance proposal
 * digest (canonical.js) is string-sensitive, so one integer value must
 * have exactly one accepted encoding at this boundary or two documents
 * with identical governed VALUES could carry different digests. Matches
 * core/intent's CANONICAL_DIGITS_RE; strictly narrower than before (a
 * previously-accepted non-canonical form now refuses — fail closed). */
const CANONICAL_INTEGER_RE = /^(0|[1-9][0-9]*)$/;
function parseIntegerField(value, field) {
  let amount;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_INTEGER_RE.test(value)) {
      refuse("INVALID_INTEGER", `${field} must be a canonical base-10 digit string ("0" or no leading zero), got ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    refuse(
      "INVALID_INTEGER",
      `${field} must be a BigInt or base-10 digit string (JS numbers are refused: floats/NaN are unsafe for consensus quantities), got ${typeof value}`
    );
  }
  if (amount < 0n) {
    refuse("INVALID_INTEGER", `${field} must not be negative`);
  }
  if (amount > I64_MAX) {
    refuse("INVALID_INTEGER", `${field} exceeds the i64 num8 encoding domain`);
  }
  return amount;
}

function parsePositiveIntegerField(value, field) {
  const amount = parseIntegerField(value, field);
  if (amount === 0n) {
    refuse("INVALID_INTEGER", `${field} must be greater than zero`);
  }
  return amount;
}

/* 0/1 flags (paused, delegateActive). */
function parseBitField(value, field) {
  const bit = parseIntegerField(value, field);
  if (bit !== 0n && bit !== 1n) {
    refuse("INVALID_INTEGER", `${field} must be 0 or 1`);
  }
  return bit;
}

/* 32-byte lowercase hex (x-only pubkeys, vault ids, Merkle roots). */
function normalizeHex64(value, field) {
  if (typeof value !== "string") {
    refuse("INVALID_HEX", `${field} must be a hex string`);
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    refuse("INVALID_HEX", `${field} must be 32-byte hex`);
  }
  return normalized;
}

function requirePlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    refuse("MALFORMED_TUPLE", `${label} must be a plain object`);
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    refuse("MALFORMED_TUPLE", `${label} must be a plain object (non-plain prototypes are refused)`);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* Tuple schemas (single source of truth, exported)                    */
/* ------------------------------------------------------------------ */

/*
 * Neutral field classes: fields that may accompany a policy tuple but are
 * NOT governed policy — any before/after difference REFUSES with the
 * class code (they change through their own covenant paths, or never).
 */
const NEUTRAL_CLASS = Object.freeze({
  IDENTITY: "IDENTITY_IMMUTABLE", //  boundVaultId — covenant pins it forever; changing identity is a migration
  FUNDING: "NOT_A_POLICY_FIELD", //   protectedValue / feeReserve — move via topUp/topUpReserve/spend, not proposals
  ACCOUNTING: "ACCOUNTING_IMMUTABLE", // v0.2/v0.3 periodStartDaa/periodSpent — owner ops preserve accounting by covenant rule
  MANAGED: "EXECUTION_MANAGED" //     policyNonce — the covenant/execution layer advances it (+1 on policy ops)
});

/*
 * Per-version tuple key sets. `required` are always-present governed
 * fields; `xor` lists pairs where EXACTLY ONE key must be present per
 * side; `neutral` maps optional fields to their refusal class. Any other
 * key refuses UNKNOWN_FIELD.
 */
const TUPLE_KEYS = Object.freeze({
  [VERSION_V2]: Object.freeze({
    kind: "delegate-v2",
    required: Object.freeze(["paused", "delegate", "delegateActive", "maxPerSpend", "periodBudget", "periodLengthDaa", "recipients"]),
    xor: Object.freeze([]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      periodStartDaa: NEUTRAL_CLASS.ACCOUNTING,
      periodSpent: NEUTRAL_CLASS.ACCOUNTING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V3]: Object.freeze({
    kind: "delegate-v3",
    required: Object.freeze(["paused", "delegate", "delegateActive", "maxPerSpend", "periodBudget", "periodLengthDaa", "approvalM", "approvalThresholdAmount"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["recipients", "recipientRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      periodStartDaa: NEUTRAL_CLASS.ACCOUNTING,
      periodSpent: NEUTRAL_CLASS.ACCOUNTING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V4]: Object.freeze({
    kind: "agents-v4",
    required: Object.freeze(["paused", "approvalM"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["agents", "agentRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      feeReserve: NEUTRAL_CLASS.FUNDING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V4_1]: Object.freeze({
    kind: "agents-v4",
    required: Object.freeze(["paused", "approvalM"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["agents", "agentRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      feeReserve: NEUTRAL_CLASS.FUNDING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  })
});

/* Agent-policy leaf keys (v0.4 family; sdk/src/agent-merkle-v4.js
 * normalizeAgentPolicyV4 + per-agent recipient list). */
const AGENT_KEYS = Object.freeze({
  required: Object.freeze(["agentPk", "maxPerSpend", "periodBudget", "periodLengthDaa", "periodStartDaa", "periodSpent", "approvalThreshold", "agentMaxFeePerTx"]),
  xor: Object.freeze([Object.freeze(["recipients", "agentRecipientRoot"])])
});

function governedVersions() {
  return Object.freeze(Object.keys(TUPLE_KEYS));
}

function resolveVersion(covenantVersion) {
  if (typeof covenantVersion !== "string" || !Object.prototype.hasOwnProperty.call(TUPLE_KEYS, covenantVersion)) {
    refuse(
      "UNKNOWN_VERSION",
      `unknown covenant version ${JSON.stringify(covenantVersion)} — governed versions are ${governedVersions().join(", ")}; unknown versions fail closed`
    );
  }
  return TUPLE_KEYS[covenantVersion];
}

/* ------------------------------------------------------------------ */
/* Tuple parsing (per side)                                            */
/* ------------------------------------------------------------------ */

function checkKeySet(obj, schema, label) {
  const allowed = new Set(schema.required);
  for (const pair of schema.xor) {
    for (const k of pair) allowed.add(k);
  }
  for (const k of Object.keys(schema.neutral)) allowed.add(k);

  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      refuse("UNKNOWN_FIELD", `${label}.${key} is not a governed field of this covenant version — unknown fields fail closed`);
    }
  }
  for (const key of schema.required) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) {
      refuse("MISSING_FIELD", `${label}.${key} is required for this covenant version`);
    }
  }
  for (const pair of schema.xor) {
    const present = pair.filter((k) => Object.prototype.hasOwnProperty.call(obj, k));
    if (present.length === 0) {
      refuse("MISSING_FIELD", `${label} must carry exactly one of {${pair.join(", ")}}`);
    }
    if (present.length > 1) {
      refuse("AMBIGUOUS_FORM", `${label} carries both ${pair.join(" and ")} — two authorities for one fact are refused (cannot verify their consistency here)`);
    }
  }
}

/* Approver set: active-list form (`approvers`, 0..10 active keys, no
 * sentinel, no duplicates) or exact 10-slot form (`approverSlots`,
 * sentinels allowed, active duplicates refused — covenant rule A2).
 * Slot positions are authority-equivalent; comparison is by SET. */
function parseApproverSet(obj, label, invalidCode) {
  if (Object.prototype.hasOwnProperty.call(obj, "approverSlots")) {
    const slots = obj.approverSlots;
    if (!Array.isArray(slots) || slots.length !== MAX_APPROVERS) {
      refuse(invalidCode, `${label}.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
    }
    const active = new Set();
    slots.forEach((k, i) => {
      const key = normalizeHex64(k, `${label}.approverSlots[${i}]`);
      if (key === APPROVER_SENTINEL) return;
      if (active.has(key)) {
        refuse(invalidCode, `${label}.approverSlots[${i}] duplicates an active approver key — active approver keys must be distinct (covenant A2)`);
      }
      active.add(key);
    });
    return active;
  }
  const raw = obj.approvers;
  if (!Array.isArray(raw) || raw.length > MAX_APPROVERS) {
    refuse(invalidCode, `${label}.approvers must be an array of at most ${MAX_APPROVERS} active x-only keys`);
  }
  const active = new Set();
  raw.forEach((k, i) => {
    const key = normalizeHex64(k, `${label}.approvers[${i}]`);
    if (key === APPROVER_SENTINEL) {
      refuse(invalidCode, `${label}.approvers[${i}] is the all-zero sentinel; pass only active approver keys`);
    }
    if (active.has(key)) {
      refuse(invalidCode, `${label}.approvers[${i}] duplicates an active approver key — active approver keys must be distinct (covenant A2)`);
    }
    active.add(key);
  });
  return active;
}

/* Recipient key list -> SET. Duplicates are tolerated and deduplicated:
 * v0.2 pads its 3 consensus slots by duplicating keys, and a duplicate
 * recipient grants no additional authority. */
function parseRecipientSet(list, label, invalidCode, { min, max }) {
  if (!Array.isArray(list)) {
    refuse(invalidCode, `${label} must be an array of x-only recipient keys`);
  }
  if (list.length < min || (max !== null && list.length > max)) {
    refuse(invalidCode, `${label} must have ${min}..${max === null ? "n" : max} entries`);
  }
  const set = new Set();
  list.forEach((k, i) => {
    set.add(normalizeHex64(k, `${label}[${i}]`));
  });
  if (set.size === 0) {
    refuse(invalidCode, `${label} must contain at least one recipient key`);
  }
  return set;
}

function parseAgentEntry(entry, label, invalidCode) {
  requirePlainObject(entry, label);
  const allowed = new Set(AGENT_KEYS.required);
  for (const pair of AGENT_KEYS.xor) for (const k of pair) allowed.add(k);
  for (const key of Object.keys(entry)) {
    if (!allowed.has(key)) {
      refuse("UNKNOWN_FIELD", `${label}.${key} is not a governed agent-policy field — unknown fields fail closed`);
    }
  }
  for (const key of AGENT_KEYS.required) {
    if (!Object.prototype.hasOwnProperty.call(entry, key)) {
      refuse("MISSING_FIELD", `${label}.${key} is required`);
    }
  }
  for (const pair of AGENT_KEYS.xor) {
    const present = pair.filter((k) => Object.prototype.hasOwnProperty.call(entry, k));
    if (present.length === 0) {
      refuse("MISSING_FIELD", `${label} must carry exactly one of {${pair.join(", ")}}`);
    }
    if (present.length > 1) {
      refuse("AMBIGUOUS_FORM", `${label} carries both ${pair.join(" and ")} — refused`);
    }
  }
  const agent = {
    agentPk: normalizeHex64(entry.agentPk, `${label}.agentPk`),
    maxPerSpend: parsePositiveIntegerField(entry.maxPerSpend, `${label}.maxPerSpend`),
    periodBudget: parsePositiveIntegerField(entry.periodBudget, `${label}.periodBudget`),
    periodLengthDaa: parsePositiveIntegerField(entry.periodLengthDaa, `${label}.periodLengthDaa`),
    periodStartDaa: parseIntegerField(entry.periodStartDaa, `${label}.periodStartDaa`),
    periodSpent: parseIntegerField(entry.periodSpent, `${label}.periodSpent`),
    approvalThreshold: parseIntegerField(entry.approvalThreshold, `${label}.approvalThreshold`),
    agentMaxFeePerTx: parseIntegerField(entry.agentMaxFeePerTx, `${label}.agentMaxFeePerTx`)
  };
  if (Object.prototype.hasOwnProperty.call(entry, "recipients")) {
    agent.recipients = parseRecipientSet(entry.recipients, `${label}.recipients`, invalidCode, { min: 1, max: null });
    agent.recipientForm = "list";
  } else {
    agent.agentRecipientRoot = normalizeHex64(entry.agentRecipientRoot, `${label}.agentRecipientRoot`);
    agent.recipientForm = "root";
  }
  return agent;
}

/*
 * Parse one side of a proposal into a normalized tuple. `invalidCode` is
 * BEFORE_TUPLE_INVALID or AFTER_TUPLE_INVALID: a malformed live state
 * (e.g. a hand-baked genesis with duplicate approver keys) is handled by
 * break-glass owner recovery, never by governed policy editing.
 */
function parseTuple(covenantVersion, obj, label) {
  const schema = resolveVersion(covenantVersion);
  const invalidCode = label === "before" ? "BEFORE_TUPLE_INVALID" : "AFTER_TUPLE_INVALID";
  requirePlainObject(obj, label);
  checkKeySet(obj, schema, label);

  const tuple = { kind: schema.kind, neutral: {} };

  tuple.paused = parseBitField(obj.paused, `${label}.paused`);

  if (schema.kind === "delegate-v2" || schema.kind === "delegate-v3") {
    tuple.delegate = normalizeHex64(obj.delegate, `${label}.delegate`);
    tuple.delegateActive = parseBitField(obj.delegateActive, `${label}.delegateActive`);
    tuple.maxPerSpend = parsePositiveIntegerField(obj.maxPerSpend, `${label}.maxPerSpend`);
    tuple.periodBudget = parsePositiveIntegerField(obj.periodBudget, `${label}.periodBudget`);
    if (tuple.periodBudget < tuple.maxPerSpend) {
      refuse(invalidCode, `${label}.periodBudget must be >= ${label}.maxPerSpend`);
    }
    tuple.periodLengthDaa = parsePositiveIntegerField(obj.periodLengthDaa, `${label}.periodLengthDaa`);
  }

  if (schema.kind === "delegate-v2") {
    tuple.recipients = parseRecipientSet(obj.recipients, `${label}.recipients`, invalidCode, { min: 1, max: 3 });
    tuple.recipientForm = "list";
  }

  if (schema.kind === "delegate-v3") {
    tuple.approvalM = parseIntegerField(obj.approvalM, `${label}.approvalM`);
    tuple.approvalThresholdAmount = parseIntegerField(obj.approvalThresholdAmount, `${label}.approvalThresholdAmount`);
    tuple.approvers = parseApproverSet(obj, label, invalidCode);
    if (tuple.approvers.size === 0) {
      if (tuple.approvalM !== 0n) {
        refuse(invalidCode, `${label}.approvalM must be 0 when there are no active approvers`);
      }
      if (tuple.approvalThresholdAmount < tuple.maxPerSpend) {
        refuse(invalidCode, `${label}: a tuple with no approvers must set approvalThresholdAmount >= maxPerSpend so a spend can never require approvals`);
      }
    } else {
      if (tuple.approvalM < 1n || tuple.approvalM > BigInt(tuple.approvers.size)) {
        refuse(invalidCode, `${label}.approvalM must satisfy 1 <= M <= activeApproverCount (${tuple.approvers.size})`);
      }
    }
    if (Object.prototype.hasOwnProperty.call(obj, "recipients")) {
      tuple.recipients = parseRecipientSet(obj.recipients, `${label}.recipients`, invalidCode, { min: 1, max: null });
      tuple.recipientForm = "list";
    } else {
      tuple.recipientRoot = normalizeHex64(obj.recipientRoot, `${label}.recipientRoot`);
      tuple.recipientForm = "root";
    }
  }

  if (schema.kind === "agents-v4") {
    tuple.approvalM = parseIntegerField(obj.approvalM, `${label}.approvalM`);
    tuple.approvers = parseApproverSet(obj, label, invalidCode);
    if (tuple.approvers.size === 0) {
      if (tuple.approvalM !== 0n) {
        refuse(invalidCode, `${label}.approvalM must be 0 when there are no active approvers`);
      }
    } else if (tuple.approvalM < 1n || tuple.approvalM > BigInt(tuple.approvers.size)) {
      refuse(invalidCode, `${label}.approvalM must satisfy 1 <= M <= activeApproverCount (${tuple.approvers.size})`);
    }
    if (Object.prototype.hasOwnProperty.call(obj, "agents")) {
      if (!Array.isArray(obj.agents)) {
        refuse(invalidCode, `${label}.agents must be an array of agent-policy objects`);
      }
      const agents = new Map();
      obj.agents.forEach((entry, i) => {
        const agent = parseAgentEntry(entry, `${label}.agents[${i}]`, invalidCode);
        if (agents.has(agent.agentPk)) {
          refuse(invalidCode, `${label}.agents duplicates agentPk ${agent.agentPk} — one key may hold exactly one policy leaf (duplicate leaves would be independent budget lanes)`);
        }
        agents.set(agent.agentPk, agent);
      });
      tuple.agents = agents;
      tuple.agentForm = "list";
    } else {
      tuple.agentRoot = normalizeHex64(obj.agentRoot, `${label}.agentRoot`);
      tuple.agentForm = "root";
    }
  }

  /* Neutral-class fields: allowed, but never changed by a proposal. */
  for (const [field, code] of Object.entries(schema.neutral)) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      tuple.neutral[field] =
        field === "boundVaultId" ? normalizeHex64(obj[field], `${label}.${field}`) : parseIntegerField(obj[field], `${label}.${field}`);
      tuple.neutral[`${field}:code`] = code;
    }
  }

  return tuple;
}

/* ------------------------------------------------------------------ */
/* Delta evaluation                                                    */
/* ------------------------------------------------------------------ */

function entryNumeric(field, before, after, direction, code) {
  return { field, direction, code, before: before.toString(), after: after.toString() };
}

function neutralEntry(field) {
  return { field, direction: DIRECTION_NEUTRAL, code: "UNCHANGED" };
}

/* Monotone sompi/count field: bigger value = more delegated authority. */
function classifyMonotoneUp(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after < before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lowered));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.raised));
  }
}

/* periodLengthDaa: LONGER period = LOWER long-run spending rate
 * (periodBudget per periodLengthDaa; the within-period cap stays
 * periodBudget) => increase is a REDUCTION, decrease an EXPANSION. */
function classifyPeriodLength(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after > before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lengthened));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.shortened));
  }
}

function classifyKeySet(perField, field, beforeSet, afterSet, codes) {
  let changed = false;
  for (const key of beforeSet) {
    if (!afterSet.has(key)) {
      changed = true;
      perField.push({ field, direction: CLASSIFICATION_REDUCTION, code: codes.removed, member: key });
    }
  }
  for (const key of afterSet) {
    if (!beforeSet.has(key)) {
      changed = true;
      perField.push({ field, direction: CLASSIFICATION_EXPANSION, code: codes.added, member: key });
    }
  }
  if (!changed) {
    perField.push(neutralEntry(field));
  }
}

/* Recipient authorization in list or opaque-root form. A bare root swap
 * (or a list-vs-root form mismatch) cannot be proven to be a subset, so
 * it classifies EXPANSION (fail closed). Proving a reduction requires
 * both sides as explicit key lists sourced from the root-verified
 * durable registry; the EXECUTION layer, not this classifier, is what
 * binds a list to the on-chain root (the SDK builders recompute roots
 * from the registry lists). */
function classifyCommitmentSet(perField, field, beforeTuple, afterTuple, listKeys, codes) {
  const bForm = beforeTuple[listKeys.form];
  const aForm = afterTuple[listKeys.form];
  if (bForm === "list" && aForm === "list") {
    classifyKeySet(perField, field, beforeTuple[listKeys.list], afterTuple[listKeys.list], codes);
    return;
  }
  if (bForm === "root" && aForm === "root") {
    if (beforeTuple[listKeys.root] === afterTuple[listKeys.root]) {
      perField.push(neutralEntry(field));
    } else {
      perField.push({
        field,
        direction: CLASSIFICATION_EXPANSION,
        code: codes.opaque,
        before: beforeTuple[listKeys.root],
        after: afterTuple[listKeys.root]
      });
    }
    return;
  }
  /* Mixed forms: membership cannot be compared — EXPANSION, fail closed. */
  perField.push({ field, direction: CLASSIFICATION_EXPANSION, code: codes.opaque });
}

function classifyPaused(perField, before, after) {
  if (before === after) {
    perField.push(neutralEntry("paused"));
  } else if (before === 0n && after === 1n) {
    perField.push(entryNumeric("paused", before, after, CLASSIFICATION_REDUCTION, "EMERGENCY_FREEZE"));
  } else {
    perField.push(entryNumeric("paused", before, after, CLASSIFICATION_EXPANSION, "RESUME_SPENDING"));
  }
}

function classifyApprovalM(perField, before, after) {
  if (before === after) {
    perField.push(neutralEntry("approvalM"));
  } else if (after > before) {
    perField.push(entryNumeric("approvalM", before, after, CLASSIFICATION_REDUCTION, "APPROVAL_QUORUM_RAISED"));
  } else {
    perField.push(entryNumeric("approvalM", before, after, CLASSIFICATION_EXPANSION, "APPROVAL_QUORUM_WEAKENED"));
  }
}

/* approvalThreshold(-Amount): spends AT OR BELOW it need no approvals.
 * Raising it exempts more spends from the approval tier => EXPANSION. */
function classifyApprovalThreshold(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after < before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lowered));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.raised));
  }
}

function classifyAgentPair(perField, pk, b, a) {
  const p = (f) => `agents[${pk}].${f}`;
  classifyMonotoneUp(perField, p("maxPerSpend"), b.maxPerSpend, a.maxPerSpend, {
    lowered: "AGENT_PER_SPEND_CAP_LOWERED",
    raised: "AGENT_PER_SPEND_CAP_RAISED"
  });
  classifyMonotoneUp(perField, p("periodBudget"), b.periodBudget, a.periodBudget, {
    lowered: "AGENT_PERIOD_BUDGET_LOWERED",
    raised: "AGENT_PERIOD_BUDGET_RAISED"
  });
  classifyPeriodLength(perField, p("periodLengthDaa"), b.periodLengthDaa, a.periodLengthDaa, {
    lengthened: "AGENT_PERIOD_LENGTHENED",
    shortened: "AGENT_PERIOD_SHORTENED"
  });
  /* Period phase: moving periodStartDaa can open a fresh budget period
   * immediately — temporal effect is not provably restrictive. */
  if (b.periodStartDaa === a.periodStartDaa) {
    perField.push(neutralEntry(p("periodStartDaa")));
  } else {
    perField.push(entryNumeric(p("periodStartDaa"), b.periodStartDaa, a.periodStartDaa, CLASSIFICATION_EXPANSION, "AGENT_PERIOD_PHASE_CHANGED"));
  }
  /* periodSpent: lowering it refunds already-consumed budget (a fresh
   * spending lane in the current period) => EXPANSION; raising it
   * records consumption => REDUCTION. */
  if (b.periodSpent === a.periodSpent) {
    perField.push(neutralEntry(p("periodSpent")));
  } else if (a.periodSpent > b.periodSpent) {
    perField.push(entryNumeric(p("periodSpent"), b.periodSpent, a.periodSpent, CLASSIFICATION_REDUCTION, "AGENT_BUDGET_CONSUMPTION_RECORDED"));
  } else {
    perField.push(entryNumeric(p("periodSpent"), b.periodSpent, a.periodSpent, CLASSIFICATION_EXPANSION, "AGENT_BUDGET_REFUNDED"));
  }
  classifyApprovalThreshold(perField, p("approvalThreshold"), b.approvalThreshold, a.approvalThreshold, {
    lowered: "AGENT_APPROVAL_THRESHOLD_LOWERED",
    raised: "AGENT_APPROVAL_THRESHOLD_RAISED"
  });
  classifyMonotoneUp(perField, p("agentMaxFeePerTx"), b.agentMaxFeePerTx, a.agentMaxFeePerTx, {
    lowered: "AGENT_FEE_CAP_LOWERED",
    raised: "AGENT_FEE_CAP_RAISED"
  });
  classifyCommitmentSet(
    perField,
    p("recipients"),
    b,
    a,
    { form: "recipientForm", list: "recipients", root: "agentRecipientRoot" },
    { removed: "AGENT_RECIPIENT_REMOVED", added: "AGENT_RECIPIENT_ADDED", opaque: "OPAQUE_COMMITMENT_CHANGED" }
  );
}

function classifyNeutralFields(beforeTuple, afterTuple) {
  const keys = new Set([
    ...Object.keys(beforeTuple.neutral).filter((k) => !k.endsWith(":code")),
    ...Object.keys(afterTuple.neutral).filter((k) => !k.endsWith(":code"))
  ]);
  for (const field of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(beforeTuple.neutral, field);
    const inAfter = Object.prototype.hasOwnProperty.call(afterTuple.neutral, field);
    const code = (inBefore ? beforeTuple.neutral[`${field}:code`] : afterTuple.neutral[`${field}:code`]);
    if (!inBefore || !inAfter) {
      refuse(code, `${field} must be present on both sides or absent from both — a one-sided value cannot be verified unchanged`);
    }
    const b = beforeTuple.neutral[field];
    const a = afterTuple.neutral[field];
    const equal = typeof b === "bigint" ? b === a : b === a;
    if (!equal) {
      refuse(code, `${field} may not change in a policy proposal (${describeNeutral(field)})`);
    }
  }
}

function describeNeutral(field) {
  switch (field) {
    case "boundVaultId":
      return "vault identity is covenant-pinned; changing identity requires a covenant migration proposal";
    case "protectedValue":
    case "feeReserve":
      return "funding levels move only through their own covenant operations (topUp/topUpReserve/spend), never through policy proposals";
    case "periodStartDaa":
    case "periodSpent":
      return "the covenant preserves budget accounting across every owner policy operation";
    case "policyNonce":
      return "the execution layer advances the nonce (+1 on policy operations); proposals never set it";
    default:
      return "not a governed policy field";
  }
}

/*
 * The classifier. Both tuples must be the SAME covenant version (an
 * in-lineage policy change). Cross-version changes are covenant
 * migrations: classifyMigrationDelta.
 */
function classifyPolicyDelta({ covenantVersion, before, after } = {}) {
  const schema = resolveVersion(covenantVersion);
  const beforeTuple = parseTuple(covenantVersion, before, "before");
  const afterTuple = parseTuple(covenantVersion, after, "after");

  classifyNeutralFields(beforeTuple, afterTuple);

  const perField = [];

  classifyPaused(perField, beforeTuple.paused, afterTuple.paused);

  if (schema.kind === "delegate-v2" || schema.kind === "delegate-v3") {
    if (beforeTuple.delegate === afterTuple.delegate) {
      perField.push(neutralEntry("delegate"));
    } else {
      /* A different key gains spending authority — never a pure
       * reduction, even when the old key is simultaneously removed. */
      perField.push({
        field: "delegate",
        direction: CLASSIFICATION_EXPANSION,
        code: "DELEGATE_KEY_CHANGED",
        before: beforeTuple.delegate,
        after: afterTuple.delegate
      });
    }
    if (beforeTuple.delegateActive === afterTuple.delegateActive) {
      perField.push(neutralEntry("delegateActive"));
    } else if (beforeTuple.delegateActive === 1n && afterTuple.delegateActive === 0n) {
      perField.push(entryNumeric("delegateActive", beforeTuple.delegateActive, afterTuple.delegateActive, CLASSIFICATION_REDUCTION, "DELEGATE_REVOKED"));
    } else {
      perField.push(entryNumeric("delegateActive", beforeTuple.delegateActive, afterTuple.delegateActive, CLASSIFICATION_EXPANSION, "DELEGATE_ENABLED"));
    }
    classifyMonotoneUp(perField, "maxPerSpend", beforeTuple.maxPerSpend, afterTuple.maxPerSpend, {
      lowered: "PER_SPEND_CAP_LOWERED",
      raised: "PER_SPEND_CAP_RAISED"
    });
    classifyMonotoneUp(perField, "periodBudget", beforeTuple.periodBudget, afterTuple.periodBudget, {
      lowered: "PERIOD_BUDGET_LOWERED",
      raised: "PERIOD_BUDGET_RAISED"
    });
    classifyPeriodLength(perField, "periodLengthDaa", beforeTuple.periodLengthDaa, afterTuple.periodLengthDaa, {
      lengthened: "PERIOD_LENGTHENED",
      shortened: "PERIOD_SHORTENED"
    });
  }

  if (schema.kind === "delegate-v2") {
    classifyKeySet(perField, "recipients", beforeTuple.recipients, afterTuple.recipients, {
      removed: "RECIPIENT_REMOVED",
      added: "RECIPIENT_ADDED"
    });
  }

  if (schema.kind === "delegate-v3") {
    classifyApprovalM(perField, beforeTuple.approvalM, afterTuple.approvalM);
    classifyApprovalThreshold(perField, "approvalThresholdAmount", beforeTuple.approvalThresholdAmount, afterTuple.approvalThresholdAmount, {
      lowered: "APPROVAL_THRESHOLD_LOWERED",
      raised: "APPROVAL_THRESHOLD_RAISED"
    });
    classifyKeySet(perField, "approvers", beforeTuple.approvers, afterTuple.approvers, {
      removed: "APPROVER_REMOVED",
      added: "APPROVER_ADDED"
    });
    classifyCommitmentSet(
      perField,
      "recipients",
      beforeTuple,
      afterTuple,
      { form: "recipientForm", list: "recipients", root: "recipientRoot" },
      { removed: "RECIPIENT_REMOVED", added: "RECIPIENT_ADDED", opaque: "OPAQUE_COMMITMENT_CHANGED" }
    );
  }

  if (schema.kind === "agents-v4") {
    classifyApprovalM(perField, beforeTuple.approvalM, afterTuple.approvalM);
    classifyKeySet(perField, "approvers", beforeTuple.approvers, afterTuple.approvers, {
      removed: "APPROVER_REMOVED",
      added: "APPROVER_ADDED"
    });
    if (beforeTuple.agentForm === "list" && afterTuple.agentForm === "list") {
      let agentChange = false;
      for (const [pk, b] of beforeTuple.agents) {
        if (!afterTuple.agents.has(pk)) {
          agentChange = true;
          perField.push({ field: "agents", direction: CLASSIFICATION_REDUCTION, code: "AGENT_REMOVED", member: pk });
        }
      }
      for (const [pk, a] of afterTuple.agents) {
        if (!beforeTuple.agents.has(pk)) {
          agentChange = true;
          perField.push({ field: "agents", direction: CLASSIFICATION_EXPANSION, code: "AGENT_ADDED", member: pk });
        }
      }
      for (const [pk, b] of beforeTuple.agents) {
        const a = afterTuple.agents.get(pk);
        if (a) {
          const lengthBefore = perField.length;
          classifyAgentPair(perField, pk, b, a);
          if (perField.slice(lengthBefore).some((e) => e.direction !== DIRECTION_NEUTRAL)) {
            agentChange = true;
          }
        }
      }
      if (!agentChange && beforeTuple.agents.size === 0 && afterTuple.agents.size === 0) {
        perField.push(neutralEntry("agents"));
      }
    } else if (beforeTuple.agentForm === "root" && afterTuple.agentForm === "root") {
      if (beforeTuple.agentRoot === afterTuple.agentRoot) {
        perField.push(neutralEntry("agentRoot"));
      } else {
        perField.push({
          field: "agentRoot",
          direction: CLASSIFICATION_EXPANSION,
          code: "AGENT_SET_OPAQUE",
          before: beforeTuple.agentRoot,
          after: afterTuple.agentRoot
        });
      }
    } else {
      perField.push({ field: "agents", direction: CLASSIFICATION_EXPANSION, code: "AGENT_SET_OPAQUE" });
    }
  }

  const expansions = perField.filter((e) => e.direction === CLASSIFICATION_EXPANSION);
  const reductions = perField.filter((e) => e.direction === CLASSIFICATION_REDUCTION);

  if (expansions.length === 0 && reductions.length === 0) {
    refuse("NO_CHANGE", "before and after tuples are identical — a no-op is not a governable change");
  }

  const codes = [...new Set(perField.filter((e) => e.direction !== DIRECTION_NEUTRAL).map((e) => e.code))].sort();
  if (expansions.length > 0 && reductions.length > 0) {
    codes.push("MIXED_CHANGE");
  }

  return Object.freeze({
    classification: expansions.length > 0 ? CLASSIFICATION_EXPANSION : CLASSIFICATION_REDUCTION,
    covenantVersion,
    perField: Object.freeze(perField.map((e) => Object.freeze(e))),
    codes: Object.freeze(codes)
  });
}

/*
 * Covenant migration (recover -> recreate; in-lineage cross-version
 * migration is VM-experiment-proven impossible, docs/covenant-spec-v0.4.md
 * §7). A migration replaces the lineage and MAY replace the authority
 * anchor itself (owner key, recovery authority) — it is ALWAYS an
 * AUTHORITY EXPANSION for governance purposes, whatever the new policy
 * looks like. Unknown versions refuse.
 */
function classifyMigrationDelta({ fromVersion, toVersion } = {}) {
  resolveVersion(fromVersion);
  resolveVersion(toVersion);
  return Object.freeze({
    classification: CLASSIFICATION_EXPANSION,
    fromVersion,
    toVersion,
    perField: Object.freeze([]),
    codes: Object.freeze(["COVENANT_MIGRATION"])
  });
}

module.exports = {
  CLASSIFICATION_REDUCTION,
  CLASSIFICATION_EXPANSION,
  CLASSIFICATIONS,
  DIRECTION_NEUTRAL,
  DIRECTIONS,
  I64_MAX,
  APPROVER_SENTINEL,
  MAX_APPROVERS,
  VERSION_V2,
  VERSION_V3,
  VERSION_V4,
  VERSION_V4_1,
  TUPLE_KEYS,
  AGENT_KEYS,
  NEUTRAL_CLASS,
  GovernanceRefusal,
  governedVersions,
  classifyPolicyDelta,
  classifyMigrationDelta
};
  });

  define("core/governance/index", function (module, exports, require) {
"use strict";

/*
 * PolicyVault post-launch governance core (Program B).
 *
 * Pure, dependency-free classification + canonical-encoding primitives
 * for policy-change governance. Design: docs/postlaunch/governance-spec.md.
 *
 * This package holds NO signing logic, NO storage, NO network access and
 * grants NO authority: covenant financial authority moves only through
 * owner/quorum wallet signatures over frozen transaction bytes, verified
 * by Kaspa consensus. Everything here is coordination logic layered
 * ABOVE that hard boundary.
 */

const canonical = require("./canonical");
const authorityDelta = require("./authority-delta");

module.exports = {
  ...canonical,
  ...authorityDelta
};
  });

  define("core/explain/governance-explain", function (module, exports, require) {
"use strict";

/*
 * PolicyVault governance authority-delta EXPLANATIONS (v1).
 *
 * Turns a core/governance classifier result — classifyPolicyDelta or
 * classifyMigrationDelta — into:
 *
 *   structured(deltaResult)    -> "policyvault-governance-explanation/1"
 *   humanReadable(deltaResult) -> deterministic English lines
 *
 * e.g. "AUTHORITY EXPANSION: per-spend cap increases from 20 to 30 KAS
 * — requires owner/quorum approval …", one line per changed governed
 * field, with mixed/opaque/unknown changes always carried on the
 * EXPANSION side with an explicit warning.
 *
 * FAIL-CLOSED RULES:
 *   - The supplied result is STRICTLY validated (shape, directions,
 *     versions) and its aggregate classification is RECOMPUTED from the
 *     per-field directions; any divergence refuses
 *     (CLASSIFICATION_MISMATCH — the §7.1 integrity-alarm rule: stored
 *     labels are never trusted over recomputation).
 *   - Unknown covenant versions, unknown directions, and malformed
 *     entries refuse. Unknown per-field CODES render generically under
 *     their validated direction (a code never softens a direction).
 *   - Both entry points are TOTAL: they never throw; malformed input
 *     and internal errors produce a REFUSAL explanation.
 *   - Amounts render as exact KAS decimal strings (integer math only);
 *     keys/roots render IN FULL (no truncation).
 *
 * TRUST NOTE (carried in every explanation): this module explains the
 * delta result it is given. Per docs/postlaunch/governance-spec.md §7.1
 * every consumer recomputes classifyPolicyDelta from the proposal's
 * before/after tuples at each decision point — an explanation is a
 * rendering, never an authority.
 *
 * Portable shared core: pure CommonJS, zero external dependencies; the
 * only module dependencies are the public exports of core/governance
 * and the local KAS renderer.
 */

const {
  CLASSIFICATION_REDUCTION,
  CLASSIFICATION_EXPANSION,
  DIRECTION_NEUTRAL,
  governedVersions
} = require("../governance");
const { sompiToKasString } = require("./kas");


function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}

const GOVERNANCE_EXPLANATION_VERSION_1 = "policyvault-governance-explanation/1";

const GOVERNANCE_EXPLANATION_VERDICTS = Object.freeze({
  EXPLAINED: "EXPLAINED",
  REFUSED: "REFUSED"
});

const TRUST_NOTE =
  "This explanation renders a classifier result; it grants nothing. Consumers recompute classifyPolicyDelta from the proposal's before/after tuples at every decision point, and every covenant policy transition still requires the owner's wallet signature over the exact frozen transaction bytes, verified by Kaspa consensus.";

const CEREMONY = Object.freeze({
  [CLASSIFICATION_EXPANSION]:
    "Requires owner/quorum approval — the strongest governance ceremony: the configured governance quorum approves the proposal digest, the delay window elapses, and the owner signs the exact frozen transaction bytes in their wallet.",
  [CLASSIFICATION_REDUCTION]:
    "Safely-restrictive change — available immediately to the vault owner; the owner's wallet signature over the exact frozen transaction bytes is still required."
});

/* Leaf-field units (real covenant/SDK field names). */
const FIELD_UNITS = Object.freeze({
  maxPerSpend: "sompi",
  periodBudget: "sompi",
  approvalThresholdAmount: "sompi",
  approvalThreshold: "sompi",
  agentMaxFeePerTx: "sompi",
  periodSpent: "sompi",
  periodLengthDaa: "daa",
  periodStartDaa: "daa",
  approvalM: "count",
  paused: "flag",
  delegateActive: "flag",
  delegate: "key",
  agentRoot: "root",
  recipientRoot: "root",
  agentRecipientRoot: "root",
  recipients: "keyset",
  approvers: "keyset",
  agents: "keyset"
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isObjectLike(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isCanonicalDigits(v) {
  return typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v);
}

function isHex64(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function leafFieldName(field) {
  const parts = String(field).split(".");
  return parts[parts.length - 1];
}

function unitOf(field) {
  return FIELD_UNITS[leafFieldName(field)] ?? "raw";
}

function refusalDocument(reason, failures) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  return deepFreeze({
    explanationVersion: GOVERNANCE_EXPLANATION_VERSION_1,
    verdict: GOVERNANCE_EXPLANATION_VERDICTS.REFUSED,
    refusal: { reason: String(reason), codes, failures: failures.map((f) => ({ code: String(f.code), detail: String(f.detail) })) },
    kind: null,
    classification: null,
    lane: null,
    covenantVersion: null,
    fromVersion: null,
    toVersion: null,
    mixed: false,
    emergencyFreeze: false,
    headline: null,
    ceremony: null,
    perField: null,
    unchangedCount: null,
    codes: null,
    note: TRUST_NOTE
  });
}

/* ------------------------------------------------------------------ */
/* strict validation of the classifier result                          */
/* ------------------------------------------------------------------ */

/* Returns { kind, problems: [{code, detail}] }. */
function validateDeltaResult(result) {
  const problems = [];
  const push = (code, detail) => problems.push({ code, detail });

  if (!isObjectLike(result)) {
    push("INVALID_DELTA_RESULT", "the delta result must be the object returned by classifyPolicyDelta / classifyMigrationDelta");
    return { kind: null, problems };
  }
  if (result.classification !== CLASSIFICATION_REDUCTION && result.classification !== CLASSIFICATION_EXPANSION) {
    push("UNKNOWN_CLASSIFICATION", `classification ${JSON.stringify(result.classification)} is unknown — failing closed`);
  }
  if (!Array.isArray(result.codes) || result.codes.some((c) => typeof c !== "string")) {
    push("INVALID_DELTA_RESULT", "codes must be an array of strings");
  }
  if (!Array.isArray(result.perField)) {
    push("INVALID_DELTA_RESULT", "perField must be an array");
  }

  const isMigration = Object.prototype.hasOwnProperty.call(result, "fromVersion") || Object.prototype.hasOwnProperty.call(result, "toVersion");
  const versions = governedVersions();
  let kind = null;
  if (isMigration) {
    kind = "covenant-migration";
    if (!versions.includes(result.fromVersion)) push("UNKNOWN_VERSION", `fromVersion ${JSON.stringify(result.fromVersion)} is not a governed covenant version`);
    if (!versions.includes(result.toVersion)) push("UNKNOWN_VERSION", `toVersion ${JSON.stringify(result.toVersion)} is not a governed covenant version`);
    if (result.classification !== CLASSIFICATION_EXPANSION) {
      push("CLASSIFICATION_MISMATCH", "a covenant migration is ALWAYS an authority expansion — a non-EXPANSION migration result is refused");
    }
    if (Array.isArray(result.codes) && !result.codes.includes("COVENANT_MIGRATION")) {
      push("INVALID_DELTA_RESULT", "a migration result must carry the COVENANT_MIGRATION code");
    }
    if (Array.isArray(result.perField) && result.perField.length !== 0) {
      push("INVALID_DELTA_RESULT", "a migration result carries no per-field entries");
    }
  } else {
    kind = "policy-change";
    if (!versions.includes(result.covenantVersion)) {
      push("UNKNOWN_VERSION", `covenantVersion ${JSON.stringify(result.covenantVersion)} is not a governed covenant version — failing closed`);
    }
  }

  if (Array.isArray(result.perField)) {
    result.perField.forEach((entry, i) => {
      if (!isObjectLike(entry)) {
        push("INVALID_DELTA_RESULT", `perField[${i}] must be an object`);
        return;
      }
      if (typeof entry.field !== "string" || entry.field.length === 0) push("INVALID_DELTA_RESULT", `perField[${i}].field must be a non-empty string`);
      if (entry.direction !== CLASSIFICATION_REDUCTION && entry.direction !== CLASSIFICATION_EXPANSION && entry.direction !== DIRECTION_NEUTRAL) {
        push("UNKNOWN_DIRECTION", `perField[${i}].direction ${JSON.stringify(entry.direction)} is unknown — failing closed`);
      }
      if (typeof entry.code !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(entry.code)) {
        push("INVALID_DELTA_RESULT", `perField[${i}].code must be an UPPER_SNAKE code`);
      }
      for (const side of ["before", "after"]) {
        if (Object.prototype.hasOwnProperty.call(entry, side) && entry[side] !== undefined) {
          if (typeof entry[side] !== "string") push("INVALID_DELTA_RESULT", `perField[${i}].${side} must be a string when present`);
        }
      }
      if (Object.prototype.hasOwnProperty.call(entry, "member") && entry.member !== undefined && !isHex64(entry.member)) {
        push("INVALID_DELTA_RESULT", `perField[${i}].member must be 32-byte lowercase hex when present`);
      }
    });

    /* Recompute the aggregate from directions — stored labels are never
     * trusted over recomputation (§7.1 integrity alarm). */
    if (!isMigration && problems.length === 0) {
      const expansions = result.perField.filter((e) => e.direction === CLASSIFICATION_EXPANSION).length;
      const reductions = result.perField.filter((e) => e.direction === CLASSIFICATION_REDUCTION).length;
      if (expansions === 0 && reductions === 0) {
        push("NO_CHANGE", "every per-field entry is neutral — a no-op is not a governable change and cannot be explained as one");
      } else {
        const recomputed = expansions > 0 ? CLASSIFICATION_EXPANSION : CLASSIFICATION_REDUCTION;
        if (recomputed !== result.classification) {
          push(
            "CLASSIFICATION_MISMATCH",
            `stored classification ${result.classification} diverges from the recomputed ${recomputed} — integrity alarm, failing closed`
          );
        }
        const mixed = expansions > 0 && reductions > 0;
        const codesSayMixed = Array.isArray(result.codes) && result.codes.includes("MIXED_CHANGE");
        if (mixed !== codesSayMixed) {
          push("CLASSIFICATION_MISMATCH", "MIXED_CHANGE marker diverges from the per-field directions — integrity alarm, failing closed");
        }
      }
    }
  }
  return { kind, problems };
}

/* ------------------------------------------------------------------ */
/* per-field descriptions                                              */
/* ------------------------------------------------------------------ */

function formatValue(unit, value, field) {
  if (value === null) return null;
  if (unit === "sompi") {
    return isCanonicalDigits(value) ? `${sompiToKasString(value, field)} KAS` : String(value);
  }
  if (unit === "daa") return `DAA ${value}`;
  return String(value);
}

const FIELD_LABELS = Object.freeze({
  maxPerSpend: "per-spend cap",
  periodBudget: "period budget",
  periodLengthDaa: "budget period length",
  periodStartDaa: "budget period start",
  periodSpent: "recorded period spending",
  approvalThresholdAmount: "approval threshold",
  approvalThreshold: "approval threshold",
  agentMaxFeePerTx: "per-transaction fee cap",
  approvalM: "approval quorum",
  paused: "pause flag",
  delegate: "delegate key",
  delegateActive: "delegate activation",
  recipients: "recipient allowlist",
  approvers: "approver set",
  agents: "agent set",
  agentRoot: "agent registry commitment",
  recipientRoot: "recipient allowlist commitment",
  agentRecipientRoot: "recipient allowlist commitment"
});

function fieldLabel(field) {
  const leaf = leafFieldName(field);
  const base = FIELD_LABELS[leaf] ?? leaf;
  const agentMatch = /^agents\[([0-9a-f]{64})\]\./.exec(String(field));
  if (agentMatch) return `agent ${agentMatch[1]} ${base}`;
  return base;
}

/* Deterministic English description of one changed per-field entry.
 * Direction is validated upstream; an unknown CODE renders generically
 * under its validated direction (a code never softens a direction). */
function describeEntry(entry) {
  const unit = unitOf(entry.field);
  const label = fieldLabel(entry.field);
  const before = Object.prototype.hasOwnProperty.call(entry, "before") ? (entry.before ?? null) : null;
  const after = Object.prototype.hasOwnProperty.call(entry, "after") ? (entry.after ?? null) : null;
  const member = Object.prototype.hasOwnProperty.call(entry, "member") ? (entry.member ?? null) : null;
  const b = formatValue(unit, before, `${entry.field}.before`);
  const a = formatValue(unit, after, `${entry.field}.after`);
  const fromTo = b !== null && a !== null ? ` from ${b} to ${a}` : "";

  switch (entry.code) {
    case "EMERGENCY_FREEZE":
      return "Emergency freeze: the vault is paused — all delegated spending stops (break-glass owner action).";
    case "RESUME_SPENDING":
      return "Resume spending: the vault is unpaused — delegated spending becomes possible again.";
    case "DELEGATE_KEY_CHANGED":
      return `Delegate key changes from ${before} to ${after} — a different key gains spending authority.`;
    case "DELEGATE_REVOKED":
      return "Delegate revoked: the delegate key loses spending authority.";
    case "DELEGATE_ENABLED":
      return "Delegate enabled: the delegate key gains spending authority.";
    case "APPROVAL_QUORUM_RAISED":
      return `Approval quorum rises from ${before} to ${after} required approval(s) — more approvals per above-threshold spend.`;
    case "APPROVAL_QUORUM_WEAKENED":
      return `Approval quorum drops from ${before} to ${after} required approval(s) — fewer approvals per above-threshold spend.`;
    case "APPROVAL_THRESHOLD_LOWERED":
    case "AGENT_APPROVAL_THRESHOLD_LOWERED":
      return `The ${label} decreases${fromTo} — MORE spends require approver signatures.`;
    case "APPROVAL_THRESHOLD_RAISED":
    case "AGENT_APPROVAL_THRESHOLD_RAISED":
      return `The ${label} increases${fromTo} — more spends escape the approval tier.`;
    case "PER_SPEND_CAP_LOWERED":
    case "AGENT_PER_SPEND_CAP_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "PER_SPEND_CAP_RAISED":
    case "AGENT_PER_SPEND_CAP_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "PERIOD_BUDGET_LOWERED":
    case "AGENT_PERIOD_BUDGET_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "PERIOD_BUDGET_RAISED":
    case "AGENT_PERIOD_BUDGET_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "PERIOD_LENGTHENED":
    case "AGENT_PERIOD_LENGTHENED":
      return `The ${label} lengthens${fromTo} — the long-run spending rate falls.`;
    case "PERIOD_SHORTENED":
    case "AGENT_PERIOD_SHORTENED":
      return `The ${label} shortens${fromTo} — the budget refreshes faster.`;
    case "AGENT_PERIOD_PHASE_CHANGED":
      return `The ${label} moves${fromTo} — a phase change can open a fresh budget period early, so it is treated as an expansion.`;
    case "AGENT_BUDGET_CONSUMPTION_RECORDED":
      return `The ${label} rises${fromTo} — consumption is recorded (less budget remains).`;
    case "AGENT_BUDGET_REFUNDED":
      return `The ${label} falls${fromTo} — already-consumed budget is refunded (a fresh spending lane this period).`;
    case "AGENT_FEE_CAP_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "AGENT_FEE_CAP_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "RECIPIENT_REMOVED":
    case "AGENT_RECIPIENT_REMOVED":
      return `Recipient ${member} is REMOVED from the ${label}.`;
    case "RECIPIENT_ADDED":
    case "AGENT_RECIPIENT_ADDED":
      return `Recipient ${member} is ADDED to the ${label} — a new key can be paid.`;
    case "APPROVER_REMOVED":
      return `Approver ${member} is REMOVED from the approver set.`;
    case "APPROVER_ADDED":
      return `Approver ${member} is ADDED to the approver set — a new key gains approval authority.`;
    case "AGENT_REMOVED":
      return `Agent ${member} is REMOVED — its key loses all delegated spending authority.`;
    case "AGENT_ADDED":
      return `Agent ${member} is ADDED — a new key gains delegated spending authority.`;
    case "OPAQUE_COMMITMENT_CHANGED":
      return before !== null && after !== null
        ? `The ${label} is replaced OPAQUELY (${before} -> ${after}) — membership cannot be compared, so this is treated as an expansion.`
        : `The ${label} changes in a form whose membership cannot be compared — treated as an expansion.`;
    case "AGENT_SET_OPAQUE":
      return before !== null && after !== null
        ? `The ${label} is replaced OPAQUELY (${before} -> ${after}) — the agent set cannot be compared, so this is treated as an expansion.`
        : `The ${label} changes in a form whose agent set cannot be compared — treated as an expansion.`;
    default: {
      const memberPart = member !== null ? ` member ${member}` : "";
      const valuePart = fromTo !== "" ? fromTo : "";
      return `The ${label}${memberPart} changes${valuePart} (${entry.code}).`;
    }
  }
}

function shortChangeSummary(entry) {
  const unit = unitOf(entry.field);
  const label = fieldLabel(entry.field);
  const hasBoth = typeof entry.before === "string" && typeof entry.after === "string";
  if (hasBoth && (unit === "sompi" || unit === "count" || unit === "daa")) {
    const b = formatValue(unit, entry.before, entry.field);
    const a = formatValue(unit, entry.after, entry.field);
    const verb = entry.direction === CLASSIFICATION_EXPANSION ? "increases" : "decreases";
    if (unit === "daa" || unit === "count") return `${label} changes from ${b} to ${a}`;
    return `${label} ${verb} from ${b} to ${a}`;
  }
  return `${label} changes`;
}

/* ------------------------------------------------------------------ */
/* structured + human-readable                                         */
/* ------------------------------------------------------------------ */

/*
 * Structured governance explanation. TOTAL: never throws; refusal on
 * malformed/inconsistent input.
 */
function structured(deltaResult) {
  try {
    const { kind, problems } = validateDeltaResult(deltaResult);
    if (problems.length > 0) {
      return refusalDocument("The governance delta result is malformed or inconsistent — failing closed.", problems);
    }

    const isMigration = kind === "covenant-migration";
    const changed = isMigration ? [] : deltaResult.perField.filter((e) => e.direction !== DIRECTION_NEUTRAL);
    const expansions = changed.filter((e) => e.direction === CLASSIFICATION_EXPANSION);
    const reductions = changed.filter((e) => e.direction === CLASSIFICATION_REDUCTION);
    const mixed = expansions.length > 0 && reductions.length > 0;
    const emergencyFreeze = !isMigration && changed.some((e) => e.code === "EMERGENCY_FREEZE");

    let headline;
    if (isMigration) {
      headline = `AUTHORITY EXPANSION: covenant migration from ${deltaResult.fromVersion} to ${deltaResult.toVersion} — requires owner/quorum approval.`;
    } else {
      const summary =
        changed.length === 1
          ? shortChangeSummary(changed[0])
          : `${changed.length} governed policy changes (${expansions.length} expansion(s), ${reductions.length} reduction(s))`;
      headline =
        deltaResult.classification === CLASSIFICATION_EXPANSION
          ? `AUTHORITY EXPANSION: ${summary} — requires owner/quorum approval.`
          : `AUTHORITY REDUCTION: ${summary} — owner signature only, available immediately.`;
    }

    const perField = isMigration
      ? []
      : deltaResult.perField.map((entry) => ({
          field: entry.field,
          direction: entry.direction,
          code: entry.code,
          before: typeof entry.before === "string" ? entry.before : null,
          after: typeof entry.after === "string" ? entry.after : null,
          member: typeof entry.member === "string" ? entry.member : null,
          unit: unitOf(entry.field),
          changed: entry.direction !== DIRECTION_NEUTRAL,
          description: entry.direction === DIRECTION_NEUTRAL ? `The ${fieldLabel(entry.field)} is unchanged.` : describeEntry(entry)
        }));

    return deepFreeze({
      explanationVersion: GOVERNANCE_EXPLANATION_VERSION_1,
      verdict: GOVERNANCE_EXPLANATION_VERDICTS.EXPLAINED,
      refusal: null,
      kind,
      classification: deltaResult.classification,
      lane: deltaResult.classification,
      covenantVersion: isMigration ? null : deltaResult.covenantVersion,
      fromVersion: isMigration ? deltaResult.fromVersion : null,
      toVersion: isMigration ? deltaResult.toVersion : null,
      mixed,
      emergencyFreeze,
      headline,
      ceremony: CEREMONY[deltaResult.classification],
      perField,
      unchangedCount: isMigration ? 0 : deltaResult.perField.length - changed.length,
      codes: [...deltaResult.codes],
      note: TRUST_NOTE
    });
  } catch (e) {
    return refusalDocument("The governance explanation engine failed internally — failing closed.", [
      { code: "EXPLAIN_INTERNAL", detail: `${e.message}` }
    ]);
  }
}

function refusalLines(doc) {
  const lines = [];
  lines.push("GOVERNANCE EXPLANATION REFUSED — do not act on this proposal rendering.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  lines.push("Recompute the classification from the proposal's before/after tuples (classifyPolicyDelta) and try again.");
  return lines;
}

/*
 * Deterministic English lines for the governance UI. TOTAL: never
 * throws. Same input -> byte-identical output.
 */
function humanReadable(deltaResult) {
  const doc = structured(deltaResult);
  if (doc.verdict === GOVERNANCE_EXPLANATION_VERDICTS.REFUSED) {
    return deepFreeze(refusalLines(doc));
  }
  const lines = [];
  lines.push(doc.headline);
  if (doc.mixed) {
    lines.push(
      "WARNING: MIXED CHANGE — this proposal contains reductions AND expansions; the whole proposal takes the EXPANSION lane (MIXED_CHANGE)."
    );
  }
  if (doc.kind === "covenant-migration") {
    lines.push("A covenant migration replaces the vault lineage: a terminal ownerRecover, then a new-version create — two owner wallet signatures.");
    lines.push("Between the two steps the funds sit in the owner's own P2PK output (the documented migration custody model).");
    lines.push("Migrations are ALWAYS classified as an authority expansion, however restrictive the new policy looks.");
  } else {
    for (const entry of doc.perField) {
      if (!entry.changed) continue;
      lines.push(`${entry.direction}: ${entry.description}`);
    }
    if (doc.unchangedCount > 0) {
      lines.push(`${doc.unchangedCount} other governed field(s) are unchanged.`);
    }
  }
  if (doc.emergencyFreeze) {
    lines.push("Emergency freeze is a break-glass owner action: no governance configuration may delay, gate, or block it.");
  }
  lines.push(`Ceremony: ${doc.ceremony}`);
  lines.push(doc.note);
  return deepFreeze(lines);
}

module.exports = {
  GOVERNANCE_EXPLANATION_VERSION_1,
  GOVERNANCE_EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
  });

  define("core/explain/risk-explain", function (module, exports, require) {
"use strict";

function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}


/*
 * PolicyVault risk-evaluation EXPLANATIONS (v1).
 *
 * Turns a risk evaluation document — the core/risk `evaluateRisk` result
 * ({ decision, results, codes, config }) or the server's stored/presented
 * evaluation record (server/src/risk.js, schema
 * "policyvault-risk-evaluation/v1": the same four fields plus
 * schema/status/ids) — into:
 *
 *   structured(evaluation)    -> "policyvault-risk-explanation/1"
 *   humanReadable(evaluation) -> deterministic English lines
 *
 * THIS RENDERS; IT NEVER RE-DECIDES RISK. Every line narrates fields the
 * risk pipeline already computed (docs/postlaunch/risk-adapter-spec.md
 * §5.4). Risk adapters are RESTRICTIVE-ONLY hosted coordination: a risk
 * ALLOW authorizes nothing, and no risk verdict can override a policy
 * DENY (core/risk/compose.js applyRiskToPolicyDecision is structurally
 * incapable of it). The covenant remains the only security boundary.
 *
 * FAIL-CLOSED RULES (the governance-explain §7.1 stored-label-distrust
 * pattern, applied to every SELF-CONSISTENCY property of the record
 * that is recomputable from the record itself):
 *   - The composed `decision` is RECOMPUTED from the stored per-adapter
 *     verdicts with the deny-wins fold (DENY > REVIEW > ALLOW); any
 *     divergence refuses (DECISION_MISMATCH — a tampered stored decision
 *     is never narrated).
 *   - The `codes` list is RECOMPUTED (sorted unique reason codes; for an
 *     empty adapter set, [] on ALLOW / ["RISK_ADAPTER_SET_EMPTY"]
 *     otherwise); divergence refuses (CODES_MISMATCH).
 *   - An ERROR/TIMEOUT result whose resolved verdict is ALLOW refuses
 *     (ERROR_PATH_ALLOW — spec §5.2: an erroring control never resolves
 *     permissive); when the composition config is present the resolved
 *     verdict must equal config.onAdapterError.
 *   - A stored lifecycle `status` inconsistent with the decision refuses
 *     (STATUS_MISMATCH: ALLOWED⇔ALLOW, DENIED⇔DENY, REVIEW_HELD/
 *     RELEASED⇔REVIEW, CONSUMED⇔ALLOW|REVIEW).
 *   - Unknown decisions, verdicts, statuses, schema versions, and
 *     malformed entries refuse. Both entry points are TOTAL: they never
 *     throw; malformed input and internal errors produce a REFUSAL
 *     explanation.
 *
 * INTEGRITY BOUNDARY (stated honestly — carried in every explanation):
 * unlike a governance classification, which every consumer recomputes
 * from the proposal's before/after tuples, the per-adapter verdicts are
 * stored EVIDENCE of past adapter executions — they are not
 * re-derivable in this runtime (the adapters ran elsewhere, earlier).
 * What this module verifies is the record's SELF-CONSISTENCY (decision,
 * codes, error semantics, status all recomputed/cross-checked from the
 * per-adapter results); a record forged consistently in every field is
 * not detectable here. The `intent`↔`intentHash` binding is separately
 * re-verified server-side before any released hold is trusted
 * (server/src/risk.js assertEvaluationIntegrity), and none of this is
 * covenant authority: even a fully forged risk record can only
 * coordinate — it cannot move funds past the covenant.
 *
 * Portable shared core: pure CommonJS, zero dependencies (not even
 * core/risk — the verdict vocabulary is mirrored here as frozen
 * constants so the module stays dependency-free in the browser bundle;
 * core/explain/test pins the mirror against core/risk's exports).
 */

const RISK_EXPLANATION_VERSION_1 = "policyvault-risk-explanation/1";

const RISK_EXPLANATION_VERDICTS = Object.freeze({
  EXPLAINED: "EXPLAINED",
  REFUSED: "REFUSED"
});

/* Mirrors of the core/risk vocabulary (pinned by core/explain/test). */
const DECISION_ALLOW = "ALLOW";
const DECISION_REVIEW = "REVIEW";
const DECISION_DENY = "DENY";
const RISK_DECISIONS = Object.freeze([DECISION_ALLOW, DECISION_REVIEW, DECISION_DENY]);
const RESULT_STATUSES = Object.freeze(["OK", "ERROR", "TIMEOUT"]);
const EVALUATION_SCHEMA_V1 = "policyvault-risk-evaluation/v1";
const LIFECYCLE_STATUSES = Object.freeze(["ALLOWED", "DENIED", "REVIEW_HELD", "RELEASED", "CONSUMED"]);
const EMPTY_SET_CODE = "RISK_ADAPTER_SET_EMPTY";

const TRUST_NOTE =
  "This explanation renders a stored risk evaluation; it grants nothing and decides nothing. Risk adapters are restrictive-only hosted coordination: a risk ALLOW never authorizes a spend (the SDK policy preflight and ultimately the Kaspa covenant decide independently), and no risk verdict can override a policy DENY. The composed decision, reason codes, and error semantics were recomputed from the stored per-adapter results before rendering — a divergent record refuses — but the per-adapter verdicts themselves are stored evidence of past adapter executions, not re-derivable in this runtime.";

const HEADLINES = Object.freeze({
  [DECISION_ALLOW]:
    "RISK ALLOW: no configured risk control added a restriction — the operation may proceed to PolicyVault's own policy pipeline (which decides independently).",
  [DECISION_REVIEW]:
    "RISK REVIEW: this operation is held for human review — an authorized reviewer (never the acting signer) must release the EXACT reviewed intent before it can proceed.",
  [DECISION_DENY]:
    "RISK DENY: the organization's risk controls refuse this operation. A denial is final for this evaluation — it cannot be released; if it is wrong, change the organization's risk configuration and submit a fresh request."
});

const STATUS_LINES = Object.freeze({
  ALLOWED: "Evaluation status: ALLOWED — recorded as durable evidence; no hold exists.",
  DENIED: "Evaluation status: DENIED — final for this evaluation.",
  REVIEW_HELD: "Evaluation status: REVIEW_HELD — waiting for an authorized reviewer's release (the acting signer can never release their own hold).",
  RELEASED: "Evaluation status: RELEASED — an authorized reviewer released the exact reviewed intent; it may execute once (a changed intent is a new evaluation).",
  CONSUMED: "Evaluation status: CONSUMED — a real build consumed this evaluation."
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isObjectLike(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isHex64(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

const ADAPTER_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/; // core/risk/interface.js NAME_RE
const REASON_CODE_RE = /^[A-Z0-9_]{1,64}$/; // core/risk/interface.js reason-code rule

function refusalDocument(reason, failures) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  return deepFreeze({
    explanationVersion: RISK_EXPLANATION_VERSION_1,
    verdict: RISK_EXPLANATION_VERDICTS.REFUSED,
    refusal: { reason: String(reason), codes, failures: failures.map((f) => ({ code: String(f.code), detail: String(f.detail) })) },
    decision: null,
    status: null,
    evaluationId: null,
    intentHash: null,
    adapterCount: null,
    errorCount: null,
    reviewRequired: null,
    emptyAdapterSet: null,
    headline: null,
    perAdapter: null,
    codes: null,
    note: TRUST_NOTE
  });
}

/* Pure deny-wins fold — the exact core/risk/compose.js composeVerdicts
 * semantics, re-stated locally so this module stays dependency-free
 * (equality with core/risk is pinned by core/explain/test). Verdicts are
 * validated upstream. */
function denyWins(verdicts) {
  let decision = DECISION_ALLOW;
  for (const v of verdicts) {
    if (v === DECISION_DENY) decision = DECISION_DENY;
    else if (v === DECISION_REVIEW && decision === DECISION_ALLOW) decision = DECISION_REVIEW;
  }
  return decision;
}

/* ------------------------------------------------------------------ */
/* strict validation of the evaluation document                        */
/* ------------------------------------------------------------------ */

/* Returns { problems: [{code, detail}] }. */
function validateEvaluation(evaluation) {
  const problems = [];
  const push = (code, detail) => problems.push({ code, detail });

  if (!isObjectLike(evaluation)) {
    push("INVALID_EVALUATION", "the evaluation must be the object returned by core/risk evaluateRisk or the server's stored risk-evaluation record");
    return { problems };
  }

  if (Object.prototype.hasOwnProperty.call(evaluation, "schema") && evaluation.schema !== EVALUATION_SCHEMA_V1) {
    push("UNKNOWN_SCHEMA_VERSION", `evaluation schema ${JSON.stringify(evaluation.schema)} is unknown — unknown versions fail closed`);
  }
  if (!RISK_DECISIONS.includes(evaluation.decision)) {
    push("UNKNOWN_DECISION", `decision ${JSON.stringify(evaluation.decision)} is unknown — decisions are exactly ${RISK_DECISIONS.join("|")}; failing closed`);
  }
  if (!Array.isArray(evaluation.results)) {
    push("INVALID_EVALUATION", "results must be an array of per-adapter results");
  }
  if (!Array.isArray(evaluation.codes) || evaluation.codes.some((c) => typeof c !== "string")) {
    push("INVALID_EVALUATION", "codes must be an array of strings");
  }

  /* Optional composition config (always present on real producer output;
   * validated strictly when present). */
  let config = null;
  if (evaluation.config !== undefined && evaluation.config !== null) {
    if (!isObjectLike(evaluation.config)) {
      push("INVALID_EVALUATION", "config must be the composition-config object when present");
    } else {
      config = evaluation.config;
      const allowed = new Set(["onAdapterError", "onEmpty", "timeoutMs", "reviewRequired"]);
      for (const k of Object.keys(config)) {
        if (!allowed.has(k)) push("INVALID_EVALUATION", `config has unknown field ${JSON.stringify(k)} — unknown fields fail closed`);
      }
      if (config.onAdapterError !== DECISION_REVIEW && config.onAdapterError !== DECISION_DENY) {
        push("INVALID_EVALUATION", `config.onAdapterError must be REVIEW or DENY (got ${JSON.stringify(config.onAdapterError)}) — an erroring adapter may never resolve to ALLOW`);
      }
      if (!RISK_DECISIONS.includes(config.onEmpty)) {
        push("INVALID_EVALUATION", `config.onEmpty must be one of ${RISK_DECISIONS.join("|")}`);
      }
      if (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > 600000) {
        push("INVALID_EVALUATION", "config.timeoutMs must be an integer in [1, 600000]");
      }
      if (typeof config.reviewRequired !== "boolean") {
        push("INVALID_EVALUATION", "config.reviewRequired must be a boolean");
      }
    }
  }

  /* Optional server-record fields. */
  if (Object.prototype.hasOwnProperty.call(evaluation, "status") && evaluation.status !== undefined && evaluation.status !== null) {
    if (!LIFECYCLE_STATUSES.includes(evaluation.status)) {
      push("UNKNOWN_STATUS", `evaluation status ${JSON.stringify(evaluation.status)} is unknown — statuses are exactly ${LIFECYCLE_STATUSES.join("|")}; failing closed`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "intentHash") && evaluation.intentHash !== undefined && evaluation.intentHash !== null && !isHex64(evaluation.intentHash)) {
    push("INVALID_EVALUATION", "intentHash must be 32-byte lowercase hex when present");
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "evaluationId") && evaluation.evaluationId !== undefined && evaluation.evaluationId !== null && (typeof evaluation.evaluationId !== "string" || evaluation.evaluationId.length === 0 || evaluation.evaluationId.length > 128)) {
    push("INVALID_EVALUATION", "evaluationId must be a non-empty string when present");
  }

  /* Per-adapter results. */
  if (Array.isArray(evaluation.results)) {
    evaluation.results.forEach((r, i) => {
      if (!isObjectLike(r)) {
        push("INVALID_EVALUATION", `results[${i}] must be an object`);
        return;
      }
      if (typeof r.adapter !== "string" || !ADAPTER_NAME_RE.test(r.adapter)) {
        push("INVALID_EVALUATION", `results[${i}].adapter must be an adapter name (/^[a-z0-9][a-z0-9-]{0,63}$/)`);
      }
      if (typeof r.adapterVersion !== "string" || r.adapterVersion.length === 0 || r.adapterVersion.length > 64) {
        push("INVALID_EVALUATION", `results[${i}].adapterVersion must be a non-empty string`);
      }
      if (!RESULT_STATUSES.includes(r.status)) {
        push("UNKNOWN_RESULT_STATUS", `results[${i}].status ${JSON.stringify(r.status)} is unknown — statuses are exactly ${RESULT_STATUSES.join("|")}; failing closed`);
        return; // status-dependent rules below would be meaningless
      }
      if (!RISK_DECISIONS.includes(r.verdict)) {
        push("UNKNOWN_VERDICT", `results[${i}].verdict ${JSON.stringify(r.verdict)} is unknown — verdicts are exactly ${RISK_DECISIONS.join("|")}; failing closed`);
        return;
      }
      if (!Array.isArray(r.reasons)) {
        push("INVALID_EVALUATION", `results[${i}].reasons must be an array`);
        return;
      }
      r.reasons.forEach((reason, j) => {
        if (!isObjectLike(reason)) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}] must be an object`);
          return;
        }
        if (typeof reason.code !== "string" || !REASON_CODE_RE.test(reason.code)) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}].code must match /^[A-Z0-9_]{1,64}$/`);
        }
        if (typeof reason.message !== "string" || reason.message.length === 0 || reason.message.length > 2000) {
          push("INVALID_EVALUATION", `results[${i}].reasons[${j}].message must be a non-empty string (max 2000 chars)`);
        }
      });
      if ((r.verdict === DECISION_REVIEW || r.verdict === DECISION_DENY) && r.reasons.length === 0) {
        push("INVALID_EVALUATION", `results[${i}] carries ${r.verdict} with no reasons — a restriction must be explainable (core/risk contract)`);
      }
      if (r.status === "ERROR" || r.status === "TIMEOUT") {
        if (typeof r.errorCode !== "string" || !REASON_CODE_RE.test(r.errorCode)) {
          push("INVALID_EVALUATION", `results[${i}] is ${r.status} but carries no machine errorCode`);
        }
        if (r.verdict === DECISION_ALLOW) {
          push("ERROR_PATH_ALLOW", `results[${i}] (adapter ${r.adapter}) is ${r.status} yet resolved to ALLOW — an erroring risk control never resolves permissive (risk-adapter-spec §5.2); integrity alarm, failing closed`);
        } else if (config && config.onAdapterError !== undefined && r.verdict !== config.onAdapterError) {
          push("ERROR_POLICY_MISMATCH", `results[${i}] (adapter ${r.adapter}) is ${r.status} and resolved to ${r.verdict}, but the stored error policy is ${config.onAdapterError} — integrity alarm, failing closed`);
        }
      } else if (r.errorCode !== undefined && r.errorCode !== null) {
        push("INVALID_EVALUATION", `results[${i}] is OK but carries an errorCode`);
      }
    });

    /* RECOMPUTE the composed decision and codes — stored labels are never
     * trusted over recomputation (the §7.1 integrity-alarm rule). */
    if (problems.length === 0) {
      let expectedDecision;
      let expectedCodes;
      if (evaluation.results.length === 0) {
        if (!config) {
          push("INVALID_EVALUATION", "an empty-adapter-set evaluation carries no composition config — the onEmpty resolution cannot be cross-checked; failing closed");
        } else {
          expectedDecision = config.onEmpty;
          expectedCodes = config.onEmpty === DECISION_ALLOW ? [] : [EMPTY_SET_CODE];
          if (config.reviewRequired === true && config.onEmpty === DECISION_ALLOW) {
            push("INVALID_EVALUATION", "config declares reviewRequired with onEmpty ALLOW — contradictory configuration the composition core refuses to produce");
          }
        }
      } else {
        expectedDecision = denyWins(evaluation.results.map((r) => r.verdict));
        expectedCodes = [...new Set(evaluation.results.flatMap((r) => r.reasons.map((reason) => reason.code)))].sort();
      }
      if (expectedDecision !== undefined) {
        if (expectedDecision !== evaluation.decision) {
          push(
            "DECISION_MISMATCH",
            `stored decision ${evaluation.decision} diverges from the deny-wins recomputation ${expectedDecision} over the stored per-adapter verdicts — integrity alarm, failing closed`
          );
        }
        if (JSON.stringify(expectedCodes) !== JSON.stringify([...evaluation.codes].sort())) {
          push("CODES_MISMATCH", "stored codes diverge from the codes recomputed from the stored per-adapter reasons — integrity alarm, failing closed");
        }
      }
    }

    /* Lifecycle-status ⇔ decision consistency (server records). */
    if (problems.length === 0 && typeof evaluation.status === "string") {
      const d = evaluation.decision;
      const s = evaluation.status;
      const consistent =
        (s === "ALLOWED" && d === DECISION_ALLOW) ||
        (s === "DENIED" && d === DECISION_DENY) ||
        ((s === "REVIEW_HELD" || s === "RELEASED") && d === DECISION_REVIEW) ||
        (s === "CONSUMED" && (d === DECISION_ALLOW || d === DECISION_REVIEW));
      if (!consistent) {
        push("STATUS_MISMATCH", `stored lifecycle status ${s} is inconsistent with decision ${d} — integrity alarm, failing closed`);
      }
    }
  }

  return { problems };
}

/* ------------------------------------------------------------------ */
/* per-adapter descriptions                                            */
/* ------------------------------------------------------------------ */

function reasonsText(reasons) {
  return reasons.map((r) => `${r.code}: ${r.message}${r.evidence !== undefined ? " [structured evidence attached]" : ""}`).join("; ");
}

function describeResult(r) {
  const who = `Adapter ${r.adapter} (version ${r.adapterVersion})`;
  if (r.status === "OK") {
    if (r.verdict === DECISION_ALLOW) {
      return r.reasons.length === 0
        ? `${who} declined to add a restriction.`
        : `${who} declined to add a restriction — ${reasonsText(r.reasons)}.`;
    }
    return `${who} returned ${r.verdict} — ${reasonsText(r.reasons)}.`;
  }
  const failMode = r.status === "TIMEOUT" ? "TIMED OUT" : "FAILED";
  return `${who} ${failMode} (${r.errorCode}) and was resolved to ${r.verdict} by the organization's error policy — an erroring risk control never resolves to ALLOW. ${reasonsText(r.reasons)}.`;
}

/* ------------------------------------------------------------------ */
/* structured + human-readable                                         */
/* ------------------------------------------------------------------ */

/*
 * Structured risk explanation. TOTAL: never throws; refusal on
 * malformed/self-inconsistent input.
 */
function structured(evaluation) {
  try {
    const { problems } = validateEvaluation(evaluation);
    if (problems.length > 0) {
      return refusalDocument("The risk evaluation is malformed or self-inconsistent — failing closed.", problems);
    }

    const errorCount = evaluation.results.filter((r) => r.status !== "OK").length;
    const perAdapter = evaluation.results.map((r) => ({
      adapter: r.adapter,
      adapterVersion: r.adapterVersion,
      status: r.status,
      verdict: r.verdict,
      errorCode: r.status === "OK" ? null : r.errorCode,
      reasons: r.reasons.map((reason) => ({
        code: reason.code,
        message: reason.message,
        hasEvidence: reason.evidence !== undefined && reason.evidence !== null
      })),
      description: describeResult(r)
    }));

    return deepFreeze({
      explanationVersion: RISK_EXPLANATION_VERSION_1,
      verdict: RISK_EXPLANATION_VERDICTS.EXPLAINED,
      refusal: null,
      decision: evaluation.decision,
      status: typeof evaluation.status === "string" ? evaluation.status : null,
      evaluationId: typeof evaluation.evaluationId === "string" ? evaluation.evaluationId : null,
      intentHash: typeof evaluation.intentHash === "string" ? evaluation.intentHash : null,
      adapterCount: evaluation.results.length,
      errorCount,
      reviewRequired: evaluation.config ? evaluation.config.reviewRequired === true : null,
      emptyAdapterSet: evaluation.results.length === 0,
      headline: HEADLINES[evaluation.decision],
      perAdapter,
      codes: [...evaluation.codes].sort(),
      note: TRUST_NOTE
    });
  } catch (e) {
    return refusalDocument("The risk explanation engine failed internally — failing closed.", [
      { code: "EXPLAIN_INTERNAL", detail: `${e.message}` }
    ]);
  }
}

function refusalLines(doc) {
  const lines = [];
  lines.push("RISK EXPLANATION REFUSED — do not act on this evaluation rendering.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  lines.push(
    "Re-fetch the evaluation from the server; if the divergence persists the stored record is corrupt or tampered — treat it as an integrity alarm and as RESTRICTIVE, never as an ALLOW."
  );
  return lines;
}

/*
 * Deterministic English lines for the risk hold UI. TOTAL: never throws.
 * Same input -> byte-identical output.
 */
function humanReadable(evaluation) {
  const doc = structured(evaluation);
  if (doc.verdict === RISK_EXPLANATION_VERDICTS.REFUSED) {
    return deepFreeze(refusalLines(doc));
  }
  const lines = [];
  lines.push(doc.headline);
  if (doc.status !== null) lines.push(STATUS_LINES[doc.status]);
  if (doc.emptyAdapterSet) {
    lines.push(`No risk adapters were configured for this evaluation — the organization's empty-set policy resolved it to ${doc.decision}.`);
    if (doc.reviewRequired === true) {
      lines.push("This organization requires review (riskPolicy.reviewRequired), so an empty adapter set can never resolve to a silent ALLOW.");
    }
  } else {
    for (const r of doc.perAdapter) {
      lines.push(`${r.verdict}: ${r.description}`);
    }
    lines.push(
      `Composition is deny-wins (DENY over REVIEW over ALLOW) across ${doc.adapterCount} adapter result(s); the composed decision above was recomputed from the stored per-adapter verdicts before rendering — a record whose stored decision diverges refuses to render.`
    );
  }
  if (doc.codes.length > 0) lines.push(`Codes: ${doc.codes.join(", ")}.`);
  if (doc.intentHash !== null) {
    lines.push(
      `Evaluated intent hash: ${doc.intentHash} — a released hold executes only the EXACT intent carrying this hash (the server re-verifies the intent↔hash binding from the stored record before trusting it).`
    );
  }
  lines.push(doc.note);
  return deepFreeze(lines);
}

module.exports = {
  RISK_EXPLANATION_VERSION_1,
  RISK_EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
  });

  var api = Object.freeze({
    require: function (id) { return load(resolveId("core", "./" + id)); },
    intent: load("core/intent/index"),
    explainKas: load("core/explain/kas"),
    intentExplain: load("core/explain/intent-explain"),
    signerErrors: load("core/signer/errors"),
    signerInterface: load("core/signer/interface"),
    recipientMerkle: load("core/model/recipient-merkle-v3"),
    agentMerkle: load("core/model/agent-merkle-v4"),
    computeBudgetV3: load("core/model/compute-budget-v3"),
    computeBudgetV4: load("core/model/compute-budget-v4"),
    feeMass: load("core/model/fee-mass"),
    frozenTx: load("core/model/frozen-tx-v3"),
    vaultStateV4: load("core/model/vault-state-v4"),
    vaultTransitionsV4: load("core/model/vault-transitions-v4"),
    governance: load("core/governance/index"),
    governanceExplain: load("core/explain/governance-explain"),
    riskExplain: load("core/explain/risk-explain")
  });

  if (typeof window !== "undefined") window.PolicyVaultCore = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
