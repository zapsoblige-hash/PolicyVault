"use strict";

/*
 * PolicyVault browser core-bundle generator (PostLaunchUpgradeOG, browser
 * verification wave).
 *
 * Produces web/core-bundle.js: a DETERMINISTIC, dependency-free browser
 * packaging of the portable shared-core modules the browser needs for
 * independent pre-sign verification (core/intent), signing-screen
 * explanations (core/explain), and the Universal Signer Interface
 * (core/signer). The core sources are embedded VERBATIM — never rewritten,
 * transformed, minified, or re-ordered — inside a tiny CommonJS loader, so
 * the browser executes byte-identical core code to Node.
 *
 * DETERMINISM CONTRACT (reproducible-build rule): same input bytes =>
 * same output bytes. No timestamps, no absolute paths, no environment
 * data, no randomness. The bundle header records the sha256 of every
 * embedded source so any reviewer can re-derive and byte-compare.
 * web/test/core-bundle.test.js regenerates the bundle and asserts the
 * committed file is byte-identical, and asserts behavioral equivalence
 * against the real core modules.
 *
 * NO external bundlers, NO npm dependencies: node builtins only.
 *
 * Usage:  node web/tools/build-core-bundle.js          (write the bundle)
 *         node web/tools/build-core-bundle.js --check  (verify, exit 1 on drift)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO_ROOT = path.join(__dirname, "..", "..");
const OUT_PATH = path.join(REPO_ROOT, "web", "core-bundle.js");

/*
 * The CLOSED module list, in fixed order. Module ids mirror the repo
 * paths (extension dropped). Adding a module is an explicit, reviewed
 * change here — the loader refuses every id not in this list (fail
 * closed: nothing outside the reviewed set can be required).
 */
const MODULES = [
  "core/intent/canonical.js",
  "core/intent/manifest.js",
  "core/intent/verify.js",
  "core/intent/index.js",
  "core/explain/kas.js",
  "core/explain/intent-explain.js",
  "core/signer/errors.js",
  "core/signer/interface.js",
  /* F1 browser-portability wave: the byte-native Merkle modules + their
   * core/model dependency closure, for independent in-browser recipient/
   * agent Merkle-root recomputation (web/verify-intent.js). */
  "core/model/amounts.js",
  "core/model/contract-version.js",
  "core/model/vault-state.js",
  "core/model/recipient-merkle-v3.js",
  "core/model/agent-merkle-v4.js",
  /* Fee/mass + successor-state recomputation wave: the EXACT modules the
   * SDK builders use for consensus fee/mass accounting
   * (calculateRequiredFee over feeDescriptorFromFrozen — the identical
   * call path of sdk/src/vault-builders-v4.js exactFee), the proven-safe
   * compute-budget tiers the SDK commits, and the canonical v0.4
   * state-serialization/transition modules, so web/verify-intent.js can
   * independently recompute fees, committed budgets, successor states,
   * and state ids instead of adopting server claims. compute-budget-v3
   * is included for portable-core completeness (no v0.3 browser verifier
   * exists; unknown versions still fail closed). */
  "core/model/compute-budget-v3.js",
  "core/model/compute-budget-v4.js",
  "core/model/fee-mass.js",
  "core/model/frozen-tx-v3.js",
  "core/model/vault-state-v4.js",
  "core/model/vault-transitions-v4.js",
  /* Residuals wave: the deterministic governance authority-delta
   * EXPLANATION renderer (core/explain/governance-explain.js) + its
   * dependency closure (core/governance). web/gov-risk-explain.js's
   * explainGovernance() seam prefers window.PolicyVaultCore
   * .governanceExplain the instant it exists — bundling it activates the
   * portable renderer (strict validation + aggregate-classification
   * recomputation: a tampered stored label now REFUSES loudly in the
   * browser instead of being narrated). NOTE core/governance/canonical.js
   * is bundled ONLY as index.js's dependency closure: its
   * governanceProposalDigest uses Buffer.from and therefore FAILS CLOSED
   * (throws) in the Buffer-free browser runtime — pinned by
   * core/crossruntime/test/bundle-anti-drift.test.js; the explain path
   * never calls it, and a thrown error is never a wrong digest. */
  "core/governance/canonical.js",
  "core/governance/authority-delta.js",
  "core/governance/index.js",
  "core/explain/governance-explain.js",
  /* W4-refinements: the deterministic risk-evaluation EXPLANATION
   * renderer (core/explain/risk-explain.js) — dependency-free by
   * construction (its verdict vocabulary mirrors core/risk as frozen
   * constants; the mirror is pinned by core/explain/test). Bundling it
   * activates web/gov-risk-explain.js's explainRisk() seam
   * (window.PolicyVaultCore.riskExplain): the browser renders risk holds
   * through the strict portable renderer, which RECOMPUTES the composed
   * decision/codes from the stored per-adapter results and refuses
   * self-inconsistent records (DECISION_MISMATCH etc.) instead of
   * narrating them. */
  "core/explain/risk-explain.js"
];

/*
 * Browser substitute for the ONE Node builtin the embedded core modules
 * use: require("crypto"), and of it only
 *   - createHash("sha256").update(<string>, "utf8").digest("hex")
 *     (core/intent/canonical.js sha256Hex; core/model/vault-state*.js
 *     state ids),
 *   - createHash("sha256").update(<Uint8Array>).digest()  ->  Uint8Array
 *     (the byte-native core/model Merkle modules recipient-merkle-v3 /
 *     agent-merkle-v4 — F1 browser-portability wave), and
 *   - randomBytes(16).toString("hex")
 *     (core/signer/interface.js newRequestId).
 * WebCrypto digest is Promise-only, so sha256 is a pure-JS synchronous
 * FIPS 180-4 implementation; its equality with Node's crypto is pinned by
 * golden vectors in web/test/core-bundle.test.js (string AND byte
 * vectors). Everything outside this exact surface FAILS CLOSED (unknown
 * algorithm, unknown encoding, an encoding on a byte update, non-string/
 * non-Uint8Array input, unknown digest format) — the shim never silently
 * degrades a hash.
 */
const CRYPTO_SHIM = `"use strict";
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
`;

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function moduleId(relPath) {
  return relPath.replace(/\.js$/, "");
}

function generateBundle() {
  const sources = MODULES.map((relPath) => {
    const abs = path.join(REPO_ROOT, relPath);
    const code = fs.readFileSync(abs, "utf8");
    return { relPath, id: moduleId(relPath), code, sha256: sha256Hex(code) };
  });

  const header = [
    "/*",
    " * PolicyVault browser core bundle — GENERATED FILE, do not edit by hand.",
    " * Generator: web/tools/build-core-bundle.js (committed; deterministic:",
    " * same input bytes => same bundle bytes; regenerate + byte-compare with",
    " * `node web/tools/build-core-bundle.js --check`).",
    " *",
    " * Embedded portable shared-core sources, VERBATIM (sha256 of each):",
    ...sources.map((s) => ` *   ${s.relPath}  sha256:${s.sha256}`),
    ` *   <crypto shim>  sha256:${sha256Hex(CRYPTO_SHIM)}`,
    " */"
  ].join("\n");

  const parts = [];
  parts.push(header);
  parts.push("(function (globalScope) {");
  parts.push('  "use strict";');
  parts.push("  var factories = {};");
  parts.push("  var cache = {};");
  parts.push("");
  parts.push("  function define(id, factory) { factories[id] = factory; }");
  parts.push("");
  parts.push("  /* Resolve a require request against the requesting module id.");
  parts.push("   * CLOSED module set: anything unresolvable throws (fail closed). */");
  parts.push("  function resolveId(fromId, request) {");
  parts.push('    if (request === "crypto" || request === "node:crypto") return "crypto";');
  parts.push('    var base = request.charAt(0) === "." ? fromId.split("/").slice(0, -1) : [];');
  parts.push('    var segments = base.concat(request.split("/"));');
  parts.push("    var out = [];");
  parts.push("    for (var i = 0; i < segments.length; i++) {");
  parts.push("      var seg = segments[i];");
  parts.push('      if (seg === "" || seg === ".") continue;');
  parts.push('      if (seg === "..") { if (out.length === 0) throw new Error("core-bundle: path escape in require " + JSON.stringify(request)); out.pop(); continue; }');
  parts.push("      out.push(seg);");
  parts.push("    }");
  parts.push('    var id = out.join("/").replace(/\\.js$/, "");');
  parts.push("    if (factories[id]) return id;");
  parts.push('    if (factories[id + "/index"]) return id + "/index";');
  parts.push('    throw new Error("core-bundle: module " + JSON.stringify(request) + " (from " + fromId + ") is not in the bundled module set — failing closed");');
  parts.push("  }");
  parts.push("");
  parts.push("  function load(id) {");
  parts.push("    if (cache[id]) return cache[id].exports;");
  parts.push("    var module = { exports: {} };");
  parts.push("    cache[id] = module;");
  parts.push("    factories[id](module, module.exports, function (request) { return load(resolveId(id, request)); });");
  parts.push("    return module.exports;");
  parts.push("  }");
  parts.push("");
  parts.push('  define("crypto", function (module, exports, require) {');
  parts.push(CRYPTO_SHIM.replace(/\n$/, ""));
  parts.push("  });");
  for (const s of sources) {
    parts.push("");
    parts.push(`  define(${JSON.stringify(s.id)}, function (module, exports, require) {`);
    parts.push(s.code.replace(/\n$/, ""));
    parts.push("  });");
  }
  parts.push("");
  parts.push("  var api = Object.freeze({");
  parts.push('    require: function (id) { return load(resolveId("core", "./" + id)); },');
  parts.push('    intent: load("core/intent/index"),');
  parts.push('    explainKas: load("core/explain/kas"),');
  parts.push('    intentExplain: load("core/explain/intent-explain"),');
  parts.push('    signerErrors: load("core/signer/errors"),');
  parts.push('    signerInterface: load("core/signer/interface"),');
  parts.push('    recipientMerkle: load("core/model/recipient-merkle-v3"),');
  parts.push('    agentMerkle: load("core/model/agent-merkle-v4"),');
  parts.push('    computeBudgetV3: load("core/model/compute-budget-v3"),');
  parts.push('    computeBudgetV4: load("core/model/compute-budget-v4"),');
  parts.push('    feeMass: load("core/model/fee-mass"),');
  parts.push('    frozenTx: load("core/model/frozen-tx-v3"),');
  parts.push('    vaultStateV4: load("core/model/vault-state-v4"),');
  parts.push('    vaultTransitionsV4: load("core/model/vault-transitions-v4"),');
  parts.push('    governance: load("core/governance/index"),');
  parts.push('    governanceExplain: load("core/explain/governance-explain"),');
  parts.push('    riskExplain: load("core/explain/risk-explain")');
  parts.push("  });");
  parts.push("");
  parts.push('  if (typeof window !== "undefined") window.PolicyVaultCore = api;');
  parts.push('  if (typeof module !== "undefined" && module.exports) module.exports = api;');
  parts.push("})(typeof globalThis !== \"undefined\" ? globalThis : this);");
  parts.push("");
  return parts.join("\n");
}

function main() {
  const bundle = generateBundle();
  const check = process.argv.includes("--check");
  if (check) {
    const existing = fs.existsSync(OUT_PATH) ? fs.readFileSync(OUT_PATH, "utf8") : null;
    if (existing !== bundle) {
      process.stderr.write("core-bundle DRIFT: web/core-bundle.js does not match a deterministic regeneration from the core sources\n");
      process.exit(1);
    }
    process.stdout.write("core-bundle OK: byte-identical regeneration\n");
    return;
  }
  fs.writeFileSync(OUT_PATH, bundle);
  process.stdout.write(`wrote ${path.relative(REPO_ROOT, OUT_PATH)} (${bundle.length} bytes)\n`);
}

if (require.main === module) main();
module.exports = { MODULES, generateBundle, CRYPTO_SHIM, OUT_PATH };
