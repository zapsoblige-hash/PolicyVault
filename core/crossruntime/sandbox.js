"use strict";

/*
 * PolicyVault cross-runtime equivalence harness — sandbox loaders.
 *
 * PostLaunchUpgradeOG completion-standard item "cross-runtime equivalence"
 * (docs/postlaunch/COMPLETION_STANDARD.md). This module is TEST-HARNESS
 * infrastructure only (writable scope: core/crossruntime/**) — it never
 * modifies core/intent, core/explain, core/model, core/signer, or web/; it
 * only LOADS their already-committed source text into isolated execution
 * contexts so the test suites in core/crossruntime/test/ can compare
 * outputs byte-for-byte across:
 *
 *   1. Node direct       — plain require() in this process's own realm.
 *   2. Browser bundle     — the COMMITTED web/core-bundle.js, evaluated in a
 *                           fresh vm.Context whose global is named `window`
 *                           (mirrors a real browser tab: window === global)
 *                           and which exposes NOTHING else Node-specific —
 *                           no require, no process, no Buffer, no module.
 *                           This exercises the bundle's ACTUAL browser
 *                           branch (`if (typeof window !== "undefined")
 *                           window.PolicyVaultCore = api;`), not the
 *                           CommonJS `module.exports` escape hatch a plain
 *                           `require("../core-bundle.js")` would use.
 *   3. Core-model probe   — an analogous vm.Context used to execute
 *                           EXPLICIT, individually-named core/model source
 *                           files that are NOT (yet) part of the reviewed
 *                           web/core-bundle.js MODULES list, to test
 *                           whether they WOULD already run unmodified in a
 *                           browser-like environment (forward-looking
 *                           portability probe, not a claim about the
 *                           shipped bundle).
 *
 * Why vm.Context and not a plain `global.window = global` trick: a fresh
 * V8 context gives each probe its OWN intrinsics (Object.prototype,
 * Array, RegExp, ...), which is the closest a single Node process can get
 * to "a different runtime" without an actual second JS engine. That
 * fidelity has one cost callers must respect: a plain object/array
 * RETURNED from sandboxed code is NOT `instanceof`/deepStrictEqual
 * compatible with a host-realm literal of the same shape (Node's
 * assert.deepStrictEqual checks prototype identity). `rehome()` below
 * converts a sandboxed value into an ordinary host-realm JSON value so
 * comparisons are meaningful; see its doc comment for the (real, checked)
 * finding this produced about core/intent's own canonicalJsonStringify.
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const nodeCrypto = require("crypto");

const { CRYPTO_SHIM } = require("../../web/tools/build-core-bundle.js");

const REPO_ROOT = path.join(__dirname, "..", "..");
const BUNDLE_PATH = path.join(REPO_ROOT, "web", "core-bundle.js");

/*
 * A fresh vm.Context shaped like a browser global scope: `window` and
 * `globalThis` both refer to the context's own global object (as in a
 * real tab), and `crypto.getRandomValues` is backed by Node's WebCrypto
 * (the same interface `web/tools/build-core-bundle.js`'s CRYPTO_SHIM
 * expects) — but `require`, `module`, `process`, and `Buffer` are all
 * deliberately ABSENT, since none exist in a real browser page.
 */
function makeBrowserGlobal() {
  const sandbox = {};
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.crypto = {
    getRandomValues(typedArray) {
      return nodeCrypto.webcrypto.getRandomValues(typedArray);
    }
  };
  vm.createContext(sandbox);
  return sandbox;
}

/*
 * Load the COMMITTED web/core-bundle.js into a fresh browser-like
 * context and return { global, PolicyVaultCore }. This is the "browser
 * bundle" runtime for every cross-runtime comparison in this suite.
 */
function loadCommittedBundleInBrowserGlobal() {
  const source = fs.readFileSync(BUNDLE_PATH, "utf8");
  const sandboxGlobal = makeBrowserGlobal();
  new vm.Script(source, { filename: BUNDLE_PATH }).runInContext(sandboxGlobal);
  if (!sandboxGlobal.PolicyVaultCore) {
    throw new Error("sandbox: web/core-bundle.js did not populate window.PolicyVaultCore — the browser branch did not run");
  }
  return { global: sandboxGlobal, PolicyVaultCore: sandboxGlobal.PolicyVaultCore };
}

/*
 * Load an EXPLICIT, closed set of repo-relative core/*.js source files
 * into one fresh browser-like vm.Context, wiring their own relative
 * require() calls to each other and mapping require("crypto"/"node:crypto")
 * to the exact CRYPTO_SHIM the real bundle generator embeds (byte-for-
 * byte the same shim source real browsers already run). This is a
 * generalization of web/tools/build-core-bundle.js's own loader technique
 * to an arbitrary explicit module list, used ONLY to PROBE portability of
 * core/model files the real bundle does not (yet) embed — it is not a
 * second bundle generator and nothing it produces is shipped.
 *
 * Requiring anything outside `relPaths` (or "crypto"/"node:crypto")
 * throws immediately (fail closed, mirrors the real loader). A module
 * whose top-level code touches a Node-only global that this sandbox does
 * NOT provide (e.g. `Buffer`) throws a plain ReferenceError from V8
 * itself — that is a genuine, intentional signal this harness preserves
 * rather than papering over (see core/crossruntime/test/
 * core-model-portability.test.js).
 */
function loadCoreFilesInSandbox(relPaths) {
  const sandboxGlobal = makeBrowserGlobal();
  const factories = {};
  const cache = {};

  const cryptoWrapped = `(function (module, exports, require) {\n${CRYPTO_SHIM}\n})`;
  factories.crypto = new vm.Script(cryptoWrapped, { filename: "core-crossruntime-sandbox:crypto-shim.js" }).runInContext(sandboxGlobal);

  const toId = (relPath) => relPath.replace(/\.js$/, "");

  for (const relPath of relPaths) {
    const id = toId(relPath);
    const abs = path.join(REPO_ROOT, relPath);
    const code = fs.readFileSync(abs, "utf8");
    const wrapped = `(function (module, exports, require) {\n${code}\n})`;
    factories[id] = new vm.Script(wrapped, { filename: abs }).runInContext(sandboxGlobal);
  }

  function resolveId(fromId, request) {
    if (request === "crypto" || request === "node:crypto") return "crypto";
    if (!request.startsWith(".")) {
      throw new Error(`core-crossruntime sandbox: bare module ${JSON.stringify(request)} (from ${fromId}) is not "crypto" and is refused — failing closed`);
    }
    const base = fromId.split("/").slice(0, -1);
    const segments = base.concat(request.split("/"));
    const out = [];
    for (const seg of segments) {
      if (seg === "" || seg === ".") continue;
      if (seg === "..") {
        if (out.length === 0) throw new Error(`core-crossruntime sandbox: path escape in require ${JSON.stringify(request)} (from ${fromId})`);
        out.pop();
        continue;
      }
      out.push(seg);
    }
    const id = out.join("/").replace(/\.js$/, "");
    if (factories[id]) return id;
    throw new Error(
      `core-crossruntime sandbox: module ${JSON.stringify(request)} (from ${fromId}) resolves to ${JSON.stringify(id)}, which is outside this probe's explicit file list — failing closed`
    );
  }

  function load(id) {
    if (cache[id]) return cache[id].exports;
    const mod = { exports: {} };
    cache[id] = mod; // set before invoking factory, matching Node's own require cycle handling
    try {
      factories[id](mod, mod.exports, (request) => load(resolveId(id, request)));
    } catch (e) {
      /* EVICT on failure — a module whose top-level code throws (e.g. a
       * ReferenceError from touching a Node-only global this sandbox does
       * not provide) must NOT be left in the cache as an empty exports
       * stub, or a module that transitively requires it would silently
       * destructure `undefined` members from that stub instead of
       * re-observing the real failure (verified directly: without this
       * eviction, core/model/vault-transitions-v4.js appeared to "load
       * successfully" with its agent-merkle-v4 imports silently
       * undefined, after agent-merkle-v4 itself had already failed once
       * in the same sandbox). Node's own require() evicts on throw for
       * the same reason; this mirrors that.
       */
      delete cache[id];
      throw e;
    }
    return mod.exports;
  }

  return {
    global: sandboxGlobal,
    /* Load (or fetch from cache) one of the explicitly provided files by
     * its repo-relative path, e.g. "core/model/amounts.js". Executes the
     * module's top-level code on first call (same as Node's own
     * require()) — a file whose top-level code touches a Node-only
     * global this sandbox does not provide (e.g. `Buffer`) throws HERE,
     * as a plain ReferenceError, not at sandbox-construction time. */
    require(relPath) {
      const id = toId(relPath);
      if (!factories[id]) {
        throw new Error(`core-crossruntime sandbox: ${JSON.stringify(relPath)} was not passed to loadCoreFilesInSandbox() — nothing to load`);
      }
      return load(id);
    }
  };
}

/*
 * Re-home a value produced by vm-sandboxed code into ordinary HOST-realm
 * JSON data (plain objects/arrays/strings/numbers/booleans/null with
 * Object.prototype/Array.prototype from THIS realm).
 *
 * Why this is necessary (a real, reproduced finding, not a hypothetical):
 * a vm.Context gives sandboxed code its OWN Object/Array/RegExp
 * intrinsics. A plain object literal `{}` built inside the sandbox has
 * `Object.getPrototypeOf(x) === sandboxRealm.Object.prototype`, which is
 * NOT reference-equal to the host realm's `Object.prototype` — even
 * though the object is, by every structural measure, a plain JSON-safe
 * object. Two consequences were verified directly against this
 * repository's own code before writing this comment:
 *   - node:assert's deepStrictEqual refuses such values ("Values have
 *     same structure but are not reference-equal"), so cross-realm
 *     structural comparisons need re-homed inputs;
 *   - core/intent/canonical.js's OWN canonicalJsonStringify (and its
 *     core/model/canonical-json.js twin) THROW on a raw cross-realm
 *     plain object ("non-plain object at $ — refusing to canonicalize"),
 *     because their plain-object check is `Object.getPrototypeOf(v) !==
 *     Object.prototype` against the CALLER's Object.prototype. This is
 *     documented precisely in docs/postlaunch/cross-runtime-
 *     equivalence.md as a latent (not currently live — PolicyVault's
 *     browser code runs in exactly one realm today) portability caveat,
 *     not a bug in those files: refusing an object of ambiguous
 *     provenance is the correct fail-closed behavior for a commitment
 *     preimage. This helper exists ONLY to correct for the artificial
 *     multi-realm nature of vm-based testing, mirroring what already
 *     happens for free inside one real browser tab (there is only ever
 *     one realm there, so canonicalJsonStringify never sees this case in
 *     production).
 *
 * Every value this suite re-homes is already JSON-safe by construction
 * (manifests/explain docs/descriptors carry canonical digit strings, not
 * BigInt; see core/intent/canonical.js's own "BigInt is not JSON" rule),
 * so a JSON round-trip is lossless here. Callers with a raw BigInt or
 * Buffer/Uint8Array result must render it to a string themselves first.
 */
function rehome(value) {
  return JSON.parse(JSON.stringify(value));
}

/*
 * The mirror-image helper: re-home a HOST-realm JSON-safe value INTO a
 * given sandbox realm, so sandboxed validation code that checks
 * `Object.getPrototypeOf(v) === Object.prototype` (core/intent/manifest.js
 * `isPlainObject`, both canonicalJsonStringify implementations, ...)
 * accepts it as a genuine plain object of ITS OWN realm rather than
 * refusing it as "non-plain" — the same realm-identity fact `rehome()`
 * documents, applied in the opposite direction. `JSON.stringify` is
 * realm-agnostic (structural, not prototype-based), so only the PARSE
 * side needs to run inside the target realm.
 *
 * Implementation note: a vm-contextified global object does NOT expose
 * its intrinsics (JSON, Object, Array, ...) as ordinary OWN properties
 * readable from the host side — `targetGlobal.JSON` is `undefined` even
 * though bare `JSON` resolves fine INSIDE a script run in that context
 * (verified directly against this Node version before relying on it).
 * The one reliable way to obtain a host-side reference to a realm's own
 * intrinsic is to evaluate the bare identifier as a tiny script IN that
 * context, which is what this does.
 */
function rehomeInto(targetGlobal, value) {
  const targetJSON = new vm.Script("JSON", { filename: "core-crossruntime-sandbox:json-bridge.js" }).runInContext(targetGlobal);
  return targetJSON.parse(JSON.stringify(value));
}

module.exports = {
  REPO_ROOT,
  BUNDLE_PATH,
  makeBrowserGlobal,
  loadCommittedBundleInBrowserGlobal,
  loadCoreFilesInSandbox,
  rehome,
  rehomeInto
};
