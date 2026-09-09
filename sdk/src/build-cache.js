"use strict";

/*
 * BOUNDED, LIFECYCLE-SAFE compiled-artifact cache (rc11 internal security
 * review F-03, 2026-09-04; owner addendum §D cleanup-safety rules).
 *
 * Every generation's compiler (contract-compiler*.js, token-program-kcc20.js,
 * swap-pool-fixture-v6.js) materialises one directory per exact covenant
 * state under `<dataRoot>/build-<gen>/<stateId>/` holding the deterministic
 * state source, its constructor args, and silverc's artifact.json. The
 * audit showed the artifact alone was ~2 MB (AST + debug info that NO
 * consumer reads) and that nothing ever reclaimed an entry, so ~120
 * unauthenticated genesis builds filled the 256 MB production data tmpfs
 * (ENOSPC for every later build until restart).
 *
 * WHAT THIS MODULE GUARANTEES
 *  1. `minimizeArtifactFile` keeps ONLY the four keys every consumer reads
 *     (contract_name, compiler_version, script, state_layout) — the
 *     consensus-visible bytes (`script`) and layout are untouched; the
 *     rewrite is atomic (tmp + rename) and idempotent.
 *  2. `enforceBuildCacheBound` keeps the WHOLE cache (all `build*` subdirs
 *     together) under `config.buildCache.maxEntries` AND `maxBytes`,
 *     evicting least-recently-USED entries first (mtime; a cache hit
 *     touches the entry via `touchCacheEntry`). Entries used within
 *     `graceMs` are never evicted (a concurrent in-flight build keeps its
 *     files); if the cap cannot be met without touching in-grace entries
 *     the NEW build is refused fail-closed (BUILD_CACHE_FULL) — availability
 *     degrades to a closed refusal, never to ENOSPC.
 *  3. The cache is a PURE CACHE: nothing durable references it as the only
 *     copy of anything. Every request build carries `template`, `stateJson`
 *     and `contractVersion`, so `ensureBuildDir` can deterministically
 *     RECOMPILE an evicted entry at finalize time and asserts the recompiled
 *     directory is byte-for-byte the one the build named (stateId equality;
 *     any mismatch fails closed). A legitimate pending flow therefore
 *     survives eviction; only CPU is spent. Cleanup never touches durable
 *     requests, claims, receipts, manifests or chain truth, cannot turn an
 *     ambiguous submission into a retry, and removes no reconciliation
 *     evidence — none of that lives here.
 *  4. A hostile client cannot keep unlimited storage alive: only a real
 *     (re)compile of an OWN-property-resolved state touches an entry, each
 *     distinct state is one bounded entry, and the global caps win.
 *
 * Idempotence: running the bound twice in a row evicts nothing the second
 * time; minimizing a minimal artifact is a no-op.
 */

const fs = require("fs");
const path = require("path");

const DEFAULT_MAX_ENTRIES = 256;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_GRACE_MS = 120_000;
const ARTIFACT_KEEP = Object.freeze(["contract_name", "compiler_version", "script", "state_layout"]);
const CACHE_SUBDIR_RE = /^build(-[A-Za-z0-9_.-]+)?$/;

function fail(message, code) {
  const e = new Error(`build-cache: ${message}`);
  e.code = code;
  throw e;
}

function limitsOf(config) {
  const bc = (config && config.buildCache) || {};
  return {
    maxEntries: Number.isInteger(bc.maxEntries) ? bc.maxEntries : DEFAULT_MAX_ENTRIES,
    maxBytes: Number.isInteger(bc.maxBytes) ? bc.maxBytes : DEFAULT_MAX_BYTES,
    graceMs: Number.isInteger(bc.graceMs) ? bc.graceMs : DEFAULT_GRACE_MS
  };
}

/* Rewrite artifact.json to the minimal consumer set. Returns true if rewritten. */
function minimizeArtifactFile(artifactPath, config = null) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  } catch {
    return false; // the compiler validates/refuses corrupt artifacts itself
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const keys = Object.keys(raw);
  if (keys.every((k) => ARTIFACT_KEEP.includes(k))) return false; // already minimal
  const min = {};
  for (const k of ARTIFACT_KEEP) if (Object.prototype.hasOwnProperty.call(raw, k)) min[k] = raw[k];
  const tmp = `${artifactPath}.min.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(min), { mode: 0o600 });
  fs.renameSync(tmp, artifactPath);
  /* rc12 review R-07: the byte cap was enforced BEFORE the artifact size was known;
   * enforce it again now that this entry's real size is on disk (LRU, grace-aware,
   * this entry kept), so the cache never persistently exceeds maxBytes. */
  if (config) {
    try {
      enforceBuildCacheBound(config, { keep: path.dirname(artifactPath) });
    } catch (error) {
      if (!(error && error.code === "BUILD_CACHE_FULL")) throw error; // one oversized in-grace neighbour: transient by design, bounded by one artifact
    }
  }
  return true;
}

/* Cache hit: mark the entry as recently used (LRU). Never throws. */
function touchCacheEntry(artifactPath) {
  try {
    const now = new Date();
    fs.utimesSync(artifactPath, now, now);
  } catch {
    /* read-only or vanished: the bound treats it by its old mtime */
  }
}

/* Enumerate every entry of every `build*` subdir under the data root. */
function listCacheEntries(dataRoot) {
  const out = [];
  let subdirs;
  try {
    subdirs = fs.readdirSync(dataRoot, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const sd of subdirs) {
    if (!sd.isDirectory() || !CACHE_SUBDIR_RE.test(sd.name)) continue;
    const subdirPath = path.join(dataRoot, sd.name);
    let entries;
    try {
      entries = fs.readdirSync(subdirPath, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      const dir = path.join(subdirPath, ent.name);
      let bytes = 0;
      let mtimeMs = 0;
      try {
        for (const f of fs.readdirSync(dir)) {
          const st = fs.statSync(path.join(dir, f));
          if (!st.isFile()) continue;
          bytes += st.size;
          if (st.mtimeMs > mtimeMs) mtimeMs = st.mtimeMs;
        }
        if (mtimeMs === 0) mtimeMs = fs.statSync(dir).mtimeMs;
      } catch {
        continue;
      }
      out.push({ subdir: sd.name, name: ent.name, dir, bytes, mtimeMs });
    }
  }
  return out;
}

/*
 * Make room for ONE new entry at `keep` (the build dir about to be compiled;
 * its already-written source/args count toward the totals). Deterministic:
 * evicts strictly least-recently-used entries outside the grace window
 * until both caps hold; refuses (fail closed) if that is impossible.
 * Returns { evicted, entries, bytes }.
 */
function enforceBuildCacheBound(config, { keep, nowMs = Date.now(), force = false } = {}) {
  if (!config || typeof config.dataRoot !== "string") return { evicted: 0, entries: 0, bytes: 0 };
  const { maxEntries, maxBytes, graceMs } = limitsOf(config);
  const keepAbs = keep ? path.resolve(keep) : null;
  const all = listCacheEntries(config.dataRoot);
  const keepEntry = keepAbs ? all.find((e) => path.resolve(e.dir) === keepAbs) : null;
  const others = all.filter((e) => e !== keepEntry);
  let count = others.length + 1; // the entry being (re)built
  let bytes = others.reduce((a, e) => a + e.bytes, 0) + (keepEntry ? keepEntry.bytes : 0);
  let evicted = 0;
  if (count > maxEntries || bytes > maxBytes) {
    /* `force` (rc12 review R-03): a FINALIZE-time recompile of an already-built
     * request may evict least-recently-used entries INSIDE the grace window —
     * the grace only protects concurrent fresh builds from each other; a
     * saturated cache must never turn a legitimate pending flow into a
     * BUILD_CACHE_FULL refusal (the evicted entry recompiles at its own
     * finalize). New builds keep the grace rule. */
    /* rc13 review N-03: even in force mode an IN-PROGRESS entry (source/args
     * written, artifact.json not yet produced, still inside the grace window)
     * belongs to a build another process is running — never delete it. */
    const inProgress = (e) => nowMs - e.mtimeMs < graceMs && !fs.existsSync(path.join(e.dir, "artifact.json"));
    const victims = others.filter((e) => nowMs - e.mtimeMs >= graceMs || (force && !inProgress(e))).sort((a, b) => a.mtimeMs - b.mtimeMs);
    for (const v of victims) {
      if (count <= maxEntries && bytes <= maxBytes) break;
      try {
        fs.rmSync(v.dir, { recursive: true, force: true });
      } catch {
        continue;
      }
      count -= 1;
      bytes -= v.bytes;
      evicted += 1;
    }
    if (count > maxEntries || bytes > maxBytes) {
      fail(
        `compiled-artifact cache is full (${count} entries / ${bytes} bytes vs caps ${maxEntries} / ${maxBytes}) and every remaining entry was used within the last ${graceMs} ms — refusing this build (fail closed, never ENOSPC); retry shortly or raise POLICYVAULT_BUILD_CACHE_MAX_ENTRIES / _MAX_BYTES`,
        "BUILD_CACHE_FULL"
      );
    }
  }
  return { evicted, entries: count, bytes };
}

/*
 * Finalize-time resilience: the build names `buildDir`; if its artifact was
 * evicted, `recompile()` (the generation's compileExactState* with the
 * build's own template/state/version) must reproduce EXACTLY that directory.
 */
function ensureBuildDir({ buildDir, recompile, config = null }) {
  if (typeof buildDir !== "string" || !buildDir) fail("build names no encoder build dir — failing closed", "BUILD_DIR_MISSING");
  const artifactPath = path.join(buildDir, "artifact.json");
  if (fs.existsSync(artifactPath)) {
    touchCacheEntry(artifactPath);
    return false;
  }
  let compiled;
  try {
    compiled = recompile();
  } catch (error) {
    /* rc12 review R-03: a cache saturated with in-grace entries must not refuse the
     * recompile of an ALREADY-BUILT request — force LRU eviction and retry once. */
    if (!(error && error.code === "BUILD_CACHE_FULL" && config)) throw error;
    enforceBuildCacheBound(config, { keep: buildDir, force: true });
    compiled = recompile();
  }
  const got = compiled && typeof compiled.buildDir === "string" ? path.resolve(compiled.buildDir) : null;
  if (got !== path.resolve(buildDir)) {
    fail(`recompiled build dir ${got} != the build's ${buildDir} — deterministic state identity drift; failing closed`, "BUILD_DIR_MISMATCH");
  }
  if (!fs.existsSync(artifactPath)) fail("recompile produced no artifact — failing closed", "BUILD_DIR_MISSING");
  return true;
}

module.exports = {
  ARTIFACT_KEEP,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_MAX_BYTES,
  DEFAULT_GRACE_MS,
  minimizeArtifactFile,
  touchCacheEntry,
  listCacheEntries,
  enforceBuildCacheBound,
  ensureBuildDir
};
