"use strict";

/*
 * DEPENDENCY-DIRECTION — the build-failing mechanical enforcement both
 * adapter specs REQUIRE (x402 §7.3 / X-34; ap2 §7.3 / A-42), plus this
 * implementation's stricter lib allowlist:
 *
 *   1. NOTHING under core/, sdk/src/, or server/src/ may import anything
 *      under integrations/ — adapters down ⇒ zero core impact, by
 *      construction (degradation is architectural, not aspirational).
 *   2. NOTHING under integrations/x402/ or integrations/ap2/ may import
 *      sdk/src/** or server/src/** (per the specs), NOR core/** NOR the
 *      kaspa wasm module directly (stricter). Their only repo doorway is
 *      integrations/lib.
 *   3. integrations/lib/ may import ONLY the four sanctioned SDK leaf
 *      modules (deny-by-default allowlist):
 *        sdk/src/http-client.js   (transport-only API client)
 *        sdk/src/canonical-json.js (the SDK public entry's canonicalJsonStringify)
 *        sdk/src/amounts.js        (canonical numeric-safety module)
 *        sdk/src/address-identity.js (the ONE authoritative address parser)
 *      and never server/src/**, never sdk/src/store|builders|signers|rpc.
 *   4. The canonicalJsonStringify used by the adapters IS the SDK public
 *      entry's export — the same function object (never a reimplementation).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.join(__dirname, "..", "..");

function jsFilesUnder(dir) {
  const out = [];
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "target") continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && (entry.name.endsWith(".js") || entry.name.endsWith(".mjs") || entry.name.endsWith(".cjs"))) out.push(full);
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return out;
}

const REQUIRE_RE = /require\s*\(\s*["']([^"']+)["']\s*\)|import\s+[^"']*["']([^"']+)["']/g;

function importsOf(file) {
  const text = fs.readFileSync(file, "utf8");
  const specs = [];
  let m;
  while ((m = REQUIRE_RE.exec(text)) !== null) specs.push(m[1] ?? m[2]);
  return specs;
}

function resolvesInto(file, spec, targetDirs) {
  if (!spec.startsWith(".") && !spec.startsWith("/")) return null; // bare package specifiers: not repo paths
  const resolved = path.resolve(path.dirname(file), spec);
  for (const target of targetDirs) {
    const abs = path.join(REPO, target);
    if (resolved === abs || resolved.startsWith(abs + path.sep)) return target;
  }
  return null;
}

test("X-34/A-42 rule 1: no core/, sdk/src/, or server/src/ file imports integrations/ — the core cannot depend on an optional integration", () => {
  const offenders = [];
  for (const dir of ["core", "sdk/src", "server/src", "web", "mcp"]) {
    for (const file of jsFilesUnder(path.join(REPO, dir))) {
      for (const spec of importsOf(file)) {
        if (resolvesInto(file, spec, ["integrations"])) offenders.push(`${path.relative(REPO, file)} -> ${spec}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `core/sdk/server/web/mcp must never import integrations/**:\n${offenders.join("\n")}`);
});

test("X-34/A-42 rule 2: integrations/x402 and integrations/ap2 import no sdk/src, server/src, core, or wasm — integrations/lib is their only repo doorway", () => {
  const offenders = [];
  for (const dir of ["integrations/x402", "integrations/ap2"]) {
    for (const file of jsFilesUnder(path.join(REPO, dir))) {
      for (const spec of importsOf(file)) {
        const hit = resolvesInto(file, spec, ["sdk", "server", "core", "web", "mcp"]);
        if (hit) offenders.push(`${path.relative(REPO, file)} -> ${spec} (${hit})`);
        if (spec.includes("rusty-kaspa")) offenders.push(`${path.relative(REPO, file)} -> ${spec} (wasm direct)`);
      }
    }
  }
  assert.deepEqual(offenders, [], `adapter modules must reach the repo only through integrations/lib:\n${offenders.join("\n")}`);
});

test("rule 3: integrations/lib imports ONLY the four sanctioned SDK leaf modules — deny-by-default allowlist", () => {
  const ALLOWED = new Set(["sdk/src/http-client.js", "sdk/src/canonical-json.js", "sdk/src/amounts.js", "sdk/src/address-identity.js"]);
  const offenders = [];
  for (const file of jsFilesUnder(path.join(REPO, "integrations/lib"))) {
    for (const spec of importsOf(file)) {
      const hit = resolvesInto(file, spec, ["sdk", "server", "core", "web", "mcp"]);
      if (!hit) continue;
      const resolved = path.relative(REPO, path.resolve(path.dirname(file), spec));
      const withExt = resolved.endsWith(".js") ? resolved : `${resolved}.js`;
      if (!ALLOWED.has(withExt)) offenders.push(`${path.relative(REPO, file)} -> ${spec}`);
    }
  }
  assert.deepEqual(offenders, [], `integrations/lib may import only the sanctioned SDK leaves:\n${offenders.join("\n")}`);
});

test("rule 3b: no integrations runtime file imports server/src at any path", () => {
  const offenders = [];
  for (const dir of ["integrations/lib", "integrations/x402", "integrations/ap2"]) {
    for (const file of jsFilesUnder(path.join(REPO, dir))) {
      for (const spec of importsOf(file)) {
        if (resolvesInto(file, spec, ["server"])) offenders.push(`${path.relative(REPO, file)} -> ${spec}`);
      }
    }
  }
  assert.deepEqual(offenders, []);
});

test("rule 4: the adapters' canonicalJsonStringify IS the SDK public entry's export (same function object, never a reimplementation)", () => {
  const sdkEntry = require(path.join(REPO, "sdk", "src", "index.js"));
  const libCanonical = require("../lib/canonical");
  assert.equal(typeof sdkEntry.canonicalJsonStringify, "function");
  assert.equal(libCanonical.canonicalJsonStringify, sdkEntry.canonicalJsonStringify, "must be the identical function reference");
});

test("integrations/ adds no runtime npm dependencies: no package.json anywhere under integrations/", () => {
  const found = [];
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === "package.json") found.push(full);
    }
  };
  walk(path.join(REPO, "integrations"));
  assert.deepEqual(found, [], "zero new runtime npm dependencies — stdlib http/crypto only");
});
