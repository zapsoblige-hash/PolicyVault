"use strict";

/*
 * PERMANENT STRUCTURAL GATE 2 — MECHANICAL AUTHORIZATION-BOUNDARY INVENTORY
 * (rc11 internal security review F-04; owner addendum §E, 2026-09-04).
 *
 * The RC11 tenancy defect was structural: three hosted route families
 * resolved (or never received) the principal and then discarded it
 * (`void principal`), so every green floor that "covered tenancy" measured
 * only the v4 family. GREEN FLOORS MEASURE WHAT WAS TESTED. This gate makes
 * the boundary itself a checked artifact:
 *
 *   server/src/authorization-boundary-inventory.json — one row per hosted
 *   route: method/path, resource class, principal type, auth gate, tenancy
 *   resolver, mutation gate, machine scope, hostile-evidence test.
 *
 * FAILS CLOSED when:
 *   1. a route family literal exists in server/src/scopes.js or
 *      server/src/api.js that the inventory does not list (a new family
 *      without a declared boundary);
 *   2. a listed machine scope disagrees with requiredScopesFor (the
 *      deny-by-default scope table) — the inventory can never drift from
 *      the enforcing code;
 *   3. a non-public route names no auth gate, or names a gate symbol that
 *      is not present in the file it claims enforces it (MISSING PRINCIPAL);
 *   4. a tenant-owned route names no tenancy resolver, or a resolver that
 *      is neither a server/src/tenancy.js export nor a symbol in its file
 *      (BYPASSED RESOLVER); a tenant-owned mutation names no mutation gate;
 *   5. a tenant-owned route has no hostile-evidence test that exercises its
 *      static path segments (GATE 1 coverage);
 *   6. any server source discards a resolved principal/context
 *      (`void principal`, `void ctx`, `void session`, `void actor…`) —
 *      DISCARDED PRINCIPAL — unless listed under documentedExceptions with
 *      a reason;
 *   7. the rendered document is out of sync with the JSON.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const INVENTORY_PATH = path.join(ROOT, "server/src/authorization-boundary-inventory.json");
const DOC_PATH = path.join(ROOT, "docs/postlaunch/authorization-boundary-inventory.md");
const inventory = JSON.parse(fs.readFileSync(INVENTORY_PATH, "utf8"));
const scopes = require("../../server/src/scopes");
const tenancy = require("../../server/src/tenancy");
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const scopesSrc = read("server/src/scopes.js");
const apiSrc = read("server/src/api.js");

const PUBLIC_CLASSES = new Set(["public", "global"]);
const SAMPLE = { ":id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ":rid": "00000000-0000-4000-8000-000000000001", ":cid": "c1", ":m": "m1", ":v": "v1", ":vaultId": "7e".repeat(32), ":slot": "1", ":address": "kaspatest:q" };
const segmentsOf = (p) => p.split("/").filter(Boolean).map((s) => (s.startsWith(":") ? SAMPLE[s] ?? "x" : s));
const staticSegments = (p) => p.split("/").filter((s) => s && !s.startsWith(":"));

test("inventory schema + every route family literal in scopes.js / api.js is inventoried", () => {
  assert.equal(inventory.schema, "policyvault-authorization-boundary-inventory/1");
  assert.ok(Array.isArray(inventory.routes) && inventory.routes.length > 50);
  const families = new Set();
  for (const src of [scopesSrc, apiSrc]) for (const m of src.matchAll(/(?:segments\[0\]|s0) === "([a-z0-9-]+)"/g)) families.add(m[1]);
  assert.ok(families.size >= 20, `expected the route-family literals to be extractable (${families.size})`);
  const listed = new Set(inventory.routes.map((r) => r.path.split("/")[1]));
  for (const f of families) assert.ok(listed.has(f), `route family "${f}" exists in the server but is NOT in the authorization-boundary inventory`);
  for (const r of inventory.routes) {
    for (const k of ["method", "path", "resourceClass", "principalType", "authGate", "file", "tenancyResolver", "mutationGate", "hostileEvidence"]) assert.ok(k in r, `${r.method} ${r.path}: missing ${k}`);
    assert.ok(r.resourceClass in inventory.resourceClasses, `${r.path}: unknown resourceClass ${r.resourceClass}`);
    assert.ok(r.principalType in inventory.principalTypes, `${r.path}: unknown principalType ${r.principalType}`);
  }
});

/*
 * rc12 review R-04: family-level coverage lets a deleted ROW go unnoticed
 * (only the rendered-doc sync check would fire, and its own remediation
 * silences it). Two row-granularity checks close that:
 *  (a) every literal path segment compared in a dispatcher (`segments[i] === "x"`)
 *      must appear at that same position in at least one inventoried route —
 *      a route whose distinguishing literal is inventoried nowhere fails;
 *  (b) the exact sorted "METHOD path" list is pinned by digest; a deleted or
 *      renamed row changes it and must be re-pinned in a reviewed commit (the
 *      failure names the row delta, not just the digest).
 */
const DISPATCHERS = ["server/src/api.js", "server/src/org-roots.js", "server/src/wallet-token-surface.js"];
function literalPositions() {
  const out = new Map(); // "i:lit" -> file
  for (const f of DISPATCHERS) {
    const src = read(f);
    for (const m of src.matchAll(/segments\[(\d)\]\s*===\s*"([a-z0-9-]+)"/g)) out.set(`${m[1]}:${m[2]}`, f);
    for (const m of src.matchAll(/\b(s\d)\s*===\s*"([a-z0-9-]+)"/g)) out.set(`${m[1].slice(1)}:${m[2]}`, f);
  }
  return out;
}
const ROUTE_LIST_SHA256 = "583a8563b6f71da28e2c1509070971e6d95e76dbe1cf395ba066711e55507e0f"; // re-pinned with the UX-05 reconcile route (GATE 2 reviewed boundary change; hostile evidence in hosted-build-authority.test.js)

test("row granularity (a): every dispatcher path literal is inventoried at its own segment position", () => {
  const positions = new Set();
  for (const r of inventory.routes) r.path.split("/").filter(Boolean).forEach((seg, i) => { if (!seg.startsWith(":")) positions.add(`${i}:${seg}`); });
  // dispatcher literals for org-roots/wallet families are matched on the SAME segments array (segments[0] is the family)
  const missing = [];
  for (const [key, file] of literalPositions()) {
    const [i, lit] = key.split(":");
    if (["true", "false"].includes(lit)) continue;
    if (!positions.has(`${i}:${lit}`)) missing.push(`${file}: segments[${i}] === "${lit}"`);
  }
  assert.deepEqual(missing, [], `dispatcher route literals with NO inventoried route at that position (a route row is missing or was deleted)`);
});

test("row granularity (b): the exact route list is pinned; a deleted, renamed or added row must be re-pinned in a reviewed change", () => {
  const list = inventory.routes.map((r) => `${r.method} ${r.path}` + (r.scopeSampleBody ? " " + JSON.stringify(r.scopeSampleBody) : "")).sort();
  const digest = require("node:crypto").createHash("sha256").update(list.join("\n")).digest("hex");
  assert.equal(digest, ROUTE_LIST_SHA256, `route list changed (${list.length} rows). If this is a reviewed boundary change, re-pin ROUTE_LIST_SHA256 in this test to ${digest} in the SAME commit that changes the inventory and its hostile evidence. Rows now:\n${list.join("\n")}`);
});

test("machine scopes in the inventory equal requiredScopesFor for every route (no drift from the enforcing table)", () => {
  for (const r of inventory.routes) {
    const actual = scopes.requiredScopesFor(r.method, segmentsOf(r.path), r.scopeSampleBody ?? {});
    assert.deepEqual(actual, r.machineScope, `${r.method} ${r.path}: requiredScopesFor=${JSON.stringify(actual)} inventory=${JSON.stringify(r.machineScope)}`);
    if (r.principalType === "session-only") assert.equal(scopes.isWalletSessionOnlyRoute(r.method, segmentsOf(r.path)), true, `${r.path} must be wallet-session-only`);
    if (r.resourceClass === "public") assert.equal(scopes.isPublicRoute(r.method, segmentsOf(r.path)), true, `${r.path} must be a public route`);
    if (r.resourceClass !== "public") assert.equal(scopes.isPublicRoute(r.method, segmentsOf(r.path)), false, `${r.path} is inventoried as ${r.resourceClass} but scopes.js treats it as public`);
  }
});

test("MISSING PRINCIPAL: every non-public route names an auth gate that exists in the file it claims; tenant-owned routes never accept 'none'/'optional' principals", () => {
  for (const r of inventory.routes) {
    if (r.resourceClass === "public") continue;
    assert.notEqual(r.authGate, "n/a", `${r.method} ${r.path}: no auth gate`);
    const src = read(r.file);
    assert.ok(src.includes(r.authGate), `${r.method} ${r.path}: auth gate "${r.authGate}" not found in ${r.file}`);
    if (!PUBLIC_CLASSES.has(r.resourceClass)) assert.ok(["session-or-machine", "session-only"].includes(r.principalType), `${r.method} ${r.path}: tenant-owned route with principalType ${r.principalType}`);
  }
});

test("BYPASSED RESOLVER: every tenant-owned route names a tenancy resolver that is a tenancy.js export or a symbol of its file; every tenant-owned mutation names a mutation gate", () => {
  const tenancyExports = new Set(Object.keys(tenancy));
  for (const r of inventory.routes) {
    if (PUBLIC_CLASSES.has(r.resourceClass)) continue;
    assert.notEqual(r.tenancyResolver, "n/a", `${r.method} ${r.path}: no tenancy resolver`);
    const src = read(r.file);
    const symbols = [...r.tenancyResolver.matchAll(/[A-Za-z_][A-Za-z0-9_]*/g)].map((m) => m[0]).filter((s) => /[a-z][A-Z]|^[a-z]+[A-Z]/.test(s) || tenancyExports.has(s));
    assert.ok(symbols.length > 0, `${r.method} ${r.path}: resolver "${r.tenancyResolver}" names no symbol`);
    for (const s of symbols) assert.ok(tenancyExports.has(s) || src.includes(s), `${r.method} ${r.path}: resolver symbol "${s}" is neither a tenancy.js export nor present in ${r.file}`);
    if (r.method !== "GET") {
      assert.notEqual(r.mutationGate, "n/a", `${r.method} ${r.path}: tenant-owned mutation without a mutation gate`);
      const ms = [...r.mutationGate.matchAll(/[A-Za-z_][A-Za-z0-9_]*/g)].map((m) => m[0]).filter((s) => /[a-z][A-Z]/.test(s) || tenancyExports.has(s));
      for (const s of ms) assert.ok(tenancyExports.has(s) || src.includes(s), `${r.method} ${r.path}: mutation gate symbol "${s}" not found`);
    }
  }
});

test("GATE 1 coverage: every tenant-owned route names an existing hostile-evidence test that exercises its static path segments with a foreign principal", () => {
  for (const r of inventory.routes) {
    if (PUBLIC_CLASSES.has(r.resourceClass)) continue;
    assert.notEqual(r.hostileEvidence, "n/a", `${r.method} ${r.path}: no hostile evidence`);
    const p = path.join(ROOT, r.hostileEvidence);
    assert.ok(fs.existsSync(p), `${r.method} ${r.path}: evidence file ${r.hostileEvidence} does not exist`);
    const src = fs.readFileSync(p, "utf8");
    for (const seg of staticSegments(r.path)) assert.ok(src.includes(seg), `${r.method} ${r.path}: evidence ${r.hostileEvidence} never mentions segment "${seg}"`);
    assert.match(src, /foreign|FOREIGN|tenant|TENANT|stranger|unauthenticated|UNAUTHENTICATED/, `${r.hostileEvidence} carries no hostile/foreign probe wording`);
  }
});

test("DISCARDED PRINCIPAL lint: no server source discards a resolved principal/context (documented exceptions only)", () => {
  const dir = path.join(ROOT, "server/src");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js"));
  const exceptions = new Map((inventory.documentedExceptions ?? []).map((e) => [`${e.file}#${e.pattern}`, e.reason]));
  for (const f of files) {
    const src = fs.readFileSync(path.join(dir, f), "utf8");
    for (const m of src.matchAll(/void\s+(principal|ctx|session|actor\w*)\b/g)) {
      const key = `server/src/${f}#${m[0]}`;
      assert.ok(exceptions.has(key) && typeof exceptions.get(key) === "string" && exceptions.get(key).length > 10, `${key}: a resolved principal/context is DISCARDED — the route must use it, or the discard must be a documented exception with a reason`);
    }
  }
});

test("the rendered document is in sync with the JSON (tools/render-authorization-inventory.js)", () => {
  const rendered = require("../../tools/render-authorization-inventory").render(inventory);
  const onDisk = fs.readFileSync(DOC_PATH, "utf8");
  assert.equal(onDisk, rendered, "docs/postlaunch/authorization-boundary-inventory.md is stale — regenerate with node tools/render-authorization-inventory.js");
});
