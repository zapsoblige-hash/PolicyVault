"use strict";
/*
 * RC45 R2-12 — THE AUTHORIZATION INVENTORY DECLARES THE NARROWED /wallet/v5,
 * /wallet/v6 AND /wallet/v7 REJECT ROUTES. Internal RED-first regression
 * material for the RC45 candidate; not an audit.
 *
 * The permanent GATE 2 suite (sdk/test/authorization-boundary-inventory.test.js)
 * keeps every inventory row bound to its own handler (comments stripped; every
 * camelCase gate symbol of a row must occur in the handler block or its family
 * prelude), keeps GATE 1 evidence on the full route pattern, pins the route
 * list digest and keeps the rendered document in sync with the JSON. It does
 * not know WHAT the reject-scope repair (exercised by
 * sdk/test/rc45-r2-az-reject-scope.test.js) changes at three rows; this suite
 * pins that the reviewed boundary text says it:
 *   - POST /wallet/v5/requests/:id/reject and POST /wallet/v6/requests/:id/reject:
 *     mutationGate "requireRequestAccess(mutation) + requireTokenRequestRejecter
 *     (the request's signer or the vault owner only; any other participant 403
 *     REQUEST_FORBIDDEN)";
 *   - POST /wallet/v7/requests/:id/reject: mutationGate
 *     "requireWalletRequest(mutation) + requireWalletRequestRejecter (the
 *     request's signer or an active owner slot of the vault's organizational
 *     root only; any other participant, another agent included, 403
 *     REQUEST_FORBIDDEN)";
 *   - all three name sdk/test/rc45-r2-az-reject-scope.test.js as hostile
 *     evidence (full route path, FOREIGN wording), and the rendered document's
 *     rows carry the same text.
 * Every other field of the three rows is unchanged (auth gate, tenancy
 * resolver, machine scope, file), and no route is added, removed or renamed
 * (the route-list digest of the permanent suite stays as it is).
 *
 * RED on b89f0f7: the three rows still declare the build-authority rule
 * (requireRequestAccess(mutation) / requireWalletRequest(mutation)) with the
 * older evidence files, and the rendered rows say the same. HOLDS: the
 * unchanged fields, and the reject-scope suite as full-pattern GATE 1 evidence
 * for all three rows.
 *
 * Layer: UNIT (static reads of the checked-in inventory, its rendered
 * document, the dispatchers and the named evidence file). No store, no node.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const B = require("../testutil/rc45-r1-authorization-binding");
const tenancy = require("../../server/src/tenancy");

const read = (rel) => fs.readFileSync(path.join(B.ROOT, rel), "utf8");
const INVENTORY = JSON.parse(read("server/src/authorization-boundary-inventory.json"));
const DOC = read("docs/postlaunch/authorization-boundary-inventory.md");
const DISPATCH = B.analyzeDispatchers();
const EXPORTS = new Set(Object.keys(tenancy));
const EVIDENCE = "sdk/test/rc45-r2-az-reject-scope.test.js";
const TOKEN_GATE = "requireRequestAccess(mutation) + requireTokenRequestRejecter (the request's signer or the vault owner only; any other participant 403 REQUEST_FORBIDDEN)";
const ROOTED_GATE = "requireWalletRequest(mutation) + requireWalletRequestRejecter (the request's signer or an active owner slot of the vault's organizational root only; any other participant, another agent included, 403 REQUEST_FORBIDDEN)";
const ROWS = [
  { path: "/wallet/v5/requests/:id/reject", file: "server/src/wallet-token-surface.js", resolver: "requireRequestAccess", scope: ["request:reject"], gate: TOKEN_GATE, helper: "requireTokenRequestRejecter" },
  { path: "/wallet/v6/requests/:id/reject", file: "server/src/wallet-token-surface.js", resolver: "requireRequestAccess", scope: ["request:reject"], gate: TOKEN_GATE, helper: "requireTokenRequestRejecter" },
  { path: "/wallet/v7/requests/:id/reject", file: "server/src/org-roots.js", resolver: "requireWalletRequest", scope: ["write:org-roots"], gate: ROOTED_GATE, helper: "requireWalletRequestRejecter" }
];
function rowOf(method, routePath) {
  const rows = INVENTORY.routes.filter((r) => r.method === method && r.path === routePath);
  assert.equal(rows.length, 1, `exactly one inventory row for ${method} ${routePath}`);
  return rows[0];
}

for (const R of ROWS) {
  test(`RC45 R2-12 inventory: the POST ${R.path} row declares the narrowed reject rule (mutationGate naming ${R.helper} and the 403 REQUEST_FORBIDDEN for every other participant), names the reject-scope suite as its hostile evidence, keeps its other fields, and binds to its handler (GATE 2) [RED on b89f0f7]`, () => {
    const row = rowOf("POST", R.path);
    assert.equal(row.authGate, "requestAuthPrincipal", "the auth gate is unchanged");
    assert.equal(row.file, R.file, "the dispatcher file is unchanged");
    assert.equal(row.tenancyResolver, R.resolver, "the tenancy resolver is unchanged");
    assert.deepEqual(row.machineScope, R.scope, "the machine scope is unchanged");
    assert.equal(row.resourceClass, "request");
    assert.equal(row.mutationGate, R.gate, `the row declares the narrowed reject rule; it says: ${row.mutationGate}`);
    assert.equal(row.hostileEvidence, EVIDENCE, `the row names the reject-scope suite as its hostile evidence; it names: ${row.hostileEvidence}`);
    assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "every declared gate symbol is bound to the reject handler (no stray camelCase word)");
    const evidence = read(row.hostileEvidence);
    assert.equal(B.evidenceMatches(row, INVENTORY, evidence), true, "the evidence spells the row's full route path, exact version segment included (GATE 1)");
    assert.match(evidence, /REQUEST_FORBIDDEN/, "the evidence exercises the 403 narrowing");
    assert.match(evidence, /FOREIGN/, "with a FOREIGN principal (GATE 1)");
  });
}

test("RC45 R2-12 inventory: the rendered document's /wallet/v5, /wallet/v6 and /wallet/v7 reject rows carry the narrowed rule and the reject-scope evidence (the document is generated from the JSON) [RED on b89f0f7]", () => {
  for (const R of ROWS) {
    const line = DOC.split("\n").find((l) => l.startsWith(`| POST | \`${R.path}\` |`));
    assert.ok(line, `the rendered document lists POST ${R.path}`);
    assert.ok(line.includes(R.gate), `the rendered row of POST ${R.path} carries the narrowed rule; it says: ${line}`);
    assert.ok(line.includes(`\`${EVIDENCE}\``), `the rendered row of POST ${R.path} names the reject-scope suite`);
  }
});

test("RC45 R2-12 GATE 1 evidence (holds): the reject-scope suite spells each of the three reject routes in full (exact version segment) with FOREIGN and UNAUTHENTICATED probe wording and the REQUEST_FORBIDDEN refusal, so it is valid full-pattern evidence for all three rows", () => {
  const evidence = read(EVIDENCE);
  for (const R of ROWS) {
    const row = { ...rowOf("POST", R.path), hostileEvidence: EVIDENCE };
    assert.equal(B.evidenceMatches(row, INVENTORY, evidence), true, `${EVIDENCE} spells POST ${R.path}`);
  }
  assert.match(evidence, /FOREIGN/);
  assert.match(evidence, /UNAUTHENTICATED/);
  assert.match(evidence, /REQUEST_FORBIDDEN/);
  /* a path that differs in its version segment never counts */
  assert.equal(B.evidenceMatches(rowOf("POST", "/wallet/v6/requests/:id/reject"), INVENTORY, "x.call(\"POST\", [\"wallet\", \"v5\", \"requests\", id, \"reject\"]);\n"), false, "control: a /wallet/v5 path is not evidence for the /wallet/v6 row");
});
