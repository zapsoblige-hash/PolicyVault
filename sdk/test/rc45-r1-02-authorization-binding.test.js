"use strict";
/*
 * RC45 R1-02 — THE AUTHORIZATION INVENTORY IS BOUND TO THE ROUTE CODE
 * (remediation plan rc45-r1-plan-01 PLAN-R1 revision 2 §2 R1-02 and §4 R1-02;
 * review finding S-02 of rc45-patch-independent-01; conditions C5 and K7).
 * Internal RED-first regression material for the RC45 successor candidate;
 * not an audit.
 *
 * THE DEFECT (S-02, MEDIUM, RC44-present): the inventory row of
 * POST /wallet/requests/:id/reject declared authGate requireRequestMutation /
 * mutationGate requestMutationAllowed while the route called
 * requireRequestAccess, and the row of POST /wallet/v4/requests/:id/approvals
 * declared the same gates while the route calls requireRequestAccess and
 * wr4.collectApprovalV4. GATE 2 only checked that a gate NAME occurs somewhere
 * in api.js, and GATE 1 only that the evidence file mentions the route's
 * static segments (the legacy row was satisfied by v4 evidence).
 *
 * The stricter GATE 2 / GATE 1 now live in sdk/test/authorization-boundary-
 * inventory.test.js (whose name-only predicates they replace, by declared
 * changed-by-design pin) on the shared extractor
 * sdk/testutil/rc45-r1-authorization-binding.js. This file adds:
 *   - the legs NAMING the rows R1-02 must change (RED on dc7552e): the legacy
 *     reject and legacy signature rows declare exactly R1-01's gates and
 *     refusal (authenticate first — 401; a missing or non-v0.2 record —
 *     404 REQUEST_NOT_FOUND, schema policyvault-wallet-request/v2; then
 *     requireRequestRejecter / requireRequestSigner) and name full-pattern
 *     legacy hostile evidence; the v4 approvals row is corrected TO THE CODE
 *     (authGate requireRequestAccess; mutationGate collectApprovalV4, an
 *     invalid approver signature writes nothing);
 *   - the SABOTAGE rows of plan §2 R1-02 / K7 (HOLD): removing one route's
 *     gate call, moving the gate into a comment, pointing a legacy row at v4
 *     evidence, dropping { mutation: true } from the v0.7 reject, and
 *     removing a family prelude's principal resolution are each detected;
 *   - the extractor's own sanity legs (HOLD): the three dispatchers lex to
 *     comment-free sources that compile, and known rows resolve to their
 *     known handler (guards, family preludes and the org-roots call-site
 *     linkage).
 *
 * Layer: UNIT (static reads of server/src and the inventory; nothing is
 * executed, no store, no node). The FOREIGN / UNAUTHENTICATED hostile
 * principals these rows rely on are exercised by the evidence files named
 * in the inventory.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const B = require("../testutil/rc45-r1-authorization-binding");
const tenancy = require("../../server/src/tenancy");

const INVENTORY = JSON.parse(fs.readFileSync(path.join(B.ROOT, "server/src/authorization-boundary-inventory.json"), "utf8"));
const EXPORTS = new Set(Object.keys(tenancy));
const DISPATCH = B.analyzeDispatchers();
const read = (rel) => fs.readFileSync(path.join(B.ROOT, rel), "utf8");
const rowOf = (method, p) => {
  const rows = INVENTORY.routes.filter((r) => r.method === method && r.path === p);
  assert.equal(rows.length, 1, `exactly one inventory row ${method} ${p}`);
  return rows[0];
};
const textOf = (row) => [row.authGate, row.tenancyResolver, row.mutationGate, row.note ?? ""].join(" | ");
const evidenceOk = (row) => fs.existsSync(path.join(B.ROOT, row.hostileEvidence)) && B.evidenceMatches(row, INVENTORY, read(row.hostileEvidence));
/* A sabotaged copy of one dispatcher, analysed with the two others unchanged. */
function sabotaged(file, mutate) {
  const src = read(file), out = mutate(src);
  assert.notEqual(out, src, `the sabotage changed ${file}`);
  return B.analyzeDispatchers({ [file]: out });
}
/* The absolute source range of a row's handler block in the unsabotaged dispatcher. */
function handlerRange(row) {
  const A = DISPATCH.get(row.file), loc = B.locate(A, row);
  assert.ok(loc.located, `${row.method} ${row.path} is located (${loc.why})`);
  return { a: loc.handler.a, b: loc.handler.b, src: A.src };
}

/* ---------------- the rows R1-02 must change (RED on dc7552e) ---------------- */
test("RC45 R1-02 row: POST /wallet/requests/:id/reject declares R1-01's gates — authGate requireRequestRejecter, mutationGate naming requireRequestRejecter, the authenticate-first 401 and the missing/non-v0.2 (policyvault-wallet-request/v2) 404 REQUEST_NOT_FOUND — binds them to its handler and names full-pattern legacy hostile evidence [RED on dc7552e]", () => {
  const row = rowOf("POST", "/wallet/requests/:id/reject"), text = textOf(row);
  assert.equal(row.authGate, "requireRequestRejecter", "the legacy reject row declares requireRequestRejecter (signer or owner; plan R1-01 C7 step 3)");
  assert.match(row.mutationGate, /requireRequestRejecter/);
  assert.match(text, /401/, "the row declares authentication first (401 unchanged)");
  assert.match(text, /REQUEST_NOT_FOUND/, "the row declares the 404 REQUEST_NOT_FOUND refusal");
  assert.match(text, /policyvault-wallet-request\/v2/, "the row declares that only policyvault-wallet-request/v2 records are admitted");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "the declared gates are bound to the legacy reject handler");
  assert.ok(evidenceOk(row), `the hostile evidence ${row.hostileEvidence} exercises POST /wallet/requests/:id/reject itself (GATE 1 full pattern)`);
});

test("RC45 R1-02 row: POST /wallet/requests/:id/signature declares R1-01's gates — authGate requireRequestSigner, mutationGate naming requireRequestSigner, the authenticate-first 401 and the missing/non-v0.2 (policyvault-wallet-request/v2) 404 REQUEST_NOT_FOUND before the signer gate — and names full-pattern legacy hostile evidence [RED on dc7552e]", () => {
  const row = rowOf("POST", "/wallet/requests/:id/signature"), text = textOf(row);
  assert.equal(row.authGate, "requireRequestSigner");
  assert.match(row.mutationGate, /requireRequestSigner/);
  assert.match(text, /401/, "the row declares authentication first (401 unchanged)");
  assert.match(text, /REQUEST_NOT_FOUND/, "the row declares the 404 REQUEST_NOT_FOUND refusal (plan R1-01 C6)");
  assert.match(text, /policyvault-wallet-request\/v2/, "the row declares that only policyvault-wallet-request/v2 records are admitted");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "the declared gates are bound to the legacy signature handler");
  assert.ok(evidenceOk(row), `the hostile evidence ${row.hostileEvidence} exercises POST /wallet/requests/:id/signature itself (GATE 1 full pattern)`);
});

test("RC45 R1-02 row: POST /wallet/v4/requests/:id/approvals is corrected TO THE CODE — authGate requireRequestAccess (approver-only principals must reach it), mutationGate collectApprovalV4 (the approver signature is verified against the approval package; an invalid one writes nothing), and no gate the route does not apply [RED on dc7552e]", () => {
  const row = rowOf("POST", "/wallet/v4/requests/:id/approvals");
  assert.equal(row.authGate, "requireRequestAccess", "the route calls requireRequestAccess (plan R1-02: the code is not changed)");
  assert.match(row.mutationGate, /collectApprovalV4/);
  assert.match(row.mutationGate, /writes nothing|nothing (is )?written/i, "the row states that an invalid approver signature writes nothing");
  assert.doesNotMatch(row.mutationGate, /requireRequestMutation|requestMutationAllowed/, "the row names no gate the route does not apply");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), []);
});

/* ---------------- sabotage rows (plan §2 R1-02, K7): each is detected ---------------- */
test("RC45 R1-02 sabotage: removing the v0.4 reject route's requireRequestRejecter call makes its row unbound (the control row binds on the real source)", () => {
  const row = rowOf("POST", "/wallet/v4/requests/:id/reject");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "control: the real v0.4 reject row binds");
  const h = handlerRange(row);
  const m = /await\s+requireRequestRejecter\([^;]*\);/.exec(h.src.slice(h.a, h.b));
  assert.ok(m, "the v0.4 reject handler calls requireRequestRejecter");
  const at = h.a + m.index;
  const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, at) + src.slice(at + m[0].length)), EXPORTS);
  assert.ok(v.some((x) => /authGate requireRequestRejecter is not called/.test(x)), `the removal is detected: ${JSON.stringify(v)}`);
});

test("RC45 R1-02 sabotage: moving the v0.4 reject route's gate call into a comment makes its row unbound (comments never count)", () => {
  const row = rowOf("POST", "/wallet/v4/requests/:id/reject"), h = handlerRange(row);
  const m = /await\s+requireRequestRejecter\([^;]*\);/.exec(h.src.slice(h.a, h.b));
  assert.ok(m);
  const at = h.a + m.index;
  for (const wrap of [(s) => `/* ${s} */`, (s) => `// ${s}\n`]) {
    const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, at) + wrap(m[0]) + src.slice(at + m[0].length)), EXPORTS);
    assert.ok(v.some((x) => /authGate requireRequestRejecter is not called/.test(x)), `the commented-out gate is detected: ${JSON.stringify(v)}`);
  }
});

test("RC45 R1-02 sabotage: pointing the legacy reject row at v0.4 evidence fails GATE 1 (exact version segment); the R1-01 suite is full-pattern legacy evidence", () => {
  const row = rowOf("POST", "/wallet/requests/:id/reject");
  for (const v4Evidence of ["sdk/test/hosted-phase-f-hostile.test.js", "sdk/test/rc45-t8-api-routes.test.js", "sdk/test/hosted-build-authority.test.js"]) {
    assert.equal(B.evidenceMatches({ ...row, hostileEvidence: v4Evidence }, INVENTORY, read(v4Evidence)), false, `${v4Evidence} (v0.4 paths only) is not evidence for the legacy row`);
  }
  assert.equal(B.evidenceMatches(row, INVENTORY, read("sdk/test/rc45-r1-01-legacy-request-routes.test.js")), true, "control: the R1-01 suite spells POST /wallet/requests/:id/reject");
  assert.equal(B.evidenceMatches(rowOf("POST", "/wallet/requests/:id/signature"), INVENTORY, read("sdk/test/rc45-r1-01-legacy-request-routes.test.js")), true, "control: and POST /wallet/requests/:id/signature");
  /* a path that only mentions the segments in a comment never counts */
  assert.equal(B.evidenceMatches(row, INVENTORY, "// POST /api/v1/wallet/requests/x/reject\n/* [\"wallet\", \"requests\", id, \"reject\"] */\nconst foreign = 1;\n"), false);
});

test("RC45 R1-02 sabotage (K7): dropping { mutation: true } from the v0.7 reject (org-roots.js requireWalletRequest) makes its parameterized mutation gate unbound", () => {
  const row = rowOf("POST", "/wallet/v7/requests/:id/reject");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "control: the real v0.7 reject row binds");
  const h = handlerRange(row), body = h.src.slice(h.a, h.b);
  assert.ok(body.includes(", { mutation: true }"), "the v0.7 reject handler calls requireWalletRequest with { mutation: true }");
  const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, h.a) + body.split(", { mutation: true }").join("") + src.slice(h.b)), EXPORTS);
  assert.ok(v.some((x) => /parameterized gate requireWalletRequest counts as a mutation gate only with \{ mutation: true \}/.test(x)), `the dropped flag is detected: ${JSON.stringify(v)}`);
});

/* ---------------- RC45 R2-12: the narrowed /wallet/v5, /wallet/v6 and /wallet/v7 reject rows (sabotage rows) ---------------- */
test("RC45 R2-12 sabotage: removing the v0.7 reject route's requireWalletRequestRejecter call makes its row unbound (the control row binds on the real source) [RED on b89f0f7]", () => {
  const row = rowOf("POST", "/wallet/v7/requests/:id/reject");
  assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], "control: the real v0.7 reject row binds");
  const h = handlerRange(row);
  const m = /await\s+requireWalletRequestRejecter\([^;]*\);/.exec(h.src.slice(h.a, h.b));
  assert.ok(m, "the v0.7 reject handler calls requireWalletRequestRejecter (the request's signer or an active root owner only)");
  assert.match(row.mutationGate, /requireWalletRequestRejecter/, "the v0.7 reject row declares it");
  const at = h.a + m.index;
  const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, at) + src.slice(at + m[0].length)), EXPORTS);
  assert.ok(v.some((x) => /mutationGate symbol requireWalletRequestRejecter is not bound/.test(x)), `the removal is detected: ${JSON.stringify(v)}`);
});

test("RC45 R2-12 sabotage: moving the v0.7 reject route's requireWalletRequestRejecter call into a comment makes its row unbound (comments never count) [RED on b89f0f7]", () => {
  const row = rowOf("POST", "/wallet/v7/requests/:id/reject"), h = handlerRange(row);
  const m = /await\s+requireWalletRequestRejecter\([^;]*\);/.exec(h.src.slice(h.a, h.b));
  assert.ok(m, "the v0.7 reject handler calls requireWalletRequestRejecter");
  assert.match(row.mutationGate, /requireWalletRequestRejecter/, "the v0.7 reject row declares it");
  const at = h.a + m.index;
  for (const wrap of [(s) => `/* ${s} */`, (s) => `// ${s}\n`]) {
    const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, at) + wrap(m[0]) + src.slice(at + m[0].length)), EXPORTS);
    assert.ok(v.some((x) => /mutationGate symbol requireWalletRequestRejecter is not bound/.test(x)), `the commented-out call is detected: ${JSON.stringify(v)}`);
  }
});

test("RC45 R2-12 sabotage: removing the requireTokenRequestRejecter call from the shared /wallet/v5 and /wallet/v6 reject handler makes both rows unbound (the control rows bind on the real source) [RED on b89f0f7]", () => {
  for (const p of ["/wallet/v5/requests/:id/reject", "/wallet/v6/requests/:id/reject"]) {
    const row = rowOf("POST", p);
    assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], `control: the real ${p} row binds`);
    const h = handlerRange(row);
    const m = /await\s+requireTokenRequestRejecter\([^;]*\);/.exec(h.src.slice(h.a, h.b));
    assert.ok(m, `the ${p} handler calls requireTokenRequestRejecter (the request's signer or the vault owner only)`);
    assert.match(row.mutationGate, /requireTokenRequestRejecter/, `the ${p} row declares it`);
    const at = h.a + m.index;
    const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, at) + src.slice(at + m[0].length)), EXPORTS);
    assert.ok(v.some((x) => /mutationGate symbol requireTokenRequestRejecter is not bound/.test(x)), `${p}: the removal is detected: ${JSON.stringify(v)}`);
  }
});

test("RC45 R2-12 sabotage (holds): dropping { mutation: true } from the shared /wallet/v5 and /wallet/v6 reject handler is detected on both rows — nothing the handler calls (a rejecter helper included) may carry the flag for it", () => {
  for (const p of ["/wallet/v5/requests/:id/reject", "/wallet/v6/requests/:id/reject"]) {
    const row = rowOf("POST", p);
    assert.deepEqual(B.bindingViolations(row, DISPATCH, EXPORTS), [], `control: the real ${p} row binds`);
    const h = handlerRange(row), body = h.src.slice(h.a, h.b);
    assert.ok(body.includes(", { mutation: true }"), `the ${p} handler calls requireRequestAccess with { mutation: true }`);
    const v = B.bindingViolations(row, sabotaged(row.file, (src) => src.slice(0, h.a) + body.split(", { mutation: true }").join("") + src.slice(h.b)), EXPORTS);
    assert.ok(v.some((x) => /parameterized gate requireRequestAccess counts as a mutation gate only with \{ mutation: true \}/.test(x)), `${p}: the dropped flag is detected: ${JSON.stringify(v)}`);
  }
});

test("RC45 R1-02 sabotage: removing a family prelude's principal resolution (org-roots.js dispatch()) unbinds the requestAuthPrincipal auth gate of the org-roots and /wallet/v7 rows", () => {
  const rows = [rowOf("GET", "/org-roots"), rowOf("POST", "/wallet/v7/requests/:id/reject")];
  for (const row of rows) assert.deepEqual(B.bindingReport(row, DISPATCH, EXPORTS).auth, [], `control: ${row.method} ${row.path} binds requestAuthPrincipal through dispatch()`);
  const an = sabotaged("server/src/org-roots.js", (src) => src.replace(/const principal = config\.tenancyEnforced \? await requestAuthPrincipal\([^;]*;/, "const principal = null;"));
  for (const row of rows) assert.ok(B.bindingReport(row, an, EXPORTS).auth.some((x) => /authGate requestAuthPrincipal is not called/.test(x)), `${row.method} ${row.path}: the removed family prelude is detected`);
});

/* ---------------- the extractor's own sanity (HOLD) ---------------- */
test("RC45 R1-02 extractor: each dispatcher lexes to a position-preserving, comment-free source that still compiles, with every bracket matched", () => {
  for (const file of B.DISPATCHERS) {
    const src = read(file), { code } = B.lex(src);
    assert.equal(code.length, src.length, `${file}: positions preserved`);
    assert.equal(B.compiles(code), true, `${file}: the comment-stripped source compiles`);
    assert.equal(B.lex(code).code, code, `${file}: stripping is idempotent (no comment survives)`);
    assert.doesNotThrow(() => B.pairsOf(B.lex(src).skel), `${file}: brackets balance`);
  }
});

test("RC45 R1-02 extractor: known rows resolve to their own handler — guards (GET /vaults/:id/agent-suspensions inside the agent-suspensions block, not GET /vaults/:id), family preludes (identities, webhooks, the v5/v6 preamble) and the org-roots dispatch() call-site linkage (/wallet/v7 vs /org-roots)", () => {
  const cases = [
    [["GET", "/vaults/:id/agent-suspensions"], /suspensions\.loadSuspensions\(/],
    [["POST", "/wallet/v4/requests/:id/reject"], /requireRequestRejecter\(/],
    [["POST", "/wallet/v7/requests/:id/reject"], /markKasWalletRejected\(/],
    [["POST", "/org-roots/:id/requests/:rid/reject"], /loadRequestScoped\(/],
    [["POST", "/wallet/v5/requests/:id/reject"], /markRejected\(config/],
    [["POST", "/identities"], /mi\.createIdentity\(/],
    [["POST", "/webhooks/:id/rotate-secret"], /rotate/i]
  ];
  for (const [[method, p], needle] of cases) {
    const row = rowOf(method, p), A = DISPATCH.get(row.file), loc = B.locate(A, row);
    assert.ok(loc.located, `${method} ${p}: ${loc.why}`);
    assert.match(A.code.slice(loc.handler.a, loc.handler.b), needle, `${method} ${p} resolves to its own handler (${row.file}:${loc.handler.line})`);
    if (row.authGate === "requestAuthPrincipal") assert.match(B.wrapperSet(A, loc), /requestAuthPrincipal\(/, `${method} ${p}: the family prelude binds requestAuthPrincipal`);
  }
  const v7 = B.locate(DISPATCH.get("server/src/org-roots.js"), rowOf("POST", "/wallet/v7/requests/:id/reject"));
  const orgRoots = B.locate(DISPATCH.get("server/src/org-roots.js"), rowOf("POST", "/org-roots/:id/requests/:rid/reject"));
  assert.notEqual(v7.handler.a, orgRoots.handler.a, "the same-shaped /wallet/v7 and /org-roots reject routes resolve to different handlers through dispatch()'s routing");
});
