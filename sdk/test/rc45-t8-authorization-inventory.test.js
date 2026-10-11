"use strict";
/*
 * RC45 T8 — THE AUTHORIZATION INVENTORY DECLARES THE L5 BOUNDARY CHANGES (fix
 * item F8 RC45-L5-API-WEB; plan rc45-simplified-plan-r2 §2.3 reject row
 * ("inventory row authorization-boundary-inventory.json:690 and doc; GATE 1"),
 * §5 A2 and A5 ("inventory row :380: 'optional owner-supplied recover
 * evidence, verified against the chain, grants no authority' (H-51)"), §8 T8
 * "inventory"). Internal RED-first regression material for the RC45
 * candidate; not an audit.
 *
 * The permanent GATE 2 suite (sdk/test/authorization-boundary-inventory.test.js)
 * keeps the inventory structurally honest (every route listed, scopes equal to
 * the enforcing table, gates present, hostile evidence present, the rendered
 * document in sync). It does not know WHAT the L5 repair changes at two rows;
 * this suite pins that the reviewed boundary text says it:
 *   - POST /vaults/:id/reconcile: the owner-only Verify now reads an optional
 *     owner-supplied recover transaction (outOfAppTransaction), verified
 *     against the chain, granting no authority (H-51);
 *   - POST /wallet/v4/requests/:id/reject: hosted rejection is narrowed to the
 *     request's signer or the vault owner, anyone else 403 REQUEST_FORBIDDEN
 *     (H-11), with GATE 1 hostile evidence that exercises the narrowing.
 * Both rows and the rendered document must say so (the doc is generated from
 * the JSON; the GATE 2 sync test keeps them equal).
 *
 * RED on C1 e62b1973: neither row mentions the paste or the narrowing (the
 * reject row's mutation gate is requestMutationAllowed: every covenant
 * participant except approver-only principals). GREEN after F8 once the rows,
 * their hostile evidence and the rendered document are updated in the same
 * reviewed change (the GATE 2 route-list digest is unaffected: no route is
 * added, removed or renamed).
 *
 * Layer: UNIT (static read of the checked-in inventory, its rendered document
 * and the named hostile-evidence file). No store, no node, no network.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const INVENTORY = JSON.parse(fs.readFileSync(path.join(ROOT, "server/src/authorization-boundary-inventory.json"), "utf8"));
const DOC = fs.readFileSync(path.join(ROOT, "docs/postlaunch/authorization-boundary-inventory.md"), "utf8");
const H51 = "optional owner-supplied recover evidence, verified against the chain, grants no authority";

function rowOf(method, routePath) {
  const rows = INVENTORY.routes.filter((r) => r.method === method && r.path === routePath);
  assert.equal(rows.length, 1, `exactly one inventory row for ${method} ${routePath}`);
  return rows[0];
}
const textOf = (row) => [row.authGate, row.tenancyResolver, row.mutationGate, row.note ?? ""].join(" \n ");
const normalize = (s) => s.replace(/\s+/g, " ").toLowerCase();

test("RC45 T8 inventory: the Verify row (POST /vaults/:id/reconcile) declares the optional owner-supplied recover evidence, verified against the chain, granting no authority (A5, H-51), and the rendered document carries it [RED on C1]", () => {
  const row = rowOf("POST", "/vaults/:id/reconcile");
  assert.equal(row.tenancyResolver, "requireVaultAccess(owner)", "Verify stays owner-only (principal and owner access FIRST, CR-L6)");
  assert.equal(row.mutationGate, "requireVaultAccess(owner)");
  assert.ok(normalize(textOf(row)).includes(normalize(H51)), `the row must state "${H51}" (plan §5 A5, H-51); it says: ${textOf(row)}`);
  assert.ok(normalize(DOC).includes(normalize(H51)), "the rendered inventory document carries the same statement");
});

test("RC45 T8 inventory: the reject row (POST /wallet/v4/requests/:id/reject) declares the narrowing — the request's signer or the vault owner only, anyone else 403 REQUEST_FORBIDDEN (A2, H-11) — its hostile evidence exercises the narrowing with a foreign principal (GATE 1), and the rendered document carries it [RED on C1]", () => {
  const row = rowOf("POST", "/wallet/v4/requests/:id/reject");
  const text = textOf(row);
  assert.match(text, /REQUEST_FORBIDDEN/, `the reject row names the 403 REQUEST_FORBIDDEN refusal (A2); it says: ${text}`);
  assert.match(text, /signer/i, "the reject row names the request's signer");
  assert.match(text, /owner/i, "the reject row names the vault owner");
  const evidence = fs.readFileSync(path.join(ROOT, row.hostileEvidence), "utf8");
  assert.match(evidence, /REQUEST_FORBIDDEN/, `the reject row's hostile evidence (${row.hostileEvidence}) exercises the 403 narrowing`);
  assert.match(evidence, /reject/, "and the reject route");
  assert.match(evidence, /foreign|FOREIGN|tenant|TENANT|stranger/, "with a foreign/tenant probe (GATE 1)");
  const docRow = DOC.split("\n").find((line) => line.includes("/wallet/v4/requests/:id/reject"));
  assert.ok(docRow, "the rendered document lists the reject route");
  assert.match(docRow, /REQUEST_FORBIDDEN/, "the rendered document's reject row carries the narrowing");
});
