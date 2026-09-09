"use strict";

/*
 * Renders server/src/authorization-boundary-inventory.json to
 * docs/postlaunch/authorization-boundary-inventory.md (GATE 2, rc11
 * internal security review F-04). The JSON is the source of truth; the test
 * sdk/test/authorization-boundary-inventory.test.js fails when the document
 * on disk differs from this rendering.
 *
 *   node tools/render-authorization-inventory.js        # rewrite the doc
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const JSON_PATH = path.join(ROOT, "server/src/authorization-boundary-inventory.json");
const DOC_PATH = path.join(ROOT, "docs/postlaunch/authorization-boundary-inventory.md");

const esc = (v) => (v === null || v === undefined ? "—" : Array.isArray(v) ? (v.length ? v.map((s) => `\`${s}\``).join(" + ") : "(none — public)") : String(v).replace(/\|/g, "\\|"));

function render(inventory) {
  const out = [];
  out.push("# Authorization-boundary inventory (hosted API) — GATE 2");
  out.push("");
  out.push("GENERATED from `server/src/authorization-boundary-inventory.json` by");
  out.push("`tools/render-authorization-inventory.js`; do not edit by hand. Verified");
  out.push("mechanically by `sdk/test/authorization-boundary-inventory.test.js`.");
  out.push("");
  out.push("## Why this exists");
  out.push("");
  out.push("The rc11 internal security review (2026-09-04, finding F-04) found three");
  out.push("hosted route families that resolved — or never received — the request");
  out.push("principal and then discarded it. Every green floor that \"covered tenancy\"");
  out.push("measured only the v0.4 family. **Green floors measure what was tested.**");
  out.push("This inventory makes the authorization boundary a checked artifact: a new");
  out.push("route family, a scope drift, a missing principal, a bypassed tenancy");
  out.push("resolver, a tenant-owned mutation without a gate, a family without a");
  out.push("foreign-tenant hostile probe, or a `void principal` discard now FAILS the");
  out.push("floor instead of passing silently.");
  out.push("");
  out.push("## Column meanings");
  out.push("");
  out.push("| column | meaning |");
  out.push("|---|---|");
  out.push("| resource class | " + Object.entries(inventory.resourceClasses).map(([k, v]) => `**${k}** — ${v}`).join("; ") + " |");
  out.push("| principal type | " + Object.entries(inventory.principalTypes).map(([k, v]) => `**${k}** — ${v}`).join("; ") + " |");
  out.push("| auth gate | the symbol (in the named file) that resolves/requires the principal |");
  out.push("| tenancy resolver | the durable-fact resolver that scopes the object to the principal (`server/src/tenancy.js` export or a file-local gate) |");
  out.push("| mutation gate | the additional rule for state-changing routes |");
  out.push("| machine scope | `requiredScopesFor` result: `pvmk_` credentials need every listed scope; `null` = never machine-reachable |");
  out.push("| hostile evidence | the test that exercises this path with a FOREIGN principal (GATE 1) |");
  out.push("");
  out.push("## Standing rules for contributors");
  out.push("");
  out.push("1. Every new hosted route gets a row here BEFORE it ships; the test fails otherwise.");
  out.push("2. A route that receives `principal`/`ctx` must USE it; `void principal` is a lint failure unless listed under `documentedExceptions` with a reason.");
  out.push("3. Authority derives only from durable covenant facts (vault manifest participants, org-root active owner slots + pinned successor, request creator/signer) — never from hosted organization roles, request bodies, or headers.");
  out.push("4. Foreign objects answer the non-oracle 404; a known participant without the required authority gets 403; a foreign caller persists or locks NOTHING.");
  out.push("5. Every tenant-owned family carries a foreign-tenant hostile probe (foreign LIST/GET/CREATE/MUTATE refused, same-tenant accepted).");
  out.push("");
  out.push("## Documented exceptions");
  out.push("");
  if (!inventory.documentedExceptions || inventory.documentedExceptions.length === 0) out.push("None.");
  else for (const e of inventory.documentedExceptions) out.push(`- \`${e.file}\` \`${e.pattern}\` — ${e.reason}`);
  out.push("");
  out.push("## Routes");
  out.push("");
  const families = new Map();
  for (const r of inventory.routes) {
    const fam = r.path.split("/")[1] + (r.path.startsWith("/wallet/") ? "/" + (r.path.split("/")[2] || "") : "");
    if (!families.has(fam)) families.set(fam, []);
    families.get(fam).push(r);
  }
  for (const [fam, routes] of families) {
    out.push(`### /${fam}`);
    out.push("");
    out.push("| method | path | resource class | principal | auth gate (file) | tenancy resolver | mutation gate | machine scope | hostile evidence | note |");
    out.push("|---|---|---|---|---|---|---|---|---|---|");
    for (const r of routes) {
      out.push(`| ${r.method} | \`${r.path}\` | ${r.resourceClass} | ${r.principalType} | \`${esc(r.authGate)}\` (${esc(r.file)}) | ${esc(r.tenancyResolver)} | ${esc(r.mutationGate)} | ${esc(r.machineScope)} | ${r.hostileEvidence === "n/a" ? "—" : "`" + r.hostileEvidence + "`"} | ${esc(r.note ?? "")} |`);
    }
    out.push("");
  }
  out.push(`Routes: ${inventory.routes.length}. Families: ${families.size}.`);
  out.push("");
  return out.join("\n");
}

if (require.main === module) {
  const inventory = JSON.parse(fs.readFileSync(JSON_PATH, "utf8"));
  fs.writeFileSync(DOC_PATH, render(inventory));
  console.log(`wrote ${path.relative(ROOT, DOC_PATH)} (${inventory.routes.length} routes)`);
}

module.exports = { render };
