"use strict";

/*
 * PERMANENT PIN — MCP CUSTODY BOUNDARY (rc11 internal security review,
 * owner addendum §H: pin the properties that HELD under hostile probing).
 *
 * The review's MCP-authority probes (docs/postlaunch/audit-evidence/
 * rc11-internal-review/probes/mcp-probe.js) could not make the MCP server
 * sign, hold, derive or transmit any key material, broadcast without a
 * wallet-finalized request, or reach a route beyond its credential's
 * deny-by-default scopes. This test makes those held properties a checked
 * artifact (a mechanical source scan + the declared tool surface) so a
 * future "convenience" signing helper cannot land silently:
 *   - no signing / key primitive is referenced anywhere in mcp/src;
 *   - no declared tool name suggests signing, key handling or seed import;
 *   - every declared tool maps to an HTTP call through the shared http
 *     module (never a direct node/RPC connection);
 *   - the bearer credential is the ONLY secret the package handles and it
 *     is read from configuration, never from tool arguments.
 * Authority statement preserved: AI MAY REQUEST; POLICYVAULT
 * DETERMINISTICALLY DECIDES; THE COVENANT ENFORCES; SIGNERS RETAIN CUSTODY.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SRC = path.join(__dirname, "..", "src");
const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".js"));
const sources = Object.fromEntries(files.map((f) => [f, fs.readFileSync(path.join(SRC, f), "utf8")]));
const all = Object.values(sources).join("\n");

test("no signing / key / seed primitive is referenced in mcp/src (source scan)", () => {
  const forbidden = [/\bPrivateKey\b/, /createInputSignature/, /\bsignMessage\b/, /\bsignTransaction\b/, /\bmnemonic\b/i, /\bseed\s*phrase/i, /\bxprv\b/i, /\bsecp256k1\b/, /\bschnorr\b/i, /rustyKaspaModule/, /kaspa-wasm/, /require\(["'][^"']*kaspa[^"']*["']\)/];
  for (const re of forbidden) assert.doesNotMatch(all, re, `mcp/src must never reference ${re}`);
});

test("the declared tool surface carries no signing / key-handling tool and every tool is an HTTP call through the shared http module", () => {
  const names = [...sources["tools.js"].matchAll(/name:\s*"(policyvault_[a-z0-9_]+)"/g)].map((m) => m[1]);
  assert.ok(names.length >= 15, `expected the full tool surface, found ${names.length}`);
  for (const n of names) assert.doesNotMatch(n, /sign|key|seed|secret|broadcast_raw|submit_raw|import|export_key|custod/i, `tool ${n} suggests custody`);
  assert.ok(/require\("\.\/http"\)/.test(sources["tools.js"]), "tools call the shared http module");
  assert.doesNotMatch(sources["tools.js"], /\bws:\/\/|wss:\/\/|RpcClient|kaspad/i, "tools never open a node connection");
});

test("the bearer credential is the only secret and comes from configuration, never from tool arguments", () => {
  assert.match(sources["config.js"], /POLICYVAULT_MCP_TOKEN|token/i, "config reads the credential");
  assert.doesNotMatch(sources["tools.js"], /args\.(token|bearer|credential|apiKey|api_key)\b/, "tool arguments never carry a credential");
  assert.doesNotMatch(sources["schema.js"], /"(token|bearer|credential|privateKey|seed)"\s*:/, "schemas never declare a secret argument");
});
