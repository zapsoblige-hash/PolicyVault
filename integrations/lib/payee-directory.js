"use strict";

/*
 * Operator-configured payee directory (ap2-adapter-spec.md §3.3
 * "Destination — the strongest property in this spec").
 *
 * AP2 carries NO destination field — `payee` is {id, name, website?}, an
 * identity — so the destination is resolved ENTIRELY PolicyVault-side:
 * payee.id -> this directory -> a literal Kaspa address -> the x-only
 * key. The directory is deployment configuration under the vault owner's
 * control, NOT mandate content: no combination of mandate bytes, however
 * signed, can name a destination the operator has not already configured
 * — and even a directory entry pays nothing unless the key is ALSO in
 * the acting agent's covenant allowlist (the real gate; spec OQ-11).
 *
 * `payee.name` / `payee.website` are NEVER used for resolution or fuzzy
 * matching (A-3) — that would reintroduce the substitution vector the
 * directory removes. Resolution uses `payee.id` only, exact match.
 *
 * Closed schema (unknown fields refuse — fail closed):
 * {
 *   "schema":    "policyvault-payee-directory/v1",
 *   "networkId": "testnet-10" | "mainnet",
 *   "payees":    { "<payeeId>": { "address": "<literal Kaspa address>", "label"?: "<display only>" } }
 * }
 */

const fs = require("node:fs");
const { resolveLiteralDestination } = require("./address");

const DIRECTORY_SCHEMA = "policyvault-payee-directory/v1";
const PAYEE_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

class PayeeDirectoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PayeeDirectoryError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PayeeDirectoryError(code, message);
}

/*
 * Validate + resolve a directory document into a frozen Map
 * payeeId -> { address, xOnlyPubkey, label }. Every address is pushed
 * through the authoritative parser at LOAD time, so a malformed or
 * wrong-network entry fails the whole deployment closed at startup
 * rather than one payment at a time.
 */
function loadPayeeDirectory(config, document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) fail("DIRECTORY_INVALID", "payee directory must be an object");
  const keys = Object.keys(document).sort();
  const expected = ["networkId", "payees", "schema"];
  if (keys.join(",") !== expected.join(",")) {
    fail("DIRECTORY_INVALID", `payee directory must have exactly the keys ${expected.join("/")} — got ${keys.join("/") || "(none)"}`);
  }
  if (document.schema !== DIRECTORY_SCHEMA) fail("DIRECTORY_SCHEMA_UNSUPPORTED", `unknown payee-directory schema ${JSON.stringify(document.schema)} — failing closed`);
  if (document.networkId !== config.networkId) {
    fail("DIRECTORY_NETWORK_MISMATCH", `payee directory is stamped for ${JSON.stringify(document.networkId)} but the adapter is configured for ${JSON.stringify(config.networkId)} — refusing`);
  }
  if (!document.payees || typeof document.payees !== "object" || Array.isArray(document.payees)) fail("DIRECTORY_INVALID", "payees must be an object map");
  const out = new Map();
  for (const [payeeId, entry] of Object.entries(document.payees)) {
    if (!PAYEE_ID_RE.test(payeeId)) fail("DIRECTORY_INVALID", `payee id ${JSON.stringify(payeeId)} is outside the closed id grammar`);
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) fail("DIRECTORY_INVALID", `payee ${payeeId}: entry must be an object`);
    for (const k of Object.keys(entry)) {
      if (k !== "address" && k !== "label") fail("DIRECTORY_INVALID", `payee ${payeeId}: unknown field ${JSON.stringify(k)} — failing closed`);
    }
    if (entry.label !== undefined && (typeof entry.label !== "string" || entry.label.length > 255)) {
      fail("DIRECTORY_INVALID", `payee ${payeeId}: label must be a string <= 255 chars`);
    }
    const resolved = resolveLiteralDestination(config, entry.address, {
      notLiteralCode: "DIRECTORY_ADDRESS_INVALID",
      invalidCode: "DIRECTORY_ADDRESS_INVALID"
    });
    out.set(payeeId, Object.freeze({ address: resolved.address, xOnlyPubkey: resolved.xOnlyPubkey, label: entry.label ?? null }));
  }
  return out;
}

function loadPayeeDirectoryFile(config, filePath) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    fail("DIRECTORY_UNAVAILABLE", `cannot read payee directory ${filePath}: ${error.message} — failing closed`);
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    fail("DIRECTORY_INVALID", `payee directory ${filePath} is not valid JSON — failing closed`);
  }
  return loadPayeeDirectory(config, document);
}

module.exports = { DIRECTORY_SCHEMA, PayeeDirectoryError, loadPayeeDirectory, loadPayeeDirectoryFile };
