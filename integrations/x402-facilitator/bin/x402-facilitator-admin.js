#!/usr/bin/env node
"use strict";

/*
 * Operator CLI for resource-server principals + facilitator credentials
 * (spec §14.1). The raw credential is printed EXACTLY ONCE, alone, on
 * stdout at mint time and exists nowhere else (only its sha256 verifier is
 * persisted). Everything else goes to stderr.
 *
 *   PV_X402F_DATA_DIR=<dir> node x402-facilitator-admin.js principal create --id <id> --networks kaspa:testnet-10[,…] \
 *        --operations verify,settle (--payto <addr>[,…] | --payto-any) [--origins <origin>[,…]] [--label <text>] [--expires <iso>]
 *   … principal list
 *   … principal revoke --id <id>
 *   … credential mint --principal <id> [--label <text>] [--expires <iso>] [--overlap]
 *   … credential revoke --principal <id> --credential <uuid>
 */

const path = require("node:path");
const { PrincipalStore } = require("../principals");

function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) out[key] = true;
      else {
        out[key] = next;
        i += 1;
      }
    } else out._.push(a);
  }
  return out;
}

function main() {
  const a = args(process.argv.slice(2));
  const dataDir = process.env.PV_X402F_DATA_DIR;
  if (!dataDir) throw new Error("PV_X402F_DATA_DIR is required");
  const store = new PrincipalStore({ dir: path.join(dataDir, "principals") });
  const [noun, verb] = a._;
  const list = (v) => (typeof v === "string" ? v.split(",").map((s) => s.trim()).filter(Boolean) : []);

  if (noun === "principal" && verb === "create") {
    if (!a.id) throw new Error("--id required");
    const allowedPayTo = a["payto-any"] === true ? { mode: "any" } : { mode: "list", addresses: list(a.payto) };
    const allowedResourceOrigins = a.origins ? { mode: "list", origins: list(a.origins) } : { mode: "any" };
    const rec = store.createPrincipal({ principalId: a.id, label: typeof a.label === "string" ? a.label : "", operations: list(a.operations ?? "verify,settle"), networks: list(a.networks), allowedPayTo, allowedResourceOrigins, expiresAt: typeof a.expires === "string" ? a.expires : null });
    process.stderr.write(`created principal ${rec.principalId} (${rec.operations.join(",")}; ${rec.networks.join(",")}; payTo ${rec.allowedPayTo.mode})\n`);
    return;
  }
  if (noun === "principal" && verb === "list") {
    process.stdout.write(`${JSON.stringify(store.list(), null, 1)}\n`);
    return;
  }
  if (noun === "principal" && verb === "revoke") {
    if (!a.id) throw new Error("--id required");
    store.revokePrincipal(a.id);
    process.stderr.write(`revoked principal ${a.id} and all of its credentials\n`);
    return;
  }
  if (noun === "credential" && verb === "mint") {
    if (!a.principal) throw new Error("--principal required");
    const minted = store.mintCredential(a.principal, { label: typeof a.label === "string" ? a.label : "", expiresAt: typeof a.expires === "string" ? a.expires : null, allowOverlap: a.overlap === true });
    process.stderr.write(`minted credential ${minted.credentialId} for ${a.principal} — the raw value follows on stdout ONCE and is never shown again\n`);
    process.stdout.write(`${minted.raw}\n`);
    return;
  }
  if (noun === "credential" && verb === "revoke") {
    if (!a.principal || !a.credential) throw new Error("--principal and --credential required");
    store.revokeCredential(a.principal, a.credential);
    process.stderr.write(`revoked credential ${a.credential} on ${a.principal}\n`);
    return;
  }
  throw new Error("usage: principal create|list|revoke … | credential mint|revoke …");
}

try {
  main();
} catch (e) {
  process.stderr.write(`x402-facilitator-admin: ${e.message}\n`);
  process.exit(1);
}
