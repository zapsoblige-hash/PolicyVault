#!/usr/bin/env node
"use strict";

/*
 * Launcher for the PolicyVault x402 facilitator — a separately deployed,
 * unprivileged, READ-ONLY chain verification / settlement attestation
 * service. Configuration is environment-only (see ../config.js); no
 * PolicyVault credential exists here, no key material is ever loaded.
 *
 * Usage: PV_X402F_NETWORK=kaspa:testnet-10 PV_X402F_RPC_URL=ws://127.0.0.1:18210 \
 *        PV_X402F_DATA_DIR=/var/lib/pv-x402f node integrations/x402-facilitator/bin/x402-facilitator.js
 * Mainnet additionally requires POLICYVAULT_ALLOW_MAINNET=true and
 * --allow-mainnet (dual unlock) and is a separate owner deployment gate.
 */

const path = require("node:path");
const { loadFacilitatorConfig } = require("../config");
const { AssetRegistry } = require("../assets");
const { PrincipalStore } = require("../principals");
const { JsonClaimStore, PgClaimStore } = require("../claims");
const { NodeSession } = require("../node");
const { Facilitator } = require("../facilitator");
const { createFacilitatorService } = require("../service");
const { scriptPublicKeyForAddress, addressForScriptPublicKey } = require("../../../sdk/src/tx-identity");

async function main() {
  const allowMainnet = process.argv.includes("--allow-mainnet");
  const config = loadFacilitatorConfig(process.env, { allowMainnet });

  let claims;
  let pool = null;
  if (config.store === "postgres") {
    // The facilitator runtime never imports a database driver; the launcher
    // resolves `pg` from the SDK package and injects a query function.
    const pgPath = require.resolve("pg", { paths: [path.join(__dirname, "..", "..", "..", "sdk")] });
    const { Pool } = require(pgPath);
    pool = new Pool({ host: config.pg.host, port: config.pg.port, user: config.pg.user, password: config.pg.password, database: config.pg.database, ssl: config.pg.ssl ? { rejectUnauthorized: true } : undefined, max: config.pg.poolMax });
    claims = new PgClaimStore({ query: (sql, params) => pool.query(sql, params) });
    await claims.ensureSchema();
  } else {
    claims = new JsonClaimStore({ dir: config.claimsDir });
  }
  const principals = new PrincipalStore({ dir: config.principalsDir });
  const assets = new AssetRegistry(config.descriptors);
  const node = new NodeSession({ config: config.chainConfig, bound: config.bound, timeoutMs: config.nodeTimeoutMs });
  const facilitator = new Facilitator({
    chainConfig: config.chainConfig,
    bound: config.bound,
    assets,
    claims,
    node,
    minDepthDaa: config.minDepthDaa,
    addressGate: (address) => scriptPublicKeyForAddress(config.chainConfig, address),
    addressForScript: (scriptHex) => addressForScriptPublicKey(config.chainConfig, scriptHex)
  });
  const log = (line) => process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), ...line })}\n`);
  const server = createFacilitatorService({ facilitator, principals, rateLimitPerMinute: config.rateLimitPerMinute, log });
  await new Promise((resolve) => server.listen(config.listen.port, config.listen.host, resolve));
  log({ event: "listening", host: config.listen.host, port: server.address().port, network: config.networkIdentifier, store: config.store, assets: assets.list(), minDepthDaa: config.minDepthDaa.toString() });
  const shutdown = async () => {
    log({ event: "shutdown" });
    server.close();
    await node.close();
    if (pool) await pool.end();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => {
  process.stderr.write(`x402-facilitator: ${e.message}\n`);
  process.exit(1);
});
