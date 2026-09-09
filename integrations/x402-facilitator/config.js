"use strict";

/*
 * Closed configuration of the facilitator (spec §14, §17.8). Everything
 * is explicit and validated; unknown values fail closed. The network is
 * NEVER defaulted (a mainnet facilitator is a deliberate act: the frozen
 * identifier `kaspa:mainnet` + POLICYVAULT_ALLOW_MAINNET=true + an
 * explicit private node URL). Public node URLs are refused at boot.
 */

const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const { bindNetwork } = require("./network");
const { resolveMinDepth } = require("./policy");

const DEFAULT_WASM = path.join(os.homedir(), "rusty-kaspa/wasm/nodejs/kaspa");

function cfgFail(message) {
  throw new Error(`x402-facilitator config: ${message} — failing closed`);
}

function parseIntBounded(name, raw, fallback, min, max) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < min || n > max) cfgFail(`${name} must be an integer ${min}..${max}`);
  return n;
}

/* Private-only node addressing: loopback, RFC 1918 / ULA / link-local, or
 * a single-label host name (container / VPC service name). Anything else
 * — a public IP, an FQDN — is a public node and is refused. */
function isPrivateHost(hostname) {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost") return true;
  const family = net.isIP(h);
  if (family === 4) {
    const [a, b] = h.split(".").map(Number);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (family === 6) {
    return h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:");
  }
  return /^[a-z0-9]([a-z0-9-]{0,62})$/.test(h); // single label, no dots
}

function assertPrivateNodeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    cfgFail(`node URL ${JSON.stringify(String(raw))} is not a URL`);
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") cfgFail("node URL must be ws:// or wss://");
  if (url.username || url.password) cfgFail("node URL must not carry credentials");
  if (!isPrivateHost(url.hostname)) cfgFail(`node URL host ${JSON.stringify(url.hostname)} is not a private / loopback / single-label host — public nodes are refused`);
  return url.toString();
}

function loadFacilitatorConfig(env = process.env, overrides = {}) {
  const networkIdentifier = overrides.network ?? env.PV_X402F_NETWORK;
  if (typeof networkIdentifier !== "string" || !networkIdentifier) cfgFail("PV_X402F_NETWORK is required (kaspa:mainnet or kaspa:testnet-10); there is no default network");
  const bound = bindNetwork(networkIdentifier);

  const rpcUrlRaw = overrides.rpcUrl ?? env.PV_X402F_RPC_URL;
  if (typeof rpcUrlRaw !== "string" || !rpcUrlRaw) cfgFail("PV_X402F_RPC_URL is required (explicit private node URL)");
  const rpcUrl = assertPrivateNodeUrl(rpcUrlRaw);

  const allowMainnet = env.POLICYVAULT_ALLOW_MAINNET === "true" && overrides.allowMainnet === true;
  if (bound.kaspadNetworkId === "mainnet" && !allowMainnet) {
    cfgFail("mainnet is locked: it requires POLICYVAULT_ALLOW_MAINNET=true AND the explicit allowMainnet launch override (dual unlock), plus an explicit private mainnet node URL");
  }

  const rustyKaspaModule = overrides.rustyKaspaModule ?? env.PV_X402F_KASPA_WASM ?? DEFAULT_WASM;
  const minDepthDaa = resolveMinDepth(overrides.minDepthDaa ?? env.PV_X402F_MIN_DEPTH_DAA);

  const dataDir = overrides.dataDir ?? env.PV_X402F_DATA_DIR;
  if (typeof dataDir !== "string" || !dataDir) cfgFail("PV_X402F_DATA_DIR is required (principals + JSON claim store root)");

  const storeKind = overrides.store ?? env.PV_X402F_STORE ?? "json";
  if (storeKind !== "json" && storeKind !== "postgres") cfgFail(`unknown PV_X402F_STORE ${JSON.stringify(storeKind)}`);
  let pg = null;
  if (storeKind === "postgres") {
    const user = overrides.pgUser ?? env.PV_X402F_PG_USER;
    const database = overrides.pgDatabase ?? env.PV_X402F_PG_DATABASE;
    if (!user || !database) cfgFail("postgres store requires PV_X402F_PG_USER and PV_X402F_PG_DATABASE");
    const noTls = overrides.pgNoTls === true || env.PV_X402F_PG_NO_TLS === "1";
    if (noTls && bound.kaspadNetworkId === "mainnet") cfgFail("PV_X402F_PG_NO_TLS must not be set on mainnet");
    pg = Object.freeze({
      host: overrides.pgHost ?? env.PV_X402F_PG_HOST ?? "127.0.0.1",
      port: parseIntBounded("PV_X402F_PG_PORT", overrides.pgPort ?? env.PV_X402F_PG_PORT, 5432, 1, 65535),
      user,
      password: overrides.pgPassword ?? env.PV_X402F_PG_PASSWORD ?? undefined,
      database,
      ssl: !noTls,
      poolMax: parseIntBounded("PV_X402F_PG_POOL_MAX", overrides.pgPoolMax ?? env.PV_X402F_PG_POOL_MAX, 4, 1, 32)
    });
  }

  let descriptors = overrides.descriptors ?? [];
  const descriptorsFile = env.PV_X402F_DESCRIPTORS;
  if (overrides.descriptors === undefined && descriptorsFile) {
    const fs = require("node:fs");
    const list = JSON.parse(fs.readFileSync(descriptorsFile, "utf8"));
    if (!Array.isArray(list)) cfgFail("PV_X402F_DESCRIPTORS must be a JSON array of { descriptorHash, file }");
    descriptors = list.map((e) => ({ ...e, file: e.file ? path.resolve(path.dirname(descriptorsFile), e.file) : undefined }));
  }

  const listenHost = overrides.listenHost ?? env.PV_X402F_LISTEN_HOST ?? "127.0.0.1";
  const allowNonLoopback = overrides.allowNonLoopback === true || env.PV_X402F_ALLOW_NON_LOOPBACK === "1";
  if (!["127.0.0.1", "localhost", "::1"].includes(listenHost) && !allowNonLoopback) {
    cfgFail(`listen host ${JSON.stringify(listenHost)} is not loopback — set PV_X402F_ALLOW_NON_LOOPBACK=1 only behind a TLS-terminating proxy (resource-server credentials travel over HTTPS)`);
  }

  return Object.freeze({
    bound,
    networkIdentifier: bound.identifier,
    kaspadNetworkId: bound.kaspadNetworkId,
    rpcUrl,
    rustyKaspaModule,
    chainConfig: Object.freeze({ networkId: bound.kaspadNetworkId, rpcUrl, rustyKaspaModule }),
    allowMainnet,
    minDepthDaa,
    dataDir,
    principalsDir: path.join(dataDir, "principals"),
    claimsDir: path.join(dataDir, "claims"),
    store: storeKind,
    pg,
    descriptors,
    listen: Object.freeze({ host: listenHost, port: parseIntBounded("PV_X402F_LISTEN_PORT", overrides.listenPort ?? env.PV_X402F_LISTEN_PORT, 3402, 0, 65535) }),
    rateLimitPerMinute: parseIntBounded("PV_X402F_RATE_PER_MINUTE", overrides.rateLimitPerMinute ?? env.PV_X402F_RATE_PER_MINUTE, 120, 1, 100000),
    nodeTimeoutMs: parseIntBounded("PV_X402F_NODE_TIMEOUT_MS", overrides.nodeTimeoutMs ?? env.PV_X402F_NODE_TIMEOUT_MS, 15000, 1000, 120000)
  });
}

module.exports = { loadFacilitatorConfig, assertPrivateNodeUrl, isPrivateHost };
