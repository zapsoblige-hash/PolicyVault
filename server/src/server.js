"use strict";

/*
 * PolicyVault HTTP server. Thin adapter over api.js with security headers,
 * CORS for the local frontend, and machine-readable error envelopes.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { handle, API_VERSION, loadConfig } = require("./api");
const { assertDataRootNetwork } = require("../../sdk/src/config");

const PORT = Number(process.env.POLICYVAULT_API_PORT || 3080);
const WEB_ROOT = path.join(__dirname, "..", "..", "web");

function apiHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  // Security-sensitive API responses are never cached.
  res.setHeader("Cache-Control", "no-store");
  // NO CORS headers: the API is same-origin only (the frontend is served by
  // this same server). A cross-origin page must not be able to read or drive
  // the local API; browser-origin POSTs are additionally Origin-checked.
}

/* Same-origin gate for browser-initiated mutating requests: a request that
 * carries an Origin header must originate from THIS server (loopback). Tools
 * without an Origin header (curl, local scripts) are unaffected. */
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const o = new URL(origin);
    const host = req.headers.host || `127.0.0.1:${PORT}`;
    return (o.hostname === "127.0.0.1" || o.hostname === "localhost") && `${o.hostname}:${o.port || (o.protocol === "https:" ? "443" : "80")}` === host;
  } catch {
    return false;
  }
}

/* Read and parse a JSON request body (1 MB cap, fail closed). */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(Object.assign(new Error("request body too large"), { status: 413, code: "BODY_TOO_LARGE" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(Object.assign(new Error("invalid JSON body"), { status: 400, code: "BAD_JSON" }));
      }
    });
    req.on("error", reject);
  });
}

function serveStatic(res, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = path.join(WEB_ROOT, rel);
  if (!filePath.startsWith(WEB_ROOT) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
    return;
  }
  const ext = path.extname(filePath);
  const type = ext === ".html" ? "text/html" : ext === ".js" ? "text/javascript" : ext === ".css" ? "text/css" : ext === ".png" ? "image/png" : "application/octet-stream";
  // All application scripts are external files — no inline script is allowed.
  // (Inline styles remain: index.html carries its stylesheet inline.)
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'");
  // Never serve a stale app build (the H2 stale-cache incident class).
  res.setHeader("Cache-Control", "no-cache");
  res.writeHead(200, { "Content-Type": type });
  res.end(fs.readFileSync(filePath));
}

function send(res, status, body) {
  const payload = JSON.stringify(body, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(payload);
}

/*
 * Production-startup validation + report (Checkpoint I §12–§14): the data
 * root's owning network is enforced, inconsistent flag combinations refuse
 * to start, and the effective posture is reported without secrets.
 */
function validateStartup(config) {
  assertDataRootNetwork(config);
  const devSigner = process.env.POLICYVAULT_DEV_SIGNER === "1";
  const legacyCreate = process.env.POLICYVAULT_LEGACY_CREATE === "1";
  const testHooks = Boolean(process.env.PV_TEST_CRASH_AT);
  if (config.networkId === "mainnet" && (devSigner || testHooks || legacyCreate)) {
    throw new Error("refusing to start: dev signer / test hooks / legacy create must not be enabled on mainnet");
  }
  return {
    network: config.networkId,
    dataRoot: config.dataRoot,
    devSigner: devSigner ? "ENABLED (development)" : "disabled",
    testHooks: testHooks ? "ARMED (development)" : "disabled",
    legacyCreate: legacyCreate ? "ENABLED (development)" : "disabled",
    mainnetBroadcast: config.networkId === "mainnet" && config.allowMainnet ? "ENABLED" : "disabled (Gate R)",
    donation: (() => {
      try {
        const { validateDonationAddress } = require("../../sdk/src/donation-address");
        return `configured (${validateDonationAddress(config, config.donationAddress).addressType})`;
      } catch (e) {
        return `NOT AVAILABLE (${e.code || "invalid"})`;
      }
    })()
  };
}

function createServer(config) {
  validateStartup(config);
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const parts = url.pathname.split("/").filter(Boolean);

    // Static frontend for non-API routes.
    if (parts[0] !== "api") {
      if (req.method !== "GET") {
        res.writeHead(405);
        res.end();
        return;
      }
      serveStatic(res, url.pathname);
      return;
    }

    apiHeaders(res);
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method !== "GET" && req.method !== "POST") {
      send(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: "only GET and POST are supported" } });
      return;
    }
    // Browser-initiated cross-origin requests are refused (same-origin API).
    if (req.method === "POST" && !originAllowed(req)) {
      send(res, 403, { error: { code: "ORIGIN_FORBIDDEN", message: "cross-origin requests are not allowed" } });
      return;
    }

    // API is mounted under /api/v1
    if (parts.length < 2 || parts[1] !== API_VERSION) {
      send(res, 404, { error: { code: "NOT_FOUND", message: "API is mounted at /api/v1" } });
      return;
    }
    const segments = parts.slice(2);
    const query = Object.fromEntries(url.searchParams.entries());

    try {
      const body = req.method === "POST" ? await readJsonBody(req) : undefined;
      const result = await handle(config, req.method, segments, query, body);
      send(res, result.status, result.body);
    } catch (error) {
      const status = error.status || 500;
      send(res, status, { error: { code: error.code || "INTERNAL", message: error.message, ...(error.extra ? { ...error.extra } : {}) } });
    }
  });
}

if (require.main === module) {
  // Gate R deployment contract (docs/production-release.md §8): a mainnet
  // server requires BOTH KASPA_NETWORK_ID=mainnet and
  // POLICYVAULT_ALLOW_MAINNET=true (the env flag doubles as the operator's
  // explicit override here), plus an explicit KASPA_RPC_URL. loadConfig still
  // refuses mainnet unless both sides of the dual flag are present.
  const config = loadConfig({ allowMainnet: process.env.POLICYVAULT_ALLOW_MAINNET === "true" });
  const server = createServer(config);
  const report = validateStartup(config);
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`PolicyVault API on http://127.0.0.1:${PORT}/api/${API_VERSION}`);
    for (const [k, v] of Object.entries(report)) console.log(`  ${k}: ${v}`);
  });
}

module.exports = { createServer, validateStartup };
