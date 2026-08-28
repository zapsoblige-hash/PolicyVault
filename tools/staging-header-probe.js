"use strict";

/*
 * STAGING-ONLY ingress measurement probe (Phase E, directive §15).
 *
 * A THROWAWAY echo server — NOT part of the PolicyVault application and
 * never deployed with it — used once, behind its own temporary
 * Cloudflare Quick Tunnel, to MEASURE (not assume) what the edge
 * actually delivers to an origin: Host, Origin, Sec-Fetch-*,
 * CF-Connecting-IP, X-Forwarded-*, CF-Visitor/scheme, cookies, and the
 * response-header treatment on the way back.
 *
 * It binds loopback only and records every request's headers to stdout
 * as JSON lines. Response deliberately sets marker headers so the
 * round-trip treatment (added/stripped/rewritten) can be observed from
 * the client side.
 *
 * Usage: node tools/staging-header-probe.js [port]   (default 3099)
 *        cloudflared tunnel --url http://127.0.0.1:3099
 */

const http = require("http");

const PORT = Number(process.argv[2] || 3099);

const server = http.createServer((req, res) => {
  const record = {
    t: new Date().toISOString(),
    method: req.method,
    url: req.url,
    httpVersion: req.httpVersion,
    socketRemote: req.socket.remoteAddress,
    headers: req.headers
  };
  console.log(JSON.stringify(record));
  res.setHeader("Content-Type", "application/json");
  // marker headers: observe from the OUTSIDE which survive the edge
  res.setHeader("X-Probe-Marker", "origin-set");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'none'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Set-Cookie", "__Secure-probe=1; Secure; HttpOnly; SameSite=Strict; Path=/api");
  res.end(JSON.stringify({ received: record.headers, socketRemote: record.socketRemote }, null, 2));
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`staging-header-probe on http://127.0.0.1:${PORT} (loopback only; front with a temporary quick tunnel)`);
});
