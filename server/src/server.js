"use strict";

/*
 * PolicyVault HTTP server. Thin adapter over api.js with security headers,
 * request protection (Origin/Host verification, rate limits, concurrency
 * semaphores — server/src/limits.js), and machine-readable error envelopes.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { handle, API_VERSION, loadConfig } = require("./api");
const { assertDataRootNetwork } = require("../../sdk/src/config");
const { verifyHost, verifyOrigin, clientIp, RateLimiter, Semaphore, classifyRoute, assertJsonDepth } = require("./limits");
const metrics = require("./metrics");

const PORT = Number(process.env.POLICYVAULT_API_PORT || 3080);
const WEB_ROOT = path.join(__dirname, "..", "..", "web");

/* Headers shared by every response class (API and static). */
function baseHeaders(config, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // HSTS is meaningful only for the hosted https application origin
  // (TLS terminates at the edge; the origin still declares the policy).
  if (config.authMode === "enabled" && config.appOrigin.startsWith("https:")) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

function apiHeaders(config, res) {
  baseHeaders(config, res);
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  // Security-sensitive API responses are never cached.
  res.setHeader("Cache-Control", "no-store");
  // NO CORS headers: the API is same-origin only (the frontend is served by
  // this same server). A cross-origin page must not be able to read or drive
  // the API; state-changing requests are additionally Origin-verified
  // (limits.js — hosted mode enforces the configured application origin).
}

/* Read and parse a JSON request body (1 MB cap, depth cap, fail closed).
 * A client that disconnects (or is cut off by the slow-client deadline)
 * mid-body settles the promise — the handler never hangs on it. */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        fail(Object.assign(new Error("request body too large"), { status: 413, code: "BODY_TOO_LARGE" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      if (chunks.length === 0) {
        settled = true;
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        assertJsonDepth(parsed);
        settled = true;
        resolve(parsed);
      } catch (e) {
        if (e && e.code === "BODY_TOO_DEEP") {
          fail(e);
          return;
        }
        fail(Object.assign(new Error("invalid JSON body"), { status: 400, code: "BAD_JSON" }));
      }
    });
    req.on("error", (e) => fail(Object.assign(e instanceof Error ? e : new Error("request stream error"), { status: 400, code: "BODY_ABORTED" })));
    req.on("close", () => fail(Object.assign(new Error("request closed before the body completed"), { status: 400, code: "BODY_ABORTED" })));
  });
}

function serveStatic(config, res, pathname) {
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
  baseHeaders(config, res);
  res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  // Never serve a stale app build (the H2 stale-cache incident class).
  res.setHeader("Cache-Control", "no-cache");
  res.writeHead(200, { "Content-Type": type });
  res.end(fs.readFileSync(filePath));
}

function send(res, status, body, error) {
  // The client may already be gone (disconnect, slow-client cutoff).
  if (res.writableEnded || res.destroyed || (res.socket && res.socket.destroyed)) return;
  if (error && error.retryAfterSeconds !== undefined) {
    res.setHeader("Retry-After", String(error.retryAfterSeconds));
  }
  const payload = JSON.stringify(body, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(payload);
}

function sendError(res, error) {
  const status = error.status || 500;
  send(res, status, { error: { code: error.code || "INTERNAL", message: error.message, ...(error.extra ? { ...error.extra } : {}) } }, error);
}

/*
 * Production-startup validation + report (Checkpoint I §12–§14): the data
 * root's owning network is enforced, inconsistent flag combinations refuse
 * to start, and the effective posture is reported without secrets.
 */
function validateStartup(config) {
  if (!config || typeof config !== "object" || !config.requestProtection) {
    // Hand-rolled configs fail closed with a clear reason: every real
    // config comes from loadConfig(), which always builds this block.
    throw new Error("refusing to start: config lacks requestProtection — construct configs with loadConfig()");
  }
  assertDataRootNetwork(config);
  const devSigner = process.env.POLICYVAULT_DEV_SIGNER === "1";
  const legacyCreate = process.env.POLICYVAULT_LEGACY_CREATE === "1";
  const testHooks = Boolean(process.env.PV_TEST_CRASH_AT);
  if (config.networkId === "mainnet" && (devSigner || testHooks || legacyCreate)) {
    throw new Error("refusing to start: dev signer / test hooks / legacy create must not be enabled on mainnet");
  }
  const rp = config.requestProtection;
  return {
    network: config.networkId,
    dataRoot: config.dataRoot,
    devSigner: devSigner ? "ENABLED (development)" : "disabled",
    testHooks: testHooks ? "ARMED (development)" : "disabled",
    legacyCreate: legacyCreate ? "ENABLED (development)" : "disabled",
    mainnetBroadcast: config.networkId === "mainnet" && config.allowMainnet ? "ENABLED" : "disabled (Gate R)",
    hostedAuth:
      config.authMode === "enabled"
        ? `enabled (origin ${config.appOrigin}, ${config.authCookieSecure ? "Secure cookies" : "INSECURE COOKIES — local/testnet testing only"})`
        : "disabled (self-hosted mode)",
    bind: `${config.bindAddress}:${PORT}${config.bindAddress === "127.0.0.1" || config.bindAddress === "::1" ? " (loopback)" : " (NON-LOOPBACK — an enclosing private network/firewall is required)"}`,
    ...(config.buildId ? { buildId: config.buildId } : {}),
    ...(config.stagingBanner ? { staging: "STAGING BANNER ENABLED — non-production deployment" } : {}),
    persistence: config.persistenceBackend,
    requestProtection: `origin ${rp.originEnforced ? "ENFORCED (hosted)" : "loopback gate (self-hosted)"}, rate limits ${
      rp.rateLimitsEnabled ? "enabled" : "disabled"
    }, semaphores rpc ${rp.semaphores.rpc.max}+${rp.semaphores.rpc.queue}q / compute ${rp.semaphores.compute.max}+${rp.semaphores.compute.queue}q${
      rp.trustedProxyHeader ? `, client IP from ${rp.trustedProxyHeader}` : ""
    }`,
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
  const rp = config.requestProtection;
  const limiter = new RateLimiter(rp.rateLimits);
  const semaphores = {
    rpc: new Semaphore(rp.semaphores.rpc),
    compute: new Semaphore(rp.semaphores.compute)
  };

  /* Rate-limit one request across its keys (IP always; session or machine
   * identity when present). Throws 429 RATE_LIMITED when any bucket is
   * exhausted. Per-identity keying (completion-standard surface 6) mirrors
   * the existing session keying exactly: a cheap hash of the presented
   * bearer token, no store lookup here (an invalid token still gets its
   * own bounded bucket — harmless, and consistent with how a bogus
   * session cookie is treated the same way today) — the credential is
   * cryptographically resolved-or-refused separately, in
   * requestAuthPrincipal. A distinct per-identity bucket means one
   * compromised/shared IP cannot starve a machine identity's own budget,
   * and vice versa. */
  function checkRateLimits(req, rateClass) {
    if (!rp.rateLimitsEnabled) return;
    limiter.check(rateClass, `ip:${clientIp(config, req)}`);
    if (config.authMode === "enabled" && req.headers.cookie) {
      const { sessionTokenFromCookieHeader } = require("./auth");
      const token = sessionTokenFromCookieHeader(config, req.headers.cookie);
      if (token) {
        limiter.check(rateClass, `session:${crypto.createHash("sha256").update(token).digest("hex").slice(0, 32)}`);
      }
    }
    if (config.authMode === "enabled" && typeof req.headers.authorization === "string" && req.headers.authorization.trim()) {
      limiter.check(rateClass, `machine:${crypto.createHash("sha256").update(req.headers.authorization).digest("hex").slice(0, 32)}`);
    }
  }

  // Node enforces headersTimeout/requestTimeout on this check interval
  // (default 30 s) — follow the configured windows so tight timeouts are
  // enforced promptly.
  const connectionsCheckingInterval = Math.min(
    30_000,
    Math.max(500, Math.floor(Math.min(rp.httpTimeouts.headersMs, rp.httpTimeouts.requestMs) / 2))
  );
  const server = http.createServer({ connectionsCheckingInterval }, async (req, res) => {
    /*
     * OBSERVABILITY (surface 25; server/src/metrics.js): one in-process
     * counter/histogram record + one structured JSON log line per finished
     * request. PRIVACY: routeClass comes from the CLOSED enumeration
     * (never the raw path — paths can embed vault ids); principalType is
     * the PRESENTED credential kind derived from header PRESENCE only
     * (never the credential, never a resolved identity); the refusal code
     * is the machine-readable error code. Recording never throws and can
     * never fail a request.
     */
    const observedStartMs = Date.now();
    let observedRoute = "static";
    let observedCode = null;
    const principalType = req.headers.authorization ? "machine" : config.authMode === "enabled" && req.headers.cookie ? "wallet" : "none";
    res.on("finish", () => {
      const durationMs = Date.now() - observedStartMs;
      metrics.recordApiRequest({ routeClass: observedRoute, method: req.method, status: res.statusCode, durationMs, code: observedCode });
      metrics.logRequestLine({ routeClass: observedRoute, method: req.method, status: res.statusCode, durationMs, principalType, code: observedCode });
    });
    const refuse = (error) => {
      observedCode = error.code || "INTERNAL";
      sendError(res, error);
    };

    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
    } catch {
      refuse(Object.assign(new Error("malformed request URL"), { status: 400, code: "BAD_REQUEST" }));
      return;
    }
    const parts = url.pathname.split("/").filter(Boolean);

    // Host verification applies to EVERYTHING served (DNS-rebinding guard).
    try {
      verifyHost(config, req.headers.host);
    } catch (error) {
      refuse(error);
      return;
    }

    // Static frontend for non-API routes.
    if (parts[0] !== "api") {
      if (req.method !== "GET") {
        res.writeHead(405);
        res.end();
        return;
      }
      try {
        checkRateLimits(req, "static");
      } catch (error) {
        refuse(error);
        return;
      }
      serveStatic(config, res, url.pathname);
      return;
    }

    apiHeaders(config, res);
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method !== "GET" && req.method !== "POST") {
      send(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: "only GET and POST are supported" } });
      return;
    }

    // API is mounted under /api/v1
    if (parts.length < 2 || parts[1] !== API_VERSION) {
      observedRoute = "other";
      observedCode = "NOT_FOUND";
      send(res, 404, { error: { code: "NOT_FOUND", message: "API is mounted at /api/v1" } });
      return;
    }
    const segments = parts.slice(2);
    const query = Object.fromEntries(url.searchParams.entries());
    observedRoute = metrics.metricsRouteClass(req.method, segments);

    let release = null;
    try {
      // Same-origin gate for state-changing requests (CSRF wall #2;
      // hosted mode enforces the configured application origin). cookie +
      // authorization feed the programmatic-client (machine-credential)
      // exemption — see limits.js verifyOrigin's doc comment; the cookie
      // path is completely unchanged by their presence.
      verifyOrigin(config, {
        method: req.method,
        origin: req.headers.origin,
        secFetchSite: req.headers["sec-fetch-site"],
        host: req.headers.host,
        cookie: req.headers.cookie,
        authorization: req.headers.authorization
      });

      // Per-class rate limits, keyed by client IP and (when present)
      // hosted session. A refusal here is pure: nothing durable happened.
      const { rateClass, semaphore } = classifyRoute(req.method, segments);
      checkRateLimits(req, rateClass);

      const body = req.method === "POST" ? await readJsonBody(req) : undefined;

      // Concurrency bound for expensive work (RPC dials, build/preflight
      // compute). Bounded queue; saturation refuses with 429.
      if (semaphore) release = await semaphores[semaphore].acquire();

      // ctx carries ONLY what routes may legitimately need (the Cookie
      // header for hosted-session resolution). Routes never treat other
      // request headers as trusted identity or configuration. authorization
      // (machine Bearer credential) and idempotencyKey (Idempotency-Key)
      // are the platform-agent-api additions — additive: a request that
      // sends neither behaves byte-identically to before.
      const result = await handle(config, req.method, segments, query, body, {
        headers: {
          cookie: req.headers.cookie,
          authorization: req.headers.authorization,
          idempotencyKey: req.headers["idempotency-key"]
        }
      });
      if (result.headers) {
        for (const [name, value] of Object.entries(result.headers)) res.setHeader(name, value);
      }
      if (result && typeof result.rawBody === "string") {
        // Non-JSON API response (GET /metrics?format=prometheus text
        // exposition). Content-Type comes from result.headers above.
        if (!(res.writableEnded || res.destroyed || (res.socket && res.socket.destroyed))) {
          res.writeHead(result.status);
          res.end(result.rawBody);
        }
      } else {
        send(res, result.status, result.body);
      }
    } catch (error) {
      refuse(error);
    } finally {
      if (release) release();
    }
  });

  // Slow-client bounds: request headers, then the entire request, must
  // arrive within the configured windows (Phase D DoS hardening).
  server.headersTimeout = rp.httpTimeouts.headersMs;
  server.requestTimeout = rp.httpTimeouts.requestMs;
  /*
   * DETERMINISTIC enforcement of those windows. Node's own connection
   * checker was observed NOT to fire on this runtime (v20.20.x, probed
   * 2026-08-24: neither a header-stalled nor a body-stalled socket was
   * ever destroyed despite headersTimeout/requestTimeout/
   * connectionsCheckingInterval) — so the receive deadlines are enforced
   * here explicitly, per socket:
   *   headers deadline — from connection (and, on keep-alive, from each
   *     response) until the next request's headers are parsed;
   *   request deadline — from parsed headers until the request body is
   *     fully received. Handler PROCESSING time is deliberately not
   *     bounded here (a submit awaiting chain proof must not be cut).
   * Destroying the socket is the only correct refusal for a client that
   * will not finish sending — there is no well-formed request to answer.
   */
  server.on("connection", (socket) => {
    let deadline = null;
    const clearDeadline = () => {
      if (deadline) {
        clearTimeout(deadline);
        deadline = null;
      }
    };
    const armHeadersDeadline = () => {
      clearDeadline();
      deadline = setTimeout(() => socket.destroy(), rp.httpTimeouts.headersMs);
      deadline.unref();
    };
    socket.pvClearDeadline = clearDeadline;
    socket.pvArmHeadersDeadline = armHeadersDeadline;
    armHeadersDeadline();
    socket.on("close", clearDeadline);
  });
  server.on("request", (req, res) => {
    const socket = req.socket;
    if (socket.pvClearDeadline) socket.pvClearDeadline();
    let deadline = setTimeout(() => socket.destroy(), rp.httpTimeouts.requestMs);
    deadline.unref();
    const bodyReceived = () => {
      if (deadline) {
        clearTimeout(deadline);
        deadline = null;
      }
    };
    req.on("end", bodyReceived);
    req.on("close", bodyReceived);
    res.on("finish", () => {
      bodyReceived();
      // Keep-alive: the next request's headers get a fresh window (the
      // idle case is additionally governed by keepAliveTimeout).
      if (!socket.destroyed && socket.pvArmHeadersDeadline) socket.pvArmHeadersDeadline();
    });
  });
  // Introspection surface for tests and operational diagnostics — the
  // live protection state of THIS server instance (never client-writable
  // state; nothing here is exposed over HTTP).
  server.pvProtection = { limiter, semaphores };
  return server;
}

if (require.main === module) {
  // Gate R deployment contract (docs/production-release.md §8): a mainnet
  // server requires BOTH KASPA_NETWORK_ID=mainnet and
  // POLICYVAULT_ALLOW_MAINNET=true (the env flag doubles as the operator's
  // explicit override here), plus an explicit KASPA_RPC_URL. loadConfig still
  // refuses mainnet unless both sides of the dual flag are present.
  //
  // HOSTED STARTUP ORDER (Phase E, fail closed — docs/hosted-deployment.md):
  //   config validation → durable backend OPEN (postgres: connect + schema
  //   current + network stamp, via openPgStore) → startup posture validation
  //   → listen. The HTTP listener never opens before the durable backend is
  //   proven; the server NEVER auto-migrates (schema changes are an explicit
  //   operator step: `node server/src/migrate.js` — advisory-locked, so
  //   concurrent migrators serialize). Any startup failure exits non-zero
  //   without ever accepting a request.
  (async () => {
    const config = loadConfig({ allowMainnet: process.env.POLICYVAULT_ALLOW_MAINNET === "true" });
    if (config.persistenceBackend === "postgres") {
      const { openPgStore } = require("../../sdk/src/store");
      await openPgStore(config);
    }
    const server = createServer(config);
    const report = validateStartup(config);
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(PORT, config.bindAddress, () => {
        console.log(`PolicyVault API on http://${config.bindAddress}:${PORT}/api/${API_VERSION}`);
        for (const [k, v] of Object.entries(report)) console.log(`  ${k}: ${v}`);
        resolve();
      });
    });
    // Webhook delivery worker (surface 18): a fully decoupled background
    // loop over the durable event outbox. Started only AFTER the listener
    // is up; its failure (or POLICYVAULT_WEBHOOK_DELIVERY=0 disabling it)
    // never affects request processing — events-delivery.js header.
    try {
      const { startDeliveryWorker } = require("./events-delivery");
      const worker = startDeliveryWorker(config);
      console.log(`  webhookDelivery: ${worker ? "running" : "disabled (POLICYVAULT_WEBHOOK_DELIVERY=0)"}`);
    } catch (error) {
      console.error(`  webhookDelivery: FAILED TO START (${error.message}) — API serving continues; deliveries paused`);
    }
    // Human-notification worker (surface 19): a decoupled second consumer
    // of the same durable outbox (its own per-rule cursors). Its failure
    // (or POLICYVAULT_NOTIFY_DELIVERY=0) never affects request
    // processing, events, or webhook delivery — notify-delivery.js header.
    try {
      const { startNotificationWorker } = require("./notify-delivery");
      const notifier = startNotificationWorker(config);
      console.log(`  notifications: ${notifier ? "running" : "disabled (POLICYVAULT_NOTIFY_DELIVERY=0)"}`);
    } catch (error) {
      console.error(`  notifications: FAILED TO START (${error.message}) — API serving continues; notifications paused`);
    }
  })().catch((error) => {
    console.error(`PolicyVault startup failed (fail closed): ${error.message}`);
    process.exit(1);
  });
}

module.exports = { createServer, validateStartup };
