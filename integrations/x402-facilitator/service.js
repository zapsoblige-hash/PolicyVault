"use strict";

/*
 * HTTP surface of the facilitator (x402 facilitator API shape; spec §2,
 * §14, §14.1, §17.7). Zero runtime dependencies (node:http only).
 *
 *   GET  /supported   PUBLIC — kinds this facilitator verifies
 *   GET  /healthz     PUBLIC — liveness only (never touches the node)
 *   POST /verify      AUTHENTICATED RESOURCE SERVER — deterministic check, no state change
 *   POST /settle      AUTHENTICATED RESOURCE SERVER — check + atomic single-use claim
 *
 * Request order on the authenticated routes is FIXED: query-string
 * refusal → credential (401) → operation scope (403) → per-principal
 * rate limit (429) → body cap (413) → facilitator. An unauthenticated
 * request therefore never reaches the body parser, the store, or the
 * node (zero acceptance, zero mutation, zero replay consumption, zero
 * evidence, zero anonymous downgrade). Credentials are never logged.
 */

const http = require("node:http");
const { describe } = require("./codes");
const { CAPS } = require("./schema");
const { PRINCIPAL_OPERATIONS } = require("./constants");

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), "Cache-Control": "no-store" });
  res.end(text);
}

function authRefusal(res, code, envelope) {
  const info = describe(code);
  const body = envelope === "settle"
    ? { success: false, errorReason: code, extensions: { policyvault: { status: "REFUSED", reasonClass: info.cls, reason: code, explanation: info.text } } }
    : { isValid: false, invalidReason: code, extensions: { policyvault: { status: "REFUSED", reasonClass: info.cls, reason: code, explanation: info.text } } };
  if (info.http === 401) res.setHeader("WWW-Authenticate", 'Bearer realm="policyvault-x402-facilitator"');
  send(res, info.http, body);
}

/* Process-local token bucket per principal (availability protection ONLY). */
class RateLimiter {
  constructor({ perMinute }) {
    this.capacity = perMinute;
    this.refillPerMs = perMinute / 60000;
    this.buckets = new Map();
  }
  take(key, now = Date.now()) {
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.capacity, at: now };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.capacity, b.tokens + (now - b.at) * this.refillPerMs);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return { ok: true };
    }
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((1 - b.tokens) / this.refillPerMs / 1000)) };
  }
}

function readBody(req, res, cap) {
  return new Promise((resolve) => {
    // A declared Content-Length above the cap is refused before ANY byte is read.
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > cap) {
      req.pause();
      resolve({ tooLarge: true });
      return;
    }
    let size = 0;
    const chunks = [];
    let done = false;
    req.on("data", (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > cap) {
        done = true;
        req.pause(); // stop consuming; the socket is closed AFTER the 413 has flushed
        resolve({ tooLarge: true });
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      resolve({ text: Buffer.concat(chunks).toString("utf8") });
    });
    req.on("error", () => {
      if (!done) {
        done = true;
        resolve({ error: true });
      }
    });
  });
}

function createFacilitatorService({ facilitator, principals, rateLimitPerMinute = 120, log = () => {}, bodyCapBytes = CAPS.bodyBytes }) {
  if (!facilitator || !principals) throw new Error("x402-facilitator service: facilitator and principals are required");
  const limiter = new RateLimiter({ perMinute: rateLimitPerMinute });
  const stats = { verify: 0, settle: 0, unauthenticated: 0, forbidden: 0, rateLimited: 0 };

  const server = http.createServer(async (req, res) => {
    req.socket.setTimeout(30_000, () => req.destroy());
    const started = Date.now();
    const url = new URL(req.url, "http://localhost");
    const route = url.pathname;

    if (req.method === "GET" && route === "/healthz") return send(res, 200, { ok: true, service: "policyvault-x402-facilitator", role: "read-only chain verification / settlement attestation", network: facilitator.deps.bound.identifier });
    if (req.method === "GET" && route === "/supported") return send(res, 200, facilitator.supported());
    if (route !== "/verify" && route !== "/settle") return send(res, 404, { error: { code: "NOT_FOUND", message: "unknown route" } });
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");
      return send(res, 405, { error: { code: "METHOD_NOT_ALLOWED", message: "POST required" } });
    }
    const operation = route.slice(1); // verify | settle
    const envelope = operation;

    // 1. no query strings — a credential must never travel in a URL
    if (url.search !== "") {
      const info = describe("SCHEMA_INVALID");
      return send(res, 400, envelope === "settle" ? { success: false, errorReason: "SCHEMA_INVALID", extensions: { policyvault: { status: "REFUSED", reasonClass: info.cls, reason: "SCHEMA_INVALID", explanation: "query strings are refused on this route" } } } : { isValid: false, invalidReason: "SCHEMA_INVALID", extensions: { policyvault: { status: "REFUSED", reasonClass: info.cls, reason: "SCHEMA_INVALID", explanation: "query strings are refused on this route" } } });
    }

    // 2. credential — before the body is touched
    const auth = req.headers.authorization;
    if (auth === undefined || auth === "") {
      stats.unauthenticated += 1;
      log({ route, http: 401, code: "CREDENTIAL_REQUIRED", ms: Date.now() - started });
      return authRefusal(res, "CREDENTIAL_REQUIRED", envelope);
    }
    const m = /^Bearer\s+(\S+)$/.exec(String(auth));
    const identity = m ? principals.authenticate(m[1]) : null;
    if (!identity) {
      stats.unauthenticated += 1;
      log({ route, http: 401, code: "CREDENTIAL_INVALID", ms: Date.now() - started });
      return authRefusal(res, "CREDENTIAL_INVALID", envelope);
    }
    const { principal } = identity;

    // 3. operation scope
    if (!PRINCIPAL_OPERATIONS.includes(operation) || !principal.operations.includes(operation)) {
      stats.forbidden += 1;
      log({ route, principalId: principal.principalId, http: 403, code: "SCOPE_FORBIDDEN", ms: Date.now() - started });
      return authRefusal(res, "SCOPE_FORBIDDEN", envelope);
    }

    // 4. per-principal rate limit (availability only)
    const gate = limiter.take(principal.principalId);
    if (!gate.ok) {
      stats.rateLimited += 1;
      res.setHeader("Retry-After", String(gate.retryAfterSeconds));
      log({ route, principalId: principal.principalId, http: 429, code: "RATE_LIMITED", ms: Date.now() - started });
      return authRefusal(res, "RATE_LIMITED", envelope);
    }

    // 5. body cap
    const body = await readBody(req, res, bodyCapBytes);
    if (body.tooLarge) {
      log({ route, principalId: principal.principalId, http: 413, code: "BODY_TOO_LARGE", ms: Date.now() - started });
      res.setHeader("Connection", "close");
      res.once("finish", () => req.destroy());
      return authRefusal(res, "BODY_TOO_LARGE", envelope);
    }
    if (body.error) return;

    // 6. the facilitator
    try {
      stats[operation] += 1;
      const out = operation === "verify" ? await facilitator.verify({ text: body.text ?? "", principal }) : await facilitator.settle({ text: body.text ?? "", principal });
      const pv = out.body && out.body.extensions && out.body.extensions.policyvault;
      log({ route, principalId: principal.principalId, http: out.http, code: pv ? pv.reason ?? pv.status ?? null : null, ms: Date.now() - started });
      return send(res, out.http, out.body);
    } catch (error) {
      log({ route, principalId: principal.principalId, http: 500, code: "FACILITATOR_INTERNAL", ms: Date.now() - started, error: String(error && error.message ? error.message : error).slice(0, 200) });
      return send(res, 500, { error: { code: "FACILITATOR_INTERNAL", message: "internal error — no judgement was made" } });
    }
  });
  server.facilitator = facilitator;
  server.stats = stats;
  server.limiter = limiter;
  return server;
}

module.exports = { createFacilitatorService, RateLimiter };
