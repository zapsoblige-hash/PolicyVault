"use strict";

/*
 * Minimal HTTP JSON client for the PolicyVault API (node:http/https only —
 * zero new dependencies; no global fetch, so connection lifecycle is fully
 * deterministic under node --test).
 *
 * Contract:
 *   callApi(cfg, { method, pathSegments, query, body, idempotencyKey })
 *     -> { httpStatus, body }   for ANY HTTP response the server produced
 *                               (2xx and refusals alike — the caller maps
 *                               them to envelope statuses; this layer
 *                               NEVER retries and NEVER interprets);
 *     -> throws TransportError  only when no usable HTTP response exists
 *                               (connect failure, timeout, oversized or
 *                               non-JSON response body).
 *
 * SECRET HANDLING: the Authorization header value is obtained from the
 * config closure at send time and exists only in this function's locals —
 * TransportError carries a deterministic reason code + the safe
 * host:port label, never header values and never raw exception text.
 */

const http = require("node:http");
const https = require("node:https");

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024; // generous; vault lists are small

class TransportError extends Error {
  constructor(reason, target, detail) {
    super(`policyvault-mcp transport: ${reason} (${target})${detail ? ` — ${detail}` : ""}`);
    this.name = "TransportError";
    this.reason = reason; // CONNECT_FAILED | TIMEOUT | RESPONSE_TOO_LARGE | RESPONSE_NOT_JSON | REQUEST_ABORTED
    this.target = target;
    this.detail = detail ?? null; // adapter-authored text only (e.g. an errno code)
  }
}

/* `anonymous: true` omits the Authorization header — used ONLY for the
 * public capability-discovery route, so the credential is never
 * transmitted where no route needs it. */
function callApi(cfg, { method, pathSegments, query, body, idempotencyKey, signal, anonymous }) {
  return new Promise((resolve, reject) => {
    const base = new URL(cfg.baseUrl);
    const isHttps = base.protocol === "https:";
    const mod = isHttps ? https : http;
    // Path segments were pattern-validated upstream (hex/uuid/enum), so no
    // traversal is possible; encode anyway as defense in depth.
    const path = `/api/v1/${pathSegments.map((s) => encodeURIComponent(s)).join("/")}`;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined) qs.set(k, String(v));
    const search = qs.toString();

    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const headers = {
      accept: "application/json",
      ...(anonymous ? {} : { authorization: cfg.authorizationHeader() }),
      ...(payload ? { "content-type": "application/json", "content-length": String(payload.length) } : {}),
      ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {})
    };

    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener("abort", onAbort);
      fn(value);
    };

    const req = mod.request(
      {
        protocol: base.protocol,
        hostname: base.hostname,
        port: base.port || (isHttps ? 443 : 80),
        method,
        path: search ? `${path}?${search}` : path,
        headers,
        agent: false // one connection per call; nothing lingers past the test/process
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            res.destroy();
            finish(reject, new TransportError("RESPONSE_TOO_LARGE", cfg.targetLabel));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if (text === "") {
            finish(resolve, { httpStatus: res.statusCode, body: null });
            return;
          }
          try {
            finish(resolve, { httpStatus: res.statusCode, body: JSON.parse(text) });
          } catch {
            finish(reject, new TransportError("RESPONSE_NOT_JSON", cfg.targetLabel, `http ${res.statusCode}`));
          }
        });
        res.on("error", () => finish(reject, new TransportError("CONNECT_FAILED", cfg.targetLabel, "response stream error")));
      }
    );

    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, new TransportError("TIMEOUT", cfg.targetLabel, `${cfg.httpTimeoutMs}ms`));
    }, cfg.httpTimeoutMs);

    const onAbort = () => {
      req.destroy();
      finish(reject, new TransportError("REQUEST_ABORTED", cfg.targetLabel, "cancelled by the MCP client"));
    };
    if (signal) {
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }

    req.on("error", (err) => {
      const code = err && typeof err.code === "string" && /^[A-Z0-9_]{2,32}$/.test(err.code) ? err.code : "unknown";
      finish(reject, new TransportError("CONNECT_FAILED", cfg.targetLabel, code));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { callApi, TransportError, MAX_RESPONSE_BYTES };
