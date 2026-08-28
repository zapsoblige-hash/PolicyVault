"use strict";

/*
 * x402 adapter HTTP service — the adapter's OWN caller-facing surface
 * (its caller is the AI agent that wants a resource paid for; the
 * resource server never talks to this service). Separate process,
 * loopback by default, zero runtime dependencies (node:http only).
 *
 * Routes (adapter-invented transport, clearly non-normative — x402
 * specifies the client<->resource-server wire, not a client's internals):
 *   POST /x402/attempts                      one logical purchase attempt
 *        { attemptId, vaultId, agentPk, paymentRequiredHeader }
 *   POST /x402/attempts/:attemptId/delivery-result
 *        { delivered: boolean, paymentResponseHeader? }
 *   GET  /x402/attempts/:attemptId           stored attempt record (rendered)
 *   GET  /healthz
 *
 * The service NEVER emits an HTTP 402 (PolicyVault is never a resource
 * server — free forever), holds no keys, and every response is JSON with
 * deterministic machine codes.
 */

const http = require("node:http");
const { X402Adapter } = require("./adapter");

const BODY_CAP_BYTES = 128 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

function readBody(req, res, cap, next) {
  let size = 0;
  const chunks = [];
  let done = false;
  req.on("data", (chunk) => {
    if (done) return;
    size += chunk.length;
    if (size > cap) {
      done = true;
      send(res, 413, { error: { code: "BODY_TOO_LARGE", message: `request body exceeds ${cap} bytes` } });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on("end", () => {
    if (done) return;
    done = true;
    let parsed = null;
    const text = Buffer.concat(chunks).toString("utf8");
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        send(res, 400, { error: { code: "BODY_NOT_JSON", message: "request body must be JSON" } });
        return;
      }
    }
    next(parsed);
  });
  req.on("error", () => {
    if (!done) {
      done = true;
      try {
        res.destroy();
      } catch {
        /* already gone */
      }
    }
  });
}

function statusFor(outcome) {
  // Deterministic HTTP mapping for the adapter's own surface; the
  // machine code inside the body is the real contract.
  if (!outcome || !outcome.status) return 500;
  if (outcome.status === "BUSY") return 409;
  if (outcome.codes && outcome.codes.includes("IDEMPOTENCY_KEY_CONFLICT")) return 409;
  if (outcome.status === "REFUSED") return 422;
  return 200;
}

function createX402Service(adapterOptions) {
  const adapter = new X402Adapter(adapterOptions);
  const server = http.createServer((req, res) => {
    req.socket.setTimeout(30_000, () => req.destroy());
    const url = new URL(req.url, "http://localhost");
    const segments = url.pathname.split("/").filter(Boolean);

    if (req.method === "GET" && segments.length === 1 && segments[0] === "healthz") {
      return send(res, 200, { ok: true, service: "policyvault-x402-adapter", role: "x402 client/payer only" });
    }

    if (segments[0] !== "x402") return send(res, 404, { error: { code: "NOT_FOUND", message: "unknown route" } });

    if (req.method === "POST" && segments.length === 2 && segments[1] === "attempts") {
      return readBody(req, res, BODY_CAP_BYTES, (body) => {
        adapter
          .handleAttempt(body ?? {})
          .then((outcome) => send(res, statusFor(outcome), outcome))
          .catch((error) => send(res, 500, { error: { code: "ADAPTER_INTERNAL", message: error.message } }));
      });
    }

    if (req.method === "POST" && segments.length === 4 && segments[1] === "attempts" && segments[3] === "delivery-result") {
      return readBody(req, res, BODY_CAP_BYTES, (body) => {
        try {
          const outcome = adapter.recordDeliveryResult({ attemptId: segments[2], ...(body ?? {}) });
          send(res, statusFor(outcome), outcome);
        } catch (error) {
          send(res, 500, { error: { code: "ADAPTER_INTERNAL", message: error.message } });
        }
      });
    }

    if (req.method === "GET" && segments.length === 3 && segments[1] === "attempts") {
      if (!UUID_RE.test(segments[2])) return send(res, 400, { error: { code: "X402_CALLER_INPUT_INVALID", message: "attemptId must be a UUID" } });
      const record = adapter.getAttempt(segments[2]);
      if (!record) return send(res, 404, { error: { code: "ATTEMPT_NOT_FOUND", message: "no such attempt" } });
      return send(res, 200, { attempt: record });
    }

    return send(res, 404, { error: { code: "NOT_FOUND", message: "unknown route" } });
  });
  server.adapter = adapter;
  return server;
}

module.exports = { createX402Service };
