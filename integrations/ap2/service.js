"use strict";

/*
 * AP2 adapter HTTP service — PolicyVault-as-Credential-Provider's
 * caller-facing surface. AP2 v0.2 specifies NO transport for reaching a
 * CP (the A2A AgentCard extension was dropped; agent-to-agent delegation
 * is out of scope), so this route shape is a PolicyVault invention and
 * is clearly labelled NON-NORMATIVE (spec OQ-2). Separate process,
 * loopback by default, node:http only.
 *
 * Routes:
 *   POST /ap2/payment-mandates
 *        { paymentMandate, checkoutMandate?, openPaymentMandate?,
 *          openCheckoutMandate?, expectedNonce? }   (compact SD-JWTs)
 *   GET  /ap2/attempts/:transactionId
 *   GET  /healthz
 */

const http = require("node:http");
const { Ap2Adapter } = require("./adapter");

const BODY_CAP_BYTES = 384 * 1024; // envelope caps re-checked inside the adapter (256 KiB submission)

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
  if (!outcome || !outcome.status) return 500;
  if (outcome.status === "BUSY") return 409;
  if (outcome.codes && outcome.codes.includes("IDEMPOTENCY_KEY_CONFLICT")) return 409;
  if (outcome.status === "REJECTED") return 422;
  return 200;
}

function createAp2Service(adapterOptions) {
  const adapter = new Ap2Adapter(adapterOptions);
  const server = http.createServer((req, res) => {
    req.socket.setTimeout(30_000, () => req.destroy());
    const url = new URL(req.url, "http://localhost");
    const segments = url.pathname.split("/").filter(Boolean);

    if (req.method === "GET" && segments.length === 1 && segments[0] === "healthz") {
      return send(res, 200, { ok: true, service: "policyvault-ap2-adapter", role: "AP2 Credential Provider only" });
    }
    if (segments[0] !== "ap2") return send(res, 404, { error: { code: "NOT_FOUND", message: "unknown route" } });

    if (req.method === "POST" && segments.length === 2 && segments[1] === "payment-mandates") {
      return readBody(req, res, BODY_CAP_BYTES, (body) => {
        adapter
          .handlePaymentMandate(body ?? {})
          .then((outcome) => send(res, statusFor(outcome), outcome))
          .catch((error) => send(res, 500, { error: { code: "ADAPTER_INTERNAL", message: error.message } }));
      });
    }

    if (req.method === "GET" && segments.length === 3 && segments[1] === "attempts") {
      const record = adapter.getAttempt(segments[2]);
      if (!record) return send(res, 404, { error: { code: "ATTEMPT_NOT_FOUND", message: "no such attempt" } });
      return send(res, 200, { attempt: record });
    }

    return send(res, 404, { error: { code: "NOT_FOUND", message: "unknown route" } });
  });
  server.adapter = adapter;
  return server;
}

module.exports = { createAp2Service };
