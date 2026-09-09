"use strict";

// RC29-LR-01: headers acknowledge delivery, but do not end the lifetime of
// the receiver's socket. Exercise the actual Node transport on loopback;
// never contact a production endpoint or broadcast a transaction.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { httpPostJson } = require("../../server/src/events-delivery");

const DEADLINE_MS = 100;
const CLOSE_BOUND_MS = 700;

async function receiverProbe(mode, count = 1) {
  const sockets = new Set();
  const timers = new Set();
  let requests = 0;
  let closed = 0;
  const server = http.createServer((req, res) => {
    requests++;
    req.on("error", () => {});
    res.on("error", () => {});
    req.resume();
    req.on("end", () => {
      if (mode === "no-headers") return;
      const status = mode === "refusal-stall" ? 500 : mode === "redirect-stall" ? 302 : 200;
      res.writeHead(status, { "content-type": "text/plain", ...(status === 302 ? { location: "/never-follow" } : {}) });
      if (mode === "complete") return res.end("ignored");
      if (mode === "oversized") return res.end("x".repeat(16 * 1024));
      res.flushHeaders();
      res.write("x");
      if (mode === "broken") {
        const timer = setTimeout(() => res.destroy(), 15);
        timers.add(timer);
      }
      if (mode === "trickle") {
        const timer = setInterval(() => res.write("x"), 15);
        timers.add(timer);
        res.once("close", () => clearInterval(timer));
      }
      // Remaining responses intentionally never finish; even a trickling
      // body must close at the absolute deadline, below the byte cap.
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => { sockets.delete(socket); closed++; });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const results = await Promise.all(Array.from({ length: count }, () => httpPostJson({
      url: `http://127.0.0.1:${server.address().port}/hook`,
      rawBody: "{}", headers: {}, timeoutMs: DEADLINE_MS, allowLoopback: true
    })));
    const expires = Date.now() + CLOSE_BOUND_MS;
    while (sockets.size && Date.now() < expires) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(requests, count, "one request per attempt; no redirect or retry");
    assert.equal(sockets.size, 0, "every receiver connection must close within the attempt bound, including after headers");
    assert.equal(closed, count);
    return results;
  } finally {
    for (const timer of timers) clearInterval(timer);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

for (const mode of ["complete", "success-stall", "refusal-stall", "redirect-stall", "oversized", "broken", "trickle"]) {
  test(`RC29-LR-01: ${mode} closes its real socket without changing the header outcome`, async () => {
    const [result] = await receiverProbe(mode);
    const status = mode === "refusal-stall" ? 500 : mode === "redirect-stall" ? 302 : 200;
    assert.equal(result.httpStatus, status);
    assert.equal(result.ok, status === 200);
    assert.equal(result.errorCode, status === 200 ? null : "WEBHOOK_HTTP_STATUS");
  });
}

test("RC29-LR-01: no headers still yields the existing timeout refusal", async () => {
  const [result] = await receiverProbe("no-headers");
  assert.equal(result.ok, false);
  assert.equal(result.httpStatus, null);
  assert.equal(result.errorCode, "WEBHOOK_TIMEOUT");
});

test("RC29-LR-01: concurrent acknowledged deliveries retain no abandoned receiver sockets", async () => {
  const results = await receiverProbe("success-stall", 6);
  assert.equal(results.length, 6);
  assert.ok(results.every((result) => result.ok && result.httpStatus === 200));
});
