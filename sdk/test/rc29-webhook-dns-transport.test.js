"use strict";
/* rc29 (post-Codex live-stack review, Claude continuation 2026-09-08): the webhook transport's DNS path.
 *
 * RED-first on the rc28 bytes (543a392): every webhook endpoint addressed by a DNS HOSTNAME failed with
 * WEBHOOK_CONNECT_FAILED on Node >= 20, because net.connect's default autoSelectFamily calls the custom
 * `lookup` with `{ all: true }` and expects an ARRAY of { address, family }, while guardedLookup answered with
 * the legacy (address, family) pair → ERR_INVALID_IP_ADDRESS inside net, surfaced as a connect failure. Literal-IP
 * targets never take that path, which is why the floor stayed green. Consequence on the rc28 bytes: the advertised
 * DNS-rebinding pin never executed for real endpoints and hostname endpoints dead-lettered after 8 attempts
 * (fail-safe direction: no forbidden dial — but delivery was broken). Found by the rc29 read-only reviewer (A4),
 * reproduced by the lead on Node v20.20.2 (the image's pinned runtime).
 *
 * Also pinned here: the conservative-deny ranges the LS-04 correction left open (6to4 2002::/16, Teredo 2001:0::/32,
 * site-local fec0::/10, discard 100::/64, documentation 3fff::/20) and the false refusal of real global addresses
 * whose first hextets merely START with the documentation prefix (2001:db81::/32 …). */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const https = require("node:https");
const dns = require("node:dns");
const { EventEmitter } = require("node:events");
const { isForbiddenTargetIp, httpPostJson } = require("../../server/src/events-delivery");

const body = { rawBody: "{}", headers: { "content-type": "application/json" }, timeoutMs: 5000 };

test("rc29: a webhook endpoint addressed by a DNS hostname is delivered through the REAL Node transport (autoSelectFamily all:true lookup contract)", async () => {
  const received = [];
  const server = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { received.push(b); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); }); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const realLookup = dns.lookup;
  // The hostname resolves ONLY to 127.0.0.1 (a stub of dns.lookup, honouring the `all` option like the real one);
  // the socket path itself is Node's real net.connect with its default autoSelectFamily.
  dns.lookup = (host, options, cb) => {
    const done = typeof options === "function" ? options : cb;
    if (host !== "receiver.test") return realLookup(host, options, cb);
    const all = typeof options === "object" && options && options.all;
    queueMicrotask(() => (all ? done(null, [{ address: "127.0.0.1", family: 4 }]) : done(null, "127.0.0.1", 4)));
  };
  try {
    const literal = await httpPostJson({ url: `http://127.0.0.1:${port}/hook`, ...body, allowLoopback: true });
    assert.equal(literal.ok, true, JSON.stringify(literal));
    const named = await httpPostJson({ url: `http://receiver.test:${port}/hook`, ...body, allowLoopback: true });
    assert.equal(named.ok, true, `hostname-addressed delivery must succeed through the real transport: ${JSON.stringify(named)}`);
    assert.equal(named.httpStatus, 200);
    assert.equal(received.length, 2);
  } finally {
    dns.lookup = realLookup;
    await new Promise((r) => server.close(r));
  }
});

test("rc29: the guarded lookup answers both lookup contracts and refuses a resolution set containing ANY forbidden address", async () => {
  const oldRequest = https.request, realLookup = dns.lookup;
  const seen = [];
  https.request = (options) => {
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = () => {
      const finish = (err, addresses, family) => { seen.push({ err: err && err.code, addresses, family }); queueMicrotask(() => req.emit("error", err || Object.assign(Error("stub only"), { code: "STUB" }))); };
      options.lookup(options.hostname, { all: true, hints: 32 }, finish);
    };
    return req;
  };
  try {
    dns.lookup = (_h, options, cb) => cb(null, [{ address: "2606:4700::1111", family: 6 }, { address: "8.8.8.8", family: 4 }]);
    await httpPostJson({ url: "https://receiver.example/x", ...body, allowLoopback: false });
    assert.equal(seen.at(-1).err, null, "a fully public answer set is handed to the transport without error");
    assert.deepEqual(seen.at(-1).addresses, [{ address: "2606:4700::1111", family: 6 }, { address: "8.8.8.8", family: 4 }], "all:true callers receive the validated ARRAY, pinned to exactly what was validated");
    // Happy-Eyeballs must never get the chance to race a private answer: one forbidden entry refuses the whole set.
    dns.lookup = (_h, options, cb) => cb(null, [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.1", family: 4 }]);
    const mixed = await httpPostJson({ url: "https://receiver.example/x", ...body, allowLoopback: false });
    assert.equal(mixed.errorCode, "WEBHOOK_TARGET_FORBIDDEN");
    assert.equal(seen.at(-1).err, "WEBHOOK_TARGET_FORBIDDEN");
    // Legacy single-answer callers (no `all`) still get (address, family); a legacy-shaped resolver answer is tolerated.
    https.request = (options) => { const req = new EventEmitter(); req.destroy = () => {}; req.end = () => { options.lookup(options.hostname, {}, (err, address, family) => { seen.push({ err: err && err.code, addresses: address, family }); queueMicrotask(() => req.emit("error", err || Object.assign(Error("stub only"), { code: "STUB" }))); }); }; return req; };
    dns.lookup = (_h, options, cb) => cb(null, "93.184.216.34", 4);
    await httpPostJson({ url: "https://receiver.example/x", ...body, allowLoopback: false });
    assert.equal(seen.at(-1).err, null);
    assert.deepEqual([seen.at(-1).addresses, seen.at(-1).family], ["93.184.216.34", 4]);
    dns.lookup = (_h, options, cb) => cb(null, []);
    const none = await httpPostJson({ url: "https://receiver.example/x", ...body, allowLoopback: false });
    assert.equal(none.ok, false);
  } finally { https.request = oldRequest; dns.lookup = realLookup; }
});

test("rc29: conservative IPv6 range policy — embedded/tunnelled and reserved ranges refuse; real global addresses next to the documentation prefix are allowed", () => {
  const forbidden = ["2002:7f00:1::1", "2002:a00:1::1", "2002:c0a8:101::1", "2001::7f00:1", "2001:0:abcd::1", "fec0::1", "100::1", "3fff::1", "2001:10::1", "2001:2f::1", "::ffff:0:7f00:1", "64:ff9b:1::a00:1", "ff02::1", "fd12::1", "fe80::1", "2001:db8::1"];
  for (const ip of forbidden) assert.equal(isForbiddenTargetIp(ip), true, ip);
  const allowed = ["2001:db81::1", "2001:db8f::1", "2001:4860:4860::8888", "2600::1", "2606:4700:4700::1111", "2003::1", "2001:1::1", "2001:30::1", "::ffff:8.8.8.8", "::ffff:808:808", "3ffe::1"];
  for (const ip of allowed) assert.equal(isForbiddenTargetIp(ip), false, ip);
  assert.equal(isForbiddenTargetIp("::1", { allowLoopback: true }), false);
  assert.equal(isForbiddenTargetIp("::ffff:127.0.0.1", { allowLoopback: true }), false);
  assert.equal(isForbiddenTargetIp("not-an-ip"), true);
  assert.equal(isForbiddenTargetIp("fe80::1%eth0"), true);
});
