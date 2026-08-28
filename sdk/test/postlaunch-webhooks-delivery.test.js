"use strict";

/*
 * WEBHOOK DELIVERY + SIGNING (completion-standard surface 18;
 * docs/postlaunch/webhooks-events-spec.md §8–§9; server/src/
 * events-delivery.js + events-signing.js).
 *
 * REAL HTTP: a local receiver (http.createServer on 127.0.0.1, permitted
 * via the explicit localhost dev override on this non-mainnet config)
 * captures every delivery; the RECEIVER verifies each signature with the
 * spec §8 consumer recipe (verifyWebhookSignature — the tested reference
 * implementation). Deterministic time via an injected clock; ticks are
 * driven manually (no background timer racing assertions).
 *
 * Proves: signature scheme pv1 (tamper/replay/window/scheme-downgrade all
 * refused); ordered per-endpoint delivery with correct headers/payload
 * envelope (including the embedded not-authority notice); at-least-once
 * semantics (cursor rewind redelivers the same eventId); exponential
 * backoff progression to dead-letter with stream progress preserved;
 * rotation grace co-signing on the wire; malicious receiver behaviors
 * (huge body, never-responding, redirect — never followed) handled
 * safely; SSRF target guard (private/reserved/loopback refused without
 * the override, DNS answers validated + pinned); per-endpoint failure
 * isolation; and TOTAL worker decoupling — a dead, stopped, or
 * never-started delivery loop leaves the API fully functional.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL = "1"; // non-mainnet config below

const { handle, loadConfig } = require("../../server/src/api");
const { emitPlatformEvent } = require("../../server/src/events");
const { DeliveryWorker, httpPostJson, isForbiddenTargetIp, WEBHOOK_PAYLOAD_SCHEMA } = require("../../server/src/events-delivery");
const { verifyWebhookSignature, signWebhookPayload, SIGNATURE_HEADER, EVENT_ID_HEADER, DELIVERY_ID_HEADER } = require("../../server/src/events-signing");
const { Categories, getEventsStore } = require("../../server/src/events-store");
const wh = require("../../server/src/webhooks");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-webhookdlv-"));
const config = loadConfig({ dataRoot }); // SELF-HOSTED (tenancy off): delivery mechanics under test; tenancy filtering is proven in postlaunch-webhooks-events.test.js
const VAULT_ID = "6d".repeat(32);

const receiver = { hits: [], failOk: false };
let receiverPort = 0;
let lurePort = 0;
let lureHits = 0;
let receiverServer;
let lureServer;

before(async () => {
  receiverServer = http.createServer((req, res) => {
    res.on("error", () => {});
    req.socket.on("error", () => {});
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      receiver.hits.push({ path: req.url, headers: req.headers, rawBody: Buffer.concat(chunks).toString("utf8") });
      if (req.url.startsWith("/fail") && !receiver.failOk) {
        res.writeHead(500);
        res.end("refusing");
        return;
      }
      if (req.url.startsWith("/huge")) {
        // A hostile consumer answering 2xx with an enormous body: the
        // deliverer must cap/drain/discard, never buffer it.
        res.writeHead(200);
        const chunk = Buffer.alloc(65536, 0x78);
        for (let i = 0; i < 160; i++) res.write(chunk); // ~10 MiB
        res.end();
        return;
      }
      if (req.url.startsWith("/slow")) {
        return; // never respond: the strict per-attempt timeout must fire
      }
      if (req.url.startsWith("/redirect")) {
        res.writeHead(302, { location: `http://127.0.0.1:${lurePort}/lure` });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('{"ignored":"responses are never parsed"}');
    });
  });
  await new Promise((r) => receiverServer.listen(0, "127.0.0.1", r));
  receiverPort = receiverServer.address().port;

  lureServer = http.createServer((req, res) => {
    lureHits += 1;
    res.writeHead(200);
    res.end();
  });
  await new Promise((r) => lureServer.listen(0, "127.0.0.1", r));
  lurePort = lureServer.address().port;
});

after(async () => {
  await new Promise((r) => receiverServer.close(r));
  await new Promise((r) => lureServer.close(r));
  delete process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL;
});

const state = {};
let clock = Date.now();
const makeWorker = (opts = {}) =>
  new DeliveryWorker(config, {
    now: () => clock,
    requestTimeoutMs: 400,
    backoffScheduleMs: [50, 100],
    maxAttempts: 3,
    ...opts
  });

const emit = (n) =>
  emitPlatformEvent(config, {
    type: "request.built",
    vaultId: VAULT_ID,
    correlation: { requestId: `req-${n}` },
    data: { action: "ownerPause", state: "BUILT" }
  });

async function createEndpoint(pathname, eventTypes) {
  const r = await handle(config, "POST", ["webhooks"], {}, { url: `http://127.0.0.1:${receiverPort}${pathname}`, ...(eventTypes ? { eventTypes } : {}), label: pathname }, {});
  assert.equal(r.status, 201);
  return { endpointId: r.body.endpoint.endpointId, secret: r.body.secret };
}

const revoke = (endpointId) => handle(config, "POST", ["webhooks", endpointId, "revoke"], {}, {}, {});

test("SIGNING unit wall: tamper, wrong secret, stale/future timestamps, malformed and downgraded headers all refuse; verification is exact", () => {
  const raw = JSON.stringify({ hello: "world", n: 1 });
  const t = Math.floor(clock / 1000);
  const header = signWebhookPayload({ secrets: ["pvwh_current", "pvwh_previous"], timestampSeconds: t, rawBody: raw });
  assert.match(header, /^v=pv1,t=\d+,s=[0-9a-f]{64},s=[0-9a-f]{64}$/);
  assert.equal(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_current", nowSeconds: t }).ok, true);
  assert.equal(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_previous", nowSeconds: t }).ok, true);
  assert.deepEqual(verifyWebhookSignature({ header, rawBody: raw + " ", secret: "pvwh_current", nowSeconds: t }), { ok: false, reason: "SIGNATURE_MISMATCH" });
  assert.deepEqual(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_wrong", nowSeconds: t }), { ok: false, reason: "SIGNATURE_MISMATCH" });
  assert.deepEqual(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_current", nowSeconds: t + 301 }), { ok: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" });
  assert.deepEqual(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_current", nowSeconds: t - 301 }), { ok: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" });
  assert.equal(verifyWebhookSignature({ header, rawBody: raw, secret: "pvwh_current", nowSeconds: t + 299 }).ok, true, "inside the window passes");
  // A REPLAYED header over a DIFFERENT body is exactly the tamper case;
  // a replayed identical delivery is caught by eventId dedup (spec §8).
  const other = JSON.stringify({ hello: "world", n: 2 });
  assert.equal(verifyWebhookSignature({ header, rawBody: other, secret: "pvwh_current", nowSeconds: t }).ok, false);
  assert.deepEqual(verifyWebhookSignature({ header: header.replace("v=pv1", "v=pv0"), rawBody: raw, secret: "pvwh_current", nowSeconds: t }), { ok: false, reason: "UNSUPPORTED_SCHEME" });
  assert.deepEqual(verifyWebhookSignature({ header: "garbage", rawBody: raw, secret: "pvwh_current" }), { ok: false, reason: "MALFORMED_HEADER" });
  assert.deepEqual(verifyWebhookSignature({ header: "v=pv1,t=123", rawBody: raw, secret: "pvwh_current" }), { ok: false, reason: "MALFORMED_HEADER" });
  assert.throws(() => signWebhookPayload({ secrets: [], timestampSeconds: t, rawBody: raw }), (e) => e.code === "WEBHOOK_SECRET_UNAVAILABLE", "an unsigned webhook is never sent");
});

test("SSRF target guard: private/reserved/loopback/mapped ranges refused; loopback only under the explicit override; DNS answers validated; redirects lack any follow path", async () => {
  for (const ip of ["10.1.2.3", "192.168.1.1", "172.16.0.9", "169.254.169.254", "127.0.0.1", "0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1"]) {
    assert.equal(isForbiddenTargetIp(ip), true, `${ip} must be forbidden`);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]) {
    assert.equal(isForbiddenTargetIp(ip), false, `${ip} must be allowed`);
  }
  assert.equal(isForbiddenTargetIp("127.0.0.1", { allowLoopback: true }), false);
  assert.equal(isForbiddenTargetIp("::1", { allowLoopback: true }), false);
  assert.equal(isForbiddenTargetIp("10.0.0.1", { allowLoopback: true }), true, "the override opens loopback ONLY, never private ranges");
  assert.equal(isForbiddenTargetIp("not-an-ip"), true, "unparseable input fails closed");

  // Literal-IP targets are refused synchronously without the override.
  const direct = await httpPostJson({ url: "https://169.254.169.254/latest/meta-data", rawBody: "{}", headers: {}, timeoutMs: 300, allowLoopback: false });
  assert.equal(direct.errorCode, "WEBHOOK_TARGET_FORBIDDEN");
  const loop = await httpPostJson({ url: `http://127.0.0.1:${receiverPort}/ok`, rawBody: "{}", headers: {}, timeoutMs: 300, allowLoopback: false });
  assert.equal(loop.errorCode, "WEBHOOK_TARGET_FORBIDDEN", "loopback refused without the override");
  // Hostname path: DNS resolves localhost -> loopback, refused by the
  // guarded lookup (the socket dials only validated addresses).
  const byName = await httpPostJson({ url: "https://localhost:9/x", rawBody: "{}", headers: {}, timeoutMs: 300, allowLoopback: false });
  assert.equal(byName.errorCode, "WEBHOOK_TARGET_FORBIDDEN");
});

test("DELIVERY happy path: ordered, signed, correct envelope + headers; the RECEIVER verifies via the spec recipe; responses are discarded", async () => {
  const ep = await createEndpoint("/ok");
  const e1 = await emit(1);
  const e2 = await emit(2);
  const e3 = await emit(3);
  receiver.hits.length = 0;
  const worker = makeWorker();
  await worker.tick();

  assert.equal(receiver.hits.length, 3, "one POST per event, drained in one tick");
  const ids = receiver.hits.map((h) => h.headers[EVENT_ID_HEADER]);
  assert.deepEqual(ids, [e1.eventId, e2.eventId, e3.eventId], "strictly ordered per endpoint");
  for (const hit of receiver.hits) {
    const payload = JSON.parse(hit.rawBody);
    assert.equal(payload.schemaVersion, WEBHOOK_PAYLOAD_SCHEMA);
    assert.equal(payload.endpointId, ep.endpointId);
    assert.equal(payload.attempt, 1);
    assert.match(payload.notice, /not authority/i);
    assert.equal(payload.event.eventId, hit.headers[EVENT_ID_HEADER]);
    assert.match(hit.headers[DELIVERY_ID_HEADER], /^[0-9a-f-]{36}$/);
    assert.equal(hit.headers["user-agent"], "PolicyVault-Webhooks/1");
    const verdict = verifyWebhookSignature({
      header: hit.headers[SIGNATURE_HEADER],
      rawBody: hit.rawBody,
      secret: ep.secret,
      nowSeconds: Math.floor(clock / 1000)
    });
    assert.equal(verdict.ok, true, `receiver-side verification: ${JSON.stringify(verdict)}`);
    // Tamper detection at the consumer: one flipped byte refuses.
    const tampered = hit.rawBody.replace("BUILT", "built");
    assert.equal(verifyWebhookSignature({ header: hit.headers[SIGNATURE_HEADER], rawBody: tampered, secret: ep.secret, nowSeconds: Math.floor(clock / 1000) }).ok, false);
  }

  const monitor = await handle(config, "GET", ["webhooks", ep.endpointId], {}, null, {});
  assert.equal(monitor.body.delivery.counters.delivered, 3);
  assert.equal(monitor.body.delivery.counters.failed, 0);
  assert.equal(monitor.body.delivery.pending, null);
  assert.equal(monitor.body.delivery.recentAttempts.length, 3);
  assert.ok(monitor.body.delivery.recentAttempts.every((a) => a.outcome === "DELIVERED" && a.httpStatus === 200));
  state.okEndpoint = ep;
  state.lastDelivered = e3;
});

test("AT-LEAST-ONCE: a crash between 2xx and the cursor write redelivers the SAME eventId (consumer dedups via the recipe)", async () => {
  const ep = state.okEndpoint;
  const store = getEventsStore(config);
  const rec = await store.read(Categories.WEBHOOK_DELIVERY_STATE, ep.endpointId);
  const rewound = { ...rec, cursor: String(BigInt(rec.cursor) - 1n) }; // simulate crash-before-cursor-persist
  await store.write(Categories.WEBHOOK_DELIVERY_STATE, ep.endpointId, rewound);
  receiver.hits.length = 0;
  await makeWorker().tick();
  assert.equal(receiver.hits.length, 1, "exactly the un-acked event is redelivered");
  assert.equal(receiver.hits[0].headers[EVENT_ID_HEADER], state.lastDelivered.eventId, "same eventId on redelivery — the dedup key");
});

test("TYPE FILTER: an endpoint subscribed to request.rejected only never receives request.built", async () => {
  const ep = await createEndpoint("/ok", ["request.rejected"]);
  await emit(40);
  await emitPlatformEvent(config, { type: "request.rejected", vaultId: VAULT_ID, correlation: { requestId: "req-41" }, data: { action: "ownerPause", state: "WALLET_REJECTED" } });
  receiver.hits.length = 0;
  await makeWorker().tick();
  const mine = receiver.hits.filter((h) => JSON.parse(h.rawBody).endpointId === ep.endpointId);
  assert.equal(mine.length, 1);
  assert.equal(JSON.parse(mine[0].rawBody).event.type, "request.rejected");
  await revoke(ep.endpointId);
  await revoke(state.okEndpoint.endpointId);
});

test("BACKOFF -> DEAD-LETTER progression: failures respect the schedule, dead-letter after maxAttempts, stream progress preserved past it", async () => {
  const ep = await createEndpoint("/fail");
  const bad = await emit(50);
  const next = await emit(51);
  receiver.hits.length = 0;

  const worker = makeWorker(); // maxAttempts 3, backoff [50, 100]
  await worker.tick(); // attempt 1 fails
  assert.equal(receiver.hits.length, 1);
  await worker.tick(); // inside backoff window: NO new attempt
  assert.equal(receiver.hits.length, 1, "backoff window is respected");
  clock += 60;
  await worker.tick(); // attempt 2 fails
  assert.equal(receiver.hits.length, 2);
  clock += 120;
  await worker.tick(); // attempt 3 fails -> DEAD LETTER; the endpoint pauses until the next tick
  const attemptsForBad = receiver.hits.filter((h) => h.headers[EVENT_ID_HEADER] === bad.eventId).length;
  assert.equal(attemptsForBad, 3, "exactly maxAttempts attempts for the dead-lettered event");

  const monitor = await handle(config, "GET", ["webhooks", ep.endpointId], {}, null, {});
  assert.equal(monitor.body.delivery.counters.deadLettered, 1);
  assert.equal(monitor.body.deadLetters.length, 1);
  assert.equal(monitor.body.deadLetters[0].eventId, bad.eventId);
  assert.equal(monitor.body.deadLetters[0].attempts, 3);
  assert.equal(monitor.body.deadLetters[0].lastHttpStatus, 500);

  // The stream moved PAST the dead letter: once the consumer heals, the
  // NEXT event delivers; the dead-lettered one is never auto-retried.
  receiver.failOk = true;
  clock += 200;
  receiver.hits.length = 0;
  await worker.tick();
  const delivered = receiver.hits.map((h) => h.headers[EVENT_ID_HEADER]);
  assert.ok(delivered.includes(next.eventId), "the following event flows after dead-lettering");
  assert.ok(!delivered.includes(bad.eventId), "a dead-lettered event is not silently retried");
  receiver.failOk = false;
  await revoke(ep.endpointId);
});

test("MALICIOUS RECEIVERS: huge 2xx body is capped+discarded (still delivered); a never-responding endpoint times out; a redirect is a FAILURE and is never followed", async () => {
  const hugeEp = await createEndpoint("/huge");
  const slowEp = await createEndpoint("/slow");
  const redirEp = await createEndpoint("/redirect");
  await emit(60);
  receiver.hits.length = 0;
  lureHits = 0;
  await makeWorker().tick();

  const hugeMon = await handle(config, "GET", ["webhooks", hugeEp.endpointId], {}, null, {});
  assert.equal(hugeMon.body.delivery.counters.delivered, 1, "a huge response body does not fail the delivery — it is drained and discarded");

  const slowMon = await handle(config, "GET", ["webhooks", slowEp.endpointId], {}, null, {});
  assert.equal(slowMon.body.delivery.counters.failed, 1);
  assert.equal(slowMon.body.delivery.recentAttempts[0].errorCode, "WEBHOOK_TIMEOUT");

  const redirMon = await handle(config, "GET", ["webhooks", redirEp.endpointId], {}, null, {});
  assert.equal(redirMon.body.delivery.counters.failed, 1);
  assert.equal(redirMon.body.delivery.recentAttempts[0].httpStatus, 302);
  assert.equal(lureHits, 0, "the redirect target is NEVER contacted");

  for (const ep of [hugeEp, slowEp, redirEp]) await revoke(ep.endpointId);
});

test("ROTATION on the wire: during grace the header carries BOTH signatures (old and new secrets verify); after grace only the new one", async () => {
  const ep = await createEndpoint("/ok");
  await emit(70);
  receiver.hits.length = 0;
  await makeWorker().tick();
  assert.equal(verifyWebhookSignature({ header: receiver.hits[0].headers[SIGNATURE_HEADER], rawBody: receiver.hits[0].rawBody, secret: ep.secret, nowSeconds: Math.floor(clock / 1000) }).ok, true);

  const { secret: secret2 } = await wh.rotateEndpointSecret(config, { endpointId: ep.endpointId, creatorXOnly: null });
  await emit(71);
  receiver.hits.length = 0;
  await makeWorker().tick();
  const inGrace = receiver.hits[0];
  assert.equal((inGrace.headers[SIGNATURE_HEADER].match(/s=/g) || []).length, 2, "grace window: two co-signatures");
  for (const s of [ep.secret, secret2]) {
    assert.equal(verifyWebhookSignature({ header: inGrace.headers[SIGNATURE_HEADER], rawBody: inGrace.rawBody, secret: s, nowSeconds: Math.floor(clock / 1000) }).ok, true);
  }

  await wh.rotateEndpointSecret(config, { endpointId: ep.endpointId, creatorXOnly: null, graceMs: 0 }); // secret3; secret2's grace ends immediately (real time)
  clock = Date.now() + 60_000; // jump the injected clock decisively past the real-time grace boundary
  await emit(72);
  receiver.hits.length = 0;
  await makeWorker().tick();
  const afterGrace = receiver.hits[0];
  assert.equal((afterGrace.headers[SIGNATURE_HEADER].match(/s=/g) || []).length, 1, "expired grace: single signature");
  assert.equal(verifyWebhookSignature({ header: afterGrace.headers[SIGNATURE_HEADER], rawBody: afterGrace.rawBody, secret: secret2, nowSeconds: Math.floor(clock / 1000) }).ok, false, "the rotated-out secret no longer verifies");
  await revoke(ep.endpointId);
});

test("ISOLATION: a throwing transport, an unreachable endpoint, and a revoked endpoint never affect other endpoints or the API; a stopped/killed loop leaves the API fully working", async () => {
  const good = await createEndpoint("/ok");
  const dead = await createEndpoint("/ok"); // repointed to a closed port below
  const store = getEventsStore(config);
  const deadRec = await store.read(Categories.WEBHOOK_ENDPOINT, dead.endpointId);
  await store.write(Categories.WEBHOOK_ENDPOINT, dead.endpointId, { ...deadRec, url: "http://127.0.0.1:9/unreachable" });
  await emit(80);
  receiver.hits.length = 0;
  await makeWorker().tick();
  assert.equal(receiver.hits.filter((h) => JSON.parse(h.rawBody).endpointId === good.endpointId).length, 1, "a dead sibling endpoint never blocks a healthy one");
  const deadMon = await handle(config, "GET", ["webhooks", dead.endpointId], {}, null, {});
  assert.equal(deadMon.body.delivery.counters.failed, 1);
  assert.equal(deadMon.body.delivery.recentAttempts[0].errorCode, "WEBHOOK_CONNECT_FAILED");

  // A hostile injected transport that THROWS synchronously: the tick
  // completes, the attempt is recorded as failed — never a crash.
  clock += 1000;
  await emit(81);
  const hostile = makeWorker({
    transport: () => {
      throw Object.assign(new Error("hostile transport"), { code: "EVIL" });
    }
  });
  await hostile.tick(); // must not throw

  // Kill-the-loop drill: a started worker is stopped; the API keeps
  // serving (and a never-started worker is the default state everywhere).
  const bg = makeWorker({ intervalMs: 25 });
  bg.start();
  await new Promise((r) => setTimeout(r, 60));
  await bg.stop();
  const health = await handle(config, "GET", ["health"], {}, null, {});
  assert.equal(health.status, 200);
  const page = await handle(config, "GET", ["events"], { limit: "5" }, null, {});
  assert.equal(page.status, 200, "polling works regardless of any delivery loop");

  // Revoked endpoints receive nothing.
  await revoke(good.endpointId);
  await revoke(dead.endpointId);
  await emit(82);
  receiver.hits.length = 0;
  await makeWorker().tick();
  assert.equal(receiver.hits.length, 0, "revoked endpoints get no deliveries");
});
