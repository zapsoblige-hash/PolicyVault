"use strict";

/*
 * HUMAN NOTIFICATIONS — rules, worker, providers (fullscale surface 19;
 * docs/postlaunch/notifications-spec.md; server/src/notifications.js +
 * notify-delivery.js; migration 009 shape is the PG suite's subject).
 *
 * Real server api.handle() on the JSON backend, hosted authMode; a real
 * v0.4 vault for wallet A; wallet B a signed-in FOREIGN tenant; machine
 * credentials for scope gating; a REAL local HTTP receiver for the
 * webhook bridge (loopback permitted via the explicit dev override).
 *
 * Proves: rule CRUD + deny-by-default scope gating + foreign-rule 404;
 * closed validation (unknown/self-referential event types, insecure
 * URLs, unknown channels, unregistered smtp, short secrets, malformed
 * filters, quota); event->notification fan-out THROUGH THE REAL OUTBOX
 * from a REAL ownerPause build (console line + signed webhook-bridge
 * delivery verified with the pv1 reference verifier); tenant isolation
 * (B's "*" rule receives nothing of A's); disable/enable semantics
 * (backlog skipped on re-enable); provider failure isolation + BOUNDED
 * failure signals (notification.rule.failing exactly once, auto-disable
 * with chained audit + notification.rule.disabled exactly once, healthy
 * rules and the API unaffected, notification.* never fans back out);
 * per-tenant rate limiting; the no-secret sweep (payloads, logs, states,
 * responses; at-rest encryption under the operator key); and the smtp
 * pluggable-provider seam (registered fake delivers; missing provider
 * fails safe; unregistered creation refuses).
 */

process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL = "1"; // non-mainnet config below

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const notif = require("../../server/src/notifications");
const { NotificationWorker, FAILING_THRESHOLD, AUTO_DISABLE_THRESHOLD } = require("../../server/src/notify-delivery");
const { verifyWebhookSignature, SIGNATURE_HEADER, EVENT_ID_HEADER, DELIVERY_ID_HEADER } = require("../../server/src/events-signing");
const { emitPlatformEvent } = require("../../server/src/events");
const { Categories, getEventsStore } = require("../../server/src/events-store");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-notify-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xa9);
const B = KEY(0xba);
const AGENT = KEY(0xcb);
const RECIP = KEY(0xdc);
const VAULT_ID = "7d".repeat(32);
const SECRET = "notify_bridge_secret_1234567890";

const POST = (segs, body, cookieOrHeaders) => handle(config, "POST", segs, {}, body, ctxFor(cookieOrHeaders));
const GET = (segs, query, cookieOrHeaders) => handle(config, "GET", segs, query ?? {}, null, ctxFor(cookieOrHeaders));
function ctxFor(cookieOrHeaders) {
  if (!cookieOrHeaders) return {};
  if (typeof cookieOrHeaders === "string") return { headers: { cookie: cookieOrHeaders } };
  return { headers: cookieOrHeaders };
}
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

async function signIn(priv) {
  const address = ADDR(priv);
  const ch = await POST(["auth", "challenge"], { walletAddress: address });
  const signature = kaspa.signMessage({ message: ch.body.challenge.message, privateKey: priv.toString() });
  const v = await POST(["auth", "verify"], { nonce: ch.body.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() });
  return v.headers["Set-Cookie"].split(";")[0];
}

async function seedVault() {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "notifications test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "91".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "44".repeat(32) },
    creationTxId: "92".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const ownerFuel = (n) => ({ outpoint: { transactionId: "93".repeat(32), index: n ?? 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(A)}ac` });

/* Local webhook-bridge receiver (the provider side). */
let receiver;
let receiverUrl;
const received = []; // { raw, headers, json }
before(async () => {
  receiver = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      let json = null;
      try {
        json = JSON.parse(raw);
      } catch {
        /* keep raw */
      }
      received.push({ raw, headers: req.headers, json });
      res.writeHead(200);
      res.end("ok");
    });
  });
  await new Promise((r) => receiver.listen(0, "127.0.0.1", r));
  receiverUrl = `http://127.0.0.1:${receiver.address().port}/hook`;
});
after(async () => {
  await new Promise((r) => receiver.close(r));
  delete process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL;
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

const consoleLines = [];
function newWorker(options = {}) {
  return new NotificationWorker(config, { consoleSink: (l) => consoleLines.push(l), ...options });
}
const notifyState = (ruleId) => getEventsStore(config).read(Categories.NOTIFY_STATE, ruleId);
async function eventsOfType(type) {
  return (await getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500, types: [type] })).map((r) => r.event);
}

const S = {};

test("setup: seed vault; A and B sign in; machine credentials (manage vs no-notify-scope)", async () => {
  fs.writeFileSync(path.join(dataRoot, ".pv-network"), config.networkId);
  await seedVault();
  S.cookieA = await signIn(A);
  S.cookieB = await signIn(B);
  const mgr = await POST(["identities"], { label: "notify-mgr", scopes: ["read:notifications", "notifications:manage"] }, S.cookieA);
  assert.equal(mgr.status, 201);
  S.tokenMgr = mgr.body.credential.token;
  const noScope = await POST(["identities"], { label: "no-notify", scopes: ["request:build", "request:break-glass"] }, S.cookieA);
  S.tokenNoScope = noScope.body.credential.token;
});

test("RULE CRUD + SCOPE GATING: create/list/detail/404-foreign; machine deny-by-default; channels discovery is honest", async () => {
  const ch = await GET(["notifications", "channels"], {}, S.cookieA);
  assert.deepEqual(ch.body.channelTypes, ["console", "webhook"], "smtp absent until a provider is registered");
  assert.ok(!ch.body.subscribableEventTypes.some((t) => t.startsWith("notification.")), "notification.* unsubscribable");

  const consoleRule = await POST(["notifications", "rules"], { label: "A console", eventTypes: ["request.built"], vaultId: VAULT_ID, channel: { type: "console" } }, S.cookieA);
  assert.equal(consoleRule.status, 201);
  S.consoleRuleId = consoleRule.body.rule.ruleId;
  assert.equal(consoleRule.body.rule.channel.type, "console");

  // Machine credential WITH scopes creates the webhook-bridge rule.
  const whRule = await POST(
    ["notifications", "rules"],
    { label: "A bridge", eventTypes: ["request.built"], channel: { type: "webhook", url: receiverUrl, secret: SECRET, template: "json" } },
    { authorization: `Bearer ${S.tokenMgr}` }
  );
  assert.equal(whRule.status, 201);
  S.whRuleId = whRule.body.rule.ruleId;
  assert.deepEqual(whRule.body.rule.channel, { type: "webhook", url: receiverUrl, template: "json", hasSecret: true }, "secret NEVER echoed — only hasSecret");
  assert.ok(!JSON.stringify(whRule.body).includes(SECRET), "create response carries no secret");

  // B's isolation rule (everything B could see — which is nothing of A's).
  const bRule = await POST(["notifications", "rules"], { label: "B star", channel: { type: "console" } }, S.cookieB);
  S.bRuleId = bRule.body.rule.ruleId;

  const listA = await GET(["notifications", "rules"], {}, S.cookieA);
  assert.deepEqual(listA.body.rules.map((r) => r.ruleId).sort(), [S.consoleRuleId, S.whRuleId].sort(), "A sees exactly A's rules (machine-created included — same wallet)");
  assert.ok(!JSON.stringify(listA.body).includes(SECRET));
  const detail = await GET(["notifications", "rules", S.whRuleId], {}, S.cookieA);
  assert.equal(detail.body.rule.channel.hasSecret, true);
  assert.ok(!JSON.stringify(detail.body).includes(SECRET));

  await expectThrow(GET(["notifications", "rules", S.consoleRuleId], {}, S.cookieB), 404, "NOTIFY_RULE_NOT_FOUND");
  await expectThrow(GET(["notifications", "rules"], {}, { authorization: `Bearer ${S.tokenNoScope}` }), 403, "SCOPE_FORBIDDEN");
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "console" } }, { authorization: `Bearer ${S.tokenNoScope}` }), 403, "SCOPE_FORBIDDEN");
  await expectThrow(POST(["notifications", "rules", S.consoleRuleId, "disable"], {}, { authorization: `Bearer ${S.tokenNoScope}` }), 403, "SCOPE_FORBIDDEN");
});

test("VALIDATION fails closed: unknown/self-referential types, insecure URL, unknown channel, unregistered smtp, short secret, malformed filters", async () => {
  const c = S.cookieA;
  await expectThrow(POST(["notifications", "rules"], { eventTypes: ["not.a.type"], channel: { type: "console" } }, c), 422, "NOTIFY_EVENT_TYPE_UNKNOWN");
  await expectThrow(POST(["notifications", "rules"], { eventTypes: ["notification.rule.failing"], channel: { type: "console" } }, c), 422, "NOTIFY_EVENT_TYPE_SELF_REFERENTIAL");
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "webhook", url: "http://example.com/hook" } }, c), 422, "WEBHOOK_URL_INSECURE");
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "pigeon" } }, c), 422, "NOTIFY_CHANNEL_UNKNOWN");
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "smtp", to: "ops@example.com" } }, c), 422, "NOTIFY_CHANNEL_UNAVAILABLE");
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "webhook", url: receiverUrl, secret: "short" } }, c), 422, "NOTIFY_SECRET_INVALID");
  await expectThrow(POST(["notifications", "rules"], { vaultId: "nope", channel: { type: "console" } }, c), 422, "NOTIFY_VAULT_FILTER_INVALID");
  await expectThrow(POST(["notifications", "rules"], { eventTypes: [], channel: { type: "console" } }, c), 422, "NOTIFY_EVENT_TYPES_INVALID");
});

test("FAN-OUT via the REAL outbox: a real ownerPause build notifies the console rule and the SIGNED webhook bridge; B's '*' rule receives nothing", async () => {
  const built = await POST(
    ["wallet", "v4", "requests"],
    { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) },
    S.cookieA
  );
  assert.equal(built.status, 201);

  const worker = newWorker();
  await worker.tick();

  // Console provider delivered exactly one structured line.
  const mine = consoleLines.filter((l) => l.includes(S.consoleRuleId));
  assert.equal(mine.length, 1, "one console notification");
  const parsed = JSON.parse(mine[0].replace("policyvault-notify: ", ""));
  assert.equal(parsed.type, "request.built");
  assert.ok(parsed.text.includes("request.built") && parsed.text.includes("ownerPause"), "deterministic human text");

  // Webhook bridge delivered a pv1-SIGNED payload to the real receiver.
  assert.equal(received.length, 1, "one bridge delivery");
  const hit = received[0];
  assert.equal(hit.json.schemaVersion, "policyvault-notification/v1");
  assert.equal(hit.json.event.type, "request.built");
  assert.ok(hit.json.notice.includes("not authority"), "NOTIFICATION_NOTICE travels verbatim");
  assert.equal(hit.headers[EVENT_ID_HEADER], hit.json.event.eventId);
  assert.ok(hit.headers[DELIVERY_ID_HEADER]);
  const verdict = verifyWebhookSignature({ header: hit.headers[SIGNATURE_HEADER], rawBody: hit.raw, secret: SECRET });
  assert.equal(verdict.ok, true, "pv1 signature verifies with the rule secret over the exact raw body");

  // Durable per-rule cursors advanced; counters recorded.
  const st = await notifyState(S.whRuleId);
  assert.equal(st.counters.delivered, 1);
  assert.equal(st.pending, null);

  // Tenant isolation: B's "*" rule saw NOTHING of A's vault.
  const bLines = consoleLines.filter((l) => l.includes(S.bRuleId));
  assert.equal(bLines.length, 0, "foreign tenant receives nothing");
  const bState = await notifyState(S.bRuleId);
  assert.ok(!bState || bState.counters.delivered === 0);
});

test("DISABLE/ENABLE: a disabled rule receives nothing; enable resumes from the CURRENT head (backlog deliberately skipped)", async () => {
  const off = await POST(["notifications", "rules", S.consoleRuleId, "disable"], {}, S.cookieA);
  assert.equal(off.body.rule.status, "DISABLED");
  assert.equal(off.body.rule.disabledReason, "OPERATOR");

  const built = await POST(
    ["wallet", "v4", "requests"],
    { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel(2) }, signerAddress: ADDR(A) },
    S.cookieA
  );
  assert.equal(built.status, 201);
  const before = consoleLines.length;
  const worker = newWorker();
  await worker.tick();
  assert.equal(consoleLines.filter((l) => l.includes(S.consoleRuleId)).length, consoleLines.slice(0, before).filter((l) => l.includes(S.consoleRuleId)).length, "no delivery while disabled");

  const on = await POST(["notifications", "rules", S.consoleRuleId, "enable"], {}, S.cookieA);
  assert.equal(on.body.rule.status, "ACTIVE");
  await worker.tick();
  const after = consoleLines.filter((l) => l.includes(S.consoleRuleId));
  assert.equal(after.length, 1, "the while-disabled event was skipped: enable resumes from the head, never a backlog flood");
});

test("FAILURE ISOLATION + BOUNDED SIGNALS: dead provider fails alone; failing event exactly once; auto-disable with chained audit; no notification.* fan-out loop", async () => {
  // A rule pointed at a dead port, and a healthy "iso" console rule.
  const deadUrl = "http://127.0.0.1:9/dead"; // discard port: connection refused
  const dead = await POST(["notifications", "rules"], { label: "dead bridge", eventTypes: ["vault.created"], channel: { type: "webhook", url: deadUrl } }, S.cookieA);
  S.deadRuleId = dead.body.rule.ruleId;
  const iso = await POST(["notifications", "rules"], { label: "iso console", eventTypes: ["vault.created"], channel: { type: "console" } }, S.cookieA);
  S.isoRuleId = iso.body.rule.ruleId;

  for (let i = 0; i < AUTO_DISABLE_THRESHOLD; i++) {
    await emitPlatformEvent(config, { type: "vault.created", vaultId: VAULT_ID, data: { contractVersion: "v0.4", label: `storm ${i}` } });
  }
  // maxAttempts 1 + zero backoff: each tick consumes one failure.
  const worker = newWorker({ maxAttempts: 1, backoffScheduleMs: [0] });
  for (let i = 0; i < AUTO_DISABLE_THRESHOLD + 5 && (await notif.loadRuleRaw(config, S.deadRuleId)).status === "ACTIVE"; i++) {
    await worker.tick();
  }

  const deadRule = await notif.loadRuleRaw(config, S.deadRuleId);
  assert.equal(deadRule.status, "DISABLED");
  assert.equal(deadRule.disabledReason, "AUTO_FAILURE");
  const st = await notifyState(S.deadRuleId);
  assert.ok(st.counters.failed >= AUTO_DISABLE_THRESHOLD, `sustained failures recorded (${st.counters.failed})`);
  assert.ok(st.counters.delivered === 0);

  // The healthy rule delivered the SAME events in the SAME ticks.
  assert.equal(consoleLines.filter((l) => l.includes(S.isoRuleId)).length, AUTO_DISABLE_THRESHOLD, "healthy rule unaffected by the dead one");
  // The API keeps serving; the event stream is intact.
  const page = await GET(["events"], { limit: "200", types: "vault.created" }, S.cookieA);
  assert.equal(page.body.events.length, AUTO_DISABLE_THRESHOLD);

  // Bounded transition signals: exactly one failing, exactly one disabled.
  const failing = await eventsOfType("notification.rule.failing");
  assert.equal(failing.length, 1, "notification.rule.failing emitted exactly once");
  assert.equal(failing[0].data.ruleId, S.deadRuleId);
  assert.equal(failing[0].data.consecutiveFailures, FAILING_THRESHOLD);
  const disabled = await eventsOfType("notification.rule.disabled");
  assert.equal(disabled.length, 1, "notification.rule.disabled emitted exactly once");
  assert.deepEqual({ ruleId: disabled[0].data.ruleId, reason: disabled[0].data.reason }, { ruleId: S.deadRuleId, reason: "AUTO_FAILURE" });

  // Loop-freedom: notification.* events fanned out to NO rule (iso rule
  // is type-filtered, but even a "*" rule structurally skips them).
  const star = await POST(["notifications", "rules"], { label: "A star", channel: { type: "console" } }, S.cookieA);
  await worker.tick();
  assert.equal(consoleLines.filter((l) => l.includes(star.body.rule.ruleId) && l.includes("notification.")).length, 0, "notification.* never fans out");
  await POST(["notifications", "rules", star.body.rule.ruleId, "delete"], {}, S.cookieA);

  // Auto-disable left a CHAINED audit line; the chain stays VALID.
  const audit = await GET(["audit"], { limit: "500" }, S.cookieA);
  void audit; // (vault-scoped hosted feed; the chain check below is the load-bearing assertion)
  const chain = await GET(["audit", "chain", "verify"], {}, S.cookieA);
  assert.equal(chain.body.status, "VALID");
  const { readAudit } = require("../../server/src/audit");
  const records = await readAudit(config, { limit: 1000 });
  const auto = records.find((r) => r.kind === "notification" && r.action === "notification_rule_disabled" && r.ruleId === S.deadRuleId);
  assert.ok(auto, "auto-disable audited");
  assert.ok(auto.chain && auto.chain.recordHash, "…and chained");

  // Hosted visibility of the health events: creator sees them, B does not.
  const pageA = await GET(["events"], { limit: "500", types: "notification.rule.disabled" }, S.cookieA);
  assert.equal(pageA.body.events.length, 1);
  const pageB = await GET(["events"], { limit: "500", types: "notification.rule.disabled" }, S.cookieB);
  assert.equal(pageB.body.events.length, 0, "foreign tenant cannot see A's notification health events");
});

test("RATE LIMITING per tenant: beyond the rolling window NEW notifications are dropped and counted; the stream cursor still advances", async () => {
  const rule = await POST(["notifications", "rules"], { label: "rate", eventTypes: ["vault.reconciled"], channel: { type: "console" } }, S.cookieA);
  const ruleId = rule.body.rule.ruleId;
  for (let i = 0; i < 5; i++) {
    await emitPlatformEvent(config, { type: "vault.reconciled", vaultId: VAULT_ID, data: { outcome: "ADVANCED", to: `s${i}` } });
  }
  const worker = newWorker({ rateLimitPerHour: 3 });
  await worker.tick();
  const st = await notifyState(ruleId);
  assert.equal(st.counters.delivered, 3, "window admits exactly the cap");
  assert.equal(st.counters.rateLimited, 2, "excess dropped and counted");
  assert.equal(consoleLines.filter((l) => l.includes(ruleId)).length, 3);
  assert.equal(st.cursor, await getEventsStore(config).latestCursor(), "cursor advanced past dropped events (no poison backlog)");
  await POST(["notifications", "rules", ruleId, "delete"], {}, S.cookieA);
});

test("NO-SECRET SWEEP: payloads, console lines, delivery state, and every API response carry no secret; the operator at-rest key encrypts the stored envelope", async () => {
  // Everything delivered/logged so far:
  for (const line of consoleLines) assert.ok(!line.includes(SECRET), "console lines carry no secret");
  for (const hit of received) {
    assert.ok(!hit.raw.includes(SECRET), "bridge payloads carry no secret");
  }
  const st = JSON.stringify(await notifyState(S.whRuleId));
  assert.ok(!st.includes(SECRET), "delivery state carries no secret");
  const detail = await GET(["notifications", "rules", S.whRuleId], {}, S.cookieA);
  assert.ok(!JSON.stringify(detail.body).includes(SECRET), "detail response carries no secret");

  // At-rest encryption under the operator key (same envelope as webhook
  // endpoints): the raw secret must not exist ANYWHERE on disk.
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = "ab".repeat(32);
  try {
    const sealedSecret = "sealed_bridge_secret_0987654321";
    const rule = await POST(["notifications", "rules"], { label: "sealed", eventTypes: ["request.built"], channel: { type: "webhook", url: receiverUrl, secret: sealedSecret } }, S.cookieA);
    assert.equal(rule.status, 201);
    let disk = "";
    const walk = (dir) => {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(p);
        else disk += fs.readFileSync(p, "utf8") + "\n";
      }
    };
    walk(path.join(dataRoot, "platform"));
    assert.ok(!disk.includes(sealedSecret), "raw secret absent from every persisted platform byte under the operator key");
    // …and delivery still signs correctly (openSecret decrypts).
    const built = await POST(
      ["wallet", "v4", "requests"],
      { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel(3) }, signerAddress: ADDR(A) },
      S.cookieA
    );
    assert.equal(built.status, 201);
    const beforeCount = received.length;
    await newWorker().tick();
    const sealedHits = received.slice(beforeCount).filter((h) => h.json && h.json.ruleId === rule.body.rule.ruleId);
    assert.equal(sealedHits.length, 1, "sealed-secret rule delivered");
    assert.equal(verifyWebhookSignature({ header: sealedHits[0].headers[SIGNATURE_HEADER], rawBody: sealedHits[0].raw, secret: sealedSecret }).ok, true);
    await POST(["notifications", "rules", rule.body.rule.ruleId, "delete"], {}, S.cookieA);
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
  }
});

test("SMTP PLUGGABLE SEAM: unregistered refuses; a registered fake provider delivers through the same worker; a missing implementation fails safe", async () => {
  notif.registerChannelProvider("smtp");
  try {
    const ch = await GET(["notifications", "channels"], {}, S.cookieA);
    assert.deepEqual(ch.body.channelTypes, ["console", "webhook", "smtp"]);
    const rule = await POST(
      ["notifications", "rules"],
      { label: "mail", eventTypes: ["vault.created"], channel: { type: "smtp", to: "ops@example.com", subjectPrefix: "[PV]" } },
      S.cookieA
    );
    assert.equal(rule.status, 201);
    const ruleId = rule.body.rule.ruleId;

    await emitPlatformEvent(config, { type: "vault.created", vaultId: VAULT_ID, data: { contractVersion: "v0.4", label: "smtp probe" } });

    // Worker WITHOUT an smtp implementation: fails safe, isolated.
    const bare = newWorker({ maxAttempts: 1, backoffScheduleMs: [0] });
    await bare.tick();
    let st = await notifyState(ruleId);
    assert.equal(st.counters.delivered, 0);
    assert.equal(st.recentAttempts[0].errorCode, "NOTIFY_PROVIDER_UNAVAILABLE");

    // Worker WITH an injected provider (the seam): delivers.
    const mails = [];
    const withSmtp = newWorker({
      providers: {
        smtp: {
          type: "smtp",
          async deliver({ rule: r, event, text }) {
            mails.push({ to: r.channel.to, subject: `${r.channel.subjectPrefix ?? ""} ${event.type}`, text });
            return { ok: true, httpStatus: null, errorCode: null, durationMs: 1 };
          }
        }
      }
    });
    await emitPlatformEvent(config, { type: "vault.created", vaultId: VAULT_ID, data: { contractVersion: "v0.4", label: "smtp probe 2" } });
    await withSmtp.tick();
    assert.equal(mails.length, 1, "injected smtp provider received the notification");
    assert.equal(mails[0].to, "ops@example.com");
    await POST(["notifications", "rules", ruleId, "delete"], {}, S.cookieA);
  } finally {
    notif.unregisterChannelProvider("smtp");
  }
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "smtp", to: "x@y.zz" } }, S.cookieA), 422, "NOTIFY_CHANNEL_UNAVAILABLE");
});

test("QUOTA: the per-wallet rule cap refuses the 21st rule", async () => {
  const existing = (await GET(["notifications", "rules"], {}, S.cookieA)).body.rules.length;
  const created = [];
  for (let i = existing; i < 20; i++) {
    const r = await POST(["notifications", "rules"], { label: `fill ${i}`, channel: { type: "console" } }, S.cookieA);
    created.push(r.body.rule.ruleId);
  }
  await expectThrow(POST(["notifications", "rules"], { channel: { type: "console" } }, S.cookieA), 429, "NOTIFY_QUOTA_EXCEEDED");
  for (const id of created) await POST(["notifications", "rules", id, "delete"], {}, S.cookieA);
});

test("DELETE removes the rule and its delivery state; foreign delete 404s", async () => {
  await expectThrow(POST(["notifications", "rules", S.deadRuleId, "delete"], {}, S.cookieB), 404, "NOTIFY_RULE_NOT_FOUND");
  const del = await POST(["notifications", "rules", S.deadRuleId, "delete"], {}, S.cookieA);
  assert.equal(del.body.deleted, true);
  assert.equal(await notif.loadRuleRaw(config, S.deadRuleId), null);
  assert.equal(await notifyState(S.deadRuleId), null, "delivery state removed with the rule");
});
