"use strict";

/*
 * ASYNCHRONOUS EVENTS + WEBHOOK SUBSCRIPTIONS (completion-standard
 * surface 18; docs/postlaunch/webhooks-events-spec.md; server/src/
 * events.js, events-store.js, webhooks.js; migration 006).
 *
 * Real server api.handle() on the JSON backend, hosted authMode (the
 * machine-identity suite's harness pattern). A real v0.4 vault is seeded
 * for wallet A; wallet B is a signed-in FOREIGN tenant.
 *
 * Proves: real request-lifecycle emission (a REAL ownerPause build emits
 * request.built with requestId+manifestHash correlation); audit-hook
 * derivation (org controls -> org.controls.updated; unmapped audit kinds
 * emit NOTHING); EMISSION FAILURE ISOLATION (a broken event store never
 * fails the mutation — the "crashed emission -> consistent" contract);
 * cursor-correct tenant-scoped polling with no cross-tenant leakage
 * (hostile B, plus a machine credential's inherited tenancy); deny-by-
 * default scopes for the new routes; endpoint CRUD with the secret shown
 * exactly once and NEVER in listings/reads/durable idempotency records;
 * at-rest secret encryption when the operator key is set (raw secret
 * absent from disk; wrong key fails closed); https-only URL validation
 * with the explicit localhost dev override; closed event-type filters.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-webhookevt-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0xa7); // vault owner
const B = KEY(0xb8); // foreign, signed-in tenant, no vault
const AGENT = KEY(0xc9);
const RECIP = KEY(0xda);
const VAULT_ID = "5b".repeat(32);

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
    label: "webhook events test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "71".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "42".repeat(32) },
    creationTxId: "72".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}
const ownerFuel = () => ({ outpoint: { transactionId: "73".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(A)}ac` });

/* Every byte persisted under the platform/ tree (endpoint records,
 * delivery state, identity/idempotency records) — the no-secret-on-disk
 * sweeps read this. */
function allPlatformFileContents() {
  const out = [];
  const walk = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else out.push(fs.readFileSync(p, "utf8"));
    }
  };
  walk(path.join(dataRoot, "platform"));
  return out.join("\n");
}

const state = {};

test("setup: seed vault; A and B sign in; A mints machine credentials (read:events+webhooks:manage, and a scopeless-for-events one)", async () => {
  fs.writeFileSync(path.join(dataRoot, ".pv-network"), config.networkId); // readiness network stamp
  await seedVault();
  state.cookieA = await signIn(A);
  state.cookieB = await signIn(B);
  const full = await POST(["identities"], { label: "events-agent", scopes: ["read:events", "webhooks:manage"] }, state.cookieA);
  assert.equal(full.status, 201);
  state.tokenEvents = full.body.credential.token;
  const buildOnly = await POST(["identities"], { label: "build-only", scopes: ["request:build", "request:break-glass"] }, state.cookieA);
  state.tokenBuildOnly = buildOnly.body.credential.token;
});

test("EMISSION: a real ownerPause build emits request.built with requestId+manifestHash correlation, visible to A's polling", async () => {
  const built = await POST(
    ["wallet", "v4", "requests"],
    { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) },
    state.cookieA
  );
  assert.equal(built.status, 201);
  state.requestId = built.body.request.requestId;
  state.manifestHash = built.body.request.manifestHash;
  assert.match(state.manifestHash, /^[0-9a-f]{64}$/);

  const page = await GET(["events"], {}, state.cookieA);
  assert.equal(page.status, 200);
  assert.equal(page.body.schemaVersion, "policyvault-events-page/v1");
  assert.match(page.body.notice, /not authority/);
  const ev = page.body.events.find((e) => e.event.type === "request.built");
  assert.ok(ev, "request.built must be in A's stream");
  assert.equal(ev.event.schemaVersion, "policyvault-event/v1");
  assert.equal(ev.event.vaultId, VAULT_ID);
  assert.equal(ev.event.correlation.requestId, state.requestId);
  assert.equal(ev.event.correlation.manifestHash, state.manifestHash);
  assert.equal(ev.event.data.action, "ownerPause");
  assert.equal(ev.event.data.state, "BUILT");
  assert.equal(ev.event.networkId, config.networkId);
  state.builtEventId = ev.event.eventId;
  state.builtCursor = ev.cursor;
});

test("EMISSION via the audit hook: org-controls update emits org.controls.updated; a rejected request emits request.rejected", async () => {
  const org = await POST(["organizations"], { name: "Events Org" }, state.cookieA);
  assert.equal(org.status, 201);
  state.orgId = org.body.organization.orgId;
  const controls = await POST(["organizations", state.orgId, "controls"], { expectedVersion: 0 }, state.cookieA);
  assert.equal(controls.status, 200);

  const rejected = await POST(["wallet", "v4", "requests", state.requestId, "reject"], {}, state.cookieA);
  assert.equal(rejected.status, 200);

  const page = await GET(["events"], { limit: "100" }, state.cookieA);
  const typeSet = page.body.events.map((e) => e.event.type);
  assert.ok(typeSet.includes("org.controls.updated"), "org.controls.updated must be emitted via the audit hook");
  assert.ok(typeSet.includes("request.rejected"), "request.rejected must be emitted");
  const orgEv = page.body.events.find((e) => e.event.type === "org.controls.updated");
  assert.equal(orgEv.event.orgId, state.orgId);
});

test("CLOSED CATALOG: unmapped audit kinds emit NOTHING; unknown emission types refuse; closed per-type fields drop extras", async () => {
  const { appendAudit } = require("../../server/src/audit");
  const { getEventsStore } = require("../../server/src/events-store");
  const store = getEventsStore(config);
  const before = await store.countEvents();
  await appendAudit(config, { kind: "chain", vaultId: VAULT_ID, action: "something_new", result: "CHAIN_VERIFIED" });
  await appendAudit(config, { kind: "governance", vaultId: VAULT_ID, action: "x", result: "SOME_FUTURE_RESULT" });
  assert.equal(await store.countEvents(), before, "unmapped audit records must not publish events");

  const { emitPlatformEvent, buildEvent } = require("../../server/src/events");
  await assert.rejects(() => emitPlatformEvent(config, { type: "totally.new.type", data: {} }), (e) => e.code === "EVENT_TYPE_UNKNOWN");
  const built = buildEvent(config, { type: "request.built", vaultId: VAULT_ID, data: { action: "ownerPause", token: "pvmk_should_never_appear", secret: "nope" } });
  assert.equal(JSON.stringify(built).includes("pvmk_should_never_appear"), false, "closed per-type schema must drop undeclared fields");
  assert.equal(built.data.token, undefined);
});

test("FAILURE ISOLATION (crashed emission -> consistent): a broken event store never fails the mutation; audit + durable request intact", async () => {
  const { getEventsStore } = require("../../server/src/events-store");
  const store = getEventsStore(config);
  const original = store.appendEvent;
  const countBefore = await store.countEvents();
  store.appendEvent = async () => {
    throw new Error("simulated event-store outage");
  };
  try {
    const built = await POST(
      ["wallet", "v4", "requests"],
      { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(A) },
      state.cookieA
    );
    assert.equal(built.status, 201, "the mutation must succeed with emission down");
    state.isolatedRequestId = built.body.request.requestId;
  } finally {
    store.appendEvent = original;
  }
  // The durable request exists and is fully consistent; the event was
  // dropped (documented notification-loss semantics), not half-written.
  const req = await GET(["wallet", "v4", "requests", state.isolatedRequestId], {}, state.cookieA);
  assert.equal(req.status, 200);
  assert.equal(req.body.request.state, "BUILT");
  assert.equal(await store.countEvents(), countBefore, "no partial event row");
  const stats = await require("../../server/src/events").eventStats(config);
  assert.ok(stats.droppedEmissions >= 1, "dropped emissions are counted for monitoring");
  // Clean up quota for later tests.
  await POST(["wallet", "v4", "requests", state.isolatedRequestId, "reject"], {}, state.cookieA);
});

test("POLLING cursors: page through with limit=1 — no duplicates, no gaps, stable resume; types filter narrows; unknown type refuses", async () => {
  const first = await GET(["events"], { limit: "500" }, state.cookieA);
  const all = first.body.events;
  assert.ok(all.length >= 3);
  const paged = [];
  let cursor = "0";
  for (let i = 0; i < all.length; i++) {
    const page = await GET(["events"], { limit: "1", cursor }, state.cookieA);
    assert.equal(page.body.events.length, 1);
    paged.push(page.body.events[0]);
    cursor = page.body.nextCursor;
  }
  assert.deepEqual(paged.map((e) => e.event.eventId), all.map((e) => e.event.eventId), "1-by-1 paging reproduces the stream exactly");
  const resumed = await GET(["events"], { cursor }, state.cookieA);
  assert.equal(resumed.body.events.length, 0, "resuming at the end yields nothing new");

  const filtered = await GET(["events"], { types: "request.rejected" }, state.cookieA);
  assert.ok(filtered.body.events.length >= 1);
  assert.ok(filtered.body.events.every((e) => e.event.type === "request.rejected"));
  await expectThrow(GET(["events"], { types: "no.such.type" }, state.cookieA), 422, "EVENT_TYPE_UNKNOWN");
  await expectThrow(GET(["events"], { cursor: "not-a-cursor" }, state.cookieA), 400, "BAD_CURSOR");
});

test("HOSTILE cross-tenant: B sees NONE of A's events (polling); a machine credential inherits exactly A's visibility", async () => {
  const asB = await GET(["events"], { limit: "500" }, state.cookieB);
  assert.equal(asB.status, 200);
  assert.deepEqual(asB.body.events, [], "a foreign tenant must see an empty stream, not A's events");

  const asMachine = await GET(["events"], { limit: "500" }, { authorization: `Bearer ${state.tokenEvents}` });
  assert.ok(asMachine.body.events.some((e) => e.event.eventId === state.builtEventId), "A's machine credential (read:events) sees A's events");

  await expectThrow(GET(["events"], {}, { authorization: `Bearer ${state.tokenBuildOnly}` }), 403, "SCOPE_FORBIDDEN");
});

test("WEBHOOK CRUD: secret shown exactly once (pvwh_), never in listings/read/detail; tenancy hides foreign endpoints; scopes gate machines", async () => {
  const created = await POST(["webhooks"], { url: "https://consumer.example.com/hooks/pv", eventTypes: ["request.built", "request.rejected"], label: "ci" }, state.cookieA);
  assert.equal(created.status, 201);
  assert.match(created.body.secret, /^pvwh_[0-9a-f]{64}$/);
  assert.match(created.body.secretNotice, /exactly once/);
  state.endpointId = created.body.endpoint.endpointId;
  state.endpointSecret = created.body.secret;
  assert.equal(created.body.endpoint.creatorXOnly, XO(A));
  assert.equal(created.body.endpoint.status, "ACTIVE");
  assert.equal(JSON.stringify(created.body.endpoint).includes(state.endpointSecret), false);

  const listed = await GET(["webhooks"], {}, state.cookieA);
  assert.equal(listed.body.endpoints.length, 1);
  assert.equal(JSON.stringify(listed.body).includes(state.endpointSecret), false, "listing must never carry the secret");

  const detail = await GET(["webhooks", state.endpointId], {}, state.cookieA);
  assert.equal(detail.status, 200);
  assert.equal(JSON.stringify(detail.body).includes(state.endpointSecret), false, "detail must never carry the secret");
  assert.equal(detail.body.endpoint.secretPrefix, state.endpointSecret.slice(0, 13));

  // Foreign tenant: existence hidden; listing empty.
  await expectThrow(GET(["webhooks", state.endpointId], {}, state.cookieB), 404, "WEBHOOK_ENDPOINT_NOT_FOUND");
  const listedB = await GET(["webhooks"], {}, state.cookieB);
  assert.deepEqual(listedB.body.endpoints, []);

  // Machine scopes: webhooks:manage reaches the surface; others refused.
  const asMachine = await GET(["webhooks"], {}, { authorization: `Bearer ${state.tokenEvents}` });
  assert.equal(asMachine.status, 200);
  assert.equal(asMachine.body.endpoints.length, 1, "machine credential inherits A's tenancy");
  await expectThrow(POST(["webhooks"], { url: "https://x.example.com/h" }, { authorization: `Bearer ${state.tokenBuildOnly}` }), 403, "SCOPE_FORBIDDEN");
});

test("WEBHOOK URL validation: https only; http refused (even localhost) without the explicit dev override; override permits loopback only, never mainnet semantics; bad types refused", async () => {
  delete process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL;
  await expectThrow(POST(["webhooks"], { url: "http://consumer.example.com/h" }, state.cookieA), 422, "WEBHOOK_URL_INSECURE");
  await expectThrow(POST(["webhooks"], { url: "http://127.0.0.1:9999/h" }, state.cookieA), 422, "WEBHOOK_URL_INSECURE");
  await expectThrow(POST(["webhooks"], { url: "ftp://x.example.com/h" }, state.cookieA), 422, "WEBHOOK_URL_INVALID");
  await expectThrow(POST(["webhooks"], { url: "https://user:pw@x.example.com/h" }, state.cookieA), 422, "WEBHOOK_URL_INVALID");
  await expectThrow(POST(["webhooks"], { url: "https://x.example.com/h", eventTypes: ["nope.nope"] }, state.cookieA), 422, "WEBHOOK_EVENT_TYPE_UNKNOWN");
  await expectThrow(POST(["webhooks"], { url: "https://x.example.com/h", eventTypes: [] }, state.cookieA), 422, "WEBHOOK_EVENT_TYPES_INVALID");

  process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL = "1";
  try {
    const local = await POST(["webhooks"], { url: "http://127.0.0.1:9999/h", label: "dev" }, state.cookieA);
    assert.equal(local.status, 201, "loopback http allowed under the explicit dev override (non-mainnet)");
    await expectThrow(POST(["webhooks"], { url: "http://consumer.example.com/h" }, state.cookieA), 422, "WEBHOOK_URL_INSECURE");
    await POST(["webhooks", local.body.endpoint.endpointId, "revoke"], {}, state.cookieA);
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_ALLOW_INSECURE_LOCAL;
  }
});

test("SECRET AT REST: plaintext envelope only inside the restricted category by default; with POLICYVAULT_WEBHOOK_SECRET_KEY the raw secret is ABSENT from disk and a wrong key fails closed", async () => {
  // Default (documented tradeoff): the raw secret exists ONLY inside the
  // webhook-endpoints category files, nowhere else on the platform tree.
  const disk = allPlatformFileContents();
  assert.ok(disk.includes(state.endpointSecret), "plain/v1 envelope is documented plaintext-at-rest");
  const outsideCategory = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "webhook-endpoints") continue;
        walk(p);
      } else outsideCategory.push(fs.readFileSync(p, "utf8"));
    }
  };
  walk(path.join(dataRoot, "platform"));
  assert.equal(outsideCategory.join("\n").includes(state.endpointSecret), false, "the raw secret never leaks outside its own category (no idempotency/audit/event copies)");

  const keyHex = "ab".repeat(32);
  process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = keyHex;
  try {
    const created = await POST(["webhooks"], { url: "https://enc.example.com/h", label: "encrypted" }, state.cookieA);
    assert.equal(created.status, 201);
    const encSecret = created.body.secret;
    assert.equal(allPlatformFileContents().includes(encSecret), false, "with the operator key set, the raw secret must NOT be on disk");

    const wh = require("../../server/src/webhooks");
    const endpoint = await wh.loadEndpointRaw(config, created.body.endpoint.endpointId);
    assert.equal(endpoint.secret.v, "aes256gcm/v1");
    assert.equal(wh.openSecret(endpoint.secret), encSecret, "the right key round-trips");
    process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = "cd".repeat(32);
    assert.throws(() => wh.openSecret(endpoint.secret), (e) => e.code === "WEBHOOK_SECRET_UNAVAILABLE", "wrong key fails closed (no plaintext fallback)");
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
    assert.throws(() => wh.openSecret(endpoint.secret), (e) => e.code === "WEBHOOK_SECRET_UNAVAILABLE", "missing key fails closed");
    assert.throws(() => wh.openSecret({ v: "future/v9", x: 1 }), (e) => e.code === "WEBHOOK_SECRET_UNAVAILABLE", "unknown envelope versions fail closed");
    process.env.POLICYVAULT_WEBHOOK_SECRET_KEY = keyHex;
    await POST(["webhooks", created.body.endpoint.endpointId, "revoke"], {}, state.cookieA);
  } finally {
    delete process.env.POLICYVAULT_WEBHOOK_SECRET_KEY;
  }
});

test("ROTATION + REVOCATION: rotate returns a NEW secret once (old co-signs during grace); revoked endpoints refuse rotation; foreign rotation hidden", async () => {
  const rotated = await POST(["webhooks", state.endpointId, "rotate-secret"], {}, state.cookieA);
  assert.equal(rotated.status, 200);
  assert.match(rotated.body.secret, /^pvwh_[0-9a-f]{64}$/);
  assert.notEqual(rotated.body.secret, state.endpointSecret);
  assert.ok(rotated.body.endpoint.previousSecretValidUntilMs > Date.now(), "grace window is armed");

  const wh = require("../../server/src/webhooks");
  const endpoint = await wh.loadEndpointRaw(config, state.endpointId);
  const secrets = wh.signingSecretsFor(endpoint);
  assert.equal(secrets.length, 2, "current + previous co-sign during the grace window");
  assert.equal(secrets[0], rotated.body.secret);
  assert.equal(secrets[1], state.endpointSecret);
  assert.equal(wh.signingSecretsFor(endpoint, endpoint.previousSecretValidUntilMs + 1).length, 1, "grace expiry drops the old secret");

  await expectThrow(POST(["webhooks", state.endpointId, "rotate-secret"], {}, state.cookieB), 404, "WEBHOOK_ENDPOINT_NOT_FOUND");

  const revoked = await POST(["webhooks", state.endpointId, "revoke"], {}, state.cookieA);
  assert.equal(revoked.body.endpoint.status, "REVOKED");
  await expectThrow(POST(["webhooks", state.endpointId, "rotate-secret"], {}, state.cookieA), 409, "WEBHOOK_ENDPOINT_REVOKED");
});

test("IDEMPOTENCY EXCLUSION: POST /webhooks with an Idempotency-Key executes but never persists the secret-bearing response; /health/ready carries only non-secret aggregate numbers", async () => {
  const headers = { cookie: state.cookieA, idempotencyKey: "webhook-create-1" };
  const created = await POST(["webhooks"], { url: "https://idem.example.com/h" }, headers);
  assert.equal(created.status, 201);
  const secret = created.body.secret;
  assert.equal(allPlatformFileContents().replace(secret, "SECRET_ITSELF").includes(secret), false, "no second copy: the idempotency store must not have persisted the response");
  // Same key again: NOT a replay (a fresh endpoint is created) — the
  // deliberate, documented tradeoff for never persisting secrets.
  const again = await POST(["webhooks"], { url: "https://idem.example.com/h" }, headers);
  assert.equal(again.status, 201);
  assert.notEqual(again.body.endpoint.endpointId, created.body.endpoint.endpointId);
  await POST(["webhooks", created.body.endpoint.endpointId, "revoke"], {}, state.cookieA);
  await POST(["webhooks", again.body.endpoint.endpointId, "revoke"], {}, state.cookieA);

  const ready = await GET(["health", "ready"], {});
  assert.equal(ready.status, 200);
  assert.ok(ready.body.events, "readiness carries the events aggregate");
  for (const [k, v] of Object.entries(ready.body.events)) {
    assert.ok(v === null || typeof v === "number", `events aggregate field ${k} must be a number or null`);
  }
  assert.equal(JSON.stringify(ready.body).includes("pvwh_"), false);
  assert.equal(JSON.stringify(ready.body).includes("example.com"), false, "no endpoint URLs on the public readiness surface");
});

test("SELF-HOSTED MODE: events + webhooks work without sessions (single operator); machine-identity surface absent does not affect events", async () => {
  const shRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-webhookevt-sh-"));
  const shConfig = loadConfig({ dataRoot: shRoot });
  const { emitPlatformEvent } = require("../../server/src/events");
  await emitPlatformEvent(shConfig, { type: "vault.reconciled", vaultId: "9c".repeat(32), data: { outcome: "CONSISTENT" } });
  const page = await handle(shConfig, "GET", ["events"], {}, null, {});
  assert.equal(page.status, 200);
  assert.equal(page.body.events.length, 1, "self-hosted operator sees the stream without a session");
  const created = await handle(shConfig, "POST", ["webhooks"], {}, { url: "https://self.example.com/h" }, {});
  assert.equal(created.status, 201);
  assert.equal(created.body.endpoint.creatorXOnly, null);
});
