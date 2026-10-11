"use strict";
/*
 * RC45 R1-11 — POST /identities CANNOT ATTACH AN IDENTITY, OR ITS EVENTS, TO AN
 * ORGANIZATION THE CALLER DOES NOT OWN (finding OBS-R1-02-A, LOW, RC42/RC44-
 * present; remediation plan R1 amendment PA-R1-01).
 * Internal RED-first regression material for the RC45 successor
 * candidate; not an audit.
 *
 * THE DEFECT (PA-R1-01 "Finding"): POST /identities passes body.orgId to
 * server/src/machine-identity.js createIdentity, which stores String(orgId)
 * without checking the organization or the caller's relationship to it; the
 * route then emits identity.created with that orgId, and POST
 * /identities/:id/revoke later emits identity.revoked with the stored orgId.
 * server/src/events.js eventVisibleTo routes any event carrying an orgId to
 * that organization's readers (orgAccessAllowed(..., "read")): the event
 * stream (GET /events), webhooks and notifications. A wallet that knows a
 * foreign organization's id can therefore inject identity.* events, with its
 * own label and scopes, into that organization's stream. The tag confers no
 * authority anywhere; the harm is cross-tenant event injection only.
 *
 * THE FIX THIS SUITE PINS (PA-R1-01 "Mechanism", hosted mode only):
 *   1. create: when body.orgId is present (not undefined, not null), BEFORE
 *      createIdentity and before any event: a malformed id (not a UUID as
 *      sdk/src/organization.js requireOrgId defines it) -> 422 ORG_ID_INVALID;
 *      otherwise requireOrgAccess(config, loadOrganization(...), principal,
 *      "owner"): a missing or foreign organization -> 404 ORG_NOT_FOUND (non-
 *      oracle), a member who is not the owner -> 403 ORG_FORBIDDEN. A refusal
 *      writes no identity, credential, event or notification. The owner and
 *      every request without orgId behave exactly as today.
 *   2. revoke: identity.revoked carries the stored orgId only if the revoking
 *      principal currently passes orgAccessAllowed(..., "owner") for it;
 *      otherwise the field is omitted and the creator-only identity.*
 *      visibility applies. The revocation itself stays creator-scoped.
 *   Self-hosted mode (tenancy not enforced) is unchanged.
 *
 * RED on 40f3a26 (the RC45 lane head this item starts from) — each named
 * "[RED on 40f3a26]": the foreign-organization, missing-organization,
 * malformed-id and non-owner-member create legs, the revoke of a pre-fix
 * identity seeded with a foreign orgId, and the PA-R1-01 revision 1 C1
 * revoke-guard legs (b) (stored orgId "not-a-uuid"; stored orgId "") and (c)
 * (an owner-tagged identity revoked after its organization was deleted).
 * HOLDS on 40f3a26 (and must keep holding): the organization owner tagging
 * its own organization (201; owner and member see identity.created), a
 * request without orgId (201, unchanged), the owner's revoke carrying orgId,
 * the creator-scoped revocation (PA-R1-01 mechanism §2), self-hosted mode,
 * and C1 revoke-guard leg (a) (stored orgId null).
 *
 * PA-R1-01 revision 1 conditions this file pins (binding):
 *   C1 the revoke guard runs after revokeIdentity persisted and never throws:
 *      whatever the stored orgId (null, "", malformed, a deleted
 *      organization's id), the answer is 200 with the durable REVOKED record
 *      and the response body exactly as today; identity.revoked carries no
 *      orgId unless the revoker currently owns that live organization, so it
 *      reaches its creator (GET /events, webhook, notification) and nobody
 *      else.
 *   C4 every "nothing written" comparison goes through the store abstractions
 *      the same way on JSON and PostgreSQL (every platform-store, events-store
 *      and sdk store category, the event rows and the audit). EXACTLY ONE
 *      write is excluded, and only because it is not part of those stores:
 *      the caller's own wallet-session touch (EXCLUDED_WRITE below).
 *   C5 the delivery observation can fail: owner, member and foreign wallet
 *      each hold an ACTIVE webhook endpoint and an ACTIVE notification rule
 *      that identity.created / identity.revoked match (asserted from the
 *      stored records), and every observation first proves that each
 *      endpoint and rule scanned the whole outbox as it stood before the tick
 *      with nothing pending — so an absence is a filtering decision, never an
 *      unscanned row.
 *   C6 the backend of every leg is asserted from the store kinds (not taken
 *      from its name) and written to the TAP output as a diagnostic.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode; wallet
 * sessions signed in with TEST keys through /auth/challenge + /auth/verify)
 * plus the real webhook DeliveryWorker (an injected in-process transport —
 * nothing leaves the process) and the real NotificationWorker (console sink).
 * The stream is observed three ways: GET /events per principal, webhook
 * deliveries per endpoint and notification lines per rule. "Nothing written"
 * compares every platform-store category (identities, credentials,
 * idempotency, suspensions, audit chain, telemetry), every events-store
 * category (event rows, webhook endpoints/state/dead letters, notification
 * rules/state), the organization records and the audit stream immediately
 * before and after the call. No node: every config names ws://127.0.0.1:1 and
 * nothing here dials it. Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only (0x61 organization
 * owner, 0x62 member, 0x63 foreign wallet).
 */
const util = require("node:util");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");

const configMod = require("../src/config");
const storeMod = require("../src/store");
const { handle } = require("../../server/src/api");
const platform = require("../../server/src/platform-store");
const eventsStore = require("../../server/src/events-store");
const { DeliveryWorker } = require("../../server/src/events-delivery");
const { NotificationWorker } = require("../../server/src/notify-delivery");
const mi = require("../../server/src/machine-identity");
const { IDENTITY_SCHEMA } = mi;

const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const WHO = ["owner", "member", "foreign"];
const TYPES = ["identity.created", "identity.revoked"];
const INJECTED_LABEL = "R1-11 TEST label chosen by a foreign wallet";
/* PA-R1-01 C4: the ONE write a "nothing written" comparison here excludes. Every authenticated request (refused or
 * not) slides its own session's inactivity window: server/src/auth.js resolveSession -> sessionTouch. That record is
 * not in any store the comparison reads (process-local MemoryAuthStore on JSON; auth_sessions.last_seen_ms on
 * PostgreSQL), so it is excluded on both backends alike; nothing else is. */
const EXCLUDED_WRITE = "the caller's own wallet-session touch (auth.js resolveSession -> sessionTouch: lastSeenMs in the process-local MemoryAuthStore on JSON, auth_sessions.last_seen_ms on PostgreSQL)";
const roots = [], stores = [], databases = [];
let admin = null, serial = 0;

before(() => { if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG); });
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();
const hookUrl = (who) => `https://${who}.r1-11.invalid/hook`;

function walletsFor(config) {
  const kaspa = require(config.rustyKaspaModule);
  const one = (byte) => {
    const secretHex = byte.toString(16).padStart(2, "0").repeat(32), priv = new kaspa.PrivateKey(secretHex);
    return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
  };
  return { owner: one(0x61), member: one(0x62), foreign: one(0x63) };
}

/* Every durable record this route family or its consumers could write, as sorted JSON strings per category, read
 * through the store abstractions the same way on JSON and PostgreSQL (PA-R1-01 C4): every platform-store category
 * (machine identities, credentials, idempotency, suspensions, audit chain, telemetry), every events-store category
 * (webhook endpoints/state/dead letters, notification rules/state) plus the event rows, every sdk store category
 * (vaults, requests, claims, receipts, organizations, assignments, roots, governance, controls, risk) and the audit
 * stream. Excluded: EXCLUDED_WRITE only. */
async function durable(config) {
  const ps = platform.getPlatformStore(config), es = eventsStore.getEventsStore(config), ss = storeMod.getStore(config);
  const sorted = (values) => values.map((v) => JSON.stringify(v)).sort();
  const out = {};
  for (const c of Object.values(platform.Categories)) out[c] = sorted(await ps.listValues(c));
  for (const c of Object.values(eventsStore.Categories)) out[c] = sorted(await es.listValues(c));
  out["platform-events"] = (await es.listEventsAfter({ cursor: "0", limit: 500 })).map((row) => JSON.stringify(row.event));
  for (const c of Object.values(storeMod.Categories)) out[`store-${c}`] = sorted(await ss.listValues(c));
  out.audit = (await ss.readAudit({ limit: 5000 })).map((row) => JSON.stringify(row));
  return out;
}
function wroteBetween(a, b) {
  const out = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (!util.isDeepStrictEqual(a[k], b[k])) out.push(`${k} ${(a[k] ?? []).length}->${(b[k] ?? []).length}`);
  }
  return out;
}

/* A fresh case. Hosted: the organization owner creates the organization and adds the member (with a wallet address,
 * so the existing rule gives it READ); owner, member and foreign wallet each subscribe one webhook endpoint and one
 * console notification rule to identity.created / identity.revoked. Self-hosted: tenancy not enforced. */
async function fresh(backend, { hosted = true } = {}) {
  const dataRoot = K.ownedTempRoot("pv-rc45-r1-11-"); roots.push(dataRoot);
  const base = { dataRoot, rpcUrl: K.LOOPBACK, ...(hosted ? { authMode: "enabled", authCookieInsecure: true } : {}) };
  let config, pgDatabase = null, opened = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1_11_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = configMod.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...(hosted ? {} : { hostedDevOpen: true }), ...base });
    opened = await storeMod.openPgStore(config, { migrate: true }); stores.push(opened);
    assert.equal(storeMod.getStore(config).kind, "postgres");
    assert.equal(platform.getPlatformStore(config).kind, "postgres");
    assert.equal(eventsStore.getEventsStore(config).kind, "postgres");
  } else config = configMod.loadConfig(base);
  assert.equal(config.tenancyEnforced, hosted, hosted ? "hosted case: tenancy enforced" : "self-hosted case: tenancy not enforced");
  /* PA-R1-01 C6: the backend a leg runs on is asserted from the three store kinds, never inferred from its name. */
  const backendKinds = { store: storeMod.getStore(config).kind, platform: platform.getPlatformStore(config).kind, events: eventsStore.getEventsStore(config).kind };
  const wantKind = backend === "PostgreSQL" ? "postgres" : "json";
  assert.deepEqual(backendKinds, { store: wantKind, platform: wantKind, events: wantKind }, `C6: every store of a ${backend} leg is ${wantKind}`);
  const kaspa = require(config.rustyKaspaModule);
  const w = walletsFor(config);
  const x = { config, w, pgDatabase, opened, backendKinds };
  x.call = async (method, segments, body = null, cookie = null, query = {}) => {
    try {
      const r = await handle(config, method, segments, query, body, cookie ? { headers: { cookie } } : {});
      return { status: r.status, code: null, body: r.body, headers: r.headers ?? {}, message: null };
    } catch (e) {
      if (e && e.code === "ERR_ASSERTION") throw e;
      return { status: e && e.status !== undefined ? e.status : null, code: e && e.code ? e.code : null, body: null, headers: {}, message: String(e && e.message) };
    }
  };
  x.durable = () => durable(config);
  if (!hosted) return x;

  const signIn = async (wallet) => {
    const priv = new kaspa.PrivateKey(wallet.secretHex);
    const ch = await x.call("POST", ["auth", "challenge"], { walletAddress: wallet.address });
    assert.equal(ch.status, 200, `auth challenge (${said(ch)})`);
    const signature = kaspa.signMessage({ message: ch.body.challenge.message, privateKey: priv.toString() });
    const v = await x.call("POST", ["auth", "verify"], { nonce: ch.body.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() });
    assert.equal(v.status, 200, `auth verify (${said(v)})`);
    return String(v.headers["Set-Cookie"]).split(";")[0];
  };
  x.cookie = {};
  for (const who of WHO) x.cookie[who] = await signIn(w[who]);

  const org = await x.call("POST", ["organizations"], { name: "R1-11 TEST organization" }, x.cookie.owner);
  assert.equal(org.status, 201, `create organization (${said(org)})`);
  x.orgId = org.body.organization.orgId;
  assert.equal(org.body.organization.tenantOwner, w.owner.xonly);
  const mem = await x.call("POST", ["organizations", x.orgId, "members"], { displayName: "R1-11 TEST member", address: w.member.address, roles: ["viewer"], expectedVersion: 1 }, x.cookie.owner);
  assert.equal(mem.status, 201, `add member (${said(mem)})`);
  assert.equal(mem.body.member.xOnlyPubkey, w.member.xonly);
  /* The existing organization rule this item relies on: the member READS, the foreign wallet gets the non-oracle 404. */
  assert.equal((await x.call("GET", ["organizations", x.orgId], null, x.cookie.member)).status, 200, "the member reads the organization");
  assert.equal((await x.call("GET", ["organizations", x.orgId], null, x.cookie.foreign)).code, "ORG_NOT_FOUND", "the foreign wallet does not");

  x.rule = {}; x.endpoint = {};
  for (const who of WHO) {
    const ep = await x.call("POST", ["webhooks"], { url: hookUrl(who), eventTypes: TYPES, label: `R1-11 TEST ${who}` }, x.cookie[who]);
    assert.equal(ep.status, 201, `webhook endpoint for ${who} (${said(ep)})`);
    x.endpoint[who] = ep.body.endpoint.endpointId;
    const rule = await x.call("POST", ["notifications", "rules"], { label: `R1-11 TEST ${who}`, eventTypes: TYPES, channel: { type: "console" } }, x.cookie[who]);
    assert.equal(rule.status, 201, `notification rule for ${who} (${said(rule)})`);
    x.rule[who] = rule.body.rule.ruleId;
  }
  /* PA-R1-01 C5: read back from the events store — each principal holds an ACTIVE endpoint and an ACTIVE rule of its
   * own that both identity event types match (no vault or organization filter on the rule). */
  const es = eventsStore.getEventsStore(config);
  for (const who of WHO) {
    const ep = await es.read(eventsStore.Categories.WEBHOOK_ENDPOINT, x.endpoint[who]);
    const rule = await es.read(eventsStore.Categories.NOTIFY_RULE, x.rule[who]);
    for (const [what, record] of [["webhook endpoint", ep], ["notification rule", rule]]) {
      assert.ok(record, `C5: ${who}'s ${what} is stored`);
      assert.equal(record.status, "ACTIVE", `C5: ${who}'s ${what} is ACTIVE`);
      assert.equal(record.creatorXOnly, w[who].xonly, `C5: ${who}'s ${what} belongs to ${who}`);
      for (const type of TYPES) assert.ok(record.eventTypes.includes(type), `C5: ${who}'s ${what} matches ${type}`);
    }
    assert.equal(rule.vaultId ?? null, null, `C5: ${who}'s notification rule has no vault filter`);
    assert.equal(rule.orgId ?? null, null, `C5: ${who}'s notification rule has no organization filter`);
  }

  /* GET /events as `who`, filtered to one event type. */
  x.seen = async (who, type) => {
    const r = await x.call("GET", ["events"], null, x.cookie[who], { types: type, limit: "500" });
    assert.equal(r.status, 200, `GET /events as ${who} (${said(r)})`);
    return r.body.events.map((row) => row.event);
  };
  /* One tick of the real webhook and notification workers; what each principal's endpoint and rule received. */
  x.deliver = async () => {
    const hooks = [], lines = [];
    const head = BigInt(await es.latestCursor());
    await new DeliveryWorker(config, {
      transport: async ({ url, rawBody }) => { hooks.push({ url, event: JSON.parse(rawBody).event }); return { ok: true, httpStatus: 200, errorCode: null, durationMs: 1 }; }
    }).tick();
    await new NotificationWorker(config, { consoleSink: (line) => lines.push(JSON.parse(String(line).replace(/^policyvault-notify: /, ""))) }).tick();
    /* PA-R1-01 C5: the observation is conclusive only if every principal's endpoint and rule is still ACTIVE, holds
     * nothing pending and scanned the whole outbox as it stood before the tick (cursor at or past that head): an event
     * that did not reach a principal was then filtered or invisible to it, never left unscanned. */
    for (const who of WHO) {
      for (const [what, cat, stateCat, id] of [["webhook endpoint", eventsStore.Categories.WEBHOOK_ENDPOINT, eventsStore.Categories.WEBHOOK_DELIVERY_STATE, x.endpoint[who]], ["notification rule", eventsStore.Categories.NOTIFY_RULE, eventsStore.Categories.NOTIFY_STATE, x.rule[who]]]) {
        const record = await es.read(cat, id), state = await es.read(stateCat, id);
        assert.equal(record.status, "ACTIVE", `C5: ${who}'s ${what} is still ACTIVE after the tick`);
        assert.equal(state ? state.pending : null, null, `C5: ${who}'s ${what} holds nothing pending after the tick`);
        const cursor = BigInt(state ? state.cursor : (record.initialCursor ?? "0"));
        assert.ok(cursor >= head, `C5: ${who}'s ${what} scanned the outbox to its pre-tick head ${head} (at ${cursor})`);
      }
    }
    const out = {};
    for (const who of WHO) {
      out[who] = {
        webhook: hooks.filter((h) => h.url === hookUrl(who)).map((h) => ({ type: h.event.type, eventId: h.event.eventId, orgId: h.event.orgId })),
        notification: lines.filter((l) => l.ruleId === x.rule[who]).map((l) => ({ type: l.type, eventId: l.eventId, orgId: l.orgId }))
      };
    }
    return out;
  };
  /* The durable events of `type` correlated to `identityId`. */
  x.eventsFor = async (type, identityId) => (await eventsStore.getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 }))
    .map((row) => row.event).filter((e) => e.type === type && e.correlation && e.correlation.identityId === identityId);
  /* A PRE-FIX identity: exactly the record createIdentity at 40f3a26 writes for `creator` naming `orgId` (the fix
   * refuses such a create, so the record is seeded through the platform store). */
  x.seedPreFixIdentity = async (creator, orgId) => {
    const now = new Date().toISOString();
    const record = { schema: IDENTITY_SCHEMA, identityId: crypto.randomUUID(), networkId: config.networkId, creatorXOnly: w[creator].xonly, orgId, label: "R1-11 TEST pre-fix identity", scopes: ["read:vaults"], status: "ACTIVE", createdAt: now, updatedAt: now, revokedAt: null };
    await platform.getPlatformStore(config).write(platform.Categories.MACHINE_IDENTITY, record.identityId, record);
    return record;
  };
  return x;
}
async function release(x) {
  if (!x.opened) return;
  const i = stores.indexOf(x.opened);
  if (i >= 0) { stores.splice(i, 1); await x.opened.close(); }
}

/* Every organization reader (owner, member) that can observe an event of `type` for `identityId`, three ways. */
async function orgReaderLeaks(x, type, identityId, deliveries) {
  const out = [];
  const eventIds = new Set((await x.eventsFor(type, identityId)).map((e) => e.eventId));
  for (const who of ["owner", "member"]) {
    const seen = (await x.seen(who, type)).filter((e) => e.correlation && e.correlation.identityId === identityId);
    for (const e of seen) out.push(`the organization ${who} sees ${type} in GET /events (orgId ${e.orgId}, label ${JSON.stringify(e.data.label)}, creatorXOnly ${String(e.data.creatorXOnly).slice(0, 8)}…)`);
    for (const d of deliveries[who].webhook) if (d.type === type && eventIds.has(d.eventId)) out.push(`the organization ${who}'s webhook endpoint received ${type}`);
    for (const d of deliveries[who].notification) if (d.type === type && eventIds.has(d.eventId)) out.push(`the organization ${who}'s notification rule fired for ${type}`);
  }
  return out;
}

const ROLE = { owner: "the organization owner", member: "the organization member", foreign: "the foreign wallet" };
/* PA-R1-01 C1: everything a revoke must show whatever the stored orgId. `before` is the durable identity record read
 * immediately before the revoke, `r` the revoke's answer, `creator` the revoking creator. Required: 200; the durable
 * record is `before` with status REVOKED and revokedAt = updatedAt = the revocation time, every other field (the stored
 * orgId included) unchanged; the body is exactly { identity: presentIdentity(durable record) }; exactly one
 * identity.revoked, carrying NO orgId (null, i.e. omitted), visible to the creator through GET /events, its webhook
 * endpoint and its notification rule, and to no other principal through any of the three. Returns the violations. */
async function revokeGuardViolations(x, { creator, before, r }) {
  const v = [];
  if (r.status !== 200) v.push(`answer ${said(r)} (200 required: the revocation itself is unchanged)`);
  const stored = await platform.getPlatformStore(x.config).read(platform.Categories.MACHINE_IDENTITY, before.identityId);
  const revokedAt = stored ? stored.revokedAt : null;
  if (!stored || stored.status !== "REVOKED" || typeof revokedAt !== "string" || Number.isNaN(Date.parse(revokedAt)) ||
      !util.isDeepStrictEqual(stored, { ...before, status: "REVOKED", revokedAt, updatedAt: revokedAt })) {
    v.push(`durable record ${JSON.stringify(stored)} (the pre-revoke record with status REVOKED and revokedAt = updatedAt, every other field unchanged, required)`);
  }
  if (r.status === 200 && stored && !util.isDeepStrictEqual(r.body, { identity: mi.presentIdentity(stored) })) {
    v.push(`response body ${JSON.stringify(r.body)} (exactly { identity: presentIdentity(durable record) } required)`);
  }
  const events = await x.eventsFor("identity.revoked", before.identityId);
  if (events.length !== 1) v.push(`${events.length} identity.revoked events for the identity (exactly 1 required)`);
  for (const e of events) if (e.orgId !== null) v.push(`the identity.revoked event carries the stored orgId ${JSON.stringify(e.orgId)} (omitted required: the revoker does not own a live organization of that id)`);
  const ids = new Set(events.map((e) => e.eventId));
  const deliveries = await x.deliver();
  for (const who of WHO) {
    const seen = (await x.seen(who, "identity.revoked")).filter((e) => ids.has(e.eventId));
    const hook = deliveries[who].webhook.filter((d) => d.type === "identity.revoked" && ids.has(d.eventId));
    const note = deliveries[who].notification.filter((d) => d.type === "identity.revoked" && ids.has(d.eventId));
    if (who === creator) {
      if (!seen.length) v.push(`the creator (${ROLE[who]}) does not see its own identity.revoked in GET /events`);
      if (!hook.length) v.push(`the creator's (${ROLE[who]}) webhook endpoint did not receive identity.revoked`);
      if (!note.length) v.push(`the creator's (${ROLE[who]}) notification rule did not fire for identity.revoked`);
    } else {
      for (const e of seen) v.push(`${ROLE[who]} sees identity.revoked in GET /events (orgId ${JSON.stringify(e.orgId)})`);
      if (hook.length) v.push(`${ROLE[who]}'s webhook endpoint received identity.revoked`);
      if (note.length) v.push(`${ROLE[who]}'s notification rule fired for identity.revoked`);
    }
  }
  return v;
}

const PG_SKIP =PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  /* PA-R1-01 C6: each leg reports the backend it actually ran on (asserted in fresh()) and the C4 exclusion. */
  const r11 = (name, fn, opts = {}) => test(`RC45 R1-11 ${backend}: ${name}`, { skip }, async (t) => {
    const x = await fresh(backend, opts);
    t.diagnostic(`R1-11 backend ${backend}: store=${x.backendKinds.store} platform=${x.backendKinds.platform} events=${x.backendKinds.events} tenancyEnforced=${x.config.tenancyEnforced}; nothing-written comparisons exclude exactly ${EXCLUDED_WRITE}`);
    try { await fn(x); } finally { await release(x); }
  });

  /* ---------------- RED legs: create (PA-R1-01 mechanism §1) ---------------- */
  r11("a FOREIGN wallet naming another tenant's organization id gets 404 ORG_NOT_FOUND; no identity, credential, event, webhook or notification is written, and neither the organization's owner nor its member sees identity.created [RED on 40f3a26]", async (x) => {
    const before = await x.durable();
    const r = await x.call("POST", ["identities"], { label: INJECTED_LABEL, scopes: ["read:vaults"], orgId: x.orgId }, x.cookie.foreign);
    const wrote = wroteBetween(before, await x.durable());
    const deliveries = await x.deliver();
    const violations = [];
    if (!(r.status === 404 && r.code === "ORG_NOT_FOUND")) violations.push(`answer ${said(r)} (404 ORG_NOT_FOUND required)`);
    if (wrote.length) violations.push(`durable writes: ${wrote.join(", ")}`);
    const identityId = r.body && r.body.identity ? r.body.identity.identityId : null;
    for (const who of ["owner", "member"]) {
      const seen = await x.seen(who, "identity.created");
      for (const e of seen) violations.push(`the organization ${who} sees identity.created in GET /events (orgId ${e.orgId}, label ${JSON.stringify(e.data.label)}, creatorXOnly ${String(e.data.creatorXOnly).slice(0, 8)}…${identityId && e.correlation.identityId === identityId ? ", the foreign wallet's identity" : ""})`);
      for (const d of deliveries[who].webhook) violations.push(`the organization ${who}'s webhook endpoint received ${d.type} (orgId ${d.orgId})`);
      for (const d of deliveries[who].notification) violations.push(`the organization ${who}'s notification rule fired for ${d.type} (orgId ${d.orgId})`);
    }
    /* Non-oracle: the foreign organization's answer is exactly a missing organization's answer (asked last, so its
     * own effects cannot reach the observations above). */
    const missing = await x.call("POST", ["identities"], { label: INJECTED_LABEL, scopes: ["read:vaults"], orgId: crypto.randomUUID() }, x.cookie.foreign);
    if (said(r) !== said(missing)) violations.push(`the foreign organization's answer (${said(r)}) differs from a missing organization's (${said(missing)})`);
    assert.deepEqual(violations, [], "PA-R1-01 §1: a foreign organization id is the non-oracle 404 ORG_NOT_FOUND, checked before createIdentity and before any event; knowing the id confers nothing");
  });

  r11("a well-formed organization id that does not exist gets 404 ORG_NOT_FOUND with nothing written [RED on 40f3a26]", async (x) => {
    const missing = crypto.randomUUID();
    const before = await x.durable();
    const r = await x.call("POST", ["identities"], { label: INJECTED_LABEL, scopes: ["read:vaults"], orgId: missing }, x.cookie.foreign);
    const wrote = wroteBetween(before, await x.durable());
    const violations = [];
    if (!(r.status === 404 && r.code === "ORG_NOT_FOUND")) violations.push(`answer ${said(r)} (404 ORG_NOT_FOUND required)`);
    if (wrote.length) violations.push(`durable writes: ${wrote.join(", ")}`);
    assert.deepEqual(violations, [], "PA-R1-01 §1: a missing organization is 404 ORG_NOT_FOUND with no identity, credential, event or notification written");
  });

  r11("malformed organization ids (not a UUID as requireOrgId defines it: free text, the empty string, a number, the upper-cased and the over-long spelling of a real id) get 422 ORG_ID_INVALID with nothing written [RED on 40f3a26]", async (x) => {
    const violations = [];
    for (const orgId of ["not-a-uuid", "", 12345, x.orgId.toUpperCase(), `${x.orgId}0`]) {
      const before = await x.durable();
      const r = await x.call("POST", ["identities"], { label: INJECTED_LABEL, scopes: ["read:vaults"], orgId }, x.cookie.foreign);
      const wrote = wroteBetween(before, await x.durable());
      if (!(r.status === 422 && r.code === "ORG_ID_INVALID")) violations.push(`orgId ${JSON.stringify(orgId)}: answer ${said(r)} (422 ORG_ID_INVALID required)`);
      if (wrote.length) violations.push(`orgId ${JSON.stringify(orgId)}: durable writes: ${wrote.join(", ")}`);
    }
    assert.deepEqual(violations, [], "PA-R1-01 §1: a malformed organization id is 422 ORG_ID_INVALID (the organization routes' mapping) with nothing written");
  });

  r11("an organization MEMBER who is not the owner gets 403 ORG_FORBIDDEN with nothing written [RED on 40f3a26]", async (x) => {
    const before = await x.durable();
    const r = await x.call("POST", ["identities"], { label: "R1-11 TEST member label", scopes: ["read:vaults"], orgId: x.orgId }, x.cookie.member);
    const wrote = wroteBetween(before, await x.durable());
    const violations = [];
    if (!(r.status === 403 && r.code === "ORG_FORBIDDEN")) violations.push(`answer ${said(r)} (403 ORG_FORBIDDEN required)`);
    if (wrote.length) violations.push(`durable writes: ${wrote.join(", ")}`);
    assert.deepEqual(violations, [], "PA-R1-01 §1: attaching an identity to an organization is an owner action (requireOrgAccess(..., \"owner\")); a READ member gets 403 ORG_FORBIDDEN");
  });

  /* ---------------- RED leg: revoke (PA-R1-01 mechanism §2) ---------------- */
  r11("revoking a PRE-FIX identity seeded with a FOREIGN orgId: identity.revoked reaches none of the foreign organization's readers (GET /events, webhooks, notifications) and stays visible to its creator [RED on 40f3a26]", async (x) => {
    const seeded = await x.seedPreFixIdentity("foreign", x.orgId);
    const r = await x.call("POST", ["identities", seeded.identityId, "revoke"], {}, x.cookie.foreign);
    assert.equal(r.status, 200, `the creator's revocation itself is unchanged (${said(r)})`);
    assert.equal(r.body.identity.status, "REVOKED");
    const deliveries = await x.deliver();
    const violations = await orgReaderLeaks(x, "identity.revoked", seeded.identityId, deliveries);
    const events = await x.eventsFor("identity.revoked", seeded.identityId);
    if (events.length !== 1) violations.push(`${events.length} identity.revoked events for the identity (exactly 1 required)`);
    const eventIds = new Set(events.map((e) => e.eventId));
    if (!(await x.seen("foreign", "identity.revoked")).some((e) => eventIds.has(e.eventId))) violations.push("the creator does not see its own identity.revoked in GET /events");
    if (!deliveries.foreign.webhook.some((d) => d.type === "identity.revoked" && eventIds.has(d.eventId))) violations.push("the creator's webhook endpoint did not receive identity.revoked");
    if (!deliveries.foreign.notification.some((d) => d.type === "identity.revoked" && eventIds.has(d.eventId))) violations.push("the creator's notification rule did not fire for identity.revoked");
    for (const e of events) if (e.orgId !== null) violations.push(`the identity.revoked event carries the stored foreign orgId ${e.orgId} (omitted required: the revoker does not own that organization)`);
    assert.deepEqual(violations, [], "PA-R1-01 §2: identity.revoked carries the stored orgId only for a revoker that owns the organization; otherwise creator-only visibility");
  });

  /* ---------------- C1 revoke guard (PA-R1-01 revision 1, condition C1 legs (a), (b), (c)) ---------------- */
  r11("C1 revoke guard (a): revoking an identity whose stored orgId is NULL answers 200 with the durable REVOKED record and response body exactly as today; identity.revoked (no orgId) reaches its creator through GET /events, its webhook and its notification rule, and no organization reader", async (x) => {
    const created = await x.call("POST", ["identities"], { label: "R1-11 TEST untagged", scopes: ["read:vaults"] }, x.cookie.foreign);
    assert.equal(created.status, 201, said(created));
    const before = await platform.getPlatformStore(x.config).read(platform.Categories.MACHINE_IDENTITY, created.body.identity.identityId);
    assert.equal(before.orgId, null, "the stored orgId is null");
    const r = await x.call("POST", ["identities", before.identityId, "revoke"], {}, x.cookie.foreign);
    const violations = await revokeGuardViolations(x, { creator: "foreign", before, r });
    assert.deepEqual(violations, [], "PA-R1-01 C1(a): a null stored orgId: 200, REVOKED and the body exactly as today; identity.revoked without orgId, creator-only");
  });

  for (const [what, storedOrgId] of [["the MALFORMED stored orgId \"not-a-uuid\"", "not-a-uuid"], ["the EMPTY stored orgId \"\"", ""]]) {
    r11(`C1 revoke guard (b): revoking a PRE-FIX identity seeded directly in the store with ${what} answers 200 with the durable REVOKED record and response body exactly as today; identity.revoked carries no orgId and reaches its creator through GET /events, its webhook and its notification rule, and no organization reader [RED on 40f3a26]`, async (x) => {
      const before = await x.seedPreFixIdentity("foreign", storedOrgId);
      assert.equal((await platform.getPlatformStore(x.config).read(platform.Categories.MACHINE_IDENTITY, before.identityId)).orgId, storedOrgId, "the seeded orgId is stored verbatim");
      const r = await x.call("POST", ["identities", before.identityId, "revoke"], {}, x.cookie.foreign);
      const violations = await revokeGuardViolations(x, { creator: "foreign", before, r });
      assert.deepEqual(violations, [], `PA-R1-01 C1(b): ${what} (not a UUID as requireOrgId defines it): the guard never throws, orgId is omitted, creator-only visibility`);
    });
  }

  r11("C1 revoke guard (c): the organization OWNER revoking its own organization-tagged identity AFTER deleting that organization (POST /organizations/:id/delete) answers 200 with the durable REVOKED record and response body exactly as today; identity.revoked carries no orgId and reaches the owner as its creator through GET /events, its webhook and its notification rule, and neither the former member nor the foreign wallet [RED on 40f3a26]", async (x) => {
    const created = await x.call("POST", ["identities"], { label: "R1-11 TEST owner identity", scopes: ["read:vaults"], orgId: x.orgId }, x.cookie.owner);
    assert.equal(created.status, 201, said(created));
    const current = await x.call("GET", ["organizations", x.orgId], null, x.cookie.owner);
    assert.equal(current.status, 200, said(current));
    const del = await x.call("POST", ["organizations", x.orgId, "delete"], { expectedVersion: current.body.organization.version }, x.cookie.owner);
    assert.equal(del.status, 200, `the owner deletes the organization through the existing route (${said(del)})`);
    assert.equal(del.body.deleted, true);
    assert.equal(await storeMod.getStore(x.config).read(storeMod.Categories.ORG, x.orgId), null, "the organization record is gone from the store");
    assert.equal((await x.call("GET", ["organizations", x.orgId], null, x.cookie.owner)).code, "ORG_NOT_FOUND", "the deleted organization answers 404 ORG_NOT_FOUND");
    const before = await platform.getPlatformStore(x.config).read(platform.Categories.MACHINE_IDENTITY, created.body.identity.identityId);
    assert.equal(before.orgId, x.orgId, "the identity still carries the deleted organization's id");
    const r = await x.call("POST", ["identities", before.identityId, "revoke"], {}, x.cookie.owner);
    const violations = await revokeGuardViolations(x, { creator: "owner", before, r });
    assert.deepEqual(violations, [], "PA-R1-01 C1(c): an organization that no longer exists: the guard never throws, orgId is omitted, creator-only visibility");
  });

  /* ---------------- HOLDS ---------------- */
  r11("the organization OWNER naming its own organization gets 201: identity and first credential created with the orgId, and the owner and the member (not the foreign wallet) see identity.created in GET /events, webhooks and notifications", async (x) => {
    const r = await x.call("POST", ["identities"], { label: "R1-11 TEST owner identity", scopes: ["read:vaults"], orgId: x.orgId }, x.cookie.owner);
    assert.equal(r.status, 201, said(r));
    const identityId = r.body.identity.identityId;
    assert.equal(r.body.identity.orgId, x.orgId);
    assert.equal(r.body.identity.creatorXOnly, x.w.owner.xonly);
    assert.match(r.body.credential.token, /^pvmk_[0-9a-f]{64}$/);
    const ps = platform.getPlatformStore(x.config);
    const stored = await ps.read(platform.Categories.MACHINE_IDENTITY, identityId);
    assert.equal(stored.orgId, x.orgId);
    assert.equal(stored.status, "ACTIVE");
    const creds = (await ps.listValues(platform.Categories.MACHINE_CREDENTIAL)).filter((c) => c.identityId === identityId);
    assert.equal(creds.length, 1, "the first credential is created");
    assert.equal(creds[0].status, "ACTIVE");
    const events = await x.eventsFor("identity.created", identityId);
    assert.equal(events.length, 1);
    assert.equal(events[0].orgId, x.orgId);
    const deliveries = await x.deliver();
    for (const who of ["owner", "member"]) {
      assert.ok((await x.seen(who, "identity.created")).some((e) => e.eventId === events[0].eventId), `the organization ${who} sees identity.created`);
      assert.ok(deliveries[who].webhook.some((d) => d.eventId === events[0].eventId), `the organization ${who}'s webhook endpoint receives identity.created`);
      assert.ok(deliveries[who].notification.some((d) => d.eventId === events[0].eventId), `the organization ${who}'s notification rule fires`);
    }
    assert.equal((await x.seen("foreign", "identity.created")).length, 0, "the foreign wallet sees nothing of the organization");
    assert.deepEqual(deliveries.foreign, { webhook: [], notification: [] });
  });

  r11("a request WITHOUT orgId (absent, or null) gets 201 unchanged: orgId null, identity.created visible to its creator only", async (x) => {
    for (const body of [{ label: "R1-11 TEST untagged", scopes: ["read:vaults"] }, { label: "R1-11 TEST null-tagged", scopes: ["read:vaults"], orgId: null }]) {
      const r = await x.call("POST", ["identities"], body, x.cookie.foreign);
      assert.equal(r.status, 201, said(r));
      assert.equal(r.body.identity.orgId, null);
      const events = await x.eventsFor("identity.created", r.body.identity.identityId);
      assert.equal(events.length, 1);
      assert.equal(events[0].orgId, null);
      assert.ok((await x.seen("foreign", "identity.created")).some((e) => e.eventId === events[0].eventId), "the creator sees its identity.created");
    }
    const deliveries = await x.deliver();
    assert.equal(deliveries.foreign.webhook.length, 2);
    assert.equal(deliveries.foreign.notification.length, 2);
    for (const who of ["owner", "member"]) {
      assert.equal((await x.seen(who, "identity.created")).length, 0, `the organization ${who} sees nothing`);
      assert.deepEqual(deliveries[who], { webhook: [], notification: [] });
    }
  });

  r11("the owner's revoke of its own organization-tagged identity still carries orgId: the owner and the member see identity.revoked", async (x) => {
    const created = await x.call("POST", ["identities"], { label: "R1-11 TEST owner identity", scopes: ["read:vaults"], orgId: x.orgId }, x.cookie.owner);
    assert.equal(created.status, 201, said(created));
    const identityId = created.body.identity.identityId;
    const r = await x.call("POST", ["identities", identityId, "revoke"], {}, x.cookie.owner);
    assert.equal(r.status, 200, said(r));
    assert.equal(r.body.identity.status, "REVOKED");
    assert.equal(r.body.identity.orgId, x.orgId);
    const events = await x.eventsFor("identity.revoked", identityId);
    assert.equal(events.length, 1);
    assert.equal(events[0].orgId, x.orgId, "identity.revoked carries the stored orgId for the organization owner");
    const deliveries = await x.deliver();
    for (const who of ["owner", "member"]) {
      assert.ok((await x.seen(who, "identity.revoked")).some((e) => e.eventId === events[0].eventId), `the organization ${who} sees identity.revoked`);
      assert.ok(deliveries[who].webhook.some((d) => d.eventId === events[0].eventId), `the organization ${who}'s webhook endpoint receives identity.revoked`);
      assert.ok(deliveries[who].notification.some((d) => d.eventId === events[0].eventId), `the organization ${who}'s notification rule fires`);
    }
    assert.equal((await x.seen("foreign", "identity.revoked")).length, 0);
  });

  r11("revocation stays creator-scoped (PA-R1-01 §2): the organization owner and member cannot revoke a foreign creator's pre-fix identity tagged with their organization (404 MACHINE_IDENTITY_NOT_FOUND, nothing written)", async (x) => {
    const seeded = await x.seedPreFixIdentity("foreign", x.orgId);
    for (const who of ["owner", "member"]) {
      const before = await x.durable();
      const r = await x.call("POST", ["identities", seeded.identityId, "revoke"], {}, x.cookie[who]);
      assert.equal(r.status, 404, said(r));
      assert.equal(r.code, "MACHINE_IDENTITY_NOT_FOUND");
      assert.deepEqual(wroteBetween(before, await x.durable()), [], `nothing written for the organization ${who}`);
    }
  });

  r11("SELF-HOSTED (tenancy not enforced) is unchanged: POST /identities, with or without an organization's id, and POST /identities/:id/revoke answer 404 AUTH_DISABLED with nothing written", async (x) => {
    const org = await x.call("POST", ["organizations"], { name: "R1-11 TEST self-hosted organization" });
    assert.equal(org.status, 201, said(org));
    const orgId = org.body.organization.orgId;
    for (const [segments, body] of [
      [["identities"], { label: "R1-11 TEST", scopes: ["read:vaults"], orgId }],
      [["identities"], { label: "R1-11 TEST", scopes: ["read:vaults"], orgId: crypto.randomUUID() }],
      [["identities"], { label: "R1-11 TEST", scopes: ["read:vaults"] }],
      [["identities", crypto.randomUUID(), "revoke"], {}]
    ]) {
      const before = await x.durable();
      const r = await x.call("POST", segments, body);
      assert.equal(r.status, 404, said(r));
      assert.equal(r.code, "AUTH_DISABLED");
      assert.deepEqual(wroteBetween(before, await x.durable()), [], `nothing written for ${segments.join("/")}`);
    }
  }, { hosted: false });
}
