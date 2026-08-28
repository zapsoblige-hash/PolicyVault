"use strict";

/*
 * HUMAN NOTIFICATION RULES (fullscale surface 19; docs/postlaunch/
 * notifications-spec.md; migration server/migrations/009_notifications.sql).
 *
 * A notification rule is a per-tenant COORDINATION record: "when an event
 * my wallet could already read appears in the durable outbox, tell a
 * human through this channel." Notifications are OBSERVATION, never
 * authority (the delivered payload carries events.js NOTIFICATION_NOTICE
 * verbatim); the delivery worker (server/src/notify-delivery.js) is a
 * SECOND consumer of the SAME platform_events outbox with its own
 * per-rule cursors — there is deliberately no second emission path, and a
 * total notification outage can never affect request processing, events,
 * or webhooks.
 *
 * TENANCY: rules inherit from creatorXOnly exactly like webhook endpoints
 * and machine identities — the worker delivers ONLY events
 * events.js eventVisibleTo grants the creating wallet, so a rule can
 * never widen what its creator could already read; filters (eventTypes /
 * vaultId / orgId) only narrow. Foreign rules 404 (existence hidden).
 *
 * CLOSED FILTER over the EXISTING event catalog (events.js EVENT_TYPES —
 * no new event semantics here). notification.* types are UNSUBSCRIBABLE
 * (refused at creation; excluded from "*" expansion by the worker): a
 * notification-health event can never fan out into more notifications —
 * the structural no-feedback-loop rule.
 *
 * CHANNELS (closed set; providers live in notify-delivery.js):
 *   console — always available; structured operator log line.
 *   webhook — generic bridge to a provider's inbound webhook (Slack/
 *             Mattermost/ntfy/...). REUSES the surface-18 machinery:
 *             URL validation (webhooks.validateEndpointUrl), the sealed
 *             secret envelope (webhooks.sealSecret/openSecret), pv1 HMAC
 *             signing (events-signing) when a secret is configured, and
 *             the hardened outbound transport (events-delivery
 *             httpPostJson: SSRF/rebinding pin, https-only with the same
 *             explicit localhost dev override, timeouts, response
 *             discarded). Nothing is duplicated.
 *   smtp    — a SPECIFIED pluggable provider seam (spec §7): config shape
 *             validated here, but rule creation REFUSES unless an SMTP
 *             provider has been explicitly registered
 *             (registerChannelProvider) — dependency-free robust SMTP is
 *             not shipped in this build, and an unconfigured channel
 *             fails safe/honest instead of pretending to deliver.
 *
 * Every rule mutation writes a chained audit record (kind
 * "notification"), and rule changes never emit platform events themselves
 * (the bounded notification.rule.failing/disabled health events are the
 * worker's transition signals — see events.js).
 */

const crypto = require("crypto");
const { Categories, getEventsStore } = require("./events-store");
const { EVENT_TYPES } = require("./events");
const { validateEndpointUrl, sealSecret } = require("./webhooks");
const { appendAudit } = require("./audit");

const RULE_SCHEMA = "policyvault-notification-rule/v1";
const MAX_RULES_PER_WALLET = 20;
const MAX_LABEL_LEN = 128;
const MAX_SECRET_LEN = 200;
const MIN_SECRET_LEN = 8;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,24}$/;

function fail(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/* ------------------------------------------------------------------ */
/* Channel registry (the pluggable provider seam)                      */
/* ------------------------------------------------------------------ */

const BUILT_IN_CHANNEL_TYPES = Object.freeze(["console", "webhook"]);
const pluggableChannelTypes = new Set();

/* Declare that a provider implementation exists for `type` (the worker
 * receives the implementation via its own options.providers). Explicit,
 * deliberate registration only — never inferred. */
function registerChannelProvider(type) {
  if (type !== "smtp") throw fail(500, "NOTIFY_CHANNEL_UNKNOWN", `channel type ${JSON.stringify(type)} is not a specified pluggable channel`);
  pluggableChannelTypes.add(type);
}

function unregisterChannelProvider(type) {
  pluggableChannelTypes.delete(type);
}

function availableChannelTypes() {
  return [...BUILT_IN_CHANNEL_TYPES, ...pluggableChannelTypes];
}

/* ------------------------------------------------------------------ */
/* Validation                                                          */
/* ------------------------------------------------------------------ */

function subscribableEventTypes() {
  return Object.keys(EVENT_TYPES).filter((t) => !t.startsWith("notification."));
}

/* ["*"] or a non-empty subset of the closed catalog EXCLUDING
 * notification.* (the structural no-loop rule). Unknown types refuse. */
function normalizeNotifyEventTypes(eventTypes) {
  if (eventTypes === undefined || eventTypes === null) return ["*"];
  if (!Array.isArray(eventTypes) || eventTypes.length === 0) {
    throw fail(422, "NOTIFY_EVENT_TYPES_INVALID", "eventTypes must be a non-empty array (or omitted for all subscribable events)");
  }
  if (eventTypes.length === 1 && eventTypes[0] === "*") return ["*"];
  const out = [];
  const seen = new Set();
  for (const t of eventTypes) {
    if (typeof t !== "string" || !EVENT_TYPES[t]) {
      throw fail(422, "NOTIFY_EVENT_TYPE_UNKNOWN", `event type ${JSON.stringify(t)} is not in the closed catalog — unknown types fail closed`);
    }
    if (t.startsWith("notification.")) {
      throw fail(422, "NOTIFY_EVENT_TYPE_SELF_REFERENTIAL", "notification.* events are unsubscribable by notification rules (no-feedback-loop rule)");
    }
    if (!seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out.sort();
}

function normalizeLabel(label) {
  if (label === undefined || label === null) return "";
  if (typeof label !== "string" || label.length > MAX_LABEL_LEN) {
    throw fail(422, "NOTIFY_LABEL_INVALID", `label must be a string of at most ${MAX_LABEL_LEN} characters`);
  }
  return label;
}

function normalizeScopeFilter(raw, name, re, code) {
  if (raw === undefined || raw === null || raw === "") return null;
  if (typeof raw !== "string" || !re.test(raw)) throw fail(422, code, `${name} filter is malformed`);
  return name === "orgId" ? raw : raw.toLowerCase();
}

/*
 * Validate + normalize one channel config. Returns the STORED form (the
 * only place a secret envelope may appear). Unknown channel types and
 * channels without a registered provider both fail closed.
 */
function normalizeChannel(config, raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw fail(422, "NOTIFY_CHANNEL_INVALID", "channel must be an object { type, ... }");
  }
  const type = raw.type;
  if (type === "console") {
    return { type: "console" };
  }
  if (type === "webhook") {
    const url = validateEndpointUrl(config, raw.url); // https-only (+ explicit localhost dev override); SSRF pinning re-checks at delivery
    let template = raw.template === undefined || raw.template === null ? "json" : raw.template;
    if (template !== "json" && template !== "text") {
      throw fail(422, "NOTIFY_TEMPLATE_INVALID", 'webhook template must be "json" (full structured payload) or "text" ({ text } provider line)');
    }
    let secret = null;
    if (raw.secret !== undefined && raw.secret !== null && raw.secret !== "") {
      if (typeof raw.secret !== "string" || raw.secret.length < MIN_SECRET_LEN || raw.secret.length > MAX_SECRET_LEN) {
        throw fail(422, "NOTIFY_SECRET_INVALID", `channel secret must be a string of ${MIN_SECRET_LEN}..${MAX_SECRET_LEN} characters`);
      }
      secret = sealSecret(raw.secret); // same envelope discipline as webhook endpoints
    }
    return { type: "webhook", url, template, secret };
  }
  if (type === "smtp") {
    if (!pluggableChannelTypes.has("smtp")) {
      throw fail(
        422,
        "NOTIFY_CHANNEL_UNAVAILABLE",
        "the smtp channel is a specified pluggable provider seam and no SMTP provider is registered in this deployment — see docs/postlaunch/notifications-spec.md §7 (console and webhook channels are available)"
      );
    }
    if (typeof raw.to !== "string" || !EMAIL_RE.test(raw.to)) throw fail(422, "NOTIFY_RECIPIENT_INVALID", "smtp channel requires a valid `to` address");
    const out = { type: "smtp", to: raw.to };
    if (raw.from !== undefined && raw.from !== null && raw.from !== "") {
      if (typeof raw.from !== "string" || !EMAIL_RE.test(raw.from)) throw fail(422, "NOTIFY_RECIPIENT_INVALID", "smtp `from` must be a valid address");
      out.from = raw.from;
    }
    if (raw.subjectPrefix !== undefined && raw.subjectPrefix !== null && raw.subjectPrefix !== "") {
      if (typeof raw.subjectPrefix !== "string" || raw.subjectPrefix.length > 64) throw fail(422, "NOTIFY_CHANNEL_INVALID", "subjectPrefix must be at most 64 characters");
      out.subjectPrefix = raw.subjectPrefix;
    }
    return out;
  }
  throw fail(422, "NOTIFY_CHANNEL_UNKNOWN", `unknown channel type ${JSON.stringify(type)} — supported: ${availableChannelTypes().join(", ")} (closed set, deny by default)`);
}

/* ------------------------------------------------------------------ */
/* Audit helper (every rule mutation leaves a chained audit line)      */
/* ------------------------------------------------------------------ */

async function auditRuleChange(config, { action, rule, actorXOnly, detail }) {
  await appendAudit(config, {
    kind: "notification",
    action,
    ruleId: rule.ruleId,
    ...(rule.vaultId ? { vaultId: rule.vaultId } : {}),
    ...(rule.orgId ? { orgId: rule.orgId } : {}),
    actorXOnly: actorXOnly ?? null,
    result: "OK",
    detail
  });
}

/* ------------------------------------------------------------------ */
/* CRUD                                                                */
/* ------------------------------------------------------------------ */

async function createRule(config, { creatorXOnly, label, eventTypes, vaultId, orgId, channel }) {
  if (creatorXOnly !== null && (typeof creatorXOnly !== "string" || !/^[0-9a-f]{64}$/.test(creatorXOnly))) {
    throw fail(500, "NOTIFY_INTERNAL", "internal: creatorXOnly must be resolved by the caller — failing closed");
  }
  const store = getEventsStore(config);
  const mine = (await store.listValues(Categories.NOTIFY_RULE)).filter((r) => r && r.creatorXOnly === creatorXOnly && r.status !== "DELETED");
  if (mine.length >= MAX_RULES_PER_WALLET) {
    throw fail(429, "NOTIFY_QUOTA_EXCEEDED", `this wallet already has ${mine.length} notification rules (limit ${MAX_RULES_PER_WALLET})`);
  }
  const rule = {
    schema: RULE_SCHEMA,
    ruleId: crypto.randomUUID(),
    networkId: config.networkId,
    creatorXOnly,
    label: normalizeLabel(label),
    eventTypes: normalizeNotifyEventTypes(eventTypes),
    vaultId: normalizeScopeFilter(vaultId, "vaultId", /^[0-9a-fA-F]{64}$/, "NOTIFY_VAULT_FILTER_INVALID"),
    orgId: normalizeScopeFilter(orgId, "orgId", /^[\x21-\x7e]{1,128}$/, "NOTIFY_ORG_FILTER_INVALID"),
    channel: normalizeChannel(config, channel),
    status: "ACTIVE",
    disabledReason: null,
    // New rules start at the CURRENT stream head: subscribing never
    // floods a human with the full history (polling serves history).
    initialCursor: await store.latestCursor(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  const created = await store.createExclusive(Categories.NOTIFY_RULE, rule.ruleId, rule);
  if (!created) throw fail(500, "NOTIFY_MINT_COLLISION", "internal: rule id collision — retry the request");
  await auditRuleChange(config, { action: "notification_rule_created", rule, actorXOnly: creatorXOnly, detail: `${rule.channel.type} channel; types ${rule.eventTypes.join(",")}` });
  return rule;
}

async function loadRuleRaw(config, ruleId) {
  if (typeof ruleId !== "string" || !UUID_RE.test(ruleId)) return null;
  return getEventsStore(config).read(Categories.NOTIFY_RULE, ruleId);
}

/* 404 hides foreign rules (tenancy.js existence-hiding discipline). */
async function requireOwnedRule(config, ruleId, creatorXOnly) {
  const rule = await loadRuleRaw(config, ruleId);
  if (!rule || rule.creatorXOnly !== creatorXOnly) {
    throw fail(404, "NOTIFY_RULE_NOT_FOUND", "no such notification rule");
  }
  return rule;
}

async function listRulesForCreator(config, creatorXOnly) {
  const all = await getEventsStore(config).listValues(Categories.NOTIFY_RULE);
  return all.filter((r) => r && r.creatorXOnly === creatorXOnly);
}

async function listActiveRules(config) {
  const all = await getEventsStore(config).listValues(Categories.NOTIFY_RULE);
  return all.filter((r) => r && r.schema === RULE_SCHEMA && r.status === "ACTIVE" && r.networkId === config.networkId);
}

/* Disable = unsubscribe (per-rule off switch). Deliveries stop at the
 * next worker scan; the rule and its counters remain inspectable. */
async function disableRule(config, { ruleId, creatorXOnly, reason = "OPERATOR" }) {
  const rule = await requireOwnedRule(config, ruleId, creatorXOnly);
  if (rule.status !== "DISABLED") {
    rule.status = "DISABLED";
    rule.disabledReason = reason;
    rule.updatedAt = new Date().toISOString();
    await getEventsStore(config).write(Categories.NOTIFY_RULE, rule.ruleId, rule);
    await auditRuleChange(config, { action: "notification_rule_disabled", rule, actorXOnly: creatorXOnly, detail: `reason ${reason}` });
  }
  return rule;
}

/* Re-enable. The cursor jumps to the CURRENT head (a rule disabled for a
 * month must not flood its human with the backlog — history stays
 * available via GET /events polling); failure tracking resets. */
async function enableRule(config, { ruleId, creatorXOnly }) {
  const rule = await requireOwnedRule(config, ruleId, creatorXOnly);
  if (rule.status !== "ACTIVE") {
    const store = getEventsStore(config);
    rule.status = "ACTIVE";
    rule.disabledReason = null;
    rule.updatedAt = new Date().toISOString();
    await store.write(Categories.NOTIFY_RULE, rule.ruleId, rule);
    const state = await store.read(Categories.NOTIFY_STATE, rule.ruleId);
    if (state) {
      state.cursor = await store.latestCursor();
      state.pending = null;
      state.consecutiveFailures = 0;
      state.failingNotified = false;
      await store.write(Categories.NOTIFY_STATE, rule.ruleId, state);
    }
    await auditRuleChange(config, { action: "notification_rule_enabled", rule, actorXOnly: creatorXOnly, detail: "re-enabled; cursor moved to stream head" });
  }
  return rule;
}

/* AUTO-disable from the delivery worker after sustained failure (bounded
 * transition; see notify-delivery.js). No tenancy check — the worker acts
 * on the stored rule itself. */
async function autoDisableRule(config, rule) {
  const fresh = (await loadRuleRaw(config, rule.ruleId)) ?? rule;
  if (fresh.status === "ACTIVE") {
    fresh.status = "DISABLED";
    fresh.disabledReason = "AUTO_FAILURE";
    fresh.updatedAt = new Date().toISOString();
    await getEventsStore(config).write(Categories.NOTIFY_RULE, fresh.ruleId, fresh);
    await auditRuleChange(config, { action: "notification_rule_disabled", rule: fresh, actorXOnly: null, detail: "reason AUTO_FAILURE (sustained delivery failure)" });
  }
  return fresh;
}

async function deleteRule(config, { ruleId, creatorXOnly }) {
  const rule = await requireOwnedRule(config, ruleId, creatorXOnly);
  const store = getEventsStore(config);
  await store.remove(Categories.NOTIFY_RULE, rule.ruleId);
  await store.remove(Categories.NOTIFY_STATE, rule.ruleId);
  await auditRuleChange(config, { action: "notification_rule_deleted", rule, actorXOnly: creatorXOnly, detail: `${rule.channel.type} channel removed` });
  return rule;
}

/* ------------------------------------------------------------------ */
/* Presentation — NEVER a secret envelope                              */
/* ------------------------------------------------------------------ */

function presentChannel(channel) {
  if (!channel || typeof channel !== "object") return null;
  if (channel.type === "webhook") {
    return { type: "webhook", url: channel.url, template: channel.template, hasSecret: Boolean(channel.secret) };
  }
  if (channel.type === "smtp") {
    return { type: "smtp", to: channel.to, ...(channel.from ? { from: channel.from } : {}), ...(channel.subjectPrefix ? { subjectPrefix: channel.subjectPrefix } : {}) };
  }
  return { type: channel.type };
}

function presentRule(rule) {
  const { schema, ruleId, networkId, creatorXOnly, label, eventTypes, vaultId, orgId, status, disabledReason, initialCursor, createdAt, updatedAt } = rule;
  return {
    schema,
    ruleId,
    networkId,
    creatorXOnly,
    label,
    eventTypes,
    vaultId,
    orgId,
    channel: presentChannel(rule.channel),
    status,
    disabledReason,
    initialCursor,
    createdAt,
    updatedAt
  };
}

module.exports = {
  RULE_SCHEMA,
  MAX_RULES_PER_WALLET,
  BUILT_IN_CHANNEL_TYPES,
  registerChannelProvider,
  unregisterChannelProvider,
  availableChannelTypes,
  subscribableEventTypes,
  normalizeNotifyEventTypes,
  normalizeChannel,
  createRule,
  loadRuleRaw,
  requireOwnedRule,
  listRulesForCreator,
  listActiveRules,
  disableRule,
  enableRule,
  autoDisableRule,
  deleteRule,
  presentChannel,
  presentRule
};
