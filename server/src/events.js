"use strict";

/*
 * Asynchronous platform events (completion-standard surface 18;
 * docs/postlaunch/webhooks-events-spec.md).
 *
 * EVENTS ARE OBSERVATION, NEVER AUTHORITY. Every event is a NOTIFICATION
 * that durable PolicyVault state changed; the truth about that state lives
 * at the API (and, for anything consensus-visible, at the Kaspa covenant).
 * The signed webhook payload carries that exact notice verbatim
 * (NOTIFICATION_NOTICE below) so no consumer can honestly mistake a
 * webhook body for authority.
 *
 * EMISSION IS FAILURE-ISOLATED BY CONTRACT: noteAuditRecord/
 * safeEmitPlatformEvent never throw. A broken event store loses the
 * NOTIFICATION, never the mutation or its audit line — the same
 * crash-window contract the audit stream itself has always documented
 * (sdk/src/store.js header). Delivery is a separate, fully decoupled
 * concern (server/src/events-delivery.js).
 *
 * CLOSED CATALOG, CLOSED PAYLOADS: every event type declares exactly which
 * data fields it carries; unknown types refuse at emission, and unmapped
 * audit records produce NO event (a new audit kind is never silently
 * published to external consumers). NO secrets, NO tokens, NO signatures,
 * NO preimages, NO key material beyond public identities that the API
 * already serves to the same tenant.
 */

const crypto = require("crypto");
const { getEventsStore } = require("./events-store");

const EVENT_SCHEMA = "policyvault-event/v1";
const EVENTS_PAGE_SCHEMA = "policyvault-events-page/v1";
const NOTIFICATION_NOTICE =
  "This event is a notification of durable PolicyVault state. It is not authority: verify current state via the PolicyVault API; Kaspa covenant consensus remains the only financial authority.";

/*
 * The closed event-type catalog. `data` lists the ONLY fields that type
 * may carry (emission drops everything else and never fails open).
 * Correlation ids (requestId/manifestHash/proposalId/riskEvaluationId/
 * txId/identityId) live in `correlation`, vaultId/orgId at the top level.
 */
const EVENT_TYPES = Object.freeze({
  // ---- wallet-request lifecycle (v0.4 family; spec §4.1) ----
  "request.built": ["action", "contractVersion", "state", "aboveThreshold", "signerRole"],
  "request.approval.collected": ["action", "collected", "required", "complete"],
  "request.finalized": ["action", "state"],
  // Submit success in this pipeline IS chain proof (txid verified, exact
  // successor observed) — there is deliberately NO "submitted but
  // unproven" success event; see spec §4.1 for the honest rationale.
  "request.confirmed": ["action", "state", "terminal"],
  "request.failed": ["action", "stage", "code"],
  "request.rejected": ["action", "state"],
  // ---- vault lifecycle ----
  "vault.created": ["contractVersion", "label"],
  "vault.reconciled": ["outcome", "to"],
  // ---- governance (spec §4.2) ----
  "governance.proposal.created": ["action", "classification"],
  "governance.proposal.approved": ["action"],
  "governance.proposal.cancelled": ["action"],
  "governance.proposal.consumed": ["action"],
  "governance.reduction.recorded": ["action"],
  // ---- risk pipeline (spec §4.3) ----
  "risk.evaluation.allowed": ["action", "decision"],
  "risk.hold.created": ["action", "decision"],
  "risk.evaluation.denied": ["action", "decision"],
  "risk.hold.released": ["action"],
  "risk.evaluation.consumed": ["action"],
  // ---- machine identities (spec §4.4; NEVER token/hash material) ----
  "identity.created": ["label", "scopes", "creatorXOnly"],
  "identity.revoked": ["label", "creatorXOnly"],
  "identity.credential.minted": ["credentialId", "creatorXOnly"],
  "identity.credential.revoked": ["credentialId", "creatorXOnly"],
  // ---- organization controls (flows through the audit hook) ----
  "org.controls.updated": ["summary"],
  // ---- hosted-layer agent suspensions (surface 21 residual; emitted
  // directly by the api.js route like the identity events). NOTIFICATION
  // of a COORDINATION control — never a covenant state change (the
  // payload's standing NOTIFICATION_NOTICE applies with full force). ----
  "vault.agent.suspended": ["agentPk", "allAgents", "byType"],
  "vault.agent.unsuspended": ["agentPk", "allAgents", "byType"],
  // ---- human-notification coordination health (surface 19; emitted by
  // server/src/notify-delivery.js on BOUNDED state TRANSITIONS only —
  // never per failed attempt). STRUCTURALLY LOOP-FREE: notification rules
  // can never subscribe to notification.* types (refused at rule
  // creation; excluded from a rule's "*" expansion), so a notification
  // failure can never fan out into more notifications. creatorXOnly is
  // the rule owner's public identity (visibility derivation below). ----
  "notification.rule.failing": ["ruleId", "channelType", "consecutiveFailures", "creatorXOnly"],
  "notification.rule.disabled": ["ruleId", "channelType", "reason", "creatorXOnly"]
});

const CORRELATION_FIELDS = Object.freeze(["requestId", "manifestHash", "proposalId", "riskEvaluationId", "txId", "identityId"]);
const MAX_STRING = 500;

class EventError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function boundedString(v) {
  if (typeof v === "string") return v.length > MAX_STRING ? `${v.slice(0, MAX_STRING - 1)}…` : v;
  if (typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) return v;
  if (Array.isArray(v)) return v.slice(0, 50).map(boundedString);
  return undefined; // objects/functions/bigints never pass through into payloads
}

/*
 * Build + validate the closed event envelope. Throws on an unknown type
 * (deny-by-default: a new event type must be added to the catalog — and
 * therefore to the spec — before anything can emit it).
 */
function buildEvent(config, { type, vaultId = null, orgId = null, correlation = {}, data = {}, occurredAt = null }) {
  const allowed = EVENT_TYPES[type];
  if (!allowed) throw new EventError("EVENT_TYPE_UNKNOWN", `event type ${JSON.stringify(type)} is not in the closed catalog — failing closed`);
  const outData = {};
  for (const field of allowed) {
    const v = boundedString(data[field]);
    if (v !== undefined) outData[field] = v;
  }
  const outCorr = {};
  for (const field of CORRELATION_FIELDS) {
    const v = correlation[field];
    if (typeof v === "string" && v.length > 0 && v.length <= MAX_STRING) outCorr[field] = v;
  }
  return {
    schemaVersion: EVENT_SCHEMA,
    eventId: crypto.randomUUID(),
    type,
    occurredAt: typeof occurredAt === "string" ? occurredAt : new Date().toISOString(),
    networkId: config.networkId,
    vaultId: typeof vaultId === "string" ? vaultId : null,
    orgId: typeof orgId === "string" ? orgId : null,
    correlation: outCorr,
    data: outData
  };
}

/* Emit (durably append) one platform event. THROWS on failure — use
 * safeEmitPlatformEvent from request paths. */
async function emitPlatformEvent(config, spec) {
  const event = buildEvent(config, spec);
  await getEventsStore(config).appendEvent(event);
  return event;
}

/* In-process count of emissions that failed and were dropped (surfaced by
 * eventStats; never a durable claim). */
let droppedEmissions = 0;

/*
 * The failure-isolated emitter for request paths: NEVER throws. A broken
 * event store must never fail the mutation it observes (binding addendum
 * rule: a webhook/event outage cannot affect core safety).
 */
async function safeEmitPlatformEvent(config, spec) {
  try {
    return await emitPlatformEvent(config, spec);
  } catch (error) {
    droppedEmissions += 1;
    try {
      console.error(`policyvault-events: dropped ${spec && spec.type ? spec.type : "event"} emission (${error.code || error.message})`);
    } catch {
      /* even logging must not throw */
    }
    return null;
  }
}

/*
 * Audit-record -> event derivation (the transactional-with-audit hook:
 * server/src/audit.js calls noteAuditRecord immediately after every audit
 * append that flows through the server audit module). CLOSED MAPPING:
 * anything unmapped yields null — an audit kind is never silently
 * published.
 */
function deriveEventFromAudit(config, record) {
  if (!record || typeof record !== "object") return null;
  const corr = {
    requestId: record.requestId,
    manifestHash: record.manifestHash,
    proposalId: record.proposalId,
    riskEvaluationId: record.riskEvaluationId,
    txId: record.txId
  };
  const base = { vaultId: record.vaultId ?? null, orgId: record.orgId ?? null, correlation: corr, occurredAt: record.at };

  if (record.kind === "governance") {
    const byResult = {
      GOVERNANCE_PROPOSAL_CREATED: "governance.proposal.created",
      GOVERNANCE_APPROVAL_COLLECTED: "governance.proposal.approved",
      GOVERNANCE_PROPOSAL_CANCELLED: "governance.proposal.cancelled",
      GOVERNANCE_ENFORCED: "governance.proposal.consumed",
      GOVERNANCE_REDUCTION: "governance.reduction.recorded"
    };
    const type = byResult[record.result];
    if (!type) return null;
    return buildEvent(config, { ...base, type, data: { action: record.action, classification: record.classification } });
  }
  if (record.kind === "risk") {
    const byResult = {
      RISK_ALLOW: "risk.evaluation.allowed",
      RISK_REVIEW: "risk.hold.created",
      RISK_DENY: "risk.evaluation.denied",
      RISK_HOLD_RELEASED: "risk.hold.released"
    };
    const type = byResult[record.result];
    if (!type) return null;
    const decision = record.result === "RISK_HOLD_RELEASED" ? undefined : record.result.slice("RISK_".length);
    return buildEvent(config, { ...base, type, data: { action: record.action, decision } });
  }
  if (record.kind === "intent" && record.result === "FAIL_CLOSED") {
    return buildEvent(config, { ...base, type: "request.failed", data: { action: record.action, stage: "intent", code: "INTENT_DERIVATION_FAILED" } });
  }
  if (record.kind === "metadata" && record.action === "org_controls_updated") {
    return buildEvent(config, { ...base, type: "org.controls.updated", data: { summary: record.detail } });
  }
  return null;
}

/* The audit hook (called by server/src/audit.js). NEVER throws. */
async function noteAuditRecord(config, record) {
  let event = null;
  try {
    event = deriveEventFromAudit(config, record);
  } catch {
    droppedEmissions += 1;
    return null;
  }
  if (!event) return null;
  try {
    await getEventsStore(config).appendEvent(event);
    return event;
  } catch (error) {
    droppedEmissions += 1;
    try {
      console.error(`policyvault-events: dropped ${event.type} emission (${error.code || error.message})`);
    } catch {
      /* never throw */
    }
    return null;
  }
}

/*
 * Tenant visibility of one event for a principal-like identity
 * ({ xOnlyPubkey, networkId }) — the SAME derivation the hosted global
 * audit feed uses (api.js GET /audit): vault events require covenant
 * participation, org events require org membership, identity events
 * require the creating wallet. DEFAULT DENY: an event that matches no
 * rule is invisible in hosted mode. Self-hosted (tenancy disabled):
 * everything is visible to the single local operator.
 * `caches` = { vaults: Map, orgs: Map } reused across a scan.
 */
async function eventVisibleTo(config, event, principalLike, caches) {
  if (!config.tenancyEnforced) return true;
  if (!principalLike || typeof principalLike.xOnlyPubkey !== "string") return false;
  if (event.networkId !== principalLike.networkId) return false;
  const { vaultAccessAllowed, orgAccessAllowed } = require("./tenancy");
  if (typeof event.vaultId === "string" && event.vaultId) {
    let loaded = caches.vaults.get(event.vaultId);
    if (loaded === undefined) {
      try {
        loaded = await require("../../sdk/src/manifest-v2").loadAnyManifest(config, event.vaultId);
      } catch {
        loaded = null;
      }
      caches.vaults.set(event.vaultId, loaded);
    }
    return vaultAccessAllowed(config, loaded, principalLike, "read");
  }
  if (typeof event.orgId === "string" && event.orgId) {
    let org = caches.orgs.get(event.orgId);
    if (org === undefined) {
      try {
        org = await require("../../sdk/src/organization").loadOrganization(config, event.orgId);
      } catch {
        org = null;
      }
      caches.orgs.set(event.orgId, org);
    }
    return orgAccessAllowed(config, org, principalLike, "read");
  }
  if (event.type.startsWith("identity.")) {
    return typeof event.data.creatorXOnly === "string" && event.data.creatorXOnly === principalLike.xOnlyPubkey;
  }
  if (event.type.startsWith("notification.")) {
    // Notification-health events belong to the rule's creating wallet,
    // exactly the identity-event derivation.
    return typeof event.data.creatorXOnly === "string" && event.data.creatorXOnly === principalLike.xOnlyPubkey;
  }
  return false; // unscoped event: fail closed in hosted mode
}

/* Fresh caches for one visibility scan. */
function visibilityCaches() {
  return { vaults: new Map(), orgs: new Map() };
}

/*
 * Aggregate, non-secret counters for monitoring (surface 25 seam; also
 * the minimal /health/ready aggregate). Numbers only — never URLs, ids,
 * or secret material.
 */
async function eventStats(config) {
  const store = getEventsStore(config);
  const { Categories } = require("./events-store");
  const endpoints = await store.listValues(Categories.WEBHOOK_ENDPOINT);
  const states = await store.listValues(Categories.WEBHOOK_DELIVERY_STATE);
  const active = endpoints.filter((e) => e && e.status === "ACTIVE");
  let delivered = 0;
  let failed = 0;
  let deadLettered = 0;
  let minCursor = null;
  const stateById = new Map(states.filter(Boolean).map((s) => [s.endpointId, s]));
  for (const endpoint of active) {
    const s = stateById.get(endpoint.endpointId);
    const cursor = BigInt(s && typeof s.cursor === "string" && /^\d+$/.test(s.cursor) ? s.cursor : (endpoint.initialCursor ?? "0"));
    if (minCursor === null || cursor < minCursor) minCursor = cursor;
  }
  for (const s of states) {
    if (!s || !s.counters) continue;
    delivered += Number(s.counters.delivered) || 0;
    failed += Number(s.counters.failed) || 0;
    deadLettered += Number(s.counters.deadLettered) || 0;
  }
  let oldestUnprocessedMs = null;
  if (active.length && minCursor !== null) {
    const next = await store.listEventsAfter({ cursor: String(minCursor), limit: 1 });
    if (next.length) {
      const t = Date.parse(next[0].event.occurredAt);
      if (Number.isFinite(t)) oldestUnprocessedMs = Math.max(0, Date.now() - t);
    }
  }
  return {
    totalEvents: await store.countEvents(),
    droppedEmissions,
    endpoints: { active: active.length, total: endpoints.length },
    delivered,
    failed,
    deadLettered,
    oldestUnprocessedMs
  };
}

module.exports = {
  EVENT_SCHEMA,
  EVENTS_PAGE_SCHEMA,
  EVENT_TYPES,
  NOTIFICATION_NOTICE,
  buildEvent,
  emitPlatformEvent,
  safeEmitPlatformEvent,
  deriveEventFromAudit,
  noteAuditRecord,
  eventVisibleTo,
  visibilityCaches,
  eventStats,
  EventError
};
