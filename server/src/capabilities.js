"use strict";

/*
 * Capability / version discovery document (completion-standard surface
 * 22; docs/postlaunch/platform-agent-api-spec.md). GET /api/v1/capabilities
 * — PUBLIC, no auth/scope required (server/src/scopes.js isPublicRoute),
 * exactly like /health.
 *
 * Generated from CODE TRUTH wherever the underlying value already exists
 * as a real exported constant (scopes, actions, supported contract
 * versions, rate limits/quotas, feature flags derived from the live
 * config) rather than retyped as hand-maintained prose. The per-scope
 * one-line description text is the one hand-maintained exception — scopes
 * are enforced by server/src/scopes.js's route classifier (a function,
 * not a data table), so an English description of what each scope GATES
 * cannot itself be mechanically derived; the scope NAMES and the set of
 * routes gated behind them are still single-sourced from scopes.js.
 */

const { API_VERSION, V4_WALLET_REQUEST_SCHEMA_VERSION } = require("./api-version");
const { SCOPES } = require("./scopes");
const wr4 = require("../../sdk/src/wallet-requests-v4");
const { SUPPORTED_COVENANT_VERSIONS } = require("../../core/intent");
const { CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1 } = require("../../sdk/src/vault-state-v4");
const { SIMULATION_SCHEMA } = require("./simulate");
const { IDENTITY_SCHEMA, CREDENTIAL_SCHEMA } = require("./machine-identity");
const { SCHEMA: IDEMPOTENCY_SCHEMA } = require("./idempotency");
const { EVENT_SCHEMA, EVENTS_PAGE_SCHEMA, EVENT_TYPES } = require("./events");
const { ENDPOINT_SCHEMA, MAX_ENDPOINTS_PER_WALLET } = require("./webhooks");
const { WEBHOOK_PAYLOAD_SCHEMA, DEFAULT_MAX_ATTEMPTS, DEFAULT_BACKOFF_MS } = require("./events-delivery");
const { SIGNATURE_SCHEME, SIGNATURE_HEADER, DEFAULT_TOLERANCE_SECONDS } = require("./events-signing");

const CAPABILITIES_SCHEMA = "policyvault-capabilities/v1";

const SCOPE_DESCRIPTIONS = Object.freeze({
  "read:vaults": "read vault manifests, live state, and status",
  "read:requests": "read durable wallet-request records",
  "read:governance": "read governance proposals",
  "read:risk": "read risk-evaluation evidence",
  "read:organizations": "read organizations, membership, and controls",
  "read:manifests": "read recorded intent-manifest records",
  "read:network": "read node/network status and ordinary fuel UTXOs",
  "read:audit": "read the audit/activity feed",
  "request:build": "build (and simulate) an unsigned wallet request — no broadcast",
  "request:sign": "attach an externally produced signature or approval to a built request",
  "request:submit": "broadcast a finalized request's transaction",
  "request:reject": "cancel an open wallet request",
  "request:break-glass": "attempt ownerPause / ownerRecover (still requires the real owner signature; a coarser API-surface gate)",
  "governance:propose": "create a governance proposal",
  "governance:approve": "submit a governance-proposal approval signature",
  "governance:cancel": "cancel a governance proposal",
  "risk:release": "release a REVIEW-held risk evaluation",
  "vaults:reconcile": "trigger chain reconciliation for a vault",
  "vaults:suspend-agents": "instantly suspend/unsuspend an agent (or all agents of a vault) at the HOSTED layer — a coordination control that makes this server refuse new build/finalize/submit requests for the agent; NEVER a covenant control (only ownerPause/removeAgent/ownerRecover bind a key holder on-chain); vault-owner tenancy still required",
  "organizations:manage": "create/rename/archive/delete organizations, manage membership, vault assignment, and controls",
  "read:events": "poll the asynchronous platform-event stream (tenant-scoped notifications; never authority)",
  "webhooks:manage": "create/list/rotate/revoke webhook endpoints delivering the caller's own tenant-scoped events",
  "read:metrics": "read the aggregate operational-metrics document (non-secret counters/histograms only; no per-tenant data)",
  "read:notifications": "read the caller's own human-notification rules, their delivery state, and the channel-type discovery document",
  "notifications:manage": "create/disable/enable/delete human-notification rules routing the caller's own tenant-scoped events to a console/webhook(/pluggable smtp) channel — coordination, never authority"
});

function scopesDocument() {
  return SCOPES.map((scope) => ({ scope, description: SCOPE_DESCRIPTIONS[scope] ?? "" }));
}

function buildCapabilities(config) {
  return {
    schemaVersion: CAPABILITIES_SCHEMA,
    apiVersion: API_VERSION,
    networkId: config.networkId,
    ...(config.buildId ? { buildId: config.buildId } : {}),
    contract: {
      supportedCovenantVersions: SUPPORTED_COVENANT_VERSIONS,
      currentV4Versions: [CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1]
    },
    actions: {
      v4: Object.entries(wr4.ROLE_BY_ACTION).map(([action, role]) => ({ action, role }))
    },
    scopes: scopesDocument(),
    schemas: {
      capabilities: CAPABILITIES_SCHEMA,
      walletV4Request: V4_WALLET_REQUEST_SCHEMA_VERSION,
      simulation: SIMULATION_SCHEMA,
      machineIdentity: IDENTITY_SCHEMA,
      machineCredential: CREDENTIAL_SCHEMA,
      idempotencyRecord: IDEMPOTENCY_SCHEMA,
      event: EVENT_SCHEMA,
      eventsPage: EVENTS_PAGE_SCHEMA,
      webhookEndpoint: ENDPOINT_SCHEMA,
      webhookPayload: WEBHOOK_PAYLOAD_SCHEMA,
      agentSuspensions: require("./agent-suspensions").AGENT_SUSPENSIONS_SCHEMA,
      metrics: require("./metrics").METRICS_SCHEMA,
      auditChainStatus: require("./audit-chain").STATUS_SCHEMA,
      auditChainVerification: require("./audit-chain").VERIFICATION_SCHEMA,
      notificationRule: require("./notifications").RULE_SCHEMA,
      notificationPayload: require("./notify-delivery").NOTIFY_PAYLOAD_SCHEMA
    },
    /* Asynchronous events + signed webhooks (surface 18). Events are
     * NOTIFICATIONS of durable state — never authority (spec §2). */
    events: {
      types: Object.keys(EVENT_TYPES),
      polling: { route: "GET /api/v1/events", cursorParam: "cursor", maxLimit: 500 },
      webhooks: {
        signature: { scheme: SIGNATURE_SCHEME, header: SIGNATURE_HEADER, signedInput: "timestamp + '.' + rawBody", toleranceSeconds: DEFAULT_TOLERANCE_SECONDS },
        delivery: { semantics: "at-least-once, ordered per endpoint", maxAttempts: DEFAULT_MAX_ATTEMPTS, backoffScheduleMs: DEFAULT_BACKOFF_MS },
        maxEndpointsPerWallet: MAX_ENDPOINTS_PER_WALLET
      }
    },
    /* Human-notification coordination (surface 19): a second consumer of
     * the same event stream, routed to human channels. Coordination only
     * — a notification is never authority, and notification.* health
     * events are unsubscribable by rules (no feedback loops). */
    notifications: {
      channelTypes: require("./notifications").availableChannelTypes(),
      maxRulesPerWallet: require("./notifications").MAX_RULES_PER_WALLET,
      delivery: {
        semantics: "best-effort at-least-once, ordered per rule; bounded retry then skip (history remains at GET /api/v1/events)",
        maxAttempts: require("./notify-delivery").DEFAULT_MAX_ATTEMPTS,
        backoffScheduleMs: require("./notify-delivery").DEFAULT_BACKOFF_MS,
        rateLimitPerCreatorPerHour: Number(process.env.POLICYVAULT_NOTIFY_RATE_PER_HOUR || require("./notify-delivery").DEFAULT_RATE_PER_HOUR) || require("./notify-delivery").DEFAULT_RATE_PER_HOUR
      }
    },
    /* Audit hash chain (surface 17 residual): tamper-evident chain over
     * server-written audit records; GET /api/v1/audit/chain/verify walks
     * it (structure only — never record content). Unchained records
     * (pre-chain history, sdk-internal writers) are reported honestly. */
    auditChain: {
      verifyRoute: "GET /api/v1/audit/chain/verify",
      statusRoute: "GET /api/v1/audit/chain",
      recordHash: "sha256(canonicalJson({content,nonce,prevHash,seq}))",
      coverage: "records written through the server audit module; unchained records are counted, never claimed chained"
    },
    limits: {
      rateLimits: config.requestProtection.rateLimits,
      openRequestQuota: config.requestProtection.openRequestQuota,
      semaphores: config.requestProtection.semaphores,
      machineIdentity: { maxIdentitiesPerWallet: require("./machine-identity").MAX_IDENTITIES_PER_WALLET, maxCredentialsPerIdentity: require("./machine-identity").MAX_CREDENTIALS_PER_IDENTITY }
    },
    features: {
      hostedAuth: config.authMode === "enabled",
      tenancy: config.tenancyEnforced,
      governance: true,
      risk: true,
      idempotency: true,
      dryRunSimulation: true,
      capabilityDiscovery: true,
      asyncEvents: true,
      webhooks: true,
      machineIdentities: config.authMode === "enabled",
      originPolicySplitForMachineCredentials: true,
      persistenceBackend: config.persistenceBackend,
      /* Hosted-layer agent suspend (surface 21 residual): a COORDINATION
       * control — this server refuses new build/finalize/submit requests
       * for suspended agents. NEVER a covenant control: it cannot stop a
       * delegate-key holder submitting directly to a Kaspa node; only
       * ownerPause / removeAgent / ownerRecover bind on-chain. */
      hostedAgentSuspend: true,
      /* Operational metrics (surface 25): GET /api/v1/metrics (JSON;
       * ?format=prometheus for text exposition) — aggregate non-secret
       * numbers only. */
      operationalMetrics: true,
      /* Audit hash chain (surface 17 residual): tamper-evident chained
       * audit records + integrity verification endpoint. */
      auditHashChain: true,
      /* Human notifications (surface 19): per-tenant rules + console/
       * webhook reference providers over the same durable event outbox.
       * Peripheral coordination — its outage never affects core safety. */
      humanNotifications: true
    }
  };
}

module.exports = { CAPABILITIES_SCHEMA, V4_WALLET_REQUEST_SCHEMA_VERSION, buildCapabilities };
