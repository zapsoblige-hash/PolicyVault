"use strict";
const { MAINNET_CREATABLE_GENERATIONS } = require("../../sdk/src/config");

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
const { CONTRACT_VERSION_V7_ROOT } = require("../../core/model/vault-state-v7-root");
const { CONTRACT_VERSION_V7: CONTRACT_VERSION_V7_PAYMENT, OWNER_OP_SELECTOR_V7 } = require("../../core/model/vault-state-v7");
const { OWNER_SLOTS_V7, ROOT_ACTIONS_V7, AUTHORITY_CLASSES_V7 } = require("../../core/model/owner-set-v7");
const { CONTRACT_VERSION_V5 } = require("../../sdk/src/vault-state-v5");
const { CONTRACT_VERSION_V6 } = require("../../sdk/src/vault-state-v6");
const { KNOWN_COVENANT_VERSIONS } = require("../../core/intent/router");
const ROOT_ACTION_NAMES_V7 = Object.keys(ROOT_ACTIONS_V7);
const CONTRACT_VERSION_V7_PAYMENT_HD = "policyvault-0.7-payment-hd";

const CAPABILITIES_SCHEMA = "policyvault-capabilities/v1";

/*
 * Every covenant generation this server ACTUALLY routes through a real
 * HTTP surface (Wave 2, Track E "token-surface" — the wallet/v5, wallet/v6
 * and wallet/v7-HD-extension routes; the v0.7-root/v0.7-payment routes
 * already existed). Validated at module load against
 * core/intent/router.js's KNOWN_COVENANT_VERSIONS (the one source of
 * truth for which covenant generations exist at all): this list may be a
 * SUBSET of what the router knows (a version can exist without a routed
 * HTTP surface yet) but must NEVER contain anything the router does not
 * recognize — that would advertise support for a version nothing in the
 * codebase actually implements. `status` distinguishes a covenant-byte-
 * frozen generation from a still-evolving CANDIDATE (never collapsed —
 * CLAUDE.md progress-reporting discipline); `authorityModel` matches
 * docs/postlaunch/v0.7-app-surface-contract.md §0's three-value vocabulary.
 */
const ROUTED_COVENANT_VERSIONS = Object.freeze([
  { contractVersion: "policyvault-0.4", status: "FROZEN", authorityModel: "SINGLE_ON_CHAIN_OWNER" },
  { contractVersion: "policyvault-0.4.1", status: "FROZEN", authorityModel: "SINGLE_ON_CHAIN_OWNER" },
  { contractVersion: CONTRACT_VERSION_V5, status: "FROZEN", authorityModel: "SINGLE_ON_CHAIN_OWNER" },
  { contractVersion: CONTRACT_VERSION_V6, status: "FROZEN", authorityModel: "SINGLE_ON_CHAIN_OWNER", venues: ["FIXTURE"] },
  { contractVersion: CONTRACT_VERSION_V7_ROOT, status: "FROZEN", authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT" },
  { contractVersion: CONTRACT_VERSION_V7_PAYMENT, status: "FROZEN", authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT" },
  { contractVersion: CONTRACT_VERSION_V7_PAYMENT_HD, status: "CANDIDATE", authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT" }
]);
(function validateRoutedCovenantVersions() {
  const known = new Set(KNOWN_COVENANT_VERSIONS);
  const seen = new Set();
  for (const entry of ROUTED_COVENANT_VERSIONS) {
    if (!known.has(entry.contractVersion)) {
      throw new Error(`server/src/capabilities.js: ROUTED_COVENANT_VERSIONS names ${JSON.stringify(entry.contractVersion)}, which core/intent/router.js's KNOWN_COVENANT_VERSIONS does not recognize — failing closed at module load`);
    }
    if (seen.has(entry.contractVersion)) {
      throw new Error(`server/src/capabilities.js: ROUTED_COVENANT_VERSIONS lists ${JSON.stringify(entry.contractVersion)} more than once`);
    }
    seen.add(entry.contractVersion);
  }
})();

const SCOPE_DESCRIPTIONS = Object.freeze({
  "read:vaults": "read vault manifests, live state, and status",
  "read:requests": "read durable wallet-request records",
  "read:governance": "read governance proposals",
  "read:risk": "read risk-evaluation evidence",
  "read:organizations": "read organizations, membership, and controls",
  "read:manifests": "read recorded intent-manifest records",
  "read:attestations": "export policyvault-execution-attestation/1 evidence records for the caller's own requests, vaults and organizations (read-only; independently verifiable offline)",
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
  "notifications:manage": "create/disable/enable/delete human-notification rules routing the caller's own tenant-scoped events to a console/webhook(/pluggable smtp) channel — coordination, never authority",
  "read:org-roots": "read on-chain organizational roots (v0.7), their pending/historical requests, and rooted vaults — never implied by read:organizations (a hosted organization grants no on-chain root authority)",
  "write:org-roots": "create an organizational-root or rooted-vault genesis, create a root-authorized request (owner action, at most one vault operation), attach an owner slot or single (genesis/succession) signature, finalize, submit, reject, reconcile, and build a delegate spend/deposit on a rooted vault — never implied by organizations:manage; the actual owner-slot (or pinned successor) signer check is enforced independently of this scope"
});

function scopesDocument() {
  return SCOPES.map((scope) => ({ scope, description: SCOPE_DESCRIPTIONS[scope] ?? "" }));
}

/* Principal-scoped discovery (2026-09-02, MCP least-privilege corrective):
 * the document stays PUBLIC and byte-for-byte unchanged for anonymous
 * callers. When it is requested WITH a presented credential, the response
 * additionally names the caller's OWN principal — for a machine
 * credential, exactly the scopes it holds — so a thin client (the MCP
 * adapter) can advertise only what the credential can actually use.
 * Information about the caller, to the caller only: never another
 * identity's scopes, never a token. Enforcement does NOT live here —
 * scopes are still checked per call in server/src/api.js handle(). */
function presentPrincipal(principal) {
  if (!principal) return null;
  if (principal.isMachine) {
    return { kind: "machine", identityId: principal.identityId, scopes: Array.isArray(principal.scopes) ? [...principal.scopes] : [] };
  }
  return { kind: "session" };
}

function buildCapabilities(config, principal = null) {
  const presented = presentPrincipal(principal);
  return {
    schemaVersion: CAPABILITIES_SCHEMA,
    apiVersion: API_VERSION,
    networkId: config.networkId,
    ...(config.buildId ? { buildId: config.buildId } : {}),
    ...(presented ? { principal: presented } : {}),
    contract: {
      /* v0.7 additions are presentation-only here (SUPPORTED_COVENANT_VERSIONS
       * itself is the v0.4-family intent-manifest router's own list — v0.5/
       * v0.6/v0.7 each own a separate manifest family, core/intent/router.js);
       * this document simply ADVERTISES every generation this build ROUTES
       * (ROUTED_COVENANT_VERSIONS above, validated against the router's
       * KNOWN_COVENANT_VERSIONS at module load — never a superset of it). */
      supportedCovenantVersions: ROUTED_COVENANT_VERSIONS.map((e) => e.contractVersion),
      /* F-02 (rc11 review): discovery is NOT authority. Every routed version is
       * READABLE / reconcilable on every network; only the generations in the
       * per-generation mainnet allowlist may be NEWLY CREATED or mutated on
       * mainnet (sdk/src/config.js MAINNET_CREATABLE_GENERATIONS). On testnet
       * every routed generation is creatable (human acceptance). */
      covenantVersions: ROUTED_COVENANT_VERSIONS.map((e) => ({ ...e, mainnetCreatable: MAINNET_CREATABLE_GENERATIONS.has(e.contractVersion) })),
      creatableCovenantVersions: ROUTED_COVENANT_VERSIONS.map((e) => e.contractVersion).filter((v) => config.networkId !== "mainnet" || MAINNET_CREATABLE_GENERATIONS.has(v)),
      currentV4Versions: [CONTRACT_VERSION_V4, CONTRACT_VERSION_V4_1]
    },
    /* v0.5 (token controller, FROZEN) / v0.6 (optional atomic composability,
     * FROZEN, fixture venue only) request surfaces (Wave 2 Track E;
     * docs/postlaunch/v0.7-app-surface-contract.md §6.1). Token amounts and
     * KAS are two separate accounting domains and are NEVER converted into
     * each other by this server. */
    tokens: {
      v5: { contractVersion: CONTRACT_VERSION_V5, status: "FROZEN", authorityModel: "SINGLE_ON_CHAIN_OWNER", actions: [...require("../../sdk/src/vault-builders-v5").OWNER_CONTROL_ACTIONS, ...require("../../sdk/src/vault-builders-v5").SPEND_ACTIONS, "ownerRecover", "tokenDeposit"] },
      v6: {
        contractVersion: CONTRACT_VERSION_V6,
        status: "FROZEN",
        authorityModel: "SINGLE_ON_CHAIN_OWNER",
        composability: "OPTIONAL_ATOMIC",
        venues: ["FIXTURE"],
        venueStatement: "the ONLY venue profile this server knows is the PolicyVault pool FIXTURE (conformance evidence) — no real DEX venue is supported; a request naming any other venue fails closed VENUE_PROFILE_UNSUPPORTED",
        deadlineStatement: "deadlineDaa is presented as a pre-sign freshness boundary, never a consensus expiry",
        actions: [...require("../../sdk/src/vault-builders-v6").OWNER_CONTROL_ACTIONS, ...require("../../sdk/src/vault-builders-v6").SPEND_ACTIONS, ...require("../../sdk/src/vault-builders-v6").SWAP_ACTIONS, "ownerRecover", "tokenDeposit"]
      }
    },
    /* v0.7-payment-hd hierarchical-delegation CANDIDATE (Wave 2 Track E;
     * NOT covenant-byte-frozen, NOT production, NOT externally reviewed).
     * expiryStatement is the verbatim sentence every HD response repeats. */
    hierarchicalDelegation: {
      contractVersion: CONTRACT_VERSION_V7_PAYMENT_HD,
      status: "CANDIDATE",
      authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT",
      spendActions: ["hdSpend", "childSpendL2", "childSpendL3"],
      delegationActions: ["delegateSetChildRoot1", "delegateSetChildRoot2"],
      expiryStatement: "expiry is enforced by PolicyVault's core and by revocation, not by consensus"
    },
    /* v0.7 ON-CHAIN ORGANIZATIONAL ROOT (docs/postlaunch/v0.7-app-surface-
     * contract.md §2 "GET /capabilities"). authorityModel here documents
     * what an /org-roots resource ITSELF carries; a HOSTED organization
     * (/organizations) carries authorityModel HOSTED_ORGANIZATION and
     * grants no on-chain authority; a legacy single-owner vault carries
     * SINGLE_ON_CHAIN_OWNER. */
    orgRoots: {
      authorityModel: "ON_CHAIN_ORGANIZATIONAL_ROOT",
      slots: OWNER_SLOTS_V7,
      actions: [...ROOT_ACTION_NAMES_V7, ...Object.keys(OWNER_OP_SELECTOR_V7)],
      actionClasses: Object.values(AUTHORITY_CLASSES_V7)
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
      notificationPayload: require("./notify-delivery").NOTIFY_PAYLOAD_SCHEMA,
      mcpTelemetryEvent: require("./mcp-telemetry").TELEMETRY_EVENT_SCHEMA,
      mcpTelemetryAggregate: require("./mcp-telemetry").TELEMETRY_AGGREGATE_SCHEMA
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
      /* Principal-scoped discovery (see presentPrincipal): a presented
       * machine credential gets its own granted scopes back on this
       * document, so discovery can be narrowed to what it may use. Only
       * meaningful where machine identities exist (hosted auth). */
      principalScopedDiscovery: config.authMode === "enabled",
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
      humanNotifications: true,
      /* MCP usage telemetry (Track 7): privacy-minimizing, config-gated,
       * OFF by default — this reflects the LIVE current setting
       * (POLICYVAULT_MCP_TELEMETRY), not a build-time capability; when
       * false, GET /api/v1/mcp-telemetry does not exist (404). No new
       * scope: reuses read:metrics (see server/src/mcp-telemetry.js). */
      mcpTelemetry: require("./mcp-telemetry").telemetryEnabled()
    }
  };
}

module.exports = { CAPABILITIES_SCHEMA, V4_WALLET_REQUEST_SCHEMA_VERSION, buildCapabilities, presentPrincipal };
