"use strict";

/*
 * PolicyVault backend API (versioned, machine-readable errors).
 *
 * This backend is NOT the security boundary. It never holds owner or
 * delegate private keys and never claims a transaction succeeded before
 * chain proof. Funds-critical mutations (create/spend/recover) run through
 * the CLI tools that hold test keys; the API exposes read/status plus a
 * lifecycle-aware view so a frontend can present exact state.
 */

const { loadConfig } = require("../../sdk/src/config");
const { listVaultIds } = require("../../sdk/src/manifest");
const { loadAnyManifest } = require("../../sdk/src/manifest-v2");
const { compileExactState } = require("../../sdk/src/contract-compiler");
const { covenantAddress, connectVerified, getVirtualDaaScore } = require("../../sdk/src/chain");
const { sompiToKas } = require("../../sdk/src/amounts");
const { readAudit, appendAudit } = require("./audit");
const { API_VERSION, V4_WALLET_REQUEST_SCHEMA_VERSION } = require("./api-version");

function apiError(status, code, message, extra) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  if (extra) {
    error.extra = extra;
  }
  return error;
}

// Closed-body top-level schema: refuse a request that carries any key
// outside the permitted set, so an agent (or an LLM filling a
// half-remembered schema) cannot believe it applied a control — e.g.
// `bypassPolicy`, `skipGovernance`, `signedSafeJson` — that the planner
// silently drops. Mirrors the mcp/adapter closed-schema discipline. Names
// the PERMITTED set only; hostile key text is never echoed back.
// (Hostile-AI review H-7, top-level. Per-action params-level closure is a
// tracked follow-up — the builder is whitelist-by-construction, so an
// unknown param already cannot reach consensus.)
function assertClosedBody(body, allowedKeys, label) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return;
  const allowed = new Set(allowedKeys);
  let unknownCount = 0;
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) unknownCount += 1;
  }
  if (unknownCount > 0) {
    throw apiError(422, "UNKNOWN_FIELD", `${label} carries ${unknownCount} field(s) outside the permitted set — a hidden field is a hidden effect, so unknown keys are refused. Permitted: ${[...allowed].sort().join(", ")}`);
  }
}

/* Present a manifest as an API resource (KAS strings + derived fields). */
async function presentVault(config, manifest, { virtualDaa } = {}) {
  const policy = manifest.policy;
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: policy.owner,
    delegate: policy.delegate,
    policy: {
      maxPerSpendKas: sompiToKas(policy.maxPerSpend),
      periodBudgetKas: sompiToKas(policy.periodBudget),
      periodLengthDaa: policy.periodLengthDaa.toString(),
      recipients: policy.recipients.slice(0, policy.declaredRecipientCount),
      initValueKas: sompiToKas(policy.initValue)
    },
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    updatedAt: manifest.updatedAt
  };
  if (manifest.live) {
    const state = manifest.live.state;
    const remaining = policy.periodBudget - state.periodSpent;
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      periodStartDaa: state.periodStartDaa.toString(),
      periodSpentKas: sompiToKas(state.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      paused: state.paused === 1n,
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      const elapsed = virtualDaa - state.periodStartDaa;
      base.live.periodElapsedDaa = (elapsed > 0n ? elapsed : 0n).toString();
      base.live.periodComplete = elapsed >= policy.periodLengthDaa;
    }
  }
  return base;
}

/*
 * Operational status for the dashboard: derived ONLY from durable
 * backend truth (manifest + transition claim + request records). The
 * derivation is fail-closed and offers no claim-override input.
 */
async function operationalFor(config, manifest) {
  const { deriveOperationalStatus } = require("../../sdk/src/operational-status");
  const { loadTransitionClaim } = require("../../sdk/src/submission-claim");
  const { listVaultRequests } = require("../../sdk/src/wallet-requests-v2");
  const claim = manifest.live ? await loadTransitionClaim(config, manifest.live.outpoint) : null;
  return deriveOperationalStatus({ manifest, claim, requests: await listVaultRequests(config, manifest.vaultId) });
}

/* Display-only wallet-address form of a stored x-only pubkey. */
function addressOf(config, xOnly) {
  try {
    return require("../../sdk/src/address-identity").addressForXOnlyPubkey(config, xOnly);
  } catch {
    return null;
  }
}

/* Present a v0.2 manifest (policy fields live in mutable state). */
async function presentVaultV2(config, manifest, { virtualDaa } = {}) {
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: manifest.template.owner,
    ownerAddress: addressOf(config, manifest.template.owner),
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    lastTransition: manifest.lastTransition,
    updatedAt: manifest.updatedAt
  };
  if (manifest.live) {
    const state = manifest.live.state;
    const remaining = state.periodBudget - state.periodSpent;
    base.delegate = state.delegate;
    base.delegateAddress = addressOf(config, state.delegate);
    base.policy = {
      maxPerSpendKas: sompiToKas(state.maxPerSpend),
      periodBudgetKas: sompiToKas(state.periodBudget),
      periodLengthDaa: state.periodLengthDaa.toString(),
      recipients: [...state.recipients],
      policyNonce: state.policyNonce.toString()
    };
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      periodStartDaa: state.periodStartDaa.toString(),
      periodSpentKas: sompiToKas(state.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      paused: state.paused === 1n,
      delegateActive: state.delegateActive === 1n,
      policyNonce: state.policyNonce.toString(),
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      const elapsed = virtualDaa - state.periodStartDaa;
      base.live.periodElapsedDaa = (elapsed > 0n ? elapsed : 0n).toString();
      base.live.periodComplete = elapsed >= state.periodLengthDaa;
    }
  }
  base.operational = await operationalFor(config, manifest);
  return base;
}

/*
 * Present a v0.4 manifest: fixed template + mutable state (protected value,
 * fee reserve, paused, agentRoot, approver slots) + the durable agent
 * registry (the verified reconstruction of the agent tree). Agent policy
 * lives in the authenticated tree, so the registry is display-derived from
 * the metadata whose root the covenant enforces.
 */
async function presentVaultV4(config, manifest, { virtualDaa } = {}) {
  const base = {
    vaultId: manifest.vaultId,
    label: manifest.label,
    status: manifest.status,
    networkId: manifest.networkId,
    contractVersion: manifest.contractVersion,
    owner: manifest.template.owner,
    ownerAddress: addressOf(config, manifest.template.owner),
    agentRegistryRoot: manifest.agentRegistryRoot,
    creationTxId: manifest.creationTxId,
    latestTransitionTxId: manifest.latestTransitionTxId,
    lastTransition: manifest.lastTransition,
    updatedAt: manifest.updatedAt
  };
  // Agents are display-derived from the durable registry (root-verified).
  base.agents = manifest.agentRegistry.map((e) => {
    const p = e.policy;
    const remaining = p.periodBudget - p.periodSpent;
    return {
      agentPk: p.agentPk,
      agentAddress: addressOf(config, p.agentPk),
      maxPerSpendKas: sompiToKas(p.maxPerSpend),
      periodBudgetKas: sompiToKas(p.periodBudget),
      periodSpentKas: sompiToKas(p.periodSpent),
      remainingBudgetKas: sompiToKas(remaining > 0n ? remaining : 0n),
      periodLengthDaa: p.periodLengthDaa.toString(),
      periodStartDaa: p.periodStartDaa.toString(),
      approvalThresholdKas: sompiToKas(p.approvalThreshold),
      agentMaxFeePerTxKas: sompiToKas(p.agentMaxFeePerTx),
      agentRecipientRoot: p.agentRecipientRoot,
      recipients: [...e.recipients],
      recipientAddresses: e.recipients.map((r) => addressOf(config, r))
    };
  });
  if (manifest.live) {
    const state = manifest.live.state;
    base.approverSlots = [...state.approvers];
    base.approvalM = state.approvalM.toString();
    base.activeApproverCount = state.activeApproverCount;
    base.live = {
      protectedValueKas: sompiToKas(state.protectedValue),
      feeReserveKas: sompiToKas(state.feeReserve),
      covenantValueKas: sompiToKas(state.protectedValue + state.feeReserve),
      paused: state.paused === 1n,
      agentRoot: state.agentRoot,
      approvalM: state.approvalM.toString(),
      policyNonce: state.policyNonce.toString(),
      stateId: manifest.live.stateId,
      outpoint: manifest.live.outpoint,
      covenantId: manifest.live.covenantId
    };
    if (virtualDaa !== undefined) {
      base.live.virtualDaaScore = virtualDaa.toString();
    }
  }
  base.operational = await operationalForV4(config, manifest);
  return base;
}

/* Operational status for a v0.4 vault (reuses the v0.2 derivation, which is
 * pure over durable truth: manifest + transition claim + v0.4 requests). */
async function operationalForV4(config, manifest) {
  const { deriveOperationalStatus } = require("../../sdk/src/operational-status");
  const { loadTransitionClaim } = require("../../sdk/src/submission-claim");
  const { listVaultRequests } = require("../../sdk/src/wallet-requests-v4");
  const claim = manifest.live ? await loadTransitionClaim(config, manifest.live.outpoint) : null;
  return deriveOperationalStatus({ manifest, claim, requests: await listVaultRequests(config, manifest.vaultId) });
}

/*
 * Off-chain organization annotation for a vault (display only — never
 * authority). Corrupt org metadata degrades to an error marker without
 * ever hiding the vault itself.
 */
async function organizationRef(config, vaultId) {
  const { assignmentFor, loadOrganization } = require("../../sdk/src/organization");
  const assignment = await assignmentFor(config, vaultId);
  if (!assignment) return null;
  let name = null;
  let metadataError = null;
  try {
    name = (await loadOrganization(config, assignment.orgId))?.name ?? null;
  } catch (e) {
    metadataError = "CORRUPT_METADATA";
  }
  return { orgId: assignment.orgId, name, group: assignment.group, ...(metadataError ? { metadataError } : {}) };
}

/* Version-aware presenter: dispatch on the stored manifest schema. */
async function presentAny(config, vaultId, opts) {
  const loaded = await loadAnyManifest(config, vaultId);
  if (!loaded) {
    return null;
  }
  const presented =
    loaded.version === "v4"
      ? await presentVaultV4(config, loaded.manifest, opts)
      : loaded.version === "v2"
        ? await presentVaultV2(config, loaded.manifest, opts)
        : await presentVault(config, loaded.manifest, opts);
  presented.organization = await organizationRef(config, vaultId);
  return presented;
}

/*
 * The API handler dispatch. Returns { status, body }. Pure over the
 * filesystem/chain; the HTTP layer in server.js adapts it.
 */
/* Present a wallet request without server-side filesystem/internal details.
 * v0.4 requests carry a heavy internal `build` (with encoder build dirs), the
 * approval package, the pending registry, and the finalized transaction —
 * none of which the browser needs (it signs `transaction.unsignedSafeJson`).
 * The approval PROGRESS is surfaced separately, without slot signatures.
 *
 * DELIBERATE DISCLOSURE (residuals wave — do NOT strip): a GENESIS request's
 * `initialRegistry` (the initial agent registry's full leaf tuples — the
 * exact nine fields the v4 agent-merkle leaf hash consumes, plus each
 * agent's recipient x-only keys, stored by
 * sdk/src/wallet-requests-v4.js buildCreateWalletRequestV4 since
 * Checkpoint G) is a LOAD-BEARING part of the presented document:
 * web/verify-intent.js independently RECOMPUTES the genesis
 * initialState.agentRoot from these tuples and FAILS CLOSED (refuses the
 * signing) when they are missing or inconsistent. Stripping the field here
 * would render every honest genesis flow DO-NOT-SIGN (a G-2-class
 * fail-closed availability break). Pinned by
 * sdk/test/postlaunch-genesis-registry-disclosure.test.js. Nothing in the
 * tuples is secret: they are the public covenant policy of the vault being
 * created, already shown in review.agents. */
function presentRequest(request) {
  if (!request) {
    return null;
  }
  const { encoderBuildDir, build, approvalPackage, newRegistry, finalTransaction, ...rest } = request;
  if (approvalPackage && typeof approvalPackage === "object") {
    const approvedSlots = Array.isArray(approvalPackage.approvals) ? approvalPackage.approvals.map((a) => typeof a === "string") : [];
    const collected = approvedSlots.filter(Boolean).length;
    const required = Number(approvalPackage.approvalM);
    rest.approvalProgress = { collected, required, approverSlots: approvalPackage.approverSlots, approvedSlots, complete: collected >= required };
  } else if (rest.aboveThreshold) {
    // The approval package is materialized lazily on the first approval;
    // a fresh above-threshold request still reports authoritative progress
    // so the browser can render "0 of M" from SERVER state alone.
    rest.approvalProgress = { collected: 0, required: Number(rest.review?.approvalsRequired ?? 0), approverSlots: null, approvedSlots: null, complete: false };
  }
  void build;
  void newRegistry;
  void finalTransaction;
  return rest;
}

/*
 * Abandoned-request quota (Phase D): count OPEN (cancellable) wallet
 * requests — v2 BUILT, v4 BUILT/AWAITING_APPROVALS — for the target vault
 * and for the acting signer wallet, across both request families (they
 * share one durable category). Enforced BEFORE any build work, so a
 * refusal is pure: nothing durable was created. Explicit cancellation
 * (the reject route) or completion frees quota.
 */
const OPEN_REQUEST_STATES = new Set(["BUILT", "AWAITING_APPROVALS"]);
async function assertOpenRequestQuota(config, { vaultId, signerAddress }) {
  const quota = config.requestProtection.openRequestQuota;
  const { getStore, Categories } = require("../../sdk/src/store");
  const all = await getStore(config).listValues(Categories.REQUEST);
  let vaultOpen = 0;
  let walletOpen = 0;
  for (const r of all) {
    if (!r || !OPEN_REQUEST_STATES.has(r.state)) continue;
    if (vaultId !== undefined && r.vaultId === vaultId) vaultOpen += 1;
    if (signerAddress !== undefined && r.signerAddress === signerAddress) walletOpen += 1;
  }
  if (vaultId !== undefined && vaultOpen >= quota.perVault) {
    throw apiError(
      429,
      "QUOTA_EXCEEDED",
      `this vault already has ${vaultOpen} open wallet requests (limit ${quota.perVault}) — cancel (reject) stale requests or complete them first`
    );
  }
  if (signerAddress !== undefined && walletOpen >= quota.perWallet) {
    throw apiError(
      429,
      "QUOTA_EXCEEDED",
      `this wallet already has ${walletOpen} open wallet requests (limit ${quota.perWallet}) — cancel (reject) stale requests or complete them first`
    );
  }
}

/* Clamp a client-supplied listing limit into [1, max] (resource cap). */
function clampLimit(raw, fallback, max) {
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) return fallback;
  return Math.min(n, max);
}

/* One HostedAuthService per config object (process-local Phase B store;
 * a server restart therefore invalidates every challenge and session —
 * fail closed by construction). */
const authServices = new WeakMap();
function authServiceFor(config) {
  if (config.authMode !== "enabled") {
    throw apiError(404, "AUTH_DISABLED", "hosted authentication is not enabled on this server");
  }
  let svc = authServices.get(config);
  if (!svc) {
    const { HostedAuthService, PgAuthStore } = require("./auth");
    let providers = {};
    if (config.persistenceBackend === "postgres") {
      // The PG store must already be open (startup fails closed otherwise);
      // hosted challenges/sessions persist in the same database.
      const { getStore } = require("../../sdk/src/store");
      providers = { store: new PgAuthStore(getStore(config).pool(), config.networkId) };
    }
    svc = new HostedAuthService(config, providers);
    authServices.set(config, svc);
  }
  return svc;
}

/*
 * The public entry point (unchanged signature/export name — every caller,
 * test, and server.js keeps working identically). This is ONLY where two
 * NEW cross-cutting platform concerns are decided, both from
 * docs/postlaunch/platform-agent-api-spec.md:
 *   - the deny-by-default SCOPE gate for machine identities (surface 6) —
 *     wallet-session / self-hosted / unauthenticated callers are
 *     completely untouched by this block (principal.isMachine is only
 *     ever true for a resolved machine credential);
 *   - the Idempotency-Key wrapper (surface 14) — engages ONLY when a POST
 *     carries the header, so the shipped web client (which never sends
 *     it) and every existing test see zero behavior change.
 * dispatchRoute (below) is the COMPLETE original handler, renamed but
 * otherwise byte-identical — it has no knowledge of scopes or idempotency.
 */
async function handle(config, method, segments, query, body, ctx = {}) {
  const { isPublicRoute, isWalletSessionOnlyRoute, requiredScopesFor } = require("./scopes");
  let principal = null;
  if (!isPublicRoute(method, segments)) {
    // required:false — an ABSENT credential is fine here (routes make
    // their own required/optional decisions exactly as before); an
    // explicitly PRESENTED but INVALID one (bad cookie or bad machine
    // token) still throws from inside requestAuthPrincipal regardless of
    // this flag for a machine credential (see its own doc comment) —
    // never silently downgraded to "no one".
    principal = await requestAuthPrincipal(config, ctx, { required: false });
  }
  if (principal && principal.isMachine) {
    if (isWalletSessionOnlyRoute(method, segments)) {
      throw apiError(403, "MACHINE_IDENTITY_ROUTE_FORBIDDEN", "this route is wallet-session-only and is never reachable by a machine identity");
    }
    const requiredScopes = requiredScopesFor(method, segments, body);
    if (requiredScopes === null) {
      throw apiError(403, "SCOPE_FORBIDDEN", "this route is not reachable by any machine-identity scope (deny-by-default)");
    }
    const missing = requiredScopes.filter((s) => !principal.scopes.includes(s));
    if (missing.length) {
      throw apiError(403, "SCOPE_FORBIDDEN", `this operation requires scope(s) ${missing.join(", ")}, which this credential does not hold`);
    }
  }
  // /webhooks create/rotate responses carry a ONE-TIME signing secret,
  // and /identities create/mint responses carry the ONE-TIME machine
  // bearer token; idempotency records persist responses verbatim, so
  // these routes are excluded from Idempotency-Key replay — a plaintext
  // credential must never be written into idempotency_records
  // (conservative: the caller simply gets no replay dedup on these
  // mutations; a retried create mints a fresh identity/credential the
  // owner can revoke, which is a nuisance, never a secret at rest).
  // /notifications rule creation ACCEPTS a caller-supplied channel HMAC
  // secret in the body — same conservative exclusion (rule responses are
  // secret-stripped, but a secret-carrying mutation gets no replay dedup
  // rather than any chance of a secret at rest outside its sealed
  // envelope).
  const secretBearingRoute = segments[0] === "webhooks" || segments[0] === "identities" || segments[0] === "notifications";
  if (method === "POST" && !secretBearingRoute && ctx.headers && typeof ctx.headers.idempotencyKey === "string" && ctx.headers.idempotencyKey.length > 0) {
    const { withIdempotency } = require("./idempotency");
    return withIdempotency(
      config,
      { rawKey: ctx.headers.idempotencyKey, principal, method, segments, query, body },
      () => dispatchRoute(config, method, segments, query, body, ctx)
    );
  }
  return dispatchRoute(config, method, segments, query, body, ctx);
}

async function dispatchRoute(config, method, segments, query, body, ctx = {}) {
  // GET /capabilities — PUBLIC capability/version discovery document
  // (completion-standard surface 22; server/src/capabilities.js). Never
  // requires a principal or scope — see scopes.js isPublicRoute.
  if (method === "GET" && segments.length === 1 && segments[0] === "capabilities") {
    const { buildCapabilities } = require("./capabilities");
    return { status: 200, body: buildCapabilities(config) };
  }

  // GET /health — LIVENESS: the process is up and serving. Deliberately
  // cheap (no database or node dial) so orchestration liveness probes
  // never restart a healthy process because a dependency blinked.
  // buildId (when configured) is the non-secret deployment identity
  // (stale-deployment protection); staging marks a labeled
  // non-production deployment.
  if (method === "GET" && segments.length === 1 && segments[0] === "health") {
    return {
      status: 200,
      body: {
        ok: true,
        api: API_VERSION,
        networkId: config.networkId,
        authMode: config.authMode,
        ...(config.buildId ? { buildId: config.buildId } : {}),
        ...(config.stagingBanner ? { staging: true } : {})
      }
    };
  }

  /*
   * GET /metrics — OPERATIONAL OBSERVABILITY (fullscale surface 25;
   * server/src/metrics.js). Aggregate NON-SECRET numbers only (closed
   * schema: route-class counters/histograms, refusal codes, event outbox
   * + webhook delivery stats, governance/risk/suspension aggregates,
   * passive node-gate observation) — never tokens, addresses, keys, ids,
   * URLs, or per-tenant breakdowns; the scrape never dials the node.
   * ?format=prometheus returns hand-rolled text exposition over the SAME
   * document. Hosted mode requires an authenticated principal; machine
   * credentials additionally need the deny-by-default read:metrics scope
   * (scopes.js). Self-hosted mode is open to the single local operator,
   * like every other route there. NOTE (honest): scopes narrow ONE
   * credential's authority — any authenticated wallet could mint itself
   * read:metrics, so the endpoint's privacy rests on the closed
   * aggregate-only schema (the same class of numbers /health/ready
   * already exposes), not on the scope as a tenant boundary.
   */
  if (method === "GET" && segments.length === 1 && segments[0] === "metrics") {
    if (config.tenancyEnforced) await requestAuthPrincipal(config, ctx, { required: true });
    const metrics = require("./metrics");
    const doc = await metrics.buildMetricsDocument(config);
    if (query && query.format === "prometheus") {
      return { status: 200, rawBody: metrics.renderPrometheus(doc), headers: { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" } };
    }
    if (query && query.format !== undefined && query.format !== "json") {
      throw apiError(400, "BAD_FORMAT", 'format must be "json" or "prometheus"');
    }
    return { status: 200, body: doc };
  }

  /*
   * GET /health/ready — READINESS: the process can actually serve its
   * durable dependencies. postgres mode proves: store open + database
   * answering + schema exactly current + network stamp matching. json
   * mode proves the data root belongs to this network. Failure reports
   * 503 with a coarse machine-readable reason — never internals, never
   * credentials. The trusted kaspad tier is deliberately NOT part of
   * readiness (a node outage is an availability event surfaced via
   * /network/status; it must not make orchestration kill the app).
   */
  if (method === "GET" && segments.length === 2 && segments[0] === "health" && segments[1] === "ready") {
    const notReady = (reason) => ({
      status: 503,
      body: { ready: false, reason, networkId: config.networkId, ...(config.buildId ? { buildId: config.buildId } : {}) }
    });
    try {
      if (config.persistenceBackend === "postgres") {
        const { getStore } = require("../../sdk/src/store");
        let pool;
        try {
          pool = getStore(config).pool();
        } catch {
          return notReady("STORE_NOT_OPEN");
        }
        try {
          await pool.query("SELECT 1");
        } catch {
          return notReady("DATABASE_UNREACHABLE");
        }
        try {
          const { assertSchemaCurrent } = require("./migrate");
          await assertSchemaCurrent(pool);
        } catch {
          return notReady("SCHEMA_NOT_CURRENT");
        }
        try {
          const stamp = await pool.query(`SELECT value FROM pv_meta WHERE key = 'network'`);
          if (!stamp.rows[0] || stamp.rows[0].value !== config.networkId) return notReady("NETWORK_STAMP_MISMATCH");
        } catch {
          return notReady("DATABASE_UNREACHABLE");
        }
      } else {
        const fs = require("fs");
        const path = require("path");
        try {
          const marker = path.join(config.dataRoot, ".pv-network");
          if (!fs.existsSync(marker) || fs.readFileSync(marker, "utf8").trim() !== config.networkId) {
            return notReady("DATA_ROOT_NOT_STAMPED");
          }
        } catch {
          return notReady("DATA_ROOT_UNREADABLE");
        }
      }
      // Minimal webhook/event-delivery aggregate (surface 25 — sourced
      // from the SAME registry function GET /metrics uses,
      // server/src/metrics.js eventsAggregate, so readiness and metrics
      // can never drift apart): NON-SECRET NUMBERS ONLY (never URLs, ids,
      // or secret material) and NEVER load-bearing for readiness — a
      // webhook outage is a delivery problem, not a reason for
      // orchestration to kill the app.
      let eventsAggregate;
      try {
        eventsAggregate = await require("./metrics").eventsAggregate(config);
      } catch {
        eventsAggregate = undefined; // stats failure never degrades readiness
      }
      return {
        status: 200,
        body: {
          ready: true,
          networkId: config.networkId,
          persistence: config.persistenceBackend,
          ...(config.buildId ? { buildId: config.buildId } : {}),
          ...(config.stagingBanner ? { staging: true } : {}),
          ...(eventsAggregate ? { events: eventsAggregate } : {})
        }
      };
    } catch {
      return notReady("READINESS_CHECK_FAILED");
    }
  }

  /*
   * HOSTED AUTHENTICATION (Phase B — server/src/auth.js).
   * AUTHENTICATION != COVENANT AUTHORITY: these routes establish a
   * wallet-bound tenancy session and nothing else. No covenant route
   * consults the session for signing authority — owner/agent/approver
   * signature validation over frozen bytes is unchanged. The raw session
   * token travels ONLY in the HttpOnly cookie (never in JSON bodies).
   */
  if (segments[0] === "auth") {
    const { buildSessionCookie, buildClearCookie, sessionTokenFromCookieHeader } = require("./auth");
    const auth = authServiceFor(config);
    const cookieToken = sessionTokenFromCookieHeader(config, ctx.headers ? ctx.headers.cookie : undefined);

    // POST /auth/challenge  { walletAddress }
    if (method === "POST" && segments.length === 2 && segments[1] === "challenge") {
      const challenge = await auth.createChallenge(body ? body.walletAddress : undefined);
      return { status: 200, body: { challenge } };
    }

    // POST /auth/verify  { nonce, signature, publicKey, walletAddress? }
    // The signature is verified against the SERVER-reconstructed canonical
    // message; any client-submitted message text is ignored entirely.
    if (method === "POST" && segments.length === 2 && segments[1] === "verify") {
      const { token, session } = await auth.verify(
        {
          nonce: body ? body.nonce : undefined,
          signature: body ? body.signature : undefined,
          publicKey: body ? body.publicKey : undefined,
          walletAddress: body ? body.walletAddress : undefined
        },
        cookieToken
      );
      return { status: 200, body: { session }, headers: { "Set-Cookie": buildSessionCookie(config, token) } };
    }

    // GET /auth/session — non-secret status/restore surface. Always 200;
    // `authenticated:false` carries the machine-readable reason.
    if (method === "GET" && segments.length === 2 && segments[1] === "session") {
      if (!cookieToken) return { status: 200, body: { authenticated: false, reason: "SESSION_INVALID" } };
      try {
        const principal = await auth.resolveSession(cookieToken);
        return { status: 200, body: principal.presentation };
      } catch (e) {
        return { status: 200, body: { authenticated: false, reason: e.code || "SESSION_INVALID" } };
      }
    }

    // POST /auth/logout — revoke server-side + clear the cookie. Idempotent.
    if (method === "POST" && segments.length === 2 && segments[1] === "logout") {
      if (cookieToken) await auth.revokeByToken(cookieToken);
      return { status: 200, body: { ok: true }, headers: { "Set-Cookie": buildClearCookie(config) } };
    }

    throw apiError(404, "NOT_FOUND", "unknown auth route");
  }

  /*
   * ---- Machine (AI/agent) identity + credential management ----
   * (completion-standard surface 6; server/src/machine-identity.js).
   * WALLET-SESSION-ONLY BY STRUCTURAL RULE (never scope-gated, never
   * reachable by a machine credential at all — see scopes.js
   * isWalletSessionOnlyRoute and its doc comment: a token must never be
   * able to mint or widen its own — or a sibling's — authority).
   */
  if (segments[0] === "identities") {
    const mi = require("./machine-identity");
    const principal = await requestAuthPrincipal(config, ctx, { required: true });
    if (principal.isMachine) {
      throw apiError(403, "MACHINE_IDENTITY_ROUTE_FORBIDDEN", "machine-identity management requires a wallet session, never a machine credential");
    }

    // POST /identities  { label?, scopes: [...], orgId? }
    if (method === "POST" && segments.length === 1) {
      const { identity, credential } = await mi.createIdentity(config, {
        creatorXOnly: principal.xOnlyPubkey,
        orgId: body?.orgId,
        label: body?.label,
        scopes: body?.scopes
      });
      // Platform event (surface 18): identity metadata only — NEVER the
      // token, NEVER its hash (events.js's closed per-type field list is
      // the second wall). Failure-isolated notification.
      await require("./events").safeEmitPlatformEvent(config, {
        type: "identity.created",
        orgId: identity.orgId,
        correlation: { identityId: identity.identityId },
        data: { label: identity.label, scopes: identity.scopes, creatorXOnly: identity.creatorXOnly }
      });
      return {
        status: 201,
        body: { identity: mi.presentIdentity(identity), credential: { ...mi.presentCredential(credential.record), token: credential.token } }
      };
    }
    // GET /identities — the caller's own machine identities only.
    if (method === "GET" && segments.length === 1) {
      const identities = await mi.listIdentitiesForCreator(config, principal.xOnlyPubkey);
      return { status: 200, body: { identities: identities.map(mi.presentIdentity) } };
    }
    // GET /identities/:id
    if (method === "GET" && segments.length === 2) {
      const identity = await mi.getIdentityScoped(config, segments[1], principal.xOnlyPubkey);
      const credentials = await mi.listCredentialsForIdentity(config, segments[1]);
      return { status: 200, body: { identity: mi.presentIdentity(identity), credentials: credentials.map(mi.presentCredential) } };
    }
    // POST /identities/:id/credentials  { label? } -> mint an ADDITIONAL credential (rotation)
    if (method === "POST" && segments.length === 3 && segments[2] === "credentials") {
      const { record, token } = await mi.mintCredential(config, { identityId: segments[1], creatorXOnly: principal.xOnlyPubkey, label: body?.label });
      await require("./events").safeEmitPlatformEvent(config, {
        type: "identity.credential.minted",
        correlation: { identityId: record.identityId },
        data: { credentialId: record.credentialId, creatorXOnly: principal.xOnlyPubkey }
      });
      return { status: 201, body: { credential: { ...mi.presentCredential(record), token } } };
    }
    // POST /identities/:id/credentials/:credentialId/revoke
    if (method === "POST" && segments.length === 5 && segments[2] === "credentials" && segments[4] === "revoke") {
      const record = await mi.revokeCredential(config, { identityId: segments[1], credentialId: segments[3], creatorXOnly: principal.xOnlyPubkey });
      await require("./events").safeEmitPlatformEvent(config, {
        type: "identity.credential.revoked",
        correlation: { identityId: record.identityId },
        data: { credentialId: record.credentialId, creatorXOnly: principal.xOnlyPubkey }
      });
      return { status: 200, body: { credential: mi.presentCredential(record) } };
    }
    // POST /identities/:id/revoke — revokes the identity AND every credential it ever minted.
    if (method === "POST" && segments.length === 3 && segments[2] === "revoke") {
      const identity = await mi.revokeIdentity(config, { identityId: segments[1], creatorXOnly: principal.xOnlyPubkey });
      await require("./events").safeEmitPlatformEvent(config, {
        type: "identity.revoked",
        orgId: identity.orgId,
        correlation: { identityId: identity.identityId },
        data: { label: identity.label, creatorXOnly: identity.creatorXOnly }
      });
      return { status: 200, body: { identity: mi.presentIdentity(identity) } };
    }
    throw apiError(404, "NOT_FOUND", "unknown identities route");
  }

  // GET /support — the voluntary-support (donation) surface. The address is
  // an explicitly configured PUBLIC mainnet address (never derived from any
  // wallet/vault/test key) and is served ONLY after canonical validation;
  // a misconfigured/testnet/malformed address fails closed to `support: null`
  // with the exact validation error surfaced for the operator.
  if (method === "GET" && segments.length === 1 && segments[0] === "support") {
    const { validateDonationAddress } = require("../../sdk/src/donation-address");
    try {
      const donation = validateDonationAddress(config, config.donationAddress);
      return { status: 200, body: { support: { donation } } };
    } catch (e) {
      return { status: 200, body: { support: null, reason: e.code || "DONATION_INVALID", message: e.message } };
    }
  }

  // POST /identity/resolve-address  { address }
  // The single address->pubkey boundary for browser clients: normal users
  // enter wallet addresses; this resolves them to the canonical x-only
  // form via the shared SDK utility (WASM-backed). Fail-closed 422s carry
  // user-facing messages; strict pubkey validation downstream is unchanged.
  if (method === "POST" && segments.length === 2 && segments[0] === "identity" && segments[1] === "resolve-address") {
    const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
    try {
      const identity = resolveAddressIdentity(config, body?.address);
      return { status: 200, body: { identity, expectedNetwork: config.networkId } };
    } catch (error) {
      throw apiError(error.status || 422, error.code || "ADDRESS_INVALID", error.message);
    }
  }

  // ---- Wallet request pipeline (browser signing flow) ----
  const walletRequests = require("../../sdk/src/wallet-requests-v2");

  // POST /wallet/create  { templateInput, initialStateInput, signerAddress, delegateFuelSompi?, label? }
  if (method === "POST" && segments.length === 2 && segments[0] === "wallet" && segments[1] === "create") {
    // LEGACY CREATION IS PRODUCTION-DISABLED (Checkpoint I §4): new vaults use
    // the current protocol (v0.4.1). Existing legacy vaults remain fully
    // supported (display / verify / manage / recover / audit) — only NEW
    // legacy creation is gated, behind an explicit developer flag.
    if (process.env.POLICYVAULT_LEGACY_CREATE !== "1") {
      throw apiError(403, "LEGACY_CREATE_DISABLED", "Legacy v0.2 vault creation is disabled in production. New vaults use the current protocol; existing legacy vaults remain fully supported. Set POLICYVAULT_LEGACY_CREATE=1 for development use only.");
    }
    const { templateInput, initialStateInput, signerAddress, delegateFuelSompi, label } = body ?? {};
    if (typeof signerAddress !== "string" || !signerAddress.startsWith("kaspatest:")) {
      throw apiError(400, "BAD_SIGNER", "signerAddress must be a testnet address");
    }
    // Fail closed with a precise diagnosis when a client sends a raw
    // 33-byte compressed provider pubkey (KasWare getPublicKey form) as
    // the owner: normalization belongs at the wallet-adapter boundary,
    // never here — template validation stays strict x-only.
    if (typeof templateInput?.owner === "string" && /^0[23][0-9a-fA-F]{64}$/.test(templateInput.owner.trim())) {
      throw apiError(422, "COMPRESSED_OWNER_PUBKEY", "template.owner is a 33-byte compressed provider public key; the wallet adapter must normalize it to 32-byte x-only hex (normalizePublicKeyToXOnly)");
    }
    await assertOpenRequestQuota(config, { signerAddress });
    try {
      const request = await walletRequests.buildCreateWalletRequestV2({ config, templateInput, initialStateInput, signerAddress, delegateFuelSompi: delegateFuelSompi ?? "0", label: label ?? "" });
      return { status: 201, body: { request: presentRequest(request) } };
    } catch (error) {
      const authz = ["NOT_OWNER", "NOT_DELEGATE", "AUTHORIZATION_FAILED"].includes(error.code);
      throw apiError(authz ? 403 : 422, error.code || "BUILD_FAILED", error.message);
    }
  }

  // POST /wallet/requests  { vaultId, action, params, signerAddress }
  if (method === "POST" && segments.length === 2 && segments[0] === "wallet" && segments[1] === "requests") {
    const { vaultId, action, params, signerAddress } = body ?? {};
    if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) {
      throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
    }
    if (typeof action !== "string" || !action) {
      throw apiError(400, "BAD_ACTION", "action is required");
    }
    if (typeof signerAddress !== "string" || !signerAddress.startsWith("kaspatest:")) {
      throw apiError(400, "BAD_SIGNER", "signerAddress must be a testnet address");
    }
    await assertOpenRequestQuota(config, { vaultId, signerAddress });
    try {
      const request = await walletRequests.buildWalletRequestV2({ config, vaultId, action, params: params ?? {}, signerAddress });
      return { status: 201, body: { request: presentRequest(request) } };
    } catch (error) {
      const authz = ["NOT_OWNER", "NOT_DELEGATE", "AUTHORIZATION_FAILED"].includes(error.code);
      throw apiError(authz ? 403 : 422, error.code || "BUILD_FAILED", error.message);
    }
  }

  // POST /wallet/requests/:id/signature  { signedSafeJson }
  if (method === "POST" && segments.length === 4 && segments[0] === "wallet" && segments[1] === "requests" && segments[3] === "signature") {
    const requestId = segments[2];
    const { signedSafeJson } = body ?? {};
    if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) {
      throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
    }
    await requireRequestAccess(config, ctx, await walletRequests.loadRequest(config, requestId));
    try {
      const request = await walletRequests.attachWalletSignatureV2({ config, requestId, signedSafeJson });
      return { status: 200, body: { request: presentRequest(request) } };
    } catch (error) {
      const request = await walletRequests.loadRequest(config, requestId);
      throw apiError(422, error.code || "FINALIZE_FAILED", error.message, { request: presentRequest(request) });
    }
  }

  // POST /wallet/requests/:id/reject  (user declined in the wallet)
  if (method === "POST" && segments.length === 4 && segments[0] === "wallet" && segments[1] === "requests" && segments[3] === "reject") {
    await requireRequestAccess(config, ctx, await walletRequests.loadRequest(config, segments[2]));
    const request = await walletRequests.markWalletRejected(config, segments[2]);
    if (!request) {
      throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[2]}`);
    }
    return { status: 200, body: { request: presentRequest(request) } };
  }

  // GET /wallet/requests/:id
  if (method === "GET" && segments.length === 3 && segments[0] === "wallet" && segments[1] === "requests") {
    const request = await walletRequests.loadRequest(config, segments[2]);
    await requireRequestAccess(config, ctx, request); // hosted: 401 unauth / 404 foreign|missing
    if (!request) {
      throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[2]}`);
    }
    return { status: 200, body: { request: presentRequest(request) } };
  }

  // ---- v0.4 wallet request pipeline (OFFLINE: BUILD -> approvals -> sign
  //      -> FINALIZE -> production covenant VM preflight; NO broadcast) ----
  if (segments[0] === "wallet" && segments[1] === "v4") {
    const wr4 = require("../../sdk/src/wallet-requests-v4");

    /*
     * POSTLAUNCH SERVER ENFORCEMENT (governance + risk + intent-manifest
     * recording — completion-standard items 3/5/7). All of it is hosted
     * COORDINATION and defense in depth ABOVE the covenant boundary: the
     * Kaspa covenant (owner/agent/approver signatures over frozen bytes,
     * verified by consensus) remains the only financial authority; these
     * gates can only make the hosted workflow MORE restrictive, never
     * authorize anything, and are documented as such
     * (docs/postlaunch/server-integration.md).
     *
     * finishBuiltV4Request: after a successful SDK build, derive+verify
     * the intent manifest from the REAL builder output, persist the
     * create-only manifest record, stamp request.manifestHash (+ the
     * consumed risk evaluation), record the consumed proposal, and fail
     * closed on a non-passing verdict (the durable request stays as
     * evidence but is refused here AND at finalize/submit).
     */
    const finishBuiltV4Request = async (request, { consumedProposal = null, riskGate = null } = {}) => {
      const { recordManifestForRequest } = require("./intent-records");
      const governance = require("./governance");
      const riskSvc = require("./risk");
      let rec;
      try {
        rec = await recordManifestForRequest(config, request, {
          proposalId: consumedProposal ? consumedProposal.record.proposalId : null
        });
      } catch (error) {
        // Derivation itself failed (bridge refusal / internal defect).
        // The durable request must NOT be mistakable for one that merely
        // predates manifest recording: mark it, so the finalize/submit
        // gate refuses it (fail closed), then refuse this response.
        request.intentRecording = "FAILED";
        await wr4.saveRequest(config, request);
        await appendAudit(config, {
          kind: "intent",
          vaultId: request.vaultId,
          action: request.action,
          actor: request.signerRole ?? "owner",
          actorXOnly: request.signerXOnly ?? null,
          result: "FAIL_CLOSED",
          detail: `intent manifest derivation failed (${error.code ?? "INTENT_DERIVATION_FAILED"}): ${error.message}`,
          requestId: request.requestId,
          txId: request.txId
        });
        throw apiError(422, error.code ?? "INTENT_DERIVATION_FAILED", `intent manifest derivation failed — refusing: ${error.message}`, {
          request: presentRequest(request)
        });
      }
      request.manifestHash = rec.manifestHash;
      if (riskGate && !riskGate.skipped) request.riskEvaluationId = riskGate.evaluationId;
      await wr4.saveRequest(config, request);
      if (!rec.ok) {
        throw apiError(422, "INTENT_VERIFICATION_FAILED", `the built transaction failed intent-manifest verification (${rec.verdict}) — refusing`, {
          request: presentRequest(request),
          intent: { manifestHash: rec.manifestHash, failureCodes: rec.record.verification.failureCodes }
        });
      }
      if (consumedProposal) {
        await governance.markProposalConsumed(config, consumedProposal.record, { requestId: request.requestId, txId: request.txId });
        await appendAudit(config, {
          kind: "governance",
          vaultId: request.vaultId,
          action: request.action,
          actor: request.signerRole,
          actorXOnly: request.signerXOnly ?? null,
          contractVersion: request.contractVersion,
          result: "GOVERNANCE_ENFORCED",
          detail: `AUTHORITY EXPANSION executed under proposal ${consumedProposal.record.proposalId} (owner-signature-verified approval path)`,
          requestId: request.requestId,
          manifestHash: rec.manifestHash,
          proposalId: consumedProposal.record.proposalId,
          txId: request.txId
        });
      }
      if (riskGate) await riskSvc.recordRiskOutcome(config, riskGate, { requestId: request.requestId, txId: request.txId });
      // Platform event (surface 18): a durable, intent-verified request
      // now exists. Notification only, failure-isolated (never throws,
      // never fails the request).
      await require("./events").safeEmitPlatformEvent(config, {
        type: "request.built",
        vaultId: request.vaultId ?? null,
        correlation: {
          requestId: request.requestId,
          manifestHash: request.manifestHash,
          proposalId: consumedProposal ? consumedProposal.record.proposalId : undefined,
          riskEvaluationId: request.riskEvaluationId
        },
        data: {
          action: request.action,
          contractVersion: request.contractVersion,
          state: request.state,
          aboveThreshold: request.aboveThreshold === true,
          signerRole: request.signerRole
        }
      });
      return request;
    };

    /* Finalize/submit-time intent gate: a manifest-stamped request must
     * re-verify VERIFIED_EXACT NOW (G-2 read-side re-hash included);
     * requests predating manifest recording pass unchanged. */
    const assertManifestGate = async (request) => {
      const { assertRequestManifestVerified } = require("./intent-records");
      await assertRequestManifestVerified(config, request);
    };
    const v4Error = (error) => {
      const authz = ["NOT_OWNER", "NOT_AGENT", "AUTHORIZATION_FAILED"].includes(error.code);
      const stateCodes = ["STALE", "CLAIM_CONFLICT", "PREFLIGHT_FAILED", "SIGNATURE_INVALID", "INSUFFICIENT_APPROVALS", "WALLET_REJECTED"];
      const status = authz ? 403 : stateCodes.includes(error.code) ? 409 : 422;
      return apiError(status, error.code || "BUILD_FAILED", error.message);
    };

    /*
     * INSTANT HOSTED-LAYER AGENT SUSPEND enforcement (surface 21 residual;
     * server/src/agent-suspensions.js — coordination control ONLY, never a
     * covenant control; the refusal text says so verbatim). Gates every
     * AGENT-role stage: build (before any durable work — a refusal is
     * pure), finalize, and submit; owner actions (including the
     * break-glass ownerPause/ownerRecover) are never touched. The acting
     * agent is attributed by EVERY identity the stage can see
     * (params/request agentPk + the resolved signer wallet) — any match
     * refuses. A corrupt suspension record throws (restrictive): a
     * security-configuration record this build cannot read must never
     * fail open.
     */
    const assertAgentNotSuspended = async ({ vaultId, action, agentPk, signerAddress, stage }) => {
      if (wr4.ROLE_BY_ACTION[action] !== "agent") return;
      const agentPks = [];
      if (typeof agentPk === "string" && /^[0-9a-f]{64}$/.test(agentPk)) agentPks.push(agentPk);
      if (typeof signerAddress === "string") {
        try {
          agentPks.push(require("../../sdk/src/address-identity").resolveAddressIdentity(config, signerAddress).xOnlyPubkey);
        } catch {
          /* the SDK authorization gate reports the precise signer error */
        }
      }
      const { checkAgentSuspension, suspendedError } = require("./agent-suspensions");
      const check = await checkAgentSuspension(config, vaultId, agentPks);
      if (check.suspended) throw suspendedError(check, stage);
    };
    // Gate R: the v0.4 family serves the CONFIGURED network — signer/approver
    // addresses must carry that network's canonical prefix (kaspatest: on
    // testnet-10, kaspa: on mainnet). Full validation happens in the SDK.
    const requiredPrefix = `${require("../../sdk/src/address-identity").requiredAddressPrefix(config.networkId)}:`;
    const badSignerMsg = (field) => `${field} must be a ${config.networkId} address (${requiredPrefix}...)`;
    const badSigner = (a) => typeof a !== "string" || !a.startsWith(requiredPrefix);

    /*
     * Versioned platform schemas (completion-standard surface 23;
     * server/src/api-version.js). ADDITIVE: `schemaVersion` in the request
     * body is OPTIONAL — omitting it (every existing caller, including the
     * shipped web client) is unchanged. If PRESENT, an unrecognized value
     * fails CLOSED (never routed to a default/best-guess handler).
     */
    const assertSchemaVersion = (b) => {
      if (b && b.schemaVersion !== undefined && b.schemaVersion !== V4_WALLET_REQUEST_SCHEMA_VERSION) {
        throw apiError(422, "SCHEMA_VERSION_UNSUPPORTED", `unsupported schemaVersion ${JSON.stringify(b.schemaVersion)} — this build supports ${JSON.stringify(V4_WALLET_REQUEST_SCHEMA_VERSION)} (or omit the field entirely)`);
      }
    };
    const v4Body = (obj) => ({ ...obj, schemaVersion: V4_WALLET_REQUEST_SCHEMA_VERSION });

    // POST /wallet/v4/create   { ..., contractVersion? }
    // Two schemas:
    //  - canonical (tools/tests): { templateInput, initialAgents, initialState, funding }
    //  - friendly (browser, §2–§14): { vaultId, label, depositKas, feeReserveKas,
    //    agent:{ agentAddress, maxPerSpendKas, budgetKas, budgetPeriod, approvalThresholdKas,
    //    maxFeePerTxKas?, recipientAddresses[] }, approvers?:{ addresses[], approvalM }, funding? }.
    // The friendly schema is normalized to the IDENTICAL canonical shape here,
    // server-side (§26): owner x-only from the signer, node-derived periodStartDaa,
    // periodSpent=0, KAS→sompi, addresses→x-only. The browser never supplies
    // consensus-visible values.
    if (method === "POST" && segments.length === 3 && segments[2] === "create") {
      const { templateInput, initialAgents, initialState, signerAddress, funding, label, contractVersion, vaultId, depositKas, feeReserveKas, agent, approvers } = body ?? {};
      assertSchemaVersion(body);
      if (badSigner(signerAddress)) throw apiError(400, "BAD_SIGNER", badSignerMsg("signerAddress"));
      await assertOpenRequestQuota(config, { signerAddress });
      try {
        if (agent) {
          // ---- friendly schema -> canonical, server-authoritative ----
          const { kasToSompi } = require("../../sdk/src/amounts");
          const { normalizeAgentPolicyInputV4, normalizeApproversInputV4 } = require("../../sdk/src/ux-normalize-v4");
          const { resolveAddressIdentity } = require("../../sdk/src/address-identity");
          const { getAddressUtxos } = require("../../sdk/src/chain");
          if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
          const ownerXOnly = resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
          const depositSompi = kasToSompi(depositKas, "deposit");
          const reserveSompi = kasToSompi(feeReserveKas, "feeReserve");
          if (depositSompi <= 0n) throw apiError(422, "BAD_DEPOSIT", "deposit must be > 0 KAS");
          const { rpc } = await connectVerified(config);
          let policy, appr, chosenFunding;
          try {
            const daa = await getVirtualDaaScore(rpc);
            policy = normalizeAgentPolicyInputV4(config, agent, daa); // periodStartDaa = daa, periodSpent = 0
            appr = normalizeApproversInputV4(config, approvers ?? {});
            if (Array.isArray(funding) && funding.length) {
              chosenFunding = funding;
            } else {
              const need = depositSompi + reserveSompi;
              const utxos = (await getAddressUtxos(rpc, signerAddress)).filter((u) => u.covenantId === null && u.amount > need).sort((a, b) => (a.amount < b.amount ? 1 : -1));
              if (!utxos.length) throw apiError(422, "INSUFFICIENT_FUNDS", `no owner UTXO covering ${depositKas} + ${feeReserveKas} KAS + fee — fund the owner address first`);
              chosenFunding = [{ outpoint: utxos[0].outpoint, amount: utxos[0].amount.toString(), scriptPublicKeyHex: utxos[0].scriptPublicKeyHex }];
            }
          } finally {
            await rpc.disconnect();
          }
          const request = await Promise.resolve(wr4.buildCreateWalletRequestV4({
            config,
            contractVersion: contractVersion ?? "policyvault-0.4.1",
            templateInput: { owner: ownerXOnly, vaultId },
            initialAgents: [{ ...policy, recipients: policy.recipients }],
            initialState: { protectedValue: depositSompi.toString(), feeReserve: reserveSompi.toString(), approvers: appr.approvers, approvalM: appr.approvalM },
            signerAddress,
            funding: chosenFunding,
            label: label ?? ""
          }));
          // Genesis is manifest-bearing (kind "genesis"): record + verify.
          // No governance gate (no before-state — creation is the owner's
          // own signed act) and no risk gate (a not-yet-created vault has
          // no organization assignment).
          await finishBuiltV4Request(request);
          return { status: 201, body: v4Body({ request: presentRequest(request) }) };
        }
        // ---- canonical schema (backward compatible) ----
        const request = await Promise.resolve(wr4.buildCreateWalletRequestV4({ config, templateInput, initialAgents: initialAgents ?? [], initialState, signerAddress, funding, label: label ?? "", ...(contractVersion ? { contractVersion } : {}) }));
        await finishBuiltV4Request(request);
        return { status: 201, body: v4Body({ request: presentRequest(request) }) };
      } catch (error) {
        if (error.status) throw error;
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/requests  { vaultId, action, params, signerAddress,
    //                             proposalId?, riskEvaluationId? }
    if (method === "POST" && segments.length === 3 && segments[2] === "requests") {
      const { vaultId, action, params, signerAddress, proposalId, riskEvaluationId } = body ?? {};
      assertSchemaVersion(body);
      assertClosedBody(body, ["schemaVersion", "vaultId", "action", "params", "signerAddress", "proposalId", "riskEvaluationId"], "the v4 request body");
      if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
      if (typeof action !== "string" || !action) throw apiError(400, "BAD_ACTION", "action is required");
      if (badSigner(signerAddress)) throw apiError(400, "BAD_SIGNER", badSignerMsg("signerAddress"));
      // Instant hosted-layer suspend gate (agent-role actions only; PURE
      // refusal — nothing durable exists yet, no fees, no chain work).
      await assertAgentNotSuspended({ vaultId, action, agentPk: params && params.agentPk, signerAddress, stage: "build this request" });
      await assertOpenRequestQuota(config, { vaultId, signerAddress });
      try {
        /*
         * INTENT-STAGE ENFORCEMENT, before any durable request exists (a
         * refusal here is pure). Order: governance first (the authority-
         * delta gate — recomputed from actual before/after policy at this
         * consumption point; stored labels distrusted), then the
         * organization's risk pipeline. Break-glass owner actions
         * (ownerPause freeze, terminal ownerRecover) bypass BOTH gates by
         * construction: no configuration may delay or block them
         * (governance-spec §6.1) — they proceed straight to the build,
         * where the covenant's own rules still apply in full.
         */
        const governance = require("./governance");
        const riskSvc = require("./risk");
        const { controlsForVault } = require("./org-controls");
        const { loadManifestV4 } = require("../../sdk/src/manifest-v4");
        const gvManifest = await loadManifestV4(config, vaultId); // null/legacy -> SDK build path reports its own error
        let consumedProposal = null;
        let riskGate = null;
        // Actions the SDK pipeline itself does not know keep their original
        // fail-closed refusal (ROLE_BY_ACTION -> BUILD_FAILED). An action
        // the SDK DOES know but the governance matrix does not is refused
        // by classifyActionV4 — a new operation can never be silently
        // ungoverned.
        if (gvManifest && gvManifest.live && wr4.ROLE_BY_ACTION[action]) {
          const gate = governance.classifyActionV4(config, gvManifest, action, params ?? {}); // unknown/malformed -> fail closed
          const breakGlass = gate.breakGlass === true;
          const { orgId, controls } = breakGlass ? { orgId: null, controls: null } : await controlsForVault(config, vaultId);
          if (gate.governed) {
            if (gate.classification === "EXPANSION") {
              consumedProposal = await governance.requireApprovedProposal({
                config, manifest: gvManifest, vaultId, action, params: params ?? {}, proposalId, gate, controls
              });
            } else {
              // REDUCTION lane: immediately available to the owner; audited.
              await appendAudit(config, {
                kind: "governance", vaultId, action, actor: "owner", actorXOnly: null,
                result: "GOVERNANCE_REDUCTION",
                detail: `authority REDUCTION [${gate.codes.join(", ")}] — lighter lane (no proposal required)`
              });
            }
          }
          if (!breakGlass) {
            let signerXOnly = null;
            try {
              signerXOnly = require("../../sdk/src/address-identity").resolveAddressIdentity(config, signerAddress).xOnlyPubkey;
            } catch {
              signerXOnly = null; // the SDK authorization gate reports the precise error
            }
            const { HIGH_LEVEL_TO_SDK } = require("../../core/intent");
            riskGate = await riskSvc.gateOperationRisk({
              config, vaultId, orgId, controls, action, params: params ?? {},
              signerAddress, signerXOnly, sdkAction: HIGH_LEVEL_TO_SDK[action] ?? action, riskEvaluationId
            });
          }
        }
        const request = await wr4.buildWalletRequestV4({ config, vaultId, action, params: params ?? {}, signerAddress });
        await finishBuiltV4Request(request, { consumedProposal, riskGate });
        return { status: 201, body: v4Body({ request: presentRequest(request) }) };
      } catch (error) {
        if (error.status) throw error;
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/simulate  { vaultId, action, params, signerAddress }
    // Dry-run / simulation (completion-standard surface 16;
    // server/src/simulate.js): runs the SAME governance/risk/build/intent
    // pipeline as POST /wallet/v4/requests above but PERSISTS NOTHING and
    // CONSUMES NO GATES — no saveRequest, no proposal consumption, no risk
    // evidence record, no audit row. Never broadcasts (nothing here is
    // even a FINALIZED transaction). A well-formed request always answers
    // 200 with `ok:true|false` — see simulate.js's header comment for
    // exactly which failures become `refusalReason` versus a real HTTP
    // error (malformed input only).
    if (method === "POST" && segments.length === 3 && segments[2] === "simulate") {
      assertSchemaVersion(body);
      assertClosedBody(body, ["schemaVersion", "vaultId", "action", "params", "signerAddress"], "the v4 simulate body");
      const { simulateWalletRequestV4 } = require("./simulate");
      const simulation = await simulateWalletRequestV4(config, body ?? {});
      return { status: 200, body: v4Body({ simulation }) };
    }

    // POST /wallet/v4/requests/:id/approvals  { approverAddress, signedSafeJson|signatureHex }
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "approvals") {
      const { approverAddress, signedSafeJson, signatureHex } = body ?? {};
      if (badSigner(approverAddress)) throw apiError(400, "BAD_APPROVER", badSignerMsg("approverAddress"));
      await requireRequestAccess(config, ctx, await wr4.loadRequest(config, segments[3]));
      try {
        const result = await wr4.collectApprovalV4({ config, requestId: segments[3], approverAddress, signedSafeJson, signatureHex });
        const presented = presentRequest(result.request);
        await require("./events").safeEmitPlatformEvent(config, {
          type: "request.approval.collected",
          vaultId: result.request.vaultId ?? null,
          correlation: { requestId: result.request.requestId, manifestHash: result.request.manifestHash },
          data: {
            action: result.request.action,
            collected: presented?.approvalProgress?.collected,
            required: presented?.approvalProgress?.required,
            complete: presented?.approvalProgress?.complete
          }
        });
        return { status: 200, body: v4Body({ request: presented, approvals: result.approvals }) };
      } catch (error) {
        throw v4Error(error);
      }
    }

    // POST /wallet/v4/requests/:id/signature  { signedSafeJson }  -> FINALIZE + PREFLIGHT
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "signature") {
      const { signedSafeJson } = body ?? {};
      if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
      const pendingRequest = await wr4.loadRequest(config, segments[3]);
      await requireRequestMutation(config, ctx, pendingRequest);
      if (pendingRequest) {
        // Instant hosted-layer suspend gate: a request built BEFORE the
        // suspension must not finalize while suspended.
        await assertAgentNotSuspended({ vaultId: pendingRequest.vaultId, action: pendingRequest.action, agentPk: pendingRequest.agentPk, signerAddress: pendingRequest.signerAddress, stage: "finalize this request" });
      }
      await assertManifestGate(pendingRequest); // manifest-stamped requests must re-verify VERIFIED_EXACT
      try {
        const request = await wr4.finalizeWalletRequestV4({ config, requestId: segments[3], signedSafeJson });
        await require("./events").safeEmitPlatformEvent(config, {
          type: "request.finalized",
          vaultId: request.vaultId ?? null,
          correlation: { requestId: request.requestId, manifestHash: request.manifestHash, txId: request.txId },
          data: { action: request.action, state: request.state }
        });
        return { status: 200, body: v4Body({ request: presentRequest(request) }) };
      } catch (error) {
        const request = await wr4.loadRequest(config, segments[3]);
        if (request) {
          await require("./events").safeEmitPlatformEvent(config, {
            type: "request.failed",
            vaultId: request.vaultId ?? null,
            correlation: { requestId: request.requestId, manifestHash: request.manifestHash },
            data: { action: request.action, stage: "finalize", code: error.code || "FINALIZE_FAILED" }
          });
        }
        const e = v4Error(error);
        e.extra = { request: presentRequest(request) };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/submit  -> LIVE broadcast of a FINALIZED
    // transition (build -> sign -> FINALIZE happened already). The SDK submit
    // path enforces config==request==manifest==node network agreement on an
    // operational network (testnet-10, or mainnet under the Gate R dual-flag
    // unlock); it verifies node-txid == frozen-txid, chain-proves the exact
    // successor, and advances the manifest+registry atomically.
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "submit") {
      const submit4 = require("../../sdk/src/wallet-submit-v4");
      const pendingSubmit = await wr4.loadRequest(config, segments[3]);
      await requireRequestMutation(config, ctx, pendingSubmit);
      if (pendingSubmit) {
        // Instant hosted-layer suspend gate: the LAST hosted stage — a
        // suspended agent's already-finalized request must not broadcast.
        await assertAgentNotSuspended({ vaultId: pendingSubmit.vaultId, action: pendingSubmit.action, agentPk: pendingSubmit.agentPk, signerAddress: pendingSubmit.signerAddress, stage: "submit this request" });
      }
      await assertManifestGate(pendingSubmit); // defense in depth: re-verify before broadcast
      try {
        const result = await submit4.submitWalletRequestV4({ config, requestId: segments[3] });
        require("./metrics").noteNodeGate(true); // chain proof = the node answered (passive observation)
        // Submit success in this pipeline IS chain proof (txid verified,
        // exact successor observed) — hence request.confirmed, and
        // deliberately no unproven "submitted" success event (spec §4.1).
        await require("./events").safeEmitPlatformEvent(config, {
          type: "request.confirmed",
          vaultId: result.request.vaultId ?? null,
          correlation: { requestId: result.request.requestId, manifestHash: result.request.manifestHash, txId: result.txId },
          data: { action: result.request.action, state: result.request.state, terminal: result.request.successorStateId == null }
        });
        return { status: 200, body: v4Body({ request: presentRequest(result.request), txId: result.txId, successorIndex: result.expected?.index ?? null }) };
      } catch (error) {
        const request = await wr4.loadRequest(config, segments[3]);
        if (request) {
          await require("./events").safeEmitPlatformEvent(config, {
            type: "request.failed",
            vaultId: request.vaultId ?? null,
            correlation: { requestId: request.requestId, manifestHash: request.manifestHash, txId: request.txId },
            data: { action: request.action, stage: "submit", code: error.code || "SUBMIT_FAILED" }
          });
        }
        const e = v4Error(error);
        e.extra = { request: request ? presentRequest(request) : null };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/genesis-submit  { signedSafeJson }  -> the
    // owner's KasWare-signed genesis funding is broadcast; the authoritative
    // manifest is created only AFTER the exact covenant output is chain-proven.
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "genesis-submit") {
      const { signedSafeJson } = body ?? {};
      if (typeof signedSafeJson !== "string" || !signedSafeJson.trim()) throw apiError(400, "BAD_SIGNATURE", "signedSafeJson is required");
      const submit4 = require("../../sdk/src/wallet-submit-v4");
      const pendingGenesis = await wr4.loadRequest(config, segments[3]);
      await requireRequestMutation(config, ctx, pendingGenesis);
      await assertManifestGate(pendingGenesis); // genesis manifests re-verify before broadcast too
      try {
        const result = await submit4.submitCreateWalletRequestV4({ config, requestId: segments[3], signedSafeJson });
        require("./metrics").noteNodeGate(true); // chain proof = the node answered (passive observation)
        const { safeEmitPlatformEvent } = require("./events");
        await safeEmitPlatformEvent(config, {
          type: "vault.created",
          vaultId: result.request.vaultId ?? null,
          correlation: { requestId: result.request.requestId, manifestHash: result.request.manifestHash, txId: result.txId },
          data: { contractVersion: result.request.contractVersion, label: result.request.label }
        });
        await safeEmitPlatformEvent(config, {
          type: "request.confirmed",
          vaultId: result.request.vaultId ?? null,
          correlation: { requestId: result.request.requestId, manifestHash: result.request.manifestHash, txId: result.txId },
          data: { action: result.request.action, state: result.request.state, terminal: false }
        });
        return { status: 200, body: v4Body({ request: presentRequest(result.request), txId: result.txId }) };
      } catch (error) {
        const request = await wr4.loadRequest(config, segments[3]);
        if (request) {
          await require("./events").safeEmitPlatformEvent(config, {
            type: "request.failed",
            vaultId: request.vaultId ?? null,
            correlation: { requestId: request.requestId, manifestHash: request.manifestHash, txId: request.txId },
            data: { action: request.action, stage: "genesis-submit", code: error.code || "SUBMIT_FAILED" }
          });
        }
        const e = v4Error(error);
        e.extra = { request: request ? presentRequest(request) : null };
        throw e;
      }
    }

    // POST /wallet/v4/requests/:id/reject
    if (method === "POST" && segments.length === 5 && segments[2] === "requests" && segments[4] === "reject") {
      await requireRequestMutation(config, ctx, await wr4.loadRequest(config, segments[3]));
      const request = await wr4.markWalletRejected(config, segments[3]);
      if (!request) throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
      await require("./events").safeEmitPlatformEvent(config, {
        type: "request.rejected",
        vaultId: request.vaultId ?? null,
        correlation: { requestId: request.requestId, manifestHash: request.manifestHash },
        data: { action: request.action, state: request.state }
      });
      return { status: 200, body: v4Body({ request: presentRequest(request) }) };
    }

    // GET /wallet/v4/requests?vaultId=&open=1 — durable request listing for
    // the approval inbox and reload-restore: the browser derives ALL pending
    // approval UI from this server state, never from its own memory.
    // open=1 -> the pre-finalize actionable states (AWAITING_APPROVALS, BUILT).
    if (method === "GET" && segments.length === 3 && segments[2] === "requests") {
      const states = query?.open ? [wr4.RequestState.AWAITING_APPROVALS, wr4.RequestState.BUILT] : undefined;
      const listed = await wr4.listWalletRequestsV4(config, { ...(query?.vaultId ? { vaultId: query.vaultId } : {}), ...(states ? { states } : {}) });
      // Hosted: scope to the principal's own requests (participant-or-signer);
      // the client-supplied vaultId can only narrow, never widen.
      const scoped = await scopeRequestsForPrincipal(config, ctx, listed);
      const requests = scoped.slice(0, 100).map(presentRequest);
      return { status: 200, body: v4Body({ requests }) };
    }

    // GET /wallet/v4/requests/:id
    if (method === "GET" && segments.length === 4 && segments[2] === "requests") {
      const request = await wr4.loadRequest(config, segments[3]);
      await requireRequestAccess(config, ctx, request); // hosted: 401 unauth / 404 foreign|missing
      if (!request) throw apiError(404, "REQUEST_NOT_FOUND", `no request ${segments[3]}`);
      return { status: 200, body: v4Body({ request: presentRequest(request) }) };
    }

    throw apiError(404, "NOT_FOUND", "unknown wallet/v4 route");
  }

  /*
   * ---- Post-launch GOVERNANCE surface (Program B server wiring) ----
   * Proposals, approvals, and cancellation for governed v0.4 policy
   * changes. Hosted tenancy wraps every route (participant/owner
   * scoping; foreign objects 404 — no existence oracle); the HTTP
   * layer's Host/Origin/rate-limit protections apply exactly as to
   * every other /api route (server.js + limits.js). Nothing here is
   * covenant authority: proposals/approvals gate the hosted WORKFLOW
   * only (server/src/governance.js header).
   */
  if (segments[0] === "governance") {
    const governance = require("./governance");
    const { controlsForVault } = require("./org-controls");
    const { vaultAccessAllowed, requireVaultAccess } = require("./tenancy");
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });

    /* A proposal is visible to the vault's covenant participants and to
     * the organization's configured governance-quorum wallets (who may
     * not be covenant participants but must fetch + sign the digest). */
    const proposalAccessAllowed = (record, loadedVault, controls) => {
      if (!config.tenancyEnforced) return true;
      if (!principal) return false;
      if (loadedVault && vaultAccessAllowed(config, loadedVault, principal, "read")) return true;
      const quorum = controls?.governance?.quorum;
      return Boolean(quorum && quorum.approvers.includes(principal.xOnlyPubkey));
    };
    const loadScopedProposal = async (proposalId) => {
      const record = await governance.loadProposalRecord(config, proposalId);
      if (!record) throw apiError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
      let loadedVault = null;
      try {
        loadedVault = await loadAnyManifest(config, record.proposal.vaultId);
      } catch {
        loadedVault = null;
      }
      const { controls } = await controlsForVault(config, record.proposal.vaultId);
      if (!proposalAccessAllowed(record, loadedVault, controls)) {
        throw apiError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal"); // hide existence
      }
      return { record, loadedVault, controls };
    };

    // POST /governance/proposals  { vaultId, action, params, expiresInMs? }
    if (method === "POST" && segments.length === 2 && segments[1] === "proposals") {
      const { vaultId, action, params, expiresInMs } = body ?? {};
      if (typeof vaultId !== "string" || !/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
      if (typeof action !== "string" || !action) throw apiError(400, "BAD_ACTION", "action is required");
      const loaded = await loadAnyManifest(config, vaultId);
      // Proposing is a vault-OWNER act (hosted); 404 hides foreign vaults.
      requireVaultAccess(config, loaded, principal, "owner");
      if (loaded.version !== "v4") throw apiError(422, "UNSUPPORTED_VERSION", "governance proposals cover the v0.4 family (legacy v0.2 policy ops are out of scope — docs/postlaunch/server-integration.md)");
      const record = await governance.createProposal({
        config,
        manifest: loaded.manifest,
        vaultId,
        action,
        params: params ?? {},
        proposedByXOnly: principal ? principal.xOnlyPubkey : loaded.manifest.template.owner,
        expiresInMs
      });
      return { status: 201, body: { proposal: await governance.presentProposal(config, record, loaded.manifest, (await controlsForVault(config, vaultId)).controls) } };
    }

    // GET /governance/proposals?vaultId=
    if (method === "GET" && segments.length === 2 && segments[1] === "proposals") {
      const vaultId = query?.vaultId;
      const records = await governance.listProposals(config, vaultId ? { vaultId } : {});
      const out = [];
      const vaultCache = new Map();
      for (const record of records.slice(0, 200)) {
        const vid = record.proposal.vaultId;
        if (!vaultCache.has(vid)) {
          let loadedVault = null;
          try {
            loadedVault = await loadAnyManifest(config, vid);
          } catch {
            loadedVault = null;
          }
          vaultCache.set(vid, { loadedVault, controls: (await controlsForVault(config, vid)).controls });
        }
        const { loadedVault, controls } = vaultCache.get(vid);
        if (!proposalAccessAllowed(record, loadedVault, controls)) continue; // server-side scoping, never a frontend filter
        out.push(await governance.presentProposal(config, record, loadedVault?.version === "v4" ? loadedVault.manifest : null, controls));
      }
      return { status: 200, body: { proposals: out.slice(0, clampLimit(query?.limit, 50, 200)) } };
    }

    // GET /governance/proposals/:id
    if (method === "GET" && segments.length === 3 && segments[1] === "proposals") {
      const { record, loadedVault, controls } = await loadScopedProposal(segments[2]);
      return { status: 200, body: { proposal: await governance.presentProposal(config, record, loadedVault?.version === "v4" ? loadedVault.manifest : null, controls) } };
    }

    // POST /governance/proposals/:id/approvals  { approverAddress, signature }
    // The signature — Schnorr over PersonalMessageSigningHash of the
    // SERVER-reconstructed canonical approval message — is what counts;
    // the session only gates route visibility. Verified with the same
    // kaspa.verifyMessage machinery hosted authentication uses.
    if (method === "POST" && segments.length === 4 && segments[1] === "proposals" && segments[3] === "approvals") {
      const { record, loadedVault, controls } = await loadScopedProposal(segments[2]);
      const { approverAddress, signature } = body ?? {};
      const result = await governance.collectProposalApproval({ config, proposalId: record.proposalId, approverAddress, signature });
      return { status: 200, body: { proposal: await governance.presentProposal(config, result.record, loadedVault?.version === "v4" ? loadedVault.manifest : null, controls) } };
    }

    // POST /governance/proposals/:id/cancel — always available to the owner.
    if (method === "POST" && segments.length === 4 && segments[1] === "proposals" && segments[3] === "cancel") {
      const { record } = await loadScopedProposal(segments[2]);
      const loaded = await loadAnyManifest(config, record.proposal.vaultId);
      requireVaultAccess(config, loaded, principal, "owner");
      const cancelled = await governance.cancelProposal({
        config,
        proposalId: record.proposalId,
        cancelledByXOnly: principal ? principal.xOnlyPubkey : loaded.manifest.template.owner
      });
      return { status: 200, body: { proposal: await governance.presentProposal(config, cancelled, loaded.version === "v4" ? loaded.manifest : null, (await controlsForVault(config, record.proposal.vaultId)).controls) } };
    }

    throw apiError(404, "NOT_FOUND", "unknown governance route");
  }

  /*
   * ---- Intent-manifest records (audit correlation, item 7) ----
   * GET /manifests/:hash — the stored manifest + recorded verdict,
   * tenant-scoped to the manifest's vault participants, with the
   * MANDATORY read-side canonical re-hash check (G-2) and a LIVE
   * re-verification (a stored verdict is a record of what the verifier
   * said then; the truth NOW is recomputed).
   */
  if (method === "GET" && segments.length === 2 && segments[0] === "manifests") {
    const { loadManifestRecord } = require("./intent-records");
    const { verifyIntentManifest } = require("../../core/intent");
    const record = await loadManifestRecord(config, segments[1]); // throws 409 on integrity mismatch
    if (config.tenancyEnforced) {
      const { requireVaultAccess } = require("./tenancy");
      const principal = await requestAuthPrincipal(config, ctx, { required: true });
      let loadedVault = null;
      if (record) {
        try {
          loadedVault = await loadAnyManifest(config, record.vaultId);
        } catch {
          loadedVault = null;
        }
      }
      if (!record || !loadedVault) throw apiError(404, "MANIFEST_NOT_FOUND", "no such manifest");
      requireVaultAccess(config, loadedVault, principal, "read"); // foreign -> 404
    }
    if (!record) throw apiError(404, "MANIFEST_NOT_FOUND", "no such manifest");
    const liveVerification = verifyIntentManifest({ manifest: record.manifest });
    return {
      status: 200,
      body: {
        manifestHash: record.manifestHash,
        manifest: record.manifest,
        verification: record.verification, // the verdict recorded when it was produced
        liveVerification: { verdict: liveVerification.verdict, ok: liveVerification.ok === true }, // recomputed NOW
        requestId: record.requestId,
        proposalId: record.proposalId,
        vaultId: record.vaultId,
        networkId: record.networkId,
        txId: record.txId
      }
    };
  }

  /*
   * ---- Risk evaluation evidence + REVIEW-hold release (Program D) ----
   */
  if (segments[0] === "risk" && segments[1] === "evaluations") {
    const riskSvc = require("./risk");
    const { vaultAccessAllowed, orgAccessAllowed } = require("./tenancy");
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });

    const loadScopedEvaluation = async (evaluationId, need) => {
      const record = await riskSvc.loadEvaluation(config, evaluationId);
      if (!record || record.schema !== riskSvc.RISK_EVALUATION_SCHEMA) {
        throw apiError(404, "RISK_EVALUATION_NOT_FOUND", "no such risk evaluation");
      }
      if (!config.tenancyEnforced) return record;
      let loadedVault = null;
      try {
        loadedVault = await loadAnyManifest(config, record.vaultId);
      } catch {
        loadedVault = null;
      }
      let org = null;
      if (record.orgId) {
        try {
          org = await require("../../sdk/src/organization").loadOrganization(config, record.orgId);
        } catch {
          org = null;
        }
      }
      if (need === "read") {
        const ok = (loadedVault && vaultAccessAllowed(config, loadedVault, principal, "read")) || (org && orgAccessAllowed(config, org, principal, "read"));
        if (!ok) throw apiError(404, "RISK_EVALUATION_NOT_FOUND", "no such risk evaluation"); // hide existence
      } else {
        // release: an authorized REVIEWER — the org tenantOwner or the
        // vault owner (v1 reviewer roles; the service additionally
        // forbids self-release by the initiating signer).
        const ok = (org && orgAccessAllowed(config, org, principal, "owner")) || (loadedVault && vaultAccessAllowed(config, loadedVault, principal, "owner"));
        if (!ok) throw apiError(404, "RISK_EVALUATION_NOT_FOUND", "no such risk evaluation");
      }
      return record;
    };

    // GET /risk/evaluations/:id — the durable evaluation evidence.
    if (method === "GET" && segments.length === 3) {
      const record = await loadScopedEvaluation(segments[2], "read");
      return { status: 200, body: { evaluation: record } };
    }

    // POST /risk/evaluations/:id/release — release a REVIEW hold for the
    // exact reviewed intent. The acting signer never releases their own
    // hold (enforced in the service from durable facts).
    if (method === "POST" && segments.length === 4 && segments[3] === "release") {
      await loadScopedEvaluation(segments[2], "release");
      const record = await riskSvc.releaseEvaluation(config, segments[2], {
        releasedByXOnly: principal ? principal.xOnlyPubkey : null
      });
      return { status: 200, body: { evaluation: record } };
    }

    throw apiError(404, "NOT_FOUND", "unknown risk route");
  }

  /*
   * ---- Asynchronous platform events: polling fallback (surface 18) ----
   * GET /events?cursor=&limit=&types=a,b — the SAME durable stream the
   * webhook deliverer reads, cursor-based, tenant-scoped server-side with
   * the SAME visibility rule deliveries use (events.js eventVisibleTo).
   * Events are notifications of durable state, never authority.
   */
  if (method === "GET" && segments.length === 1 && segments[0] === "events") {
    const { getEventsStore } = require("./events-store");
    const { eventVisibleTo, visibilityCaches, EVENT_TYPES, EVENTS_PAGE_SCHEMA, NOTIFICATION_NOTICE } = require("./events");
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });
    const limit = clampLimit(query?.limit, 100, 500);
    let types = null;
    if (typeof query?.types === "string" && query.types.trim()) {
      types = query.types.split(",").map((t) => t.trim()).filter(Boolean);
      for (const t of types) {
        if (t !== "*" && !EVENT_TYPES[t]) throw apiError(422, "EVENT_TYPE_UNKNOWN", `event type ${JSON.stringify(t)} is not in the closed catalog`);
      }
    }
    const store = getEventsStore(config);
    const caches = visibilityCaches();
    const out = [];
    let scanned = typeof query?.cursor === "string" && query.cursor !== "" ? query.cursor : "0";
    try {
      // Bounded forward scan: filtered/invisible rows advance the cursor
      // so a resumed client never re-scans them.
      for (let rounds = 0; rounds < 20 && out.length < limit; rounds++) {
        const batch = await store.listEventsAfter({ cursor: scanned, limit: 200, ...(types ? { types } : {}) });
        if (!batch.length) break;
        for (const row of batch) {
          scanned = row.cursor;
          if (await eventVisibleTo(config, row.event, principal, caches)) {
            out.push({ cursor: row.cursor, event: row.event });
            if (out.length >= limit) break;
          }
        }
      }
    } catch (error) {
      if (error.code === "EVENTS_CURSOR_INVALID") throw apiError(400, "BAD_CURSOR", error.message);
      throw error;
    }
    return {
      status: 200,
      body: {
        schemaVersion: EVENTS_PAGE_SCHEMA,
        notice: NOTIFICATION_NOTICE,
        events: out,
        nextCursor: scanned,
        latestCursor: await store.latestCursor()
      }
    };
  }

  /*
   * ---- Webhook endpoint management (surface 18) ----
   * Per-tenant subscriptions to the event stream. Tenancy inherits from
   * the creating wallet (creatorXOnly), exactly like machine identities;
   * foreign endpoints 404 (existence hidden). Machine credentials reach
   * these routes only with the webhooks:manage scope (scopes.js). The
   * signing secret appears EXACTLY ONCE in the create/rotate response and
   * never in listings, detail reads, logs, or idempotency records (these
   * routes are excluded from Idempotency-Key persistence in handle()).
   */
  if (segments[0] === "webhooks") {
    const wh = require("./webhooks");
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });
    const creatorXOnly = principal ? principal.xOnlyPubkey : null;
    const SECRET_NOTICE = "This signing secret is shown exactly once and cannot be retrieved again. Store it now; rotate the endpoint if it is lost.";

    // POST /webhooks  { url, eventTypes?, label? }
    if (method === "POST" && segments.length === 1) {
      const { endpoint, secret } = await wh.createEndpoint(config, { creatorXOnly, url: body?.url, eventTypes: body?.eventTypes, label: body?.label });
      return { status: 201, body: { endpoint: wh.presentEndpoint(endpoint), secret, secretNotice: SECRET_NOTICE } };
    }
    // GET /webhooks — the caller's own endpoints only.
    if (method === "GET" && segments.length === 1) {
      const endpoints = await wh.listEndpointsForCreator(config, creatorXOnly);
      return { status: 200, body: { endpoints: endpoints.map(wh.presentEndpoint) } };
    }
    // GET /webhooks/:id — endpoint + delivery monitoring view (counters,
    // cursor, bounded recent-attempt log, dead letters). No secrets.
    if (method === "GET" && segments.length === 2) {
      const endpoint = await wh.requireOwnedEndpoint(config, segments[1], creatorXOnly);
      const { Categories, getEventsStore } = require("./events-store");
      const store = getEventsStore(config);
      const stateRec = await store.read(Categories.WEBHOOK_DELIVERY_STATE, endpoint.endpointId);
      const deadLetters = (await store.listValues(Categories.WEBHOOK_DEAD_LETTER)).filter((r) => r && r.endpointId === endpoint.endpointId);
      deadLetters.sort((a, b) => String(b.deadLetteredAt).localeCompare(String(a.deadLetteredAt)));
      return {
        status: 200,
        body: {
          endpoint: wh.presentEndpoint(endpoint),
          delivery: stateRec
            ? {
                cursor: stateRec.cursor,
                counters: stateRec.counters,
                pending: stateRec.pending
                  ? { eventId: stateRec.pending.eventId, attempts: stateRec.pending.attempts, nextAttemptAtMs: stateRec.pending.nextAttemptAtMs }
                  : null,
                recentAttempts: stateRec.recentAttempts ?? []
              }
            : null,
          deadLetters: deadLetters.slice(0, 50).map((dl) => ({
            eventId: dl.eventId,
            type: dl.event ? dl.event.type : null,
            cursor: dl.cursor,
            attempts: dl.attempts,
            lastHttpStatus: dl.lastHttpStatus,
            lastErrorCode: dl.lastErrorCode,
            firstAttemptAt: dl.firstAttemptAt,
            deadLetteredAt: dl.deadLetteredAt
          }))
        }
      };
    }
    // POST /webhooks/:id/rotate-secret — new secret returned once; the
    // previous secret co-signs deliveries for the rotation grace window.
    if (method === "POST" && segments.length === 3 && segments[2] === "rotate-secret") {
      const { endpoint, secret } = await wh.rotateEndpointSecret(config, { endpointId: segments[1], creatorXOnly });
      return { status: 200, body: { endpoint: wh.presentEndpoint(endpoint), secret, secretNotice: SECRET_NOTICE } };
    }
    // POST /webhooks/:id/revoke — terminal disable (deliveries stop).
    if (method === "POST" && segments.length === 3 && segments[2] === "revoke") {
      const endpoint = await wh.revokeEndpoint(config, { endpointId: segments[1], creatorXOnly });
      return { status: 200, body: { endpoint: wh.presentEndpoint(endpoint) } };
    }
    throw apiError(404, "NOT_FOUND", "unknown webhooks route");
  }

  /*
   * ---- Human-notification rules (fullscale surface 19) ----
   * Per-tenant notification subscriptions over the SAME durable event
   * stream (a second consumer group — server/src/notifications.js +
   * notify-delivery.js). Tenancy inherits from the creating wallet
   * exactly like webhooks; foreign rules 404 (existence hidden). Machine
   * credentials need read:notifications / notifications:manage
   * (scopes.js, deny-by-default). Channel secrets are caller-supplied,
   * sealed at rest, and NEVER echoed back (presentRule strips them; the
   * route family is excluded from Idempotency-Key persistence in
   * handle()). Notifications are coordination, never authority.
   */
  if (segments[0] === "notifications") {
    const notif = require("./notifications");
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });
    const creatorXOnly = principal ? principal.xOnlyPubkey : null;

    // GET /notifications/channels — the closed channel-type set this
    // deployment can actually deliver (console/webhook built in; smtp
    // appears only when a provider is registered — honest discovery).
    if (method === "GET" && segments.length === 2 && segments[1] === "channels") {
      return { status: 200, body: { channelTypes: notif.availableChannelTypes(), subscribableEventTypes: notif.subscribableEventTypes() } };
    }

    if (segments[1] === "rules") {
      // POST /notifications/rules  { label?, eventTypes?, vaultId?, orgId?, channel }
      if (method === "POST" && segments.length === 2) {
        const rule = await notif.createRule(config, {
          creatorXOnly,
          label: body?.label,
          eventTypes: body?.eventTypes,
          vaultId: body?.vaultId,
          orgId: body?.orgId,
          channel: body?.channel
        });
        return { status: 201, body: { rule: notif.presentRule(rule) } };
      }
      // GET /notifications/rules — the caller's own rules only.
      if (method === "GET" && segments.length === 2) {
        const rules = await notif.listRulesForCreator(config, creatorXOnly);
        return { status: 200, body: { rules: rules.map(notif.presentRule) } };
      }
      // GET /notifications/rules/:id — rule + delivery monitoring view
      // (cursor, counters, bounded recent-attempt log). No secrets.
      if (method === "GET" && segments.length === 3) {
        const rule = await notif.requireOwnedRule(config, segments[2], creatorXOnly);
        const { Categories, getEventsStore } = require("./events-store");
        const stateRec = await getEventsStore(config).read(Categories.NOTIFY_STATE, rule.ruleId);
        return {
          status: 200,
          body: {
            rule: notif.presentRule(rule),
            delivery: stateRec
              ? {
                  cursor: stateRec.cursor,
                  counters: stateRec.counters,
                  consecutiveFailures: stateRec.consecutiveFailures,
                  pending: stateRec.pending
                    ? { eventId: stateRec.pending.eventId, attempts: stateRec.pending.attempts, nextAttemptAtMs: stateRec.pending.nextAttemptAtMs }
                    : null,
                  recentAttempts: stateRec.recentAttempts ?? []
                }
              : null
          }
        };
      }
      // POST /notifications/rules/:id/disable — unsubscribe (per-rule off
      // switch). POST .../enable re-subscribes from the CURRENT stream
      // head. POST .../delete removes the rule and its delivery state.
      if (method === "POST" && segments.length === 4 && segments[3] === "disable") {
        const rule = await notif.disableRule(config, { ruleId: segments[2], creatorXOnly });
        return { status: 200, body: { rule: notif.presentRule(rule) } };
      }
      if (method === "POST" && segments.length === 4 && segments[3] === "enable") {
        const rule = await notif.enableRule(config, { ruleId: segments[2], creatorXOnly });
        return { status: 200, body: { rule: notif.presentRule(rule) } };
      }
      if (method === "POST" && segments.length === 4 && segments[3] === "delete") {
        const rule = await notif.deleteRule(config, { ruleId: segments[2], creatorXOnly });
        return { status: 200, body: { deleted: true, ruleId: rule.ruleId } };
      }
    }
    throw apiError(404, "NOT_FOUND", "unknown notifications route");
  }

  // ---- TEST-ONLY dev signer endpoints (mock adapter / architecture test) ----
  // Gated by POLICYVAULT_DEV_SIGNER=1 and testnet only. Never on mainnet.
  const devSignerEnabled = process.env.POLICYVAULT_DEV_SIGNER === "1" && config.networkId !== "mainnet";

  if (segments[0] === "wallet" && (segments[1] === "dev-accounts" || segments[1] === "dev-sign")) {
    if (!devSignerEnabled) {
      throw apiError(404, "DEV_SIGNER_DISABLED", "dev signer is disabled (set POLICYVAULT_DEV_SIGNER=1 on testnet)");
    }
    const { loadOrCreateTestKeys } = require("../../sdk/src/keys");
    const { makeDevSigner } = require("../../sdk/src/signer-dev");
    const keys = loadOrCreateTestKeys(config);
    const roster = ["owner", "delegate", "recipient1", "recipient2", "recipient3"]
      .filter((role) => keys[role])
      .map((role) => ({ role, address: keys[role].address, xonly: keys[role].xonly }));

    // GET /wallet/dev-accounts
    if (method === "GET" && segments.length === 2) {
      return { status: 200, body: { warning: "TEST-ONLY dev signer (testnet)", accounts: roster } };
    }
    // POST /wallet/dev-sign  { address, unsignedSafeJson, signInputs }
    if (method === "POST" && segments.length === 2 && segments[1] === "dev-sign") {
      const { address, unsignedSafeJson, signInputs } = body ?? {};
      const match = roster.find((a) => a.address === address);
      if (!match) {
        throw apiError(400, "UNKNOWN_DEV_ACCOUNT", "address is not in the test keyring");
      }
      try {
        const signer = makeDevSigner(config, { secretHex: keys[match.role].secret, expectedAddress: address });
        const signedSafeJson = signer.signInputs(unsignedSafeJson, signInputs);
        return { status: 200, body: { signedSafeJson } };
      } catch (error) {
        throw apiError(422, "DEV_SIGN_FAILED", error.message);
      }
    }
  }

  // GET /wallet/fuel/:address — ordinary (non-covenant) UTXOs for an address
  // on the CONFIGURED network, largest first, so the browser can auto-select
  // genesis funding / owner-op fuel instead of hand-crafting UTXO JSON.
  // Read-only public receiving info; no keys, no signing.
  if (method === "GET" && segments.length === 3 && segments[0] === "wallet" && segments[1] === "fuel") {
    // path segments are not URL-decoded upstream; the kaspa address colon
    // arrives percent-encoded (%3A) from encodeURIComponent.
    const address = decodeURIComponent(segments[2] || "");
    const fuelPrefix = `${require("../../sdk/src/address-identity").requiredAddressPrefix(config.networkId)}:`;
    if (typeof address !== "string" || !address.startsWith(fuelPrefix)) throw apiError(400, "BAD_ADDRESS", `address must be a ${config.networkId} address (${fuelPrefix}...)`);
    const { getAddressUtxos } = require("../../sdk/src/chain");
    const { rpc } = await connectVerified(config);
    try {
      const utxos = (await getAddressUtxos(rpc, address)).filter((u) => u.covenantId === null);
      utxos.sort((a, b) => (a.amount < b.amount ? 1 : -1));
      return { status: 200, body: { address, utxos: utxos.map((u) => ({ outpoint: u.outpoint, amount: u.amount.toString(), scriptPublicKeyHex: u.scriptPublicKeyHex })) } };
    } finally {
      await rpc.disconnect();
    }
  }

  // GET /network/status — the node-gate outcome additionally feeds the
  // PASSIVE metrics observation (server/src/metrics.js noteNodeGate): a
  // metrics scrape never dials the node, it reports the last real outcome.
  if (method === "GET" && segments.length === 2 && segments[0] === "network" && segments[1] === "status") {
    const metrics = require("./metrics");
    let conn;
    try {
      conn = await connectVerified(config);
    } catch (error) {
      metrics.noteNodeGate(false, error.code || "NODE_UNREACHABLE");
      throw error;
    }
    const { rpc, serverInfo } = conn;
    try {
      const daa = await getVirtualDaaScore(rpc);
      metrics.noteNodeGate(true);
      return {
        status: 200,
        body: {
          networkId: serverInfo.networkId,
          isSynced: serverInfo.isSynced,
          hasUtxoIndex: serverInfo.hasUtxoIndex,
          serverVersion: serverInfo.serverVersion,
          virtualDaaScore: daa.toString()
        }
      };
    } finally {
      await rpc.disconnect();
    }
  }

  // ---- Organizations (OFF-CHAIN application metadata; never authority) ----
  if (segments[0] === "organizations") {
    const org = require("../../sdk/src/organization");
    const { requireOrgAccess, orgAccessAllowed } = require("./tenancy");
    // Hosted tenancy: the authenticated principal (null in self-hosted
    // mode, where tenancy is not enforced and every gate allows).
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });
    const orgError = (error) => {
      const status =
        error.code === "VERSION_CONFLICT" || error.code === "ORG_NOT_EMPTY" ? 409
        : error.code === "ORG_NOT_FOUND" || error.code === "MEMBER_NOT_FOUND" || error.code === "ASSIGNMENT_NOT_FOUND" || error.code === "VAULT_NOT_FOUND" ? 404
        : 422;
      const e = apiError(status, error.code || "ORG_ERROR", error.message);
      if (error.assignedVaultIds) e.extra = { assignedVaultIds: error.assignedVaultIds };
      return e;
    };
    const vaultExists = async (vaultId) => (await loadAnyManifest(config, vaultId)) !== null;
    const assignedVaultIds = async (orgId) => {
      const record = await org.loadAssignments(config); // throws on corruption (surfaced as 422)
      return Object.entries(record.assignments)
        .filter(([, a]) => a.orgId === orgId)
        .map(([vaultId]) => vaultId);
    };
    // Load an org and enforce tenancy in one step (404 hides existence).
    const scopedOrg = async (orgId, need) => requireOrgAccess(config, await org.loadOrganization(config, orgId), principal, need);
    try {
      // GET /organizations — list. In hosted mode ONLY the principal's
      // organizations (owned or wallet-member) are returned; server-side
      // scoping, never a frontend filter.
      if (method === "GET" && segments.length === 1) {
        let assignments;
        let assignmentsError = null;
        try {
          assignments = await org.loadAssignments(config);
        } catch (e) {
          assignments = null;
          assignmentsError = e.message;
        }
        let organizations = await org.listOrganizations(config);
        if (config.tenancyEnforced) {
          organizations = organizations.filter((o) => !o.error && orgAccessAllowed(config, o, principal, "read"));
          // Assignments are scoped to visible orgs only.
          if (assignments) {
            const visible = new Set(organizations.map((o) => o.orgId));
            assignments = { ...assignments, assignments: Object.fromEntries(Object.entries(assignments.assignments).filter(([, a]) => visible.has(a.orgId))) };
          }
        }
        return {
          status: 200,
          body: {
            organizations,
            assignmentsVersion: assignments ? assignments.version : null,
            assignments: assignments ? assignments.assignments : null,
            ...(assignmentsError ? { assignmentsError } : {}),
            roleLabels: org.ROLE_LABELS,
            note: "Organization roles are application metadata. They do not grant or modify Kaspa covenant authority."
          }
        };
      }
      // POST /organizations { name } — the creator becomes tenantOwner.
      if (method === "POST" && segments.length === 1) {
        const tenantOwner = config.tenancyEnforced ? principal.xOnlyPubkey : null;
        return { status: 201, body: { organization: await org.createOrganization(config, { name: body?.name, tenantOwner }) } };
      }

      const orgId = segments[1];
      // Every scoped route resolves ONLY this organization AND enforces
      // tenancy server-side; unknown, mismatched, or foreign ids fail
      // closed (404 hides another tenant's object).
      if (method === "GET" && segments.length === 2) {
        const record = await scopedOrg(orgId, "read");
        return { status: 200, body: { organization: record, vaultIds: await assignedVaultIds(orgId) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "rename") {
        await scopedOrg(orgId, "owner");
        return { status: 200, body: { organization: await org.renameOrganization(config, orgId, { name: body?.name, expectedVersion: body?.expectedVersion }) } };
      }
      // Lifecycle (§ org management): archive/restore/delete are LOCAL METADATA
      // VISIBILITY operations only — they never touch vaults, covenant
      // authority, or on-chain state. Delete fails closed (409 ORG_NOT_EMPTY,
      // with assignedVaultIds) while any vault is still assigned.
      if (method === "POST" && segments.length === 3 && segments[2] === "archive") {
        await scopedOrg(orgId, "owner");
        return { status: 200, body: { organization: await org.archiveOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "restore") {
        await scopedOrg(orgId, "owner");
        return { status: 200, body: { organization: await org.restoreOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "delete") {
        await scopedOrg(orgId, "owner");
        return { status: 200, body: await org.deleteOrganization(config, orgId, { expectedVersion: body?.expectedVersion }) };
      }
      if (method === "GET" && segments.length === 3 && segments[2] === "members") {
        const record = await scopedOrg(orgId, "read");
        return { status: 200, body: { members: record.members, version: record.version } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "members") {
        await scopedOrg(orgId, "owner");
        const { org: updated, member } = await org.addMember(config, orgId, { ...body, expectedVersion: body?.expectedVersion });
        return { status: 201, body: { member, version: updated.version } };
      }
      if (method === "POST" && segments.length === 5 && segments[2] === "members" && segments[4] === "remove") {
        await scopedOrg(orgId, "owner");
        const updated = await org.removeMember(config, orgId, segments[3], { expectedVersion: body?.expectedVersion });
        return { status: 200, body: { version: updated.version } };
      }
      if (method === "POST" && segments.length === 4 && segments[2] === "members") {
        await scopedOrg(orgId, "owner");
        const { org: updated, member } = await org.updateMember(config, orgId, segments[3], { ...body, expectedVersion: body?.expectedVersion });
        return { status: 200, body: { member, version: updated.version } };
      }
      if (method === "GET" && segments.length === 3 && segments[2] === "vaults") {
        await scopedOrg(orgId, "read");
        const vaults = (await Promise.all((await assignedVaultIds(orgId)).map((id) => presentAny(config, id)))).filter(Boolean);
        return { status: 200, body: { vaults } };
      }
      if (method === "POST" && segments.length === 3 && segments[2] === "vaults") {
        // Assigning a vault requires org ownership AND (hosted) vault
        // access — a principal cannot pull a foreign vault into its org.
        await scopedOrg(orgId, "owner");
        if (config.tenancyEnforced) {
          const { requireVaultAccess } = require("./tenancy");
          requireVaultAccess(config, await loadAnyManifest(config, body?.vaultId), principal, "owner");
        }
        const assignment = await org.assignVault(config, {
          vaultId: body?.vaultId,
          orgId,
          group: body?.group ?? null,
          expectedVersion: body?.expectedVersion,
          vaultExists
        });
        return { status: 200, body: { assignment } };
      }
      if (method === "POST" && segments.length === 5 && segments[2] === "vaults" && segments[4] === "unassign") {
        await scopedOrg(orgId, "owner");
        const current = await org.assignmentFor(config, segments[3]);
        if (!current || current.orgId !== orgId) {
          throw apiError(404, "ASSIGNMENT_NOT_FOUND", `vault ${segments[3]} is not assigned to organization ${orgId}`);
        }
        await org.unassignVault(config, { vaultId: segments[3], expectedVersion: body?.expectedVersion });
        return { status: 200, body: { unassigned: true } };
      }
      // GET /organizations/:id/controls — the governance + risk controls
      // configuration for this organization (metadata plane: ceremony and
      // restrictive workflow configuration only, never covenant authority).
      if (method === "GET" && segments.length === 3 && segments[2] === "controls") {
        await scopedOrg(orgId, "read");
        const { loadOrgControls, defaultControls } = require("./org-controls");
        const controls = await loadOrgControls(config, orgId);
        return {
          status: 200,
          body: {
            controls: controls ?? { ...defaultControls(), orgId },
            note: "Controls configure hosted governance ceremony and restrictive risk adapters. They never grant or modify Kaspa covenant authority; the vault owner's approval remains mandatory for every authority expansion, and break-glass owner actions are never gated."
          }
        };
      }
      // POST /organizations/:id/controls  { governance?, risk?, expectedVersion }
      if (method === "POST" && segments.length === 3 && segments[2] === "controls") {
        await scopedOrg(orgId, "owner");
        const { saveOrgControls } = require("./org-controls");
        const record = await saveOrgControls(config, orgId, {
          governance: body?.governance,
          risk: body?.risk,
          expectedVersion: body?.expectedVersion
        });
        await appendAudit(config, {
          kind: "metadata",
          orgId,
          action: "org_controls_updated",
          actor: "owner",
          actorXOnly: principal ? principal.xOnlyPubkey : null,
          result: "OK",
          detail: `controls v${record.version}: governance quorum ${record.governance.quorum ? `${record.governance.quorum.m} of ${record.governance.quorum.approvers.length}` : "owner-only"}, delay ${record.governance.delayMs}ms, ${record.risk.adapters.length} risk adapters`
        });
        return { status: 200, body: { controls: record } };
      }
      // GET /organizations/:id/audit — chain events for assigned vaults +
      // this organization's metadata events, each explicitly typed.
      if (method === "GET" && segments.length === 3 && segments[2] === "audit") {
        await scopedOrg(orgId, "read");
        const vaultSet = new Set(await assignedVaultIds(orgId));
        const eventTypeOf = (e) =>
          e.kind === "metadata"
            ? "APPLICATION METADATA EVENT"
            : e.kind === "governance"
              ? "GOVERNANCE EVENT"
              : e.kind === "risk"
                ? "RISK EVENT"
                : e.kind === "intent"
                  ? "INTENT EVENT"
                  : "CHAIN EVENT";
        const events = (await readAudit(config, { limit: 1000 }))
          .filter((e) => (e.kind === "metadata" ? e.orgId === orgId : e.vaultId && vaultSet.has(e.vaultId)))
          .map((e) => ({ ...e, eventType: eventTypeOf(e) }))
          .slice(0, clampLimit(query?.limit, 300, 1000));
        return { status: 200, body: { events } };
      }
      throw apiError(404, "NOT_FOUND", "unknown organizations route");
    } catch (error) {
      if (error.status) throw error;
      throw orgError(error);
    }
  }

  // ---- Hosted-layer agent suspensions (fullscale surface 21 residual;
  // server/src/agent-suspensions.js; docs/postlaunch/hosted-agent-suspend.md).
  // COORDINATION CONTROL ONLY — NEVER A COVENANT CONTROL: it makes THIS
  // server refuse new agent-driven build/finalize/submit requests
  // instantly (0 fees, no chain interaction); it cannot stop a delegate-
  // key holder submitting directly to a Kaspa node. Every response carries
  // the covenant-honesty notice; nothing treats a suspension as satisfying
  // or replacing covenant pause. Mutation = vault OWNER tenancy (wallet
  // session, or a machine identity that BOTH inherits the owner wallet's
  // tenancy AND holds the dedicated deny-by-default vaults:suspend-agents
  // scope — scopes.js). Read = vault participants (agents can see they are
  // suspended).
  if (segments.length === 3 && segments[0] === "vaults" && segments[2] === "agent-suspensions") {
    const vaultId = segments[1];
    if (!/^[0-9a-f]{64}$/.test(vaultId)) throw apiError(400, "BAD_VAULT_ID", "vaultId must be 32-byte hex");
    const suspensions = require("./agent-suspensions");
    const { requireVaultAccess } = require("./tenancy");
    const loaded = await loadAnyManifest(config, vaultId);
    const principal = await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced });
    if (method === "GET") {
      requireVaultAccess(config, loaded, principal, "read"); // foreign/missing -> 404
      const record = await suspensions.loadSuspensions(config, vaultId);
      return { status: 200, body: { suspensions: suspensions.presentSuspensions(record) } };
    }
    if (method === "POST") {
      requireVaultAccess(config, loaded, principal, "owner"); // owner tenancy for the flip
      const { op, agentPk, allAgents, expectedVersion } = body ?? {};
      const registryAgentPks =
        loaded && loaded.version === "v4" && Array.isArray(loaded.manifest.agentRegistry)
          ? loaded.manifest.agentRegistry.map((e) => (e.policy ? e.policy.agentPk : e.agentPk)).filter((k) => typeof k === "string")
          : [];
      const updatedBy = principal
        ? principal.isMachine
          ? { type: "machine", identityId: principal.identityId ?? null }
          : { type: "wallet", identityId: null }
        : { type: "operator", identityId: null };
      const record = await suspensions.updateSuspensions(config, vaultId, { op, agentPk, allAgents, expectedVersion, updatedBy, registryAgentPks });
      await appendAudit(config, {
        kind: "metadata",
        vaultId,
        action: "agent_suspension_updated",
        actor: updatedBy.type,
        actorXOnly: principal ? principal.xOnlyPubkey : null,
        result: op === "suspend" ? "AGENT_SUSPENDED_HOSTED" : "AGENT_UNSUSPENDED_HOSTED",
        detail: `hosted-layer ${op} (${allAgents === true ? "ALL agents" : `agent ${agentPk}`}) — coordination control, never a covenant control (version ${record.version})`
      });
      await require("./events").safeEmitPlatformEvent(config, {
        type: op === "suspend" ? "vault.agent.suspended" : "vault.agent.unsuspended",
        vaultId,
        data: { agentPk: allAgents === true ? undefined : agentPk, allAgents: allAgents === true, byType: updatedBy.type }
      });
      return { status: 200, body: { suspensions: suspensions.presentSuspensions(record) } };
    }
    throw apiError(405, "METHOD_NOT_ALLOWED", "agent-suspensions supports GET and POST");
  }

  // POST /vaults/:id/reconcile — "Verify Vault State". Invokes ONLY the
  // existing reconcile-v2 exact-proof path with its default gates; no
  // force/override/claim-deletion inputs exist or are accepted.
  if (method === "POST" && segments.length === 3 && segments[0] === "vaults" && segments[2] === "reconcile") {
    const vaultId = segments[1];
    const loaded = await loadAnyManifest(config, vaultId);
    // Reconcile is a hosted OWNER action (it can advance the durable
    // manifest against chain proof) — tenancy-gated so a principal cannot
    // drive reconciliation on a vault it does not own.
    const { requireVaultAccess } = require("./tenancy");
    requireVaultAccess(config, loaded, await requestAuthPrincipal(config, ctx, { required: config.tenancyEnforced }), "owner");
    if (!loaded) {
      throw apiError(404, "VAULT_NOT_FOUND", `no vault ${vaultId}`);
    }
    // Route by the vault's version to the matching exact-proof reconciler. Both
    // reconcilers use only their default gates; no force/override/claim-deletion
    // input exists or is accepted. The v0.4 reconciler serves the v0.4 family
    // (v0.4 + v0.4.1); it fails closed on any other version internally.
    // Reconciliation-outcome notification (surface 18): the sdk
    // reconciler's own audit writes happen deep in sdk/src (not through
    // the server audit hook), so the route — the server's observation
    // point — emits the event from the returned outcome. Notification
    // only; the manifest advanced (or not) on chain proof alone.
    const emitReconcileEvent = (result) =>
      require("./events").safeEmitPlatformEvent(config, {
        type: "vault.reconciled",
        vaultId,
        correlation: { txId: result?.txId },
        data: { outcome: result?.status, to: result?.to }
      });
    try {
      if (loaded.version === "v2") {
        const { reconcileVaultV2 } = require("../../sdk/src/reconcile-v2");
        const result = await reconcileVaultV2(config, vaultId);
        await emitReconcileEvent(result);
        return { status: 200, body: { reconcile: result, vault: await presentAny(config, vaultId) } };
      }
      if (loaded.version === "v4") {
        const { reconcileVaultV4 } = require("../../sdk/src/reconcile-v4");
        const result = await reconcileVaultV4(config, vaultId);
        await emitReconcileEvent(result);
        return { status: 200, body: { reconcile: result, vault: await presentAny(config, vaultId) } };
      }
      throw apiError(422, "UNSUPPORTED_VERSION", `reconcile is not available for vault version ${loaded.version}`);
    } catch (error) {
      if (error.status) throw error;
      throw apiError(422, "RECONCILE_FAILED", error.message);
    }
  }

  // GET /vaults — hosted mode tenant-scopes the list server-side to the
  // principal's covenant-participant vaults (never a frontend filter).
  if (method === "GET" && segments.length === 1 && segments[0] === "vaults") {
    const ids = await listVaultIds(config);
    let vaults = await Promise.all(ids.map((id) => presentAny(config, id)));
    if (config.tenancyEnforced) {
      const { vaultAccessAllowed } = require("./tenancy");
      const principal = await requestAuthPrincipal(config, ctx, { required: true });
      const filtered = [];
      for (const id of ids) {
        const loaded = await loadAnyManifest(config, id);
        if (vaultAccessAllowed(config, loaded, principal, "read")) filtered.push(await presentAny(config, id));
      }
      vaults = filtered;
    }
    return { status: 200, body: { vaults } };
  }

  // GET /vaults/:id  and  /vaults/:id/status | /audit
  if (method === "GET" && segments.length >= 2 && segments[0] === "vaults") {
    const vaultId = segments[1];
    const loaded = await loadAnyManifest(config, vaultId);
    // Hosted tenancy: a non-participant gets 404 (existence hidden).
    if (config.tenancyEnforced) {
      const { requireVaultAccess } = require("./tenancy");
      requireVaultAccess(config, loaded, await requestAuthPrincipal(config, ctx, { required: true }), "read");
    }
    if (!loaded) {
      throw apiError(404, "VAULT_NOT_FOUND", `no vault ${vaultId}`);
    }
    const manifest = loaded.manifest;

    if (segments.length === 2) {
      return { status: 200, body: await presentAny(config, vaultId) };
    }
    if (segments.length === 3 && segments[2] === "status") {
      const { rpc } = await connectVerified(config);
      try {
        const daa = await getVirtualDaaScore(rpc);
        const body = await presentAny(config, vaultId, { virtualDaa: daa });
        if (manifest.live) {
          const compiled =
            loaded.version === "v2"
              ? require("../../sdk/src/contract-compiler-v2").compileExactStateV2({
                  config,
                  template: manifest.template,
                  state: manifest.live.state
                })
              : compileExactState({ config, policy: manifest.policy, state: manifest.live.state });
          const address = covenantAddress(config, compiled.scriptBytes);
          const resp = await rpc.getUtxosByAddresses({ addresses: [address] });
          body.live.chainConfirmed = (resp.entries ?? []).some((e) => {
            const o = e.outpoint ?? e.entry?.outpoint;
            return (
              String(o.transactionId).toLowerCase() === manifest.live.outpoint.transactionId &&
              Number(o.index) === manifest.live.outpoint.index
            );
          });
        }
        return { status: 200, body };
      } finally {
        await rpc.disconnect();
      }
    }
    if (segments.length === 3 && segments[2] === "audit") {
      return { status: 200, body: { events: await readAudit(config, { vaultId }) } };
    }
  }

  /*
   * ---- Audit hash-chain integrity (fullscale surface 17 residual) ----
   * GET /audit/chain          — anchor + counts (no walk).
   * GET /audit/chain/verify   — walk the chained subsequence (?fromSeq=
   *   &toSeq=&limit=; bounded — complete:false + nextFromSeq continues)
   *   and report VALID / BROKEN-at-seq / EMPTY.
   * STRUCTURE ONLY: responses carry seqs, hashes, counts, reasons —
   * NEVER record content, so any tenant can confirm integrity of the
   * shared stream without reading foreign records (record content stays
   * behind the existing tenant-scoped audit reads; every recordHash
   * preimage includes a per-record nonce so a hash cannot confirm a
   * guessed foreign record). Hosted: authenticated principals; machine
   * credentials need read:audit (scopes.js). The chain describes the
   * hosted audit copy — Kaspa consensus remains the only financial truth.
   */
  if (method === "GET" && segments[0] === "audit" && segments.length >= 2 && segments[1] === "chain") {
    if (config.tenancyEnforced) await requestAuthPrincipal(config, ctx, { required: true });
    const chain = require("./audit-chain");
    try {
      if (segments.length === 2) {
        return { status: 200, body: await chain.chainStatus(config) };
      }
      if (segments.length === 3 && segments[2] === "verify") {
        return { status: 200, body: await chain.verifyChain(config, { fromSeq: query?.fromSeq, toSeq: query?.toSeq, limit: query?.limit }) };
      }
    } catch (error) {
      if (error.code === "AUDIT_CHAIN_BAD_RANGE") throw apiError(400, error.code, error.message);
      throw error;
    }
    throw apiError(404, "NOT_FOUND", "unknown audit chain route");
  }

  // GET /audit — the global activity feed. Hosted: tenant-scoped to the
  // principal's covenant-participant vaults (a foreign vault's events never
  // appear); org-metadata events are read through the per-org audit route.
  // Self-hosted: unchanged (single operator).
  if (method === "GET" && segments.length === 1 && segments[0] === "audit") {
    const events = await readAudit(config, { limit: clampLimit(query.limit, 200, 1000) });
    if (!config.tenancyEnforced) {
      return { status: 200, body: { events } };
    }
    const principal = await requestAuthPrincipal(config, ctx, { required: true });
    const { vaultAccessAllowed } = require("./tenancy");
    const cache = new Map();
    const scoped = [];
    for (const e of events) {
      if (!e || typeof e.vaultId !== "string") continue; // vault events only in the hosted global feed
      let loaded = cache.get(e.vaultId);
      if (loaded === undefined) {
        try {
          loaded = await loadAnyManifest(config, e.vaultId);
        } catch {
          loaded = null;
        }
        cache.set(e.vaultId, loaded);
      }
      if (vaultAccessAllowed(config, loaded, principal, "read")) scoped.push(e);
    }
    return { status: 200, body: { events: scoped } };
  }

  throw apiError(404, "NOT_FOUND", `no route for ${method} /${segments.join("/")}`);
}

/*
 * Cookie -> authenticated principal (or null). THE single resolution
 * path future tenancy authorization (Phase C) must consume — routes
 * never treat wallet fields from bodies/queries/headers as the
 * authenticated identity. With authMode=disabled this always yields
 * null (the self-hosted product has no hosted sessions).
 */
/*
 * Wallet-request tenancy gate (Phase F). A wallet request is a private
 * hosted object (its review carries the intended amount/recipient; its id
 * is the cancel/submit handle). In hosted mode a principal may reach a
 * request only if it is a covenant participant of the request's vault OR
 * the request's own signer (see tenancy.requestAccessAllowed). A denied
 * or missing request is 404 (existence hidden — no cross-tenant oracle).
 * In self-hosted mode this is a no-op (returns null) so the released
 * single-operator product is unchanged. Returns the principal on success.
 */
async function resolveRequestAccess(config, ctx, request) {
  if (!config.tenancyEnforced) return { principal: null, loadedVault: null };
  const principal = await requestAuthPrincipal(config, ctx, { required: true });
  let loadedVault = null;
  if (request && typeof request.vaultId === "string") {
    try {
      loadedVault = await loadAnyManifest(config, request.vaultId);
    } catch {
      loadedVault = null;
    }
  }
  const { requestAccessAllowed } = require("./tenancy");
  if (!requestAccessAllowed(config, request, principal, loadedVault)) {
    throw apiError(404, "REQUEST_NOT_FOUND", "no such request");
  }
  return { principal, loadedVault };
}

async function requireRequestAccess(config, ctx, request) {
  return (await resolveRequestAccess(config, ctx, request)).principal;
}

/* Mutating v4 request-lifecycle routes (reject, spend signature, submit,
 * genesis-submit): a participant who may READ the request but holds only
 * an APPROVER slot gets 403 — an external covenant approver's authority
 * is their approval signature alone, never the request lifecycle
 * (external-approver incident, 2026-08-27). Non-participants keep the
 * 404 non-oracle from resolveRequestAccess above. */
async function requireRequestMutation(config, ctx, request) {
  const { principal, loadedVault } = await resolveRequestAccess(config, ctx, request);
  if (!config.tenancyEnforced) return principal;
  const { requestMutationAllowed } = require("./tenancy");
  if (!requestMutationAllowed(config, request, principal, loadedVault)) {
    throw apiError(403, "REQUEST_FORBIDDEN", "this wallet may review and approve this request; it cannot cancel, sign, or submit it");
  }
  return principal;
}

/* Scope a wallet-request listing to the authenticated principal (Phase F).
 * Self-hosted: unchanged. Hosted: only requests the principal may reach,
 * with a per-vault manifest cache so the participant check is one load per
 * distinct vault. */
async function scopeRequestsForPrincipal(config, ctx, requests) {
  if (!config.tenancyEnforced) return requests;
  const principal = await requestAuthPrincipal(config, ctx, { required: true });
  const { requestAccessAllowed } = require("./tenancy");
  const cache = new Map();
  const out = [];
  for (const r of requests) {
    let loaded = null;
    if (r && typeof r.vaultId === "string") {
      if (cache.has(r.vaultId)) loaded = cache.get(r.vaultId);
      else {
        try {
          loaded = await loadAnyManifest(config, r.vaultId);
        } catch {
          loaded = null;
        }
        cache.set(r.vaultId, loaded);
      }
    }
    if (requestAccessAllowed(config, r, principal, loaded)) out.push(r);
  }
  return out;
}

/*
 * THE single principal-resolution path (Phase C directive, extended by
 * the platform-agent-api addendum, surface 6): every tenancy/covenant-
 * adjacent route call reaches identity through here — never a raw wallet
 * field from a body/query/header. Now resolves TWO distinct credential
 * kinds:
 *   - a machine (AI/agent) Bearer token (server/src/machine-identity.js)
 *     — checked FIRST when an Authorization header is present. An
 *     EXPLICITLY presented machine credential must resolve or this always
 *     throws (401 MACHINE_TOKEN_INVALID), REGARDLESS of `required` — an
 *     invalid credential is never silently downgraded to "no one" the way
 *     an absent cookie is. The returned principal's xOnlyPubkey is the
 *     CREATING wallet's own key (machine-identity.js), so every existing
 *     tenancy/covenant check below applies completely unmodified; scope
 *     enforcement (server/src/scopes.js) is a separate, additional gate
 *     applied once in api.js's handle() wrapper, not here.
 *   - the existing hosted wallet-session cookie, unchanged in every
 *     respect (including its lenient required:false-swallows-errors
 *     behavior) when no Authorization header is present.
 */
async function requestAuthPrincipal(config, ctx, { required = false } = {}) {
  if (config.authMode !== "enabled") {
    if (required) throw apiError(404, "AUTH_DISABLED", "hosted authentication is not enabled on this server");
    return null;
  }
  const authHeader = ctx && ctx.headers ? ctx.headers.authorization : undefined;
  if (typeof authHeader === "string" && authHeader.trim()) {
    const { resolveBearerToken } = require("./machine-identity");
    const { identity, credential } = await resolveBearerToken(config, authHeader); // throws 401 MACHINE_TOKEN_INVALID — never swallowed
    return Object.freeze({
      isMachine: true,
      xOnlyPubkey: identity.creatorXOnly,
      networkId: identity.networkId,
      identityId: identity.identityId,
      credentialId: credential.credentialId,
      scopes: identity.scopes,
      sessionIdentity: credential.credentialId.slice(0, 16)
    });
  }
  const { sessionTokenFromCookieHeader } = require("./auth");
  const token = sessionTokenFromCookieHeader(config, ctx && ctx.headers ? ctx.headers.cookie : undefined);
  if (!token) {
    if (required) throw apiError(401, "SESSION_INVALID", "sign in to use this route");
    return null;
  }
  try {
    return await authServiceFor(config).resolveSession(token);
  } catch (e) {
    if (required) throw apiError(e.status || 401, e.code || "SESSION_INVALID", e.message);
    return null;
  }
}

module.exports = { handle, presentVault, API_VERSION, apiError, loadConfig, requestAuthPrincipal };
