"use strict";

/*
 * PolicyVault API client — zero runtime dependencies, global `fetch`
 * (Node >= 18 / any modern browser / any WinterCG runtime).
 * (FULLSCALE_COMPLETION_ADDENDUM.md surface 9, consuming surface 8.)
 *
 * ANTI-BLOAT CONTRACT. This file is TRANSPORT ONLY. It builds a URL,
 * attaches headers, sends JSON, and turns a non-2xx response into a typed
 * error. It contains NO financial authority, NO policy semantics, NO
 * successor derivation, NO transaction verification, NO reconciliation
 * truth, and NO reinterpretation of a server decision. Local deterministic
 * checking is done with the modules re-exported from ./index.js (intent,
 * vault-transitions-*, agent-merkle-v4, fee-mass, ...) — never re-derived
 * here. "AI MAY REQUEST. POLICYVAULT DETERMINISTICALLY DECIDES. THE
 * COVENANT ENFORCES FINANCIAL AUTHORITY. SIGNERS RETAIN CUSTODY."
 *
 * The route map below mirrors server/src/api.js exactly and is documented
 * in docs/postlaunch/platform-agent-api-spec.md. Route coverage is
 * deliberately partial in one direction only: routes that exist but are
 * NOT reachable by a machine credential (POST /wallet/dev-sign,
 * GET /wallet/dev-accounts — the TEST-ONLY dev signer) have no method
 * here, and the legacy v0.2 wallet routes have no method here either
 * (production-disabled for new creation). Anything else is reachable via
 * the low-level `request()` escape hatch.
 *
 * ---------------------------------------------------------------------
 * FOUR PROPERTIES THIS CLIENT GUARANTEES
 * ---------------------------------------------------------------------
 *
 * 1. THE TOKEN IS NEVER LOGGED, NEVER STRINGIFIED, NEVER THROWN.
 *    It lives in a module-private WeakMap keyed by the client instance —
 *    not an own property — so `console.log(client)`, `JSON.stringify(client)`,
 *    `util.inspect(client)`, a crash dump, and an error's `.message`/
 *    `.stack`/`.toString()` can none of them leak it. This client also
 *    never writes to the console at all: it has no logger and calls no
 *    logging function, so there is no "log level" that could turn
 *    credential printing on. Redaction of a value that was never in the
 *    string is not a mitigation you have to trust — it is structural.
 *
 * 2. INTEGER SOMPI STAY STRINGS, END TO END. Responses are parsed with
 *    plain `JSON.parse`, which is why the server sends every consensus/
 *    accounting value as a decimal STRING: `JSON.parse` would silently
 *    destroy a u64 as an IEEE-754 double (2^53 precision cliff). This
 *    client therefore never coerces, rounds, formats, or "conveniently"
 *    converts an amount. Feed those strings to `parseSompi`/`sompiToKas`
 *    from the SDK entry point when you need arithmetic or display.
 *
 * 3. SERVER ERRORS ARE CARRIED VERBATIM, NEVER REINTERPRETED. A non-2xx
 *    response becomes a PolicyVaultApiError holding the server's exact
 *    `{ error: { code, message, ...extra } }` envelope plus the HTTP
 *    status. This client never maps one code onto another, never
 *    "upgrades" a refusal into a success, and never invents a code the
 *    server did not send. A refusal you did not understand must stay a
 *    refusal (CLAUDE.md fail-closed discipline).
 *
 * 4. NO AUTOMATIC RETRIES. Deliberate, and the reason is funds safety:
 *    a client cannot distinguish "the request never arrived" from "the
 *    request executed and the response was lost", so a library-level
 *    retry of a mutating call is a library-level double-spend risk. What
 *    this client does instead is make CALLER-CONTROLLED retry SAFE:
 *    every mutating call carries an `Idempotency-Key` (yours, or one
 *    generated per call) and the key is handed back to you on both the
 *    result and any thrown error. Retrying with the SAME key is
 *    guaranteed by the server to execute at most once — it replays the
 *    original response instead (server/src/idempotency.js; the funds-
 *    safety property is proven under real concurrency in
 *    sdk/test/postlaunch-idempotency-server.test.js). Retry when YOU
 *    decide to, with the key you already hold. Transport failures
 *    (DNS/connect/abort) surface as PolicyVaultNetworkError, which
 *    likewise carries the key you would reuse.
 */

const nodeCrypto = require("crypto");

/* The API is mounted here by server/src/server.js. */
const API_PREFIX = "/api/v1";

/*
 * The versioned platform schema this client is WRITTEN AGAINST
 * (server/src/api-version.js V4_WALLET_REQUEST_SCHEMA_VERSION; the value
 * is pinned here rather than imported because an API CLIENT must not
 * depend on the server package — that dependency direction is what makes
 * a client a client).
 *
 * Stamping it on the three request bodies the server validates
 * (`/wallet/v4/create`, `/wallet/v4/requests`, `/wallet/v4/simulate`) is
 * the fail-closed choice the spec recommends for machine callers: a
 * server that speaks a different wire shape answers a clean
 * `422 SCHEMA_VERSION_UNSUPPORTED` instead of silently reinterpreting
 * your body under new semantics. Omitting the field is also valid and is
 * what the shipped web client does; pass `stampSchemaVersion: false` to
 * behave that way. It is stamped ONLY on bodies the server actually
 * validates — stamping it where nothing checks it would be decoration
 * that implies a guarantee that does not exist.
 */
const V4_WALLET_REQUEST_SCHEMA_VERSION = "policyvault-wallet-v4-request/v1";

/* Idempotency-Key grammar, from server/src/idempotency.js validateKey. */
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_.:-]{1,200}$/;

/* Module-private token storage — see guarantee (1). Never an own property
 * of the client, so no serializer, inspector, or error formatter can reach
 * it by walking the object. */
const TOKENS = new WeakMap();

/* -------------------------------------------------------------------- */
/* Errors                                                                */
/* -------------------------------------------------------------------- */

/**
 * A non-2xx answer from a PolicyVault server.
 *
 * The server's envelope is preserved EXACTLY as received (`body`), with
 * `code`/`message` lifted for convenience and `extra` holding whatever
 * additional fields that specific refusal carried (`request`,
 * `idempotency`, ... — api.js attaches these per-route; they are surfaced,
 * never interpreted).
 */
class PolicyVaultApiError extends Error {
  constructor({ status, body, method, path, idempotencyKey }) {
    const envelope = body && typeof body === "object" && body.error && typeof body.error === "object" ? body.error : null;
    const code = envelope && typeof envelope.code === "string" ? envelope.code : "UNKNOWN";
    const message = envelope && typeof envelope.message === "string" ? envelope.message : `HTTP ${status}`;
    /* NOTE: the message is built from the server's envelope and the
     * method/path only. The token is not in scope here and never can be. */
    super(`PolicyVault ${method} ${path} -> ${status} ${code}: ${message}`);
    this.name = "PolicyVaultApiError";
    this.status = status;
    this.code = code;
    this.serverMessage = message;
    this.method = method;
    this.path = path;
    this.body = body ?? null;
    this.extra = envelope ? Object.fromEntries(Object.entries(envelope).filter(([k]) => k !== "code" && k !== "message")) : {};
    this.idempotencyKey = idempotencyKey ?? null;
    /* Convenience for the idempotency contract: a replayed refusal is a
     * refusal the server had already recorded, not a fresh one. */
    this.replayed = Boolean(envelope && envelope.idempotency && envelope.idempotency.replayed);
  }
}

/**
 * The request never produced an HTTP answer (DNS, connect, TLS, timeout,
 * abort). Carries the Idempotency-Key that was sent, because THIS is the
 * case where you cannot know whether the server executed the call — and
 * replaying with that same key is exactly how you find out safely.
 */
class PolicyVaultNetworkError extends Error {
  constructor({ method, path, cause, idempotencyKey }) {
    super(`PolicyVault ${method} ${path} -> transport failure: ${cause && cause.message ? cause.message : String(cause)}`);
    this.name = "PolicyVaultNetworkError";
    this.method = method;
    this.path = path;
    this.cause = cause;
    this.idempotencyKey = idempotencyKey ?? null;
  }
}

/* -------------------------------------------------------------------- */
/* Helpers                                                               */
/* -------------------------------------------------------------------- */

function randomIdempotencyKey() {
  /* randomUUID's output is inside the server's [A-Za-z0-9_.:-]{1,200}
   * grammar. Prefixed so an operator reading a durable idempotency record
   * can tell a client-generated key from a caller-supplied one. */
  const uuid = typeof nodeCrypto.randomUUID === "function"
    ? nodeCrypto.randomUUID()
    : nodeCrypto.randomBytes(16).toString("hex");
  return `pvsdk-${uuid}`;
}

function assertIdempotencyKey(key) {
  if (!IDEMPOTENCY_KEY_RE.test(key)) {
    throw new TypeError("idempotencyKey must be 1..200 characters of [A-Za-z0-9_.:-] (server/src/idempotency.js)");
  }
  return key;
}

function encodeQuery(query) {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    /* Everything is stringified as-is: a sompi value arriving here as a
     * decimal string stays that exact string. */
    params.append(key, typeof value === "string" ? value : String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

/* Attach the key to the returned body WITHOUT changing the body's JSON
 * shape: non-enumerable means JSON.stringify(result) is still byte-for-byte
 * the server's response, so a caller forwarding the result to its own
 * consumers forwards exactly what PolicyVault said. */
function tagIdempotencyKey(body, idempotencyKey) {
  if (idempotencyKey && body && typeof body === "object") {
    Object.defineProperty(body, "idempotencyKey", { value: idempotencyKey, enumerable: false, writable: false, configurable: true });
  }
  return body;
}

/* -------------------------------------------------------------------- */
/* Client                                                                */
/* -------------------------------------------------------------------- */

class PolicyVaultClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl        e.g. "http://127.0.0.1:8080" or "https://app.policy-vault.org".
   *                                        A path suffix is honored; "/api/v1" is appended if absent.
   * @param {string} [options.token]        A machine credential ("pvmk_..."), sent as `Authorization: Bearer`.
   *                                        Omit for a self-hosted server (single trusted local operator,
   *                                        no hosted sessions, no machine identities).
   * @param {Function} [options.fetchImpl]  Defaults to global fetch. Injectable for tests/proxies/agents.
   * @param {boolean} [options.stampSchemaVersion=true]  See V4_WALLET_REQUEST_SCHEMA_VERSION above.
   * @param {object} [options.headers]      Extra default headers (never overrides Authorization).
   */
  constructor({ baseUrl, token, fetchImpl, stampSchemaVersion = true, headers } = {}) {
    if (typeof baseUrl !== "string" || !baseUrl.trim()) {
      throw new TypeError("PolicyVaultClient: baseUrl is required (e.g. \"http://127.0.0.1:8080\")");
    }
    const fetcher = fetchImpl ?? (typeof fetch === "function" ? fetch : null);
    if (typeof fetcher !== "function") {
      throw new TypeError("PolicyVaultClient: no global fetch available — pass options.fetchImpl (Node >= 18 has fetch built in)");
    }
    if (token !== undefined && (typeof token !== "string" || !token)) {
      throw new TypeError("PolicyVaultClient: token, when supplied, must be a non-empty string");
    }

    const trimmed = baseUrl.replace(/\/+$/, "");
    /* Endpoint = origin(+path) with the API mount appended once. Accepting
     * a base that already ends in /api/v1 keeps copy-pasted URLs working. */
    this.baseUrl = trimmed.endsWith(API_PREFIX) ? trimmed : `${trimmed}${API_PREFIX}`;
    this.stampSchemaVersion = stampSchemaVersion !== false;
    this.defaultHeaders = Object.freeze({ ...(headers ?? {}) });
    /* Never assigned as an own property — guarantee (1). */
    TOKENS.set(this, token ?? null);
    Object.defineProperty(this, "_fetch", { value: fetcher, enumerable: false });
  }

  /** True when this client was constructed with a credential. Reveals only existence, never the value. */
  get authenticated() {
    return Boolean(TOKENS.get(this));
  }

  /* Keeps `console.log(client)` / util.inspect from ever being a leak
   * vector even if a future field were added carelessly. */
  toJSON() {
    return { baseUrl: this.baseUrl, authenticated: this.authenticated, stampSchemaVersion: this.stampSchemaVersion };
  }

  /**
   * Low-level escape hatch. Every method below is a thin wrapper over this.
   *
   * @returns {Promise<any>} the parsed JSON body (with a non-enumerable
   *   `idempotencyKey` when one was sent).
   * @throws {PolicyVaultApiError} on any non-2xx answer.
   * @throws {PolicyVaultNetworkError} when no answer arrived at all.
   */
  async request(method, path, { query, body, idempotencyKey, headers, signal } = {}) {
    const url = `${this.baseUrl}${path}${encodeQuery(query)}`;
    const requestHeaders = { Accept: "application/json", ...this.defaultHeaders, ...(headers ?? {}) };

    const token = TOKENS.get(this);
    if (token) requestHeaders.Authorization = `Bearer ${token}`;

    let key = null;
    if (method === "POST") {
      /* Mutating calls always carry a key: an explicit `idempotencyKey: null`
       * opts out (byte-identical to the pre-platform behavior, which is what
       * the shipped web client does), anything else is used or generated. */
      if (idempotencyKey === null) {
        key = null;
      } else {
        key = idempotencyKey === undefined ? randomIdempotencyKey() : assertIdempotencyKey(String(idempotencyKey));
      }
      if (key) requestHeaders["Idempotency-Key"] = key;
    }

    let payload;
    if (body !== undefined) {
      requestHeaders["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }

    let response;
    try {
      /* Called through a LOCAL binding, never as `this._fetch(...)`: a
       * browser's global `fetch` throws "Illegal invocation" when its
       * receiver is anything other than the window/worker global, so
       * invoking it as a method of this client would break every browser
       * consumer. A local call leaves `this` undefined, which is exactly
       * how a standalone function is expected to be called. */
      const doFetch = this._fetch;
      response = await doFetch(url, { method, headers: requestHeaders, body: payload, signal });
    } catch (cause) {
      throw new PolicyVaultNetworkError({ method, path, cause, idempotencyKey: key });
    }

    const text = await response.text();
    let parsed = null;
    if (text) {
      try {
        /* Plain JSON.parse: sompi values arrive as decimal STRINGS and are
         * left as strings — see guarantee (2). No reviver, no coercion. */
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }

    if (!response.ok) {
      throw new PolicyVaultApiError({ status: response.status, body: parsed, method, path, idempotencyKey: key });
    }
    return tagIdempotencyKey(parsed, key);
  }

  /* Stamp the pinned schemaVersion on the three bodies server/src/api.js
   * actually validates. A caller-supplied schemaVersion always wins — if
   * you deliberately pin a different one, you get the server's clean 422,
   * which is the point. */
  _v4Body(body) {
    const base = body ?? {};
    if (!this.stampSchemaVersion || base.schemaVersion !== undefined) return base;
    return { ...base, schemaVersion: V4_WALLET_REQUEST_SCHEMA_VERSION };
  }

  /* ------------------------------------------------------------------ */
  /* Discovery (public routes — no credential required)                  */
  /* ------------------------------------------------------------------ */

  /** GET /health — liveness. Cheap by design: no database, no node dial. */
  health(opts) {
    return this.request("GET", "/health", opts);
  }

  /** GET /health/ready — readiness (store open, schema current, network stamp matching). 503 => PolicyVaultApiError. */
  ready(opts) {
    return this.request("GET", "/health/ready", opts);
  }

  /**
   * GET /capabilities — the discovery document: apiVersion, networkId,
   * supported covenant versions, the v0.4 action list with each action's
   * required signer ROLE, the full scope vocabulary with descriptions, every
   * schemaVersion this build understands, live rate limits/quotas, and
   * feature booleans computed from the live config. Read this FIRST rather
   * than assuming a deployment's shape.
   */
  capabilities(opts) {
    return this.request("GET", "/capabilities", opts);
  }

  /** GET /support — the voluntary-support (donation) surface. Public receiving info only. */
  support(opts) {
    return this.request("GET", "/support", opts);
  }

  /* ------------------------------------------------------------------ */
  /* Vaults / audit / network                    (read:vaults, read:audit,*/
  /*                                              read:network, vaults:reconcile) */
  /* ------------------------------------------------------------------ */

  /** GET /vaults — tenant-scoped server-side to vaults this principal participates in. */
  listVaults(opts) {
    return this.request("GET", "/vaults", opts);
  }

  /** GET /vaults/:vaultId — a foreign or unknown vault is 404 either way (existence is hidden, deliberately). */
  getVault(vaultId, opts) {
    return this.request("GET", `/vaults/${encodeURIComponent(vaultId)}`, opts);
  }

  /** GET /vaults/:vaultId/status */
  getVaultStatus(vaultId, opts) {
    return this.request("GET", `/vaults/${encodeURIComponent(vaultId)}/status`, opts);
  }

  /** GET /vaults/:vaultId/audit — this vault's activity. */
  getVaultAudit(vaultId, opts) {
    return this.request("GET", `/vaults/${encodeURIComponent(vaultId)}/audit`, opts);
  }

  /** GET /audit?limit= — the global activity feed, tenant-scoped. */
  audit({ limit, ...opts } = {}) {
    return this.request("GET", "/audit", { ...opts, query: { ...(limit !== undefined ? { limit } : {}) } });
  }

  /**
   * POST /vaults/:vaultId/reconcile — chain reconciliation ("Verify Vault
   * State"). Owner action. Only proven chain reconciliation advances the
   * durable manifest; there is no force/override input and this client
   * does not invent one.
   */
  reconcileVault(vaultId, opts) {
    return this.request("POST", `/vaults/${encodeURIComponent(vaultId)}/reconcile`, opts);
  }

  /** GET /network/status — node network id, sync state, UTXO index, DAA. Verify before live operations; never assume sync. */
  networkStatus(opts) {
    return this.request("GET", "/network/status", opts);
  }

  /** GET /wallet/fuel/:address — ordinary (non-covenant) UTXOs, largest first. Read-only; no keys, no signing. */
  fuel(address, opts) {
    return this.request("GET", `/wallet/fuel/${encodeURIComponent(address)}`, opts);
  }

  /** GET /manifests/:hash — a recorded intent manifest + its verified verdict (audit correlation). */
  getManifest(manifestHash, opts) {
    return this.request("GET", `/manifests/${encodeURIComponent(manifestHash)}`, opts);
  }

  /* ------------------------------------------------------------------ */
  /* v0.4 wallet requests    (request:build / :sign / :submit / :reject,  */
  /*                          read:requests)                              */
  /* ------------------------------------------------------------------ */

  /**
   * POST /wallet/v4/simulate — DRY RUN. Same body as createRequest, runs the
   * IDENTICAL pipeline (governance classification, risk composition, plan,
   * signer authorization, the real builder, real intent derivation +
   * verification) but persists nothing, consumes no gate, and never
   * broadcasts. Always answers 200 for a well-formed body, with
   * `simulation.ok: true|false`; a MALFORMED body is a real 4xx.
   *
   * Simulate first. Always. A dry run tells you which approvals, proposal,
   * or risk release the real call would require BEFORE you consume anything.
   *
   * Note: no Idempotency-Key is sent by default — a simulation has nothing
   * to make idempotent, and spending a key on it would be misleading. Pass
   * one explicitly if your infrastructure requires it.
   */
  simulate(body, { idempotencyKey = null, ...opts } = {}) {
    return this.request("POST", "/wallet/v4/simulate", { ...opts, idempotencyKey, body: this._v4Body(body) });
  }

  /**
   * POST /wallet/v4/requests — build an unsigned v0.4 transition.
   * `{ vaultId, action, params, signerAddress, proposalId?, riskEvaluationId? }`.
   * Builders NEVER broadcast (CLAUDE.md pipeline discipline): this returns a
   * durable request to be signed externally, then finalized, then submitted.
   * All amounts in `params` are integer-sompi decimal STRINGS.
   */
  createRequest(body, opts) {
    return this.request("POST", "/wallet/v4/requests", { ...opts, body: this._v4Body(body) });
  }

  /** POST /wallet/v4/create — genesis (new vault). Canonical or friendly schema; see server/src/api.js. */
  createVault(body, opts) {
    return this.request("POST", "/wallet/v4/create", { ...opts, body: this._v4Body(body) });
  }

  /** GET /wallet/v4/requests?vaultId=&open=1 — durable request listing (the approval inbox / reload-restore source of truth). */
  listRequests({ vaultId, open, ...opts } = {}) {
    return this.request("GET", "/wallet/v4/requests", {
      ...opts,
      query: { ...(vaultId ? { vaultId } : {}), ...(open ? { open: "1" } : {}) }
    });
  }

  /** GET /wallet/v4/requests/:requestId */
  getRequest(requestId, opts) {
    return this.request("GET", `/wallet/v4/requests/${encodeURIComponent(requestId)}`, opts);
  }

  /** POST /wallet/v4/requests/:requestId/approvals — `{ approverAddress, signedSafeJson | signatureHex }` (M-of-N). */
  submitApproval(requestId, body, opts) {
    return this.request("POST", `/wallet/v4/requests/${encodeURIComponent(requestId)}/approvals`, { ...opts, body });
  }

  /**
   * POST /wallet/v4/requests/:requestId/signature — `{ signedSafeJson }`.
   * FINALIZE + VM preflight. Finalizers never mark chain state changed.
   */
  submitSignature(requestId, body, opts) {
    return this.request("POST", `/wallet/v4/requests/${encodeURIComponent(requestId)}/signature`, { ...opts, body });
  }

  /**
   * POST /wallet/v4/requests/:requestId/submit — LIVE broadcast of an
   * already-finalized transition.
   *
   * This is the one call in this client that can move funds on a live
   * network. `submitTransaction()` returning is NOT success (CLAUDE.md):
   * the server proves txid == frozen txid, the exact successor on chain,
   * and durable receipt persistence before it advances the manifest. Read
   * the returned request state — do not assume a 200 means settled.
   */
  submitRequest(requestId, opts) {
    return this.request("POST", `/wallet/v4/requests/${encodeURIComponent(requestId)}/submit`, opts);
  }

  /** POST /wallet/v4/requests/:requestId/genesis-submit — `{ signedSafeJson }`. Broadcasts owner-signed genesis funding. */
  submitGenesis(requestId, body, opts) {
    return this.request("POST", `/wallet/v4/requests/${encodeURIComponent(requestId)}/genesis-submit`, { ...opts, body });
  }

  /** POST /wallet/v4/requests/:requestId/reject — cancel an open request. */
  rejectRequest(requestId, opts) {
    return this.request("POST", `/wallet/v4/requests/${encodeURIComponent(requestId)}/reject`, opts);
  }

  /* ------------------------------------------------------------------ */
  /* Governance   (read:governance, governance:propose/:approve/:cancel) */
  /* ------------------------------------------------------------------ */

  /** GET /governance/proposals?vaultId=&limit= */
  listProposals({ vaultId, limit, ...opts } = {}) {
    return this.request("GET", "/governance/proposals", {
      ...opts,
      query: { ...(vaultId ? { vaultId } : {}), ...(limit !== undefined ? { limit } : {}) }
    });
  }

  /** GET /governance/proposals/:proposalId */
  getProposal(proposalId, opts) {
    return this.request("GET", `/governance/proposals/${encodeURIComponent(proposalId)}`, opts);
  }

  /** POST /governance/proposals — `{ vaultId, action, params, expiresInMs? }`. Owner act. */
  createProposal(body, opts) {
    return this.request("POST", "/governance/proposals", { ...opts, body });
  }

  /**
   * POST /governance/proposals/:proposalId/approvals — `{ approverAddress, signature }`.
   * The Schnorr signature over the SERVER-reconstructed canonical approval
   * message is what counts; a session only gates route visibility. Hosted
   * admin/DB is never a substitute for cryptographic financial authority.
   */
  approveProposal(proposalId, body, opts) {
    return this.request("POST", `/governance/proposals/${encodeURIComponent(proposalId)}/approvals`, { ...opts, body });
  }

  /** POST /governance/proposals/:proposalId/cancel — always available to the owner. */
  cancelProposal(proposalId, opts) {
    return this.request("POST", `/governance/proposals/${encodeURIComponent(proposalId)}/cancel`, opts);
  }

  /* ------------------------------------------------------------------ */
  /* Risk                                       (read:risk, risk:release) */
  /* ------------------------------------------------------------------ */

  /** GET /risk/evaluations/:evaluationId — the durable evaluation evidence. */
  getRiskEvaluation(evaluationId, opts) {
    return this.request("GET", `/risk/evaluations/${encodeURIComponent(evaluationId)}`, opts);
  }

  /**
   * POST /risk/evaluations/:evaluationId/release — release a REVIEW hold for
   * the exact reviewed intent. The service forbids self-release by the
   * initiating signer, from durable facts. A DENY is final and is not
   * releasable — that is a server decision this client never second-guesses.
   */
  releaseRiskEvaluation(evaluationId, opts) {
    return this.request("POST", `/risk/evaluations/${encodeURIComponent(evaluationId)}/release`, opts);
  }

  /* ------------------------------------------------------------------ */
  /* Organizations       (read:organizations, organizations:manage)      */
  /* ------------------------------------------------------------------ */
  /*
   * Reads plus the risk/governance CONTROLS, which are the part of the org
   * surface that affects financial decisions. The remaining org-lifecycle
   * and membership routes (create/rename/archive/restore/delete, members,
   * vault assignment) are hosted ACCOUNT ADMINISTRATION rather than the
   * financial surface this SDK is for, and are deliberately left to
   * `request()` rather than given named methods that would imply this
   * client is an admin console.
   */

  /** GET /organizations */
  listOrganizations(opts) {
    return this.request("GET", "/organizations", opts);
  }

  /** GET /organizations/:orgId */
  getOrganization(orgId, opts) {
    return this.request("GET", `/organizations/${encodeURIComponent(orgId)}`, opts);
  }

  /** GET /organizations/:orgId/controls — the org's risk/governance control configuration. */
  getOrganizationControls(orgId, opts) {
    return this.request("GET", `/organizations/${encodeURIComponent(orgId)}/controls`, opts);
  }

  /** POST /organizations/:orgId/controls — compare-and-set; a conflict means reload and re-apply, never blind overwrite. */
  setOrganizationControls(orgId, body, opts) {
    return this.request("POST", `/organizations/${encodeURIComponent(orgId)}/controls`, { ...opts, body });
  }

  /** GET /organizations/:orgId/audit — org-metadata events (separate from the vault feed). */
  getOrganizationAudit(orgId, opts) {
    return this.request("GET", `/organizations/${encodeURIComponent(orgId)}/audit`, opts);
  }

  /* ------------------------------------------------------------------ */
  /* Machine identities — WALLET-SESSION ONLY                            */
  /* ------------------------------------------------------------------ */
  /*
   * These routes are STRUCTURALLY unreachable by a machine credential, at
   * ANY scope (server/src/scopes.js isWalletSessionOnlyRoute): a token can
   * never mint, widen, or revoke its own — or a sibling's — authority. They
   * are included here for the operator tooling that provisions credentials
   * from an authenticated wallet session (pass the session cookie via
   * `headers`); called with a Bearer token they will correctly refuse with
   * 403 MACHINE_IDENTITY_ROUTE_FORBIDDEN, and that refusal is a feature.
   *
   * A minted token is returned EXACTLY ONCE, at creation. Store it the way
   * you would any bearer credential; only its SHA-256 is ever persisted
   * server-side. Rotate by minting a second credential, deploying it, then
   * revoking the first — never by revoking first.
   */

  /** POST /identities — `{ label?, scopes: [...], orgId? }`. 201 with the one-time raw token. */
  createIdentity(body, opts) {
    return this.request("POST", "/identities", { ...opts, body });
  }

  /** GET /identities — the calling wallet's own machine identities only. */
  listIdentities(opts) {
    return this.request("GET", "/identities", opts);
  }

  /** GET /identities/:identityId — identity + its credential records (hashes/metadata, never tokens). */
  getIdentity(identityId, opts) {
    return this.request("GET", `/identities/${encodeURIComponent(identityId)}`, opts);
  }

  /** POST /identities/:identityId/credentials — `{ label? }`. Mints an ADDITIONAL credential (zero-downtime rotation). */
  mintCredential(identityId, body, opts) {
    return this.request("POST", `/identities/${encodeURIComponent(identityId)}/credentials`, { ...opts, body: body ?? {} });
  }

  /** POST /identities/:identityId/credentials/:credentialId/revoke */
  revokeCredential(identityId, credentialId, opts) {
    return this.request("POST", `/identities/${encodeURIComponent(identityId)}/credentials/${encodeURIComponent(credentialId)}/revoke`, opts);
  }

  /** POST /identities/:identityId/revoke — invalidates the identity and every credential it ever minted. */
  revokeIdentity(identityId, opts) {
    return this.request("POST", `/identities/${encodeURIComponent(identityId)}/revoke`, opts);
  }
}

/** Convenience factory. `createClient({ baseUrl, token })`. */
function createClient(options) {
  return new PolicyVaultClient(options);
}

module.exports = {
  PolicyVaultClient,
  PolicyVaultApiError,
  PolicyVaultNetworkError,
  createClient,
  randomIdempotencyKey,
  API_PREFIX,
  V4_WALLET_REQUEST_SCHEMA_VERSION
};
