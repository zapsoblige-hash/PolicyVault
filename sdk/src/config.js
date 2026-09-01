"use strict";

const path = require("path");
const fs = require("fs");

const HOME = process.env.HOME;

if (!HOME) {
  throw new Error("HOME environment variable is missing");
}

/*
 * The repository root is derived from this module's location (sdk/src/..),
 * NOT from a fixed home-directory name, so a checkout works wherever it is
 * cloned: contracts resolve inside the checkout and per-network data roots
 * live inside the checkout (data/ and data-mainnet/, both gitignored).
 * External sibling toolchains (silverscript, rusty-kaspa) remain
 * HOME-anchored documented prerequisites.
 */
const REPO_ROOT = path.join(__dirname, "..", "..");

const Network = Object.freeze({
  TESTNET_10: "testnet-10",
  MAINNET: "mainnet"
});

// Single-sourced frozen protocol-identity constant (shared-core extraction
// step 2): the value lives in core/model/contract-version.js and is
// re-exported here unchanged for config's existing consumers.
const { CONTRACT_VERSION } = require("../../core/model/contract-version");

/*
 * Voluntary-support donation destination (docs/product-policy.md): the
 * project owner's PUBLIC mainnet receiving address. Overridable via
 * POLICYVAULT_DONATION_ADDRESS; never derived from any wallet/vault/test
 * key; validated through sdk/src/donation-address.js before display.
 */
const DEFAULT_DONATION_ADDRESS = "kaspa:qyppakv5y7kmeynffldl9zshwgkjrl3fy9jjj8wf24v7f64v0gnuragz7ehdqhn";

/*
 * Mainnet is intentionally locked. Enabling it requires BOTH the explicit
 * environment flag and a per-call override, and broadcasting on mainnet
 * additionally requires separate explicit human authorization (mission
 * §62). Unknown networks fail closed.
 */
function loadConfig(overrides = {}) {
  const networkId = overrides.networkId ?? process.env.KASPA_NETWORK_ID ?? Network.TESTNET_10;

  if (!Object.values(Network).includes(networkId)) {
    throw new Error(`config: unknown networkId ${JSON.stringify(networkId)} — failing closed`);
  }

  const explicitRpcUrl = overrides.rpcUrl ?? process.env.KASPA_RPC_URL;
  const rpcUrl = explicitRpcUrl ?? "ws://127.0.0.1:18210";

  const allowMainnet =
    (overrides.allowMainnet ?? false) === true &&
    process.env.POLICYVAULT_ALLOW_MAINNET === "true";

  if (networkId === Network.MAINNET && !allowMainnet) {
    throw new Error(
      "config: PolicyVault mainnet mode is locked. " +
        "It requires POLICYVAULT_ALLOW_MAINNET=true and an explicit allowMainnet override " +
        "(the Gate R release procedure, docs/production-release.md §8)."
    );
  }

  // A mainnet process must never inherit the testnet default RPC endpoint:
  // the node URL is part of the explicit Gate R deployment procedure (§8).
  if (networkId === Network.MAINNET && !explicitRpcUrl) {
    throw new Error(
      "config: mainnet requires an explicit KASPA_RPC_URL (or rpcUrl override) — refusing the testnet default endpoint."
    );
  }

  /*
   * HOSTED AUTHENTICATION (Hosted Web checkpoint, Phase B). Disabled by
   * default: the released self-hosted loopback product requires no hosted
   * login and is unchanged. Enabling is an explicit deliberate act
   * (POLICYVAULT_HOSTED_AUTH=1 or an authMode override). All values are
   * validated here and FAIL CLOSED — auth code never infers
   * security-critical configuration from incoming requests.
   */
  const authMode = overrides.authMode ?? (process.env.POLICYVAULT_HOSTED_AUTH === "1" ? "enabled" : "disabled");
  if (authMode !== "enabled" && authMode !== "disabled") {
    throw new Error(`config: unknown authMode ${JSON.stringify(authMode)} — failing closed`);
  }
  const appOriginRaw = overrides.appOrigin ?? process.env.POLICYVAULT_APP_ORIGIN ?? "http://127.0.0.1:3080";
  let appOrigin = appOriginRaw;
  const cookieInsecureOverride =
    overrides.authCookieInsecure === true || process.env.POLICYVAULT_AUTH_COOKIE_INSECURE === "1";
  const authCookieSecure = !cookieInsecureOverride;
  /*
   * Mobile session-bootstrap DESIGN FREEZE §2 (docs pointer:
   * mobile/docs/session-bootstrap-DESIGN.md): a config-gated SIBLING of
   * cookie sessions — same challenge/verify ceremony, same session store,
   * same TTL/revocation — presented via `Authorization: Bearer` instead of
   * a `Set-Cookie`, for native clients that cannot carry a SameSite=Strict
   * cookie cross-origin. Default OFF; fail closed on anything but the
   * exact env value "1" (identical discipline to every other boolean flag
   * in this block — e.g. POLICYVAULT_AUTH_COOKIE_INSECURE above).
   * Production enablement is a separate, later release decision — this
   * flag existing and defaulting off is not that decision.
   */
  const authBearerSessionsEnabled =
    overrides.authBearerSessionsEnabled === true || process.env.POLICYVAULT_AUTH_BEARER_SESSIONS === "1";
  const parsePositiveMs = (name, raw, fallback, min, max) => {
    if (raw === undefined) return fallback;
    const n = Number(raw);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
      throw new Error(`config: ${name} must be an integer between ${min} and ${max} ms — failing closed`);
    }
    return n;
  };
  const authChallengeTtlMs = parsePositiveMs(
    "authChallengeTtlMs",
    overrides.authChallengeTtlMs ?? process.env.POLICYVAULT_AUTH_CHALLENGE_TTL_MS,
    5 * 60 * 1000,
    30 * 1000,
    15 * 60 * 1000
  );
  const authSessionInactivityMs = parsePositiveMs(
    "authSessionInactivityMs",
    overrides.authSessionInactivityMs ?? process.env.POLICYVAULT_AUTH_INACTIVITY_MS,
    30 * 60 * 1000,
    60 * 1000,
    24 * 60 * 60 * 1000
  );
  const authSessionAbsoluteMs = parsePositiveMs(
    "authSessionAbsoluteMs",
    overrides.authSessionAbsoluteMs ?? process.env.POLICYVAULT_AUTH_ABSOLUTE_MS,
    24 * 60 * 60 * 1000,
    60 * 1000,
    7 * 24 * 60 * 60 * 1000
  );
  if (authSessionAbsoluteMs < authSessionInactivityMs) {
    throw new Error("config: authSessionAbsoluteMs must be >= authSessionInactivityMs — failing closed");
  }
  if (authMode === "enabled") {
    let parsed;
    try {
      parsed = new URL(appOriginRaw);
    } catch {
      throw new Error(`config: appOrigin ${JSON.stringify(appOriginRaw)} is not a valid URL — failing closed`);
    }
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      parsed.pathname !== "/" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      parsed.username !== "" ||
      parsed.password !== ""
    ) {
      throw new Error("config: appOrigin must be a bare http(s) origin with no path/query/credentials — failing closed");
    }
    appOrigin = parsed.origin; // canonical form
    // Cookie security matrix (fail closed):
    //   https origin  -> Secure cookies MANDATORY (no insecure override).
    //   http origin   -> only with the EXPLICIT insecure override, and
    //                    never on mainnet (local/testnet testing only).
    if (parsed.protocol === "https:" && !authCookieSecure) {
      throw new Error("config: the insecure-cookie override is not allowed with an https appOrigin — failing closed");
    }
    if (parsed.protocol === "http:" && authCookieSecure) {
      throw new Error(
        "config: hosted auth over an http appOrigin requires the explicit insecure-cookie override " +
          "(POLICYVAULT_AUTH_COOKIE_INSECURE=1, local/testnet testing only) — browsers will not send Secure cookies over plaintext HTTP. Failing closed."
      );
    }
    if (parsed.protocol === "http:" && networkId === Network.MAINNET) {
      throw new Error("config: hosted auth on mainnet requires an https appOrigin with Secure cookies — failing closed");
    }
  } else if (cookieInsecureOverride && networkId === Network.MAINNET) {
    throw new Error("config: the insecure-cookie override must not be set on mainnet — failing closed");
  }

  /*
   * PERSISTENCE BACKEND (Phase C). json = the released self-hosted
   * filesystem backend (default; requires no database, no login).
   * postgres = the hosted multi-user backend. Unknown values fail
   * closed; postgres NEVER falls back to json (and vice versa).
   */
  const persistenceBackend = overrides.persistenceBackend ?? process.env.POLICYVAULT_PERSISTENCE ?? "json";
  if (persistenceBackend !== "json" && persistenceBackend !== "postgres") {
    throw new Error(`config: unknown persistenceBackend ${JSON.stringify(persistenceBackend)} — failing closed`);
  }
  let pg = null;
  if (persistenceBackend === "postgres") {
    const pgPortRaw = overrides.pgPort ?? process.env.POLICYVAULT_PG_PORT ?? "5432";
    const pgPort = Number(pgPortRaw);
    if (!Number.isInteger(pgPort) || pgPort < 1 || pgPort > 65535) {
      throw new Error("config: POLICYVAULT_PG_PORT must be a valid TCP port — failing closed");
    }
    const pgUser = overrides.pgUser ?? process.env.POLICYVAULT_PG_USER;
    const pgDatabase = overrides.pgDatabase ?? process.env.POLICYVAULT_PG_DATABASE;
    if (typeof pgUser !== "string" || !pgUser || typeof pgDatabase !== "string" || !pgDatabase) {
      throw new Error("config: postgres persistence requires POLICYVAULT_PG_USER and POLICYVAULT_PG_DATABASE — failing closed");
    }
    // Encrypted transport is the hosted default. The explicit no-TLS
    // override exists for LOCAL testing only and never on mainnet.
    const noTls = overrides.pgNoTls === true || process.env.POLICYVAULT_PG_NO_TLS === "1";
    if (noTls && networkId === Network.MAINNET) {
      throw new Error("config: POLICYVAULT_PG_NO_TLS must not be set on mainnet — failing closed");
    }
    const poolMax = Number(overrides.pgPoolMax ?? process.env.POLICYVAULT_PG_POOL_MAX ?? "10");
    if (!Number.isInteger(poolMax) || poolMax < 1 || poolMax > 100) {
      throw new Error("config: POLICYVAULT_PG_POOL_MAX must be an integer 1..100 — failing closed");
    }
    pg = Object.freeze({
      host: overrides.pgHost ?? process.env.POLICYVAULT_PG_HOST ?? "127.0.0.1",
      port: pgPort,
      user: pgUser,
      password: overrides.pgPassword ?? process.env.POLICYVAULT_PG_PASSWORD ?? undefined,
      database: pgDatabase,
      ssl: !noTls,
      poolMax,
      connectTimeoutMs: 5000
    });
    /*
     * HOSTED-SAFE BY DEFAULT (directive §44): a multi-user postgres
     * deployment without authentication would expose every tenant's
     * data. Refuse the combination unless the EXPLICIT development
     * override is set — and never on mainnet.
     */
    if (authMode !== "enabled") {
      const devOpen = overrides.hostedDevOpen === true || process.env.POLICYVAULT_HOSTED_DEV_OPEN === "1";
      if (!devOpen) {
        throw new Error(
          "config: postgres persistence (hosted multi-user mode) requires hosted authentication " +
            "(POLICYVAULT_HOSTED_AUTH=1). To run an OPEN single-user development instance set " +
            "POLICYVAULT_HOSTED_DEV_OPEN=1 (never available on mainnet). Failing closed."
        );
      }
      if (networkId === Network.MAINNET) {
        throw new Error("config: POLICYVAULT_HOSTED_DEV_OPEN must never be set on mainnet — failing closed");
      }
    }
  }

  /*
   * REQUEST PROTECTION (Phase D — origin/CSRF/rate-limit/DoS; see
   * server/src/limits.js and docs/hosted-request-protection.md). All
   * values validated here, fail closed. Rate limiting is MANDATORY in
   * hosted mode (authMode enabled) — there is no hosted off-switch; the
   * self-hosted loopback product keeps its released behavior (limits off
   * unless explicitly enabled).
   */
  const parseBoundedInt = (name, raw, fallback, min, max) => {
    if (raw === undefined) return fallback;
    const n = Number(raw);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
      throw new Error(`config: ${name} must be an integer between ${min} and ${max} — failing closed`);
    }
    return n;
  };
  const rateLimitsEnvRaw = process.env.POLICYVAULT_RATE_LIMITS;
  if (authMode === "enabled" && rateLimitsEnvRaw === "0") {
    throw new Error("config: rate limits cannot be disabled in hosted mode (authMode enabled) — failing closed");
  }
  const rateLimitsEnabled =
    overrides.rateLimitsEnabled === true || authMode === "enabled" || rateLimitsEnvRaw === "1";
  // Per-class request budgets: { limit, windowMs }. Env overrides adjust
  // the LIMIT only; windows are fixed per class. The auth limit is a DoS/
  // load bound, not a guessing bound (nonces are 256-bit, signatures
  // Schnorr) — strictness beyond load protection buys nothing.
  const defaultRateLimits = {
    auth: { limit: 60, windowMs: 10 * 60 * 1000 },
    build: { limit: 60, windowMs: 60 * 1000 },
    mutate: { limit: 120, windowMs: 60 * 1000 },
    submit: { limit: 30, windowMs: 60 * 1000 },
    rpcRead: { limit: 120, windowMs: 60 * 1000 },
    read: { limit: 600, windowMs: 60 * 1000 },
    static: { limit: 1200, windowMs: 60 * 1000 }
  };
  const rateLimitEnv = {
    auth: process.env.POLICYVAULT_RATE_AUTH,
    build: process.env.POLICYVAULT_RATE_BUILD,
    mutate: process.env.POLICYVAULT_RATE_MUTATE,
    submit: process.env.POLICYVAULT_RATE_SUBMIT,
    rpcRead: process.env.POLICYVAULT_RATE_RPC_READ,
    read: process.env.POLICYVAULT_RATE_READ,
    static: process.env.POLICYVAULT_RATE_STATIC
  };
  const rateLimits = {};
  for (const [cls, def] of Object.entries(defaultRateLimits)) {
    const o = overrides.rateLimits ? overrides.rateLimits[cls] : undefined;
    if (o !== undefined && (typeof o !== "object" || o === null)) {
      throw new Error(`config: rateLimits.${cls} override must be an object — failing closed`);
    }
    rateLimits[cls] = Object.freeze({
      limit: parseBoundedInt(`rateLimits.${cls}.limit`, o?.limit ?? rateLimitEnv[cls], def.limit, 1, 1_000_000),
      windowMs: parseBoundedInt(`rateLimits.${cls}.windowMs`, o?.windowMs, def.windowMs, 250, 24 * 60 * 60 * 1000)
    });
  }
  if (overrides.rateLimits) {
    for (const cls of Object.keys(overrides.rateLimits)) {
      if (!(cls in defaultRateLimits)) throw new Error(`config: unknown rate-limit class ${JSON.stringify(cls)} — failing closed`);
    }
  }
  // Concurrency semaphores (always active; queue + reject when saturated,
  // never unbounded — architecture §11). `rpc` bounds routes that dial
  // kaspad; `compute` bounds build/finalize/VM-preflight work.
  const semaphores = Object.freeze({
    rpc: Object.freeze({
      max: parseBoundedInt("rpcConcurrency", overrides.rpcConcurrency ?? process.env.POLICYVAULT_RPC_CONCURRENCY, 4, 1, 256),
      queue: parseBoundedInt("rpcQueue", overrides.rpcQueue ?? process.env.POLICYVAULT_RPC_QUEUE, 16, 0, 1024)
    }),
    compute: Object.freeze({
      max: parseBoundedInt("computeConcurrency", overrides.computeConcurrency ?? process.env.POLICYVAULT_COMPUTE_CONCURRENCY, 2, 1, 256),
      queue: parseBoundedInt("computeQueue", overrides.computeQueue ?? process.env.POLICYVAULT_COMPUTE_QUEUE, 8, 0, 1024)
    })
  });
  // Abandoned-request quota: open (cancellable) wallet requests per vault
  // and per signer wallet. Refusals are pure — they never touch durable
  // state; explicit cancellation (reject) frees quota.
  const openRequestQuota = Object.freeze({
    perVault: parseBoundedInt(
      "maxOpenRequestsPerVault",
      overrides.maxOpenRequestsPerVault ?? process.env.POLICYVAULT_MAX_OPEN_REQUESTS_PER_VAULT,
      32, 1, 10_000
    ),
    perWallet: parseBoundedInt(
      "maxOpenRequestsPerWallet",
      overrides.maxOpenRequestsPerWallet ?? process.env.POLICYVAULT_MAX_OPEN_REQUESTS_PER_WALLET,
      64, 1, 10_000
    )
  });
  // HTTP slow-client bounds (headers must finish, then the whole request
  // must be received, within these windows).
  const httpTimeouts = Object.freeze({
    headersMs: parseBoundedInt(
      "httpHeadersTimeoutMs",
      overrides.httpHeadersTimeoutMs ?? process.env.POLICYVAULT_HTTP_HEADERS_TIMEOUT_MS,
      15_000, 500, 300_000
    ),
    requestMs: parseBoundedInt(
      "httpRequestTimeoutMs",
      overrides.httpRequestTimeoutMs ?? process.env.POLICYVAULT_HTTP_REQUEST_TIMEOUT_MS,
      30_000, 500, 300_000
    )
  });
  if (httpTimeouts.headersMs > httpTimeouts.requestMs) {
    throw new Error("config: httpHeadersTimeoutMs must be <= httpRequestTimeoutMs — failing closed");
  }
  // Trusted proxy header for the CLIENT IP (trust-boundary B2): believed
  // ONLY when explicitly configured, and only sensible when the origin is
  // reachable exclusively through that proxy (Cloudflare Tunnel). Unknown
  // header names fail closed.
  const trustedProxyHeaderRaw = overrides.trustedProxyHeader ?? process.env.POLICYVAULT_TRUSTED_PROXY_HEADER ?? null;
  let trustedProxyHeader = null;
  if (trustedProxyHeaderRaw !== null && trustedProxyHeaderRaw !== "") {
    const candidate = String(trustedProxyHeaderRaw).toLowerCase();
    if (candidate !== "cf-connecting-ip" && candidate !== "x-real-ip") {
      throw new Error(
        `config: trustedProxyHeader ${JSON.stringify(trustedProxyHeaderRaw)} is not a supported single-value client-IP header (cf-connecting-ip, x-real-ip) — failing closed`
      );
    }
    trustedProxyHeader = candidate;
  }
  // Host allowlist: exact host[:port] strings (lowercase). The application
  // origin's host is always allowed in hosted mode; loopback-family hosts
  // are additionally allowed by server/src/limits.js in every mode (only a
  // machine-local client can present them — a DNS-rebinding browser always
  // presents the attacker's hostname). Extra entries are an explicit
  // operator act.
  const extraHostsRaw = overrides.extraHosts ?? process.env.POLICYVAULT_EXTRA_HOSTS ?? "";
  const extraHosts = [];
  const hostShape = /^(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(:\d{1,5})?$/;
  for (const entry of String(extraHostsRaw).split(",")) {
    const h = entry.trim().toLowerCase();
    if (!h) continue;
    if (!hostShape.test(h)) {
      throw new Error(`config: POLICYVAULT_EXTRA_HOSTS entry ${JSON.stringify(entry)} is not a valid host[:port] — failing closed`);
    }
    extraHosts.push(h);
  }
  const hostAllowlist = Object.freeze(
    authMode === "enabled" ? [new URL(appOrigin).host.toLowerCase(), ...extraHosts] : [...extraHosts]
  );
  const requestProtection = Object.freeze({
    // Hosted mode enforces the configured application origin on
    // state-changing requests; self-hosted keeps the released loopback
    // same-origin gate exactly.
    originEnforced: authMode === "enabled",
    hostAllowlist,
    trustedProxyHeader,
    rateLimitsEnabled,
    rateLimits: Object.freeze(rateLimits),
    semaphores,
    openRequestQuota,
    httpTimeouts
  });

  /*
   * DEPLOYMENT POSTURE (Phase E — containers/staging). All optional, all
   * validated, all fail closed; defaults preserve the released
   * self-hosted behavior exactly.
   *
   * bindAddress — the listener interface. Default 127.0.0.1 (the released
   * loopback deployment model). A container namespace may bind a
   * non-loopback interface (e.g. 0.0.0.0 INSIDE the container) as an
   * explicit operator act; only IP literals are accepted (never a
   * hostname — no DNS resolution decides where the server listens).
   */
  const bindAddressRaw = overrides.bindAddress ?? process.env.POLICYVAULT_BIND_ADDRESS ?? "127.0.0.1";
  const bindAddress = String(bindAddressRaw).trim();
  if (require("net").isIP(bindAddress) === 0) {
    throw new Error(
      `config: POLICYVAULT_BIND_ADDRESS ${JSON.stringify(bindAddressRaw)} is not an IP literal — failing closed`
    );
  }
  /*
   * buildId — non-secret deployment identity (git commit / image tag)
   * surfaced in /health so operators can prove WHICH build is running
   * (stale-deployment protection). Never derived from the request.
   */
  const buildIdRaw = overrides.buildId ?? process.env.POLICYVAULT_BUILD_ID ?? null;
  let buildId = null;
  if (buildIdRaw !== null && buildIdRaw !== "") {
    if (typeof buildIdRaw !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(buildIdRaw)) {
      throw new Error("config: POLICYVAULT_BUILD_ID must be 1..64 chars of [A-Za-z0-9._-] — failing closed");
    }
    buildId = buildIdRaw;
  }
  /*
   * stagingBanner — marks a deployment as a clearly-labeled
   * NON-PRODUCTION staging environment (/health reports staging:true and
   * the UI banner says so). A mainnet process must never be labeled
   * staging: the combination fails closed (staging is testnet-only).
   */
  const stagingBanner = overrides.stagingBanner === true || process.env.POLICYVAULT_STAGING_BANNER === "1";
  if (stagingBanner && networkId === Network.MAINNET) {
    throw new Error("config: POLICYVAULT_STAGING_BANNER must never be set on mainnet (staging is testnet-only) — failing closed");
  }

  return Object.freeze({
    networkId,
    rpcUrl,
    contractVersion: CONTRACT_VERSION,

    // Persistence backend (Phase C; see sdk/src/store.js).
    persistenceBackend,
    pg,
    // Tenancy enforcement follows hosted authentication: when a server
    // authenticates wallets, private surfaces are tenant-scoped to them.
    tenancyEnforced: authMode === "enabled",

    // Hosted authentication posture (Phase B; see server/src/auth.js).
    authMode,
    appOrigin,
    authCookieSecure,
    authChallengeTtlMs,
    authSessionInactivityMs,
    authSessionAbsoluteMs,
    authBearerSessionsEnabled,

    // Request protection (Phase D; see server/src/limits.js).
    requestProtection,

    // Deployment posture (Phase E; see docs/hosted-deployment.md).
    bindAddress,
    buildId,
    stagingBanner,

    repoRoot: REPO_ROOT,
    contractSource: path.join(REPO_ROOT, "contracts/PolicyVault.v0.1.beta.sil"),
    silvercPath: overrides.silvercPath ?? path.join(HOME, "silverscript/target/debug/silverc"),
    rustyKaspaModule: overrides.rustyKaspaModule ?? path.join(HOME, "rusty-kaspa/wasm/nodejs/kaspa"),

    // NETWORK DATA SEPARATION (Checkpoint I §11): mainnet and testnet
    // persistent state never share a directory. testnet-10 keeps the
    // historical `data/` root (all existing evidence stays valid); mainnet
    // uses its own `data-mainnet/` root. assertDataRootNetwork() additionally
    // stamps and enforces the owning network per root.
    dataRoot:
      overrides.dataRoot ??
      validatedEnvDataRoot() ??
      (networkId === Network.MAINNET ? path.join(REPO_ROOT, "data-mainnet") : path.join(REPO_ROOT, "data")),

    donationAddress: overrides.donationAddress ?? process.env.POLICYVAULT_DONATION_ADDRESS ?? DEFAULT_DONATION_ADDRESS,

    allowMainnet
  });
}

/*
 * Optional explicit data-root override for deployments (containers mount
 * a dedicated writable volume). Absolute path only — a relative root
 * would silently depend on the process working directory. The
 * `.pv-network` write-once stamp still binds whatever root is chosen to
 * exactly one network (assertDataRootNetwork).
 */
function validatedEnvDataRoot() {
  const raw = process.env.POLICYVAULT_DATA_ROOT;
  if (raw === undefined || raw === "") return undefined;
  if (!path.isAbsolute(raw)) {
    throw new Error(`config: POLICYVAULT_DATA_ROOT must be an absolute path — failing closed`);
  }
  return raw;
}

/*
 * Operational-network gate (Gate R, authorized by the owner 2026-08-22:
 * "Authorize Gate R. Enable PolicyVault mainnet production release.").
 * The live transaction pipeline (build / preflight / submit / reconcile)
 * operates on EXACTLY two networks: testnet-10, and mainnet when — and only
 * when — the config object carries the dual-flag unlock that loadConfig
 * grants (env flag AND explicit override). A hand-rolled mainnet config
 * without that unlock, and every other network id, fails closed here even
 * though loadConfig would already have refused to construct it.
 */
function assertOperationalNetwork(config) {
  const networkId = config ? config.networkId : undefined;
  if (networkId === Network.TESTNET_10) return networkId;
  if (networkId === Network.MAINNET) {
    if (config.allowMainnet !== true) {
      const e = new Error("network: mainnet config lacks the dual-flag unlock (allowMainnet) — refusing");
      e.code = "NETWORK_UNSUPPORTED";
      throw e;
    }
    return networkId;
  }
  const e = new Error(`network: ${JSON.stringify(networkId)} is not an operational PolicyVault network — failing closed`);
  e.code = "NETWORK_UNSUPPORTED";
  throw e;
}

/*
 * Cross-network contamination gate (§11): every data root is stamped with the
 * ONE network that owns it (`.pv-network`, write-once). A process configured
 * for a different network REFUSES to touch the root — a mainnet process can
 * never consume testnet manifests/requests/claims, and vice versa. Called at
 * server startup; safe to call repeatedly.
 */
function assertDataRootNetwork(config) {
  fs.mkdirSync(config.dataRoot, { recursive: true });
  const marker = path.join(config.dataRoot, ".pv-network");
  if (fs.existsSync(marker)) {
    const owner = fs.readFileSync(marker, "utf8").trim();
    if (owner !== config.networkId) {
      throw new Error(
        `data root ${config.dataRoot} belongs to network ${JSON.stringify(owner)} but this process is configured for ${JSON.stringify(config.networkId)} — refusing to start (cross-network data contamination)`
      );
    }
    return config.dataRoot;
  }
  fs.writeFileSync(marker, `${config.networkId}\n`, { mode: 0o600 });
  return config.dataRoot;
}

module.exports = {
  Network,
  CONTRACT_VERSION,
  DEFAULT_DONATION_ADDRESS,
  loadConfig,
  assertOperationalNetwork,
  assertDataRootNetwork
};
