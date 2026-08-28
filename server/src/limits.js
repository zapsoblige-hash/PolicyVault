"use strict";

/*
 * PolicyVault request protection (Phase D of the Hosted Web Architecture
 * + Security checkpoint): Origin/Host verification, per-class rate
 * limits, concurrency semaphores, and input-shape caps.
 *
 * NONE of this is the funds-security boundary (Kaspa consensus is). This
 * layer bounds abuse of the HOSTED surface: cross-site request forgery,
 * DNS rebinding, request floods, slow clients, and resource exhaustion.
 * Every refusal is PURE — it happens before any durable mutation, so a
 * throttled or refused request never touches manifests, requests,
 * claims, or covenant state (a throttled submission keeps its claims
 * exactly as an ambiguous submission does; reconcile remains the
 * recovery path).
 *
 * Model reference: docs/hosted-request-protection.md.
 */

/* Machine-readable protection errors (same envelope as api.js errors). */
function limitError(status, code, message, retryAfterSeconds) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (retryAfterSeconds !== undefined) e.retryAfterSeconds = retryAfterSeconds;
  return e;
}

/* ------------------------------------------------------------------ */
/* Host verification                                                   */
/* ------------------------------------------------------------------ */

const HOST_SHAPE = /^(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(:\d{1,5})?$/;

/* Loopback-family hostnames. Only a machine-local client (or a client
 * that hand-sets its own Host header — never a browser) can present
 * these: a DNS-rebinding browser always presents the ATTACKER'S
 * hostname, which this check refuses. */
function isLoopbackHostname(hostname) {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]";
}

function parseHost(hostHeader) {
  if (typeof hostHeader !== "string") return null;
  const host = hostHeader.trim().toLowerCase();
  if (!host || host.length > 255 || !HOST_SHAPE.test(host)) return null;
  try {
    const u = new URL(`http://${host}`);
    return { host, hostname: u.hostname, port: u.port };
  } catch {
    return null;
  }
}

/*
 * Host validation (trust boundary B2; DNS-rebinding guard). Allowed:
 * loopback-family hosts (any port; see above) and the configured
 * allowlist (hosted: the application origin's host, plus explicit
 * POLICYVAULT_EXTRA_HOSTS entries). Hosted mode REQUIRES a Host header;
 * self-hosted tolerates its absence (HTTP/1.0 tooling against the
 * loopback-bound listener) but refuses a present non-loopback Host.
 */
function verifyHost(config, hostHeader) {
  const rp = config.requestProtection;
  if (hostHeader === undefined || hostHeader === "") {
    if (rp.originEnforced) {
      throw limitError(400, "HOST_REQUIRED", "a Host header is required");
    }
    return;
  }
  const parsed = parseHost(hostHeader);
  if (!parsed) {
    throw limitError(400, "HOST_FORBIDDEN", "malformed Host header");
  }
  if (isLoopbackHostname(parsed.hostname)) return;
  if (rp.hostAllowlist.includes(parsed.host)) return;
  throw limitError(
    421,
    "HOST_FORBIDDEN",
    "this server does not serve the requested host"
  );
}

/* ------------------------------------------------------------------ */
/* Origin verification (CSRF wall #2 — SameSite=Strict cookies are #1)  */
/* ------------------------------------------------------------------ */

/*
 * A request carries no ambient browser credential AT ALL and presents a
 * syntactically plausible machine Bearer credential (server/src/machine-
 * identity.js token shape checked cryptographically downstream, in
 * requestAuthPrincipal — this is only a cheap SHAPE pre-filter, kept
 * deliberately loose/generic here since limits.js has no store access and
 * must stay a fast, dependency-light synchronous check).
 */
const MACHINE_BEARER_SHAPE = /^Bearer\s+\S{20,300}$/i;

/*
 * State-changing requests must prove browser same-origin intent.
 *
 * Self-hosted (originEnforced=false) keeps the RELEASED semantics
 * exactly: requests without an Origin header pass (curl, local tools);
 * a browser-sent Origin must be loopback AND match the Host header.
 *
 * Hosted (originEnforced=true): a present Origin must equal the
 * configured application origin exactly ("null" refused), with the
 * loopback-and-Host-matching allowance for machine-local hosted
 * simulation (a production request that reaches this path with a
 * loopback Origin+Host came from inside the box — Tunnel topology has
 * no public inbound port). Without an Origin header the request must
 * carry `Sec-Fetch-Site: same-origin`; anything else is refused —
 * programmatic hosted clients set `Origin: <appOrigin>` explicitly.
 * A mismatched Origin is never rescued by Sec-Fetch-Site.
 *
 * PROGRAMMATIC-CLIENT EXEMPTION (platform-agent-api addendum, surface
 * "origin policy"; docs/postlaunch/platform-agent-api-spec.md §origin
 * policy has the full reasoning): CSRF is fundamentally an AMBIENT-
 * credential attack — a cross-origin attacker page cannot read the
 * victim's response, but the victim's BROWSER still automatically
 * attaches cookies to the forged request, so the mutation happens
 * anyway. A `Authorization: Bearer <token>` header is never ambient: no
 * browser mechanism attaches it automatically, so a cross-origin page
 * cannot forge one it does not already know — and if it already knows a
 * valid token, it is an authenticated party, not a forgery (the token
 * itself is verified cryptographically downstream in
 * requestAuthPrincipal; an invalid/unknown one is refused there
 * regardless of this exemption). The exemption therefore applies ONLY
 * when NO Cookie header is present at all — a request carrying BOTH a
 * cookie and a bearer header (or a cookie alone) gets the FULL,
 * UNCHANGED origin wall below; a cookie session can never mutate
 * cross-origin, exactly as before this addendum.
 */
function verifyOrigin(config, { method, origin, secFetchSite, host, cookie, authorization }) {
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return;
  const rp = config.requestProtection;

  if (!rp.originEnforced) {
    if (!origin) return;
    if (loopbackOriginMatchesHost(origin, host)) return;
    throw limitError(403, "ORIGIN_FORBIDDEN", "cross-origin requests are not allowed");
  }

  if (!cookie && typeof authorization === "string" && MACHINE_BEARER_SHAPE.test(authorization.trim())) {
    return; // no ambient credential in play — see the doc comment above
  }

  if (origin) {
    if (origin === "null") {
      throw limitError(403, "ORIGIN_FORBIDDEN", "opaque (null) origins are not allowed");
    }
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw limitError(403, "ORIGIN_FORBIDDEN", "malformed Origin header");
    }
    if (parsed.origin === config.appOrigin) return;
    if (loopbackOriginMatchesHost(origin, host)) return;
    throw limitError(403, "ORIGIN_FORBIDDEN", "cross-origin requests are not allowed");
  }

  if (typeof secFetchSite === "string" && secFetchSite.trim().toLowerCase() === "same-origin") return;
  throw limitError(
    403,
    "ORIGIN_REQUIRED",
    `state-changing requests require an Origin header matching ${config.appOrigin} (browsers send it automatically; programmatic clients must set it)`
  );
}

/* The released self-hosted rule, verbatim semantics: Origin hostname is
 * loopback AND `${hostname}:${effective port}` equals the Host header. */
function loopbackOriginMatchesHost(origin, host) {
  try {
    const o = new URL(origin);
    if (o.hostname !== "127.0.0.1" && o.hostname !== "localhost") return false;
    const effective = `${o.hostname}:${o.port || (o.protocol === "https:" ? "443" : "80")}`;
    return typeof host === "string" && effective === host;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* Client IP (trusted-proxy aware)                                     */
/* ------------------------------------------------------------------ */

const IP_SHAPE = /^[0-9a-fA-F:.]{3,45}$/;

/*
 * The client IP used as a rate-limit key. The trusted proxy header is
 * believed ONLY when explicitly configured (config.requestProtection
 * .trustedProxyHeader — sensible only when the origin is reachable
 * exclusively through that proxy, e.g. Cloudflare Tunnel). A missing or
 * malformed header value falls back to the socket address — never an
 * error, so a direct VPC-internal health probe still works.
 */
function clientIp(config, req) {
  const hdr = config.requestProtection.trustedProxyHeader;
  if (hdr) {
    const raw = req.headers[hdr];
    if (typeof raw === "string") {
      const v = raw.trim();
      if (IP_SHAPE.test(v)) return v.toLowerCase();
    }
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

/* ------------------------------------------------------------------ */
/* Rate limiter (fixed window per class+key, bounded memory)           */
/* ------------------------------------------------------------------ */

class RateLimiter {
  /*
   * `limits`: { [cls]: { limit, windowMs } } (config.requestProtection
   * .rateLimits). Fixed-window counting: simple, allocation-light, and
   * honest about its boundary behavior (a burst can span two windows —
   * documented; the semaphores independently bound instantaneous
   * concurrency). Memory is bounded: at most `maxKeys` live buckets;
   * beyond that, expired buckets are swept and oldest buckets evicted.
   */
  constructor(limits, { maxKeys = 50_000, now = () => Date.now() } = {}) {
    this._limits = limits;
    this._maxKeys = maxKeys;
    this._now = now;
    this._buckets = new Map(); // "cls|key" -> { start, count }
  }

  /* Returns undefined when allowed; throws 429 RATE_LIMITED otherwise. */
  check(cls, key) {
    const cfg = this._limits[cls];
    if (!cfg) {
      // Classification must be exhaustive — an unknown class fails closed.
      throw limitError(500, "RATE_CLASS_UNKNOWN", `internal: unknown rate-limit class ${JSON.stringify(cls)}`);
    }
    const nowMs = this._now();
    const id = `${cls}|${key}`;
    let bucket = this._buckets.get(id);
    if (!bucket || nowMs - bucket.start >= cfg.windowMs) {
      this._evictIfNeeded(nowMs);
      bucket = { start: nowMs, count: 0 };
      this._buckets.set(id, bucket);
    }
    bucket.count += 1;
    if (bucket.count > cfg.limit) {
      const retryAfterSeconds = Math.max(1, Math.ceil((bucket.start + cfg.windowMs - nowMs) / 1000));
      throw limitError(429, "RATE_LIMITED", "too many requests — slow down", retryAfterSeconds);
    }
  }

  _evictIfNeeded(nowMs) {
    if (this._buckets.size < this._maxKeys) return;
    // First pass: drop expired buckets (their windows are over anyway).
    for (const [id, b] of this._buckets) {
      const cls = id.slice(0, id.indexOf("|"));
      const cfg = this._limits[cls];
      if (!cfg || nowMs - b.start >= cfg.windowMs) this._buckets.delete(id);
    }
    // Still full: evict oldest-inserted buckets (bounded memory beats
    // perfect per-key fairness under a key-spraying attack).
    while (this._buckets.size >= this._maxKeys) {
      const oldest = this._buckets.keys().next().value;
      if (oldest === undefined) break;
      this._buckets.delete(oldest);
    }
  }

  size() {
    return this._buckets.size;
  }
}

/* ------------------------------------------------------------------ */
/* Concurrency semaphore (bounded queue; reject when saturated)        */
/* ------------------------------------------------------------------ */

class Semaphore {
  constructor({ max, queue }) {
    this._max = max;
    this._queueMax = queue;
    this._active = 0;
    this._waiters = [];
  }

  /*
   * Resolves to a release() function (idempotent). When `max` slots are
   * busy the caller waits in a bounded FIFO queue; beyond `queue`
   * waiters the request is refused immediately with 429 SERVER_BUSY —
   * never unbounded buffering.
   */
  async acquire() {
    if (this._active < this._max) {
      this._active += 1;
      return this._makeRelease();
    }
    if (this._waiters.length >= this._queueMax) {
      throw limitError(429, "SERVER_BUSY", "the server is at capacity for this operation — retry shortly", 2);
    }
    await new Promise((resolve) => this._waiters.push(resolve));
    this._active += 1;
    return this._makeRelease();
  }

  _makeRelease() {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this._active -= 1;
      const next = this._waiters.shift();
      if (next) next();
    };
  }

  stats() {
    return { active: this._active, queued: this._waiters.length };
  }
}

/* ------------------------------------------------------------------ */
/* Route classification (single source of truth for limits/semaphores) */
/* ------------------------------------------------------------------ */

/*
 * Maps an API request (method + path segments AFTER /api/v1) to its
 * rate class and semaphore group. Strictest classes are the expensive
 * ones (build, submit, RPC-backed reads); unknown routes default to the
 * ordinary class for their method and then 404 in the handler.
 *   rateClass ∈ config.requestProtection.rateLimits keys
 *   semaphore ∈ "rpc" | "compute" | null
 */
function classifyRoute(method, segments) {
  const s0 = segments[0];
  if (s0 === "auth") {
    return method === "POST" ? { rateClass: "auth", semaphore: null } : { rateClass: "read", semaphore: null };
  }
  if (s0 === "network") return { rateClass: "rpcRead", semaphore: "rpc" };
  if (s0 === "wallet") {
    const s1 = segments[1];
    if (s1 === "fuel") return { rateClass: "rpcRead", semaphore: "rpc" };
    if (method === "GET") return { rateClass: "read", semaphore: null };
    if (s1 === "create") return { rateClass: "build", semaphore: "compute" };
    if (s1 === "requests" && segments.length === 2) return { rateClass: "build", semaphore: "compute" };
    if (s1 === "requests" && segments[3] === "signature") return { rateClass: "mutate", semaphore: "compute" };
    if (s1 === "v4") {
      if (segments[2] === "create") return { rateClass: "build", semaphore: "compute" };
      if (segments[2] === "requests" && segments.length === 3) return { rateClass: "build", semaphore: "compute" };
      // simulate runs the SAME compute-bound builder (silverc + the call
      // encoder, spawned subprocesses) as create/requests above — the
      // SAME class/semaphore, even though it persists nothing.
      if (segments[2] === "simulate") return { rateClass: "build", semaphore: "compute" };
      const tail = segments[4];
      if (tail === "submit" || tail === "genesis-submit") return { rateClass: "submit", semaphore: "rpc" };
      if (tail === "signature" || tail === "approvals") return { rateClass: "mutate", semaphore: "compute" };
      return { rateClass: "mutate", semaphore: null }; // reject etc.
    }
    return { rateClass: "mutate", semaphore: null }; // dev-sign, reject etc.
  }
  if (s0 === "vaults") {
    if (segments[2] === "reconcile") return { rateClass: "submit", semaphore: "rpc" };
    if (segments[2] === "status") return { rateClass: "rpcRead", semaphore: "rpc" };
    return method === "GET" ? { rateClass: "read", semaphore: null } : { rateClass: "mutate", semaphore: null };
  }
  // identities* (machine-identity management, mutate-class default below)
  // and capabilities (read-class default below) need no special casing —
  // both are cheap, in-process, non-RPC operations.
  return method === "GET" ? { rateClass: "read", semaphore: null } : { rateClass: "mutate", semaphore: null };
}

/* ------------------------------------------------------------------ */
/* Parsed-body shape cap                                               */
/* ------------------------------------------------------------------ */

/*
 * Depth cap over an already-parsed JSON value (the 1 MB size cap runs
 * before parsing). Iterative — the guard itself must not recurse.
 */
function assertJsonDepth(value, maxDepth = 64) {
  let stack = [{ v: value, d: 1 }];
  while (stack.length) {
    const { v, d } = stack.pop();
    if (v === null || typeof v !== "object") continue;
    if (d > maxDepth) {
      throw limitError(400, "BODY_TOO_DEEP", `request body exceeds the maximum JSON nesting depth (${maxDepth})`);
    }
    for (const key of Object.keys(v)) {
      stack.push({ v: v[key], d: d + 1 });
    }
  }
}

module.exports = {
  limitError,
  verifyHost,
  verifyOrigin,
  clientIp,
  RateLimiter,
  Semaphore,
  classifyRoute,
  assertJsonDepth,
  isLoopbackHostname,
  parseHost,
  MACHINE_BEARER_SHAPE
};
