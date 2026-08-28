"use strict";

/*
 * Idempotent machine operations (completion-standard surface 14;
 * docs/postlaunch/platform-agent-api-spec.md).
 *
 * Header-driven: a POST that carries `Idempotency-Key` is wrapped; a POST
 * without it behaves EXACTLY as before (this is why the existing web
 * client — which never sends the header — sees zero behavior change).
 *
 * Semantics (Stripe-style, adapted to this codebase's existing CAS-claim
 * idiom — server/src/auth.js challengeClaim is the direct precedent):
 *   1. CLAIM the key (store.createExclusive). Win -> execute for real.
 *   2. Lose (key exists):
 *      - stored request fingerprint differs -> 409 IDEMPOTENCY_KEY_CONFLICT
 *        (deterministic refusal; the underlying handler is never called).
 *      - fingerprint matches, still IN_PROGRESS, not stale -> 409
 *        IDEMPOTENCY_IN_PROGRESS (a genuine concurrent duplicate: the
 *        SECOND caller never reaches the handler, so at most ONE durable
 *        mutation happens no matter how many identical requests race).
 *      - fingerprint matches, IN_PROGRESS but stale (a crashed handler
 *        that never completed) -> ONE reclaim attempt, then handled as a
 *        fresh claim or falls back to IN_PROGRESS on a lost race.
 *      - COMPLETE -> replay the ORIGINAL response verbatim, with an
 *        idempotency-replay marker.
 *   3. On completion of a REAL execution:
 *      - a durable outcome (2xx, or a deterministic <500 business
 *        refusal — e.g. governance/risk DENY, validation errors) is
 *        recorded and will be replayed on any retry with the same key.
 *      - a transient outcome (no status, or >=500 — an infrastructure
 *        failure: RPC down, store unavailable, an unexpected internal
 *        throw) RELEASES the claim instead of poisoning the key forever;
 *        the original error still propagates to THIS caller once.
 *
 * Scoped per authenticated identity (`principalScope`): two different
 * callers can never collide or replay each other's keys, and the SAME
 * caller replaying a key against a DIFFERENT body is a conflict, never a
 * silent reuse.
 */

const crypto = require("crypto");
const { Categories, getPlatformStore } = require("./platform-store");
const { canonicalJsonStringify } = require("../../core/intent");

const SCHEMA = "policyvault-idempotency-record/v1";
const KEY_RE = /^[A-Za-z0-9_.:-]{1,200}$/;
const IN_PROGRESS_STALE_MS = 5 * 60 * 1000;

function fail(status, code, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (extra) e.extra = extra;
  return e;
}

/* The caller's identity for idempotency-key SCOPING (never authorization —
 * that happens elsewhere). Mirrors machine-identity.js/tenancy.js identity
 * shapes without importing route-authorization logic here. */
function scopeForPrincipal(principal) {
  if (principal && principal.isMachine) return `machine:${principal.identityId}`;
  if (principal && typeof principal.xOnlyPubkey === "string") return `wallet:${principal.xOnlyPubkey}`;
  return "anonymous"; // self-hosted / unauthenticated hosted request
}

function requestFingerprint({ method, segments, query, body }) {
  return crypto
    .createHash("sha256")
    .update(canonicalJsonStringify({ method, path: segments, query: query ?? {}, body: body ?? null }), "utf8")
    .digest("hex");
}

function validateKey(rawKey) {
  if (typeof rawKey !== "string" || !KEY_RE.test(rawKey)) {
    throw fail(400, "IDEMPOTENCY_KEY_INVALID", "Idempotency-Key must be 1..200 characters of [A-Za-z0-9_.:-]");
  }
  return rawKey;
}

/*
 * Wrap one mutating call. `run()` returns { status, body, headers? } on
 * success or throws an apiError-shaped error (status/code/message/extra).
 * Returns the SAME shape `run()` would; on a durable replay/first-recorded
 * outcome the body additionally carries `idempotency: { replayed }`.
 */
async function withIdempotency(config, { rawKey, principal, method, segments, query, body }, run) {
  const idempotencyKey = validateKey(rawKey);
  const scope = scopeForPrincipal(principal);
  const compositeKey = `${scope}:${idempotencyKey}`;
  const fingerprint = requestFingerprint({ method, segments, query, body });
  const store = getPlatformStore(config);

  const claimNow = () =>
    store.createExclusive(Categories.IDEMPOTENCY, compositeKey, {
      schema: SCHEMA,
      status: "IN_PROGRESS",
      requestFingerprint: fingerprint,
      response: null,
      createdAtMs: Date.now(),
      completedAtMs: null
    });

  let won = await claimNow();
  if (!won) {
    const existing = await store.read(Categories.IDEMPOTENCY, compositeKey);
    if (existing && existing.status === "IN_PROGRESS" && Date.now() - existing.createdAtMs > IN_PROGRESS_STALE_MS) {
      await store.remove(Categories.IDEMPOTENCY, compositeKey); // best-effort reclaim of a crashed attempt
      won = await claimNow();
    }
  }

  if (!won) {
    const existing = await store.read(Categories.IDEMPOTENCY, compositeKey);
    if (!existing || existing.schema !== SCHEMA) {
      // Lost the reclaim race to a third party and the record vanished
      // again between our two reads — treat as busy (safe, retryable).
      throw fail(409, "IDEMPOTENCY_IN_PROGRESS", "a request with this Idempotency-Key is already in progress — retry shortly");
    }
    if (existing.requestFingerprint !== fingerprint) {
      throw fail(409, "IDEMPOTENCY_KEY_CONFLICT", "this Idempotency-Key was already used with a different request body — use a new key for a different request");
    }
    if (existing.status === "IN_PROGRESS") {
      throw fail(409, "IDEMPOTENCY_IN_PROGRESS", "a request with this Idempotency-Key is already in progress — retry shortly");
    }
    // COMPLETE: replay the ORIGINAL outcome verbatim.
    const outcome = existing.response;
    if (outcome.kind === "success") {
      return { status: outcome.status, body: { ...outcome.body, idempotency: { replayed: true, key: idempotencyKey } }, headers: outcome.headers ?? undefined };
    }
    const e = new Error(outcome.message);
    e.status = outcome.status;
    e.code = outcome.code;
    e.extra = { ...(outcome.extra ?? {}), idempotency: { replayed: true, key: idempotencyKey } };
    throw e;
  }

  // We hold the claim: execute for real, exactly once.
  let outcome;
  try {
    const result = await run();
    outcome = { kind: "success", status: result.status, body: result.body, headers: result.headers };
  } catch (error) {
    const status = error && error.status;
    const isDurableRefusal = typeof status === "number" && status >= 400 && status < 500;
    if (!isDurableRefusal) {
      // Transient/infrastructure failure: never poison the key.
      await store.remove(Categories.IDEMPOTENCY, compositeKey).catch(() => {});
      throw error;
    }
    outcome = { kind: "error", status, code: error.code || "ERROR", message: error.message, extra: error.extra ?? null };
  }

  await store.write(Categories.IDEMPOTENCY, compositeKey, {
    schema: SCHEMA,
    status: "COMPLETE",
    requestFingerprint: fingerprint,
    response: outcome,
    createdAtMs: Date.now(),
    completedAtMs: Date.now()
  });

  if (outcome.kind === "success") {
    return { status: outcome.status, body: { ...outcome.body, idempotency: { replayed: false, key: idempotencyKey } }, headers: outcome.headers };
  }
  const e = new Error(outcome.message);
  e.status = outcome.status;
  e.code = outcome.code;
  e.extra = { ...(outcome.extra ?? {}), idempotency: { replayed: false, key: idempotencyKey } };
  throw e;
}

module.exports = { withIdempotency, scopeForPrincipal, requestFingerprint, IN_PROGRESS_STALE_MS, SCHEMA };
