"use strict";

/* Header-driven idempotency, scoped by the already-authenticated caller.
 * A claim never expires or resets. Time and handler errors do not establish
 * absence of effects. Only its owner may record a completion. The exact
 * response is first retained in the claim, so finalization can be recovered
 * without rerunning the handler. See docs/postlaunch/idempotency-recovery.md.
 * Scope selection here is not authorization; callers must enforce it first. */
const crypto = require("crypto");
const { isDeepStrictEqual } = require("node:util");
const { Categories, getPlatformStore } = require("./platform-store");
const { canonicalJsonStringify } = require("../../core/intent");
const SCHEMA = "policyvault-idempotency-record/v1";
const COMPLETION_SCHEMA = "policyvault-idempotency-completion/v1";
const KEY_RE = /^[A-Za-z0-9_.:-]{1,200}$/;
// Retained export for source compatibility only. Age never grants ownership.
const IN_PROGRESS_STALE_MS = 5 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function fail(status, code, message, extra) {
  return Object.assign(new Error(message), { status, code, ...(extra ? { extra } : {}) });
}
function unknown(key, status = 503) {
  return fail(status, "IDEMPOTENCY_OUTCOME_UNKNOWN", "the original operation remains unresolved; inspect its retained outcome before any further action", { idempotency: { key, replayed: false, state: "UNRESOLVED" } });
}
function scopeForPrincipal(principal) {
  if (principal && principal.isMachine) return `machine:${principal.identityId}`;
  if (principal && typeof principal.xOnlyPubkey === "string") return `wallet:${principal.xOnlyPubkey}`;
  return "anonymous";
}
function requestFingerprint({ method, segments, query, body }) {
  return crypto.createHash("sha256").update(canonicalJsonStringify({ method, path: segments, query: query ?? {}, body: body ?? null }), "utf8").digest("hex");
}
function binding(config, args) {
  if (typeof args.rawKey !== "string" || !KEY_RE.test(args.rawKey)) throw fail(400, "IDEMPOTENCY_KEY_INVALID", "Idempotency-Key must be 1..200 characters of [A-Za-z0-9_.:-]");
  return { store: getPlatformStore(config), key: `${scopeForPrincipal(args.principal)}:${args.rawKey}`, rawKey: args.rawKey, fingerprint: requestFingerprint(args), networkId: config.networkId };
}
function jsonValue(value) { return JSON.parse(JSON.stringify(value, (_, v) => typeof v === "bigint" ? v.toString() : v)); }
function validOutcome(outcome) {
  return outcome && Number.isInteger(outcome.status) &&
    (outcome.kind === "success" && outcome.status >= 200 && outcome.status < 500 ||
     outcome.kind === "error" && outcome.status >= 400 && outcome.status < 500 && typeof outcome.code === "string" && typeof outcome.message === "string");
}
function isLegacyRecord(record) {
  // Field presence distinguishes the old shape. Falsy or malformed new
  // fields must not discard a receipt's owner/binding validation.
  return !["claimId", "completionReceipt", "outcomeState"].some(key => Object.hasOwn(record, key));
}
function checkRecord(b, record) {
  if (!record || record.schema !== SCHEMA) throw unknown(b.rawKey, 409);
  if (record.requestFingerprint !== b.fingerprint) throw fail(409, "IDEMPOTENCY_KEY_CONFLICT", "this Idempotency-Key is bound to a different request; inspect the original operation before further action");
  if (!["IN_PROGRESS", "COMPLETE"].includes(record.status) || !Number.isSafeInteger(record.createdAtMs) || record.createdAtMs < 0) throw unknown(b.rawKey, 409);
  if (!isLegacyRecord(record)) {
    if (!Object.hasOwn(record, "claimId") || typeof record.claimId !== "string" || !UUID_RE.test(record.claimId)) throw unknown(b.rawKey, 409);
    if (Object.hasOwn(record, "completionReceipt") && !validReceipt(b, record)) throw unknown(b.rawKey, 409);
    if (record.status === "COMPLETE" && (!validReceipt(b, record) ||
        !isDeepStrictEqual(record.response, record.completionReceipt.response) ||
        record.completedAtMs !== record.completionReceipt.completedAtMs)) throw unknown(b.rawKey, 409);
  }
  if (record.status === "COMPLETE" && !validOutcome(record.response)) throw unknown(b.rawKey, 409);
}
function validReceipt(b, record) {
  const r = record.completionReceipt;
  return r && r.schema === COMPLETION_SCHEMA && UUID_RE.test(record.claimId) &&
    r.claimId === record.claimId && r.networkId === b.networkId && r.compositeKey === b.key && r.requestFingerprint === b.fingerprint &&
    r.createdAtMs === record.createdAtMs && Number.isSafeInteger(r.completedAtMs) && r.completedAtMs >= 0 && validOutcome(r.response);
}
function completed(record) {
  return { ...record, status: "COMPLETE", response: record.completionReceipt.response, completedAtMs: record.completionReceipt.completedAtMs };
}
function deliver(outcome, rawKey, replayed) {
  if (outcome.kind === "success") return { status: outcome.status, body: { ...outcome.body, idempotency: { replayed, key: rawKey } }, headers: outcome.headers };
  throw fail(outcome.status, outcome.code, outcome.message, { ...(outcome.extra ?? {}), idempotency: { replayed, key: rawKey } });
}
async function read(b) { return b.store.read(Categories.IDEMPOTENCY, b.key); }
async function advance(b, expected, next) {
  try { if (await b.store.compareIdempotency(b.key, expected, next)) return next; } catch { /* A missing acknowledgement is not a failed write. */ }
  // Readback may establish this exact transition. A different owner, value or
  // unavailable read never grants permission to overwrite or execute again.
  try { const current = await read(b); if (isDeepStrictEqual(current, next)) return current; } catch { /* retain uncertainty */ }
  throw unknown(b.rawKey);
}
async function finalize(b, record) {
  if (!validReceipt(b, record)) throw unknown(b.rawKey, 409);
  return advance(b, record, completed(record));
}
async function existingOutcome(b) {
  let record = await read(b); checkRecord(b, record);
  if (record.status === "COMPLETE") return record.response;
  if (record.completionReceipt) { record = await finalize(b, record); return record.response; }
  if (record.outcomeState === "UNKNOWN") throw unknown(b.rawKey, 409);
  throw fail(409, "IDEMPOTENCY_IN_PROGRESS", "the original request remains in progress; age never permits another execution");
}
async function withIdempotency(config, args, run) {
  const b = binding(config, args);
  const claim = { schema: SCHEMA, status: "IN_PROGRESS", claimId: crypto.randomUUID(), requestFingerprint: b.fingerprint, response: null, createdAtMs: Date.now(), completedAtMs: null };
  let won;
  try { won = await b.store.createExclusive(Categories.IDEMPOTENCY, b.key, claim); }
  catch { throw unknown(b.rawKey); } // run has not started; preserve any unacknowledged claim.
  if (!won) return deliver(await existingOutcome(b), b.rawKey, true);
  let outcome;
  try {
    const result = await run();
    outcome = { kind: "success", status: result.status, body: result.body, headers: result.headers };
    if (!validOutcome(outcome)) throw new Error("handler did not return a definitive response");
  } catch (error) {
    const status = error && error.status;
    if (!Number.isInteger(status) || status < 400 || status >= 500) {
      // Best-effort classification only; failure leaves the original claim.
      // This CAS cannot replace a prepared response or another owner's record.
      try { await advance(b, claim, { ...claim, outcomeState: "UNKNOWN" }); } catch { /* original remains protected */ }
      throw unknown(b.rawKey);
    }
    outcome = { kind: "error", status, code: error.code || "ERROR", message: error.message, extra: error.extra ?? null };
  }
  let prepared;
  try {
    const response = jsonValue(outcome);
    if (!validOutcome(response)) throw new Error("invalid durable response");
    prepared = { ...claim, completionReceipt: { schema: COMPLETION_SCHEMA, networkId: b.networkId, compositeKey: b.key, claimId: claim.claimId, requestFingerprint: b.fingerprint, createdAtMs: claim.createdAtMs, completedAtMs: Date.now(), response } };
  } catch { throw unknown(b.rawKey); }
  await advance(b, claim, prepared);
  const result = await finalize(b, prepared);
  return deliver(result.response, b.rawKey, false);
}

/* Trusted local maintenance helpers, not public routes and not authorization
 * entry points. They require the exact original principal/key/request binding.
 * Inspection returns metadata, never the stored response. Recovery has no
 * handler or supplied-outcome argument: it only finalizes a retained receipt. */
async function inspectIdempotency(config, args) {
  const b = binding(config, args), record = await read(b);
  if (!record) return { state: "ABSENT", recoverable: false };
  checkRecord(b, record);
  const hasReceipt = validReceipt(b, record);
  if (record.completionReceipt && !hasReceipt) throw unknown(b.rawKey, 409);
  const state = record.status === "COMPLETE" ? "COMPLETE" : hasReceipt ? "COMPLETION_AVAILABLE" : record.outcomeState === "UNKNOWN" ? "UNRESOLVED" : "IN_PROGRESS";
  return { state, recoverable: state === "COMPLETION_AVAILABLE", legacy: isLegacyRecord(record), createdAtMs: record.createdAtMs, completedAtMs: record.completedAtMs };
}
async function recoverIdempotency(config, args) {
  const b = binding(config, args), record = await read(b); checkRecord(b, record);
  if (record.status !== "COMPLETE") await finalize(b, record);
  return inspectIdempotency(config, args);
}
module.exports = { withIdempotency, inspectIdempotency, recoverIdempotency, scopeForPrincipal, requestFingerprint, IN_PROGRESS_STALE_MS, SCHEMA };
