"use strict";

/*
 * Pre-build period-budget reservations for v0.4 agent spends
 * (full-scale surface 15 — closes the documented reservation-honesty gap).
 *
 * PROBLEM: concurrent agent-spend BUILDS all validate against the SAME
 * durable manifest state, so each one independently proves
 * periodSpent + pay <= periodBudget and together they can optimistically
 * over-commit the agent's period headroom. Until this module, the first
 * exclusivity arbitration happened only at FINALIZE (the transition claim
 * on the predecessor outpoint) and, financially, on chain (the covenant).
 *
 * TRUTH DISCIPLINE (unchanged, permanent): the Kaspa covenant is the ONLY
 * financial authority. A reservation is an AVAILABILITY / COORDINATION
 * layer that keeps the hosted build pipeline honest about headroom it has
 * already promised to open requests — it prevents wasted builds and
 * optimistic over-commitment. It is NOT a security boundary: an actor
 * with the legitimate delegate key submitting transactions directly to a
 * node bypasses this layer entirely, and the covenant refuses over-budget
 * spends on chain regardless. Nothing here changes consensus-visible
 * bytes: reservations run strictly OUTSIDE the builder/encoder/finalizer
 * (the frozen transaction for a given build is byte-identical with or
 * without them — asserted by test).
 *
 * DESIGN (same store idioms as submission-claim.js; JSON + PG parity):
 *   - Records live in the existing TRANSITION_CLAIM category (PG table
 *     transition_claims, JSON dir claims/transition/) under reserved key
 *     prefixes that can NEVER collide with a transition-claim key
 *     ("<64-hex-txid>-<index>"): "resv-..." and "resvlock-...". Both
 *     backends therefore keep exactly identical list/read/create/remove
 *     semantics with NO schema migration. No existing reader interprets
 *     these keys (transition claims are read only by exact outpoint key).
 *   - One reservation record per request:
 *       key  resv-<vaultId>-<agentPk>-<requestId>
 *     created with createExclusive (the link()/EEXIST // INSERT ... ON
 *     CONFLICT DO NOTHING arbiter) so a reservation cannot be forged or
 *     duplicated for the same request, and can only be consumed/released
 *     through its embedded requestId.
 *   - Admission (list + sum + create) is serialized per vault by a short-
 *     lived lock record (key resvlock-<vaultId>) taken with
 *     createExclusive, with the SAME deterministic stale-reclaim pattern
 *     as server idempotency IN_PROGRESS records: a crashed holder is
 *     reclaimed after LOCK_STALE_MS; a live holder makes contenders retry
 *     briefly, then fail closed (RESERVATION_BUSY — pure, retryable).
 *
 * WINDOW MODEL (mirrors deriveSuccessorRegistry / the covenant exactly —
 * the numbers come from the ALREADY-VALIDATED build, never re-derived
 * policy semantics):
 *   windowStartDaa = periodsElapsed >= 1
 *       ? periodStartDaa + periodsElapsed * periodLengthDaa
 *       : periodStartDaa
 *   candidate newSpent = periodsElapsed >= 1 ? pay : periodSpent + pay
 * The builder (agentSpendSuccessorV4, the covenant mirror) has ALREADY
 * proven pay <= maxPerSpend and newSpent <= periodBudget for the single
 * build. Admission adds ONLY the cross-request cumulative rule:
 *   newSpent + SUM(open reservations in the same window) <= periodBudget
 * so every refusal introduced by this module is reservation-caused
 * (BUDGET_RESERVED_EXCEEDED); every pre-existing refusal surface (per-
 * spend cap, single-spend budget, pause, proofs, ...) still comes from
 * the real builder with its unchanged codes.
 *
 * LIFECYCLE:
 *   ACTIVE    taken immediately before the durable request is persisted.
 *   CONSUMED  at finalize, after the transition claim succeeded (the
 *             finalize claim REMAINS the exclusivity arbiter — the
 *             reservation never replaces or weakens it). Consumed
 *             reservations KEEP counting against the window until the
 *             manifest actually advances (the spend is in flight).
 *   released  (removed) when the owning request dies: wallet rejection,
 *             finalize failure states, STALE, definitive node rejection,
 *             stale-claim release by reconciliation.
 *   swept     (removed, deterministic, self-healing — during admission,
 *             under the lock): context-stale records whose
 *             predecessorStateId no longer matches the live manifest
 *             state (the chain advanced; period truth now lives in the
 *             manifest registry), records whose durable request reached a
 *             released state (crash between state write and release
 *             hook), and ORPHANS — ACTIVE records older than
 *             ORPHAN_STALE_MS whose request was never persisted (crash
 *             between reservation and saveRequest).
 *
 * FAIL-CLOSED RULES: an unreadable/corrupt reservation record or an
 * UNKNOWN reservation schema version inside the admission scope REFUSES
 * admission (headroom cannot be proven; skipping would under-count and
 * re-open the over-commit gap). Unknown versions are never routed to a
 * default.
 *
 * Owner operations, genesis builds, dry-run simulation
 * (server/src/simulate.js — persists nothing, calls the pure builder
 * directly) and v2 flows take NO reservation and are untouched.
 */

const { getStore, Categories } = require("./store");

const RESERVATION_SCHEMA = "policyvault-budget-reservation/v1";
const RESERVATION_LOCK_SCHEMA = "policyvault-reservation-lock/v1";

const RESERVATION_KEY_PREFIX = "resv-";
const RESERVATION_LOCK_PREFIX = "resvlock-";

/* A crashed admission-lock holder is reclaimable after this age (the lock
 * covers only list+sum+create — milliseconds; 30s is deliberately
 * generous). Deterministic, mirrored from server idempotency's
 * IN_PROGRESS stale-reclaim pattern. */
const LOCK_STALE_MS = 30_000;
/* Bounded wait for a LIVE lock holder before failing closed. */
const LOCK_RETRY_ATTEMPTS = 80;
const LOCK_RETRY_DELAY_MS = 25;
/* An ACTIVE reservation whose request record never appeared (crash
 * between reservation and saveRequest) is an orphan after this age —
 * same deadline class as idempotency IN_PROGRESS_STALE_MS. */
const ORPHAN_STALE_MS = 5 * 60 * 1000;

/* Request states whose reservation is releasable: the request can never
 * reach broadcast from these states (closed set; the KEEP set is
 * BUILT / AWAITING_APPROVALS / SIGNED / FINALIZED / PREFLIGHT_VERIFIED /
 * SUBMITTING / SUBMITTED / RECONCILIATION_REQUIRED / CHAIN_VERIFIED —
 * chain-verified context-staleness is handled by the stateId sweep). */
const RELEASED_REQUEST_STATES = Object.freeze(
  new Set([
    "WALLET_REJECTED",
    "SIGNATURE_INVALID",
    "PREFLIGHT_FAILED",
    "STALE",
    "CLAIM_CONFLICT",
    "AUTHORIZATION_FAILED",
    "INSUFFICIENT_APPROVALS",
    "BUILD_FAILED",
    "SUBMISSION_REJECTED"
  ])
);

function fail(message, code) {
  const error = new Error(`budget-reservation: ${message}`);
  error.code = code;
  return error;
}

function requireHex64(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw fail(`${field} must be 32-byte lowercase hex`, "RESERVATION_INTERNAL");
  }
  return value;
}

/* Canonical digit-string -> BigInt (the values come from the SDK's own
 * frozen build; anything else fails closed, never floats). */
function digits(value, field) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw fail(`${field} must be a canonical digit string, got ${JSON.stringify(value)}`, "RESERVATION_INTERNAL");
  }
  return BigInt(value);
}

function reservationKey({ vaultId, agentPk, requestId }) {
  requireHex64(vaultId, "vaultId");
  requireHex64(agentPk, "agentPk");
  if (typeof requestId !== "string" || requestId.length === 0 || requestId.length > 128 || !/^[A-Za-z0-9-]+$/.test(requestId)) {
    throw fail("requestId must be a uuid-shaped identifier", "RESERVATION_INTERNAL");
  }
  return `${RESERVATION_KEY_PREFIX}${vaultId}-${agentPk}-${requestId}`;
}

function reservationScopePrefix({ vaultId, agentPk }) {
  requireHex64(vaultId, "vaultId");
  requireHex64(agentPk, "agentPk");
  return `${RESERVATION_KEY_PREFIX}${vaultId}-${agentPk}-`;
}

function lockKey(vaultId) {
  requireHex64(vaultId, "vaultId");
  return `${RESERVATION_LOCK_PREFIX}${vaultId}`;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/*
 * Acquire the per-vault admission lock. createExclusive is the arbiter;
 * a stale (crashed) holder is reclaimed deterministically; a live holder
 * makes us retry briefly and then fail closed with RESERVATION_BUSY
 * (pure — nothing durable was created; the caller may simply retry).
 */
async function acquireAdmissionLock(config, vaultId, holderRequestId) {
  const store = getStore(config);
  const key = lockKey(vaultId);
  for (let attempt = 0; attempt <= LOCK_RETRY_ATTEMPTS; attempt++) {
    const created = await store.createExclusive(Categories.TRANSITION_CLAIM, key, {
      schema: RESERVATION_LOCK_SCHEMA,
      vaultId,
      holderRequestId,
      createdAt: new Date().toISOString(),
      createdAtMs: Date.now()
    });
    if (created) return key;
    const existing = await store.read(Categories.TRANSITION_CLAIM, key);
    if (existing && existing.schema !== RESERVATION_LOCK_SCHEMA) {
      throw fail(`admission lock record ${key} has unknown schema ${JSON.stringify(existing.schema)} — failing closed`, "RESERVATION_UNRECOGNIZED");
    }
    if (existing && typeof existing.createdAtMs === "number" && Date.now() - existing.createdAtMs > LOCK_STALE_MS) {
      await store.remove(Categories.TRANSITION_CLAIM, key); // reclaim a crashed holder; the next createExclusive re-arbitrates
      continue;
    }
    await sleep(LOCK_RETRY_DELAY_MS);
  }
  throw fail(
    "another build is computing budget admission for this vault — retry shortly",
    "RESERVATION_BUSY"
  );
}

/* Guarded, idempotent lock release: never removes another holder's lock. */
async function releaseAdmissionLock(config, vaultId, holderRequestId) {
  const store = getStore(config);
  const key = lockKey(vaultId);
  const existing = await store.read(Categories.TRANSITION_CLAIM, key);
  if (existing === null) return false;
  if (existing.schema !== RESERVATION_LOCK_SCHEMA || existing.holderRequestId !== holderRequestId) return false;
  await store.remove(Categories.TRANSITION_CLAIM, key);
  return true;
}

/* All reservation records in one (vault, agent) scope: [{ key, record }].
 * A record that cannot be read/parsed FAILS CLOSED (an unprovable
 * reservation must never be silently under-counted). */
async function readScopeReservations(config, { vaultId, agentPk }) {
  const store = getStore(config);
  const prefix = reservationScopePrefix({ vaultId, agentPk });
  const keys = (await store.listKeys(Categories.TRANSITION_CLAIM)).filter((k) => typeof k === "string" && k.startsWith(prefix));
  const out = [];
  for (const key of keys) {
    let record;
    try {
      record = await store.read(Categories.TRANSITION_CLAIM, key);
    } catch (error) {
      throw fail(`reservation record ${key} is unreadable (${error.message}) — failing closed; remove or repair it before building`, "RESERVATION_RECORD_CORRUPT");
    }
    if (record === null) continue; // released concurrently between list and read
    if (record.schema !== RESERVATION_SCHEMA) {
      throw fail(`reservation record ${key} has unknown schema ${JSON.stringify(record.schema)} — failing closed (unknown versions are never ignored)`, "RESERVATION_UNRECOGNIZED");
    }
    out.push({ key, record });
  }
  return out;
}

/*
 * The deterministic sweep (runs under the admission lock). Removes:
 *   - context-stale records: predecessorStateId !== the live stateId OR
 *     predecessorOutpoint !== the live outpoint. The OUTPOINT is the
 *     primary context key ("the predecessor outpoint context"): the same
 *     stateId can legitimately recur at a different outpoint (e.g. spend
 *     then top-up back to an identical state), and headroom promised
 *     against a consumed outpoint must never bind the new one — the new
 *     state's registry already carries the true periodSpent;
 *   - records whose durable request reached a released state;
 *   - ACTIVE orphans older than ORPHAN_STALE_MS with NO durable request.
 * Keeps everything else. Returns the surviving [{ key, record }].
 */
function sameOutpoint(a, b) {
  return Boolean(a && b && a.transactionId === b.transactionId && Number(a.index) === Number(b.index));
}

async function sweepScope(config, { vaultId, agentPk, liveStateId, liveOutpoint, loadRequest }) {
  const store = getStore(config);
  const survivors = [];
  for (const item of await readScopeReservations(config, { vaultId, agentPk })) {
    const { key, record } = item;
    if (record.predecessorStateId !== liveStateId || !sameOutpoint(record.predecessorOutpoint, liveOutpoint)) {
      await store.remove(Categories.TRANSITION_CLAIM, key); // chain/manifest advanced: period truth now lives in the registry
      continue;
    }
    const request = await loadRequest(config, record.requestId);
    if (request && RELEASED_REQUEST_STATES.has(request.state)) {
      await store.remove(Categories.TRANSITION_CLAIM, key); // request died; release hook was missed (crash) — reclaim
      continue;
    }
    if (!request && record.status === "ACTIVE" && typeof record.createdAtMs === "number" && Date.now() - record.createdAtMs > ORPHAN_STALE_MS) {
      await store.remove(Categories.TRANSITION_CLAIM, key); // crashed build: reservation without a durable request
      continue;
    }
    survivors.push(item);
  }
  return survivors;
}

/*
 * Take the pre-persist reservation for one VALIDATED agent-spend build.
 * Called by buildWalletRequestV4 (persist path only) AFTER the real SDK
 * builder succeeded and BEFORE the durable request is written. Throws
 * BUDGET_RESERVED_EXCEEDED (deterministic explanation naming the holding
 * requestIds) when open reservations in the same period window leave
 * insufficient headroom; every other spend refusal still comes from the
 * real builder. PURE on refusal: nothing durable is created or kept.
 */
async function reserveForSpendBuild(config, { manifest, build, requestId }) {
  if (!build || build.action !== "agentSpend" || !build.callExtra) {
    throw fail("reserveForSpendBuild requires a frozen agentSpend build", "RESERVATION_INTERNAL");
  }
  const vaultId = requireHex64(manifest.vaultId, "manifest.vaultId");
  const agentPk = requireHex64(build.callExtra.agentPk, "build.callExtra.agentPk");
  const liveStateId = requireHex64(build.predecessorStateId, "build.predecessorStateId");

  /* Window math — the EXACT deriveSuccessorRegistry / covenant rule, on
   * the builder's own canonical values. */
  const pay = digits(build.accounting.payAmount, "accounting.payAmount");
  const periods = digits(build.callExtra.periodsElapsed ?? "0", "callExtra.periodsElapsed");
  const prevStart = digits(build.callExtra.periodStartDaa, "callExtra.periodStartDaa");
  const prevSpent = digits(build.callExtra.periodSpent, "callExtra.periodSpent");
  const periodBudget = digits(build.callExtra.periodBudget, "callExtra.periodBudget");
  const periodLength = digits(build.callExtra.periodLengthDaa, "callExtra.periodLengthDaa");
  const windowStartDaa = periods >= 1n ? prevStart + periods * periodLength : prevStart;
  const newSpent = periods >= 1n ? pay : prevSpent + pay;
  if (newSpent > periodBudget) {
    // The real builder proved the single-spend rule already; disagreement here is an internal defect.
    throw fail("internal: builder admitted a spend above periodBudget — failing closed", "RESERVATION_INTERNAL");
  }

  const key = reservationKey({ vaultId, agentPk, requestId });
  const store = getStore(config);
  const { loadRequest } = require("./wallet-requests-v4"); // late require (module cycle: wallet-requests-v4 requires this module)

  await acquireAdmissionLock(config, vaultId, requestId);
  try {
    const open = await sweepScope(config, { vaultId, agentPk, liveStateId, liveOutpoint: build.predecessorOutpoint, loadRequest });
    let reservedSum = 0n;
    const holders = [];
    for (const { record } of open) {
      if (record.windowStartDaa !== windowStartDaa.toString()) continue; // other period window: independent budget
      reservedSum += digits(record.amountSompi, "reservation.amountSompi");
      holders.push(record.requestId);
    }
    if (newSpent + reservedSum > periodBudget) {
      const already = periods >= 1n ? 0n : prevSpent;
      throw fail(
        `period budget headroom is already reserved: budget ${periodBudget} sompi, spent ${already} sompi this period, ` +
          `${reservedSum} sompi reserved by open request(s) [${holders.join(", ")}], requested ${pay} sompi — ` +
          `finalize, reject, or wait for the open request(s), then rebuild`,
        "BUDGET_RESERVED_EXCEEDED"
      );
    }
    const created = await store.createExclusive(Categories.TRANSITION_CLAIM, key, {
      schema: RESERVATION_SCHEMA,
      requestId,
      vaultId,
      agentPk,
      action: "agentSpend",
      amountSompi: pay.toString(),
      reserveConsumedSompi: String(build.accounting.reserveConsumed ?? "0"),
      windowStartDaa: windowStartDaa.toString(),
      newSpentSompi: newSpent.toString(),
      periodBudgetSompi: periodBudget.toString(),
      predecessorStateId: liveStateId,
      predecessorOutpoint: build.predecessorOutpoint,
      status: "ACTIVE",
      txId: null,
      createdAt: new Date().toISOString(),
      createdAtMs: Date.now()
    });
    if (!created) {
      // requestId is a fresh uuid — an existing record under this exact key is a logic breach, never overwritten.
      throw fail(`reservation ${key} already exists — refusing to overwrite`, "RESERVATION_CONFLICT");
    }
    return { key, windowStartDaa: windowStartDaa.toString(), reservedSompi: pay.toString() };
  } finally {
    await releaseAdmissionLock(config, vaultId, requestId).catch(() => {});
  }
}

/* True when a request record is a v4 agent spend that can hold a reservation. */
function requestHoldsReservation(request) {
  return Boolean(
    request &&
      request.schema === "policyvault-wallet-request/v4" &&
      request.sdkAction === "agentSpend" &&
      typeof request.agentPk === "string" &&
      typeof request.vaultId === "string"
  );
}

/*
 * CONSUME at finalize (after the transition claim succeeded — the claim
 * remains the exclusivity arbiter; consumption is bookkeeping that ties
 * the reservation to the finalized txId). The record KEEPS counting
 * against its window until the manifest advances. Guarded by the
 * embedded requestId: a reservation can never be consumed by a different
 * request (the key itself encodes the owner). A missing record is a
 * LEGACY no-op (requests built before this layer, or already swept).
 */
async function consumeReservationForRequest(config, request, { txId }) {
  if (!requestHoldsReservation(request)) return { consumed: false, reason: "not-a-spend-request" };
  const key = reservationKey({ vaultId: request.vaultId, agentPk: request.agentPk, requestId: request.requestId });
  const store = getStore(config);
  const record = await store.read(Categories.TRANSITION_CLAIM, key);
  if (record === null) return { consumed: false, reason: "legacy-or-swept" };
  if (record.schema !== RESERVATION_SCHEMA) {
    throw fail(`reservation ${key} has unknown schema — failing closed`, "RESERVATION_UNRECOGNIZED");
  }
  if (record.requestId !== request.requestId) {
    throw fail(`refusing to consume reservation owned by request ${record.requestId} from request ${request.requestId}`, "RESERVATION_FORGERY");
  }
  await store.write(Categories.TRANSITION_CLAIM, key, {
    ...record,
    status: "CONSUMED",
    txId: typeof txId === "string" ? txId : null,
    consumedAt: new Date().toISOString()
  });
  return { consumed: true, key };
}

/*
 * RELEASE when the owning request dies (rejection / finalize failure /
 * STALE / definitive node rejection / reconciliation stale-claim
 * release) or its effect is chain-complete. Guarded by the embedded
 * requestId; idempotent; missing record is a no-op. NEVER throws into a
 * caller's failure path (release is best-effort tidiness — the admission
 * sweep is the deterministic backstop).
 */
async function releaseReservationForRequest(config, request) {
  try {
    if (!requestHoldsReservation(request)) return false;
    const key = reservationKey({ vaultId: request.vaultId, agentPk: request.agentPk, requestId: request.requestId });
    const store = getStore(config);
    const record = await store.read(Categories.TRANSITION_CLAIM, key);
    if (record === null) return false;
    if (record.schema !== RESERVATION_SCHEMA || record.requestId !== request.requestId) return false;
    await store.remove(Categories.TRANSITION_CLAIM, key);
    return true;
  } catch {
    return false; // sweep reclaims deterministically; never mask the caller's own error path
  }
}

/* Read-only listing for tests/tools/observability. */
async function listReservationsV4(config, { vaultId, agentPk }) {
  const items = await readScopeReservations(config, { vaultId, agentPk });
  return items.map(({ key, record }) => ({ key, ...record }));
}

module.exports = {
  RESERVATION_SCHEMA,
  RESERVATION_LOCK_SCHEMA,
  RESERVATION_KEY_PREFIX,
  RESERVATION_LOCK_PREFIX,
  LOCK_STALE_MS,
  ORPHAN_STALE_MS,
  RELEASED_REQUEST_STATES,
  reservationKey,
  reserveForSpendBuild,
  consumeReservationForRequest,
  releaseReservationForRequest,
  listReservationsV4
};
