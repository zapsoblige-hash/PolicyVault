"use strict";

/*
 * Tamper-evident AUDIT HASH CHAIN (fullscale surface 17 residual: "audit
 * log not hash-chained"; docs/postlaunch/audit-chain-spec.md; migration
 * server/migrations/008_audit_chain.sql).
 *
 * Every audit record written through server/src/audit.js gains an embedded
 * chain envelope:
 *
 *   chain = { v, seq, nonce, prevHash, recordHash }
 *   recordHash = SHA-256( canonicalJsonStringify({ content, nonce,
 *                                                  prevHash, seq }) )
 *
 * where `content` is the record WITHOUT its chain envelope, in
 * STORAGE-NORMAL form (BigInt->string, undefined dropped — exactly what
 * both persistence backends put at rest), and canonicalJsonStringify is
 * the SDK's G-2 key-order-independent serializer (sdk/src/canonical-json,
 * re-exported by the SDK public entry) — so a PostgreSQL jsonb round trip,
 * which reorders object keys, re-verifies byte-identically (the exact
 * defect class of Phase G-2; the PG regression suite proves it).
 *
 * STREAM PARTITIONING (deliberate, documented in the spec §4): ONE chain
 * per (networkId, data root). Audit visibility is DERIVED state (covenant
 * participation / org membership) and can change over time, so a
 * per-tenant partition could never be immutable; the single stream is the
 * same shape the audit log itself has always had. Cross-tenant safety
 * comes from the VERIFICATION surface instead: verification reports
 * integrity structure only (seqs, hashes, counts) and never record
 * content, and every recordHash preimage includes a per-record random
 * `nonce` so a hash can never be used to confirm a guessed foreign
 * record's content.
 *
 * COVERAGE (honest — spec §5): chained records are exactly those flowing
 * through server/src/audit.js (api.js, governance.js, risk.js,
 * intent-records.js, org-controls/agent-suspension metadata). Audit
 * records written by sdk-internal paths (wallet-submit/reconcile chain
 * proofs, sdk organization metadata, CLI-tool flows) do NOT pass through
 * that module and are reported as UNCHAINED alongside records that
 * predate this deployment — never silently claimed chained. Closing that
 * gap is a one-line adoption inside sdk/src/audit.js (another lane owns
 * that file); this module is layer-neutral so it can be adopted there
 * unchanged.
 *
 * FAIL-SAFE (never a new failure mode): if chain computation or the head
 * anchor is unavailable, the audit record is appended UNCHAINED exactly
 * as before — the chain must never cost a mutation its audit line. Chain
 * gaps surface honestly in verification; they are never hidden.
 *
 * SERIALIZATION: chained appends serialize on an in-process mutex per
 * (data root, network). The released deployment shape is ONE server
 * process per data root (launch pin: single app replica; the events-store
 * JSON seq counter and the process-local rate limiter already assume it).
 * A misconfigured second writer cannot corrupt silently: it produces
 * duplicate/out-of-order seqs that verification reports as BROKEN.
 *
 * The chain DESCRIBES the hosted audit copy; it never grants or verifies
 * covenant authority. Kaspa consensus remains the only financial truth.
 */

const crypto = require("crypto");
const path = require("path");

const sdkAudit = require("../../sdk/src/audit");
// The SDK's canonical serializer (G-2). This module object is what the SDK
// public entry (sdk/src/index.js `canonicalJsonStringify`) re-exports —
// the chain suite asserts that identity so the two can never drift.
const { canonicalJsonStringify } = require("../../sdk/src/canonical-json");
const { Categories, getPlatformStore } = require("./platform-store");

const CHAIN_SCHEMA = "policyvault-audit-chain/v1";
const HEAD_SCHEMA = "policyvault-audit-chain-head/v1";
const STATUS_SCHEMA = "policyvault-audit-chain-status/v1";
const VERIFICATION_SCHEMA = "policyvault-audit-chain-verification/v1";
const HEAD_KEY = "head";

const DEFAULT_VERIFY_LIMIT = 5000;
const MAX_VERIFY_LIMIT = 20000;

const PRE_CHAIN_NOTICE =
  "Unchained records are audit lines written before the chain deployed, or written by sdk-internal audit paths that do not flow through the server audit module. They are authentic audit records but carry no chain envelope and are never claimed chained. VALID means the CHAINED subsequence is intact.";

const HEX64_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;

/* In-process count of appends that fell back to unchained because chain
 * bookkeeping failed (observability only; never a durable claim). */
let chainSkips = 0;

class AuditChainError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/* ------------------------------------------------------------------ */
/* Hash primitives                                                     */
/* ------------------------------------------------------------------ */

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/* Deterministic genesis anchor: the prevHash of chain seq 1. */
function genesisAnchor(networkId) {
  return sha256Hex(canonicalJsonStringify({ genesis: CHAIN_SCHEMA, networkId }));
}

/*
 * STORAGE-NORMAL form of a record: BigInt -> string (the PG backend's
 * toJsonb replacer), undefined dropped, toJSON applied — precisely the
 * value both backends persist. Hashing THIS (not the live object) is what
 * makes re-verification after any round trip exact.
 */
function storageNormal(record) {
  return JSON.parse(JSON.stringify(record, (_, item) => (typeof item === "bigint" ? item.toString() : item)));
}

/* recordHash preimage + hash for one chained record. `content` must be
 * storage-normal and must NOT include the chain envelope. */
function computeRecordHash({ content, nonce, prevHash, seq }) {
  return sha256Hex(canonicalJsonStringify({ content, nonce, prevHash, seq }));
}

/* Strict shape check for a persisted chain envelope. */
function chainEnvelopeValid(chain) {
  return (
    chain !== null &&
    typeof chain === "object" &&
    !Array.isArray(chain) &&
    chain.v === CHAIN_SCHEMA &&
    Number.isSafeInteger(chain.seq) &&
    chain.seq >= 1 &&
    typeof chain.nonce === "string" &&
    NONCE_RE.test(chain.nonce) &&
    typeof chain.prevHash === "string" &&
    HEX64_RE.test(chain.prevHash) &&
    typeof chain.recordHash === "string" &&
    HEX64_RE.test(chain.recordHash)
  );
}

/* ------------------------------------------------------------------ */
/* Head state (process cache + durable anchor + recovery from records) */
/* ------------------------------------------------------------------ */

/* Keyed by resolved data root + network so two config objects over the
 * same store share one head/mutex (the events-store seq idiom). */
const headByStream = new Map();
const mutexByStream = new Map();

function streamKey(config) {
  return `${path.resolve(config.dataRoot)}|${config.networkId}`;
}

/* Serialize fn() with every other chained append on this stream. */
function withStreamMutex(config, fn) {
  const key = streamKey(config);
  const tail = mutexByStream.get(key) || Promise.resolve();
  const run = tail.then(fn, fn);
  // The stored tail must never reject (a failed append must not poison
  // the queue for every later append).
  mutexByStream.set(
    key,
    run.then(
      () => undefined,
      () => undefined
    )
  );
  return run;
}

/* Newest VALID chain envelope present in the stored records (recovery
 * truth for the head). Returns { seq, recordHash } or null. */
async function lastChainedFromRecords(config) {
  if (config.persistenceBackend === "postgres") {
    const { getStore } = require("../../sdk/src/store");
    const pool = getStore(config).pool();
    const r = await pool.query(
      `SELECT value FROM audit_events
       WHERE network_id = $1 AND value ? 'chain'
       ORDER BY (((value -> 'chain') ->> 'seq')::bigint) DESC NULLS LAST, id DESC
       LIMIT 5`,
      [config.networkId]
    );
    for (const row of r.rows) {
      const chain = row.value && row.value.chain;
      if (chainEnvelopeValid(chain)) return { seq: chain.seq, recordHash: chain.recordHash };
    }
    return null;
  }
  // JSON backend: one full read of the stream (init happens once per
  // process; appends afterwards are O(1) against the cached head).
  const rows = await readAllAuditRecords(config);
  let best = null;
  for (const record of rows) {
    const chain = record && record.chain;
    if (chainEnvelopeValid(chain) && (!best || chain.seq > best.seq)) best = { seq: chain.seq, recordHash: chain.recordHash };
  }
  return best;
}

/* Durable head anchor (platform store; migration 008 on PG). */
async function readDurableHead(config) {
  const value = await getPlatformStore(config).read(Categories.AUDIT_CHAIN, HEAD_KEY);
  if (!value || value.schema !== HEAD_SCHEMA || !Number.isSafeInteger(value.seq) || value.seq < 1 || !HEX64_RE.test(value.recordHash ?? "")) {
    return null; // malformed anchor: recover from records (never guess)
  }
  return { seq: value.seq, recordHash: value.recordHash };
}

async function writeDurableHead(config, head) {
  await getPlatformStore(config).write(Categories.AUDIT_CHAIN, HEAD_KEY, {
    schema: HEAD_SCHEMA,
    networkId: config.networkId,
    seq: head.seq,
    recordHash: head.recordHash,
    updatedAt: new Date().toISOString()
  });
}

/*
 * The append head for this stream. Recovery rule (spec §6): the RECORDS
 * are truth; the durable anchor wins only when it is AHEAD of the records
 * (evidence of a truncated tail — continuing from the anchor preserves
 * the seq gap as permanent, verifiable evidence instead of papering over
 * the loss). Cached per process after the first resolution.
 */
async function currentHead(config) {
  const key = streamKey(config);
  if (headByStream.has(key)) return headByStream.get(key);
  const [durable, fromRecords] = [await readDurableHead(config), await lastChainedFromRecords(config)];
  let head;
  if (fromRecords && (!durable || fromRecords.seq >= durable.seq)) head = fromRecords;
  else if (durable) head = durable; // records behind the anchor: keep the gap visible
  else head = { seq: 0, recordHash: null }; // fresh chain: genesis
  headByStream.set(key, head);
  return head;
}

/* Tests-only: drop process caches (a fresh process would rebuild them). */
function resetProcessCache() {
  headByStream.clear();
  mutexByStream.clear();
}

/* ------------------------------------------------------------------ */
/* Chained append                                                      */
/* ------------------------------------------------------------------ */

/*
 * Append one audit record WITH a chain envelope. The exact sdk appendAudit
 * CONTRACT is preserved (same arguments, same durability, same stream, an
 * `at` supplied by the caller wins, the persisted record is returned) —
 * the chain envelope is purely additive.
 *
 * FAIL-SAFE: any failure of chain BOOKKEEPING (head anchor unavailable,
 * canonicalization refusal, cache corruption) falls back to the exact
 * pre-chain unchained append. Only a failure of the underlying audit
 * store itself still propagates — precisely the pre-existing behavior.
 */
async function appendChainedAudit(config, event) {
  return withStreamMutex(config, async () => {
    const base = { at: new Date().toISOString(), ...event };
    if (base.chain !== undefined) {
      // No caller writes a `chain` field today. If one ever does, the
      // data is PRESERVED under an honest name and the record is chained
      // normally — a caller-supplied field must never be able to poison
      // stream verification by masquerading as a chain envelope.
      base.chainFieldCollision = base.chain;
      delete base.chain;
    }
    let chained = null;
    let nextHead = null;
    try {
      const content = storageNormal(base);
      const head = await currentHead(config);
      const seq = head.seq + 1;
      const prevHash = head.seq === 0 ? genesisAnchor(config.networkId) : head.recordHash;
      const nonce = crypto.randomBytes(16).toString("hex");
      const recordHash = computeRecordHash({ content, nonce, prevHash, seq });
      chained = { ...content, chain: { v: CHAIN_SCHEMA, seq, nonce, prevHash, recordHash } };
      nextHead = { seq, recordHash };
    } catch (error) {
      chainSkips += 1;
      try {
        console.error(`policyvault-audit-chain: appended UNCHAINED (${error.code || error.message}) — chain bookkeeping failed; the audit line is preserved`);
      } catch {
        /* even logging must not throw */
      }
      return sdkAudit.appendAudit(config, base); // the exact pre-chain append
    }
    // The real append. A store failure here propagates exactly as before.
    const record = await sdkAudit.appendAudit(config, chained);
    headByStream.set(streamKey(config), nextHead);
    try {
      await writeDurableHead(config, nextHead);
    } catch (error) {
      // Record IS chained; only the advisory anchor is stale. The next
      // process init recovers the head from the records themselves.
      try {
        console.error(`policyvault-audit-chain: head anchor write failed (${error.code || error.message}) — recovered from records at next init`);
      } catch {
        /* never throw */
      }
    }
    return record;
  });
}

/* ------------------------------------------------------------------ */
/* Reading for verification                                            */
/* ------------------------------------------------------------------ */

/* Full audit stream in APPEND ORDER (JSON backend only — one file read). */
async function readAllAuditRecords(config) {
  const rows = await sdkAudit.readAudit(config, { limit: Number.MAX_SAFE_INTEGER });
  return rows.reverse(); // readAudit returns newest-first
}

/*
 * Chained records with seq in [fromSeq, toSeq], in APPEND order, capped at
 * `cap` rows. Duplicated seqs (multi-writer misconfiguration) are
 * returned as-is so the walk can report them.
 */
async function loadChainedRange(config, { fromSeq, toSeq, cap }) {
  if (config.persistenceBackend === "postgres") {
    const { getStore } = require("../../sdk/src/store");
    const pool = getStore(config).pool();
    const params = [config.networkId, String(fromSeq), String(toSeq)];
    const r = await pool.query(
      `SELECT value FROM audit_events
       WHERE network_id = $1 AND value ? 'chain'
         AND (((value -> 'chain') ->> 'seq')::bigint) BETWEEN $2::bigint AND $3::bigint
       ORDER BY id ASC
       LIMIT ${Math.max(1, Math.min(cap, MAX_VERIFY_LIMIT)) + 1}`,
      params
    );
    return r.rows.map((row) => row.value);
  }
  const out = [];
  for (const record of await readAllAuditRecords(config)) {
    const chain = record && record.chain;
    if (chain === undefined) continue;
    // In-range valid envelopes are walked; a MALFORMED envelope is always
    // included so the walk reports CHAIN_MALFORMED (its claimed seq is
    // untrustworthy, so it cannot be range-filtered honestly).
    if (chainEnvelopeValid(chain) && (chain.seq < fromSeq || chain.seq > toSeq)) continue;
    out.push(record);
    if (out.length > cap) break;
  }
  return out;
}

/* One chained record by exact seq (predecessor lookup for ranged walks). */
async function loadChainedAtSeq(config, seq) {
  if (config.persistenceBackend === "postgres") {
    const { getStore } = require("../../sdk/src/store");
    const pool = getStore(config).pool();
    const r = await pool.query(
      `SELECT value FROM audit_events
       WHERE network_id = $1 AND value ? 'chain' AND (((value -> 'chain') ->> 'seq')::bigint) = $2::bigint
       ORDER BY id ASC LIMIT 1`,
      [config.networkId, String(seq)]
    );
    return r.rowCount ? r.rows[0].value : null;
  }
  for (const record of await readAllAuditRecords(config)) {
    if (record && chainEnvelopeValid(record.chain) && record.chain.seq === seq) return record;
  }
  return null;
}

/* Aggregate stream counts (structure only — no content). */
async function streamCounts(config) {
  if (config.persistenceBackend === "postgres") {
    const { getStore } = require("../../sdk/src/store");
    const pool = getStore(config).pool();
    const r = await pool.query(
      `SELECT count(*)::int AS total, count(*) FILTER (WHERE value ? 'chain')::int AS chained
       FROM audit_events WHERE network_id = $1`,
      [config.networkId]
    );
    const { total, chained } = r.rows[0];
    return { total, chained, unchained: total - chained };
  }
  const rows = await readAllAuditRecords(config);
  const chained = rows.filter((r) => r && r.chain !== undefined).length;
  return { total: rows.length, chained, unchained: rows.length - chained };
}

/* ------------------------------------------------------------------ */
/* Verification                                                        */
/* ------------------------------------------------------------------ */

function parseSeqParam(raw, name, fallback) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) {
    throw Object.assign(new AuditChainError("AUDIT_CHAIN_BAD_RANGE", `${name} must be a positive integer sequence number`), { status: 400 });
  }
  return n;
}

/*
 * Walk the chained subsequence and report integrity. STRUCTURE ONLY: the
 * response carries seqs, hashes, counts, and reasons — never record
 * content (cross-tenant verifiability without content exposure; the
 * per-record nonce keeps hashes non-confirmable). A bounded walk returns
 * complete:false + nextFromSeq for continuation; the authoritative check
 * is the full walk from seq 1 (ranged walks are windows into it).
 */
async function verifyChain(config, { fromSeq: rawFrom, toSeq: rawTo, limit: rawLimit } = {}) {
  const fromSeq = parseSeqParam(rawFrom, "fromSeq", 1);
  const toSeq = parseSeqParam(rawTo, "toSeq", Number.MAX_SAFE_INTEGER);
  if (toSeq < fromSeq) throw Object.assign(new AuditChainError("AUDIT_CHAIN_BAD_RANGE", "toSeq must be >= fromSeq"), { status: 400 });
  let cap = parseSeqParam(rawLimit, "limit", DEFAULT_VERIFY_LIMIT);
  cap = Math.min(cap, MAX_VERIFY_LIMIT);

  const counts = await streamCounts(config);
  const durableHead = await readDurableHead(config);
  const base = {
    schemaVersion: VERIFICATION_SCHEMA,
    networkId: config.networkId,
    genesisAnchor: genesisAnchor(config.networkId),
    head: durableHead,
    records: counts,
    notice: PRE_CHAIN_NOTICE
  };

  const rows = await loadChainedRange(config, { fromSeq, toSeq, cap });
  const truncatedByCap = rows.length > cap;
  const walk = truncatedByCap ? rows.slice(0, cap) : rows;

  if (walk.length === 0) {
    // Nothing chained in the window. If the anchor claims records at or
    // past fromSeq, records the chain once contained are MISSING — a
    // fully truncated chain reports TAIL_TRUNCATED, a hollowed-out window
    // reports SEQ_GAP. A window past the head is simply empty.
    if (durableHead && durableHead.seq >= fromSeq) {
      const reason = counts.chained === 0 ? "TAIL_TRUNCATED" : "SEQ_GAP";
      return { ...base, status: "BROKEN", complete: true, checked: { fromSeq, toSeq: null, count: 0 }, broken: { atSeq: fromSeq, reason }, nextFromSeq: null };
    }
    return { ...base, status: counts.chained === 0 ? "EMPTY" : "VALID", complete: true, checked: { fromSeq, toSeq: null, count: 0 }, broken: null, nextFromSeq: null };
  }

  // Predecessor link for a mid-chain window (needed only once the window
  // actually contains records).
  let prevHash;
  if (fromSeq === 1) prevHash = genesisAnchor(config.networkId);
  else {
    const prev = await loadChainedAtSeq(config, fromSeq - 1);
    if (!prev) {
      return { ...base, status: "BROKEN", complete: false, checked: { fromSeq, toSeq: null, count: 0 }, broken: { atSeq: fromSeq - 1, reason: "PREV_RECORD_MISSING" }, nextFromSeq: null };
    }
    prevHash = prev.chain.recordHash;
  }

  let expectSeq = fromSeq;
  let verified = 0;
  const brokenOut = (atSeq, reason) => ({
    ...base,
    status: "BROKEN",
    complete: false,
    checked: { fromSeq, toSeq: verified ? expectSeq - 1 : null, count: verified },
    broken: { atSeq, reason },
    nextFromSeq: null
  });

  for (const record of walk) {
    const chain = record ? record.chain : undefined;
    if (!chainEnvelopeValid(chain)) return brokenOut(expectSeq, "CHAIN_MALFORMED");
    if (chain.seq < expectSeq) return brokenOut(chain.seq, "SEQ_DUPLICATE");
    if (chain.seq > expectSeq) return brokenOut(expectSeq, "SEQ_GAP");
    if (chain.prevHash !== prevHash) return brokenOut(chain.seq, "LINK_BROKEN");
    const { chain: _chain, ...content } = record;
    const recomputed = computeRecordHash({ content: storageNormal(content), nonce: chain.nonce, prevHash: chain.prevHash, seq: chain.seq });
    if (recomputed !== chain.recordHash) return brokenOut(chain.seq, "RECORD_TAMPERED");
    prevHash = chain.recordHash;
    expectSeq += 1;
    verified += 1;
  }

  const lastVerified = expectSeq - 1;
  const moreRemain = truncatedByCap || (durableHead && durableHead.seq > lastVerified && toSeq > lastVerified);
  if (moreRemain && truncatedByCap) {
    return {
      ...base,
      status: "VALID",
      complete: false,
      checked: { fromSeq, toSeq: lastVerified, count: verified },
      broken: null,
      nextFromSeq: lastVerified + 1
    };
  }
  // Walk exhausted the stored records in range. If the anchor claims MORE
  // records past the last stored one (and the caller did not stop early
  // with toSeq), the tail has been truncated.
  if (durableHead && durableHead.seq > lastVerified && toSeq >= durableHead.seq) {
    return brokenOut(lastVerified + 1, "TAIL_TRUNCATED");
  }
  return {
    ...base,
    status: "VALID",
    complete: true,
    checked: { fromSeq, toSeq: lastVerified, count: verified },
    broken: null,
    nextFromSeq: null
  };
}

/* Cheap status document: anchor + counts, no walk. */
async function chainStatus(config) {
  return {
    schemaVersion: STATUS_SCHEMA,
    networkId: config.networkId,
    genesisAnchor: genesisAnchor(config.networkId),
    head: await readDurableHead(config),
    records: await streamCounts(config),
    verifyRoute: "GET /api/v1/audit/chain/verify",
    notice: PRE_CHAIN_NOTICE
  };
}

function chainSkipCount() {
  return chainSkips;
}

module.exports = {
  CHAIN_SCHEMA,
  HEAD_SCHEMA,
  STATUS_SCHEMA,
  VERIFICATION_SCHEMA,
  PRE_CHAIN_NOTICE,
  DEFAULT_VERIFY_LIMIT,
  MAX_VERIFY_LIMIT,
  genesisAnchor,
  storageNormal,
  computeRecordHash,
  chainEnvelopeValid,
  appendChainedAudit,
  verifyChain,
  chainStatus,
  chainSkipCount,
  resetProcessCache,
  AuditChainError
};
