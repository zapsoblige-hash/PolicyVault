"use strict";

/*
 * GLOBAL VAULT-RECORD UNIQUENESS — RC33-ID-01 (independent RC33 affected
 * review, 2026-09-11; owner repair directive of the same day).
 *
 * Every covenant generation stores its vault manifest under the SAME durable
 * category (Categories.VAULT, key = vaultId) and discriminates by its own
 * schema tag. The per-generation loaders (loadManifestV4 / V5 / V6 / V7 /
 * V7Hd / V7Kas) deliberately return null for a record of ANOTHER generation so
 * a caller can try its own family. That is correct for READS but, at genesis
 * COMPLETION, `current ?? persist(expected)` turned an OCCUPIED identity into
 * an apparently free one and overwrote the other generation's record — the
 * reviewer reproduced this on the exact fullscale-rc33 image with a synthetic
 * other-generation record, test signatures and a mock node (no production
 * loss, no real broadcast). A caller-selected identity that collided with an
 * existing record of the SAME generation was refused only late, after the
 * funding could already have been broadcast.
 *
 * This module is the ONE place a vault identity is arbitrated:
 *
 *   readVaultRecordAny        the raw stored record under a vaultId regardless
 *                             of generation (a record this build cannot read
 *                             still OCCUPIES the identity — fail closed);
 *   findVaultIdentityReservation
 *                             the durable reason an identity is NOT free: a
 *                             vault record of ANY generation, or a request
 *                             (wallet request / org-root request) that names
 *                             the identity as its vault. Two phases:
 *                             phase "build" (a NEW creation): ANY request in
 *                             ANY state reserves the identity — a request is a
 *                             durable reservation from the moment it is
 *                             written and identities are NEVER recycled (a
 *                             withdrawn or rejected draft keeps its identity;
 *                             a new creation takes a fresh one). A durable
 *                             SUBMISSION claim naming the identity reserves it
 *                             in BOTH phases (RC35-RES-01, 2026-09-11: a
 *                             headless v0.1 / v0.2 creation persists exactly
 *                             this claim before its broadcast, and a legacy
 *                             retained claim carries the binding vaultId ↔
 *                             txId) — only the caller's own transaction is
 *                             excluded (`exceptTxId`);
 *                             phase "commit" (a request's OWN signature /
 *                             submission): another request blocks only when
 *                             it may already carry a signed transaction or a
 *                             broadcast (any state outside the closed
 *                             UNCOMMITTED_REQUEST_STATES allowlist; an unknown
 *                             state counts as committed — fail closed). An
 *                             unsigned or definitively negative request cannot
 *                             put a vault under the identity on chain without
 *                             first passing its own sign / submit checks, so
 *                             it never strands a legitimate signed genesis. A
 *                             SUBMISSION_REJECTED request counts as negative
 *                             ONLY when its negative is ESTABLISHED (RC35-
 *                             REC-01: the outcome observer's proof, the bound-
 *                             rejection + output-absent proof, or a legacy
 *                             record whose stored node answer is a bound
 *                             rejection); a record written for an "already
 *                             accepted" node answer may carry a chain effect
 *                             and blocks like a committed request;
 *   assertVaultIdentityFree   throws the closed code VAULT_ID_IN_USE. Used
 *                             BEFORE a genesis request is written, BEFORE a
 *                             wallet signature is accepted and BEFORE any
 *                             claim or broadcast, so a conflict that is
 *                             already knowable never consumes a signature or
 *                             reaches the node. The refusal names only the
 *                             identity the caller supplied — never the other
 *                             record's owner, root, label, generation or
 *                             state (no cross-principal disclosure);
 *   createVaultRecordOrMatch  the ATOMIC create-only completion write. The
 *                             store's create-only primitive is the arbiter
 *                             (link()/EEXIST on the JSON driver, INSERT … ON
 *                             CONFLICT DO NOTHING on PostgreSQL) — never a
 *                             read followed by an unconditional write. An
 *                             existing record is accepted ONLY when it is this
 *                             exact genesis outcome (same schema tag and every
 *                             field except the volatile updatedAt / createdAt
 *                             / label: creation transaction, covenant
 *                             identity, template, initial state, outpoint);
 *                             anything else is a conflict
 *                             (RECONCILIATION_REQUIRED) and the existing record
 *                             is left untouched. Matching the identity alone
 *                             is never sufficient;
 *   withVaultIdentityLock     process-local serialization of a check-then-
 *                             write sequence per identity (the hosted
 *                             ONE-replica rule; the durable arbiter above holds
 *                             across processes). Held around EVERY genesis
 *                             build, EVERY genesis signature acceptance and
 *                             EVERY genesis submission of every family (review
 *                             finding F1, 2026-09-11: without it the commit-
 *                             phase check is check-then-act and a pre-
 *                             correction pair of drafts could double-broadcast).
 *                             Lock order everywhere: a root / signer / request
 *                             lock FIRST, the identity lock INSIDE it — never
 *                             the reverse; the lock is not re-entrant.
 *
 * What this module does NOT do: it never rewrites, migrates or deletes an
 * existing manifest of any generation, never releases a claim, never touches
 * a signed transaction, and never decides chain truth — a proven chain
 * outcome whose identity is occupied stays on its request for reconciliation.
 */

const { getStore, Categories } = require("./store");
const { canonicalJsonStringify } = require("../../core/intent/canonical");
const { recordedNegativeIsEstablished, recordedNonAcceptanceIsEstablished } = require("./submission-classification"); // RC35-REC-01 (2026-09-11): a persisted negative reserves unless ESTABLISHED

const HEX64 = /^[0-9a-f]{64}$/;
const VOLATILE_FIELDS = Object.freeze(["updatedAt", "createdAt", "label"]);

function fail(message, code) {
  const e = new Error(`vault-identity: ${message}`);
  e.code = code;
  return e;
}

function normalizeVaultId(vaultId) {
  const id = typeof vaultId === "string" ? vaultId.toLowerCase() : "";
  if (!HEX64.test(id)) throw fail("vaultId must be 32-byte hex", "BAD_VAULT_ID");
  return id;
}

/* ------------------------------------------------------------------ */
/* process-local per-identity exclusion (same queue discipline as       */
/* sdk/src/org-root-lock.js; separate namespace)                        */
/* ------------------------------------------------------------------ */

const queues = new Map();
async function withVaultIdentityLock(vaultId, work) {
  const id = normalizeVaultId(vaultId);
  const previous = queues.get(id) ?? Promise.resolve();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const tail = previous.then(() => gate, () => gate);
  queues.set(id, tail);
  try {
    await previous.catch(() => {});
    return await work();
  } finally {
    release();
    if (queues.get(id) === tail) queues.delete(id);
  }
}

/* ------------------------------------------------------------------ */
/* reads                                                               */
/* ------------------------------------------------------------------ */

/*
 * The raw record under a vault identity, whatever generation wrote it.
 *   { record, readable: true }   record is null only when the key is ABSENT
 *   { record: null, readable: false, error }
 *                                 something is stored under the key but this
 *                                 build cannot read it (corrupt JSON, a record
 *                                 whose own identity differs from its key) —
 *                                 the identity is OCCUPIED; never "free".
 */
async function readVaultRecordAny(config, vaultId) {
  const id = normalizeVaultId(vaultId);
  try {
    return { record: await getStore(config).read(Categories.VAULT, id), readable: true };
  } catch (error) {
    return { record: null, readable: false, error };
  }
}

/* Every field a durable request of any generation uses to name its vault:
 * wallet requests (v2 / v4 / v5 / v6 / v7-hd / v7-kas) carry `vaultId` and
 * `template.vaultId` / `build.template.vaultId`; a v7 rooted-vault genesis
 * (an org-root request) carries `build.template.vaultId` and its
 * signer-visible `manifest.vaultId`; the KAS genesis `summary.vaultId`. A
 * request naming an EXISTING vault (a spend, an owner operation) matches too —
 * harmless, that identity is occupied by the vault record anyway. */
function requestNamesVaultId(record, id) {
  if (!record || typeof record !== "object") return false;
  const named = [
    record.vaultId,
    record.template && record.template.vaultId,
    record.build && record.build.template && record.build.template.vaultId,
    record.summary && record.summary.vaultId,
    record.manifest && record.manifest.vaultId
  ];
  return named.some((v) => typeof v === "string" && v.toLowerCase() === id);
}

/*
 * The durable reservation of an identity, or null when it is free.
 *   { kind: "VAULT_RECORD", readable }  a vault record of some generation
 *   { kind: "REQUEST" }                 a wallet request names it
 *   { kind: "ORG_ROOT_REQUEST" }        an org-root request names it
 * `exceptRequestId` excludes the caller's OWN request (its `requestId` for a
 * wallet request, its `id` for an org-root request) so a request can be
 * signed and submitted against its own reservation. A request record this
 * build cannot read is skipped by the store's non-strict listing (it cannot
 * name an identity); the create-only completion arbiter below still protects
 * the vault record itself.
 */
/* Request states in which a request provably carries NO signed transaction and NO broadcast (every family: v2 / v4 / v5 /
 * v6 / v7-hd / v7-kas wallet requests and v7 org-root requests). A request in one of these states cannot put a vault
 * under its identity on chain without first passing its own sign / submit checks. EVERY other state — SIGNED, FINALIZED,
 * SUBMITTING, SUBMITTED, BROADCAST, CHAIN_SEEN, CHAIN_VERIFIED, VERIFIED_OUTCOME, RECONCILIATION_REQUIRED, … — and any
 * state this build does not know is treated as COMMITTED (fail closed). */
const UNCOMMITTED_REQUEST_STATES = Object.freeze(new Set([
  "BUILT", "AWAITING_APPROVALS", "AUTHORIZED", // pre-signature
  "WALLET_REJECTED", "SIGNATURE_INVALID", "BUILD_FAILED", "PREFLIGHT_FAILED", "STALE", "REFUSED", "FAILED", // never signed / never left the process
  "SUBMISSION_REJECTED", "NOT_BROADCAST", "SUPERSEDED" // definitively negative chain outcomes (claims released by proof)
]));
const PHASES = new Set(["build", "commit"]);

/* A request state that provably carries no chain effect. SUBMISSION_REJECTED qualifies only as an ESTABLISHED negative
 * (RC35-REC-01); every other SUBMISSION_REJECTED record (an "already accepted" node answer, an absent / unbound answer) may
 * carry a chain effect and counts as committed. */
function requestProvablyUncommitted(record) {
  if (typeof record.state !== "string" || !UNCOMMITTED_REQUEST_STATES.has(record.state)) return false;
  if (record.state === "SUBMISSION_REJECTED") return recordedNegativeIsEstablished(record);
  if (record.state === "NOT_BROADCAST" && record.schema === "policyvault-wallet-request/v4" && record.kind === "genesis") return recordedNonAcceptanceIsEstablished(record);
  return true;
}

async function findVaultIdentityReservation(config, vaultId, { exceptRequestId = null, exceptTxId = null, phase = "build" } = {}) {
  const id = normalizeVaultId(vaultId);
  if (!PHASES.has(phase)) throw fail(`unknown reservation phase ${JSON.stringify(phase)} — failing closed`, "BAD_PHASE");
  const stored = await readVaultRecordAny(config, id);
  if (!stored.readable || stored.record !== null) return { kind: "VAULT_RECORD", readable: stored.readable };
  const store = getStore(config);
  for (const category of [Categories.REQUEST, Categories.ORG_ROOT_REQUEST]) {
    for (const record of await store.listValues(category)) {
      if (!requestNamesVaultId(record, id)) continue;
      const own = exceptRequestId !== null && (record.requestId === exceptRequestId || record.id === exceptRequestId);
      if (own) continue;
      if (phase === "commit" && requestProvablyUncommitted(record)) continue;
      return { kind: category === Categories.REQUEST ? "REQUEST" : "ORG_ROOT_REQUEST" };
    }
  }
  /* RC35-RES-01 (2026-09-11): a durable submission claim naming the identity is a possible chain effect under it (the
   * headless v0.1 / v0.2 creators persist exactly this claim before their broadcast; a legacy retained claim carries the
   * binding vaultId ↔ txId and nothing else) — it reserves the identity in BOTH phases; only the caller's OWN transaction
   * (its own claim, or a same-effect duplicate carrying identical bytes) is excluded. */
  const ownTx = typeof exceptTxId === "string" ? exceptTxId.toLowerCase() : null;
  for (const claim of await store.listValues(Categories.SUBMISSION_CLAIM)) {
    if (!claim || typeof claim.vaultId !== "string" || claim.vaultId.toLowerCase() !== id) continue;
    if (ownTx !== null && typeof claim.txId === "string" && claim.txId.toLowerCase() === ownTx) continue;
    return { kind: "SUBMISSION_CLAIM", txId: typeof claim.txId === "string" ? claim.txId : null, action: typeof claim.action === "string" ? claim.action : null };
  }
  return null;
}

async function assertVaultIdentityFree(config, vaultId, options = {}) {
  const id = normalizeVaultId(vaultId);
  const reservation = await findVaultIdentityReservation(config, id, options);
  if (reservation) {
    throw fail(
      `vault identity ${id} is already in use — an existing vault record or an existing creation request names it; existing records are never replaced and identities are never recycled, so choose a fresh identity (nothing was built, signed, claimed or sent)`,
      "VAULT_ID_IN_USE"
    );
  }
  return id;
}

/* ------------------------------------------------------------------ */
/* the atomic create-only completion write                             */
/* ------------------------------------------------------------------ */

function schemaTagOf(record) {
  if (!record || typeof record !== "object") return null;
  if (typeof record.schema === "string") return record.schema;
  if (typeof record.manifestVersion === "string") return record.manifestVersion;
  return null;
}

/* The identity of a genesis outcome: the record as both drivers persist it
 * (BigInt → decimal string, undefined dropped), minus the volatile fields,
 * in canonical key order. */
function genesisRecordIdentity(record) {
  const plain = JSON.parse(JSON.stringify(record, (_key, value) => (typeof value === "bigint" ? value.toString() : value)));
  for (const field of VOLATILE_FIELDS) delete plain[field];
  return canonicalJsonStringify(plain);
}

/* true only when `existing` is the SAME genesis outcome as `expected`: the
 * same schema tag and every non-volatile field equal. A later record of the
 * same vault (advanced live state), a different creation under the same
 * identity, or a record of another generation is NOT the same outcome. */
function sameGenesisRecord(existing, expected) {
  const tag = schemaTagOf(existing);
  if (tag === null || tag !== schemaTagOf(expected)) return false;
  try {
    return genesisRecordIdentity(existing) === genesisRecordIdentity(expected);
  } catch {
    return false;
  }
}

/*
 * Create the vault record for a PROVEN genesis, or accept the identical record
 * a previous completion of the SAME genesis already wrote.
 *   { outcome: "CREATED", record }          this call created the record
 *   { outcome: "ALREADY_PRESENT", record }  the same genesis outcome was there
 *   throws RECONCILIATION_REQUIRED          the identity holds a DIFFERENT record
 *                                           (any generation, any creation) —
 *                                           left untouched
 * `value` is exactly what the generation's persist function would write.
 */
async function createVaultRecordOrMatch(config, vaultId, value) {
  const id = normalizeVaultId(vaultId);
  const created = await getStore(config).createExclusive(Categories.VAULT, id, value);
  if (created) return { outcome: "CREATED", record: value };
  const existing = await readVaultRecordAny(config, id);
  if (existing.readable && existing.record !== null && sameGenesisRecord(existing.record, value)) {
    return { outcome: "ALREADY_PRESENT", record: existing.record };
  }
  throw fail(
    `vault identity ${id} is occupied by a different durable record — that record is preserved untouched; this creation's proven chain outcome stays on its request (signed transaction, txid, claim) for reconciliation, nothing is rebuilt, re-signed or rebroadcast`,
    "RECONCILIATION_REQUIRED"
  );
}

module.exports = {
  UNCOMMITTED_REQUEST_STATES,
  requestProvablyUncommitted,
  normalizeVaultId,
  withVaultIdentityLock,
  readVaultRecordAny,
  requestNamesVaultId,
  findVaultIdentityReservation,
  assertVaultIdentityFree,
  sameGenesisRecord,
  genesisRecordIdentity,
  createVaultRecordOrMatch
};
