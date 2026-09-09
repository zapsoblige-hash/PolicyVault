"use strict";

/*
 * Durable, CREATE-ONLY settlement claims (spec §9). Two uniqueness
 * invariants: (network, transactionId, outputIndex) and requirementDigest.
 * A claim carries its evidence IN the same atomic record — never a
 * two-phase "claim then evidence". Records are never mutated or
 * backfilled. The store holds no PolicyVault tenant data and no secrets.
 *
 * JSON store (single instance): POSIX create-exclusive via link(2) of a
 * fully written temp file — atomic AND complete (a crash can never leave
 * a torn record at the final path). Layout under `dir`:
 *   outpoints/<sha256(network|txid|index)>.json   reservation → digest
 *   claims/<requirementDigest>.json               THE claim + evidence
 *   destinations/<sha256(network|payTo|amount)>/<digest>.json   window index
 * Order: reserve the outpoint, then create the claim. Crash recovery and
 * race dispositions are in createClaim().
 *
 * PostgreSQL store (shared, before any second instance): one INSERT with
 * two UNIQUE constraints — the database is the single race authority.
 * The `query` function is INJECTED (the facilitator runtime never imports
 * a database driver; the launcher resolves `pg` from the SDK package).
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const CLAIM_SCHEMA = "policyvault-x402-facilitator-claim/1";

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}
function outpointKey(network, transactionId, outputIndex) {
  return sha256Hex(`${network}|${transactionId}|${outputIndex}`);
}
function destinationKey(network, payTo, amount) {
  return sha256Hex(`${network}|${payTo}|${amount}`);
}

const HEX64_RE = /^[0-9a-f]{64}$/;
const DAA_RE = /^(0|[1-9][0-9]*)$/;

/* Closed shape of a claim record; BigInt-free (decimal strings). */
function normalizeClaim(input) {
  const required = ["requirementDigest", "network", "transactionId", "outputIndex", "payTo", "amount", "asset", "validFromDaaScore", "validUntilDaaScore", "evidence"];
  if (!input || typeof input !== "object") throw new Error("claim must be an object");
  for (const k of required) if (input[k] === undefined) throw new Error(`claim.${k} is required`);
  if (!HEX64_RE.test(input.requirementDigest) || !HEX64_RE.test(input.transactionId)) throw new Error("claim digests must be 64 hex");
  if (!Number.isInteger(input.outputIndex) || input.outputIndex < 0) throw new Error("claim.outputIndex must be a non-negative integer");
  for (const k of ["network", "payTo", "amount", "asset"]) if (typeof input[k] !== "string" || !input[k]) throw new Error(`claim.${k} must be a string`);
  if (!DAA_RE.test(input.validFromDaaScore) || !DAA_RE.test(input.validUntilDaaScore)) throw new Error("claim window must be decimal strings");
  if (!input.evidence || typeof input.evidence !== "object") throw new Error("claim.evidence must be an object");
  return {
    schema: CLAIM_SCHEMA,
    claimKey: outpointKey(input.network, input.transactionId, input.outputIndex),
    requirementDigest: input.requirementDigest,
    network: input.network,
    transactionId: input.transactionId,
    outputIndex: input.outputIndex,
    payTo: input.payTo,
    amount: input.amount,
    asset: input.asset,
    validFromDaaScore: input.validFromDaaScore,
    validUntilDaaScore: input.validUntilDaaScore,
    evidence: input.evidence,
    createdAt: input.createdAt ?? new Date().toISOString()
  };
}

function windowsOverlap(aFrom, aUntil, bFrom, bUntil) {
  return BigInt(aFrom) <= BigInt(bUntil) && BigInt(bFrom) <= BigInt(aUntil);
}

/* ------------------------------------------------------------------ */
/* JSON store                                                          */
/* ------------------------------------------------------------------ */

class JsonClaimStore {
  constructor({ dir }) {
    if (typeof dir !== "string" || !dir) throw new Error("x402-facilitator: claim store dir is required");
    this.dir = dir;
    for (const sub of ["outpoints", "claims", "destinations", "tmp"]) fs.mkdirSync(path.join(dir, sub), { recursive: true, mode: 0o700 });
  }

  /* Atomic, exclusive, COMPLETE create: write the whole body to a temp
   * file, then link(2) it to the final path (EEXIST if present). */
  _createExclusive(finalPath, body) {
    const tmp = path.join(this.dir, "tmp", `${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
    fs.writeFileSync(tmp, body, { mode: 0o600 });
    try {
      fs.linkSync(tmp, finalPath);
      return true;
    } catch (e) {
      if (e.code === "EEXIST") return false;
      throw e;
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  }

  _readJson(file) {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
  }

  async readByDigest(requirementDigest) {
    if (!HEX64_RE.test(requirementDigest)) return null;
    return this._readJson(path.join(this.dir, "claims", `${requirementDigest}.json`));
  }

  async readByOutpoint(network, transactionId, outputIndex) {
    const pointer = this._readJson(path.join(this.dir, "outpoints", `${outpointKey(network, transactionId, outputIndex)}.json`));
    if (!pointer) return null;
    const claim = await this.readByDigest(pointer.requirementDigest);
    return { pointer, claim };
  }

  /* Settled requirements with the same (network, payTo, amount) whose
   * window overlaps [validFrom, validUntil], excluding `excludeDigest`. */
  async findDestinationConflicts({ network, payTo, amount, validFromDaaScore, validUntilDaaScore, excludeDigest }) {
    const dir = path.join(this.dir, "destinations", destinationKey(network, payTo, amount));
    let entries;
    try {
      entries = fs.readdirSync(dir);
    } catch (e) {
      if (e.code === "ENOENT") return [];
      throw e;
    }
    const out = [];
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      const rec = this._readJson(path.join(dir, entry));
      if (!rec || rec.requirementDigest === excludeDigest) continue;
      if (windowsOverlap(rec.validFromDaaScore, rec.validUntilDaaScore, validFromDaaScore, validUntilDaaScore)) out.push(rec);
    }
    return out;
  }

  /*
   * createClaim → { created: true, claim }
   *             | { created: false, reason: "REPLAY", claim }              identical (digest, outpoint) already claimed
   *             | { created: false, reason: "PAYMENT_ALREADY_CLAIMED", claim }   outpoint bound to another digest
   *             | { created: false, reason: "REQUIREMENT_ALREADY_SETTLED", claim } digest bound to another outpoint
   */
  async createClaim(input) {
    const claim = normalizeClaim(input);
    const pointerPath = path.join(this.dir, "outpoints", `${claim.claimKey}.json`);
    const claimPath = path.join(this.dir, "claims", `${claim.requirementDigest}.json`);

    // 1. reserve the outpoint
    let reservedHere = this._createExclusive(pointerPath, JSON.stringify({ requirementDigest: claim.requirementDigest, network: claim.network, transactionId: claim.transactionId, outputIndex: claim.outputIndex, reservedAt: claim.createdAt }, null, 1));
    if (!reservedHere) {
      const pointer = this._readJson(pointerPath);
      if (!pointer || pointer.requirementDigest !== claim.requirementDigest) {
        const other = pointer ? await this.readByDigest(pointer.requirementDigest) : null;
        return { created: false, reason: "PAYMENT_ALREADY_CLAIMED", claim: other };
      }
      // same digest: idempotent retry (or crash recovery) — fall through
    }

    // 2. create the claim (with its evidence) exclusively by digest
    const created = this._createExclusive(claimPath, JSON.stringify(claim, null, 1));
    if (!created) {
      const existing = this._readJson(claimPath);
      if (existing && existing.transactionId === claim.transactionId && existing.outputIndex === claim.outputIndex && existing.network === claim.network) {
        return { created: false, reason: "REPLAY", claim: existing };
      }
      if (reservedHere) fs.rmSync(pointerPath, { force: true }); // release OUR reservation only
      return { created: false, reason: "REQUIREMENT_ALREADY_SETTLED", claim: existing };
    }

    // 3. destination index (idempotent; rebuildable from claims/)
    const destDir = path.join(this.dir, "destinations", destinationKey(claim.network, claim.payTo, claim.amount));
    fs.mkdirSync(destDir, { recursive: true, mode: 0o700 });
    this._createExclusive(path.join(destDir, `${claim.requirementDigest}.json`), JSON.stringify({ requirementDigest: claim.requirementDigest, validFromDaaScore: claim.validFromDaaScore, validUntilDaaScore: claim.validUntilDaaScore }, null, 1));
    return { created: true, claim };
  }
}

/* ------------------------------------------------------------------ */
/* PostgreSQL store (injected query function)                          */
/* ------------------------------------------------------------------ */

const PG_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS x402f_claims (
  requirement_digest text PRIMARY KEY,
  network text NOT NULL,
  transaction_id text NOT NULL,
  output_index integer NOT NULL CHECK (output_index >= 0),
  pay_to text NOT NULL,
  amount text NOT NULL,
  asset text NOT NULL,
  valid_from numeric(20,0) NOT NULL,
  valid_until numeric(20,0) NOT NULL,
  record jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT x402f_claims_outpoint_unique UNIQUE (network, transaction_id, output_index)
);
CREATE INDEX IF NOT EXISTS x402f_claims_destination_idx ON x402f_claims (network, pay_to, amount);
`;

class PgClaimStore {
  /* query(sql, params) → Promise<{ rows }> — injected by the launcher. */
  constructor({ query }) {
    if (typeof query !== "function") throw new Error("x402-facilitator: PgClaimStore requires an injected query function");
    this.query = query;
  }

  async ensureSchema() {
    await this.query(PG_SCHEMA_SQL, []);
  }

  async readByDigest(requirementDigest) {
    if (!HEX64_RE.test(requirementDigest)) return null;
    const r = await this.query("SELECT record FROM x402f_claims WHERE requirement_digest = $1", [requirementDigest]);
    return r.rows.length ? r.rows[0].record : null;
  }

  async readByOutpoint(network, transactionId, outputIndex) {
    const r = await this.query("SELECT record FROM x402f_claims WHERE network = $1 AND transaction_id = $2 AND output_index = $3", [network, transactionId, outputIndex]);
    if (!r.rows.length) return null;
    const claim = r.rows[0].record;
    return { pointer: { requirementDigest: claim.requirementDigest }, claim };
  }

  async findDestinationConflicts({ network, payTo, amount, validFromDaaScore, validUntilDaaScore, excludeDigest }) {
    const r = await this.query(
      "SELECT record FROM x402f_claims WHERE network = $1 AND pay_to = $2 AND amount = $3 AND requirement_digest <> $4 AND valid_from <= $6::numeric AND valid_until >= $5::numeric",
      [network, payTo, amount, excludeDigest ?? "", validFromDaaScore, validUntilDaaScore]
    );
    return r.rows.map((row) => ({ requirementDigest: row.record.requirementDigest, validFromDaaScore: row.record.validFromDaaScore, validUntilDaaScore: row.record.validUntilDaaScore }));
  }

  async createClaim(input) {
    const claim = normalizeClaim(input);
    const inserted = await this.query(
      "INSERT INTO x402f_claims (requirement_digest, network, transaction_id, output_index, pay_to, amount, asset, valid_from, valid_until, record) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::jsonb) ON CONFLICT DO NOTHING RETURNING requirement_digest",
      [claim.requirementDigest, claim.network, claim.transactionId, claim.outputIndex, claim.payTo, claim.amount, claim.asset, claim.validFromDaaScore, claim.validUntilDaaScore, JSON.stringify(claim)]
    );
    if (inserted.rows.length) return { created: true, claim };
    const byDigest = await this.readByDigest(claim.requirementDigest);
    if (byDigest) {
      if (byDigest.transactionId === claim.transactionId && byDigest.outputIndex === claim.outputIndex && byDigest.network === claim.network) return { created: false, reason: "REPLAY", claim: byDigest };
      return { created: false, reason: "REQUIREMENT_ALREADY_SETTLED", claim: byDigest };
    }
    const byOutpoint = await this.readByOutpoint(claim.network, claim.transactionId, claim.outputIndex);
    return { created: false, reason: "PAYMENT_ALREADY_CLAIMED", claim: byOutpoint ? byOutpoint.claim : null };
  }
}

module.exports = { CLAIM_SCHEMA, JsonClaimStore, PgClaimStore, PG_SCHEMA_SQL, normalizeClaim, outpointKey, destinationKey, windowsOverlap };
