"use strict";

/*
 * Durable, CREATE-ONLY attempt records for the adapters (x402 spec §4.8,
 * ap2 spec §4.7) — adapter-LOCAL state. The adapters have no database
 * handle and no PolicyVault store access (that would be a privileged
 * path); each adapter keeps its own append-only JSON records under its
 * own data directory, exactly like any other unprivileged client would.
 *
 * Rules carried from the specs:
 *   - createExclusive semantics, keyed by the caller-supplied anchor
 *     (x402 attemptId / AP2 transaction_id) per network. Winning the
 *     claim is what makes a concurrent duplicate refuse (X-10 / A-13
 *     adapter side; the platform Idempotency-Key is the second wall).
 *   - Records are never updated in place EXCEPT by appending an
 *     outcome-transition event: `outcome` holds the latest, and
 *     `outcomeHistory` appends every transition. The normalized proposal,
 *     digests, and `protocol.*` raw metadata are frozen at creation.
 *   - `protocol.*` is quarantined by construction: nothing in any
 *     decision path reads it (enforced by the adapters' code shape and
 *     asserted by test X-35 / A-43).
 *   - No secrets: no machine credential, no credential hash, no
 *     Authorization material — the derived idempotency KEY is a public
 *     digest of public inputs and is stored; tokens never are.
 *   - Never backfilled.
 *
 * Durability: atomic tempfile + rename inside the store directory;
 * create-exclusive via `wx` open. Single-adapter-process deployment is a
 * stated assumption (mirroring the launch pin's process-local limiter
 * precedent) — two adapter processes must never share a data directory.
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

class AttemptStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AttemptStoreError";
    this.code = code;
  }
}

/* Anchor -> filename. x402 attemptIds are UUIDs and AP2 transaction_ids
 * are base64url — both filesystem-safe charsets — but the file name is
 * ALWAYS the sha256 of the anchor, so no untrusted string ever chooses a
 * path (defense in depth over charset validation). */
function fileNameFor(anchor) {
  return `${crypto.createHash("sha256").update(anchor, "utf8").digest("hex")}.json`;
}

class AttemptStore {
  constructor({ dir }) {
    if (typeof dir !== "string" || !dir) throw new AttemptStoreError("STORE_CONFIG", "attempt store dir is required");
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  _pathFor(anchor) {
    return path.join(this.dir, fileNameFor(anchor));
  }

  /*
   * Claim an anchor exclusively. Returns { claimed: true } on a win;
   * { claimed: false, existing } when a record already exists. A crashed
   * IN_PROGRESS claim older than staleMs may be reclaimed once (the
   * platform Idempotency-Key makes the underlying build at-most-once even
   * if this ever raced).
   */
  claim(anchor, record, { staleMs = 5 * 60 * 1000 } = {}) {
    const file = this._pathFor(anchor);
    const body = JSON.stringify(record, null, 1);
    try {
      fs.writeFileSync(file, body, { flag: "wx", mode: 0o600 });
      return { claimed: true };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    const existing = this.read(anchor);
    if (
      existing &&
      existing.outcome &&
      existing.outcome.status === "IN_PROGRESS" &&
      Date.now() - Date.parse(existing.outcome.at) > staleMs
    ) {
      // One reclaim attempt for a crashed handler; still create-exclusive
      // against a concurrent reclaimer via a fresh wx on a temp + rename.
      try {
        fs.rmSync(file, { force: true });
        fs.writeFileSync(file, body, { flag: "wx", mode: 0o600 });
        return { claimed: true, reclaimed: true };
      } catch {
        return { claimed: false, existing: this.read(anchor) };
      }
    }
    return { claimed: false, existing };
  }

  read(anchor) {
    try {
      return JSON.parse(fs.readFileSync(this._pathFor(anchor), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  }

  /*
   * Append an outcome transition. The ONLY mutation the store performs:
   * `outcome` is replaced (previous outcome appended to
   * `outcomeHistory`), and the WRITE-ONCE correlation-spine fields below
   * may go null -> value exactly once. Everything else — the normalized
   * proposal, the digests, `protocol.*` — is frozen at creation; a
   * caller that tries to rewrite it gets a refusal, not a silent update.
   */
  transition(anchor, outcome, { set } = {}) {
    const file = this._pathFor(anchor);
    const existing = this.read(anchor);
    if (!existing) throw new AttemptStoreError("ATTEMPT_NOT_FOUND", `no attempt record for anchor`);
    if (!outcome || typeof outcome.status !== "string" || typeof outcome.stage !== "string" || !Array.isArray(outcome.codes)) {
      throw new AttemptStoreError("OUTCOME_INVALID", "outcome must be { status, stage, codes[] }");
    }
    const next = { ...existing };
    next.outcomeHistory = [...(existing.outcomeHistory ?? []), existing.outcome].filter(Boolean);
    next.outcome = { ...outcome, at: new Date().toISOString() };
    if (set !== undefined) {
      const WRITE_ONCE = new Set(["requestId", "manifestHash", "txId", "riskEvaluationId", "settlement", "delivery", "constraints", "settlementResponseRaw"]);
      for (const [key, value] of Object.entries(set)) {
        if (!WRITE_ONCE.has(key)) throw new AttemptStoreError("FIELD_FROZEN", `field ${JSON.stringify(key)} is not an additive correlation field — attempt records are create-only`);
        if (key === "settlementResponseRaw") {
          // The one protocol.* slot that arrives after creation, by design
          // (the counterparty's own claim, recorded verbatim, read by
          // nothing) — still write-once.
          if (existing.protocol && existing.protocol.settlementResponseRaw != null) {
            throw new AttemptStoreError("FIELD_FROZEN", "protocol.settlementResponseRaw was already recorded");
          }
          next.protocol = { ...existing.protocol, settlementResponseRaw: value };
          continue;
        }
        if (existing[key] != null && existing[key] !== value) {
          throw new AttemptStoreError("FIELD_FROZEN", `correlation field ${JSON.stringify(key)} is write-once (${JSON.stringify(existing[key])} recorded)`);
        }
        next[key] = value;
      }
    }
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, file);
    return next;
  }

  /* Read every record (budget/recurrence accounting walks; audit). */
  list() {
    const out = [];
    for (const entry of fs.readdirSync(this.dir)) {
      if (!entry.endsWith(".json")) continue;
      try {
        out.push(JSON.parse(fs.readFileSync(path.join(this.dir, entry), "utf8")));
      } catch {
        // A torn record is skipped for accounting; conservative callers
        // treat unreadable records as counting AGAINST budgets.
        out.push(null);
      }
    }
    return out;
  }
}

module.exports = { AttemptStore, AttemptStoreError };
