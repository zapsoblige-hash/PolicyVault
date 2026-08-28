"use strict";

/*
 * PolicyVault hosted wallet authentication + sessions (Phases B/C of the
 * Hosted Web Architecture + Security checkpoint).
 *
 * AUTHENTICATION != COVENANT AUTHORITY. A hosted session proves only
 * "this browser holds a live Schnorr-verified login for wallet X on
 * network Y". It grants tenancy/application identity and NOTHING more:
 * every covenant operation keeps its own independent signer validation
 * over frozen transaction bytes. No route may treat the session wallet
 * as covenant authorization.
 *
 * Cryptography: the challenge signature is Kaspa personal-message
 * signing — keyed-blake2b domain `PersonalMessageSigningHash`, BIP-340
 * Schnorr, verified against the x-only public key — via the pinned
 * kaspa-wasm module (`verifyMessage`). Transaction signatures live in
 * the distinct `TransactionSigningHash` domain, so an authentication
 * signature can never be replayed as covenant authority (and vice
 * versa). No custom cryptography is implemented here.
 *
 * Storage (Phase C): pluggable auth store.
 *   MemoryAuthStore — process-local (json/self-hosted testing): restart
 *     invalidates every challenge and session (fail closed).
 *   PgAuthStore — hosted mode: challenges and sessions persist in
 *     PostgreSQL; single-use consumption is a database compare-and-set,
 *     so even TWO app processes cannot consume one challenge twice, and
 *     revocation/expiry survive restart. Only the SHA-256 of a session
 *     token is ever stored — the raw bearer token exists only in the
 *     HttpOnly cookie. All identity/expiry DECISIONS stay in this
 *     service; the store provides atomic primitives.
 */

const crypto = require("crypto");
const { loadKaspa } = require("../../sdk/src/chain");
const { resolveAddressIdentity } = require("../../sdk/src/address-identity");

/* Stable machine-readable error classes (directive §23). Cryptographic
 * failure modes deliberately collapse into AUTH_SIGNATURE_INVALID (no
 * verification oracle); challenge lifecycle states and the unsupported
 * account type are distinguished because users need actionable errors. */
const AuthErrorCodes = Object.freeze({
  AUTH_DISABLED: "AUTH_DISABLED",
  AUTH_BAD_INPUT: "AUTH_BAD_INPUT",
  AUTH_CHALLENGE_UNKNOWN: "AUTH_CHALLENGE_UNKNOWN",
  AUTH_CHALLENGE_EXPIRED: "AUTH_CHALLENGE_EXPIRED",
  AUTH_CHALLENGE_USED: "AUTH_CHALLENGE_USED",
  AUTH_CHALLENGE_CAPACITY: "AUTH_CHALLENGE_CAPACITY",
  AUTH_SIGNATURE_INVALID: "AUTH_SIGNATURE_INVALID",
  AUTH_PUBKEY_INVALID: "AUTH_PUBKEY_INVALID",
  AUTH_ADDRESS_MISMATCH: "AUTH_ADDRESS_MISMATCH",
  AUTH_NETWORK_MISMATCH: "AUTH_NETWORK_MISMATCH",
  AUTH_ACCOUNT_TYPE_UNSUPPORTED: "AUTH_ACCOUNT_TYPE_UNSUPPORTED",
  SESSION_INVALID: "SESSION_INVALID",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_REVOKED: "SESSION_REVOKED"
});

function authError(status, code, message) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  return e;
}

/* Memory bounds only — real per-IP/session rate limiting is Phase D. */
const MAX_CHALLENGES_PER_WALLET = 8;
const MAX_TOTAL_CHALLENGES = 10_000;
const MAX_TOTAL_SESSIONS = 20_000;

const NONCE_HEX = /^[0-9a-f]{64}$/;
const SCHNORR_SIG_HEX = /^[0-9a-f]{128}$/;
const TOKEN_HEX = /^[0-9a-f]{64}$/;

const ECDSA_UNSUPPORTED_MESSAGE =
  "This wallet account type (ECDSA, e.g. Tangem) is not supported for hosted sign-in in v1. " +
  "Use a standard Schnorr public-key account. Signature verification was not attempted.";

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

/* ------------------------------------------------------------------ */
/* Auth stores                                                         */
/* ------------------------------------------------------------------ */

class MemoryAuthStore {
  constructor() {
    this.kind = "memory";
    this._challenges = new Map(); // nonce -> record
    this._sessions = new Map(); // tokenHash -> record
  }

  async challengeInsert(rec) {
    if (this._challenges.has(rec.nonce)) return false;
    this._challenges.set(rec.nonce, { ...rec });
    return true;
  }

  /* Atomic CAS: issued -> verifying. Returns the claimed record, or a
   * status string ("unknown" | "busy" | "expired") — never both racers. */
  async challengeClaim(nonce, nowMs) {
    const rec = this._challenges.get(nonce);
    if (!rec) return "unknown";
    if (rec.state !== "issued") return "busy";
    if (nowMs > rec.expiresAtMs) {
      this._challenges.delete(nonce);
      return "expired";
    }
    rec.state = "verifying";
    return { ...rec };
  }

  async challengeRelease(nonce) {
    const rec = this._challenges.get(nonce);
    if (rec && rec.state === "verifying") rec.state = "issued";
  }

  async challengeConsume(nonce) {
    this._challenges.delete(nonce);
  }

  async challengeSweep(nowMs) {
    for (const [nonce, rec] of this._challenges) {
      if (nowMs > rec.expiresAtMs && rec.state !== "verifying") this._challenges.delete(nonce);
    }
  }

  async challengeStats(walletAddress) {
    const mine = [...this._challenges.values()].filter((r) => r.walletAddress === walletAddress && r.state === "issued");
    mine.sort((a, b) => a.issuedAtMs - b.issuedAtMs);
    return { total: this._challenges.size, mineCount: mine.length, oldestMineNonce: mine.length ? mine[0].nonce : null };
  }

  async sessionInsert(rec) {
    if (this._sessions.has(rec.tokenHash)) return false;
    this._sessions.set(rec.tokenHash, { ...rec });
    return true;
  }

  async sessionGet(tokenHash) {
    const s = this._sessions.get(tokenHash);
    return s ? { ...s } : null;
  }

  async sessionTouch(tokenHash, nowMs) {
    const s = this._sessions.get(tokenHash);
    if (s) s.lastSeenMs = nowMs;
  }

  async sessionDelete(tokenHash) {
    return this._sessions.delete(tokenHash);
  }

  async sessionSweep(nowMs, { inactivityMs, absoluteMs }) {
    for (const [hash, s] of this._sessions) {
      if (s.revoked || nowMs - s.createdAtMs > absoluteMs || nowMs - s.lastSeenMs > inactivityMs) this._sessions.delete(hash);
    }
  }

  async sessionCount() {
    return this._sessions.size;
  }
}

/*
 * PostgreSQL auth store (hosted). All operations are single-statement
 * atomic; challengeClaim is a CAS UPDATE with the state+expiry predicate
 * — under ANY number of app processes exactly one claimant wins.
 */
class PgAuthStore {
  constructor(pool, networkId) {
    this.kind = "postgres";
    this._pool = pool;
    this._net = networkId;
  }

  async challengeInsert(rec) {
    const r = await this._pool.query(
      `INSERT INTO auth_challenges (network_id, nonce, wallet_address, xonly, issued_at_ms, expires_at_ms, state)
       VALUES ($1, $2, $3, $4, $5, $6, 'issued') ON CONFLICT (network_id, nonce) DO NOTHING`,
      [this._net, rec.nonce, rec.walletAddress, rec.xOnlyPubkey, rec.issuedAtMs, rec.expiresAtMs]
    );
    return r.rowCount === 1;
  }

  async challengeClaim(nonce, nowMs) {
    const claim = await this._pool.query(
      `UPDATE auth_challenges SET state = 'verifying'
       WHERE network_id = $1 AND nonce = $2 AND state = 'issued' AND expires_at_ms >= $3
       RETURNING nonce, wallet_address, xonly, issued_at_ms, expires_at_ms`,
      [this._net, nonce, nowMs]
    );
    if (claim.rowCount === 1) {
      const row = claim.rows[0];
      return {
        nonce: row.nonce,
        walletAddress: row.wallet_address,
        xOnlyPubkey: row.xonly,
        networkId: this._net,
        issuedAtMs: Number(row.issued_at_ms),
        expiresAtMs: Number(row.expires_at_ms),
        state: "verifying"
      };
    }
    const probe = await this._pool.query(`SELECT state, expires_at_ms FROM auth_challenges WHERE network_id = $1 AND nonce = $2`, [this._net, nonce]);
    if (probe.rowCount === 0) return "unknown";
    if (Number(probe.rows[0].expires_at_ms) < nowMs) {
      await this._pool.query(`DELETE FROM auth_challenges WHERE network_id = $1 AND nonce = $2 AND state = 'issued'`, [this._net, nonce]);
      return "expired";
    }
    return "busy";
  }

  async challengeRelease(nonce) {
    await this._pool.query(`UPDATE auth_challenges SET state = 'issued' WHERE network_id = $1 AND nonce = $2 AND state = 'verifying'`, [this._net, nonce]);
  }

  async challengeConsume(nonce) {
    await this._pool.query(`DELETE FROM auth_challenges WHERE network_id = $1 AND nonce = $2`, [this._net, nonce]);
  }

  async challengeSweep(nowMs) {
    await this._pool.query(`DELETE FROM auth_challenges WHERE network_id = $1 AND expires_at_ms < $2 AND state = 'issued'`, [this._net, nowMs]);
  }

  async challengeStats(walletAddress) {
    const totals = await this._pool.query(`SELECT count(*)::int AS total FROM auth_challenges WHERE network_id = $1`, [this._net]);
    const mine = await this._pool.query(
      `SELECT nonce FROM auth_challenges WHERE network_id = $1 AND wallet_address = $2 AND state = 'issued' ORDER BY issued_at_ms ASC`,
      [this._net, walletAddress]
    );
    return { total: totals.rows[0].total, mineCount: mine.rowCount, oldestMineNonce: mine.rowCount ? mine.rows[0].nonce : null };
  }

  async sessionInsert(rec) {
    const r = await this._pool.query(
      `INSERT INTO auth_sessions (network_id, token_hash, wallet_address, xonly, created_at_ms, last_seen_ms, revoked)
       VALUES ($1, $2, $3, $4, $5, $6, false) ON CONFLICT (network_id, token_hash) DO NOTHING`,
      [this._net, rec.tokenHash, rec.walletAddress, rec.xOnlyPubkey, rec.createdAtMs, rec.lastSeenMs]
    );
    return r.rowCount === 1;
  }

  async sessionGet(tokenHash) {
    const r = await this._pool.query(
      `SELECT token_hash, wallet_address, xonly, created_at_ms, last_seen_ms, revoked FROM auth_sessions WHERE network_id = $1 AND token_hash = $2`,
      [this._net, tokenHash]
    );
    if (r.rowCount === 0) return null;
    const row = r.rows[0];
    return {
      tokenHash: row.token_hash,
      walletAddress: row.wallet_address,
      xOnlyPubkey: row.xonly,
      networkId: this._net,
      createdAtMs: Number(row.created_at_ms),
      lastSeenMs: Number(row.last_seen_ms),
      revoked: row.revoked
    };
  }

  async sessionTouch(tokenHash, nowMs) {
    await this._pool.query(`UPDATE auth_sessions SET last_seen_ms = $3 WHERE network_id = $1 AND token_hash = $2 AND revoked = false`, [
      this._net,
      tokenHash,
      nowMs
    ]);
  }

  async sessionDelete(tokenHash) {
    const r = await this._pool.query(`DELETE FROM auth_sessions WHERE network_id = $1 AND token_hash = $2`, [this._net, tokenHash]);
    return r.rowCount > 0;
  }

  async sessionSweep(nowMs, { inactivityMs, absoluteMs }) {
    await this._pool.query(
      `DELETE FROM auth_sessions WHERE network_id = $1 AND (revoked OR created_at_ms < $2 OR last_seen_ms < $3)`,
      [this._net, nowMs - absoluteMs, nowMs - inactivityMs]
    );
  }

  async sessionCount() {
    const r = await this._pool.query(`SELECT count(*)::int AS n FROM auth_sessions WHERE network_id = $1`, [this._net]);
    return r.rows[0].n;
  }
}

/* ------------------------------------------------------------------ */
/* The service                                                         */
/* ------------------------------------------------------------------ */

class HostedAuthService {
  /*
   * `providers` (test-only injection, directive §26): { now, randomBytes,
   * store }. Production constructs with the real clock, Node's CSPRNG,
   * and the backend-matched store. No environment flag switches these
   * implicitly.
   */
  constructor(config, providers = {}) {
    if (config.authMode !== "enabled") {
      throw authError(500, AuthErrorCodes.AUTH_DISABLED, "internal: HostedAuthService requires authMode=enabled config");
    }
    this._config = config;
    this._now = providers.now || (() => Date.now());
    this._randomBytes = providers.randomBytes || ((n) => crypto.randomBytes(n));
    this._store = providers.store || new MemoryAuthStore();
  }

  /*
   * THE single canonical challenge builder (directive §6) — used by
   * issuance AND verification. Frozen shape: exactly 7 lines joined by
   * "\n" (LF only), no trailing newline, UTF-8; origin is the server's
   * CONFIGURED application origin (never a request header); timestamp is
   * RFC3339 UTC with milliseconds (Date.toISOString). Any one-byte
   * difference produces a different PersonalMessageSigningHash and the
   * signature fails.
   */
  challengeText({ walletAddress, nonce, issuedAtMs }) {
    return [
      "PolicyVault authentication",
      `origin: ${this._config.appOrigin}`,
      `network: ${this._config.networkId}`,
      `address: ${walletAddress}`,
      `nonce: ${nonce}`,
      `issued: ${new Date(issuedAtMs).toISOString()}`,
      "This signature only signs you in. It cannot move funds."
    ].join("\n");
  }

  /*
   * POST /auth/challenge. The wallet address is validated through the ONE
   * existing identity resolver: canonical form, correct network family,
   * PubKey (Schnorr) version only. ECDSA/Tangem and script-hash accounts
   * fail HERE with the stable unsupported-type error — before any
   * signing round-trip.
   */
  async createChallenge(addressInput) {
    let identity;
    try {
      identity = resolveAddressIdentity(this._config, addressInput);
    } catch (e) {
      if (e.code === "ADDRESS_TYPE_UNSUPPORTED") {
        throw authError(422, AuthErrorCodes.AUTH_ACCOUNT_TYPE_UNSUPPORTED, ECDSA_UNSUPPORTED_MESSAGE);
      }
      throw authError(422, AuthErrorCodes.AUTH_BAD_INPUT, e.message);
    }

    const nowMs = this._now();
    await this._store.challengeSweep(nowMs);

    const stats = await this._store.challengeStats(identity.address);
    if (stats.mineCount >= MAX_CHALLENGES_PER_WALLET && stats.oldestMineNonce) {
      await this._store.challengeConsume(stats.oldestMineNonce); // self-evict this wallet's oldest
    }
    if (stats.total >= MAX_TOTAL_CHALLENGES) {
      throw authError(503, AuthErrorCodes.AUTH_CHALLENGE_CAPACITY, "too many outstanding sign-in challenges — try again shortly");
    }

    const record = {
      nonce: this._randomBytes(32).toString("hex"),
      walletAddress: identity.address,
      xOnlyPubkey: identity.xOnlyPubkey,
      networkId: this._config.networkId,
      issuedAtMs: nowMs,
      expiresAtMs: nowMs + this._config.authChallengeTtlMs,
      state: "issued"
    };
    if (!NONCE_HEX.test(record.nonce) || !(await this._store.challengeInsert(record))) {
      throw authError(500, AuthErrorCodes.AUTH_BAD_INPUT, "internal: nonce generation failed");
    }
    return {
      nonce: record.nonce,
      message: this.challengeText(record),
      walletAddress: identity.address,
      networkId: record.networkId,
      expiresAt: new Date(record.expiresAtMs).toISOString()
    };
  }

  /*
   * POST /auth/verify. Fail-closed order: shape -> atomic claim (store
   * CAS: exactly one concurrent claimant wins, across processes under
   * PostgreSQL) -> wallet/network binding -> pubkey<->address identity
   * -> Schnorr signature over the SERVER-reconstructed message (a
   * client-submitted message string is never accepted). A FAILED verify
   * releases the challenge (single-use applies to success); the nonce is
   * a 256-bit secret known only to its requester, so third parties
   * cannot reach this path to burn someone's challenge.
   */
  async verify({ nonce, signature, publicKey, walletAddress }, presentedSessionToken) {
    if (typeof nonce !== "string" || !NONCE_HEX.test(nonce)) {
      throw authError(400, AuthErrorCodes.AUTH_BAD_INPUT, "nonce must be the 64-hex challenge nonce");
    }
    if (typeof signature !== "string" || !SCHNORR_SIG_HEX.test(signature.toLowerCase())) {
      // Length-gate enforces the Schnorr scheme: 64-byte BIP-340 only —
      // no silent retry as another signature type.
      throw authError(400, AuthErrorCodes.AUTH_BAD_INPUT, "signature must be a 128-hex (64-byte) Schnorr personal-message signature");
    }
    if (typeof publicKey !== "string" || !/^[0-9a-f]{64}$|^0[23][0-9a-f]{64}$/i.test(publicKey)) {
      throw authError(400, AuthErrorCodes.AUTH_PUBKEY_INVALID, "publicKey must be 64-hex x-only or 66-hex compressed");
    }

    const nowMs = this._now();
    const claimed = await this._store.challengeClaim(nonce, nowMs);
    if (claimed === "unknown") throw authError(401, AuthErrorCodes.AUTH_CHALLENGE_UNKNOWN, "unknown sign-in challenge — request a new one");
    if (claimed === "busy") throw authError(401, AuthErrorCodes.AUTH_CHALLENGE_USED, "this sign-in challenge is already being used — request a new one");
    if (claimed === "expired") throw authError(401, AuthErrorCodes.AUTH_CHALLENGE_EXPIRED, "the sign-in challenge expired — request a new one");
    const rec = claimed;
    try {
      if (walletAddress !== undefined && walletAddress !== rec.walletAddress) {
        throw authError(401, AuthErrorCodes.AUTH_ADDRESS_MISMATCH, "this challenge was issued for a different wallet address");
      }
      if (rec.networkId !== this._config.networkId) {
        throw authError(401, AuthErrorCodes.AUTH_NETWORK_MISMATCH, "the challenge network does not match this server's network");
      }

      const kaspa = loadKaspa(this._config);
      let xOnly;
      try {
        xOnly =
          publicKey.length === 64
            ? new kaspa.XOnlyPublicKey(publicKey.toLowerCase()).toString().toLowerCase()
            : new kaspa.PublicKey(publicKey.toLowerCase()).toXOnlyPublicKey().toString().toLowerCase();
      } catch {
        throw authError(400, AuthErrorCodes.AUTH_PUBKEY_INVALID, "publicKey does not parse as a secp256k1 public key");
      }
      // Lossless identity binding: the submitted key must be exactly the
      // key inside the challenge's wallet address.
      if (xOnly !== rec.xOnlyPubkey) {
        throw authError(401, AuthErrorCodes.AUTH_ADDRESS_MISMATCH, "public key does not match the challenge wallet address");
      }

      const message = this.challengeText(rec); // server-side reconstruction — the ONLY message verified
      let ok = false;
      try {
        ok = kaspa.verifyMessage({ message, signature: signature.toLowerCase(), publicKey: xOnly }) === true;
      } catch {
        ok = false;
      }
      if (!ok) {
        throw authError(401, AuthErrorCodes.AUTH_SIGNATURE_INVALID, "signature verification failed");
      }

      // Success: consume (single-use) + create the rotated session.
      await this._store.challengeConsume(rec.nonce);
      rec.state = "used";
      if (presentedSessionToken) await this.revokeByToken(presentedSessionToken); // rotation: replace THIS browser's old session
      return this._createSession(rec, nowMs);
    } catch (e) {
      if (rec.state !== "used") await this._store.challengeRelease(rec.nonce);
      throw e;
    }
  }

  async _createSession(identityRec, nowMs) {
    if ((await this._store.sessionCount()) >= MAX_TOTAL_SESSIONS) {
      await this._store.sessionSweep(nowMs, {
        inactivityMs: this._config.authSessionInactivityMs,
        absoluteMs: this._config.authSessionAbsoluteMs
      });
      if ((await this._store.sessionCount()) >= MAX_TOTAL_SESSIONS) {
        throw authError(503, AuthErrorCodes.AUTH_CHALLENGE_CAPACITY, "session capacity reached — try again shortly");
      }
    }
    const token = this._randomBytes(32).toString("hex"); // 256-bit opaque bearer
    const session = {
      tokenHash: sha256Hex(token), // only the hash is stored
      walletAddress: identityRec.walletAddress,
      xOnlyPubkey: identityRec.xOnlyPubkey,
      networkId: identityRec.networkId,
      createdAtMs: nowMs,
      lastSeenMs: nowMs,
      revoked: false
    };
    if (!(await this._store.sessionInsert(session))) {
      throw authError(500, AuthErrorCodes.AUTH_BAD_INPUT, "internal: session token collision");
    }
    return { token, session: this._presentSession(session, nowMs) };
  }

  _presentSession(session, nowMs) {
    return {
      authenticated: true,
      walletAddress: session.walletAddress,
      networkId: session.networkId,
      inactivityExpiresAt: new Date(session.lastSeenMs + this._config.authSessionInactivityMs).toISOString(),
      absoluteExpiresAt: new Date(session.createdAtMs + this._config.authSessionAbsoluteMs).toISOString(),
      now: new Date(nowMs).toISOString()
    };
  }

  /*
   * Cookie -> immutable authenticated principal (the ONE resolution
   * path). Expiry DECISIONS live here, above the store; deletion of an
   * expired record is cleanup, not the decision. Touches lastSeen on
   * success (the inactivity window slides).
   */
  async resolveSession(token, { touch = true } = {}) {
    if (typeof token !== "string" || !TOKEN_HEX.test(token)) {
      throw authError(401, AuthErrorCodes.SESSION_INVALID, "no valid session");
    }
    const nowMs = this._now();
    const session = await this._store.sessionGet(sha256Hex(token));
    if (!session) throw authError(401, AuthErrorCodes.SESSION_INVALID, "no valid session");
    if (session.revoked) throw authError(401, AuthErrorCodes.SESSION_REVOKED, "the session was signed out");
    if (nowMs - session.createdAtMs > this._config.authSessionAbsoluteMs) {
      await this._store.sessionDelete(session.tokenHash);
      throw authError(401, AuthErrorCodes.SESSION_EXPIRED, "the session expired — sign in again");
    }
    if (nowMs - session.lastSeenMs > this._config.authSessionInactivityMs) {
      await this._store.sessionDelete(session.tokenHash);
      throw authError(401, AuthErrorCodes.SESSION_EXPIRED, "the session expired from inactivity — sign in again");
    }
    if (touch) await this._store.sessionTouch(session.tokenHash, nowMs);
    return Object.freeze({
      walletAddress: session.walletAddress,
      xOnlyPubkey: session.xOnlyPubkey,
      networkId: session.networkId,
      sessionIdentity: session.tokenHash.slice(0, 16), // non-secret diagnostic id
      presentation: this._presentSession(session, nowMs)
    });
  }

  /* Logout (revocation by presented token); idempotent. */
  async revokeByToken(token) {
    if (typeof token !== "string" || !TOKEN_HEX.test(token)) return false;
    return this._store.sessionDelete(sha256Hex(token));
  }
}

/* ---- Cookie policy (unchanged from Phase B) ---- */

function sessionCookieName(config) {
  return config.authCookieSecure ? "__Secure-pv_session" : "pv_session";
}

function buildSessionCookie(config, token) {
  const attrs = [
    `${sessionCookieName(config)}=${token}`,
    `Max-Age=${Math.floor(config.authSessionAbsoluteMs / 1000)}`,
    "Path=/api",
    "HttpOnly",
    "SameSite=Strict"
  ];
  if (config.authCookieSecure) attrs.push("Secure");
  return attrs.join("; ");
}

function buildClearCookie(config) {
  const attrs = [`${sessionCookieName(config)}=`, "Max-Age=0", "Path=/api", "HttpOnly", "SameSite=Strict"];
  if (config.authCookieSecure) attrs.push("Secure");
  return attrs.join("; ");
}

function sessionTokenFromCookieHeader(config, cookieHeader) {
  if (typeof cookieHeader !== "string" || cookieHeader.length === 0 || cookieHeader.length > 8192) return null;
  const wanted = sessionCookieName(config);
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (name !== wanted) continue;
    const value = part.slice(eq + 1).trim();
    return TOKEN_HEX.test(value) ? value : null;
  }
  return null;
}

module.exports = {
  HostedAuthService,
  MemoryAuthStore,
  PgAuthStore,
  AuthErrorCodes,
  sessionCookieName,
  buildSessionCookie,
  buildClearCookie,
  sessionTokenFromCookieHeader
};
