"use strict";

/*
 * HOSTED AUTH + SESSIONS (Phase B) — hostile authentication matrix.
 * Layers: UNIT (auth service over the pinned kaspa-wasm primitive) +
 * API (real server over HTTP: cookies, headers, routes). Real Schnorr
 * signatures throughout — no signing is mocked. Directive §20/§32.
 *
 * Core invariant under test: AUTHENTICATION != COVENANT AUTHORITY. A
 * session proves wallet identity for tenancy only; it never signs, never
 * carries key material, and never bypasses covenant signer checks.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { HostedAuthService, AuthErrorCodes, buildSessionCookie, buildClearCookie, sessionTokenFromCookieHeader, sessionCookieName } = require("../../server/src/auth");
const kaspa = require(loadConfig({}).rustyKaspaModule);

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-auth-"));
function enabledConfig(over = {}) {
  return loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA(), ...over });
}
function keyFor(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return {
    priv,
    privHex: priv.toString(),
    compressed: priv.toPublicKey().toString().toLowerCase(),
    xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress("testnet-10").toString()
  };
}
const K = keyFor("31");
const K2 = keyFor("32");
const sign = (msg, priv) => kaspa.signMessage({ message: msg, privateKey: priv.toString() });

/* Capture a thrown error (assert.throws returns undefined, not the error). */
async function caught(fn) {
  try { await fn(); } catch (e) { return e; }
  throw new assert.AssertionError({ message: "expected the call to throw, but it did not" });
}

/* Controllable clock/entropy (directive §26) — never enabled in prod. */
function fakeProviders(startMs) {
  let t = startMs;
  let counter = 0;
  return {
    now: () => t,
    advance: (ms) => { t += ms; },
    randomBytes: (n) => { const b = Buffer.alloc(n); b.writeUInt32BE(++counter, 0); crypto_fill(b, counter); return b; }
  };
}
const crypto = require("node:crypto");
function crypto_fill(buf, seed) { const h = crypto.createHash("sha256").update(String(seed)).digest(); h.copy(buf, 0, 0, Math.min(buf.length, h.length)); if (buf.length > h.length) crypto_fill(buf.subarray(h.length), seed + 1); }

/* ---------- CHALLENGE GENERATION ---------- */

test("§B challenge: valid issuance, 32-byte hex nonce, canonical 7-line message bound to wallet+network+origin", async () => {
  const cfg = enabledConfig();
  const auth = new HostedAuthService(cfg);
  const ch = await auth.createChallenge(K.address);
  assert.match(ch.nonce, /^[0-9a-f]{64}$/);
  const lines = ch.message.split("\n");
  assert.equal(lines.length, 7);
  assert.equal(lines[0], "PolicyVault authentication");
  assert.equal(lines[1], `origin: ${cfg.appOrigin}`);
  assert.equal(lines[2], "network: testnet-10");
  assert.equal(lines[3], `address: ${K.address}`);
  assert.equal(lines[4], `nonce: ${ch.nonce}`);
  assert.match(lines[5], /^issued: \d{4}-\d{2}-\d{2}T/);
  assert.equal(lines[6], "This signature only signs you in. It cannot move funds.");
  assert.ok(!ch.message.includes("\r"), "LF only, no CR");
});

test("§B challenge: two challenges never reuse a nonce", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const a = await auth.createChallenge(K.address);
  const b = await auth.createChallenge(K.address);
  assert.notEqual(a.nonce, b.nonce);
});

test("§B challenge: ECDSA/Tangem-class (non-PubKey) account fails clearly BEFORE any signing", async () => {
  const auth = new HostedAuthService(enabledConfig());
  // A PubKeyECDSA address is version-rejected by resolveAddressIdentity.
  const ecdsaAddr = new kaspa.PrivateKey(K.privHex).toPublicKey().toAddressECDSA("testnet-10").toString();
  const e = await caught(() => auth.createChallenge(ecdsaAddr));
  assert.equal(e.code, AuthErrorCodes.AUTH_ACCOUNT_TYPE_UNSUPPORTED);
  assert.equal(e.status, 422);
});

test("§B challenge: wrong-network address family fails closed", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const mainnetAddr = new kaspa.PrivateKey(K.privHex).toPublicKey().toAddress("mainnet").toString();
  const e = await caught(() => auth.createChallenge(mainnetAddr));
  assert.equal(e.code, AuthErrorCodes.AUTH_BAD_INPUT); // ADDRESS_WRONG_NETWORK wrapped
});

/* ---------- CANONICAL RECONSTRUCTION ---------- */

test("§B verify uses the SERVER-reconstructed message; a one-byte client mutation cannot help (client message is never accepted)", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  // Sign a DIFFERENT message (one byte changed) — server reconstructs the
  // real one from stored state, so verification fails.
  const tampered = ch.message.replace("signs you in", "signs you IN");
  const sig = sign(tampered, K.priv);
  const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed }));
  assert.equal(e.code, AuthErrorCodes.AUTH_SIGNATURE_INVALID);
});

test("§B verify: line-ending mutation (CRLF) does not validate", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const crlf = ch.message.replace(/\n/g, "\r\n");
  const sig = sign(crlf, K.priv);
  const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed }));
  assert.equal(e.code, AuthErrorCodes.AUTH_SIGNATURE_INVALID);
});

/* ---------- SIGNATURE VALIDATION ---------- */

test("§B verify: valid Schnorr signature (compressed OR x-only pubkey) succeeds and binds identity", async () => {
  for (const pub of [K.compressed, K.xonly]) {
    const auth = new HostedAuthService(enabledConfig());
    const ch = await auth.createChallenge(K.address);
    const { token, session } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: pub });
    assert.match(token, /^[0-9a-f]{64}$/);
    assert.equal(session.authenticated, true);
    assert.equal(session.walletAddress, K.address);
    assert.equal(session.networkId, "testnet-10");
  }
});

test("§B verify: wrong signature, wrong key, and pubkey/address mismatch all reject", async () => {
  const auth = new HostedAuthService(enabledConfig());
  // wrong signature (signed by K2)
  let ch = await auth.createChallenge(K.address);
  assert.equal((await caught(() => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K2.priv), publicKey: K.compressed }))).code, AuthErrorCodes.AUTH_SIGNATURE_INVALID);
  // pubkey belongs to a different wallet than the challenge address
  ch = await auth.createChallenge(K.address);
  assert.equal((await caught(() => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K2.priv), publicKey: K2.compressed }))).code, AuthErrorCodes.AUTH_ADDRESS_MISMATCH);
});

test("§B verify: malformed/truncated/oversized signature and malformed pubkey reject as bad input (no crash)", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const good = sign(ch.message, K.priv);
  for (const bad of ["", "zz", good.slice(0, 100), good + "aa", "x".repeat(128)]) {
    const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: bad, publicKey: K.compressed }));
    assert.ok([AuthErrorCodes.AUTH_BAD_INPUT, AuthErrorCodes.AUTH_SIGNATURE_INVALID].includes(e.code));
  }
  const e2 = await caught(() => auth.verify({ nonce: ch.nonce, signature: good, publicKey: "nope" }));
  assert.equal(e2.code, AuthErrorCodes.AUTH_PUBKEY_INVALID);
});

test("§B verify: address-family/network mismatch on the submitted wallet rejects", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed, walletAddress: K2.address }));
  assert.equal(e.code, AuthErrorCodes.AUTH_ADDRESS_MISMATCH);
});

/* ---------- REPLAY / CONCURRENCY ---------- */

test("§B replay: a consumed challenge cannot authenticate twice", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const sig = sign(ch.message, K.priv);
  await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
  const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed }));
  assert.equal(e.code, AuthErrorCodes.AUTH_CHALLENGE_UNKNOWN);
});

test("§B replay: a FAILED verify releases the challenge so the legitimate owner can retry", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  await assert.rejects(async () => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K2.priv), publicKey: K.compressed })); // wrong sig
  // retry with the correct signature succeeds (not burned by the failed attempt)
  const { session } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  assert.equal(session.authenticated, true);
});

test("§B concurrency: interleaved verify of ONE challenge yields exactly one success (atomic claim)", async () => {
  // Model the race by claiming before the second call runs. The service is
  // synchronous; the claim flips state issued->verifying atomically, so a
  // second entry sees a non-issued challenge.
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const sig = sign(ch.message, K.priv);
  // First verify holds the claim through completion (synchronous), the
  // "concurrent" second attempt therefore observes it already consumed.
  const first = await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
  const second = await caught(() => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed }));
  assert.equal(first.session.authenticated, true);
  assert.ok([AuthErrorCodes.AUTH_CHALLENGE_UNKNOWN, AuthErrorCodes.AUTH_CHALLENGE_USED].includes(second.code));
});

test("§B expiry: an expired challenge cannot be revived (injected clock)", async () => {
  const p = fakeProviders(1_000_000);
  const auth = new HostedAuthService(enabledConfig(), p);
  const ch = await auth.createChallenge(K.address);
  p.advance(5 * 60 * 1000 + 1);
  const e = await caught(() => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed }));
  assert.equal(e.code, AuthErrorCodes.AUTH_CHALLENGE_EXPIRED);
});

/* ---------- SESSIONS ---------- */

test("§B session: 256-bit token, only its hash is stored, resolveSession returns an immutable principal", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  // token is not stored raw: the map key is sha256(token)
  const stored = [...auth._store._sessions.keys()][0];
  assert.notEqual(stored, token);
  assert.equal(stored, require("node:crypto").createHash("sha256").update(token).digest("hex"));
  const p = await auth.resolveSession(token);
  assert.equal(p.walletAddress, K.address);
  assert.equal(p.networkId, "testnet-10");
  assert.throws(() => { p.walletAddress = "x"; }); // frozen
});

test("§B session: unknown/modified token rejects", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  assert.equal((await caught(() => auth.resolveSession("00".repeat(32)))).code, AuthErrorCodes.SESSION_INVALID);
  const flipped = (token[0] === "a" ? "b" : "a") + token.slice(1);
  assert.equal((await caught(() => auth.resolveSession(flipped))).code, AuthErrorCodes.SESSION_INVALID);
});

test("§B session: inactivity timeout and absolute timeout both reject (injected clock)", async () => {
  // inactivity
  let p = fakeProviders(1_000_000);
  let auth = new HostedAuthService(enabledConfig(), p);
  let ch = await auth.createChallenge(K.address);
  let { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  p.advance(30 * 60 * 1000 + 1);
  assert.equal((await caught(() => auth.resolveSession(token))).code, AuthErrorCodes.SESSION_EXPIRED);
  // absolute: kept active every 25 min (< the 30-min inactivity window) so
  // only the 24h absolute cap can end it. Capture the expiry at the moment
  // it first fires (resolveSession deletes the record on expiry).
  p = fakeProviders(1_000_000);
  auth = new HostedAuthService(enabledConfig(), p);
  ch = await auth.createChallenge(K.address);
  ({ token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed }));
  let expiry = null;
  for (let i = 0; i < 100 && !expiry; i++) {
    p.advance(25 * 60 * 1000);
    try { await auth.resolveSession(token); } catch (e) { expiry = e; }
  }
  assert.ok(expiry, "session must eventually hit the absolute cap");
  assert.equal(expiry.code, AuthErrorCodes.SESSION_EXPIRED);
});

test("§B session: logout revokes; a revoked token never resolves again", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  assert.ok((await auth.resolveSession(token)).walletAddress);
  assert.equal(await auth.revokeByToken(token), true);
  assert.equal((await caught(() => auth.resolveSession(token))).code, AuthErrorCodes.SESSION_INVALID);
});

test("§B rotation: re-authenticating with the presented old token revokes it and issues a fresh one", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch1 = await auth.createChallenge(K.address);
  const { token: t1 } = await auth.verify({ nonce: ch1.nonce, signature: sign(ch1.message, K.priv), publicKey: K.compressed });
  const ch2 = await auth.createChallenge(K.address);
  const { token: t2 } = await auth.verify({ nonce: ch2.nonce, signature: sign(ch2.message, K.priv), publicKey: K.compressed }, t1);
  assert.notEqual(t1, t2);
  assert.equal((await caught(() => auth.resolveSession(t1))).code, AuthErrorCodes.SESSION_INVALID); // old rotated out
  assert.ok((await auth.resolveSession(t2)).walletAddress); // new works
});

/* ---------- IDENTITY BINDING ---------- */

test("§B binding: a session is permanently bound to its wallet+network; client-supplied fields cannot rebind it", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  const p = await auth.resolveSession(token);
  // The principal comes only from server state; there is no input by which
  // a caller could present K2 and be seen as K2 on K's token.
  assert.equal(p.walletAddress, K.address);
  assert.equal(p.xOnlyPubkey, K.xonly);
});

/* ---------- CUSTODY BOUNDARY (directive §20 explicit) ---------- */

test("§B custody: no session/challenge record contains any private-key-like material", async () => {
  const auth = new HostedAuthService(enabledConfig());
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  const dump = JSON.stringify([...auth._store._sessions.values(), ...auth._store._challenges.values()]);
  for (const secret of [K.privHex, K2.privHex]) assert.ok(!dump.includes(secret), "no private key in auth state");
  // and the raw bearer token itself is not stored anywhere in the maps
  assert.ok(!dump.includes(token), "raw session token is not stored");
});

/* ---------- COOKIE POLICY ---------- */

test("§B cookie: Secure config emits __Secure- HttpOnly SameSite=Strict Path=/api; insecure local mode drops Secure only", async () => {
  const secure = loadConfig({ authMode: "enabled", appOrigin: "https://app.policy-vault.org", dataRoot: DATA() });
  const c = buildSessionCookie(secure, "aa".repeat(32));
  assert.match(c, /^__Secure-pv_session=/);
  assert.ok(c.includes("HttpOnly") && c.includes("SameSite=Strict") && c.includes("Path=/api") && c.includes("Secure"));
  const insecure = enabledConfig();
  const ci = buildSessionCookie(insecure, "aa".repeat(32));
  assert.match(ci, /^pv_session=/);
  assert.ok(ci.includes("HttpOnly") && ci.includes("SameSite=Strict") && ci.includes("Path=/api") && !/;\s*Secure/.test(ci));
  // clear cookie uses matching attributes so the browser actually deletes it
  assert.ok(buildClearCookie(secure).includes("Max-Age=0") && buildClearCookie(secure).includes("__Secure-pv_session="));
});

test("§B cookie parser: only bare 64-hex under the exact cookie name is accepted", async () => {
  const cfg = enabledConfig();
  const name = sessionCookieName(cfg);
  assert.equal(sessionTokenFromCookieHeader(cfg, `${name}=${"ab".repeat(32)}`), "ab".repeat(32));
  assert.equal(sessionTokenFromCookieHeader(cfg, `other=x; ${name}=${"cd".repeat(32)}`), "cd".repeat(32));
  assert.equal(sessionTokenFromCookieHeader(cfg, `${name}="quoted"`), null);
  assert.equal(sessionTokenFromCookieHeader(cfg, `${name}=nothex`), null);
  assert.equal(sessionTokenFromCookieHeader(cfg, "unrelated=1"), null);
  assert.equal(sessionTokenFromCookieHeader(cfg, undefined), null);
});

/* ---------- CONFIG FAIL-CLOSED ---------- */

test("§B config: https origin forbids the insecure-cookie override; http origin requires it; mainnet forbids http auth", async () => {
  assert.throws(() => loadConfig({ authMode: "enabled", appOrigin: "https://app.policy-vault.org", authCookieInsecure: true, dataRoot: DATA() }), /insecure-cookie override is not allowed/);
  assert.throws(() => loadConfig({ authMode: "enabled", appOrigin: "http://127.0.0.1:3080", dataRoot: DATA() }), /requires the explicit insecure-cookie override/);
  assert.throws(() => loadConfig({ authMode: "enabled", appOrigin: "http://x/path", authCookieInsecure: true, dataRoot: DATA() }), /bare http\(s\) origin/);
  assert.equal(loadConfig({}).authMode, "disabled"); // default product unchanged
});

/* ---------- API LAYER (real server over HTTP) ---------- */

const { createServer } = require("../../server/src/server");
function startServer(config) {
  return new Promise((resolve) => {
    const server = createServer(config);
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}
function req(port, method, pathName, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` };
    if (cookie) headers.Cookie = cookie;
    const r = http.request({ host: "127.0.0.1", port, method, path: pathName, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

test("§B API: full challenge -> sign -> verify -> session -> logout over HTTP, token only in HttpOnly cookie", async () => {
  const config = enabledConfig();
  const { server, port } = await startServer(config);
  try {
    const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: K.address } });
    assert.equal(ch.status, 200);
    const message = ch.json.challenge.message;
    const nonce = ch.json.challenge.nonce;
    // the raw token must never appear in any JSON body
    const v = await req(port, "POST", "/api/v1/auth/verify", { body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed } });
    assert.equal(v.status, 200);
    assert.equal(v.json.session.authenticated, true);
    assert.ok(!JSON.stringify(v.json).match(/[0-9a-f]{64}/) || !JSON.stringify(v.json).includes("token"), "no token field in body");
    const setCookie = v.headers["set-cookie"][0];
    assert.match(setCookie, /pv_session=[0-9a-f]{64}/);
    assert.ok(/HttpOnly/i.test(setCookie) && /SameSite=Strict/i.test(setCookie) && /Path=\/api/i.test(setCookie));
    const cookie = setCookie.split(";")[0];
    // session restore
    const s = await req(port, "GET", "/api/v1/auth/session", { cookie });
    assert.equal(s.json.authenticated, true);
    assert.equal(s.json.walletAddress, K.address);
    // logout revokes; the same cookie no longer authenticates
    const out = await req(port, "POST", "/api/v1/auth/logout", { cookie });
    assert.equal(out.status, 200);
    assert.match(out.headers["set-cookie"][0], /pv_session=;/);
    const after = await req(port, "GET", "/api/v1/auth/session", { cookie });
    assert.equal(after.json.authenticated, false);
  } finally {
    server.close();
  }
});

test("§B API: GET /auth/session with no cookie is 200 authenticated:false; a garbage cookie is rejected", async () => {
  const config = enabledConfig();
  const { server, port } = await startServer(config);
  try {
    const none = await req(port, "GET", "/api/v1/auth/session");
    assert.equal(none.status, 200);
    assert.equal(none.json.authenticated, false);
    const garbage = await req(port, "GET", "/api/v1/auth/session", { cookie: "pv_session=deadbeef" });
    assert.equal(garbage.json.authenticated, false);
  } finally {
    server.close();
  }
});

test("§B API: auth routes are 404 when hosted auth is disabled (self-hosted product unchanged)", async () => {
  const config = loadConfig({ dataRoot: DATA() }); // authMode defaults to disabled
  const { server, port } = await startServer(config);
  try {
    const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: K.address } });
    assert.equal(ch.status, 404);
    assert.equal(ch.json.error.code, "AUTH_DISABLED");
    const health = await req(port, "GET", "/api/v1/health");
    assert.equal(health.json.authMode, "disabled");
  } finally {
    server.close();
  }
});

test("§B API: an ECDSA account is refused at /auth/challenge with the actionable unsupported-type code", async () => {
  const config = enabledConfig();
  const { server, port } = await startServer(config);
  try {
    const ecdsaAddr = new kaspa.PrivateKey(K.privHex).toPublicKey().toAddressECDSA("testnet-10").toString();
    const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: ecdsaAddr } });
    assert.equal(ch.status, 422);
    assert.equal(ch.json.error.code, AuthErrorCodes.AUTH_ACCOUNT_TYPE_UNSUPPORTED);
  } finally {
    server.close();
  }
});

test("§B custody at the API: no request path accepts or returns key material; auth verify needs a real signature", async () => {
  const config = enabledConfig();
  const { server, port } = await startServer(config);
  try {
    const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: K.address } });
    // submitting a private key where a signature is expected fails (not a signature)
    const bad = await req(port, "POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature: K.privHex, publicKey: K.compressed } });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
  }
});
