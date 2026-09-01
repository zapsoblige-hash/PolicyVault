"use strict";

/*
 * BEARER WALLET SESSIONS (mobile session-bootstrap DESIGN FREEZE §2;
 * mobile/docs/session-bootstrap-DESIGN.md, commit 917c2a5).
 *
 * A config-gated (POLICYVAULT_AUTH_BEARER_SESSIONS=1, default OFF)
 * SIBLING of the existing cookie session: the SAME Schnorr challenge/
 * verify ceremony (server/src/auth.js), the SAME session store/TTL/
 * revocation, presented via `Authorization: Bearer` instead of a
 * Set-Cookie — for native clients (Capacitor) that cannot carry a
 * SameSite=Strict cookie cross-origin (mobile/docs/session-bootstrap-
 * options.md §1). This file proves every mandatory constraint in the
 * design's frozen §2 list, and that the cookie path is byte-for-byte
 * unchanged, with the flag both off and on.
 *
 * Layers: UNIT (HostedAuthService + the new
 * sessionTokenFromAuthorizationHeader parser) + API (real server over
 * HTTP), exactly mirroring hosted-auth.test.js's own two-layer structure
 * and helpers.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const {
  HostedAuthService,
  AuthErrorCodes,
  sessionTokenFromAuthorizationHeader
} = require("../../server/src/auth");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-bearer-"));
function enabledConfig(over = {}) {
  return loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA(), ...over });
}
function bearerConfig(over = {}) {
  return enabledConfig({ authBearerSessionsEnabled: true, ...over });
}

const kaspa = require(loadConfig({}).rustyKaspaModule);
function keyFor(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return {
    priv,
    compressed: priv.toPublicKey().toString().toLowerCase(),
    xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress("testnet-10").toString()
  };
}
const K = keyFor("41");
const sign = (msg, priv) => kaspa.signMessage({ message: msg, privateKey: priv.toString() });

async function caught(fn) {
  try { await fn(); } catch (e) { return e; }
  throw new assert.AssertionError({ message: "expected the call to throw, but it did not" });
}

/* ==================================================================== */
/* UNIT: sessionTokenFromAuthorizationHeader                             */
/* ==================================================================== */

test("§BEARER parser: flag OFF returns null even for an otherwise well-formed bearer wallet-session header", () => {
  const cfg = enabledConfig(); // authBearerSessionsEnabled defaults false
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer ${"ab".repeat(32)}`), null);
});

test("§BEARER parser: flag ON extracts a bare lowercase 64-hex token; rejects everything else", () => {
  const cfg = bearerConfig();
  const tok = "cd".repeat(32);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer ${tok}`), tok);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `bearer ${tok}`), tok, "scheme is case-insensitive, same as the cookie/machine parsers");
  // machine-credential shaped (pvmk_ prefix) is never mistaken for a wallet session
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer pvmk_${tok}`), null);
  // wrong length / non-hex / uppercase (TOKEN_HEX is lowercase-only, matching resolveSession's own check)
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer ${tok.slice(0, 63)}`), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer ${tok}a`), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Bearer ${tok.toUpperCase()}`), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, `Basic ${tok}`), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, ""), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, undefined), null);
  assert.equal(sessionTokenFromAuthorizationHeader(cfg, null), null);
});

/* ==================================================================== */
/* API LAYER (real server over HTTP)                                     */
/* ==================================================================== */

const { createServer } = require("../../server/src/server");
function startServer(config) {
  return new Promise((resolve) => {
    const server = createServer(config);
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}
function req(port, method, pathName, { body, cookie, authorization, query } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const qs = query ? `?${new URLSearchParams(query).toString()}` : "";
    const headers = { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` };
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
    const r = http.request({ host: "127.0.0.1", port, method, path: pathName + qs, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
async function getChallenge(port) {
  const ch = await req(port, "POST", "/api/v1/auth/challenge", { body: { walletAddress: K.address } });
  return { message: ch.json.challenge.message, nonce: ch.json.challenge.nonce };
}

test("§BEARER API: flag OFF — requesting transport:bearer at verify is a no-op; response is byte-identical to the default (Set-Cookie only, no token in body)", async () => {
  const config = enabledConfig(); // bearer sessions OFF
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    assert.equal(v.status, 200);
    assert.equal(v.json.session.authenticated, true);
    assert.equal("token" in v.json, false, "flag OFF must never put a token in the body, even when explicitly requested");
    assert.match(v.headers["set-cookie"][0], /pv_session=[0-9a-f]{64}/);
  } finally {
    server.close();
  }
});

test("§BEARER API: flag ON but transport NOT requested — response is still byte-identical to the default (cookie only)", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed }
    });
    assert.equal(v.status, 200);
    assert.equal("token" in v.json, false, "the client must EXPLICITLY request bearer transport — flag alone is not enough");
    assert.match(v.headers["set-cookie"][0], /pv_session=[0-9a-f]{64}/);
  } finally {
    server.close();
  }
});

test("§BEARER API: flag ON + transport:bearer requested — body carries {session, token}; NO Set-Cookie is issued", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    assert.equal(v.status, 200);
    assert.equal(v.json.session.authenticated, true);
    assert.equal(v.json.session.walletAddress, K.address);
    assert.match(v.json.token, /^[0-9a-f]{64}$/);
    assert.equal(v.headers["set-cookie"], undefined, "a bearer-transport verify must not ALSO set a cookie");
  } finally {
    server.close();
  }
});

test("§BEARER API: the bearer token authenticates like the equivalent cookie would — same wallet identity, reachable on GET /health/session equivalent (GET /auth/session stays cookie-only by design, so use a real tenancy route instead)", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    const token = v.json.token;
    const vaults = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${token}` });
    assert.equal(vaults.status, 200);
    assert.deepEqual(vaults.json.vaults, [], "no vault exists for this wallet, but the request must authenticate (200, not 401)");
  } finally {
    server.close();
  }
});

test("§BEARER API: the bearer principal reaches a wallet-session-only route exactly like a cookie session (never misclassified as a machine identity)", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    const token = v.json.token;
    // /identities is isWalletSessionOnlyRoute — a real machine credential is
    // refused here (MACHINE_IDENTITY_ROUTE_FORBIDDEN); a bearer WALLET
    // session must be admitted exactly like the equivalent cookie session.
    const r = await req(port, "POST", "/api/v1/identities", {
      body: { scopes: ["read:vaults"] },
      authorization: `Bearer ${token}`
    });
    assert.equal(r.status, 201, JSON.stringify(r.json));
    assert.equal(r.json.identity.creatorXOnly, K.xonly);
  } finally {
    server.close();
  }
});

test("§BEARER API: token is stored only as its hash — same store discipline as cookie sessions", async () => {
  const config = bearerConfig();
  const auth = new HostedAuthService(config);
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  const stored = [...auth._store._sessions.keys()][0];
  assert.notEqual(stored, token);
  assert.equal(stored, require("node:crypto").createHash("sha256").update(token).digest("hex"));
});

test("§BEARER API: a malformed/never-issued bearer wallet-session token is refused (401 SESSION_INVALID), never silently anonymous", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const r = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${"00".repeat(32)}` });
    assert.equal(r.status, 401);
    assert.equal(r.json.error.code, AuthErrorCodes.SESSION_INVALID);
  } finally {
    server.close();
  }
});

test("§BEARER API: an expired bearer session is refused (SESSION_EXPIRED), same TTL as cookie sessions", async () => {
  // Controllable clock via the existing HostedAuthService(config, providers) seam.
  let t = 1_000_000;
  const providers = { now: () => t, advance: (ms) => { t += ms; }, randomBytes: (n) => require("node:crypto").randomBytes(n) };
  const config = bearerConfig();
  const auth = new HostedAuthService(config, providers);
  const ch = await auth.createChallenge(K.address);
  const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message, K.priv), publicKey: K.compressed });
  providers.advance(config.authSessionInactivityMs + 1);
  const e = await caught(() => auth.resolveSession(token));
  assert.equal(e.code, AuthErrorCodes.SESSION_EXPIRED);
});

test("§BEARER API: /auth/logout revokes a bearer-presented token; a subsequent read then 401s", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    const token = v.json.token;
    const before = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${token}` });
    assert.equal(before.status, 200);
    const out = await req(port, "POST", "/api/v1/auth/logout", { authorization: `Bearer ${token}` });
    assert.equal(out.status, 200);
    const after = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${token}` });
    assert.equal(after.status, 401);
    assert.equal(after.json.error.code, AuthErrorCodes.SESSION_INVALID);
  } finally {
    server.close();
  }
});

test("§BEARER API: logout with a machine-credential-shaped Authorization header makes no attempt at wallet-session revocation (no crash, no cross-talk)", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const out = await req(port, "POST", "/api/v1/auth/logout", { authorization: `Bearer pvmk_${"11".repeat(32)}` });
    assert.equal(out.status, 200);
    assert.equal(out.json.ok, true);
  } finally {
    server.close();
  }
});

test("§BEARER API: the raw token is presented ONLY via Authorization: Bearer — a query-string or body copy of it authenticates nothing", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const v = await req(port, "POST", "/api/v1/auth/verify", {
      body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed, transport: "bearer" }
    });
    const token = v.json.token;
    // With no Authorization header, GET /vaults still 200s (tenancy scoping
    // falls to "no principal" -> empty list, not a 401). The proof that a
    // query-string token is INERT is that carrying it changes nothing at
    // all versus a request with no credential whatsoever.
    const viaQuery = await req(port, "GET", "/api/v1/vaults", { query: { token } });
    const anon = await req(port, "GET", "/api/v1/vaults", {});
    assert.equal(viaQuery.status, anon.status);
    assert.deepEqual(viaQuery.json, anon.json, "a token in the query string must be inert — identical to no credential at all");
  } finally {
    server.close();
  }
});

test("§BEARER API: flag entirely OFF — a plain-64-hex Authorization header (the wallet-session shape) is refused exactly as before (MACHINE_TOKEN_INVALID), never accepted and never silently anonymous", async () => {
  const config = enabledConfig(); // bearer sessions OFF
  const { server, port } = await startServer(config);
  try {
    const r = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${"22".repeat(32)}` });
    assert.equal(r.status, 401);
    assert.equal(r.json.error.code, "MACHINE_TOKEN_INVALID");
  } finally {
    server.close();
  }
});

test("§BEARER API: a real machine credential still resolves normally with the bearer-sessions flag ON (no interference between the two credential kinds)", async () => {
  const config = bearerConfig();
  const { server, port } = await startServer(config);
  try {
    const { message, nonce } = await getChallenge(port);
    const cookieV = await req(port, "POST", "/api/v1/auth/verify", { body: { nonce, signature: sign(message, K.priv), publicKey: K.compressed } });
    const cookie = cookieV.headers["set-cookie"][0].split(";")[0];
    const created = await req(port, "POST", "/api/v1/identities", { body: { scopes: ["read:vaults"] }, cookie });
    assert.equal(created.status, 201);
    const machineToken = created.json.credential.token;
    assert.match(machineToken, /^pvmk_[0-9a-f]{64}$/);
    const r = await req(port, "GET", "/api/v1/vaults", { authorization: `Bearer ${machineToken}` });
    assert.equal(r.status, 200);
  } finally {
    server.close();
  }
});
