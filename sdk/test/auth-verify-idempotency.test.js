"use strict";

/*
 * AUTH-VERIFY-IDEMPOTENCY-01 — sign-in responses are never persisted for
 * Idempotency-Key replay. POST /auth/verify returns a live session token (in
 * the bearer body or in Set-Cookie); session records are stored only as token
 * hashes, so the idempotency store must never hold one, and a replay must not
 * return a token after the one-time challenge nonce has been consumed.
 * Layer: API (real server over loopback HTTP, hosted authentication, JSON
 * store in a private data root). A deterministic TEST-ONLY key signs the
 * challenge, as in hosted-auth.test.js; no funds, no network.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const { once } = require("node:events");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const kaspa = require(loadConfig({}).rustyKaspaModule);

function files(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(path.join(dir, e.name)) : [path.join(dir, e.name)]));
}

test("POST /auth/challenge, /auth/verify and /auth/logout under an Idempotency-Key persist nothing; a replay never returns a session token", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pv-auth-idem-"));
  let server;
  try {
    const reserve = net.createServer();
    reserve.listen(0, "127.0.0.1");
    await once(reserve, "listening");
    const port = reserve.address().port;
    await new Promise((r) => reserve.close(r));
    const base = `http://127.0.0.1:${port}`;
    const config = loadConfig({ networkId: "testnet-10", persistenceBackend: "json", dataRoot: dir, authMode: "enabled", authCookieInsecure: true, appOrigin: base, bindAddress: "127.0.0.1", authBearerSessionsEnabled: true });
    server = createServer(config);
    server.listen(port, "127.0.0.1");
    await once(server, "listening");
    const priv = new kaspa.PrivateKey("34".repeat(32));
    const pub = priv.toPublicKey();
    const address = pub.toAddress("testnet-10").toString();
    const post = async (route, body, headers = {}) => {
      const r = await fetch(base + "/api/v1" + route, { method: "POST", headers: { "content-type": "application/json", origin: base, Connection: "close", ...headers }, body: JSON.stringify(body) });
      return { status: r.status, setCookie: r.headers.get("set-cookie") || "", text: await r.text() };
    };
    const platformFiles = () => files(path.join(dir, "platform"));
    for (const transport of ["bearer", "cookie"]) {
      const before = platformFiles().length;
      const ch = await post("/auth/challenge", { walletAddress: address }, { "Idempotency-Key": `challenge-${transport}` });
      assert.equal(ch.status, 200);
      const challenge = JSON.parse(ch.text).challenge;
      const body = { nonce: challenge.nonce, signature: kaspa.signMessage({ message: challenge.message, privateKey: priv.toString() }), publicKey: pub.toString(), ...(transport === "bearer" ? { transport: "bearer" } : {}) };
      const key = `verify-${transport}`;
      const first = await post("/auth/verify", body, { "Idempotency-Key": key });
      assert.equal(first.status, 200, transport);
      const token = transport === "bearer" ? JSON.parse(first.text).token : (first.setCookie.match(/pv_session=([0-9a-f]{64})/) || [])[1];
      assert.match(token, /^[0-9a-f]{64}$/, transport);
      assert.equal(JSON.parse(first.text).idempotency, undefined, "a sign-in response is not an idempotent replay record");
      for (const f of files(dir)) assert.equal(fs.readFileSync(f, "utf8").includes(token), false, `plaintext session token at rest in ${path.relative(dir, f)}`);
      assert.equal(platformFiles().length, before, "no idempotency record for the challenge or the sign-in");
      const replay = await post("/auth/verify", body, { "Idempotency-Key": key });
      assert.equal(replay.status, 401, transport);
      assert.equal(JSON.parse(replay.text).error.code, "AUTH_CHALLENGE_UNKNOWN");
      assert.equal(replay.text.includes(token) || replay.setCookie.includes(token), false);
      const cookie = transport === "cookie" ? { cookie: `pv_session=${token}` } : { authorization: `Bearer ${token}` };
      const logout = await post("/auth/logout", {}, { "Idempotency-Key": `logout-${transport}`, ...cookie });
      assert.equal(logout.status, 200);
      assert.equal(platformFiles().length, before, "no idempotency record for logout");
    }
  } finally {
    if (server?.listening) { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
