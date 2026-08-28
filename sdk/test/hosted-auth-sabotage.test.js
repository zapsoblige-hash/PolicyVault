"use strict";

/*
 * HOSTED AUTH sabotage sensitivity (Phase B, directive §21). Each guard
 * in server/src/auth.js is neutralized by a REAL in-source edit, the
 * relevant assertion is shown to go RED, then the file is restored
 * BYTE-IDENTICALLY. A guard whose removal changes nothing is a blind
 * spot. Nothing sabotaged is ever committed.
 *
 * Runs in-band and must own the auth source exclusively — the SDK suite
 * is run with --test-concurrency=1 (docs/test-plan.md rule 7), which is
 * what makes in-place mutation of a shared file safe here.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");
const kaspa = require(loadConfig({}).rustyKaspaModule);

const AUTH_SRC = path.join(__dirname, "..", "..", "server", "src", "auth.js");
const ORIGINAL = fs.readFileSync(AUTH_SRC);
const ORIGINAL_SHA = crypto.createHash("sha256").update(ORIGINAL).digest("hex");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-auth-sab-"));
function enabledConfig() {
  return loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() });
}
const priv = new kaspa.PrivateKey("31".repeat(32));
const K = {
  priv,
  compressed: priv.toPublicKey().toString().toLowerCase(),
  address: priv.toPublicKey().toAddress("testnet-10").toString()
};
const priv2 = new kaspa.PrivateKey("32".repeat(32));
const K2compressed = priv2.toPublicKey().toString().toLowerCase();
const sign = (msg, p = priv) => kaspa.signMessage({ message: msg, privateKey: p.toString() });

/*
 * Load a FRESH copy of auth.js from disk (bypassing require cache) so an
 * on-disk mutation is actually exercised, then restore byte-identically.
 */
async function withSabotage(find, replace, fn) {
  const mutated = ORIGINAL.toString().replace(find, replace);
  assert.notEqual(mutated, ORIGINAL.toString(), "sabotage pattern must actually change the source");
  fs.writeFileSync(AUTH_SRC, mutated);
  try {
    const tmp = path.join(path.dirname(AUTH_SRC), `.auth.sabotage.${process.pid}.${Math.random().toString(36).slice(2)}.js`);
    fs.copyFileSync(AUTH_SRC, tmp);
    try {
      const mod = require(tmp);
      return await fn(mod);
    } finally {
      delete require.cache[require.resolve(tmp)];
      fs.unlinkSync(tmp);
    }
  } finally {
    fs.writeFileSync(AUTH_SRC, ORIGINAL);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(AUTH_SRC)).digest("hex"), ORIGINAL_SHA, "auth.js restored byte-identically");
  }
}

function newAuth(mod) {
  return new mod.HostedAuthService(enabledConfig());
}

test("SABOTAGE baseline: the real guards make each attack fail (control)", async () => {
  const mod = require(AUTH_SRC);
  const auth = new mod.HostedAuthService(enabledConfig());
  // single-use
  let ch = await auth.createChallenge(K.address);
  const sig = sign(ch.message);
  await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
  await assert.rejects(async () => auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed }));
  // pubkey/address equality
  ch = await auth.createChallenge(K.address);
  await assert.rejects(async () => auth.verify({ nonce: ch.nonce, signature: sign(ch.message, priv2), publicKey: K2compressed }));
});

test("SABOTAGE 1: removing single-use nonce consumption -> the replay test goes RED", async () => {
  // Neutralize the success-path consume by RELEASING the challenge back to
  // reusable (state -> issued, kept in the map) instead of deleting it.
  // This defeats the single-use property in one move; the real guard both
  // deletes and marks used, so the production replay test rejects the
  // second verify. (Single-use is defended in depth: the claim state
  // machine ALSO guards it, so a weaker sabotage would still be caught —
  // this is the sabotage that fully removes single-use.)
  await withSabotage(
    "await this._store.challengeConsume(rec.nonce);\n      rec.state = \"used\";",
    "await this._store.challengeRelease(rec.nonce); /* sabotaged: released, not consumed */",
    async (mod) => {
      const auth = new mod.HostedAuthService(enabledConfig());
      const ch = await auth.createChallenge(K.address);
      const sig = sign(ch.message);
      await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
      // Under sabotage the replay SUCCEEDS -> our production replay test would fail.
      const second = await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
      assert.equal(second.session.authenticated, true, "sabotage confirmed: replay now succeeds (guard was load-bearing)");
    }
  );
});

test("SABOTAGE 2: skipping pubkey<->address equality -> the mismatch test goes RED", async () => {
  // Force the identity check to pass regardless. A signature by the WRONG
  // key over a matching message would then authenticate the wrong wallet.
  await withSabotage(
    "if (xOnly !== rec.xOnlyPubkey) {",
    "if (false && xOnly !== rec.xOnlyPubkey) {",
    async (mod) => {
      const auth = new mod.HostedAuthService(enabledConfig());
      const ch = await auth.createChallenge(K.address);
      // K2 signs K's challenge message; with the equality gate bypassed AND
      // the signature verified against K2's own key, this wrongly succeeds.
      const badSig = sign(ch.message, priv2);
      const res = await auth.verify({ nonce: ch.nonce, signature: badSig, publicKey: K2compressed });
      assert.equal(res.session.walletAddress, K.address, "sabotage confirmed: wrong key authenticated K's address");
    }
  );
});

test("SABOTAGE 3: trusting a client message instead of server reconstruction -> tamper test goes RED", async () => {
  // Make challengeText echo an attacker-adjustable field. Here we sabotage
  // by verifying against a re-derived message that drops the nonce line,
  // so a signature over a nonce-free message would validate.
  await withSabotage(
    "const message = this.challengeText(rec); // server-side reconstruction — the ONLY message verified",
    "const message = this.challengeText(rec).split(\"\\n\").filter((l) => !l.startsWith(\"nonce:\")).join(\"\\n\"); // sabotaged",
    async (mod) => {
      const auth = new mod.HostedAuthService(enabledConfig());
      const ch = await auth.createChallenge(K.address);
      const noNonceMsg = ch.message.split("\n").filter((l) => !l.startsWith("nonce:")).join("\n");
      const sig = sign(noNonceMsg);
      const res = await auth.verify({ nonce: ch.nonce, signature: sig, publicKey: K.compressed });
      assert.equal(res.session.authenticated, true, "sabotage confirmed: a nonce-free signature validated");
    }
  );
});

test("SABOTAGE 4: accepting an expired session -> the absolute-expiry test goes RED", async () => {
  await withSabotage(
    "if (nowMs - session.createdAtMs > this._config.authSessionAbsoluteMs) {",
    "if (false && nowMs - session.createdAtMs > this._config.authSessionAbsoluteMs) {",
    async (mod) => {
      let t = 1_000_000;
      const auth = new mod.HostedAuthService(enabledConfig(), { now: () => t, randomBytes: (n) => crypto.randomBytes(n) });
      const ch = await auth.createChallenge(K.address);
      const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: K.compressed });
      t += 100 * 24 * 60 * 60 * 1000; // 100 days later
      // Inactivity would still catch it; neutralize by touching within window is
      // not possible here, so assert the ABSOLUTE branch specifically is dead:
      // resolveSession still throws (inactivity), but NOT via the absolute cap.
      const err = await (async () => { try { await auth.resolveSession(token); } catch (e) { return e; } })();
      assert.ok(err, "still expired by inactivity");
      // Prove the absolute guard itself was the sabotage target: with a fresh
      // session and lastSeen kept current, the absolute cap no longer fires.
      const ch2 = await auth.createChallenge(K.address);
      const { token: tok2 } = await auth.verify({ nonce: ch2.nonce, signature: sign(ch2.message), publicKey: K.compressed });
      for (let i = 0; i < 200; i++) { t += 20 * 60 * 1000; await auth.resolveSession(tok2); } // > 24h total, kept active
      assert.ok((await auth.resolveSession(tok2)).walletAddress, "sabotage confirmed: absolute cap no longer ends a kept-alive session");
    }
  );
});

test("SABOTAGE 5: skipping logout revocation -> the revoke test goes RED", async () => {
  await withSabotage(
    "return this._store.sessionDelete(sha256Hex(token));",
    "return false; /* sabotaged: no revocation */",
    async (mod) => {
      const auth = new mod.HostedAuthService(enabledConfig());
      const ch = await auth.createChallenge(K.address);
      const { token } = await auth.verify({ nonce: ch.nonce, signature: sign(ch.message), publicKey: K.compressed });
      await auth.revokeByToken(token); // no-op under sabotage
      assert.ok((await auth.resolveSession(token)).walletAddress, "sabotage confirmed: session survived logout");
    }
  );
});

test("SABOTAGE cleanup: auth.js is byte-identical to the committed original", async () => {
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(AUTH_SRC)).digest("hex"), ORIGINAL_SHA);
});
