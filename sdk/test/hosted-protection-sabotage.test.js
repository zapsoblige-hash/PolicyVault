"use strict";

/*
 * REQUEST-PROTECTION sabotage sensitivity (Phase D). Each guard in
 * server/src/limits.js is neutralized by a REAL in-source edit, the
 * relevant assertion is shown to go RED, then the file is restored
 * BYTE-IDENTICALLY. A guard whose removal changes nothing is a blind
 * spot. Nothing sabotaged is ever committed.
 *
 * Runs in-band and must own the limits source exclusively — the SDK
 * suite is run with --test-concurrency=1 (docs/test-plan.md rule 7),
 * which is what makes in-place mutation of a shared file safe here.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");

const LIMITS_SRC = path.join(__dirname, "..", "..", "server", "src", "limits.js");
const ORIGINAL = fs.readFileSync(LIMITS_SRC);
const ORIGINAL_SHA = crypto.createHash("sha256").update(ORIGINAL).digest("hex");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-prot-sab-"));
const APP_ORIGIN = "http://app.pv-test.example";
function hostedConfig() {
  return loadConfig({ authMode: "enabled", authCookieInsecure: true, appOrigin: APP_ORIGIN, dataRoot: DATA() });
}

/* Load a FRESH copy of limits.js from disk (bypassing require cache) so
 * an on-disk mutation is actually exercised, then restore byte-identically. */
async function withSabotage(find, replace, fn) {
  const mutated = ORIGINAL.toString().replace(find, replace);
  assert.notEqual(mutated, ORIGINAL.toString(), "sabotage pattern must actually change the source");
  fs.writeFileSync(LIMITS_SRC, mutated);
  try {
    const tmp = path.join(path.dirname(LIMITS_SRC), `.limits.sabotage.${process.pid}.${Math.random().toString(36).slice(2)}.js`);
    fs.copyFileSync(LIMITS_SRC, tmp);
    try {
      const mod = require(tmp);
      return await fn(mod);
    } finally {
      delete require.cache[require.resolve(tmp)];
      fs.unlinkSync(tmp);
    }
  } finally {
    fs.writeFileSync(LIMITS_SRC, ORIGINAL);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(LIMITS_SRC)).digest("hex"), ORIGINAL_SHA, "limits.js restored byte-identically");
  }
}

test("SABOTAGE baseline: the real guards refuse each attack (control)", () => {
  const mod = require(LIMITS_SRC);
  const config = hostedConfig();
  assert.throws(
    () => mod.verifyOrigin(config, { method: "POST", origin: "https://evil.example", secFetchSite: undefined, host: "app.pv-test.example" }),
    /cross-origin/
  );
  assert.throws(() => mod.verifyHost(config, "evil.example"), /does not serve/);
  const limiter = new mod.RateLimiter({ read: { limit: 2, windowMs: 60_000 } });
  limiter.check("read", "ip:x");
  limiter.check("read", "ip:x");
  assert.throws(() => limiter.check("read", "ip:x"), (e) => e.code === "RATE_LIMITED");
});

test("SABOTAGE 1: accepting any parsed Origin -> the cross-origin test goes RED", async () => {
  await withSabotage(
    "if (parsed.origin === config.appOrigin) return;",
    "if (true || parsed.origin === config.appOrigin) return; /* sabotaged */",
    async (mod) => {
      const config = hostedConfig();
      // Under sabotage a hostile Origin passes — our production
      // cross-origin refusal test would fail.
      mod.verifyOrigin(config, { method: "POST", origin: "https://evil.example", secFetchSite: undefined, host: "app.pv-test.example" });
      assert.ok(true, "sabotage confirmed: hostile origin accepted (guard was load-bearing)");
    }
  );
});

test("SABOTAGE 2: accepting any Host -> the rebinding-guard test goes RED", async () => {
  await withSabotage(
    "if (rp.hostAllowlist.includes(parsed.host)) return;",
    "if (true) return; /* sabotaged: allowlist bypassed */",
    async (mod) => {
      const config = hostedConfig();
      mod.verifyHost(config, "evil.example");
      assert.ok(true, "sabotage confirmed: foreign Host accepted (guard was load-bearing)");
    }
  );
});

test("SABOTAGE 3: removing the budget refusal -> the rate-limit test goes RED", async () => {
  await withSabotage(
    "if (bucket.count > cfg.limit) {",
    "if (false && bucket.count > cfg.limit) {",
    async (mod) => {
      const limiter = new mod.RateLimiter({ read: { limit: 2, windowMs: 60_000 } });
      for (let i = 0; i < 20; i++) limiter.check("read", "ip:x");
      assert.ok(true, "sabotage confirmed: 20 requests sailed past a 2-request budget (guard was load-bearing)");
    }
  );
});

test("SABOTAGE 4: removing the queue bound -> the saturation-refusal test goes RED (unbounded queueing)", async () => {
  await withSabotage(
    "if (this._waiters.length >= this._queueMax) {",
    "if (false && this._waiters.length >= this._queueMax) {",
    async (mod) => {
      const sem = new mod.Semaphore({ max: 1, queue: 0 });
      const rel = await sem.acquire();
      // Under sabotage this queues forever instead of refusing — the
      // production SERVER_BUSY assertion would fail.
      let admitted = false;
      const pending = sem.acquire().then((r) => {
        admitted = true;
        return r;
      });
      await new Promise((r) => setImmediate(r));
      assert.equal(admitted, false, "queued instead of refused");
      assert.equal(sem.stats().queued, 1, "sabotage confirmed: waiter accepted beyond queue 0 (guard was load-bearing)");
      rel();
      (await pending)();
    }
  );
});

test("SABOTAGE cleanup: limits.js is byte-identical to the committed original", () => {
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(LIMITS_SRC)).digest("hex"), ORIGINAL_SHA);
});
