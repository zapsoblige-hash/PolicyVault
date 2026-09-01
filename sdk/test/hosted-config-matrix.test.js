"use strict";

/*
 * HOSTED CONFIGURATION MATRIX — fail-closed on dangerous combinations
 * (Phase C, directive §44/§5/§57). Pure config-layer UNIT tests (no DB
 * needed). Proves the backend/auth/network/cookie safety interlocks.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-cfg-"));

test("§C default is self-hosted: json backend, auth disabled, tenancy off", () => {
  const c = loadConfig({ dataRoot: DATA() });
  assert.equal(c.persistenceBackend, "json");
  assert.equal(c.authMode, "disabled");
  assert.equal(c.tenancyEnforced, false);
  assert.equal(c.pg, null);
});

test("§C unknown persistence backend fails closed", () => {
  assert.throws(() => loadConfig({ persistenceBackend: "mongodb", dataRoot: DATA() }), /unknown persistenceBackend/);
});

test("§C postgres backend REQUIRES user + database", () => {
  assert.throws(() => loadConfig({ persistenceBackend: "postgres", authMode: "enabled", appOrigin: "https://app.policy-vault.org", dataRoot: DATA() }), /requires POLICYVAULT_PG_USER/);
});

test("§C DANGEROUS COMBO: postgres (hosted multi-user) + auth DISABLED is refused unless the explicit dev-open override is set", () => {
  // The dangerous default: multi-user PG with no login = all tenant data
  // visible. Refused.
  assert.throws(
    () => loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, dataRoot: DATA() }),
    /requires hosted authentication/
  );
  // The explicit single-user dev override is allowed on testnet.
  const dev = loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, hostedDevOpen: true, dataRoot: DATA() });
  assert.equal(dev.persistenceBackend, "postgres");
  assert.equal(dev.tenancyEnforced, false); // no auth -> tenancy not enforced (dev-open, single user)
});

test("§C postgres + auth enabled -> tenancy enforced (hosted-safe)", () => {
  const c = loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() });
  assert.equal(c.tenancyEnforced, true);
  assert.equal(c.pg.ssl, false); // explicit no-TLS local override
});

test("§C postgres TLS is the default; only the explicit override disables it", () => {
  const secure = loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", authMode: "enabled", appOrigin: "https://app.policy-vault.org", dataRoot: DATA() });
  assert.equal(secure.pg.ssl, true);
});

test("§C MAINNET: the dev-open override and no-TLS override are BOTH refused", () => {
  const base = { persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", networkId: "mainnet", allowMainnet: true, appOrigin: "https://app.policy-vault.org", authMode: "enabled", rpcUrl: "ws://127.0.0.1:18110" };
  const withEnv = (extra, fn) => {
    const prev = process.env.POLICYVAULT_ALLOW_MAINNET;
    process.env.POLICYVAULT_ALLOW_MAINNET = "true";
    try { return fn(); } finally { if (prev === undefined) delete process.env.POLICYVAULT_ALLOW_MAINNET; else process.env.POLICYVAULT_ALLOW_MAINNET = prev; }
  };
  withEnv({}, () => {
    assert.throws(() => loadConfig({ ...base, pgNoTls: true, dataRoot: DATA() }), /POLICYVAULT_PG_NO_TLS must not be set on mainnet/);
    // dev-open on mainnet: auth-disabled mainnet PG. Refused for auth first, but with dev-open it must refuse for mainnet.
    assert.throws(() => loadConfig({ ...base, authMode: "disabled", hostedDevOpen: true, dataRoot: DATA() }), /HOSTED_DEV_OPEN must never be set on mainnet/);
  });
});

test("§C pool size is bounded and validated", () => {
  assert.throws(() => loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, pgPoolMax: 0, dataRoot: DATA() }), /POOL_MAX/);
  assert.throws(() => loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, pgPoolMax: 500, dataRoot: DATA() }), /POOL_MAX/);
  const ok = loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, pgPoolMax: 5, dataRoot: DATA() });
  assert.equal(ok.pg.poolMax, 5);
});

test("§C getStore for a postgres config that was never opened fails closed (no lazy dial, no JSON fallback)", () => {
  const { getStore } = require("../src/store");
  const c = loadConfig({ persistenceBackend: "postgres", pgUser: "u", pgDatabase: "d", pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() });
  assert.throws(() => getStore(c), /was not opened at startup|no silent JSON fallback/);
});

/* ---------- BEARER WALLET SESSIONS (mobile session-bootstrap DESIGN §2) ---------- */

test("§C authBearerSessionsEnabled: OFF by default, OFF for any env value but the exact string \"1\", ON only via that exact env value or an explicit true override", () => {
  // Default: neither override nor env set.
  assert.equal(loadConfig({ dataRoot: DATA() }).authBearerSessionsEnabled, false);
  assert.equal(loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() }).authBearerSessionsEnabled, false);

  // Fail-closed on every near-miss env value — only the exact string "1" enables it.
  const prev = process.env.POLICYVAULT_AUTH_BEARER_SESSIONS;
  try {
    for (const v of ["true", "TRUE", "yes", "on", "0", "01", " 1", "1 ", ""]) {
      process.env.POLICYVAULT_AUTH_BEARER_SESSIONS = v;
      assert.equal(
        loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() }).authBearerSessionsEnabled,
        false,
        `env value ${JSON.stringify(v)} must NOT enable bearer sessions`
      );
    }
    process.env.POLICYVAULT_AUTH_BEARER_SESSIONS = "1";
    assert.equal(loadConfig({ authMode: "enabled", authCookieInsecure: true, dataRoot: DATA() }).authBearerSessionsEnabled, true);
  } finally {
    if (prev === undefined) delete process.env.POLICYVAULT_AUTH_BEARER_SESSIONS;
    else process.env.POLICYVAULT_AUTH_BEARER_SESSIONS = prev;
  }

  // Explicit override, independent of env.
  assert.equal(loadConfig({ authMode: "enabled", authCookieInsecure: true, authBearerSessionsEnabled: true, dataRoot: DATA() }).authBearerSessionsEnabled, true);
});
