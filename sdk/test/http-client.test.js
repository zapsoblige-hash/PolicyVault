"use strict";

/*
 * POLICYVAULT API CLIENT — driven against a REAL spawned PolicyVault HTTP
 * server (FULLSCALE_COMPLETION_ADDENDUM.md surface 9, consuming surface 8).
 *
 * Layer: INTEGRATION (real server/src/server.js over a real socket on an
 * ephemeral port, real machine-identity minting, real scope enforcement,
 * real Idempotency-Key CAS, JSON persistence backend). Same idiom as
 * sdk/test/postlaunch-origin-policy-server.test.js — several of the
 * properties here (the origin wall's programmatic-client exemption, the
 * Idempotency-Key header path, real HTTP status/headers) are simply not
 * observable through direct handle() calls.
 *
 * WHY A REAL SERVER AND NOT A MOCK. A mocked client proves only that the
 * client agrees with the test author's idea of the API. The failure this
 * project has actually been bitten by is the opposite one: code that passed
 * every in-process test and disagreed with the real downstream validator
 * (docs/v02-production-boundary-audit.md). A client is a boundary component;
 * it gets tested against the boundary.
 *
 * ENVIRONMENT PREREQUISITE. The dry-run tests drive the REAL v0.4 builder,
 * which shells out to the Rust helpers `tests/vm/target/debug/pv_call_encoder`
 * and `pv_tx_probe`. `tests/vm/target/` is gitignored, so a freshly created
 * git worktree does not have them: build with
 * `cd tests/vm && cargo build --bin pv_call_encoder --bin pv_tx_probe`
 * (or copy them from a tree that already has them). Without them the
 * simulate route answers a real, honest `SIMULATION_FAILED` refusal rather
 * than silently degrading — which is correct behavior, and would fail these
 * tests loudly rather than passing a weakened assertion.
 *
 * Properties proven here:
 *   - health + capabilities work with NO credential (public routes);
 *   - a dry run reaches the real simulate pipeline and answers ok:true;
 *   - an idempotent create REPLAYS rather than creating a second row;
 *   - a differing body under the same key is a deterministic 409;
 *   - the server's error envelope arrives VERBATIM on a typed error;
 *   - a deny-by-default scope refusal and the structural
 *     wallet-session-only refusal both surface as typed errors;
 *   - the pinned schemaVersion fails CLOSED against a mismatch;
 *   - integer sompi stay STRINGS end to end;
 *   - THE TOKEN APPEARS NOWHERE: not in the client's serialization, not in
 *     any error's message/stack/body, and not in console output (the client
 *     writes to the console at all);
 *   - no automatic retries: exactly one transport attempt per call.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const util = require("node:util");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const { PolicyVaultClient, PolicyVaultApiError, PolicyVaultNetworkError, createClient, randomIdempotencyKey } = require("../src/http-client");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-httpclient-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = KEY(0x31);
const AGENT = KEY(0x32);
const RECIP = KEY(0x33);
const VAULT_ID = "8a".repeat(32);

let server;
let port;
let baseUrl;
const state = {};

/* A well-formed agentSpend body, reused by several tests. */
function spendBody(extra = {}) {
  return {
    vaultId: VAULT_ID,
    action: "agentSpend",
    params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) },
    signerAddress: ADDR(AGENT),
    ...extra
  };
}

before(async () => {
  const template = { owner: XO(OWNER), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const st = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state: st });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state: st });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "http client test", status: "ACTIVE", template, agentRegistry: registry,
    live: {
      state: stateToJsonV4(st), stateId, outpoint: { transactionId: "8b".repeat(32), index: 0 },
      outpointValue: (st.protectedValue + st.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "8c".repeat(32)
    },
    creationTxId: "8d".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  if (server) await new Promise((r) => server.close(r));
});

/* Raw HTTP, used ONLY for the wallet sign-in dance (challenge -> signature
 * -> Set-Cookie). Cookie sessions are a browser concern; the SDK client is
 * deliberately a bearer-credential client and has no cookie-session methods. */
function raw(method, pathName, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Host: `127.0.0.1:${port}`, Origin: baseUrl };
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

async function signIn(priv) {
  const ch = await raw("POST", "/api/v1/auth/challenge", { body: { walletAddress: ADDR(priv) } });
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: priv.toString() });
  const v = await raw("POST", "/api/v1/auth/verify", {
    body: { nonce: ch.json.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() }
  });
  return v.headers["set-cookie"][0].split(";")[0];
}

async function mintToken(cookie, scopes) {
  const created = await raw("POST", "/api/v1/identities", { body: { scopes }, cookie });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  return created.json.credential.token;
}

/* ---------------------------------------------------------------------- */
/* Setup                                                                   */
/* ---------------------------------------------------------------------- */

test("setup: the owner signs in and mints two machine credentials (full and read-only)", async () => {
  state.cookie = await signIn(OWNER);
  state.token = await mintToken(state.cookie, ["read:vaults", "read:requests", "request:build", "organizations:manage", "read:organizations"]);
  state.readOnlyToken = await mintToken(state.cookie, ["read:vaults"]);
  assert.match(state.token, /^pvmk_/);
  assert.notEqual(state.token, state.readOnlyToken);

  state.client = createClient({ baseUrl, token: state.token });
  state.readOnlyClient = createClient({ baseUrl, token: state.readOnlyToken });
  state.anonClient = createClient({ baseUrl });
});

test("the client appends /api/v1 once, and accepts a baseUrl that already has it", () => {
  assert.equal(new PolicyVaultClient({ baseUrl }).baseUrl, `${baseUrl}/api/v1`);
  assert.equal(new PolicyVaultClient({ baseUrl: `${baseUrl}/api/v1` }).baseUrl, `${baseUrl}/api/v1`);
  assert.equal(new PolicyVaultClient({ baseUrl: `${baseUrl}/` }).baseUrl, `${baseUrl}/api/v1`);
  assert.throws(() => new PolicyVaultClient({}), /baseUrl is required/);
  assert.throws(() => new PolicyVaultClient({ baseUrl, token: "" }), /non-empty string/);
});

/* ---------------------------------------------------------------------- */
/* Public discovery                                                        */
/* ---------------------------------------------------------------------- */

test("health: works with NO credential and reports the live network identity", async () => {
  const body = await state.anonClient.health();
  assert.equal(body.ok, true);
  assert.equal(body.api, "v1");
  assert.equal(body.networkId, config.networkId);
  assert.equal(state.anonClient.authenticated, false);
  assert.equal(state.client.authenticated, true);
});

test("capabilities: public, and reports scopes/actions/schemas from the SERVER's code truth", async () => {
  const caps = await state.anonClient.capabilities();
  assert.equal(caps.schemaVersion, "policyvault-capabilities/v1");
  assert.equal(caps.apiVersion, "v1");
  assert.deepEqual(caps.contract.supportedCovenantVersions, ["policyvault-0.4", "policyvault-0.4.1"]);

  /* The client's PINNED schema version must be one the live server accepts —
   * this is the compatibility check the README tells integrators to make. */
  assert.equal(caps.schemas.walletV4Request, require("../src/http-client").V4_WALLET_REQUEST_SCHEMA_VERSION);

  const scopeNames = caps.scopes.map((s) => s.scope);
  for (const required of ["read:vaults", "request:build", "request:submit", "request:break-glass", "risk:release"]) {
    assert.ok(scopeNames.includes(required), `capabilities must advertise ${required}`);
  }
  const actions = caps.actions.v4.map((a) => a.action);
  assert.ok(actions.includes("agentSpend"));
  assert.equal(caps.actions.v4.find((a) => a.action === "agentSpend").role, "agent");
  assert.equal(caps.actions.v4.find((a) => a.action === "ownerPause").role, "owner");
});

test("capabilities WITH a machine credential names the caller's OWN granted scopes (principal-scoped discovery); anonymous carries no principal; an invalid bearer is refused, never downgraded", async () => {
  const anon = await state.anonClient.capabilities();
  assert.equal(anon.principal, undefined, "the public document is unchanged for anonymous callers");
  assert.equal(anon.features.principalScopedDiscovery, true, "hosted mode declares principal-scoped discovery");
  assert.equal(anon.features.machineIdentities, true);

  const ro = await state.readOnlyClient.capabilities();
  assert.deepEqual(ro.principal, { kind: "machine", identityId: ro.principal.identityId, scopes: ["read:vaults"] });
  assert.match(ro.principal.identityId, /^[0-9a-f-]{36}$/);
  const { principal: _p, ...roRest } = ro;
  assert.deepEqual(roRest, anon, "apart from the caller's own principal the document is byte-for-byte the public one");

  const full = await state.client.capabilities();
  assert.deepEqual([...full.principal.scopes].sort(), ["organizations:manage", "read:organizations", "read:requests", "read:vaults", "request:build"]);
  assert.ok(!JSON.stringify(full).includes(state.token) && !JSON.stringify(full).includes(state.readOnlyToken), "never a token");

  const bogus = createClient({ baseUrl, token: "pvmk_totally-invalid-credential-value-that-is-long-enough" });
  await assert.rejects(() => bogus.capabilities(), (error) => { assert.equal(error.status, 401); assert.equal(error.code, "MACHINE_TOKEN_INVALID"); return true; });
});

/* ---------------------------------------------------------------------- */
/* Reads + dry run                                                         */
/* ---------------------------------------------------------------------- */

test("vault reads: tenancy-scoped, and every amount arrives as a STRING (never a bare JSON number)", async () => {
  const { vaults } = await state.client.listVaults();
  assert.equal(vaults.length, 1);
  assert.equal(vaults[0].vaultId, VAULT_ID);

  const detail = await state.client.getVault(VAULT_ID);
  assert.equal(detail.vaultId, VAULT_ID);

  /* Walk the WHOLE response: no key naming an amount may hold a number.
   * `JSON.parse` would have destroyed a u64 as an IEEE-754 double, so the
   * server sends decimal strings and this client never coerces them. */
  const offenders = [];
  (function walk(node, trail) {
    if (Array.isArray(node)) return node.forEach((v, i) => walk(v, `${trail}[${i}]`));
    if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (typeof v === "number" && /kas$|sompi$|value$|amount|budget|fee|threshold|spent/i.test(k)) offenders.push(`${trail}.${k}=${v}`);
        walk(v, `${trail}.${k}`);
      }
    }
  })(detail, "vault");
  assert.deepEqual(offenders, [], "amounts must never cross the wire as JSON numbers");

  /* And the values are exact after the round trip. */
  const { kasToSompi, sompiToKas } = require("../src/amounts");
  assert.equal(typeof detail.live.protectedValueKas, "string");
  assert.equal(kasToSompi(detail.live.protectedValueKas), 1000n * KAS);
  assert.equal(kasToSompi(detail.live.feeReserveKas), 5n * KAS);
  assert.equal(sompiToKas(kasToSompi(detail.live.covenantValueKas)), "1005");
  assert.equal(detail.live.stateId, computeStateIdV4({
    networkId: config.networkId,
    template: { owner: XO(OWNER), vaultId: VAULT_ID },
    state: normalizeStateV4({
      protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
      agentRoot: detail.live.agentRoot, approvers: [], approvalM: "0", policyNonce: "0"
    })
  }), "the reported stateId must be independently recomputable by the client — that is the whole point");
});

test("dry run: simulate reaches the REAL pipeline through the client and answers ok:true", async () => {
  const body = await state.client.simulate(spendBody());
  assert.equal(body.schemaVersion, "policyvault-wallet-v4-request/v1");
  const sim = body.simulation;
  assert.equal(sim.ok, true, JSON.stringify(sim));

  /* The real builder really ran: an exact fee, an exact compute budget, and
   * exact before/after accounting — not an estimate. */
  assert.equal(typeof sim.review.feeSompi, "string");
  assert.match(sim.review.feeSompi, /^\d+$/);
  const { parseSompi, sompiToKas } = require("../src/amounts");
  assert.ok(parseSompi(sim.review.feeSompi) > 0n);
  assert.equal(sompiToKas(sim.review.feeSompi), sim.review.feeKas, "feeKas and feeSompi must be the same number in two renderings");

  /* The real intent bridge really ran and really verified. */
  assert.equal(sim.intent.verdict, "VERIFIED_EXACT");
  assert.match(sim.intent.manifestHash, /^[0-9a-f]{64}$/);
  assert.deepEqual(sim.intent.failureCodes, []);

  /* It reports what a real call would still require, BEFORE consuming anything. */
  assert.equal(sim.wouldRequire.proposal, false);
  assert.equal(sim.wouldRequire.riskRelease, false);

  /* And it is honest about the one stage it cannot exercise. */
  assert.equal(sim.vmPreflight.skipped, true);
  assert.ok(typeof sim.vmPreflight.reason === "string" && sim.vmPreflight.reason.length > 0);

  /* No idempotency key is spent on a simulation by default. */
  assert.equal(body.idempotency, undefined);
  assert.equal(body.idempotencyKey, undefined);
});

test("dry run: a refusal is reported as ok:false with the real refusal, not as an HTTP error", async () => {
  const body = await state.client.simulate(spendBody({
    params: { payAmountSompi: (5000n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) } // far over budget
  }));
  assert.equal(body.simulation.ok, false);
  assert.equal(typeof body.simulation.refusalReason.code, "string");
  assert.ok(body.simulation.refusalReason.code.length > 0);

  /* A MALFORMED body, by contrast, is a real HTTP 4xx: a dry run answers
   * "would this succeed", not "is this even well-formed". */
  await assert.rejects(
    () => state.client.simulate({ vaultId: "not-hex", action: "agentSpend", params: {}, signerAddress: ADDR(AGENT) }),
    (error) => {
      assert.ok(error instanceof PolicyVaultApiError);
      assert.ok(error.status >= 400 && error.status < 500);
      return true;
    }
  );
});

test("dry run persists NOTHING: the durable request store is untouched by simulation", async () => {
  const before = (await state.client.listRequests()).requests.length;
  await state.client.simulate(spendBody());
  await state.client.simulate(spendBody({ params: { payAmountSompi: (2n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) } }));
  assert.equal((await state.client.listRequests()).requests.length, before);
});

/* ---------------------------------------------------------------------- */
/* Idempotency                                                             */
/* ---------------------------------------------------------------------- */

test("idempotent create: the same key REPLAYS the original response instead of creating a second row", async () => {
  const key = randomIdempotencyKey();
  const body = { name: `idem-org-${Date.now()}` };

  const first = await state.client.request("POST", "/organizations", { body, idempotencyKey: key });
  assert.equal(first.idempotency.replayed, false);
  assert.equal(first.idempotency.key, key);
  assert.equal(first.idempotencyKey, key, "the key must be readable off the result");

  const before = (await state.client.listOrganizations()).organizations.length;

  const replay = await state.client.request("POST", "/organizations", { body, idempotencyKey: key });
  assert.equal(replay.idempotency.replayed, true, "a retry with the same key must replay, never re-execute");
  assert.equal(replay.organization.orgId, first.organization.orgId, "the replay must be the ORIGINAL object, not a new one");

  const after = (await state.client.listOrganizations()).organizations.length;
  assert.equal(after, before, "no second organization may exist after the replay");
});

test("the exposed idempotency key is NON-ENUMERABLE — JSON.stringify(result) is still exactly the server's body", async () => {
  const key = randomIdempotencyKey();
  const result = await state.client.request("POST", "/organizations", { body: { name: `nonenum-${Date.now()}` }, idempotencyKey: key });
  assert.equal(result.idempotencyKey, key);
  assert.ok(!Object.keys(result).includes("idempotencyKey"));
  assert.ok(!JSON.stringify(result).includes("idempotencyKey"));
  assert.ok(JSON.stringify(result).includes(key), "the SERVER's own idempotency marker still carries the key, as it should");
});

test("a DIFFERENT body under the same key is a deterministic 409 — the handler is never reached", async () => {
  const key = randomIdempotencyKey();
  await state.client.request("POST", "/organizations", { body: { name: `conflict-a-${Date.now()}` }, idempotencyKey: key });
  const before = (await state.client.listOrganizations()).organizations.length;

  await assert.rejects(
    () => state.client.request("POST", "/organizations", { body: { name: "conflict-b" }, idempotencyKey: key }),
    (error) => {
      assert.ok(error instanceof PolicyVaultApiError);
      assert.equal(error.status, 409);
      assert.equal(error.code, "IDEMPOTENCY_KEY_CONFLICT");
      assert.equal(error.idempotencyKey, key);
      return true;
    }
  );
  assert.equal((await state.client.listOrganizations()).organizations.length, before, "a conflicting replay must not have mutated anything");
});

test("every mutating call carries a key by default; idempotencyKey:null opts out entirely", async () => {
  const auto = await state.client.request("POST", "/organizations", { body: { name: `auto-${Date.now()}` } });
  assert.match(auto.idempotencyKey, /^pvsdk-/);
  assert.equal(auto.idempotency.replayed, false);

  const optedOut = await state.client.request("POST", "/organizations", { body: { name: `optout-${Date.now()}` }, idempotencyKey: null });
  assert.equal(optedOut.idempotency, undefined, "with no header the server's idempotency wrapper must not engage at all");
  assert.equal(optedOut.idempotencyKey, undefined);

  /* A key outside the server's grammar is refused LOCALLY, before any
   * transport happens — proven by a fetch that is never called. */
  let attempts = 0;
  const counting = createClient({ baseUrl, token: state.token, fetchImpl: (...args) => { attempts += 1; return fetch(...args); } });
  await assert.rejects(
    () => counting.request("POST", "/organizations", { body: {}, idempotencyKey: "bad key with spaces" }),
    (error) => {
      assert.ok(error instanceof TypeError);
      assert.match(error.message, /A-Za-z0-9/);
      return true;
    }
  );
  assert.equal(attempts, 0, "a malformed key must be refused before the request is ever sent");
});

/* ---------------------------------------------------------------------- */
/* Error envelope + refusals                                               */
/* ---------------------------------------------------------------------- */

test("error envelope: the server's {error:{code,message}} arrives VERBATIM, never reinterpreted", async () => {
  await assert.rejects(
    () => state.client.getVault("ff".repeat(32)),
    (error) => {
      assert.ok(error instanceof PolicyVaultApiError);
      assert.equal(error.name, "PolicyVaultApiError");
      assert.equal(error.status, 404);
      assert.equal(error.code, "VAULT_NOT_FOUND");
      /* Verbatim: the lifted fields must equal the raw envelope exactly. */
      assert.equal(error.body.error.code, error.code);
      assert.equal(error.body.error.message, error.serverMessage);
      assert.equal(error.method, "GET");
      assert.ok(error.path.includes("ff".repeat(32)));
      assert.equal(error.idempotencyKey, null, "a GET spends no idempotency key");
      return true;
    }
  );
});

test("scope refusal: a read-only credential cannot build or simulate (deny-by-default)", async () => {
  /* The read-only credential CAN read. */
  const { vaults } = await state.readOnlyClient.listVaults();
  assert.equal(vaults.length, 1);

  await assert.rejects(
    () => state.readOnlyClient.simulate(spendBody()),
    (error) => {
      assert.ok(error instanceof PolicyVaultApiError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "SCOPE_FORBIDDEN");
      assert.match(error.serverMessage, /request:build/);
      return true;
    }
  );
});

test("structural refusal: NO machine credential can reach machine-identity management, at any scope", async () => {
  for (const client of [state.client, state.readOnlyClient]) {
    await assert.rejects(
      () => client.listIdentities(),
      (error) => {
        assert.equal(error.status, 403);
        assert.equal(error.code, "MACHINE_IDENTITY_ROUTE_FORBIDDEN");
        return true;
      }
    );
  }
});

test("an unauthenticated client is refused on a tenancy-gated route (not silently downgraded)", async () => {
  await assert.rejects(
    () => state.anonClient.listVaults(),
    (error) => {
      assert.ok(error instanceof PolicyVaultApiError);
      assert.equal(error.status, 401);
      return true;
    }
  );
});

test("an invalid credential fails at AUTHENTICATION with the server's own code", async () => {
  const bogus = createClient({ baseUrl, token: "pvmk_totally-invalid-credential-value-that-is-long-enough" });
  await assert.rejects(
    () => bogus.simulate(spendBody()),
    (error) => {
      assert.equal(error.status, 401);
      assert.equal(error.code, "MACHINE_TOKEN_INVALID");
      return true;
    }
  );
});

/* ---------------------------------------------------------------------- */
/* Schema version                                                          */
/* ---------------------------------------------------------------------- */

test("schemaVersion: the client's pin is accepted, and a mismatched pin FAILS CLOSED with 422", async () => {
  /* Stamped by default and accepted. */
  assert.equal((await state.client.simulate(spendBody())).simulation.ok, true);

  /* A caller-supplied version wins — and an unknown one is refused, never
   * routed to a default handler. */
  await assert.rejects(
    () => state.client.simulate(spendBody({ schemaVersion: "policyvault-wallet-v4-request/v999" })),
    (error) => {
      assert.equal(error.status, 422);
      assert.equal(error.code, "SCHEMA_VERSION_UNSUPPORTED");
      return true;
    }
  );

  /* stampSchemaVersion:false omits the field entirely (web-client behavior). */
  const unstamped = createClient({ baseUrl, token: state.token, stampSchemaVersion: false });
  assert.equal((await unstamped.simulate(spendBody())).simulation.ok, true);
});

/* ---------------------------------------------------------------------- */
/* The token never leaks                                                   */
/* ---------------------------------------------------------------------- */

test("THE TOKEN NEVER LEAKS: not into the client's serialization, an error, a stack, or the console", async () => {
  const token = state.token;
  assert.ok(token.length > 20);

  const contains = (value) => typeof value === "string" && value.includes(token);

  /* (a) The client object itself, by every serialization route. */
  assert.ok(!contains(JSON.stringify(state.client)));
  assert.ok(!contains(util.inspect(state.client, { depth: 10, showHidden: true })));
  assert.ok(!contains(String(state.client)));
  assert.ok(!contains(Object.getOwnPropertyNames(state.client).join("|")));
  for (const name of Object.getOwnPropertyNames(state.client)) {
    assert.ok(!contains(util.inspect(state.client[name], { depth: 6 })), `own property ${name} exposes the token`);
  }
  /* Not even as a hidden own property. */
  assert.ok(!contains(util.inspect(Object.getOwnPropertyDescriptors(state.client), { depth: 6 })));

  /* (b) Thrown errors, on every field a caller or crash reporter would read. */
  const capture = [];
  const original = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  for (const level of Object.keys(original)) {
    console[level] = (...args) => capture.push(args.map((a) => util.inspect(a)).join(" "));
  }
  try {
    await state.client.getVault("ee".repeat(32)).catch((error) => {
      for (const field of [error.message, error.stack, String(error), util.inspect(error, { depth: 10 }), JSON.stringify(error.body), JSON.stringify(error.extra)]) {
        assert.ok(!contains(field), "a thrown error exposed the token");
      }
    });
    await state.client.simulate(spendBody()).catch(() => {});
    await state.client.request("POST", "/organizations", { body: { name: `leakcheck-${Date.now()}` } });
  } finally {
    for (const level of Object.keys(original)) console[level] = original[level];
  }

  /* (c) The console. The client has no logger at all, so a full request
   *     cycle must produce ZERO output — there is no verbosity setting that
   *     could ever turn credential printing on. */
  assert.deepEqual(capture, [], "the client must never write to the console");

  /* (d) A transport failure carries the key, never the credential. */
  const dead = createClient({ baseUrl: "http://127.0.0.1:1", token });
  await assert.rejects(
    () => dead.request("POST", "/organizations", { body: { name: "x" }, idempotencyKey: "retry-me-safely" }),
    (error) => {
      assert.ok(error instanceof PolicyVaultNetworkError);
      assert.equal(error.idempotencyKey, "retry-me-safely", "the key you would replay must be recoverable from the error");
      assert.ok(!contains(error.message));
      assert.ok(!contains(error.stack));
      assert.ok(!contains(util.inspect(error, { depth: 10 })));
      return true;
    }
  );

  /* (e) toJSON reveals existence, never the value. */
  assert.deepEqual(state.client.toJSON(), { baseUrl: `${baseUrl}/api/v1`, authenticated: true, stampSchemaVersion: true });
});

test("the token IS sent — the leak guarantee is not achieved by dropping the credential", async () => {
  let seen = null;
  const spy = createClient({
    baseUrl,
    token: state.token,
    fetchImpl: (url, init) => {
      seen = init.headers;
      return fetch(url, init);
    }
  });
  const body = await spy.health();
  assert.equal(body.ok, true);
  assert.equal(seen.Authorization, `Bearer ${state.token}`);
});

/* ---------------------------------------------------------------------- */
/* No automatic retries                                                    */
/* ---------------------------------------------------------------------- */

test("NO automatic retries: exactly one transport attempt per call, on success, refusal, and transport failure", async () => {
  let attempts = 0;
  const counting = createClient({
    baseUrl,
    token: state.token,
    fetchImpl: (url, init) => {
      attempts += 1;
      return fetch(url, init);
    }
  });

  attempts = 0;
  await counting.health();
  assert.equal(attempts, 1, "a successful call must not be duplicated");

  attempts = 0;
  await counting.getVault("dd".repeat(32)).catch(() => {});
  assert.equal(attempts, 1, "a refusal must never be retried — a refusal is a decision");

  attempts = 0;
  const failing = createClient({
    baseUrl,
    token: state.token,
    fetchImpl: () => {
      attempts += 1;
      return Promise.reject(new Error("simulated transport failure"));
    }
  });
  await assert.rejects(() => failing.request("POST", "/organizations", { body: { name: "never-retried" } }), PolicyVaultNetworkError);
  assert.equal(attempts, 1, "a transport failure must NOT be silently retried — the client cannot know whether it executed");
});

test("a caller-controlled retry with the SAME key is at-most-once (the property that makes no-retry safe)", async () => {
  const key = randomIdempotencyKey();
  const body = { name: `manual-retry-${Date.now()}` };

  const first = await state.client.request("POST", "/organizations", { body, idempotencyKey: key });
  const before = (await state.client.listOrganizations()).organizations.length;

  /* Three deliberate caller retries, exactly as the README documents. */
  for (let i = 0; i < 3; i++) {
    const again = await state.client.request("POST", "/organizations", { body, idempotencyKey: key });
    assert.equal(again.idempotency.replayed, true);
    assert.equal(again.organization.orgId, first.organization.orgId);
  }
  assert.equal((await state.client.listOrganizations()).organizations.length, before, "N retries must produce exactly ONE organization");
});
