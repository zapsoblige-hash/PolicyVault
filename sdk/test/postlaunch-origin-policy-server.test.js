"use strict";

/*
 * PROGRAMMATIC-CLIENT ORIGIN POLICY (completion-standard "origin policy"
 * item under surface 8/REST-Agent-API; docs/postlaunch/
 * platform-agent-api-spec.md §origin policy; server/src/limits.js
 * verifyOrigin).
 *
 * verifyOrigin (the CSRF wall) is enforced in server.js BEFORE handle()
 * is ever called — this property is untestable through direct handle()
 * calls and REQUIRES a real HTTP server, exactly like the existing
 * hosted-tenancy.test.js / postlaunch-server-tenancy.test.js idiom.
 *
 * The adversarial matrix item this file proves: "cookie-CSRF unchanged" —
 * a hostile cross-origin page can never ride a victim's cookie session
 * into a mutation (with or without an ALSO-attached bogus Authorization
 * header — the exemption never applies once any Cookie header is
 * present), while a genuine machine (Bearer-token) client with NO cookie
 * at all is correctly exempted from the browser-CSRF wall (it was never
 * subject to CSRF in the first place — see limits.js's doc comment for
 * the full reasoning) and a garbage/unresolvable bearer credential is
 * still refused, just by AUTHENTICATION rather than the origin wall.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-originpolicy-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const A = KEY(0x21);
const AGENT = KEY(0x22);
const RECIP = KEY(0x23);
const VAULT_ID = "7a".repeat(32);

let server, port;
const state = {};

before(async () => {
  const template = { owner: XO(A), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const st = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state: st });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state: st });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "origin policy test", status: "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(st), stateId, outpoint: { transactionId: "7b".repeat(32), index: 0 }, outpointValue: (st.protectedValue + st.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "7c".repeat(32) },
    creationTxId: "7d".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(async () => {
  if (server) await new Promise((r) => server.close(r));
});

function req(method, pathName, { body, cookie, origin, omitOrigin, authorization } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Host: `127.0.0.1:${port}` };
    if (!omitOrigin) headers.Origin = origin !== undefined ? origin : `http://127.0.0.1:${port}`;
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
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
  const address = ADDR(priv);
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: address } });
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: priv.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: priv.toPublicKey().toString().toLowerCase() } });
  return v.headers["set-cookie"][0].split(";")[0];
}

test("setup: A signs in and mints a machine credential", async () => {
  state.cookieA = await signIn(A);
  const created = await req("POST", "/api/v1/identities", {
    body: { scopes: ["read:vaults", "request:build"] },
    cookie: state.cookieA
  });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  state.token = created.json.credential.token;
});

test("UNCHANGED: a cookie session cannot mutate cross-origin (hostile Origin refused)", async () => {
  const r = await req("POST", "/api/v1/organizations", { body: { name: "csrf-attempt" }, cookie: state.cookieA, origin: "https://evil.example" });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, "ORIGIN_FORBIDDEN");
});

test("UNCHANGED: a cookie session with no Origin and no Sec-Fetch-Site is refused (the released same-origin proof requirement, verbatim)", async () => {
  const r = await req("POST", "/api/v1/organizations", { body: { name: "no-origin-attempt" }, cookie: state.cookieA, omitOrigin: true });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, "ORIGIN_REQUIRED");
});

test("NEVER WEAKENED: a cookie session carrying a hostile Origin PLUS an attached (garbage) Authorization header is STILL fully refused — the machine exemption never applies once ANY cookie is present", async () => {
  const r = await req("POST", "/api/v1/organizations", {
    body: { name: "mixed-csrf-attempt" },
    cookie: state.cookieA,
    origin: "https://evil.example",
    authorization: "Bearer some-plausible-looking-token-that-is-twenty-plus-chars"
  });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, "ORIGIN_FORBIDDEN", "a cookie must NEVER be rescued into passing by an accompanying bearer header");
});

test("UNCHANGED: a same-origin cookie session mutates normally", async () => {
  const r = await req("POST", "/api/v1/organizations", { body: { name: "legit-org" }, cookie: state.cookieA });
  assert.equal(r.status, 201);
});

test("PROGRAMMATIC-CLIENT EXEMPTION: a machine Bearer credential with NO cookie succeeds despite a hostile/absent Origin (never ambient — cannot be CSRF-forged)", async () => {
  const hostileOrigin = await req("POST", "/api/v1/wallet/v4/simulate", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) },
    authorization: `Bearer ${state.token}`,
    origin: "https://evil.example"
  });
  assert.equal(hostileOrigin.status, 200, JSON.stringify(hostileOrigin.json));
  assert.equal(hostileOrigin.json.simulation.ok, true);

  const noOriginAtAll = await req("POST", "/api/v1/wallet/v4/simulate", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) },
    authorization: `Bearer ${state.token}`,
    omitOrigin: true
  });
  assert.equal(noOriginAtAll.status, 200, JSON.stringify(noOriginAtAll.json));

  const nullOrigin = await req("POST", "/api/v1/wallet/v4/simulate", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) },
    authorization: `Bearer ${state.token}`,
    origin: "null"
  });
  assert.equal(nullOrigin.status, 200, JSON.stringify(nullOrigin.json));
});

test("the exemption is NOT a free pass for garbage credentials — it moves the refusal from the origin wall to AUTHENTICATION, never to nothing", async () => {
  const r = await req("POST", "/api/v1/wallet/v4/simulate", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: {}, signerAddress: ADDR(AGENT) },
    authorization: "Bearer totally-invalid-credential-value-that-is-long-enough",
    origin: "https://evil.example"
  });
  assert.equal(r.status, 401, "the origin check must PASS (it is exempted) and the request must fail at authentication instead");
  assert.equal(r.json.error.code, "MACHINE_TOKEN_INVALID");
});

test("a same-origin machine Bearer request works normally too (the exemption is additive, not a replacement path)", async () => {
  const r = await req("POST", "/api/v1/wallet/v4/simulate", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }, signerAddress: ADDR(AGENT) },
    authorization: `Bearer ${state.token}`
  });
  assert.equal(r.status, 200);
});
