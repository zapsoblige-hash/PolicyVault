"use strict";

/*
 * POSTLAUNCH ROUTES — HOSTED TENANCY + ORIGIN GUARDS
 * (completion-standard items 3/5/7; Phase C/F tenancy model).
 *
 * Real HTTP server + hosted authentication + PostgreSQL backend
 * (SKIPPED cleanly without POLICYVAULT_TEST_PG_*). Wallet A owns a
 * seeded v0.4 vault; wallet B is an authenticated FOREIGN tenant. Using
 * REAL VALID FOREIGN IDS, every new surface must deny B with 404
 * (existence hidden — no cross-tenant oracle), deny the unauthenticated
 * with 401, and refuse state-changing requests without browser
 * same-origin proof (ORIGIN_REQUIRED — the same limits.js wall that
 * guards every existing route, because the new routes are served by the
 * SAME /api pipeline).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const kaspa = require(loadConfig({}).rustyKaspaModule);

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run hosted tenancy tests";

function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { priv, compressed: priv.toPublicKey().toString().toLowerCase(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress("testnet-10").toString() };
}
const A = wallet("a1"); // vault owner
const B = wallet("b2"); // authenticated foreign tenant
const AGENT = wallet("c3");
const RECIP = wallet("d4");
const KAS = 100000000n;

let adminPool, server, port, config, store, dbName;
const VAULT_ID = "3a".repeat(32);

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_plten_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-plten-"))
  });
  store = await openPgStore(config, { migrate: true });

  // Seed a REAL v0.4 manifest owned by A with AGENT as the one agent.
  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const template = { owner: A.xonly, vaultId: VAULT_ID };
  const REGISTRY = [
    {
      agentPk: AGENT.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [RECIP.xonly]
    }
  ];
  const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "tenancy", status: "ACTIVE", template, agentRegistry: REGISTRY,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "71".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(async () => {
  if (!PG_AVAILABLE) return;
  if (server) await new Promise((r) => server.close(r));
  if (store) await store.close();
  if (adminPool) { await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {}); await adminPool.end(); }
});

function req(method, pathName, { body, cookie, omitOrigin } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Host: `127.0.0.1:${port}` };
    if (!omitOrigin) headers.Origin = `http://127.0.0.1:${port}`;
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

async function signIn(w) {
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: w.address } });
  assert.equal(ch.status, 200);
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed } });
  assert.equal(v.status, 200);
  return v.headers["set-cookie"][0].split(";")[0];
}

const state = {};

test("setup: A and B sign in; A creates an org owning the vault with REVIEW risk controls", { skip }, async () => {
  state.cookieA = await signIn(A);
  state.cookieB = await signIn(B);
  const org = await req("POST", "/api/v1/organizations", { body: { name: "A treasury" }, cookie: state.cookieA });
  assert.equal(org.status, 201);
  state.orgId = org.json.organization.orgId;
  const assign = await req("POST", `/api/v1/organizations/${state.orgId}/vaults`, { body: { vaultId: VAULT_ID, expectedVersion: 0 }, cookie: state.cookieA });
  assert.equal(assign.status, 200, JSON.stringify(assign.json));
  // controls: static REVIEW on everything
  const controls = await req("POST", `/api/v1/organizations/${state.orgId}/controls`, {
    body: { governance: {}, risk: { adapters: [{ type: "static-verdict", params: { verdict: "REVIEW", code: "ORG_REVIEW_ALL" } }] }, expectedVersion: 0 },
    cookie: state.cookieA
  });
  assert.equal(controls.status, 200, JSON.stringify(controls.json));
  assert.equal(controls.json.controls.version, 1);
});

test("org controls tenancy: B cannot read or write A's controls (404); unauthenticated is 401", { skip }, async () => {
  const readB = await req("GET", `/api/v1/organizations/${state.orgId}/controls`, { cookie: state.cookieB });
  assert.equal(readB.status, 404);
  const writeB = await req("POST", `/api/v1/organizations/${state.orgId}/controls`, { body: { risk: {}, expectedVersion: 1 }, cookie: state.cookieB });
  assert.equal(writeB.status, 404);
  const anon = await req("GET", `/api/v1/organizations/${state.orgId}/controls`, {});
  assert.equal(anon.status, 401);
});

test("risk hold + evidence tenancy: the held evaluation is invisible to B and unreleasable by B; A (org owner) releases", { skip }, async () => {
  // the build route is signer-authorized (existing posture); the REVIEW
  // hold comes from A's org controls
  const held = await req("POST", "/api/v1/wallet/v4/requests", {
    body: { vaultId: VAULT_ID, action: "agentSpend", params: { payAmountSompi: (4n * KAS).toString(), agentPk: AGENT.xonly, recipient: RECIP.xonly }, signerAddress: AGENT.address },
    cookie: state.cookieA
  });
  assert.equal(held.status, 409, JSON.stringify(held.json));
  assert.equal(held.json.error.code, "RISK_REVIEW_REQUIRED");
  const evaluationId = held.json.error.riskEvaluation.evaluationId;

  const readB = await req("GET", `/api/v1/risk/evaluations/${evaluationId}`, { cookie: state.cookieB });
  assert.equal(readB.status, 404, "foreign tenant cannot see the evaluation (existence hidden)");
  const releaseB = await req("POST", `/api/v1/risk/evaluations/${evaluationId}/release`, { cookie: state.cookieB });
  assert.equal(releaseB.status, 404);
  const anon = await req("GET", `/api/v1/risk/evaluations/${evaluationId}`, {});
  assert.equal(anon.status, 401);

  const readA = await req("GET", `/api/v1/risk/evaluations/${evaluationId}`, { cookie: state.cookieA });
  assert.equal(readA.status, 200);
  assert.equal(readA.json.evaluation.status, "REVIEW_HELD");
  const releaseA = await req("POST", `/api/v1/risk/evaluations/${evaluationId}/release`, { cookie: state.cookieA });
  assert.equal(releaseA.status, 200, JSON.stringify(releaseA.json));
  assert.equal(releaseA.json.evaluation.status, "RELEASED");
  state.evaluationId = evaluationId;
});

test("manifest record tenancy: A's built request manifest is 404 to B and 401 unauthenticated", { skip }, async () => {
  const built = await req("POST", "/api/v1/wallet/v4/requests", {
    body: {
      vaultId: VAULT_ID, action: "agentSpend",
      params: { payAmountSompi: (4n * KAS).toString(), agentPk: AGENT.xonly, recipient: RECIP.xonly },
      signerAddress: AGENT.address, riskEvaluationId: state.evaluationId
    },
    cookie: state.cookieA
  });
  assert.equal(built.status, 201, JSON.stringify(built.json));
  const manifestHash = built.json.request.manifestHash;
  assert.match(manifestHash, /^[0-9a-f]{64}$/);

  const asA = await req("GET", `/api/v1/manifests/${manifestHash}`, { cookie: state.cookieA });
  assert.equal(asA.status, 200);
  assert.equal(asA.json.liveVerification.ok, true);
  const asB = await req("GET", `/api/v1/manifests/${manifestHash}`, { cookie: state.cookieB });
  assert.equal(asB.status, 404, "foreign tenant gets 404 for a REAL manifest hash");
  const anon = await req("GET", `/api/v1/manifests/${manifestHash}`, {});
  assert.equal(anon.status, 401);
});

test("governance tenancy: B cannot propose on, read, approve, or cancel A's proposals (404); unauthenticated 401", { skip }, async () => {
  const NEW_AGENT = {
    agentPk: wallet("e5").xonly, maxPerSpend: (10n * KAS).toString(), periodBudget: (30n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [RECIP.xonly]
  };
  // B proposing on A's vault: 404 (vault existence hidden)
  const asB = await req("POST", "/api/v1/governance/proposals", { body: { vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT } }, cookie: state.cookieB });
  assert.equal(asB.status, 404);
  // unauthenticated: 401
  const anonCreate = await req("POST", "/api/v1/governance/proposals", { body: { vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT } } });
  assert.equal(anonCreate.status, 401);
  // A creates a real proposal
  const asA = await req("POST", "/api/v1/governance/proposals", { body: { vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT } }, cookie: state.cookieA });
  assert.equal(asA.status, 201, JSON.stringify(asA.json));
  const proposalId = asA.json.proposal.proposalId;

  // B against A's REAL proposal id: read/approve/cancel all 404
  assert.equal((await req("GET", `/api/v1/governance/proposals/${proposalId}`, { cookie: state.cookieB })).status, 404);
  assert.equal(
    (await req("POST", `/api/v1/governance/proposals/${proposalId}/approvals`, { body: { approverAddress: B.address, signature: "ab".repeat(64) }, cookie: state.cookieB })).status,
    404
  );
  assert.equal((await req("POST", `/api/v1/governance/proposals/${proposalId}/cancel`, { cookie: state.cookieB })).status, 404);
  // B's listing does not leak A's proposals
  const listB = await req("GET", "/api/v1/governance/proposals", { cookie: state.cookieB });
  assert.equal(listB.status, 200);
  assert.deepEqual(listB.json.proposals, []);
  // A sees + can read it
  const readA = await req("GET", `/api/v1/governance/proposals/${proposalId}`, { cookie: state.cookieA });
  assert.equal(readA.status, 200);
  assert.equal(readA.json.proposal.integrity.digestOk, true);
});

test("origin guard: every new state-changing route refuses without browser same-origin proof (ORIGIN_REQUIRED)", { skip }, async () => {
  for (const [pathName, body] of [
    ["/api/v1/governance/proposals", { vaultId: VAULT_ID, action: "addAgent", params: {} }],
    [`/api/v1/risk/evaluations/${state.evaluationId}/release`, {}],
    [`/api/v1/organizations/${state.orgId}/controls`, { risk: {}, expectedVersion: 1 }]
  ]) {
    const r = await req("POST", pathName, { body, cookie: state.cookieA, omitOrigin: true });
    assert.equal(r.status, 403, `${pathName}: ${JSON.stringify(r.json)}`);
    assert.equal(r.json.error.code, "ORIGIN_REQUIRED", pathName);
  }
});
