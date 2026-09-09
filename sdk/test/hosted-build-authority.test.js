"use strict";

/*
 * PERMANENT REGRESSION — rc11 internal security review F-03 / F-04 (hosted
 * BUILD AUTHORITY), owner addendum §E GATE 1 (foreign-tenant hostile probe).
 *
 * RED before the fix (docs/postlaunch/audit-evidence/rc11-internal-review/
 * logs/tenancy-probe.json T21–T23, live-probe L4e): with hosted auth ON an
 * UNAUTHENTICATED caller created 58 v4 genesis requests naming a victim
 * wallet as signer (quota + inbox pollution + ~2 MB of artifacts each), and
 * a foreign session built spends naming another tenant's agent.
 *
 * Contract (server/src/api.js requireBuildAuthority / requireLegacyBuildAuthority):
 *   - a principal is REQUIRED for every hosted build/create/simulate;
 *   - genesis: the signer must BE the principal;
 *   - existing vault: principal must be a participant with build authority
 *     (owner / agent / delegate; approver-only never), the signer must be a
 *     participant of that SAME vault, a non-owner builds only for itself,
 *     the owner may build for its own registered agents (documented MCP flow);
 *   - foreign principals get the non-oracle 404; nothing is persisted.
 * Real server over HTTP + hosted authentication + PostgreSQL (skipped
 * cleanly without POLICYVAULT_TEST_PG_*).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore, getStore, Categories } = require("../src/store");
const kaspa = require(loadConfig({}).rustyKaspaModule);
const { ENCODER_PATH } = require("../src/vault-builders-v4");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const TOOLCHAIN = fs.existsSync(loadConfig({}).silvercPath) && fs.existsSync(ENCODER_PATH);
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !TOOLCHAIN ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder" : undefined;

function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { priv, compressed: priv.toPublicKey().toString().toLowerCase(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress("testnet-10").toString() };
}
const O = wallet("d1"), AG = wallet("d2"), B = wallet("d3"), REC = wallet("d4");
const KAS = 100000000n;
const VAULT_ID = "6d".repeat(32);

let adminPool, server, port, config, store, dbName;

before(async () => {
  if (skip) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_buildauth_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-buildauth-"))
  });
  store = await openPgStore(config, { migrate: true });
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  // a LIVE v4 vault owned by O with agent AG (synthetic outpoint; builds are offline with explicit fuel)
  const vs4 = require("../../core/model/vault-state-v4");
  const { normalizeAgentPolicyV4, buildAgentTreeV4 } = require("../../core/model/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
  const template = { owner: O.xonly, vaultId: VAULT_ID };
  const entry = { agentPk: AG.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [REC.xonly] };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 });
  await persistManifestV4(config, { schema: MANIFEST_SCHEMA_V4, contractVersion: vs4.CONTRACT_VERSION_V4_1, networkId: config.networkId, vaultId: VAULT_ID, label: "build-authority", status: "ACTIVE", template, agentRegistry: [entry], live: { state: vs4.stateToJsonV4(state), stateId: vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion: vs4.CONTRACT_VERSION_V4_1 }), outpoint: { transactionId: "0a".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "4a".repeat(32) }, creationTxId: "4b".repeat(32), latestTransitionTxId: null, lastTransition: null });
});

after(async () => {
  if (skip) return;
  if (server) await new Promise((r) => server.close(r));
  if (store) await store.close();
  if (adminPool) { await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {}); await adminPool.end(); }
});

function req(method, pathName, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` };
    if (cookie) headers.Cookie = cookie;
    const r = http.request({ host: "127.0.0.1", port, method, path: pathName, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, json: buf ? JSON.parse(buf) : null }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
async function signInCookie(w) {
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: w.address } });
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed });
    const r = http.request({ host: "127.0.0.1", port, method: "POST", path: "/api/v1/auth/verify", headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` } }, (res) => {
      let buf = ""; res.on("data", (d) => (buf += d)); res.on("end", () => { assert.equal(res.statusCode, 200, buf); resolve(res.headers["set-cookie"][0].split(";")[0]); });
    });
    r.on("error", reject); r.write(data); r.end();
  });
}
const genesisBody = (signer) => ({ vaultId: "7e".repeat(32), label: "g", depositKas: "10", feeReserveKas: "1", signerAddress: signer.address, funding: [{ outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (5000n * KAS).toString(), scriptPublicKeyHex: `20${signer.xonly}ac` }], agent: { agentAddress: AG.address, maxPerSpendKas: "1", budgetKas: "5", budgetPeriod: { value: 1, unit: "day" }, approvalThresholdKas: "0.5", recipientAddresses: [REC.address] } });
const spendBody = (signer, agentPk = AG.xonly) => ({ vaultId: VAULT_ID, action: "agentSpend", signerAddress: signer.address, params: { payAmountSompi: (4n * KAS).toString(), agentPk, recipient: REC.xonly, fuel: { outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${agentPk}ac` } } });
const openCount = async () => (await getStore(config).listValues(Categories.REQUEST)).filter((r) => r.state === "BUILT" || r.state === "AWAITING_APPROVALS").length;

test("UNAUTHENTICATED: create / build / simulate are refused (401) and persist nothing", { skip }, async () => {
  const before = await openCount();
  let r = await req("POST", "/api/v1/wallet/v4/create", { body: genesisBody(O) });
  assert.equal(r.status, 401, JSON.stringify(r.json));
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: spendBody(AG) });
  assert.equal(r.status, 401);
  r = await req("POST", "/api/v1/wallet/v4/simulate", { body: spendBody(AG) });
  assert.equal(r.status, 401);
  assert.equal(await openCount(), before);
});

test("FOREIGN tenant B: cannot create a genesis naming O (403), cannot build/simulate on O's vault (404 non-oracle), quota of O untouched", { skip }, async () => {
  const cookieB = await signInCookie(B);
  const before = await openCount();
  let r = await req("POST", "/api/v1/wallet/v4/create", { body: genesisBody(O), cookie: cookieB });
  assert.equal(r.status, 403); assert.equal(r.json.error.code, "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: spendBody(AG), cookie: cookieB });
  assert.equal(r.status, 404); assert.equal(r.json.error.code, "VAULT_NOT_FOUND");
  r = await req("POST", "/api/v1/wallet/v4/simulate", { body: spendBody(AG), cookie: cookieB });
  assert.equal(r.status, 404);
  assert.equal(await openCount(), before, "nothing persisted for the foreign tenant");
});

test("AGENT builds only for itself: own spend 201; naming the OWNER as signer 403", { skip }, async () => {
  const cookieAG = await signInCookie(AG);
  let r = await req("POST", "/api/v1/wallet/v4/requests", { body: spendBody(AG), cookie: cookieAG });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  await req("POST", `/api/v1/wallet/v4/requests/${r.json.request.requestId}/reject`, { cookie: cookieAG });
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: { ...spendBody(AG), signerAddress: O.address }, cookie: cookieAG });
  assert.equal(r.status, 403); assert.equal(r.json.error.code, "SIGNER_NOT_PRINCIPAL");
});

test("OWNER may build for its own registered agent (documented owner-minted machine-credential flow), never for a stranger", { skip }, async () => {
  const cookieO = await signInCookie(O);
  let r = await req("POST", "/api/v1/wallet/v4/requests", { body: spendBody(AG), cookie: cookieO });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  await req("POST", `/api/v1/wallet/v4/requests/${r.json.request.requestId}/reject`, { cookie: cookieO });
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: { ...spendBody(AG), signerAddress: B.address }, cookie: cookieO });
  assert.equal(r.status, 403); assert.equal(r.json.error.code, "SIGNER_NOT_PARTICIPANT");
  r = await req("POST", "/api/v1/wallet/v4/create", { body: genesisBody(O), cookie: cookieO });
  assert.equal(r.status, 201, "own genesis still builds");
  await req("POST", `/api/v1/wallet/v4/requests/${r.json.request.requestId}/reject`, { cookie: cookieO });
  r = await req("POST", "/api/v1/wallet/v4/simulate", { body: spendBody(AG), cookie: cookieO });
  assert.equal(r.status, 200, JSON.stringify(r.json));
});

test("MACHINE credential minted by the OWNER builds agent spends (principal = owner) but not for strangers; a machine credential minted by B is foreign", { skip }, async () => {
  const cookieO = await signInCookie(O);
  const minted = await req("POST", "/api/v1/identities", { body: { label: "owner agent", scopes: ["request:build", "read:requests", "read:vaults"] }, cookie: cookieO });
  assert.equal(minted.status, 201);
  const token = minted.json.token || minted.json.credential?.token;
  const bearer = (body) => new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const r = http.request({ host: "127.0.0.1", port, method: "POST", path: "/api/v1/wallet/v4/requests", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, Host: `127.0.0.1:${port}` } }, (res) => { let buf = ""; res.on("data", (d) => (buf += d)); res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(buf) })); });
    r.on("error", reject); r.write(data); r.end();
  });
  let r = await bearer(spendBody(AG));
  assert.equal(r.status, 201, JSON.stringify(r.json));
  await req("POST", `/api/v1/wallet/v4/requests/${r.json.request.requestId}/reject`, { cookie: cookieO });
  r = await bearer({ ...spendBody(AG), signerAddress: B.address });
  assert.equal(r.status, 403); assert.equal(r.json.error.code, "SIGNER_NOT_PARTICIPANT");
});

test("FOREIGN B against O's live v4 vault and O's genesis request (audit L5 rows): agent-suspensions GET/POST 404, reconcile 404, agent reconcile 403; signature/submit/genesis-submit/reject of O's request 404 — nothing changes", { skip }, async () => {
  const cookieO = await signInCookie(O), cookieAG = await signInCookie(AG), cookieB = await signInCookie(B);
  let r = await req("GET", `/api/v1/vaults/${VAULT_ID}/agent-suspensions`, { cookie: cookieB });
  assert.equal(r.status, 404); assert.equal(r.json.error.code, "VAULT_NOT_FOUND");
  r = await req("POST", `/api/v1/vaults/${VAULT_ID}/agent-suspensions`, { body: { agentPk: AG.xonly, suspended: true }, cookie: cookieB });
  assert.equal(r.status, 404); assert.equal(r.json.error.code, "VAULT_NOT_FOUND");
  r = await req("POST", `/api/v1/vaults/${VAULT_ID}/reconcile`, { cookie: cookieB });
  assert.equal(r.status, 404); assert.equal(r.json.error.code, "VAULT_NOT_FOUND");
  r = await req("POST", `/api/v1/vaults/${VAULT_ID}/reconcile`, { cookie: cookieAG });
  assert.equal(r.status, 403, "an agent is a participant, not the owner: reconcile is an owner action");
  r = await req("GET", `/api/v1/vaults/${VAULT_ID}/agent-suspensions`, { cookie: cookieAG });
  assert.equal(r.status, 200, "a participant reads suspensions");
  r = await req("POST", "/api/v1/wallet/v4/create", { body: genesisBody(O), cookie: cookieO });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id = r.json.request.requestId;
  const unsigned = r.json.request.transaction.unsignedSafeJson;
  const bogus = JSON.stringify({ ...JSON.parse(unsigned), inputs: JSON.parse(unsigned).inputs.map((i) => ({ ...i, signatureScript: "41" + "00".repeat(65) })) });
  for (const [tail, body] of [["signature", { signedSafeJson: bogus }], ["submit", {}], ["genesis-submit", { signedSafeJson: bogus }], ["reject", {}], ["reconcile", {}]]) { // UX-05: reconcile joins the signer-only family
    r = await req("POST", `/api/v1/wallet/v4/requests/${id}/${tail}`, { body, cookie: cookieB });
    assert.equal(r.status, 404, `${tail}: ${JSON.stringify(r.json)}`);
  }
  // UX-05: the unresolved listing is scoped like every listing — the foreign tenant sees nothing of O's requests
  r = await req("GET", `/api/v1/wallet/v4/requests?unresolved=1`, { cookie: cookieB });
  assert.equal(r.status, 200); assert.deepEqual(r.json.requests, []);
  // UX-05: the agent on O's GENESIS request is not even a participant yet (non-oracle 404); the signer may reconcile a BUILT request (nothing to reconcile → its own state, no change)
  r = await req("POST", `/api/v1/wallet/v4/requests/${id}/reconcile`, { cookie: cookieAG });
  assert.equal(r.status, 404, JSON.stringify(r.json));
  r = await req("POST", `/api/v1/wallet/v4/requests/${id}/reconcile`, { cookie: cookieO });
  assert.equal(r.status, 200); assert.equal(r.json.outcome, "BUILT"); assert.equal(r.json.request.state, "BUILT");
  r = await req("GET", `/api/v1/wallet/v4/requests/${id}`, { cookie: cookieO });
  assert.equal(r.status, 200); assert.equal(r.json.request.state, "BUILT", "nothing changed for the foreign caller");
  r = await req("POST", `/api/v1/wallet/v4/requests/${id}/reject`, { cookie: cookieO });
  assert.equal(r.status, 200);
});

/* ---------------- rc13 internal review N-01 / N-02 (2026-09-05) ---------------- */

test("N-01: GET /vaults/:id/status for a LIVE v0.4.1 vault answers 200 to the owner and the agent (never a 500 from the v1 policy path); foreign B 404; unauthenticated 401", { skip }, async () => {
  const cookieO = await signInCookie(O), cookieAG = await signInCookie(AG), cookieB = await signInCookie(B);
  const net = await req("GET", "/api/v1/network/status");
  if (net.status !== 200) { console.log("# ENVIRONMENT: no reachable testnet-10 node — status route needs connectVerified; skipping the 200 assertions"); return; }
  let r = await req("GET", `/api/v1/vaults/${VAULT_ID}/status`);
  assert.equal(r.status, 401);
  r = await req("GET", `/api/v1/vaults/${VAULT_ID}/status`, { cookie: cookieB });
  assert.equal(r.status, 404); assert.equal(r.json.error.code, "VAULT_NOT_FOUND");
  r = await req("GET", `/api/v1/vaults/${VAULT_ID}/status`, { cookie: cookieO });
  assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.vaultId, VAULT_ID); assert.equal(typeof r.json.live?.chainConfirmed, "boolean", "chainConfirmed computed from the v0.4.1 covenant address");
  r = await req("GET", `/api/v1/vaults/${VAULT_ID}/status`, { cookie: cookieAG });
  assert.equal(r.status, 200, JSON.stringify(r.json));
});

test("N-02: only the request's SIGNER may reach a signature-bearing route — the vault's agent cannot burn the owner's request (403 NOT_THE_SIGNER, state BUILT); a malformed payload from the signer is a closed 400 BAD_SIGNATURE (state BUILT); foreign B 404", { skip }, async () => {
  const cookieO = await signInCookie(O), cookieAG = await signInCookie(AG), cookieB = await signInCookie(B);
  let r = await req("POST", "/api/v1/wallet/v4/create", { body: genesisBody(O), cookie: cookieO });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const gen = r.json.request.requestId;
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: spendBody(AG), cookie: cookieO });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const spend = r.json.request.requestId; // signer = AG, built by the owner
  // an OWNER action on the LIVE vault (the reviewer's removeAgent shape): signer = O, the agent AG is a vault participant
  r = await req("POST", "/api/v1/wallet/v4/requests", { body: { vaultId: VAULT_ID, action: "ownerPause", signerAddress: O.address, params: { fuel: spendBody(AG).params.fuel } }, cookie: cookieO });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const ownerOp = r.json.request.requestId;
  const stateOf = async (id, cookie) => (await req("GET", `/api/v1/wallet/v4/requests/${id}`, { cookie })).json.request.state;
  for (const bad of ['{"inputs":null}', "x", '{"inputs":[]}']) {
    // the agent on the OWNER's live-vault request: a participant, but NOT the signer
    r = await req("POST", `/api/v1/wallet/v4/requests/${ownerOp}/signature`, { body: { signedSafeJson: bad }, cookie: cookieAG });
    assert.equal(r.status, 403, JSON.stringify(r.json)); assert.equal(r.json.error.code, "NOT_THE_SIGNER");
    // the agent on the OWNER's GENESIS request: no vault exists yet, so the agent is not even a participant — non-oracle 404
    r = await req("POST", `/api/v1/wallet/v4/requests/${gen}/signature`, { body: { signedSafeJson: bad }, cookie: cookieAG });
    assert.equal(r.status, 404, JSON.stringify(r.json));
    r = await req("POST", `/api/v1/wallet/v4/requests/${gen}/genesis-submit`, { body: { signedSafeJson: bad }, cookie: cookieAG });
    assert.equal(r.status, 404);
    // the owner on the AGENT's spend request: not the signer either (the owner built it for its agent; only the agent signs)
    r = await req("POST", `/api/v1/wallet/v4/requests/${spend}/signature`, { body: { signedSafeJson: bad }, cookie: cookieO });
    assert.equal(r.status, 403); assert.equal(r.json.error.code, "NOT_THE_SIGNER");
    // the signer with a malformed payload: closed 400, nothing burned
    r = await req("POST", `/api/v1/wallet/v4/requests/${gen}/signature`, { body: { signedSafeJson: bad }, cookie: cookieO });
    assert.equal(r.status, 400, JSON.stringify(r.json)); assert.equal(r.json.error.code, "BAD_SIGNATURE");
    assert.doesNotMatch(String(r.json.error.message), /Cannot read|TypeError|undefined/);
    r = await req("POST", `/api/v1/wallet/v4/requests/${spend}/signature`, { body: { signedSafeJson: bad }, cookie: cookieAG });
    assert.equal(r.status, 400); assert.equal(r.json.error.code, "BAD_SIGNATURE");
    // foreign
    r = await req("POST", `/api/v1/wallet/v4/requests/${gen}/signature`, { body: { signedSafeJson: bad }, cookie: cookieB });
    assert.equal(r.status, 404);
  }
  assert.equal(await stateOf(gen, cookieO), "BUILT", "the owner's genesis request was never burned");
  assert.equal(await stateOf(ownerOp, cookieO), "BUILT", "the owner's live-vault request was never burned by its agent");
  assert.equal(await stateOf(spend, cookieAG), "BUILT", "the agent's spend request was never burned");
  await req("POST", `/api/v1/wallet/v4/requests/${ownerOp}/reject`, { cookie: cookieO });
  await req("POST", `/api/v1/wallet/v4/requests/${gen}/reject`, { cookie: cookieO });
  await req("POST", `/api/v1/wallet/v4/requests/${spend}/reject`, { cookie: cookieAG });
});
