"use strict";

/*
 * EXTERNAL COVENANT APPROVER DISCOVERY — PostgreSQL parity
 * (mainnet incident 2026-08-27; JSON twin:
 * external-approver-discovery.test.js, which carries the full rationale).
 *
 * The hosted production backend is PostgreSQL; the tenancy derivation
 * consumes loadAnyManifest's NORMALIZED manifests identically over both
 * stores, and this suite proves the same discovery/authority matrix over
 * a REAL PG store + real HTTP + hosted authentication:
 *   - external approver discovers vault + open request, reaches the
 *     approval route (inner verifier still decides);
 *   - approver-only principals get 403 on lifecycle mutation
 *     (reject / signature / submit) — never silently widened;
 *   - unrelated wallets keep the 404 non-oracle;
 *   - owner behavior unchanged.
 * Skips cleanly without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}.
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

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run external-approver PG parity";

function wallet(hexPair) {
  const priv = new kaspa.PrivateKey(hexPair.repeat(32));
  return {
    priv,
    compressed: priv.toPublicKey().toString().toLowerCase(),
    xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress("testnet-10").toString()
  };
}
const OWNER = wallet("a7");
const AGENT = wallet("b8");
const APPROVER = wallet("c9");
const OUTSIDER = wallet("d4");

const VID_A = "aa".repeat(32);
const REQ_OPEN = "a1000000-0000-4000-8000-000000000001";
const REQ_CANCEL = "a1000000-0000-4000-8000-000000000002";

let adminPool, server, port, config, store, dbName;

function rawManifest(vaultId, ownerXOnly, approverXOnlys, label) {
  const { computeStateIdV4, normalizeTemplateV4, normalizeStateV4 } = require("../src/vault-state-v4");
  const template = normalizeTemplateV4({ owner: ownerXOnly, vaultId });
  const state = normalizeStateV4({
    protectedValue: "1000000000", feeReserve: "100000000", paused: "0", policyNonce: "0",
    approvers: approverXOnlys, approvalM: String(approverXOnlys.length ? 1 : 0),
    agentRoot: "5c646a4a6876b59e313254411585f771fee77dba8d9e947d5bd4a777b2a1d7f8"
  });
  return {
    schema: "policyvault-vault-manifest/v4", contractVersion: "policyvault-0.4.1", networkId: "testnet-10",
    vaultId, label, status: "ACTIVE", template, agentRegistry: [],
    live: {
      state: {
        protectedValue: state.protectedValue.toString(), feeReserve: state.feeReserve.toString(),
        paused: state.paused.toString(), agentRoot: state.agentRoot, approverSlots: [...state.approvers],
        approvalM: state.approvalM.toString(), policyNonce: state.policyNonce.toString()
      },
      stateId: computeStateIdV4({ networkId: "testnet-10", template, state, contractVersion: "policyvault-0.4.1" }),
      outpoint: { transactionId: "ee".repeat(32), index: 0 }, outpointValue: "1100000000",
      scriptSha256: "ab".repeat(32), covenantId: "cd".repeat(32)
    },
    creationTxId: "12".repeat(32), latestTransitionTxId: null, lastTransition: null
  };
}

function requestRecord(requestId, vaultId, signerAddress) {
  return {
    schema: "policyvault-wallet-request/v4", requestId, vaultId,
    action: "agentSpend", state: "AWAITING_APPROVALS", signerAddress,
    aboveThreshold: true, review: { approvalsRequired: 1 },
    createdAt: new Date().toISOString()
  };
}

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_extappr_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-extappr-pg-"))
  });
  store = await openPgStore(config, { migrate: true });
  const { persistManifestV4 } = require("../src/manifest-v4");
  await persistManifestV4(config, rawManifest(VID_A, OWNER.xonly, [APPROVER.xonly], "approver vault (pg)"));
  const s = getStore(config);
  await s.write(Categories.REQUEST, REQ_OPEN, requestRecord(REQ_OPEN, VID_A, AGENT.address));
  await s.write(Categories.REQUEST, REQ_CANCEL, requestRecord(REQ_CANCEL, VID_A, AGENT.address));
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

function req(method, pathName, { body, cookie } = {}) {
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
    if (data !== undefined) r.write(data);
    r.end();
  });
}

async function signIn(w) {
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: w.address } });
  assert.equal(ch.status, 200, "challenge issued");
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed } });
  assert.equal(v.status, 200, "verified");
  return v.headers["set-cookie"][0].split(";")[0];
}

const S = {};

test("§EAP0 setup: sessions over the PG-backed server", { skip }, async () => {
  S.owner = await signIn(OWNER);
  S.approver = await signIn(APPROVER);
  S.outsider = await signIn(OUTSIDER);
});

test("§EAP1 PG parity: approver discovers the vault and the open request; outsider sees neither", { skip }, async () => {
  const v = await req("GET", "/api/v1/vaults", { cookie: S.approver });
  assert.ok((v.json.vaults || []).filter(Boolean).some((x) => x.vaultId === VID_A), "approver vault list contains the vault (PG)");
  const l = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.approver });
  assert.ok((l.json.requests || []).some((q) => q.requestId === REQ_OPEN), "approver inbox lists the open request (PG)");
  const g = await req("GET", `/api/v1/wallet/v4/requests/${REQ_OPEN}`, { cookie: S.approver });
  assert.equal(g.status, 200, "approver fetches the exact request by id (PG)");
  const xv = await req("GET", "/api/v1/vaults", { cookie: S.outsider });
  assert.ok(!(xv.json.vaults || []).filter(Boolean).some((x) => x.vaultId === VID_A), "outsider vault list stays empty (PG)");
  const xg = await req("GET", `/api/v1/wallet/v4/requests/${REQ_OPEN}`, { cookie: S.outsider });
  assert.equal(xg.status, 404, "outsider by-id stays a 404 non-oracle (PG)");
});

test("§EAP2 PG parity: approvals route reachable for the approver (inner verifier refusal, never the tenancy 404)", { skip }, async () => {
  const a = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/approvals`,
    { body: { approverAddress: APPROVER.address, signatureHex: "00".repeat(65) }, cookie: S.approver });
  assert.notEqual(a.status, 404, `gate must open for the approver (got ${a.status})`);
  assert.notEqual(a.json?.error?.code, "REQUEST_NOT_FOUND", "refusal is the verifier's");
  const x = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/approvals`,
    { body: { approverAddress: OUTSIDER.address, signatureHex: "00".repeat(65) }, cookie: S.outsider });
  assert.equal(x.status, 404, "outsider stays 404 (PG)");
});

test("§EAP3 PG parity: approver-only mutation refused (403); owner reject unchanged (200)", { skip }, async () => {
  const rej = await req("POST", `/api/v1/wallet/v4/requests/${REQ_CANCEL}/reject`, { body: {}, cookie: S.approver });
  assert.equal(rej.status, 403, `approver cannot reject (PG; got ${rej.status})`);
  const sig = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/signature`, { body: { signedSafeJson: "{}" }, cookie: S.approver });
  assert.equal(sig.status, 403, "approver cannot attach the spend signature (PG)");
  const sub = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/submit`, { body: {}, cookie: S.approver });
  assert.equal(sub.status, 403, "approver cannot submit (PG)");
  const o = await req("POST", `/api/v1/wallet/v4/requests/${REQ_CANCEL}/reject`, { body: {}, cookie: S.owner });
  assert.equal(o.status, 200, `owner reject unchanged (PG; got ${o.status} ${JSON.stringify(o.json)})`);
  assert.equal(o.json.request.state, "WALLET_REJECTED");
});
