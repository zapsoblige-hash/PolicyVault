"use strict";

/*
 * HOSTED MULTI-TENANT ISOLATION (Phase C, directive §35).
 *
 * Real server over HTTP + hosted authentication + PostgreSQL backend
 * (SKIPPED cleanly without POLICYVAULT_TEST_PG_*). Three wallets
 * (A/B/C), real Schnorr sign-in, real object ids. The hostile cases use
 * REAL VALID FOREIGN IDS (directive §34) — A authenticated + B's real
 * object id must DENY. Positive controls confirm legitimate access still
 * works. Covenant authority is never exercised here: this proves the
 * hosted TENANCY layer, independently of covenant signing.
 *
 * AUTHENTICATION != TENANCY AUTHORIZATION != COVENANT AUTHORITY.
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
const A = wallet("a1"), B = wallet("b2"), C = wallet("c3");

let adminPool, server, port, config, store, dbName;

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_tenancy_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ten-"))
  });
  store = await openPgStore(config, { migrate: true });
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
    if (data) r.write(data);
    r.end();
  });
}

/* Sign in a wallet, return its session cookie. */
async function signIn(w) {
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: w.address } });
  assert.equal(ch.status, 200, "challenge issued");
  const message = ch.json.challenge.message;
  const signature = kaspa.signMessage({ message, privateKey: w.priv.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed } });
  assert.equal(v.status, 200, "verified");
  return v.headers["set-cookie"][0].split(";")[0];
}

/* Create an organization as a wallet; return its id. */
async function createOrg(cookie, name) {
  const r = await req("POST", "/api/v1/organizations", { body: { name }, cookie });
  assert.equal(r.status, 201, `org created (${JSON.stringify(r.json)})`);
  return r.json.organization.orgId;
}

test("§C1 setup: A and B each sign in and own an organization; C signs in with none", { skip }, async () => {
  const cookieA = await signIn(A);
  const cookieB = await signIn(B);
  const orgA = await createOrg(cookieA, "A org");
  const orgB = await createOrg(cookieB, "B org");
  assert.match(orgA, /^[0-9a-f-]{36}$/);
  assert.notEqual(orgA, orgB);
  // stash on the module for later cases
  test.orgA = orgA;
  test.orgB = orgB;
  test.cookieA = cookieA;
  test.cookieB = cookieB;
  test.cookieC = await signIn(C);
});

test("§C2 org read isolation: A sees only A's org in the list; cannot GET B's org (404 hides existence)", { skip }, async () => {
  const list = await req("GET", "/api/v1/organizations", { cookie: test.cookieA });
  assert.equal(list.status, 200);
  const ids = list.json.organizations.map((o) => o.orgId);
  assert.ok(ids.includes(test.orgA), "A sees A's org");
  assert.ok(!ids.includes(test.orgB), "A does NOT see B's org");
  // A fetching B's REAL org id -> 404 (not 403; no existence oracle).
  const foreign = await req("GET", `/api/v1/organizations/${test.orgB}`, { cookie: test.cookieA });
  assert.equal(foreign.status, 404);
});

test("§C3 org mutation isolation: A cannot rename/archive/restore/delete B's org", { skip }, async () => {
  for (const action of ["rename", "archive", "restore", "delete"]) {
    const r = await req("POST", `/api/v1/organizations/${test.orgB}/${action}`, { body: { name: "hijacked", expectedVersion: 1 }, cookie: test.cookieA });
    assert.equal(r.status, 404, `A ${action} B's org must 404`);
  }
  // B's org is untouched.
  const asB = await req("GET", `/api/v1/organizations/${test.orgB}`, { cookie: test.cookieB });
  assert.equal(asB.status, 200);
  assert.equal(asB.json.organization.name, "B org");
});

test("§C4 org membership isolation: A cannot add/remove members in B's org", { skip }, async () => {
  const add = await req("POST", `/api/v1/organizations/${test.orgB}/members`, { body: { displayName: "mole", roles: [], expectedVersion: 1 }, cookie: test.cookieA });
  assert.equal(add.status, 404);
  // Even C (authenticated, unrelated) cannot.
  const addC = await req("POST", `/api/v1/organizations/${test.orgB}/members`, { body: { displayName: "mole", roles: [], expectedVersion: 1 }, cookie: test.cookieC });
  assert.equal(addC.status, 404);
});

test("§C5 request-body cannot rebind identity: a walletAddress field in the body does not make A act as B", { skip }, async () => {
  // The principal comes ONLY from the session cookie; a body field is ignored.
  const r = await req("POST", `/api/v1/organizations/${test.orgB}/rename`, { body: { name: "x", expectedVersion: 1, walletAddress: B.address, xOnlyPubkey: B.xonly }, cookie: test.cookieA });
  assert.equal(r.status, 404, "body identity is never trusted");
});

test("§C6 unauthenticated access is refused when tenancy is enforced", { skip }, async () => {
  const noCookie = await req("GET", "/api/v1/organizations");
  assert.equal(noCookie.status, 401);
  const orgNoCookie = await req("GET", `/api/v1/organizations/${test.orgA}`);
  assert.equal(orgNoCookie.status, 401);
});

test("§C7 positive control: legitimate owner retains full access to their own org", { skip }, async () => {
  const get = await req("GET", `/api/v1/organizations/${test.orgA}`, { cookie: test.cookieA });
  assert.equal(get.status, 200);
  const rename = await req("POST", `/api/v1/organizations/${test.orgA}/rename`, { body: { name: "A renamed", expectedVersion: 1 }, cookie: test.cookieA });
  assert.equal(rename.status, 200);
  assert.equal(rename.json.organization.name, "A renamed");
});

test("§C8 vault isolation: a foreign vault id is 404 for a non-participant, readable for a participant", { skip }, async () => {
  // Seed a v4 vault owned (covenant) by wallet B directly in the store.
  const { persistManifestV4 } = require("../src/manifest-v4");
  const { computeStateIdV4, normalizeTemplateV4, normalizeStateV4 } = require("../src/vault-state-v4");
  const VID = "dd".repeat(32);
  const template = normalizeTemplateV4({ owner: B.xonly, vaultId: VID });
  const state = normalizeStateV4({
    protectedValue: "1000000000", feeReserve: "100000000", paused: "0", policyNonce: "0",
    periodStartDaa: "1000", approvers: [], approvalM: "0", agentRoot: "5c646a4a6876b59e313254411585f771fee77dba8d9e947d5bd4a777b2a1d7f8"
  });
  await persistManifestV4(config, {
    schema: "policyvault-vault-manifest/v4", contractVersion: "policyvault-0.4.1", networkId: "testnet-10",
    vaultId: VID, label: "B vault", status: "ACTIVE", template, agentRegistry: [],
    live: {
      state: {
        protectedValue: state.protectedValue.toString(), feeReserve: state.feeReserve.toString(),
        paused: state.paused.toString(), agentRoot: state.agentRoot, approverSlots: [...state.approvers],
        approvalM: state.approvalM.toString(), policyNonce: state.policyNonce.toString()
      },
      stateId: computeStateIdV4({ networkId: "testnet-10", template, state, contractVersion: "policyvault-0.4.1" }),
      outpoint: { transactionId: "ee".repeat(32), index: 0 }, outpointValue: "1100000000", scriptSha256: "ab".repeat(32), covenantId: "cd".repeat(32)
    },
    creationTxId: "12".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
  // A (non-participant) GET of B's real vault id -> 404.
  const asA = await req("GET", `/api/v1/vaults/${VID}`, { cookie: test.cookieA });
  assert.equal(asA.status, 404, "non-participant cannot read the vault");
  // A cannot reconcile B's vault (owner action) -> 404.
  const recon = await req("POST", `/api/v1/vaults/${VID}/reconcile`, { cookie: test.cookieA });
  assert.equal(recon.status, 404);
  // B (covenant owner) CAN read it.
  const asB = await req("GET", `/api/v1/vaults/${VID}`, { cookie: test.cookieB });
  assert.equal(asB.status, 200);
  assert.equal(asB.json.vaultId, VID);
  // The vault list for A does not include B's vault.
  const listA = await req("GET", "/api/v1/vaults", { cookie: test.cookieA });
  assert.ok(!listA.json.vaults.some((v) => v && v.vaultId === VID), "A's vault list excludes B's vault");
});

test("§C9 vault->org assignment isolation: A cannot pull B's vault into A's org", { skip }, async () => {
  const VID = "dd".repeat(32); // B's vault from §C8
  const assign = await req("POST", `/api/v1/organizations/${test.orgA}/vaults`, { body: { vaultId: VID, expectedVersion: 1 }, cookie: test.cookieA });
  assert.ok(assign.status === 404 || assign.status === 403, `A must not assign B's vault (got ${assign.status})`);
});

test("§C10 org role is not covenant authority: an org 'owner'-labeled member gains no signing power", { skip }, async () => {
  // Add C as a member of A's org with the strongest role label.
  const add = await req("POST", `/api/v1/organizations/${test.orgA}/members`,
    { body: { displayName: "C", address: C.address, roles: ["owner", "approver"], expectedVersion: 2 }, cookie: test.cookieA });
  assert.equal(add.status, 201, `member added (${JSON.stringify(add.json)})`);
  // C can now READ A's org (wallet member) ...
  const read = await req("GET", `/api/v1/organizations/${test.orgA}`, { cookie: test.cookieC });
  assert.equal(read.status, 200, "wallet member reads the org");
  // ... but CANNOT mutate it (not the tenant owner) despite the 'owner' LABEL.
  const rename = await req("POST", `/api/v1/organizations/${test.orgA}/rename`, { body: { name: "C takeover", expectedVersion: 3 }, cookie: test.cookieC });
  assert.equal(rename.status, 403, "org role label grants NO mutation authority");
  // The label is application metadata; it never becomes covenant authority
  // (covenant signing is validated independently and is not exercised here).
});

test("§C11 session cannot be reused across identities: B's cookie never acts as A", { skip }, async () => {
  const get = await req("GET", `/api/v1/organizations/${test.orgA}`, { cookie: test.cookieB });
  assert.equal(get.status, 404, "B's session cannot reach A's org");
});
