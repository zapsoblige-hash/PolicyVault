"use strict";

/*
 * PHASE F — HOSTILE MULTI-USER hosted-security review (directive §5–§10,
 * §15, §46/§47). Real server over HTTP + hosted authentication +
 * PostgreSQL backend (SKIPPED cleanly without POLICYVAULT_TEST_PG_*).
 *
 * Focus: the WALLET-REQUEST pipeline tenancy boundary. Phase C tenancy
 * gated the vault and organization routes, but the hosted wallet-request
 * READ / LIST / REJECT / mutate-by-id routes and the global GET /audit
 * feed were NOT tenant-scoped. This suite is written to assert the
 * SECURE (tenant-scoped) behavior; run against the pre-fix tree it
 * reproduces the cross-tenant read + mutation leak (Phase F finding
 * F-1/F-2), and against the fixed tree it passes.
 *
 * THREE INDEPENDENT LAYERS: authentication (which wallet) != tenancy
 * authorization (may this wallet SEE/EDIT this hosted object) != covenant
 * authority (did the right wallet SIGN the exact transaction). This suite
 * attacks layer 2 with cryptographically distinct wallets and REAL
 * foreign object ids; covenant authority (layer 3) is never exercised.
 *
 * Requests + audit events are seeded directly into the durable store
 * (the tenancy boundary is independent of how a request was built), then
 * attacked through the REAL HTTP routes with REAL Schnorr sessions.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");
const { openPgStore, Categories } = require("../src/store");
const {
  vaultAccessAllowed,
  requestAccessAllowed
} = require("../../server/src/tenancy");
const kaspa = require(loadConfig({}).rustyKaspaModule);

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run Phase F hostile tests";

function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return {
    priv,
    compressed: priv.toPublicKey().toString().toLowerCase(),
    xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(),
    address: priv.toPublicKey().toAddress("testnet-10").toString()
  };
}
// Cryptographically distinct identities (directive §5): tenant A, tenant
// B, outsider C, plus an agent + approver bound to A's world.
const A = wallet("a1");
const B = wallet("b2");
const C = wallet("c3");
const AGENT_A = wallet("a7");
const APPROVER_A = wallet("a9");

let adminPool, server, port, config, store, dbName;

// Seeded object ids (populated in before()).
const ID = {};
const vidA = "a".repeat(64);
const vidB = "b".repeat(64);
const vidB2 = "e".repeat(64);

function v4Request(signer, vaultId, state, extra = {}) {
  const requestId = crypto.randomUUID();
  return {
    requestId,
    schema: "policyvault-wallet-request/v4",
    vaultId,
    signerAddress: signer.address,
    state,
    review: { action: "agentSpend", payKas: "5", recipientAddress: "kaspatest:secret-recipient" },
    createdAt: new Date().toISOString(),
    ...extra
  };
}
function v2Request(signer, vaultId, state) {
  const requestId = crypto.randomUUID();
  return {
    requestId,
    schema: "policyvault-wallet-request/v2",
    vaultId,
    signerAddress: signer.address,
    state,
    review: { action: "spend", payKas: "3" },
    createdAt: new Date().toISOString()
  };
}

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_phasef_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres",
    pgHost: PG.host,
    pgPort: PG.port,
    pgUser: PG.user,
    pgDatabase: dbName,
    pgNoTls: true,
    authMode: "enabled",
    authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-phasef-"))
  });
  store = await openPgStore(config, { migrate: true });

  // Seed tenant-owned requests + audit events directly into the store.
  const rA = v4Request(A, vidA, "AWAITING_APPROVALS");
  const rB = v4Request(B, vidB, "AWAITING_APPROVALS");
  const rBrej = v4Request(B, vidB, "AWAITING_APPROVALS");
  const rB2 = v2Request(B, vidB2, "BUILT");
  ID.rA = rA.requestId;
  ID.rB = rB.requestId;
  ID.rBrej = rBrej.requestId;
  ID.rB2 = rB2.requestId;
  await store.write(Categories.REQUEST, rA.requestId, rA);
  await store.write(Categories.REQUEST, rB.requestId, rB);
  await store.write(Categories.REQUEST, rBrej.requestId, rBrej);
  await store.write(Categories.REQUEST, rB2.requestId, rB2);
  await store.appendAudit({ at: new Date().toISOString(), vaultId: vidA, kind: "chain", action: "agentSpend", txId: "a".repeat(64) });
  await store.appendAudit({ at: new Date().toISOString(), vaultId: vidB, kind: "chain", action: "agentSpend", txId: "b".repeat(64) });

  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(async () => {
  if (!PG_AVAILABLE) return;
  if (server) await new Promise((r) => server.close(r));
  if (store) await store.close();
  if (adminPool) {
    await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
    await adminPool.end();
  }
});

function req(method, pathName, { body, cookie, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const h = { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}`, ...headers };
    if (cookie) h.Cookie = cookie;
    const r = http.request({ host: "127.0.0.1", port, method, path: pathName, headers: h }, (res) => {
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
  assert.equal(ch.status, 200, "challenge issued");
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed } });
  assert.equal(v.status, 200, "verified");
  return v.headers["set-cookie"][0].split(";")[0];
}

/* ---------------- unit: the tenancy predicate itself ---------------- */

test("§F-unit request access = participant(vault) OR signer(request); default deny", { skip }, () => {
  const principalB = { xOnlyPubkey: B.xonly, networkId: "testnet-10" };
  const principalA = { xOnlyPubkey: A.xonly, networkId: "testnet-10" };
  const principalApprover = { xOnlyPubkey: APPROVER_A.xonly, networkId: "testnet-10" };
  // signer rule (no manifest, e.g. genesis): only the signer wallet.
  const rB = { signerAddress: B.address, vaultId: vidB };
  assert.equal(requestAccessAllowed(config, rB, principalB, null), true, "B is the request signer");
  assert.equal(requestAccessAllowed(config, rB, principalA, null), false, "A is neither signer nor participant");
  assert.equal(requestAccessAllowed(config, rB, null, null), false, "unauthenticated denied");
  // participant rule (manifest present): an approver (not the signer) of
  // the vault may access a request whose signer is the agent — mirrors
  // vault read tenancy exactly.
  const loadedVault = {
    version: "v4",
    manifest: {
      networkId: "testnet-10",
      template: { owner: A.xonly },
      agentRegistry: [{ policy: { agentPk: AGENT_A.xonly } }],
      live: { state: { approverSlots: [APPROVER_A.xonly, "00".repeat(32)] } }
    }
  };
  const rAgent = { signerAddress: AGENT_A.address, vaultId: vidA };
  assert.equal(vaultAccessAllowed(config, loadedVault, principalApprover, "read"), true, "approver reads the vault");
  assert.equal(requestAccessAllowed(config, rAgent, principalApprover, loadedVault), true, "approver reaches the agent's request via participant rule");
  assert.equal(requestAccessAllowed(config, rAgent, principalB, loadedVault), false, "B (foreign) denied even with the manifest");
});

/* ---------------- cross-tenant READ matrix (directive §7) ---------------- */

test("§F1 v4 open-request LIST is tenant-scoped (no cross-tenant leak, no vaultId oracle)", { skip }, async () => {
  const cookieA = await signIn(A);
  const listA = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: cookieA });
  assert.equal(listA.status, 200);
  const ids = listA.json.requests.map((r) => r.requestId);
  assert.ok(ids.includes(ID.rA), "A sees its own request");
  assert.ok(!ids.includes(ID.rB), "A does NOT see B's request in the open-request list");
  assert.ok(!ids.includes(ID.rBrej), "A does NOT see B's other request");
  // Naming B's vault in the query must not rescue the read (server scopes
  // by the authenticated principal, never by the client-supplied vaultId).
  const oracle = await req("GET", `/api/v1/wallet/v4/requests?open=1&vaultId=${vidB}`, { cookie: cookieA });
  assert.equal(oracle.status, 200);
  assert.equal(oracle.json.requests.length, 0, "A cannot list B's vault requests by naming B's vaultId");
});

test("§F2 v4 request DETAIL by id: foreign id 404 (existence hidden), own id 200", { skip }, async () => {
  const cookieA = await signIn(A);
  const foreign = await req("GET", `/api/v1/wallet/v4/requests/${ID.rB}`, { cookie: cookieA });
  assert.equal(foreign.status, 404, "A reading B's request id must 404");
  assert.ok(!(foreign.json && foreign.json.request), "no B request body leaks");
  const own = await req("GET", `/api/v1/wallet/v4/requests/${ID.rA}`, { cookie: cookieA });
  assert.equal(own.status, 200, "A reads its own request");
  assert.equal(own.json.request.requestId, ID.rA);
});

test("§F3 v2 request DETAIL by id: foreign id 404", { skip }, async () => {
  const cookieA = await signIn(A);
  const foreign = await req("GET", `/api/v1/wallet/requests/${ID.rB2}`, { cookie: cookieA });
  assert.equal(foreign.status, 404, "A reading B's v2 request id must 404");
});

test("§F4 outsider C (no relationship) sees nothing", { skip }, async () => {
  const cookieC = await signIn(C);
  const list = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: cookieC });
  assert.equal(list.status, 200);
  assert.equal(list.json.requests.length, 0, "C sees no requests");
  assert.equal((await req("GET", `/api/v1/wallet/v4/requests/${ID.rA}`, { cookie: cookieC })).status, 404);
  assert.equal((await req("GET", `/api/v1/wallet/v4/requests/${ID.rB}`, { cookie: cookieC })).status, 404);
});

test("§F5 unauthenticated caller cannot read the request pipeline", { skip }, async () => {
  assert.equal((await req("GET", "/api/v1/wallet/v4/requests?open=1")).status, 401);
  assert.equal((await req("GET", `/api/v1/wallet/v4/requests/${ID.rB}`)).status, 401);
  assert.equal((await req("GET", `/api/v1/wallet/requests/${ID.rB2}`)).status, 401);
});

/* ---------------- cross-tenant MUTATION matrix (directive §8) ---------------- */

test("§F6 A cannot REJECT (cancel) B's v4 request; B's durable state is unchanged", { skip }, async () => {
  const cookieA = await signIn(A);
  const before = await store.read(Categories.REQUEST, ID.rBrej);
  const attack = await req("POST", `/api/v1/wallet/v4/requests/${ID.rBrej}/reject`, { cookie: cookieA });
  assert.equal(attack.status, 404, "A rejecting B's request must 404");
  const afterRec = await store.read(Categories.REQUEST, ID.rBrej);
  assert.equal(afterRec.state, before.state, "B's request state is unchanged");
  assert.notEqual(afterRec.state, "WALLET_REJECTED", "B's request was NOT cancelled by A");
});

test("§F7 identity-source: a body/header claiming to be B cannot rescue A's foreign access", { skip }, async () => {
  const cookieA = await signIn(A);
  const spoofBody = { signerAddress: B.address, walletAddress: B.address, owner: B.xonly, tenantOwner: B.xonly };
  const spoofHeaders = { "X-Forwarded-For": "9.9.9.9", "CF-Connecting-IP": "9.9.9.9", "X-Real-IP": "9.9.9.9" };
  const r1 = await req("POST", `/api/v1/wallet/v4/requests/${ID.rB}/reject`, { cookie: cookieA, body: spoofBody, headers: spoofHeaders });
  assert.equal(r1.status, 404, "session principal is authoritative; body identity ignored");
  const r2 = await req("GET", `/api/v1/wallet/v4/requests/${ID.rB}`, { cookie: cookieA, headers: spoofHeaders });
  assert.equal(r2.status, 404, "spoofed proxy headers do not rebind identity");
});

test("§F8 positive control: B (the request signer) CAN read and reject its own request", { skip }, async () => {
  const cookieB = await signIn(B);
  assert.equal((await req("GET", `/api/v1/wallet/v4/requests/${ID.rB}`, { cookie: cookieB })).status, 200);
  const listB = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: cookieB });
  const ids = listB.json.requests.map((r) => r.requestId);
  assert.ok(ids.includes(ID.rB) && ids.includes(ID.rBrej), "B sees its own requests");
  assert.ok(!ids.includes(ID.rA), "B does not see A's request");
  // B legitimately cancels one of its own (mutation allowed for the owner).
  const rej = await req("POST", `/api/v1/wallet/v4/requests/${ID.rBrej}/reject`, { cookie: cookieB });
  assert.equal(rej.status, 200, "B rejects its own request");
});

/* ---------------- activity / audit (directive §7) ---------------- */

test("§F9 global GET /audit is tenant-scoped to the principal's vaults", { skip }, async () => {
  const cookieA = await signIn(A);
  const auditA = await req("GET", "/api/v1/audit", { cookie: cookieA });
  assert.equal(auditA.status, 200);
  const vaultIds = new Set(auditA.json.events.map((e) => e.vaultId));
  assert.ok(!vaultIds.has(vidB), "A's activity feed does NOT contain B's vault events");
  // unauthenticated has no feed
  assert.equal((await req("GET", "/api/v1/audit")).status, 401);
});

/* ---------------- auth-signature != tx-signature (directive §32) ----------------
 * No PG needed: a pure kaspa-wasm cryptographic-boundary check. A hosted
 * auth signature is a BIP-340 Schnorr signature over the keyed-blake2b
 * `PersonalMessageSigningHash` domain (rusty-kaspa hashers.rs:31); a
 * transaction input signature is Schnorr over the DISTINCT
 * `TransactionSigningHash` domain (hashers.rs:25, used by
 * consensus/core/src/hashing/sighash.rs). Distinct domain keys ⇒ the same
 * signature bytes cannot validate in both domains; an auth signature can
 * never authorize a covenant transaction (and no covenant SDK path even
 * reads the session — verified by grep in the Phase F review). Here we
 * prove the auth signature is message-bound and is an ordinary 64-byte
 * Schnorr signature (the SEPARATION is the domain, not the wire format). */
test("§F10 hosted auth signature is message-bound and domain-separated from tx signing", () => {
  const message = [
    "PolicyVault authentication",
    "origin: http://app.pv-test.example",
    "network: testnet-10",
    `address: ${A.address}`,
    "nonce: " + "a".repeat(64),
    "issued: 2026-08-25T00:00:00.000Z",
    "This signature only signs you in. It cannot move funds."
  ].join("\n");
  const sig = kaspa.signMessage({ message, privateKey: A.priv.toString() });
  assert.match(sig.toLowerCase(), /^[0-9a-f]{128}$/, "auth signature is a 64-byte Schnorr signature (same wire format as a tx sig)");
  assert.equal(kaspa.verifyMessage({ message, signature: sig, publicKey: A.xonly }), true, "verifies for the exact challenge message");
  // Message binding: a one-byte change to the signed content invalidates it
  // (the personal-message hash changed) — the signature is bound to its
  // exact domain input and cannot be re-pointed at other bytes.
  const tampered = message.replace("It cannot move funds.", "It CAN move funds.");
  assert.equal(kaspa.verifyMessage({ message: tampered, signature: sig, publicKey: A.xonly }), false, "does not verify over any other message");
  // Wrong key never verifies (identity binding).
  assert.equal(kaspa.verifyMessage({ message, signature: sig, publicKey: B.xonly }), false, "does not verify under a foreign key");
});
