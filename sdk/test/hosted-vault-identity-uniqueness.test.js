"use strict";
/*
 * API / HOSTED (real HTTP server over a REAL PostgreSQL store) — RC33-ID-01 GLOBAL VAULT-RECORD UNIQUENESS at the served
 * boundary (sdk/src/vault-identity.js; owner repair directive 2026-09-11).
 *
 * The reviewer's finding started at "real isolated HTTP accepts caller-supplied vaultId already pending/live" (checkpoint
 * 01/02). These checks drive the SAME routes through the real server: every route that forwards a caller-supplied
 * identity to a genesis builder (POST /org-roots/:id/vaults for the KAS / payment / HD profiles, POST /wallet/v4/create,
 * POST /wallet/v5/create) answers a closed 409 VAULT_ID_IN_USE for an identity held by ANY generation's record or by ANY
 * existing creation request, persists nothing, and discloses nothing about the other record; the signature route of a
 * genesis whose identity became occupied refuses with the same code and leaves the request BUILT; fresh identities
 * (server-generated or caller-supplied) still create; a foreign principal never reaches the uniqueness check (tenancy
 * first — the code is not an oracle across tenants).
 *
 * Skipped cleanly, never silently passed, without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} or the toolchain.
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
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const assets = require("../../core/assets");
const { compileKcc20Program } = require("../src/token-program-kcc20");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { covenantAddress } = require("../src/chain");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-hvid-probe-")) });
const TOOLCHAIN = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !TOOLCHAIN ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" : undefined;
const kaspa = TOOLCHAIN ? require(probe.rustyKaspaModule) : null;

const KAS = 100000000n;
const NET = "testnet-10";
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const hex32 = () => crypto.randomBytes(32).toString("hex");
function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { priv, compressed: priv.toPublicKey().toString().toLowerCase(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(NET).toString() };
}
function fuelUtxoFor(w, amount = 50n * KAS) {
  return { outpoint: { transactionId: hex32(), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${w.xonly}ac` };
}
function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, w] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, w.priv);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function mockRpc() {
  const table = {};
  return {
    async getUtxosByAddresses({ addresses }) { const entries = []; for (const a of addresses) for (const e of table[a] ?? []) entries.push(e); return { entries }; },
    async submitTransaction({ transaction }) { return { transactionId: transaction.finalize().toString().toLowerCase() }; },
    async disconnect() {},
    seed(address, entry) { table[address] = [...(table[address] ?? []), entry]; }
  };
}
const utxo = (address, txId, index, amount, covenantId) => ({ address, outpoint: { transactionId: txId, index }, amount: BigInt(amount), covenantId: covenantId ?? null });
const marker = (id) => ({ schema: "test-other-generation", vaultId: id, retained: "existing-record", secretLabel: "OTHER-TENANT-PRIVATE-LABEL" });

let A, A2, A3, B, AG, REC, AP1;
let adminPool, server, port, config, store, dbName, rpc, rootId, descriptor;

function kasPolicyFor(agent) {
  return { agentPk: agent.xonly, maxPerSpend: (5n * KAS).toString(), periodBudget: (20n * KAS).toString(), periodLengthDaa: "1000", periodStartDaa: "5000", periodSpent: "0", approvalThreshold: (2n * KAS).toString(), agentMaxFeePerTx: (KAS / 10n).toString(), recipients: [REC.xonly] };
}
function tokenPolicyFor(agent) {
  const rTree = buildRecipientTree([REC.xonly]);
  return { agentPk: agent.xonly, tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: rTree.root, recipients: [REC.xonly] };
}
async function driveOrgRootRequest(request, funder) {
  const signed = signAll(request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: request.id, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const addr = covenantAddress(config, Buffer.from(finalized.build.rootScriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, finalized.build.rootOutputIndex, finalized.build.accounting.kas.rootValue, finalized.rootCovenantId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

before(async () => {
  if (skip) return;
  A = wallet("a1"); A2 = wallet("a2"); A3 = wallet("a3"); B = wallet("b2"); AG = wallet("c7"); REC = wallet("e1"); AP1 = wallet("d1");
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_hvid_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-hvid-")),
    rateLimits: { auth: { limit: 100000 }, build: { limit: 100000 }, mutate: { limit: 100000 }, submit: { limit: 100000 } }
  });
  assert.equal(config.tenancyEnforced, true, "harness must be a HOSTED (tenancy-enforced) server");
  store = await openPgStore(config, { migrate: true });
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  rpc = mockRpc();
  const ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "HVID Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const rootReq = await wr7.buildRootGenesisRequest({
    config, label: "tenant A root",
    owners: [{ slot: 1, publicKey: A.xonly }, { slot: 2, publicKey: A2.xonly }, { slot: 3, publicKey: A3.xonly }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: A.address, funding: [fuelUtxoFor(A)]
  });
  rootId = (await driveOrgRootRequest(rootReq, A)).rootCovenantId;
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
    const r = http.request({ host: "127.0.0.1", port, method, path: `/api/v1${pathName}`, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, json: buf ? JSON.parse(buf) : null, raw: buf }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}
const code = (r) => r.json?.error?.code;
async function signInCookie(w) {
  const ch = await req("POST", "/auth/challenge", { body: { walletAddress: w.address } });
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: w.priv.toString() });
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ nonce: ch.json.challenge.nonce, signature, publicKey: w.compressed });
    const r = http.request({ host: "127.0.0.1", port, method: "POST", path: "/api/v1/auth/verify", headers: { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` } }, (res) => {
      let buf = ""; res.on("data", (d) => (buf += d)); res.on("end", () => { assert.equal(res.statusCode, 200, buf); resolve(res.headers["set-cookie"][0].split(";")[0]); });
    });
    r.on("error", reject); r.write(data); r.end();
  });
}
const cookies = {};
const asW = async (w) => (cookies[w.xonly] ??= await signInCookie(w));

const kasBody = (vaultId) => ({ profile: "policyvault-0.7-kas", label: "kas treasury", agents: [kasPolicyFor(AG)], approvers: [AP1.xonly], approvalM: 1, recoveryAddress: A.address, depositKas: "10", feeReserveKas: "1", signerAddress: A.address, funding: [fuelUtxoFor(A, 200n * KAS)], ...(vaultId ? { vaultId } : {}) });
const paymentBody = (vaultId) => ({ profile: "policyvault-0.7-payment", label: "rooted", descriptor, templateIndex: 0, agents: [tokenPolicyFor(AG)], recoveryAddress: A.address, depositKas: "0", feeReserveKas: "5", signerAddress: A.address, funding: [fuelUtxoFor(A)], ...(vaultId ? { vaultId } : {}) });
const hdBody = (vaultId) => ({ profile: "policyvault-0.7-payment-hd", label: "hd", descriptor, templateIndex: 0, agents: [{ pk: AG.xonly, maxPerSpend: "500", periodBudget: "2000", periodLengthDaa: "1000", periodStartDaa: "0", periodSpent: "0", maxFeePerTx: KAS.toString(), maxCarryKas: KAS.toString(), expiryDaa: "999999999", recipients: [REC.xonly] }], recoveryAddress: A.address, feeReserveKas: "5", signerAddress: A.address, funding: [fuelUtxoFor(A)], ...(vaultId ? { vaultId } : {}) });
const v4Body = (vaultId) => ({ contractVersion: "policyvault-0.4.1", templateInput: { owner: A.xonly, vaultId }, initialAgents: [], initialState: { protectedValue: "1000000000", feeReserve: "100000000", approvers: [], approvalM: "0" }, signerAddress: A.address, funding: [fuelUtxoFor(A, 5000n * KAS)], label: "v4" });
const v5Body = (vaultId) => ({ label: "ctl", descriptor, templateIndex: 0, initialAgents: [tokenPolicyFor(AG)], feeReserveKas: "5", signerAddress: A.address, funding: [fuelUtxoFor(A)], ...(vaultId ? { vaultId } : {}) });

async function requestRows() {
  const a = await store.pool().query(`SELECT count(*)::int AS n FROM wallet_requests`);
  const b = await store.pool().query(`SELECT count(*)::int AS n FROM org_root_requests`);
  return a.rows[0].n + b.rows[0].n;
}
function assertClosedRefusal(r, label) {
  assert.equal(r.status, 409, `${label}: ${r.raw}`);
  assert.equal(code(r), "VAULT_ID_IN_USE", label);
  assert.deepEqual(Object.keys(r.json).sort(), ["error"], `${label}: the refusal carries nothing but the error`);
  assert.deepEqual(Object.keys(r.json.error).sort(), ["code", "message"], `${label}: no request, no record, no other principal's data`);
  assert.doesNotMatch(r.raw, /OTHER-TENANT-PRIVATE-LABEL|test-other-generation|retained|existing-record/, `${label}: the other record's content is never disclosed`);
}

test("every rooted-vault profile of POST /org-roots/:id/vaults refuses a caller-supplied identity held by another generation's record with a closed 409 VAULT_ID_IN_USE, persists nothing and discloses nothing; a fresh identity still creates (201); the created draft's identity is then refused for every profile", { skip }, async () => {
  const cA = await asW(A);
  const occupied = hex32();
  const before = marker(occupied);
  await store.write(Categories.VAULT, occupied, before);
  const rows = await requestRows();
  for (const [label, body] of [["kas", kasBody(occupied)], ["payment", paymentBody(occupied)], ["hd", hdBody(occupied)]]) {
    assertClosedRefusal(await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body }), label);
  }
  assert.equal(await requestRows(), rows, "a refused creation persists no request");
  assert.deepEqual(await store.read(Categories.VAULT, occupied), before, "the other generation's record is untouched");
  /* fresh identities (server-generated) create */
  const created = await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body: kasBody() });
  assert.equal(created.status, 201, created.raw);
  const draftId = created.json.request.vaultId;
  assert.match(draftId, /^[0-9a-f]{64}$/);
  assert.equal(created.json.request.state, "BUILT");
  /* that draft's identity is reserved against every profile (a request in ANY state reserves its identity) */
  for (const [label, body] of [["kas", kasBody(draftId)], ["payment", paymentBody(draftId)], ["hd", hdBody(draftId)]]) {
    assertClosedRefusal(await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body }), `${label} vs the BUILT draft`);
  }
  /* an explicitly chosen UNUSED identity creates too */
  const chosen = hex32();
  const explicit = await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body: kasBody(chosen) });
  assert.equal(explicit.status, 201, explicit.raw);
  assert.equal(explicit.json.request.vaultId, chosen);
});

test("the signature route of a KAS genesis whose identity became occupied refuses 409 VAULT_ID_IN_USE before accepting the wallet's signature; the request stays BUILT with no signed bytes; the funder may still withdraw it", { skip }, async () => {
  const cA = await asW(A);
  const created = await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body: kasBody() });
  assert.equal(created.status, 201, created.raw);
  const request = created.json.request;
  const before = marker(request.vaultId);
  await store.write(Categories.VAULT, request.vaultId, before);
  const signed = signAll(request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, A]));
  assertClosedRefusal(await req("POST", `/wallet/v7/requests/${request.requestId}/signature`, { cookie: cA, body: { signedSafeJson: signed } }), "signature");
  const got = await req("GET", `/wallet/v7/requests/${request.requestId}`, { cookie: cA });
  assert.equal(got.status, 200, got.raw);
  assert.equal(got.json.request.state, "BUILT", "the request is untouched");
  assert.equal(got.json.request.signedSafeJson, undefined, "no signature was stored");
  assert.deepEqual(await store.read(Categories.VAULT, request.vaultId), before);
  const rejected = await req("POST", `/wallet/v7/requests/${request.requestId}/reject`, { cookie: cA, body: { reason: "withdrawn" } });
  assert.equal(rejected.status, 200, rejected.raw);
  assert.equal(rejected.json.request.state, "WALLET_REJECTED");
});

test("POST /wallet/v4/create (the mainnet production generation) and POST /wallet/v5/create refuse an occupied caller-supplied identity with a closed 409 and persist nothing; fresh identities create", { skip }, async () => {
  const cA = await asW(A);
  const occupied = hex32();
  const before = marker(occupied);
  await store.write(Categories.VAULT, occupied, before);
  const rows = await requestRows();
  assertClosedRefusal(await req("POST", "/wallet/v4/create", { cookie: cA, body: v4Body(occupied) }), "v4 create");
  assertClosedRefusal(await req("POST", "/wallet/v5/create", { cookie: cA, body: v5Body(occupied) }), "v5 create");
  assert.equal(await requestRows(), rows);
  assert.deepEqual(await store.read(Categories.VAULT, occupied), before);
  const v4 = await req("POST", "/wallet/v4/create", { cookie: cA, body: v4Body(hex32()) });
  assert.equal(v4.status, 201, v4.raw);
  assert.equal(v4.json.request.state, "BUILT");
  /* the v4 draft now reserves its identity for every other family too */
  assertClosedRefusal(await req("POST", "/wallet/v5/create", { cookie: cA, body: v5Body(v4.json.request.vaultId) }), "v5 vs the v4 draft");
  assertClosedRefusal(await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cA, body: kasBody(v4.json.request.vaultId) }), "kas vs the v4 draft");
  const v5 = await req("POST", "/wallet/v5/create", { cookie: cA, body: v5Body(hex32()) });
  assert.equal(v5.status, 201, v5.raw);
});

test("tenancy first: a foreign principal never reaches the uniqueness check — the same occupied identity under A's root answers 404 ROOT_NOT_FOUND (non-oracle) for B, and B's own controller creation with an occupied identity answers the same closed 409 it would for any identity", { skip }, async () => {
  const cB = await asW(B);
  const occupied = hex32();
  await store.write(Categories.VAULT, occupied, marker(occupied));
  const r = await req("POST", `/org-roots/${rootId}/vaults`, { cookie: cB, body: { ...kasBody(occupied), signerAddress: B.address, funding: [fuelUtxoFor(B, 200n * KAS)] } });
  assert.equal(r.status, 404, r.raw);
  assert.equal(code(r), "ROOT_NOT_FOUND");
  const own = await req("POST", "/wallet/v5/create", { cookie: cB, body: { ...v5Body(occupied), signerAddress: B.address, funding: [fuelUtxoFor(B)] } });
  assertClosedRefusal(own, "B's own creation");
});
