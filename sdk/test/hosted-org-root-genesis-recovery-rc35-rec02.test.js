"use strict";
/*
 * API / HOSTED (real HTTP server over a REAL PostgreSQL store) — RC35-REC-02 principal access before any root ACL exists
 * (independent RC35 affected review, 2026-09-11; owner repair directive of the same day).
 *
 * A root genesis whose node response was lost has NO root record, so no root ACL exists yet. The recovery route is the
 * SAME public submit entry (POST /org-roots/:rootId/requests/:id/submit): hosted tenancy scopes a pending genesis request
 * to ITS CREATOR (tenancy.orgRootRequestMutationAllowed with a null root) — a foreign principal receives the non-oracle
 * 404 before any lock, node call or durable write; the creator reaches the observation-only recovery (which, on the real
 * testnet-10 node where this synthetic genesis never existed, stays truthfully RECONCILIATION_REQUIRED with the claim,
 * txid and signed bytes preserved — nothing is rebroadcast). POST /org-roots/:rootId/reconcile stays root-scoped (404
 * without a root record): hosted recovery of a missing root goes through the creator's submit route only.
 *
 * Skipped cleanly, never silently passed, without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} or the toolchain; the
 * creator's live-node subtest is skipped (and reported) when the local testnet-10 node is not reachable.
 */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { openPgStore, Categories } = require("../src/store");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const { covenantAddress, connectVerified } = require("../src/chain");
const { answers, scriptedRpc } = require("./helpers/rc35-recovery-fixtures");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-hrec02-probe-")) });
const TOOLCHAIN = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !TOOLCHAIN ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" : undefined;
const kaspa = TOOLCHAIN ? require(probe.rustyKaspaModule) : null;

const KAS = 100000000n;
const NET = "testnet-10";
function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { priv, compressed: priv.toPublicKey().toString().toLowerCase(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(NET).toString() };
}
const hex32 = () => require("node:crypto").randomBytes(32).toString("hex");
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

let A, A2, A3, B;
let adminPool, server, port, config, store, dbName, rpc, nodeUp = false;

before(async () => {
  if (skip) return;
  A = wallet("a1"); A2 = wallet("a2"); A3 = wallet("a3"); B = wallet("b2");
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_hrec02_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-hrec02-")),
    rateLimits: { auth: { limit: 100000 }, build: { limit: 100000 }, mutate: { limit: 100000 }, submit: { limit: 100000 } }
  });
  assert.equal(config.tenancyEnforced, true, "harness must be a HOSTED (tenancy-enforced) server");
  store = await openPgStore(config, { migrate: true });
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  rpc = mockRpc();
  try {
    const live = await connectVerified(config);
    await live.rpc.disconnect();
    nodeUp = true;
  } catch {
    nodeUp = false; // the creator's live-node subtest is skipped and reported
  }
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

test("hosted REC-02: a root genesis with a LOST node response (no root record) is reachable ONLY by its creator — a foreign principal gets the non-oracle 404 at GET and at submit (no lock, no node call, no write); the root-scoped reconcile route stays 404 without a root; the creator's submit reaches the observation-only recovery on the real node and keeps the request, claim, txid and signed bytes when the output is not observed", { skip }, async (t) => {
  const cA = await asW(A);
  const cB = await asW(B);
  /* the creator's pending root genesis, signed, then broadcast with a LOST response (the mock node accepted; the output landed on that node view) */
  const r = await wr7.buildRootGenesisRequest({
    config, label: "tenant A root (lost response)",
    owners: [{ slot: 1, publicKey: A.xonly }, { slot: 2, publicKey: A2.xonly }, { slot: 3, publicKey: A3.xonly }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: A.address, funding: [fuelUtxoFor(A)]
  });
  const signed = await wr7.submitOrgRootRequestSignature({ config, requestId: r.id, signedSafeJson: signAll(r.transaction.unsignedSafeJson, r.transaction.signInputs.map((s) => [s.index, A])) });
  assert.equal(signed.state, "SIGNED");
  const addr = covenantAddress(config, Buffer.from(signed.build.rootScriptHex, "hex"));
  const s = scriptedRpc(rpc);
  s.answers.push({ before: () => rpc.seed(addr, utxo(addr, signed.txId, signed.build.rootOutputIndex, signed.build.accounting.kas.rootValue, signed.rootCovenantId)), throw: answers.transportLost() });
  await assert.rejects(() => wr7.submitOrgRootRequest({ config, requestId: r.id, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(s.calls, 1);
  const pending = await wr7.loadOrgRootRequest(config, r.id);
  assert.equal(pending.state, "RECONCILIATION_REQUIRED");
  assert.ok(await store.read(Categories.SUBMISSION_CLAIM, signed.txId), "claim held");
  assert.equal(await wr7.loadOrgRoot(config, signed.rootCovenantId), null, "no root record, hence no root ACL yet");
  const rootId = signed.rootCovenantId;
  /* foreign principal: non-oracle 404 everywhere — before any lock, node call or write */
  const rowsBefore = (await store.pool().query(`SELECT count(*)::int AS n FROM org_root_requests`)).rows[0].n;
  for (const [label, r1] of [["GET request", await req("GET", `/org-roots/${rootId}/requests/${r.id}`, { cookie: cB })], ["submit", await req("POST", `/org-roots/${rootId}/requests/${r.id}/submit`, { cookie: cB })], ["GET root", await req("GET", `/org-roots/${rootId}`, { cookie: cB })], ["reconcile", await req("POST", `/org-roots/${rootId}/reconcile`, { cookie: cB })]]) {
    assert.equal(r1.status, 404, `${label}: ${r1.raw}`);
    assert.doesNotMatch(r1.raw, new RegExp(signed.txId), `${label}: nothing about the request is disclosed`);
  }
  assert.equal((await store.pool().query(`SELECT count(*)::int AS n FROM org_root_requests`)).rows[0].n, rowsBefore);
  const untouched = await wr7.loadOrgRootRequest(config, r.id);
  assert.equal(untouched.state, "RECONCILIATION_REQUIRED");
  assert.equal(untouched.updatedAt, pending.updatedAt, "a foreign principal never touches the request");
  /* an anonymous caller is refused too */
  assert.equal((await req("POST", `/org-roots/${rootId}/requests/${r.id}/submit`)).status, 401);
  /* the creator can read the pending genesis; the root-scoped reconcile route stays 404 without a root record (documented: hosted recovery of a missing root goes through the creator's submit) */
  const mine = await req("GET", `/org-roots/${rootId}/requests/${r.id}`, { cookie: cA });
  assert.equal(mine.status, 200, mine.raw);
  assert.equal(mine.json.request.state, "RECONCILIATION_REQUIRED");
  assert.equal((await req("POST", `/org-roots/${rootId}/reconcile`, { cookie: cA })).status, 404);
  /* the creator's submit reaches the observation-only recovery on the REAL node (this synthetic genesis never existed there) */
  await t.test("creator submit on the live testnet-10 node: recovery is reached, nothing observed, nothing rebroadcast, everything preserved", { skip: nodeUp ? undefined : "local testnet-10 node not reachable (ws://127.0.0.1:18210) — creator live-node subtest skipped" }, async () => {
    const res = await req("POST", `/org-roots/${rootId}/requests/${r.id}/submit`, { cookie: cA });
    assert.equal(res.status, 409, res.raw);
    assert.equal(code(res), "RECONCILIATION_REQUIRED");
    const after = await wr7.loadOrgRootRequest(config, r.id);
    assert.equal(after.state, "RECONCILIATION_REQUIRED");
    assert.equal(after.txId, signed.txId);
    assert.equal(after.signedSafeJson, signed.signedSafeJson);
    assert.ok(await store.read(Categories.SUBMISSION_CLAIM, signed.txId), "claim still held");
    assert.equal(await wr7.loadOrgRoot(config, rootId), null, "no record is invented");
  });
  /* control: the SDK-level recovery on the node view where the output landed completes the same request (creator path semantics) */
  const done = await wr7.submitOrgRootRequest({ config, requestId: r.id, rpc: s.rpc, pollAttempts: 1, pollDelayMs: 0 });
  assert.equal(done.state, "CHAIN_VERIFIED");
  assert.equal(s.calls, 1, "never rebroadcast");
  const root = await wr7.loadOrgRoot(config, rootId);
  assert.ok(root);
  assert.equal(root.live.outpoint.transactionId, signed.txId);
  /* once the root exists its ACL applies: the creator (an owner slot) reads it; the stranger still gets 404 */
  assert.equal((await req("GET", `/org-roots/${rootId}`, { cookie: cA })).status, 200);
  assert.equal((await req("GET", `/org-roots/${rootId}`, { cookie: cB })).status, 404);
});
