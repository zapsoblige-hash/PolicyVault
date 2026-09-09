"use strict";

/*
 * PERMANENT REGRESSION — rc11 internal security review F-04 (2026-09-04),
 * owner addendum §E GATE 1: the FOREIGN-TENANT HOSTILE PROBE for every
 * hosted tenant-owned route family that the audit found unscoped:
 *   /org-roots/*        (principal was resolved then DISCARDED — `void principal`)
 *   /wallet/v7/*        (same dispatcher)
 *   /wallet/v5|v6/*     (dispatched WITHOUT the request context — no auth at all)
 *
 * RED before the fix (docs/postlaunch/audit-evidence/rc11-internal-review/
 * logs/tenancy-probe.json T2–T18, live-probe.json L3a–L3e on a REAL
 * testnet-10 root): a foreign session listed every root and request, read
 * a live root's owner set/outpoint/nonce, drove a foreign genesis request
 * to SIGNED with a bogus signature, submitted / rejected foreign requests,
 * and LOCKED a live root by building a root action that named the owner
 * as signer; v5/v6 were reachable unauthenticated end to end.
 *
 * Contract pinned here (server/src/tenancy.js org-root / any-vault resolvers,
 * server/src/org-roots.js, server/src/wallet-token-surface.js):
 *   - hosted mode REQUIRES a principal on every route of these families;
 *   - authority derives ONLY from durable covenant facts: the root record's
 *     ACTIVE owner slots (+ pinned successor, read-only except succession),
 *     the vault manifest's agents, the request's own creator/signer;
 *   - the initiating signer of every build is BOUND to the principal
 *     (an active owner may build for its vault's registered agents);
 *   - a slot signing request / slot signature is bound to that slot's key;
 *   - foreign objects answer the non-oracle 404; a participant without the
 *     required authority gets 403; NOTHING is persisted or locked for a
 *     foreign caller; the same-tenant path is ACCEPTED (201/200).
 * Real server over HTTP + hosted authentication + PostgreSQL; fixtures are
 * driven to CHAIN_VERIFIED against a mock RPC in the SAME database (skipped
 * cleanly without POLICYVAULT_TEST_PG_*; REQUIREMENT_NOT_AVAILABLE without
 * the toolchain).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { ENCODER_PATH } = require("../src/vault-builders-v4");
const wr7 = require("../src/wallet-requests-v7");
const wr5 = require("../src/wallet-requests-v5");
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
const probe = loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ftm-probe-")) });
const TOOLCHAIN = fs.existsSync(probe.silvercPath) && fs.existsSync(ENCODER_PATH) && fs.existsSync(path.join(probe.repoRoot, "tests/vm/target/debug/pv_tx_probe"));
const skip = !PG_AVAILABLE ? "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}" : !TOOLCHAIN ? "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe" : undefined;
const kaspa = TOOLCHAIN ? require(probe.rustyKaspaModule) : null;

const KAS = 100000000n;
const NET = "testnet-10";
function wallet(hex) {
  const priv = new kaspa.PrivateKey(hex.repeat(32));
  return { priv, compressed: priv.toPublicKey().toString().toLowerCase(), xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(NET).toString() };
}
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
function fuelUtxoFor(w, amount = 50n * KAS) {
  return { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, amount: amount.toString(), scriptPublicKeyHex: `20${w.xonly}ac` };
}
function signAll(unsignedSafeJson, entries) {
  const tx = kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson);
  const ins = tx.inputs;
  for (const [i, w] of entries) ins[i].signatureScript = kaspa.createInputSignature(tx, i, w.priv);
  tx.inputs = ins;
  return tx.serializeToSafeJSON();
}
function sign65(unsignedSafeJson, index, w) {
  return kaspa.createInputSignature(kaspa.Transaction.deserializeFromSafeJSON(unsignedSafeJson), index, w.priv).slice(2);
}
/* a "signed" Safe JSON that keeps every consensus field but carries a BOGUS 66-byte signature script per input (audit T7 / T16) */
function bogusSigned(unsignedSafeJson) {
  const t = JSON.parse(unsignedSafeJson);
  t.inputs = t.inputs.map((i) => ({ ...i, signatureScript: "41" + "00".repeat(65) }));
  return JSON.stringify(t);
}
function mockRpc() {
  const table = {};
  return {
    async getUtxosByAddresses({ addresses }) {
      const entries = [];
      for (const a of addresses) for (const e of table[a] ?? []) entries.push(e);
      return { entries };
    },
    async submitTransaction({ transaction }) {
      return { transactionId: transaction.finalize().toString().toLowerCase() };
    },
    async disconnect() {},
    seed(address, entry) {
      table[address] = [...(table[address] ?? []), entry];
    }
  };
}
const utxo = (address, txId, index, amount, covenantId) => ({ address, outpoint: { transactionId: txId, index }, amount: BigInt(amount), covenantId: covenantId ?? null });

/* tenants: A / A2 / A3 = active owner slots of root R (M=2); S = pinned successor;
 * AG7 = agent of the rooted payment vault; AG5 = agent of A's v5 controller;
 * B = a foreign wallet; REC = recipient key */
let A, A2, A3, S, AG7, AG5, B, REC, FUEL;
let adminPool, server, port, config, store, dbName, rpc;
let descriptor, ref;
let rootId, v7VaultId, v5VaultId;

function policyFor(agent) {
  const rTree = buildRecipientTree([REC.xonly]);
  return { agentPk: agent.xonly, tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: (1n * KAS).toString(), agentMaxCarryKas: KAS.toString(), agentRecipientRoot: rTree.root, recipients: [REC.xonly] };
}
async function driveOrgRootRequest(request, funder) {
  const signed = signAll(request.transaction.unsignedSafeJson, request.transaction.signInputs.map((s) => [s.index, funder]));
  const finalized = await wr7.submitOrgRootRequestSignature({ config, requestId: request.id, signedSafeJson: signed });
  assert.equal(finalized.state, "SIGNED");
  const scriptHex = finalized.build.rootScriptHex ?? finalized.build.vaultScriptHex;
  const outIndex = finalized.build.rootOutputIndex ?? finalized.build.vaultOutputIndex;
  const covId = finalized.build.covenantId ?? finalized.rootCovenantId;
  const value = finalized.build.accounting?.kas?.rootValue ?? finalized.build.initialState.feeReserve;
  const addr = covenantAddress(config, Buffer.from(scriptHex, "hex"));
  rpc.seed(addr, utxo(addr, finalized.txId, outIndex, value, covId));
  const submitted = await wr7.submitOrgRootRequest({ config, requestId: request.id, rpc });
  assert.equal(submitted.state, "CHAIN_VERIFIED");
  return submitted;
}

async function createOwnerRoot(label) {
  const rootReq = await wr7.buildRootGenesisRequest({
    config, label,
    owners: [{ slot: 1, publicKey: A.xonly }, { slot: 2, publicKey: A2.xonly }, { slot: 3, publicKey: A3.xonly }],
    ownerM: 2, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: S.address,
    rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: A.address, funding: [fuelUtxoFor(A)]
  });
  return (await driveOrgRootRequest(rootReq, A)).rootCovenantId;
}

before(async () => {
  if (skip) return;
  A = wallet("a1"); A2 = wallet("a2"); A3 = wallet("a3"); S = wallet("a5"); AG7 = wallet("c7"); AG5 = wallet("c5"); B = wallet("b2"); REC = wallet("e1"); FUEL = wallet("f1");
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  dbName = `pv_ftm_${process.pid}`;
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true, dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-ftm-"))
  });
  assert.equal(config.tenancyEnforced, true, "harness must be a HOSTED (tenancy-enforced) server");
  store = await openPgStore(config, { migrate: true });
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  rpc = mockRpc();

  ref = compileKcc20Program({ config, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "FTM Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };

  /* LIVE org root R: owners A/A2/A3 (M=2), successor S, funded by A */
  rootId = await createOwnerRoot("tenant A root");

  /* LIVE rooted payment vault under R with agent AG7 */
  const vaultReq = await wr7.buildRootedVaultGenesisRequest({
    config, rootCovenantId: rootId, label: "rooted treasury", descriptor, templateIndex: 0,
    agents: [policyFor(AG7)], recoveryAddress: A.address, depositKas: "0", feeReserveKas: "5", signerAddress: A.address, funding: [fuelUtxoFor(A)]
  });
  v7VaultId = (await driveOrgRootRequest(vaultReq, A)).build.template.vaultId;

  /* LIVE v5 controller owned by A with agent AG5 */
  const v5Req = await wr5.buildCreateWalletRequestV5({ config, label: "A controller", descriptor, templateIndex: 0, initialAgents: [policyFor(AG5)], feeReserveKas: "5", signerAddress: A.address, funding: [fuelUtxoFor(A)] });
  const v5Signed = signAll(v5Req.transaction.unsignedSafeJson, v5Req.transaction.signInputs.map((s) => [s.index, A]));
  const v5Final = await wr5.submitSignatureV5({ config, requestId: v5Req.requestId, signedSafeJson: v5Signed });
  const v5Addr = covenantAddress(config, Buffer.from(v5Final.build.controllerScriptHex, "hex"));
  rpc.seed(v5Addr, utxo(v5Addr, v5Final.txId, v5Final.build.controllerOutputIndex, v5Final.build.initialState.feeReserve, v5Final.build.covenantId));
  v5VaultId = (await wr5.submitWalletRequestV5({ config, requestId: v5Req.requestId, rpc })).vaultId;
});

after(async () => {
  if (skip) return;
  if (server) await new Promise((r) => server.close(r));
  if (store) await store.close();
  if (adminPool) { await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {}); await adminPool.end(); }
});

function req(method, pathName, { body, cookie, bearer } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Origin: `http://127.0.0.1:${port}`, Host: `127.0.0.1:${port}` };
    if (cookie) headers.Cookie = cookie;
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = http.request({ host: "127.0.0.1", port, method, path: `/api/v1${pathName}`, headers }, (res) => {
      let buf = "";
      res.on("data", (d) => (buf += d));
      res.on("end", () => resolve({ status: res.statusCode, json: buf ? JSON.parse(buf) : null }));
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
const rootActionBody = (signer) => ({ action: "authorize", params: { fuel: fuelUtxoFor(FUEL) }, signerAddress: signer.address });
const rootGenesisBody = (signer) => ({ label: "B root", owners: [{ slot: 1, address: signer.address }], ownerM: 1, emergencyK: 1, recoveryM: 1, recoveryDelayDaa: "600", successionDelayDaa: "600", successorAddress: null, rootValueKas: "2", rootMaxFeePerTxKas: "0.01", signerAddress: signer.address, funding: [fuelUtxoFor(signer)] });
const rootedVaultBody = (signer) => ({ profile: "policyvault-0.7-payment", label: "second treasury", descriptor, templateIndex: 0, agents: [policyFor(AG7)], recoveryAddress: A.address, depositKas: "0", feeReserveKas: "5", signerAddress: signer.address, funding: [fuelUtxoFor(signer)] });
function depositBody(vaultId, signer) {
  const st = { ownerIdentifier: signer.xonly, identifierType: assets.kcc20.OWNER_SCHEMES.P2PK, amount: 500n, isMinter: false };
  const prog = compileKcc20Program({ config, state: st, familyBound: 2 });
  return { vaultId, action: "tokenDeposit", signerAddress: signer.address, params: { userPosition: { outpoint: { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 }, value: (2n * KAS).toString(), scriptPublicKeyHex: prog.p2shSpkHex, covenantId: H(0x54), state: { ...st, amount: "500" } }, fuel: fuelUtxoFor(FUEL), depositAmount: "300", depositCarryKasSompi: (1n * KAS).toString() } };
}
const v5CreateBody = (signer) => ({ label: "ctl", descriptor, templateIndex: 0, initialAgents: [policyFor(AG5)], feeReserveKas: "5", signerAddress: signer.address, funding: [fuelUtxoFor(signer)] });
const v5PauseBody = (signer) => ({ vaultId: v5VaultId, action: "ownerPause", signerAddress: signer.address, params: { fuel: fuelUtxoFor(FUEL) } });

/* ------------------------------------------------------------------ */
/* ORG ROOTS                                                           */
/* ------------------------------------------------------------------ */

test("org-roots READ: unauthenticated 401; foreign B sees no root (list/GET/vaults/requests/reconcile = 404 non-oracle); co-owner A2 and successor S read; a rooted-vault agent is not a root participant", { skip }, async () => {
  for (const p of ["/org-roots", `/org-roots/${rootId}`, `/org-roots/${rootId}/vaults`, `/org-roots/${rootId}/requests`]) {
    const r = await req("GET", p);
    assert.equal(r.status, 401, `${p}: ${JSON.stringify(r.json)}`);
  }
  const cB = await asW(B);
  let r = await req("GET", "/org-roots", { cookie: cB });
  assert.equal(r.status, 200); assert.equal(r.json.orgRoots.some((o) => o.rootCovenantId === rootId), false, "T2: foreign B must not enumerate A's root");
  for (const p of [`/org-roots/${rootId}`, `/org-roots/${rootId}/vaults`, `/org-roots/${rootId}/requests`]) {
    r = await req("GET", p, { cookie: cB });
    assert.equal(r.status, 404, `${p}: ${JSON.stringify(r.json)}`); assert.equal(code(r), "ROOT_NOT_FOUND");
  }
  r = await req("POST", `/org-roots/${rootId}/reconcile`, { cookie: cB });
  assert.equal(r.status, 404); assert.equal(code(r), "ROOT_NOT_FOUND");
  r = await req("GET", "/org-roots", { cookie: await asW(A2) });
  assert.equal(r.json.orgRoots.some((o) => o.rootCovenantId === rootId), true, "co-owner enumerates its root");
  r = await req("GET", `/org-roots/${rootId}`, { cookie: await asW(A2) });
  assert.equal(r.status, 200);
  r = await req("GET", `/org-roots/${rootId}/vaults`, { cookie: await asW(A2) });
  assert.equal(r.status, 200); assert.equal(r.json.vaults.length, 1);
  r = await req("GET", `/org-roots/${rootId}`, { cookie: await asW(S) });
  assert.equal(r.status, 200, "the pinned successor may READ the root");
  r = await req("POST", `/org-roots/${rootId}/reconcile`, { cookie: await asW(S) });
  assert.equal(r.status, 403); assert.equal(code(r), "NOT_AN_ACTIVE_SLOT", "successor cannot reconcile (owner action)");
  r = await req("GET", `/org-roots/${rootId}`, { cookie: await asW(AG7) });
  assert.equal(r.status, 404, "a rooted vault's agent holds no root authority (hosted org != on-chain root, agent != owner)");
});

test("org-root GENESIS: the funding signer is bound to the principal; B's own genesis request is invisible to A and mutable only by B", { skip }, async () => {
  const cB = await asW(B), cA = await asW(A);
  let r = await req("POST", "/org-roots", { body: rootGenesisBody(A), cookie: cB });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/org-roots", { body: rootGenesisBody(B), cookie: cB });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const bRoot = r.json.request.rootCovenantId, bReq = r.json.request.id;
  r = await req("GET", `/org-roots/${bRoot}/requests/${bReq}`, { cookie: cA });
  assert.equal(r.status, 404, "A cannot read B's pending genesis request");
  r = await req("POST", `/org-roots/${bRoot}/requests/${bReq}/reject`, { body: { reason: "x" }, cookie: cA });
  assert.equal(r.status, 404);
  r = await req("POST", `/org-roots/${bRoot}/requests/${bReq}/signature`, { body: { signedSafeJson: bogusSigned(JSON.stringify({ inputs: [{}] })) }, cookie: cA });
  assert.equal(r.status, 404, "rc12 review R-05: a foreign wallet cannot sign another wallet's pending genesis (non-oracle 404)");
  assert.equal((await wr7.loadOrgRootRequest(config, bReq)).state, "AUTHORIZED", "nothing changed");
  r = await req("GET", `/org-roots/${bRoot}/requests/${bReq}`, { cookie: cB });
  assert.equal(r.status, 200); assert.equal(r.json.request.state, "AUTHORIZED");
  r = await req("POST", `/org-roots/${bRoot}/requests/${bReq}/reject`, { body: { reason: "done" }, cookie: cB });
  assert.equal(r.status, 200);
});

test("ROOT-LOCK GRIEFING (audit L3): a foreign or non-owner caller can neither build a root action nor lock the root; the owner's own action still builds; slot envelopes/signatures are bound to the slot key; foreign mutation is refused before any state change", { skip }, async () => {
  const cA = await asW(A), cA2 = await asW(A2), cB = await asW(B), cS = await asW(S);
  // This request must remain reserved after its valid signature. Give it its
  // own real SDK-built root instead of canceling signed state as test cleanup.
  const rootId = await createOwnerRoot("signed owner withdrawal isolation");
  const pending = async () => (await wr7.loadOrgRoot(config, rootId)).pendingRequestId;
  assert.equal(await pending(), null);
  // L3a: foreign B names the OWNER as signer (the exact griefing shape) -> 404, no lock
  let r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json)); assert.equal(code(r), "ROOT_NOT_FOUND"); assert.equal(await pending(), null, "L3b: no lock left by the foreign caller");
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(B), cookie: cB });
  assert.equal(r.status, 404); assert.equal(await pending(), null);
  // the pinned successor may only initiate a succession
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cS });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL"); assert.equal(await pending(), null);
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(S), cookie: cS });
  assert.equal(r.status, 403, JSON.stringify(r.json)); assert.equal(code(r), "NOT_AN_ACTIVE_SLOT"); assert.equal(await pending(), null);
  // an owner cannot initiate in another owner's name
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A2), cookie: cA });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL"); assert.equal(await pending(), null);
  // the owner's OWN action builds (same-tenant accepted)
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const unsignedId = r.json.request.id;
  r = await req("POST", `/org-roots/${rootId}/requests/${unsignedId}/reject`, { body: { reason: "unsigned withdrawal control" }, cookie: cA2 });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(await pending(), null, "co-owner may withdraw an unsigned request");
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const reqId = r.json.request.id;
  assert.equal(await pending(), reqId);
  const unsigned = r.json.request.transaction.unsignedSafeJson;
  const rootInputIndex = r.json.request.rootInputIndex ?? 0;

  // foreign B against the pending request: every read and mutation is the non-oracle 404, state untouched
  r = await req("GET", `/org-roots/${rootId}/requests`, { cookie: cB });
  assert.equal(r.status, 404);
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}`, { cookie: cB });
  assert.equal(r.status, 404); assert.equal(code(r), "REQUEST_NOT_FOUND");
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}/slot-request/1`, { cookie: cB });
  assert.equal(r.status, 404);
  const env1ForA = await wr7.getOrCreateSlotSigningRequest({ config, requestId: reqId, slot: 1 });
  const slotResp = (env, w, slot) => ({ responseVersion: "policyvault-org-root-slot-response/1", requestVersion: env.requestVersion, requestId: env.requestId, network: env.network, manifestHash: env.manifestHash, txId: env.txId, root: env.root, slot: env.slot, signerAddress: w.address, signatureHex: sign65(unsigned, rootInputIndex, w), sighashType: 1, signedAtMs: Date.now() });
  r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/slot-signatures`, { body: { slot: 1, response: slotResp(env1ForA, A, 1) }, cookie: cB });
  assert.equal(r.status, 404, "foreign B cannot attach even a VALID owner signature");
  for (const [tail, body] of [["signature", { signedSafeJson: bogusSigned(unsigned) }], ["finalize", {}], ["submit", {}], ["reject", {}]]) {
    r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/${tail}`, { body, cookie: cB });
    assert.equal(r.status, 404, `${tail}: ${JSON.stringify(r.json)}`);
  }
  let stored = await wr7.loadOrgRootRequest(config, reqId);
  assert.equal(stored.slots.every((s) => s.status === "PENDING"), true, "no slot moved for the foreign caller");
  assert.equal(await pending(), reqId);

  // slot binding: A (slot 1) may not fetch or attach slot 2; A2 may
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}/slot-request/2`, { cookie: cA });
  assert.equal(r.status, 403); assert.equal(code(r), "NOT_AN_ACTIVE_SLOT");
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}/slot-request/1`, { cookie: cA });
  assert.equal(r.status, 200);
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}/slot-request/2`, { cookie: cA2 });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const env2 = r.json.slotRequest ?? r.json.request ?? r.json;
  r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/slot-signatures`, { body: { slot: 2, response: slotResp(env2, A2, 2) }, cookie: cA });
  assert.equal(r.status, 403, "slot 1's holder cannot attach slot 2's signature");
  r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/slot-signatures`, { body: { slot: 2, response: slotResp(env2, A2, 2) }, cookie: cA2 });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  stored = await wr7.loadOrgRootRequest(config, reqId);
  assert.equal(stored.slots.find((s) => s.slot === 2).status, "SIGNED");

  // The successor cannot mutate; even a co-owner cannot release signed state.
  r = await req("GET", `/org-roots/${rootId}/requests/${reqId}`, { cookie: cS });
  assert.equal(r.status, 200);
  r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/reject`, { body: { reason: "s" }, cookie: cS });
  assert.equal(r.status, 403); assert.equal(code(r), "REQUEST_FORBIDDEN");
  r = await req("POST", `/org-roots/${rootId}/requests/${reqId}/reject`, { body: { reason: "signed withdrawal refusal" }, cookie: cA2 });
  assert.equal(r.status, 409, JSON.stringify(r.json)); assert.equal(code(r), "CANNOT_REJECT");
  assert.equal(await pending(), reqId);
  assert.deepEqual(await wr7.loadOrgRootRequest(config, reqId), stored, "refused withdrawal cannot alter the signed request");
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cA });
  assert.equal(r.status, 409, JSON.stringify(r.json)); assert.equal(code(r), "ROOT_PENDING_REQUEST");
  assert.equal(await pending(), reqId);
});

test("ROOTED-VAULT GENESIS: foreign 404, successor 403 NOT_AN_ACTIVE_SLOT, owner-in-another-owner's-name 403, active owner in its own name 201", { skip }, async () => {
  let r = await req("POST", `/org-roots/${rootId}/vaults`, { body: rootedVaultBody(A), cookie: await asW(B) });
  assert.equal(r.status, 404); assert.equal(code(r), "ROOT_NOT_FOUND");
  r = await req("POST", `/org-roots/${rootId}/vaults`, { body: rootedVaultBody(S), cookie: await asW(S) });
  assert.equal(r.status, 403); assert.equal(code(r), "NOT_AN_ACTIVE_SLOT");
  r = await req("POST", `/org-roots/${rootId}/vaults`, { body: rootedVaultBody(A), cookie: await asW(A2) });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", `/org-roots/${rootId}/vaults`, { body: rootedVaultBody(A2), cookie: await asW(A2) });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  r = await req("POST", `/org-roots/${rootId}/requests/${r.json.request.id}/reject`, { body: { reason: "cleanup" }, cookie: await asW(A2) });
  assert.equal(r.status, 200);
});

/* ------------------------------------------------------------------ */
/* /wallet/v7 (rooted vault requests)                                  */
/* ------------------------------------------------------------------ */

test("/wallet/v7: unauthenticated 401; foreign B 404 on build/list-visibility/GET/mutate; agent builds only for itself; owner builds for its agent or itself (201); list is tenant-scoped", { skip }, async () => {
  let r = await req("GET", "/wallet/v7/requests");
  assert.equal(r.status, 401);
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A) });
  assert.equal(r.status, 401);
  const cA = await asW(A), cB = await asW(B), cAG = await asW(AG7);
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json)); assert.equal(code(r), "VAULT_NOT_FOUND");
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, B), cookie: cB });
  assert.equal(r.status, 404);
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), cookie: cAG });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, B), cookie: cA });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PARTICIPANT");
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id = r.json.request.requestId;
  const unsigned = r.json.request.transaction.unsignedSafeJson;
  r = await req("GET", "/wallet/v7/requests", { cookie: cB });
  assert.equal(r.status, 200); assert.equal(r.json.requests.some((x) => x.requestId === id), false, "foreign B does not see A's request");
  r = await req("GET", `/wallet/v7/requests?vaultId=${v7VaultId}`, { cookie: cAG });
  assert.equal(r.json.requests.some((x) => x.requestId === id), true, "the vault's agent (participant) sees it");
  r = await req("GET", `/wallet/v7/requests/${id}`, { cookie: cB });
  assert.equal(r.status, 404); assert.equal(code(r), "REQUEST_NOT_FOUND");
  r = await req("POST", `/wallet/v7/requests/${id}/signature`, { body: { signedSafeJson: bogusSigned(unsigned) }, cookie: cB });
  assert.equal(r.status, 404, "T7-class: foreign signature refused BEFORE any verification/state change");
  assert.equal((await wr7.loadV7WalletRequest(config, id)).state, "BUILT");
  r = await req("POST", `/wallet/v7/requests/${id}/submit`, { cookie: cB });
  assert.equal(r.status, 404);
  r = await req("POST", `/wallet/v7/requests/${id}/reject`, { cookie: cB });
  assert.equal(r.status, 404);
  assert.equal((await wr7.loadV7WalletRequest(config, id)).state, "BUILT");
  // the owner's bogus signature is refused by the real VM (F-04a): the request is recorded SIGNATURE_INVALID (terminal), never SIGNED
  r = await req("POST", `/wallet/v7/requests/${id}/signature`, { body: { signedSafeJson: bogusSigned(unsigned) }, cookie: cA });
  assert.notEqual(r.status, 200); assert.ok(["SIGNATURE_INVALID", "SIGHASH_NOT_ALL"].includes(code(r)), `refused pre-sign or on the VM: ${code(r)}`);
  assert.equal((await wr7.loadV7WalletRequest(config, id)).state, "SIGNATURE_INVALID");
});

test("MACHINE credential (F-06 + F-04): an owner-minted write:org-roots credential reaches /wallet/v7/requests and /org-roots as the owner; a stranger-minted one is foreign", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B);
  const mintA = await req("POST", "/identities", { body: { label: "A machine", scopes: ["read:org-roots", "write:org-roots"] }, cookie: cA });
  assert.equal(mintA.status, 201, JSON.stringify(mintA.json));
  const tokA = mintA.json.credential.token;
  let r = await req("GET", "/org-roots", { bearer: tokA });
  assert.equal(r.status, 200); assert.equal(r.json.orgRoots.some((o) => o.rootCovenantId === rootId), true);
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), bearer: tokA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  await req("POST", `/wallet/v7/requests/${r.json.request.requestId}/reject`, { cookie: cA });
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, B), bearer: tokA });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PARTICIPANT");
  const mintB = await req("POST", "/identities", { body: { label: "B machine", scopes: ["read:org-roots", "write:org-roots"] }, cookie: cB });
  assert.equal(mintB.status, 201);
  r = await req("GET", "/org-roots", { bearer: mintB.json.credential.token });
  assert.equal(r.status, 200); assert.equal(r.json.orgRoots.some((o) => o.rootCovenantId === rootId), false);
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), bearer: mintB.json.credential.token });
  assert.equal(r.status, 404);
});

/* ------------------------------------------------------------------ */
/* /wallet/v5 and /wallet/v6 (token controllers)                       */
/* ------------------------------------------------------------------ */

test("/wallet/v5: unauthenticated create/list/GET/mutate 401; foreign create-in-A's-name 403; A's genesis request invisible and immutable to B and to A's own agent (not yet a vault); bogus foreign signature changes nothing", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B), cAG = await asW(AG5);
  let r = await req("POST", "/wallet/v5/create", { body: v5CreateBody(A) });
  assert.equal(r.status, 401, "T13");
  r = await req("GET", "/wallet/v5/requests");
  assert.equal(r.status, 401, "T14");
  r = await req("POST", "/wallet/v5/create", { body: v5CreateBody(A), cookie: cB });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/wallet/v5/create", { body: v5CreateBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id = r.json.request.requestId, unsigned = r.json.request.transaction.unsignedSafeJson;
  for (const [tail, body] of [["", undefined], ["/signature", { signedSafeJson: bogusSigned(unsigned) }], ["/submit", undefined], ["/reject", undefined]]) {
    r = await req(tail ? "POST" : "GET", `/wallet/v5/requests/${id}${tail}`, { body });
    assert.equal(r.status, 401, `unauthenticated ${tail || "GET"}`);
    r = await req(tail ? "POST" : "GET", `/wallet/v5/requests/${id}${tail}`, { body, cookie: cB });
    assert.equal(r.status, 404, `foreign ${tail || "GET"}: ${JSON.stringify(r.json)}`); assert.equal(code(r), "REQUEST_NOT_FOUND");
    r = await req(tail ? "POST" : "GET", `/wallet/v5/requests/${id}${tail}`, { body, cookie: cAG });
    assert.equal(r.status, 404, `agent of ANOTHER vault ${tail || "GET"}`);
  }
  assert.equal((await wr5.loadWalletRequestV5(config, id)).state, "BUILT", "T16/T17/T18: nothing changed");
  r = await req("GET", "/wallet/v5/requests", { cookie: cB });
  assert.equal(r.status, 200); assert.equal(r.json.requests.some((x) => x.requestId === id), false, "T14: tenant-scoped list");
  r = await req("GET", `/wallet/v5/requests/${id}`, { cookie: cA });
  assert.equal(r.status, 200);
  r = await req("POST", `/wallet/v5/requests/${id}/reject`, { cookie: cA });
  assert.equal(r.status, 200);
});

test("/wallet/v5 on a LIVE controller: foreign build 404; agent-in-owner's-name 403; owner-for-stranger 403; owner's own request 201 and visible to its agent; foreign reject 404; owner reject 200", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B), cAG = await asW(AG5);
  let r = await req("POST", "/wallet/v5/requests", { body: v5PauseBody(A), cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json)); assert.equal(code(r), "VAULT_NOT_FOUND");
  r = await req("POST", "/wallet/v5/requests", { body: v5PauseBody(A), cookie: cAG });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/wallet/v5/requests", { body: v5PauseBody(B), cookie: cA });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PARTICIPANT");
  r = await req("POST", "/wallet/v5/requests", { body: v5PauseBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id = r.json.request.requestId;
  r = await req("GET", `/wallet/v5/requests?vaultId=${v5VaultId}`, { cookie: cAG });
  assert.equal(r.json.requests.some((x) => x.requestId === id), true, "the controller's agent sees the owner's request");
  r = await req("GET", `/wallet/v5/requests?vaultId=${v5VaultId}`, { cookie: cB });
  assert.equal(r.json.requests.length, 0);
  r = await req("POST", `/wallet/v5/requests/${id}/reject`, { cookie: cB });
  assert.equal(r.status, 404);
  r = await req("POST", `/wallet/v5/requests/${id}/reject`, { cookie: cA });
  assert.equal(r.status, 200);
});

test("/wallet/v6 shares the surface: unauthenticated 401, foreign create-in-A's-name 403, foreign build on an unknown vault 404 (no oracle)", { skip }, async () => {
  let r = await req("POST", "/wallet/v6/create", { body: { ...v5CreateBody(A), initialSwapPolicies: [] } });
  assert.equal(r.status, 401);
  r = await req("GET", "/wallet/v6/requests");
  assert.equal(r.status, 401);
  r = await req("POST", "/wallet/v6/create", { body: { ...v5CreateBody(A), initialSwapPolicies: [] }, cookie: await asW(B) });
  assert.equal(r.status, 403); assert.equal(code(r), "SIGNER_NOT_PRINCIPAL");
  r = await req("POST", "/wallet/v6/requests", { body: { vaultId: v5VaultId, action: "ownerPause", signerAddress: B.address, params: {} }, cookie: await asW(B) });
  assert.equal(r.status, 404); assert.equal(code(r), "VAULT_NOT_FOUND", "a v5 controller is not a v6 vault — and B is foreign: uniform 404");
  r = await req("POST", "/wallet/v6/requests", { body: { vaultId: "00".repeat(32), action: "ownerPause", signerAddress: A.address, params: {} }, cookie: await asW(A) });
  assert.equal(r.status, 404); assert.equal(code(r), "VAULT_NOT_FOUND");
});

/* ------------------------------------------------------------------ */
/* remaining families (GATE 1 completeness)                            */
/* ------------------------------------------------------------------ */

test("GLOBAL aggregates and per-vault evidence: /metrics and /mcp-telemetry require a principal (401 unauthenticated); /attestations/export for A's vault is 401 unauthenticated and 404 for foreign B — indistinguishable from the owner's answer for a generation the export loader does not serve (no oracle)", { skip }, async () => {
  for (const p of ["/metrics", `/attestations/export?vaultId=${v5VaultId}`]) {
    const r = await req("GET", p);
    assert.equal(r.status, 401, `${p}: ${JSON.stringify(r.json)}`);
  }
  // /mcp-telemetry is feature-gated OFF here: the same closed 404 for every caller (no data, no principal oracle)
  for (const cookie of [undefined, await asW(B)]) {
    const r = await req("GET", "/mcp-telemetry", { cookie });
    assert.equal(r.status, 404); assert.equal(code(r), "MCP_TELEMETRY_DISABLED");
  }
  const rB = await req("GET", `/attestations/export?vaultId=${v5VaultId}`, { cookie: await asW(B) });
  assert.equal(rB.status, 404); assert.equal(code(rB), "VAULT_NOT_FOUND");
  const rA = await req("GET", `/attestations/export?vaultId=${v5VaultId}`, { cookie: await asW(A) });
  assert.equal(rA.status, rB.status, "the foreign answer must not differ from the owner's answer (no existence oracle)");
  const rM = await req("GET", "/metrics", { cookie: await asW(B) });
  assert.equal(rM.status, 200, "an authenticated principal reads the global aggregate");
});

test("LEGACY v0.2 family: /wallet/create is production-disabled for everyone (403 LEGACY_CREATE_DISABLED, nothing built); /wallet/requests requires a principal (401) and answers a foreign/unknown vault with the non-oracle 404", { skip }, async () => {
  const legacyBody = { label: "legacy", signerAddress: A.address, templateInput: {}, initialStateInput: {}, delegateFuelSompi: "0" };
  let r = await req("POST", "/wallet/create", { body: legacyBody });
  assert.notEqual(r.status, 201); assert.equal(code(r), "LEGACY_CREATE_DISABLED");
  r = await req("POST", "/wallet/create", { body: legacyBody, cookie: await asW(B) });
  assert.notEqual(r.status, 201); assert.equal(code(r), "LEGACY_CREATE_DISABLED");
  const buildBody = { vaultId: "5a".repeat(32), signerAddress: A.address, action: "delegateSpend", params: {} };
  r = await req("POST", "/wallet/requests", { body: buildBody });
  assert.equal(r.status, 401, JSON.stringify(r.json));
  r = await req("POST", "/wallet/requests", { body: buildBody, cookie: await asW(B) });
  assert.equal(r.status, 404, JSON.stringify(r.json)); assert.equal(code(r), "VAULT_NOT_FOUND");
  r = await req("POST", "/wallet/requests", { body: { ...buildBody, vaultId: v5VaultId }, cookie: await asW(B) });
  assert.equal(r.status, 404, "a foreign v5 controller is not a legacy vault and B is foreign: uniform 404");
});

test("v4-FAMILY routes given a v5 controller id (another generation): unauthenticated 401 FIRST; foreign B and owner A both get the non-oracle 404 — never a 500 that distinguishes 'exists with another schema' from 'does not exist'", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B);
  const spend = { vaultId: v5VaultId, action: "agentSpend", signerAddress: A.address, params: {} };
  for (const [m, p, body] of [["GET", `/vaults/${v5VaultId}`], ["GET", `/vaults/${v5VaultId}/agent-suspensions`], ["POST", `/vaults/${v5VaultId}/reconcile`], ["POST", "/wallet/v4/requests", spend], ["POST", "/wallet/v4/simulate", spend]]) {
    let r = await req(m, p, { body });
    assert.equal(r.status, 401, `${m} ${p} unauthenticated: ${JSON.stringify(r.json)}`);
    r = await req(m, p, { body, cookie: cB });
    assert.equal(r.status, 404, `${m} ${p} foreign: ${JSON.stringify(r.json)}`); assert.equal(code(r), "VAULT_NOT_FOUND");
    const rA = await req(m, p, { body, cookie: cA });
    assert.equal(rA.status, 404, `${m} ${p} owner on the v4 family: ${JSON.stringify(rA.json)}`);
  }
  const r = await req("GET", `/vaults/${"11".repeat(32)}`, { cookie: cB });
  assert.equal(r.status, 404); assert.equal(code(r), "VAULT_NOT_FOUND");
});

test("rc12 review R-01: GET /vaults (the v4-family LIST) with a v0.5 controller and a v0.7 rooted vault in the store — unauthenticated 401 FIRST; foreign and owner get 200 (never 500); records of other generations are not part of this listing; /vaults/:id/status and /audit answer 404 for another generation", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B);
  let r = await req("GET", "/vaults");
  assert.equal(r.status, 401, JSON.stringify(r.json));
  r = await req("GET", "/vaults", { cookie: cB });
  assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.vaults.length, 0, "B participates in no v4-family vault");
  r = await req("GET", "/vaults", { cookie: cA });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.vaults.some((v) => v.vaultId === v5VaultId || v.vaultId === v7VaultId), false, "v0.5 / v0.7 records are served by their own families, never by a 500 here");
  for (const tail of ["status", "audit"]) {
    r = await req("GET", `/vaults/${v5VaultId}/${tail}`);
    assert.equal(r.status, 401, `${tail} unauthenticated`);
    r = await req("GET", `/vaults/${v5VaultId}/${tail}`, { cookie: cB });
    assert.equal(r.status, 404, `${tail} foreign: ${JSON.stringify(r.json)}`);
    r = await req("GET", `/vaults/${v5VaultId}/${tail}`, { cookie: cA });
    assert.equal(r.status, 404, `${tail} owner on the v4 family: ${JSON.stringify(r.json)}`);
  }
});

test("rc12 review R-08: a malformed signedSafeJson (null / missing / non-array inputs, non-JSON) on the v5 and v7 signature routes answers the CLOSED 400 BAD_SIGNATURE — never the text of an internal TypeError, never a state change", { skip }, async () => {
  const cA = await asW(A);
  let r = await req("POST", "/wallet/v5/create", { body: v5CreateBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id5 = r.json.request.requestId;
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id7 = r.json.request.requestId;
  for (const bad of ['{"inputs":null}', '{"inputs":{}}', '{"inputs":[]}', '{"inputs":[null]}', "[]", "not json", '{"version":0}']) {
    for (const [p, id] of [[`/wallet/v5/requests/${id5}/signature`, id5], [`/wallet/v7/requests/${id7}/signature`, id7]]) {
      r = await req("POST", p, { body: { signedSafeJson: bad }, cookie: cA });
      assert.equal(r.status, 400, `${p} ${bad}: ${JSON.stringify(r.json)}`); assert.equal(code(r), "BAD_SIGNATURE");
      assert.doesNotMatch(String(r.json.error.message), /Cannot read|undefined|TypeError|of null/, "closed message only");
    }
  }
  assert.equal((await wr5.loadWalletRequestV5(config, id5)).state, "BUILT");
  assert.equal((await wr7.loadV7WalletRequest(config, id7)).state, "BUILT");
  await req("POST", `/wallet/v5/requests/${id5}/reject`, { cookie: cA });
  await req("POST", `/wallet/v7/requests/${id7}/reject`, { cookie: cA });
});

test("rc13 review N-02 (all families): a participant that is NOT the request's signer cannot reach a signature route — v5 agent on the owner's controller request, v7 agent on the owner's deposit, co-owner on the creator's root action: 403 NOT_THE_SIGNER, state unchanged; the signer's own malformed payload stays a closed 400", { skip }, async () => {
  const cA = await asW(A), cAG5 = await asW(AG5), cAG7 = await asW(AG7), cA2 = await asW(A2);
  let r = await req("POST", "/wallet/v5/requests", { body: v5PauseBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id5 = r.json.request.requestId;
  r = await req("POST", `/wallet/v5/requests/${id5}/signature`, { body: { signedSafeJson: '{"inputs":[{}]}' }, cookie: cAG5 });
  assert.equal(r.status, 403, JSON.stringify(r.json)); assert.equal(code(r), "NOT_THE_SIGNER");
  assert.equal((await wr5.loadWalletRequestV5(config, id5)).state, "BUILT");
  r = await req("POST", "/wallet/v7/requests", { body: depositBody(v7VaultId, A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const id7 = r.json.request.requestId;
  r = await req("POST", `/wallet/v7/requests/${id7}/signature`, { body: { signedSafeJson: '{"inputs":[{}]}' }, cookie: cAG7 });
  assert.equal(r.status, 403, JSON.stringify(r.json)); assert.equal(code(r), "NOT_THE_SIGNER");
  assert.equal((await wr7.loadV7WalletRequest(config, id7)).state, "BUILT");
  r = await req("POST", `/org-roots/${rootId}/requests`, { body: rootActionBody(A), cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const rid = r.json.request.id;
  r = await req("POST", `/org-roots/${rootId}/requests/${rid}/signature`, { body: { signedSafeJson: '{"inputs":[{}]}' }, cookie: cA2 });
  assert.equal(r.status, 403, JSON.stringify(r.json)); assert.equal(code(r), "NOT_THE_SIGNER");
  assert.equal((await wr7.loadOrgRootRequest(config, rid)).state, "AUTHORIZED");
  await req("POST", `/org-roots/${rootId}/requests/${rid}/reject`, { body: { reason: "cleanup" }, cookie: cA });
  await req("POST", `/wallet/v5/requests/${id5}/reject`, { cookie: cA });
  await req("POST", `/wallet/v7/requests/${id7}/reject`, { cookie: cA });
});

test("DEV HOOKS are never a tenant surface: /wallet/dev-accounts and /wallet/dev-sign are production-disabled (closed refusal for unauthenticated, foreign and owner callers alike; nothing signed)", { skip }, async () => {
  for (const cookie of [undefined, await asW(B), await asW(A)]) {
    let r = await req("GET", "/wallet/dev-accounts", { cookie });
    assert.notEqual(r.status, 200, JSON.stringify(r.json));
    r = await req("POST", "/wallet/dev-sign", { body: { unsignedSafeJson: "{}", signerAddress: A.address }, cookie });
    assert.notEqual(r.status, 200, JSON.stringify(r.json));
    assert.ok(r.status === 401 || r.status === 403 || r.status === 404, `closed refusal, got ${r.status}`);
  }
});

test("OFF-CHAIN organizations and creator-owned webhooks: foreign B gets the non-oracle 404 on /organizations/:id/audit and /organizations/:id/vaults/:v/unassign and on /webhooks/:id/rotate-secret; the creator succeeds; the signing secret is never re-shown to a foreign caller", { skip }, async () => {
  const cA = await asW(A), cB = await asW(B);
  let r = await req("POST", "/organizations", { body: { name: "A org" }, cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const orgId = r.json.organization.orgId ?? r.json.organization.id;
  r = await req("GET", `/organizations/${orgId}/audit`, { cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json));
  r = await req("POST", `/organizations/${orgId}/vaults/${v5VaultId}/unassign`, { body: { expectedVersion: 1 }, cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json));
  r = await req("GET", `/organizations/${orgId}/audit`, { cookie: cA });
  assert.equal(r.status, 200);
  r = await req("POST", "/webhooks", { body: { url: "https://consumer.example.com/hooks/pv", eventTypes: ["request.built"], label: "a" }, cookie: cA });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  const hookId = r.json.endpoint?.endpointId;
  assert.ok(hookId, JSON.stringify(r.json));
  r = await req("POST", `/webhooks/${hookId}/rotate-secret`, { cookie: cB });
  assert.equal(r.status, 404, JSON.stringify(r.json));
  r = await req("GET", `/webhooks/${hookId}`, { cookie: cB });
  assert.equal(r.status, 404);
  r = await req("POST", `/webhooks/${hookId}/rotate-secret`, { cookie: cA });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  await req("POST", `/webhooks/${hookId}/revoke`, { cookie: cA });
});
