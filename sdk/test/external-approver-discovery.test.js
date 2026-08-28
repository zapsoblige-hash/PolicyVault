"use strict";

/*
 * EXTERNAL COVENANT APPROVER DISCOVERY (mainnet incident 2026-08-27).
 *
 * Live production defect: a vault configured with an EXTERNAL covenant
 * approver (a wallet that is neither the template owner, nor a registry
 * agent, nor any request's signer) was INVISIBLE to that approver in
 * hosted mode — GET /vaults empty, GET /wallet/v4/requests?open=1 empty,
 * request by-id 404, and POST …/approvals 404 (the tenancy gate sits in
 * front of the approval collector). Root cause: tenancy.vaultParticipants
 * read `live.state.approverSlots` — the PERSISTED-JSON field name — from
 * the NORMALIZED manifest that loadAnyManifest actually returns, where
 * the field is `live.state.approvers` (core/model/vault-state-v4
 * normalizeStateV4). The approver branch therefore never matched and the
 * wallet failed closed out of every discovery and approval surface.
 *
 * This suite drives the REAL path — persisted manifest JSON →
 * loadAnyManifest normalization → HTTP API with hosted authentication —
 * and asserts the REQUIRED security model:
 *
 *   AUTHORITY COMES FROM THE COVENANT'S APPROVER SLOTS, NOT ORG ROLES.
 *   - the external approver DISCOVERS the vault and its open request;
 *   - the external approver REACHES the approval route (inner
 *     signature/slot verification still decides the approval itself);
 *   - the external approver gains NO mutation authority: reject stays
 *     403 (visible object, no cancel authority) — never silently opened;
 *   - an unrelated authenticated wallet sees NOTHING (404, no oracle);
 *   - the same approver on vault A sees nothing of vault B;
 *   - wrong-network principals stay excluded (defence in depth).
 *
 * Reproduce-first: on the frozen fullscale-rc2 source the discovery rows
 * are RED (archived); after the tenancy fix they are GREEN and pin the
 * normalized-manifest shape forever (the historical unit tests used a
 * hand-built persisted-shape fixture, which is why this shipped).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const kaspa = require(loadConfig({}).rustyKaspaModule);

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
const AGENT = wallet("b8"); // acting agent = request signer (NOT in the registry: signer rule covers it)
const APPROVER = wallet("c9"); // EXTERNAL covenant approver — on the vault's approver slots ONLY
const OUTSIDER = wallet("d4"); // authenticated, unrelated

const VID_A = "aa".repeat(32); // approver sits on this vault
const VID_B = "bb".repeat(32); // approver is NOT on this vault
const REQ_OPEN = "a1000000-0000-4000-8000-000000000001"; // AWAITING_APPROVALS on A
const REQ_CANCEL = "a1000000-0000-4000-8000-000000000002"; // reject-authority probe on A
const REQ_FOREIGN = "b1000000-0000-4000-8000-000000000003"; // AWAITING_APPROVALS on B

let server, port, config;

/* The exact §C8-style persisted manifest JSON (the shape production
 * writes), parameterized; kept raw so the unit row below can prove the
 * NORMALIZED shape carries the approver too. */
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
  config = loadConfig({
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-extappr-"))
  });
  const { persistManifestV4 } = require("../src/manifest-v4");
  await persistManifestV4(config, rawManifest(VID_A, OWNER.xonly, [APPROVER.xonly], "approver vault"));
  await persistManifestV4(config, rawManifest(VID_B, OWNER.xonly, [], "no-approver vault"));
  const { getStore, Categories } = require("../src/store");
  const store = getStore(config);
  await store.write(Categories.REQUEST, REQ_OPEN, requestRecord(REQ_OPEN, VID_A, AGENT.address));
  await store.write(Categories.REQUEST, REQ_CANCEL, requestRecord(REQ_CANCEL, VID_A, AGENT.address));
  await store.write(Categories.REQUEST, REQ_FOREIGN, requestRecord(REQ_FOREIGN, VID_B, AGENT.address));
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(async () => {
  if (server) await new Promise((r) => server.close(r));
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

const S = {}; // session cookies

test("§EA0 setup: owner, agent, external approver, outsider sign in", async () => {
  S.owner = await signIn(OWNER);
  S.agent = await signIn(AGENT);
  S.approver = await signIn(APPROVER);
  S.outsider = await signIn(OUTSIDER);
});

/* ---------- unit sensitivity: the REAL normalized-manifest shape ---------- */

test("§EA1 vaultParticipants derives the approver from the NORMALIZED manifest (the loadAnyManifest shape)", () => {
  const { normalizeManifestV4 } = require("../src/manifest-v4");
  const { vaultParticipants, vaultAccessAllowed } = require("../../server/src/tenancy");
  const bigintSafe = JSON.parse(JSON.stringify(rawManifest(VID_A, OWNER.xonly, [APPROVER.xonly], "unit"), (_, v) => (typeof v === "bigint" ? v.toString() : v)));
  const loaded = { version: "v4", manifest: normalizeManifestV4(bigintSafe) };
  const { owner, others } = vaultParticipants(loaded);
  assert.ok(owner.has(OWNER.xonly), "owner derived");
  assert.ok(others.has(APPROVER.xonly), "approver slot derived from the normalized live state (state.approvers)");
  assert.ok(!others.has("00".repeat(32)), "the all-zero sentinel is never a participant");
  const principal = { xOnlyPubkey: APPROVER.xonly, networkId: "testnet-10" };
  assert.equal(vaultAccessAllowed(config, loaded, principal, "read"), true, "approver has covenant-derived READ");
  assert.equal(vaultAccessAllowed(config, loaded, principal, "owner"), false, "approver is NOT owner");
  const wrongNet = { xOnlyPubkey: APPROVER.xonly, networkId: "mainnet" };
  assert.equal(vaultAccessAllowed(config, loaded, wrongNet, "read"), false, "wrong-network principal excluded");
});

/* ------------------------- vault discovery ------------------------- */

test("§EA2 external approver sees vault A in GET /vaults, and NOT vault B", async () => {
  const r = await req("GET", "/api/v1/vaults", { cookie: S.approver });
  assert.equal(r.status, 200);
  const ids = (r.json.vaults || []).filter(Boolean).map((v) => v.vaultId);
  assert.ok(ids.includes(VID_A), `approver's vault list contains the vault whose approver slot they hold (got ${JSON.stringify(ids)})`);
  assert.ok(!ids.includes(VID_B), "approver does NOT see the unrelated vault");
});

test("§EA3 approver reads vault A by id (200) but vault B stays hidden (404)", async () => {
  const a = await req("GET", `/api/v1/vaults/${VID_A}`, { cookie: S.approver });
  assert.equal(a.status, 200, "approver reads the vault they approve for");
  assert.equal(a.json.vaultId, VID_A);
  assert.ok(Array.isArray(a.json.approverSlots) && a.json.approverSlots.includes(APPROVER.xonly), "presented approver slots include the approver (the web card derives Review & approve from this)");
  const b = await req("GET", `/api/v1/vaults/${VID_B}`, { cookie: S.approver });
  assert.equal(b.status, 404, "no oracle for the unrelated vault");
});

test("§EA4 owner vault list unchanged; outsider sees neither vault", async () => {
  const o = await req("GET", "/api/v1/vaults", { cookie: S.owner });
  const oids = (o.json.vaults || []).filter(Boolean).map((v) => v.vaultId);
  assert.ok(oids.includes(VID_A) && oids.includes(VID_B), "owner sees both own vaults");
  const x = await req("GET", "/api/v1/vaults", { cookie: S.outsider });
  const xids = (x.json.vaults || []).filter(Boolean).map((v) => v.vaultId);
  assert.ok(!xids.includes(VID_A) && !xids.includes(VID_B), "outsider sees nothing");
});

/* ------------------------ request discovery ------------------------ */

test("§EA5 approval inbox: approver's GET /wallet/v4/requests?open=1 contains vault A's request and never vault B's", async () => {
  const r = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.approver });
  assert.equal(r.status, 200);
  const ids = (r.json.requests || []).map((q) => q.requestId);
  assert.ok(ids.includes(REQ_OPEN), `the open request for the approver's vault is discoverable (got ${JSON.stringify(ids)})`);
  assert.ok(!ids.includes(REQ_FOREIGN), "vault B's request never appears for the approver");
});

test("§EA6 approver fetches the exact request by id (200); outsider gets 404 by-id (no oracle)", async () => {
  const a = await req("GET", `/api/v1/wallet/v4/requests/${REQ_OPEN}`, { cookie: S.approver });
  assert.equal(a.status, 200, "approver reviews the exact frozen request");
  assert.equal(a.json.request.requestId, REQ_OPEN);
  const x = await req("GET", `/api/v1/wallet/v4/requests/${REQ_OPEN}`, { cookie: S.outsider });
  assert.equal(x.status, 404, "unrelated wallet cannot fetch it by guessed id");
  const f = await req("GET", `/api/v1/wallet/v4/requests/${REQ_FOREIGN}`, { cookie: S.approver });
  assert.equal(f.status, 404, "approver-of-A cannot fetch B's request by id");
});

test("§EA7 agent (request signer) still sees the request; outsider inbox is empty of it", async () => {
  const g = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.agent });
  assert.ok((g.json.requests || []).map((q) => q.requestId).includes(REQ_OPEN), "signer rule unchanged");
  const x = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.outsider });
  assert.ok(!(x.json.requests || []).map((q) => q.requestId).includes(REQ_OPEN), "outsider inbox never lists it");
});

/* ------------------- approval route reachability ------------------- */

test("§EA8 the approvals route is REACHABLE for the approver (tenancy no longer 404s before the verifier); outsider still 404", async () => {
  // Garbage signature: the INNER approval verifier must reject it — but the
  // refusal must NOT be the tenancy 404 that hid the request pre-fix. The
  // approval AUTHORITY (slot-bound signature verification) is unchanged.
  const a = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/approvals`,
    { body: { approverAddress: APPROVER.address, signatureHex: "00".repeat(65) }, cookie: S.approver });
  assert.notEqual(a.status, 404, `approver must reach the approval verifier (got ${a.status} ${JSON.stringify(a.json)})`);
  assert.notEqual(a.json?.error?.code, "REQUEST_NOT_FOUND", "refusal is the verifier's, not the tenancy oracle");
  const x = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/approvals`,
    { body: { approverAddress: OUTSIDER.address, signatureHex: "00".repeat(65) }, cookie: S.outsider });
  assert.equal(x.status, 404, "unrelated wallet is refused at tenancy with 404 (no existence oracle)");
});

/* --------------------- mutation stays closed ---------------------- */

test("§EA9 approver gains NO mutation authority: reject is 403 (never opened by the discovery fix), owner/agent unchanged", async () => {
  const a = await req("POST", `/api/v1/wallet/v4/requests/${REQ_CANCEL}/reject`, { body: {}, cookie: S.approver });
  assert.equal(a.status, 403, `approver cannot cancel/reject (got ${a.status} ${JSON.stringify(a.json)})`);
  const x = await req("POST", `/api/v1/wallet/v4/requests/${REQ_CANCEL}/reject`, { body: {}, cookie: S.outsider });
  assert.equal(x.status, 404, "outsider reject stays a 404 non-oracle");
  // Positive control LAST: the owner (a rejection-authorized participant)
  // rejects the probe request exactly as before the fix.
  const o = await req("POST", `/api/v1/wallet/v4/requests/${REQ_CANCEL}/reject`, { body: {}, cookie: S.owner });
  assert.equal(o.status, 200, `owner reject unchanged (got ${o.status} ${JSON.stringify(o.json)})`);
  assert.equal(o.json.request.state, "WALLET_REJECTED");
});

test("§EA10 approver cannot drive finalize/submit: signature and submit routes refuse the approver-only principal", async () => {
  const s1 = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/signature`,
    { body: { signedSafeJson: "{}" }, cookie: S.approver });
  assert.equal(s1.status, 403, `approver cannot attach the spend signature (got ${s1.status})`);
  const s2 = await req("POST", `/api/v1/wallet/v4/requests/${REQ_OPEN}/submit`, { body: {}, cookie: S.approver });
  assert.equal(s2.status, 403, `approver cannot trigger submit (got ${s2.status})`);
});

/* ------------------- terminal requests drop out -------------------- */

test("§EA11 the rejected request leaves the actionable inbox for everyone", async () => {
  const a = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.approver });
  assert.ok(!(a.json.requests || []).map((q) => q.requestId).includes(REQ_CANCEL), "terminal request absent for the approver");
  const o = await req("GET", "/api/v1/wallet/v4/requests?open=1", { cookie: S.owner });
  assert.ok(!(o.json.requests || []).map((q) => q.requestId).includes(REQ_CANCEL), "terminal request absent for the owner");
});
