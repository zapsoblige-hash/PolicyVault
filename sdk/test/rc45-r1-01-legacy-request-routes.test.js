"use strict";
/*
 * RC45 R1-01 — THE LEGACY v0.2 REQUEST ROUTES REFUSE EVERY NON-v0.2 RECORD;
 * LEGACY REJECTION IS SIGNER-OR-OWNER (remediation plan rc45-r1-plan-01
 * PLAN-R1 revision 2 §2 R1-01 and §4 R1-01; review finding S-01 of
 * rc45-patch-independent-01; conditions C6, C7, K2, K3). Internal RED-first
 * regression material for the RC45 successor candidate; not an audit.
 *
 * THE DEFECT (S-01, HIGH, RC42/RC44-present): POST /wallet/requests/:id/reject
 * loads ANY record of the shared REQUEST category through
 * wallet-requests-v2.loadRequest (no schema check), authorizes with
 * requireRequestAccess (READ access: owner, agents, approvers, delegate,
 * signer) and, for a BUILT record, writes WALLET_REJECTED. An agent or an
 * approver-only principal can therefore silently cancel the owner's hosted
 * Pause / Close & recover / removeAgent of a v0.4 vault, repeatably and while
 * hosted-suspended, bypassing RC45 A2 on its own route. POST
 * /wallet/requests/:id/signature likewise hands any record its signer reaches
 * to the v0.2 signing pipeline (attachWalletSignatureV2): a BUILT v0.4
 * genesis reaches the v0.2 genesis signing/broadcast path (a node
 * connection), a v0.4 transition the v0.2 finalize.
 *
 * THE FIX THIS SUITE PINS (plan §2 R1-01, in this order — C7):
 *   1. authenticate first (401 unchanged for an unauthenticated caller);
 *   2. load the record; missing OR record.schema !== "policyvault-wallet-request/v2"
 *      -> 404 REQUEST_NOT_FOUND with NO write (and, on the signature route,
 *      no node call and no broadcast — C6, AZ-04);
 *   3. a v0.2 record: requireRequestRejecter on reject (the request's signer
 *      or the vault owner; the v0.2 delegate on the owner's request gets
 *      403 REQUEST_FORBIDDEN — AZ-03), requireRequestSigner on signature;
 *   4. defence in depth (sdk/src/wallet-requests-v2.js): markWalletRejected
 *      returns null and attachWalletSignatureV2 refuses for any non-v2 record,
 *      with no write and no node call.
 * The web half (web/app.js offers Cancel only for contractVersion
 * "policyvault-0.2") is web/test/rc45-r1-01-legacy-cancel.test.js.
 * NOT pinned here (K2): AZ-09 (the v0.4 reject route writing v0.4 states onto
 * non-v0.4 records for their signer/owner) is a separate follow-up finding;
 * the v0.4 route x v0.2 record cells for the signer and the owner
 * are therefore left out, and the other v0.4 route x v0.2 cells assert only
 * "refused, nothing written" (no status code is pinned there).
 *
 * THE MATRIX (plan §4 R1-01): principal {owner 0x11, agent 0x21 (the v0.4
 * agent and the v0.2 delegate), approver-only 0x32 (the v0.4 vault's single
 * covenant approver), foreign 0x33, unauthenticated} x request {the owner's
 * BUILT ownerPause / ownerRecover / removeAgent and the agent's BUILT
 * agentSpend of a v0.4.1 vault, the owner's BUILT v0.4.1 genesis, the
 * owner's BUILT v0.2 ownerPause and the delegate's BUILT v0.2 delegateSpend,
 * a missing id} x route {legacy reject, legacy signature, v0.4 reject} x
 * generation, each cell on its own before/after durable snapshot (requests,
 * vaults, claims, reservations, receipts, audit and the platform event
 * stream) with a node sentinel; plus the repeat and the agent-suspension
 * legs, a SYNTHETIC non-v0.2 schema sweep (every other schema that shares the
 * REQUEST category, an unknown one and a schema-less record: the routes and
 * the SDK refuse on the schema alone, before any record content is used) and
 * the SDK direct-call legs.
 *
 * RED on dc7552e (the frozen RC45 review subject) — each named "[RED on
 * dc7552e]": the owner / agent / approver-only legacy reject and legacy
 * signature matrix cells on v0.4 records (200 + WALLET_REJECTED written, 403,
 * 422, or a node connection where 404 with nothing written is required), the
 * v0.2 delegate rejecting the owner's v0.2 request (200 where 403
 * REQUEST_FORBIDDEN is required), the synthetic sweep, the repeat and
 * suspension legs, and the two SDK defence-in-depth legs.
 * HOLDS on dc7552e (and must keep holding): the foreign and unauthenticated
 * legacy cells (404 / 401), the v0.4 reject route matrix (RC45 A2), the owner
 * and the signer rejecting v0.2 requests, a v0.2 signer reaching the v0.2
 * signing pipeline, and markWalletRejected on a v0.2 record.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode, wallet
 * sessions signed in with TEST keys through /auth/challenge + /auth/verify;
 * sdk/testutil/rc45-f3-kit.js apiFor) plus SDK. Real v0.4.1 compiler and
 * builder, the real v0.2 compiler, pv_call_encoder and builder
 * (sdk/testutil/rc45-r1-legacy-kit.js, in a child bound to an EXPLICIT mocked
 * chain model), TEST-key signatures (deterministic dev signer) and the
 * pinned pv_vm_preflight for the owner's finalize in the repeat leg. No node:
 * every config names ws://127.0.0.1:1 and the node sentinel replaces the only
 * node client for every route call (a cell's "node calls" count is the number
 * of node clients constructed). Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). Hostile principals: a FOREIGN
 * wallet (0x33) and an UNAUTHENTICATED caller in every route family below.
 */
const path = require("node:path");
const util = require("node:util");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const L = require("../testutil/rc45-r1-legacy-kit");
/* RC45 R2-13 seam: a build or check of a new or changed delegate leaf reads the
 * node's DAA through chain.readAnchorDaa. 0 is at or below every delegate start
 * this file commits, so max(start, DAA) keeps each fixture's start unchanged. */
const { useAnchorDaa } = require("../testutil/rc45-r2-daa");
useAnchorDaa(0n);
const { KAS, LOOPBACK } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const wr2 = require(path.join(SDK_SRC, "wallet-requests-v2.js"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const V4_SCHEMA = "policyvault-wallet-request/v4";
const V = K.vault("r1-01-legacy"); // the v0.4.1 vault (one covenant approver)
const G = K.vault("r1-01-genesis"); // the identity of the owner's BUILT v0.4.1 genesis (no manifest yet)
const MISSING_ID = "00000000-0000-4000-8000-0000000000f1";
const V4_KEYS = ["pause", "recover", "removeAgent", "spend", "genesis"];
const V2_KEYS = ["v2pause", "v2spend"];
const SIGNER = { pause: "owner", recover: "owner", removeAgent: "owner", spend: "agent", genesis: "owner", v2pause: "owner", v2spend: "agent" };
const PRINCIPALS = ["owner", "agent", "approver", "foreign", "unauth"];
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, w = null, history = null, templateRoot = null, ids = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();

/* A v0.4.1 vault: owner 0x11, agent 0x21 (recipient 0x31), ONE covenant approver 0x32 (approvalM 1); 0x33 is foreign. */
function agentEntry() {
  return { agentPk: w.agent.xonly, maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0", approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: KAS.toString(), recipients: [w.recipient.xonly] };
}
async function seedApproverVault(config, v) {
  const m = cand, entry = agentEntry(), template = { owner: w.owner.xonly, vaultId: v.vaultId };
  const policy = m.agents.normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: m.recipients.buildRecipientTree(entry.recipients).root });
  const state = m.vs4.normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: m.agents.buildAgentTreeV4([policy]).root, approvers: [w.recipient2.xonly], approvalM: "1", policyNonce: "0" });
  const contractVersion = m.vs4.CONTRACT_VERSION_V4_1;
  const compiled = m.compiler4.compileExactStateV4({ config, template, state, contractVersion });
  await m.manifest4.persistManifestV4(config, { schema: "policyvault-vault-manifest/v4", contractVersion, networkId: config.networkId, vaultId: v.vaultId, label: `RC45 R1-01 TEST ${v.tag}`, status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: m.vs4.stateToJsonV4(state), stateId: m.vs4.computeStateIdV4({ networkId: config.networkId, template, state, contractVersion }), outpoint: { transactionId: v.out, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: v.cov },
    creationTxId: v.out, latestTransitionTxId: null, lastTransition: null });
}

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r1-01-template-"), rpcUrl: LOOPBACK });
  assert.equal(template.tenancyEnforced, false, "the template is self-hosted (tenancy off); every case is hosted");
  assert.equal(template.networkId, "testnet-10");
  w = K.walletsFor(template);
  await seedApproverVault(template, V);
  const k = K.kitFor(cand, template, w);
  const pause = await k.ownerOp(V, "ownerPause", "fuel"); await K.sleep(3);
  const recover = await k.ownerOp(V, "ownerRecover", "fuel2"); await K.sleep(3);
  const removeAgent = await cand.wr4.buildWalletRequestV4({ config: template, vaultId: V.vaultId, action: "removeAgent", params: { agentPk: w.agent.xonly, fuel: k.fuelOf(V, "fuel3") }, signerAddress: w.owner.address }); await K.sleep(3);
  const spend = await k.agentSpend(V, 3); await K.sleep(3);
  const genesis = await cand.wr4.buildCreateWalletRequestV4({ config: template, templateInput: { owner: w.owner.xonly, vaultId: G.vaultId }, initialAgents: [agentEntry()],
    initialState: { protectedValue: (100n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: w.owner.address,
    funding: [{ outpoint: { transactionId: G.fuel, index: 0 }, amount: (200n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` }], label: "RC45 R1-01 TEST genesis", contractVersion: cand.vs4.CONTRACT_VERSION_V4_1 });
  for (const r of [pause, recover, removeAgent, spend, genesis]) {
    assert.equal(r.schema, V4_SCHEMA, `${r.action} is a v0.4 record`);
    assert.equal(r.state, "BUILT", `${r.action} is BUILT`);
  }
  assert.equal(genesis.kind, "genesis");
  const v2 = L.buildV2Records(template, "r1-01");
  ids = { pause: pause.requestId, recover: recover.requestId, removeAgent: removeAgent.requestId, spend: spend.requestId, genesis: genesis.requestId, v2pause: v2.pause, v2spend: v2.spend, v2Vault: v2.vaultId };
  for (const key of V2_KEYS) {
    const r = await wr2.loadRequest(template, ids[key]);
    assert.equal(r.schema, L.V2_REQUEST_SCHEMA); assert.equal(r.state, "BUILT"); assert.equal(r.contractVersion, "policyvault-0.2");
  }
  history = await K.snapshot(cand, template);
  templateRoot = template.dataRoot;
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* A fresh hosted case (authMode enabled; owner, agent, approver-only and foreign wallets signed in with TEST keys). */
async function fresh(backend) {
  const dataRoot = mk("pv-rc45-r1-01-case-");
  K.warmCompileCache(templateRoot, dataRoot);
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot, rpcUrl: LOOPBACK };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1_01_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig(hosted);
  assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), api = F3.apiFor(config);
  const x = { config, store, api, pgDatabase, k: K.kitFor(cand, config, w), raw: (id) => store.read(Categories.REQUEST, id) };
  x.cookie = { owner: await api.signIn(w.owner), agent: await api.signIn(w.agent), approver: await api.signIn(w.recipient2), foreign: await api.signIn(w.recipient3), unauth: null };
  x.snap = async () => ({ ...(await K.snapshot(cand, config)), events: await L.eventRows(config) });
  /* The routes, spelled as literal request paths (this file is the GATE 1 hostile evidence of these rows). */
  x.legacyReject = (cookie, requestId) => api.call("POST", ["wallet", "requests", requestId, "reject"], {}, cookie);
  x.legacySignature = (cookie, requestId, signedSafeJson) => api.call("POST", ["wallet", "requests", requestId, "signature"], { signedSafeJson }, cookie);
  x.v4Reject = (cookie, requestId) => api.call("POST", ["wallet", "v4", "requests", requestId, "reject"], {}, cookie);
  x.v4Signature = (cookie, requestId, signedSafeJson) => api.call("POST", ["wallet", "v4", "requests", requestId, "signature"], { signedSafeJson }, cookie);
  x.v4Build = (cookie, body) => api.call("POST", ["wallet", "v4", "requests"], body, cookie);
  /* A shape-valid wallet payload for `requestId`: a v0.4 record carries its own signer's TEST-key signature over its
   * exact unsigned bytes; any other record carries its stored unsigned Safe JSON or a minimal { inputs: [{}] }. */
  x.payloadFor = async (requestId) => {
    const r = await x.raw(requestId);
    if (r && V4_KEYS.some((key) => ids[key] === requestId)) return x.k.sign(await cand.wr4.loadRequest(config, requestId), r.signerAddress === w.agent.address ? w.agent : w.owner);
    if (r && r.transaction && typeof r.transaction.unsignedSafeJson === "string") return r.transaction.unsignedSafeJson;
    return JSON.stringify({ inputs: [{}] });
  };
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

/* ---------------- the expected outcome of one matrix cell ---------------- */
const SKIP = Symbol("skip");
const idOf = (key) => (key === "missing" ? MISSING_ID : ids[key]);
function expectedLegacy(route, principal, key) {
  if (principal === "unauth") return { status: 401 }; // authenticate first, unchanged (C7 step 1)
  if (key === "missing" || V4_KEYS.includes(key)) return { status: 404, code: "REQUEST_NOT_FOUND" }; // C7 step 2 / C6
  if (principal === "approver" || principal === "foreign") return { status: 404, code: "REQUEST_NOT_FOUND" }; // not a participant of the v0.2 vault
  if (route === "legacyReject") {
    if (principal === "owner" || SIGNER[key] === principal) return { status: 200, state: "WALLET_REJECTED" };
    return { status: 403, code: "REQUEST_FORBIDDEN" }; // the v0.2 delegate on the owner's request (AZ-03)
  }
  if (SIGNER[key] === principal) return { pipeline: true }; // the v0.2 signer reaches the v0.2 signing pipeline (one node connection, refused by the sentinel)
  return { status: 403, code: "NOT_THE_SIGNER" };
}
function expectedV4Reject(principal, key) {
  if (principal === "unauth") return { status: 401 };
  if (principal === "foreign" || key === "missing") return { status: 404, code: "REQUEST_NOT_FOUND" };
  if (key === "genesis") return principal === "owner" ? SKIP : { status: 404, code: "REQUEST_NOT_FOUND" }; // non-participants of an unborn vault
  if (V2_KEYS.includes(key)) {
    if (principal === "approver") return { status: 404, code: "REQUEST_NOT_FOUND" };
    if (principal === "owner" || SIGNER[key] === principal) return SKIP; // AZ-09: separate follow-up finding (K2), not pinned here
    return { refused: true };
  }
  if (principal === "approver") return { status: 403, code: "REQUEST_FORBIDDEN" };
  if (principal === "owner" || SIGNER[key] === principal) return { status: 200, state: "WALLET_REJECTED" };
  return { status: 403, code: "REQUEST_FORBIDDEN" }; // RC45 A2: an agent on the owner's request
}
async function runCell(x, route, principal, key) {
  const id = idOf(key), cookie = x.cookie[principal];
  const payload = route === "legacySignature" ? await x.payloadFor(id) : null;
  const before = await x.snap(), recordBefore = await x.raw(id);
  const { value: r, nodeCalls } = await L.withNodeSentinel(x.config, () => (route === "legacySignature" ? x.legacySignature(cookie, id, payload) : x[route](cookie, id)));
  const after = await x.snap(), recordAfter = await x.raw(id);
  return { r, nodeCalls, wrote: !util.isDeepStrictEqual(before, after), stateBefore: recordBefore ? recordBefore.state : null, stateAfter: recordAfter ? recordAfter.state : null };
}
function verdict(exp, got) {
  const { r, nodeCalls, wrote, stateAfter } = got;
  if (exp.pipeline) return r.status === 422 && nodeCalls === 1 && !wrote ? null : `reaches the v0.2 pipeline (422 after one refused node connection, nothing written); got ${said(r)}, node calls ${nodeCalls}, wrote ${wrote}`;
  if (exp.refused) return r.status !== 200 && r.status >= 400 && nodeCalls === 0 && !wrote ? null : `refused with nothing written; got ${said(r)}, wrote ${wrote}`;
  if (exp.status === 200) return r.status === 200 && stateAfter === exp.state && nodeCalls === 0 ? null : `200 and ${exp.state}; got ${said(r)}, state ${stateAfter}, node calls ${nodeCalls}`;
  const ok = r.status === exp.status && (exp.code === undefined || r.code === exp.code) && !wrote && nodeCalls === 0;
  return ok ? null : `${exp.status}${exp.code ? " " + exp.code : ""} with nothing written and no node call; got ${said(r)}, wrote ${wrote} (state ${got.stateBefore} -> ${stateAfter}), node calls ${nodeCalls}`;
}
async function matrixRow(x, route, principal) {
  const violations = [];
  for (const key of [...V4_KEYS, ...V2_KEYS, "missing"]) {
    const exp = route === "v4Reject" ? expectedV4Reject(principal, key) : expectedLegacy(route, principal, key);
    if (exp === SKIP) continue;
    const why = verdict(exp, await runCell(x, route, principal, key));
    if (why) violations.push(`${route} ${principal} -> ${key}: expected ${why}`);
  }
  return violations;
}

/* SYNTHETIC records of every other schema that shares Categories.REQUEST (plus an unknown schema, a case variant and a
 * schema-less record), BUILT, signed by the owner, on the v0.2 vault: the routes and the SDK must refuse on the schema. */
const OTHER_SCHEMAS = ["policyvault-wallet-request/v4", "policyvault-wallet-request/v5", "policyvault-wallet-request/v6", "policyvault-wallet-request/v7", "policyvault-wallet-request/v7-kas",
  "policyvault-wallet-request/v7-hd", "policyvault-org-root-request/1", "policyvault-headless-creation/v1", "policyvault-wallet-request/v3", "policyvault-wallet-request/V2", null];
async function seedSynthetic(x) {
  const out = [];
  for (const schema of OTHER_SCHEMAS) {
    const requestId = crypto.randomUUID();
    const record = { requestId, state: "BUILT", contractVersion: "policyvault-0.2", networkId: x.config.networkId, vaultId: ids.v2Vault, action: "ownerPause", signerRole: "owner", signerAddress: w.owner.address,
      transaction: { unsignedSafeJson: JSON.stringify({ inputs: [{}] }), signInputs: [{ index: 0, sighashType: 1 }], covenantInputIndex: 0 }, createdAt: new Date().toISOString() };
    if (schema !== null) record.schema = schema;
    await x.store.write(Categories.REQUEST, requestId, record);
    out.push({ schema: String(schema), requestId });
  }
  return out;
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r1 = (name, fn) => test(`RC45 R1-01 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  /* ---------------- the legacy reject route (C7) ---------------- */
  r1("legacy reject x owner: every v0.4 record (BUILT ownerPause / ownerRecover / removeAgent, the agent's BUILT agentSpend, the owner's own BUILT v0.4.1 genesis) and a missing id answer 404 REQUEST_NOT_FOUND with nothing written; the owner still rejects both v0.2 requests [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacyReject", "owner"), [], "legacy reject: non-v0.2 records are REQUEST_NOT_FOUND; v0.2 rejection is signer-or-owner (plan R1-01, C7)");
  });
  r1("legacy reject x agent (the v0.4 agent and the v0.2 delegate): every v0.4 record including its own spend answers 404 with nothing written; on v0.2 the delegate rejects its own spend but gets 403 REQUEST_FORBIDDEN on the owner's request (AZ-03) [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacyReject", "agent"), [], "legacy reject: non-v0.2 records are REQUEST_NOT_FOUND; v0.2 rejection is signer-or-owner (plan R1-01, C7)");
  });
  r1("legacy reject x approver-only principal: every v0.4 record answers 404 with nothing written (it cannot cancel the owner's Pause / Close & recover / removeAgent or the agent's spend); v0.2 records of a vault it is foreign to answer 404 [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacyReject", "approver"), [], "legacy reject: non-v0.2 records are REQUEST_NOT_FOUND (plan R1-01, C7)");
  });
  r1("legacy reject x FOREIGN principal: every record and a missing id answer the non-oracle 404 REQUEST_NOT_FOUND with nothing written", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacyReject", "foreign"), []);
  });
  r1("legacy reject x UNAUTHENTICATED caller: v0.4, v0.2 and missing ids all answer 401 before anything is loaded or written (authenticate first, C7)", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacyReject", "unauth"), []);
  });

  /* ---------------- the legacy signature route (C6, AZ-04) ---------------- */
  r1("legacy signature x owner: its BUILT v0.4.1 genesis and v0.4 transitions (with the owner's own TEST-key signature) and the agent's spend answer 404 REQUEST_NOT_FOUND with nothing written, no node call and no broadcast; the owner's v0.2 request still reaches the v0.2 pipeline [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacySignature", "owner"), [], "legacy signature: non-v0.2 records are REQUEST_NOT_FOUND before any signer check, write or node call (plan R1-01, C6)");
  });
  r1("legacy signature x agent: its own BUILT v0.4 spend (with its own TEST-key signature) and the owner's v0.4 records answer 404 with nothing written and no node call; on v0.2 the delegate's own spend reaches the v0.2 pipeline and the owner's request answers 403 NOT_THE_SIGNER [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacySignature", "agent"), [], "legacy signature: non-v0.2 records are REQUEST_NOT_FOUND before any signer check, write or node call (plan R1-01, C6)");
  });
  r1("legacy signature x approver-only principal: every v0.4 record answers 404 (not the 403 of the mutation gate) with nothing written and no node call [RED on dc7552e]", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacySignature", "approver"), [], "legacy signature: non-v0.2 records are REQUEST_NOT_FOUND before any signer check (plan R1-01, C6)");
  });
  r1("legacy signature x FOREIGN principal: every record and a missing id answer the non-oracle 404 REQUEST_NOT_FOUND with nothing written and no node call", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacySignature", "foreign"), []);
  });
  r1("legacy signature x UNAUTHENTICATED caller (shape-valid payloads): v0.4, v0.2 and missing ids all answer 401 with nothing written and no node call", async (x) => {
    assert.deepEqual(await matrixRow(x, "legacySignature", "unauth"), []);
  });

  /* ---------------- the v0.4 reject route (RC45 A2; the AZ-09 cells are left out, K2) ---------------- */
  for (const principal of PRINCIPALS) {
    r1(`v0.4 reject x ${principal === "unauth" ? "UNAUTHENTICATED caller" : principal === "foreign" ? "FOREIGN principal" : principal}: signer or owner only on v0.4 records (A2), 403 / 404 otherwise with nothing written; v0.2 records are refused for every non-signer non-owner`, async (x) => {
      assert.deepEqual(await matrixRow(x, "v4Reject", principal), []);
    });
  }

  /* ---------------- the SYNTHETIC non-v0.2 schema sweep (fail closed on the schema alone) ---------------- */
  r1("SYNTHETIC sweep: a BUILT record of every other schema sharing the REQUEST category (v4, v5, v6, v7, v7-kas, v7-hd, org-root, headless creation), an unknown v3, a case variant 'V2' and a schema-less record, each signed by the owner on the owner's v0.2 vault, answers 404 REQUEST_NOT_FOUND on the legacy reject and the legacy signature route for its own signer, with nothing written and no node call [RED on dc7552e]", async (x) => {
    const violations = [];
    for (const route of ["legacySignature", "legacyReject"]) {
      for (const { schema, requestId } of await seedSynthetic(x)) { // a fresh BUILT set per route
        const before = await x.snap();
        const { value: r, nodeCalls } = await L.withNodeSentinel(x.config, () => (route === "legacyReject" ? x.legacyReject(x.cookie.owner, requestId) : x.legacySignature(x.cookie.owner, requestId, JSON.stringify({ inputs: [{}] }))));
        const wrote = !util.isDeepStrictEqual(before, await x.snap());
        if (!(r.status === 404 && r.code === "REQUEST_NOT_FOUND" && !wrote && nodeCalls === 0)) violations.push(`${route} on schema ${schema}: ${said(r)}, wrote ${wrote}, node calls ${nodeCalls}`);
      }
    }
    assert.deepEqual(violations, [], "the legacy routes admit only policyvault-wallet-request/v2 records (plan R1-01: missing or record.schema !== v2 -> 404, no write)");
  });

  /* ---------------- the repeat leg (the owner's hosted Pause can no longer be vetoed) ---------------- */
  r1("repeat: the owner builds Pause through the hosted v0.4 build route twice; each time the agent finds it in its own open-request listing and its legacy reject answers 404 with nothing written (the approver-only principal's too); the owner's finalize of the last Pause then succeeds (PREFLIGHT_VERIFIED, real pv_vm_preflight) [RED on dc7552e]", async (x) => {
    let last = null;
    for (const which of ["repeat-1", "repeat-2"]) {
      const fuel = { outpoint: { transactionId: K.hex(`rc45-r1-01-${which}-fuel`), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` }; // TEST fuel no other request uses
      const built = await x.v4Build(x.cookie.owner, { vaultId: V.vaultId, action: "ownerPause", params: { fuel }, signerAddress: w.owner.address });
      assert.equal(built.status, 201, `the owner's hosted Pause build (${said(built)})`);
      const id = built.body.request.requestId;
      const before = await x.snap();
      const rej = await x.legacyReject(x.cookie.agent, id);
      assert.equal(rej.status, 404, `the agent's legacy reject of the owner's hosted Pause (${which}) must be REQUEST_NOT_FOUND; got ${said(rej)} and the Pause is now ${(await x.raw(id)).state}`);
      assert.equal(rej.code, "REQUEST_NOT_FOUND");
      const rejA = await x.legacyReject(x.cookie.approver, id);
      assert.equal(rejA.status, 404, `the approver-only principal's legacy reject (${said(rejA)})`);
      assert.deepEqual(await x.snap(), before, "nothing was written by either refused legacy reject");
      const listing = await x.api.call("GET", ["wallet", "v4", "requests"], null, x.cookie.agent, { vaultId: V.vaultId, open: "1" });
      assert.equal(listing.status, 200, said(listing));
      assert.ok(listing.body.requests.some((r) => r.requestId === id && r.state === "BUILT"), "the agent still sees the owner's open Pause, BUILT");
      last = id;
    }
    const fin = await x.v4Signature(x.cookie.owner, last, x.k.sign(await cand.wr4.loadRequest(x.config, last), w.owner));
    assert.equal(fin.status, 200, `the owner's finalize of its Pause (${said(fin)})`);
    assert.equal((await x.raw(last)).state, "PREFLIGHT_VERIFIED");
  });

  /* ---------------- the agent-suspension leg ---------------- */
  r1("suspension: after the owner hosted-suspends ALL agents, the suspended agent's legacy reject of the owner's BUILT Pause and of its own BUILT spend answer 404 with nothing written; its v0.4 reject of the owner's ownerRecover stays 403 REQUEST_FORBIDDEN [RED on dc7552e]", async (x) => {
    const sus = await x.api.call("POST", ["vaults", V.vaultId, "agent-suspensions"], { op: "suspend", allAgents: true }, x.cookie.owner);
    assert.equal(sus.status, 200, `the owner's hosted suspension (${said(sus)})`);
    const before = await x.snap();
    const onPause = await x.legacyReject(x.cookie.agent, ids.pause);
    assert.equal(onPause.status, 404, `the suspended agent's legacy reject of the owner's Pause must be REQUEST_NOT_FOUND; got ${said(onPause)} and the Pause is now ${(await x.raw(ids.pause)).state}`);
    assert.equal(onPause.code, "REQUEST_NOT_FOUND");
    const onSpend = await x.legacyReject(x.cookie.agent, ids.spend);
    assert.equal(onSpend.status, 404, `the suspended agent's legacy reject of its own v0.4 spend (${said(onSpend)})`);
    const v4 = await x.v4Reject(x.cookie.agent, ids.recover);
    assert.equal(v4.status, 403, `the suspended agent's v0.4 reject of the owner's ownerRecover (${said(v4)})`);
    assert.equal(v4.code, "REQUEST_FORBIDDEN");
    assert.deepEqual(await x.snap(), before, "nothing was written");
    const agentBuild = await x.v4Build(x.cookie.agent, { vaultId: V.vaultId, action: "agentSpend", params: x.k.spend(2n * KAS), signerAddress: w.agent.address });
    assert.notEqual(agentBuild.status, 201, `the suspension holds for the agent's new builds (${said(agentBuild)})`);
  });

  /* ---------------- SDK defence in depth (sdk/src/wallet-requests-v2.js) ---------------- */
  r1("SDK markWalletRejected (direct call, no route): every non-v0.2 record (the owner's v0.4 Pause, the agent's v0.4 spend, the v0.4.1 genesis and the SYNTHETIC sweep) returns null with nothing written [RED on dc7552e]", async (x) => {
    const synthetic = await seedSynthetic(x), violations = [];
    for (const [label, id] of [["v4 ownerPause", ids.pause], ["v4 agentSpend", ids.spend], ["v4 genesis", ids.genesis], ...synthetic.map((s) => [`schema ${s.schema}`, s.requestId])]) {
      const before = await x.snap();
      const out = await wr2.markWalletRejected(x.config, id);
      const wrote = !util.isDeepStrictEqual(before, await x.snap());
      if (!(out === null && !wrote)) violations.push(`${label}: returned ${out === null ? "null" : `a record (${out && out.state})`}, wrote ${wrote}`);
    }
    assert.deepEqual(violations, [], "markWalletRejected returns null and writes nothing unless request.schema is the v2 schema (plan R1-01 defence in depth)");
  });
  r1("SDK markWalletRejected on the owner's BUILT v0.2 request still writes WALLET_REJECTED, and a missing id returns null", async (x) => {
    assert.equal(await wr2.markWalletRejected(x.config, MISSING_ID), null);
    const out = await wr2.markWalletRejected(x.config, ids.v2pause);
    assert.equal(out.state, "WALLET_REJECTED");
    assert.equal((await x.raw(ids.v2pause)).state, "WALLET_REJECTED");
  });
  r1("SDK attachWalletSignatureV2 (direct call, no route): the owner's BUILT v0.4.1 genesis with the owner's TEST-key signature, the owner's v0.4 Pause, the agent's v0.4 spend and the SYNTHETIC sweep are refused with nothing written and no node call (no v0.2 genesis signing or broadcast path is entered) [RED on dc7552e]", async (x) => {
    const synthetic = await seedSynthetic(x), violations = [];
    const cases = [["v4 genesis", ids.genesis], ["v4 ownerPause", ids.pause], ["v4 agentSpend", ids.spend], ...synthetic.map((s) => [`schema ${s.schema}`, s.requestId])];
    for (const [label, id] of cases) {
      const signedSafeJson = await x.payloadFor(id), before = await x.snap();
      const { value: outcome, nodeCalls } = await L.withNodeSentinel(x.config, async () => {
        try { return { resolved: await wr2.attachWalletSignatureV2({ config: x.config, requestId: id, signedSafeJson }) }; } catch (error) { return { refused: error }; }
      });
      const wrote = !util.isDeepStrictEqual(before, await x.snap());
      if (!(outcome.refused && !wrote && nodeCalls === 0)) violations.push(`${label}: ${outcome.refused ? `refused (${outcome.refused.code ?? ""} ${outcome.refused.message})` : "resolved"}, wrote ${wrote}, node calls ${nodeCalls}`);
    }
    assert.deepEqual(violations, [], "attachWalletSignatureV2 refuses every non-v2 record before any write or node call (plan R1-01 defence in depth, C6)");
  });
}
