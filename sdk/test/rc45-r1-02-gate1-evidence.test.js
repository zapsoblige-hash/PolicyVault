"use strict";
/*
 * RC45 R1-02 — FULL-PATTERN GATE 1 HOSTILE EVIDENCE for the inventory rows
 * that had none (remediation plan rc45-r1-plan-01 PLAN-R1 revision 2 §2 R1-02
 * "GATE 1: each row's hostile-evidence file must contain a request path
 * matching the row's full route pattern with its exact version segment";
 * review finding S-02). Internal regression material; not an audit.
 *
 * With GATE 1 bound to the full route pattern (sdk/test/authorization-
 * boundary-inventory.test.js on sdk/testutil/rc45-r1-authorization-binding.js),
 * a scan of every sdk/web/server test at dc7552e found NO file exercising
 * these routes by their exact path with a hostile principal (the old check was
 * satisfied by the static segments alone: the v0.6 rows by the v0.5 legs, the
 * member rows by POST /organizations/:id/members):
 *   GET  /wallet/v6/requests/:id
 *   POST /wallet/v6/requests/:id/signature | /submit | /reject
 *   POST /organizations/:id/members/:m
 *   POST /organizations/:id/members/:m/remove
 * This file is that evidence, so the R1-02 inventory correction can name it:
 * a FOREIGN wallet gets the non-oracle 404 and an UNAUTHENTICATED caller 401
 * on each route, with nothing written; the owner's positive controls succeed.
 * These legs HOLD on dc7552e (the tenancy gates exist; only the evidence was
 * missing) and must keep holding.
 *
 * Layers: API (the real server/src/api.js handle in hosted mode with TEST-key
 * wallet sessions, sdk/testutil/rc45-f3-kit.js apiFor) plus SDK (the real
 * v0.6 controller genesis builder with the real KCC20 template compiler).
 * Nothing dials a node (every config names ws://127.0.0.1:1). Both stores:
 * JSON always; PostgreSQL with POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the
 * rc45 runner's pg mode; a skipped PostgreSQL leg there is a FAIL). TEST keys
 * only.
 */
const path = require("node:path");
const util = require("node:util");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const { KAS, LOOPBACK } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const wr6 = require(path.join(SDK_SRC, "wallet-requests-v6.js"));
const assets = require("../../core/assets");
const { compileKcc20Program } = require(path.join(SDK_SRC, "token-program-kcc20.js"));
const { buildRecipientTree } = require(path.join(SDK_SRC, "recipient-merkle-v3.js"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const H = (b) => b.toString(16).padStart(2, "0").repeat(32);
const roots = [], stores = [], databases = [];
let admin = null, serial = 0, w = null, history = null, v6Id = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const said = (r) => `${r.status} ${r.code ?? ""} ${r.message ?? ""}`.trim();

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  const template = cand.config.loadConfig({ dataRoot: mk("pv-rc45-r1-02-g1-template-"), rpcUrl: LOOPBACK });
  w = K.walletsFor(template);
  const ref = compileKcc20Program({ config: template, state: assets.kcc20.ZERO_STATE, familyBound: 2 });
  const descriptor = {
    schema: "policyvault-asset-descriptor/1", assetId: H(0x11), displayName: "R1-02 TEST Token", tokenStandard: "kcc20/1", tokenCovenantId: H(0x54),
    acceptedTransferTemplates: [{ templateVmHashBlake2b256: ref.templateVmHashBlake2b256, prefixLen: ref.geometry.prefixLen, suffixLen: ref.geometry.suffixLen, stateLayout: "kcc20-state/1" }],
    decimalsDisplay: 2,
    issuerPowers: { mint: false, burn: false, freeze: false, blacklist: false, redemptionControl: false, upgradeMigration: false, controllerRotation: false, emergencyControl: false }
  };
  const policy = { agentPk: w.agent.xonly, tokenMaxPerSpend: "500", tokenPeriodBudget: "1000", periodLengthDaa: "1000", periodStartDaa: "0", tokenPeriodSpent: "0", agentMaxFeePerTx: KAS.toString(), agentMaxCarryKas: KAS.toString(),
    agentRecipientRoot: buildRecipientTree([w.recipient.xonly]).root, recipients: [w.recipient.xonly] };
  const req = await wr6.buildCreateWalletRequestV6({ config: template, label: "R1-02 TEST v0.6 controller", descriptor, templateIndex: 0, initialAgents: [policy], initialSwapPolicies: [], feeReserveKas: "5",
    signerAddress: w.owner.address, funding: [{ outpoint: { transactionId: K.hex("rc45-r1-02-g1-v6-fuel"), index: 0 }, amount: (50n * KAS).toString(), scriptPublicKeyHex: `20${w.owner.xonly}ac` }] });
  assert.equal(req.schema, "policyvault-wallet-request/v6");
  assert.equal(req.state, "BUILT");
  v6Id = req.requestId;
  history = await K.snapshot(cand, template);
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

async function fresh(backend) {
  const hosted = { authMode: "enabled", authCookieInsecure: true, dataRoot: mk("pv-rc45-r1-02-g1-case-"), rpcUrl: LOOPBACK };
  let config, pgDatabase = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r1_02_g1_${process.pid}_${++serial}`;
    await admin.query(`CREATE DATABASE ${pgDatabase}`); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...hosted });
    stores.push(await cand.store.openPgStore(config, { migrate: true }));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig(hosted);
  assert.equal(config.tenancyEnforced, true);
  await K.install(cand, config, history);
  const store = cand.store.getStore(config), api = F3.apiFor(config);
  const x = { config, store, api, pgDatabase };
  x.cookie = { owner: await api.signIn(w.owner), foreign: await api.signIn(w.recipient3), unauth: null };
  x.snap = async () => K.snapshot(cand, config);
  return x;
}
async function release(x) {
  if (!x.pgDatabase) return;
  const i = stores.indexOf(x.store);
  if (i >= 0) { stores.splice(i, 1); await x.store.close(); }
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const g1 = (name, fn) => test(`RC45 R1-02 GATE 1 evidence ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend); try { await fn(x); } finally { await release(x); } });

  g1("/wallet/v6/requests/:id (GET, signature, submit, reject): a FOREIGN wallet gets the non-oracle 404 REQUEST_NOT_FOUND and an UNAUTHENTICATED caller 401 on the owner's BUILT v0.6 controller genesis request, with nothing written; the owner reads it", async (x) => {
    const before = await x.snap();
    const unsigned = (await x.store.read(Categories.REQUEST, v6Id)).transaction.unsignedSafeJson;
    const calls = [
      ["GET", ["wallet", "v6", "requests", v6Id], null],
      ["POST", ["wallet", "v6", "requests", v6Id, "signature"], { signedSafeJson: unsigned }],
      ["POST", ["wallet", "v6", "requests", v6Id, "submit"], {}],
      ["POST", ["wallet", "v6", "requests", v6Id, "reject"], {}]
    ];
    for (const [method, segments, body] of calls) {
      const foreign = await x.api.call(method, segments, body, x.cookie.foreign);
      assert.equal(foreign.status, 404, `foreign ${method} /${segments.join("/")}: ${said(foreign)}`);
      assert.equal(foreign.code, "REQUEST_NOT_FOUND");
      const unauth = await x.api.call(method, segments, body, x.cookie.unauth);
      assert.equal(unauth.status, 401, `unauthenticated ${method} /${segments.join("/")}: ${said(unauth)}`);
    }
    assert.ok(util.isDeepStrictEqual(await x.snap(), before), "nothing was written");
    const own = await x.api.call("GET", ["wallet", "v6", "requests", v6Id], null, x.cookie.owner);
    assert.equal(own.status, 200, `the owner reads its own request (${said(own)})`);
    assert.equal(own.body.request.requestId, v6Id);
  });

  g1("/organizations/:id/members/:m (update and remove): a FOREIGN wallet gets the non-oracle 404 and an UNAUTHENTICATED caller 401 on the owner's organization member, with the member unchanged; the owner updates and then removes it", async (x) => {
    const created = await x.api.call("POST", ["organizations"], { name: "R1-02 TEST org" }, x.cookie.owner);
    assert.equal(created.status, 201, said(created));
    const orgId = created.body.organization.orgId;
    const added = await x.api.call("POST", ["organizations", orgId, "members"], { displayName: "R1-02 member", roles: ["viewer"], expectedVersion: created.body.organization.version }, x.cookie.owner);
    assert.equal(added.status, 201, said(added));
    const memberId = added.body.member.memberId, version = added.body.version;
    const orgBefore = await x.api.call("GET", ["organizations", orgId], null, x.cookie.owner);
    for (const [segments, body] of [[["organizations", orgId, "members", memberId], { displayName: "mole", expectedVersion: version }], [["organizations", orgId, "members", memberId, "remove"], { expectedVersion: version }]]) {
      const foreign = await x.api.call("POST", segments, body, x.cookie.foreign);
      assert.equal(foreign.status, 404, `foreign POST /${segments.join("/")}: ${said(foreign)}`);
      const unauth = await x.api.call("POST", segments, body, x.cookie.unauth);
      assert.equal(unauth.status, 401, `unauthenticated POST /${segments.join("/")}: ${said(unauth)}`);
    }
    const orgAfter = await x.api.call("GET", ["organizations", orgId], null, x.cookie.owner);
    assert.deepEqual(orgAfter.body.organization, orgBefore.body.organization, "the organization and its member are unchanged");
    const updated = await x.api.call("POST", ["organizations", orgId, "members", memberId], { displayName: "R1-02 member renamed", expectedVersion: version }, x.cookie.owner);
    assert.equal(updated.status, 200, `the owner updates its member (${said(updated)})`);
    const removed = await x.api.call("POST", ["organizations", orgId, "members", memberId, "remove"], { expectedVersion: updated.body.version }, x.cookie.owner);
    assert.equal(removed.status, 200, `the owner removes its member (${said(removed)})`);
  });
}

