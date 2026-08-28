"use strict";

/*
 * INSTANT HOSTED-LAYER AGENT SUSPEND (fullscale surface 21 residual;
 * server/src/agent-suspensions.js + migration 007 + api.js gates +
 * scopes.js vaults:suspend-agents + events + capabilities).
 *
 * COORDINATION CONTROL, NEVER A COVENANT CONTROL — this suite proves BOTH
 * halves: (a) the server instantly refuses NEW agent-driven build/
 * finalize/submit (and reports the same refusal in dry-run simulation)
 * for suspended agents, restores on unsuspend, scope-gates and
 * tenancy-gates the flip; and (b) NOTHING anywhere treats a suspension as
 * covenant state: the vault's covenant `paused` stays untouched, owner
 * actions (including break-glass ownerPause) are never blocked, and every
 * response/refusal carries the covenant-honesty notice verbatim.
 *
 * Layers: API (real api.handle(); JSON backend; real SDK build pipeline —
 * needs the gitignored tests/vm probe binaries + sdk/node_modules) + an
 * optional POSTGRES section (migration 007 applies; the suspension store
 * round-trips through the real server against PG) that SKIPS cleanly
 * without POLICYVAULT_TEST_PG_*.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { Categories: PlatCategories, getPlatformStore } = require("../../server/src/platform-store");
const { NOT_COVENANT_NOTICE } = require("../../server/src/agent-suspensions");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-agent-suspend-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = KEY(0xb1);
const AGENT = KEY(0xb2);
const AGENT_B = KEY(0xb3);
const RECIP = KEY(0xb4);
const VAULT_ID = "4d".repeat(32);

const POST = (segs, body, headers) => handle(config, "POST", segs, {}, body, { headers: headers ?? {} });
const GET = (segs, query, headers) => handle(config, "GET", segs, query ?? {}, null, { headers: headers ?? {} });
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected an API error (${code})`);
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}

async function seedVault(cfg = config, vaultId = VAULT_ID) {
  const template = { owner: XO(OWNER), vaultId };
  const registry = [AGENT, AGENT_B].map((k) => ({
    agentPk: XO(k),
    maxPerSpend: (20n * KAS).toString(),
    periodBudget: (500n * KAS).toString(),
    periodLengthDaa: "864000",
    periodStartDaa: "541000000",
    periodSpent: "0",
    approvalThreshold: (500n * KAS).toString(),
    agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(RECIP)]
  }));
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(),
    feeReserve: (5n * KAS).toString(),
    paused: "0",
    agentRoot: buildAgentTreeV4(policies).root,
    approvers: [],
    approvalM: "0",
    policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config: cfg, template, state });
  const stateId = computeStateIdV4({ networkId: cfg.networkId, template, state });
  await persistManifestV4(cfg, {
    schema: MANIFEST_SCHEMA_V4,
    contractVersion: CONTRACT_VERSION_V4,
    networkId: cfg.networkId,
    vaultId,
    label: "suspend test",
    status: "ACTIVE",
    template,
    agentRegistry: registry,
    live: {
      state: stateToJsonV4(state),
      stateId,
      outpoint: { transactionId: "4e".repeat(32), index: 0 },
      outpointValue: (state.protectedValue + state.feeReserve).toString(),
      scriptSha256: compiled.scriptSha256,
      covenantId: "4f".repeat(32)
    },
    creationTxId: "5a".repeat(32),
    latestTransitionTxId: null,
    lastTransition: null
  });
}

const spendBody = (agent = AGENT) => ({
  vaultId: VAULT_ID,
  action: "agentSpend",
  params: { payAmountSompi: (5n * KAS).toString(), agentPk: XO(agent), recipient: XO(RECIP) },
  signerAddress: ADDR(agent)
});
const ownerFuel = () => ({ outpoint: { transactionId: "5b".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(OWNER)}ac` });

const suspendRoute = ["vaults", VAULT_ID, "agent-suspensions"];

test("setup: seed a real two-agent v0.4 vault; suspensions start empty", async () => {
  await seedVault();
  const r = await GET(suspendRoute);
  assert.equal(r.status, 200);
  assert.deepEqual({ allAgents: r.body.suspensions.allAgents, agents: r.body.suspensions.agents, version: r.body.suspensions.version }, { allAgents: false, agents: [], version: 0 });
  assert.equal(r.body.suspensions.notice, NOT_COVENANT_NOTICE, "every suspensions response carries the covenant-honesty notice verbatim");
  assert.match(NOT_COVENANT_NOTICE, /NOT a covenant control/);
  assert.match(NOT_COVENANT_NOTICE, /directly to a Kaspa node/);
  assert.match(NOT_COVENANT_NOTICE, /pause the vault or remove the agent/, "the notice pairs the control with the existing covenant pause guidance");
});

test("an unsuspended agent builds normally (baseline 201)", async () => {
  const r = await POST(["wallet", "v4", "requests"], spendBody());
  assert.equal(r.status, 201, JSON.stringify(r.body).slice(0, 300));
  assert.equal(r.body.request.state, "BUILT");
});

let builtBeforeSuspension = null;

test("suspend one agent: instant, audited, evented; response is honest about what it is NOT", async () => {
  // keep a pre-suspension BUILT request around for the finalize/submit gates
  const pre = await POST(["wallet", "v4", "requests"], spendBody());
  assert.equal(pre.status, 201);
  builtBeforeSuspension = pre.body.request;

  const r = await POST(suspendRoute, { op: "suspend", agentPk: XO(AGENT) });
  assert.equal(r.status, 200);
  assert.equal(r.body.suspensions.version, 1);
  assert.deepEqual(r.body.suspensions.agents, [XO(AGENT)]);
  assert.equal(r.body.suspensions.allAgents, false);
  assert.equal(r.body.suspensions.notice, NOT_COVENANT_NOTICE);

  // audit line exists and never claims covenant enforcement
  const audit = await GET(["audit"]);
  const line = audit.body.events.find((e) => e.action === "agent_suspension_updated" && e.result === "AGENT_SUSPENDED_HOSTED");
  assert.ok(line, "audit line for the suspension");
  assert.match(line.detail, /coordination control, never a covenant control/);

  // platform event emitted (closed catalog; rows are { cursor, event })
  const events = await GET(["events"]);
  const row = events.body.events.find((e) => e.event.type === "vault.agent.suspended");
  assert.ok(row, "vault.agent.suspended event emitted");
  assert.equal(row.event.data.agentPk, XO(AGENT));
  assert.equal(row.event.data.allAgents, false);
});

test("HOSTILE: the suspended agent's NEW build is refused instantly (0 fees, no chain interaction) with the covenant-honest refusal", async () => {
  const e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody()), 403, "AGENT_SUSPENDED_HOSTED");
  assert.match(e.message, /suspended at the hosted layer/);
  assert.match(e.message, /NOT a covenant control/);
  assert.match(e.message, /directly to a Kaspa node/);
  assert.equal(e.extra.suspension.agentPk, XO(AGENT));
});

test("HOSTILE: a request BUILT before the suspension can neither finalize nor submit while suspended", async () => {
  const id = builtBeforeSuspension.requestId;
  const fin = await expectThrow(POST(["wallet", "v4", "requests", id, "signature"], { signedSafeJson: "{}" }), 403, "AGENT_SUSPENDED_HOSTED");
  assert.match(fin.message, /finalize this request/);
  const sub = await expectThrow(POST(["wallet", "v4", "requests", id, "submit"], {}), 403, "AGENT_SUSPENDED_HOSTED");
  assert.match(sub.message, /submit this request/);
});

test("dry-run simulation reports the SAME refusal (never ok:true for an operation the real route refuses)", async () => {
  const r = await POST(["wallet", "v4", "simulate"], spendBody());
  assert.equal(r.status, 200);
  assert.equal(r.body.simulation.ok, false);
  assert.equal(r.body.simulation.refusalReason.code, "AGENT_SUSPENDED_HOSTED");
  assert.match(r.body.simulation.refusalReason.message, /NOT a covenant control/);
});

test("suspension is PER-AGENT: the other agent still builds; and it NEVER touches covenant state or owner authority", async () => {
  const other = await POST(["wallet", "v4", "requests"], spendBody(AGENT_B));
  assert.equal(other.status, 201, "the un-suspended agent is unaffected");

  // covenant state untouched: the vault is NOT paused (suspension is not pause)
  const vault = await GET(["vaults", VAULT_ID]);
  assert.equal(vault.body.live.paused, false, "a hosted suspension must never masquerade as covenant pause");

  // owner actions — including break-glass ownerPause — are never suspend-gated:
  // the REAL covenant control stays available while the hosted stopgap is active
  const pause = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(OWNER) });
  assert.equal(pause.status, 201, "break-glass ownerPause must build while an agent is suspended");
  await POST(["wallet", "v4", "requests", pause.body.request.requestId, "reject"], {});
});

test("unsuspend restores the agent immediately (CAS-guarded)", async () => {
  await expectThrow(POST(suspendRoute, { op: "unsuspend", agentPk: XO(AGENT), expectedVersion: 0 }), 409, "VERSION_CONFLICT");
  const r = await POST(suspendRoute, { op: "unsuspend", agentPk: XO(AGENT), expectedVersion: 1 });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.suspensions.agents, []);
  const build = await POST(["wallet", "v4", "requests"], spendBody());
  assert.equal(build.status, 201, "unsuspend restores building");
  const ev = await GET(["events"]);
  assert.ok(ev.body.events.some((e) => e.event.type === "vault.agent.unsuspended"), "unsuspend event emitted");
});

test("suspend ALL agents of the vault: every agent refused; unsuspending all restores", async () => {
  const r = await POST(suspendRoute, { op: "suspend", allAgents: true });
  assert.equal(r.status, 200);
  assert.equal(r.body.suspensions.allAgents, true);
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody()), 403, "AGENT_SUSPENDED_HOSTED");
  await expectThrow(POST(["wallet", "v4", "requests"], spendBody(AGENT_B)), 403, "AGENT_SUSPENDED_HOSTED");
  const off = await POST(suspendRoute, { op: "unsuspend", allAgents: true });
  assert.equal(off.body.suspensions.allAgents, false);
  const build = await POST(["wallet", "v4", "requests"], spendBody());
  assert.equal(build.status, 201);
});

test("fail-closed input handling: unknown agent key, malformed op, both-selectors, bad agentPk", async () => {
  await expectThrow(POST(suspendRoute, { op: "suspend", agentPk: "ab".repeat(32) }), 422, "AGENT_UNKNOWN");
  await expectThrow(POST(suspendRoute, { op: "freeze", agentPk: XO(AGENT) }), 400, "BAD_SUSPENSION_OP");
  await expectThrow(POST(suspendRoute, { op: "suspend", agentPk: XO(AGENT), allAgents: true }), 400, "BAD_SUSPENSION_OP");
  await expectThrow(POST(suspendRoute, { op: "suspend", agentPk: "not-hex" }), 400, "BAD_AGENT_PK");
  // unsuspend stays permissive for stale keys (clearable after removeAgent)
  const stale = await POST(suspendRoute, { op: "unsuspend", agentPk: "ab".repeat(32) });
  assert.equal(stale.status, 200);
});

test("HOSTILE: a CORRUPT stored suspension record fails CLOSED (refuses agent builds; never silently 'not suspended')", async () => {
  const store = getPlatformStore(config);
  const good = await store.read(PlatCategories.AGENT_SUSPENSION, VAULT_ID);
  await store.write(PlatCategories.AGENT_SUSPENSION, VAULT_ID, { schema: "policyvault-agent-suspensions/v999", vaultId: VAULT_ID, evil: true });
  const e = await expectThrow(POST(["wallet", "v4", "requests"], spendBody()), 500, "SUSPENSIONS_SCHEMA_UNKNOWN");
  assert.match(e.message, /failing closed/);
  await expectThrow(GET(suspendRoute), 500, "SUSPENSIONS_SCHEMA_UNKNOWN");
  await store.write(PlatCategories.AGENT_SUSPENSION, VAULT_ID, good); // repair
  const build = await POST(["wallet", "v4", "requests"], spendBody());
  assert.equal(build.status, 201);
});

test("copy/logic sweep: nothing presents a suspension as pause or covenant state", async () => {
  const r = await GET(suspendRoute);
  const text = JSON.stringify(r.body);
  assert.ok(!/"paused"/.test(text), "the suspensions document never carries a covenant paused field");
  assert.match(text, /NOT a covenant control/);
  const caps = await GET(["capabilities"]);
  const suspendScope = caps.body.scopes.find((s) => s.scope === "vaults:suspend-agents");
  assert.match(suspendScope.description, /NEVER a covenant control/);
  assert.equal(caps.body.features.hostedAgentSuspend, true);
});

/* ---------------- hosted mode: scope + tenancy gating ---------------- */

const hostedRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-agent-suspend-hosted-"));
const hostedConfig = loadConfig({ dataRoot: hostedRoot, authMode: "enabled", authCookieInsecure: true });
const HPOST = (segs, body, headers) => handle(hostedConfig, "POST", segs, {}, body, { headers: headers ?? {} });
const HGET = (segs, query, headers) => handle(hostedConfig, "GET", segs, query ?? {}, null, { headers: headers ?? {} });

test("hosted: machine identities are scope-gated (deny-by-default) AND owner-tenancy-gated; cross-tenant flips are refused", async () => {
  await seedVault(hostedConfig);
  const mi = require("../../server/src/machine-identity");

  // owner-created machine identity WITHOUT the dedicated scope: 403 SCOPE_FORBIDDEN
  const noScope = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(OWNER), label: "no-scope", scopes: ["request:build", "read:vaults"] });
  const noScopeAuth = { authorization: `Bearer ${noScope.credential.token}` };
  await expectThrow(HPOST(suspendRoute, { op: "suspend", agentPk: XO(AGENT) }, noScopeAuth), 403, "SCOPE_FORBIDDEN");

  // TRULY FOREIGN wallet's machine identity WITH the scope: tenancy hides
  // the vault entirely (404 — existence oracle discipline)
  const outsider = KEY(0xb9); // not a covenant participant of the vault
  const foreign = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(outsider), label: "foreign", scopes: ["vaults:suspend-agents"] });
  const foreignAuth = { authorization: `Bearer ${foreign.credential.token}` };
  await expectThrow(HPOST(suspendRoute, { op: "suspend", agentPk: XO(AGENT) }, foreignAuth), 404, "VAULT_NOT_FOUND");

  // a PARTICIPANT (agent) who is not the owner, WITH the scope: the vault
  // is visible to them, but the flip needs the OWNER role (403)
  const participant = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(AGENT_B), label: "participant", scopes: ["vaults:suspend-agents"] });
  await expectThrow(HPOST(suspendRoute, { op: "suspend", agentPk: XO(AGENT) }, { authorization: `Bearer ${participant.credential.token}` }), 403, "VAULT_FORBIDDEN");

  // owner-created machine identity WITH the scope: allowed, attributed as machine
  const scoped = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(OWNER), label: "scoped", scopes: ["vaults:suspend-agents", "read:vaults"] });
  const scopedAuth = { authorization: `Bearer ${scoped.credential.token}` };
  const on = await HPOST(suspendRoute, { op: "suspend", agentPk: XO(AGENT) }, scopedAuth);
  assert.equal(on.status, 200);
  assert.equal(on.body.suspensions.updatedBy.type, "machine");
  assert.equal(on.body.suspensions.updatedBy.identityId, scoped.identity.identityId);

  // the suspension ENFORCES against machine-driven builds too
  const buildScoped = await mi.createIdentity(hostedConfig, { creatorXOnly: XO(AGENT), label: "agent-bot", scopes: ["request:build", "read:vaults"] });
  const e = await expectThrow(
    HPOST(["wallet", "v4", "requests"], spendBody(), { authorization: `Bearer ${buildScoped.credential.token}` }),
    403,
    "AGENT_SUSPENDED_HOSTED"
  );
  assert.match(e.message, /NOT a covenant control/);

  // agent-participant READ visibility: the suspended agent's credential can SEE the suspension
  const view = await HGET(suspendRoute, {}, { authorization: `Bearer ${buildScoped.credential.token}` });
  assert.equal(view.status, 200);
  assert.deepEqual(view.body.suspensions.agents, [XO(AGENT)]);

  // ...but cannot flip it (no scope AND not the owner)
  await expectThrow(HPOST(suspendRoute, { op: "unsuspend", agentPk: XO(AGENT) }, { authorization: `Bearer ${buildScoped.credential.token}` }), 403, "SCOPE_FORBIDDEN");
});

/* ---------------- PostgreSQL: migration 007 + PG round-trip ---------------- */

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);

test("postgres: migration 007 applies and the suspension store round-trips through the real server on PG", { skip: PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the PG section" }, async () => {
  const { Pool } = require("pg");
  const adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  const dbName = `pv_suspend_${process.pid}_${Date.now() % 100000}`;
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  let pgStore = null;
  try {
    const pgConfig = loadConfig({
      persistenceBackend: "postgres",
      pgHost: PG.host,
      pgPort: PG.port,
      pgUser: PG.user,
      pgDatabase: dbName,
      pgNoTls: true,
      hostedDevOpen: true, // single-user PG dev instance (testnet only) — same posture as the other PG suites
      dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-suspend-pg-"))
    });
    const { openPgStore, getStore } = require("../src/store");
    pgStore = await openPgStore(pgConfig, { migrate: true });
    // 007 applied: the agent_suspensions table exists
    const t = await getStore(pgConfig).pool().query("SELECT to_regclass('agent_suspensions') AS reg");
    assert.equal(t.rows[0].reg, "agent_suspensions");

    await seedVault(pgConfig);
    const r = await handle(pgConfig, "POST", suspendRoute, {}, { op: "suspend", agentPk: XO(AGENT) }, { headers: {} });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.suspensions.agents, [XO(AGENT)]);
    // durable in PG (network-scoped row)
    const row = await getStore(pgConfig).pool().query("SELECT value FROM agent_suspensions WHERE network_id = $1 AND key = $2", [pgConfig.networkId, VAULT_ID]);
    assert.equal(row.rowCount, 1);
    assert.deepEqual(row.rows[0].value.agents, [XO(AGENT)]);
    // and enforced through the real route against PG
    await expectThrow(handle(pgConfig, "POST", ["wallet", "v4", "requests"], {}, spendBody(), { headers: {} }), 403, "AGENT_SUSPENDED_HOSTED");
  } finally {
    if (pgStore) await pgStore.close().catch(() => {});
    await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
    await adminPool.end();
  }
});
