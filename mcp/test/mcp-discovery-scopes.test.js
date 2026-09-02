"use strict";

/*
 * MCP LEAST-PRIVILEGE DISCOVERY (mock-API harness; layer: UNIT/PROTOCOL).
 *
 * Owner-live finding (2026-09-02): a production machine credential holding
 * ONLY read:network saw all 14 tools on tools/list, while the server still
 * refused policyvault_list_vaults with 403 SCOPE_FORBIDDEN. Root cause: the
 * catalog was derived from the PUBLIC discovery document's build-level
 * scope ENUM (fetched anonymously), never from the credential's grants.
 *
 * Contract pinned here (server remains the final boundary):
 *   scope absent → capability absent → tool absent from discovery;
 *   full scopes → the full catalog;
 *   a hidden tool invoked by exact name still meets the server's own
 *     403 SCOPE_FORBIDDEN (this layer never decides authority);
 *   malformed / missing principal data fails closed (startup refused);
 *   scope removal can never INCREASE discovery (monotonic);
 *   a server without the feature keeps the build-level catalog and says
 *     so on stderr; a refused credential fails closed at discovery.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { startMockApi, defaultCapabilities, McpDriver, startDriver, TEST_TOKEN, scopeEnforcingRoute } = require("./harness");
const { normalizeCapabilities, buildToolCatalog, DiscoveryError } = require("../src/tools");

const ALL_SCOPES = defaultCapabilities().scopes.map((s) => s.scope);
const FULL_CATALOG = [
  "policyvault_capabilities",
  "policyvault_list_vaults",
  "policyvault_vault",
  "policyvault_vault_audit",
  "policyvault_audit_feed",
  "policyvault_network_status",
  "policyvault_simulate_request",
  "policyvault_create_request",
  "policyvault_request_status",
  "policyvault_list_requests",
  "policyvault_reject_request",
  "policyvault_governance_proposals",
  "policyvault_governance_proposal",
  "policyvault_risk_evaluation"
];

const NETWORK_STATUS = { networkId: "testnet-10", isSynced: true, hasUtxoIndex: true, serverVersion: "2.0.1", virtualDaaScore: "1" };
function liveRoutes(record) {
  if (record.method === "GET" && record.path === "/api/v1/network/status") return { status: 200, body: NETWORK_STATUS };
  if (record.method === "GET" && record.path === "/api/v1/vaults") return { status: 200, body: { vaults: [] } };
  return null;
}
const listNames = async (driver) => (await driver.request("l", "tools/list")).result.tools.map((t) => t.name);

test("full scopes → the expected full catalog (14 tools), and discovery PRESENTED the credential", async () => {
  const mock = await startMockApi({ scoped: { scopes: ALL_SCOPES } });
  const driver = await startDriver({ mock });
  try {
    await driver.initialize();
    assert.deepEqual(await listNames(driver), FULL_CATALOG);
    const disc = mock.requests.find((r) => r.path === "/api/v1/capabilities");
    assert.equal(disc.headers.authorization, `Bearer ${TEST_TOKEN}`, "the credential is presented at discovery so the server can scope it");
    assert.match(driver.stderrRaw, /14 of 14 tool\(s\) advertised \(discovery: credential-scoped\)/);
    assert.ok(!driver.stderrRaw.includes(TEST_TOKEN), "credential never reaches stderr");
  } finally {
    driver.close();
    await mock.close();
  }
});

test("read:network only → ONLY the authorized discoverable tools (capabilities + network status); nothing else is advertised", async () => {
  const mock = await startMockApi({ scoped: { scopes: ["read:network"] }, route: scopeEnforcingRoute(["read:network"], liveRoutes) });
  const driver = await startDriver({ mock });
  try {
    await driver.initialize();
    assert.deepEqual(await listNames(driver), ["policyvault_capabilities", "policyvault_network_status"]);
    assert.match(driver.stderrRaw, /2 of 14 tool\(s\) advertised \(discovery: credential-scoped\)/);
    const ns = await driver.callTool("ns", "policyvault_network_status", {});
    assert.equal(ns.result.structuredContent.status, "OK");
    assert.equal(ns.result.structuredContent.data.networkId, "testnet-10");
  } finally {
    driver.close();
    await mock.close();
  }
});

test("a HIDDEN tool invoked by exact name still reaches the server and is answered by ITS 403 SCOPE_FORBIDDEN — exactly one attempt, this layer decides nothing", async () => {
  const mock = await startMockApi({ scoped: { scopes: ["read:network"] }, route: scopeEnforcingRoute(["read:network"], liveRoutes) });
  const driver = await startDriver({ mock });
  try {
    await driver.initialize();
    assert.ok(!(await listNames(driver)).includes("policyvault_list_vaults"), "hidden from discovery");
    const res = await driver.callTool("lv", "policyvault_list_vaults", {});
    const sc = res.result.structuredContent;
    assert.equal(sc.status, "REFUSED", JSON.stringify(sc));
    assert.equal(sc.data.error.code, "SCOPE_FORBIDDEN");
    assert.equal(sc.httpStatus, 403);
    assert.equal(mock.requests.filter((r) => r.path === "/api/v1/vaults").length, 1, "exactly one server attempt, no retry");
    // An UNKNOWN name (not a blueprint at all) is still a protocol error, never a fabricated refusal.
    const unknown = await driver.callTool("u", "policyvault_not_a_tool", {});
    assert.equal(unknown.error.code, -32602);
  } finally {
    driver.close();
    await mock.close();
  }
});

test("malformed / missing capability data FAILS CLOSED at startup: feature declared but no principal; non-machine principal; scopes off-shape; unknown granted scope", async () => {
  const cases = [
    { scoped: { scopes: null }, re: /named no principal/ },
    { scoped: { principal: { kind: "session" } }, re: /did not resolve to a machine principal/ },
    { scoped: { principal: { kind: "machine", identityId: "x", scopes: "read:network" } }, re: /principal\.scopes is missing\/off-shape/ },
    { scoped: { principal: { kind: "machine", identityId: "x", scopes: ["read:network", "Read:Everything!"] } }, re: /off-shape/ },
    { scoped: { scopes: ["read:network", "read:not-a-real-scope"] }, re: /not in the server's scope enum/ },
    { scoped: { principal: ["read:network"] }, re: /named no principal/ }
  ];
  for (const c of cases) {
    const mock = await startMockApi({ scoped: c.scoped });
    const driver = await startDriver({ mock, start: false });
    try {
      await assert.rejects(() => driver.start(), (e) => e instanceof DiscoveryError && c.re.test(e.message), `case ${JSON.stringify(c.scoped)}`);
      assert.equal(driver.session._toolCount(), 0, "no catalog exists after a refused discovery");
    } finally {
      driver.close();
      await mock.close();
    }
  }
});

test("a credential the server refuses at discovery fails closed (no catalog, DiscoveryError), and a non-200 discovery still fails closed", async () => {
  const mock = await startMockApi({ scoped: { scopes: ["read:network"], validToken: "pvmk_SOMEONE_ELSE_0123456789abcdefghijklmnopqrstuv" } });
  const driver = await startDriver({ mock, start: false });
  try {
    await assert.rejects(() => driver.start(), (e) => e instanceof DiscoveryError && /refused at discovery \(http 401 MACHINE_TOKEN_INVALID\)/.test(e.message));
    assert.equal(driver.session._toolCount(), 0);
  } finally {
    driver.close();
    await mock.close();
  }
});

test("scope removal can NEVER increase discovery (monotonic), and operator narrowing (POLICYVAULT_MCP_SCOPES) only intersects", () => {
  const caps = (granted) => normalizeCapabilities({ ...defaultCapabilities(), features: { ...defaultCapabilities().features, principalScopedDiscovery: true }, principal: { kind: "machine", identityId: "x", scopes: granted } });
  const advertised = (c, cfg = {}) => [...buildToolCatalog(c, cfg).values()].filter((t) => t.advertised).map((t) => t.definition.name);
  // exhaustive-ish: for many nested chains S0 ⊂ S1 ⊂ ... the advertised set never shrinks as scopes are added
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  for (let trial = 0; trial < 40; trial++) {
    const order = [...ALL_SCOPES].sort(() => rnd() - 0.5);
    let prev = new Set(advertised(caps([])));
    assert.deepEqual([...prev], ["policyvault_capabilities"], "with no scopes only the scope-free discovery tool is advertised");
    for (let i = 1; i <= order.length; i++) {
      const cur = new Set(advertised(caps(order.slice(0, i))));
      for (const name of prev) assert.ok(cur.has(name), `adding scope ${order[i - 1]} must not hide ${name}`);
      prev = cur;
    }
    assert.deepEqual([...prev], FULL_CATALOG);
  }
  // operator narrowing: env wider than the grant changes nothing; env narrower removes tools entirely
  assert.deepEqual(advertised(caps(["read:network"]), { advertisedScopes: ALL_SCOPES }), ["policyvault_capabilities", "policyvault_network_status"]);
  assert.deepEqual(advertised(caps(ALL_SCOPES), { advertisedScopes: ["read:network"] }), ["policyvault_capabilities", "policyvault_network_status"]);
  // full grant with no narrowing == build catalog
  assert.deepEqual(advertised(caps(ALL_SCOPES)), FULL_CATALOG);
});

test("a server WITHOUT principal-scoped discovery (older build / self-hosted) keeps the build-level catalog and says so on stderr; the credential is still presented", async () => {
  const mock = await startMockApi(); // no `scoped`: the legacy public document
  const driver = await startDriver({ mock });
  try {
    await driver.initialize();
    assert.deepEqual(await listNames(driver), FULL_CATALOG);
    assert.match(driver.stderrRaw, /14 of 14 tool\(s\) advertised \(discovery: build-level\)/);
    assert.match(driver.stderrRaw, /does not declare principal-scoped discovery/);
    const disc = mock.requests.find((r) => r.path === "/api/v1/capabilities");
    assert.equal(disc.headers.authorization, `Bearer ${TEST_TOKEN}`);
    assert.ok(!driver.stderrRaw.includes(TEST_TOKEN));
  } finally {
    driver.close();
    await mock.close();
  }
});

test("the policyvault_capabilities TOOL still returns the PUBLIC document anonymously (no credential on that call)", async () => {
  const mock = await startMockApi({ scoped: { scopes: ["read:network"] } });
  const driver = await startDriver({ mock });
  try {
    await driver.initialize();
    const res = await driver.callTool("c", "policyvault_capabilities", {});
    assert.equal(res.result.structuredContent.status, "OK");
    assert.equal(res.result.structuredContent.data.principal, undefined, "the tool's read is anonymous: the public document carries no principal");
    const calls = mock.requests.filter((r) => r.path === "/api/v1/capabilities");
    assert.equal(calls.length, 2);
    assert.equal(calls[1].headers.authorization, undefined);
  } finally {
    driver.close();
    await mock.close();
  }
});
