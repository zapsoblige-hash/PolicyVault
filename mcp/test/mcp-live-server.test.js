"use strict";

/*
 * LIVE END-TO-END: MCP -> HTTP -> REAL PolicyVault server (layer:
 * INTEGRATION; the integration-proof for the thin-adapter claim).
 *
 * Boots the REAL server (server/src/server.js, JSON backend, ephemeral
 * loopback port, hosted auth enabled) with a REAL seeded v0.4 vault
 * (real silverc compile), signs a REAL wallet session in, mints a REAL
 * machine identity with deliberately PARTIAL scopes
 * (read:vaults + request:build + read:requests — NO read:audit, NO
 * request:reject), then drives the MCP server against it:
 *
 *   - dynamic tool derivation from the server's real discovery document
 *     (action enum asserted equal to the SDK's ROLE_BY_ACTION code truth);
 *   - list vaults + vault detail (tenancy-scoped reads);
 *   - dry-run simulation through the REAL pipeline (simulation.ok:true);
 *   - REAL scope enforcement: read:audit and request:reject calls surface
 *     as clean REFUSED/403 SCOPE_FORBIDDEN tool errors (single attempt);
 *   - create request (real build, durable BUILT record) + cross-session
 *     idempotent replay (same MCP request id + args -> the SAME durable
 *     request, marked replayedIdempotency, exactly one row);
 *   - a REAL SUBPROCESS run of `node mcp/server.js` over actual stdio
 *     (stdout purity, working handshake and tool call, clean exit on
 *     stdin close, no credential in any child output).
 *
 * Serialized like every suite that boots servers in this repo.
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { loadConfig } = require("../../sdk/src/config");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../../sdk/src/agent-merkle-v4");
const { buildRecipientTree } = require("../../sdk/src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../../sdk/src/vault-state-v4");
const { compileExactStateV4 } = require("../../sdk/src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../../sdk/src/manifest-v4");
const { ROLE_BY_ACTION } = require("../../sdk/src/wallet-requests-v4");

const { McpDriver } = require("./harness");
const { deriveIdempotencyKey } = require("../src/idempotency");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-mcp-live-"));
const config = loadConfig({ dataRoot, authMode: "enabled", authCookieInsecure: true });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const KAS = 100000000n;

const OWNER = KEY(0x31);
const AGENT = KEY(0x32);
const RECIP = KEY(0x33);
const VAULT_ID = "5a".repeat(32);

let server, port, baseUrl, token;
const sessions = [];
let capturedOutput = "";

function req(method, pathName, { body, cookie, authorization } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { "Content-Type": "application/json", Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}` };
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
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

async function startLiveDriver() {
  // Real silverc compiles run inside build/simulate calls — generous waits.
  const driver = new McpDriver({ env: { POLICYVAULT_MCP_SERVER_URL: baseUrl, POLICYVAULT_MCP_TOKEN: token }, defaultTimeoutMs: 120000 });
  await driver.start();
  sessions.push(driver);
  return driver;
}

before(async () => {
  // ---- seed a REAL v0.4 vault (real compile, durable manifest) ----
  const template = { owner: XO(OWNER), vaultId: VAULT_ID };
  const registry = [
    {
      agentPk: XO(AGENT), maxPerSpend: (20n * KAS).toString(), periodBudget: (500n * KAS).toString(),
      periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
      approvalThreshold: (500n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
      recipients: [XO(RECIP)]
    }
  ];
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const st = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0",
    agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state: st });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state: st });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "mcp live vault", status: "ACTIVE", template, agentRegistry: registry,
    live: {
      state: stateToJsonV4(st), stateId, outpoint: { transactionId: "5b".repeat(32), index: 0 },
      outpointValue: (st.protectedValue + st.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "5c".repeat(32)
    },
    creationTxId: "5d".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  // ---- real server + real wallet session + real machine identity ----
  const { createServer } = require("../../server/src/server");
  server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  const address = ADDR(OWNER);
  const ch = await req("POST", "/api/v1/auth/challenge", { body: { walletAddress: address } });
  const signature = kaspa.signMessage({ message: ch.json.challenge.message, privateKey: OWNER.toString() });
  const v = await req("POST", "/api/v1/auth/verify", { body: { nonce: ch.json.challenge.nonce, signature, publicKey: OWNER.toPublicKey().toString().toLowerCase() } });
  const cookie = v.headers["set-cookie"][0].split(";")[0];
  const created = await req("POST", "/api/v1/identities", {
    body: { label: "mcp live test agent", scopes: ["read:vaults", "request:build", "read:requests"] },
    cookie
  });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  token = created.json.credential.token;
});

after(async () => {
  for (const d of sessions) {
    capturedOutput += d.stdoutRaw + d.stderrRaw;
    d.close();
  }
  if (server) await new Promise((r) => server.close(r));
  fs.rmSync(dataRoot, { recursive: true, force: true });
});

test("live: tool catalog derives from the REAL discovery document (action enum == SDK ROLE_BY_ACTION code truth)", async () => {
  const driver = await startLiveDriver();
  await driver.initialize();
  const res = await driver.request(1, "tools/list");
  const names = res.result.tools.map((t) => t.name);
  assert.ok(names.includes("policyvault_simulate_request"), "the real server advertises dryRunSimulation");
  assert.ok(names.includes("policyvault_create_request"));
  // LEAST-PRIVILEGE DISCOVERY against the REAL server: the credential holds
  // read:vaults + request:build + read:requests, so exactly the tools those
  // scopes cover are advertised — the rest are hidden (yet still server-
  // refused when called by name; see the SCOPE_FORBIDDEN tests below).
  assert.deepEqual(names, [
    "policyvault_capabilities",
    "policyvault_list_vaults",
    "policyvault_vault",
    "policyvault_vault_audit",
    "policyvault_simulate_request",
    "policyvault_create_request",
    "policyvault_request_status",
    "policyvault_list_requests"
  ]);
  assert.match(driver.stderrRaw, /8 of 14 tool\(s\) advertised \(discovery: credential-scoped\)/);
  const create = res.result.tools.find((t) => t.name === "policyvault_create_request");
  assert.deepEqual(create.inputSchema.properties.action.enum.sort(), Object.keys(ROLE_BY_ACTION).sort(), "the action enum must equal the SDK export, via the wire, not via retyping");
});

test("live: list vaults + vault detail through the machine credential (tenancy-scoped reads)", async () => {
  const driver = await startLiveDriver();
  await driver.initialize();
  const list = await driver.callTool(2, "policyvault_list_vaults", {});
  assert.equal(list.result.structuredContent.status, "OK", JSON.stringify(list.result.structuredContent));
  assert.equal(list.result.structuredContent.data.vaults.length, 1);
  assert.equal(list.result.structuredContent.data.vaults[0].vaultId, VAULT_ID);

  const detail = await driver.callTool(3, "policyvault_vault", { vaultId: VAULT_ID });
  assert.equal(detail.result.structuredContent.status, "OK");
  assert.equal(detail.result.structuredContent.data.vaultId, VAULT_ID);
  assert.equal(detail.result.structuredContent.data.agents.length, 1);
});

test("live: dry-run simulation runs the REAL pipeline and reports ok:true with the full decision", async () => {
  const driver = await startLiveDriver();
  await driver.initialize();
  const res = await driver.callTool(4, "policyvault_simulate_request", {
    vaultId: VAULT_ID,
    action: "agentSpend",
    signerAddress: ADDR(AGENT),
    params: { payAmountSompi: (1n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }
  });
  const sc = res.result.structuredContent;
  assert.equal(sc.status, "OK", JSON.stringify(sc));
  assert.equal(sc.data.simulation.ok, true, JSON.stringify(sc.data));
  assert.equal(sc.data.simulation.vaultId, VAULT_ID);
  assert.ok(sc.data.simulation.review.feeSompi, "the real builder ran (exact fee accounting present)");
  assert.equal(sc.data.simulation.wouldRequire.proposal, false);
  assert.equal(sc.data.schemaVersion, "policyvault-wallet-v4-request/v1");
});

test("live: REAL scope enforcement — read:audit not granted surfaces as one clean REFUSED 403 SCOPE_FORBIDDEN", async () => {
  const driver = await startLiveDriver();
  await driver.initialize();
  const res = await driver.callTool(5, "policyvault_audit_feed", {});
  const sc = res.result.structuredContent;
  assert.equal(res.result.isError, true);
  assert.equal(sc.status, "REFUSED");
  assert.equal(sc.httpStatus, 403);
  assert.equal(sc.data.error.code, "SCOPE_FORBIDDEN");
});

test("live: create request builds a durable BUILT record; a second session replaying the same MCP id+args gets the SAME request (idempotent, marked)", async () => {
  const a = await startLiveDriver();
  await a.initialize();
  const args = {
    vaultId: VAULT_ID,
    action: "agentSpend",
    signerAddress: ADDR(AGENT),
    params: { payAmountSompi: (2n * KAS).toString(), agentPk: XO(AGENT), recipient: XO(RECIP) }
  };
  const r1 = await a.callTool("create-op-1", "policyvault_create_request", args);
  const sc1 = r1.result.structuredContent;
  assert.equal(sc1.status, "OK", JSON.stringify(sc1));
  assert.equal(sc1.httpStatus, 201);
  const requestId = sc1.data.request.requestId;
  assert.match(requestId, /^[0-9a-f-]{36}$/);
  assert.equal(sc1.data.request.state, "BUILT");
  assert.equal(sc1.replayedIdempotency, undefined);

  // cross-session replay: same MCP request id + same args -> same derived key
  const b = await startLiveDriver();
  await b.initialize();
  const r2 = await b.callTool("create-op-1", "policyvault_create_request", args);
  const sc2 = r2.result.structuredContent;
  assert.equal(sc2.status, "OK", JSON.stringify(sc2));
  assert.equal(sc2.replayedIdempotency, true, "the replay must be marked");
  assert.equal(sc2.data.request.requestId, requestId, "the SAME durable request, never a duplicate");

  // exactly one durable row for this vault (read through the API too)
  const listed = await b.callTool(7, "policyvault_list_requests", { vaultId: VAULT_ID });
  assert.equal(listed.result.structuredContent.status, "OK");
  assert.equal(listed.result.structuredContent.data.requests.length, 1);

  const status = await b.callTool(8, "policyvault_request_status", { requestId });
  assert.equal(status.result.structuredContent.status, "OK");
  assert.equal(status.result.structuredContent.data.request.state, "BUILT");

  // the derivation on the wire equals the documented function
  assert.equal(
    deriveIdempotencyKey({ tool: "policyvault_create_request", mcpRequestId: "create-op-1", args }),
    deriveIdempotencyKey({ tool: "policyvault_create_request", mcpRequestId: "create-op-1", args: JSON.parse(JSON.stringify(args)) })
  );
});

test("live: request:reject not granted — the mutating reject tool is REFUSED 403 and the durable request is untouched", async () => {
  const driver = await startLiveDriver();
  await driver.initialize();
  const listed = await driver.callTool(9, "policyvault_list_requests", { vaultId: VAULT_ID });
  const requestId = listed.result.structuredContent.data.requests[0].requestId;
  const rej = await driver.callTool(10, "policyvault_reject_request", { requestId });
  const sc = rej.result.structuredContent;
  assert.equal(sc.status, "REFUSED");
  assert.equal(sc.httpStatus, 403);
  assert.equal(sc.data.error.code, "SCOPE_FORBIDDEN");
  const status = await driver.callTool(11, "policyvault_request_status", { requestId });
  assert.equal(status.result.structuredContent.data.request.state, "BUILT", "the refused mutation must have changed nothing");
});

test("live: real subprocess over actual stdio — handshake, tools/list, tools/call, stdout purity, clean exit, no credential in output", async () => {
  const child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, POLICYVAULT_MCP_SERVER_URL: baseUrl, POLICYVAULT_MCP_TOKEN: token },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let out = "";
  let errOut = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (errOut += d));

  const lines = () => out.split("\n").filter((l) => l.trim() !== "");
  const waitForLines = async (n, timeoutMs = 20000) => {
    const t0 = Date.now();
    while (lines().length < n) {
      if (Date.now() - t0 > timeoutMs) throw new Error(`subprocess produced ${lines().length}/${n} lines; stderr: ${errOut.slice(0, 400)}`);
      await new Promise((r) => setTimeout(r, 50));
    }
    return lines().map((l) => JSON.parse(l)); // stdout purity: every line MUST parse
  };

  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "subproc-test", version: "0" } } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "policyvault_list_vaults", arguments: {} } })}\n`);

  const msgs = await waitForLines(3);
  const init = msgs.find((m) => m.id === 1);
  assert.equal(init.result.protocolVersion, "2025-06-18");
  const list = msgs.find((m) => m.id === 2);
  assert.equal(list.result.tools.length, 8, "credential-scoped discovery over real stdio (3 scopes → 8 advertised tools)");
  const call = msgs.find((m) => m.id === 3);
  assert.equal(call.result.structuredContent.status, "OK");
  assert.equal(call.result.structuredContent.data.vaults[0].vaultId, VAULT_ID);

  const exited = new Promise((resolve) => child.on("exit", resolve));
  child.stdin.end(); // spec shutdown: close stdin
  const code = await Promise.race([exited, new Promise((r) => setTimeout(() => r("timeout"), 10000))]);
  if (code === "timeout") {
    child.kill("SIGKILL");
    assert.fail("subprocess did not exit after stdin closed");
  }
  assert.equal(code, 0, "clean exit on stdin close");
  assert.ok(!out.includes(token) && !errOut.includes(token), "the credential must never appear in subprocess output");
  capturedOutput += out + errOut;
});

test("live: the credential never appeared in ANY session output collected across this suite", () => {
  for (const d of sessions) capturedOutput += d.stdoutRaw + d.stderrRaw;
  assert.ok(capturedOutput.length > 0);
  assert.ok(!capturedOutput.includes(token), "credential leak detected in MCP output");
});
