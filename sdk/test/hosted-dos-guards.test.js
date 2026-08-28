"use strict";

/*
 * HOSTED DoS GUARDS (Phase D) — concurrency semaphores, slow-client
 * bounds, JSON depth cap, and listing clamps.
 *
 * Semaphores are ACTIVE IN EVERY MODE (a wedged RPC pile-up is a real
 * self-hosted failure mode too); defaults are generous enough to be
 * invisible in normal use. Saturation refuses with 429 SERVER_BUSY and
 * NEVER queues unbounded. Slow clients are cut off by the configured
 * header/request receive windows.
 */

const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { loadConfig } = require("../src/config");
const { createServer } = require("../../server/src/server");
const { Semaphore, classifyRoute, assertJsonDepth } = require("../../server/src/limits");
const { appendAudit } = require("../src/audit");

const DATA = () => fs.mkdtempSync(path.join(os.tmpdir(), "pv-dos-"));

const servers = [];
async function startServer(config) {
  const server = createServer(config);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { server, port: server.address().port };
}
after(async () => {
  for (const s of servers) await new Promise((r) => s.close(r));
});

function req(port, method, pathName, { body, rawBody, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = rawBody !== undefined ? rawBody : body === undefined ? undefined : JSON.stringify(body);
    const r = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: pathName,
        headers: { "Content-Type": "application/json", Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}`, ...headers }
      },
      (res) => {
        let buf = "";
        res.on("data", (d) => (buf += d));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, json: buf ? JSON.parse(buf) : null }));
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

test("§S1 UNIT Semaphore: bounded concurrency, FIFO queue, saturation refusal, idempotent release", async () => {
  const sem = new Semaphore({ max: 2, queue: 1 });
  const relA = await sem.acquire();
  const relB = await sem.acquire();
  assert.deepEqual(sem.stats(), { active: 2, queued: 0 });

  let cResolved = false;
  const cPromise = sem.acquire().then((rel) => {
    cResolved = true;
    return rel;
  });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(sem.stats(), { active: 2, queued: 1 }, "C waits in the queue");

  await assert.rejects(async () => sem.acquire(), (e) => e.code === "SERVER_BUSY" && e.status === 429, "queue full refuses immediately");

  relA();
  const relC = await cPromise;
  assert.ok(cResolved, "queued waiter admitted after a release");
  assert.deepEqual(sem.stats(), { active: 2, queued: 0 });

  relA(); // double release must not free a second slot
  assert.deepEqual(sem.stats(), { active: 2, queued: 0 }, "release is idempotent");
  relB();
  relC();
  assert.deepEqual(sem.stats(), { active: 0, queued: 0 });
});

test("§S2 UNIT classifyRoute: expensive routes map to their strict class and semaphore", () => {
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "requests", "r1", "submit"]), { rateClass: "submit", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "requests", "r1", "genesis-submit"]), { rateClass: "submit", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("POST", ["vaults", "v1", "reconcile"]), { rateClass: "submit", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("GET", ["network", "status"]), { rateClass: "rpcRead", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("GET", ["wallet", "fuel", "kaspatest:xyz"]), { rateClass: "rpcRead", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("GET", ["vaults", "v1", "status"]), { rateClass: "rpcRead", semaphore: "rpc" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "create"]), { rateClass: "build", semaphore: "compute" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "requests"]), { rateClass: "build", semaphore: "compute" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "requests"]), { rateClass: "build", semaphore: "compute" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "requests", "r1", "signature"]), { rateClass: "mutate", semaphore: "compute" });
  assert.deepEqual(classifyRoute("POST", ["wallet", "v4", "requests", "r1", "approvals"]), { rateClass: "mutate", semaphore: "compute" });
  assert.deepEqual(classifyRoute("POST", ["auth", "challenge"]), { rateClass: "auth", semaphore: null });
  assert.deepEqual(classifyRoute("GET", ["auth", "session"]), { rateClass: "read", semaphore: null });
  assert.deepEqual(classifyRoute("GET", ["health"]), { rateClass: "read", semaphore: null });
  assert.deepEqual(classifyRoute("GET", ["vaults"]), { rateClass: "read", semaphore: null });
  assert.deepEqual(classifyRoute("POST", ["organizations"]), { rateClass: "mutate", semaphore: null });
  assert.deepEqual(classifyRoute("POST", ["nonsense"]), { rateClass: "mutate", semaphore: null });
  assert.deepEqual(classifyRoute("GET", ["nonsense"]), { rateClass: "read", semaphore: null });
});

test("§S3 HTTP: compute saturation refuses with 429 SERVER_BUSY and recovers (no slot leak)", async () => {
  // Real v4 builds through the API with a 1-slot, 0-queue compute
  // semaphore. Self-hosted config proves semaphores are always active.
  const dataRoot = DATA();
  const config = loadConfig({ dataRoot, computeConcurrency: 1, computeQueue: 0 });
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const KAS = 100000000n;
  const owner = KEY(1);
  const agentA = KEY(0x1e);
  const recipient = KEY(0x28);

  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
  const { buildRecipientTree } = require("../src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
  const { compileExactStateV4 } = require("../src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");

  const VAULT_ID = "77".repeat(32);
  const template = { owner: XO(owner), vaultId: VAULT_ID };
  const entry = {
    agentPk: XO(agentA), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: [XO(recipient)]
  };
  const policies = [normalizeAgentPolicyV4({ ...entry, agentRecipientRoot: buildRecipientTree(entry.recipients).root })];
  const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "0", agentRoot: buildAgentTreeV4(policies).root, approvers: [], approvalM: "0", policyNonce: "0" });
  const compiled = compileExactStateV4({ config, template, state });
  await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "dos test", status: "ACTIVE", template, agentRegistry: [entry],
    live: { state: stateToJsonV4(state), stateId: computeStateIdV4({ networkId: config.networkId, template, state }), outpoint: { transactionId: "88".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });

  const { server, port } = await startServer(config);
  const fuel = { outpoint: { transactionId: "44".repeat(32), index: 0 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` };
  const build = (action = "ownerPause") =>
    req(port, "POST", "/api/v1/wallet/v4/requests", {
      body: { vaultId: VAULT_ID, action, params: { fuel }, signerAddress: ADDR(owner) }
    });

  // Hold the single compute slot: every build route must refuse NOW
  // (queue 0 — bounded, never unbounded buffering).
  const holdSlot = await server.pvProtection.semaphores.compute.acquire();
  const refused = await build();
  assert.equal(refused.status, 429, JSON.stringify(refused.json));
  assert.equal(refused.json.error.code, "SERVER_BUSY");
  assert.ok(Number(refused.headers["retry-after"]) >= 1, "Retry-After present");

  // Release — the same build now goes through the real builder.
  holdSlot();
  const ok = await build();
  assert.equal(ok.status, 201, `slot released (${JSON.stringify(ok.json)})`);

  // A route-level FAILURE must still release the slot (finally path):
  // an unknown action 422s, then a valid build succeeds again.
  const failing = await build("nonsenseAction");
  assert.equal(failing.status, 422);
  const after = await build();
  assert.equal(after.status, 201, `no semaphore leak on the error path (${JSON.stringify(after.json)})`);
});

test("§S4 HTTP: slow clients are disconnected by the configured receive windows", async () => {
  const config = loadConfig({ dataRoot: DATA(), httpHeadersTimeoutMs: 800, httpRequestTimeoutMs: 1000 });
  const { port } = await startServer(config);

  // (a) Header stall: the request line arrives, headers never complete.
  const headerStall = await new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write("POST /api/v1/health HTTP/1.1\r\nHost: 127.0."); // unfinished
    });
    sock.on("close", () => resolve(Date.now() - t0));
    sock.on("error", () => {}); // reset is fine — we only need the close
    setTimeout(() => reject(new Error("server never disconnected the header-stall client")), 8000).unref();
  });
  assert.ok(headerStall < 5000, `header stall cut off in ${headerStall}ms`);

  // (b) Body stall: complete headers, declared body never arrives.
  const bodyStall = await new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write(
        `POST /api/v1/identity/resolve-address HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"partial`
      );
    });
    sock.on("close", () => resolve(Date.now() - t0));
    sock.on("error", () => {});
    setTimeout(() => reject(new Error("server never disconnected the body-stall client")), 8000).unref();
  });
  assert.ok(bodyStall < 5000, `body stall cut off in ${bodyStall}ms`);
});

test("§S5 HTTP: JSON depth cap refuses pathological nesting; ordinary nesting passes", async () => {
  const config = loadConfig({ dataRoot: DATA() });
  const { port } = await startServer(config);
  const nested = (depth) => `${'{"a":'.repeat(depth)}1${"}".repeat(depth)}`;
  const deep = await req(port, "POST", "/api/v1/identity/resolve-address", { rawBody: nested(100) });
  assert.equal(deep.status, 400);
  assert.equal(deep.json.error.code, "BODY_TOO_DEEP");
  const fine = await req(port, "POST", "/api/v1/identity/resolve-address", { rawBody: nested(50) });
  assert.equal(fine.status, 422, "route-level answer — protection passed");

  // UNIT: arrays count toward depth; the guard itself never recurses.
  assertJsonDepth(JSON.parse(nested(64)));
  assert.throws(() => assertJsonDepth(JSON.parse(nested(65))), /nesting depth/);
  assert.throws(() => assertJsonDepth(JSON.parse(`${"[".repeat(70)}1${"]".repeat(70)}`)), /nesting depth/);
});

test("§S6 HTTP: audit listing limits are clamped server-side", async () => {
  const config = loadConfig({ dataRoot: DATA() });
  for (let i = 0; i < 1010; i++) {
    await appendAudit(config, { kind: "chain", vaultId: "00".repeat(32), action: "test-seed", seq: i });
  }
  const { port } = await startServer(config);
  const greedy = await req(port, "GET", "/api/v1/audit?limit=999999");
  assert.equal(greedy.status, 200);
  assert.equal(greedy.json.events.length, 1000, "hard cap 1000");
  const five = await req(port, "GET", "/api/v1/audit?limit=5");
  assert.equal(five.json.events.length, 5);
  const junk = await req(port, "GET", "/api/v1/audit?limit=-3");
  assert.equal(junk.json.events.length, 200, "junk limit falls back to the default");
});
