"use strict";

/*
 * Shared test harness for the PolicyVault MCP server tests:
 *   - startMockApi: a real node:http server standing in for the
 *     PolicyVault API (records every request it sees, so tests can assert
 *     "the refused call NEVER reached HTTP" and "exactly one attempt, no
 *     retry loop");
 *   - McpDriver: drives createMcpSession over in-process streams, line-
 *     framed exactly like the stdio transport, asserting stdout purity
 *     (every emitted line must parse as a JSON-RPC message).
 */

const http = require("node:http");
const { PassThrough } = require("node:stream");
const assert = require("node:assert/strict");

const { createMcpSession } = require("../server");

/* A capabilities document shaped like server/src/capabilities.js output.
 * Tests override pieces to prove dynamic derivation. */
function defaultCapabilities(overrides = {}) {
  const base = {
    schemaVersion: "policyvault-capabilities/v1",
    apiVersion: "test-api",
    networkId: "testnet-10",
    contract: { supportedCovenantVersions: ["policyvault-0.4", "policyvault-0.4.1"] },
    actions: {
      v4: [
        "agentSpend",
        "ownerSetAgentRoot",
        "ownerSetApprovers",
        "ownerTopUp",
        "ownerTopUpReserve",
        "ownerPause",
        "ownerUnpause",
        "ownerRecover",
        "addAgent",
        "removeAgent",
        "rotateAgent",
        "rePolicyAgent"
      ].map((action) => ({ action, role: action === "agentSpend" ? "agent" : "owner" }))
    },
    scopes: [
      "read:vaults",
      "read:requests",
      "read:governance",
      "read:risk",
      "read:organizations",
      "read:manifests",
      "read:network",
      "read:audit",
      "request:build",
      "request:sign",
      "request:submit",
      "request:reject",
      "request:break-glass",
      "governance:propose",
      "governance:approve",
      "governance:cancel",
      "risk:release",
      "vaults:reconcile",
      "organizations:manage"
    ].map((scope) => ({ scope, description: "test" })),
    schemas: {
      capabilities: "policyvault-capabilities/v1",
      walletV4Request: "policyvault-wallet-v4-request/v1",
      simulation: "policyvault-simulation/v1"
    },
    limits: {},
    features: {
      hostedAuth: true,
      machineIdentities: true,
      dryRunSimulation: true,
      idempotency: true,
      capabilityDiscovery: true
    }
  };
  return { ...base, ...overrides };
}

/*
 * startMockApi({ capabilities, route }) -> { port, baseUrl, requests, close }
 * `route(req)` (req = { method, path, query, headers, body }) returns
 * { status, body } | null (null -> 404). Every request (INCLUDING the
 * capabilities fetch) is appended to `requests`.
 */
async function startMockApi({ capabilities = defaultCapabilities(), route = () => null } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url, "http://127.0.0.1");
      const text = Buffer.concat(chunks).toString("utf8");
      let body = null;
      try {
        body = text === "" ? null : JSON.parse(text);
      } catch {
        body = { unparseable: true };
      }
      const record = {
        method: req.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams.entries()),
        headers: req.headers,
        body
      };
      requests.push(record);
      let out;
      if (record.method === "GET" && record.path === "/api/v1/capabilities") {
        out = { status: 200, body: capabilities };
      } else {
        out = route(record) ?? { status: 404, body: { error: { code: "NOT_FOUND", message: "mock: no route" } } };
      }
      if (out.raw !== undefined) {
        res.writeHead(out.status, { "content-type": "text/plain" });
        res.end(out.raw);
        return;
      }
      if (out.delayMs) {
        setTimeout(() => {
          res.writeHead(out.status, { "content-type": "application/json" });
          res.end(JSON.stringify(out.body));
        }, out.delayMs);
        return;
      }
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  return {
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise((r) => server.close(r))
  };
}

const TEST_TOKEN = "pvmk_MOCKSECRET_abcdefghijklmnopqrstuvwxyz0123456789";

/*
 * McpDriver — in-process MCP session over PassThrough streams.
 * Every stdout line is asserted to parse as JSON (stdout purity); stderr
 * is captured for the credential-leak scan.
 */
class McpDriver {
  constructor({ env, defaultTimeoutMs = 5000 }) {
    this.defaultTimeoutMs = defaultTimeoutMs;
    this.input = new PassThrough();
    this.output = new PassThrough();
    this.errput = new PassThrough();
    this.env = env;
    this.inbox = [];
    this.waiters = [];
    this.stdoutRaw = "";
    this.stderrRaw = "";
    this._outBuf = "";
    this.output.setEncoding("utf8");
    this.errput.setEncoding("utf8");
    this.output.on("data", (chunk) => {
      this.stdoutRaw += chunk;
      this._outBuf += chunk;
      let nl;
      while ((nl = this._outBuf.indexOf("\n")) >= 0) {
        const line = this._outBuf.slice(0, nl);
        this._outBuf = this._outBuf.slice(nl + 1);
        assert.ok(line.length > 0, "stdout emitted an empty line");
        let msg;
        assert.doesNotThrow(() => {
          msg = JSON.parse(line);
        }, `stdout purity violated — non-JSON line emitted: ${line.slice(0, 80)}`);
        assert.equal(msg.jsonrpc, "2.0", "every stdout line must be a JSON-RPC 2.0 message");
        this.inbox.push(msg);
        this._drain();
      }
    });
    this.errput.on("data", (chunk) => {
      this.stderrRaw += chunk;
    });
    this.session = createMcpSession({ input: this.input, output: this.output, errput: this.errput, env });
  }

  async start() {
    await this.session.start();
  }

  close() {
    this.session.close();
  }

  _drain() {
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const w = this.waiters[i];
      const idx = this.inbox.findIndex(w.match);
      if (idx >= 0) {
        const [msg] = this.inbox.splice(idx, 1);
        this.waiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve(msg);
      }
    }
  }

  send(obj) {
    this.input.write(`${JSON.stringify(obj)}\n`);
  }

  sendRaw(text) {
    this.input.write(text);
  }

  /* Wait for the next message matching `match` (default: by response id). */
  await(match, { timeoutMs = this.defaultTimeoutMs, label = "message" } = {}) {
    return new Promise((resolve, reject) => {
      const w = {
        match,
        resolve,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error(`timed out waiting for ${label}`));
        }, timeoutMs)
      };
      this.waiters.push(w);
      this._drain();
    });
  }

  response(id, opts = {}) {
    return this.await((m) => m.id === id && (m.result !== undefined || m.error !== undefined), { label: `response id=${id}`, ...opts });
  }

  async request(id, method, params) {
    this.send({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) });
    return this.response(id);
  }

  async initialize(protocolVersion = "2025-06-18") {
    const res = await this.request("init", "initialize", {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: "harness", version: "0.0.0" }
    });
    this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return res;
  }

  async callTool(id, name, args) {
    return this.request(id, "tools/call", { name, ...(args !== undefined ? { arguments: args } : {}) });
  }

  /* settle pending microtasks/io briefly (for negative assertions) */
  static pause(ms = 150) {
    return new Promise((r) => setTimeout(r, ms));
  }
}

/* Boot a driver against a mock API with sane defaults. */
async function startDriver({ mock, env = {}, start = true } = {}) {
  const driver = new McpDriver({
    env: {
      POLICYVAULT_MCP_SERVER_URL: mock.baseUrl,
      POLICYVAULT_MCP_TOKEN: TEST_TOKEN,
      ...env
    }
  });
  if (start) await driver.start();
  return driver;
}

module.exports = { startMockApi, defaultCapabilities, McpDriver, startDriver, TEST_TOKEN };
