"use strict";

/*
 * MCP-path driver (surface 7): spawns the REAL PolicyVault MCP server
 * (`node mcp/server.js`) as a subprocess and speaks the actual stdio
 * transport — newline-delimited JSON-RPC 2.0 over stdin/stdout — exactly
 * as an MCP host would. One McpSession = one subprocess = one machine
 * credential (the adapter's own model: the token arrives via environment
 * and is deleted from process.env at load).
 *
 * STDOUT PURITY is asserted on every line (each must parse as a JSON-RPC
 * message), and all raw stdout/stderr is retained for the token-hygiene
 * scan. This driver is a test CLIENT of the protocol only — it implements
 * no PolicyVault semantics.
 */

const path = require("path");
const { spawn } = require("child_process");
const assert = require("node:assert/strict");

const { outcome } = require("../lib/normalize");

const ROOT = path.resolve(__dirname, "..", "..");
const MCP_SERVER = path.join(ROOT, "mcp", "server.js");

class McpSession {
  constructor({ baseUrl, token, label, timeoutMs = 180000, env = {} }) {
    this.id = `mcp:${label}`;
    this.label = label;
    this.timeoutMs = timeoutMs;
    this.proc = spawn(process.execPath, [MCP_SERVER], {
      env: {
        ...process.env,
        POLICYVAULT_MCP_SERVER_URL: baseUrl,
        POLICYVAULT_MCP_TOKEN: token,
        ...env
      },
      cwd: ROOT,
      stdio: ["pipe", "pipe", "pipe"]
    });
    this.stdoutRaw = "";
    this.stderrRaw = "";
    this._buf = "";
    this.inbox = [];
    this._waiters = [];
    this._exit = null;
    this.proc.stdout.setEncoding("utf8");
    this.proc.stderr.setEncoding("utf8");
    this.proc.stdout.on("data", (chunk) => {
      this.stdoutRaw += chunk;
      this._buf += chunk;
      let nl;
      while ((nl = this._buf.indexOf("\n")) >= 0) {
        const line = this._buf.slice(0, nl);
        this._buf = this._buf.slice(nl + 1);
        if (line.length === 0) continue;
        let msg;
        assert.doesNotThrow(() => {
          msg = JSON.parse(line);
        }, `MCP stdout purity violated (${this.label}): ${line.slice(0, 120)}`);
        assert.equal(msg.jsonrpc, "2.0", `MCP stdout line is not JSON-RPC 2.0 (${this.label})`);
        this.inbox.push(msg);
        this._drain();
      }
    });
    this.proc.stderr.on("data", (chunk) => {
      this.stderrRaw += chunk;
    });
    this.proc.on("exit", (code) => {
      this._exit = code;
      this._drain();
    });
  }

  _drain() {
    for (let i = this._waiters.length - 1; i >= 0; i--) {
      const w = this._waiters[i];
      const idx = this.inbox.findIndex(w.match);
      if (idx >= 0) {
        const [msg] = this.inbox.splice(idx, 1);
        this._waiters.splice(i, 1);
        clearTimeout(w.timer);
        w.resolve(msg);
      } else if (this._exit !== null) {
        this._waiters.splice(i, 1);
        clearTimeout(w.timer);
        w.reject(new Error(`MCP session ${this.label} exited (code ${this._exit}) before ${w.label}; stderr: ${this.stderrRaw.slice(0, 400)}`));
      }
    }
  }

  send(obj) {
    this.proc.stdin.write(`${JSON.stringify(obj)}\n`);
  }

  await(match, label) {
    return new Promise((resolve, reject) => {
      const w = {
        match,
        label,
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this._waiters.indexOf(w);
          if (i >= 0) this._waiters.splice(i, 1);
          reject(new Error(`timed out waiting for ${label} (mcp ${this.label})`));
        }, this.timeoutMs)
      };
      this._waiters.push(w);
      this._drain();
    });
  }

  response(id) {
    return this.await((m) => m.id === id && (m.result !== undefined || m.error !== undefined), `response id=${id}`);
  }

  async request(id, method, params) {
    this.send({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) });
    return this.response(id);
  }

  async initialize(protocolVersion = "2025-06-18") {
    const res = await this.request("init", "initialize", {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: "policyvault-conformance", version: "1.0.0" }
    });
    if (res.error) throw new Error(`MCP initialize failed (${this.label}): ${JSON.stringify(res.error)}`);
    this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    this.serverInfo = res.result;
    return res.result;
  }

  async toolsList() {
    const res = await this.request(`list-${Date.now()}`, "tools/list");
    if (res.error) throw new Error(`tools/list failed (${this.label}): ${JSON.stringify(res.error)}`);
    return res.result.tools;
  }

  /* Raw tool call: returns { envelope } or { rpcError } — the MCP-native view. */
  async callToolRaw(id, name, args) {
    const res = await this.request(id, "tools/call", { name, ...(args !== undefined ? { arguments: args } : {}) });
    if (res.error) return { rpcError: res.error };
    const envelope = res.result.structuredContent;
    // Spec rule: content[0].text is EXACTLY the serialized structuredContent.
    assert.equal(res.result.content[0].text, JSON.stringify(envelope), `MCP text/structured divergence (${this.label})`);
    return { envelope };
  }

  /* Normalized outcome for cross-path comparison. */
  async callTool(id, name, args) {
    const r = await this.callToolRaw(id, name, args);
    if (r.rpcError) {
      return outcome({ ok: false, errorType: "JsonRpcError", body: r.rpcError, code: null });
    }
    const env = r.envelope;
    if (env.status === "OK") {
      return outcome({ ok: true, httpStatus: env.httpStatus, body: env.data, replayed: env.replayedIdempotency === true });
    }
    if (env.status === "REFUSED") {
      const code = env.data && env.data.error && typeof env.data.error.code === "string" ? env.data.error.code : null;
      return outcome({
        ok: false,
        httpStatus: env.httpStatus,
        code,
        body: env.data,
        replayed: env.replayedIdempotency === true,
        errorType: "McpRefused"
      });
    }
    return outcome({ ok: false, code: null, body: env.data, errorType: `Mcp${env.status}` });
  }

  async close() {
    try {
      this.proc.stdin.end(); // stdin EOF = the spec's shutdown signal
    } catch {
      /* already gone */
    }
    await new Promise((resolve) => {
      if (this._exit !== null) return resolve();
      const t = setTimeout(() => {
        this.proc.kill("SIGKILL");
        resolve();
      }, 5000);
      this.proc.on("exit", () => {
        clearTimeout(t);
        resolve();
      });
    });
  }
}

/* Boot + handshake in one step. */
async function startMcpSession(opts) {
  const s = new McpSession(opts);
  await s.initialize();
  return s;
}

module.exports = { McpSession, startMcpSession };
