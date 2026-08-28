"use strict";

/*
 * Python-path driver wrapper: spawns the REAL Python reference client as a
 * subprocess (`python3 -m pv_conformance_driver`, stdlib-only, from this
 * worktree's python/ tree) and speaks the one-JSON-per-line protocol of
 * conformance/drivers/pv_conformance_driver.py.
 *
 * ALL subprocess output is captured raw (stdoutRaw/stderrRaw) for the
 * token-hygiene scenario: credentials enter via environment only and must
 * never appear in anything the process prints.
 */

const path = require("path");
const { spawn } = require("child_process");

const { outcome } = require("../lib/normalize");

const ROOT = path.resolve(__dirname, "..", "..");

class PyDriver {
  constructor({ baseUrl, tokens, timeoutMs = 180000 }) {
    this.id = "python";
    this.timeoutMs = timeoutMs;
    const env = {
      ...process.env,
      PV_BASE_URL: baseUrl,
      PYTHONPATH: [path.join(ROOT, "python"), __dirname, process.env.PYTHONPATH || ""].filter(Boolean).join(path.delimiter)
    };
    // Strip ambient PolicyVault configuration that could redirect the
    // client at a real deployment (mirrors python/tests/harness.py).
    for (const name of ["POLICYVAULT_API_URL", "POLICYVAULT_API_TOKEN"]) delete env[name];
    for (const [name, token] of Object.entries(tokens)) env[`PV_TOKEN_${name.toUpperCase()}`] = token;

    this.proc = spawn("python3", ["-m", "pv_conformance_driver"], { env, cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
    this.stdoutRaw = "";
    this.stderrRaw = "";
    this._buf = "";
    this._pending = new Map(); // id -> { resolve, reject, timer }
    this._nextId = 1;
    this._exited = null;

    this.proc.stdout.setEncoding("utf8");
    this.proc.stderr.setEncoding("utf8");
    this.proc.stdout.on("data", (chunk) => {
      this.stdoutRaw += chunk;
      this._buf += chunk;
      let nl;
      while ((nl = this._buf.indexOf("\n")) >= 0) {
        const line = this._buf.slice(0, nl);
        this._buf = this._buf.slice(nl + 1);
        if (!line.trim()) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue; // hygiene scan still sees the raw line
        }
        const waiter = this._pending.get(msg.id);
        if (waiter) {
          this._pending.delete(msg.id);
          clearTimeout(waiter.timer);
          waiter.resolve(msg);
        }
      }
    });
    this.proc.stderr.on("data", (chunk) => {
      this.stderrRaw += chunk;
    });
    this.proc.on("exit", (code) => {
      this._exited = code;
      for (const [, waiter] of this._pending) {
        clearTimeout(waiter.timer);
        waiter.reject(new Error(`python driver exited (code ${code}) with ops in flight`));
      }
      this._pending.clear();
    });
  }

  op(op, who, args) {
    if (this._exited !== null) return Promise.reject(new Error(`python driver already exited (code ${this._exited})`));
    const id = this._nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`python driver op ${op} timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      this.proc.stdin.write(`${JSON.stringify({ id, op, client: who, args: args || {} })}\n`);
    }).then((msg) =>
      outcome({
        ok: msg.ok,
        httpStatus: msg.httpStatus ?? null,
        code: msg.code ?? null,
        body: msg.body ?? null,
        replayed: msg.replayed === true,
        errorType: msg.errorType ?? null
      })
    );
  }

  /* Same logical surface as JsDriver (native client-shape results). */
  capabilities() {
    return this.op("capabilities", "anonymous");
  }
  assertCompatible(who) {
    return this.op("assert_compatible", who);
  }
  pinnedSchema() {
    return this.op("pinned_schema", "anonymous");
  }
  introspect() {
    return this.op("introspect", "anonymous");
  }
  listVaults(who) {
    return this.op("list_vaults", who);
  }
  getVault(who, vaultId) {
    return this.op("get_vault", who, { vaultId });
  }
  vaultAudit(who, vaultId) {
    return this.op("vault_audit", who, { vaultId });
  }
  auditFeed(who, limit) {
    return this.op("audit_feed", who, { limit });
  }
  simulate(who, spec) {
    return this.op("simulate", who, { spec });
  }
  buildRequest(who, spec, idempotencyKey) {
    return this.op("build_request", who, { spec, idempotencyKey });
  }
  getRequest(who, requestId) {
    return this.op("get_request", who, { requestId });
  }
  listRequests(who, { vaultId, openOnly } = {}) {
    return this.op("list_requests", who, { vaultId, openOnly });
  }
  submitApproval(who, requestId, spec) {
    return this.op("approve_request", who, { requestId, spec });
  }
  getProposal(who, proposalId) {
    return this.op("get_proposal", who, { proposalId });
  }
  listProposals(who, { vaultId, limit } = {}) {
    return this.op("list_proposals", who, { vaultId, limit });
  }
  getRiskEvaluation(who, evaluationId) {
    return this.op("get_risk_evaluation", who, { evaluationId });
  }
  rejectRequest(who, requestId) {
    return this.op("reject_request", who, { requestId });
  }
  raw(who, { method, path: p, query, body, idempotencyKey }) {
    return this.op("raw", who, { method, path: p, query, body, idempotencyKey });
  }

  async close() {
    try {
      this.proc.stdin.end();
    } catch {
      /* already gone */
    }
    await new Promise((resolve) => {
      if (this._exited !== null) return resolve();
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

module.exports = { PyDriver };
