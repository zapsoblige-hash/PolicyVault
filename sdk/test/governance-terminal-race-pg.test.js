"use strict";

/*
 * GOVERNANCE-TERMINAL-RACE-01 — PostgreSQL PARITY of the terminal-claim
 * arbitration (sdk/test/governance-terminal-race.test.js is the JSON
 * suite). Two real processes share one fresh database: the first holds
 * its record write (or its terminal-claim insert), the second runs with
 * a +31001 ms Date.now offset, reclaims the transition lock and finishes;
 * the first then continues. Exactly one success is the invariant on this
 * backend too, arbitrated by INSERT ... ON CONFLICT DO NOTHING. Skipped
 * (never silently passed) without POLICYVAULT_TEST_PG_{PORT,USER,DATABASE}.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");
const crypto = require("crypto");

const OWNER = "11".repeat(32);
const VAULT = "12".repeat(32);
const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);

function pgConfig(dbName, dataRoot) {
  const { loadConfig } = require("../src/config");
  return loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true, authMode: "enabled", authCookieInsecure: true, dataRoot });
}

if (process.argv[2] === "worker") {
  const input = JSON.parse(process.argv[3]);
  const { openPgStore, Categories } = require("../src/store");
  const gov = require("../../server/src/governance");
  const config = pgConfig(input.dbName, input.dataRoot);
  const realNow = Date.now;
  Date.now = () => realNow() + input.clockShift;
  let continued;
  const barrier = new Promise((resolve) => { continued = resolve; });
  process.on("message", (m) => { if (m === "continue") continued(); });
  (async () => {
    let store = null;
    try {
      store = await openPgStore(config);
      const realWrite = store.write.bind(store);
      const realCreate = store.createExclusive.bind(store);
      store.write = async function (category, key, value) {
        if (input.hold === "write" && category === Categories.GOVERNANCE_PROPOSAL && key === input.proposalId) {
          process.send({ phase: "before-write", status: value.status });
          await barrier;
        }
        return realWrite(category, key, value);
      };
      store.createExclusive = async function (category, key, value) {
        if (input.hold === "claim" && category === Categories.GOVERNANCE_PROPOSAL && key === `xterm-${input.proposalId}`) {
          process.send({ phase: "before-claim", status: value.status });
          await barrier;
        }
        return realCreate(category, key, value);
      };
      const result = input.action === "consume"
        ? await gov.markProposalConsumed(config, { proposalId: input.proposalId }, { requestId: input.requestId, txId: "ed".repeat(32) })
        : await gov.cancelProposal({ config, proposalId: input.proposalId, cancelledByXOnly: OWNER });
      process.send({ phase: "finished", ok: true, status: result.status, requestId: result.lastConsumedRequestId ?? null });
    } catch (error) {
      process.send({ phase: "finished", ok: false, code: error.code ?? null, message: error.message });
    } finally {
      try { if (store) await store.close(); } catch { /* closed */ }
      process.disconnect();
    }
  })();
} else {
  const { test, before, after } = require("node:test");
  const assert = require("node:assert/strict");
  const { openPgStore, Categories } = require("../src/store");
  const { normalizeStateV4 } = require("../src/vault-state-v4");
  const gov = require("../../server/src/governance");
  const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the terminal-claim PG parity suite";
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gov-race-pg-"));
  const dbName = `pv_govrace_${process.pid}_${Date.now() % 100000}`;
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  let adminPool, config, store;

  before(async () => {
    if (!PG_AVAILABLE) return;
    const { Pool } = require("pg");
    adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
    await adminPool.query(`CREATE DATABASE ${dbName}`);
    config = pgConfig(dbName, fs.mkdtempSync(path.join(work, "root-")));
    store = await openPgStore(config, { migrate: true });
  });
  after(async () => {
    if (!PG_AVAILABLE) return;
    try { await store.close(); } catch { /* closed */ }
    await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await adminPool.end();
  });

  async function freshProposal() {
    const state = normalizeStateV4({ protectedValue: "10000", feeReserve: "1000", paused: "1", agentRoot: "00".repeat(32), approvers: [], approvalM: "0", policyNonce: "0" });
    const manifest = { contractVersion: "policyvault-0.4.1", template: { owner: OWNER, vaultId: VAULT }, live: { state }, agentRegistry: [] };
    const record = await gov.createProposal({ config, manifest, vaultId: VAULT, action: "ownerUnpause", params: {}, proposedByXOnly: OWNER });
    return record.proposalId;
  }
  function worker(input) {
    const child = cp.fork(__filename, ["worker", JSON.stringify(input)], { stdio: ["ignore", "pipe", "pipe", "ipc"], env: { ...process.env, TMPDIR: work } });
    const events = [];
    let stderr = "";
    child.stderr.on("data", (b) => { stderr += b; });
    child.on("message", (m) => events.push(m));
    return {
      child, events,
      until: async (phase) => {
        const start = Date.now();
        for (;;) {
          const m = events.find((e) => e.phase === phase);
          if (m) return m;
          if (Date.now() - start > 15000) throw new Error(`worker ${phase} timeout: ${stderr}`);
          await wait(5);
        }
      },
      settle: () => new Promise((resolve) => { if (child.exitCode !== null) return resolve(child.exitCode); child.once("exit", resolve); })
    };
  }
  async function twoProcessCase({ first, clockShift, hold = "write" }) {
    const proposalId = await freshProposal();
    const requestId = crypto.randomUUID();
    const base = { dbName, dataRoot: config.dataRoot, proposalId, requestId };
    let a, b;
    try {
      a = worker({ ...base, action: first, hold, clockShift: 0 });
      await a.until(hold === "claim" ? "before-claim" : "before-write");
      b = worker({ ...base, action: first === "consume" ? "cancel" : "consume", hold: "none", clockShift });
      const second = await b.until("finished");
      a.child.send("continue");
      const original = await a.until("finished");
      await Promise.all([a.settle(), b.settle()]);
      const final = await gov.loadProposalRecord(config, proposalId);
      const row = await store.pool().query(`SELECT value FROM governance_proposals WHERE network_id=$1 AND key=$2`, [config.networkId, `xterm-${proposalId}`]);
      return { original, second, final, requestId, proposalId, claim: row.rows[0]?.value ?? null };
    } finally {
      for (const x of [a, b]) if (x && x.child.exitCode === null) x.child.kill("SIGKILL");
    }
  }

  for (const [first, hold] of [["cancel", "write"], ["consume", "write"], ["cancel", "claim"], ["consume", "claim"]]) {
    test(`PG two processes, ${first} held before its ${hold}, +31001ms contender: exactly one success, the row equals the winner, exactly one terminal claim row`, { skip }, async () => {
      const r = await twoProcessCase({ first, clockShift: 31001, hold });
      const successes = [r.original, r.second].filter((x) => x.ok);
      assert.equal(successes.length, 1, `exactly one success (original=${JSON.stringify(r.original)}, second=${JSON.stringify(r.second)})`);
      const winner = successes[0];
      const loser = r.original.ok ? r.second : r.original;
      assert.ok(["GOVERNANCE_PROPOSAL_TERMINAL", "GOVERNANCE_PROPOSAL_CLOSED"].includes(loser.code), `loser refuses (${loser.code})`);
      assert.equal(r.final.status, winner.status);
      assert.equal(r.final.lastConsumedRequestId ?? null, winner.status === "CONSUMED" ? r.requestId : null);
      assert.ok(r.claim && r.claim.schema === "policyvault-governance-terminal-claim/v1" && r.claim.status === winner.status, "the single terminal claim row belongs to the winner");
      if (hold === "claim") assert.equal(r.original.ok, false, "held-before-claim original takes the arbiter's LOSE branch");
    });
  }

  test("PG zero clock skew control: the live holder wins; the contender refuses BUSY or TERMINAL", { skip }, async () => {
    const r = await twoProcessCase({ first: "consume", clockShift: 0 });
    assert.equal(r.original.ok, true);
    assert.equal(r.second.ok, false);
    assert.ok(["GOVERNANCE_TRANSITION_BUSY", "GOVERNANCE_PROPOSAL_TERMINAL"].includes(r.second.code));
  });

  test("PG crash after the terminal claim: the row is still OPEN, reads overlay the claim, transitions refuse, same-request replay is idempotent, listings exclude claims", { skip }, async () => {
    const proposalId = await freshProposal();
    const requestId = crypto.randomUUID();
    assert.equal(await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xterm-${proposalId}`, {
      schema: "policyvault-governance-terminal-claim/v1", proposalId, status: "CONSUMED", holderToken: "crashed", requestId, txId: "ab".repeat(32), claimedAt: new Date().toISOString(), claimedAtMs: Date.now()
    }), true);
    const raw = await store.pool().query(`SELECT value->>'status' AS s FROM governance_proposals WHERE network_id=$1 AND key=$2`, [config.networkId, proposalId]);
    assert.equal(raw.rows[0].s, "OPEN", "the raw row is still OPEN (crash window)");
    const loaded = await gov.loadProposalRecord(config, proposalId);
    assert.equal(loaded.status, "CONSUMED");
    assert.equal(loaded.lastConsumedRequestId, requestId);
    await assert.rejects(gov.cancelProposal({ config, proposalId, cancelledByXOnly: OWNER }), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
    await assert.rejects(gov.markProposalConsumed(config, { proposalId }, { requestId: crypto.randomUUID(), txId: null }), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
    const replay = await gov.markProposalConsumed(config, { proposalId }, { requestId, txId: null });
    assert.equal(replay.lastConsumedRequestId, requestId);
    const listed = await gov.listProposals(config, { vaultId: VAULT });
    assert.ok(listed.every((r) => r.schema === "policyvault-governance-proposal-record/v1"));
    assert.equal(listed.find((r) => r.proposalId === proposalId).status, "CONSUMED");
  });
}
