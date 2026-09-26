"use strict";

/*
 * GOVERNANCE-TERMINAL-RACE-01 — REGRESSION + ADVERSARIAL SUITE.
 *
 * THE DEFECT (confirmed by a RED reproduction; governance.js blob
 * 7fa00638 identical at development and the retained RC42 source): the
 * per-proposal transition lock is
 * reclaimable by ANY contender whose LOCAL clock sees the lock as older
 * than TRANSITION_LOCK_STALE_MS. A contender whose clock is skewed by
 * >30 s removes a LIVE holder's lock, re-arbitrates, and completes its
 * own terminal transition; the original (delayed) holder then performs
 * its UNCONDITIONAL record write and replaces the contender's terminal
 * evidence. Both callers observe success (CANCELLED and CONSUMED);
 * exactly one success is the invariant.
 *
 * THE CORRECTION: the terminal transition itself is arbitrated by a
 * create-only TERMINAL CLAIM record (`xterm-<proposalId>`, link()/EEXIST
 * on JSON, INSERT ... ON CONFLICT DO NOTHING on PostgreSQL) written
 * BEFORE the record write. Exactly one contender can create it; the
 * loser refuses on the claim's terminal state without writing. Reads
 * overlay a present claim so a crash after the claim (before the record
 * write) still reads terminal. The stale-lock reclaim stays (it only
 * serves crashed holders) but can no longer produce a second success.
 *
 * Layer: SDK module-level (direct governance.js calls, exactly the api.js
 * usage contract) over a temp JSON data root; the confirmed race is
 * reproduced with TWO real processes (child_process.fork), an injected
 * write hold in the first and a Date.now offset in the second — the
 * retained RED's own shape. SABOTAGE mutates governance.js in place and
 * requires the serialized runner (docs/test-plan.md rule 7).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");
const crypto = require("crypto");

const GOVERNANCE_PATH = path.join(__dirname, "..", "..", "server", "src", "governance.js");
const OWNER = "11".repeat(32);
const VAULT = "12".repeat(32);

/* ------------------------------------------------------------------ */
/* Worker mode: one real contender process.                            */
/* ------------------------------------------------------------------ */
if (process.argv[2] === "worker") {
  const input = JSON.parse(process.argv[3]);
  const { loadConfig } = require("../src/config");
  const { getStore, Categories } = require("../src/store");
  const gov = require("../../server/src/governance");
  const config = loadConfig({ dataRoot: input.dataRoot });
  const store = getStore(config);
  const realWrite = store.write.bind(store);
  const realCreate = store.createExclusive.bind(store);
  const realNow = Date.now;
  Date.now = () => realNow() + input.clockShift;
  let continued;
  const barrier = new Promise((resolve) => { continued = resolve; });
  process.on("message", (m) => { if (m === "continue") continued(); });
  store.write = async function (category, key, value) {
    if (input.hold === "write" && category === Categories.GOVERNANCE_PROPOSAL && key === input.proposalId) {
      process.send({ phase: "before-write", status: value.status });
      await barrier;
    }
    return realWrite(category, key, value);
  };
  // IR-01: hold INSIDE the terminal-claim arbiter, after the lock was taken
  // and the durable record was read, but before the claim is created — the
  // contender then wins the claim and the original must take the LOSE branch.
  store.createExclusive = async function (category, key, value) {
    if (input.hold === "claim" && category === Categories.GOVERNANCE_PROPOSAL && key === `xterm-${input.proposalId}`) {
      process.send({ phase: "before-claim", status: value.status });
      await barrier;
    }
    return realCreate(category, key, value);
  };
  (async () => {
    try {
      const result = input.action === "consume"
        ? await gov.markProposalConsumed(config, { proposalId: input.proposalId }, { requestId: input.requestId, txId: "ed".repeat(32) })
        : await gov.cancelProposal({ config, proposalId: input.proposalId, cancelledByXOnly: OWNER });
      process.send({ phase: "finished", ok: true, status: result.status, requestId: result.lastConsumedRequestId ?? null });
    } catch (error) {
      process.send({ phase: "finished", ok: false, code: error.code ?? null, message: error.message });
    } finally {
      process.disconnect();
    }
  })();
} else {
  const { test } = require("node:test");
  const assert = require("node:assert/strict");
  const { loadConfig } = require("../src/config");
  const { getStore, Categories } = require("../src/store");
  const { normalizeStateV4 } = require("../src/vault-state-v4");
  const gov = require("../../server/src/governance");

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gov-race-"));
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function freshProposal() {
    const dataRoot = fs.mkdtempSync(path.join(work, "root-"));
    const config = loadConfig({ dataRoot });
    const state = normalizeStateV4({ protectedValue: "10000", feeReserve: "1000", paused: "1", agentRoot: "00".repeat(32), approvers: [], approvalM: "0", policyNonce: "0" });
    const manifest = { contractVersion: "policyvault-0.4.1", template: { owner: OWNER, vaultId: VAULT }, live: { state }, agentRegistry: [] };
    const record = await gov.createProposal({ config, manifest, vaultId: VAULT, action: "ownerUnpause", params: {}, proposedByXOnly: OWNER });
    return { dataRoot, config, proposalId: record.proposalId };
  }

  function worker(input) {
    const child = cp.fork(__filename, ["worker", JSON.stringify(input)], { stdio: ["ignore", "pipe", "pipe", "ipc"], env: { ...process.env, TMPDIR: work } });
    const events = [];
    let stderr = "";
    child.stderr.on("data", (b) => { stderr += b; });
    child.on("message", (m) => events.push(m));
    return {
      child, events, stderr: () => stderr,
      until: async (phase) => {
        const start = Date.now();
        for (;;) {
          const m = events.find((e) => e.phase === phase);
          if (m) return m;
          if (Date.now() - start > 8000) throw new Error(`worker ${phase} timeout: ${stderr}`);
          await wait(5);
        }
      },
      settle: () => new Promise((resolve) => { if (child.exitCode !== null) return resolve(child.exitCode); child.once("exit", resolve); })
    };
  }

  /* Two real processes: the first holds its record write; the second,
   * with a skewed clock, reclaims the lock and finishes; the first then
   * continues. Exactly one may succeed and the durable record must equal
   * the winner. */
  async function twoProcessCase({ first, clockShift, hold = "write" }) {
    const { dataRoot, config, proposalId } = await freshProposal();
    const requestId = crypto.randomUUID();
    const base = { dataRoot, proposalId, requestId };
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
      return { original, second, final, requestId, config, proposalId };
    } finally {
      for (const x of [a, b]) if (x && x.child.exitCode === null) x.child.kill("SIGKILL");
    }
  }

  for (const [first, clockShift] of [["cancel", 31001], ["consume", 31001]]) {
    test(`two processes, ${first} held, opposite contender with +${clockShift}ms clock: exactly one transition succeeds and the durable record equals the winner`, async () => {
      const r = await twoProcessCase({ first, clockShift });
      const successes = [r.original, r.second].filter((x) => x.ok);
      assert.equal(successes.length, 1, `exactly one success (original=${JSON.stringify(r.original)}, second=${JSON.stringify(r.second)})`);
      const winner = successes[0];
      const loser = r.original.ok ? r.second : r.original;
      assert.equal(r.final.status, winner.status, "durable record equals the winner");
      assert.equal(r.final.lastConsumedRequestId ?? null, winner.status === "CONSUMED" ? r.requestId : null);
      assert.ok(["GOVERNANCE_PROPOSAL_TERMINAL", "GOVERNANCE_PROPOSAL_CLOSED"].includes(loser.code), `the loser refuses deterministically (got ${loser.code})`);
    });
  }

  for (const first of ["cancel", "consume"]) {
    test(`IR-01: ${first} held INSIDE the arbiter before its claim, +31001ms contender claims first: the original takes the arbiter's LOSE branch (refuses without writing) and the contender's record stands`, async () => {
      const r = await twoProcessCase({ first, clockShift: 31001, hold: "claim" });
      assert.equal(r.second.ok, true, `the contender won the claim (${JSON.stringify(r.second)})`);
      assert.equal(r.original.ok, false, `the original lost the claim after its lock/read (${JSON.stringify(r.original)})`);
      assert.ok(["GOVERNANCE_PROPOSAL_TERMINAL", "GOVERNANCE_PROPOSAL_CLOSED"].includes(r.original.code), `loser code ${r.original.code}`);
      assert.equal(r.final.status, r.second.status, "durable record equals the contender (the original never wrote)");
      assert.equal(r.final.lastConsumedRequestId ?? null, r.second.status === "CONSUMED" ? r.requestId : null);
    });
  }

  test("two processes, zero clock skew control: the live holder wins and the contender refuses BUSY or TERMINAL", async () => {
    const r = await twoProcessCase({ first: "consume", clockShift: 0 });
    assert.equal(r.original.ok, true);
    assert.equal(r.second.ok, false);
    assert.ok(["GOVERNANCE_TRANSITION_BUSY", "GOVERNANCE_PROPOSAL_TERMINAL"].includes(r.second.code));
    assert.equal(r.final.status, "CONSUMED");
  });

  test("crash after the terminal claim, before the record write: reads overlay the claim as terminal; transitions refuse; same-request consume replays idempotently", async () => {
    const { config, proposalId } = await freshProposal();
    const store = getStore(config);
    const requestId = crypto.randomUUID();
    const created = await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xterm-${proposalId}`, {
      schema: "policyvault-governance-terminal-claim/v1", proposalId, status: "CONSUMED", holderToken: "crashed",
      requestId, txId: "ab".repeat(32), claimedAt: new Date().toISOString(), claimedAtMs: Date.now()
    });
    assert.equal(created, true);
    assert.equal(JSON.parse(fs.readFileSync(path.join(config.dataRoot, "governance", "proposals", `${proposalId}.json`), "utf8")).status, "OPEN", "the on-disk record is still OPEN (crash window)");
    const loaded = await gov.loadProposalRecord(config, proposalId);
    assert.equal(loaded.status, "CONSUMED", "the claim overlays the stale OPEN record");
    assert.equal(loaded.lastConsumedRequestId, requestId);
    await assert.rejects(gov.cancelProposal({ config, proposalId, cancelledByXOnly: OWNER }), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
    await assert.rejects(gov.markProposalConsumed(config, { proposalId }, { requestId: crypto.randomUUID(), txId: null }), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
    const replay = await gov.markProposalConsumed(config, { proposalId }, { requestId, txId: null });
    assert.equal(replay.status, "CONSUMED");
    assert.equal(replay.lastConsumedRequestId, requestId, "same-request replay is idempotent and preserves the first evidence");
    const listed = await gov.listProposals(config, { vaultId: VAULT });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].status, "CONSUMED", "listings overlay the claim too");
    assert.ok(listed.every((r) => r.schema === "policyvault-governance-proposal-record/v1"), "claim records never surface as proposals");
  });

  test("a crashed (stale) lock holder without a claim is still reclaimed; the terminal claim persists after the lock is released", async () => {
    const { config, proposalId } = await freshProposal();
    const store = getStore(config);
    await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xlock-${proposalId}`, {
      schema: "policyvault-governance-transition-lock/v1", proposalId, holderToken: "dead", createdAt: new Date(Date.now() - 60000).toISOString(), createdAtMs: Date.now() - 60000
    });
    const cancelled = await gov.cancelProposal({ config, proposalId, cancelledByXOnly: OWNER });
    assert.equal(cancelled.status, "CANCELLED");
    assert.equal(await store.read(Categories.GOVERNANCE_PROPOSAL, `xlock-${proposalId}`), null, "lock released");
    const claim = await store.read(Categories.GOVERNANCE_PROPOSAL, `xterm-${proposalId}`);
    assert.equal(claim && claim.status, "CANCELLED", "the terminal claim is durable evidence, never released");
    await assert.rejects(gov.cancelProposal({ config, proposalId, cancelledByXOnly: OWNER }), (e) => e.code === "GOVERNANCE_PROPOSAL_CLOSED");
  });

  test("SABOTAGE: neutralizing the terminal claim resurrects the double success under clock skew (and restoring re-arms exactly-one)", async () => {
    const original = fs.readFileSync(GOVERNANCE_PATH, "utf8");
    // Neutralize the whole mechanism (claim arbitration AND read overlay)
    // by giving every claim a fresh key: no contender ever sees another's
    // claim, exactly the pre-fix world.
    const marker = "const terminalClaimKey = (proposalId) => `xterm-${proposalId}`;";
    assert.equal(original.split(marker).length, 2, "sabotage marker present exactly once");
    const sabotaged = original.replace(marker, "const terminalClaimKey = (proposalId) => `xterm-${proposalId}-${crypto.randomUUID()}`; // SABOTAGE");
    fs.writeFileSync(GOVERNANCE_PATH, sabotaged);
    try {
      const r = await twoProcessCase({ first: "cancel", clockShift: 31001 });
      const successes = [r.original, r.second].filter((x) => x.ok).length;
      assert.equal(successes, 2, "with the claim neutralized both contenders succeed (the original defect)");
    } finally {
      fs.writeFileSync(GOVERNANCE_PATH, original);
    }
    assert.equal(fs.readFileSync(GOVERNANCE_PATH, "utf8"), original, "source restored byte-for-byte");
    const r = await twoProcessCase({ first: "cancel", clockShift: 31001 });
    assert.equal([r.original, r.second].filter((x) => x.ok).length, 1, "restored source re-arms exactly-one");
  });
}
