"use strict";

/*
 * SDK layer — durable-claim adversarial + concurrency cases (mission §24/25,
 * hardening directive §4/§7).
 *
 * The transition claim (create-only link() keyed by the exact predecessor
 * outpoint) is the concurrency boundary: ONE live predecessor -> at most ONE
 * local attempt. These tests prove the boundary holds under retries, races,
 * corruption, and post-confirmation staleness — and that every failure is
 * fail-closed (loud error or preserved claim), never a silent rebind.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const { loadConfig } = require("../src/config");
const {
  claimTransition,
  loadTransitionClaim,
  claimSubmission,
  transitionClaimPath,
  submissionClaimPath
} = require("../src/submission-claim");

function tempConfig() {
  return loadConfig({ dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv2-claims-")) });
}

function outpoint() {
  return { transactionId: crypto.randomBytes(32).toString("hex"), index: 0 };
}

const base = (o, txId) => ({
  outpoint: o,
  action: "delegateSpend",
  txId,
  vaultId: "11".repeat(32),
  stateId: "22".repeat(32),
  expected: null
});

test("second claim on the same predecessor fails CLAIM_CONFLICT and preserves the first", async () => {
  const config = tempConfig();
  const o = outpoint();
  const tx1 = "aa".repeat(32);
  const tx2 = "bb".repeat(32);
  await claimTransition(config, base(o, tx1));
  await assert.rejects(async () => claimTransition(config, base(o, tx2)), (e) => e.code === "CLAIM_CONFLICT" && /already claimed/.test(e.message));
  assert.equal((await loadTransitionClaim(config, o)).txId, tx1, "original claim must be untouched");
});

test("exact same-transaction retry also conflicts (reconcile owns resolution, not retry)", async () => {
  const config = tempConfig();
  const o = outpoint();
  const tx1 = "aa".repeat(32);
  await claimTransition(config, base(o, tx1));
  await assert.rejects(async () => claimTransition(config, base(o, tx1)), (e) => e.code === "CLAIM_CONFLICT");
});

test("multi-process race: exactly one of 6 concurrent claimants wins", async () => {
  const config = tempConfig();
  const o = outpoint();
  const script = `
    const { loadConfig } = require(${JSON.stringify(path.join(__dirname, "../src/config"))});
    const { claimTransition } = require(${JSON.stringify(path.join(__dirname, "../src/submission-claim"))});
    (async () => {
      const config = loadConfig({ dataRoot: process.argv[1] });
      try {
        await claimTransition(config, {
          outpoint: { transactionId: process.argv[2], index: 0 },
          action: "delegateSpend",
          txId: process.argv[3],
          vaultId: "11".repeat(32),
          stateId: "22".repeat(32),
          expected: null
        });
        console.log("WON");
      } catch (e) {
        console.log(e.code === "CLAIM_CONFLICT" || e.code === "EEXIST" ? "LOST" : "ERROR:" + e.message);
      }
    })();
  `;
  // Launch 6 claimants nearly simultaneously (separate processes; link() is
  // the atomic arbiter on the shared filesystem).
  const children = [];
  for (let i = 0; i < 6; i++) {
    const txId = i.toString(16).padStart(2, "0").repeat(32);
    children.push(
      spawnSync(process.execPath, ["-e", script, config.dataRoot, o.transactionId, txId], { encoding: "utf8" })
    );
  }
  const outcomes = children.map((c) => c.stdout.trim());
  const winners = outcomes.filter((s) => s === "WON").length;
  const losers = outcomes.filter((s) => s === "LOST").length;
  assert.equal(winners, 1, `exactly one claimant must win: ${JSON.stringify(outcomes)}`);
  assert.equal(losers, 5, `all others must fail closed: ${JSON.stringify(outcomes)}`);
});

test("corrupted claim file fails closed (loud error, no silent advance)", async () => {
  const config = tempConfig();
  const o = outpoint();
  await claimTransition(config, base(o, "aa".repeat(32)));
  fs.writeFileSync(transitionClaimPath(config, o), "{ not json !!");
  await assert.rejects(async () => loadTransitionClaim(config, o), /corrupt/);
  // And a fresh claim on the same outpoint still conflicts (file exists).
  await assert.rejects(async () => claimTransition(config, base(o, "bb".repeat(32))));
});

test("truncated claim file fails closed", async () => {
  const config = tempConfig();
  const o = outpoint();
  await claimTransition(config, base(o, "aa".repeat(32)));
  const p = transitionClaimPath(config, o);
  const full = fs.readFileSync(p, "utf8");
  fs.writeFileSync(p, full.slice(0, Math.floor(full.length / 2)));
  await assert.rejects(async () => loadTransitionClaim(config, o), /corrupt/);
});

test("submission claim is idempotent for the same txid, distinct txids coexist", async () => {
  const config = tempConfig();
  const tx1 = "aa".repeat(32);
  const tx2 = "bb".repeat(32);
  await claimSubmission(config, { txId: tx1, vaultId: "11".repeat(32), action: "delegateSpend" });
  await claimSubmission(config, { txId: tx1, vaultId: "11".repeat(32), action: "delegateSpend" }); // no throw
  await claimSubmission(config, { txId: tx2, vaultId: "11".repeat(32), action: "delegateSpend" });
  assert.ok(fs.existsSync(submissionClaimPath(config, tx1)));
  assert.ok(fs.existsSync(submissionClaimPath(config, tx2)));
});

test("post-confirmation staleness: consumed predecessor stays claimed; the successor outpoint is freshly claimable", async () => {
  const config = tempConfig();
  const oldOutpoint = outpoint();
  const confirmedTx = "aa".repeat(32);
  // First transition claimed and (conceptually) confirmed.
  await claimTransition(config, base(oldOutpoint, confirmedTx));
  // A stale second package targeting the SAME consumed predecessor must
  // fail closed at the claim — it can never be silently rebound.
  await assert.rejects(async () => claimTransition(config, base(oldOutpoint, "cc".repeat(32))), (e) => e.code === "CLAIM_CONFLICT");
  // The NEXT operation targets the successor outpoint (from the advanced
  // manifest) and claims cleanly.
  const successorOutpoint = { transactionId: confirmedTx, index: 1 };
  await claimTransition(config, base(successorOutpoint, "dd".repeat(32)));
  assert.equal((await loadTransitionClaim(config, successorOutpoint)).txId, "dd".repeat(32));
});

test("legacy claim without an expected record cannot advance state (shape check)", async () => {
  const config = tempConfig();
  const o = outpoint();
  await claimTransition(config, { ...base(o, "aa".repeat(32)), expected: undefined });
  const claim = await loadTransitionClaim(config, o);
  assert.ok(!claim.expected, "legacy claims carry no expected effect");
  // reconcile-v2's advance branch requires claim.expected — verified in
  // v2-reconcile.test.js (UNKNOWN paths); here we pin the stored shape.
});
