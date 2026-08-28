"use strict";

/*
 * RC-UX-1 PG PARITY — the id-less RELEASED-hold continuation against a
 * REAL PostgreSQL backend (finding: docs/postlaunch/
 * rc-mainnet-acceptance-evidence.md §5.2; JSON-store behavior proven in
 * sdk/test/rc-ux1-released-hold-continuation.test.js and the browser
 * suite). SKIPPED cleanly without POLICYVAULT_TEST_PG_* (same pattern
 * as budget-reservation-pg.test.js: a fresh, uniquely-named database on
 * the shared cluster, created + dropped here).
 *
 * Proves ON POSTGRES, at the service boundary (server/src/risk.js —
 * the exact code the API route calls):
 *   - hold -> release -> id-less exact-intent re-submission consumes
 *     the release via ONE atomic conditional UPDATE (WHERE
 *     status='RELEASED' ... — the cross-process arbiter), and
 *     recordRiskOutcome then stamps the consuming request;
 *   - the jsonb round trip (which reorders object keys) never breaks
 *     the read-side integrity re-hash (canonicalJsonStringify is
 *     key-order-independent) — the stored intent still binds;
 *   - exactly-once: a second identical attempt gets a FRESH hold;
 *   - concurrency: two simultaneous identical id-less attempts — one
 *     wins the row, the loser falls through to a fresh evaluation
 *     (HOLDS, default-restrictive), the row is consumed once;
 *   - wrong-vault / wrong-intent / stale-controls-version attempts
 *     never touch the released row.
 *
 * No manifests, no builds, no signatures, no broadcast — the risk gate
 * runs entirely above the covenant pipeline (restrictive-only hosted
 * coordination).
 */

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");

const { loadConfig } = require("../src/config");
const { openPgStore } = require("../src/store");
const { saveOrgControls } = require("../../server/src/org-controls");
const org = require("../src/organization");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const skip = PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the RC-UX-1 PG parity suite";

let adminPool;
let config;
let store;
let riskSvc;
const dbName = `pv_rcux1_${process.pid}_${Date.now() % 100000}`;

const KAS = 100000000n;
const VAULT_A = "d1".repeat(32);
const VAULT_B = "d2".repeat(32);
const AGENT_X = "e1".repeat(32);
const OWNER_X = "e2".repeat(32);
const RECIP_X = "e3".repeat(32);
const AGENT_ADDR = "kaspatest:rcux1agentaddressfixture0000000000000000000000000000000000000";

let orgId;
let controls; // the CURRENT normalized org-controls record (carries .version)

before(async () => {
  if (!PG_AVAILABLE) return;
  const { Pool } = require("pg");
  adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
  await adminPool.query(`CREATE DATABASE ${dbName}`);
  const fs = require("fs");
  const os = require("os");
  const path = require("path");
  config = loadConfig({
    persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: dbName, pgNoTls: true,
    authMode: "enabled", authCookieInsecure: true,
    dataRoot: fs.mkdtempSync(path.join(os.tmpdir(), "pv-rcux1pg-"))
  });
  store = await openPgStore(config, { migrate: true });
  riskSvc = require("../../server/src/risk");
  const created = await org.createOrganization(config, { name: "rc-ux1 pg org" });
  orgId = created.orgId;
  controls = await saveOrgControls(config, orgId, {
    governance: {},
    risk: { adapters: [{ type: "amount-threshold", params: { reviewAboveSompi: (5n * KAS).toString() } }] },
    expectedVersion: 0
  });
});

after(async () => {
  if (!PG_AVAILABLE) return;
  try {
    await store.close();
  } catch {
    /* closed */
  }
  await adminPool.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  await adminPool.end();
});

const gate = (vaultId, amountKas, extra = {}) =>
  riskSvc.gateOperationRisk({
    config, vaultId, orgId, controls: extra.controls ?? controls,
    action: "agentSpend",
    params: { payAmountSompi: (amountKas * KAS).toString(), agentPk: AGENT_X, recipient: RECIP_X },
    signerAddress: AGENT_ADDR, signerXOnly: AGENT_X, sdkAction: "agentSpend",
    riskEvaluationId: extra.riskEvaluationId
  });

async function expectHold(promise) {
  try {
    await promise;
    assert.fail("expected RISK_REVIEW_REQUIRED");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    assert.equal(e.code, "RISK_REVIEW_REQUIRED", e.message);
    return e.extra.riskEvaluation.evaluationId;
  }
}

const rowOf = async (id) => {
  const r = await store.pool().query(`SELECT value FROM risk_evaluations WHERE network_id = $1 AND key = $2`, [config.networkId, id]);
  return r.rowCount ? r.rows[0].value : null;
};

test("PG: hold -> release -> id-less exact-intent continuation consumes the released row atomically; jsonb key reordering never breaks the integrity re-hash", { skip }, async () => {
  assert.equal(store.kind, "postgres", "the run really is on the PG backend");
  const evId = await expectHold(gate(VAULT_A, 7n));
  assert.equal((await rowOf(evId)).status, "REVIEW_HELD");
  const released = await riskSvc.releaseEvaluation(config, evId, { releasedByXOnly: OWNER_X });
  assert.equal(released.status, "RELEASED");

  // The PG round trip reorders jsonb object keys — the read-side
  // recompute must still bind (canonicalJsonStringify key independence).
  const stored = await rowOf(evId);
  assert.doesNotThrow(() => riskSvc.assertEvaluationIntegrity(stored));
  assert.equal(stored.intentHash, riskSvc.intentHashOf(stored.intent));
  assert.equal(stored.controlsVersion, controls.version);

  // The id-less exact re-submission continues the release.
  const g = await gate(VAULT_A, 7n);
  assert.equal(g.released, true);
  assert.equal(g.rematched, true);
  assert.equal(g.evaluationId, evId);
  const consumed = await rowOf(evId);
  assert.equal(consumed.status, "CONSUMED");
  assert.equal(consumed.consumedVia, "RELEASED_INTENT_REMATCH");

  // recordRiskOutcome (the build-success stamp) binds the request id.
  await riskSvc.recordRiskOutcome(config, g, { requestId: "req-rcux1-pg-1", txId: null });
  const stamped = await rowOf(evId);
  assert.equal(stamped.status, "CONSUMED");
  assert.equal(stamped.consumedByRequestId, "req-rcux1-pg-1");
  assert.deepEqual(stamped.policyGate, { final: "REVIEW", source: "risk" });
});

test("PG: exactly-once — a second identical id-less attempt gets a FRESH hold and the consumed row is untouched", { skip }, async () => {
  const freshId = await expectHold(gate(VAULT_A, 7n));
  const fresh = await rowOf(freshId);
  assert.equal(fresh.status, "REVIEW_HELD");
  const consumedRows = await store.pool().query(
    `SELECT key FROM risk_evaluations WHERE network_id = $1 AND value->>'status' = 'CONSUMED'`,
    [config.networkId]
  );
  assert.equal(consumedRows.rowCount, 1, "still exactly one consumed evaluation");
  assert.notEqual(freshId, consumedRows.rows[0].key);
});

test("PG: concurrency — two simultaneous identical id-less attempts, one atomic winner, the loser holds fresh", { skip }, async () => {
  const evId = await expectHold(gate(VAULT_A, 9n));
  await riskSvc.releaseEvaluation(config, evId, { releasedByXOnly: OWNER_X });
  const results = await Promise.allSettled([gate(VAULT_A, 9n), gate(VAULT_A, 9n)]);
  const ok = results.filter((r) => r.status === "fulfilled");
  const failed = results.filter((r) => r.status === "rejected");
  assert.equal(ok.length, 1, `exactly one winner (${JSON.stringify(results.map((r) => (r.status === "rejected" ? r.reason.code : "consumed")))})`);
  assert.equal(ok[0].value.evaluationId, evId);
  assert.equal(ok[0].value.rematched, true);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].reason.code, "RISK_REVIEW_REQUIRED", "the race loser fell through to a FRESH evaluation, which HOLDS");
  assert.notEqual(failed[0].reason.extra.riskEvaluation.evaluationId, evId);
  const row = await rowOf(evId);
  assert.equal(row.status, "CONSUMED");
  assert.equal(row.consumedVia, "RELEASED_INTENT_REMATCH");
});

test("PG: wrong-vault, wrong-intent, and stale-controls-version attempts never touch a released row", { skip }, async () => {
  const evId = await expectHold(gate(VAULT_A, 11n));
  await riskSvc.releaseEvaluation(config, evId, { releasedByXOnly: OWNER_X });

  // wrong intent (different amount, still above the review line)
  await expectHold(gate(VAULT_A, 12n));
  assert.equal((await rowOf(evId)).status, "RELEASED");

  // wrong vault (identical parameters, different vault)
  await expectHold(gate(VAULT_B, 11n));
  assert.equal((await rowOf(evId)).status, "RELEASED");

  // stale controls version: a re-save (identical content) bumps the CAS
  // version — the id-less continuation refuses; a fresh hold spawns.
  const bumped = await saveOrgControls(config, orgId, { governance: {}, risk: controls.risk, expectedVersion: controls.version });
  assert.equal(bumped.version, controls.version + 1);
  await expectHold(gate(VAULT_A, 11n, { controls: bumped }));
  assert.equal((await rowOf(evId)).status, "RELEASED", "the stale release is never consumed id-lessly");

  // The EXPLICIT riskEvaluationId path is unchanged: it still consumes
  // the release across the controls-version change (existing semantics).
  const g = await gate(VAULT_A, 11n, { controls: bumped, riskEvaluationId: evId });
  assert.equal(g.released, true);
  assert.notEqual(g.rematched, true, "the explicit path is not a rematch");
  controls = bumped; // keep the module-level record current
});
