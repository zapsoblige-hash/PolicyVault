"use strict";
/*
 * RC45 T8 — THE LADDER TWIN (fix item F8 RC45-L5-API-WEB; plan
 * rc45-simplified-plan-r2 §2.2 twinComplete (CR-M10: only signed-state
 * same-txid members relabel; "BUILT, AWAITING_APPROVALS and pre-signature
 * closed twins stay unchanged, else attestations.js:266-268 drops a TERMINAL
 * governance refusal (pin governance-attestation-ladder.test.js:1165-1212)"),
 * §8 rules (CR-M13, CR2-L11) and T8 "ladder twin (CR-M10): Verify on
 * TWIN_DEF_CREATOR_BUILT after the retry is at depth leaves the creator BUILT
 * and REFUSED_TERMINAL_LADDER"). Internal RED-first regression material for
 * the RC45 candidate; not an audit.
 *
 * The RC42 population (sdk/test/governance-attestation-ladder.test.js
 * cross-version case, written by its own RC42 writer, unchanged): on one
 * PAUSED policyvault-0.4 vault, TWIN_DEF_CREATOR_BUILT is the RC42 defect
 * creator (its governed ownerUnpause build was refused 409
 * GOVERNANCE_PROPOSAL_TERMINAL, yet a BUILT row persisted and CREATED the
 * shared intent-manifest record naming its CANCELLED proposal) and
 * TWIN_SHARER_CV is its content-identical retry (a new proposal, the same
 * fuel: the same txid W) that RC42 advanced to CHAIN_VERIFIED + receipt as a
 * durable-record synthesis — the vault manifest was never advanced. Here W's
 * frozen outputs land on the explicit chain model and reach depth D, and the
 * candidate's Verify settles the vault.
 *
 * RED on C1 e62b1973: the recorded outpoint is gone and no claim exists, so
 * C1's Verify writes TERMINATED_UNKNOWN (case E) and answers UNKNOWN (below D
 * as well). GREEN after F5/F8: below D, CLAIM_PENDING{txId, depth, required}
 * with zero writes; at D, step 7 groups {creator, retry} by W, the primary is
 * the signed-state member (the CHAIN_VERIFIED retry), completePositive
 * advances the manifest to W's successor (the vault ACTIVE again) keeping the
 * existing receipt, and twinComplete leaves the never-signed creator BUILT —
 * byte-identical — so the export still REFUSES it (REFUSED_TERMINAL_LADDER)
 * and the retry keeps its SETTLED ladder (sabotage: a twinComplete that
 * relabels BUILT twins, or a primary chosen from unsigned members).
 *
 * Layers: SDK + API (the candidate's reconcileVaultV4 with the explicit chain
 * model of sdk/testutil/rc45-f5-kit.js passed as `rpc`; the attestation store
 * path and GET /attestations/requests/:id on the self-hosted handle). The
 * RC42 writer needs POLICYVAULT_TEST_RC42_TREE (the a84e2a9 extraction; its
 * writer pins are verified on the tree and on the overlay copy; a missing or
 * mismatched tree FAILS in before(), never skips — CR2-L11). Nothing dials a
 * node. Both stores: JSON always; PostgreSQL (RC42's own migrator applies
 * 001-011; the candidate opens it with no migration) with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). TEST keys only.
 */
const path = require("node:path");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const R42 = require("../testutil/rc45-f8-rc42");
const { LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const cand = K.modulesOf(path.join(__dirname, "..", "src"));
const { Categories } = cand.store;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const RC42_TREE = process.env.POLICYVAULT_TEST_RC42_TREE || "";
const REFUSED_TERMINAL_LADDER = Object.freeze({ decision: "REFUSED", refusalCode: "GOVERNANCE_PROPOSAL_TERMINAL", failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "REFUSED", disposition: "REFUSED", reached: [] });
const settledLadder = (txId, index) => ({ decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId, outputs: 1, successorOutpoint: { transactionId: txId, index }, state: "CHAIN_VERIFIED", disposition: "SETTLED", reached: ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"] });
function ladderOf(attestation) {
  const o = attestation.outcome;
  return { decision: attestation.authorization.decision, refusalCode: attestation.authorization.refusalCode, failureCode: o.failureCode, txId: o.txId,
    outputs: o.chain.outputs.length, successorOutpoint: o.chain.successorOutpoint, state: o.state, disposition: o.disposition, reached: o.reached.map((r) => r.state) };
}
const roots = [], stores = [];
let admin = null, overlay = null;
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
const databases = [];

before(() => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  R42.verifyRc42Tree(RC42_TREE);
  overlay = R42.rc42Overlay(RC42_TREE, mk("pv-rc45-f8-rc42-overlay-"));
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of databases) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* The RC42 writer's population in a fresh JSON root or PostgreSQL database, opened by the candidate with no migration. */
async function rc42Population(backend) {
  const dataRoot = mk("pv-rc45-f8-rc42-data-");
  let pg = null, config;
  if (backend === "PostgreSQL") {
    const database = `pv_rc45_f8_ladder_${process.pid}_${databases.length + 1}`;
    await admin.query(`CREATE DATABASE ${database}`); databases.push(database);
    pg = { host: PG.host, port: PG.port, user: PG.user, database };
  }
  const result = R42.runRc42LadderWriter({ overlay, backend: backend === "PostgreSQL" ? "postgres" : "json", dataRoot, pg });
  if (pg) {
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: pg.host, pgPort: pg.port, pgUser: pg.user, pgDatabase: pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot, rpcUrl: LOOPBACK });
    stores.push(await cand.store.openPgStore(config));
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK });
  return { config, result, store: cand.store.getStore(config) };
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  test(`RC45 T8 ${backend}: ladder twin (CR-M10) — Verify on the RC42 TWIN_DEF_CREATOR_BUILT vault after the retry W is at depth: below D CLAIM_PENDING with zero writes; at D the vault advances by the CHAIN_VERIFIED retry (existing receipt kept), the never-signed creator stays BUILT byte-identical and REFUSED_TERMINAL_LADDER, the retry keeps its SETTLED ladder [RED on C1]`, { skip }, async () => {
    const { config, result, store } = await rc42Population(backend);
    const { buildAttestationForRequest } = require("../../server/src/attestations");
    const { handle } = require("../../server/src/api");
    assert.deepEqual(result.twin, { sameTx: true, sameManifest: true }, "the RC42 writer produced a content-identical pair");
    const cc = result.cases.TWIN_DEF_CREATOR_BUILT, sc = result.cases.TWIN_SHARER_CV;
    assert.ok(cc && sc, "the RC42 writer wrote both twin cases");
    assert.equal(cc.vaultId, sc.vaultId);
    const creator = await cand.wr4.loadRequest(config, cc.requestId), retry = await cand.wr4.loadRequest(config, sc.requestId);
    assert.equal(creator.state, "BUILT"); assert.equal(retry.state, "CHAIN_VERIFIED"); assert.equal(creator.txId, retry.txId);
    const creatorRaw = await store.read(Categories.REQUEST, creator.requestId), receiptBefore = await store.read(Categories.RECEIPT, retry.txId);
    assert.equal(receiptBefore?.proof?.requestId, retry.requestId, "the receipt keyed by the shared txid is the retry's");
    const manifest0 = await store.read(Categories.VAULT, cc.vaultId);
    assert.equal(manifest0.status, "PAUSED"); assert.deepEqual(manifest0.live.outpoint, retry.predecessorOutpoint, "the RC42 synthesis never advanced the manifest");
    assert.deepEqual(ladderOf((await buildAttestationForRequest(config, creator)).attestation), REFUSED_TERMINAL_LADDER, "before Verify the creator is REFUSED like the gate");
    // W lands and deepens on the explicit chain model (the recorded outpoint is spent by W; nothing else is indexed).
    const model = K.chainModel(config);
    model.confirm(frozenOf(retry), retry.txId); model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await K.snapshot(cand, config);
    const pending = await cand.reconcile4.reconcileVaultV4(config, cc.vaultId, { rpc: model.rpc });
    assert.equal(pending.status, "CLAIM_PENDING", `depth 999 < D: the SEEN retry is not yet CONFIRMED (got ${JSON.stringify(pending).slice(0, 300)})`);
    assert.equal(pending.txId, retry.txId); assert.equal(String(pending.required), String(SETTLE_DEPTH_DAA));
    assert.deepEqual(await K.snapshot(cand, config), below, "below D nothing is written (no TERMINATED_UNKNOWN)");
    model.advance(1n);
    const done = await cand.reconcile4.reconcileVaultV4(config, cc.vaultId, { rpc: model.rpc });
    assert.equal(done.status, "ADVANCED", `at D Verify settles the vault by W (got ${JSON.stringify(done).slice(0, 300)})`);
    assert.equal(done.txId, retry.txId); assert.equal(done.requestId, retry.requestId, "the primary is the signed-state member (the retry), never the BUILT creator");
    const m = await store.read(Categories.VAULT, cc.vaultId);
    assert.equal(m.status, "ACTIVE", "the retry is an ownerUnpause of the PAUSED vault");
    assert.deepEqual(m.live.outpoint, { transactionId: retry.txId, index: sc.successorIndex }); assert.equal(m.latestTransitionTxId, retry.txId);
    assert.deepEqual(await store.read(Categories.REQUEST, creator.requestId), creatorRaw, "the never-signed BUILT creator is byte-identical (CR-M10)");
    assert.equal((await store.read(Categories.REQUEST, retry.requestId)).state, "CHAIN_VERIFIED");
    assert.deepEqual(await store.read(Categories.RECEIPT, retry.txId), receiptBefore, "the existing receipt is kept (H-40)");
    const creatorAfter = await cand.wr4.loadRequest(config, creator.requestId), retryAfter = await cand.wr4.loadRequest(config, retry.requestId);
    assert.deepEqual(ladderOf((await buildAttestationForRequest(config, creatorAfter)).attestation), REFUSED_TERMINAL_LADDER, "the creator stays REFUSED_TERMINAL_LADDER (store path)");
    const route = await handle(config, "GET", ["attestations", "requests", creator.requestId], {}, null);
    assert.equal(route.status, 200); assert.deepEqual(ladderOf(route.body.attestation), REFUSED_TERMINAL_LADDER, "the creator stays REFUSED_TERMINAL_LADDER (request route)");
    assert.deepEqual(ladderOf((await buildAttestationForRequest(config, retryAfter)).attestation), settledLadder(retry.txId, sc.successorIndex), "the retry keeps its SETTLED ladder");
  });
}
