"use strict";
/*
 * RC45 R1-03 — A GOVERNANCE-REFUSED UNSIGNED PRIMARY IS NEVER RELABELLED
 * (finding F-01 of the independent candidate review rc45-patch-independent-01;
 * remediation plan R1 revision 2, R1-03 with conditions C1 and K6 and the INFO
 * implementation notes RC1-08 and RC1-09). Internal RED-first regression
 * material for the RC45 successor candidate; not an audit. Adapted from the
 * review-only probes review-verify1-governed-primary (verify-1) and
 * review-lead-governed-primary (lead).
 *
 * The rule (plan R1-03): when the CONFIRMED group's primary is outside
 * SIGNED_STATES u {SUBMISSION_REJECTED} and governanceRefusalFor(config,
 * primary, creatorManifestRecord) is non-null, Verify advances the manifest
 * (lastTransition records the action, txid and outpoints) and settles the
 * losers as today, but does NOT relabel the primary and writes NO receipt
 * naming it; the audit row is reconciled_advanced {via:
 * "governance-refused-request-txid", txId}; the ADVANCED answer omits
 * requestId (RC1-09); an unknown proposal or terminal-claim schema answers 422
 * with nothing written. The predicate is evaluated inside the pass for every
 * caller (RC1-08): the SDK-direct reconcileVaultV4 (also what
 * tools/staging-backup-restore.js calls), request-scoped recovery
 * (settleJournalFree) and the hosted Verify route. The governed row stays
 * BUILT and exports REFUSED_TERMINAL_LADDER on every export path; its hosted
 * finalize and submit answer 409 GOVERNANCE_PROPOSAL_TERMINAL from
 * assertManifestGate with no write (K6). Every other primary keeps dc7552e's
 * completion (CHAIN_VERIFIED with a receipt): an unsigned primary whose
 * proposal was consumed by it, a governance-refused primary in a signed state,
 * and an ungoverned BUILT primary (the T4 pin
 * sdk/test/rc45-t4-finalize-gap.test.js:678-695 is unchanged).
 *
 * RED on dc7552e: step 7 picks the unsigned governed row as the primary and
 * relabels it CHAIN_VERIFIED with a receipt naming it; the ADVANCED answer and
 * the vault.reconciled event name it; the export flips REFUSED ->
 * AUTHORIZED/SETTLED; an unknown proposal / claim schema is never read, so
 * Verify advances and writes.
 * HOLDS on dc7552e (and must keep holding): the hosted 409 legs; the
 * consumed-governed, signed-governed and ungoverned primaries' completion.
 *
 * Population: the EXISTING RC42 ladder writer (sdk/testutil/rc45-f8-rc42.js,
 * a84e2a9 modules only, unchanged), run ONCE per store backend; every test
 * works on its own copy (JSON: a copy of the data root; PostgreSQL: CREATE
 * DATABASE ... TEMPLATE plus a copy of the data root). Cases used:
 * TWIN_PU_DEF_CREATOR_BUILT (governed ownerUnpause, BUILT, proposal
 * CANCELLED, no marker, alone on its PAUSED vault), the main vault's control
 * (governed ownerUnpause BUILT whose proposal it consumed) and defect rows,
 * and DEF_PREFLIGHT_VERIFIED (a governance-refused row RC42 advanced to a
 * signed state). The owner (TEST key 0x01) signs the unsigned transaction
 * outside PolicyVault; it lands on the explicit chain model of
 * sdk/testutil/rc45-f5-kit.js and deepens to D. Candidate-written additions:
 * an ordinary ownerTopUp finalized with the owner's TEST key (real compiler,
 * pv_call_encoder, deterministic dev signer, pinned pv_vm_preflight) as a
 * signed loser on L, and an ungoverned agentSpend built through the
 * self-hosted v0.4 build route (intent-manifest record, no proposal) on an
 * F5 TEST vault. SYNTHETIC: an unknown-schema proposal record and terminal
 * claims written over the RC42 records for the 422 legs.
 *
 * Layers: SDK + API (server/src/api.js handle, self-hosted for the export
 * reads, hosted with TEST-key wallet sessions for the route legs; the
 * route-level Verify / submit wrap the module-cache exports of the REAL
 * reconcileVaultV4 / submitWalletRequestV4 to pass the model's rpc, plan r2 §8
 * rules CR-M14, CR2-L12). Nothing dials a node: every config names
 * ws://127.0.0.1:1. Both stores: JSON always; PostgreSQL with
 * POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} (the rc45 runner's pg mode; a
 * skipped PostgreSQL leg there is a FAIL). POLICYVAULT_TEST_RC42_TREE must name
 * the a84e2a9 extraction (a missing tree is a FAIL in before(), never a skip).
 * TEST keys only.
 */
const path = require("node:path"), fs = require("node:fs");
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const K = require("../testutil/rc45-f5-kit");
const F3 = require("../testutil/rc45-f3-kit");
const R42 = require("../testutil/rc45-f8-rc42");
const { KAS, LOOPBACK, SETTLE_DEPTH_DAA, frozenOf } = K;

const SDK_SRC = path.join(__dirname, "..", "src");
const cand = K.modulesOf(SDK_SRC);
const { Categories } = cand.store;
const recovery4 = require(path.join(SDK_SRC, "wallet-recovery-v4.js"));
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();
const RC42_TREE = process.env.POLICYVAULT_TEST_RC42_TREE || "";
const PG = K.pgFromEnv();
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const GOVERNED_VIA = "governance-refused-request-txid";
const REFUSED_TERMINAL_LADDER = Object.freeze({ decision: "REFUSED", refusalCode: "GOVERNANCE_PROPOSAL_TERMINAL", failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "REFUSED", disposition: "REFUSED", reached: [] });
const FULL_LADDER = Object.freeze(["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"]);
const SNAP_CATEGORIES = [Categories.VAULT, Categories.REQUEST, Categories.TRANSITION_CLAIM, Categories.SUBMISSION_CLAIM, Categories.RECEIPT,
  Categories.INTENT_MANIFEST, Categories.GOVERNANCE_PROPOSAL, Categories.GOVERNANCE_APPROVAL];

const roots = [], stores = [], databases = [];
const mk = (prefix) => { const dir = K.ownedTempRoot(prefix); roots.push(dir); return dir; };
let admin = null, overlay = null, serial = 0;
const bases = {};

before(() => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  R42.verifyRc42Tree(RC42_TREE);
  overlay = R42.rc42Overlay(RC42_TREE, mk("pv-rc45-r103-rc42-overlay-"));
  if (PG_AVAILABLE) admin = new (require("pg").Pool)(PG);
});
after(async () => {
  for (const s of stores) { try { await s.close(); } catch { /* closed */ } }
  if (admin) { for (const db of [...databases].reverse()) await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); }
  for (const root of roots) K.removeOwnedRoot(root);
});

/* The RC42 writer's population, written ONCE per backend (lazily), then copied per test. */
function baseFor(backend) {
  if (!bases[backend]) {
    bases[backend] = (async () => {
      const dataRoot = mk("pv-rc45-r103-base-");
      let pg = null;
      if (backend === "PostgreSQL") {
        const database = `pv_rc45_r103_base_${process.pid}`;
        await admin.query(`CREATE DATABASE ${database}`); databases.push(database);
        pg = { host: PG.host, port: PG.port, user: PG.user, database };
      }
      const result = R42.runRc42LadderWriter({ overlay, backend: pg ? "postgres" : "json", dataRoot, pg });
      return { dataRoot, database: pg ? pg.database : null, result };
    })();
  }
  return bases[backend];
}
async function cloneDatabase(from, to) {
  for (let attempt = 0; ; attempt++) {
    try { await admin.query(`CREATE DATABASE ${to} TEMPLATE ${from}`); return; } catch (error) {
      if (attempt >= 40 || !/being accessed by other users/.test(String(error && error.message))) throw error;
      await K.sleep(250);
    }
  }
}
/* The RC42 writer's owner (makeKit KEY(1)): TEST key 0x01. */
function rc42Owner(config) {
  const kaspa = require(config.rustyKaspaModule);
  const secretHex = "01".repeat(32), priv = new kaspa.PrivateKey(secretHex);
  return { secretHex, xonly: priv.toPublicKey().toXOnlyPublicKey().toString().toLowerCase(), address: priv.toPublicKey().toAddress(config.networkId).toString() };
}

/* A fresh copy of the RC42 population: self-hosted (export reads, SDK legs) or hosted (authMode enabled, owner signed in). */
async function fresh(backend, { hosted = false } = {}) {
  const base = await baseFor(backend);
  const dataRoot = mk("pv-rc45-r103-case-");
  fs.cpSync(base.dataRoot, dataRoot, { recursive: true });
  const mode = hosted ? { authMode: "enabled", authCookieInsecure: true } : {};
  let config, pgDatabase = null, pgStore = null;
  if (backend === "PostgreSQL") {
    pgDatabase = `pv_rc45_r103_${process.pid}_${++serial}`;
    await cloneDatabase(base.database, pgDatabase); databases.push(pgDatabase);
    config = cand.config.loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase, pgNoTls: true, ...(hosted ? {} : { hostedDevOpen: true }), dataRoot, rpcUrl: LOOPBACK, ...mode });
    pgStore = await cand.store.openPgStore(config); stores.push(pgStore);
    assert.equal(cand.store.getStore(config).kind, "postgres");
  } else config = cand.config.loadConfig({ dataRoot, rpcUrl: LOOPBACK, ...mode });
  assert.equal(config.networkId, "testnet-10");
  assert.equal(config.tenancyEnforced, hosted);
  const store = cand.store.getStore(config), api = F3.apiFor(config), owner = rc42Owner(config);
  const x = {
    config, store, api, owner, pgStore, result: base.result, model: K.chainModel(config),
    req: (requestId) => cand.wr4.loadRequest(config, requestId),
    raw: (requestId) => store.read(Categories.REQUEST, requestId),
    rawManifest: (vaultId) => store.read(Categories.VAULT, vaultId),
    receipt: (txId) => store.read(Categories.RECEIPT, txId),
    receiptsNaming: async (requestId) => (await store.listValues(Categories.RECEIPT)).filter((r) => r && r.proof && r.proof.requestId === requestId),
    claimOn: (outpoint) => store.read(Categories.TRANSITION_CLAIM, cand.claims.transitionClaimKey(outpoint)),
    audit: async (vaultId) => (await store.readAudit({ limit: 5000 })).filter((a) => a.vaultId === vaultId),
    events: async (type) => (await require("../../server/src/events-store").getEventsStore(config).listEventsAfter({ cursor: "0", limit: 500 })).map((r) => r.event).filter((e) => type === null || e.type === type),
    verify: (vaultId) => cand.reconcile4.reconcileVaultV4(config, vaultId, { rpc: x.model.rpc }),
    sign: (request, signer = owner) => cand.signer.makeDevSigner(config, { secretHex: signer.secretHex, expectedAddress: signer.address }).signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs)
  };
  /* Every durable category the pass, the routes or the governance gate could write, the audit and the platform events. */
  x.snap = async () => {
    const records = {};
    // A record the store refuses to read (the SYNTHETIC misbound terminal claim) is kept as its refusal code; its key stays listed.
    const readOrRefusal = async (c, k) => { try { return await store.read(c, k); } catch (e) { return { unreadable: e && e.code ? e.code : String(e) }; } };
    for (const c of SNAP_CATEGORIES) records[c] = await Promise.all((await store.listKeys(c)).sort().map(async (k) => [k, await readOrRefusal(c, k)]));
    return { records, audit: await store.readAudit({ limit: 5000 }), events: (await x.events(null)).map((e) => JSON.stringify(e)) };
  };
  /* POST /vaults/:id/reconcile through the REAL reconcilers wrapped with the explicit chain model's rpc. */
  x.verifyRoute = async (vaultId, cookie) => {
    const m4 = require(path.join(SDK_SRC, "reconcile-v4.js")), real4 = m4.reconcileVaultV4;
    m4.reconcileVaultV4 = (c, vid, options = {}) => real4(c, vid, { ...options, rpc: x.model.rpc });
    try { return await api.call("POST", ["vaults", vaultId, "reconcile"], {}, cookie); } finally { m4.reconcileVaultV4 = real4; }
  };
  if (hosted) x.cookie = { owner: await api.signIn(owner) };
  return x;
}
async function release(x) {
  if (!x.pgStore) return;
  const i = stores.indexOf(x.pgStore);
  if (i >= 0) { stores.splice(i, 1); await x.pgStore.close(); }
}

/* The attestation ladder, exactly as sdk/test/governance-attestation-ladder.test.js reads it. */
function ladderOf(attestation) {
  const o = attestation.outcome;
  return { decision: attestation.authorization.decision, refusalCode: attestation.authorization.refusalCode, failureCode: o.failureCode, txId: o.txId,
    outputs: o.chain.outputs.length, successorOutpoint: o.chain.successorOutpoint, state: o.state, disposition: o.disposition, reached: o.reached.map((r) => r.state) };
}
const ndjsonRecords = (raw) => String(raw).split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
/* Every export path: the store path, GET /attestations/requests/:id (json, ndjson), GET /attestations/export?vaultId (json, ndjson). */
async function exportsOf(x, request, vaultId, cookie = null) {
  const { buildAttestationForRequest } = require("../../server/src/attestations");
  const out = { store: ladderOf((await buildAttestationForRequest(x.config, request)).attestation) };
  const one = await x.api.call("GET", ["attestations", "requests", request.requestId], null, cookie);
  assert.equal(one.status, 200, `request route (${one.code} ${one.message})`);
  out.route = ladderOf(one.body.attestation);
  const { handle } = require("../../server/src/api");
  const rawOne = await handle(x.config, "GET", ["attestations", "requests", request.requestId], { format: "ndjson" }, null, cookie ? { headers: { cookie } } : {});
  const ndOne = ndjsonRecords(rawOne.rawBody);
  assert.equal(ndOne.length, 1);
  out.routeNdjson = ladderOf(ndOne[0]);
  const batch = await x.api.call("GET", ["attestations", "export"], null, cookie, { vaultId });
  assert.equal(batch.status, 200, `vault export (${batch.code} ${batch.message})`);
  const rec = batch.body.records.find((r) => r.attestation.subject.requestId === request.requestId);
  assert.ok(rec, "the vault export lists the request");
  out.export = ladderOf(rec.attestation);
  const rawBatch = await handle(x.config, "GET", ["attestations", "export"], { vaultId, format: "ndjson" }, null, cookie ? { headers: { cookie } } : {});
  const ndRec = ndjsonRecords(rawBatch.rawBody).find((a) => a.subject.requestId === request.requestId);
  assert.ok(ndRec, "the ndjson vault export lists the request");
  out.exportNdjson = ladderOf(ndRec);
  return out;
}
function assertEveryPath(paths, expected, label) {
  for (const [name, ladder] of Object.entries(paths)) assert.deepEqual(ladder, expected, `${label}: ${name}`);
}
const covenantIndex = (request) => frozenOf(request).outputs.findIndex((o) => o.covenant !== null && o.covenant !== undefined);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
async function gateOf(config, request) {
  const ir = require("../../server/src/intent-records");
  try { await ir.assertRequestManifestVerified(config, request); return "admits"; } catch (e) { return `${e.status} ${e.code}`; }
}

/* The governed unsigned primary (TWIN_PU_DEF_CREATOR_BUILT) and its preconditions, as both probes read them. */
async function governedRow(x) {
  const c = x.result.cases.TWIN_PU_DEF_CREATOR_BUILT;
  assert.ok(c, "the RC42 writer wrote TWIN_PU_DEF_CREATOR_BUILT");
  const row = await x.req(c.requestId);
  assert.equal(row.state, "BUILT"); assert.equal(row.finalTransaction, undefined, "never signed through PolicyVault");
  assert.equal(row.governanceConsumption, undefined, "RC42 row shape (no refusal marker)");
  assert.equal(typeof row.manifestHash, "string");
  const ir = require("../../server/src/intent-records");
  const record = await ir.loadManifestRecord(x.config, row.manifestHash);
  assert.equal(record.requestId, row.requestId, "the row CREATED its manifest record");
  assert.equal(record.proposalId, c.proposalId, "the record names the row's CANCELLED proposal");
  assert.equal((await ir.governanceRefusalFor(x.config, row, record))?.code, "GOVERNANCE_PROPOSAL_TERMINAL", "the candidate's governance truth refuses the row");
  assert.equal(await x.receipt(row.txId), null);
  const m0 = await x.rawManifest(c.vaultId);
  assert.equal(m0.status, "PAUSED"); assert.deepEqual(m0.live.outpoint, row.predecessorOutpoint);
  return { c, row, index: covenantIndex(row), record };
}
/* The manifest advanced by the governed row's txid exactly as a completion advances it (lastTransition: action, txid, outpoints). */
function assertAdvancedBy(m, row, index) {
  assert.equal(m.status, "ACTIVE", "the governed ownerUnpause unpaused the vault");
  assert.deepEqual(m.live.outpoint, { transactionId: row.txId, index });
  assert.equal(m.live.stateId, row.successorStateId);
  assert.equal(m.latestTransitionTxId, row.txId);
  assert.deepEqual({ action: m.lastTransition.action, txId: m.lastTransition.txId, oldStateId: m.lastTransition.oldStateId, newStateId: m.lastTransition.newStateId,
    oldOutpoint: { transactionId: m.lastTransition.oldOutpoint.transactionId, index: Number(m.lastTransition.oldOutpoint.index) }, newOutpoint: m.lastTransition.newOutpoint },
  { action: row.action, txId: row.txId, oldStateId: row.predecessorStateId, newStateId: row.successorStateId,
    oldOutpoint: { transactionId: row.predecessorOutpoint.transactionId, index: Number(row.predecessorOutpoint.index) }, newOutpoint: { transactionId: row.txId, index } });
}
/* The governed path's audit: exactly one reconciled_advanced row for the txid, via governance-refused-request-txid; no completion row. */
async function assertGovernedAudit(x, vaultId, row) {
  const rows = (await x.audit(vaultId)).filter((a) => a.txId === row.txId && a.action === "reconciled_advanced");
  assert.deepEqual(rows.map((a) => a.via), [GOVERNED_VIA], `one reconciled_advanced row {via: "${GOVERNED_VIA}"} for the txid (got ${JSON.stringify(rows.map((a) => a.via))})`);
  assert.equal((await x.audit(vaultId)).some((a) => a.txId === row.txId && a.via === "reconcile"), false, "no completion row (via reconcile) for the governed txid");
}
/* The governed row untouched: byte-identical, no receipt at its txid, no receipt naming it. */
async function assertUntouched(x, row, rawBefore) {
  assert.deepEqual(await x.raw(row.requestId), rawBefore, "the governance-refused unsigned primary is NOT relabelled (its record is byte-identical)");
  assert.equal(await x.receipt(row.txId), null, "no receipt is written for the governed row's txid");
  assert.deepEqual(await x.receiptsNaming(row.requestId), [], "no receipt names the governed row");
}
/* An ordinary owner ownerTopUp on the RC42 vault, built and finalized by the candidate with the owner's TEST key: a signed PENDING loser on L. */
async function signedLoser(x, vaultId) {
  const fuel = { outpoint: { transactionId: "d1".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${x.owner.xonly}ac` };
  const built = await cand.wr4.buildWalletRequestV4({ config: x.config, vaultId, action: "ownerTopUp", params: { topUpAmountSompi: KAS.toString(), fuel }, signerAddress: x.owner.address });
  assert.equal(built.state, "BUILT");
  const done = await cand.wr4.finalizeWalletRequestV4({ config: x.config, requestId: built.requestId, signedSafeJson: x.sign(built) });
  assert.equal(done.state, "PREFLIGHT_VERIFIED", "the owner's ordinary top-up finalizes (real TEST-key signature, pinned pv_vm_preflight)");
  assert.equal((await x.claimOn(done.predecessorOutpoint))?.txId, done.txId, "the top-up holds the claim on L");
  return done;
}

const PG_SKIP = PG_AVAILABLE ? undefined : "REQUIREMENT_NOT_AVAILABLE in this process: isolated PostgreSQL (the rc45 runner's pg mode runs these legs; a skipped PostgreSQL leg there is a FAIL)";
for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", PG_SKIP]]) {
  const r103 = (name, opts, fn) => test(`RC45 R1-03 ${backend}: ${name}`, { skip }, async () => { const x = await fresh(backend, opts); try { await fn(x); } finally { await release(x); } });

  /* ---------------- RED: the governed unsigned primary ---------------- */
  r103("SDK-direct Verify: the governance-refused, never-signed RC42 row (TWIN_PU_DEF_CREATOR_BUILT, proposal CANCELLED) is the step-7 primary; below D CLAIM_PENDING with nothing written; at D the manifest advances by its txid (lastTransition action/txid/outpoints) but the row is NOT relabelled, no receipt names it, the audit row is reconciled_advanced via governance-refused-request-txid, the ADVANCED answer omits requestId, the export stays REFUSED_TERMINAL_LADDER on every export path and the gate still refuses it; a second Verify writes nothing [RED on dc7552e]", {}, async (x) => {
    const { c, row, index } = await governedRow(x);
    assert.deepEqual((await cand.wr4.listVaultRequests(x.config, c.vaultId)).map((r) => r.requestId), [row.requestId], "the BUILT governed row is the only request on its vault");
    assertEveryPath(await exportsOf(x, row, c.vaultId), REFUSED_TERMINAL_LADDER, "before Verify");
    const rawBefore = await x.raw(row.requestId);
    // The owner signs the BUILT row's unsigned transaction outside PolicyVault; it lands and deepens.
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA - 1n);
    const below = await x.snap();
    const pending = await x.verify(c.vaultId);
    assert.equal(pending.status, "CLAIM_PENDING", `below D (got ${JSON.stringify(pending).slice(0, 300)})`);
    assert.deepEqual(await x.snap(), below, "below D nothing is written");
    x.model.advance(1n);
    const out = await x.verify(c.vaultId);
    assert.equal(out.status, "ADVANCED", `at D Verify advances the vault by the observed txid (got ${JSON.stringify(out).slice(0, 300)})`);
    await assertUntouched(x, row, rawBefore);
    assert.equal(hasOwn(out, "requestId"), false, `the governed ADVANCED answer omits requestId (RC1-09; got ${JSON.stringify(out).slice(0, 300)})`);
    assert.equal(out.to, "ownerUnpause"); assert.equal(out.txId, row.txId); assert.equal(out.stateId, row.successorStateId);
    assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
    await assertGovernedAudit(x, c.vaultId, row);
    const after = await x.req(row.requestId);
    assertEveryPath(await exportsOf(x, after, c.vaultId), REFUSED_TERMINAL_LADDER, "after Verify at D");
    assert.equal(await gateOf(x.config, after), "409 GOVERNANCE_PROPOSAL_TERMINAL", "the candidate's gate still refuses the row");
    // A second Verify (L is the recorded successor; settleOneHop sees the governed row as W1) writes nothing.
    const settledSnap = await x.snap();
    const again = await x.verify(c.vaultId);
    assert.equal(again.status, "CONSISTENT", `a second Verify (got ${JSON.stringify(again).slice(0, 300)})`);
    assert.deepEqual(await x.snap(), settledSnap, "the second Verify writes nothing; the governed row stays unlabelled");
  });

  r103("SDK-direct Verify with a signed loser on L: the owner's ordinary top-up (PREFLIGHT_VERIFIED, claim on L) is superseded STALE by the governed row's txid as today (settled[], transition_superseded, claims released) while the governance-refused primary is NOT relabelled, gets no receipt, and the ADVANCED answer omits requestId [RED on dc7552e]", {}, async (x) => {
    const { c, row, index } = await governedRow(x);
    const loser = await signedLoser(x, c.vaultId);
    const rawBefore = await x.raw(row.requestId);
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await x.verify(c.vaultId);
    assert.equal(out.status, "ADVANCED", `got ${JSON.stringify(out).slice(0, 300)}`);
    await assertUntouched(x, row, rawBefore);
    assert.equal(hasOwn(out, "requestId"), false, "the governed ADVANCED answer omits requestId (RC1-09)");
    assert.equal(out.txId, row.txId);
    assert.deepEqual(out.settled, [{ requestId: loser.requestId, action: "ownerTopUp", state: "STALE", txId: loser.txId }], "the loser is settled as today");
    assert.equal((await x.req(loser.requestId)).state, "STALE");
    assert.equal(await x.claimOn(loser.predecessorOutpoint), null, "the loser's claim on L is released");
    assert.equal(await x.store.read(Categories.SUBMISSION_CLAIM, loser.txId), null, "the loser's submission claim is released");
    assert.ok((await x.audit(c.vaultId)).some((a) => a.action === "transition_superseded" && a.requestId === loser.requestId && a.winnerTxId === row.txId), "transition_superseded names the governed txid as the winner");
    assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
    await assertGovernedAudit(x, c.vaultId, row);
    assertEveryPath(await exportsOf(x, await x.req(row.requestId), c.vaultId), REFUSED_TERMINAL_LADDER, "after Verify at D");
  });

  r103("request-scoped recovery (settleJournalFree, RC1-08: the predicate is evaluated inside the pass for every caller): recovering the signed loser runs the pass, which supersedes it STALE by the governed txid while the governance-refused primary is NOT relabelled and gets no receipt [RED on dc7552e]", {}, async (x) => {
    const { c, row, index } = await governedRow(x);
    const loser = await signedLoser(x, c.vaultId);
    const rawBefore = await x.raw(row.requestId);
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await recovery4.reconcileTransitionWalletRequestV4({ config: x.config, requestId: loser.requestId, rpc: x.model.rpc });
    assert.equal(out.outcome, "STALE", `the loser is settled by the pass (got ${JSON.stringify({ outcome: out.outcome, detail: out.detail })})`);
    await assertUntouched(x, row, rawBefore);
    assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
    await assertGovernedAudit(x, c.vaultId, row);
    assertEveryPath(await exportsOf(x, await x.req(row.requestId), c.vaultId), REFUSED_TERMINAL_LADDER, "after request-scoped recovery");
  });

  r103("hosted Verify route (the owner's wallet session): POST /vaults/:id/reconcile at D answers 200 ADVANCED without requestId, so the vault.reconciled event correlates only the txid, never the governed request; the row is NOT relabelled and gets no receipt [RED on dc7552e]", { hosted: true }, async (x) => {
    const { c, row, index } = await governedRow(x);
    const rawBefore = await x.raw(row.requestId);
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const r = await x.verifyRoute(c.vaultId, x.cookie.owner);
    assert.equal(r.status, 200, `the route answers (${r.status} ${r.code} ${r.message})`);
    assert.equal(r.body.reconcile.status, "ADVANCED");
    assert.equal(hasOwn(r.body.reconcile, "requestId"), false, `the governed ADVANCED answer omits requestId (RC1-09; got ${JSON.stringify(r.body.reconcile).slice(0, 300)})`);
    const events = (await x.events("vault.reconciled")).filter((e) => e.vaultId === c.vaultId);
    assert.equal(events.length, 1, "one vault.reconciled event");
    assert.equal(events[0].correlation?.txId, row.txId);
    assert.equal(events[0].correlation?.requestId ?? null, null, "the event does not correlate the governance-refused request");
    await assertUntouched(x, row, rawBefore);
    assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
    assert.equal(r.body.vault.status, "ACTIVE");
    await assertGovernedAudit(x, c.vaultId, row);
  });

  r103("unknown proposal record schema: with the governed row's txid at D, Verify fails closed 422 with nothing written — the SDK-direct pass rejects and POST /vaults/:id/reconcile answers 422 (GOVERNANCE_SCHEMA_UNKNOWN or RECONCILE_FAILED); no event [RED on dc7552e]", { hosted: true }, async (x) => {
    const { c, row } = await governedRow(x);
    const proposal = await x.store.read(Categories.GOVERNANCE_PROPOSAL, c.proposalId);
    assert.equal(proposal.schema, "policyvault-governance-proposal-record/v1");
    await x.store.write(Categories.GOVERNANCE_PROPOSAL, c.proposalId, { ...proposal, schema: "policyvault-governance-proposal-record/v999" }); // SYNTHETIC
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const before = await x.snap();
    await assert.rejects(x.verify(c.vaultId), (e) => e && e.code !== "ERR_ASSERTION", "the SDK-direct pass refuses an unknown proposal schema");
    assert.deepEqual(await x.snap(), before, "nothing is written (SDK-direct)");
    const r = await x.verifyRoute(c.vaultId, x.cookie.owner);
    assert.equal(r.status, 422, `the route answers 422 (got ${r.status} ${r.code} ${r.message})`);
    assert.ok(["GOVERNANCE_SCHEMA_UNKNOWN", "RECONCILE_FAILED"].includes(r.code), `the 422 code (got ${r.code})`);
    assert.deepEqual(await x.snap(), before, "nothing is written (route), no event");
  });

  r103("unknown terminal claim: with the governed row's txid at D and a terminal claim for its proposal of an unknown schema (a future typed policyvault-governance-terminal-claim/v2, which the store refuses as misbound) or of the v1 schema with an unknown status (the governance loader's own 422 GOVERNANCE_SCHEMA_UNKNOWN), Verify fails closed 422 with nothing written each time (SDK-direct rejects; the route answers 422); no event [RED on dc7552e]", { hosted: true }, async (x) => {
    const { c, row } = await governedRow(x);
    const governance = require("../../server/src/governance");
    const key = `xterm-${c.proposalId}`;
    assert.equal(await x.store.read(Categories.GOVERNANCE_PROPOSAL, key), null, "RC42 writes no terminal claim");
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const claims = [
      ["unknown schema", { schema: "policyvault-governance-terminal-claim/v2", proposalId: c.proposalId, status: "CANCELLED", claimedAt: new Date(0).toISOString(), claimedAtMs: 0 }],
      ["v1 schema, unknown status", { schema: governance.TERMINAL_CLAIM_SCHEMA, proposalId: c.proposalId, status: "SUPERSEDED", claimedAt: new Date(0).toISOString(), claimedAtMs: 0 }]
    ];
    for (const [label, claim] of claims) {
      await x.store.write(Categories.GOVERNANCE_PROPOSAL, key, claim); // SYNTHETIC
      await assert.rejects(governance.loadProposalRecord(x.config, c.proposalId), (e) => e && e.code !== "ERR_ASSERTION", `${label}: the governance loader fails closed on the claim`);
      const before = await x.snap();
      await assert.rejects(x.verify(c.vaultId), (e) => e && e.code !== "ERR_ASSERTION", `${label}: the SDK-direct pass refuses the unknown terminal claim`);
      assert.deepEqual(await x.snap(), before, `${label}: nothing is written (SDK-direct)`);
      const r = await x.verifyRoute(c.vaultId, x.cookie.owner);
      assert.equal(r.status, 422, `${label}: the route answers 422 (got ${r.status} ${r.code} ${r.message})`);
      assert.ok(["GOVERNANCE_SCHEMA_UNKNOWN", "RECONCILE_FAILED"].includes(r.code), `${label}: the 422 code (got ${r.code})`);
      assert.deepEqual(await x.snap(), before, `${label}: nothing is written (route), no event`);
    }
  });

  /* ---------------- HOLDS ---------------- */
  r103("hosted finalize and submit of the governed row (K6): the owner's POST /wallet/v4/requests/:id/signature with the owner's real TEST-key signature and POST .../submit answer 409 GOVERNANCE_PROPOSAL_TERMINAL from assertManifestGate with nothing written and nothing broadcast, both before Verify and after Verify at D", { hosted: true }, async (x) => {
    const { c, row } = await governedRow(x);
    const signed = x.sign(row);
    const attempt = async (label) => {
      const before = await x.snap();
      const fin = await x.api.signature(x.cookie.owner, row.requestId, signed);
      assert.equal(`${fin.status} ${fin.code}`, "409 GOVERNANCE_PROPOSAL_TERMINAL", `${label}: hosted finalize (${fin.message})`);
      assert.deepEqual(await x.snap(), before, `${label}: the hosted finalize writes nothing`);
      const sub = await F3.submitThroughModel(() => x.model, () => x.api.submit(x.cookie.owner, row.requestId));
      assert.equal(`${sub.status} ${sub.code}`, "409 GOVERNANCE_PROPOSAL_TERMINAL", `${label}: hosted submit (${sub.message})`);
      assert.deepEqual(await x.snap(), before, `${label}: the hosted submit writes nothing`);
      assert.deepEqual(x.model.broadcasts, [], `${label}: nothing is broadcast`);
    };
    await attempt("before Verify");
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await x.verify(c.vaultId);
    assert.equal(out.status, "ADVANCED");
    await attempt("after Verify at D");
  });

  r103("a governed unsigned primary whose proposal it CONSUMED (the RC42 control row on the main vault, governanceRefusalFor null) completes exactly as at dc7552e: ADVANCED naming it, CHAIN_VERIFIED, a receipt naming it, reconciled_advanced via reconcile, the full SETTLED ladder; the refused BUILT defect row on the same outpoint stays byte-identical and REFUSED_TERMINAL_LADDER", {}, async (x) => {
    const ir = require("../../server/src/intent-records");
    const vaultId = "39".repeat(32), ctrlId = x.result.control.requestId, defId = x.result.defect.requestIds[0];
    assert.equal(x.result.control.status, 201); assert.equal(x.result.defect.requestIds.length, 1);
    const ctrl = await x.req(ctrlId), def = await x.req(defId);
    assert.equal(ctrl.state, "BUILT"); assert.equal(ctrl.finalTransaction, undefined); assert.equal(ctrl.vaultId, vaultId);
    assert.equal(await ir.governanceRefusalFor(x.config, ctrl, await ir.loadManifestRecord(x.config, ctrl.manifestHash)), null, "the control consumed its proposal");
    assert.equal(def.state, "BUILT"); assert.deepEqual(def.predecessorOutpoint, ctrl.predecessorOutpoint);
    const defRaw = await x.raw(defId), index = covenantIndex(ctrl);
    x.model.confirm(frozenOf(ctrl), ctrl.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await x.verify(vaultId);
    assert.equal(out.status, "ADVANCED", `got ${JSON.stringify(out).slice(0, 300)}`);
    assert.equal(out.requestId, ctrlId); assert.equal(out.txId, ctrl.txId); assert.equal(out.to, "ownerUnpause");
    assert.equal((await x.req(ctrlId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.receipt(ctrl.txId))?.proof?.requestId, ctrlId, "the receipt names the completed primary");
    assert.ok((await x.audit(vaultId)).some((a) => a.action === "reconciled_advanced" && a.via === "reconcile" && a.txId === ctrl.txId));
    assertAdvancedBy(await x.rawManifest(vaultId), ctrl, index);
    const ctrlLadder = await exportsOf(x, await x.req(ctrlId), vaultId);
    for (const [name, l] of Object.entries(ctrlLadder)) {
      assert.equal(l.decision, "AUTHORIZED", name); assert.equal(l.disposition, "SETTLED", name); assert.deepEqual(l.reached, FULL_LADDER, name); assert.equal(l.txId, ctrl.txId, name);
    }
    assert.deepEqual(await x.raw(defId), defRaw, "the refused BUILT defect row on the same outpoint is byte-identical");
    assertEveryPath(await exportsOf(x, await x.req(defId), vaultId), REFUSED_TERMINAL_LADDER, "the refused defect row");
  });

  r103("a governance-refused primary in a SIGNED state (RC42 DEF_PREFLIGHT_VERIFIED: RC42's gate admitted it) completes exactly as at dc7552e: ADVANCED naming it, CHAIN_VERIFIED, a receipt naming it, reconciled_advanced via reconcile, and the export keeps the broadcast-evidence rule (AUTHORIZED, SETTLED)", {}, async (x) => {
    const c = x.result.cases.DEF_PREFLIGHT_VERIFIED;
    assert.ok(c, "the RC42 writer wrote DEF_PREFLIGHT_VERIFIED");
    const row = await x.req(c.requestId), ir = require("../../server/src/intent-records");
    assert.equal(row.state, "PREFLIGHT_VERIFIED");
    assert.equal((await ir.governanceRefusalFor(x.config, row, await ir.loadManifestRecord(x.config, row.manifestHash)))?.code, "GOVERNANCE_PROPOSAL_TERMINAL");
    const index = covenantIndex(row);
    x.model.confirm(frozenOf(row), row.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await x.verify(c.vaultId);
    assert.equal(out.status, "ADVANCED", `got ${JSON.stringify(out).slice(0, 300)}`);
    assert.equal(out.requestId, row.requestId); assert.equal(out.txId, row.txId);
    assert.equal((await x.req(row.requestId)).state, "CHAIN_VERIFIED");
    assert.equal((await x.receipt(row.txId))?.proof?.requestId, row.requestId);
    assert.ok((await x.audit(c.vaultId)).some((a) => a.action === "reconciled_advanced" && a.via === "reconcile" && a.txId === row.txId));
    assert.equal((await x.audit(c.vaultId)).some((a) => a.via === GOVERNED_VIA), false);
    assertAdvancedBy(await x.rawManifest(c.vaultId), row, index);
    for (const [name, l] of Object.entries(await exportsOf(x, await x.req(row.requestId), c.vaultId))) {
      assert.equal(l.decision, "AUTHORIZED", name); assert.equal(l.refusalCode, null, name); assert.equal(l.disposition, "SETTLED", name); assert.deepEqual(l.reached, FULL_LADDER, name);
    }
  });

  r103("an ungoverned BUILT primary (an agent spend built through the self-hosted v0.4 build route on an F5 TEST vault: an intent-manifest record, no proposal) completes exactly as at dc7552e: ADVANCED naming it, CHAIN_VERIFIED, a receipt naming it, reconciled_advanced via reconcile, and the export reaches the SIGNED rung through the chain's acceptance of its build-fixed txid (full SETTLED ladder)", {}, async (x) => {
    const w = K.walletsFor(x.config), v = K.vault("r103-ungoverned"), k = K.kitFor(cand, x.config, w);
    await K.seedVault(cand, x.config, v, w);
    const built = await x.api.call("POST", ["wallet", "v4", "requests"], { vaultId: v.vaultId, action: "agentSpend", params: k.spend(4n * KAS), signerAddress: w.agent.address });
    assert.equal(built.status, 201, `the self-hosted build route (${built.code} ${built.message})`);
    const r = await x.req(built.body.request.requestId), ir = require("../../server/src/intent-records");
    assert.equal(r.state, "BUILT"); assert.equal(typeof r.manifestHash, "string"); assert.equal(r.governanceProposalId, undefined);
    assert.equal(await ir.governanceRefusalFor(x.config, r, await ir.loadManifestRecord(x.config, r.manifestHash)), null, "no proposal binds it");
    const index = covenantIndex(r);
    x.model.confirm(frozenOf(r), r.txId); x.model.advance(SETTLE_DEPTH_DAA);
    const out = await x.verify(v.vaultId);
    assert.equal(out.status, "ADVANCED", `got ${JSON.stringify(out).slice(0, 300)}`);
    assert.equal(out.requestId, r.requestId); assert.equal(out.txId, r.txId);
    const after = await x.req(r.requestId);
    assert.equal(after.state, "CHAIN_VERIFIED"); assert.equal(after.finalTransaction, undefined, "PolicyVault holds no signed bytes for it");
    assert.equal((await x.receipt(r.txId))?.proof?.requestId, r.requestId);
    assert.ok((await x.audit(v.vaultId)).some((a) => a.action === "reconciled_advanced" && a.via === "reconcile" && a.txId === r.txId));
    const m = await x.rawManifest(v.vaultId);
    assert.deepEqual(m.live.outpoint, { transactionId: r.txId, index }); assert.equal(m.lastTransition.txId, r.txId);
    for (const [name, l] of Object.entries(await exportsOf(x, after, v.vaultId))) {
      assert.equal(l.decision, "AUTHORIZED", name); assert.equal(l.disposition, "SETTLED", name); assert.deepEqual(l.reached, FULL_LADDER, name); assert.equal(l.txId, r.txId, name);
    }
  });
}
