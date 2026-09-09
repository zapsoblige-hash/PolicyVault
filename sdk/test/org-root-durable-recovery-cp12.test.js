"use strict";

/*
 * SDK / CRASH-RECOVERY (real builds through the real compiler; mocked chain
 * readback; in-process JSON store with deterministic fault injection and
 * RELOAD between steps): Codex checkpoint 12 (rc26 round-7 review R7-02,
 * "durable completion remains defective — Medium; high confidence").
 *
 * Checkpoint 12 reproduced, on the rc27 runtime `9da991f`:
 *   • the root's pending pointer was cleared and persisted BEFORE the claims,
 *     receipt, audit and final request persistence, so a failure at any of
 *     those boundaries left the request RECONCILIATION_REQUIRED while public
 *     reconciliation reported CONSISTENT (live root, no claim) and submission
 *     refused the retry ("not SIGNED") — unfinished work was unreachable
 *     through the public entry points;
 *   • legacy partial records (root advanced, vault/registry stale, request
 *     BROADCAST or already labelled CHAIN_VERIFIED) were left unchanged;
 *   • a `latestTransitionTxId` marker substituted for state validation (a
 *     stale vault carrying the marker produced a CHAIN_VERIFIED request);
 *   • a same-request vault predecessor claim was never released after the
 *     vault advanced (the key was derived from the NEW outpoint) and release
 *     errors were swallowed.
 *
 * Required now (checkpoint-12 correction directive §3): unfinished work is
 * DISCOVERABLE through `submitOrgRootRequest` and `reconcileOrgRootV7`
 * after a reload at EVERY consequential failure boundary; the incomplete-
 * request guard (the root's pending pointer) is retained until the required
 * steps finish; completion is VALIDATED (not marked); predecessor identities
 * are immutable; claim handling is truthful and retryable; receipt / audit /
 * request participate in recovery; repeated entry never duplicates
 * advancement, never rebroadcasts, never falsely marks completion.
 * RED on 9da991f (see docs/postlaunch/ux-evidence/<runtime>/red/).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fx = require("../testutil/org-root-durable-fixture");
const { reconcileOrgRootV7 } = require("../src/reconcile-v7");
const { claimTransition, loadTransitionClaim } = require("../src/submission-claim");
const { persistManifestV7 } = require("../src/manifest-v7");

const SKIP = !fx.toolchainAvailable() && "REQUIREMENT_NOT_AVAILABLE: silverc / pv_call_encoder / pv_tx_probe";
const { wr7, Categories, getStore } = fx;

/* ONE organization + ONE signed setAgentRoot, built once; every boundary runs on an independent COPY of the data root */
let base = null;
async function baseFixture() {
  if (base) return base;
  const cfg = fx.freshJsonConfig("pv-durable12-base-");
  const rpc = fx.mockRpc();
  const o = await fx.organization(cfg, rpc);
  const fin = await fx.signedSetAgentRoot(cfg, o);
  base = { cfg, o, fin };
  return base;
}
/* a fresh copy + a fresh mocked chain in which the transaction has SETTLED (predecessors spent, successors present) */
async function settledCopy() {
  const b = await baseFixture();
  const cfg = fx.cloneJsonConfig(b.cfg);
  const rpc = fx.mockRpc();
  const pred = await fx.spendPredecessors(cfg, rpc, b.o);
  fx.settle(cfg, rpc, b.fin);
  return { cfg, rpc, o: b.o, fin: b.fin, pred };
}
const newBuildAllowed = async (cfg, o) => wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", params: { fuel: fx.fuelUtxoFor(cfg, o.fuelKey) }, signerAddress: fx.ADDR(cfg, o.owner1) });

/* ------------------------------------------------------------------ *
 * §3 focused recovery controls: every consequential failure boundary of
 * the completion, in the order the completion performs it.
 * ------------------------------------------------------------------ */
const BOUNDARIES = [
  { name: "root record persisted, then the ROOT predecessor claim release fails", method: "remove", pred: (c, fin, pred) => (cat, key) => cat === Categories.TRANSITION_CLAIM && key === fx.transitionClaimKey(pred.rootOutpoint), retryVia: "reconcile" },
  { name: "the same-request VAULT predecessor claim release fails", method: "remove", pred: (c, fin, pred) => (cat, key) => cat === Categories.TRANSITION_CLAIM && key === fx.transitionClaimKey(pred.vaultOutpoint), seedVaultClaim: true, retryVia: "submit" },
  { name: "the submission claim release fails", method: "remove", pred: (c, fin) => (cat, key) => cat === Categories.SUBMISSION_CLAIM && key === fin.txId, retryVia: "reconcile" },
  { name: "the receipt write fails", method: "write", pred: (c, fin) => (cat, key) => cat === Categories.RECEIPT && key === fin.txId, retryVia: "submit" },
  { name: "the audit append fails", method: "appendAudit", pred: (c, fin) => (record) => record.txId === fin.txId && record.result === "CHAIN_VERIFIED", retryVia: "reconcile" },
  { name: "the final request write (CHAIN_VERIFIED) fails", method: "write", pred: (c, fin) => (cat, key, value) => cat === Categories.ORG_ROOT_REQUEST && key === fin.id && value.state === "CHAIN_VERIFIED", retryVia: "submit" },
  { name: "the pending-pointer clear fails AFTER the request is CHAIN_VERIFIED", method: "write", pred: (c, fin, pred, o) => (cat, key, value) => cat === Categories.ORG_ROOT && key === o.rootCovenantId && value.pendingRequestId === null && value.live.outpoint.transactionId === fin.txId, requestStateAfter: "CHAIN_VERIFIED", retryVia: "reconcile" },
  { name: "the root record write fails after the VAULT already advanced (retry must not derive the old claim key from the new outpoint)", method: "write", pred: (c, fin, pred, o) => (cat, key, value) => cat === Categories.ORG_ROOT && key === o.rootCovenantId && value.live.outpoint.transactionId === fin.txId, retryVia: "submit", vaultAdvancedBeforeFailure: true }
];

for (const b of BOUNDARIES) {
  test(`R7-02 checkpoint 12 — boundary: ${b.name} → truthful state after reload, guard held, public retry refused while writes still fail, then completed exactly once by ${b.retryVia}`, { skip: SKIP }, async () => {
    const { cfg, rpc, o, fin, pred } = await settledCopy();
    if (b.seedVaultClaim) await claimTransition(cfg, { outpoint: pred.vaultOutpoint, txId: fin.txId, action: "ownerSetAgentRoot", vaultId: o.vaultId, stateId: null, expected: { kind: "orgRootRequest", requestId: fin.id } });
    const predicate = b.pred(cfg, fin, pred, o);
    const inj = fx.inject(cfg, b.method, predicate);
    await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED", "the inline submit reports the incomplete completion truthfully");
    assert.equal(inj.count(), 1, "the injected failure fired exactly once");
    inj.restore();
    const submitsAfterBroadcast = rpc.submits();
    assert.equal(submitsAfterBroadcast, 1, "exactly one broadcast so far");

    /* truthful durable state, read through a RELOADED store */
    const cfg2 = fx.reloadJsonConfig(cfg);
    const req = await wr7.loadOrgRootRequest(cfg2, fin.id);
    assert.equal(req.state, b.requestStateAfter ?? "RECONCILIATION_REQUIRED", `request state after the failure (${req.error ?? "no error"})`);
    const rootMid = await wr7.loadOrgRoot(cfg2, o.rootCovenantId);
    assert.equal(rootMid.live.outpoint.transactionId, b.vaultAdvancedBeforeFailure ? pred.rootOutpoint.transactionId : fin.txId, "root record position after the failure");
    assert.equal(rootMid.pendingRequestId, fin.id, "the incomplete-request guard (pending pointer) is HELD while the completion is incomplete");
    await assert.rejects(() => newBuildAllowed(cfg2, o), (e) => e.code === "ROOT_PENDING_REQUEST", "a new root action is refused while this one is incomplete");
    const vaultMid = await fx.loadManifestV7(cfg2, o.vaultId);
    assert.ok(rootMid.generation <= 1 && vaultMid.generation <= 1, "no generation advanced twice");

    /* public retry through BOTH entry points WHILE the same write still fails: truthful, no duplicate advancement, no rebroadcast */
    const still = fx.inject(cfg2, b.method, predicate, { times: Infinity });
    await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg2, requestId: fin.id, rpc }), (e) => e.code === "RECONCILIATION_REQUIRED", "submit while the write still fails");
    await assert.rejects(() => reconcileOrgRootV7(cfg2, o.rootCovenantId, { rpc }), (e) => e.code === "RECONCILIATION_REQUIRED", "reconcile while the write still fails");
    assert.ok(still.count() >= 2, "both public entry points reached the failing step (discoverable)");
    still.restore();
    assert.equal(rpc.submits(), submitsAfterBroadcast, "NEVER rebroadcast");
    const reqStill = await wr7.loadOrgRootRequest(fx.reloadJsonConfig(cfg), fin.id);
    assert.equal(reqStill.state, b.requestStateAfter ?? "RECONCILIATION_REQUIRED", "state stays truthful across failed retries");
    assert.equal((await wr7.loadOrgRoot(fx.reloadJsonConfig(cfg), o.rootCovenantId)).pendingRequestId, fin.id, "guard still held");
    assert.ok((await wr7.loadOrgRoot(fx.reloadJsonConfig(cfg), o.rootCovenantId)).generation <= 1 && (await fx.loadManifestV7(fx.reloadJsonConfig(cfg), o.vaultId)).generation <= 1, "still no double advancement");
    /* local (read-only) verification names what is missing — asserted after the behavioural checks so a RED run on the
     * old runtime reaches the behaviour before this new interface */
    const verified = await wr7.verifyRootActionCompletion(fx.reloadJsonConfig(cfg), reqStill);
    assert.equal(verified.complete, false, "local verification reports the incomplete completion");
    assert.ok(verified.missing.length >= 1, `missing: ${verified.missing.join("; ")}`);

    /* the write recovers: ONE public retry (after another reload) completes everything */
    const cfg3 = fx.reloadJsonConfig(cfg);
    if (b.retryVia === "reconcile") {
      const r = await reconcileOrgRootV7(cfg3, o.rootCovenantId, { rpc });
      assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
      assert.ok(Array.isArray(r.root.completion) && r.root.completion.some((c) => c.replayed && c.requestId === fin.id), "the replay is reported with the request it completed");
      assert.deepEqual(r.vaults.map((v) => v.status), ["CONSISTENT"], `the vault side reconciles CONSISTENT: ${JSON.stringify(r.vaults)}`);
    } else {
      const s = await wr7.submitOrgRootRequest({ config: cfg3, requestId: fin.id, rpc });
      assert.equal(s.state, "CHAIN_VERIFIED");
      assert.equal(s.chain.completion.via, "submit-recovery");
    }
    assert.equal(rpc.submits(), submitsAfterBroadcast, "the recovery never rebroadcast");
    const done = await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "after recovery", { predecessors: pred });
    if (b.seedVaultClaim) assert.equal(done.req.chain.completion.claims.vaultPredecessor, done.req.chain.completion.claims.vaultPredecessor, "recorded");
    assert.equal(await loadTransitionClaim(fx.reloadJsonConfig(cfg), pred.vaultOutpoint), null, "no vault predecessor claim remains (released against the IMMUTABLE predecessor key, not the new outpoint)");

    /* repeated entry through the OTHER entry point and again: idempotent — exactly once, no duplicate records */
    const cfg4 = fx.reloadJsonConfig(cfg);
    const again = await reconcileOrgRootV7(cfg4, o.rootCovenantId, { rpc });
    assert.equal(again.root.status, "CONSISTENT", JSON.stringify(again.root));
    assert.equal(again.root.completion, undefined, "nothing left to complete");
    assert.equal((await wr7.submitOrgRootRequest({ config: cfg4, requestId: fin.id, rpc })).state, "CHAIN_VERIFIED");
    await fx.assertFullyCompleted(cfg4, o, fin, "after repeated entry", { predecessors: pred });
    assert.equal(rpc.submits(), submitsAfterBroadcast, "still never rebroadcast");
    const next = await newBuildAllowed(cfg4, o);
    assert.equal(next.state, "AUTHORIZED", "the guard is released only after everything completed: a new root action builds");
  });
}

/* ------------------------------------------------------------------ *
 * foreign claims stay protected; the completion reports them truthfully
 * ------------------------------------------------------------------ */
test("R7-02 checkpoint 12 — a FOREIGN claim on the vault predecessor (another attempt's txid) is never released, is reported as FOREIGN, and does not block completion", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred } = await settledCopy();
  const other = "ab".repeat(32);
  await claimTransition(cfg, { outpoint: pred.vaultOutpoint, txId: other, action: "agentSpend", vaultId: o.vaultId, stateId: null, expected: { kind: "v7Successor", txId: other } });
  const s = await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 });
  assert.equal(s.state, "CHAIN_VERIFIED");
  const held = await loadTransitionClaim(cfg, pred.vaultOutpoint);
  assert.ok(held && held.txId === other, "the foreign claim is still held (control: protected on the old runtime as well)");
  assert.equal(s.chain.completion.claims.vaultPredecessor, `FOREIGN:${other}`, "the foreign claim is REPORTED, not released");
  assert.equal(s.chain.completion.claims.rootPredecessor, "RELEASED");
  assert.equal(s.chain.completion.claims.submission, "RELEASED");
  const v = await wr7.verifyRootActionCompletion(fx.reloadJsonConfig(cfg), await wr7.loadOrgRootRequest(cfg, fin.id));
  assert.equal(v.complete, true, `complete despite the protected foreign claim (${v.missing.join("; ")})`);
  assert.equal(v.claims.vaultPredecessor, `FOREIGN:${other}`);
});

/* ------------------------------------------------------------------ *
 * legacy partial records (the shapes checkpoint 12 found stranded on the
 * WIP / rc27 runtime): discovered and completed by the public entry points
 * ------------------------------------------------------------------ */
async function completedThenRewound(state) {
  const { cfg, rpc, o, fin, pred } = await settledCopy();
  const before = fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId));
  const s = await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 });
  assert.equal(s.state, "CHAIN_VERIFIED", "control: the inline completion succeeds");
  /* rewind to the legacy partial shape: root advanced + pointer cleared (as the WIP left it), vault/registry STALE, the
   * predecessor root claim HELD (the WIP released the wrong key), receipt absent, request labelled `state` */
  await persistManifestV7(cfg, before);
  await getStore(cfg).remove(Categories.RECEIPT, fin.txId);
  await claimTransition(cfg, { outpoint: pred.rootOutpoint, action: fin.action, txId: fin.txId, vaultId: o.rootCovenantId, stateId: null, expected: { kind: "orgRootRequest", requestId: fin.id } });
  const req = await wr7.loadOrgRootRequest(cfg, fin.id);
  req.state = state;
  req.chain = null;
  await wr7.saveOrgRootRequest(cfg, req);
  const root = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  assert.equal(root.live.outpoint.transactionId, fin.txId, "precondition: root advanced");
  assert.equal(root.pendingRequestId, null, "precondition: pointer cleared (legacy)");
  assert.equal((await fx.loadManifestV7(cfg, o.vaultId)).agentRegistry.length, 1, "precondition: registry stale");
  return { cfg: fx.reloadJsonConfig(cfg), rpc, o, fin, pred, before };
}

test("R7-02 checkpoint 12 — LEGACY partial record (root advanced, pointer cleared, vault/registry stale, request BROADCAST): public reconcile discovers it by the live outpoint's transaction and completes it exactly once", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred } = await completedThenRewound("BROADCAST");
  const r = await reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
  const c = r.root.completion.find((x) => x.requestId === fin.id);
  assert.ok(c && c.replayed, "the legacy request was replayed");
  assert.ok(c.missingBefore.some((m) => /vault record/.test(m)) && c.missingBefore.some((m) => /root predecessor claim/.test(m)), `what was missing is recorded: ${c.missingBefore.join("; ")}`);
  await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "legacy BROADCAST completed", { predecessors: pred });
  assert.equal((await reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc })).root.status, "CONSISTENT");
});

test("R7-02 checkpoint 12 — LEGACY record already labelled CHAIN_VERIFIED beside a stale vault: the label is not evidence — submit verifies, finds the vault stale, repairs it exactly once (root generation untouched)", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred } = await completedThenRewound("CHAIN_VERIFIED");
  const s = await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc });
  assert.equal(s.state, "CHAIN_VERIFIED");
  assert.equal((await fx.loadManifestV7(fx.reloadJsonConfig(cfg), o.vaultId)).agentRegistry.length, 2, "the stale vault was REPAIRED by the submit (the label alone was not trusted)");
  assert.equal(s.chain.completion.vault, "ADVANCED");
  assert.equal(s.chain.completion.root, "ALREADY_COMPLETE");
  assert.equal(s.chain.completion.claims.rootPredecessor, "RELEASED");
  await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "legacy CHAIN_VERIFIED repaired", { predecessors: pred });
});

test("R7-02 checkpoint 12 — a matching-but-inconsistent marker (stale vault carrying latestTransitionTxId == txid) is REPAIRED by state validation, never skipped on the marker", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred, before } = await completedThenRewound("BROADCAST");
  await persistManifestV7(cfg, { ...before, latestTransitionTxId: fin.txId });
  const stale = await fx.loadManifestV7(cfg, o.vaultId);
  assert.equal(stale.latestTransitionTxId, fin.txId, "precondition: the marker matches");
  assert.equal(stale.agentRegistry.length, 1, "precondition: the state is stale");
  const r = await reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
  const c = r.root.completion.find((x) => x.requestId === fin.id);
  assert.ok(c.missingBefore.some((m) => /marker without state/.test(m)), `the marker-without-state condition is named: ${c.missingBefore.join("; ")}`);
  await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "marker repaired", { predecessors: pred });
});

test("R7-02 checkpoint 13 — generation-only later vault evidence is refused without overwriting it or releasing its guard", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred } = await settledCopy();
  await wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 });
  const later = "cd".repeat(32);
  const newer = fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId));
  const validVault = structuredClone(newer);
  newer.live.outpoint = { transactionId: later, index: 0 };
  newer.latestTransitionTxId = later;
  newer.generation = 2;
  await persistManifestV7(cfg, newer);
  const installed = fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId));
  await getStore(cfg).remove(Categories.RECEIPT, fin.txId);
  await claimTransition(cfg, { outpoint: pred.rootOutpoint, action: fin.action, txId: fin.txId, vaultId: o.rootCovenantId, stateId: null, expected: { kind: "orgRootRequest", requestId: fin.id } });
  const req = await wr7.loadOrgRootRequest(cfg, fin.id); req.state = "BROADCAST"; await wr7.saveOrgRootRequest(cfg, req);
  const rootBefore = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  await assert.rejects(reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal((await wr7.loadOrgRootRequest(cfg, fin.id)).state, "RECONCILIATION_REQUIRED");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId)), installed);
  assert.ok(await loadTransitionClaim(cfg, pred.rootOutpoint));
  assert.deepEqual(await wr7.loadOrgRoot(cfg, o.rootCovenantId), rootBefore, "failed preflight does not install a historical pointer");
  assert.equal(await fx.loadReceipt(cfg, fin.txId), null);
  const requestCount = (await wr7.listOrgRootRequests(cfg)).length;
  for (const vaultOperations of [[], [{ vaultId: o.vaultId, action: "ownerPause", params: {} }]]) {
    await assert.rejects(wr7.buildRootActionRequest({ config: fx.reloadJsonConfig(cfg), rootCovenantId: o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(cfg, o.owner1), params: { fuel: fx.fuelUtxoFor(cfg, o.fuelKey) }, vaultOperations }), (e) => e.code === "ROOT_PENDING_REQUEST", "unfinished completion stays guarded without pinning the old root request");
  }
  assert.equal((await wr7.listOrgRootRequests(cfg)).length, requestCount);
  assert.deepEqual(await wr7.loadOrgRoot(cfg, o.rootCovenantId), rootBefore);
  await persistManifestV7(cfg, validVault);
  await reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc });
  assert.equal((await wr7.loadOrgRootRequest(cfg, fin.id)).state, "CHAIN_VERIFIED");
  assert.equal(await loadTransitionClaim(cfg, pred.rootOutpoint), null);
  assert.equal((await wr7.buildRootActionRequest({ config: cfg, rootCovenantId: o.rootCovenantId, action: "authorize", signerAddress: fx.ADDR(cfg, o.owner1), params: { fuel: fx.fuelUtxoFor(cfg, o.fuelKey) } })).state, "AUTHORIZED");
});

test("R7-02 checkpoint 12 — an UNEXPLAINED vault record (neither predecessor nor successor, no recorded predecessor generation — a legacy request) FAILS CLOSED: truthful RECONCILIATION_REQUIRED, nothing overwritten, no guessed state", { skip: SKIP }, async () => {
  const { cfg, rpc, o, fin, pred } = await settledCopy();
  /* strip the checkpoint-12 predecessor evidence to the legacy request shape */
  const req0 = await wr7.loadOrgRootRequest(cfg, fin.id);
  delete req0.vaultOperations[0].predecessor;
  await wr7.saveOrgRootRequest(cfg, req0);
  /* the vault is at some third outpoint (unexplained) */
  const doc = fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId));
  doc.live = { ...doc.live, outpoint: { transactionId: "ef".repeat(32), index: 0 } };
  await persistManifestV7(cfg, doc);
  const unexplained = fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId));
  const rootBefore = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED" && /no proven dependency history/.test(e.message));
  const req = await wr7.loadOrgRootRequest(fx.reloadJsonConfig(cfg), fin.id);
  assert.equal(req.state, "RECONCILIATION_REQUIRED");
  assert.ok(req.error.includes(o.vaultId) && /no proven dependency history/.test(req.error), "the error names the vault and its missing history proof");
  assert.deepEqual(fx.manifestToJsonV7(await fx.loadManifestV7(cfg, o.vaultId)), unexplained, "the vault record is untouched");
  const rootAfter = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  assert.equal(rootAfter.live.outpoint.transactionId, rootBefore.live.outpoint.transactionId, "the root is not advanced past an unexplained vault");
  assert.equal(rootAfter.pendingRequestId, fin.id, "guard held");
  await assert.rejects(() => reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc }), (e) => e.code === "RECONCILIATION_REQUIRED", "reconcile fails closed the same way (the live predecessor is gone: proven successor, unexplained vault)");
  assert.equal(rpc.submits(), 1, "no rebroadcast");
});

/* ------------------------------------------------------------------ *
 * root-only actions and terminal recovery: the same replay, on their own
 * record shapes
 * ------------------------------------------------------------------ */
test("R7-02 checkpoint 12 — ROOT-ONLY action on the deferred path: a claim-release failure after the root advanced is discovered by the next public reconcile (pointer) and completed; CONSISTENT afterwards", { skip: SKIP }, async () => {
  const cfg = fx.freshJsonConfig("pv-durable12-rootonly-"); const rpc = fx.mockRpc();
  const o = await fx.organization(cfg, rpc);
  const fin = await fx.signedRootOnly(cfg, o);
  const genesisBroadcasts = rpc.submits(); // the two genesis broadcasts went through this same mock node
  const root0 = await wr7.loadOrgRoot(cfg, o.rootCovenantId);
  const pred = { rootOutpoint: root0.live.outpoint };
  rpc.clear(root0.live.address);
  await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  fx.settle(cfg, rpc, fin);
  const inj = fx.inject(cfg, "remove", (cat, key) => cat === Categories.TRANSITION_CLAIM && key === fx.transitionClaimKey(pred.rootOutpoint));
  await assert.rejects(() => reconcileOrgRootV7(cfg, o.rootCovenantId, { rpc }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(inj.count(), 1); inj.restore();
  const cfg2 = fx.reloadJsonConfig(cfg);
  const mid = await wr7.loadOrgRoot(cfg2, o.rootCovenantId);
  assert.equal(mid.live.outpoint.transactionId, fin.txId, "root advanced before the failing step");
  assert.equal(mid.pendingRequestId, fin.id, "guard held");
  assert.equal((await wr7.loadOrgRootRequest(cfg2, fin.id)).state, "RECONCILIATION_REQUIRED");
  const r = await reconcileOrgRootV7(cfg2, o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "ADVANCED", JSON.stringify(r.root));
  await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "root-only completed", { kind: "rootOnly", predecessors: pred });
  assert.equal((await reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc })).root.status, "CONSISTENT");
  assert.equal(rpc.submits(), genesisBroadcasts + 1, "exactly one broadcast of the action; never rebroadcast");
});

test("R7-02 checkpoint 12 — TERMINAL recovery (ownerRecover on the rooted vault): a failure after the terminal vault record was written is completed exactly once; the recovered vault is validated as the successor, never rewritten", { skip: SKIP }, async () => {
  const cfg = fx.freshJsonConfig("pv-durable12-terminal-"); const rpc = fx.mockRpc();
  const o = await fx.organization(cfg, rpc);
  const fin = await fx.signedTerminalRecover(cfg, o);
  const genesisBroadcasts = rpc.submits();
  assert.equal(fin.build.successorState, null, "precondition: a TERMINAL build");
  const pred = await fx.spendPredecessors(cfg, rpc, o);
  fx.settle(cfg, rpc, fin);
  const inj = fx.inject(cfg, "remove", (cat, key) => cat === Categories.SUBMISSION_CLAIM && key === fin.txId);
  await assert.rejects(() => wr7.submitOrgRootRequest({ config: cfg, requestId: fin.id, rpc, pollAttempts: 1, pollDelayMs: 1 }), (e) => e.code === "RECONCILIATION_REQUIRED");
  assert.equal(inj.count(), 1); inj.restore();
  const cfg2 = fx.reloadJsonConfig(cfg);
  const mid = await fx.loadManifestV7(cfg2, o.vaultId);
  assert.equal(mid.status, "RECOVERED"); assert.equal(mid.live, null); assert.equal(mid.generation, 1);
  assert.equal((await wr7.loadOrgRoot(cfg2, o.rootCovenantId)).pendingRequestId, fin.id, "guard held");
  const s = await wr7.submitOrgRootRequest({ config: cfg2, requestId: fin.id, rpc });
  assert.equal(s.state, "CHAIN_VERIFIED");
  assert.equal(s.chain.completion.vault, "ALREADY_COMPLETE", "the terminal record is validated, not rewritten");
  await fx.assertFullyCompleted(fx.reloadJsonConfig(cfg), o, fin, "terminal completed", { kind: "terminal", predecessors: pred });
  const r = await reconcileOrgRootV7(fx.reloadJsonConfig(cfg), o.rootCovenantId, { rpc });
  assert.equal(r.root.status, "CONSISTENT");
  assert.deepEqual(r.vaults.map((v) => v.status), ["TERMINAL"]);
  assert.equal(rpc.submits(), genesisBroadcasts + 1, "exactly one broadcast of the action; never rebroadcast");
});
