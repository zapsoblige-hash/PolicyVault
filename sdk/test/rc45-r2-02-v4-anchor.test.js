"use strict";
/*
 * RC45 R2-02 — v0.4.1 BUILD ANCHORING of delegate period starts. Internal
 * RED-first regression material for the RC45 candidate; not an audit.
 *
 * THE DEFECT (b89f0f7): every hosted v0.4.1 path that commits a new or changed
 * delegate leaf commits the caller's (or the governance proposal's frozen)
 * periodStartDaa verbatim — "0", a stale value, or a lagging start carried
 * through a re-policy — so the delegate confirms with every elapsed period's
 * budget at once. The friendly create reads the node DAA with BigInt() (a hex
 * or padded answer anchors), and the dry run is offline.
 *
 * REQUIRED BEHAVIOUR (the period-start rule; anchor at build):
 *   - a leaf of the new registry that is not byte-identical in its nine
 *     committed fields to its predecessor leaf (new key, rotated key, any
 *     changed field) commits periodStartDaa = max(requested, D_build), D_build
 *     being the configured synced node's canonical virtual DAA score read in
 *     the builder AFTER every intent-stage gate; every other field (periodSpent
 *     included) exactly as requested; byte-identical (CARRIED) leaves are
 *     untouched and a registry without such a leaf reads no DAA;
 *   - the agent root is recomputed from the committed leaves: the stored
 *     registry folds to the committed root (create: the genesis build's root,
 *     equal to the top-level initial state's);
 *   - governed executions keep matching their proposals (the proposal and the
 *     risk intent hash carry the requested start; the committed start may be
 *     later than approved, never earlier, periodSpent unchanged);
 *   - an unreadable or non-canonical node DAA refuses 422
 *     PERIOD_START_REQUIRED writing no request, reservation, proposal
 *     consumption or claim (a matched released risk hold consumed by the
 *     intent-stage gate before the read is the disclosed effect);
 *   - POST /wallet/v4/simulate mirrors the anchor (a refusal becomes its
 *     refusalReason).
 *
 * Layers: API (the real server/src/api.js handle in hosted mode — wallet
 * sessions signed in with TEST keys, an owner-minted machine credential —
 * over the JSON store and a fresh PostgreSQL database per leg) plus SDK. Real
 * v0.4.1 compiler, pv_call_encoder, TEST-key signatures and the pinned
 * pv_vm_preflight: every built lifecycle request of a leg that reaches that
 * point is finalized through the hosted signature route (production-byte
 * rule). The node DAA read at build is the test seam (useAnchorDaa: a value,
 * or a thrower modelling a node that is down); the friendly create's node is
 * an explicit mock answering getBlockDagInfo (installed before api.js loads).
 * The RC44-era proposal is written by the pinned df5b8de governance writer
 * (sdk/testutil/rc45-r2-rc44-writer.js). Realistic DAA values (about
 * 5.45e8). Nothing dials a node; no production data.
 */
const R = require("../testutil/rc45-r2-kit");
const NODE = R.installNodePatch(); // before anything loads server/src/api.js
const assert = require("node:assert/strict");
const { test, before, after } = require("node:test");
const W44 = require("../testutil/rc45-r2-rc44-writer");
const { cand, Categories, K, KAS, D, DAY, said } = R;
const TOOLCHAIN = require("../testutil/org-root-durable-fixture").toolchainAvailable();

const S = R.suite("r2-02");
const V = Object.freeze({ base: K.vault("r2-02-base") });
const D_EXEC = D + 7777n; // the node has moved on between the proposal and its execution
const DELAY_MS = 1500;
const STALE_A = D - 5n * DAY;
let w = null, A = null, B = null, PRED = null, RC44_PROPOSAL = null;

before(async () => {
  assert.ok(TOOLCHAIN, "real compiler, encoder and VM are required (a missing VM toolchain is a FAIL, never a SKIP)");
  await S.setup(async (template) => {
    w = R.wallets(template);
    A = R.delegate(w.agent.xonly, [w.recipient.xonly], { maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodStartDaa: STALE_A.toString(), periodSpent: (3n * KAS).toString() });
    B = R.delegate(w.agentB.xonly, [w.recipient.xonly], { maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(), periodStartDaa: (D - 1000n).toString(), periodSpent: "0" });
    PRED = R.canonicalEntries([A, B]);
    await R.seedVault(template, V.base, w, [A, B]);
    // The RC44-era proposal: addAgent of n3 with start "0", written by the pinned RC44 governance writer.
    const rc44 = W44.runRc44R2("proposal", { base: { vaultId: V.base.vaultId, out: V.base.out, cov: V.base.cov, owner: w.owner.xonly, registry: [A, B], label: `RC45 R2 TEST ${V.base.tag}` }, params: { agent: newAgent(w.n3, "0") } }, { track: S.track });
    RC44_PROPOSAL = rc44.result.record;
    assert.equal(RC44_PROPOSAL.proposal.params.agent.periodStartDaa, "0", "the RC44 proposal records the requested start 0");
  });
});
after(async () => { await S.teardown(); });

function newAgent(wallet, start, over = {}) { return R.delegate(wallet.xonly, [w.recipient.xonly], { periodStartDaa: String(start), ...over }); }
const exec = (x, action, params, extra = {}) => ({ vaultId: V.base.vaultId, action, params: { fuel: x.kit.fuelOf(V.base), ...params }, signerAddress: w.owner.address, ...extra });
const createBody = (tag, initialAgents) => ({ templateInput: { owner: w.owner.xonly, vaultId: K.hex(`rc45-r2-02-create-${tag}`) }, initialAgents, initialState: { protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), approvers: [], approvalM: "0" }, signerAddress: w.owner.address, funding: [R.fundingFor(w.owner, `r2-02-${tag}`)], contractVersion: "policyvault-0.4.1", label: `RC45 R2 TEST ${tag}` });
const friendlyBody = (tag) => ({ vaultId: K.hex(`rc45-r2-02-friendly-${tag}`), label: `RC45 R2 TEST ${tag}`, depositKas: "1000", feeReserveKas: "5", agent: { agentAddress: w.n6.address, maxPerSpendKas: "10", budgetKas: "30", periodLengthDaa: DAY.toString(), approvalThresholdKas: "5", recipientAddresses: [w.recipient.address] }, signerAddress: w.owner.address, funding: [R.fundingFor(w.owner, `r2-02-friendly-${tag}`)] });
const reduction = () => ({ agentPk: A.agentPk, agent: { ...A, maxPerSpend: (15n * KAS).toString() } }); // a REDUCTION re-policy carrying A's lagging start
const REVIEW_ALL = { adapters: [{ type: "static-verdict", params: { verdict: "REVIEW", code: "R2_TEST_REVIEW" } }] };
const effectiveStatus = (record) => require("../../server/src/governance").effectiveProposalStatus(record);

/* The carried leaves are byte-identical to their predecessor leaves; `expect` maps each anchored key to its committed start. */
function assertCommitted(q, expect, label) {
  for (const [pk, start] of Object.entries(expect)) {
    const e = R.entryOf(q.newRegistry ?? q.initialRegistry, pk);
    assert.ok(e, `${label}: the delegate ${pk.slice(0, 8)} is in the committed registry`);
    assert.equal(e.periodStartDaa, String(start), `${label}: the committed period start of ${pk.slice(0, 8)} is max(requested, node DAA at the build)`);
  }
}
function assertCarried(q, pks, label) {
  for (const pk of pks) assert.deepEqual(R.entryOf(q.newRegistry, pk), R.entryOf(PRED, pk), `${label}: the CARRIED delegate ${pk.slice(0, 8)} is byte-identical to its predecessor leaf`);
}
/* Every committed field other than the start is exactly as requested. */
function assertAsRequested(q, requested, label) {
  const want = R.canonicalEntries([requested])[0], got = R.entryOf(q.newRegistry ?? q.initialRegistry, requested.agentPk);
  for (const f of Object.keys(want).filter((k) => k !== "periodStartDaa")) assert.deepEqual(got[f], want[f], `${label}: ${f} is committed exactly as requested`);
}
async function finalizedThroughVm(x, requestId, label) {
  const f = await x.ownerFinalize(requestId);
  assert.equal(f.status, 200, `${label}: the owner's real TEST-key signature finalizes through the VM preflight (${said(f)})`);
  assert.equal(f.body.request.state, "PREFLIGHT_VERIFIED");
}

for (const [backend, skip] of [["JSON", undefined], ["PostgreSQL", S.PG_SKIP]]) {
  const leg = (name, fn) => test(`RC45 R2-02 ${backend}: ${name}`, { skip }, async () => { const x = await S.fresh(backend, w); try { await fn(x); } finally { await S.release(x); } });

  /* ---------------- governed executions (proposals of every origin) ---------------- */
  leg("governed addAgent whose proposal (new delegate start 0) the owner session created, executed after the organization's delay window: 201, the new delegate's period start is the node DAA at the execution build, the other delegates are byte-identical, the registry folds to the committed root, review.periodStartAnchorDaa names it, the proposal is CONSUMED, the committed state differs from the approved one only by a later start, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    await x.organize(V.base, { governance: { delayMs: DELAY_MS } });
    const params = { agent: newAgent(w.n1, "0") };
    const proposal = await x.propose(V.base.vaultId, "addAgent", params);
    await x.approve(proposal.proposalId);
    await R.withAnchor(D_EXEC, async () => {
      const early = await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(early.status, 409, `the delay window still runs (${said(early)})`); assert.equal(early.code, "GOVERNANCE_DELAY_PENDING");
      await R.sleep(DELAY_MS + 300);
      const r = await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 201, `the approved proposal executes after its delay window (${said(r)})`);
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n1.xonly]: D_EXEC }, "owner-session proposal");
      assertCarried(q, [A.agentPk, B.agentPk], "owner-session proposal");
      assertAsRequested(q, params.agent, "owner-session proposal");
      R.assertLifecycleFolds(q, "owner-session proposal");
      assert.equal(q.review.periodStartAnchorDaa, D_EXEC.toString(), "the build reports the node DAA it anchored at");
      const record = await x.proposalRecord(proposal.proposalId);
      assert.equal(effectiveStatus(record), "CONSUMED"); assert.equal(record.lastConsumedRequestId, q.requestId);
      R.assertGovernanceException(record, await x.manifest(V.base), q, "owner-session proposal");
      await finalizedThroughVm(x, q.requestId, "owner-session proposal");
    });
  });

  leg("governed rotateAgent whose proposal (the lagging delegate rotated to a new key with start 0) an owner-minted machine credential holding governance:propose created, executed after the delay window: 201, the rotated key's start is the node DAA at the execution build, the untouched delegate is byte-identical, the registry folds, the proposal is CONSUMED, only a later start differs from the approved state, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    await x.organize(V.base, { governance: { delayMs: DELAY_MS } });
    const params = { agentPk: A.agentPk, agent: newAgent(w.n2, "0") };
    const proposal = await x.propose(V.base.vaultId, "rotateAgent", params, await x.proposerCredential());
    await x.approve(proposal.proposalId);
    await R.sleep(DELAY_MS + 300);
    await R.withAnchor(D_EXEC, async () => {
      const r = await x.build(exec(x, "rotateAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 201, `the machine-proposed rotation executes (${said(r)})`);
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n2.xonly]: D_EXEC }, "machine-credential proposal");
      assert.equal(R.entryOf(q.newRegistry, A.agentPk), null, "the rotated key is gone");
      assertCarried(q, [B.agentPk], "machine-credential proposal");
      assertAsRequested(q, params.agent, "machine-credential proposal");
      R.assertLifecycleFolds(q, "machine-credential proposal");
      const record = await x.proposalRecord(proposal.proposalId);
      assert.equal(effectiveStatus(record), "CONSUMED"); assert.equal(record.lastConsumedRequestId, q.requestId);
      R.assertGovernanceException(record, await x.manifest(V.base), q, "machine-credential proposal");
      await finalizedThroughVm(x, q.requestId, "machine-credential proposal");
    });
  });

  leg("governed addAgent executing an RC44-era stored proposal (written by the pinned RC44 governance writer with the new delegate's start 0) after the owner's approval: 201, the start is the node DAA at the build, the proposal still matches and is CONSUMED, the registry folds, only a later start differs from the approved state, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    await x.store.write(Categories.GOVERNANCE_PROPOSAL, RC44_PROPOSAL.proposalId, RC44_PROPOSAL);
    await x.approve(RC44_PROPOSAL.proposalId);
    await R.withAnchor(D, async () => {
      const r = await x.build(exec(x, "addAgent", RC44_PROPOSAL.proposal.params, { proposalId: RC44_PROPOSAL.proposalId }));
      assert.equal(r.status, 201, `the RC44-era proposal executes (${said(r)})`);
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n3.xonly]: D }, "RC44-era proposal");
      assertCarried(q, [A.agentPk, B.agentPk], "RC44-era proposal");
      R.assertLifecycleFolds(q, "RC44-era proposal");
      const record = await x.proposalRecord(RC44_PROPOSAL.proposalId);
      assert.equal(effectiveStatus(record), "CONSUMED"); assert.equal(record.lastConsumedRequestId, q.requestId);
      R.assertGovernanceException(record, await x.manifest(V.base), q, "RC44-era proposal");
      await finalizedThroughVm(x, q.requestId, "RC44-era proposal");
    });
  });

  leg("governed rePolicyAgent that raises the lagging delegate's budget (an EXPANSION carrying its start D - 5L and spent amount): 201, the changed delegate re-anchors to the node DAA with periodSpent unchanged, the registry folds, the proposal is CONSUMED, only a later start differs from the approved state, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    const params = { agentPk: A.agentPk, agent: { ...A, periodBudget: (60n * KAS).toString() } };
    const proposal = await x.propose(V.base.vaultId, "rePolicyAgent", params);
    await x.approve(proposal.proposalId);
    await R.withAnchor(D, async () => {
      const r = await x.build(exec(x, "rePolicyAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [A.agentPk]: D }, "budget raise");
      assert.equal(R.entryOf(q.newRegistry, A.agentPk).periodSpent, A.periodSpent, "budget raise: periodSpent is committed exactly as requested");
      assertCarried(q, [B.agentPk], "budget raise");
      assertAsRequested(q, params.agent, "budget raise");
      R.assertLifecycleFolds(q, "budget raise");
      const record = await x.proposalRecord(proposal.proposalId);
      assert.equal(effectiveStatus(record), "CONSUMED");
      R.assertGovernanceException(record, await x.manifest(V.base), q, "budget raise");
      await finalizedThroughVm(x, q.requestId, "budget raise");
    });
  });

  leg("governed direct ownerSetAgentRoot with newAgents (both installed delegates exactly as installed plus a new delegate with start 0): 201, the new delegate's start is the node DAA, both installed delegates are byte-identical (CARRIED), the registry folds, the proposal is CONSUMED, and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    const params = { newAgents: [A, B, newAgent(w.n4, "0")] };
    const proposal = await x.propose(V.base.vaultId, "ownerSetAgentRoot", params);
    await x.approve(proposal.proposalId);
    await R.withAnchor(D, async () => {
      const r = await x.build(exec(x, "ownerSetAgentRoot", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n4.xonly]: D }, "direct newAgents");
      assertCarried(q, [A.agentPk, B.agentPk], "direct newAgents");
      R.assertLifecycleFolds(q, "direct newAgents");
      const record = await x.proposalRecord(proposal.proposalId);
      assert.equal(effectiveStatus(record), "CONSUMED");
      R.assertGovernanceException(record, await x.manifest(V.base), q, "direct newAgents");
      await finalizedThroughVm(x, q.requestId, "direct newAgents");
    });
  });

  /* ---------------- the ungoverned REDUCTION lane and the risk hold ---------------- */
  leg("an ungoverned REDUCTION re-policy (lower per-spend cap) that carries the lagging start D - 5L builds without a proposal and commits the changed delegate's start at the node DAA (never more capacity than requested), periodSpent unchanged; the registry folds and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    await R.withAnchor(D, async () => {
      const r = await x.build(exec(x, "rePolicyAgent", reduction()));
      assert.equal(r.status, 201, `the REDUCTION lane needs no proposal (${said(r)})`);
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [A.agentPk]: D }, "REDUCTION re-policy");
      assert.equal(R.entryOf(q.newRegistry, A.agentPk).periodSpent, A.periodSpent);
      assertCarried(q, [B.agentPk], "REDUCTION re-policy");
      R.assertLifecycleFolds(q, "REDUCTION re-policy");
      await finalizedThroughVm(x, q.requestId, "REDUCTION re-policy");
    });
  });

  leg("a re-submission of the same REDUCTION params after the organization's reviewer released its risk hold consumes the hold exactly once and builds with the changed delegate's start at the node DAA (the risk intent hash keeps the requested params); the registry folds [RED on b89f0f7]", async (x) => {
    await x.organize(V.base, { risk: REVIEW_ALL });
    await R.withAnchor(D, async () => {
      const held = await x.build(exec(x, "rePolicyAgent", reduction()));
      assert.equal(held.status, 409, `the organization holds the change for review (${said(held)})`); assert.equal(held.code, "RISK_REVIEW_REQUIRED");
      const evaluationId = held.extra.riskEvaluation.evaluationId;
      await x.release(evaluationId);
      const r = await x.build(exec(x, "rePolicyAgent", reduction()));
      assert.equal(r.status, 201, `the released intent continues (${said(r)})`);
      assert.equal((await x.evaluation(evaluationId)).status, "CONSUMED");
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [A.agentPk]: D }, "risk-hold re-submission");
      assertCarried(q, [B.agentPk], "risk-hold re-submission");
      R.assertLifecycleFolds(q, "risk-hold re-submission");
      await finalizedThroughVm(x, q.requestId, "risk-hold re-submission");
    });
  });

  /* ---------------- node unavailable at the build ---------------- */
  leg("an approved addAgent executed while the node DAA cannot be read refuses 422 PERIOD_START_REQUIRED: no request, reservation or claim is written, the vault is unchanged and the proposal is NOT consumed (still OPEN, no consumer) [RED on b89f0f7]", async (x) => {
    const params = { agent: newAgent(w.n5, "0") };
    const proposal = await x.propose(V.base.vaultId, "addAgent", params);
    await x.approve(proposal.proposalId);
    const before = await x.scope();
    await R.withAnchor(R.nodeDown, async () => {
      const r = await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 422, `an unreadable node DAA refuses the anchored build (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
    });
    assert.deepEqual(await x.scope(), before, "no request, reservation, claim, vault or proposal write");
    const record = await x.proposalRecord(proposal.proposalId);
    assert.equal(effectiveStatus(record), "OPEN", "the proposal is not consumed"); assert.equal(record.lastConsumedRequestId ?? null, null);
  });

  leg("a re-submission of a released REDUCTION while the node DAA cannot be read refuses 422 PERIOD_START_REQUIRED with no request, reservation, claim or vault write; the released hold matched by the intent-stage gate before the read is consumed (the disclosed effect: the reviewer must release it again) [RED on b89f0f7]", async (x) => {
    await x.organize(V.base, { risk: REVIEW_ALL });
    const held = await R.withAnchor(D, () => x.build(exec(x, "rePolicyAgent", reduction())));
    assert.equal(held.code, "RISK_REVIEW_REQUIRED", said(held));
    const evaluationId = held.extra.riskEvaluation.evaluationId;
    await x.release(evaluationId);
    const before = await x.scope();
    await R.withAnchor(R.nodeDown, async () => {
      const r = await x.build(exec(x, "rePolicyAgent", reduction()));
      assert.equal(r.status, 422, `an unreadable node DAA refuses the anchored build (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
    });
    assert.deepEqual(await x.scope(), before, "no request, reservation, claim or vault write");
    assert.equal((await x.evaluation(evaluationId)).status, "CONSUMED", "the matched released hold was consumed before the read (disclosed)");
  });

  leg("the friendly create refuses 422 PERIOD_START_REQUIRED and writes no request when the node answers a non-canonical virtual DAA score (hex, padded, signed, missing) [RED on b89f0f7]", async (x) => {
    await R.withAnchor(D, async () => {
      for (const raw of ["0x207b9e40", " 545000000", "-1", undefined]) {
        const before = await x.scope();
        const r = await NODE.with(R.dagNode(raw), () => x.create(friendlyBody(`noncanonical-${String(raw).trim()}`)));
        assert.equal(r.status, 422, `a non-canonical node DAA (${JSON.stringify(raw)}) never anchors (${said(r)})`);
        assert.equal(r.code, "PERIOD_START_REQUIRED", `the refusal names the unreadable network position (${JSON.stringify(raw)})`);
        assert.deepEqual(await x.scope(), before, `nothing is written (${JSON.stringify(raw)})`);
      }
    });
  });

  /* ---------------- the real node DAA read (no test seam; the node client is a TEST client below connectVerified) ----------------
   * The build reads the configured node through its own body: connect, the network / isSynced / hasUtxoIndex gate, the
   * canonical parse of virtualDaaScore, disconnect. Every unreadable answer refuses 422 PERIOD_START_REQUIRED writing
   * nothing; a connect error carries its cause; no connection is left open. */
  for (const [label, node] of R.UNREADABLE_NODES) {
    leg(`an approved addAgent built with NO test seam while the configured node answers ${label}: the real node DAA read refuses 422 PERIOD_START_REQUIRED${node.connectError ? " carrying the connection error as its cause" : ""}, every opened node connection is disconnected, nothing is written and the proposal is not consumed [RED on b89f0f7]`, async (x) => {
      assert.notEqual(x.config.networkId, "mainnet", "the configured network differs from the node's in the network case");
      const params = { agent: newAgent(w.n4, "0") };
      const proposal = await x.propose(V.base.vaultId, "addAgent", params);
      await x.approve(proposal.proposalId);
      const before = await x.scope();
      const { r, log } = await R.withNodeClient(x.config, node, async (client) => ({ r: await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId })), log: client.log() }));
      assert.equal(r.status, 422, `an unreadable node never anchors a start (${said(r)})`);
      assert.equal(r.code, "PERIOD_START_REQUIRED");
      if (node.connectError) assert.ok(String(r.message).includes(node.connectError), `the refusal carries the connection error as its cause: ${r.message}`);
      R.assertNodeClientClosed(log, node, label);
      assert.deepEqual(await x.scope(), before, "no request, reservation, claim, vault or proposal write");
      const record = await x.proposalRecord(proposal.proposalId);
      assert.equal(effectiveStatus(record), "OPEN", "the proposal is not consumed"); assert.equal(record.lastConsumedRequestId ?? null, null);
    });
  }

  leg("an approved addAgent built with NO test seam while the configured, synced, indexed node answers a canonical virtual DAA score (the client's bigint): the real node DAA read anchors the new delegate's start at that score, the installed delegates are byte-identical, the node connection is disconnected, the registry folds and the request finalizes through the VM [RED on b89f0f7]", async (x) => {
    const DN = D + 4242n, node = { virtualDaaScore: DN };
    const params = { agent: newAgent(w.n4, "0") };
    const proposal = await x.propose(V.base.vaultId, "addAgent", params);
    await x.approve(proposal.proposalId);
    const { r, log } = await R.withNodeClient(x.config, node, async (client) => ({ r: await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId })), log: client.log() }));
    assert.equal(r.status, 201, `a synced node's canonical score anchors the build (${said(r)})`);
    const q = await x.req(r.body.request.requestId);
    assertCommitted(q, { [w.n4.xonly]: DN }, "real node read");
    assertCarried(q, [A.agentPk, B.agentPk], "real node read");
    assertAsRequested(q, params.agent, "real node read");
    R.assertLifecycleFolds(q, "real node read");
    R.assertNodeClientClosed(log, node, "real node read");
    await R.withAnchor(DN, () => finalizedThroughVm(x, q.requestId, "real node read"));
  });

  /* ---------------- creates ---------------- */
  leg("the canonical create (the SDK / Python / curl / self-host schema) with delegate starts 0, D - 3L and D + 5,000 commits D, D and D + 5,000: the stored initial registry folds to the genesis build's agent root, which equals the top-level initial state's, and review.periodStartAnchorDaa names D [RED on b89f0f7]", async (x) => {
    const agents = [newAgent(w.n1, "0"), newAgent(w.n2, D - 3n * DAY), newAgent(w.n3, D + 5000n)];
    await R.withAnchor(D, async () => {
      const r = await x.create(createBody("c1", agents));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n1.xonly]: D, [w.n2.xonly]: D, [w.n3.xonly]: D + 5000n }, "canonical create");
      for (const a of agents) assertAsRequested(q, a, "canonical create");
      R.assertGenesisFolds(q, "canonical create");
      assert.equal(q.review.periodStartAnchorDaa, D.toString(), "the create reports the node DAA it anchored at");
    });
  });

  leg("the canonical create with a single delegate whose requested start is in the future (D + 5,000) keeps it; the registry folds to the genesis build's root, equal to the top-level initial state's", async (x) => {
    await R.withAnchor(D, async () => {
      const r = await x.create(createBody("c2", [newAgent(w.n1, D + 5000n)]));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n1.xonly]: D + 5000n }, "future start");
      assert.equal(q.review.technical.periodStartDaa, (D + 5000n).toString());
      R.assertGenesisFolds(q, "future start");
    });
  });

  leg("the canonical create with no delegates builds without any node DAA read (the read throws if made); the empty registry folds to the empty tree's root in both roots", async (x) => {
    await R.withAnchor(R.nodeDown, async (seam) => {
      const r = await x.create(createBody("c3", []));
      assert.equal(r.status, 201, said(r));
      assert.equal(seam.calls(), 0, "no ANCHORED leaf, no node read");
      R.assertGenesisFolds(await x.req(r.body.request.requestId), "no delegates");
    });
  });

  leg("the friendly create commits max(D1, D_build): the node answered D1 = D - 1,000 before the build and the builder's read answers D, so the delegate starts at D; the registry folds to the genesis build's root, equal to the top-level initial state's [RED on b89f0f7]", async (x) => {
    await R.withAnchor(D, async () => {
      const r = await NODE.with(R.dagNode((D - 1000n).toString()), () => x.create(friendlyBody("c4")));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n6.xonly]: D }, "friendly create");
      assert.equal(q.review.technical.periodStartDaa, D.toString());
      R.assertGenesisFolds(q, "friendly create");
    });
  });

  leg("the friendly create with D1 = D_build = D commits D; the registry folds to the genesis build's root, equal to the top-level initial state's", async (x) => {
    await R.withAnchor(D, async () => {
      const r = await NODE.with(R.dagNode(D.toString()), () => x.create(friendlyBody("c5")));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assertCommitted(q, { [w.n6.xonly]: D }, "friendly create at D");
      R.assertGenesisFolds(q, "friendly create at D");
    });
  });

  /* ---------------- no ANCHORED leaf: no node read ---------------- */
  leg("removeAgent builds and finalizes through the VM with the node DAA read throwing: no read is made, the remaining delegate is byte-identical (its lagging start untouched) and the registry folds", async (x) => {
    await R.withAnchor(R.nodeDown, async (seam) => {
      const r = await x.build(exec(x, "removeAgent", { agentPk: B.agentPk }));
      assert.equal(r.status, 201, said(r));
      const q = await x.req(r.body.request.requestId);
      assert.deepEqual(q.newRegistry, [R.entryOf(PRED, A.agentPk)], "the remaining delegate is CARRIED byte-identically");
      R.assertLifecycleFolds(q, "removeAgent");
      await finalizedThroughVm(x, q.requestId, "removeAgent");
      assert.equal(seam.calls(), 0, "no node DAA read");
    });
  });

  leg("ownerPause, ownerTopUp and an agent spend build, and the pause finalizes through the VM, with the node DAA read throwing: no read is made", async (x) => {
    await R.withAnchor(R.nodeDown, async (seam) => {
      const pause = await x.build(exec(x, "ownerPause", {}));
      assert.equal(pause.status, 201, said(pause));
      const topUp = await x.build(exec(x, "ownerTopUp", { topUpAmountSompi: KAS.toString() }));
      assert.equal(topUp.status, 201, said(topUp));
      const spend = await x.build({ vaultId: V.base.vaultId, action: "agentSpend", params: { payAmountSompi: KAS.toString(), agentPk: A.agentPk, recipient: w.recipient.xonly }, signerAddress: w.agent.address }, x.cookie.agent);
      assert.equal(spend.status, 201, said(spend));
      await finalizedThroughVm(x, pause.body.request.requestId, "ownerPause");
      assert.equal(seam.calls(), 0, "no node DAA read");
    });
  });

  /* ---------------- the dry run mirrors the build ---------------- */
  leg("POST /wallet/v4/simulate of an addAgent with start 0 reports the successor agent root of the ANCHORED registry (the new delegate at the node DAA), the same root a real governed build at the same DAA commits [RED on b89f0f7]", async (x) => {
    const params = { agent: newAgent(w.n1, "0") };
    const expected = R.fold([A, B, { ...params.agent, periodStartDaa: D.toString() }]);
    await R.withAnchor(D, async () => {
      const s = await x.simulate(exec(x, "addAgent", params));
      assert.equal(s.status, 200, said(s));
      assert.equal(s.body.simulation.ok, true, JSON.stringify(s.body.simulation.refusalReason ?? null));
      assert.equal(s.body.simulation.review.successorAgentRoot, expected, "the dry run anchors exactly as the build does");
      const proposal = await x.propose(V.base.vaultId, "addAgent", params);
      await x.approve(proposal.proposalId);
      const r = await x.build(exec(x, "addAgent", params, { proposalId: proposal.proposalId }));
      assert.equal(r.status, 201, said(r));
      assert.equal((await x.req(r.body.request.requestId)).build.successorState.agentRoot, s.body.simulation.review.successorAgentRoot, "simulate and build agree at the same node DAA");
      await finalizedThroughVm(x, r.body.request.requestId, "simulated addAgent");
    });
  });

  leg("POST /wallet/v4/simulate of an addAgent while the node DAA cannot be read answers ok:false with refusalReason 422 PERIOD_START_REQUIRED (the status and code the real route refuses with) [RED on b89f0f7]", async (x) => {
    await R.withAnchor(R.nodeDown, async () => {
      const s = await x.simulate(exec(x, "addAgent", { agent: newAgent(w.n1, "0") }));
      assert.equal(s.status, 200, said(s));
      assert.equal(s.body.simulation.ok, false, "the dry run reports the refusal");
      assert.equal(s.body.simulation.refusalReason?.code, "PERIOD_START_REQUIRED");
      assert.equal(s.body.simulation.refusalReason?.status, 422);
    });
  });

  leg("POST /wallet/v4/simulate of a removeAgent with the node DAA read throwing makes no read and reports the root of the carried registry", async (x) => {
    await R.withAnchor(R.nodeDown, async (seam) => {
      const s = await x.simulate(exec(x, "removeAgent", { agentPk: B.agentPk }));
      assert.equal(s.status, 200, said(s));
      assert.equal(s.body.simulation.ok, true, JSON.stringify(s.body.simulation.refusalReason ?? null));
      assert.equal(s.body.simulation.review.successorAgentRoot, R.fold([A]));
      assert.equal(seam.calls(), 0, "no node DAA read");
    });
  });
}
