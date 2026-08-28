"use strict";

/*
 * POSTLAUNCH SERVER GOVERNANCE — HOSTILE FALSIFICATION SUITE
 * (docs/postlaunch/server-enforcement-falsification.md).
 *
 * Adversarial attempts to EXPAND covenant authority through the hosted
 * governance layer — a hosted admin / DB tamperer with full write access
 * to the stored governance records, plus a caller who controls request
 * bodies. Each test is a concrete hostile input; every one must fail
 * closed. NONE of these gates is covenant authority — the covenant's own
 * owner-signature-over-frozen-bytes requirement is enforced by consensus
 * regardless — but each is a defense-in-depth invariant the spec claims
 * (docs/postlaunch/governance-spec.md; server-integration.md), so each
 * claim is falsified here with a real hostile construction.
 *
 * Complements sdk/test/postlaunch-governance-server.test.js (the positive
 * suite): this suite adds the attacks that suite does not cover —
 * owner-signature floor under an org quorum, mixed-op smuggling
 * (rotate/rePolicy direction), cross-action proposal reuse, same-digest
 * cross-proposal approval replay, cross-vault retarget (both integrity
 * layers), content-tamper with a re-fixed cached digest, and
 * tampered-version fail-closed.
 *
 * Terminology: these are authorized negative-validation constructions
 * against the project's own hosted enforcement (policy-invalid adversarial
 * test inputs). Integer sompi / BigInt throughout.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { governanceProposalDigest } = require("../../core/governance");
const org = require("../src/organization");
const { saveOrgControls, loadOrgControls } = require("../../server/src/org-controls");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-hostile-gov-"));
const config = loadConfig({ dataRoot });
const kaspa = require(config.rustyKaspaModule);
const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
const SIGN = (p, message) => kaspa.signMessage({ message, privateKey: p.toString() });
const KAS = 100000000n;

const owner = KEY(1);
const agentA = KEY(0x1e);
const agentB = KEY(0x1f);
const recipient = KEY(0x28);
const approver1 = KEY(20);
const approver2 = KEY(21);

function agentEntry(kp, recipients, over = {}) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (50n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO), ...over
  };
}
const REGISTRY = [agentEntry(agentA, [recipient]), agentEntry(agentB, [recipient])];
const NEW_AGENT = {
  agentPk: XO(KEY(0x55)), maxPerSpend: (10n * KAS).toString(), periodBudget: (30n * KAS).toString(),
  periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
  approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(), recipients: [XO(recipient)]
};

let seedCounter = 0;
async function seed(vaultId, registry = REGISTRY, over = {}) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const template = { owner: XO(owner), vaultId };
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(),
    paused: over.paused ?? "0", agentRoot, approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
    label: "hostile-gov", status: over.paused === "1" ? "PAUSED" : "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const GET = (segs, query) => handle(config, "GET", segs, query ?? {}, null);
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail("expected an API error");
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}
const ownerFuel = () => ({ outpoint: { transactionId: "43".repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const proposalFile = (id) => path.join(dataRoot, "governance", "proposals", `${id}.json`);

async function proposeAndApprove(vaultId, action, params, { approveWith = owner } = {}) {
  const created = await POST(["governance", "proposals"], { vaultId, action, params });
  const proposal = created.body.proposal;
  const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], {
    approverAddress: ADDR(approveWith), signature: SIGN(approveWith, proposal.approvalMessage)
  });
  return approved.body.proposal;
}

/* -------------------------------------------------------------------- */
/* 1. OWNER-SIGNATURE FLOOR under an organization quorum                 */
/* -------------------------------------------------------------------- */
test("owner floor: an org quorum can APPROVE in full while the OWNER has not — expansion still refuses (config never removes the owner requirement)", async () => {
  const V = "a1".repeat(32);
  await seed(V);
  const created = await org.createOrganization(config, { name: "floor org" });
  await org.assignVault(config, { vaultId: V, orgId: created.orgId, group: null, expectedVersion: 0, vaultExists: async () => true });
  // a 2-of-2 external quorum, zero delay: the strongest configured ceremony
  await saveOrgControls(config, created.orgId, {
    governance: { quorum: { approvers: [XO(approver1), XO(approver2)], m: 2 }, delayMs: 0 }, risk: {}, expectedVersion: 0
  });
  const createdP = await POST(["governance", "proposals"], { vaultId: V, action: "addAgent", params: { agent: NEW_AGENT } });
  const proposal = createdP.body.proposal;
  // BOTH quorum members sign — but the owner deliberately does NOT
  for (const a of [approver1, approver2]) {
    await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(a), signature: SIGN(a, proposal.approvalMessage) });
  }
  const view = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(view.body.proposal.approvals.ownerApproved, false, "owner has not approved");
  assert.equal(view.body.proposal.approvals.orgQuorum.collected, 2, "the full external quorum HAS approved");
  assert.equal(view.body.proposal.approvals.satisfied, false, "quorum-without-owner is never satisfied");
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
  assert.equal(e.extra.governance.ownerApproved, false);
  // the owner's own approval then completes the (now genuinely satisfied) quorum
  await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: SIGN(owner, proposal.approvalMessage) });
  const after = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(after.body.proposal.approvals.satisfied, true);
  const assignments = await org.loadAssignments(config);
  await org.unassignVault(config, { vaultId: V, expectedVersion: assignments.version });
});

/* -------------------------------------------------------------------- */
/* 2. MIXED-OP SMUGGLING — a "rotation" is an authority EXPANSION        */
/* -------------------------------------------------------------------- */
test("rotateAgent is an EXPANSION (a NEW key gains spending authority) and cannot take the reduction lane", async () => {
  const V = "a2".repeat(32);
  await seed(V);
  // No proposal supplied: a rotation must NOT slip through as a reduction.
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "rotateAgent", params: { fuel: ownerFuel(), agentPk: XO(agentB), agent: NEW_AGENT }, signerAddress: ADDR(owner) }),
    409, "GOVERNANCE_PROPOSAL_REQUIRED"
  );
  assert.equal(e.extra.governance.classification, "EXPANSION");
  // AGENT_ADDED for the new key is present (a new authority holder)
  assert.ok(e.extra.governance.codes.includes("AGENT_ADDED"), `codes: ${e.extra.governance.codes}`);
});

test("rePolicyAgent RAISING a per-spend cap is EXPANSION (proposal required); LOWERING it is REDUCTION (lighter lane builds)", async () => {
  const V = "a3".repeat(32);
  await seed(V);
  const raise = { ...agentEntry(agentA, [recipient]), maxPerSpend: (999n * KAS).toString() };
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "rePolicyAgent", params: { fuel: ownerFuel(), agentPk: XO(agentA), agent: raise }, signerAddress: ADDR(owner) }),
    409, "GOVERNANCE_PROPOSAL_REQUIRED"
  );
  assert.equal(e.extra.governance.classification, "EXPANSION");
  assert.ok(e.extra.governance.codes.includes("AGENT_PER_SPEND_CAP_RAISED"), `codes: ${e.extra.governance.codes}`);
  // the mirror-image reduction takes the lighter lane and builds with no proposal
  const lower = { ...agentEntry(agentA, [recipient]), maxPerSpend: (1n * KAS).toString() };
  const built = await POST(["wallet", "v4", "requests"], { vaultId: V, action: "rePolicyAgent", params: { fuel: ownerFuel(), agentPk: XO(agentA), agent: lower }, signerAddress: ADDR(owner) });
  assert.equal(built.status, 201);
  assert.equal(built.body.request.state, "BUILT");
});

/* -------------------------------------------------------------------- */
/* 3. CROSS-ACTION reuse — proposal for op A applied to op B             */
/* -------------------------------------------------------------------- */
test("an owner-approved addAgent proposal cannot be redirected to a DIFFERENT governed action (ownerUnpause) on the same vault", async () => {
  const V = "a4".repeat(32);
  await seed(V, REGISTRY, { paused: "1" }); // paused so ownerUnpause is itself a valid EXPANSION
  const proposal = await proposeAndApprove(V, "addAgent", { agent: NEW_AGENT });
  assert.equal(proposal.approvals.satisfied, true);
  // consume the addAgent approval to authorize a resume (RESUME_SPENDING expansion)
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_PROPOSAL_MISMATCH"
  );
});

/* -------------------------------------------------------------------- */
/* 4. createProposal refuses for non-governed / break-glass actions      */
/* -------------------------------------------------------------------- */
test("no governance proposal can be minted for a non-governed or break-glass action (they can never gain a gated-expansion vehicle)", async () => {
  const V = "a5".repeat(32);
  await seed(V);
  for (const [action, params] of [
    ["ownerPause", {}],                                                                 // break-glass
    ["ownerRecover", {}],                                                               // break-glass terminal
    ["agentSpend", { payAmountSompi: (1n * KAS).toString(), agentPk: XO(agentA), recipient: XO(recipient) }],
    ["ownerTopUp", { topUpAmountSompi: (1n * KAS).toString() }]                          // funding, not policy
  ]) {
    await expectThrow(POST(["governance", "proposals"], { vaultId: V, action, params }), 422, "GOVERNANCE_NOT_REQUIRED");
  }
});

/* -------------------------------------------------------------------- */
/* 5. SAME-DIGEST cross-proposal approval REPLAY (DB tamper)             */
/* -------------------------------------------------------------------- */
test("an approval cannot be replayed onto a DIFFERENT proposal even with byte-identical content and the same cached digest (the signed message binds proposalId)", async () => {
  const V = "a6".repeat(32);
  await seed(V);
  // P1: created, owner-approved (approval row keyed by digest, signed over P1's proposalId)
  const p1 = (await POST(["governance", "proposals"], { vaultId: V, action: "addAgent", params: { agent: NEW_AGENT } })).body.proposal;
  await POST(["governance", "proposals", p1.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: SIGN(owner, p1.approvalMessage) });
  // P2: a second, UN-approved proposal
  const p2 = (await POST(["governance", "proposals"], { vaultId: V, action: "addAgent", params: { agent: NEW_AGENT } })).body.proposal;
  assert.notEqual(p1.proposalId, p2.proposalId);
  // DB TAMPER: overwrite P2's stored content + cached digest with P1's, so P2 now
  // shares P1's digest exactly — an attacker trying to inherit P1's approval row.
  const r1 = JSON.parse(fs.readFileSync(proposalFile(p1.proposalId), "utf8"));
  const r2 = JSON.parse(fs.readFileSync(proposalFile(p2.proposalId), "utf8"));
  r2.proposal = r1.proposal;
  r2.proposalDigest = r1.proposalDigest;
  r2.classification = r1.classification;
  r2.codes = r1.codes;
  fs.writeFileSync(proposalFile(p2.proposalId), JSON.stringify(r2));
  // P2 now recomputes a consistent digest (integrity check passes)…
  const view = await GET(["governance", "proposals", p2.proposalId]);
  assert.equal(view.body.proposal.integrity.digestOk, true, "the copied content matches the copied digest");
  // …but the owner's approval — signed over P1's proposalId — does NOT count for P2.
  assert.equal(view.body.proposal.approvals.ownerApproved, false, "the approval binds P1's proposalId, not P2's");
  assert.equal(view.body.proposal.approvals.satisfied, false);
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner), proposalId: p2.proposalId }),
    409, "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
});

/* -------------------------------------------------------------------- */
/* 6. CROSS-VAULT retarget of an approved proposal (both integrity       */
/*    layers: digest binds vaultId; the signature binds the digest)      */
/* -------------------------------------------------------------------- */
test("an approved proposal cannot be retargeted to another vault by DB edit — the digest binds vaultId, and re-fixing the cached digest breaks the owner signature", async () => {
  const V1 = "a7".repeat(32);
  const V2 = "a8".repeat(32); // a second REAL vault (so the gate actually runs)
  await seed(V1);
  await seed(V2);
  const proposal = await proposeAndApprove(V1, "addAgent", { agent: NEW_AGENT });

  // Attempt A: change only proposal.vaultId -> the recomputed digest no longer matches the cached one.
  const rec = JSON.parse(fs.readFileSync(proposalFile(proposal.proposalId), "utf8"));
  rec.proposal.vaultId = V2;
  fs.writeFileSync(proposalFile(proposal.proposalId), JSON.stringify(rec));
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V2, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_DIGEST_MISMATCH"
  );
  // Attempt B: ALSO re-fix the cached digest so digestOk passes — now the owner's
  // approval signature (over the ORIGINAL vault's digest) fails to verify.
  rec.proposalDigest = governanceProposalDigest(rec.proposal);
  fs.writeFileSync(proposalFile(proposal.proposalId), JSON.stringify(rec));
  const view = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(view.body.proposal.integrity.digestOk, true);
  assert.equal(view.body.proposal.approvals.ownerApproved, false, "the owner signature binds the original digest");
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V2, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
});

/* -------------------------------------------------------------------- */
/* 7. CONTENT tamper (raise a cap in the approved `after`) + digest re-fix */
/* -------------------------------------------------------------------- */
test("smuggling a bigger cap into an approved proposal's after-state cannot survive even with the cached digest re-fixed — the owner signature no longer verifies", async () => {
  const V = "a9".repeat(32);
  await seed(V);
  const proposal = await proposeAndApprove(V, "addAgent", { agent: NEW_AGENT });
  const rec = JSON.parse(fs.readFileSync(proposalFile(proposal.proposalId), "utf8"));
  // raise the smuggled agent's cap in BOTH the params and the after tuple (self-consistent),
  // then re-fix the cached digest — the only thing left protecting the vault is the signature.
  const idx = rec.proposal.after.agents.findIndex((a) => a.agentPk === NEW_AGENT.agentPk.toLowerCase());
  rec.proposal.after.agents[idx].maxPerSpend = (999n * KAS).toString();
  rec.proposal.params.agent.maxPerSpend = (999n * KAS).toString();
  rec.proposalDigest = governanceProposalDigest(rec.proposal);
  fs.writeFileSync(proposalFile(proposal.proposalId), JSON.stringify(rec));
  const view = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(view.body.proposal.integrity.digestOk, true, "attacker re-fixed the cached digest");
  assert.equal(view.body.proposal.approvals.ownerApproved, false, "the owner never signed the raised-cap digest");
  const raised = { ...NEW_AGENT, maxPerSpend: (999n * KAS).toString() };
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "addAgent", params: { fuel: ownerFuel(), agent: raised }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
});

/* -------------------------------------------------------------------- */
/* 8. TAMPERED covenant version in a stored proposal fails closed        */
/* -------------------------------------------------------------------- */
test("a stored proposal whose covenantVersion is tampered fails closed at consumption (digest binds it; the classifier would also refuse the unknown version)", async () => {
  const V = "aa".repeat(32);
  await seed(V);
  const proposal = await proposeAndApprove(V, "addAgent", { agent: NEW_AGENT });
  const rec = JSON.parse(fs.readFileSync(proposalFile(proposal.proposalId), "utf8"));
  rec.proposal.covenantVersion = "policyvault-9.9"; // an unknown/forged version
  fs.writeFileSync(proposalFile(proposal.proposalId), JSON.stringify(rec));
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: V, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner), proposalId: proposal.proposalId }),
    409, "GOVERNANCE_DIGEST_MISMATCH"
  );
});
