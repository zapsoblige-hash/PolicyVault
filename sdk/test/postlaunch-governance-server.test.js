"use strict";

/*
 * POSTLAUNCH SERVER GOVERNANCE ENFORCEMENT (completion-standard item 3;
 * docs/postlaunch/governance-spec.md; docs/postlaunch/server-integration.md).
 *
 * Drives the REAL server api.handle over a temp JSON data root with the
 * REAL v0.4 build pipeline (encoder toolchain), proving at the server
 * boundary:
 *   - AUTHORITY EXPANSION requires an approved governance proposal
 *     (owner-signature-verified over the canonical digest) — the refusal
 *     is PURE (no durable request);
 *   - REDUCTION takes the lighter path (no proposal);
 *   - mixed changes classify EXPANSION;
 *   - break-glass ownerPause is NEVER gated;
 *   - classification is recomputed at consumption: a forged stored
 *     label loses to the recomputation; tampered proposal content trips
 *     the recomputed digest;
 *   - approval signatures verify with the auth-machinery verifier:
 *     valid owner approval counts, an invalid signature and a foreign
 *     (non-quorum) key are refused;
 *   - staleness: a proposal whose before-tuple no longer equals live
 *     policy refuses STALE_PROPOSAL;
 *   - org quorum + delay windows gate the expansion lane when
 *     configured.
 *
 * NONE of this is covenant authority: these gates are hosted
 * coordination; the covenant's own owner-signature requirement over
 * frozen bytes is enforced by consensus, unchanged.
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
const governance = require("../../server/src/governance");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gov-"));
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
const foreign = KEY(0x66);

const VAULT_ID = "31".repeat(32);
const template = { owner: XO(owner), vaultId: VAULT_ID };

function agentEntry(kp, recipients, over = {}) {
  return {
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO), ...over
  };
}
const REGISTRY = [agentEntry(agentA, [recipient]), agentEntry(agentB, [recipient])];

let seedCounter = 0;
async function seed(registry = REGISTRY, over = {}) {
  seedCounter += 1;
  const outTxId = seedCounter.toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const policies = registry.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
  const agentRoot = buildAgentTreeV4(policies).root;
  const state = normalizeStateV4({
    protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(),
    paused: over.paused ?? "0", agentRoot,
    approvers: over.approvers ?? [], approvalM: over.approvalM ?? "0", policyNonce: "0"
  });
  const compiled = compileExactStateV4({ config, template, state });
  const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
  return await persistManifestV4(config, {
    schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId: VAULT_ID,
    label: "governance test", status: over.paused === "1" ? "PAUSED" : "ACTIVE", template, agentRegistry: registry,
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
const requestFiles = () => (fs.existsSync(path.join(dataRoot, "requests")) ? fs.readdirSync(path.join(dataRoot, "requests")) : []);

const NEW_AGENT = {
  agentPk: XO(KEY(0x55)), maxPerSpend: (10n * KAS).toString(), periodBudget: (30n * KAS).toString(),
  periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
  approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
  recipients: [XO(recipient)]
};

/* Create a proposal via the API and approve it with the OWNER wallet's
 * real Schnorr personal-message signature over the canonical message. */
async function proposeAndApprove(action, params, { approveWith = owner, approveAddr } = {}) {
  const created = await POST(["governance", "proposals"], { vaultId: VAULT_ID, action, params });
  assert.equal(created.status, 201);
  const proposal = created.body.proposal;
  assert.equal(proposal.integrity.digestOk, true);
  const signature = SIGN(approveWith, proposal.approvalMessage);
  const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], {
    approverAddress: approveAddr ?? ADDR(approveWith),
    signature
  });
  assert.equal(approved.status, 200);
  return approved.body.proposal;
}

test("EXPANSION without a proposal refuses PURELY (no durable request) with the recomputed classification", async () => {
  await seed();
  const before = requestFiles().length;
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT }, signerAddress: ADDR(owner) }),
    409,
    "GOVERNANCE_PROPOSAL_REQUIRED"
  );
  assert.equal(e.extra.governance.classification, "EXPANSION");
  assert.ok(e.extra.governance.codes.includes("AGENT_ADDED"));
  assert.equal(requestFiles().length, before, "no durable request was created by the refusal");
});

test("EXPANSION with an owner-approved proposal builds; the proposal is consumed and the manifest recorded", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  assert.equal(proposal.approvals.ownerApproved, true);
  assert.equal(proposal.approvals.satisfied, true);
  const built = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
    signerAddress: ADDR(owner), proposalId: proposal.proposalId
  });
  assert.equal(built.status, 201);
  const req = built.body.request;
  assert.equal(req.state, "BUILT");
  assert.match(req.manifestHash, /^[0-9a-f]{64}$/, "the intent manifest hash is stamped on the request");
  // the manifest record is readable and re-verifies NOW
  const man = await GET(["manifests", req.manifestHash]);
  assert.equal(man.status, 200);
  assert.equal(man.body.verification.verdict, "VERIFIED_EXACT");
  assert.equal(man.body.liveVerification.ok, true);
  assert.equal(man.body.requestId, req.requestId);
  assert.equal(man.body.proposalId, proposal.proposalId, "the manifest record carries the consumed proposal id");
  // the proposal records its consumption
  const after = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(after.body.proposal.lastConsumedRequestId, req.requestId);
});

test("REDUCTION takes the lighter path: removeAgent builds without any proposal", async () => {
  await seed();
  const built = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "removeAgent", params: { fuel: ownerFuel(), agentPk: XO(agentB) }, signerAddress: ADDR(owner)
  });
  assert.equal(built.status, 201);
  assert.equal(built.body.request.state, "BUILT");
  assert.match(built.body.request.manifestHash, /^[0-9a-f]{64}$/);
});

test("mixed change classifies EXPANSION (adding an approver while raising the quorum) and requires a proposal", async () => {
  await seed();
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "ownerSetApprovers",
      params: { fuel: ownerFuel(), newApprovers: { approvers: [XO(approver1)], approvalM: "1" } },
      signerAddress: ADDR(owner)
    }),
    409,
    "GOVERNANCE_PROPOSAL_REQUIRED"
  );
});

test("break-glass ownerPause is NEVER gated: it builds with no proposal even under restrictive org controls", async () => {
  await seed();
  // Emergency freeze must go straight through (governance-spec §6.1).
  const built = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner)
  });
  assert.equal(built.status, 201);
  assert.equal(built.body.request.state, "BUILT");
});

test("ownerUnpause (resume) is an EXPANSION and requires the proposal path", async () => {
  await seed(REGISTRY, { paused: "1" });
  await expectThrow(
    POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner) }),
    409,
    "GOVERNANCE_PROPOSAL_REQUIRED"
  );
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const built = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId
  });
  assert.equal(built.status, 201);
});

test("forged stored label: a DB writer flipping classification to REDUCTION loses to the recomputation (integrity alarm)", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const file = path.join(dataRoot, "governance", "proposals", `${proposal.proposalId}.json`);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  record.classification = "REDUCTION"; // the forged label
  fs.writeFileSync(file, JSON.stringify(record));
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "CLASSIFICATION_MISMATCH"
  );
});

test("tampered proposal CONTENT trips the recomputed digest (stored approvals cannot survive edits)", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const file = path.join(dataRoot, "governance", "proposals", `${proposal.proposalId}.json`);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  record.proposal.after.agents[2].maxPerSpend = (999n * KAS).toString(); // smuggle a bigger cap
  fs.writeFileSync(file, JSON.stringify(record));
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_DIGEST_MISMATCH"
  );
});

test("approval signatures: invalid signature refused; foreign (non-quorum) wallet refused; owner approval verifies", async () => {
  await seed();
  const created = await POST(["governance", "proposals"], { vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT } });
  const proposal = created.body.proposal;
  // invalid signature (right shape, wrong content)
  await expectThrow(
    POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: "ab".repeat(64) }),
    401,
    "GOVERNANCE_SIGNATURE_INVALID"
  );
  // a foreign wallet's VALID signature over the digest does not satisfy the quorum
  const foreignSig = SIGN(foreign, proposal.approvalMessage);
  const collected = await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(foreign), signature: foreignSig });
  assert.equal(collected.status, 200); // stored as an approval row…
  assert.equal(collected.body.proposal.approvals.ownerApproved, false); // …but it is OUTSIDE the quorum set
  assert.equal(collected.body.proposal.approvals.satisfied, false);
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
  // the owner's real approval satisfies the personal quorum
  const ownerSig = SIGN(owner, proposal.approvalMessage);
  const ok = await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: ownerSig });
  assert.equal(ok.body.proposal.approvals.ownerApproved, true);
  assert.equal(ok.body.proposal.approvals.satisfied, true);
});

test("proposal params must match the execution request exactly (minus the execution-only fuel)", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const different = { ...NEW_AGENT, maxPerSpend: (11n * KAS).toString() };
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: different },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_PROPOSAL_MISMATCH"
  );
});

test("STALE_PROPOSAL: a proposal built against superseded live policy refuses at consumption", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  // the vault's policy advances (agentB removed) after the proposal was approved
  await seed([agentEntry(agentA, [recipient])]);
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "STALE_PROPOSAL"
  );
});

test("cancelled proposals refuse consumption; cancellation is always available", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const cancelled = await POST(["governance", "proposals", proposal.proposalId, "cancel"], {});
  assert.equal(cancelled.body.proposal.status, "CANCELLED");
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
});

test("org governance controls ADD ceremony: quorum member + delay window gate the expansion lane; owner approval alone is insufficient", async () => {
  await seed();
  // organization owning this vault, with a 1-of-1 extra quorum (approver1) and a delay
  const org = require("../src/organization");
  const created = await org.createOrganization(config, { name: "governed org" });
  await org.assignVault(config, { vaultId: VAULT_ID, orgId: created.orgId, group: null, expectedVersion: 0, vaultExists: async () => true });
  const { saveOrgControls } = require("../../server/src/org-controls");
  await saveOrgControls(config, created.orgId, {
    governance: { quorum: { approvers: [XO(approver1)], m: 1 }, delayMs: 60_000 },
    risk: {},
    expectedVersion: 0
  });

  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT }); // owner approval only
  // owner approved, but the org quorum has not
  await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );
  // quorum member approves
  const sig = SIGN(approver1, proposal.approvalMessage);
  const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(approver1), signature: sig });
  assert.equal(approved.body.proposal.approvals.satisfied, true);
  // …but the delay window still gates execution
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_DELAY_PENDING"
  );
  assert.ok(e.extra.governance.availableAt, "the refusal names when execution becomes available");
  // break-glass freeze remains unaffected by ALL of this configuration
  const pause = await POST(["wallet", "v4", "requests"], { vaultId: VAULT_ID, action: "ownerPause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner) });
  assert.equal(pause.status, 201);
  const assignments = await org.loadAssignments(config);
  await org.unassignVault(config, { vaultId: VAULT_ID, expectedVersion: assignments.version });
});

test("classifier unit matrix at the server module: matrix honesty + fail-closed derivations", async () => {
  const manifest = await seed();
  // not governed
  assert.deepEqual(governance.classifyActionV4(config, manifest, "agentSpend", {}), { governed: false });
  assert.deepEqual(governance.classifyActionV4(config, manifest, "ownerTopUp", {}), { governed: false });
  // break-glass
  assert.deepEqual(governance.classifyActionV4(config, manifest, "ownerPause", {}), { governed: false, breakGlass: true });
  assert.deepEqual(governance.classifyActionV4(config, manifest, "ownerRecover", {}), { governed: false, breakGlass: true });
  // unknown action fails closed
  assert.throws(() => governance.classifyActionV4(config, manifest, "futureMysteryOp", {}), (e) => e.code === "GOVERNANCE_ACTION_UNKNOWN");
  // reduction / expansion directions on the real registry
  const removal = governance.classifyActionV4(config, manifest, "removeAgent", { agentPk: XO(agentB) });
  assert.equal(removal.classification, "REDUCTION");
  assert.ok(removal.codes.includes("AGENT_REMOVED"));
  const addition = governance.classifyActionV4(config, manifest, "addAgent", { agent: NEW_AGENT });
  assert.equal(addition.classification, "EXPANSION");
  // a no-op proposal refuses (NO_CHANGE)
  assert.throws(
    () => governance.classifyActionV4(config, manifest, "rePolicyAgent", { agentPk: XO(agentA), agent: { ...agentEntry(agentA, [recipient]) } }),
    (e) => e.code === "NO_CHANGE"
  );
});
