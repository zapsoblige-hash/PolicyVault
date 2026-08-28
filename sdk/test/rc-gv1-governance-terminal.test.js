"use strict";

/*
 * RC-GV-1 REGRESSION + ADVERSARIAL SUITE — governance proposal lifecycle
 * terminality (finding RC-GV-1, docs/postlaunch/rc-mainnet-acceptance-evidence.md
 * §5.6; remediation evidence docs/postlaunch/rc-gv1-RED-evidence.txt).
 *
 * THE LIVE DEFECT (mainnet acceptance, 2026-08-27 03:25:07 UTC): a
 * governance proposal that had been ENFORCED/CONSUMED (audit spine
 * GOVERNANCE_PROPOSAL_CREATED -> GOVERNANCE_APPROVAL_COLLECTED ->
 * GOVERNANCE_ENFORCED) later ACCEPTED a cancel and its stored record's
 * terminal status read CANCELLED — misstating history. Root cause:
 * markProposalConsumed stamped lastConsumed* evidence but never left
 * status "OPEN", so cancelProposal's only guard (status !== "OPEN")
 * passed on an already-consumed proposal.
 *
 * OWNER REQUIREMENTS PINNED HERE (verbatim, binding):
 *   - once a proposal is CONSUMED, that state is terminal;
 *   - cancel-after-consume must refuse deterministically;
 *   - cancellation is valid only in states the state machine permits;
 *   - a consumed approval may not be reopened, relabeled, replayed, or
 *     made reusable;
 *   - audit history preserves the true sequence permanently.
 *
 * Everything here is HOSTED-COORDINATION lifecycle truth (the covenant
 * remains the only financial authority — unchanged by this fix). Digest
 * computation, signature verification, authority classification,
 * approval thresholds, and consumption semantics are asserted UNCHANGED.
 *
 * Layer: SDK (server integration over a temp JSON data root, real
 * api.handle + real v0.4 build pipeline) + module-level determinism
 * (direct governance.js calls — exactly the api.js usage contract) +
 * SABOTAGE (mutation sensitivity: neutralizing the guard resurrects the
 * live defect). Serialized runner required (sabotage mutates source
 * in-place; docs/test-plan.md rule 7).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { handle, loadConfig } = require("../../server/src/api");
const { buildAgentTreeV4, normalizeAgentPolicyV4 } = require("../src/agent-merkle-v4");
const { buildRecipientTree } = require("../src/recipient-merkle-v3");
const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = require("../src/vault-state-v4");
const { compileExactStateV4 } = require("../src/contract-compiler-v4");
const { MANIFEST_SCHEMA_V4, persistManifestV4 } = require("../src/manifest-v4");
const { getStore, Categories } = require("../src/store");
const governance = require("../../server/src/governance");

const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pv-rcgv1-"));
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

const VAULT_ID = "37".repeat(32);
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
  const outTxId = (0x50 + seedCounter).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
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
    label: "rc-gv1 test", status: over.paused === "1" ? "PAUSED" : "ACTIVE", template, agentRegistry: registry,
    live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: outTxId, index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
    creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
  });
}

const POST = (segs, body) => handle(config, "POST", segs, {}, body);
const GET = (segs, query) => handle(config, "GET", segs, query ?? {}, null);
async function expectThrow(promise, status, code) {
  try {
    await promise;
    assert.fail(`expected an API error (${code ?? "any"})`);
  } catch (e) {
    if (e.code === "ERR_ASSERTION") throw e;
    if (status !== undefined) assert.equal(e.status, status, `status ${e.status} != ${status}: ${e.message}`);
    if (code !== undefined) assert.equal(e.code, code, `code ${e.code} != ${code}: ${e.message}`);
    return e;
  }
}
const fuelAt = (txByte, index) => ({ outpoint: { transactionId: txByte.repeat(32), index }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
const ownerFuel = () => fuelAt("43", 1);

const NEW_AGENT = {
  agentPk: XO(KEY(0x55)), maxPerSpend: (10n * KAS).toString(), periodBudget: (30n * KAS).toString(),
  periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
  approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
  recipients: [XO(recipient)]
};

async function proposeAndApprove(action, params) {
  const created = await POST(["governance", "proposals"], { vaultId: VAULT_ID, action, params });
  assert.equal(created.status, 201);
  const proposal = created.body.proposal;
  const signature = SIGN(owner, proposal.approvalMessage);
  const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], {
    approverAddress: ADDR(owner), signature
  });
  assert.equal(approved.status, 200);
  return approved.body.proposal;
}

/* Create a proposal WITHOUT approvals (cancel paths need none). */
async function proposeOnly(action, params) {
  const created = await POST(["governance", "proposals"], { vaultId: VAULT_ID, action, params });
  assert.equal(created.status, 201);
  return created.body.proposal;
}

const proposalFile = (id) => path.join(dataRoot, "governance", "proposals", `${id}.json`);
const readRecordFile = (id) => JSON.parse(fs.readFileSync(proposalFile(id), "utf8"));
const writeRecordFile = (id, record) => fs.writeFileSync(proposalFile(id), JSON.stringify(record));

function auditResultsFor(proposalId) {
  const file = path.join(dataRoot, "audit", "events.log");
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((e) => e.proposalId === proposalId)
    .map((e) => e.result);
}

/* ============================================================== */
/* 1. THE LIVE DEFECT, reproduced at the full API surface          */
/* ============================================================== */

test("RC-GV-1 mirror: cancel after ENFORCED consumption refuses; the record's terminal status stays CONSUMED; audit keeps the true sequence", async () => {
  await seed(REGISTRY, { paused: "1" }); // the live incident action was ownerUnpause on a paused vault
  const proposal = await proposeAndApprove("ownerUnpause", {});
  const built = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "ownerUnpause", params: { fuel: ownerFuel() }, signerAddress: ADDR(owner), proposalId: proposal.proposalId
  });
  assert.equal(built.status, 201);
  const requestId = built.body.request.requestId;

  // Consumption is now the record's TERMINAL status (the web layer already
  // renders CONSUMED — web/governance-ui.js — the server must present it).
  const afterConsume = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(afterConsume.body.proposal.status, "CONSUMED", "consumed proposal presents status CONSUMED");
  assert.equal(afterConsume.body.proposal.lastConsumedRequestId, requestId);

  // THE FIX: cancel-after-consume refuses deterministically (live defect: it was accepted).
  await expectThrow(POST(["governance", "proposals", proposal.proposalId, "cancel"], {}), 409, "GOVERNANCE_PROPOSAL_TERMINAL");

  // The durable record still states the truth.
  const record = readRecordFile(proposal.proposalId);
  assert.equal(record.status, "CONSUMED", "stored terminal status is CONSUMED, not CANCELLED");
  assert.equal(record.lastConsumedRequestId, requestId);
  assert.equal(record.cancelledAt, undefined, "no cancellation fields were stamped by the refused cancel");
  assert.equal(record.cancelledBy, undefined);

  // Audit history preserves the true sequence permanently — and the
  // refused cancel appended NO cancellation event.
  const results = auditResultsFor(proposal.proposalId);
  assert.deepEqual(
    results.filter((r) => r.startsWith("GOVERNANCE")),
    ["GOVERNANCE_PROPOSAL_CREATED", "GOVERNANCE_APPROVAL_COLLECTED", "GOVERNANCE_ENFORCED"],
    "audit spine is CREATED -> APPROVAL_COLLECTED -> ENFORCED with no CANCELLED event"
  );

  // Presentation still refuses to relabel.
  const again = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(again.body.proposal.status, "CONSUMED");
});

/* ============================================================== */
/* 2. A consumed proposal is never reusable                        */
/* ============================================================== */

test("replay: a consumed proposal refuses re-admission at the earliest gate and refuses further approvals", async () => {
  await seed();
  const proposal = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const first = await POST(["wallet", "v4", "requests"], {
    vaultId: VAULT_ID, action: "addAgent", params: { fuel: ownerFuel(), agent: NEW_AGENT },
    signerAddress: ADDR(owner), proposalId: proposal.proposalId
  });
  assert.equal(first.status, 201);

  // A SECOND build under the same proposal (different fuel, so the frozen
  // bytes and intent manifest differ — the intent-conflict guard cannot
  // mask the governance hole) must refuse: the proposal is CONSUMED.
  const e = await expectThrow(
    POST(["wallet", "v4", "requests"], {
      vaultId: VAULT_ID, action: "addAgent", params: { fuel: fuelAt("44", 2), agent: NEW_AGENT },
      signerAddress: ADDR(owner), proposalId: proposal.proposalId
    }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  assert.match(e.message, /CONSUMED/, "the refusal names the terminal state");

  // Approval collection on a consumed proposal refuses too.
  const sig = SIGN(owner, proposal.approvalMessage);
  const e2 = await expectThrow(
    POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: sig }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  assert.match(e2.message, /CONSUMED/);
});

/* ============================================================== */
/* 3. Cancellation state machine                                   */
/* ============================================================== */

test("duplicate cancel refuses GOVERNANCE_PROPOSAL_CLOSED (preserved behavior); CANCELLED is terminal against consumption", async () => {
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const cancelled = await POST(["governance", "proposals", proposal.proposalId, "cancel"], {});
  assert.equal(cancelled.body.proposal.status, "CANCELLED");

  // Duplicate cancel: deterministic refusal, same code as before this fix.
  const e = await expectThrow(POST(["governance", "proposals", proposal.proposalId, "cancel"], {}), 409, "GOVERNANCE_PROPOSAL_CLOSED");
  assert.match(e.message, /CANCELLED/);
  assert.equal(auditResultsFor(proposal.proposalId).filter((r) => r === "GOVERNANCE_PROPOSAL_CANCELLED").length, 1, "exactly one cancellation audit event");

  // A cancelled proposal can never record a consumption (module-level:
  // the exact api.js call shape).
  const stale = await governance.loadProposalRecord(config, proposal.proposalId);
  await expectThrow(
    governance.markProposalConsumed(config, stale, { requestId: crypto.randomUUID(), txId: null }),
    409,
    "GOVERNANCE_PROPOSAL_TERMINAL"
  );
  const record = readRecordFile(proposal.proposalId);
  assert.equal(record.status, "CANCELLED", "the cancelled terminal state survived the refused consumption");
  assert.ok(record.cancelledAt, "cancellation stamp intact");
  assert.equal(record.lastConsumedRequestId ?? null, null, "no consumption evidence was forged");
});

test("consume is idempotent for the SAME request, terminal against a DIFFERENT request (no relabel, first evidence preserved)", async () => {
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const reqX = crypto.randomUUID();
  const reqY = crypto.randomUUID();

  const rec = await governance.loadProposalRecord(config, proposal.proposalId);
  await governance.markProposalConsumed(config, rec, { requestId: reqX, txId: "aa".repeat(32) });
  const afterFirst = readRecordFile(proposal.proposalId);
  assert.equal(afterFirst.status, "CONSUMED");
  assert.equal(afterFirst.lastConsumedRequestId, reqX);

  // Same-request replay (crash/retry of the same consumption): idempotent, byte-identical record.
  const replayed = await governance.markProposalConsumed(config, await governance.loadProposalRecord(config, proposal.proposalId), { requestId: reqX, txId: "aa".repeat(32) });
  assert.equal(replayed.lastConsumedRequestId, reqX);
  assert.deepEqual(readRecordFile(proposal.proposalId), afterFirst, "idempotent replay changed nothing");

  // Different-request consumption of an already-consumed proposal: refused, evidence NOT relabeled.
  await expectThrow(
    governance.markProposalConsumed(config, await governance.loadProposalRecord(config, proposal.proposalId), { requestId: reqY, txId: null }),
    409,
    "GOVERNANCE_PROPOSAL_TERMINAL"
  );
  assert.deepEqual(readRecordFile(proposal.proposalId), afterFirst, "the first consumption evidence is permanent");
});

test("stale in-memory record cannot resurrect or relabel a terminal proposal (durable truth wins)", async () => {
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const stale = await governance.loadProposalRecord(config, proposal.proposalId); // captured while OPEN
  assert.equal(stale.status, "OPEN");

  await governance.cancelProposal({ config, proposalId: proposal.proposalId, cancelledByXOnly: XO(owner) });

  // The consumption stamp arrives with the STALE OPEN object (the exact
  // api.js shape: consumedProposal.record captured at admission time).
  await expectThrow(
    governance.markProposalConsumed(config, stale, { requestId: crypto.randomUUID(), txId: null }),
    409,
    "GOVERNANCE_PROPOSAL_TERMINAL"
  );
  const record = readRecordFile(proposal.proposalId);
  assert.equal(record.status, "CANCELLED", "stale object did not reopen/relabel the record");
  assert.equal(record.lastConsumedRequestId ?? null, null);
});

/* ============================================================== */
/* 4. Concurrency: cancel/consume races arbitrate exactly one way  */
/* ============================================================== */

test("cancel/consume race: exactly one transition wins; the loser refuses deterministically; the record equals the winner", async () => {
  await seed();
  for (let round = 0; round < 6; round++) {
    const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
    const requestId = crypto.randomUUID();
    const recForConsume = await governance.loadProposalRecord(config, proposal.proposalId);
    const [cancelR, consumeR] = await Promise.allSettled([
      governance.cancelProposal({ config, proposalId: proposal.proposalId, cancelledByXOnly: XO(owner) }),
      governance.markProposalConsumed(config, recForConsume, { requestId, txId: null })
    ]);
    const winners = [cancelR, consumeR].filter((r) => r.status === "fulfilled");
    assert.equal(winners.length, 1, `round ${round}: exactly one of cancel/consume must win (got ${winners.length})`);
    const loser = cancelR.status === "fulfilled" ? consumeR : cancelR;
    assert.equal(loser.reason.code, "GOVERNANCE_PROPOSAL_TERMINAL", `round ${round}: the loser refuses with the terminal code`);
    const record = readRecordFile(proposal.proposalId);
    if (cancelR.status === "fulfilled") {
      assert.equal(record.status, "CANCELLED", `round ${round}: record matches the cancel winner`);
      assert.equal(record.lastConsumedRequestId ?? null, null);
      assert.equal(auditResultsFor(proposal.proposalId).filter((r) => r === "GOVERNANCE_PROPOSAL_CANCELLED").length, 1);
    } else {
      assert.equal(record.status, "CONSUMED", `round ${round}: record matches the consume winner`);
      assert.equal(record.lastConsumedRequestId, requestId);
      assert.equal(auditResultsFor(proposal.proposalId).filter((r) => r === "GOVERNANCE_PROPOSAL_CANCELLED").length, 0, `round ${round}: no cancellation audit when cancel lost`);
    }
  }
});

test("concurrent duplicate cancels: exactly one succeeds, exactly one audit event", async () => {
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const results = await Promise.allSettled(
    Array.from({ length: 5 }, () => governance.cancelProposal({ config, proposalId: proposal.proposalId, cancelledByXOnly: XO(owner) }))
  );
  const ok = results.filter((r) => r.status === "fulfilled");
  assert.equal(ok.length, 1, "exactly one concurrent cancel wins");
  for (const r of results) {
    if (r.status === "rejected") assert.equal(r.reason.code, "GOVERNANCE_PROPOSAL_CLOSED");
  }
  assert.equal(readRecordFile(proposal.proposalId).status, "CANCELLED");
  assert.equal(auditResultsFor(proposal.proposalId).filter((r) => r === "GOVERNANCE_PROPOSAL_CANCELLED").length, 1, "one durable cancellation event exactly");
});

/* ============================================================== */
/* 5. Legacy records written by the PRE-FIX code                   */
/* ============================================================== */

test("legacy pre-fix shapes normalize: consumption evidence is terminal truth (OPEN+consumed and the live CANCELLED+consumed record)", async () => {
  await seed();

  // (a) The pre-fix consumed shape: status left OPEN, lastConsumed* stamped.
  const a = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const ra = readRecordFile(a.proposalId);
  ra.lastConsumedRequestId = crypto.randomUUID();
  ra.lastConsumedTxId = "bb".repeat(32);
  ra.lastConsumedAt = new Date().toISOString(); // status stays "OPEN" — exactly what the pre-fix code persisted
  writeRecordFile(a.proposalId, ra);
  const shownA = await GET(["governance", "proposals", a.proposalId]);
  assert.equal(shownA.body.proposal.status, "CONSUMED", "legacy OPEN+evidence presents as CONSUMED");
  await expectThrow(POST(["governance", "proposals", a.proposalId, "cancel"], {}), 409, "GOVERNANCE_PROPOSAL_TERMINAL");
  assert.equal(readRecordFile(a.proposalId).status, "OPEN", "the refused cancel rewrote nothing");

  // (b) The live-incident damaged shape (proposal ad72edf2 analog):
  // consumed first, cancel wrongly accepted later — status CANCELLED with
  // consumption evidence. Consumption evidence WINS: it presents CONSUMED
  // and stays terminal.
  const b = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const rb = readRecordFile(b.proposalId);
  rb.lastConsumedRequestId = crypto.randomUUID();
  rb.lastConsumedTxId = "cc".repeat(32);
  rb.lastConsumedAt = new Date().toISOString();
  rb.status = "CANCELLED";
  rb.cancelledAt = new Date().toISOString();
  rb.cancelledBy = XO(owner);
  writeRecordFile(b.proposalId, rb);
  const shownB = await GET(["governance", "proposals", b.proposalId]);
  assert.equal(shownB.body.proposal.status, "CONSUMED", "consumption evidence outranks the wrong CANCELLED label");
  const sigB = SIGN(owner, shownB.body.proposal.approvalMessage ?? "x");
  const eB = await expectThrow(
    POST(["governance", "proposals", b.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: sigB }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  assert.match(eB.message, /CONSUMED/, "gates report the effective (true) state");
  await expectThrow(POST(["governance", "proposals", b.proposalId, "cancel"], {}), 409, "GOVERNANCE_PROPOSAL_TERMINAL");
});

/* ============================================================== */
/* 6. Unknown stored status fails closed                           */
/* ============================================================== */

test("unknown stored status: transitions fail closed with GOVERNANCE_STATUS_UNKNOWN; admission gates refuse CLOSED; presentation stays honest", async () => {
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const record = readRecordFile(proposal.proposalId);
  record.status = "MYSTERY_FUTURE_STATE";
  writeRecordFile(proposal.proposalId, record);

  await expectThrow(POST(["governance", "proposals", proposal.proposalId, "cancel"], {}), 422, "GOVERNANCE_STATUS_UNKNOWN");
  await expectThrow(
    governance.markProposalConsumed(config, readRecordFile(proposal.proposalId), { requestId: crypto.randomUUID(), txId: null }),
    422,
    "GOVERNANCE_STATUS_UNKNOWN"
  );
  const sig = SIGN(owner, "irrelevant");
  const e = await expectThrow(
    POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: sig }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
  assert.match(e.message, /MYSTERY_FUTURE_STATE/);
  const shown = await GET(["governance", "proposals", proposal.proposalId]);
  assert.equal(shown.body.proposal.status, "MYSTERY_FUTURE_STATE", "presentation shows the raw unknown status (display-only; every gate refused)");
  assert.equal(readRecordFile(proposal.proposalId).status, "MYSTERY_FUTURE_STATE", "nothing rewrote the unknown record");
});

/* ============================================================== */
/* 7. The state machine is explicit and pinned                     */
/* ============================================================== */

test("the permitted-transition table is the closed machine: OPEN->{CONSUMED,CANCELLED}; CONSUMED and CANCELLED are terminal", () => {
  const t = governance.PROPOSAL_STATUS_TRANSITIONS;
  assert.ok(t && typeof t === "object", "the transition table is exported");
  assert.deepEqual(Object.keys(t).sort(), ["CANCELLED", "CONSUMED", "OPEN"]);
  assert.deepEqual([...t.OPEN].sort(), ["CANCELLED", "CONSUMED"]);
  assert.deepEqual([...t.CONSUMED], [], "CONSUMED is terminal");
  assert.deepEqual([...t.CANCELLED], [], "CANCELLED is terminal");
  assert.ok(Object.isFrozen(t), "the table is frozen");
});

/* ============================================================== */
/* 8. Approval non-reuse: a consumed proposal's approval can       */
/*    never authorize anything again (digest + proposalId binding) */
/* ============================================================== */

test("an approval bound to a consumed proposal's digest cannot authorize a new proposal (verbatim copy AND digest-field forgery both fail verification)", async () => {
  const manifest = await seed();
  const p1 = await proposeAndApprove("addAgent", { agent: NEW_AGENT });
  const r1 = await governance.loadProposalRecord(config, p1.proposalId);
  await governance.markProposalConsumed(config, r1, { requestId: crypto.randomUUID(), txId: "dd".repeat(32) });

  await new Promise((r) => setTimeout(r, 5)); // force distinct createdAt -> distinct canonical digest
  const p2 = await proposeOnly("addAgent", { agent: NEW_AGENT }); // same action+params, NO approval
  assert.notEqual(p2.proposalDigest, p1.proposalDigest, "canonical digests are proposal-instance-specific");

  const store = getStore(config);
  const ownerXo = XO(owner);
  const oldRow = await store.read(Categories.GOVERNANCE_APPROVAL, `${p1.proposalDigest}-${ownerXo}`);
  assert.ok(oldRow, "the consumed proposal's verified approval row exists");

  // Transplant 1: verbatim copy of the old approval row under the new digest key.
  await store.write(Categories.GOVERNANCE_APPROVAL, `${p2.proposalDigest}-${ownerXo}`, oldRow);
  let status = await governance.approvalStatus(config, await governance.loadProposalRecord(config, p2.proposalId), p2.proposalDigest, manifest, null);
  assert.equal(status.ownerApproved, false, "verbatim transplant fails (row digest mismatch)");

  // Transplant 2: forge the row's digest field to the new digest, keeping the old signature.
  await store.write(Categories.GOVERNANCE_APPROVAL, `${p2.proposalDigest}-${ownerXo}`, { ...oldRow, proposalDigest: p2.proposalDigest, proposalId: p2.proposalId });
  status = await governance.approvalStatus(config, await governance.loadProposalRecord(config, p2.proposalId), p2.proposalDigest, manifest, null);
  assert.equal(status.ownerApproved, false, "digest-field forgery fails (the signature covers the OLD proposalId+digest message)");

  // The admission gate therefore refuses the new proposal outright.
  const gate = governance.classifyActionV4(config, manifest, "addAgent", { agent: NEW_AGENT });
  await expectThrow(
    governance.requireApprovedProposal({ config, manifest, vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT }, proposalId: p2.proposalId, gate, controls: null }),
    409,
    "GOVERNANCE_APPROVALS_INSUFFICIENT"
  );

  // Sanity (the negative is not vacuous): a REAL fresh owner approval on
  // the new digest satisfies the same gate — signature verification and
  // threshold semantics are UNCHANGED by this fix.
  await store.remove(Categories.GOVERNANCE_APPROVAL, `${p2.proposalDigest}-${ownerXo}`);
  const sig = SIGN(owner, governance.approvalMessageText(config, p2.proposalId, p2.proposalDigest));
  await governance.collectProposalApproval({ config, proposalId: p2.proposalId, approverAddress: ADDR(owner), signature: sig });
  const admitted = await governance.requireApprovedProposal({ config, manifest, vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT }, proposalId: p2.proposalId, gate, controls: null });
  assert.equal(admitted.record.proposalId, p2.proposalId);

  // And the consumed proposal itself refuses re-admission with its own intact approval.
  await expectThrow(
    governance.requireApprovedProposal({ config, manifest, vaultId: VAULT_ID, action: "addAgent", params: { agent: NEW_AGENT }, proposalId: p1.proposalId, gate, controls: null }),
    409,
    "GOVERNANCE_PROPOSAL_CLOSED"
  );
});

/* ============================================================== */
/* 9. Transition lock hygiene                                      */
/* ============================================================== */

test("transition locks leave no residue; a crashed holder is reclaimed deterministically; a live foreign holder fails closed BUSY; locks never appear in listings", async () => {
  await seed();
  const store = getStore(config);

  // No xlock- residue from all prior transitions in this suite.
  const residue = (await store.listKeys(Categories.GOVERNANCE_PROPOSAL)).filter((k) => k.startsWith("xlock-"));
  assert.deepEqual(residue, [], "every completed transition released its lock");

  // A crashed (stale) holder is reclaimed and the transition proceeds.
  const p = await proposeOnly("addAgent", { agent: NEW_AGENT });
  await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xlock-${p.proposalId}`, {
    schema: "policyvault-governance-transition-lock/v1", proposalId: p.proposalId, holderToken: "dead-holder",
    createdAt: new Date(Date.now() - 60_000).toISOString(), createdAtMs: Date.now() - 60_000
  });
  const cancelled = await governance.cancelProposal({ config, proposalId: p.proposalId, cancelledByXOnly: XO(owner) });
  assert.equal(cancelled.status, "CANCELLED", "stale lock reclaimed; cancel proceeded");
  assert.equal(await store.read(Categories.GOVERNANCE_PROPOSAL, `xlock-${p.proposalId}`), null, "reclaimed lock released");

  // A LIVE foreign holder makes the transition fail closed (bounded retry, then BUSY) — nothing durable changes.
  const q = await proposeOnly("addAgent", { agent: NEW_AGENT });
  await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xlock-${q.proposalId}`, {
    schema: "policyvault-governance-transition-lock/v1", proposalId: q.proposalId, holderToken: "live-holder",
    createdAt: new Date().toISOString(), createdAtMs: Date.now()
  });
  await expectThrow(governance.cancelProposal({ config, proposalId: q.proposalId, cancelledByXOnly: XO(owner) }), 409, "GOVERNANCE_TRANSITION_BUSY");
  assert.equal(readRecordFile(q.proposalId).status, "OPEN", "the refused transition changed nothing");
  await store.remove(Categories.GOVERNANCE_PROPOSAL, `xlock-${q.proposalId}`);
  const done = await governance.cancelProposal({ config, proposalId: q.proposalId, cancelledByXOnly: XO(owner) });
  assert.equal(done.status, "CANCELLED");

  // Lock records never surface as proposals.
  await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, `xlock-${crypto.randomUUID()}`, {
    schema: "policyvault-governance-transition-lock/v1", proposalId: "orphan", holderToken: "t",
    createdAt: new Date().toISOString(), createdAtMs: Date.now()
  });
  const listed = await GET(["governance", "proposals"], { vaultId: VAULT_ID });
  for (const item of listed.body.proposals) {
    assert.equal(typeof item.proposalId, "string");
    assert.ok(!String(item.proposalId).startsWith("xlock-"), "lock records are invisible to listings");
  }
});

/* ============================================================== */
/* 10. SABOTAGE / MUTATION SENSITIVITY                             */
/* ============================================================== */

/* Neutralizing the cancel-side guard must resurrect the live defect —
 * proving the regression tests above actually depend on the guard line
 * (same in-place source-mutation technique as the SDK sabotage suites;
 * requires the serialized runner). */
test("SABOTAGE: neutralizing the cancel transition guard resurrects cancel-after-consume (and restoring it re-arms the refusal)", async () => {
  const srcPath = path.resolve(__dirname, "../../server/src/governance.js");
  const original = fs.readFileSync(srcPath, "utf8");
  const TARGET = 'if (!allowedFrom || !allowedFrom.includes("CANCELLED")) throw refuseTransition(record, from, "CANCELLED");';
  assert.ok(original.includes(TARGET), "sabotage target line present (the RC-GV-1 cancel guard)");
  const reload = () => {
    for (const k of Object.keys(require.cache)) {
      if (k.endsWith(`${path.sep}governance.js`) || k.endsWith(`${path.sep}api.js`)) delete require.cache[k];
    }
    return require("../../server/src/api");
  };
  await seed();
  const proposal = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const rec = await governance.loadProposalRecord(config, proposal.proposalId);
  await governance.markProposalConsumed(config, rec, { requestId: crypto.randomUUID(), txId: null });

  fs.writeFileSync(srcPath, original.replace(TARGET, "/* SABOTAGED */ void 0;"));
  try {
    const sabotagedApi = reload();
    const res = await sabotagedApi.handle(config, "POST", ["governance", "proposals", proposal.proposalId, "cancel"], {}, {});
    assert.equal(res.status, 200, "sabotaged guard accepted cancel-after-consume (the live RC-GV-1 defect)");
    assert.equal(readRecordFile(proposal.proposalId).status, "CANCELLED", "sabotaged code relabeled the consumed proposal's STORED record (misstating history)");
  } finally {
    fs.writeFileSync(srcPath, original);
    reload();
  }
  // Repair the damaged record the sabotaged code produced, then prove the
  // restored guard refuses again on a fresh consumed proposal.
  const restoredApi = reload();
  const p2 = await proposeOnly("addAgent", { agent: NEW_AGENT });
  const rec2 = await governance.loadProposalRecord(config, p2.proposalId);
  await require("../../server/src/governance").markProposalConsumed(config, rec2, { requestId: crypto.randomUUID(), txId: null });
  await expectThrow(restoredApi.handle(config, "POST", ["governance", "proposals", p2.proposalId, "cancel"], {}, {}), 409, "GOVERNANCE_PROPOSAL_TERMINAL");
  assert.equal(fs.readFileSync(srcPath, "utf8"), original, "source restored byte-identically");
});
