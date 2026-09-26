"use strict";
/*
 * GOVERNANCE-ATTESTATION-LADDER-01 — RC44 STORE-PATH PORT (finding FLC-01 of
 * rc44-lr-fixlist-01-confirmation; lane source de1aab2, reviewed by
 * governance-attestation-ladder-independent-01/-02).
 *
 * The RC44 finalize/submit gate (GOVERNANCE-TERMINAL-RACE-01 IR-02) decides
 * a governed v0.4 request on DURABLE proposal truth: the request is bound by
 * its own governanceProposalId or, for a request that predates that field,
 * by the intent-manifest record it CREATED; it is finalizable only while the
 * bound proposal records THIS request as its consumer. The attestation
 * evidence export read only the refusal marker, so it presented AUTHORIZED
 * for requests the gate refuses:
 *   - governed requests built on RC42 whose proposal was not consumed by
 *     them (no crash involved — the cross-version case below writes the
 *     data with a pinned a84e2a9 extraction);
 *   - the crash window between a refused consumption and the marker write;
 *   - the integrity states (proposal missing / for another vault, unknown
 *     proposal or terminal-claim schema).
 * The attestation now decides governance through the SAME helper as the
 * gate (intent-records governanceRefusalFor), after intent-manifest
 * verification and before the state refusals — the gate's precedence.
 * Evidence product only: no authority, funds or write path changes, and
 * the gate keeps throwing exactly the same errors (pinned below).
 *
 * BROADCAST EVIDENCE (review finding R1-F01, round 2; narrowed by review
 * finding R2-F01, round 3): the gate guards finalize/submit, so its
 * refusal describes only requests that have NOT yet reached the broadcast
 * pipeline. A governed request has broadcast evidence when its state is in
 * {SUBMITTING, SUBMITTED, CHAIN_VERIFIED, SUBMISSION_REJECTED,
 * RECONCILIATION_REQUIRED, TERMINATED_UNKNOWN}, or when a receipt for its
 * txId exists AND the row carries an accepted signature (attestations.js
 * SIGNED_STATES). The receipt half exists for the VAULT-RECONCILE
 * population: sdk/src/reconcile-v4.js persists a receipt (no requestId)
 * for a claimed transaction proven on chain and leaves a FINALIZED or
 * PREFLIGHT_VERIFIED row's state unchanged — the row's OWN signed
 * transaction, broadcast outside the pipeline. The receipt is keyed by
 * txId, so an UNSIGNED row can hold one only through a content-identical
 * request sharing its txId (the TWIN population: an RC42 defect row whose
 * retry with a new proposal and the same fuel executed) or tampering; the
 * 2c6e336 ladder shows no broadcast for such a row, so it is REFUSED like
 * the gate (pinned below from RC42-written twins and from a post-upgrade
 * retry built by the candidate). A request with broadcast evidence went
 * through a gate that admitted it (RC42 has no governance re-check), so:
 *   - a TERMINAL result keeps the exact pre-port (2c6e336) ladder, never a
 *     REFUSED record with txId null over a broadcast or chain-verified
 *     transaction (pinned below from RC42-written SUBMITTED,
 *     CHAIN_VERIFIED + receipt and RECONCILIATION_REQUIRED rows);
 *   - an INTEGRITY result (proposal missing / for another vault) fails
 *     closed with the gate's own 409 GOVERNANCE_PROPOSAL_UNKNOWN error
 *     (option (c)): never silently AUTHORIZED, never a REFUSED record
 *     that would erase the broadcast; unknown schemas keep the gate's 422.
 * Pre-broadcast rows (BUILT, SIGNED, FINALIZED, PREFLIGHT_VERIFIED and the
 * pre-broadcast failure states) without broadcast evidence keep the FLC-01
 * fix: REFUSED like the gate.
 *
 * The lane's bounded page-read half (attestation-page-dependencies.js /
 * attestation-page-reads.js) does not exist at RC42/RC44 and is not ported.
 *
 * Layers: SDK (real api.handle over a temp data root, real v0.4 build
 * pipeline, real attestation builder) on BOTH stores — JSON always;
 * PostgreSQL (migrations 001-011) with POLICYVAULT_TEST_PG_{PORT,USER,
 * DATABASE}; the cross-version RC42 -> RC44 case additionally needs
 * POLICYVAULT_TEST_RC42_TREE (an extraction of a84e2a9 whose writer files
 * must match the pins below — a mismatch FAILS, it never skips). Each
 * missing prerequisite SKIPS with its reason (never silently passes).
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const cp = require("child_process");
const crypto = require("crypto");

const PG = {
  host: process.env.POLICYVAULT_TEST_PG_HOST || "127.0.0.1",
  port: Number(process.env.POLICYVAULT_TEST_PG_PORT || 0),
  user: process.env.POLICYVAULT_TEST_PG_USER,
  database: process.env.POLICYVAULT_TEST_PG_DATABASE
};
const PG_AVAILABLE = Boolean(PG.port && PG.user && PG.database);
const RC42_TREE = process.env.POLICYVAULT_TEST_RC42_TREE || "";

/* The a84e2a9 (RC42) files that define what an RC42 governed build writes
 * (request row, manifest record, proposal record, store encoding, schema
 * 001-011). sha256 of the exact committed bytes. */
const RC42_WRITER_PINS = Object.freeze({
  "server/src/api.js": "2b2c52907dd02c80989e41e59df112a58df2984afc562a3d3552925998b879f9",
  "server/src/governance.js": "d473675125157e7806b60832f4baf317766b6eb03a8b6e65fdf9f584a89b5fb3",
  "server/src/intent-records.js": "a3be61ac1f91b54daf8bec1841da7ea7607742efe0e3378b4cc0cc5494e12444",
  "sdk/src/store.js": "340cc27939a32d3f988d6066c7b5e104313d346922e7f003d176ce40cbdaaee6",
  "sdk/src/wallet-requests-v4.js": "267ea76b5f580cdf10495d83721b862748f416b7c5b1dea570047dd4d3178dfe",
  "server/src/migrate.js": "5214503c431c265f783cd6bc5ab32067a4aca02c94357c9933607eb081121413",
  "server/migrations/011_org_roots.sql": "9b0655f1c6de0eed7d2bd50b93bf81d775bd214ce0d71d522c0c8cb7b9822daf",
  "sdk/src/submission-claim.js": "fa79ee52c645f7004edc04a2d02a06bd8119ab949026750df8cb9816860c7e35"
});

/* Broadcast-pipeline states (the finalize/submit gate is behind them) and
 * the pre-broadcast states the gate still guards. */
const POST_GATE_STATES = Object.freeze(["SUBMITTING", "SUBMITTED", "CHAIN_VERIFIED", "RECONCILIATION_REQUIRED", "SUBMISSION_REJECTED", "TERMINATED_UNKNOWN"]);
const PRE_BROADCAST_DEFECT_STATES = Object.freeze(["FINALIZED", "PREFLIGHT_VERIFIED"]);

/* The EXACT pre-port (2c6e336) ladder of an AUTHORIZED v0.4 request in a
 * broadcast-pipeline state (server/src/attestations.js, unchanged at
 * 2c6e336). These assertions pass on the unmodified 2c6e336 tree — that is
 * what makes them the 2c6e336 ladder. */
function historyLadder(state, txId, successorIndex) {
  const base = { decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId: null, outputs: 0, successorOutpoint: null };
  switch (state) {
    case "SUBMITTING":
      return { ...base, state: "SIGNED", disposition: "IN_PROGRESS", reached: ["AUTHORIZED", "SIGNED"] };
    case "SUBMITTED":
      return { ...base, state: "BROADCAST", disposition: "IN_PROGRESS", reached: ["AUTHORIZED", "SIGNED", "BROADCAST"], txId };
    case "CHAIN_VERIFIED":
      return { ...base, state: "CHAIN_VERIFIED", disposition: "SETTLED", reached: ["AUTHORIZED", "SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED"], txId, outputs: 1, successorOutpoint: { transactionId: txId, index: successorIndex } };
    case "RECONCILIATION_REQUIRED":
    case "TERMINATED_UNKNOWN":
      return { ...base, state: "SIGNED", disposition: "UNKNOWN", failureCode: state, reached: ["AUTHORIZED", "SIGNED"] };
    case "SUBMISSION_REJECTED":
      return { ...base, state: "SIGNED", disposition: "FAILED", failureCode: "SUBMISSION_REJECTED", reached: ["AUTHORIZED", "SIGNED"] };
    default:
      throw new Error(`no history ladder for ${state}`);
  }
}
const REFUSED_TERMINAL_LADDER = Object.freeze({ decision: "REFUSED", refusalCode: "GOVERNANCE_PROPOSAL_TERMINAL", failureCode: null, txId: null, outputs: 0, successorOutpoint: null, state: "REFUSED", disposition: "REFUSED", reached: [] });
/* The EXACT 2c6e336 ladder of an AUTHORIZED v0.4 request in a signed
 * pre-pipeline state (FINALIZED, PREFLIGHT_VERIFIED — attestations.js
 * SIGNED_STATES) with a receipt for its txId: the SIGNED rung, then the
 * receipt as the BROADCAST rung with the txId; the state is not
 * CHAIN_VERIFIED, so no chain rung and no outputs. Outside the broadcast
 * pipeline, 2c6e336 turns a receipt into a BROADCAST rung only for a row in
 * SIGNED_STATES (SIGNED, FINALIZED, PREFLIGHT_VERIFIED): the rung needs the
 * SIGNED rung before it. */
function reconciledSignedLadder(txId) {
  return { decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId, outputs: 0, successorOutpoint: null, state: "BROADCAST", disposition: "IN_PROGRESS", reached: ["AUTHORIZED", "SIGNED", "BROADCAST"] };
}
function ladderOf(attestation) {
  const o = attestation.outcome;
  return {
    decision: attestation.authorization.decision,
    refusalCode: attestation.authorization.refusalCode,
    failureCode: o.failureCode,
    txId: o.txId,
    outputs: o.chain.outputs.length,
    successorOutpoint: o.chain.successorOutpoint,
    state: o.state,
    disposition: o.disposition,
    reached: o.reached.map((r) => r.state)
  };
}

/* Advance a durable request to `target` exactly as the v0.4 pipeline
 * persists it: the state field, and for CHAIN_VERIFIED the receipt
 * (sdk/src/wallet-submit-v4.js persistReceipt shape). Driven through the
 * GIVEN tree's own modules (RC42's in the writer child, the candidate's in
 * the suite). No signature, broadcast or chain read is performed — this
 * is durable-record synthesis, labelled as such. Returns the successor
 * output index (CHAIN_VERIFIED) or null. */
async function advanceRequest(req, config, requestId, target) {
  const wr4 = req("sdk/src/wallet-requests-v4");
  const { loadManifestRecord } = req("server/src/intent-records");
  const { persistReceipt } = req("sdk/src/submission-claim");
  const r = await wr4.loadRequest(config, requestId);
  let successorIndex = null;
  if (target === "CHAIN_VERIFIED") {
    const rec = await loadManifestRecord(config, r.manifestHash);
    successorIndex = rec.manifest.effects.outputs.findIndex((o) => o.kind === "successor");
    if (successorIndex < 0) throw new Error("the recorded manifest names no successor output");
    await persistReceipt(config, {
      txId: r.txId, vaultId: r.vaultId, action: r.action,
      proof: { requestId: r.requestId, successorOutpoint: `${r.txId}:${successorIndex}`, value: rec.manifest.transaction.outputs[successorIndex].value, requiredFeeSompi: r.build.accounting.fee, actualFeeSompi: r.build.accounting.fee }
    });
  }
  r.state = target;
  await wr4.saveRequest(config, r);
  return successorIndex;
}

/* Persist the receipt the VAULT RECONCILE writes for a claimed transaction
 * proven on chain (sdk/src/reconcile-v4.js reconcileVaultV4, the
 * `persistReceipt` after `advanceFromClaim`; byte-identical at a84e2a9 and
 * 2c6e336): keyed by the txId, proof without requestId, `reconciled: true`,
 * and the request row's state is NOT changed. Driven through the GIVEN
 * tree's own persistReceipt. Durable-record synthesis (no node): the chain
 * proof itself is not performed. Returns the successor output index. */
async function persistReconcileReceipt(req, config, requestId) {
  const wr4 = req("sdk/src/wallet-requests-v4");
  const { loadManifestRecord } = req("server/src/intent-records");
  const { persistReceipt } = req("sdk/src/submission-claim");
  const r = await wr4.loadRequest(config, requestId);
  const rec = await loadManifestRecord(config, r.manifestHash);
  const successorIndex = rec.manifest.effects.outputs.findIndex((o) => o.kind === "successor");
  if (successorIndex < 0) throw new Error("the recorded manifest names no successor output");
  await persistReceipt(config, {
    txId: r.txId, vaultId: r.vaultId, action: r.action,
    proof: { successorOutpoint: `${r.txId}:${successorIndex}`, value: rec.manifest.transaction.outputs[successorIndex].value, reconciled: true }
  });
  return successorIndex;
}

const KAS = 100000000n;

/* One kit over ONE tree's modules: the RC42 writer and the candidate use
 * the identical scenario code, each against its own tree. */
function makeKit(req, config) {
  const { handle } = req("server/src/api");
  const { buildAgentTreeV4, normalizeAgentPolicyV4 } = req("sdk/src/agent-merkle-v4");
  const { buildRecipientTree } = req("sdk/src/recipient-merkle-v3");
  const { normalizeStateV4, computeStateIdV4, stateToJsonV4, CONTRACT_VERSION_V4 } = req("sdk/src/vault-state-v4");
  const { compileExactStateV4 } = req("sdk/src/contract-compiler-v4");
  const { MANIFEST_SCHEMA_V4, persistManifestV4 } = req("sdk/src/manifest-v4");
  const kaspa = require(config.rustyKaspaModule);
  const KEY = (v) => new kaspa.PrivateKey(v.toString(16).padStart(2, "0").repeat(32));
  const XO = (p) => p.toPublicKey().toXOnlyPublicKey().toString().toLowerCase();
  const ADDR = (p) => p.toPublicKey().toAddress(config.networkId).toString();
  const SIGN = (p, message) => kaspa.signMessage({ message, privateKey: p.toString() });
  const owner = KEY(1);
  const agentA = KEY(0x1e);
  const recipient = KEY(0x28);
  const agentEntry = (kp, recipients) => ({
    agentPk: XO(kp), maxPerSpend: (20n * KAS).toString(), periodBudget: (50n * KAS).toString(),
    periodLengthDaa: "864000", periodStartDaa: "541000000", periodSpent: "0",
    approvalThreshold: (5n * KAS).toString(), agentMaxFeePerTx: (1n * KAS).toString(),
    recipients: recipients.map(XO)
  });
  const REGISTRY = [agentEntry(agentA, [recipient])];
  async function seed(vaultId, label) {
    const template = { owner: XO(owner), vaultId };
    const policies = REGISTRY.map((e) => normalizeAgentPolicyV4({ ...e, agentRecipientRoot: buildRecipientTree(e.recipients).root }));
    const agentRoot = buildAgentTreeV4(policies).root;
    const state = normalizeStateV4({ protectedValue: (1000n * KAS).toString(), feeReserve: (5n * KAS).toString(), paused: "1", agentRoot, approvers: [], approvalM: "0", policyNonce: "0" });
    const compiled = compileExactStateV4({ config, template, state });
    const stateId = computeStateIdV4({ networkId: config.networkId, template, state });
    return persistManifestV4(config, {
      schema: MANIFEST_SCHEMA_V4, contractVersion: CONTRACT_VERSION_V4, networkId: config.networkId, vaultId,
      label, status: "PAUSED", template, agentRegistry: REGISTRY,
      live: { state: stateToJsonV4(state), stateId, outpoint: { transactionId: "51".repeat(32), index: 0 }, outpointValue: (state.protectedValue + state.feeReserve).toString(), scriptSha256: compiled.scriptSha256, covenantId: "41".repeat(32) },
      creationTxId: "42".repeat(32), latestTransitionTxId: null, lastTransition: null
    });
  }
  const POST = (segs, body) => handle(config, "POST", segs, {}, body);
  const GET = (segs, query = {}) => handle(config, "GET", segs, query, null);
  const fuel = (tag) => ({ outpoint: { transactionId: tag.repeat(32), index: 1 }, amount: (100n * KAS).toString(), scriptPublicKeyHex: `20${XO(owner)}ac` });
  async function proposeAndApprove(vaultId, action, params) {
    const created = await POST(["governance", "proposals"], { vaultId, action, params });
    if (created.status !== 201) throw new Error(`propose: ${created.status} ${JSON.stringify(created.body).slice(0, 200)}`);
    const proposal = created.body.proposal;
    const approved = await POST(["governance", "proposals", proposal.proposalId, "approvals"], { approverAddress: ADDR(owner), signature: SIGN(owner, proposal.approvalMessage) });
    if (approved.status !== 200) throw new Error(`approve: ${approved.status} ${JSON.stringify(approved.body).slice(0, 200)}`);
    return approved.body.proposal;
  }
  const build = (vaultId, proposalId, tag, action = "ownerUnpause", params = {}) =>
    POST(["wallet", "v4", "requests"], { vaultId, action, params: { ...params, fuel: fuel(tag) }, signerAddress: ADDR(owner), ...(proposalId ? { proposalId } : {}) });
  return { XO, owner, seed, POST, GET, fuel, proposeAndApprove, build };
}

function sha256File(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

/* ======================================================================
 * RC42 WRITER (child process; executes ONLY a84e2a9 modules). The exact
 * scenario of the confirmation probe (rc44-lr-fixlist-01-confirmation
 * probe/phase1-rc42.js): (B) a control governed build consumed normally;
 * (A) the RC42 defect — a cancel lands between build admission and
 * consumption, the build answers 409 GOVERNANCE_PROPOSAL_TERMINAL but a
 * BUILT request persists with no governanceProposalId and no marker.
 * ==================================================================== */
if (process.argv[2] === "rc42-writer") {
  const input = JSON.parse(process.argv[3]);
  const R = (p) => require(path.join(input.tree, p));
  (async () => {
    const { loadConfig } = R("server/src/api");
    const config = input.backend === "postgres"
      ? loadConfig({ persistenceBackend: "postgres", pgHost: input.pg.host, pgPort: input.pg.port, pgUser: input.pg.user, pgDatabase: input.pg.database, pgNoTls: true, hostedDevOpen: true, dataRoot: input.dataRoot, rustyKaspaModule: process.env.PV_KASPA_MODULE })
      : loadConfig({ dataRoot: input.dataRoot, rustyKaspaModule: process.env.PV_KASPA_MODULE });
    let store = null;
    if (input.backend === "postgres") store = await R("sdk/src/store").openPgStore(config, { migrate: true }); // RC42's own migrator: 001-011
    try {
      const wr4 = R("sdk/src/wallet-requests-v4");
      const governance = R("server/src/governance");
      const kit = makeKit(R, config);
      const vaultId = input.vaultId;
      await kit.seed(vaultId, "rc42 writer");
      const { assertRequestManifestVerified } = R("server/src/intent-records");
      const rc42Gate = async (requestId) => {
        try {
          await assertRequestManifestVerified(config, await wr4.loadRequest(config, requestId));
          return "admits";
        } catch (e) {
          return `${e.status} ${e.code}`;
        }
      };
      const out = { backend: input.backend, networkId: config.networkId, cases: {} };
      const consumed = async (vid, tag) => {
        const p = await kit.proposeAndApprove(vid, "ownerUnpause", {});
        const built = await kit.build(vid, p.proposalId, tag);
        return { proposalId: p.proposalId, status: built.status, requestId: built.body?.request?.requestId ?? null };
      };
      // (A) the RC42 defect: cancel injected between admission and consumption
      const defect = async (vid, tag) => {
        const p = await kit.proposeAndApprove(vid, "ownerUnpause", {});
        const before = new Set((await wr4.listVaultRequests(config, vid)).map((r) => r.requestId));
        const originalAdmit = governance.requireApprovedProposal;
        governance.requireApprovedProposal = async (args) => {
          const admitted = await originalAdmit(args);
          await governance.cancelProposal({ config, proposalId: args.proposalId, cancelledByXOnly: kit.XO(kit.owner) });
          return admitted;
        };
        let buildOutcome;
        try {
          const r = await kit.build(vid, p.proposalId, tag);
          buildOutcome = { status: r.status, code: r.body?.error?.code ?? null };
        } catch (e) {
          buildOutcome = { threw: true, status: e.status ?? null, code: e.code ?? null };
        } finally {
          governance.requireApprovedProposal = originalAdmit;
        }
        const created = (await wr4.listVaultRequests(config, vid)).map((r) => r.requestId).filter((id) => !before.has(id));
        return { proposalId: p.proposalId, buildOutcome, requestIds: created };
      };
      // (B) control: an ordinary consumed governed build on RC42
      out.control = await consumed(vaultId, "c1");
      out.defect = await defect(vaultId, "c2");
      /* Post-gate population (review finding R1-F01): RC42 has no governance
       * re-check, so its finalize/submit gate admits the defect row and the
       * row can reach every pipeline state. One fresh vault per case; RC42's
       * own gate is asked on the row before and after the advance; the
       * advance is driven through RC42's own modules (state + receipt). */
      let n = 0;
      const nextVault = () => `${input.vaultPrefix}${(0x10 + n++).toString(16)}`;
      const advanced = async (name, kind, target) => {
        const vid = nextVault();
        await kit.seed(vid, `rc42 writer ${name}`);
        const made = kind === "control" ? await consumed(vid, "c3") : await defect(vid, "c4");
        const requestId = kind === "control" ? made.requestId : made.requestIds.length === 1 ? made.requestIds[0] : null;
        if (!requestId) throw new Error(`${name}: expected exactly one durable request, got ${JSON.stringify(made)}`);
        const gateBuilt = await rc42Gate(requestId);
        const successorIndex = await advanceRequest(R, config, requestId, target);
        const gateAdvanced = await rc42Gate(requestId);
        out.cases[name] = { kind, target, vaultId: vid, proposalId: made.proposalId, requestId, buildOutcome: made.buildOutcome ?? { status: made.status }, rc42GateBuilt: gateBuilt, rc42GateAdvanced: gateAdvanced, successorIndex };
      };
      for (const target of [...PRE_BROADCAST_DEFECT_STATES, ...POST_GATE_STATES]) await advanced(`DEF_${target}`, "defect", target);
      await advanced("CTRL_CV", "control", "CHAIN_VERIFIED"); // executed control (never mutated)
      await advanced("CTRL_CV_INTEGRITY", "control", "CHAIN_VERIFIED"); // executed control, mutated by the integrity test
      await advanced("DEF_CV_INTEGRITY", "defect", "CHAIN_VERIFIED"); // executed defect, mutated by the integrity test
      /* Content-identical TWIN pair (review finding R2-F01; the reviewer's
       * writer-rc42.js scenario, with this suite's injection point). On ONE
       * vault: the RC42 defect creator (build 409, a BUILT row that CREATED
       * the manifest record naming its CANCELLED proposal), then a retry
       * with a NEW proposal and the SAME fuel. Identical transaction bytes
       * give the same txId and the shared manifest record; the retry is
       * consumed and advanced to CHAIN_VERIFIED + receipt through RC42's own
       * modules, so the receipt keyed by the shared txId also exists for the
       * never-signed creator row. */
      {
        const vid = nextVault();
        await kit.seed(vid, "rc42 writer twin");
        const creator = await defect(vid, "c5");
        if (creator.requestIds.length !== 1) throw new Error(`twin creator: expected exactly one durable request, got ${JSON.stringify(creator)}`);
        const creatorId = creator.requestIds[0];
        const creatorGateBuilt = await rc42Gate(creatorId);
        const sharer = await consumed(vid, "c5");
        if (sharer.status !== 201 || !sharer.requestId) throw new Error(`twin sharer: build answered ${sharer.status}`);
        const sharerGateBuilt = await rc42Gate(sharer.requestId);
        const successorIndex = await advanceRequest(R, config, sharer.requestId, "CHAIN_VERIFIED");
        const c = await wr4.loadRequest(config, creatorId);
        const s = await wr4.loadRequest(config, sharer.requestId);
        out.cases.TWIN_DEF_CREATOR_BUILT = { kind: "defect", target: "BUILT", vaultId: vid, proposalId: creator.proposalId, requestId: creatorId, buildOutcome: creator.buildOutcome, rc42GateBuilt: creatorGateBuilt, rc42GateAfterTwinExecuted: await rc42Gate(creatorId), successorIndex: null };
        out.cases.TWIN_SHARER_CV = { kind: "control", target: "CHAIN_VERIFIED", vaultId: vid, proposalId: sharer.proposalId, requestId: sharer.requestId, buildOutcome: { status: sharer.status }, rc42GateBuilt: sharerGateBuilt, rc42GateAdvanced: await rc42Gate(sharer.requestId), successorIndex };
        out.twin = { sameTx: c.txId === s.txId, sameManifest: c.manifestHash === s.manifestHash };
      }
      /* The POST-UPGRADE twin (review finding R2-F01, probe
       * twin-post-upgrade.js): RC42 writes only the defect creator; the
       * candidate suite builds the ordinary retry itself after the upgrade. */
      {
        const vid = nextVault();
        await kit.seed(vid, "rc42 writer twin post-upgrade");
        const made = await defect(vid, "c6");
        if (made.requestIds.length !== 1) throw new Error(`post-upgrade creator: expected exactly one durable request, got ${JSON.stringify(made)}`);
        out.cases.TWIN_PU_DEF_CREATOR_BUILT = { kind: "defect", target: "BUILT", vaultId: vid, proposalId: made.proposalId, requestId: made.requestIds[0], buildOutcome: made.buildOutcome, rc42GateBuilt: await rc42Gate(made.requestIds[0]), fuelTag: "c6", successorIndex: null };
      }
      /* The VAULT-RECONCILE population (review finding R2-F01; hostile case
       * H21): an RC42 defect row that RC42 finalized (its gate admits it),
       * whose OWN signed transaction was then proven on chain by the vault
       * reconcile — receipt without requestId, the row's state unchanged. */
      for (const target of PRE_BROADCAST_DEFECT_STATES) {
        const name = `DEF_${target}_RECONCILED`;
        const vid = nextVault();
        await kit.seed(vid, `rc42 writer ${name}`);
        const made = await defect(vid, "c7");
        if (made.requestIds.length !== 1) throw new Error(`${name}: expected exactly one durable request, got ${JSON.stringify(made)}`);
        const requestId = made.requestIds[0];
        const gateBuilt = await rc42Gate(requestId);
        await advanceRequest(R, config, requestId, target);
        const successorIndex = await persistReconcileReceipt(R, config, requestId);
        out.cases[name] = { kind: "defect", target, vaultId: vid, proposalId: made.proposalId, requestId, buildOutcome: made.buildOutcome, rc42GateBuilt: gateBuilt, rc42GateAdvanced: await rc42Gate(requestId), successorIndex };
      }
      process.stdout.write(`\nRC42-WRITER-RESULT ${JSON.stringify(out)}\n`);
    } finally {
      if (store) await store.close();
    }
  })().then(() => process.exit(0), (e) => {
    process.stderr.write(`RC42 WRITER FAILED: ${e && e.stack ? e.stack : e}\n`);
    process.exit(1);
  });
} else {
  /* ====================================================================
   * CANDIDATE SUITE
   * ================================================================== */
  const { describe, test, before, after } = require("node:test");
  const assert = require("node:assert/strict");
  const { loadConfig } = require("../../server/src/api");
  const { openPgStore, getStore, Categories } = require("../src/store");
  const wr4 = require("../src/wallet-requests-v4");
  const governance = require("../../server/src/governance");
  const { assertRequestManifestVerified, loadManifestRecord } = require("../../server/src/intent-records");
  const { buildAttestationForRequest } = require("../../server/src/attestations");
  const { computeManifestHashV1, verifyIntentManifest } = require("../../core/intent");

  const CAND = (p) => require(path.join(__dirname, "..", "..", p));
  const GOV_SOURCE = "policyvault-governance-proposal-record/v1";
  // The gate's refusals, byte-exact as 2c6e336 throws them (unchanged by the port).
  const GATE = Object.freeze({
    UNKNOWN: { status: 409, code: "GOVERNANCE_PROPOSAL_UNKNOWN", message: "the governance proposal recorded for this request no longer exists for its vault — integrity alarm, failing closed" },
    TERMINAL: { status: 409, code: "GOVERNANCE_PROPOSAL_TERMINAL", message: "the governance proposal recorded for this request was not consumed by it — refusing to finalize/submit" },
    MARKER: { status: 409, code: "GOVERNANCE_PROPOSAL_TERMINAL", message: "the governance proposal for this request was not consumed by it (terminal before consumption) — refusing to finalize/submit" }
  });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "pv-gov-ladder-"));
  const pgDbPrefix = `pv_ladder_${process.pid}_${Date.now() % 100000}`;
  let adminPool = null;
  async function admin() {
    if (!adminPool) {
      const { Pool } = require("pg");
      adminPool = new Pool({ host: PG.host, port: PG.port, user: PG.user, database: PG.database });
    }
    return adminPool;
  }
  after(async () => {
    if (adminPool) await adminPool.end();
  });

  function jsonConfig(dataRoot) {
    return loadConfig({ dataRoot, rustyKaspaModule: process.env.PV_KASPA_MODULE });
  }
  function pgConfig(database, dataRoot) {
    return loadConfig({ persistenceBackend: "postgres", pgHost: PG.host, pgPort: PG.port, pgUser: PG.user, pgDatabase: database, pgNoTls: true, hostedDevOpen: true, dataRoot, rustyKaspaModule: process.env.PV_KASPA_MODULE });
  }

  async function gateOf(config, request) {
    try {
      await assertRequestManifestVerified(config, request);
      return null;
    } catch (e) {
      return { status: e.status ?? null, code: e.code ?? null, message: e.message };
    }
  }
  async function attestOf(config, request) {
    try {
      const { attestation, sources } = await buildAttestationForRequest(config, request);
      const a = attestation.authorization;
      return { decision: a.decision, refusalCode: a.refusalCode, outcomeState: attestation.outcome.state, disposition: attestation.outcome.disposition, txId: attestation.outcome.txId, sources, producerSources: attestation.producer.sources };
    } catch (e) {
      return { threw: { status: e.status ?? null, code: e.code ?? null } };
    }
  }
  const pickGate = (g) => g && { status: g.status, code: g.code };

  /* The backend matrix: JSON always, PostgreSQL 001-011 when configured. */
  const BACKENDS = [
    { name: "json", skip: undefined },
    { name: "postgres", skip: PG_AVAILABLE ? undefined : "set POLICYVAULT_TEST_PG_{PORT,USER,DATABASE} to run the PostgreSQL (001-011) half of the ladder suite" }
  ];

  for (const backend of BACKENDS) {
    describe(`[${backend.name}] governance attestation ladder (store path)`, { skip: backend.skip }, () => {
      let config = null;
      let store = null;
      let kit = null;
      let vaultCounter = 0;
      let VAULT_ID = null;
      const dbName = `${pgDbPrefix}_${backend.name}`;

      before(async () => {
        const dataRoot = fs.mkdtempSync(path.join(work, `${backend.name}-`));
        if (backend.name === "postgres") {
          await (await admin()).query(`CREATE DATABASE ${dbName}`);
          config = pgConfig(dbName, dataRoot);
          store = await openPgStore(config, { migrate: true });
        } else {
          config = jsonConfig(dataRoot);
          store = getStore(config);
        }
        kit = makeKit(CAND, config);
      });
      after(async () => {
        if (backend.name === "postgres") {
          try { if (store) await store.close(); } catch { /* closed */ }
          await (await admin()).query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
        }
      });

      /* one fresh PAUSED vault per test (a protected request would otherwise protect the vault across tests) */
      async function seed() {
        VAULT_ID = "3d".repeat(31) + (0x10 + vaultCounter).toString(16).padStart(2, "0");
        vaultCounter += 1;
        await kit.seed(VAULT_ID, `ladder ${backend.name}`);
      }
      async function consumedBuild(tag = "43") {
        const proposal = await kit.proposeAndApprove(VAULT_ID, "ownerUnpause", {});
        const built = await kit.build(VAULT_ID, proposal.proposalId, tag);
        assert.equal(built.status, 201, JSON.stringify(built.body).slice(0, 300));
        const request = await wr4.loadRequest(config, built.body.request.requestId);
        assert.equal(request.governanceProposalId, proposal.proposalId, "RC44 binds the proposal on the durable request");
        return { proposal, request };
      }
      /* A governed build whose consumption is refused by a cancel racing
       * the build (the candidate writes its REFUSED marker). */
      async function refusedBuild() {
        const proposal = await kit.proposeAndApprove(VAULT_ID, "ownerUnpause", {});
        const before = new Set((await wr4.listVaultRequests(config, VAULT_ID)).map((r) => r.requestId));
        const originalAdmit = governance.requireApprovedProposal;
        governance.requireApprovedProposal = async (args) => {
          const admitted = await originalAdmit(args);
          await governance.cancelProposal({ config, proposalId: args.proposalId, cancelledByXOnly: kit.XO(kit.owner) });
          return admitted;
        };
        try {
          await assert.rejects(kit.build(VAULT_ID, proposal.proposalId, "44"), (e) => e.code === "GOVERNANCE_PROPOSAL_TERMINAL");
        } finally {
          governance.requireApprovedProposal = originalAdmit;
        }
        const created = (await wr4.listVaultRequests(config, VAULT_ID)).map((r) => r.requestId).filter((id) => !before.has(id));
        assert.equal(created.length, 1, "exactly one durable request was persisted by the refused build");
        const marked = await wr4.loadRequest(config, created[0]);
        assert.equal(marked.governanceConsumption, "REFUSED");
        return { marked, proposal };
      }
      const writeProposal = (id, value) => store.write(Categories.GOVERNANCE_PROPOSAL, id, value);
      const readProposalRow = (id) => store.read(Categories.GOVERNANCE_PROPOSAL, id);
      const forgeSibling = async (request, n, overrides = {}) => {
        const forged = { ...request, requestId: `ffffffff-0000-4000-8000-${String(n).repeat(12)}`, ...overrides };
        for (const k of Object.keys(overrides)) if (overrides[k] === undefined) delete forged[k];
        await wr4.saveRequest(config, forged);
        return wr4.loadRequest(config, forged.requestId);
      };

      /* ---------------- controls (pass before and after the port) ---------------- */

      test("control: an ordinary consumed governed build attests AUTHORIZED and the gate admits it", async () => {
        await seed();
        const { request } = await consumedBuild();
        assert.equal(await gateOf(config, request), null);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "AUTHORIZED");
        assert.equal(att.refusalCode, null);
        assert.equal(att.outcomeState, "AUTHORIZED");
      });

      test("control: an ungoverned request (ownerTopUp) attests AUTHORIZED, declares no governance source, and the gate admits it", async () => {
        await seed();
        const built = await kit.build(VAULT_ID, null, "45", "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() });
        assert.equal(built.status, 201, JSON.stringify(built.body).slice(0, 300));
        const request = await wr4.loadRequest(config, built.body.request.requestId);
        assert.equal(request.governanceProposalId, undefined);
        const record = await loadManifestRecord(config, request.manifestHash);
        assert.equal(record.proposalId, null, "the manifest record names no proposal");
        assert.equal(await gateOf(config, request), null);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "AUTHORIZED");
        assert.equal(att.refusalCode, null);
        assert.ok(!att.sources.includes(GOV_SOURCE), "no governance source for an ungoverned request");
      });

      test("control: a refused build WITH its marker attests REFUSED GOVERNANCE_PROPOSAL_TERMINAL; the gate throws the marker refusal (unchanged)", async () => {
        await seed();
        const { marked } = await refusedBuild();
        assert.deepEqual(await gateOf(config, marked), GATE.MARKER);
        const att = await attestOf(config, marked);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.ok(!att.sources.includes(GOV_SOURCE), "the marker decides; the proposal is not read");
      });

      test("control: a legacy SHARER (no governanceProposalId; the shared record was created by another request) is unbound — gate admits, AUTHORIZED, no governance source", async () => {
        await seed();
        const { request } = await consumedBuild();
        const sharer = await forgeSibling(request, 3, { governanceProposalId: undefined });
        const record = await loadManifestRecord(config, sharer.manifestHash);
        assert.notEqual(record.requestId, sharer.requestId, "the record names its creator, not the sharer");
        assert.equal(await gateOf(config, sharer), null, "the IR-02 gate binds only the creator");
        const att = await attestOf(config, sharer);
        assert.equal(att.decision, "AUTHORIZED");
        assert.ok(!att.sources.includes(GOV_SOURCE));
      });

      test("precedence pin: manifest fails live re-verification AND the proposal refuses — gate and ladder both say INTENT_VERIFICATION_FAILED (governance is not read)", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const record = await store.read(Categories.INTENT_MANIFEST, request.manifestHash);
        const { manifestHash: _old, ...body } = JSON.parse(JSON.stringify(record.manifest));
        void _old;
        const out0 = body.transaction.outputs[0];
        out0.value = typeof out0.value === "number" ? out0.value + 1 : (BigInt(out0.value) + 1n).toString();
        const H = computeManifestHashV1(body);
        assert.notEqual(verifyIntentManifest({ manifest: { ...body, manifestHash: H } }).ok, true, "the re-hashed body fails live verification");
        await store.write(Categories.INTENT_MANIFEST, H, { ...record, manifestHash: H, manifest: { ...body, manifestHash: H } });
        await wr4.saveRequest(config, { ...request, manifestHash: H });
        const p = await readProposalRow(proposal.proposalId);
        await writeProposal(proposal.proposalId, { ...p, lastConsumedRequestId: "ffffffff-0000-4000-8000-" + "9".repeat(12) });
        const repointed = await wr4.loadRequest(config, request.requestId);
        assert.equal((await gateOf(config, repointed)).code, "INTENT_VERIFICATION_FAILED");
        const att = await attestOf(config, repointed);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "INTENT_VERIFICATION_FAILED");
        assert.ok(!att.sources.includes(GOV_SOURCE), "decided before governance, exactly like the gate");
      });

      /* ---------------- the ladder now agrees with the gate (RED on 2c6e336) ---------------- */

      test("crash before the refusal marker: the ladder refuses on durable proposal truth exactly like the gate", async () => {
        await seed();
        const { marked } = await refusedBuild();
        const unmarked = { ...marked };
        delete unmarked.governanceConsumption;
        delete unmarked.governanceConsumptionCode;
        await wr4.saveRequest(config, unmarked);
        const reloaded = await wr4.loadRequest(config, marked.requestId);
        assert.equal(reloaded.governanceConsumption, undefined, "marker absent (simulated crash)");
        assert.deepEqual(await gateOf(config, reloaded), GATE.TERMINAL, "the gate refuses (unchanged error)");
        const att = await attestOf(config, reloaded);
        assert.equal(att.decision, "REFUSED", "the ladder never presents AUTHORIZED for a request the gate refuses");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.equal(att.outcomeState, "REFUSED");
        assert.equal(att.disposition, "REFUSED");
        assert.equal(att.txId, null);
        assert.ok(att.sources.includes(GOV_SOURCE), "the proposal record is a declared evidence source");
      });

      test("a proposal consumed by a DIFFERENT request: the bound sibling attests REFUSED like the gate; the true consumer stays AUTHORIZED", async () => {
        await seed();
        const { request: consumer } = await consumedBuild();
        const sibling = await forgeSibling(consumer, 1);
        assert.deepEqual(await gateOf(config, sibling), GATE.TERMINAL);
        const att = await attestOf(config, sibling);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.equal(await gateOf(config, consumer), null);
        const ok = await attestOf(config, consumer);
        assert.equal(ok.decision, "AUTHORIZED");
        assert.ok(ok.sources.includes(GOV_SOURCE), "a consumed governed request declares the proposal record it was decided on");
      });

      test("a governed request whose proposal record is MISSING attests REFUSED GOVERNANCE_PROPOSAL_UNKNOWN like the gate", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        await store.remove(Categories.GOVERNANCE_PROPOSAL, proposal.proposalId);
        assert.equal(await readProposalRow(proposal.proposalId), null);
        assert.deepEqual(await gateOf(config, request), GATE.UNKNOWN);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_UNKNOWN");
        assert.equal(att.outcomeState, "REFUSED");
      });

      test("a governed request whose proposal names ANOTHER vault attests REFUSED GOVERNANCE_PROPOSAL_UNKNOWN like the gate", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const row = await readProposalRow(proposal.proposalId);
        await writeProposal(proposal.proposalId, { ...row, proposal: { ...row.proposal, vaultId: "ee".repeat(32) } });
        assert.deepEqual(await gateOf(config, request), GATE.UNKNOWN);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_UNKNOWN");
      });

      test("an unknown-schema proposal record fails closed with the gate's exact error (422 GOVERNANCE_SCHEMA_UNKNOWN), never AUTHORIZED", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const row = await readProposalRow(proposal.proposalId);
        await writeProposal(proposal.proposalId, { ...row, schema: "policyvault-governance-proposal-record/v0-unknown" });
        assert.deepEqual(pickGate(await gateOf(config, request)), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" });
        assert.deepEqual(await attestOf(config, request), { threw: { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" } });
      });

      test("an unknown terminal-claim schema or status fails closed with the gate's exact error on every variant, never AUTHORIZED", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const key = `xterm-${proposal.proposalId}`;
        const claim = await readProposalRow(key);
        assert.equal(claim?.status, "CONSUMED");
        assert.equal(claim.requestId, request.requestId);
        const variants = [
          // unknown schema that still passes the store's identity check -> the claim schema check
          [{ ...claim, schema: "policyvault-governance-terminal-claim/v2", proposalId: key }, { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" }],
          // unknown (non-policyvault) schema without an identity field -> the claim schema check
          [(() => { const c = { ...claim, schema: "x-unknown-terminal-claim/1" }; delete c.proposalId; return c; })(), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" }],
          // known schema, unknown status -> the claim status check
          [{ ...claim, status: "SOMETHING_ELSE" }, { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" }],
          // unknown typed schema whose identity no longer matches its key -> the store's read-side identity check
          [{ ...claim, schema: "policyvault-governance-terminal-claim/v2" }, { status: null, code: "STORE_IDENTITY_MISMATCH" }]
        ];
        for (const [value, expected] of variants) {
          await writeProposal(key, value);
          assert.deepEqual(pickGate(await gateOf(config, request)), expected, `gate on ${JSON.stringify(value.schema)}/${value.status}`);
          assert.deepEqual(await attestOf(config, request), { threw: expected }, `ladder on ${JSON.stringify(value.schema)}/${value.status}`);
        }
        await writeProposal(key, claim); // restore: the true consumer attests AUTHORIZED again
        assert.equal(await gateOf(config, request), null);
        assert.equal((await attestOf(config, request)).decision, "AUTHORIZED");
      });

      test("crash AFTER the terminal claim (claim present, record consumption fields never landed): the consumer stays AUTHORIZED (overlay); a bound sibling is REFUSED", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const record = await readProposalRow(proposal.proposalId);
        delete record.lastConsumedRequestId; delete record.lastConsumedTxId; delete record.lastConsumedAt; delete record.consumedAt;
        record.status = "APPROVED";
        await writeProposal(proposal.proposalId, record);
        assert.equal(await gateOf(config, request), null, "the gate admits on the claim overlay");
        assert.equal((await attestOf(config, request)).decision, "AUTHORIZED");
        const sibling = await forgeSibling(request, 2);
        assert.deepEqual(await gateOf(config, sibling), GATE.TERMINAL);
        const att = await attestOf(config, sibling);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
      });

      test("RC42-shaped legacy CREATOR (no governanceProposalId, bound through the record it created): not consumed -> REFUSED like the gate; consumed -> AUTHORIZED", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        const legacy = { ...request };
        delete legacy.governanceProposalId;
        await wr4.saveRequest(config, legacy);
        const reloaded = await wr4.loadRequest(config, request.requestId);
        const record = await loadManifestRecord(config, reloaded.manifestHash);
        assert.equal(record.requestId, reloaded.requestId, "the request CREATED its record");
        assert.equal(record.proposalId, proposal.proposalId, "the record names the proposal");
        assert.equal(await gateOf(config, reloaded), null);
        const ok = await attestOf(config, reloaded);
        assert.equal(ok.decision, "AUTHORIZED");
        // the RC42 defect shape: the proposal ends CANCELLED, never consumed by this request
        const row = await readProposalRow(proposal.proposalId);
        const cancelled = { ...row, status: "CANCELLED", cancelledAt: new Date().toISOString() };
        delete cancelled.lastConsumedRequestId; delete cancelled.lastConsumedTxId; delete cancelled.lastConsumedAt; delete cancelled.consumedAt;
        await writeProposal(proposal.proposalId, cancelled);
        await store.remove(Categories.GOVERNANCE_PROPOSAL, `xterm-${proposal.proposalId}`);
        assert.deepEqual(await gateOf(config, reloaded), GATE.TERMINAL);
        const att = await attestOf(config, reloaded);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.ok(ok.sources.includes(GOV_SOURCE) && att.sources.includes(GOV_SOURCE), "bound through the creator record, so the proposal is read and declared");
      });

      test("precedence: a governed request in a refusal STATE whose proposal was consumed by another request presents the gate's GOVERNANCE_PROPOSAL_TERMINAL; consumed by itself it keeps the state code", async () => {
        await seed();
        const { proposal, request } = await consumedBuild();
        await wr4.saveRequest(config, { ...request, state: wr4.RequestState.AUTHORIZATION_FAILED });
        const failed = await wr4.loadRequest(config, request.requestId);
        const own = await attestOf(config, failed);
        assert.equal(own.decision, "REFUSED");
        assert.equal(own.refusalCode, "AUTHORIZATION_FAILED", "consumed by itself: governance does not refuse, the state does");
        const row = await readProposalRow(proposal.proposalId);
        await writeProposal(proposal.proposalId, { ...row, lastConsumedRequestId: "ffffffff-0000-4000-8000-" + "8".repeat(12) });
        await store.remove(Categories.GOVERNANCE_PROPOSAL, `xterm-${proposal.proposalId}`);
        assert.deepEqual(await gateOf(config, failed), GATE.TERMINAL);
        const att = await attestOf(config, failed);
        assert.equal(att.decision, "REFUSED");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL", "governance precedes the state refusals, as in the gate");
      });

      test("HTTP export surfaces: GET /attestations/requests/:id and /attestations/export present the ladder's decision; an unknown schema answers the gate's 422", async () => {
        await seed();
        const { marked } = await refusedBuild();
        const unmarked = { ...marked };
        delete unmarked.governanceConsumption;
        delete unmarked.governanceConsumptionCode;
        await wr4.saveRequest(config, unmarked);
        const one = await kit.GET(["attestations", "requests", marked.requestId]);
        assert.equal(one.status, 200);
        assert.equal(one.body.attestation.authorization.decision, "REFUSED");
        assert.equal(one.body.attestation.authorization.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.deepEqual(Object.keys(one.body).sort(), ["attestation", "summary", "verification"]);
        const batch = await kit.GET(["attestations", "export"], { vaultId: VAULT_ID });
        assert.equal(batch.status, 200);
        const rec = batch.body.records.find((r) => r.attestation.subject.requestId === marked.requestId);
        assert.equal(rec.attestation.authorization.decision, "REFUSED");
        assert.equal(rec.attestation.authorization.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        // unknown-schema proposal: the request route answers the gate's own error
        const { proposal: p2, request: r2 } = await consumedBuild("46");
        const row = await readProposalRow(p2.proposalId);
        await writeProposal(p2.proposalId, { ...row, schema: "policyvault-governance-proposal-record/v0-unknown" });
        await assert.rejects(kit.GET(["attestations", "requests", r2.requestId]), (e) => e.status === 422 && e.code === "GOVERNANCE_SCHEMA_UNKNOWN");
      });

      /* ---------------- broadcast evidence (review finding R1-F01, round 2) ---------------- */

      const ladderFor = async (request) => {
        const { attestation, sources } = await buildAttestationForRequest(config, request);
        return { ladder: ladderOf(attestation), sources };
      };
      const threwFor = async (request) => {
        const r = await attestOf(config, request);
        return r.threw ?? { notThrown: { decision: r.decision, refusalCode: r.refusalCode } };
      };

      test("control: an executed UNGOVERNED request (CHAIN_VERIFIED + receipt) keeps the exact ladder and declares no governance source", async () => {
        await seed();
        const built = await kit.build(VAULT_ID, null, "47", "ownerTopUp", { topUpAmountSompi: (10n * KAS).toString() });
        assert.equal(built.status, 201, JSON.stringify(built.body).slice(0, 300));
        const idx = await advanceRequest(CAND, config, built.body.request.requestId, "CHAIN_VERIFIED");
        const request = await wr4.loadRequest(config, built.body.request.requestId);
        const { ladder, sources } = await ladderFor(request);
        assert.deepEqual(ladder, historyLadder("CHAIN_VERIFIED", request.txId, idx));
        assert.ok(!sources.includes(GOV_SOURCE));
        assert.ok(sources.includes("policyvault-receipt/v1"));
      });

      test("an executed consumed governed request (CHAIN_VERIFIED + receipt) attests the exact SETTLED ladder; its INTEGRITY states fail closed with the gate's own errors — never AUTHORIZED, never a REFUSED record over the broadcast", async () => {
        await seed();
        const { proposal, request: built } = await consumedBuild("48");
        const idx = await advanceRequest(CAND, config, built.requestId, "CHAIN_VERIFIED");
        const request = await wr4.loadRequest(config, built.requestId);
        assert.equal(await gateOf(config, request), null, "consumed by itself: the gate admits");
        const ok = await ladderFor(request);
        assert.deepEqual(ok.ladder, historyLadder("CHAIN_VERIFIED", request.txId, idx));
        const row = await readProposalRow(proposal.proposalId);
        const claimKey = `xterm-${proposal.proposalId}`;
        const claim = await readProposalRow(claimKey);
        // (1) proposal record missing -> the gate's 409 GOVERNANCE_PROPOSAL_UNKNOWN, thrown (no record)
        await store.remove(Categories.GOVERNANCE_PROPOSAL, proposal.proposalId);
        assert.deepEqual(await gateOf(config, request), GATE.UNKNOWN);
        assert.deepEqual(await threwFor(request), { status: 409, code: "GOVERNANCE_PROPOSAL_UNKNOWN" }, "proposal missing on an executed request");
        await writeProposal(proposal.proposalId, row);
        // (2) proposal names another vault -> the same 409
        await writeProposal(proposal.proposalId, { ...row, proposal: { ...row.proposal, vaultId: "ee".repeat(32) } });
        assert.deepEqual(await gateOf(config, request), GATE.UNKNOWN);
        assert.deepEqual(await threwFor(request), { status: 409, code: "GOVERNANCE_PROPOSAL_UNKNOWN" }, "proposal for another vault on an executed request");
        await writeProposal(proposal.proposalId, row);
        // (3) unknown proposal schema -> the gate's 422
        await writeProposal(proposal.proposalId, { ...row, schema: "policyvault-governance-proposal-record/v0-unknown" });
        assert.deepEqual(pickGate(await gateOf(config, request)), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" });
        assert.deepEqual(await threwFor(request), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" }, "unknown proposal schema on an executed request");
        await writeProposal(proposal.proposalId, row);
        // (4) unknown terminal-claim schema -> the gate's 422
        await writeProposal(claimKey, { ...claim, schema: "policyvault-governance-terminal-claim/v2", proposalId: claimKey });
        assert.deepEqual(pickGate(await gateOf(config, request)), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" });
        assert.deepEqual(await threwFor(request), { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" }, "unknown terminal-claim schema on an executed request");
        await writeProposal(claimKey, claim);
        // restored: the exact ladder again
        assert.deepEqual((await ladderFor(request)).ladder, historyLadder("CHAIN_VERIFIED", request.txId, idx));
        // HTTP: the request route answers the gate's 409; the vault export fails closed as a whole
        await store.remove(Categories.GOVERNANCE_PROPOSAL, proposal.proposalId);
        await assert.rejects(kit.GET(["attestations", "requests", request.requestId]), (e) => e.status === 409 && e.code === "GOVERNANCE_PROPOSAL_UNKNOWN");
        await assert.rejects(kit.GET(["attestations", "export"], { vaultId: VAULT_ID }), (e) => e.status === 409 && e.code === "GOVERNANCE_PROPOSAL_UNKNOWN");
        await writeProposal(proposal.proposalId, row);
        assert.ok(ok.sources.includes(GOV_SOURCE), "the proposal record is read (integrity check) and declared");
      });

      test("a governed request NOT consumed by it (crash before the marker) that nevertheless reached the broadcast pipeline keeps the exact 2c6e336 ladder in every post-gate state; the gate still refuses (unchanged)", async () => {
        const declared = {};
        for (const target of POST_GATE_STATES) {
          await seed();
          const { marked } = await refusedBuild();
          const unmarked = { ...marked };
          delete unmarked.governanceConsumption;
          delete unmarked.governanceConsumptionCode;
          await wr4.saveRequest(config, unmarked);
          const idx = await advanceRequest(CAND, config, marked.requestId, target);
          const request = await wr4.loadRequest(config, marked.requestId);
          assert.equal(request.state, target);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, `${target}: the gate still refuses`);
          const { ladder, sources } = await ladderFor(request);
          assert.deepEqual(ladder, historyLadder(target, request.txId, idx), `${target}: the broadcast history is kept`);
          declared[target] = sources.includes(GOV_SOURCE);
        }
        // the proposal record was read (integrity check) and is declared in every state
        assert.deepEqual(declared, Object.fromEntries(POST_GATE_STATES.map((t) => [t, true])));
      });

      test("crash between the CHAIN_VERIFIED state save and the receipt persist (no receipt yet): the state alone is broadcast evidence and the 2c6e336 ladder (BROADCAST, IN_PROGRESS) is kept", async () => {
        await seed();
        const { marked } = await refusedBuild();
        const unmarked = { ...marked, state: "CHAIN_VERIFIED" };
        delete unmarked.governanceConsumption;
        delete unmarked.governanceConsumptionCode;
        await wr4.saveRequest(config, unmarked);
        const request = await wr4.loadRequest(config, marked.requestId);
        assert.equal(await store.read(Categories.RECEIPT, request.txId), null, "no receipt persisted");
        assert.deepEqual(await gateOf(config, request), GATE.TERMINAL);
        const { ladder } = await ladderFor(request);
        assert.deepEqual(ladder, { decision: "AUTHORIZED", refusalCode: null, failureCode: null, txId: request.txId, outputs: 0, successorOutpoint: null, state: "BROADCAST", disposition: "IN_PROGRESS", reached: ["AUTHORIZED", "SIGNED", "BROADCAST"] });
      });

      test("pre-broadcast rows keep the FLC-01 fix: SIGNED, FINALIZED, PREFLIGHT_VERIFIED and the pre-broadcast failure states attest REFUSED GOVERNANCE_PROPOSAL_TERMINAL like the gate", async () => {
        for (const target of ["SIGNED", "FINALIZED", "PREFLIGHT_VERIFIED", "WALLET_REJECTED", "SIGNATURE_INVALID", "PREFLIGHT_FAILED", "STALE", "CLAIM_CONFLICT"]) {
          await seed();
          const { marked } = await refusedBuild();
          const unmarked = { ...marked };
          delete unmarked.governanceConsumption;
          delete unmarked.governanceConsumptionCode;
          await wr4.saveRequest(config, unmarked);
          await advanceRequest(CAND, config, marked.requestId, target);
          const request = await wr4.loadRequest(config, marked.requestId);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, `${target}: the gate refuses`);
          assert.deepEqual((await ladderFor(request)).ladder, REFUSED_TERMINAL_LADDER, `${target}: REFUSED like the gate`);
        }
      });

      test("a persisted receipt for the request's txId on an UNSIGNED row (BUILT) is not broadcast evidence: the row carries no accepted signature and 2c6e336 shows no broadcast for it, so it is REFUSED like the gate (review finding R2-F01)", async () => {
        await seed();
        const { marked } = await refusedBuild();
        const unmarked = { ...marked };
        delete unmarked.governanceConsumption;
        delete unmarked.governanceConsumptionCode;
        await wr4.saveRequest(config, unmarked);
        const idx = await advanceRequest(CAND, config, marked.requestId, "CHAIN_VERIFIED");
        const cv = await wr4.loadRequest(config, marked.requestId);
        await wr4.saveRequest(config, { ...cv, state: "BUILT" });
        const request = await wr4.loadRequest(config, marked.requestId);
        assert.ok(idx >= 0);
        assert.equal(request.state, "BUILT");
        assert.notEqual(await store.read(Categories.RECEIPT, request.txId), null, "a receipt exists for its txId");
        assert.deepEqual(await gateOf(config, request), GATE.TERMINAL);
        const { ladder, sources } = await ladderFor(request);
        assert.deepEqual(ladder, REFUSED_TERMINAL_LADDER, "REFUSED like the gate: the receipt proves nothing about an unsigned row");
        assert.ok(sources.includes("policyvault-receipt/v1"), "the receipt was read and is declared");
      });

      test("the VAULT-RECONCILE population: a SIGNED row (FINALIZED, PREFLIGHT_VERIFIED) whose own transaction the vault reconcile proved (receipt without requestId, row state unchanged) keeps the exact 2c6e336 BROADCAST ladder; the gate still refuses (unchanged)", async () => {
        const declared = {};
        for (const target of ["FINALIZED", "PREFLIGHT_VERIFIED"]) {
          await seed();
          const { marked } = await refusedBuild();
          const unmarked = { ...marked };
          delete unmarked.governanceConsumption;
          delete unmarked.governanceConsumptionCode;
          await wr4.saveRequest(config, unmarked);
          await advanceRequest(CAND, config, marked.requestId, target);
          await persistReconcileReceipt(CAND, config, marked.requestId);
          const request = await wr4.loadRequest(config, marked.requestId);
          assert.equal(request.state, target, `${target}: the reconcile leaves the row's state unchanged`);
          const receipt = await store.read(Categories.RECEIPT, request.txId);
          assert.equal(receipt?.proof?.reconciled, true, `${target}: the vault-reconcile receipt shape`);
          assert.equal("requestId" in receipt.proof, false, `${target}: the vault-reconcile receipt names no request`);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, `${target}: the gate still refuses`);
          const { ladder, sources } = await ladderFor(request);
          assert.deepEqual(ladder, reconciledSignedLadder(request.txId), `${target}: the broadcast of its own signed transaction is kept`);
          declared[target] = sources.includes(GOV_SOURCE);
        }
        assert.deepEqual(declared, { FINALIZED: true, PREFLIGHT_VERIFIED: true }, "the proposal record was read (integrity check) and is declared");
      });

      test("a receipt for the request's txId on a row OUTSIDE SIGNED_STATES and the broadcast pipeline (AWAITING_APPROVALS, the failure states, a refusal state) is not broadcast evidence: 2c6e336 presents no broadcast for these states, so the row is REFUSED like the gate", async () => {
        for (const target of ["AWAITING_APPROVALS", "WALLET_REJECTED", "SIGNATURE_INVALID", "PREFLIGHT_FAILED", "STALE", "CLAIM_CONFLICT", "AUTHORIZATION_FAILED"]) {
          await seed();
          const { marked } = await refusedBuild();
          const unmarked = { ...marked };
          delete unmarked.governanceConsumption;
          delete unmarked.governanceConsumptionCode;
          await wr4.saveRequest(config, unmarked);
          await advanceRequest(CAND, config, marked.requestId, target);
          await persistReconcileReceipt(CAND, config, marked.requestId);
          const request = await wr4.loadRequest(config, marked.requestId);
          assert.equal(request.state, target);
          assert.notEqual(await store.read(Categories.RECEIPT, request.txId), null, `${target}: a receipt exists for its txId`);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, `${target}: the gate refuses`);
          assert.deepEqual((await ladderFor(request)).ladder, REFUSED_TERMINAL_LADDER, `${target}: REFUSED like the gate`);
        }
      });
    });
  }

  /* ====================================================================
   * CROSS-VERSION: RC42 (a84e2a9) writes, the candidate reads the SAME data
   * root / database — the exact confirmation probe scenario.
   * ================================================================== */
  function rc42Skip() {
    if (!RC42_TREE) return "set POLICYVAULT_TEST_RC42_TREE to an extraction of a84e2a9 to run the RC42 -> RC44 cross-version case";
    return undefined;
  }
  for (const backend of BACKENDS) {
    const skip = backend.skip ?? rc42Skip();
    describe(`[${backend.name}] cross-version: RC42-written governed requests read by the candidate`, { skip }, () => {
      let config = null;
      let store = null;
      let result = null;
      let kit = null;
      const dbName = `${pgDbPrefix}_x_${backend.name}`;
      const vaultId = "39".repeat(32);

      before(async () => {
        assert.ok(path.isAbsolute(RC42_TREE), "POLICYVAULT_TEST_RC42_TREE must be absolute");
        for (const [rel, pin] of Object.entries(RC42_WRITER_PINS)) {
          assert.equal(sha256File(path.join(RC42_TREE, rel)), pin, `RC42 writer file ${rel} is not the pinned a84e2a9 byte sequence`);
        }
        const dataRoot = fs.mkdtempSync(path.join(work, `x-${backend.name}-`));
        if (backend.name === "postgres") await (await admin()).query(`CREATE DATABASE ${dbName}`);
        const input = { tree: RC42_TREE, backend: backend.name, dataRoot, vaultId, vaultPrefix: "3a".repeat(31), pg: { host: PG.host, port: PG.port, user: PG.user, database: dbName } };
        const child = cp.spawnSync(process.execPath, [__filename, "rc42-writer", JSON.stringify(input)], { encoding: "utf8", env: process.env, timeout: 600000, maxBuffer: 64 * 1024 * 1024 });
        const line = (child.stdout || "").split("\n").find((l) => l.startsWith("RC42-WRITER-RESULT "));
        assert.equal(child.status, 0, `RC42 writer failed: ${(child.stderr || "").slice(-2000)}`);
        assert.ok(line, "the RC42 writer reported its result");
        result = JSON.parse(line.slice("RC42-WRITER-RESULT ".length));
        // The candidate opens the RC42-written data with NO migration.
        if (backend.name === "postgres") {
          config = pgConfig(dbName, dataRoot);
          store = await openPgStore(config); // assertSchemaCurrent: the RC42 schema (001-011) is current for the candidate
          const applied = await store.pool().query("SELECT version FROM schema_migrations ORDER BY version");
          assert.deepEqual(applied.rows.map((r) => Number(r.version)), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], "schema 001-011 exactly, applied by the RC42 migrator");
        } else {
          config = jsonConfig(dataRoot);
          store = getStore(config);
        }
        kit = makeKit(CAND, config);
      });
      after(async () => {
        if (backend.name === "postgres") {
          try { if (store) await store.close(); } catch { /* closed */ }
          await (await admin()).query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
        }
      });

      test("RC42 wrote the defect shape: build refused 409, one BUILT request, no governanceProposalId, no marker, creator record naming the CANCELLED proposal", async () => {
        assert.equal(result.control.status, 201);
        assert.deepEqual({ threw: result.defect.buildOutcome.threw, status: result.defect.buildOutcome.status, code: result.defect.buildOutcome.code }, { threw: true, status: 409, code: "GOVERNANCE_PROPOSAL_TERMINAL" });
        assert.equal(result.defect.requestIds.length, 1, "the refused RC42 build still persisted exactly one request");
        const request = await wr4.loadRequest(config, result.defect.requestIds[0]);
        assert.equal(request.state, "BUILT");
        assert.equal(typeof request.manifestHash, "string");
        assert.equal("governanceProposalId" in request, false);
        assert.equal("governanceConsumption" in request, false);
        const record = await loadManifestRecord(config, request.manifestHash);
        assert.equal(record.requestId, request.requestId);
        assert.equal(record.proposalId, result.defect.proposalId);
        const proposal = await governance.loadProposalRecord(config, result.defect.proposalId);
        assert.equal(governance.effectiveProposalStatus(proposal), "CANCELLED");
        assert.equal(proposal.lastConsumedRequestId ?? null, null);
      });

      test("control: the RC42 consumed governed build is admitted by the candidate gate and attests AUTHORIZED", async () => {
        const request = await wr4.loadRequest(config, result.control.requestId);
        assert.equal("governanceProposalId" in request, false, "RC42 never wrote the field");
        assert.equal(await gateOf(config, request), null);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "AUTHORIZED");
        assert.equal(att.refusalCode, null);
      });

      test("the RC42 defect request (no crash involved): the candidate gate refuses 409 GOVERNANCE_PROPOSAL_TERMINAL and the attestation now REFUSES with the same code", async () => {
        const request = await wr4.loadRequest(config, result.defect.requestIds[0]);
        assert.deepEqual(await gateOf(config, request), GATE.TERMINAL);
        const att = await attestOf(config, request);
        assert.equal(att.decision, "REFUSED", "never AUTHORIZED for a request the candidate gate refuses");
        assert.equal(att.refusalCode, "GOVERNANCE_PROPOSAL_TERMINAL");
        assert.equal(att.outcomeState, "REFUSED");
        assert.equal(att.disposition, "REFUSED");
        assert.equal(att.txId, null);
      });

      /* ---------------- post-gate RC42 rows (review finding R1-F01, round 2) ---------------- */

      const caseOf = (name) => {
        const c = result.cases[name];
        assert.ok(c, `the RC42 writer wrote case ${name}`);
        return c;
      };
      const loadCase = async (name) => {
        const c = caseOf(name);
        const request = await wr4.loadRequest(config, c.requestId);
        assert.equal(request.state, c.target, `${name}: the RC42-written row is in ${c.target}`);
        return { c, request };
      };

      test("RC42 wrote the post-gate population: every defect row was refused at build (409) yet RC42's own finalize/submit gate ADMITS it before and after the advance; controls consumed", async () => {
        for (const target of [...PRE_BROADCAST_DEFECT_STATES, ...POST_GATE_STATES, "CV_INTEGRITY"]) {
          const name = `DEF_${target}`;
          const c = caseOf(name);
          assert.deepEqual({ threw: c.buildOutcome.threw, status: c.buildOutcome.status, code: c.buildOutcome.code }, { threw: true, status: 409, code: "GOVERNANCE_PROPOSAL_TERMINAL" }, name);
          assert.equal(c.rc42GateBuilt, "admits", `${name}: RC42's gate admits the BUILT defect row`);
          assert.equal(c.rc42GateAdvanced, "admits", `${name}: RC42's gate admits the advanced defect row`);
          const request = await wr4.loadRequest(config, c.requestId);
          assert.equal("governanceProposalId" in request, false, `${name}: RC42 row shape (no field)`);
          assert.equal("governanceConsumption" in request, false, `${name}: RC42 row shape (no marker)`);
        }
        for (const name of ["CTRL_CV", "CTRL_CV_INTEGRITY"]) {
          const c = caseOf(name);
          assert.equal(c.buildOutcome.status, 201, name);
          assert.equal(c.rc42GateAdvanced, "admits", name);
        }
      });

      for (const target of PRE_BROADCAST_DEFECT_STATES) {
        test(`RC42 defect row in ${target} (RC42 finalized it; never broadcast): the candidate gate refuses and the attestation REFUSES — the FLC-01 fix is kept`, async () => {
          const { request } = await loadCase(`DEF_${target}`);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL);
          const { attestation } = await buildAttestationForRequest(config, request);
          assert.deepEqual(ladderOf(attestation), REFUSED_TERMINAL_LADDER);
        });
      }

      for (const target of POST_GATE_STATES) {
        test(`RC42 defect row in ${target} (past RC42's gate): the attestation keeps the exact 2c6e336 ladder on the store path, the request route and the vault export; the candidate gate is unchanged (409 TERMINAL)`, async () => {
          const { c, request } = await loadCase(`DEF_${target}`);
          const expected = historyLadder(target, request.txId, c.successorIndex);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, "the gate's own answer is unchanged");
          const { attestation } = await buildAttestationForRequest(config, request);
          assert.deepEqual(ladderOf(attestation), expected, "never REFUSED with txId null over a request RC42 sent to the broadcast pipeline");
          const one = await kit.GET(["attestations", "requests", request.requestId]);
          assert.equal(one.status, 200);
          assert.deepEqual(ladderOf(one.body.attestation), expected);
          assert.equal(one.body.verification.verdict, "STRUCTURE_VERIFIED");
          const batch = await kit.GET(["attestations", "export"], { vaultId: c.vaultId });
          assert.equal(batch.status, 200);
          const rec = batch.body.records.find((r) => r.attestation.subject.requestId === request.requestId);
          assert.deepEqual(ladderOf(rec.attestation), expected);
        });
      }

      test("control: the RC42 executed consumed governed build (CHAIN_VERIFIED + receipt) is admitted by the candidate gate and keeps the exact SETTLED ladder", async () => {
        const { c, request } = await loadCase("CTRL_CV");
        assert.equal(await gateOf(config, request), null);
        const { attestation } = await buildAttestationForRequest(config, request);
        assert.deepEqual(ladderOf(attestation), historyLadder("CHAIN_VERIFIED", request.txId, c.successorIndex));
      });

      test("RC42 executed rows in an INTEGRITY state fail closed with the gate's own errors (409 GOVERNANCE_PROPOSAL_UNKNOWN; 422 GOVERNANCE_SCHEMA_UNKNOWN) — never silently AUTHORIZED, never a REFUSED record over the broadcast", async () => {
        for (const name of ["CTRL_CV_INTEGRITY", "DEF_CV_INTEGRITY"]) {
          const { c, request } = await loadCase(name);
          const row = await store.read(Categories.GOVERNANCE_PROPOSAL, c.proposalId);
          assert.ok(row, `${name}: the proposal row exists before the integrity event`);
          await store.remove(Categories.GOVERNANCE_PROPOSAL, c.proposalId);
          assert.deepEqual(await gateOf(config, request), GATE.UNKNOWN, `${name}: gate`);
          const missing = await attestOf(config, request);
          assert.deepEqual(missing, { threw: { status: 409, code: "GOVERNANCE_PROPOSAL_UNKNOWN" } }, `${name}: proposal missing`);
          await assert.rejects(kit.GET(["attestations", "requests", request.requestId]), (e) => e.status === 409 && e.code === "GOVERNANCE_PROPOSAL_UNKNOWN");
          await assert.rejects(kit.GET(["attestations", "export"], { vaultId: c.vaultId }), (e) => e.status === 409 && e.code === "GOVERNANCE_PROPOSAL_UNKNOWN");
          await store.write(Categories.GOVERNANCE_PROPOSAL, c.proposalId, { ...row, schema: "policyvault-governance-proposal-record/v0-unknown" });
          assert.deepEqual(await attestOf(config, request), { threw: { status: 422, code: "GOVERNANCE_SCHEMA_UNKNOWN" } }, `${name}: unknown proposal schema`);
          await store.write(Categories.GOVERNANCE_PROPOSAL, c.proposalId, row);
          // restored: back to the exact ladder (CANCELLED-not-consumed for the defect, consumed for the control)
          const { attestation } = await buildAttestationForRequest(config, request);
          assert.deepEqual(ladderOf(attestation), historyLadder("CHAIN_VERIFIED", request.txId, c.successorIndex), `${name}: restored`);
        }
      });

      /* ---------------- review finding R2-F01 (round 3) ---------------- */

      /* The request route and the vault export present the same ladder as
       * the store path; the verifier checks the route's record. */
      async function assertLadderOnAllSurfaces(request, vaultId, expected, label) {
        const { attestation } = await buildAttestationForRequest(config, request);
        assert.deepEqual(ladderOf(attestation), expected, `${label}: store path`);
        const one = await kit.GET(["attestations", "requests", request.requestId]);
        assert.equal(one.status, 200, `${label}: request route`);
        assert.deepEqual(ladderOf(one.body.attestation), expected, `${label}: request route`);
        assert.equal(one.body.verification.verdict, "STRUCTURE_VERIFIED", `${label}: verifier`);
        const batch = await kit.GET(["attestations", "export"], { vaultId });
        assert.equal(batch.status, 200, `${label}: vault export`);
        const rec = batch.body.records.find((r) => r.attestation.subject.requestId === request.requestId);
        assert.ok(rec, `${label}: the vault export lists the request`);
        assert.deepEqual(ladderOf(rec.attestation), expected, `${label}: vault export`);
      }

      test("TWIN (R2-F01): RC42 wrote TWIN_DEF_CREATOR_BUILT and its content-identical retry TWIN_SHARER_CV (same txId, shared manifest record, CHAIN_VERIFIED + receipt); the never-signed creator is REFUSED like the candidate gate, never AUTHORIZED through the retry's receipt; the retry keeps its SETTLED ladder", async () => {
        assert.deepEqual(result.twin, { sameTx: true, sameManifest: true }, "the RC42 writer produced a content-identical pair");
        const { c: cc, request: creator } = await loadCase("TWIN_DEF_CREATOR_BUILT");
        const { c: sc, request: sharer } = await loadCase("TWIN_SHARER_CV");
        assert.equal(cc.vaultId, sc.vaultId);
        assert.deepEqual({ threw: cc.buildOutcome.threw, status: cc.buildOutcome.status, code: cc.buildOutcome.code }, { threw: true, status: 409, code: "GOVERNANCE_PROPOSAL_TERMINAL" }, "the creator's RC42 build was refused");
        assert.equal(sc.buildOutcome.status, 201, "the retry's RC42 build succeeded");
        assert.equal(cc.rc42GateBuilt, "admits", "RC42's own gate admits the defect creator");
        assert.equal(cc.rc42GateAfterTwinExecuted, "admits", "... and still admits it after the retry executed");
        assert.equal(sc.rc42GateAdvanced, "admits");
        assert.equal(creator.txId, sharer.txId);
        assert.equal(creator.manifestHash, sharer.manifestHash);
        assert.equal("governanceProposalId" in creator, false, "RC42 row shape (no field)");
        assert.equal("governanceConsumption" in creator, false, "RC42 row shape (no marker)");
        const record = await loadManifestRecord(config, creator.manifestHash);
        assert.equal(record.requestId, creator.requestId, "the shared record was CREATED by the defect creator");
        assert.equal(record.proposalId, cc.proposalId, "... and names the creator's CANCELLED proposal");
        const receipt = await store.read(Categories.RECEIPT, creator.txId);
        assert.equal(receipt?.proof?.requestId, sharer.requestId, "the receipt keyed by the shared txId is the retry's");
        assert.deepEqual(await gateOf(config, creator), GATE.TERMINAL, "the candidate gate refuses the creator");
        assert.equal(await gateOf(config, sharer), null, "the candidate gate admits the retry (an unbound legacy sharer)");
        await assertLadderOnAllSurfaces(creator, cc.vaultId, REFUSED_TERMINAL_LADDER, "creator");
        await assertLadderOnAllSurfaces(sharer, sc.vaultId, historyLadder("CHAIN_VERIFIED", sharer.txId, sc.successorIndex), "retry");
      });

      test("TWIN after the upgrade (R2-F01): an ordinary retry of the RC42 defect creator, built and executed on the candidate with a new proposal and the same fuel (201, same txId, shared manifest record, bound by its own field), leaves the RC42 defect row REFUSED like the gate", async () => {
        const { c, request: creator } = await loadCase("TWIN_PU_DEF_CREATOR_BUILT");
        assert.equal(c.rc42GateBuilt, "admits", "RC42's own gate admits the defect creator");
        assert.deepEqual(await gateOf(config, creator), GATE.TERMINAL);
        assert.deepEqual(ladderOf((await buildAttestationForRequest(config, creator)).attestation), REFUSED_TERMINAL_LADDER, "before the retry");
        const proposal = await kit.proposeAndApprove(c.vaultId, "ownerUnpause", {});
        const built = await kit.build(c.vaultId, proposal.proposalId, c.fuelTag);
        assert.equal(built.status, 201, JSON.stringify(built.body).slice(0, 300));
        const retryId = built.body.request.requestId;
        const retryBuilt = await wr4.loadRequest(config, retryId);
        assert.equal(retryBuilt.txId, creator.txId, "identical transaction bytes: the same txId");
        assert.equal(retryBuilt.manifestHash, creator.manifestHash, "the shared manifest record");
        assert.equal(retryBuilt.governanceProposalId, proposal.proposalId, "the retry is bound by its own field");
        assert.equal(await gateOf(config, retryBuilt), null, "the candidate gate admits the retry");
        const idx = await advanceRequest(CAND, config, retryId, "CHAIN_VERIFIED");
        const retry = await wr4.loadRequest(config, retryId);
        assert.equal((await store.read(Categories.RECEIPT, creator.txId))?.proof?.requestId, retryId, "the receipt keyed by the shared txId is the retry's");
        const after = await wr4.loadRequest(config, creator.requestId);
        assert.equal(after.state, "BUILT");
        assert.deepEqual(await gateOf(config, after), GATE.TERMINAL, "the candidate gate still refuses the defect row");
        await assertLadderOnAllSurfaces(after, c.vaultId, REFUSED_TERMINAL_LADDER, "RC42 defect row after the retry executed");
        await assertLadderOnAllSurfaces(retry, c.vaultId, historyLadder("CHAIN_VERIFIED", retry.txId, idx), "the retry");
      });

      test("the VAULT-RECONCILE population from RC42 (R2-F01, hostile case H21): RC42 defect rows that RC42 finalized (FINALIZED, PREFLIGHT_VERIFIED) and whose own transaction the vault reconcile proved keep the exact 2c6e336 BROADCAST ladder; the candidate gate refuses", async () => {
        for (const target of PRE_BROADCAST_DEFECT_STATES) {
          const name = `DEF_${target}_RECONCILED`;
          const { c, request } = await loadCase(name);
          assert.equal(c.rc42GateBuilt, "admits", `${name}: RC42's gate admits the BUILT defect row`);
          assert.equal(c.rc42GateAdvanced, "admits", `${name}: RC42's gate admits the finalized defect row`);
          const receipt = await store.read(Categories.RECEIPT, request.txId);
          assert.equal(receipt?.proof?.reconciled, true, `${name}: vault-reconcile receipt shape`);
          assert.deepEqual(await gateOf(config, request), GATE.TERMINAL, `${name}: the candidate gate refuses`);
          await assertLadderOnAllSurfaces(request, c.vaultId, reconciledSignedLadder(request.txId), name);
        }
      });
    });
  }
}
