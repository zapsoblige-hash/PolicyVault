"use strict";

/*
 * Policy-change governance — SERVER ENFORCEMENT (Program B wiring,
 * docs/postlaunch/governance-spec.md + completion-standard item 3).
 *
 * THE BOUNDARY, stated first and enforced nowhere weaker: the Kaspa
 * covenant is the hard financial authority boundary. Everything in this
 * module is HOSTED COORDINATION + DEFENSE IN DEPTH layered ABOVE it —
 * proposals, approval signatures, quorum/delay ceremony, and refusals
 * gate the hosted WORKFLOW only. They never grant, replace, weaken, or
 * substitute for the covenant's own requirement: every policy
 * transition still needs the vault owner's BIP-340 signature over the
 * exact frozen transaction bytes, verified by Kaspa consensus. A
 * compromised hosted admin/database can at most reduce or deny hosted
 * ceremony (governance-spec §9.6); it cannot expand covenant authority,
 * because consensus never reads these records.
 *
 * Enforcement rules implemented here (spec §5/§6):
 *   - the authority-delta classification is RECOMPUTED from actual
 *     before/after policy at EVERY consumption point — stored labels
 *     are distrusted (spec §9.4); divergence is an integrity alarm;
 *   - AUTHORITY EXPANSION (and every mixed/opaque/unknown-leaning
 *     outcome — the classifier lands those on EXPANSION or refuses)
 *     requires an OPEN, unexpired, non-stale governance proposal whose
 *     canonical digest carries a verified owner approval signature
 *     (plus the organization's configured quorum, which ADDS ceremony
 *     and can never remove the owner requirement), after the
 *     configured delay window;
 *   - REDUCTION takes the lighter path (no proposal; audited);
 *   - break-glass owner actions — ownerPause (freeze) and terminal
 *     ownerRecover — are NEVER gated, delayed, quorumed, or blocked by
 *     any governance configuration (spec §6.1);
 *   - the proposal record lifecycle is a closed, explicit state machine
 *     (OPEN -> CONSUMED | CANCELLED, both TERMINAL — finding RC-GV-1,
 *     docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.6): every
 *     status transition is serialized per proposal and decided on the
 *     DURABLE record; consumption evidence is terminal truth, so a
 *     consumed proposal can never be cancelled, reopened, relabeled,
 *     or reused;
 *   - unknown actions/versions/fields/statuses FAIL CLOSED.
 *
 * Approval signatures use the SAME wallet-signature verification
 * machinery hosted authentication uses: kaspa-wasm `verifyMessage` —
 * BIP-340 Schnorr over the keyed-blake2b `PersonalMessageSigningHash`
 * domain (see server/src/auth.js HostedAuthService.verify, the cited
 * mechanism) — over a SERVER-reconstructed canonical message embedding
 * the domain-separated proposal digest
 * (`policyvault-governance-proposal-digest/v1`,
 * core/governance/canonical.js). That domain is permanently disjoint
 * from `TransactionSigningHash`, so a governance approval can never be
 * replayed as covenant/transaction authority, and vice versa.
 */

const crypto = require("crypto");
const { getStore, Categories } = require("../../sdk/src/store");
const { appendAudit } = require("./audit"); // server audit = sdk audit + failure-isolated event hook
const {
  classifyPolicyDelta,
  GovernanceRefusal,
  GOVERNANCE_PROPOSAL_SCHEMA,
  governanceProposalDigest
} = require("../../core/governance");
const { canonicalEqual } = require("../../core/intent");
const { stateToJsonV4 } = require("../../sdk/src/vault-state-v4");
const { registryEntryToJson } = require("../../sdk/src/manifest-v4");
const { resolveAddressIdentity } = require("../../sdk/src/address-identity");

const PROPOSAL_RECORD_SCHEMA = "policyvault-governance-proposal-record/v1";
const APPROVAL_SCHEMA = "policyvault-governance-approval/v1";
const DEFAULT_PROPOSAL_TTL_MS = 14 * 24 * 60 * 60 * 1000; // 14 days
const MAX_PROPOSAL_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const SCHNORR_SIG_HEX = /^[0-9a-f]{128}$/;

function govError(status, code, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (extra) e.extra = extra;
  return e;
}

/*
 * RC-GV-1 — the explicit proposal status machine
 * (docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.6): the ONLY
 * permitted stored statuses and transitions; every other transition
 * refuses deterministically. CONSUMED and CANCELLED are TERMINAL — once
 * a proposal is consumed it can never be cancelled, reopened,
 * relabeled, or reused (the live defect was a cancel accepted AFTER
 * enforcement, because consumption never left status "OPEN"). EXPIRED
 * remains a presentation-only derivation of an OPEN record's
 * expiresAt: expiry is enforced by time checks at every gate, never
 * stored, so an expired-but-OPEN proposal may still be cancelled
 * (unchanged behavior).
 */
const PROPOSAL_STATUS_TRANSITIONS = Object.freeze({
  OPEN: Object.freeze(["CONSUMED", "CANCELLED"]),
  CONSUMED: Object.freeze([]),
  CANCELLED: Object.freeze([])
});

/*
 * Effective status, recomputed from CONTENT like every other stored
 * label in this module (spec §9.4 — stored labels are distrusted).
 * Consumption evidence (lastConsumed*) is terminal truth: it outranks a
 * stale "OPEN" (records persisted by the pre-fix code, which stamped
 * evidence without leaving OPEN) and a wrong "CANCELLED" (the live
 * RC-GV-1 record shape, where a cancel was accepted after enforcement —
 * such a record presents and gates as CONSUMED; the audit chain keeps
 * the full true sequence). Unknown stored statuses pass through and
 * fail closed at the transition table / OPEN gates.
 */
function effectiveProposalStatus(record) {
  if (record.lastConsumedAt || record.lastConsumedRequestId) return "CONSUMED";
  return record.status;
}

/* The deterministic refusal for a transition the machine does not
 * permit. Codes: GOVERNANCE_PROPOSAL_TERMINAL for terminal-state
 * violations (cancel-after-consume — the RC-GV-1 defect —, re-consume
 * by a different request, consume-after-cancel);
 * GOVERNANCE_PROPOSAL_CLOSED for a duplicate cancel (the pre-fix code
 * for that case, preserved); GOVERNANCE_STATUS_UNKNOWN when the stored
 * status is outside the machine entirely (fail closed, never routed to
 * a default). */
function refuseTransition(record, from, to) {
  if (from === "CONSUMED") {
    const evidence = record.lastConsumedRequestId
      ? ` (consumed by request ${record.lastConsumedRequestId}${record.lastConsumedAt ? ` at ${record.lastConsumedAt}` : ""})`
      : "";
    return govError(
      409,
      "GOVERNANCE_PROPOSAL_TERMINAL",
      to === "CANCELLED"
        ? `proposal is CONSUMED${evidence} — consumption is terminal; it can no longer be cancelled`
        : `proposal is CONSUMED${evidence} — consumption is terminal; it cannot record another consumption`
    );
  }
  if (from === "CANCELLED") {
    return to === "CONSUMED"
      ? govError(409, "GOVERNANCE_PROPOSAL_TERMINAL", "proposal is CANCELLED — a cancelled proposal cannot record a consumption")
      : govError(409, "GOVERNANCE_PROPOSAL_CLOSED", "proposal is CANCELLED");
  }
  return govError(422, "GOVERNANCE_STATUS_UNKNOWN", `stored proposal status ${JSON.stringify(record.status)} is unknown — failing closed`);
}

/*
 * The governed-action matrix for the v0.4-family hosted wallet flows —
 * derived honestly from the REAL request kinds
 * (sdk/src/wallet-requests-v4.js ROLE_BY_ACTION; nothing invented):
 *
 *   agentSpend           not policy-governed (a spend; risk pipeline +
 *                        consensus policy enforcement apply)
 *   ownerTopUp/-Reserve  funding, not policy (NOT_A_POLICY_FIELD class)
 *   ownerPause           break-glass REDUCTION (freeze) — NEVER gated
 *   ownerRecover         break-glass terminal recovery — NEVER gated
 *   ownerUnpause         governed (resume = EXPANSION)
 *   ownerSetApprovers    governed (quorum/approver-set changes)
 *   ownerSetAgentRoot    governed (agent set / per-agent policy)
 *   addAgent/removeAgent/rotateAgent/rePolicyAgent
 *                        governed (they EXECUTE as ownerSetAgentRoot)
 *   createVault          genesis — no before-state; not governed here
 *
 * Unknown actions FAIL CLOSED (they are also refused by the build
 * pipeline's own ROLE_BY_ACTION gate).
 */
const ACTION_MATRIX = Object.freeze({
  agentSpend: { governed: false },
  ownerTopUp: { governed: false },
  ownerTopUpReserve: { governed: false },
  ownerPause: { governed: false, breakGlass: true },
  ownerRecover: { governed: false, breakGlass: true },
  ownerUnpause: { governed: true },
  ownerSetApprovers: { governed: true },
  ownerSetAgentRoot: { governed: true },
  addAgent: { governed: true },
  removeAgent: { governed: true },
  rotateAgent: { governed: true },
  rePolicyAgent: { governed: true },
  createVault: { governed: false }
});

/* Registry entry -> classifier agent-policy LIST form. The stored
 * registry entry carries BOTH the recipients list and the derived
 * agentRecipientRoot; the classifier's xor rule (one authority per
 * fact) takes the LIST — the EXECUTION layer (the SDK builders +
 * manifest loader) is what binds the list to the committed root
 * (spec §5.1 opaque-commitment rule). */
function agentEntryForClassifier(entryJson) {
  const { agentRecipientRoot, ...rest } = entryJson;
  void agentRecipientRoot;
  return rest;
}

/*
 * The JSON-safe policy tuple of a v0.4-family manifest's LIVE state:
 * exactly the classifier's TUPLE_KEYS shape (paused, approvalM,
 * approverSlots 10-slot layout, agents in list form from the
 * root-verified durable registry). Funding/identity/nonce fields are
 * neutral-class and deliberately omitted (they are not policy).
 */
function v4PolicyTuple(manifest) {
  if (!manifest || !manifest.live) {
    throw govError(422, "GOVERNANCE_NO_LIVE_STATE", "the vault has no live state to govern");
  }
  const stateJson = stateToJsonV4(manifest.live.state);
  return {
    paused: stateJson.paused,
    approvalM: stateJson.approvalM,
    approverSlots: stateJson.approverSlots,
    agents: manifest.agentRegistry.map((e) => agentEntryForClassifier(registryEntryToJson(e)))
  };
}

/*
 * Derive the AFTER policy tuple a v0.4 action+params would produce.
 * Agent-lifecycle derivation goes through the EXPORTED SDK planner
 * (sdk/src/wallet-requests-v4.js planV4) — the SAME pure derivation the
 * build will execute, so classification and execution cannot drift.
 */
function deriveAfterTupleV4(config, manifest, action, params) {
  const before = v4PolicyTuple(manifest);
  switch (action) {
    case "ownerPause":
      return { ...before, paused: "1" };
    case "ownerUnpause":
      return { ...before, paused: "0" };
    case "ownerSetApprovers": {
      const na = params && typeof params === "object" ? params.newApprovers : undefined;
      if (na === null || typeof na !== "object" || Array.isArray(na)) {
        throw govError(422, "GOVERNANCE_PARAMS_INVALID", "ownerSetApprovers requires params.newApprovers ({ approvers | approverSlots, approvalM })");
      }
      const { approverSlots, ...rest } = before;
      void approverSlots;
      const after = { ...rest };
      if (na.approverSlots !== undefined) after.approverSlots = na.approverSlots;
      else after.approvers = na.approvers; // classifier accepts either form per side; missing -> refuses (fail closed)
      after.approvalM = na.approvalM;
      return after;
    }
    case "ownerSetAgentRoot":
    case "addAgent":
    case "removeAgent":
    case "rotateAgent":
    case "rePolicyAgent": {
      const { planV4 } = require("../../sdk/src/wallet-requests-v4");
      const plan = planV4(config, manifest, action, params ?? {}); // throws (fail closed) on malformed input
      if (!Array.isArray(plan.newRegistry)) {
        throw govError(422, "GOVERNANCE_PARAMS_INVALID", `${action} produced no explicit new agent registry — an opaque root swap cannot be classified and fails closed`);
      }
      return { ...before, agents: plan.newRegistry.map((e) => agentEntryForClassifier(e)) };
    }
    default:
      throw govError(422, "GOVERNANCE_ACTION_UNKNOWN", `no after-state derivation for action ${JSON.stringify(action)} — failing closed`);
  }
}

/*
 * Classify one requested v0.4 operation at a consumption point.
 * Returns:
 *   { governed:false, breakGlass?:true }              — no governance gate
 *   { governed:true, classification, perField, codes, before, after }
 * Throws (fail closed) on unknown actions and classifier refusals.
 */
function classifyActionV4(config, manifest, action, params) {
  const entry = ACTION_MATRIX[action];
  if (!entry) {
    throw govError(422, "GOVERNANCE_ACTION_UNKNOWN", `unknown action ${JSON.stringify(action)} — unknown operations are never silently ungoverned`);
  }
  if (!entry.governed) return { governed: false, ...(entry.breakGlass ? { breakGlass: true } : {}) };
  const before = v4PolicyTuple(manifest);
  const after = deriveAfterTupleV4(config, manifest, action, params);
  let result;
  try {
    result = classifyPolicyDelta({ covenantVersion: manifest.contractVersion, before, after });
  } catch (e) {
    if (e instanceof GovernanceRefusal) throw govError(422, e.code, e.message);
    throw e;
  }
  return { governed: true, classification: result.classification, perField: result.perField, codes: result.codes, before, after };
}

/* ------------------------------------------------------------------ */
/* Proposals                                                           */
/* ------------------------------------------------------------------ */

function stripExecutionOnlyParams(params) {
  const { fuel, ...rest } = params ?? {};
  void fuel; // fuel is a fee-UTXO reference chosen at execution time, not intent
  return rest;
}

async function saveProposalRecord(config, record) {
  record.updatedAt = new Date().toISOString();
  await getStore(config).write(Categories.GOVERNANCE_PROPOSAL, record.proposalId, record);
  return record;
}

async function loadProposalRecord(config, proposalId) {
  if (typeof proposalId !== "string" || !/^[0-9a-f-]{1,64}$/i.test(proposalId)) return null;
  const record = await getStore(config).read(Categories.GOVERNANCE_PROPOSAL, proposalId);
  if (record === null) return null;
  if (record.schema !== PROPOSAL_RECORD_SCHEMA) {
    throw govError(422, "GOVERNANCE_SCHEMA_UNKNOWN", `stored proposal record has unknown schema ${JSON.stringify(record.schema)} — failing closed`);
  }
  return record;
}

/*
 * Per-proposal transition serialization (RC-GV-1; the budget-reservation
 * lock idiom, sdk/src/budget-reservation.js): a short-lived create-only
 * lock record arbitrated by the store's atomic exclusive create —
 * link()/EEXIST on the JSON backend, INSERT ... ON CONFLICT DO NOTHING
 * on PostgreSQL — so consume/cancel races resolve to exactly ONE winner
 * on BOTH backends and across processes; the loser re-reads the durable
 * record under the lock and refuses on the terminal state it finds. The
 * lock key prefix "xlock-" contains non-hex characters, so it can never
 * collide with uuid proposal keys and is unaddressable through the API
 * id charset; lock records carry their own schema and are filtered out
 * of every proposal listing. A crashed holder is reclaimed
 * deterministically after TRANSITION_LOCK_STALE_MS (the server
 * idempotency IN_PROGRESS stale-reclaim pattern); a live holder makes
 * contenders retry briefly, then fail closed with
 * GOVERNANCE_TRANSITION_BUSY — pure and retryable, nothing durable
 * changed.
 */
const TRANSITION_LOCK_SCHEMA = "policyvault-governance-transition-lock/v1";
const TRANSITION_LOCK_STALE_MS = 30_000;
const TRANSITION_LOCK_RETRY_ATTEMPTS = 80;
const TRANSITION_LOCK_RETRY_DELAY_MS = 25;
const transitionLockKey = (proposalId) => `xlock-${proposalId}`;
const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function acquireTransitionLock(config, proposalId, holderToken) {
  const store = getStore(config);
  const key = transitionLockKey(proposalId);
  for (let attempt = 0; attempt <= TRANSITION_LOCK_RETRY_ATTEMPTS; attempt++) {
    const created = await store.createExclusive(Categories.GOVERNANCE_PROPOSAL, key, {
      schema: TRANSITION_LOCK_SCHEMA,
      proposalId,
      holderToken,
      createdAt: new Date().toISOString(),
      createdAtMs: Date.now()
    });
    if (created) return key;
    const existing = await store.read(Categories.GOVERNANCE_PROPOSAL, key);
    if (existing && existing.schema !== TRANSITION_LOCK_SCHEMA) {
      throw govError(422, "GOVERNANCE_SCHEMA_UNKNOWN", `transition lock record ${key} has unknown schema ${JSON.stringify(existing.schema)} — failing closed`);
    }
    if (existing && typeof existing.createdAtMs === "number" && Date.now() - existing.createdAtMs > TRANSITION_LOCK_STALE_MS) {
      await store.remove(Categories.GOVERNANCE_PROPOSAL, key); // reclaim a crashed holder; the next createExclusive re-arbitrates
      continue;
    }
    await sleepMs(TRANSITION_LOCK_RETRY_DELAY_MS);
  }
  throw govError(409, "GOVERNANCE_TRANSITION_BUSY", "another lifecycle transition for this proposal is in progress — retry shortly");
}

/* Guarded, idempotent lock release: never removes another holder's lock. */
async function releaseTransitionLock(config, proposalId, holderToken) {
  const store = getStore(config);
  const key = transitionLockKey(proposalId);
  const existing = await store.read(Categories.GOVERNANCE_PROPOSAL, key);
  if (existing === null) return false;
  if (existing.schema !== TRANSITION_LOCK_SCHEMA || existing.holderToken !== holderToken) return false;
  await store.remove(Categories.GOVERNANCE_PROPOSAL, key);
  return true;
}

/*
 * Create a proposal for a governed v0.4 policy change. The server
 * derives `before` from the reconciled live manifest and `after` from
 * the requested action+params (the same derivations every later
 * consumer re-runs); the stored record caches the digest and
 * classification, both of which every consumer recomputes and
 * distrusts.
 */
async function createProposal({ config, manifest, vaultId, action, params, proposedByXOnly, expiresInMs }) {
  const gate = classifyActionV4(config, manifest, action, params);
  if (!gate.governed) {
    throw govError(
      422,
      "GOVERNANCE_NOT_REQUIRED",
      gate.breakGlass
        ? `${action} is a break-glass owner action — it needs no proposal and no governance configuration may gate it`
        : `${action} is not a governed policy change — no proposal applies`
    );
  }
  const ttl = expiresInMs === undefined ? DEFAULT_PROPOSAL_TTL_MS : expiresInMs;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_PROPOSAL_TTL_MS) {
    throw govError(422, "GOVERNANCE_PARAMS_INVALID", `expiresInMs must be an integer 1..${MAX_PROPOSAL_TTL_MS}`);
  }
  const now = Date.now();
  const proposal = {
    schema: GOVERNANCE_PROPOSAL_SCHEMA,
    kind: "policy-change",
    network: config.networkId,
    vaultId,
    covenantVersion: manifest.contractVersion,
    action,
    params: stripExecutionOnlyParams(params),
    before: gate.before,
    after: gate.after,
    proposedBy: proposedByXOnly,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttl).toISOString()
  };
  const proposalDigest = governanceProposalDigest(proposal); // canonical, jsonb-key-order-immune
  const proposalId = crypto.randomUUID();
  const record = {
    schema: PROPOSAL_RECORD_SCHEMA,
    proposalId,
    proposal,
    proposalDigest, // cached; every consumer recomputes
    classification: gate.classification, // cached LABEL; every consumer recomputes and distrusts
    codes: gate.codes,
    status: "OPEN",
    createdAt: proposal.createdAt,
    updatedAt: proposal.createdAt
  };
  await getStore(config).write(Categories.GOVERNANCE_PROPOSAL, proposalId, record);
  await appendAudit(config, {
    kind: "governance",
    vaultId,
    action,
    actor: "owner",
    actorXOnly: proposedByXOnly ?? null,
    result: "GOVERNANCE_PROPOSAL_CREATED",
    detail: `proposal ${proposalId} (${gate.classification}) [${gate.codes.join(", ")}] digest ${proposalDigest.slice(0, 16)}…`,
    proposalId
  });
  return record;
}

/*
 * The canonical approval message — SERVER-reconstructed at every
 * verification; a client-submitted message text is never accepted
 * (the auth.js discipline). Signing this message in a wallet approves
 * one hosted-workflow step; it cannot move funds and cannot be
 * replayed as transaction authority (disjoint signing domains).
 */
function approvalMessageText(config, proposalId, proposalDigest) {
  return [
    "PolicyVault governance approval",
    `network: ${config.networkId}`,
    `proposal: ${proposalId}`,
    `digest: ${proposalDigest}`,
    "This signature approves a policy-change workflow step. It cannot move funds."
  ].join("\n");
}

/* Recompute-and-check the stored record's digest (jsonb-safe by
 * canonical encoding). A mismatch is DB tampering or a serialization
 * defect — an integrity alarm, never acceptable drift. */
function recomputedDigestOf(record) {
  const digest = governanceProposalDigest(record.proposal);
  if (record.proposalDigest !== digest) {
    throw govError(409, "GOVERNANCE_DIGEST_MISMATCH", "stored proposal content does not match its recorded digest — integrity alarm, failing closed");
  }
  return digest;
}

/* The governance quorum set for a vault: the vault OWNER always, plus
 * the organization's configured governance approvers (config ADDS
 * ceremony; it can never remove the owner requirement). */
function quorumSetFor(manifest, controls) {
  const owner = manifest.template.owner.toLowerCase();
  const set = new Set([owner]);
  const quorum = controls?.governance?.quorum ?? null;
  if (quorum) for (const a of quorum.approvers) set.add(a);
  return { owner, set, orgQuorum: quorum };
}

const kaspaByConfig = new WeakMap();
function kaspaFor(config) {
  let kaspa = kaspaByConfig.get(config);
  if (!kaspa) {
    kaspa = require("../../sdk/src/chain").loadKaspa(config);
    kaspaByConfig.set(config, kaspa);
  }
  return kaspa;
}

/* Verify ONE stored approval row against the recomputed digest. */
function approvalRowVerifies(config, record, digest, row) {
  if (!row || row.schema !== APPROVAL_SCHEMA) return false;
  if (row.proposalDigest !== digest) return false;
  if (typeof row.approverXOnly !== "string" || !/^[0-9a-f]{64}$/.test(row.approverXOnly)) return false;
  if (typeof row.signature !== "string" || !SCHNORR_SIG_HEX.test(row.signature)) return false;
  const message = approvalMessageText(config, record.proposalId, digest);
  try {
    return kaspaFor(config).verifyMessage({ message, signature: row.signature, publicKey: row.approverXOnly }) === true;
  } catch {
    return false;
  }
}

/* All approval rows for a digest (key prefix "<digest>-"). */
async function approvalRowsFor(config, digest) {
  const store = getStore(config);
  const keys = await store.listKeys(Categories.GOVERNANCE_APPROVAL);
  const rows = [];
  for (const key of keys) {
    if (!key.startsWith(`${digest}-`)) continue;
    try {
      const row = await store.read(Categories.GOVERNANCE_APPROVAL, key);
      if (row) rows.push(row);
    } catch {
      /* a corrupt row never counts toward a quorum (fail closed) */
    }
  }
  return rows;
}

/*
 * Approval status, re-verified from content: every counted approval is
 * a VERIFIED Schnorr signature over the recomputed digest by a wallet
 * in the quorum set. Owner approval is ALWAYS required; the org quorum
 * (m of its configured approvers) is additionally required when
 * configured.
 */
async function approvalStatus(config, record, digest, manifest, controls) {
  const { owner, set, orgQuorum } = quorumSetFor(manifest, controls);
  const rows = await approvalRowsFor(config, digest);
  const verified = [];
  for (const row of rows) {
    if (!set.has(row.approverXOnly)) continue; // outside the quorum: never counted
    if (approvalRowVerifies(config, record, digest, row)) {
      verified.push({ approverXOnly: row.approverXOnly, collectedAt: row.collectedAt });
    }
  }
  const verifiedKeys = new Set(verified.map((v) => v.approverXOnly));
  const ownerApproved = verifiedKeys.has(owner);
  const orgApproved = orgQuorum ? orgQuorum.approvers.filter((a) => verifiedKeys.has(a)).length >= orgQuorum.m : true;
  return {
    owner,
    ownerApproved,
    orgQuorum: orgQuorum ? { required: orgQuorum.m, of: orgQuorum.approvers.length, collected: orgQuorum.approvers.filter((a) => verifiedKeys.has(a)).length } : null,
    verified,
    satisfied: ownerApproved && orgApproved
  };
}

/*
 * Collect one governance approval signature. The signer's identity
 * resolves through the SAME address boundary the covenant flows use;
 * the signature is verified against the SERVER-reconstructed canonical
 * message with the auth-machinery verifier (kaspa.verifyMessage) before
 * anything durable is written. One approval per wallet per digest
 * (create-only row).
 */
async function collectProposalApproval({ config, proposalId, approverAddress, signature }) {
  const record = await loadProposalRecord(config, proposalId);
  if (!record) throw govError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
  // RC-GV-1: the EFFECTIVE status gates — consumption evidence included,
  // so consumed/cancelled (and legacy pre-fix consumed) proposals never
  // collect further approvals.
  const status = effectiveProposalStatus(record);
  if (status !== "OPEN") throw govError(409, "GOVERNANCE_PROPOSAL_CLOSED", `proposal is ${status}`);
  if (Date.parse(record.proposal.expiresAt) <= Date.now()) {
    throw govError(409, "GOVERNANCE_PROPOSAL_EXPIRED", "the proposal expired — create a fresh one");
  }
  const digest = recomputedDigestOf(record);
  let approverXOnly;
  try {
    approverXOnly = resolveAddressIdentity(config, approverAddress).xOnlyPubkey;
  } catch (e) {
    throw govError(422, "GOVERNANCE_APPROVER_INVALID", `approver address rejected: ${e.message}`);
  }
  if (typeof signature !== "string" || !SCHNORR_SIG_HEX.test(signature.toLowerCase())) {
    throw govError(400, "GOVERNANCE_SIGNATURE_INVALID", "signature must be a 128-hex (64-byte) Schnorr personal-message signature");
  }
  const message = approvalMessageText(config, record.proposalId, digest);
  let ok = false;
  try {
    ok = kaspaFor(config).verifyMessage({ message, signature: signature.toLowerCase(), publicKey: approverXOnly }) === true;
  } catch {
    ok = false;
  }
  if (!ok) throw govError(401, "GOVERNANCE_SIGNATURE_INVALID", "governance approval signature verification failed");

  const row = {
    schema: APPROVAL_SCHEMA,
    proposalId: record.proposalId,
    proposalDigest: digest,
    approverXOnly,
    approverAddress,
    signature: signature.toLowerCase(),
    collectedAt: new Date().toISOString()
  };
  const created = await getStore(config).createExclusive(Categories.GOVERNANCE_APPROVAL, `${digest}-${approverXOnly}`, row);
  if (!created) throw govError(409, "GOVERNANCE_ALREADY_APPROVED", "this wallet already approved this proposal digest");
  await appendAudit(config, {
    kind: "governance",
    vaultId: record.proposal.vaultId,
    action: record.proposal.action,
    actor: "approver",
    actorXOnly: approverXOnly,
    result: "GOVERNANCE_APPROVAL_COLLECTED",
    detail: `approval by ${approverXOnly.slice(0, 16)}… on proposal ${record.proposalId}`,
    proposalId: record.proposalId
  });
  return { record, digest, approverXOnly };
}

/*
 * Cancel a proposal. RC-GV-1: cancellation is valid ONLY where the
 * state machine permits it (OPEN -> CANCELLED). The decision is
 * serialized per proposal and made on the DURABLE record re-read under
 * the transition lock, so a cancel racing a consumption loses
 * deterministically (exactly one transition ever wins), and a consumed
 * proposal — including legacy records whose consumption evidence
 * predates the terminal-status fix — refuses
 * GOVERNANCE_PROPOSAL_TERMINAL without writing or auditing anything.
 */
async function cancelProposal({ config, proposalId, cancelledByXOnly }) {
  const pre = await loadProposalRecord(config, proposalId);
  if (!pre) throw govError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
  const holderToken = crypto.randomUUID();
  await acquireTransitionLock(config, proposalId, holderToken);
  let record;
  try {
    record = await loadProposalRecord(config, proposalId); // durable truth, re-read under the lock
    if (!record) throw govError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
    const from = effectiveProposalStatus(record);
    const allowedFrom = PROPOSAL_STATUS_TRANSITIONS[from];
    if (!allowedFrom || !allowedFrom.includes("CANCELLED")) throw refuseTransition(record, from, "CANCELLED");
    record.status = "CANCELLED";
    record.cancelledAt = new Date().toISOString();
    record.cancelledBy = cancelledByXOnly ?? null;
    await saveProposalRecord(config, record);
  } finally {
    await releaseTransitionLock(config, proposalId, holderToken).catch(() => {});
  }
  await appendAudit(config, {
    kind: "governance",
    vaultId: record.proposal.vaultId,
    action: record.proposal.action,
    actor: "owner",
    actorXOnly: cancelledByXOnly ?? null,
    result: "GOVERNANCE_PROPOSAL_CANCELLED",
    detail: `proposal ${record.proposalId} cancelled`,
    proposalId: record.proposalId
  });
  return record;
}

async function listProposals(config, { vaultId } = {}) {
  const all = await getStore(config).listValues(Categories.GOVERNANCE_PROPOSAL);
  return all
    .filter((r) => r && r.schema === PROPOSAL_RECORD_SCHEMA && (vaultId === undefined || r.proposal?.vaultId === vaultId))
    .sort((a, b) => String(b.createdAt ?? "").localeCompare(String(a.createdAt ?? "")));
}

/*
 * THE consumption-point gate for an AUTHORITY EXPANSION build.
 * Everything is recomputed from content — live manifest, derived
 * after-tuple, proposal digest, proposal classification, approval
 * signatures — and every divergence fails closed:
 *
 *   1. a proposal id must be supplied (GOVERNANCE_PROPOSAL_REQUIRED);
 *   2. the proposal must exist, be OPEN, unexpired, and bind THIS
 *      network + vault + covenant version;
 *   3. the proposal's `before` must equal the CURRENT live policy tuple
 *      (STALE_PROPOSAL otherwise — the frozen-tx pipeline additionally
 *      enforces this at the byte level via the exact predecessor);
 *   4. the proposal's action+params must equal the execution request's
 *      action+params (minus the execution-only fuel reference), and its
 *      `after` must equal the tuple derived from those params NOW;
 *   5. recomputed classification of the proposal content must be
 *      EXPANSION and must match the recomputed request classification;
 *      a diverging stored label is an integrity alarm
 *      (CLASSIFICATION_MISMATCH);
 *   6. the recomputed digest must carry a VERIFIED owner approval
 *      signature plus the org quorum where configured;
 *   7. the configured delay window must have elapsed.
 */
async function requireApprovedProposal({ config, manifest, vaultId, action, params, proposalId, gate, controls }) {
  if (proposalId === undefined || proposalId === null || proposalId === "") {
    throw govError(
      409,
      "GOVERNANCE_PROPOSAL_REQUIRED",
      `${action} is an AUTHORITY EXPANSION (${gate.codes.join(", ")}) — it requires an approved governance proposal (create one via POST /governance/proposals, collect the owner approval signature, then pass proposalId with this request)`,
      { governance: { classification: gate.classification, codes: gate.codes } }
    );
  }
  const record = await loadProposalRecord(config, proposalId);
  if (!record || record.proposal.vaultId !== vaultId) {
    throw govError(409, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such governance proposal for this vault");
  }
  // RC-GV-1: the EFFECTIVE status gates admission — a consumed proposal
  // (status or evidence) is terminal and never admits another build.
  const proposalStatus = effectiveProposalStatus(record);
  if (proposalStatus !== "OPEN") throw govError(409, "GOVERNANCE_PROPOSAL_CLOSED", `proposal is ${proposalStatus}`);
  if (Date.parse(record.proposal.expiresAt) <= Date.now()) {
    throw govError(409, "GOVERNANCE_PROPOSAL_EXPIRED", "the proposal expired — create a fresh one");
  }
  // RECORD INTEGRITY FIRST: the recomputed canonical digest must match
  // the cached one before any semantic use of the stored content.
  const digest = recomputedDigestOf(record);
  const p = record.proposal;
  if (p.schema !== GOVERNANCE_PROPOSAL_SCHEMA || p.kind !== "policy-change") {
    throw govError(422, "GOVERNANCE_SCHEMA_UNKNOWN", "unknown proposal schema/kind — failing closed");
  }
  if (p.network !== config.networkId) throw govError(409, "GOVERNANCE_NETWORK_MISMATCH", "proposal network does not match this server");
  if (p.covenantVersion !== manifest.contractVersion) {
    throw govError(409, "GOVERNANCE_VERSION_MISMATCH", "proposal covenant version does not match the vault");
  }
  if (p.action !== action || !canonicalEqual(p.params, stripExecutionOnlyParams(params))) {
    throw govError(409, "GOVERNANCE_PROPOSAL_MISMATCH", "the requested operation does not match the approved proposal's action/params");
  }
  if (!canonicalEqual(p.before, gate.before)) {
    throw govError(409, "STALE_PROPOSAL", "the vault's live policy no longer equals the proposal's before-state — re-propose against current state");
  }
  if (!canonicalEqual(p.after, gate.after)) {
    throw govError(409, "GOVERNANCE_PROPOSAL_MISMATCH", "the derived after-state does not equal the proposal's approved after-state");
  }
  /* Recompute the proposal's own classification from ITS content. */
  let proposalCls;
  try {
    proposalCls = classifyPolicyDelta({ covenantVersion: p.covenantVersion, before: p.before, after: p.after });
  } catch (e) {
    if (e instanceof GovernanceRefusal) throw govError(422, e.code, e.message);
    throw e;
  }
  if (proposalCls.classification !== gate.classification) {
    throw govError(409, "CLASSIFICATION_MISMATCH", "recomputed proposal classification diverges from the request classification — integrity alarm, failing closed");
  }
  if (record.classification !== proposalCls.classification) {
    // The cached label was tampered with or is stale: the recomputation
    // WINS (spec §9.4) and the divergence is refused as an alarm.
    throw govError(409, "CLASSIFICATION_MISMATCH", "stored classification label diverges from the recomputed classification — integrity alarm, failing closed");
  }
  const approvals = await approvalStatus(config, record, digest, manifest, controls);
  if (!approvals.satisfied) {
    throw govError(
      409,
      "GOVERNANCE_APPROVALS_INSUFFICIENT",
      approvals.ownerApproved
        ? "the organization's governance quorum has not approved this proposal digest"
        : "the vault owner's governance approval signature is required (and organization quorum where configured)",
      { governance: { ownerApproved: approvals.ownerApproved, orgQuorum: approvals.orgQuorum } }
    );
  }
  const delayMs = controls?.governance?.delayMs ?? 0;
  const availableAtMs = Date.parse(record.proposal.createdAt) + delayMs;
  if (Date.now() < availableAtMs) {
    throw govError(409, "GOVERNANCE_DELAY_PENDING", "the organization's governance delay window has not elapsed", {
      governance: { availableAt: new Date(availableAtMs).toISOString() }
    });
  }
  return { record, digest, approvals };
}

/*
 * Stamp a consumed proposal with the request/tx that executed it.
 * RC-GV-1: consumption is the TERMINAL state transition OPEN ->
 * CONSUMED on the explicit machine — serialized by the per-proposal
 * transition lock and decided on the DURABLE record (a caller's stale
 * in-memory record can never resurrect or relabel a terminal
 * proposal). Replaying the SAME request's stamp is idempotent
 * (crash/retry safety); any other transition attempt on a terminal
 * proposal refuses deterministically, so the FIRST consumption
 * evidence is permanent — while, exactly as before, the covenant +
 * transition claims remain the financial arbiter of which frozen
 * transaction actually executes, and a stale proposal additionally
 * fails the before-tuple gate on any later admission attempt.
 */
async function markProposalConsumed(config, record, { requestId, txId }) {
  const proposalId = record ? record.proposalId : undefined;
  const pre = await loadProposalRecord(config, proposalId);
  if (!pre) throw govError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
  const holderToken = crypto.randomUUID();
  await acquireTransitionLock(config, proposalId, holderToken);
  try {
    const durable = await loadProposalRecord(config, proposalId); // durable truth — never the caller's (possibly stale) object
    if (!durable) throw govError(404, "GOVERNANCE_PROPOSAL_UNKNOWN", "no such proposal");
    const from = effectiveProposalStatus(durable);
    if (from === "CONSUMED" && requestId != null && durable.lastConsumedRequestId === requestId) {
      return durable; // idempotent replay of the SAME consumption (crash/retry): evidence preserved, nothing relabeled
    }
    const allowedFrom = PROPOSAL_STATUS_TRANSITIONS[from];
    if (!allowedFrom || !allowedFrom.includes("CONSUMED")) throw refuseTransition(durable, from, "CONSUMED");
    durable.status = "CONSUMED";
    durable.consumedAt = new Date().toISOString();
    durable.lastConsumedRequestId = requestId ?? null;
    durable.lastConsumedTxId = txId ?? null;
    durable.lastConsumedAt = durable.consumedAt;
    await saveProposalRecord(config, durable);
    return durable;
  } finally {
    await releaseTransitionLock(config, proposalId, holderToken).catch(() => {});
  }
}

/* Presentation: recomputed-integrity view of one proposal record. */
async function presentProposal(config, record, manifest, controls) {
  let digest = null;
  let digestOk = false;
  try {
    digest = recomputedDigestOf(record);
    digestOk = true;
  } catch {
    digest = null;
  }
  let recomputed = null;
  let classificationOk = false;
  try {
    const cls = classifyPolicyDelta({ covenantVersion: record.proposal.covenantVersion, before: record.proposal.before, after: record.proposal.after });
    recomputed = { classification: cls.classification, codes: cls.codes, perField: cls.perField };
    classificationOk = cls.classification === record.classification;
  } catch (e) {
    recomputed = { refusal: e.code ?? "GOVERNANCE_REFUSAL" };
  }
  const approvals = digestOk && manifest ? await approvalStatus(config, record, digest, manifest, controls) : null;
  const expired = Date.parse(record.proposal.expiresAt) <= Date.now();
  // RC-GV-1: present the EFFECTIVE status (consumption evidence is
  // terminal truth — legacy pre-fix records included); EXPIRED remains a
  // presentation-only derivation of an effectively-OPEN record. An
  // unknown stored status is shown raw (display honesty) — every
  // transition and admission gate refuses it regardless.
  const effective = effectiveProposalStatus(record);
  return {
    proposalId: record.proposalId,
    status: effective === "OPEN" && expired ? "EXPIRED" : effective,
    proposal: record.proposal,
    proposalDigest: digest,
    integrity: { digestOk, classificationOk },
    classification: recomputed,
    approvals,
    approvalMessage: digestOk ? approvalMessageText(config, record.proposalId, digest) : null,
    lastConsumedRequestId: record.lastConsumedRequestId ?? null,
    lastConsumedTxId: record.lastConsumedTxId ?? null,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
  };
}

module.exports = {
  ACTION_MATRIX,
  PROPOSAL_RECORD_SCHEMA,
  APPROVAL_SCHEMA,
  PROPOSAL_STATUS_TRANSITIONS,
  effectiveProposalStatus,
  v4PolicyTuple,
  deriveAfterTupleV4,
  classifyActionV4,
  createProposal,
  collectProposalApproval,
  cancelProposal,
  listProposals,
  loadProposalRecord,
  requireApprovedProposal,
  markProposalConsumed,
  presentProposal,
  approvalMessageText,
  approvalStatus
};
