"use strict";

/*
 * Operational risk pipeline (Program D server wiring,
 * docs/postlaunch/risk-adapter-spec.md §2/§5 + completion-standard
 * item 5): per-organization adapter configuration -> core/risk
 * evaluateRisk at the INTENT stage (before any durable wallet request
 * is built) -> ALLOW proceeds, REVIEW holds for an authorized human
 * release, DENY refuses with structured reasons. Every evaluation
 * persists a durable evidence record (Categories.RISK_EVALUATION,
 * migration 004) and an audit event carrying the correlation fields.
 *
 * BOUNDARY (invariant 2, restated where it is enforced): this pipeline
 * is RESTRICTIVE-ONLY hosted coordination. A risk ALLOW authorizes
 * nothing — the SDK build/preflight (mirroring covenant rules) and
 * ultimately Kaspa consensus decide independently, and
 * core/risk applyRiskToPolicyDecision is structurally incapable of
 * upgrading a policy DENY. Adapter errors/timeouts/malformed verdicts
 * resolve REVIEW or DENY per configuration — never a silent ALLOW
 * (core/risk compose semantics, exercised as-is).
 *
 * REVIEW hold lifecycle (durable, evidence-preserving):
 *   REVIEW_HELD --release--> RELEASED --exact-intent build--> CONSUMED
 * A release binds the EXACT evaluated intent (its canonical hash): a
 * changed intent is a new evaluation, never a reuse of an old release.
 * The releaser must be an authorized reviewer and must not be the
 * initiating signer (the acting signer never releases their own hold).
 *
 * A RELEASED hold is consumable two equivalent ways (RC-UX-1 fix,
 * docs/postlaunch/rc-mainnet-acceptance-evidence.md §5.2):
 *   1. the request names `riskEvaluationId` (the reviewer-driven UI
 *      re-submit path — semantics unchanged, byte-for-byte);
 *   2. the request carries NO id but IS the exact reviewed intent: the
 *      same vault, the same canonical intent hash, AND the same
 *      org-controls version the evaluation was created under. This is
 *      the deterministic solo-operator continuation — re-attempting
 *      the original action after a release consumes the released hold
 *      exactly once (atomic claim; a concurrent duplicate loses cleanly
 *      and falls through to a FRESH evaluation, which HOLDS). Any
 *      non-match — different intent, different vault, changed controls
 *      version (stale), non-RELEASED status (HELD/DENIED/CONSUMED) —
 *      falls through to the fresh-evaluation path unchanged:
 *      restrictive-only, never an ALLOW upgrade.
 */

const crypto = require("crypto");
const { getStore, Categories } = require("../../sdk/src/store");
const { appendAudit } = require("./audit"); // server audit = sdk audit + failure-isolated event hook
const { evaluateRisk, applyRiskToPolicyDecision } = require("../../core/risk");
const { canonicalJsonStringify, sha256Hex } = require("../../core/intent");
const { buildAdaptersFromConfig } = require("./risk-adapters");

const RISK_EVALUATION_SCHEMA = "policyvault-risk-evaluation/v1";
const RISK_INTENT_SCHEMA = "policyvault-risk-intent/1";

function riskError(status, code, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.code = code;
  if (extra) e.extra = extra;
  return e;
}

/*
 * The JSON-safe intent document adapters evaluate (risk-adapter-spec
 * §3.1): the proposed operation BEFORE any build exists — network,
 * vault, action, acting signer, and the operation parameters verbatim
 * (JSON body data; core/risk refuses anything not JSON-safe). Spend
 * screening fields (payAmountSompi, recipient) are lifted to the top
 * level for adapter convenience; `fuel` is execution plumbing (a UTXO
 * reference), not intent, and is excluded so the SAME intent hashes
 * identically whichever fuel UTXO executes it.
 */
function buildRiskIntent({ config, vaultId, action, params, signerAddress, signerXOnly, sdkAction }) {
  const { fuel, ...intentParams } = params ?? {};
  void fuel;
  const intent = {
    schema: RISK_INTENT_SCHEMA,
    networkId: config.networkId,
    vaultId,
    action,
    sdkAction: sdkAction ?? action,
    signerAddress: signerAddress ?? null,
    signerXOnly: signerXOnly ?? null,
    params: intentParams
  };
  if (action === "agentSpend") {
    intent.payAmountSompi = typeof intentParams.payAmountSompi === "string" ? intentParams.payAmountSompi : String(intentParams.payAmountSompi ?? "");
    intent.recipient = typeof intentParams.recipient === "string" ? intentParams.recipient.toLowerCase() : null;
    intent.agentPk = typeof intentParams.agentPk === "string" ? intentParams.agentPk.toLowerCase() : null;
  }
  return intent;
}

function intentHashOf(intent) {
  return sha256Hex("policyvault-risk-intent-hash/1" + canonicalJsonStringify(intent));
}

/*
 * READ-SIDE SELF-CONSISTENCY (G-2 parity, hardening from the postlaunch
 * server-enforcement falsification pass). Every OTHER integrity-bearing
 * record recomputes its own commitment from its own stored body on use —
 * the governance proposal digest (server/src/governance.js
 * recomputedDigestOf) and the intent-manifest hash
 * (server/src/intent-records.js loadManifestRecord). A risk evaluation
 * likewise stores BOTH the full canonical `intent` and its `intentHash`;
 * before that hash is TRUSTED to authorize a released hold, recompute it
 * from the stored intent and refuse on any divergence. This closes the
 * naive DB-tamper vector where only the stored `intentHash` scalar is
 * edited to retarget a released hold at a different intent — the record
 * is then self-inconsistent and fails closed here. (A fully self-
 * consistent forged record — intent AND hash rewritten together — is the
 * irreducible DB-write residual bounded by the covenant: restrictive-only
 * REVIEW coordination can be neutralized by a DB writer but never expands
 * covenant authority; docs/postlaunch/server-enforcement-falsification.md.)
 * canonicalJsonStringify is key-order-independent, so a PostgreSQL jsonb
 * round-trip that reorders the stored intent's keys re-hashes identically
 * — only a real value change trips this.
 */
function assertEvaluationIntegrity(record) {
  if (!record || typeof record !== "object" || record.intent === undefined || record.intent === null) {
    throw riskError(409, "RISK_EVALUATION_INTEGRITY", "risk evaluation record carries no intent — integrity alarm, failing closed");
  }
  let recomputed;
  try {
    recomputed = intentHashOf(record.intent);
  } catch (e) {
    throw riskError(409, "RISK_EVALUATION_INTEGRITY", `stored risk intent does not canonicalize (${e.message}) — integrity alarm, failing closed`);
  }
  if (recomputed !== record.intentHash) {
    throw riskError(409, "RISK_EVALUATION_INTEGRITY", "stored risk evaluation intent does not match its recorded intentHash — tampering or a serialization defect; failing closed and raising an integrity alarm");
  }
}

async function saveEvaluation(config, record) {
  await getStore(config).write(Categories.RISK_EVALUATION, record.evaluationId, record);
  return record;
}

async function loadEvaluation(config, evaluationId) {
  return getStore(config).read(Categories.RISK_EVALUATION, evaluationId);
}

/*
 * RC-UX-1: consume a RELEASED hold for an id-less re-submission of the
 * EXACT reviewed intent (gateOperationRisk path 2 in the header comment).
 *
 * Match key (ALL must hold, checked against the durable record at claim
 * time, never only a listing snapshot): schema, vaultId, canonical
 * intentHash, status RELEASED, and controlsVersion — the org-controls
 * CAS version the evaluation was created under must equal the version
 * governing THIS request. The version binding is the staleness rule: a
 * risk-configuration change (any saveOrgControls, even a no-op re-save)
 * invalidates pending releases for the ID-LESS path and forces a fresh
 * evaluation under the new configuration. (The explicit riskEvaluationId
 * path keeps its existing cross-version semantics unchanged.)
 *
 * Exactly-once (per backend):
 *   postgres — one atomic conditional UPDATE ... WHERE status='RELEASED'
 *     (single-statement autocommit; the row lock is the cross-process
 *     arbiter; rowCount 0 = someone else consumed it first).
 *   json — the released single-writer/single-process backend: an
 *     in-process synchronous claim registry arbitrates first (a bare
 *     read-check-write is NOT atomic across its await boundaries even
 *     single-threaded), then the durable record is re-read, re-verified,
 *     written CONSUMED with a unique claim token, and re-read again —
 *     a token mismatch (an out-of-contract writer) loses cleanly.
 * A claim loser NEVER errors here: it falls through to the next
 * candidate and finally to the fresh-evaluation path, which HOLDS —
 * default-restrictive. A record that matched on its stored intentHash
 * but is self-inconsistent (intent does not re-hash to intentHash)
 * throws RISK_EVALUATION_INTEGRITY exactly like the explicit path —
 * tampering is an alarm, never something to skip silently.
 *
 * The winner's record is stamped status=CONSUMED + consumedVia=
 * "RELEASED_INTENT_REMATCH" + consumedAt AT CLAIM TIME (before the
 * build). If the subsequent build fails the release stays consumed —
 * deliberately restrictive: a review authorization is never silently
 * revived after the operation it approved misfired; the operator
 * requests a new review. recordRiskOutcome later adds
 * consumedByRequestId/consumedTxId/policyGate on build success, exactly
 * as on the explicit path.
 */
const rematchClaimsInFlight = new Set();

async function consumeReleasedHoldForIntent(config, { vaultId, intentHash, controlsVersion }) {
  // Evaluations exist only for configured controls (version >= 1); a
  // missing/non-integer version can never match — restrictive.
  if (!Number.isInteger(controlsVersion) || controlsVersion < 1) return null;
  const store = getStore(config);
  const matches = (r) =>
    r &&
    typeof r === "object" &&
    r.schema === RISK_EVALUATION_SCHEMA &&
    r.vaultId === vaultId &&
    r.status === "RELEASED" &&
    r.intentHash === intentHash &&
    r.controlsVersion === controlsVersion;
  const candidates = (await store.listValues(Categories.RISK_EVALUATION))
    .filter(matches)
    .sort((a, b) => {
      const ta = String(a.releasedAt ?? a.createdAt ?? "");
      const tb = String(b.releasedAt ?? b.createdAt ?? "");
      return ta < tb ? -1 : ta > tb ? 1 : a.evaluationId < b.evaluationId ? -1 : 1;
    }); // deterministic: oldest release first

  for (const candidate of candidates) {
    const id = candidate.evaluationId;
    if (typeof id !== "string" || !id) continue;

    if (store.kind === "postgres") {
      /* Atomic cross-process claim. Table name per sdk/src/store.js
       * CATEGORY_TABLE[RISK_EVALUATION]; raw-pool access is the
       * established server idiom (audit-chain.js, platform-store.js). */
      const patch = {
        status: "CONSUMED",
        consumedVia: "RELEASED_INTENT_REMATCH",
        consumedAt: new Date().toISOString(),
        rematchClaimToken: crypto.randomUUID()
      };
      const r = await store.pool().query(
        `UPDATE risk_evaluations SET value = value || $3::jsonb, updated_at = now()
          WHERE network_id = $1 AND key = $2
            AND value->>'status' = 'RELEASED'
            AND value->>'schema' = $4
            AND value->>'vaultId' = $5
            AND value->>'intentHash' = $6
            AND value->>'controlsVersion' = $7
          RETURNING value`,
        [config.networkId, id, JSON.stringify(patch), RISK_EVALUATION_SCHEMA, vaultId, intentHash, String(controlsVersion)]
      );
      if (r.rowCount !== 1) continue; // raced/changed: lose cleanly
      const won = r.rows[0].value;
      assertEvaluationIntegrity(won); // tamper alarm (record already burned — restrictive)
      if (won.intentHash !== intentHash) {
        throw riskError(409, "RISK_EVALUATION_INTEGRITY", "consumed risk evaluation no longer matches the reviewed intent — tampering between match and claim; failing closed");
      }
      return won;
    }

    /* JSON single-writer backend. */
    if (rematchClaimsInFlight.has(id)) continue; // another in-process attempt owns this claim window
    rematchClaimsInFlight.add(id); // synchronous check+add: atomic in single-threaded JS
    try {
      const fresh = await loadEvaluation(config, id);
      if (!matches(fresh)) continue; // consumed/changed since the listing: lose cleanly
      assertEvaluationIntegrity(fresh); // tamper alarm BEFORE the claim is written (fail closed)
      const token = crypto.randomUUID();
      const claimed = {
        ...fresh,
        status: "CONSUMED",
        consumedVia: "RELEASED_INTENT_REMATCH",
        consumedAt: new Date().toISOString(),
        rematchClaimToken: token
      };
      await saveEvaluation(config, claimed);
      // Re-read verification of the single-writer contract: an
      // out-of-contract concurrent writer means we cannot prove the
      // claim is exclusively ours — lose cleanly (fresh evaluation HOLDS).
      const verify = await loadEvaluation(config, id);
      if (!verify || verify.status !== "CONSUMED" || verify.rematchClaimToken !== token) continue;
      return verify;
    } finally {
      rematchClaimsInFlight.delete(id);
    }
  }
  return null;
}

/*
 * Gate one operation through the organization's risk pipeline.
 * Returns { skipped: true } when no controls apply (personal vault, no
 * adapters, review not required), else { evaluationId, decision } for
 * ALLOW / a consumed release. Throws (pure refusal — nothing durable
 * beyond the evidence record + audit row was created) on DENY, on a
 * fresh REVIEW hold, and on any configuration this build cannot
 * interpret (fail closed).
 *
 * `riskEvaluationId` (optional, from the client) names a RELEASED hold
 * to consume: it must be RELEASED, for this vault, and for the EXACT
 * canonical intent being executed now.
 *
 * Without `riskEvaluationId`, a RELEASED hold for this vault whose
 * intentHash equals THIS exact intent's hash (created under the SAME
 * org-controls version) is consumed exactly once instead of spawning a
 * duplicate hold — the RC-UX-1 solo continuation (header comment,
 * path 2). Every non-match falls through to the fresh evaluation.
 */
async function gateOperationRisk({ config, vaultId, orgId, controls, action, params, signerAddress, signerXOnly, sdkAction, riskEvaluationId }) {
  const risk = controls.risk;
  const hasControls = (risk.adapters ?? []).length > 0 || risk.reviewRequired === true || (risk.onEmpty !== undefined && risk.onEmpty !== "ALLOW");
  if (!hasControls) return { skipped: true };

  const intent = buildRiskIntent({ config, vaultId, action, params, signerAddress, signerXOnly, sdkAction });
  const intentHash = intentHashOf(intent);

  /* Consume a released hold for THIS exact intent. */
  if (riskEvaluationId !== undefined && riskEvaluationId !== null) {
    const held = await loadEvaluation(config, riskEvaluationId);
    if (!held || held.schema !== RISK_EVALUATION_SCHEMA || held.vaultId !== vaultId) {
      throw riskError(404, "RISK_EVALUATION_NOT_FOUND", "no such risk evaluation for this vault");
    }
    // READ-SIDE re-hash BEFORE the stored intentHash is trusted (G-2 parity):
    // a hold whose stored intent and intentHash disagree is tampered.
    assertEvaluationIntegrity(held);
    if (held.status !== "RELEASED") {
      throw riskError(409, "RISK_EVALUATION_NOT_RELEASED", `risk evaluation is ${held.status}; only a RELEASED hold can authorize this operation`);
    }
    if (held.intentHash !== intentHash) {
      throw riskError(409, "RISK_INTENT_CHANGED", "the operation no longer matches the reviewed intent — a changed intent is a new evaluation");
    }
    return { evaluationId: held.evaluationId, decision: "REVIEW", released: true, record: held };
  }

  /* RC-UX-1: id-less deterministic continuation — an exact re-submission
   * of a reviewed-and-released intent consumes that release exactly once
   * and proceeds, instead of looping into a duplicate hold. Restrictive-
   * only: any non-match (or a lost claim race) falls through to the
   * fresh evaluation below, which holds/denies per configuration. */
  const rematched = await consumeReleasedHoldForIntent(config, { vaultId, intentHash, controlsVersion: controls.version });
  if (rematched) {
    await appendAudit(config, {
      kind: "risk",
      vaultId,
      orgId,
      action,
      actor: "system",
      actorXOnly: null,
      result: "RISK_RELEASED_CONSUMED",
      detail: `risk evaluation ${rematched.evaluationId}: released hold consumed by an exact re-submission of the reviewed intent (no riskEvaluationId supplied; matched vault + canonical intent hash + controls version ${rematched.controlsVersion}; consumed exactly once)`,
      riskEvaluationId: rematched.evaluationId,
      intentHash
    });
    return { evaluationId: rematched.evaluationId, decision: "REVIEW", released: true, rematched: true, record: rematched };
  }

  /* Fresh evaluation. Adapter construction fails closed on unknown
   * stored types; the composition core enforces deny-wins and
   * never-silent-ALLOW error/timeout semantics. */
  const adapters = buildAdaptersFromConfig(risk);
  const composeConfig = {
    onAdapterError: risk.onAdapterError,
    ...(risk.onEmpty !== undefined ? { onEmpty: risk.onEmpty } : {}),
    ...(risk.timeoutMs !== undefined ? { timeoutMs: risk.timeoutMs } : {})
  };
  const context = { orgId, riskPolicy: { reviewRequired: risk.reviewRequired === true } };
  const result = await evaluateRisk({ adapters, intent, context, config: composeConfig });

  const evaluationId = crypto.randomUUID();
  const record = await saveEvaluation(config, {
    schema: RISK_EVALUATION_SCHEMA,
    evaluationId,
    networkId: config.networkId,
    vaultId,
    orgId,
    intentHash,
    intent,
    // The org-controls CAS version this evaluation was created under —
    // the staleness binding for the id-less RELEASED continuation
    // (consumeReleasedHoldForIntent). Evidence-only, additive; NOT part
    // of the canonical intent or its hash preimage.
    controlsVersion: Number.isInteger(controls.version) ? controls.version : null,
    initiatorXOnly: signerXOnly ?? null,
    decision: result.decision,
    results: result.results,
    codes: result.codes,
    config: result.config,
    status: result.decision === "ALLOW" ? "ALLOWED" : result.decision === "DENY" ? "DENIED" : "REVIEW_HELD",
    createdAt: new Date().toISOString()
  });

  await appendAudit(config, {
    kind: "risk",
    vaultId,
    orgId,
    action,
    actor: "system",
    actorXOnly: null,
    result: `RISK_${result.decision}`,
    detail: `risk evaluation ${evaluationId}: ${result.decision}${result.codes.length ? ` [${result.codes.join(", ")}]` : ""} (${adapters.length} adapters)`,
    riskEvaluationId: evaluationId,
    intentHash
  });

  if (result.decision === "DENY") {
    throw riskError(403, "RISK_DENIED", "the organization's risk controls refused this operation", {
      riskEvaluation: { evaluationId, decision: result.decision, codes: result.codes }
    });
  }
  if (result.decision === "REVIEW") {
    throw riskError(409, "RISK_REVIEW_REQUIRED", "the organization's risk controls require human review before this operation can proceed", {
      riskEvaluation: { evaluationId, decision: result.decision, codes: result.codes }
    });
  }
  return { evaluationId, decision: result.decision, released: false, record };
}

/*
 * After the SDK build succeeded (the policy pipeline allowed), record
 * the structural policy gate application and consume a released hold.
 * applyRiskToPolicyDecision is the invariant-2 gate: it is exercised
 * here with the REAL composed decision so the stored evidence proves
 * which side decided. (A build failure is a policy refusal on its own
 * path; risk is never consulted there — the DENY branch cannot be
 * upgraded by construction.)
 */
async function recordRiskOutcome(config, gate, { requestId, txId }) {
  if (!gate || gate.skipped) return null;
  const final = applyRiskToPolicyDecision({ policyDecision: "ALLOW", riskDecision: gate.decision === "REVIEW" ? "REVIEW" : gate.decision });
  const record = await loadEvaluation(config, gate.evaluationId);
  if (record) {
    record.status = "CONSUMED";
    record.consumedByRequestId = requestId ?? null;
    record.consumedTxId = txId ?? null;
    record.consumedAt = new Date().toISOString();
    record.policyGate = final;
    await saveEvaluation(config, record);
    // Platform event (surface 18): the evaluation was consumed by a real
    // build. Failure-isolated notification — never authority, never a
    // request-path failure (safeEmitPlatformEvent never throws).
    await require("./events").safeEmitPlatformEvent(config, {
      type: "risk.evaluation.consumed",
      vaultId: record.vaultId ?? null,
      orgId: record.orgId ?? null,
      correlation: { riskEvaluationId: record.evaluationId, requestId: requestId ?? undefined, txId: txId ?? undefined },
      data: { action: record.intent?.action }
    });
  }
  return gate.evaluationId;
}

/*
 * Release a REVIEW hold. Authorization (checked by the ROUTE with the
 * tenancy principal; re-checked here from durable facts):
 *   - hosted: the releasing wallet must be an authorized reviewer
 *     (org tenantOwner or the vault owner) and MUST NOT be the
 *     initiating signer — the acting signer never releases their own
 *     hold. Self-hosted (no sessions): the single local operator may
 *     release; recorded as such.
 */
async function releaseEvaluation(config, evaluationId, { releasedByXOnly }) {
  const record = await loadEvaluation(config, evaluationId);
  if (!record || record.schema !== RISK_EVALUATION_SCHEMA) {
    throw riskError(404, "RISK_EVALUATION_NOT_FOUND", "no such risk evaluation");
  }
  // A hold whose stored intent and intentHash disagree is tampered — a
  // reviewer must never release a self-inconsistent record (G-2 parity).
  assertEvaluationIntegrity(record);
  if (record.status !== "REVIEW_HELD") {
    throw riskError(409, "RISK_EVALUATION_NOT_HELD", `risk evaluation is ${record.status}; only a REVIEW_HELD evaluation can be released`);
  }
  if (releasedByXOnly && record.initiatorXOnly && releasedByXOnly === record.initiatorXOnly) {
    throw riskError(403, "RISK_SELF_RELEASE_FORBIDDEN", "the acting signer cannot release their own review hold");
  }
  record.status = "RELEASED";
  record.releasedBy = releasedByXOnly ?? "self-hosted-operator";
  record.releasedAt = new Date().toISOString();
  await saveEvaluation(config, record);
  await appendAudit(config, {
    kind: "risk",
    vaultId: record.vaultId,
    orgId: record.orgId,
    action: record.intent?.action,
    actor: "system",
    actorXOnly: releasedByXOnly ?? null,
    result: "RISK_HOLD_RELEASED",
    detail: `risk evaluation ${evaluationId} released for execution of the exact reviewed intent`,
    riskEvaluationId: evaluationId,
    intentHash: record.intentHash
  });
  return record;
}

module.exports = {
  RISK_EVALUATION_SCHEMA,
  RISK_INTENT_SCHEMA,
  buildRiskIntent,
  intentHashOf,
  assertEvaluationIntegrity,
  gateOperationRisk,
  consumeReleasedHoldForIntent,
  recordRiskOutcome,
  releaseEvaluation,
  loadEvaluation
};
