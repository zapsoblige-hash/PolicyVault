"use strict";

/*
 * PolicyVault governance authority-delta EXPLANATIONS (v1).
 *
 * Turns a core/governance classifier result — classifyPolicyDelta or
 * classifyMigrationDelta — into:
 *
 *   structured(deltaResult)    -> "policyvault-governance-explanation/1"
 *   humanReadable(deltaResult) -> deterministic English lines
 *
 * e.g. "AUTHORITY EXPANSION: per-spend cap increases from 20 to 30 KAS
 * — requires owner/quorum approval …", one line per changed governed
 * field, with mixed/opaque/unknown changes always carried on the
 * EXPANSION side with an explicit warning.
 *
 * FAIL-CLOSED RULES:
 *   - The supplied result is STRICTLY validated (shape, directions,
 *     versions) and its aggregate classification is RECOMPUTED from the
 *     per-field directions; any divergence refuses
 *     (CLASSIFICATION_MISMATCH — the §7.1 integrity-alarm rule: stored
 *     labels are never trusted over recomputation).
 *   - Unknown covenant versions, unknown directions, and malformed
 *     entries refuse. Unknown per-field CODES render generically under
 *     their validated direction (a code never softens a direction).
 *   - Both entry points are TOTAL: they never throw; malformed input
 *     and internal errors produce a REFUSAL explanation.
 *   - Amounts render as exact KAS decimal strings (integer math only);
 *     keys/roots render IN FULL (no truncation).
 *
 * TRUST NOTE (carried in every explanation): this module explains the
 * delta result it is given. Per docs/postlaunch/governance-spec.md §7.1
 * every consumer recomputes classifyPolicyDelta from the proposal's
 * before/after tuples at each decision point — an explanation is a
 * rendering, never an authority.
 *
 * Portable shared core: pure CommonJS, zero external dependencies; the
 * only module dependencies are the public exports of core/governance
 * and the local KAS renderer.
 */

const {
  CLASSIFICATION_REDUCTION,
  CLASSIFICATION_EXPANSION,
  DIRECTION_NEUTRAL,
  governedVersions
} = require("../governance");
const { sompiToKasString } = require("./kas");


function sanitizeDetail(value) {
  let s = String(value == null ? "" : value);
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    // C0/C1 controls (incl. newline/CR/tab) and bidi overrides -> single space
    const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
    const isBidi = (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    out += (isControl || isBidi) ? " " : ch;
  }
  out = out.replace(/ +/g, " ").trim();
  return out.length > 500 ? out.slice(0, 497) + "..." : out;
}

const GOVERNANCE_EXPLANATION_VERSION_1 = "policyvault-governance-explanation/1";

const GOVERNANCE_EXPLANATION_VERDICTS = Object.freeze({
  EXPLAINED: "EXPLAINED",
  REFUSED: "REFUSED"
});

const TRUST_NOTE =
  "This explanation renders a classifier result; it grants nothing. Consumers recompute classifyPolicyDelta from the proposal's before/after tuples at every decision point, and every covenant policy transition still requires the owner's wallet signature over the exact frozen transaction bytes, verified by Kaspa consensus.";

const CEREMONY = Object.freeze({
  [CLASSIFICATION_EXPANSION]:
    "Requires owner/quorum approval — the strongest governance ceremony: the configured governance quorum approves the proposal digest, the delay window elapses, and the owner signs the exact frozen transaction bytes in their wallet.",
  [CLASSIFICATION_REDUCTION]:
    "Safely-restrictive change — available immediately to the vault owner; the owner's wallet signature over the exact frozen transaction bytes is still required."
});

/* Leaf-field units (real covenant/SDK field names). */
const FIELD_UNITS = Object.freeze({
  maxPerSpend: "sompi",
  periodBudget: "sompi",
  approvalThresholdAmount: "sompi",
  approvalThreshold: "sompi",
  agentMaxFeePerTx: "sompi",
  periodSpent: "sompi",
  periodLengthDaa: "daa",
  periodStartDaa: "daa",
  approvalM: "count",
  paused: "flag",
  delegateActive: "flag",
  delegate: "key",
  agentRoot: "root",
  recipientRoot: "root",
  agentRecipientRoot: "root",
  recipients: "keyset",
  approvers: "keyset",
  agents: "keyset"
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const k of Object.keys(value)) deepFreeze(value[k]);
  }
  return value;
}

function isObjectLike(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isCanonicalDigits(v) {
  return typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v);
}

function isHex64(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function leafFieldName(field) {
  const parts = String(field).split(".");
  return parts[parts.length - 1];
}

function unitOf(field) {
  return FIELD_UNITS[leafFieldName(field)] ?? "raw";
}

function refusalDocument(reason, failures) {
  const codes = [...new Set(failures.map((f) => f.code))].sort();
  return deepFreeze({
    explanationVersion: GOVERNANCE_EXPLANATION_VERSION_1,
    verdict: GOVERNANCE_EXPLANATION_VERDICTS.REFUSED,
    refusal: { reason: String(reason), codes, failures: failures.map((f) => ({ code: String(f.code), detail: String(f.detail) })) },
    kind: null,
    classification: null,
    lane: null,
    covenantVersion: null,
    fromVersion: null,
    toVersion: null,
    mixed: false,
    emergencyFreeze: false,
    headline: null,
    ceremony: null,
    perField: null,
    unchangedCount: null,
    codes: null,
    note: TRUST_NOTE
  });
}

/* ------------------------------------------------------------------ */
/* strict validation of the classifier result                          */
/* ------------------------------------------------------------------ */

/* Returns { kind, problems: [{code, detail}] }. */
function validateDeltaResult(result) {
  const problems = [];
  const push = (code, detail) => problems.push({ code, detail });

  if (!isObjectLike(result)) {
    push("INVALID_DELTA_RESULT", "the delta result must be the object returned by classifyPolicyDelta / classifyMigrationDelta");
    return { kind: null, problems };
  }
  if (result.classification !== CLASSIFICATION_REDUCTION && result.classification !== CLASSIFICATION_EXPANSION) {
    push("UNKNOWN_CLASSIFICATION", `classification ${JSON.stringify(result.classification)} is unknown — failing closed`);
  }
  if (!Array.isArray(result.codes) || result.codes.some((c) => typeof c !== "string")) {
    push("INVALID_DELTA_RESULT", "codes must be an array of strings");
  }
  if (!Array.isArray(result.perField)) {
    push("INVALID_DELTA_RESULT", "perField must be an array");
  }

  const isMigration = Object.prototype.hasOwnProperty.call(result, "fromVersion") || Object.prototype.hasOwnProperty.call(result, "toVersion");
  const versions = governedVersions();
  let kind = null;
  if (isMigration) {
    kind = "covenant-migration";
    if (!versions.includes(result.fromVersion)) push("UNKNOWN_VERSION", `fromVersion ${JSON.stringify(result.fromVersion)} is not a governed covenant version`);
    if (!versions.includes(result.toVersion)) push("UNKNOWN_VERSION", `toVersion ${JSON.stringify(result.toVersion)} is not a governed covenant version`);
    if (result.classification !== CLASSIFICATION_EXPANSION) {
      push("CLASSIFICATION_MISMATCH", "a covenant migration is ALWAYS an authority expansion — a non-EXPANSION migration result is refused");
    }
    if (Array.isArray(result.codes) && !result.codes.includes("COVENANT_MIGRATION")) {
      push("INVALID_DELTA_RESULT", "a migration result must carry the COVENANT_MIGRATION code");
    }
    if (Array.isArray(result.perField) && result.perField.length !== 0) {
      push("INVALID_DELTA_RESULT", "a migration result carries no per-field entries");
    }
  } else {
    kind = "policy-change";
    if (!versions.includes(result.covenantVersion)) {
      push("UNKNOWN_VERSION", `covenantVersion ${JSON.stringify(result.covenantVersion)} is not a governed covenant version — failing closed`);
    }
  }

  if (Array.isArray(result.perField)) {
    result.perField.forEach((entry, i) => {
      if (!isObjectLike(entry)) {
        push("INVALID_DELTA_RESULT", `perField[${i}] must be an object`);
        return;
      }
      if (typeof entry.field !== "string" || entry.field.length === 0) push("INVALID_DELTA_RESULT", `perField[${i}].field must be a non-empty string`);
      if (entry.direction !== CLASSIFICATION_REDUCTION && entry.direction !== CLASSIFICATION_EXPANSION && entry.direction !== DIRECTION_NEUTRAL) {
        push("UNKNOWN_DIRECTION", `perField[${i}].direction ${JSON.stringify(entry.direction)} is unknown — failing closed`);
      }
      if (typeof entry.code !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(entry.code)) {
        push("INVALID_DELTA_RESULT", `perField[${i}].code must be an UPPER_SNAKE code`);
      }
      for (const side of ["before", "after"]) {
        if (Object.prototype.hasOwnProperty.call(entry, side) && entry[side] !== undefined) {
          if (typeof entry[side] !== "string") push("INVALID_DELTA_RESULT", `perField[${i}].${side} must be a string when present`);
        }
      }
      if (Object.prototype.hasOwnProperty.call(entry, "member") && entry.member !== undefined && !isHex64(entry.member)) {
        push("INVALID_DELTA_RESULT", `perField[${i}].member must be 32-byte lowercase hex when present`);
      }
    });

    /* Recompute the aggregate from directions — stored labels are never
     * trusted over recomputation (§7.1 integrity alarm). */
    if (!isMigration && problems.length === 0) {
      const expansions = result.perField.filter((e) => e.direction === CLASSIFICATION_EXPANSION).length;
      const reductions = result.perField.filter((e) => e.direction === CLASSIFICATION_REDUCTION).length;
      if (expansions === 0 && reductions === 0) {
        push("NO_CHANGE", "every per-field entry is neutral — a no-op is not a governable change and cannot be explained as one");
      } else {
        const recomputed = expansions > 0 ? CLASSIFICATION_EXPANSION : CLASSIFICATION_REDUCTION;
        if (recomputed !== result.classification) {
          push(
            "CLASSIFICATION_MISMATCH",
            `stored classification ${result.classification} diverges from the recomputed ${recomputed} — integrity alarm, failing closed`
          );
        }
        const mixed = expansions > 0 && reductions > 0;
        const codesSayMixed = Array.isArray(result.codes) && result.codes.includes("MIXED_CHANGE");
        if (mixed !== codesSayMixed) {
          push("CLASSIFICATION_MISMATCH", "MIXED_CHANGE marker diverges from the per-field directions — integrity alarm, failing closed");
        }
      }
    }
  }
  return { kind, problems };
}

/* ------------------------------------------------------------------ */
/* per-field descriptions                                              */
/* ------------------------------------------------------------------ */

function formatValue(unit, value, field) {
  if (value === null) return null;
  if (unit === "sompi") {
    return isCanonicalDigits(value) ? `${sompiToKasString(value, field)} KAS` : String(value);
  }
  if (unit === "daa") return `DAA ${value}`;
  return String(value);
}

const FIELD_LABELS = Object.freeze({
  maxPerSpend: "per-spend cap",
  periodBudget: "period budget",
  periodLengthDaa: "budget period length",
  periodStartDaa: "budget period start",
  periodSpent: "recorded period spending",
  approvalThresholdAmount: "approval threshold",
  approvalThreshold: "approval threshold",
  agentMaxFeePerTx: "per-transaction fee cap",
  approvalM: "approval quorum",
  paused: "pause flag",
  delegate: "delegate key",
  delegateActive: "delegate activation",
  recipients: "recipient allowlist",
  approvers: "approver set",
  agents: "agent set",
  agentRoot: "agent registry commitment",
  recipientRoot: "recipient allowlist commitment",
  agentRecipientRoot: "recipient allowlist commitment"
});

function fieldLabel(field) {
  const leaf = leafFieldName(field);
  const base = FIELD_LABELS[leaf] ?? leaf;
  const agentMatch = /^agents\[([0-9a-f]{64})\]\./.exec(String(field));
  if (agentMatch) return `agent ${agentMatch[1]} ${base}`;
  return base;
}

/* Deterministic English description of one changed per-field entry.
 * Direction is validated upstream; an unknown CODE renders generically
 * under its validated direction (a code never softens a direction). */
function describeEntry(entry) {
  const unit = unitOf(entry.field);
  const label = fieldLabel(entry.field);
  const before = Object.prototype.hasOwnProperty.call(entry, "before") ? (entry.before ?? null) : null;
  const after = Object.prototype.hasOwnProperty.call(entry, "after") ? (entry.after ?? null) : null;
  const member = Object.prototype.hasOwnProperty.call(entry, "member") ? (entry.member ?? null) : null;
  const b = formatValue(unit, before, `${entry.field}.before`);
  const a = formatValue(unit, after, `${entry.field}.after`);
  const fromTo = b !== null && a !== null ? ` from ${b} to ${a}` : "";

  switch (entry.code) {
    case "EMERGENCY_FREEZE":
      return "Emergency freeze: the vault is paused — all delegated spending stops (break-glass owner action).";
    case "RESUME_SPENDING":
      return "Resume spending: the vault is unpaused — delegated spending becomes possible again.";
    case "DELEGATE_KEY_CHANGED":
      return `Delegate key changes from ${before} to ${after} — a different key gains spending authority.`;
    case "DELEGATE_REVOKED":
      return "Delegate revoked: the delegate key loses spending authority.";
    case "DELEGATE_ENABLED":
      return "Delegate enabled: the delegate key gains spending authority.";
    case "APPROVAL_QUORUM_RAISED":
      return `Approval quorum rises from ${before} to ${after} required approval(s) — more approvals per above-threshold spend.`;
    case "APPROVAL_QUORUM_WEAKENED":
      return `Approval quorum drops from ${before} to ${after} required approval(s) — fewer approvals per above-threshold spend.`;
    case "APPROVAL_THRESHOLD_LOWERED":
    case "AGENT_APPROVAL_THRESHOLD_LOWERED":
      return `The ${label} decreases${fromTo} — MORE spends require approver signatures.`;
    case "APPROVAL_THRESHOLD_RAISED":
    case "AGENT_APPROVAL_THRESHOLD_RAISED":
      return `The ${label} increases${fromTo} — more spends escape the approval tier.`;
    case "PER_SPEND_CAP_LOWERED":
    case "AGENT_PER_SPEND_CAP_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "PER_SPEND_CAP_RAISED":
    case "AGENT_PER_SPEND_CAP_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "PERIOD_BUDGET_LOWERED":
    case "AGENT_PERIOD_BUDGET_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "PERIOD_BUDGET_RAISED":
    case "AGENT_PERIOD_BUDGET_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "PERIOD_LENGTHENED":
    case "AGENT_PERIOD_LENGTHENED":
      return `The ${label} lengthens${fromTo} — the long-run spending rate falls.`;
    case "PERIOD_SHORTENED":
    case "AGENT_PERIOD_SHORTENED":
      return `The ${label} shortens${fromTo} — the budget refreshes faster.`;
    case "AGENT_PERIOD_PHASE_CHANGED":
      return `The ${label} moves${fromTo} — a phase change can open a fresh budget period early, so it is treated as an expansion.`;
    case "AGENT_BUDGET_CONSUMPTION_RECORDED":
      return `The ${label} rises${fromTo} — consumption is recorded (less budget remains).`;
    case "AGENT_BUDGET_REFUNDED":
      return `The ${label} falls${fromTo} — already-consumed budget is refunded (a fresh spending lane this period).`;
    case "AGENT_FEE_CAP_LOWERED":
      return `The ${label} decreases${fromTo}.`;
    case "AGENT_FEE_CAP_RAISED":
      return `The ${label} increases${fromTo}.`;
    case "RECIPIENT_REMOVED":
    case "AGENT_RECIPIENT_REMOVED":
      return `Recipient ${member} is REMOVED from the ${label}.`;
    case "RECIPIENT_ADDED":
    case "AGENT_RECIPIENT_ADDED":
      return `Recipient ${member} is ADDED to the ${label} — a new key can be paid.`;
    case "APPROVER_REMOVED":
      return `Approver ${member} is REMOVED from the approver set.`;
    case "APPROVER_ADDED":
      return `Approver ${member} is ADDED to the approver set — a new key gains approval authority.`;
    case "AGENT_REMOVED":
      return `Agent ${member} is REMOVED — its key loses all delegated spending authority.`;
    case "AGENT_ADDED":
      return `Agent ${member} is ADDED — a new key gains delegated spending authority.`;
    case "OPAQUE_COMMITMENT_CHANGED":
      return before !== null && after !== null
        ? `The ${label} is replaced OPAQUELY (${before} -> ${after}) — membership cannot be compared, so this is treated as an expansion.`
        : `The ${label} changes in a form whose membership cannot be compared — treated as an expansion.`;
    case "AGENT_SET_OPAQUE":
      return before !== null && after !== null
        ? `The ${label} is replaced OPAQUELY (${before} -> ${after}) — the agent set cannot be compared, so this is treated as an expansion.`
        : `The ${label} changes in a form whose agent set cannot be compared — treated as an expansion.`;
    default: {
      const memberPart = member !== null ? ` member ${member}` : "";
      const valuePart = fromTo !== "" ? fromTo : "";
      return `The ${label}${memberPart} changes${valuePart} (${entry.code}).`;
    }
  }
}

function shortChangeSummary(entry) {
  const unit = unitOf(entry.field);
  const label = fieldLabel(entry.field);
  const hasBoth = typeof entry.before === "string" && typeof entry.after === "string";
  if (hasBoth && (unit === "sompi" || unit === "count" || unit === "daa")) {
    const b = formatValue(unit, entry.before, entry.field);
    const a = formatValue(unit, entry.after, entry.field);
    const verb = entry.direction === CLASSIFICATION_EXPANSION ? "increases" : "decreases";
    if (unit === "daa" || unit === "count") return `${label} changes from ${b} to ${a}`;
    return `${label} ${verb} from ${b} to ${a}`;
  }
  return `${label} changes`;
}

/* ------------------------------------------------------------------ */
/* structured + human-readable                                         */
/* ------------------------------------------------------------------ */

/*
 * Structured governance explanation. TOTAL: never throws; refusal on
 * malformed/inconsistent input.
 */
function structured(deltaResult) {
  try {
    const { kind, problems } = validateDeltaResult(deltaResult);
    if (problems.length > 0) {
      return refusalDocument("The governance delta result is malformed or inconsistent — failing closed.", problems);
    }

    const isMigration = kind === "covenant-migration";
    const changed = isMigration ? [] : deltaResult.perField.filter((e) => e.direction !== DIRECTION_NEUTRAL);
    const expansions = changed.filter((e) => e.direction === CLASSIFICATION_EXPANSION);
    const reductions = changed.filter((e) => e.direction === CLASSIFICATION_REDUCTION);
    const mixed = expansions.length > 0 && reductions.length > 0;
    const emergencyFreeze = !isMigration && changed.some((e) => e.code === "EMERGENCY_FREEZE");

    let headline;
    if (isMigration) {
      headline = `AUTHORITY EXPANSION: covenant migration from ${deltaResult.fromVersion} to ${deltaResult.toVersion} — requires owner/quorum approval.`;
    } else {
      const summary =
        changed.length === 1
          ? shortChangeSummary(changed[0])
          : `${changed.length} governed policy changes (${expansions.length} expansion(s), ${reductions.length} reduction(s))`;
      headline =
        deltaResult.classification === CLASSIFICATION_EXPANSION
          ? `AUTHORITY EXPANSION: ${summary} — requires owner/quorum approval.`
          : `AUTHORITY REDUCTION: ${summary} — owner signature only, available immediately.`;
    }

    const perField = isMigration
      ? []
      : deltaResult.perField.map((entry) => ({
          field: entry.field,
          direction: entry.direction,
          code: entry.code,
          before: typeof entry.before === "string" ? entry.before : null,
          after: typeof entry.after === "string" ? entry.after : null,
          member: typeof entry.member === "string" ? entry.member : null,
          unit: unitOf(entry.field),
          changed: entry.direction !== DIRECTION_NEUTRAL,
          description: entry.direction === DIRECTION_NEUTRAL ? `The ${fieldLabel(entry.field)} is unchanged.` : describeEntry(entry)
        }));

    return deepFreeze({
      explanationVersion: GOVERNANCE_EXPLANATION_VERSION_1,
      verdict: GOVERNANCE_EXPLANATION_VERDICTS.EXPLAINED,
      refusal: null,
      kind,
      classification: deltaResult.classification,
      lane: deltaResult.classification,
      covenantVersion: isMigration ? null : deltaResult.covenantVersion,
      fromVersion: isMigration ? deltaResult.fromVersion : null,
      toVersion: isMigration ? deltaResult.toVersion : null,
      mixed,
      emergencyFreeze,
      headline,
      ceremony: CEREMONY[deltaResult.classification],
      perField,
      unchangedCount: isMigration ? 0 : deltaResult.perField.length - changed.length,
      codes: [...deltaResult.codes],
      note: TRUST_NOTE
    });
  } catch (e) {
    return refusalDocument("The governance explanation engine failed internally — failing closed.", [
      { code: "EXPLAIN_INTERNAL", detail: `${e.message}` }
    ]);
  }
}

function refusalLines(doc) {
  const lines = [];
  lines.push("GOVERNANCE EXPLANATION REFUSED — do not act on this proposal rendering.");
  lines.push(`Reason: ${sanitizeDetail(doc.refusal.reason)}`);
  lines.push(`Refusal codes: ${doc.refusal.codes.join(", ")}.`);
  for (const f of doc.refusal.failures) {
    lines.push(`- ${f.code}: ${sanitizeDetail(f.detail)}`);
  }
  lines.push("Recompute the classification from the proposal's before/after tuples (classifyPolicyDelta) and try again.");
  return lines;
}

/*
 * Deterministic English lines for the governance UI. TOTAL: never
 * throws. Same input -> byte-identical output.
 */
function humanReadable(deltaResult) {
  const doc = structured(deltaResult);
  if (doc.verdict === GOVERNANCE_EXPLANATION_VERDICTS.REFUSED) {
    return deepFreeze(refusalLines(doc));
  }
  const lines = [];
  lines.push(doc.headline);
  if (doc.mixed) {
    lines.push(
      "WARNING: MIXED CHANGE — this proposal contains reductions AND expansions; the whole proposal takes the EXPANSION lane (MIXED_CHANGE)."
    );
  }
  if (doc.kind === "covenant-migration") {
    lines.push("A covenant migration replaces the vault lineage: a terminal ownerRecover, then a new-version create — two owner wallet signatures.");
    lines.push("Between the two steps the funds sit in the owner's own P2PK output (the documented migration custody model).");
    lines.push("Migrations are ALWAYS classified as an authority expansion, however restrictive the new policy looks.");
  } else {
    for (const entry of doc.perField) {
      if (!entry.changed) continue;
      lines.push(`${entry.direction}: ${entry.description}`);
    }
    if (doc.unchangedCount > 0) {
      lines.push(`${doc.unchangedCount} other governed field(s) are unchanged.`);
    }
  }
  if (doc.emergencyFreeze) {
    lines.push("Emergency freeze is a break-glass owner action: no governance configuration may delay, gate, or block it.");
  }
  lines.push(`Ceremony: ${doc.ceremony}`);
  lines.push(doc.note);
  return deepFreeze(lines);
}

module.exports = {
  GOVERNANCE_EXPLANATION_VERSION_1,
  GOVERNANCE_EXPLANATION_VERDICTS,
  structured,
  humanReadable
};
