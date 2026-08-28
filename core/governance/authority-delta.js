"use strict";

/*
 * PolicyVault post-launch governance — AUTHORITY-DELTA CLASSIFIER.
 *
 * Pure classification of a proposed policy change:
 *
 *   classifyPolicyDelta({ covenantVersion, before, after })
 *     -> { classification: "REDUCTION" | "EXPANSION", covenantVersion,
 *          perField: [...], codes: [...] }
 *
 * The classifier decides ONLY how much governance ceremony a proposal
 * gets (lighter for safely-restrictive changes, strongest for authority
 * expansions). It grants nothing: every covenant policy transition still
 * requires the vault owner's BIP-340 wallet signature over the exact
 * frozen transaction bytes, verified by Kaspa consensus. A hosted
 * administrator or database writer who tampers with stored tuples or a
 * stored classification label changes what the app DISPLAYS, never what
 * the covenant ACCEPTS (docs/hosted-threat-model.md §3: a fully
 * compromised server steals nothing unilaterally; the database cannot
 * sign). Consumers therefore RECOMPUTE this classification from the
 * proposal's before/after tuples at every decision point and never trust
 * a stored label.
 *
 * Fail-closed rules (docs/postlaunch/governance-spec.md §5):
 *   - unknown covenant versions REFUSE (never routed to a default);
 *   - unknown / missing / malformed fields REFUSE;
 *   - a change whose direction cannot be proven restrictive is
 *     EXPANSION (opaque commitment swaps, period-phase changes, mixed
 *     reduction+expansion proposals);
 *   - identical before/after REFUSES (NO_CHANGE) — a no-op is not a
 *     governable change;
 *   - numeric safety: BigInt or base-10 digit strings only, bounded to
 *     the i64 num8 encoding domain; JS numbers, floats, NaN, negatives,
 *     and overflow all REFUSE.
 *
 * Field names below are the REAL covenant/SDK field names, taken from
 * contracts/PolicyVault.v0.{2,3,4,4.1}.sil and
 * sdk/src/{vault-state-v2,vault-state-v3,vault-state-v4,agent-merkle-v4}.js.
 */

const CLASSIFICATION_REDUCTION = "REDUCTION";
const CLASSIFICATION_EXPANSION = "EXPANSION";
const CLASSIFICATIONS = Object.freeze([CLASSIFICATION_REDUCTION, CLASSIFICATION_EXPANSION]);
const DIRECTION_NEUTRAL = "NEUTRAL";
const DIRECTIONS = Object.freeze([CLASSIFICATION_REDUCTION, CLASSIFICATION_EXPANSION, DIRECTION_NEUTRAL]);

/* num8 = OpNum2Bin(v, 8) is injective over i64; 0 <= v < 2^63 covers every
 * consensus-encodable sompi/DAA quantity in the frozen ABIs. */
const I64_MAX = 2n ** 63n - 1n;

const APPROVER_SENTINEL = "00".repeat(32);
const MAX_APPROVERS = 10;

const VERSION_V2 = "policyvault-0.2";
const VERSION_V3 = "policyvault-0.3";
const VERSION_V4 = "policyvault-0.4";
const VERSION_V4_1 = "policyvault-0.4.1";

class GovernanceRefusal extends Error {
  constructor(code, message) {
    super(`authority-delta: ${message}`);
    this.name = "GovernanceRefusal";
    this.code = code;
    this.failClosed = true;
  }
}

function refuse(code, message) {
  throw new GovernanceRefusal(code, message);
}

/* ------------------------------------------------------------------ */
/* Strict primitives (numeric safety, hex identity)                    */
/* ------------------------------------------------------------------ */

/* BigInt or CANONICAL base-10 digit string only ("0" or no leading zero);
 * 0 <= v <= I64_MAX. JS numbers are refused entirely (floating-point risk
 * on funds-relevant quantities). Leading-zero forms ("010") are refused —
 * hardening from the core-v1 falsification pass: the governance proposal
 * digest (canonical.js) is string-sensitive, so one integer value must
 * have exactly one accepted encoding at this boundary or two documents
 * with identical governed VALUES could carry different digests. Matches
 * core/intent's CANONICAL_DIGITS_RE; strictly narrower than before (a
 * previously-accepted non-canonical form now refuses — fail closed). */
const CANONICAL_INTEGER_RE = /^(0|[1-9][0-9]*)$/;
function parseIntegerField(value, field) {
  let amount;
  if (typeof value === "bigint") {
    amount = value;
  } else if (typeof value === "string") {
    if (!CANONICAL_INTEGER_RE.test(value)) {
      refuse("INVALID_INTEGER", `${field} must be a canonical base-10 digit string ("0" or no leading zero), got ${JSON.stringify(value)}`);
    }
    amount = BigInt(value);
  } else {
    refuse(
      "INVALID_INTEGER",
      `${field} must be a BigInt or base-10 digit string (JS numbers are refused: floats/NaN are unsafe for consensus quantities), got ${typeof value}`
    );
  }
  if (amount < 0n) {
    refuse("INVALID_INTEGER", `${field} must not be negative`);
  }
  if (amount > I64_MAX) {
    refuse("INVALID_INTEGER", `${field} exceeds the i64 num8 encoding domain`);
  }
  return amount;
}

function parsePositiveIntegerField(value, field) {
  const amount = parseIntegerField(value, field);
  if (amount === 0n) {
    refuse("INVALID_INTEGER", `${field} must be greater than zero`);
  }
  return amount;
}

/* 0/1 flags (paused, delegateActive). */
function parseBitField(value, field) {
  const bit = parseIntegerField(value, field);
  if (bit !== 0n && bit !== 1n) {
    refuse("INVALID_INTEGER", `${field} must be 0 or 1`);
  }
  return bit;
}

/* 32-byte lowercase hex (x-only pubkeys, vault ids, Merkle roots). */
function normalizeHex64(value, field) {
  if (typeof value !== "string") {
    refuse("INVALID_HEX", `${field} must be a hex string`);
  }
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    refuse("INVALID_HEX", `${field} must be 32-byte hex`);
  }
  return normalized;
}

function requirePlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    refuse("MALFORMED_TUPLE", `${label} must be a plain object`);
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    refuse("MALFORMED_TUPLE", `${label} must be a plain object (non-plain prototypes are refused)`);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* Tuple schemas (single source of truth, exported)                    */
/* ------------------------------------------------------------------ */

/*
 * Neutral field classes: fields that may accompany a policy tuple but are
 * NOT governed policy — any before/after difference REFUSES with the
 * class code (they change through their own covenant paths, or never).
 */
const NEUTRAL_CLASS = Object.freeze({
  IDENTITY: "IDENTITY_IMMUTABLE", //  boundVaultId — covenant pins it forever; changing identity is a migration
  FUNDING: "NOT_A_POLICY_FIELD", //   protectedValue / feeReserve — move via topUp/topUpReserve/spend, not proposals
  ACCOUNTING: "ACCOUNTING_IMMUTABLE", // v0.2/v0.3 periodStartDaa/periodSpent — owner ops preserve accounting by covenant rule
  MANAGED: "EXECUTION_MANAGED" //     policyNonce — the covenant/execution layer advances it (+1 on policy ops)
});

/*
 * Per-version tuple key sets. `required` are always-present governed
 * fields; `xor` lists pairs where EXACTLY ONE key must be present per
 * side; `neutral` maps optional fields to their refusal class. Any other
 * key refuses UNKNOWN_FIELD.
 */
const TUPLE_KEYS = Object.freeze({
  [VERSION_V2]: Object.freeze({
    kind: "delegate-v2",
    required: Object.freeze(["paused", "delegate", "delegateActive", "maxPerSpend", "periodBudget", "periodLengthDaa", "recipients"]),
    xor: Object.freeze([]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      periodStartDaa: NEUTRAL_CLASS.ACCOUNTING,
      periodSpent: NEUTRAL_CLASS.ACCOUNTING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V3]: Object.freeze({
    kind: "delegate-v3",
    required: Object.freeze(["paused", "delegate", "delegateActive", "maxPerSpend", "periodBudget", "periodLengthDaa", "approvalM", "approvalThresholdAmount"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["recipients", "recipientRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      periodStartDaa: NEUTRAL_CLASS.ACCOUNTING,
      periodSpent: NEUTRAL_CLASS.ACCOUNTING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V4]: Object.freeze({
    kind: "agents-v4",
    required: Object.freeze(["paused", "approvalM"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["agents", "agentRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      feeReserve: NEUTRAL_CLASS.FUNDING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  }),
  [VERSION_V4_1]: Object.freeze({
    kind: "agents-v4",
    required: Object.freeze(["paused", "approvalM"]),
    xor: Object.freeze([Object.freeze(["approvers", "approverSlots"]), Object.freeze(["agents", "agentRoot"])]),
    neutral: Object.freeze({
      boundVaultId: NEUTRAL_CLASS.IDENTITY,
      protectedValue: NEUTRAL_CLASS.FUNDING,
      feeReserve: NEUTRAL_CLASS.FUNDING,
      policyNonce: NEUTRAL_CLASS.MANAGED
    })
  })
});

/* Agent-policy leaf keys (v0.4 family; sdk/src/agent-merkle-v4.js
 * normalizeAgentPolicyV4 + per-agent recipient list). */
const AGENT_KEYS = Object.freeze({
  required: Object.freeze(["agentPk", "maxPerSpend", "periodBudget", "periodLengthDaa", "periodStartDaa", "periodSpent", "approvalThreshold", "agentMaxFeePerTx"]),
  xor: Object.freeze([Object.freeze(["recipients", "agentRecipientRoot"])])
});

function governedVersions() {
  return Object.freeze(Object.keys(TUPLE_KEYS));
}

function resolveVersion(covenantVersion) {
  if (typeof covenantVersion !== "string" || !Object.prototype.hasOwnProperty.call(TUPLE_KEYS, covenantVersion)) {
    refuse(
      "UNKNOWN_VERSION",
      `unknown covenant version ${JSON.stringify(covenantVersion)} — governed versions are ${governedVersions().join(", ")}; unknown versions fail closed`
    );
  }
  return TUPLE_KEYS[covenantVersion];
}

/* ------------------------------------------------------------------ */
/* Tuple parsing (per side)                                            */
/* ------------------------------------------------------------------ */

function checkKeySet(obj, schema, label) {
  const allowed = new Set(schema.required);
  for (const pair of schema.xor) {
    for (const k of pair) allowed.add(k);
  }
  for (const k of Object.keys(schema.neutral)) allowed.add(k);

  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      refuse("UNKNOWN_FIELD", `${label}.${key} is not a governed field of this covenant version — unknown fields fail closed`);
    }
  }
  for (const key of schema.required) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) {
      refuse("MISSING_FIELD", `${label}.${key} is required for this covenant version`);
    }
  }
  for (const pair of schema.xor) {
    const present = pair.filter((k) => Object.prototype.hasOwnProperty.call(obj, k));
    if (present.length === 0) {
      refuse("MISSING_FIELD", `${label} must carry exactly one of {${pair.join(", ")}}`);
    }
    if (present.length > 1) {
      refuse("AMBIGUOUS_FORM", `${label} carries both ${pair.join(" and ")} — two authorities for one fact are refused (cannot verify their consistency here)`);
    }
  }
}

/* Approver set: active-list form (`approvers`, 0..10 active keys, no
 * sentinel, no duplicates) or exact 10-slot form (`approverSlots`,
 * sentinels allowed, active duplicates refused — covenant rule A2).
 * Slot positions are authority-equivalent; comparison is by SET. */
function parseApproverSet(obj, label, invalidCode) {
  if (Object.prototype.hasOwnProperty.call(obj, "approverSlots")) {
    const slots = obj.approverSlots;
    if (!Array.isArray(slots) || slots.length !== MAX_APPROVERS) {
      refuse(invalidCode, `${label}.approverSlots must be exactly ${MAX_APPROVERS} slots (sentinel = 64 zero hex)`);
    }
    const active = new Set();
    slots.forEach((k, i) => {
      const key = normalizeHex64(k, `${label}.approverSlots[${i}]`);
      if (key === APPROVER_SENTINEL) return;
      if (active.has(key)) {
        refuse(invalidCode, `${label}.approverSlots[${i}] duplicates an active approver key — active approver keys must be distinct (covenant A2)`);
      }
      active.add(key);
    });
    return active;
  }
  const raw = obj.approvers;
  if (!Array.isArray(raw) || raw.length > MAX_APPROVERS) {
    refuse(invalidCode, `${label}.approvers must be an array of at most ${MAX_APPROVERS} active x-only keys`);
  }
  const active = new Set();
  raw.forEach((k, i) => {
    const key = normalizeHex64(k, `${label}.approvers[${i}]`);
    if (key === APPROVER_SENTINEL) {
      refuse(invalidCode, `${label}.approvers[${i}] is the all-zero sentinel; pass only active approver keys`);
    }
    if (active.has(key)) {
      refuse(invalidCode, `${label}.approvers[${i}] duplicates an active approver key — active approver keys must be distinct (covenant A2)`);
    }
    active.add(key);
  });
  return active;
}

/* Recipient key list -> SET. Duplicates are tolerated and deduplicated:
 * v0.2 pads its 3 consensus slots by duplicating keys, and a duplicate
 * recipient grants no additional authority. */
function parseRecipientSet(list, label, invalidCode, { min, max }) {
  if (!Array.isArray(list)) {
    refuse(invalidCode, `${label} must be an array of x-only recipient keys`);
  }
  if (list.length < min || (max !== null && list.length > max)) {
    refuse(invalidCode, `${label} must have ${min}..${max === null ? "n" : max} entries`);
  }
  const set = new Set();
  list.forEach((k, i) => {
    set.add(normalizeHex64(k, `${label}[${i}]`));
  });
  if (set.size === 0) {
    refuse(invalidCode, `${label} must contain at least one recipient key`);
  }
  return set;
}

function parseAgentEntry(entry, label, invalidCode) {
  requirePlainObject(entry, label);
  const allowed = new Set(AGENT_KEYS.required);
  for (const pair of AGENT_KEYS.xor) for (const k of pair) allowed.add(k);
  for (const key of Object.keys(entry)) {
    if (!allowed.has(key)) {
      refuse("UNKNOWN_FIELD", `${label}.${key} is not a governed agent-policy field — unknown fields fail closed`);
    }
  }
  for (const key of AGENT_KEYS.required) {
    if (!Object.prototype.hasOwnProperty.call(entry, key)) {
      refuse("MISSING_FIELD", `${label}.${key} is required`);
    }
  }
  for (const pair of AGENT_KEYS.xor) {
    const present = pair.filter((k) => Object.prototype.hasOwnProperty.call(entry, k));
    if (present.length === 0) {
      refuse("MISSING_FIELD", `${label} must carry exactly one of {${pair.join(", ")}}`);
    }
    if (present.length > 1) {
      refuse("AMBIGUOUS_FORM", `${label} carries both ${pair.join(" and ")} — refused`);
    }
  }
  const agent = {
    agentPk: normalizeHex64(entry.agentPk, `${label}.agentPk`),
    maxPerSpend: parsePositiveIntegerField(entry.maxPerSpend, `${label}.maxPerSpend`),
    periodBudget: parsePositiveIntegerField(entry.periodBudget, `${label}.periodBudget`),
    periodLengthDaa: parsePositiveIntegerField(entry.periodLengthDaa, `${label}.periodLengthDaa`),
    periodStartDaa: parseIntegerField(entry.periodStartDaa, `${label}.periodStartDaa`),
    periodSpent: parseIntegerField(entry.periodSpent, `${label}.periodSpent`),
    approvalThreshold: parseIntegerField(entry.approvalThreshold, `${label}.approvalThreshold`),
    agentMaxFeePerTx: parseIntegerField(entry.agentMaxFeePerTx, `${label}.agentMaxFeePerTx`)
  };
  if (Object.prototype.hasOwnProperty.call(entry, "recipients")) {
    agent.recipients = parseRecipientSet(entry.recipients, `${label}.recipients`, invalidCode, { min: 1, max: null });
    agent.recipientForm = "list";
  } else {
    agent.agentRecipientRoot = normalizeHex64(entry.agentRecipientRoot, `${label}.agentRecipientRoot`);
    agent.recipientForm = "root";
  }
  return agent;
}

/*
 * Parse one side of a proposal into a normalized tuple. `invalidCode` is
 * BEFORE_TUPLE_INVALID or AFTER_TUPLE_INVALID: a malformed live state
 * (e.g. a hand-baked genesis with duplicate approver keys) is handled by
 * break-glass owner recovery, never by governed policy editing.
 */
function parseTuple(covenantVersion, obj, label) {
  const schema = resolveVersion(covenantVersion);
  const invalidCode = label === "before" ? "BEFORE_TUPLE_INVALID" : "AFTER_TUPLE_INVALID";
  requirePlainObject(obj, label);
  checkKeySet(obj, schema, label);

  const tuple = { kind: schema.kind, neutral: {} };

  tuple.paused = parseBitField(obj.paused, `${label}.paused`);

  if (schema.kind === "delegate-v2" || schema.kind === "delegate-v3") {
    tuple.delegate = normalizeHex64(obj.delegate, `${label}.delegate`);
    tuple.delegateActive = parseBitField(obj.delegateActive, `${label}.delegateActive`);
    tuple.maxPerSpend = parsePositiveIntegerField(obj.maxPerSpend, `${label}.maxPerSpend`);
    tuple.periodBudget = parsePositiveIntegerField(obj.periodBudget, `${label}.periodBudget`);
    if (tuple.periodBudget < tuple.maxPerSpend) {
      refuse(invalidCode, `${label}.periodBudget must be >= ${label}.maxPerSpend`);
    }
    tuple.periodLengthDaa = parsePositiveIntegerField(obj.periodLengthDaa, `${label}.periodLengthDaa`);
  }

  if (schema.kind === "delegate-v2") {
    tuple.recipients = parseRecipientSet(obj.recipients, `${label}.recipients`, invalidCode, { min: 1, max: 3 });
    tuple.recipientForm = "list";
  }

  if (schema.kind === "delegate-v3") {
    tuple.approvalM = parseIntegerField(obj.approvalM, `${label}.approvalM`);
    tuple.approvalThresholdAmount = parseIntegerField(obj.approvalThresholdAmount, `${label}.approvalThresholdAmount`);
    tuple.approvers = parseApproverSet(obj, label, invalidCode);
    if (tuple.approvers.size === 0) {
      if (tuple.approvalM !== 0n) {
        refuse(invalidCode, `${label}.approvalM must be 0 when there are no active approvers`);
      }
      if (tuple.approvalThresholdAmount < tuple.maxPerSpend) {
        refuse(invalidCode, `${label}: a tuple with no approvers must set approvalThresholdAmount >= maxPerSpend so a spend can never require approvals`);
      }
    } else {
      if (tuple.approvalM < 1n || tuple.approvalM > BigInt(tuple.approvers.size)) {
        refuse(invalidCode, `${label}.approvalM must satisfy 1 <= M <= activeApproverCount (${tuple.approvers.size})`);
      }
    }
    if (Object.prototype.hasOwnProperty.call(obj, "recipients")) {
      tuple.recipients = parseRecipientSet(obj.recipients, `${label}.recipients`, invalidCode, { min: 1, max: null });
      tuple.recipientForm = "list";
    } else {
      tuple.recipientRoot = normalizeHex64(obj.recipientRoot, `${label}.recipientRoot`);
      tuple.recipientForm = "root";
    }
  }

  if (schema.kind === "agents-v4") {
    tuple.approvalM = parseIntegerField(obj.approvalM, `${label}.approvalM`);
    tuple.approvers = parseApproverSet(obj, label, invalidCode);
    if (tuple.approvers.size === 0) {
      if (tuple.approvalM !== 0n) {
        refuse(invalidCode, `${label}.approvalM must be 0 when there are no active approvers`);
      }
    } else if (tuple.approvalM < 1n || tuple.approvalM > BigInt(tuple.approvers.size)) {
      refuse(invalidCode, `${label}.approvalM must satisfy 1 <= M <= activeApproverCount (${tuple.approvers.size})`);
    }
    if (Object.prototype.hasOwnProperty.call(obj, "agents")) {
      if (!Array.isArray(obj.agents)) {
        refuse(invalidCode, `${label}.agents must be an array of agent-policy objects`);
      }
      const agents = new Map();
      obj.agents.forEach((entry, i) => {
        const agent = parseAgentEntry(entry, `${label}.agents[${i}]`, invalidCode);
        if (agents.has(agent.agentPk)) {
          refuse(invalidCode, `${label}.agents duplicates agentPk ${agent.agentPk} — one key may hold exactly one policy leaf (duplicate leaves would be independent budget lanes)`);
        }
        agents.set(agent.agentPk, agent);
      });
      tuple.agents = agents;
      tuple.agentForm = "list";
    } else {
      tuple.agentRoot = normalizeHex64(obj.agentRoot, `${label}.agentRoot`);
      tuple.agentForm = "root";
    }
  }

  /* Neutral-class fields: allowed, but never changed by a proposal. */
  for (const [field, code] of Object.entries(schema.neutral)) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      tuple.neutral[field] =
        field === "boundVaultId" ? normalizeHex64(obj[field], `${label}.${field}`) : parseIntegerField(obj[field], `${label}.${field}`);
      tuple.neutral[`${field}:code`] = code;
    }
  }

  return tuple;
}

/* ------------------------------------------------------------------ */
/* Delta evaluation                                                    */
/* ------------------------------------------------------------------ */

function entryNumeric(field, before, after, direction, code) {
  return { field, direction, code, before: before.toString(), after: after.toString() };
}

function neutralEntry(field) {
  return { field, direction: DIRECTION_NEUTRAL, code: "UNCHANGED" };
}

/* Monotone sompi/count field: bigger value = more delegated authority. */
function classifyMonotoneUp(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after < before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lowered));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.raised));
  }
}

/* periodLengthDaa: LONGER period = LOWER long-run spending rate
 * (periodBudget per periodLengthDaa; the within-period cap stays
 * periodBudget) => increase is a REDUCTION, decrease an EXPANSION. */
function classifyPeriodLength(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after > before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lengthened));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.shortened));
  }
}

function classifyKeySet(perField, field, beforeSet, afterSet, codes) {
  let changed = false;
  for (const key of beforeSet) {
    if (!afterSet.has(key)) {
      changed = true;
      perField.push({ field, direction: CLASSIFICATION_REDUCTION, code: codes.removed, member: key });
    }
  }
  for (const key of afterSet) {
    if (!beforeSet.has(key)) {
      changed = true;
      perField.push({ field, direction: CLASSIFICATION_EXPANSION, code: codes.added, member: key });
    }
  }
  if (!changed) {
    perField.push(neutralEntry(field));
  }
}

/* Recipient authorization in list or opaque-root form. A bare root swap
 * (or a list-vs-root form mismatch) cannot be proven to be a subset, so
 * it classifies EXPANSION (fail closed). Proving a reduction requires
 * both sides as explicit key lists sourced from the root-verified
 * durable registry; the EXECUTION layer, not this classifier, is what
 * binds a list to the on-chain root (the SDK builders recompute roots
 * from the registry lists). */
function classifyCommitmentSet(perField, field, beforeTuple, afterTuple, listKeys, codes) {
  const bForm = beforeTuple[listKeys.form];
  const aForm = afterTuple[listKeys.form];
  if (bForm === "list" && aForm === "list") {
    classifyKeySet(perField, field, beforeTuple[listKeys.list], afterTuple[listKeys.list], codes);
    return;
  }
  if (bForm === "root" && aForm === "root") {
    if (beforeTuple[listKeys.root] === afterTuple[listKeys.root]) {
      perField.push(neutralEntry(field));
    } else {
      perField.push({
        field,
        direction: CLASSIFICATION_EXPANSION,
        code: codes.opaque,
        before: beforeTuple[listKeys.root],
        after: afterTuple[listKeys.root]
      });
    }
    return;
  }
  /* Mixed forms: membership cannot be compared — EXPANSION, fail closed. */
  perField.push({ field, direction: CLASSIFICATION_EXPANSION, code: codes.opaque });
}

function classifyPaused(perField, before, after) {
  if (before === after) {
    perField.push(neutralEntry("paused"));
  } else if (before === 0n && after === 1n) {
    perField.push(entryNumeric("paused", before, after, CLASSIFICATION_REDUCTION, "EMERGENCY_FREEZE"));
  } else {
    perField.push(entryNumeric("paused", before, after, CLASSIFICATION_EXPANSION, "RESUME_SPENDING"));
  }
}

function classifyApprovalM(perField, before, after) {
  if (before === after) {
    perField.push(neutralEntry("approvalM"));
  } else if (after > before) {
    perField.push(entryNumeric("approvalM", before, after, CLASSIFICATION_REDUCTION, "APPROVAL_QUORUM_RAISED"));
  } else {
    perField.push(entryNumeric("approvalM", before, after, CLASSIFICATION_EXPANSION, "APPROVAL_QUORUM_WEAKENED"));
  }
}

/* approvalThreshold(-Amount): spends AT OR BELOW it need no approvals.
 * Raising it exempts more spends from the approval tier => EXPANSION. */
function classifyApprovalThreshold(perField, field, before, after, codes) {
  if (before === after) {
    perField.push(neutralEntry(field));
  } else if (after < before) {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_REDUCTION, codes.lowered));
  } else {
    perField.push(entryNumeric(field, before, after, CLASSIFICATION_EXPANSION, codes.raised));
  }
}

function classifyAgentPair(perField, pk, b, a) {
  const p = (f) => `agents[${pk}].${f}`;
  classifyMonotoneUp(perField, p("maxPerSpend"), b.maxPerSpend, a.maxPerSpend, {
    lowered: "AGENT_PER_SPEND_CAP_LOWERED",
    raised: "AGENT_PER_SPEND_CAP_RAISED"
  });
  classifyMonotoneUp(perField, p("periodBudget"), b.periodBudget, a.periodBudget, {
    lowered: "AGENT_PERIOD_BUDGET_LOWERED",
    raised: "AGENT_PERIOD_BUDGET_RAISED"
  });
  classifyPeriodLength(perField, p("periodLengthDaa"), b.periodLengthDaa, a.periodLengthDaa, {
    lengthened: "AGENT_PERIOD_LENGTHENED",
    shortened: "AGENT_PERIOD_SHORTENED"
  });
  /* Period phase: moving periodStartDaa can open a fresh budget period
   * immediately — temporal effect is not provably restrictive. */
  if (b.periodStartDaa === a.periodStartDaa) {
    perField.push(neutralEntry(p("periodStartDaa")));
  } else {
    perField.push(entryNumeric(p("periodStartDaa"), b.periodStartDaa, a.periodStartDaa, CLASSIFICATION_EXPANSION, "AGENT_PERIOD_PHASE_CHANGED"));
  }
  /* periodSpent: lowering it refunds already-consumed budget (a fresh
   * spending lane in the current period) => EXPANSION; raising it
   * records consumption => REDUCTION. */
  if (b.periodSpent === a.periodSpent) {
    perField.push(neutralEntry(p("periodSpent")));
  } else if (a.periodSpent > b.periodSpent) {
    perField.push(entryNumeric(p("periodSpent"), b.periodSpent, a.periodSpent, CLASSIFICATION_REDUCTION, "AGENT_BUDGET_CONSUMPTION_RECORDED"));
  } else {
    perField.push(entryNumeric(p("periodSpent"), b.periodSpent, a.periodSpent, CLASSIFICATION_EXPANSION, "AGENT_BUDGET_REFUNDED"));
  }
  classifyApprovalThreshold(perField, p("approvalThreshold"), b.approvalThreshold, a.approvalThreshold, {
    lowered: "AGENT_APPROVAL_THRESHOLD_LOWERED",
    raised: "AGENT_APPROVAL_THRESHOLD_RAISED"
  });
  classifyMonotoneUp(perField, p("agentMaxFeePerTx"), b.agentMaxFeePerTx, a.agentMaxFeePerTx, {
    lowered: "AGENT_FEE_CAP_LOWERED",
    raised: "AGENT_FEE_CAP_RAISED"
  });
  classifyCommitmentSet(
    perField,
    p("recipients"),
    b,
    a,
    { form: "recipientForm", list: "recipients", root: "agentRecipientRoot" },
    { removed: "AGENT_RECIPIENT_REMOVED", added: "AGENT_RECIPIENT_ADDED", opaque: "OPAQUE_COMMITMENT_CHANGED" }
  );
}

function classifyNeutralFields(beforeTuple, afterTuple) {
  const keys = new Set([
    ...Object.keys(beforeTuple.neutral).filter((k) => !k.endsWith(":code")),
    ...Object.keys(afterTuple.neutral).filter((k) => !k.endsWith(":code"))
  ]);
  for (const field of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(beforeTuple.neutral, field);
    const inAfter = Object.prototype.hasOwnProperty.call(afterTuple.neutral, field);
    const code = (inBefore ? beforeTuple.neutral[`${field}:code`] : afterTuple.neutral[`${field}:code`]);
    if (!inBefore || !inAfter) {
      refuse(code, `${field} must be present on both sides or absent from both — a one-sided value cannot be verified unchanged`);
    }
    const b = beforeTuple.neutral[field];
    const a = afterTuple.neutral[field];
    const equal = typeof b === "bigint" ? b === a : b === a;
    if (!equal) {
      refuse(code, `${field} may not change in a policy proposal (${describeNeutral(field)})`);
    }
  }
}

function describeNeutral(field) {
  switch (field) {
    case "boundVaultId":
      return "vault identity is covenant-pinned; changing identity requires a covenant migration proposal";
    case "protectedValue":
    case "feeReserve":
      return "funding levels move only through their own covenant operations (topUp/topUpReserve/spend), never through policy proposals";
    case "periodStartDaa":
    case "periodSpent":
      return "the covenant preserves budget accounting across every owner policy operation";
    case "policyNonce":
      return "the execution layer advances the nonce (+1 on policy operations); proposals never set it";
    default:
      return "not a governed policy field";
  }
}

/*
 * The classifier. Both tuples must be the SAME covenant version (an
 * in-lineage policy change). Cross-version changes are covenant
 * migrations: classifyMigrationDelta.
 */
function classifyPolicyDelta({ covenantVersion, before, after } = {}) {
  const schema = resolveVersion(covenantVersion);
  const beforeTuple = parseTuple(covenantVersion, before, "before");
  const afterTuple = parseTuple(covenantVersion, after, "after");

  classifyNeutralFields(beforeTuple, afterTuple);

  const perField = [];

  classifyPaused(perField, beforeTuple.paused, afterTuple.paused);

  if (schema.kind === "delegate-v2" || schema.kind === "delegate-v3") {
    if (beforeTuple.delegate === afterTuple.delegate) {
      perField.push(neutralEntry("delegate"));
    } else {
      /* A different key gains spending authority — never a pure
       * reduction, even when the old key is simultaneously removed. */
      perField.push({
        field: "delegate",
        direction: CLASSIFICATION_EXPANSION,
        code: "DELEGATE_KEY_CHANGED",
        before: beforeTuple.delegate,
        after: afterTuple.delegate
      });
    }
    if (beforeTuple.delegateActive === afterTuple.delegateActive) {
      perField.push(neutralEntry("delegateActive"));
    } else if (beforeTuple.delegateActive === 1n && afterTuple.delegateActive === 0n) {
      perField.push(entryNumeric("delegateActive", beforeTuple.delegateActive, afterTuple.delegateActive, CLASSIFICATION_REDUCTION, "DELEGATE_REVOKED"));
    } else {
      perField.push(entryNumeric("delegateActive", beforeTuple.delegateActive, afterTuple.delegateActive, CLASSIFICATION_EXPANSION, "DELEGATE_ENABLED"));
    }
    classifyMonotoneUp(perField, "maxPerSpend", beforeTuple.maxPerSpend, afterTuple.maxPerSpend, {
      lowered: "PER_SPEND_CAP_LOWERED",
      raised: "PER_SPEND_CAP_RAISED"
    });
    classifyMonotoneUp(perField, "periodBudget", beforeTuple.periodBudget, afterTuple.periodBudget, {
      lowered: "PERIOD_BUDGET_LOWERED",
      raised: "PERIOD_BUDGET_RAISED"
    });
    classifyPeriodLength(perField, "periodLengthDaa", beforeTuple.periodLengthDaa, afterTuple.periodLengthDaa, {
      lengthened: "PERIOD_LENGTHENED",
      shortened: "PERIOD_SHORTENED"
    });
  }

  if (schema.kind === "delegate-v2") {
    classifyKeySet(perField, "recipients", beforeTuple.recipients, afterTuple.recipients, {
      removed: "RECIPIENT_REMOVED",
      added: "RECIPIENT_ADDED"
    });
  }

  if (schema.kind === "delegate-v3") {
    classifyApprovalM(perField, beforeTuple.approvalM, afterTuple.approvalM);
    classifyApprovalThreshold(perField, "approvalThresholdAmount", beforeTuple.approvalThresholdAmount, afterTuple.approvalThresholdAmount, {
      lowered: "APPROVAL_THRESHOLD_LOWERED",
      raised: "APPROVAL_THRESHOLD_RAISED"
    });
    classifyKeySet(perField, "approvers", beforeTuple.approvers, afterTuple.approvers, {
      removed: "APPROVER_REMOVED",
      added: "APPROVER_ADDED"
    });
    classifyCommitmentSet(
      perField,
      "recipients",
      beforeTuple,
      afterTuple,
      { form: "recipientForm", list: "recipients", root: "recipientRoot" },
      { removed: "RECIPIENT_REMOVED", added: "RECIPIENT_ADDED", opaque: "OPAQUE_COMMITMENT_CHANGED" }
    );
  }

  if (schema.kind === "agents-v4") {
    classifyApprovalM(perField, beforeTuple.approvalM, afterTuple.approvalM);
    classifyKeySet(perField, "approvers", beforeTuple.approvers, afterTuple.approvers, {
      removed: "APPROVER_REMOVED",
      added: "APPROVER_ADDED"
    });
    if (beforeTuple.agentForm === "list" && afterTuple.agentForm === "list") {
      let agentChange = false;
      for (const [pk, b] of beforeTuple.agents) {
        if (!afterTuple.agents.has(pk)) {
          agentChange = true;
          perField.push({ field: "agents", direction: CLASSIFICATION_REDUCTION, code: "AGENT_REMOVED", member: pk });
        }
      }
      for (const [pk, a] of afterTuple.agents) {
        if (!beforeTuple.agents.has(pk)) {
          agentChange = true;
          perField.push({ field: "agents", direction: CLASSIFICATION_EXPANSION, code: "AGENT_ADDED", member: pk });
        }
      }
      for (const [pk, b] of beforeTuple.agents) {
        const a = afterTuple.agents.get(pk);
        if (a) {
          const lengthBefore = perField.length;
          classifyAgentPair(perField, pk, b, a);
          if (perField.slice(lengthBefore).some((e) => e.direction !== DIRECTION_NEUTRAL)) {
            agentChange = true;
          }
        }
      }
      if (!agentChange && beforeTuple.agents.size === 0 && afterTuple.agents.size === 0) {
        perField.push(neutralEntry("agents"));
      }
    } else if (beforeTuple.agentForm === "root" && afterTuple.agentForm === "root") {
      if (beforeTuple.agentRoot === afterTuple.agentRoot) {
        perField.push(neutralEntry("agentRoot"));
      } else {
        perField.push({
          field: "agentRoot",
          direction: CLASSIFICATION_EXPANSION,
          code: "AGENT_SET_OPAQUE",
          before: beforeTuple.agentRoot,
          after: afterTuple.agentRoot
        });
      }
    } else {
      perField.push({ field: "agents", direction: CLASSIFICATION_EXPANSION, code: "AGENT_SET_OPAQUE" });
    }
  }

  const expansions = perField.filter((e) => e.direction === CLASSIFICATION_EXPANSION);
  const reductions = perField.filter((e) => e.direction === CLASSIFICATION_REDUCTION);

  if (expansions.length === 0 && reductions.length === 0) {
    refuse("NO_CHANGE", "before and after tuples are identical — a no-op is not a governable change");
  }

  const codes = [...new Set(perField.filter((e) => e.direction !== DIRECTION_NEUTRAL).map((e) => e.code))].sort();
  if (expansions.length > 0 && reductions.length > 0) {
    codes.push("MIXED_CHANGE");
  }

  return Object.freeze({
    classification: expansions.length > 0 ? CLASSIFICATION_EXPANSION : CLASSIFICATION_REDUCTION,
    covenantVersion,
    perField: Object.freeze(perField.map((e) => Object.freeze(e))),
    codes: Object.freeze(codes)
  });
}

/*
 * Covenant migration (recover -> recreate; in-lineage cross-version
 * migration is VM-experiment-proven impossible, docs/covenant-spec-v0.4.md
 * §7). A migration replaces the lineage and MAY replace the authority
 * anchor itself (owner key, recovery authority) — it is ALWAYS an
 * AUTHORITY EXPANSION for governance purposes, whatever the new policy
 * looks like. Unknown versions refuse.
 */
function classifyMigrationDelta({ fromVersion, toVersion } = {}) {
  resolveVersion(fromVersion);
  resolveVersion(toVersion);
  return Object.freeze({
    classification: CLASSIFICATION_EXPANSION,
    fromVersion,
    toVersion,
    perField: Object.freeze([]),
    codes: Object.freeze(["COVENANT_MIGRATION"])
  });
}

module.exports = {
  CLASSIFICATION_REDUCTION,
  CLASSIFICATION_EXPANSION,
  CLASSIFICATIONS,
  DIRECTION_NEUTRAL,
  DIRECTIONS,
  I64_MAX,
  APPROVER_SENTINEL,
  MAX_APPROVERS,
  VERSION_V2,
  VERSION_V3,
  VERSION_V4,
  VERSION_V4_1,
  TUPLE_KEYS,
  AGENT_KEYS,
  NEUTRAL_CLASS,
  GovernanceRefusal,
  governedVersions,
  classifyPolicyDelta,
  classifyMigrationDelta
};
