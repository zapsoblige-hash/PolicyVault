"use strict";

/*
 * UNIT tests — authority-delta classifier (Program B core).
 * Layer: UNIT (pure classification, no I/O).
 *
 * Covers, per governed covenant version, the REDUCTION and EXPANSION
 * side of every governed field class; mixed changes; unknown versions/
 * fields; fail-closed refusals; BigInt boundary cases.
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  CLASSIFICATION_REDUCTION,
  CLASSIFICATION_EXPANSION,
  DIRECTION_NEUTRAL,
  DIRECTIONS,
  I64_MAX,
  APPROVER_SENTINEL,
  VERSION_V2,
  VERSION_V3,
  VERSION_V4,
  VERSION_V4_1,
  TUPLE_KEYS,
  GovernanceRefusal,
  governedVersions,
  classifyPolicyDelta,
  classifyMigrationDelta
} = require("../authority-delta");
const { canonicalJsonStringify } = require("../canonical");

/* Distinct deterministic 32-byte hex identities. */
function k(n) {
  return n.toString(16).padStart(2, "0").repeat(32);
}
const D1 = k(0x11);
const D2 = k(0x12);
const A1 = k(0x21);
const A2 = k(0x22);
const A3 = k(0x23);
const A4 = k(0x24);
const R1 = k(0x31);
const R2 = k(0x32);
const R3 = k(0x33);
const G1 = k(0x41);
const G2 = k(0x42);
const ROOT1 = k(0x51);
const ROOT2 = k(0x52);
const VID = k(0x61);

function refusalCode(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof GovernanceRefusal, `expected GovernanceRefusal, got ${err && err.name}: ${err && err.message}`);
    assert.equal(err.failClosed, true);
    return err.code;
  }
  assert.fail("expected a fail-closed refusal");
}

function v2Base(overrides = {}) {
  return {
    paused: "0",
    delegate: D1,
    delegateActive: "1",
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "1000",
    recipients: [R1, R2],
    ...overrides
  };
}

function v3Base(overrides = {}) {
  return {
    paused: "0",
    delegate: D1,
    delegateActive: "1",
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "1000",
    approvalM: "2",
    approvalThresholdAmount: "50000000",
    approvers: [A1, A2, A3],
    recipientRoot: ROOT1,
    ...overrides
  };
}

function v4Agent(overrides = {}) {
  return {
    agentPk: G1,
    maxPerSpend: "100000000",
    periodBudget: "1000000000",
    periodLengthDaa: "1000",
    periodStartDaa: "5000",
    periodSpent: "250000000",
    approvalThreshold: "50000000",
    agentMaxFeePerTx: "5000000",
    recipients: [R1, R2],
    ...overrides
  };
}

function v4Base(overrides = {}) {
  return {
    paused: "0",
    approvalM: "1",
    approvers: [A1, A2],
    agents: [v4Agent()],
    ...overrides
  };
}

function fieldEntry(result, field) {
  const entries = result.perField.filter((e) => e.field === field);
  assert.ok(entries.length >= 1, `expected a perField entry for ${field}`);
  return entries;
}

function assertSingle(result, field, direction, code) {
  const [entry] = fieldEntry(result, field);
  assert.equal(entry.direction, direction, `${field} direction`);
  assert.equal(entry.code, code, `${field} code`);
}

/* ------------------------------------------------------------------ */
/* Unknown versions fail closed                                        */
/* ------------------------------------------------------------------ */

test("unknown covenant versions refuse (never routed to a default)", () => {
  for (const bad of ["policyvault-0.5", "policyvault-0.1", "policyvault-0.4.2", "", null, undefined, 4]) {
    assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: bad, before: v2Base(), after: v2Base() })), "UNKNOWN_VERSION");
  }
  assert.equal(refusalCode(() => classifyMigrationDelta({ fromVersion: "policyvault-0.5", toVersion: VERSION_V4 })), "UNKNOWN_VERSION");
  assert.equal(refusalCode(() => classifyMigrationDelta({ fromVersion: VERSION_V3, toVersion: "policyvault-9.9" })), "UNKNOWN_VERSION");
});

test("governed version registry is exactly the four frozen versions", () => {
  assert.deepEqual([...governedVersions()].sort(), [VERSION_V2, VERSION_V3, VERSION_V4, VERSION_V4_1].sort());
  assert.ok(Object.isFrozen(TUPLE_KEYS));
});

/* ------------------------------------------------------------------ */
/* v0.2 — delegate, caps, budget, period, recipients, pause            */
/* ------------------------------------------------------------------ */

test("v0.2 maxPerSpend: decrease = REDUCTION, increase = EXPANSION", () => {
  const down = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ maxPerSpend: "50000000" }) });
  assert.equal(down.classification, CLASSIFICATION_REDUCTION);
  assertSingle(down, "maxPerSpend", CLASSIFICATION_REDUCTION, "PER_SPEND_CAP_LOWERED");

  const up = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ maxPerSpend: "200000000" }) });
  assert.equal(up.classification, CLASSIFICATION_EXPANSION);
  assertSingle(up, "maxPerSpend", CLASSIFICATION_EXPANSION, "PER_SPEND_CAP_RAISED");
});

test("v0.2 periodBudget: decrease = REDUCTION, increase = EXPANSION", () => {
  const down = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ periodBudget: "500000000" }) });
  assert.equal(down.classification, CLASSIFICATION_REDUCTION);
  assertSingle(down, "periodBudget", CLASSIFICATION_REDUCTION, "PERIOD_BUDGET_LOWERED");

  const up = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ periodBudget: "2000000000" }) });
  assert.equal(up.classification, CLASSIFICATION_EXPANSION);
  assertSingle(up, "periodBudget", CLASSIFICATION_EXPANSION, "PERIOD_BUDGET_RAISED");
});

test("v0.2 periodLengthDaa: longer period = REDUCTION (lower spend rate), shorter = EXPANSION", () => {
  const longer = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ periodLengthDaa: "2000" }) });
  assert.equal(longer.classification, CLASSIFICATION_REDUCTION);
  assertSingle(longer, "periodLengthDaa", CLASSIFICATION_REDUCTION, "PERIOD_LENGTHENED");

  const shorter = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ periodLengthDaa: "500" }) });
  assert.equal(shorter.classification, CLASSIFICATION_EXPANSION);
  assertSingle(shorter, "periodLengthDaa", CLASSIFICATION_EXPANSION, "PERIOD_SHORTENED");
});

test("v0.2 delegateActive: revoke = REDUCTION, enable = EXPANSION", () => {
  const revoke = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ delegateActive: "0" }) });
  assert.equal(revoke.classification, CLASSIFICATION_REDUCTION);
  assertSingle(revoke, "delegateActive", CLASSIFICATION_REDUCTION, "DELEGATE_REVOKED");

  const enable = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ delegateActive: "0" }), after: v2Base({ delegateActive: "1" }) });
  assert.equal(enable.classification, CLASSIFICATION_EXPANSION);
  assertSingle(enable, "delegateActive", CLASSIFICATION_EXPANSION, "DELEGATE_ENABLED");
});

test("v0.2 delegate key rotation is always an EXPANSION (a new key gains authority)", () => {
  const rotated = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ delegate: D2 }) });
  assert.equal(rotated.classification, CLASSIFICATION_EXPANSION);
  assertSingle(rotated, "delegate", CLASSIFICATION_EXPANSION, "DELEGATE_KEY_CHANGED");
});

test("v0.2 recipients: removal = REDUCTION, addition = EXPANSION", () => {
  const removed = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ recipients: [R1] }) });
  assert.equal(removed.classification, CLASSIFICATION_REDUCTION);
  const removedEntries = fieldEntry(removed, "recipients");
  assert.equal(removedEntries.length, 1);
  assert.equal(removedEntries[0].code, "RECIPIENT_REMOVED");
  assert.equal(removedEntries[0].member, R2);

  const added = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ recipients: [R1, R2, R3] }) });
  assert.equal(added.classification, CLASSIFICATION_EXPANSION);
  assert.equal(fieldEntry(added, "recipients")[0].code, "RECIPIENT_ADDED");
});

test("v0.2 recipient reorder/duplicate-padding is authority-neutral (set semantics)", () => {
  /* Reorder + duplicate padding alone changes nothing -> NO_CHANGE refusal. */
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ recipients: [R2, R1, R1] }) })),
    "NO_CHANGE"
  );
  /* Combined with a real reduction, recipients stay NEUTRAL. */
  const combined = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base(),
    after: v2Base({ recipients: [R2, R1, R1], maxPerSpend: "50000000" })
  });
  assert.equal(combined.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(combined, "recipients")[0].direction, DIRECTION_NEUTRAL);
});

test("v0.2 pause is a REDUCTION (emergency freeze), unpause an EXPANSION", () => {
  const freeze = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ paused: "1" }) });
  assert.equal(freeze.classification, CLASSIFICATION_REDUCTION);
  assertSingle(freeze, "paused", CLASSIFICATION_REDUCTION, "EMERGENCY_FREEZE");

  const resume = classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ paused: "1" }), after: v2Base({ paused: "0" }) });
  assert.equal(resume.classification, CLASSIFICATION_EXPANSION);
  assertSingle(resume, "paused", CLASSIFICATION_EXPANSION, "RESUME_SPENDING");
});

test("mixed reduction + expansion classifies EXPANSION with MIXED_CHANGE (fail closed)", () => {
  const mixed = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base(),
    after: v2Base({ maxPerSpend: "50000000", periodBudget: "2000000000" })
  });
  assert.equal(mixed.classification, CLASSIFICATION_EXPANSION);
  assert.ok(mixed.codes.includes("MIXED_CHANGE"));
  assert.ok(mixed.codes.includes("PER_SPEND_CAP_LOWERED"));
  assert.ok(mixed.codes.includes("PERIOD_BUDGET_RAISED"));
});

/* ------------------------------------------------------------------ */
/* Neutral-class fields: refusals                                      */
/* ------------------------------------------------------------------ */

test("accounting fields may not change in a proposal (covenant preserves accounting)", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V2,
        before: v2Base({ periodSpent: "10", maxPerSpend: "100000000" }),
        after: v2Base({ periodSpent: "0", maxPerSpend: "50000000" })
      })
    ),
    "ACCOUNTING_IMMUTABLE"
  );
  /* Present and equal is fine. */
  const ok = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base({ periodSpent: "10", periodStartDaa: "77" }),
    after: v2Base({ periodSpent: "10", periodStartDaa: "77", maxPerSpend: "50000000" })
  });
  assert.equal(ok.classification, CLASSIFICATION_REDUCTION);
});

test("funding fields are not policy fields (protectedValue/feeReserve refuse on change)", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V2,
        before: v2Base({ protectedValue: "5000000000" }),
        after: v2Base({ protectedValue: "6000000000" })
      })
    ),
    "NOT_A_POLICY_FIELD"
  );
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V4,
        before: v4Base({ feeReserve: "100000000" }),
        after: v4Base({ feeReserve: "200000000" })
      })
    ),
    "NOT_A_POLICY_FIELD"
  );
});

test("identity fields are immutable in-lineage (boundVaultId refuses on change)", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V2,
        before: v2Base({ boundVaultId: VID }),
        after: v2Base({ boundVaultId: ROOT2 })
      })
    ),
    "IDENTITY_IMMUTABLE"
  );
});

test("policyNonce is execution-managed (refuses on proposal-specified change)", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V2,
        before: v2Base({ policyNonce: "3" }),
        after: v2Base({ policyNonce: "4" })
      })
    ),
    "EXECUTION_MANAGED"
  );
});

test("one-sided neutral fields refuse (cannot verify unchanged)", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V2,
        before: v2Base({ protectedValue: "5000000000" }),
        after: v2Base({ maxPerSpend: "50000000" })
      })
    ),
    "NOT_A_POLICY_FIELD"
  );
});

/* ------------------------------------------------------------------ */
/* Structural refusals                                                 */
/* ------------------------------------------------------------------ */

test("identical tuples refuse NO_CHANGE (a no-op is not governable)", () => {
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base() })), "NO_CHANGE");
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base(), after: v4Base() })), "NO_CHANGE");
});

test("unknown fields refuse (v0.3-only field on a v0.2 tuple)", () => {
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ recipientRoot: ROOT1 }), after: v2Base() })),
    "UNKNOWN_FIELD"
  );
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base({ feeReserve: "1" }), after: v3Base() })),
    "UNKNOWN_FIELD"
  );
});

test("missing required fields refuse", () => {
  const missing = v2Base();
  delete missing.periodBudget;
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: missing, after: v2Base() })), "MISSING_FIELD");
});

test("malformed tuples refuse (non-object, array, class instance)", () => {
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: null, after: v2Base() })), "MALFORMED_TUPLE");
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: [], after: v2Base() })), "MALFORMED_TUPLE");
  class T {}
  assert.equal(refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: new T(), after: v2Base() })), "MALFORMED_TUPLE");
});

test("cross-field validity: periodBudget < maxPerSpend refuses per side", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ periodBudget: "1" }), after: v2Base() })
    ),
    "BEFORE_TUPLE_INVALID"
  );
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ periodBudget: "1" }) })
    ),
    "AFTER_TUPLE_INVALID"
  );
});

test("v0.2 recipient shape: empty or >3 refuses", () => {
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ recipients: [] }) })),
    "AFTER_TUPLE_INVALID"
  );
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base(), after: v2Base({ recipients: [R1, R2, R3, D1] }) })),
    "AFTER_TUPLE_INVALID"
  );
});

/* ------------------------------------------------------------------ */
/* Numeric safety (BigInt boundaries, refused representations)         */
/* ------------------------------------------------------------------ */

test("JS numbers, floats, exponents, signs, and whitespace refuse", () => {
  for (const bad of [5, 1.5, "1.5", "1e5", "-1", " 5", "5 ", "0x10", "", "NaN"]) {
    assert.equal(
      refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ maxPerSpend: bad }), after: v2Base() })),
      "INVALID_INTEGER",
      `expected refusal for ${JSON.stringify(bad)}`
    );
  }
});

test("negative and over-i64 values refuse; I64_MAX is accepted", () => {
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ maxPerSpend: -1n }), after: v2Base() })),
    "INVALID_INTEGER"
  );
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ maxPerSpend: I64_MAX + 1n }), after: v2Base() })),
    "INVALID_INTEGER"
  );
  const ok = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base({ maxPerSpend: I64_MAX, periodBudget: I64_MAX }),
    after: v2Base({ maxPerSpend: I64_MAX - 1n, periodBudget: I64_MAX })
  });
  assert.equal(ok.classification, CLASSIFICATION_REDUCTION);
});

test("BigInt and digit-string forms of the same value compare equal (NEUTRAL)", () => {
  const r = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base({ periodBudget: "9223372036854775806" }),
    after: v2Base({ periodBudget: 9223372036854775806n, maxPerSpend: "50000000" })
  });
  assert.equal(r.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(r, "periodBudget")[0].direction, DIRECTION_NEUTRAL);
});

test("bit fields accept only 0/1", () => {
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ paused: "2" }), after: v2Base() })),
    "INVALID_INTEGER"
  );
});

test("hex identity fields refuse malformed values", () => {
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ delegate: "zz" }), after: v2Base() })),
    "INVALID_HEX"
  );
  /* Uppercase input normalizes to the same identity (NEUTRAL). */
  const r = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base({ delegate: D1.toUpperCase() }),
    after: v2Base({ maxPerSpend: "50000000" })
  });
  assert.equal(fieldEntry(r, "delegate")[0].direction, DIRECTION_NEUTRAL);
});

/* ------------------------------------------------------------------ */
/* v0.3 — approvals, threshold, recipient commitment                   */
/* ------------------------------------------------------------------ */

test("v0.3 approvalM: raise = REDUCTION, weaken = EXPANSION", () => {
  const raised = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvalM: "3" }) });
  assert.equal(raised.classification, CLASSIFICATION_REDUCTION);
  assertSingle(raised, "approvalM", CLASSIFICATION_REDUCTION, "APPROVAL_QUORUM_RAISED");

  const weakened = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvalM: "1" }) });
  assert.equal(weakened.classification, CLASSIFICATION_EXPANSION);
  assertSingle(weakened, "approvalM", CLASSIFICATION_EXPANSION, "APPROVAL_QUORUM_WEAKENED");
});

test("v0.3 approvalThresholdAmount: lower = REDUCTION, raise = EXPANSION", () => {
  const lowered = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvalThresholdAmount: "10000000" }) });
  assert.equal(lowered.classification, CLASSIFICATION_REDUCTION);
  assertSingle(lowered, "approvalThresholdAmount", CLASSIFICATION_REDUCTION, "APPROVAL_THRESHOLD_LOWERED");

  const raisedT = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvalThresholdAmount: "90000000" }) });
  assert.equal(raisedT.classification, CLASSIFICATION_EXPANSION);
  assertSingle(raisedT, "approvalThresholdAmount", CLASSIFICATION_EXPANSION, "APPROVAL_THRESHOLD_RAISED");
});

test("v0.3 approver set: removal = REDUCTION, addition = EXPANSION, replacement = EXPANSION", () => {
  const removed = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [A1, A2] }) });
  assert.equal(removed.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(removed, "approvers")[0].code, "APPROVER_REMOVED");

  const added = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [A1, A2, A3, A4] }) });
  assert.equal(added.classification, CLASSIFICATION_EXPANSION);
  assert.equal(fieldEntry(added, "approvers")[0].code, "APPROVER_ADDED");

  const replaced = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [A1, A2, A4] }) });
  assert.equal(replaced.classification, CLASSIFICATION_EXPANSION);
  assert.ok(replaced.codes.includes("APPROVER_ADDED"));
  assert.ok(replaced.codes.includes("APPROVER_REMOVED"));
  assert.ok(replaced.codes.includes("MIXED_CHANGE"));
});

test("v0.3 approver slot layout vs active list are set-equivalent", () => {
  const slots = [A2, APPROVER_SENTINEL, A1, APPROVER_SENTINEL, A3, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL];
  const r = classifyPolicyDelta({
    covenantVersion: VERSION_V3,
    before: v3Base(),
    after: (() => {
      const t = v3Base({ maxPerSpend: "50000000" });
      delete t.approvers;
      t.approverSlots = slots;
      return t;
    })()
  });
  assert.equal(r.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(r, "approvers")[0].direction, DIRECTION_NEUTRAL);
});

test("v0.3 approver-set validity refusals (A2 distinctness, M bounds, sentinel-as-active)", () => {
  const dupSlots = [A1, A1, A2, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL, APPROVER_SENTINEL];
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({
        covenantVersion: VERSION_V3,
        before: v3Base(),
        after: (() => {
          const t = v3Base();
          delete t.approvers;
          t.approverSlots = dupSlots;
          return t;
        })()
      })
    ),
    "AFTER_TUPLE_INVALID"
  );
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [A1], approvalM: "2" }) })),
    "AFTER_TUPLE_INVALID"
  );
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [A1, APPROVER_SENTINEL] }) })),
    "AFTER_TUPLE_INVALID"
  );
  /* Zero-approver tuple must make approvals unreachable. */
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ approvers: [], approvalM: "0" }) })
    ),
    "AFTER_TUPLE_INVALID"
  );
  const ok = classifyPolicyDelta({
    covenantVersion: VERSION_V3,
    before: v3Base(),
    after: v3Base({ approvers: [], approvalM: "0", approvalThresholdAmount: "100000000" })
  });
  assert.equal(ok.classification, CLASSIFICATION_EXPANSION); // approvers removed + threshold raised to cap
});

test("v0.3 recipientRoot: an opaque root swap is an EXPANSION (cannot prove subset)", () => {
  const r = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base(), after: v3Base({ recipientRoot: ROOT2 }) });
  assert.equal(r.classification, CLASSIFICATION_EXPANSION);
  assertSingle(r, "recipients", CLASSIFICATION_EXPANSION, "OPAQUE_COMMITMENT_CHANGED");
});

test("v0.3 recipient lists on both sides prove reductions", () => {
  const before = v3Base();
  delete before.recipientRoot;
  before.recipients = [R1, R2, R3];
  const after = v3Base();
  delete after.recipientRoot;
  after.recipients = [R1, R2];
  const r = classifyPolicyDelta({ covenantVersion: VERSION_V3, before, after });
  assert.equal(r.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(r, "recipients")[0].code, "RECIPIENT_REMOVED");
});

test("v0.3 mixed recipient forms (root vs list) classify EXPANSION, both forms on one side refuse", () => {
  const beforeRoot = v3Base();
  const afterList = v3Base();
  delete afterList.recipientRoot;
  afterList.recipients = [R1];
  const r = classifyPolicyDelta({ covenantVersion: VERSION_V3, before: beforeRoot, after: afterList });
  assert.equal(r.classification, CLASSIFICATION_EXPANSION);
  assertSingle(r, "recipients", CLASSIFICATION_EXPANSION, "OPAQUE_COMMITMENT_CHANGED");

  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V3, before: v3Base({ recipients: [R1] }), after: v3Base() })
    ),
    "AMBIGUOUS_FORM"
  );
});

/* ------------------------------------------------------------------ */
/* v0.4 / v0.4.1 — agent registry, leaf fields, opaque roots           */
/* ------------------------------------------------------------------ */

test("v0.4 agent added = EXPANSION, agent removed = REDUCTION", () => {
  const added = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent(), v4Agent({ agentPk: G2 })] })
  });
  assert.equal(added.classification, CLASSIFICATION_EXPANSION);
  const addEntry = added.perField.find((e) => e.code === "AGENT_ADDED");
  assert.ok(addEntry);
  assert.equal(addEntry.member, G2);

  const removed = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base({ agents: [v4Agent(), v4Agent({ agentPk: G2 })] }),
    after: v4Base()
  });
  assert.equal(removed.classification, CLASSIFICATION_REDUCTION);
  assert.ok(removed.perField.some((e) => e.code === "AGENT_REMOVED" && e.member === G2));
});

test("v0.4 per-agent caps: maxPerSpend / periodBudget / agentMaxFeePerTx directions", () => {
  const capDown = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ maxPerSpend: "50000000" })] })
  });
  assert.equal(capDown.classification, CLASSIFICATION_REDUCTION);
  assert.ok(capDown.codes.includes("AGENT_PER_SPEND_CAP_LOWERED"));

  const capUp = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ maxPerSpend: "200000000" })] })
  });
  assert.equal(capUp.classification, CLASSIFICATION_EXPANSION);
  assert.ok(capUp.codes.includes("AGENT_PER_SPEND_CAP_RAISED"));

  const budgetUp = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodBudget: "2000000000" })] })
  });
  assert.equal(budgetUp.classification, CLASSIFICATION_EXPANSION);
  assert.ok(budgetUp.codes.includes("AGENT_PERIOD_BUDGET_RAISED"));

  const budgetDown = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodBudget: "500000000" })] })
  });
  assert.equal(budgetDown.classification, CLASSIFICATION_REDUCTION);
  assert.ok(budgetDown.codes.includes("AGENT_PERIOD_BUDGET_LOWERED"));

  const feeUp = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ agentMaxFeePerTx: "10000000" })] })
  });
  assert.equal(feeUp.classification, CLASSIFICATION_EXPANSION);
  assert.ok(feeUp.codes.includes("AGENT_FEE_CAP_RAISED"));

  const feeDown = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ agentMaxFeePerTx: "1000000" })] })
  });
  assert.equal(feeDown.classification, CLASSIFICATION_REDUCTION);
  assert.ok(feeDown.codes.includes("AGENT_FEE_CAP_LOWERED"));
});

test("v0.4 per-agent period semantics: length, phase, spent", () => {
  const longer = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodLengthDaa: "2000" })] })
  });
  assert.equal(longer.classification, CLASSIFICATION_REDUCTION);
  assert.ok(longer.codes.includes("AGENT_PERIOD_LENGTHENED"));

  const shorter = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodLengthDaa: "500" })] })
  });
  assert.equal(shorter.classification, CLASSIFICATION_EXPANSION);
  assert.ok(shorter.codes.includes("AGENT_PERIOD_SHORTENED"));

  /* Any phase move is an EXPANSION: it can open a fresh period early. */
  const phase = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodStartDaa: "6000" })] })
  });
  assert.equal(phase.classification, CLASSIFICATION_EXPANSION);
  assert.ok(phase.codes.includes("AGENT_PERIOD_PHASE_CHANGED"));

  /* Refunding consumed budget (e.g. reset to 0) is a fresh spending lane. */
  const refund = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodSpent: "0" })] })
  });
  assert.equal(refund.classification, CLASSIFICATION_EXPANSION);
  assert.ok(refund.codes.includes("AGENT_BUDGET_REFUNDED"));

  const consume = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ periodSpent: "500000000" })] })
  });
  assert.equal(consume.classification, CLASSIFICATION_REDUCTION);
  assert.ok(consume.codes.includes("AGENT_BUDGET_CONSUMPTION_RECORDED"));
});

test("v0.4 per-agent approvalThreshold: raise = EXPANSION, lower = REDUCTION", () => {
  const up = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ approvalThreshold: "90000000" })] })
  });
  assert.equal(up.classification, CLASSIFICATION_EXPANSION);
  assert.ok(up.codes.includes("AGENT_APPROVAL_THRESHOLD_RAISED"));

  const down = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ approvalThreshold: "10000000" })] })
  });
  assert.equal(down.classification, CLASSIFICATION_REDUCTION);
  assert.ok(down.codes.includes("AGENT_APPROVAL_THRESHOLD_LOWERED"));
});

test("v0.4 per-agent recipients: removal = REDUCTION, addition = EXPANSION, root swap = EXPANSION", () => {
  const removed = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ recipients: [R1] })] })
  });
  assert.equal(removed.classification, CLASSIFICATION_REDUCTION);
  assert.ok(removed.codes.includes("AGENT_RECIPIENT_REMOVED"));

  const added = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ recipients: [R1, R2, R3] })] })
  });
  assert.equal(added.classification, CLASSIFICATION_EXPANSION);
  assert.ok(added.codes.includes("AGENT_RECIPIENT_ADDED"));

  const rootAgentBefore = v4Agent();
  delete rootAgentBefore.recipients;
  rootAgentBefore.agentRecipientRoot = ROOT1;
  const rootAgentAfter = { ...rootAgentBefore, agentRecipientRoot: ROOT2 };
  const swapped = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: v4Base({ agents: [rootAgentBefore] }),
    after: v4Base({ agents: [rootAgentAfter] })
  });
  assert.equal(swapped.classification, CLASSIFICATION_EXPANSION);
  assert.ok(swapped.codes.includes("OPAQUE_COMMITMENT_CHANGED"));
});

test("v0.4 opaque agentRoot handling (root form, mixed forms)", () => {
  const rootTuple = (root) => {
    const t = v4Base();
    delete t.agents;
    t.agentRoot = root;
    return t;
  };
  const swap = classifyPolicyDelta({ covenantVersion: VERSION_V4, before: rootTuple(ROOT1), after: rootTuple(ROOT2) });
  assert.equal(swap.classification, CLASSIFICATION_EXPANSION);
  assertSingle(swap, "agentRoot", CLASSIFICATION_EXPANSION, "AGENT_SET_OPAQUE");

  /* Same root + freeze -> pure reduction, agentRoot NEUTRAL. */
  const freeze = classifyPolicyDelta({
    covenantVersion: VERSION_V4,
    before: rootTuple(ROOT1),
    after: { ...rootTuple(ROOT1), paused: "1" }
  });
  assert.equal(freeze.classification, CLASSIFICATION_REDUCTION);
  assert.equal(fieldEntry(freeze, "agentRoot")[0].direction, DIRECTION_NEUTRAL);

  /* Mixed forms: list before, root after -> EXPANSION fail closed. */
  const mixed = classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base(), after: rootTuple(ROOT2) });
  assert.equal(mixed.classification, CLASSIFICATION_EXPANSION);
  assertSingle(mixed, "agents", CLASSIFICATION_EXPANSION, "AGENT_SET_OPAQUE");
});

test("v0.4 duplicate agentPk, unknown agent fields, missing agent fields refuse", () => {
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base({ agents: [v4Agent(), v4Agent()] }), after: v4Base() })
    ),
    "BEFORE_TUPLE_INVALID"
  );
  assert.equal(
    refusalCode(() =>
      classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base({ agents: [v4Agent({ delegate: D1 })] }), after: v4Base() })
    ),
    "UNKNOWN_FIELD"
  );
  const missingAgent = v4Agent();
  delete missingAgent.agentMaxFeePerTx;
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base({ agents: [missingAgent] }), after: v4Base() })),
    "MISSING_FIELD"
  );
  const bothForms = v4Agent();
  bothForms.agentRecipientRoot = ROOT1;
  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base({ agents: [bothForms] }), after: v4Base() })),
    "AMBIGUOUS_FORM"
  );
});

test("v0.4 vault-global approvals mirror v0.3 rules", () => {
  const mUp = classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base(), after: v4Base({ approvalM: "2" }) });
  assert.equal(mUp.classification, CLASSIFICATION_REDUCTION);
  assertSingle(mUp, "approvalM", CLASSIFICATION_REDUCTION, "APPROVAL_QUORUM_RAISED");

  assert.equal(
    refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base(), after: v4Base({ approvalM: "3" }) })),
    "AFTER_TUPLE_INVALID"
  );

  const approverAdd = classifyPolicyDelta({ covenantVersion: VERSION_V4, before: v4Base(), after: v4Base({ approvers: [A1, A2, A3] }) });
  assert.equal(approverAdd.classification, CLASSIFICATION_EXPANSION);
  assert.ok(approverAdd.codes.includes("APPROVER_ADDED"));
});

test("v0.4.1 classifies identically to v0.4 (distinct registry entries, same schema)", () => {
  const down41 = classifyPolicyDelta({
    covenantVersion: VERSION_V4_1,
    before: v4Base(),
    after: v4Base({ agents: [v4Agent({ maxPerSpend: "50000000" })] })
  });
  assert.equal(down41.classification, CLASSIFICATION_REDUCTION);
  assert.ok(down41.codes.includes("AGENT_PER_SPEND_CAP_LOWERED"));
  assert.equal(down41.covenantVersion, VERSION_V4_1);

  const freeze41 = classifyPolicyDelta({ covenantVersion: VERSION_V4_1, before: v4Base(), after: v4Base({ paused: "1" }) });
  assert.equal(freeze41.classification, CLASSIFICATION_REDUCTION);
  assert.ok(freeze41.codes.includes("EMERGENCY_FREEZE"));
});

/* ------------------------------------------------------------------ */
/* Migration + result-shape discipline                                 */
/* ------------------------------------------------------------------ */

test("covenant migration is ALWAYS an EXPANSION (recover -> recreate replaces the authority anchor)", () => {
  for (const [from, to] of [
    [VERSION_V3, VERSION_V4_1],
    [VERSION_V2, VERSION_V3],
    [VERSION_V4, VERSION_V4_1],
    [VERSION_V4_1, VERSION_V4_1] // same-version recreate (e.g. owner change)
  ]) {
    const r = classifyMigrationDelta({ fromVersion: from, toVersion: to });
    assert.equal(r.classification, CLASSIFICATION_EXPANSION);
    assert.deepEqual([...r.codes], ["COVENANT_MIGRATION"]);
  }
});

test("results are frozen, JSON-safe (decimal strings, no BigInt), with sorted unique codes", () => {
  const r = classifyPolicyDelta({
    covenantVersion: VERSION_V3,
    before: v3Base(),
    after: v3Base({ maxPerSpend: "50000000", periodBudget: "500000000" })
  });
  assert.ok(Object.isFrozen(r));
  assert.ok(Object.isFrozen(r.perField));
  assert.ok(Object.isFrozen(r.codes));
  for (const entry of r.perField) {
    assert.ok(DIRECTIONS.includes(entry.direction));
    if (entry.before !== undefined) assert.equal(typeof entry.before, "string");
    if (entry.after !== undefined) assert.equal(typeof entry.after, "string");
  }
  /* canonicalJsonStringify refuses BigInt/undefined — proves the result
   * is directly commitment-encodable. */
  canonicalJsonStringify({ classification: r.classification, perField: [...r.perField].map((e) => ({ ...e })), codes: [...r.codes] });
  assert.deepEqual([...r.codes], [...new Set(r.codes)].sort());
});

test("hardening: leading-zero digit strings refuse (one integer value = one accepted encoding)", () => {
  /* Falsification-pass hardening: the governance proposal digest
   * (canonical.js) is string-sensitive, so "010" and "10" — equal VALUES —
   * would digest differently. The integer boundary therefore accepts only
   * the canonical encoding; leading-zero forms fail closed. */
  for (const bad of ["010", "00", "01", "0123456789"]) {
    assert.equal(
      refusalCode(() => classifyPolicyDelta({ covenantVersion: VERSION_V2, before: v2Base({ maxPerSpend: bad }), after: v2Base() })),
      "INVALID_INTEGER",
      `expected refusal for leading-zero form ${JSON.stringify(bad)}`
    );
  }
  /* the canonical zero and canonical values stay accepted */
  const ok = classifyPolicyDelta({
    covenantVersion: VERSION_V2,
    before: v2Base({ periodStartDaa: "0", periodSpent: "0" }),
    after: v2Base({ periodStartDaa: "0", periodSpent: "0", maxPerSpend: "50000000" })
  });
  assert.equal(ok.classification, CLASSIFICATION_REDUCTION);
});
