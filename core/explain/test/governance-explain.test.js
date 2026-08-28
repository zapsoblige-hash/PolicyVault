"use strict";

/*
 * UNIT / ADVERSARIAL (display level) — governance authority-delta
 * explanations (core/explain/governance-explain.js).
 *
 * Real classifier results (core/governance classifyPolicyDelta /
 * classifyMigrationDelta) rendered as structured + human-readable
 * explanations: golden EXPANSION/REDUCTION headlines, per-field lines,
 * mixed/opaque expansion warnings, migration rendering, exact KAS
 * amounts, full-value key display, determinism, and fail-closed
 * refusals for tampered/unknown/malformed delta results.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { classifyPolicyDelta, classifyMigrationDelta } = require("../../governance");
const { canonicalJsonStringify } = require("../../intent");
const { governanceExplain, GOVERNANCE_EXPLANATION_VERSION_1, GOVERNANCE_EXPLANATION_VERDICTS } = require("../index");

const HEX = (b) => b.repeat(32);
const DELEGATE = HEX("11");
const R1 = HEX("22");
const R2 = HEX("33");
const A1 = HEX("44");
const A2 = HEX("55");
const A3 = HEX("66");
const AGENT = HEX("aa");
const ROOT1 = HEX("bb");
const ROOT2 = HEX("cc");

/* v0.2 delegate tuple (real field names). */
function v2Tuple(overrides = {}) {
  return {
    paused: "0",
    delegate: DELEGATE,
    delegateActive: "1",
    maxPerSpend: "2000000000",
    periodBudget: "5000000000",
    periodLengthDaa: "86400",
    recipients: [R1, R2],
    ...overrides
  };
}

/* v0.4.1 agents tuple (list form). */
function v4Agent(overrides = {}) {
  return {
    agentPk: AGENT,
    maxPerSpend: "2000000000",
    periodBudget: "5000000000",
    periodLengthDaa: "86400",
    periodStartDaa: "1000000",
    periodSpent: "500000000",
    approvalThreshold: "1500000000",
    agentMaxFeePerTx: "100000",
    recipients: [R1],
    ...overrides
  };
}

function v4Tuple(overrides = {}) {
  const tuple = {
    paused: "0",
    approvalM: "2",
    approvers: [A1, A2],
    agents: [v4Agent()],
    ...overrides
  };
  // An `undefined` override means "omit this key" (the classifier's
  // xor rule reads key PRESENCE, so a present-but-undefined key would
  // trip AMBIGUOUS_FORM instead of selecting the other form).
  for (const key of Object.keys(tuple)) {
    if (tuple[key] === undefined) delete tuple[key];
  }
  return tuple;
}

function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

function assertRefused(doc, codes, label) {
  assert.equal(doc.verdict, GOVERNANCE_EXPLANATION_VERDICTS.REFUSED, `${label}: verdict`);
  assert.equal(doc.perField, null, `${label}: no per-field rendering on refusal`);
  assert.equal(doc.headline, null, `${label}: no headline on refusal`);
  for (const code of codes) {
    assert.ok(doc.refusal.codes.includes(code), `${label}: expected ${code}, got ${JSON.stringify(doc.refusal.codes)}`);
  }
}

/* ------------------------------------------------------------------ */
/* golden renderings                                                   */
/* ------------------------------------------------------------------ */

test("governance-explain: per-spend cap raise — golden EXPANSION headline with exact KAS", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "3000000000" })
  });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.explanationVersion, GOVERNANCE_EXPLANATION_VERSION_1);
  assert.equal(doc.verdict, GOVERNANCE_EXPLANATION_VERDICTS.EXPLAINED);
  assert.equal(doc.kind, "policy-change");
  assert.equal(doc.classification, "EXPANSION");
  assert.equal(doc.headline, "AUTHORITY EXPANSION: per-spend cap increases from 20 KAS to 30 KAS — requires owner/quorum approval.");
  assert.equal(doc.mixed, false);
  const changed = doc.perField.filter((e) => e.changed);
  assert.equal(changed.length, 1);
  assert.deepEqual(
    { field: changed[0].field, code: changed[0].code, before: changed[0].before, after: changed[0].after, unit: changed[0].unit },
    { field: "maxPerSpend", code: "PER_SPEND_CAP_RAISED", before: "2000000000", after: "3000000000", unit: "sompi" }
  );
  const lines = governanceExplain.humanReadable(delta);
  assert.equal(lines[0], doc.headline);
  assert.ok(lines.includes("EXPANSION: The per-spend cap increases from 20 KAS to 30 KAS."), lines.join("\n"));
  assert.match(lines[lines.length - 2], /^Ceremony: Requires owner\/quorum approval/);
});

test("governance-explain: per-spend cap lowering — golden REDUCTION rendering", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "1000000000" })
  });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.classification, "REDUCTION");
  assert.equal(doc.headline, "AUTHORITY REDUCTION: per-spend cap decreases from 20 KAS to 10 KAS — owner signature only, available immediately.");
  const lines = governanceExplain.humanReadable(delta);
  assert.ok(lines.includes("REDUCTION: The per-spend cap decreases from 20 KAS to 10 KAS."), lines.join("\n"));
  assert.match(lines[lines.length - 2], /^Ceremony: Safely-restrictive change/);
});

test("governance-explain: mixed change carries the prominent expansion warning", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "1000000000", periodBudget: "6000000000" }) // cap down + budget up
  });
  assert.equal(delta.classification, "EXPANSION");
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.mixed, true);
  assert.ok(doc.codes.includes("MIXED_CHANGE"));
  const lines = governanceExplain.humanReadable(delta);
  assert.ok(
    lines.includes("WARNING: MIXED CHANGE — this proposal contains reductions AND expansions; the whole proposal takes the EXPANSION lane (MIXED_CHANGE)."),
    lines.join("\n")
  );
});

test("governance-explain: emergency freeze renders the break-glass note; resume is an expansion", () => {
  const freeze = classifyPolicyDelta({ covenantVersion: "policyvault-0.2", before: v2Tuple(), after: v2Tuple({ paused: "1" }) });
  const freezeDoc = governanceExplain.structured(freeze);
  assert.equal(freezeDoc.classification, "REDUCTION");
  assert.equal(freezeDoc.emergencyFreeze, true);
  const freezeLines = governanceExplain.humanReadable(freeze);
  assert.ok(freezeLines.includes("Emergency freeze is a break-glass owner action: no governance configuration may delay, gate, or block it."), freezeLines.join("\n"));

  const resume = classifyPolicyDelta({ covenantVersion: "policyvault-0.2", before: v2Tuple({ paused: "1" }), after: v2Tuple() });
  const resumeDoc = governanceExplain.structured(resume);
  assert.equal(resumeDoc.classification, "EXPANSION");
  assert.ok(governanceExplain.humanReadable(resume).some((l) => l.includes("Resume spending")), "resume line");
});

test("governance-explain: opaque commitment swap renders as an explicit opaque expansion (full roots)", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.4.1",
    before: v4Tuple({ agents: undefined, agentRoot: ROOT1 }),
    after: v4Tuple({ agents: undefined, agentRoot: ROOT2 })
  });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.classification, "EXPANSION");
  const entry = doc.perField.find((e) => e.code === "AGENT_SET_OPAQUE");
  assert.deepEqual({ before: entry.before, after: entry.after }, { before: ROOT1, after: ROOT2 });
  const lines = governanceExplain.humanReadable(delta);
  const line = lines.find((l) => l.includes("OPAQUELY"));
  assert.ok(line.includes(ROOT1) && line.includes(ROOT2), "full roots rendered, never truncated");
  assert.ok(line.includes("treated as an expansion"), line);
});

test("governance-explain: agent add/remove and leaf edits render member keys in full", () => {
  const NEW_AGENT = HEX("dd");
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.4.1",
    before: v4Tuple(),
    after: v4Tuple({ agents: [v4Agent(), v4Agent({ agentPk: NEW_AGENT })] })
  });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.classification, "EXPANSION");
  const added = doc.perField.find((e) => e.code === "AGENT_ADDED");
  assert.equal(added.member, NEW_AGENT);
  const lines = governanceExplain.humanReadable(delta);
  const joined = lines.join("\n");
  assert.ok(joined.includes(`Agent ${NEW_AGENT} is ADDED`), joined);
  assert.ok(!joined.includes("…") && !joined.includes("..."), "no truncation anywhere");
});

test("governance-explain: agent budget refund renders as an expansion with exact KAS", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.4.1",
    before: v4Tuple(),
    after: v4Tuple({ agents: [v4Agent({ periodSpent: "0" })] })
  });
  assert.equal(delta.classification, "EXPANSION");
  const lines = governanceExplain.humanReadable(delta);
  const line = lines.find((l) => l.includes("refunded"));
  assert.ok(line.includes("from 5 KAS to 0 KAS"), line);
  assert.ok(line.startsWith(`EXPANSION: The agent ${AGENT} recorded period spending falls`), line);
});

test("governance-explain: approver and quorum changes render counts and full keys", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.4.1",
    before: v4Tuple(),
    after: v4Tuple({ approvers: [A1, A2, A3], approvalM: "1" })
  });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.classification, "EXPANSION");
  const lines = governanceExplain.humanReadable(delta);
  const joined = lines.join("\n");
  assert.ok(joined.includes(`Approver ${A3} is ADDED to the approver set`), joined);
  assert.ok(joined.includes("Approval quorum drops from 2 to 1 required approval(s)"), joined);
});

test("governance-explain: covenant migration renders the always-expansion two-step rendering", () => {
  const delta = classifyMigrationDelta({ fromVersion: "policyvault-0.4", toVersion: "policyvault-0.4.1" });
  const doc = governanceExplain.structured(delta);
  assert.equal(doc.kind, "covenant-migration");
  assert.equal(doc.classification, "EXPANSION");
  assert.deepEqual({ from: doc.fromVersion, to: doc.toVersion }, { from: "policyvault-0.4", to: "policyvault-0.4.1" });
  assert.equal(doc.headline, "AUTHORITY EXPANSION: covenant migration from policyvault-0.4 to policyvault-0.4.1 — requires owner/quorum approval.");
  const lines = governanceExplain.humanReadable(delta);
  assert.ok(lines.some((l) => l.includes("terminal ownerRecover, then a new-version create")), lines.join("\n"));
  assert.ok(lines.some((l) => l.includes("ALWAYS classified as an authority expansion")), lines.join("\n"));
});

test("governance-explain: period length and phase fields render as DAA (not KAS)", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ periodLengthDaa: "172800" })
  });
  const lines = governanceExplain.humanReadable(delta);
  assert.ok(lines[0].includes("from DAA 86400 to DAA 172800"), lines[0]);
  const line = lines.find((l) => l.includes("lengthens"));
  assert.ok(line.includes("from DAA 86400 to DAA 172800"), line);
  assert.ok(line.includes("long-run spending rate falls"), line);
  assert.equal(governanceExplain.structured(delta).classification, "REDUCTION");
});

test("governance-explain: i64-scale amounts render exactly (integer path)", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple({ maxPerSpend: "9223372036854775806", periodBudget: "9223372036854775807" }),
    after: v2Tuple({ maxPerSpend: "9223372036854775807", periodBudget: "9223372036854775807" })
  });
  const lines = governanceExplain.humanReadable(delta);
  const line = lines.find((l) => l.includes("per-spend cap"));
  assert.ok(line.includes("from 92233720368.54775806 KAS to 92233720368.54775807 KAS"), line);
});

/* ------------------------------------------------------------------ */
/* determinism + shape                                                 */
/* ------------------------------------------------------------------ */

test("governance-explain: determinism — same delta renders byte-identically; output frozen + JSON-safe", () => {
  const make = () =>
    classifyPolicyDelta({ covenantVersion: "policyvault-0.4.1", before: v4Tuple(), after: v4Tuple({ approvalM: "1" }) });
  const a = make();
  const b = make();
  assert.equal(canonicalJsonStringify(governanceExplain.structured(a)), canonicalJsonStringify(governanceExplain.structured(b)));
  assert.equal(governanceExplain.humanReadable(a).join("\n"), governanceExplain.humanReadable(b).join("\n"));
  const doc = governanceExplain.structured(a);
  assert.ok(Object.isFrozen(doc) && Object.isFrozen(doc.perField[0]));
});

test("governance-explain: unknown per-field CODES render generically under their validated direction", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "3000000000" })
  });
  const forward = clone(delta);
  forward.perField = forward.perField.map((e) => (e.code === "PER_SPEND_CAP_RAISED" ? { ...e, code: "FUTURE_UNKNOWN_CODE" } : e));
  forward.codes = ["FUTURE_UNKNOWN_CODE"];
  const doc = governanceExplain.structured(forward);
  assert.equal(doc.verdict, GOVERNANCE_EXPLANATION_VERDICTS.EXPLAINED);
  const entry = doc.perField.find((e) => e.code === "FUTURE_UNKNOWN_CODE");
  assert.equal(entry.direction, "EXPANSION");
  assert.ok(entry.description.includes("(FUTURE_UNKNOWN_CODE)"), entry.description);
  assert.ok(entry.description.includes("from 20 KAS to 30 KAS"), entry.description);
});

/* ------------------------------------------------------------------ */
/* fail-closed refusals                                                */
/* ------------------------------------------------------------------ */

test("governance-explain: a tampered stored classification refuses (CLASSIFICATION_MISMATCH integrity alarm)", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "3000000000" })
  });
  const tampered = clone(delta);
  tampered.classification = "REDUCTION"; // a DB writer flipping the label achieves nothing
  assertRefused(governanceExplain.structured(tampered), ["CLASSIFICATION_MISMATCH"], "flipped label");
  const lines = governanceExplain.humanReadable(tampered);
  assert.equal(lines[0], "GOVERNANCE EXPLANATION REFUSED — do not act on this proposal rendering.");
  assert.ok(lines.some((l) => l.includes("CLASSIFICATION_MISMATCH")), lines.join("\n"));
});

test("governance-explain: a forged MIXED_CHANGE marker refuses", () => {
  const delta = classifyPolicyDelta({
    covenantVersion: "policyvault-0.2",
    before: v2Tuple(),
    after: v2Tuple({ maxPerSpend: "3000000000" })
  });
  const tampered = clone(delta);
  tampered.codes = [...tampered.codes, "MIXED_CHANGE"];
  assertRefused(governanceExplain.structured(tampered), ["CLASSIFICATION_MISMATCH"], "forged mixed marker");
});

test("governance-explain: unknown directions, classifications, and versions refuse", () => {
  const base = classifyPolicyDelta({ covenantVersion: "policyvault-0.2", before: v2Tuple(), after: v2Tuple({ maxPerSpend: "3000000000" }) });

  const badDirection = clone(base);
  badDirection.perField = badDirection.perField.map((e) => (e.direction === "EXPANSION" ? { ...e, direction: "SIDEWAYS" } : e));
  assertRefused(governanceExplain.structured(badDirection), ["UNKNOWN_DIRECTION"], "unknown direction");

  const badClassification = clone(base);
  badClassification.classification = "MAYBE";
  assertRefused(governanceExplain.structured(badClassification), ["UNKNOWN_CLASSIFICATION"], "unknown classification");

  const badVersion = clone(base);
  badVersion.covenantVersion = "policyvault-9.9";
  assertRefused(governanceExplain.structured(badVersion), ["UNKNOWN_VERSION"], "unknown covenant version");

  const badMigration = { classification: "EXPANSION", fromVersion: "policyvault-0.4", toVersion: "policyvault-99", perField: [], codes: ["COVENANT_MIGRATION"] };
  assertRefused(governanceExplain.structured(badMigration), ["UNKNOWN_VERSION"], "unknown migration version");
});

test("governance-explain: an all-neutral result refuses (NO_CHANGE) — a no-op is not a governable change", () => {
  const base = classifyPolicyDelta({ covenantVersion: "policyvault-0.2", before: v2Tuple(), after: v2Tuple({ maxPerSpend: "3000000000" }) });
  const neutral = clone(base);
  neutral.perField = neutral.perField.map((e) => ({ ...e, direction: "NEUTRAL", code: "UNCHANGED" }));
  assertRefused(governanceExplain.structured(neutral), ["NO_CHANGE"], "all neutral");
});

test("governance-explain: a non-EXPANSION migration result refuses", () => {
  const forged = { classification: "REDUCTION", fromVersion: "policyvault-0.2", toVersion: "policyvault-0.3", perField: [], codes: ["COVENANT_MIGRATION"] };
  assertRefused(governanceExplain.structured(forged), ["CLASSIFICATION_MISMATCH"], "reduction-labeled migration");
});

test("governance-explain: total functions — malformed input never throws, always a refusal rendering", () => {
  for (const input of [undefined, null, 42, "delta", [], {}, { classification: "EXPANSION" }, { classification: "EXPANSION", covenantVersion: "policyvault-0.2", perField: "x", codes: [] }]) {
    const doc = governanceExplain.structured(input);
    assert.equal(doc.verdict, GOVERNANCE_EXPLANATION_VERDICTS.REFUSED);
    const lines = governanceExplain.humanReadable(input);
    assert.equal(lines[0], "GOVERNANCE EXPLANATION REFUSED — do not act on this proposal rendering.");
    assert.ok(canonicalJsonStringify(doc).length > 0, "refusal documents are JSON-safe");
  }
});

test("governance-explain: refusal rendering is deterministic", () => {
  const make = () => {
    const d = clone(classifyPolicyDelta({ covenantVersion: "policyvault-0.2", before: v2Tuple(), after: v2Tuple({ paused: "1" }) }));
    d.classification = "EXPANSION"; // diverges from recomputed REDUCTION
    return d;
  };
  assert.equal(canonicalJsonStringify(governanceExplain.structured(make())), canonicalJsonStringify(governanceExplain.structured(make())));
  assert.equal(governanceExplain.humanReadable(make()).join("\n"), governanceExplain.humanReadable(make()).join("\n"));
});
