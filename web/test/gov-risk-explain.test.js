"use strict";

/*
 * web/gov-risk-explain.js — presentational explanation rendering for the
 * governance ceremony / risk hold UI (completion-standard item 6). Covers:
 * the local fallback renderer over server-shaped proposal/evaluation
 * documents, and the SEAM (window.PolicyVaultCore.governanceExplain /
 * .riskExplain preferred when present, never throwing into the caller).
 */

const { test } = require("node:test");
const assert = require("node:assert/strict");

const explainMod = require("../gov-risk-explain.js");

/* ---------------- governance ---------------- */

function proposalFixture({ classification = "EXPANSION", codes = ["PER_SPEND_CAP_RAISED"], perField } = {}) {
  return {
    proposalId: "prop-1",
    status: "OPEN",
    createdAt: "2026-08-26T00:00:00.000Z",
    proposal: { action: "addAgent", vaultId: "aa".repeat(32), covenantVersion: "policyvault-0.4.1", expiresAt: "2026-09-09T00:00:00.000Z" },
    proposalDigest: "de".repeat(32),
    integrity: { digestOk: true, classificationOk: true },
    classification: {
      classification,
      codes,
      perField: perField || [{ field: "agents[..].maxPerSpend", direction: classification, code: codes[0], before: "1000000000", after: "2000000000" }]
    },
    approvals: { owner: "bb".repeat(32), ownerApproved: false, orgQuorum: null, verified: [], satisfied: false },
    approvalMessage: "PolicyVault governance approval\n..."
  };
}

test("explainGovernance: EXPANSION renders the requires-approval headline and per-field codes", () => {
  const lines = explainMod.explainGovernance(proposalFixture());
  assert.ok(lines.some((l) => /AUTHORITY EXPANSION/.test(l)), lines.join("\n"));
  assert.ok(lines.some((l) => /requires owner\/quorum approval/i.test(l)));
  assert.ok(lines.some((l) => /increases/i.test(l)), "known code renders its specific text");
});

test("explainGovernance: REDUCTION renders the immediate-availability headline", () => {
  const lines = explainMod.explainGovernance(proposalFixture({ classification: "REDUCTION", codes: ["PER_SPEND_CAP_LOWERED"] }));
  assert.ok(lines.some((l) => /AUTHORITY REDUCTION/.test(l)));
  assert.ok(lines.some((l) => /available immediately/i.test(l)));
});

test("explainGovernance: MIXED_CHANGE code is prefixed WARNING", () => {
  const lines = explainMod.explainGovernance(proposalFixture({ codes: ["PER_SPEND_CAP_RAISED", "MIXED_CHANGE"] }));
  assert.ok(lines.some((l) => l.startsWith("WARNING:") && /mixes reductions AND expansions/i.test(l)));
});

test("explainGovernance: an unrecognized classification renders an honest refusal-shaped line, never a fabricated explanation", () => {
  const lines = explainMod.explainGovernance({ classification: { classification: "SOMETHING_ELSE" } });
  assert.equal(lines.length, 1);
  assert.ok(/did not return a recognized classification/i.test(lines[0]));
});

test("explainGovernance: a missing proposal never throws", () => {
  assert.doesNotThrow(() => explainMod.explainGovernance(null));
  assert.doesNotThrow(() => explainMod.explainGovernance(undefined));
});

test("explainGovernance: unknown codes still render generically rather than being dropped", () => {
  const lines = explainMod.explainGovernance(proposalFixture({ codes: ["SOME_FUTURE_CODE"] }));
  assert.ok(lines.some((l) => l.includes("SOME_FUTURE_CODE")));
});

/* ---- the core/explain seam: prefer window.PolicyVaultCore.governanceExplain
 * the instant it is present, recombining classification+covenantVersion
 * into the classifyPolicyDelta-shaped input it expects. ---- */
test("explainGovernance: defers to window.PolicyVaultCore.governanceExplain when present, with the correct recombined shape", () => {
  const seen = [];
  global.window = {
    PolicyVaultCore: {
      governanceExplain: {
        humanReadable(deltaResult) {
          seen.push(deltaResult);
          return ["FROM CORE MODULE"];
        }
      }
    }
  };
  try {
    const p = proposalFixture();
    const lines = explainMod.explainGovernance(p);
    assert.deepEqual(lines, ["FROM CORE MODULE"]);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].classification, "EXPANSION");
    assert.equal(seen[0].covenantVersion, "policyvault-0.4.1", "covenantVersion recombined from proposal.proposal");
    assert.deepEqual(seen[0].codes, p.classification.codes);
  } finally {
    delete global.window;
  }
});

test("explainGovernance: a throwing core module falls back to the local renderer instead of propagating", () => {
  global.window = { PolicyVaultCore: { governanceExplain: { humanReadable() { throw new Error("boom"); } } } };
  try {
    const lines = explainMod.explainGovernance(proposalFixture());
    assert.ok(lines.some((l) => /AUTHORITY EXPANSION/.test(l)), "fell back to the local renderer");
  } finally {
    delete global.window;
  }
});

/* ---- REAL committed bundle (residuals wave): core/explain/governance-
 * explain.js is now IN web/core-bundle.js, so the seam ACTIVATES — the
 * deterministic portable renderer produces the ceremony lines, not the
 * local fallback. The presented-proposal shape used here is exactly
 * server/src/governance.js presentProposal's: classification =
 * { classification, codes, perField } (the RECOMPUTED result) with
 * covenantVersion on proposal.proposal. ---- */
test("explainGovernance: with the REAL committed core bundle the deterministic core renderer takes over (exact module lines; fallback headline absent)", () => {
  const bundle = require("../core-bundle.js");
  const coreExplain = require("../../core/explain/governance-explain.js");
  const { classifyPolicyDelta } = require("../../core/governance");
  const v4Tuple = (agentOverrides = {}) => ({
    paused: "0",
    approvalM: "2",
    approvers: ["44".repeat(32), "55".repeat(32)],
    agents: [{
      agentPk: "22".repeat(32), maxPerSpend: "2000000000", periodBudget: "5000000000",
      periodLengthDaa: "86400", periodStartDaa: "1000000", periodSpent: "500000000",
      approvalThreshold: "1500000000", agentMaxFeePerTx: "100000", recipients: ["66".repeat(32)],
      ...agentOverrides
    }]
  });
  const delta = classifyPolicyDelta({ covenantVersion: "policyvault-0.4.1", before: v4Tuple(), after: v4Tuple({ maxPerSpend: "3000000000" }) });
  // JSON round trip: the browser receives the presented proposal over HTTP.
  const presented = JSON.parse(JSON.stringify({
    proposal: { covenantVersion: delta.covenantVersion, action: "rePolicyAgent", expiresAt: "2026-09-09T00:00:00.000Z" },
    classification: { classification: delta.classification, codes: delta.codes, perField: delta.perField },
    integrity: { digestOk: true, classificationOk: true }
  }));
  global.window = { PolicyVaultCore: bundle };
  try {
    const lines = explainMod.explainGovernance(presented);
    assert.deepEqual(lines, [...coreExplain.humanReadable(delta)], "the seam must render EXACTLY the core module's deterministic lines");
    assert.match(lines[0], /^AUTHORITY EXPANSION: agent [0-9a-f]{64} per-spend cap increases from 20 KAS to 30 KAS/, "core renderer headline (exact-value phrasing the fallback does not produce)");
    assert.ok(!lines.some((l) => /^AUTHORITY EXPANSION — requires owner\/quorum approval:/.test(l)), "the local fallback headline must NOT appear");
  } finally {
    delete global.window;
  }
});

test("explainGovernance: with the REAL bundle a TAMPERED stored classification label REFUSES loudly (stored-label distrust) instead of narrating the lie", () => {
  const bundle = require("../core-bundle.js");
  const { classifyPolicyDelta } = require("../../core/governance");
  const v4Tuple = (agentOverrides = {}) => ({
    paused: "0",
    approvalM: "1",
    approvers: ["44".repeat(32)],
    agents: [{
      agentPk: "22".repeat(32), maxPerSpend: "2000000000", periodBudget: "5000000000",
      periodLengthDaa: "86400", periodStartDaa: "1000000", periodSpent: "0",
      approvalThreshold: "1500000000", agentMaxFeePerTx: "100000", recipients: ["66".repeat(32)],
      ...agentOverrides
    }]
  });
  const delta = classifyPolicyDelta({ covenantVersion: "policyvault-0.4.1", before: v4Tuple(), after: v4Tuple({ maxPerSpend: "3000000000" }) });
  const presented = JSON.parse(JSON.stringify({
    proposal: { covenantVersion: delta.covenantVersion },
    // hostile: the label says REDUCTION while every per-field direction says EXPANSION
    classification: { classification: "REDUCTION", codes: delta.codes, perField: delta.perField }
  }));
  global.window = { PolicyVaultCore: bundle };
  try {
    const lines = explainMod.explainGovernance(presented);
    assert.ok(lines.some((l) => /CLASSIFICATION_MISMATCH|REFUSED/.test(l)), "the tampered label must surface as a refusal, never as a narrated REDUCTION: " + lines.join("\n"));
    assert.ok(!lines.some((l) => /available immediately/i.test(l)), "must not render the REDUCTION ceremony text for a tampered label");
  } finally {
    delete global.window;
  }
});

/* ---------------- risk ---------------- */

function evaluationFixture({ decision = "REVIEW", results } = {}) {
  return {
    evaluationId: "eval-1",
    status: "REVIEW_HELD",
    decision,
    codes: ["THRESHOLD_EXCEEDED"],
    results: results || [
      { adapter: "threshold-guard", adapterVersion: "1", status: "OK", verdict: "REVIEW", reasons: [{ code: "THRESHOLD_EXCEEDED", message: "amount above the configured threshold" }] }
    ],
    createdAt: "2026-08-26T00:00:00.000Z"
  };
}

test("explainRisk: OK-status results render the adapter's verdict and reasons", () => {
  const lines = explainMod.explainRisk(evaluationFixture());
  assert.ok(lines.some((l) => /Composed decision: REVIEW/.test(l)));
  assert.ok(lines.some((l) => l.includes("threshold-guard") && l.includes("REVIEW") && l.includes("THRESHOLD_EXCEEDED")));
});

test("explainRisk: ERROR/TIMEOUT statuses never render as ALLOW and name the resolved restrictive verdict", () => {
  const lines = explainMod.explainRisk(
    evaluationFixture({
      results: [{ adapter: "flaky", adapterVersion: "1", status: "TIMEOUT", errorCode: "ADAPTER_TIMEOUT", verdict: "REVIEW", reasons: [] }]
    })
  );
  const line = lines.find((l) => l.includes("flaky"));
  assert.ok(line, lines.join("\n"));
  assert.ok(line.includes("TIMEOUT") && line.includes("ADAPTER_TIMEOUT") && line.includes("REVIEW"));
  assert.ok(!/: ALLOW/.test(line), "an error/timeout path never reports ALLOW");
});

test("explainRisk: never claims authority — always states risk cannot override the covenant", () => {
  const lines = explainMod.explainRisk(evaluationFixture());
  assert.ok(lines.some((l) => /never authorizes|cannot override/i.test(l)));
});

test("explainRisk: a missing evaluation never throws and says so honestly", () => {
  const lines = explainMod.explainRisk(null);
  assert.deepEqual(lines, ["No risk evaluation evidence is available."]);
});

test("explainRisk: falls through to the local renderer when no core bundle is registered (degraded build)", () => {
  const lines = explainMod.explainRisk(evaluationFixture());
  assert.ok(Array.isArray(lines) && lines.length > 0);
  assert.ok(lines.some((l) => /Composed decision: REVIEW/.test(l)), "the local fallback rendered (no window.PolicyVaultCore in this test)");
});

/* ---- REAL committed bundle (W4-refinements): core/explain/risk-explain.js
 * is now IN web/core-bundle.js, so the risk seam ACTIVATES — the
 * deterministic portable renderer produces the hold lines, not the local
 * fallback. The evaluation shape used here is exactly the server's stored
 * record (server/src/risk.js GET /risk/evaluations/:id returns it
 * verbatim). ---- */

/* a fully self-consistent server-shaped evaluation (codes recomputed from
 * reasons; status consistent with decision; real config object) */
function consistentEvaluation({ decision = "REVIEW", status = "REVIEW_HELD", results } = {}) {
  const rs = results || [
    { adapter: "threshold-guard", adapterVersion: "1.0.0", status: "OK", verdict: decision, reasons: [{ code: "THRESHOLD_EXCEEDED", message: "amount above the configured threshold" }] }
  ];
  return {
    schema: "policyvault-risk-evaluation/v1",
    evaluationId: "11111111-2222-4333-8444-555555555555",
    networkId: "testnet-10",
    vaultId: "aa".repeat(32),
    orgId: "org-1",
    intentHash: "bd".repeat(32),
    intent: { schema: "policyvault-risk-intent/1", action: "agentSpend" },
    initiatorXOnly: "cc".repeat(32),
    decision,
    results: rs,
    codes: [...new Set(rs.flatMap((r) => r.reasons.map((x) => x.code)))].sort(),
    config: { onAdapterError: "REVIEW", onEmpty: "ALLOW", timeoutMs: 5000, reviewRequired: false },
    status,
    createdAt: "2026-08-26T00:00:00.000Z"
  };
}

test("explainRisk: with the REAL committed core bundle the deterministic core renderer takes over (exact module lines; fallback headline absent)", () => {
  const bundle = require("../core-bundle.js");
  const coreRiskExplain = require("../../core/explain/risk-explain.js");
  // JSON round trip: the browser receives the record over HTTP.
  const evaluation = JSON.parse(JSON.stringify(consistentEvaluation()));
  global.window = { PolicyVaultCore: bundle };
  try {
    const lines = explainMod.explainRisk(evaluation);
    assert.deepEqual(lines, [...coreRiskExplain.humanReadable(evaluation)], "the seam must render EXACTLY the core module's deterministic lines");
    assert.match(lines[0], /^RISK REVIEW: this operation is held for human review/, "core renderer headline");
    assert.ok(lines.some((l) => l.startsWith("Evaluation status: REVIEW_HELD")), "lifecycle status narrated");
    assert.ok(lines.some((l) => l.includes("deny-wins")), "composition semantics stated");
    assert.ok(!lines.some((l) => /^Composed decision:/.test(l)), "the local fallback rendering must NOT appear");
  } finally {
    delete global.window;
  }
});

test("explainRisk: with the REAL bundle a TAMPERED stored risk decision REFUSES loudly (recomputed deny-wins distrusts the flat label) instead of narrating the lie", () => {
  const bundle = require("../core-bundle.js");
  // hostile: per-adapter verdict says DENY; the flat stored decision (and
  // status) were flipped to look permissive.
  const tampered = JSON.parse(JSON.stringify(consistentEvaluation({
    decision: "DENY",
    status: "DENIED",
    results: [{ adapter: "sanctions", adapterVersion: "1.0.0", status: "OK", verdict: "DENY", reasons: [{ code: "SANCTIONS_HIT", message: "recipient matched a watchlist" }] }]
  })));
  tampered.decision = "ALLOW";
  tampered.status = "ALLOWED";
  global.window = { PolicyVaultCore: bundle };
  try {
    const lines = explainMod.explainRisk(tampered);
    assert.match(lines[0], /^RISK EXPLANATION REFUSED/, "the tampered record must surface as a refusal: " + lines.join("\n"));
    assert.ok(lines.some((l) => l.includes("DECISION_MISMATCH")), "the decision tamper is named");
    assert.ok(!lines.some((l) => /^RISK ALLOW/.test(l)), "must not render the ALLOW headline for a tampered label");
    assert.ok(!lines.some((l) => /Composed decision: ALLOW/.test(l)), "must not fall back to the lenient local narration");
    assert.ok(lines.some((l) => /never as an ALLOW/i.test(l)), "the refusal instructs restrictive handling");
  } finally {
    delete global.window;
  }
});

test("explainRisk: with the REAL bundle an ERROR-path result resolved to ALLOW refuses (never-silent-ALLOW is enforced at render time too)", () => {
  const bundle = require("../core-bundle.js");
  const doc = JSON.parse(JSON.stringify(consistentEvaluation({
    decision: "ALLOW",
    status: "ALLOWED",
    results: [{ adapter: "flaky", adapterVersion: "1.0.0", status: "TIMEOUT", errorCode: "ADAPTER_TIMEOUT", verdict: "ALLOW", reasons: [] }]
  })));
  global.window = { PolicyVaultCore: bundle };
  try {
    const lines = explainMod.explainRisk(doc);
    assert.match(lines[0], /^RISK EXPLANATION REFUSED/);
    assert.ok(lines.some((l) => l.includes("ERROR_PATH_ALLOW")));
  } finally {
    delete global.window;
  }
});

test("explainRisk: with the REAL bundle a MISSING evaluation still gets the graceful local line (seam shape guard, mirrors governance)", () => {
  const bundle = require("../core-bundle.js");
  global.window = { PolicyVaultCore: bundle };
  try {
    assert.deepEqual(explainMod.explainRisk(null), ["No risk evaluation evidence is available."]);
  } finally {
    delete global.window;
  }
});
