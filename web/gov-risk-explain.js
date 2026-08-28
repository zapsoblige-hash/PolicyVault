"use strict";

/*
 * Presentational explanations for the governance ceremony + risk hold UI
 * (PostLaunchUpgradeOG completion-standard item 6 / FULLSCALE addendum:
 * "human-readable intent/governance explanations in UI + structured
 * API/agent equivalents").
 *
 * THIS RENDERS; IT IS NOT AN AUTHORITY. Every line here narrates fields
 * the SERVER already computed and returned — server/src/governance.js
 * presentProposal()'s recomputed `proposal.classification`
 * ({classification, codes, perField}, itself a RECOMPUTATION the server
 * ran from the proposal's stored before/after tuples, per
 * docs/postlaunch/governance-spec.md §9.4 — never a trusted label), and
 * server/src/risk.js's stored evaluation (`decision`, `results`,
 * `codes`). This module never re-derives a classification or a risk
 * verdict of its own; it only turns codes/fields the server already
 * decided into readable English. A refusal or an unrecognized shape
 * renders a generic, honest line — never a fabricated explanation.
 *
 * SEAM — GOVERNANCE SIDE ACTIVE (residuals wave): the full, tested,
 * portable renderer core/explain/governance-explain.js (structured()/
 * humanReadable() over a classifyPolicyDelta-shaped result) IS now part
 * of web/core-bundle.js (exposed as window.PolicyVaultCore
 * .governanceExplain), so explainGovernance() below defers to it on
 * every real page load: deterministic exact-value ceremony lines, strict
 * validation, and aggregate-classification RECOMPUTATION (a tampered
 * stored label renders a loud refusal, never a narrated lie — proven by
 * web/test/gov-risk-explain.test.js against the REAL committed bundle).
 * The smaller local fallback below is retained for degraded builds
 * served without the core bundle (browser-verification.md degraded-page
 * rule) and covers the codes actually emitted by
 * core/governance/authority-delta.js (governance-spec §5.1) so the
 * ceremony UI is never silent.
 *
 * SEAM — RISK SIDE ACTIVE (W4-refinements): core/explain/risk-explain.js
 * is now ALSO part of web/core-bundle.js (window.PolicyVaultCore
 * .riskExplain), so explainRisk() below defers to it on every real page
 * load: deterministic rendering of the stored evaluation with the
 * composed decision/codes RECOMPUTED from the per-adapter results
 * (deny-wins) and lifecycle-status/error-path cross-checks — a
 * self-inconsistent record (e.g. a tampered flat `decision`) REFUSES
 * loudly (DECISION_MISMATCH and friends) instead of being narrated,
 * proven by web/test/gov-risk-explain.test.js against the REAL committed
 * bundle. INTEGRITY BOUNDARY (honest): unlike a governance
 * classification, the per-adapter verdicts are stored evidence of past
 * adapter executions, not re-derivable in the browser — the core module
 * verifies the record's SELF-CONSISTENCY, and the module's own trust
 * note states this in every rendering. The local fallback below remains
 * for degraded builds without the bundle.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  /* ------------------------------------------------------------------ */
  /* governance                                                          */
  /* ------------------------------------------------------------------ */

  // Mirrors core/explain/governance-explain.js describeEntry()'s code
  // coverage at the HEADLINE level (not the exact before/after phrasing —
  // that needs KAS/DAA unit conversion this presentational-only module
  // does not own). docs/postlaunch/governance-spec.md §5.1 is the
  // authoritative code list.
  const GOVERNANCE_CODE_TEXT = Object.freeze({
    EMERGENCY_FREEZE: "Emergency freeze — the vault is paused; all delegated spending stops (break-glass owner action).",
    RESUME_SPENDING: "Resume spending — the vault is unpaused; delegated spending becomes possible again.",
    DELEGATE_KEY_CHANGED: "Delegate key changes — a different key gains spending authority.",
    DELEGATE_REVOKED: "Delegate revoked — the delegate key loses spending authority.",
    DELEGATE_ENABLED: "Delegate enabled — the delegate key gains spending authority.",
    PER_SPEND_CAP_LOWERED: "Per-spend cap decreases.",
    PER_SPEND_CAP_RAISED: "Per-spend cap increases.",
    AGENT_PER_SPEND_CAP_LOWERED: "Agent per-spend cap decreases.",
    AGENT_PER_SPEND_CAP_RAISED: "Agent per-spend cap increases.",
    PERIOD_BUDGET_LOWERED: "Period budget decreases.",
    PERIOD_BUDGET_RAISED: "Period budget increases.",
    AGENT_PERIOD_BUDGET_LOWERED: "Agent period budget decreases.",
    AGENT_PERIOD_BUDGET_RAISED: "Agent period budget increases.",
    PERIOD_LENGTHENED: "Budget period lengthens — the long-run spending rate falls.",
    PERIOD_SHORTENED: "Budget period shortens — the budget refreshes faster.",
    AGENT_PERIOD_LENGTHENED: "Agent budget period lengthens.",
    AGENT_PERIOD_SHORTENED: "Agent budget period shortens.",
    AGENT_PERIOD_PHASE_CHANGED: "Agent budget period phase moves — can open a fresh period early, so it is treated as an expansion.",
    AGENT_BUDGET_CONSUMPTION_RECORDED: "Recorded spending increases (less agent budget remains).",
    AGENT_BUDGET_REFUNDED: "Recorded spending decreases — already-consumed budget is refunded (a fresh spending lane this period).",
    AGENT_FEE_CAP_LOWERED: "Agent per-transaction fee cap decreases.",
    AGENT_FEE_CAP_RAISED: "Agent per-transaction fee cap increases.",
    RECIPIENT_REMOVED: "A recipient is REMOVED from the allowlist.",
    RECIPIENT_ADDED: "A recipient is ADDED to the allowlist — a new key can be paid.",
    AGENT_RECIPIENT_REMOVED: "A recipient is REMOVED from an agent's allowlist.",
    AGENT_RECIPIENT_ADDED: "A recipient is ADDED to an agent's allowlist.",
    APPROVER_REMOVED: "An approver is REMOVED from the approver set.",
    APPROVER_ADDED: "An approver is ADDED to the approver set — a new key gains approval authority.",
    APPROVAL_QUORUM_RAISED: "Approval quorum rises — more approvals required per above-threshold spend.",
    APPROVAL_QUORUM_WEAKENED: "Approval quorum drops — fewer approvals required per above-threshold spend.",
    APPROVAL_THRESHOLD_LOWERED: "Approval threshold decreases — MORE spends require approver signatures.",
    APPROVAL_THRESHOLD_RAISED: "Approval threshold increases — more spends escape the approval tier.",
    AGENT_APPROVAL_THRESHOLD_LOWERED: "Agent approval threshold decreases — MORE of this agent's spends require approver signatures.",
    AGENT_APPROVAL_THRESHOLD_RAISED: "Agent approval threshold increases — more of this agent's spends escape the approval tier.",
    AGENT_REMOVED: "An agent is REMOVED — its key loses all delegated spending authority.",
    AGENT_ADDED: "An agent is ADDED — a new key gains delegated spending authority.",
    OPAQUE_COMMITMENT_CHANGED: "A commitment (Merkle root) is replaced opaquely — membership cannot be compared, so this is treated as an expansion.",
    AGENT_SET_OPAQUE: "The agent set is replaced opaquely — membership cannot be compared, so this is treated as an expansion.",
    MIXED_CHANGE: "This proposal mixes reductions AND expansions — the WHOLE proposal takes the stronger expansion lane.",
    COVENANT_MIGRATION: "A covenant migration replaces the vault lineage (terminal recovery + a new-version create) — always an authority expansion."
  });

  /* Local fallback: renders directly from the server's RECOMPUTED
   * classification object (never trusts a cached label — this module
   * only narrates what the server already recomputed). `proposal` is the
   * full presented proposal from GET/POST /governance/proposals[/:id]
   * (server/src/governance.js presentProposal). */
  function explainGovernanceLocal(proposal) {
    const cls = proposal && proposal.classification;
    if (!cls || (cls.classification !== "EXPANSION" && cls.classification !== "REDUCTION")) {
      return [
        "The server did not return a recognized classification for this proposal — treat it as unexplained. " +
          "Rely on the raw proposal fields; do not assume this is safe to approve."
      ];
    }
    const lines = [];
    lines.push(
      cls.classification === "EXPANSION"
        ? "AUTHORITY EXPANSION — requires owner/quorum approval: the configured governance quorum approves the proposal digest, the delay window elapses, and the owner signs the exact frozen transaction bytes in their wallet."
        : "AUTHORITY REDUCTION — a safely-restrictive change, available immediately to the vault owner (their wallet signature over the exact frozen transaction bytes is still required)."
    );
    const codes = Array.isArray(cls.codes) ? cls.codes : [];
    for (const code of codes) {
      lines.push(`${code === "MIXED_CHANGE" ? "WARNING: " : ""}${GOVERNANCE_CODE_TEXT[code] || `${code} (see the per-field detail below).`}`);
    }
    if (Array.isArray(cls.perField)) {
      for (const f of cls.perField) {
        if (!f || !f.direction || f.direction === "NEUTRAL") continue;
        const range = f.before !== undefined && f.before !== null && f.after !== undefined && f.after !== null ? ` ${f.before} -> ${f.after}` : "";
        const member = f.member ? ` [${f.member}]` : "";
        lines.push(`  - ${f.field}${member}:${range} (${f.code}, ${f.direction})`);
      }
    }
    lines.push(
      "This explanation renders the server's recomputed classification; it grants nothing. The covenant policy transition still requires the owner's wallet signature over the exact frozen transaction bytes, verified by Kaspa consensus."
    );
    return lines;
  }

  /* Prefer the real portable core/explain/governance-explain.js renderer
   * once web/core-bundle.js carries it (window.PolicyVaultCore.governanceExplain).
   * That module expects the RAW classifyPolicyDelta result shape
   * ({classification, perField, codes, covenantVersion}); the presented
   * proposal splits `covenantVersion` onto `proposal.proposal` and the
   * rest onto `proposal.classification`, so the two are recombined here —
   * the only integration work the future swap-in needs. */
  function explainGovernance(proposal) {
    try {
      const core = typeof window !== "undefined" ? window.PolicyVaultCore : undefined;
      if (core && core.governanceExplain && typeof core.governanceExplain.humanReadable === "function" && proposal && proposal.classification && proposal.proposal) {
        const deltaResult = Object.assign({}, proposal.classification, { covenantVersion: proposal.proposal.covenantVersion });
        const lines = core.governanceExplain.humanReadable(deltaResult);
        if (Array.isArray(lines) && lines.length) return lines.slice();
      }
    } catch {
      /* never let the explanation seam throw into the ceremony UI — fall through */
    }
    return explainGovernanceLocal(proposal);
  }

  /* ------------------------------------------------------------------ */
  /* risk                                                                */
  /* ------------------------------------------------------------------ */

  /* Local fallback: renders directly from the server's stored evaluation
   * record (server/src/risk.js gateOperationRisk / GET /risk/evaluations/
   * :id). `results` entries are { adapter, adapterVersion, status:
   * "OK"|"ERROR"|"TIMEOUT", verdict: "ALLOW"|"REVIEW"|"DENY", reasons:
   * [{code,message}], errorCode? } (core/risk/compose.js evaluateRisk —
   * risk-adapter-spec.md §5.4); `verdict` is the flat resolved-verdict
   * string on every status, including error/timeout paths (never ALLOW
   * there — risk-adapter-spec.md §5.2). */
  function explainRiskLocal(evaluation) {
    if (!evaluation) return ["No risk evaluation evidence is available."];
    const lines = [];
    lines.push(`Composed decision: ${evaluation.decision || "UNKNOWN"}.`);
    for (const r of evaluation.results || []) {
      if (!r) continue;
      const who = r.adapter ? `${r.adapter}${r.adapterVersion ? ` (v${r.adapterVersion})` : ""}` : "an adapter";
      if (r.status === "OK") {
        const reasons = Array.isArray(r.reasons) ? r.reasons : [];
        const reasonText = reasons.length ? reasons.map((rr) => `${rr.code}: ${rr.message}`).join("; ") : "no reasons given";
        lines.push(`${who}: ${r.verdict || "?"} — ${reasonText}`);
      } else {
        lines.push(
          `${who}: ${r.status}${r.errorCode ? ` (${r.errorCode})` : ""} — resolved to ${r.verdict || "a restrictive verdict"} per the organization's error policy (never ALLOW on error/timeout).`
        );
      }
    }
    if (Array.isArray(evaluation.codes) && evaluation.codes.length) lines.push(`Codes: ${evaluation.codes.join(", ")}.`);
    lines.push(
      "This is hosted coordination, not covenant authority: a risk ALLOW never authorizes a spend, and this hold can only ADD a restriction — it cannot override the covenant or the SDK's own policy checks."
    );
    return lines;
  }

  /* Prefer the real portable core/explain/risk-explain.js renderer now
   * that web/core-bundle.js carries it (window.PolicyVaultCore
   * .riskExplain — W4-refinements). The core module takes the stored
   * evaluation record verbatim (no recombination needed); it is TOTAL, so
   * a malformed or self-inconsistent record returns loud refusal lines
   * that render here as the explanation (never softened back to the
   * lenient fallback). A MISSING evaluation stays on the local renderer's
   * graceful line, mirroring the governance seam's shape guard; a page
   * served without the bundle uses the documented local fallback. */
  function explainRisk(evaluation) {
    try {
      const core = typeof window !== "undefined" ? window.PolicyVaultCore : undefined;
      if (evaluation && core && core.riskExplain && typeof core.riskExplain.humanReadable === "function") {
        const lines = core.riskExplain.humanReadable(evaluation);
        if (Array.isArray(lines) && lines.length) return lines.slice();
      }
    } catch {
      /* never let the explanation seam throw into the hold UI — fall through */
    }
    return explainRiskLocal(evaluation);
  }

  const surface = { explainGovernance, explainRisk, esc };
  if (typeof window !== "undefined") window.PolicyVaultGovRiskExplain = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
