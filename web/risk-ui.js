"use strict";

/*
 * Risk hold UI (FULLSCALE addendum / PostLaunchUpgradeOG completion-
 * standard item 5). Renders the held evaluation when the server refuses
 * an action with RISK_REVIEW_REQUIRED (409) or RISK_DENIED (403)
 * (server/src/risk.js gateOperationRisk, docs/postlaunch/risk-adapter-
 * spec.md §2): fetch the durable evidence by id, show each adapter's
 * verdict/reasons and the composed decision, let an AUTHORIZED HUMAN
 * release a REVIEW_HELD hold, then hand back to the caller to re-submit
 * the original request carrying riskEvaluationId — or, equivalently
 * (RC-UX-1 continuation), the user simply re-attempts the identical
 * action from the vault card: the server matches an exact id-less
 * re-submission of the released, reviewed intent (same vault, same
 * parameters, same risk-control configuration) and consumes the release
 * exactly once (server/src/risk.js consumeReleasedHoldForIntent).
 * DENY renders as FINAL
 * — no release action is ever offered for a denied evaluation, matching
 * the server's own invariant (only a REVIEW_HELD record can be
 * released; core/risk applyRiskToPolicyDecision is structurally
 * incapable of upgrading a DENY, risk-adapter-spec.md §5.3).
 *
 * NEVER AUTO-RELEASE; NEVER RETRY-LOOP. Both release and re-submit are
 * exposed here as functions the CALLER invokes from an explicit user
 * click — nothing in this module calls itself, polls, or retries on a
 * timer. A release requires a human decision every time.
 *
 * THE SERVER IS THE AUTHORITY: every field rendered is the server's own
 * stored evaluation record, verbatim. This module does not compute a
 * risk decision, does not decide who "should" be allowed to release
 * (that is enforced server-side — RISK_SELF_RELEASE_FORBIDDEN and the
 * reviewer-role check happen there regardless of what this UI shows),
 * and never retries a release/re-submit automatically. The self-release
 * pre-check below is UX only — a convenience that avoids a wasted round
 * trip; the server re-checks unconditionally.
 *
 * Network calls are injected via `api` ({ getJSON, postJSON }) so this
 * module is unit-testable headless, without fetch or a DOM.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  function shortId(id) {
    return id ? String(id).slice(0, 8) + "…" + String(id).slice(-6) : "—";
  }

  function createModule({ api, explain } = {}) {
    if (!api || typeof api.getJSON !== "function" || typeof api.postJSON !== "function") {
      throw new Error("risk-ui: createModule requires api.{getJSON,postJSON}");
    }
    const explainer =
      explain ||
      (typeof window !== "undefined" && window.PolicyVaultGovRiskExplain) || {
        explainRisk: () => ["(explanation renderer not loaded)"]
      };

    /* ---------------- pure state machine ----------------
     * `evaluation` is the stored record from GET /risk/evaluations/:id
     * (server/src/risk.js). Status values: ALLOWED | DENIED |
     * REVIEW_HELD | RELEASED | CONSUMED. The `isSelf` pre-check mirrors
     * the server's RISK_SELF_RELEASE_FORBIDDEN rule for UX only — the
     * server re-checks from durable facts regardless of what this
     * returns.
     */
    function holdState(evaluation, { xOnly } = {}) {
      if (!evaluation || typeof evaluation !== "object") {
        return { phase: "MISSING", status: null, isFinal: false, isSelf: false, canRelease: false, canResubmit: false };
      }
      const status = evaluation.status;
      const isSelf = !!(xOnly && evaluation.initiatorXOnly && xOnly === evaluation.initiatorXOnly);
      if (status === "REVIEW_HELD") {
        return { phase: "REVIEW_HELD", status, isFinal: false, isSelf, canRelease: !isSelf, canResubmit: false };
      }
      if (status === "RELEASED") {
        return { phase: "RELEASED", status, isFinal: false, isSelf, canRelease: false, canResubmit: true };
      }
      if (status === "DENIED") {
        return { phase: "DENIED", status, isFinal: true, isSelf, canRelease: false, canResubmit: false };
      }
      // ALLOWED / CONSUMED: historical evidence only, nothing actionable.
      return { phase: status || "UNKNOWN", status, isFinal: true, isSelf, canRelease: false, canResubmit: false };
    }

    /* ---------------- rendering (HTML fragment; no DOM access) ----------------
     * [data-risk-release]   -> release()
     * [data-risk-resubmit]  -> caller re-runs the original action with
     *                          riskEvaluationId (this module holds no
     *                          reference to the original action/params)
     * [data-risk-close]     -> dismiss, no action
     */
    function renderEvaluationHtml(evaluation, state) {
      if (!evaluation) {
        return `<div class="opbanner bad"><b>No risk evaluation loaded.</b></div>`;
      }
      const lines = explainer.explainRisk(evaluation) || [];
      const explainHtml = lines.map((l) => `<div class="hint" style="margin-top:0.15rem">${esc(l)}</div>`).join("");

      const isDeny = state.phase === "DENIED";
      const badgeClass = isDeny ? "PAUSED" : state.phase === "REVIEW_HELD" ? "PAUSED" : "ACTIVE";
      const headline = isDeny
        ? `<div class="opbanner bad" style="margin-top:0.6rem"><b style="color:var(--bad)">DENIED — final</b><div class="hint" style="margin-top:0.2rem">The organization's risk controls refused this operation. This decision is final: it cannot be released or overridden from this UI. If this is wrong, change the organization's risk configuration and have the acting signer submit a fresh request.</div></div>`
        : "";
      const selfWarn =
        state.phase === "REVIEW_HELD" && state.isSelf
          ? `<div class="opbanner warn" style="margin-top:0.6rem">The connected wallet initiated this request — the acting signer cannot release their own review hold. Connect an authorized reviewer's wallet to release it.</div>`
          : "";

      const actions = [];
      if (state.canRelease) actions.push(`<button class="primary" data-risk-release="${esc(evaluation.evaluationId)}">Release for execution</button>`);
      if (state.canResubmit) actions.push(`<button class="primary" data-risk-resubmit="${esc(evaluation.evaluationId)}">Re-submit the original action</button>`);
      actions.push(`<button data-risk-close="1">Close</button>`);

      return (
        `<div class="modal-card" style="max-width:640px;width:92%">` +
        `<h3 style="margin-top:0">Risk evaluation <span class="badge ${badgeClass}">${esc(evaluation.status || "UNKNOWN")}</span></h3>` +
        `<div class="kv-line">Evaluation <span class="mono">${esc(shortId(evaluation.evaluationId))}</span> · vault <span class="mono">${esc(shortId(evaluation.vaultId))}</span> · created ${esc(evaluation.createdAt || "—")}</div>` +
        headline +
        selfWarn +
        `<div style="margin-top:0.7rem">${explainHtml}</div>` +
        (evaluation.releasedAt ? `<div class="hint" style="margin-top:0.4rem">Released ${esc(evaluation.releasedAt)}</div>` : "") +
        (state.phase === "RELEASED"
          ? `<div class="hint" style="margin-top:0.3rem">Released for the exact reviewed intent. Use Re-submit here, or re-attempt the identical action from the vault card — the server matches this released review (same vault, same parameters, same risk-control configuration) and consumes it exactly once. A changed intent or configuration starts a fresh review instead.</div>`
          : "") +
        (evaluation.consumedTxId ? `<div class="hint" style="margin-top:0.4rem">Consumed by tx <span class="mono">${esc(shortId(evaluation.consumedTxId))}</span></div>` : "") +
        `<div class="modal-actions">${actions.join("")}</div>` +
        `</div>`
      );
    }

    /* ---------------- network operations ---------------- */

    async function fetchEvaluation(evaluationId) {
      const { evaluation } = await api.getJSON(`/risk/evaluations/${encodeURIComponent(evaluationId)}`);
      return evaluation;
    }

    /* Explicit, human-initiated release ONLY — never called automatically. */
    async function release(evaluationId) {
      const { evaluation } = await api.postJSON(`/risk/evaluations/${encodeURIComponent(evaluationId)}/release`, {});
      return evaluation;
    }

    return { holdState, renderEvaluationHtml, fetchEvaluation, release };
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultRiskUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
