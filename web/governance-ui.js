"use strict";

/*
 * Governance ceremony UI (FULLSCALE addendum / PostLaunchUpgradeOG
 * completion-standard item 1). Renders the hosted-workflow ceremony for
 * an AUTHORITY EXPANSION action the server refused with
 * GOVERNANCE_PROPOSAL_REQUIRED (server/src/governance.js
 * requireApprovedProposal, docs/postlaunch/governance-spec.md §6.2):
 * create the proposal, show status (approvals collected/required,
 * expiry), let an authorized wallet perform the approval ceremony
 * THROUGH THE APP'S EXISTING SIGNER PLUMBING (adapter.signAuthMessage —
 * the same personal-message signing path web/app.js's hosted sign-in
 * already uses; this module never talks to window.kasware directly and
 * never adds a second signing path), cancel, and retry the ORIGINAL
 * action once approvals are satisfied, consuming the proposal.
 *
 * THE SERVER IS THE AUTHORITY. Nothing here invents a classification, an
 * approval count, a delay outcome, or a retry-eligibility guess: every
 * field rendered comes verbatim from the server's presentProposal()
 * response, which itself recomputes everything from content at read time
 * (governance-spec §9.4 — stored labels are distrusted). A server
 * refusal (STALE_PROPOSAL, GOVERNANCE_PROPOSAL_EXPIRED,
 * GOVERNANCE_PROPOSAL_MISMATCH, CLASSIFICATION_MISMATCH,
 * GOVERNANCE_DELAY_PENDING, GOVERNANCE_APPROVALS_INSUFFICIENT, ...) is
 * rendered exactly as returned — this layer never papers over, retries
 * automatically, or offers a soft bypass for a refusal. The delay
 * window's exact clock is deliberately NOT predicted client-side (this
 * module does not know the organization's controls or its own clock
 * skew): "retry" is offered once approvals are satisfied, and a
 * GOVERNANCE_DELAY_PENDING refusal from the actual retry attempt is
 * rendered with the server's own `availableAt` timestamp.
 *
 * Network calls are injected via `api` ({ getJSON, postJSON } — the same
 * signatures web/app-v4.js already uses) so this module is unit-testable
 * headless, without fetch or a DOM.
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
      throw new Error("governance-ui: createModule requires api.{getJSON,postJSON}");
    }
    const explainer =
      explain ||
      (typeof window !== "undefined" && window.PolicyVaultGovRiskExplain) || {
        explainGovernance: () => ["(explanation renderer not loaded)"]
      };

    /* ---------------- pure state machine ----------------
     * `proposal` is the full presented-proposal document from GET/POST
     * /governance/proposals[/:id] (server/src/governance.js
     * presentProposal). Returns flags the CALLER combines with its own
     * knowledge (e.g. vault ownership for cancel-authority) — this module
     * never assumes which wallet is connected beyond the xOnly it is
     * given, and never assumes vault ownership (it has no vault object).
     */
    function ceremonyState(proposal, { xOnly } = {}) {
      if (!proposal || typeof proposal !== "object") {
        return { phase: "MISSING", status: null, satisfied: false, alreadyApproved: false, isOwner: false, canApprove: false, canRetry: false };
      }
      const status = proposal.status;
      if (status !== "OPEN") {
        return { phase: "CLOSED", status, satisfied: false, alreadyApproved: false, isOwner: false, canApprove: false, canRetry: false };
      }
      const approvals = proposal.approvals || null;
      const satisfied = !!(approvals && approvals.satisfied === true);
      const verified = (approvals && Array.isArray(approvals.verified) && approvals.verified) || [];
      const alreadyApproved = !!(xOnly && verified.some((v) => v && v.approverXOnly === xOnly));
      const isOwner = !!(approvals && xOnly && approvals.owner === xOnly);
      return {
        phase: satisfied ? "READY_TO_RETRY" : "COLLECTING_APPROVALS",
        status,
        satisfied,
        alreadyApproved,
        isOwner,
        canApprove: !satisfied && !alreadyApproved,
        canRetry: satisfied
      };
    }

    /* ---------------- rendering (HTML fragment; no DOM access) ----------------
     * The caller inserts the returned string into its own modal container
     * and wires the data-* buttons present per the `state` flags:
     *   [data-gov-approve]   -> approve()
     *   [data-gov-retry]     -> re-run the original action with proposalId
     *   [data-gov-cancel]    -> cancelProposal() (caller additionally gates
     *                           this on vault ownership; this module does
     *                           not know the vault)
     *   [data-gov-close]     -> dismiss, no action
     * Buttons the current phase does not support are simply absent —
     * there is no disabled-but-clickable "approve anyway" affordance.
     */
    function renderProposalHtml(proposal, state) {
      if (!proposal) {
        return `<div class="opbanner bad"><b>No proposal loaded.</b></div>`;
      }
      const p = proposal.proposal || {};
      const lines = explainer.explainGovernance(proposal) || [];
      const explainHtml = lines.map((l) => `<div class="hint" style="margin-top:0.15rem">${esc(l)}</div>`).join("");

      const approvals = proposal.approvals;
      let approvalsHtml = `<div class="hint">Approval status unavailable (this vault could not be loaded).</div>`;
      if (approvals) {
        const owner = `<div class="mono" style="font-size:0.78rem">Owner ${esc(shortId(approvals.owner))}: ${approvals.ownerApproved ? "APPROVED" : "not yet approved"}</div>`;
        const org = approvals.orgQuorum
          ? `<div class="mono" style="font-size:0.78rem">Organization quorum: ${esc(String(approvals.orgQuorum.collected))} of ${esc(String(approvals.orgQuorum.required))} required (${esc(String(approvals.orgQuorum.of))} configured)</div>`
          : `<div class="hint" style="font-size:0.78rem">No organization quorum configured — the owner's approval alone satisfies this proposal.</div>`;
        approvalsHtml = owner + org;
      }

      const statusBadge = `<span class="badge ${p_statusClass(proposal.status)}">${esc(proposal.status || "UNKNOWN")}</span>`;
      const integrity = proposal.integrity;
      const integrityWarn =
        integrity && (integrity.digestOk === false || integrity.classificationOk === false)
          ? `<div class="opbanner bad" style="margin-top:0.6rem"><b>INTEGRITY ALARM</b> — this proposal's stored content does not match its recorded digest or classification. Do not approve or retry; this indicates tampering or a serialization defect.</div>`
          : "";

      const actions = [];
      if (state.canApprove) actions.push(`<button class="primary" data-gov-approve="${esc(proposal.proposalId)}">Approve this proposal</button>`);
      else if (state.alreadyApproved) actions.push(`<span class="hint" style="display:inline">You already approved this proposal.</span>`);
      if (state.canRetry) actions.push(`<button class="primary" data-gov-retry="${esc(proposal.proposalId)}">Retry the original action</button>`);
      if (proposal.status === "OPEN") actions.push(`<button class="warn" data-gov-cancel="${esc(proposal.proposalId)}">Cancel proposal</button>`);
      actions.push(`<button data-gov-close="1">Close</button>`);

      return (
        `<div class="modal-card" style="max-width:640px;width:92%">` +
        `<h3 style="margin-top:0">Governance proposal ${statusBadge}</h3>` +
        `<div class="kv-line">Action <b>${esc(p.action || "?")}</b> · vault <span class="mono">${esc(shortId(p.vaultId))}</span> · proposal <span class="mono">${esc(shortId(proposal.proposalId))}</span></div>` +
        `<div class="kv-line">Created ${esc(proposal.createdAt || "—")} · expires ${esc(p.expiresAt || "—")}</div>` +
        integrityWarn +
        `<div style="margin-top:0.7rem">${explainHtml}</div>` +
        `<div style="margin-top:0.7rem">${approvalsHtml}</div>` +
        (proposal.lastConsumedTxId
          ? `<div class="hint" style="margin-top:0.4rem">Last consumed by tx <span class="mono">${esc(shortId(proposal.lastConsumedTxId))}</span></div>`
          : "") +
        `<div class="modal-actions">${actions.join("")}</div>` +
        `</div>`
      );
    }
    function p_statusClass(status) {
      if (status === "OPEN") return "ver";
      if (status === "CONSUMED") return "ACTIVE";
      return "PAUSED";
    }

    /* Compact card for a vault's open-proposals list (mirrors
     * web/app-v4.js's approvalRequestCard styling/shape). */
    function renderCompactCard(proposal) {
      const p = proposal.proposal || {};
      const approvals = proposal.approvals;
      const progress = approvals
        ? `owner ${approvals.ownerApproved ? "approved" : "pending"}${approvals.orgQuorum ? ` · quorum ${approvals.orgQuorum.collected}/${approvals.orgQuorum.required}` : ""}`
        : "approval status unavailable";
      return (
        `<div class="opbanner warn" data-govcard="${esc(proposal.proposalId)}">` +
        `<b>Governance proposal</b> — ${esc(p.action || "?")} · ${esc(progress)} · proposal ${esc(shortId(proposal.proposalId))} ` +
        `<button class="primary" data-govopen="${esc(proposal.proposalId)}">View &amp; act</button>` +
        `</div>`
      );
    }

    /* ---------------- network operations ---------------- */

    async function createProposalFor({ vaultId, action, params, expiresInMs }) {
      const body = { vaultId, action, params };
      if (expiresInMs !== undefined) body.expiresInMs = expiresInMs;
      const { proposal } = await api.postJSON("/governance/proposals", body);
      return proposal;
    }

    async function fetchProposal(proposalId) {
      const { proposal } = await api.getJSON(`/governance/proposals/${encodeURIComponent(proposalId)}`);
      return proposal;
    }

    async function fetchOpenProposals({ vaultId } = {}) {
      const qs = vaultId ? `?vaultId=${encodeURIComponent(vaultId)}` : "";
      const { proposals } = await api.getJSON(`/governance/proposals${qs}`);
      return (proposals || []).filter((p) => p && p.status === "OPEN");
    }

    /* Approve THROUGH the app's existing signer plumbing: the caller
     * supplies the session's `adapter` (web/signer-kasware-adapter.js's
     * createKasWareSessionAdapter, or any adapter implementing the same
     * legacy surface) — this function calls ONLY
     * adapter.signAuthMessage(message, {expectedSignerAddress, network}),
     * the SAME personal-message signing path web/app.js's hosted sign-in
     * already uses. It never constructs a second signing path and never
     * touches window.kasware. The message signed is the server's own
     * `proposal.approvalMessage` (server-reconstructed at every
     * verification, per server/src/governance.js approvalMessageText) —
     * never a client-composed string. */
    async function approve({ proposal, adapter, address, network }) {
      if (!proposal || typeof proposal.approvalMessage !== "string" || !proposal.approvalMessage) {
        throw Object.assign(new Error("this proposal carries no approval message (digest integrity failed) — refusing to sign"), {
          code: "GOVERNANCE_APPROVAL_MESSAGE_MISSING"
        });
      }
      if (!adapter || typeof adapter.signAuthMessage !== "function") {
        throw Object.assign(new Error("no connected wallet signer is available"), { code: "WALLET_NOT_READY" });
      }
      const signature = await adapter.signAuthMessage(proposal.approvalMessage, { expectedSignerAddress: address, network });
      const { proposal: updated } = await api.postJSON(`/governance/proposals/${encodeURIComponent(proposal.proposalId)}/approvals`, {
        approverAddress: address,
        signature
      });
      return updated;
    }

    async function cancelProposal(proposalId) {
      const { proposal } = await api.postJSON(`/governance/proposals/${encodeURIComponent(proposalId)}/cancel`, {});
      return proposal;
    }

    return {
      ceremonyState,
      renderProposalHtml,
      renderCompactCard,
      createProposalFor,
      fetchProposal,
      fetchOpenProposals,
      approve,
      cancelProposal
    };
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultGovernanceUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
