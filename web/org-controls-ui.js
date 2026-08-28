"use strict";

/*
 * Organization governance/risk CONTROLS editor UI (FULLSCALE addendum /
 * PostLaunchUpgradeOG completion-standard item 3): read and edit the
 * per-organization governance quorum/delay and risk-adapter
 * configuration via the CAS-versioned endpoint
 * (server/src/org-controls.js, GET/POST /organizations/:id/controls).
 *
 * METADATA PLANE ONLY (docs/postlaunch/governance-spec.md §2.1): this
 * record can ADD hosted workflow ceremony (extra governance approvers, a
 * delay window, restrictive risk adapters) and can NEVER subtract the
 * covenant's own requirements — the vault owner's approval remains
 * mandatory for every authority expansion, and break-glass owner actions
 * (ownerPause freeze, terminal ownerRecover) are never gated by any
 * configuration. This module edits hosted coordination, not covenant
 * authority; it grants nothing on its own.
 *
 * CAS discipline (mission item 3: "surface version conflicts as
 * reload-and-retry, never blind overwrite"): every save carries the
 * `expectedVersion` the form was loaded with. A 409 VERSION_CONFLICT
 * from the server is never retried with the stale edit — saveControls()
 * marks the error `versionConflict: true` so the caller can show
 * "reload and retry" and re-fetch fresh controls before the admin edits
 * again; this module performs no automatic merge or overwrite.
 *
 * Network calls are injected via `api`
 * ({ getJSON, postJSON, resolveXOnly }) so this module is unit-testable
 * headless, without fetch or a DOM. `resolveXOnly(address) -> xOnlyHex`
 * mirrors web/app-v4.js's existing private helper (POST
 * /identity/resolve-address) — reused here rather than duplicated so
 * every address the admin types goes through the ONE server address
 * boundary, exactly like every other form in this app.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  const XONLY_RE = /^[0-9a-f]{64}$/i;

  function formInvalid(message) {
    return Object.assign(new Error(message), { code: "CONTROLS_FORM_INVALID" });
  }

  function hoursToMs(h) {
    const s = String(h ?? "").trim();
    if (s === "") return 0;
    if (!/^[0-9]+(\.[0-9]+)?$/.test(s)) throw formInvalid("Delay window must be a non-negative number of hours.");
    const ms = Math.round(Number(s) * 3600000);
    if (!Number.isFinite(ms) || ms < 0) throw formInvalid("Delay window must be a non-negative number of hours.");
    return ms;
  }

  function msToHoursDisplay(ms) {
    if (!Number.isFinite(ms) || ms <= 0) return "0";
    const hours = ms / 3600000;
    return Number.isInteger(hours) ? String(hours) : String(Math.round(hours * 1000) / 1000);
  }

  function createModule({ api } = {}) {
    if (!api || typeof api.getJSON !== "function" || typeof api.postJSON !== "function" || typeof api.resolveXOnly !== "function") {
      throw new Error("org-controls-ui: createModule requires api.{getJSON,postJSON,resolveXOnly}");
    }

    /* ---------------- rendering (HTML fragment; no DOM access) ----------------
     * A single <form data-controls-form data-org-version="N"> the caller
     * wires: collect its field values on submit (see FIELD NAMES below),
     * call saveControls(orgId, values, {expectedVersion: N}).
     *
     * FIELD NAMES: approverAddresses (textarea, one wallet address OR
     * 64-hex x-only key per line), m (text), delayHours (text),
     * onAdapterError (select), onEmpty (select, "" = server default),
     * timeoutMs (text, "" = server default), reviewRequired (checkbox),
     * adaptersJson (textarea, JSON array).
     */
    function renderControlsFormHtml(controls) {
      const gov = (controls && controls.governance) || { quorum: null, delayMs: 0 };
      const risk = (controls && controls.risk) || { adapters: [], onAdapterError: "REVIEW", reviewRequired: false };
      const approverLines = (gov.quorum && Array.isArray(gov.quorum.approvers) ? gov.quorum.approvers : []).join("\n");
      const mVal = gov.quorum ? String(gov.quorum.m) : "";
      const delayHoursVal = msToHoursDisplay(gov.delayMs || 0);
      const adaptersJson = JSON.stringify((risk && risk.adapters) || [], null, 2);
      const version = controls && Number.isInteger(controls.version) ? controls.version : 0;
      const orgId = (controls && controls.orgId) || "";

      return (
        `<form class="cform" data-controls-form data-org-id="${esc(orgId)}" data-org-version="${esc(version)}">` +
        `<div class="full"><h4 style="margin:0.4rem 0">Governance ceremony</h4>` +
        `<div class="hint">The vault owner's approval is ALWAYS required for an authority-expansion policy change; these settings can only ADD organization ceremony on top of it — they can never remove the owner requirement, and break-glass owner actions (pause / terminal recover) are never gated by any configuration here.</div></div>` +
        `<div class="full"><label>Additional governance approvers (one wallet address or 64-hex x-only key per line — blank means owner-only governance)</label>` +
        `<textarea name="approverAddresses" rows="3" class="mono" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:0.45rem 0.6rem;font-size:0.8rem">${esc(approverLines)}</textarea></div>` +
        `<div><label>Required approvals (M) among the approvers above</label><input name="m" value="${esc(mVal)}" inputmode="numeric" /></div>` +
        `<div><label>Delay window (hours) before an approved proposal may execute</label><input name="delayHours" value="${esc(delayHoursVal)}" inputmode="decimal" /></div>` +
        `<div class="full"><h4 style="margin:0.8rem 0 0.4rem">Risk pipeline</h4>` +
        `<div class="hint">Restrictive-only: a risk ALLOW never authorizes anything — the covenant and the SDK's own policy checks remain independent and final (docs/postlaunch/risk-adapter-spec.md §5.3).</div></div>` +
        `<div><label>On adapter error / timeout</label><select name="onAdapterError">` +
        `<option value="REVIEW"${risk.onAdapterError !== "DENY" ? " selected" : ""}>REVIEW</option>` +
        `<option value="DENY"${risk.onAdapterError === "DENY" ? " selected" : ""}>DENY</option>` +
        `</select><div class="hint">Never ALLOW — an erroring control can never resolve permissive.</div></div>` +
        `<div><label>On empty adapter set</label><select name="onEmpty">` +
        `<option value="">(server default)</option>` +
        `<option value="ALLOW"${risk.onEmpty === "ALLOW" ? " selected" : ""}>ALLOW</option>` +
        `<option value="REVIEW"${risk.onEmpty === "REVIEW" ? " selected" : ""}>REVIEW</option>` +
        `<option value="DENY"${risk.onEmpty === "DENY" ? " selected" : ""}>DENY</option>` +
        `</select></div>` +
        `<div><label>Per-adapter timeout (ms)</label><input name="timeoutMs" value="${risk.timeoutMs !== undefined ? esc(risk.timeoutMs) : ""}" inputmode="numeric" placeholder="5000" /></div>` +
        `<div class="full"><label style="text-transform:none;display:flex;align-items:center;gap:0.4rem"><input type="checkbox" name="reviewRequired" style="width:auto"${risk.reviewRequired ? " checked" : ""} /> Require human review whenever no adapter allows outright (refuses onEmpty="ALLOW")</label></div>` +
        `<div class="full"><label>Adapters (JSON array of {type, name?, params?, timeoutMs?} — see docs/postlaunch/risk-adapter-spec.md §3)</label>` +
        `<textarea name="adaptersJson" rows="6" class="mono" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:0.45rem 0.6rem;font-size:0.76rem">${esc(adaptersJson)}</textarea></div>` +
        `<div class="full"><button type="submit" class="primary">Save controls</button> <span class="hint">version ${esc(version)} — a concurrent change is detected and never silently overwritten.</span></div>` +
        `</form>`
      );
    }

    /* ---------------- form values -> request body ----------------
     * `values` is the plain object of raw field strings the caller
     * collected from the DOM (see FIELD NAMES above). Client-side
     * validation here is UX convenience only — server/src/org-controls.js
     * normalizeControls() re-validates authoritatively and is the only
     * thing that can actually accept or refuse a save.
     */
    async function resolveApproverLine(line) {
      const t = line.trim();
      if (XONLY_RE.test(t)) return t.toLowerCase();
      return api.resolveXOnly(t);
    }

    async function buildControlsBody(values) {
      const approverLines = String(values.approverAddresses || "")
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      let governance;
      if (approverLines.length === 0) {
        governance = { delayMs: hoursToMs(values.delayHours) };
      } else {
        const approvers = [];
        for (const line of approverLines) {
          let x;
          try {
            x = await resolveApproverLine(line);
          } catch (e) {
            throw formInvalid(`Approver "${line}": ${e.message}`);
          }
          approvers.push(x);
        }
        const mRaw = String(values.m ?? "").trim();
        if (!/^[0-9]+$/.test(mRaw)) throw formInvalid("Required approvals (M) must be a whole number when approvers are configured.");
        const m = Number(mRaw);
        if (m < 1 || m > approvers.length) throw formInvalid(`Required approvals (M) must be between 1 and ${approvers.length}.`);
        governance = { quorum: { approvers, m }, delayMs: hoursToMs(values.delayHours) };
      }

      let adapters = [];
      const adaptersRaw = String(values.adaptersJson || "").trim();
      if (adaptersRaw) {
        let parsed;
        try {
          parsed = JSON.parse(adaptersRaw);
        } catch (e) {
          throw formInvalid(`Adapters JSON is invalid: ${e.message}`);
        }
        if (!Array.isArray(parsed)) throw formInvalid("Adapters JSON must be an array.");
        adapters = parsed;
      }
      const risk = { adapters, reviewRequired: !!values.reviewRequired };
      if (values.onAdapterError) risk.onAdapterError = values.onAdapterError;
      if (values.onEmpty) risk.onEmpty = values.onEmpty;
      const timeoutRaw = String(values.timeoutMs ?? "").trim();
      if (timeoutRaw) {
        if (!/^[0-9]+$/.test(timeoutRaw)) throw formInvalid("Per-adapter timeout must be a whole number of milliseconds.");
        risk.timeoutMs = Number(timeoutRaw);
      }
      return { governance, risk };
    }

    /* ---------------- network operations ---------------- */

    async function fetchControls(orgId) {
      const { controls } = await api.getJSON(`/organizations/${encodeURIComponent(orgId)}/controls`);
      return controls;
    }

    /* Save with expectedVersion CAS. On VERSION_CONFLICT the error is
     * marked `versionConflict: true` and thrown UNCHANGED — this
     * function never retries, merges, or force-overwrites; the caller is
     * expected to reload fresh controls and have the admin re-apply
     * their edit against the new version. */
    async function saveControls(orgId, values, { expectedVersion } = {}) {
      const body = await buildControlsBody(values);
      try {
        const { controls } = await api.postJSON(`/organizations/${encodeURIComponent(orgId)}/controls`, {
          governance: body.governance,
          risk: body.risk,
          expectedVersion
        });
        return controls;
      } catch (e) {
        if (e && e.code === "VERSION_CONFLICT") throw Object.assign(e, { versionConflict: true });
        throw e;
      }
    }

    return { renderControlsFormHtml, buildControlsBody, fetchControls, saveControls };
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultOrgControlsUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
