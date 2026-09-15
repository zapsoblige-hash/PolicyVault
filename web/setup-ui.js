"use strict";

/*
 * PolicyVault GUIDED SETUP components (owner UX directive 2026-09-05).
 *
 * WHAT THIS MODULE IS. A headless, DOM-free `createModule({ core })` factory
 * (same shape as web/org-root-ui.js / governance-ui.js) that renders the
 * SHARED building blocks of the Create-vault and Create-organizational-root
 * flows — and of the owner action forms that reuse them — as HTML strings,
 * and validates the DRAFTS those forms produce as plain objects:
 *
 *   - stepper + Back / Continue navigation
 *   - field + helper text + field-local error
 *   - human DURATION control (presets + custom number + unit) whose every
 *     conversion goes through core.durationDaa — never a UI-local constant
 *   - approval-count selector that reads "2 of 3 owners" and NEVER lowers a
 *     threshold on the user's behalf when a row is removed
 *   - repeatable address rows (name / wallet address / advanced public key)
 *   - review sections with Edit links, funding breakdown, live summary
 *   - vault-draft and root-draft validation
 *
 * `core` is window.PolicyVaultCore (web/core-bundle.js): amounts (the ONLY
 * KAS<->sompi parser) and durationDaa (the ONLY human-duration<->DAA path).
 * Every funds-relevant number is parsed by those two modules; nothing here
 * does arithmetic of its own.
 *
 * AUTHORITY BOUNDARY (unchanged): this module renders and pre-validates. The
 * server re-derives every value, the browser verifier re-checks the frozen
 * transaction, and the covenant on Kaspa enforces. A refusal here never has
 * an override; a pass here authorizes nothing.
 *
 * No fetch, no storage, no wallet call, no ambient state. Address resolution
 * is injected (`resolve(address) -> x-only`), so this file never decides what
 * an address means — the server's one address-identity boundary does.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  const HEX64_RE = /^[0-9a-f]{64}$/i;

  function fail(message, code, extra) {
    return Object.assign(new Error(message), { code, ...(extra || {}) });
  }

  /* Fixed helper sentences shared by every duration control / review. */
  const COPY = Object.freeze({
    MEASUREMENT: "Measured using Kaspa network progress, so the elapsed time is approximate.",
    UNITS: "1 day = 24 hours; 1 week = 7 days.",
    BUDGET_WINDOW: "Budget periods run back-to-back from the moment this policy starts (for example, every 24 hours from creation) — they are never aligned to midnight or to a calendar.",
    ROOT_RESET: "Any governance transaction on this root (an authorization, a change of owners or rules, a freeze, an unfreeze, a recovery, a succession) restarts the waiting period, because each one creates a new root output and the wait is counted from that output's age."
  });

  function createModule({ core } = {}) {
    if (!core || !core.amounts || typeof core.amounts.kasToSompi !== "function" || !core.durationDaa || typeof core.durationDaa.normalizeDurationSelection !== "function") {
      throw new Error("setup-ui: createModule requires the core bundle (core.amounts + core.durationDaa)");
    }
    const DUR = core.durationDaa;

    /* ---------- KAS parsing through the ONE canonical parser ---------- */
    function kasToSompi(kas) {
      try {
        return core.amounts.kasToSompi(String(kas ?? "").trim()).toString();
      } catch {
        return null;
      }
    }
    function sompiToKas(sompi) {
      return core.amounts.sompiToKas(BigInt(String(sompi)));
    }

    /* =================================================================
     * Rendering primitives
     * ================================================================= */

    function renderStepper({ steps, current }) {
      const items = steps.map((s, i) => {
        const state = i < current ? "done" : i === current ? "current" : "todo";
        return (
          `<li class="stepper-item ${state}" data-step="${esc(s.id)}"${state === "current" ? ' aria-current="step"' : ""}>` +
          `<span class="stepper-num" aria-hidden="true">${i + 1}</span><span class="stepper-label">${esc(s.label)}</span></li>`
        );
      }).join("");
      return `<ol class="stepper" aria-label="Setup steps">${items}</ol>` +
        `<div class="stepper-status" role="status" aria-live="polite" aria-atomic="true">Step ${current + 1} of ${steps.length}: ${esc(steps[current].label)}</div>`;
    }

    /* Back / Continue (or the final primary action) for one step. The
     * destructive/secondary Cancel is kept visually apart from the primary. */
    function renderNav({ index, total, finalLabel, cancelLabel, busy }) {
      const back = index > 0 ? `<button type="button" data-setup-back="1"${busy ? " disabled" : ""}>Back</button>` : `<span></span>`;
      const next = index < total - 1
        ? `<button type="button" class="primary" data-setup-next="1"${busy ? " disabled" : ""}>Continue</button>`
        : `<button type="submit" class="primary" data-setup-build="1"${busy ? " disabled" : ""}>${esc(finalLabel || "Review")}</button>`;
      return `<div class="setup-nav">${back}<span class="setup-nav-spacer"></span>${cancelLabel ? `<button type="button" class="quiet" data-setup-cancel="1">${esc(cancelLabel)}</button>` : ""}${next}</div>`;
    }

    function renderField({ id, name, label, control, help, error, optional, technical, wide }) {
      const fid = id || `f-${name}`;
      return (
        `<div class="f${wide ? " f-wide" : ""}${error ? " f-invalid" : ""}" data-field="${esc(name)}">` +
        `<label class="f-label" for="${esc(fid)}">${esc(label)}${optional ? ` <span class="f-opt">(optional)</span>` : ""}</label>` +
        control +
        (help ? `<div class="f-help" id="${esc(fid)}-help">${help}</div>` : "") +
        `<div class="ferr" data-err="${esc(name)}"${error ? ' style="display:block"' : ""}>${esc(error || "")}</div>` +
        (technical ? `<details class="adv f-tech"><summary>Technical detail</summary><div class="f-help">${technical}</div></details>` : "") +
        `</div>`
      );
    }

    function textInput({ id, name, value, placeholder, inputmode, mono, autocomplete, ariaLabel, maxlength, readonly }) {
      const fid = id || `f-${name}`;
      return `<input id="${esc(fid)}" name="${esc(name)}" value="${esc(value ?? "")}"${placeholder ? ` placeholder="${esc(placeholder)}"` : ""}` +
        `${inputmode ? ` inputmode="${esc(inputmode)}"` : ""}${mono ? ' class="mono"' : ""} autocomplete="${esc(autocomplete || "off")}"` +
        `${ariaLabel ? ` aria-label="${esc(ariaLabel)}"` : ""}${maxlength ? ` maxlength="${Number(maxlength)}"` : ""}${readonly ? " readonly" : ""} aria-describedby="${esc(fid)}-help" />`;
    }

    function kasInput({ id, name, value, placeholder }) {
      const fid = id || `f-${name}`;
      return `<div class="f-unit-wrap"><input id="${esc(fid)}" name="${esc(name)}" value="${esc(value ?? "")}"${placeholder ? ` placeholder="${esc(placeholder)}"` : ""} inputmode="decimal" autocomplete="off" aria-describedby="${esc(fid)}-help" /><span class="f-unit" aria-hidden="true">KAS</span></div>`;
    }

    function select({ id, name, options, value, disabled, ariaLabel }) {
      const fid = id || `f-${name}`;
      const opts = options.map((o) => `<option value="${esc(o.value)}"${String(o.value) === String(value) ? " selected" : ""}${o.disabled ? " disabled" : ""}>${esc(o.label)}</option>`).join("");
      return `<select id="${esc(fid)}" name="${esc(name)}"${disabled ? " disabled" : ""}${ariaLabel ? ` aria-label="${esc(ariaLabel)}"` : ""} aria-describedby="${esc(fid)}-help">${opts}</select>`;
    }

    function checkbox({ id, name, checked, label }) {
      const fid = id || `f-${name}`;
      return `<label class="f-check" for="${esc(fid)}"><input type="checkbox" id="${esc(fid)}" name="${esc(name)}" value="1"${checked ? " checked" : ""} /> <span>${esc(label)}</span></label>`;
    }

    /* =================================================================
     * DURATION control — presets + custom, ONE conversion path
     * ================================================================= */

    /*
     * selection: { preset: "1d" | "custom" | "existing", customValue, customUnit, existingDaa }
     * The "existing" option appears ONLY when an existing exact value was
     * supplied (re-policy of a live agent, an imported delay): it round-trips
     * the exact DAA score UNCHANGED until the user deliberately picks
     * something else.
     */
    function renderDurationControl({ name, setting, selection, id, allowExactDaa = false }) {
      const sel = selection || {};
      const fid = id || `f-${name}`;
      const existing = sel.existingDaa !== undefined && sel.existingDaa !== null && String(sel.existingDaa) !== "";
      let existingDesc = null;
      if (existing) {
        try { existingDesc = DUR.normalizeDurationSelection(setting, { mode: "existing", daa: sel.existingDaa }); } catch { existingDesc = null; }
      }
      const current = sel.preset || (existing ? "existing" : setting.defaultPreset);
      const options = [];
      if (existing) {
        options.push({ value: "existing", label: existingDesc ? `Keep current value (${existingDesc.describe.text}${existingDesc.preset ? "" : ", exact"})` : "Keep current value" });
      }
      for (const p of setting.presets) options.push({ value: p.key, label: allowExactDaa ? `${p.label} (approx.)` : p.label });
      options.push({ value: "custom", label: "Custom…" });
      const units = ["hour", "day", "week"].map((u) => ({ value: u, label: u === "hour" ? "hours" : u === "day" ? "days" : "weeks" }));
      if (allowExactDaa) units.push({ value: "daa", label: "DAA score (exact)" });
      const showCustom = current === "custom";
      return (
        `<div class="duration" data-duration="${esc(name)}">` +
        select({ id: fid, name, options, value: current, ariaLabel: setting.label }) +
        `<div class="duration-custom" data-duration-custom="${esc(name)}"${showCustom ? "" : " hidden"}>` +
        `<input id="${esc(fid)}-value" name="${esc(name)}Value" value="${esc(sel.customValue ?? "")}" inputmode="numeric" placeholder="e.g. 3" aria-label="${esc(setting.label)} — number" autocomplete="off" />` +
        select({ id: `${fid}-unit`, name: `${name}Unit`, options: units, value: sel.customUnit || (setting.largestUnit === "week" ? "day" : "day"), ariaLabel: `${setting.label} — unit` }) +
        `</div>` +
        `<div class="f-help duration-effect" data-duration-effect="${esc(name)}" aria-live="polite">${esc(durationEffectText(setting, sel, { allowExactDaa }))}</div>` +
        `<details class="adv f-tech"><summary>Technical detail</summary><div class="f-help" data-duration-exact="${esc(name)}">${esc(durationExactText(setting, sel, { allowExactDaa }))}</div></details>` +
        `</div>`
      );
    }

    /* The exact protocol value — shown only under "Technical detail". */
    function durationExactText(setting, raw, options) {
      try {
        const n = readDurationSelection(setting, raw, options);
        const flags = [];
        if (n.source === "existing") flags.push("current value kept unchanged");
        if (n.outOfProductRange) flags.push(options && options.allowExactDaa ? "outside the hours/days/weeks input range" : "outside the range this app offers for new policies");
        if (!n.exact) flags.push(`not a whole number of seconds (${n.describe.exactText})`);
        return `Exactly ${n.daa} DAA score (10 DAA per second; 1 day = 864000)${flags.length ? "; " + flags.join("; ") : ""}.`;
      } catch {
        return "No exact value yet — choose a preset or enter a whole number.";
      }
    }

    /* The raw selection read back from a form -> normalized (throws with .code). */
    function readDurationSelection(setting, raw, { allowExactDaa = false } = {}) {
      const r = raw || {};
      const preset = r.preset || (r.existingDaa !== undefined && r.existingDaa !== null && String(r.existingDaa) !== "" ? "existing" : setting.defaultPreset);
      if (preset === "existing") return DUR.normalizeDurationSelection(setting, { mode: "existing", daa: r.existingDaa });
      if (preset === "custom") {
        // Treasury forms already accept exact positive protocol values. Use
        // the same core encoding checks without imposing the human-unit range
        // or claiming a newly entered value is an unchanged existing policy.
        if (allowExactDaa && r.customUnit === "daa") {
          const n = DUR.normalizeDurationSelection(setting, { mode: "existing", daa: r.customValue });
          return Object.freeze({ ...n, source: "custom-exact" });
        }
        return DUR.normalizeDurationSelection(setting, { mode: "custom", value: r.customValue, unit: r.customUnit });
      }
      return DUR.normalizeDurationSelection(setting, { mode: "preset", preset });
    }

    /* Live effect line under the control: "about 1 day · exact 864000 DAA …" */
    function durationEffectText(setting, raw, options) {
      let n;
      try {
        n = readDurationSelection(setting, raw, options);
      } catch (e) {
        if ((raw || {}).preset === "custom" && !String((raw || {}).customValue ?? "").trim()) return `Enter a whole number of ${options && options.allowExactDaa ? "hours, days, weeks, or exact DAA score" : "hours, days, or weeks"}. ${COPY.UNITS} ${COPY.MEASUREMENT}`;
        return `${e.message.replace(/^duration-daa: /, "")} ${COPY.UNITS}`;
      }
      const flags = [];
      if (n.source === "existing") flags.push("current value kept unchanged");
      if (n.outOfProductRange) flags.push(options && options.allowExactDaa ? "outside the hours/days/weeks input range" : "outside the range this app offers for new policies");
      return `${n.describe.text.replace(/^about/, "About")}${flags.length ? " (" + flags.join("; ") + ")" : ""}. ${COPY.MEASUREMENT}`;
    }

    /* =================================================================
     * APPROVAL COUNT — "k of N owners"; never auto-lowered
     * ================================================================= */

    function approvalOptions(count, noun, { min = 1, max } = {}) {
      const top = max === undefined ? count : Math.min(count, max);
      const out = [];
      for (let k = min; k <= top; k++) out.push({ value: String(k), label: `${k} of ${count} ${noun}` });
      return out;
    }

    /*
     * Preserve-and-flag rule: when owners change and the selected value no
     * longer fits, the draft KEEPS the impossible value and the caller must
     * show `message` — the threshold is never silently lowered (or raised).
     */
    function thresholdCheck({ count, value, noun, min = 1, max, label }) {
      const s = String(value ?? "").trim();
      if (!/^[0-9]+$/.test(s)) return { ok: false, message: `${label}: choose how many ${noun}.` };
      const k = Number(s);
      const top = max === undefined ? count : Math.min(count, max);
      if (count < 1) return { ok: false, message: `${label}: add at least one ${noun.replace(/s$/, "")} first.` };
      if (k < min) return { ok: false, message: `${label}: must be at least ${min}.` };
      if (k > top) return { ok: false, message: `${label}: ${k} of ${count} is impossible — you now have ${count} ${noun}. Choose a new number (it was not changed for you).` };
      return { ok: true, message: "" };
    }

    function renderApprovalSelect({ id, name, count, value, noun, min = 1, max }) {
      const options = approvalOptions(count, noun, { min, max });
      const s = String(value ?? "");
      if (s && !options.some((o) => o.value === s)) {
        options.unshift({ value: s, label: `${s} of ${count} ${noun} — impossible, choose again`, disabled: false });
      }
      if (options.length === 0) options.push({ value: "", label: `add ${noun} first`, disabled: true });
      return select({ id, name, options, value: s || (options[0] && options[0].value), ariaLabel: `${name}` });
    }

    /* =================================================================
     * ADDRESS ROWS — name (optional) / wallet address / advanced key
     * ================================================================= */

    /*
     * rows: [{ address, label, publicKey }]. `allowKey` adds the advanced
     * public-key entry (owners only). `errors` maps row index -> message.
     * A new row is always blank by construction. Labels are rendered as TEXT.
     */
    function renderAddressRows({ kind, rows, withLabel, allowKey, errors, addLabel, placeholder, min = 1, max, connectedAddress, useConnectedLabel, rowLabel = kind, addressLabel = "wallet address" }) {
      /* An OPTIONAL list (min 0, e.g. payment approvers) renders no row until
       * the user adds one — a blank row would read as a required entry. A
       * required list always shows at least one (blank) row. */
      const list = (rows && rows.length ? rows : min === 0 ? [] : [{ address: "", label: "", publicKey: "" }]).map((r, i) => {
        const err = errors && errors[i];
        const keyMode = !!(r && (r.keyMode === true || (r.publicKey && String(r.publicKey).trim())));
        return (
          `<div class="addr-row${err ? " f-invalid" : ""}" data-row="${i}">` +
          (withLabel ? `<input name="${esc(kind)}Label" value="${esc(r.label ?? "")}" placeholder="Name (optional)" aria-label="${esc(kind)} ${i + 1} name" autocomplete="off" class="addr-name" />` : "") +
          `<input name="${esc(kind)}" value="${esc(keyMode ? "" : r.address ?? "")}" placeholder="${esc(placeholder || "kaspa:…")}" aria-label="${esc(rowLabel)} ${i + 1} ${esc(addressLabel)}" autocomplete="off" class="mono addr-addr"${keyMode ? " hidden" : ""} />` +
          (allowKey ? `<input name="${esc(kind)}Key" value="${esc(r.publicKey ?? "")}" placeholder="64-hex public key" aria-label="${esc(kind)} ${i + 1} public key" autocomplete="off" class="mono addr-key"${keyMode ? "" : " hidden"} />` : "") +
          `<button type="button" class="rm-${esc(kind)} quiet" aria-label="Remove ${esc(rowLabel)} ${i + 1}">Remove</button>` +
          (allowKey ? `<button type="button" class="quiet addr-keytoggle" data-keytoggle="${i}" aria-label="${keyMode ? "Use a wallet address instead" : "Use a public key instead"}">${keyMode ? "Use address" : "Use public key"}</button>` : "") +
          (err ? `<div class="ferr" style="display:block;flex-basis:100%;min-width:0;overflow-wrap:anywhere">${esc(err)}</div>` : "") +
          `</div>`
        );
      }).join("");
      const count = rows && rows.length ? rows.length : min === 0 ? 0 : 1;
      const addDisabled = max !== undefined && count >= max;
      return (
        `<div class="addr-rows" data-rows="${esc(kind)}" data-min="${min}"${max !== undefined ? ` data-max="${max}"` : ""}>${list}</div>` +
        `<div class="addr-actions">` +
        `<button type="button" id="v4-add-${esc(kind)}" class="quiet"${addDisabled ? ` disabled title="Maximum of ${max} reached"` : ""}>+ ${esc(addLabel || `Add ${kind}`)}</button>` +
        (connectedAddress ? ` <button type="button" class="quiet" data-use-connected="${esc(kind)}">${esc(useConnectedLabel || "Use connected wallet")}</button>` : "") +
        `</div>`
      );
    }

    /* =================================================================
     * REVIEW blocks
     * ================================================================= */

    /* A review value is TEXT (escaped) unless explicitly marked as
     * already-safe HTML with html(...) — a user-typed value can never be
     * interpreted as markup by accident. */
    const html = (safeHtml) => ({ html: String(safeHtml) });
    const isHtml = (v) => !!(v && typeof v === "object" && typeof v.html === "string");
    function renderReviewSection({ title, editStep, rows, note, id }) {
      const body = rows.map(([k, v, cls]) => `<div class="rv-row"><div class="rv-k">${esc(k)}</div><div class="rv-v${cls ? ` ${cls}` : ""}">${isHtml(v) ? v.html : esc(v)}</div></div>`).join("");
      return (
        `<section class="review-sec"${id ? ` id="${esc(id)}"` : ""}>` +
        `<div class="review-head"><h4>${esc(title)}</h4>${editStep !== undefined ? `<button type="button" class="quiet" data-edit-step="${esc(String(editStep))}">Edit</button>` : ""}</div>` +
        body + (note ? `<div class="f-help">${note}</div>` : "") +
        `</section>`
      );
    }

    /* rows: [{ label, kas, note }], total: { label, kas } */
    function renderFundingBreakdown({ title, rows, total, note }) {
      const lines = rows.map((r) => `<div class="fund-row${r.emphasis ? " fund-emph" : ""}"><span>${esc(r.label)}${r.note ? ` <span class="f-help" style="display:inline">${esc(r.note)}</span>` : ""}</span><span class="mono">${esc(r.kas)} KAS</span></div>`).join("");
      return (
        `<div class="funding" data-funding="1"><h4>${esc(title || "Funding breakdown")}</h4>${lines}` +
        (total ? `<div class="fund-row fund-total"><span>${esc(total.label)}</span><span class="mono">${esc(total.kas)} KAS</span></div>` : "") +
        (note ? `<div class="f-help">${note}</div>` : "") + `</div>`
      );
    }

    function renderLiveSummary(sentences, id) {
      const items = (sentences || []).filter(Boolean).map((s) => `<li>${esc(s)}</li>`).join("");
      return `<div class="live-summary" ${id ? `id="${esc(id)}" ` : ""}data-live-summary="1" aria-live="polite"><div class="live-title">What you are setting up</div>${items ? `<ul>${items}</ul>` : `<div class="f-help">Fill in the fields above to see a summary.</div>`}</div>`;
    }

    /* =================================================================
     * VAULT DRAFT (protocol v0.4.1)
     * ================================================================= */

    const BUDGET_SETTING = DUR.durationSettingFor("budgetPeriod", "policyvault-0.4.1");

    const CREATION_MAX_FEE_DEFAULT_SOMPI = "100000000"; // 1 KAS — the browser verifier's default creation fee limit (UX-12)
    const MAX_APPROVER_ROWS = 10; // frozen v0.4/v0.4.1 consensus model: exactly 10 approver slots

    function vaultDraftDefaults() {
      return {
        label: "", deposit: "", reserve: "",
        agent: "", recipients: [{ address: "" }],
        maxPerSpend: "", budget: "", period: { preset: BUDGET_SETTING.defaultPreset, customValue: "", customUnit: "day" },
        approvalThreshold: "", approvers: [], approvalM: "",
        maxFee: "",
        creationMaxFee: ""
      };
    }

    /* Plain-language sentences for the live summary (best effort; no parsing failures shown). */
    function vaultRulesSummary(d) {
      const out = [];
      const kasOk = (v) => kasToSompi(v) !== null && BigInt(kasToSompi(v)) > 0n;
      if (d.agent) out.push(`Agent ${d.agent} may pay only the ${d.recipients.filter((r) => r.address && r.address.trim()).length || "listed"} allowed recipient wallet(s).`);
      if (kasOk(d.maxPerSpend)) out.push(`No single payment may exceed ${String(d.maxPerSpend).trim()} KAS.`);
      if (kasOk(d.budget)) {
        let per = "";
        try { per = readDurationSelection(BUDGET_SETTING, d.period).describe.text; } catch { per = "the budget period"; }
        out.push(`Payments may total at most ${String(d.budget).trim()} KAS per ${per.replace(/^about /, "")} (approximate; back-to-back periods from creation).`);
      }
      const thr = kasToSompi(d.approvalThreshold);
      const n = d.approvers.filter((r) => r.address && r.address.trim()).length;
      if (thr !== null) {
        if (n > 0 && /^[0-9]+$/.test(String(d.approvalM))) out.push(`Payments above ${String(d.approvalThreshold).trim()} KAS need ${d.approvalM} of ${n} approvers to sign first; at or below, the agent signs alone.`);
        else if (n === 0 && BigInt(thr) === 0n) out.push("Every payment would need extra approval, but no approvers are configured — the agent could not pay at all. Add approvers or raise the threshold.");
        else if (n === 0) out.push(`Payments above ${String(d.approvalThreshold).trim()} KAS would need extra approval, but no approvers are configured — such payments will be refused until approvers are set.`);
      }
      if (kasOk(d.deposit)) out.push(`The vault will hold ${String(d.deposit).trim()} KAS for the agent to spend under these rules${kasToSompi(d.reserve) !== null ? ` plus a ${String(d.reserve).trim()} KAS fee reserve` : ""}.`);
      return out;
    }

    /*
     * Validate a vault draft. `resolve(address)` -> x-only (throws on a bad
     * address: wrong network / checksum / unsupported type — the server's ONE
     * address-identity boundary). Returns { ok, errors: Map(field->message),
     * body (the exact POST /wallet/v4/create body), context (browser-local
     * genesis verification context), normalized }.
     */
    async function validateVaultDraft(d, { resolve, signerAddress, vaultId, step, existingApprovers } = {}) {
      const errors = new Map();
      const bad = (key, message) => { if (!errors.has(key)) errors.set(key, message); };
      const v = (x) => String(x ?? "").trim();
      const only = (s) => step === undefined || step === s; // validate one step or everything

      // ---- step 0: basics ----
      const label = v(d.label);
      if (only("basics")) {
        if (!label) bad("label", "Give the vault a name.");
        else if (label.length > 120) bad("label", "The name is too long (120 characters at most).");
      }

      // ---- step 1: agent + recipients ----
      const cache = new Map();
      const resolveCached = async (addr) => {
        if (!cache.has(addr)) {
          try { cache.set(addr, { x: await resolve(addr) }); }
          catch (err) { cache.set(addr, { err: (err && err.message) || "invalid address" }); }
        }
        return cache.get(addr);
      };
      let agentXOnly = null;
      const agentAddr = v(d.agent);
      const recipientAddresses = [];
      const recipientXOnlys = [];
      if (only("agent")) {
        if (!agentAddr) bad("agent", "Enter the agent's wallet address.");
        else {
          const r = await resolveCached(agentAddr);
          if (r.err) bad("agent", `Agent address rejected: ${r.err}`);
          else agentXOnly = r.x;
        }
        const rows = Array.isArray(d.recipients) ? d.recipients : [];
        const msgs = [];
        const rowErrors = {};
        const seen = new Map();
        for (let i = 0; i < rows.length; i++) {
          const a = v(rows[i] && rows[i].address);
          if (!a) {
            if (rows.length > 1) { rowErrors[i] = "Enter an address or remove this row."; }
            continue;
          }
          if (seen.has(a)) { rowErrors[i] = `Same as recipient ${seen.get(a) + 1}.`; continue; }
          seen.set(a, i);
          const r = await resolveCached(a);
          if (r.err) { rowErrors[i] = r.err; continue; }
          recipientAddresses.push(a);
          recipientXOnlys.push(r.x);
        }
        if (Object.keys(rowErrors).length) { msgs.push("Fix the highlighted recipient rows."); errors.set("recipientRows", rowErrors); }
        if (!Object.keys(rowErrors).length && recipientAddresses.length === 0) msgs.push("Add at least one allowed recipient wallet.");
        if (msgs.length) bad("recipients", msgs.join(" "));
      }

      // ---- step 2: spending rules ----
      const maxPerSpend = kasToSompi(v(d.maxPerSpend));
      const budget = kasToSompi(v(d.budget));
      const threshold = kasToSompi(v(d.approvalThreshold));
      let periodNorm = null;
      const approverAddresses = [];
      const approverXOnlys = [];
      let approvalM = "0";
      if (only("rules")) {
        if (maxPerSpend === null || BigInt(maxPerSpend) <= 0n) bad("maxPerSpend", "Enter the maximum per payment: a KAS amount greater than 0 (up to 8 decimals).");
        if (budget === null || BigInt(budget) <= 0n) bad("budget", "Enter the spending budget: a KAS amount greater than 0.");
        else if (maxPerSpend !== null && BigInt(budget) < BigInt(maxPerSpend)) bad("budget", "The spending budget must be at least the maximum per payment.");
        try { periodNorm = readDurationSelection(BUDGET_SETTING, d.period); }
        catch (e) { bad("period", e.message.replace(/^duration-daa: /, "")); }
        if (threshold === null) bad("approvalThreshold", "Enter the amount above which payments need extra approval (0 means every payment needs approval).");
        // UX-04 (Codex checkpoint 2): an agent change on an EXISTING vault is
        // validated against the vault's ACTUAL approver configuration (which
        // the change does not touch), never against an empty draft list.
        if (existingApprovers && typeof existingApprovers === "object") {
          const count = Number(existingApprovers.count || 0);
          if (threshold !== null && BigInt(threshold) === 0n && count === 0) bad("approvalThreshold", "This vault has no payment approvers, so a threshold of 0 KAS would make every payment impossible. Raise the threshold, or set payment approvers first.");
          approvalM = String(Number(existingApprovers.approvalM || 0));
        }
        const rows = existingApprovers ? [] : (Array.isArray(d.approvers) ? d.approvers : []);
        const rowErrors = {};
        const seenAddr = new Map();
        const seenX = new Map();
        if (rows.length > MAX_APPROVER_ROWS) bad("approvers", `At most ${MAX_APPROVER_ROWS} approvers are supported by this vault type.`);
        for (let i = 0; i < rows.length; i++) {
          const a = v(rows[i] && rows[i].address);
          if (!a) { rowErrors[i] = "Enter an address or remove this row."; continue; }
          if (seenAddr.has(a)) { rowErrors[i] = `Same wallet as approver ${seenAddr.get(a) + 1}.`; continue; }
          seenAddr.set(a, i);
          const r = await resolveCached(a);
          if (r.err) { rowErrors[i] = r.err; continue; }
          if (seenX.has(r.x)) { rowErrors[i] = `Same signing identity as approver ${seenX.get(r.x) + 1} (a different address form of the same key).`; continue; }
          seenX.set(r.x, i);
          approverAddresses.push(a);
          approverXOnlys.push(r.x);
        }
        if (Object.keys(rowErrors).length) { bad("approvers", "Fix the highlighted approver rows."); errors.set("approverRows", rowErrors); }
        const configured = approverAddresses.length;
        if (existingApprovers) {
          /* rows are not edited by an agent change; the checks above used the vault's real configuration */
        } else if (rows.length === 0) {
          const m = v(d.approvalM);
          if (m && m !== "0") bad("approvalM", "Add approver rows first, or leave the approval count empty.");
          if (threshold !== null && BigInt(threshold) === 0n) bad("approvalThreshold", "With no approvers, a threshold of 0 KAS would make every payment impossible. Raise the threshold or add approvers.");
        } else {
          const t = thresholdCheck({ count: configured, value: d.approvalM, noun: "approvers", label: "Approvals needed", max: MAX_APPROVER_ROWS });
          if (!errors.has("approvers") && !t.ok) bad("approvalM", t.message);
          else if (t.ok) approvalM = String(Number(v(d.approvalM)));
        }
      }

      // ---- step 3: funding ----
      const deposit = kasToSompi(v(d.deposit));
      const reserve = kasToSompi(v(d.reserve));
      const maxFee = v(d.maxFee);
      // UX-12: the creation-transaction fee LIMIT is a separate control from
      // the agent's per-payment fee cap (a policy the covenant enforces on
      // every agent payment). Default 1 KAS = the browser verifier's default.
      const creationMaxFee = v(d.creationMaxFee);
      if (only("funding")) {
        if (deposit === null || BigInt(deposit) <= 0n) bad("deposit", "Enter a deposit greater than 0 KAS.");
        if (reserve === null) bad("reserve", "Enter a fee reserve of 0 KAS or more.");
        if (maxFee && (kasToSompi(maxFee) === null || BigInt(kasToSompi(maxFee)) <= 0n)) bad("maxFee", "The maximum network fee per payment must be a positive KAS amount.");
        if (creationMaxFee && (kasToSompi(creationMaxFee) === null || BigInt(kasToSompi(creationMaxFee)) <= 0n)) bad("creationMaxFee", "The network fee limit for creating the vault must be a positive KAS amount.");
      }

      if (errors.size || step !== undefined) return { ok: errors.size === 0, errors, body: null, context: null, normalized: null };

      /* HUMAN INTENT travels to the server — a preset key or { value, unit } —
       * and the SERVER derives periodLengthDaa through the SAME core module
       * (sdk/src/ux-normalize-v4.js). The browser's conversion above is
       * display + pre-validation only: a consensus-visible value is never
       * browser-supplied on this path (H2 §17 security property, kept). */
      const budgetPeriod = periodNorm.source === "preset" ? periodNorm.preset : { value: String(d.period.customValue ?? "").trim(), unit: String(d.period.customUnit ?? "").trim() };
      const body = {
        contractVersion: "policyvault-0.4.1",
        signerAddress,
        vaultId,
        label,
        depositKas: v(d.deposit),
        feeReserveKas: v(d.reserve),
        agent: {
          agentAddress: agentAddr,
          maxPerSpendKas: v(d.maxPerSpend),
          budgetKas: v(d.budget),
          budgetPeriod,
          approvalThresholdKas: v(d.approvalThreshold),
          ...(maxFee ? { maxFeePerTxKas: maxFee } : {}),
          recipientAddresses
        }
      };
      if (approverAddresses.length) body.approvers = { addresses: approverAddresses, approvalM };
      const context = {
        vaultId,
        depositKas: v(d.deposit),
        feeReserveKas: v(d.reserve),
        approvalM: approverAddresses.length ? approvalM : "0",
        approverXOnlys,
        agentXOnly,
        agentMaxPerSpendKas: v(d.maxPerSpend),
        agentBudgetKas: v(d.budget),
        agentApprovalThresholdKas: v(d.approvalThreshold),
        // UX-01: the EXACT period this browser normalized through the one
        // core path — the verifier binds the committed policy leaf to it.
        agentPeriodLengthDaa: periodNorm.daa,
        ...(maxFee ? { agentMaxFeePerTxKas: maxFee } : {}),
        agentRecipientXOnlys: recipientXOnlys,
        // UX-12: the CREATION fee limit (never the agent's per-payment cap)
        maxFeeSompi: creationMaxFee ? kasToSompi(creationMaxFee) : CREATION_MAX_FEE_DEFAULT_SOMPI
      };
      const normalized = {
        label, agentAddr, agentXOnly, recipientAddresses, recipientXOnlys,
        maxPerSpendKas: v(d.maxPerSpend), budgetKas: v(d.budget), period: periodNorm,
        approvalThresholdKas: v(d.approvalThreshold), approverAddresses, approverXOnlys, approvalM,
        depositKas: v(d.deposit), reserveKas: v(d.reserve), maxFeeKas: maxFee || null,
        creationMaxFeeKas: creationMaxFee || null
      };
      return { ok: true, errors, body, context, normalized };
    }

    /* Review rows for the vault draft (the intent the server will build from). */
    function vaultReviewRows(n) {
      const approvals = n.approverAddresses.length
        ? [`${n.approvalM} of ${n.approverAddresses.length} approvers must sign a payment above ${n.approvalThresholdKas} KAS`, ...n.approverAddresses.map((a) => `<span class="mono">${esc(a)}</span>`)]
        : [`No payment approvers: every payment must be at or below ${n.approvalThresholdKas} KAS (payments above it are refused)`];
      return {
        basics: [["Vault name", n.label], ["Protocol", "PolicyVault v0.4.1 — single owner key (the connected wallet)"]],
        agent: [["Agent wallet", html(`<span class="mono">${esc(n.agentAddr)}</span>`)], ["Allowed recipients", html(n.recipientAddresses.map((a) => `<span class="mono">${esc(a)}</span>`).join("<br/>"))]],
        rules: [
          ["Maximum per payment", `${n.maxPerSpendKas} KAS`],
          ["Spending budget", `${n.budgetKas} KAS per ${n.period.describe.text.replace(/^about /, "")} (approximate)`],
          ["Budget period", html(`${esc(n.period.describe.text)}<details class="adv f-tech"><summary>Technical detail</summary>exactly ${esc(n.period.daa)} DAA score</details>`)],
          ["Payments needing extra approval", `above ${n.approvalThresholdKas} KAS`],
          ["Approvals", html(approvals.join("<br/>"))],
          ...(n.maxFeeKas ? [["Maximum network fee per payment", `${n.maxFeeKas} KAS`]] : [["Maximum network fee per payment", "0.10 KAS (default)"]])
        ],
        funding: [["Deposit (protected)", `${n.depositKas} KAS`], ["Fee reserve", `${n.reserveKas} KAS`], ["Network fee limit for creating the vault", n.creationMaxFeeKas ? `${n.creationMaxFeeKas} KAS` : "1 KAS (default)"]]
      };
    }

    /* =================================================================
     * ROOT DRAFT (protocol v0.7-root: the on-chain organizational root whose owners approve changes together)
     * ================================================================= */

    const RECOVERY_SETTING = DUR.durationSettingFor("rootRecoveryDelay", "policyvault-0.7-root");
    const SUCCESSION_SETTING = DUR.durationSettingFor("rootSuccessionDelay", "policyvault-0.7-root");
    const OWNER_SLOTS = 12;

    function rootDraftDefaults(connectedAddress) {
      return {
        label: "",
        owners: [{ address: connectedAddress || "", label: "", publicKey: "" }],
        ownerM: "1",
        emergencyK: "1",
        recoveryEnabled: false,
        recoveryM: "1",
        recoveryDelay: { preset: RECOVERY_SETTING.defaultPreset, customValue: "", customUnit: "day" },
        successionEnabled: false,
        successorAddress: "",
        successionDelay: { preset: SUCCESSION_SETTING.defaultPreset, customValue: "", customUnit: "day" },
        rootValueKas: "1",
        rootMaxFeePerTxKas: "0.001",
        signerAddress: connectedAddress || ""
      };
    }

    function activeOwnerRows(d) {
      return (Array.isArray(d.owners) ? d.owners : []).filter((r) => r && ((r.address && String(r.address).trim()) || (r.publicKey && String(r.publicKey).trim())));
    }

    /* Plain-language sentences for the live summary of the root rules. */
    function rootRulesSummary(d) {
      const n = activeOwnerRows(d).length;
      const out = [];
      if (n === 0) return ["Add at least one owner."];
      const m = /^[0-9]+$/.test(String(d.ownerM)) ? Number(d.ownerM) : null;
      const k = /^[0-9]+$/.test(String(d.emergencyK)) ? Number(d.emergencyK) : null;
      out.push(`${n} owner${n === 1 ? "" : "s"} hold this organization's on-chain governance.`);
      if (m) out.push(`Any ${m} of the ${n} owner${n === 1 ? "" : "s"} must sign to approve a change or a vault owner operation.`);
      if (k) out.push(`Any ${k} owner${k === 1 ? "" : "s"} can freeze governance in an emergency; ${m || "the approval quorum (M)"} of ${n} must sign to unfreeze. A freeze does not stop agent payments.`);
      if (d.recoveryEnabled) {
        const r = /^[0-9]+$/.test(String(d.recoveryM)) ? Number(d.recoveryM) : null;
        let wait = "the recovery waiting period";
        try { wait = readDurationSelection(RECOVERY_SETTING, d.recoveryDelay).describe.text; } catch { /* shown in the field error */ }
        out.push(`If the root is left untouched for ${wait}, any ${r || "?"} of the owners can recover control (the root then lands frozen).`);
      } else {
        out.push(d.successionEnabled && String(d.successorAddress || "").trim() ? "Recovery is off: if too many owner keys are lost, only the designated successor can regain control (after its waiting period)." : "Recovery is off: if too many owner keys are lost, nobody can regain control of this organization's vaults.");
      }
      if (d.successionEnabled && String(d.successorAddress || "").trim()) {
        let wait = "the successor waiting period";
        try { wait = readDurationSelection(SUCCESSION_SETTING, d.successionDelay).describe.text; } catch { /* shown in the field error */ }
        out.push(`A designated successor can take over the whole organization alone after the root is untouched for ${wait} (permanent choice).`);
      } else {
        out.push("No successor: only the owners (and recovery, if enabled) can ever control this root.");
      }
      return out;
    }

    /*
     * Validate a root draft. `resolve(address)` -> x-only. Returns { ok,
     * errors, form } where `form` is the exact input of
     * org-root-ui's normalizeWizardGenesis (the core well-formedness gate).
     */
    async function validateRootDraft(d, { resolve, step, connectedAddress } = {}) {
      const errors = new Map();
      const bad = (key, message) => { if (!errors.has(key)) errors.set(key, message); };
      const v = (x) => String(x ?? "").trim();
      const only = (s) => step === undefined || step === s;
      const cache = new Map();
      const resolveCached = async (addr) => {
        if (!cache.has(addr)) {
          try { cache.set(addr, { x: await resolve(addr) }); }
          catch (err) { cache.set(addr, { err: (err && err.message) || "invalid address" }); }
        }
        return cache.get(addr);
      };

      // ---- owners ----
      const rows = Array.isArray(d.owners) ? d.owners : [];
      const owners = [];
      const rowErrors = {};
      const seenAddr = new Map();
      const seenKey = new Map();
      if (only("owners")) {
        if (rows.length === 0) bad("owners", "Add at least one owner.");
        if (rows.length > OWNER_SLOTS) bad("owners", `At most ${OWNER_SLOTS} owners are supported by the organizational root.`);
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i] || {};
          const key = v(r.publicKey).toLowerCase();
          const addr = v(r.address);
          const label = v(r.label);
          if (label.length > 60) { rowErrors[i] = "The name is too long (60 characters at most)."; continue; }
          if (r.keyMode === true && !key) { rowErrors[i] = "Enter the owner's 64-hex public key, or switch back to a wallet address."; continue; }
          if (key) {
            if (!HEX64_RE.test(key)) { rowErrors[i] = "A public key must be exactly 64 hex characters."; continue; }
            if (seenKey.has(key)) { rowErrors[i] = `Same signing key as owner ${seenKey.get(key) + 1}.`; continue; }
            seenKey.set(key, i);
            owners.push({ publicKey: key, label: label || undefined });
            continue;
          }
          if (!addr) { rowErrors[i] = rows.length > 1 ? "Enter a wallet address or remove this row." : "Enter the owner's wallet address."; continue; }
          if (seenAddr.has(addr)) { rowErrors[i] = `Same wallet as owner ${seenAddr.get(addr) + 1}.`; continue; }
          seenAddr.set(addr, i);
          const res = await resolveCached(addr);
          if (res.err) { rowErrors[i] = res.err; continue; }
          const x = String(res.x).toLowerCase();
          if (seenKey.has(x)) { rowErrors[i] = `Same signing identity as owner ${seenKey.get(x) + 1} (that owner's public key belongs to this address).`; continue; }
          seenKey.set(x, i);
          owners.push({ address: addr, label: label || undefined });
        }
        if (Object.keys(rowErrors).length) { bad("owners", "Fix the highlighted owner rows."); errors.set("ownerRows", rowErrors); }
      }
      const n = only("owners") ? owners.length : activeOwnerRows(d).length;

      // ---- approval rules ----
      if (only("approvals")) {
        const t = thresholdCheck({ count: n, value: d.ownerM, noun: "owners", label: "Owners needed to approve changes" });
        if (!t.ok) bad("ownerM", t.message);
      }
      const m = /^[0-9]+$/.test(v(d.ownerM)) ? Number(v(d.ownerM)) : 0;

      // ---- emergency access, recovery, succession ----
      let recoveryDelay = null;
      let successionDelay = null;
      if (only("emergency")) {
        const k = thresholdCheck({ count: n, value: d.emergencyK, noun: "owners", label: "Owners needed for an emergency freeze", max: m || undefined });
        if (!k.ok) bad("emergencyK", m && Number(v(d.emergencyK)) > m ? `Owners needed for an emergency freeze: ${v(d.emergencyK)} cannot exceed the ${m} needed to approve changes (a freeze may never require more owners than a change). Choose again.` : k.message);
        if (d.recoveryEnabled) {
          const r = thresholdCheck({ count: n, value: d.recoveryM, noun: "owners", label: "Owners needed to recover control", max: m || undefined });
          if (!r.ok) bad("recoveryM", m && Number(v(d.recoveryM)) > m ? `Owners needed to recover control: ${v(d.recoveryM)} cannot exceed the ${m} needed to approve changes. Choose again.` : r.message);
        }
        try { recoveryDelay = readDurationSelection(RECOVERY_SETTING, d.recoveryDelay); }
        catch (e) { bad("recoveryDelay", e.message.replace(/^duration-daa: /, "")); }
        if (d.successionEnabled) {
          const s = v(d.successorAddress);
          if (!s) bad("successorAddress", "Enter the successor's wallet address, or switch succession off.");
          else {
            const res = await resolveCached(s);
            if (res.err) bad("successorAddress", `Successor address rejected: ${res.err}`);
          }
        }
        try { successionDelay = readDurationSelection(SUCCESSION_SETTING, d.successionDelay); }
        catch (e) { bad("successionDelay", e.message.replace(/^duration-daa: /, "")); }
      }

      // ---- funding ----
      if (only("funding")) {
        const rv = kasToSompi(v(d.rootValueKas));
        if (rv === null || BigInt(rv) <= 0n) bad("rootValueKas", "Enter the governance funding: a KAS amount greater than 0.");
        const mf = kasToSompi(v(d.rootMaxFeePerTxKas));
        if (mf === null) bad("rootMaxFeePerTxKas", "Enter the maximum the root may lose per governance action (0 or more KAS).");
        else if (BigInt(mf) > 100000000000n) bad("rootMaxFeePerTxKas", "That cap exceeds the covenant's encoding bound (1000 KAS).");
        if (!v(d.signerAddress)) bad("signerAddress", "Connect the wallet that will fund this setup.");
        else if (connectedAddress && v(d.signerAddress) !== connectedAddress) bad("signerAddress", "The funding wallet must be the connected wallet — it signs the creation transaction.");
      }

      if (errors.size || step !== undefined) return { ok: errors.size === 0, errors, form: null };

      const form = {
        label: v(d.label),
        owners: owners.map((o) => ({ ...(o.publicKey ? { publicKey: o.publicKey } : { address: o.address }), ...(o.label ? { label: o.label } : {}) })),
        ownerM: String(m),
        emergencyK: v(d.emergencyK),
        recoveryM: d.recoveryEnabled ? v(d.recoveryM) : "0",
        recoveryDelayDaa: recoveryDelay.daa,
        successionDelayDaa: successionDelay.daa,
        successorAddress: d.successionEnabled ? v(d.successorAddress) : "",
        rootValueKas: v(d.rootValueKas),
        rootMaxFeePerTxKas: v(d.rootMaxFeePerTxKas),
        signerAddress: v(d.signerAddress)
      };
      return { ok: true, errors, form, recoveryDelay, successionDelay };
    }

    /*
     * Cross-check the SERVER's genesis summary (request.manifest, kind
     * "genesis-summary") against the LOCALLY normalized intent: owner keys per
     * slot, M / K / R, both delays, the successor key, the root value. A
     * mismatch means the wallet would sign something other than what was
     * reviewed — the caller must refuse to offer signing.
     */
    function genesisCrossCheck({ summary, norm }) {
      const mismatches = [];
      if (!summary || summary.kind !== "genesis-summary") return { ok: false, mismatches: ["the server did not return a genesis summary"] };
      const slots = Array.isArray(summary.slots) ? summary.slots : [];
      const local = core.ownerSetV7 ? core.ownerSetV7.activeOwnerSlotsV7(norm.ownerSet) : [];
      if (slots.length !== local.length) mismatches.push(`owner count: server ${slots.length}, reviewed ${local.length}`);
      for (let i = 0; i < Math.min(slots.length, local.length); i++) {
        if (String(slots[i].publicKey).toLowerCase() !== String(local[i].publicKey).toLowerCase()) mismatches.push(`owner ${i + 1} key differs from the reviewed owner`);
      }
      const st = summary.initialState || {};
      const cmp = (label, a, b) => { if (String(a) !== String(b)) mismatches.push(`${label}: server ${a}, reviewed ${b}`); };
      cmp("owners needed to approve changes", st.ownerM, norm.ownerSet.ownerM.toString());
      cmp("owners needed for an emergency freeze", st.emergencyK, norm.ownerSet.emergencyK.toString());
      cmp("owners needed to recover control", st.recoveryM, norm.ownerSet.recoveryM.toString());
      const t = summary.template || {};
      cmp("recovery waiting period (DAA)", t.recoveryDelayDaa, String(norm.recoveryDelayDaa));
      cmp("successor waiting period (DAA)", t.successionDelayDaa, String(norm.successionDelayDaa));
      cmp("successor key", String(t.successorPk || "").toLowerCase(), String(norm.successorPk || "").toLowerCase());
      cmp("maximum the root may lose per action (sompi)", t.rootMaxFeePerTx, norm.rootMaxFeePerTxSompi.toString());
      if (summary.rootValueKas !== undefined) cmp("governance funding (KAS)", summary.rootValueKas, sompiToKas(norm.rootValueSompi));
      return { ok: mismatches.length === 0, mismatches };
    }

    return Object.freeze({
      esc,
      html,
      COPY,
      BUDGET_SETTING,
      RECOVERY_SETTING,
      SUCCESSION_SETTING,
      MAX_APPROVER_ROWS,
      OWNER_SLOTS,
      kasToSompi,
      sompiToKas,
      renderStepper, renderNav, renderField, textInput, kasInput, select, checkbox,
      renderDurationControl, readDurationSelection, durationEffectText, durationExactText,
      approvalOptions, thresholdCheck, renderApprovalSelect,
      renderAddressRows,
      renderReviewSection, renderFundingBreakdown, renderLiveSummary,
      vaultDraftDefaults, vaultRulesSummary, validateVaultDraft, vaultReviewRows,
      rootDraftDefaults, rootRulesSummary, validateRootDraft, genesisCrossCheck
    });
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultSetupUi = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
