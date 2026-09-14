"use strict";

/*
 * PolicyVault v0.7-kas ROOTED KAS SAFE-PAYMENT VAULT ("KAS treasury") — web UI
 * module. v0.7 mainnet-enablement directive (2026-09-10): the complete browser
 * path for the KAS profile — creation under an organizational root, owner
 * operations as ROOT REQUESTS, delegate payments, and the vault-level
 * approval tier — with threshold ownership, approvals, funding/reserves,
 * fees, delays, emergency and the irreversible recovery explained BEFORE
 * anything is signed. Sibling of web/org-root-ui.js / web/hd-vault-ui.js:
 * a headless, DOM-free `createModule({ api, core, setup, payload })` factory
 * (app-v4.js wires the DOM; org-root-ui.js delegates the KAS profile here).
 *
 * WHAT A KAS TREASURY IS. A `policyvault-0.7-kas` vault holds native KAS as
 * a PROTECTED PRINCIPAL plus a FEE RESERVE. It has NO owner key: it is owned
 * by the organization's on-chain root (M of N owners, enforced by the Kaspa
 * covenant). Delegates pay within v0.4.1 rules (cap per payment, budget per
 * period, allowed recipients, fee cap); a payment above a delegate's approval
 * threshold also needs M of the vault's OWN approvers — the frozen v0.4.1
 * approval mechanism, a separate tier from the root's quorum. Recovery pays
 * the ENTIRE balance to the key pinned at creation and is irreversible.
 *
 * EVERY review re-verifies through the shared core (core/explain/org-root-
 * kas-explain.js -> core/intent/org-root-manifest-v7-kas.js) with the vault's
 * predecessor redeem bound (R7-04); every signing payload is bound to the
 * reviewed frozen bytes (org-root-ui's payload parser + frozen cross-check,
 * injected as `payload`); a genesis rebuilds the vault's locking script from
 * the reviewed rules through core/intent/vault-script-v7-kas.js and refuses a
 * substituted destination. Refusals have no override. This module never
 * fetches on its own initiative, never stores, never calls a wallet outside
 * the explicit `adapter` argument, holds no keys.
 *
 * CANDIDATE PROFILE: rendered as CANDIDATE (not byte-frozen) everywhere; the
 * mainnet set is decided by the server's discovery + the SDK gate, never here.
 */

(function () {
  const PROFILE = "policyvault-0.7-kas";
  const HEX64 = /^[0-9a-f]{64}$/;
  const DIGITS = /^(0|[1-9][0-9]*)$/;
  const SENTINEL = "00".repeat(32);
  const MAX_AGENTS = 8;
  const MAX_APPROVERS = 10;
  /* A KAS treasury payment carries the treasury's ~18.5 KB covenant script, so its network fee is about 0.04 KAS
   * (measured: 4,099,400 sompi on the production-byte fixtures and the live testnet-10 lifecycle). A delegate whose fee
   * cap is below that can never pay (the pre-sign parity check refuses OVER_AGENT_FEE_CAP) — the wizard refuses such a cap
   * up front and says why. */
  const MIN_AGENT_FEE_CAP_SOMPI = 5000000n; // 0.05 KAS
  const TYPICAL_PAYMENT_FEE_KAS = "0.04";
  const NATIVE_SUBNETWORK = "00".repeat(20);

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fail(message, code, extra) {
    const e = new Error(message);
    e.code = code || "KAS_UI_REFUSED";
    if (extra && typeof extra === "object") Object.assign(e, extra);
    return e;
  }
  const short = (s) => { const t = String(s ?? ""); return t.length > 12 ? `${t.slice(0, 8)}…${t.slice(-4)}` : t; };
  const p2pkWire = (xonly) => `000020${String(xonly).toLowerCase()}ac`;
  const isP2shWire = (spk) => /^0000aa20[0-9a-f]{64}87$/.test(String(spk || "").toLowerCase());
  const p2pkOwnerOf = (spk) => { const m = /^000020([0-9a-f]{64})ac$/.exec(String(spk || "").toLowerCase()); return m ? m[1] : null; };

  const KAS_REFUSAL_CODES = Object.freeze(["AGENT_NOT_REGISTERED", "NOT_AN_APPROVER", "UNKNOWN_APPROVER", "VAULT_PAUSED", "VAULT_TERMINAL", "VAULT_PENDING_REQUEST", "VAULT_ID_IN_USE", "INSUFFICIENT_APPROVALS", "DUPLICATE_APPROVAL", "STALE", "RECONCILIATION_REQUIRED", "OVER_CAP", "OVER_BUDGET", "OVER_AGENT_FEE_CAP", "INSUFFICIENT_RESERVE", "RECIPIENT_NOT_ALLOWED", "INTENT_VERIFICATION_FAILED", "GENERATION_NOT_MAINNET_AUTHORIZED", "REVIEW_REFUSED", "PAYLOAD_MISMATCH", "NOT_THE_SIGNER", "WALLET_NOT_READY"]);
  function displayCodeFor(e) {
    if (!e) return "UNKNOWN";
    if (e.code) return String(e.code);
    if (e.signerCode) return String(e.signerCode);
    return "UNKNOWN";
  }

  function createModule({ api, core, setup, payload } = {}) {
    if (!core || !core.orgRootKasExplain || !core.orgRootManifestV7Kas || !core.vaultScriptV7Kas || !core.amounts || !core.agentMerkle || !core.recipientMerkle) throw fail("kas-vault-ui: the core bundle lacks the v0.7-kas modules", "CORE_UNAVAILABLE");
    const EX = core.orgRootKasExplain;
    const MAN = core.orgRootManifestV7Kas;
    const SU = setup || null;
    const requireSetup = (fn) => { if (!SU) throw fail(`kas-vault-ui: ${fn} requires the setup components (web/setup-ui.js)`, "SETUP_UNAVAILABLE"); return SU; };
    const PAYLOAD = payload || null;
    const requirePayload = (fn) => { if (!PAYLOAD || typeof PAYLOAD.parseSigningPayload !== "function" || typeof PAYLOAD.frozenMismatches !== "function") throw fail(`kas-vault-ui: ${fn} requires org-root-ui's signing-payload tools`, "PAYLOAD_TOOLS_UNAVAILABLE"); return PAYLOAD; };
    const OWNERSHIP_STATEMENT = EX.KAS_OWNERSHIP_STATEMENT;
    const kasToSompi = (v, field) => core.amounts.kasToSompi(String(v ?? "").trim(), field);
    const sompiToKas = (v) => core.amounts.sompiToKas(BigInt(String(v)));
    const statusRegion = (inner, cls) => `<div class="opbanner${cls ? ` ${cls}` : ""}" role="status" aria-live="polite" aria-atomic="true">${inner}</div>`;
    async function resolveXOnlyKey(raw, what, code) {
      const s = String(raw || "").trim();
      if (!s) throw fail(`${what} is required`, code || "BUILD_FAILED");
      if (HEX64.test(s)) return s.toLowerCase();
      try { return String(await api.resolveXOnly(s)).toLowerCase(); } catch (e) { throw fail(`${what} "${s}": ${e.message}`, code || "BUILD_FAILED", { cause: e }); }
    }

    /* ================================================================
     * OWNER OPERATIONS — the KAS profile's table (consumed by org-root-ui)
     * ================================================================ */
    const VAULT_OPS = Object.freeze({
      ownerSetAgentRoot: Object.freeze({ label: "Change delegate rules", rootAction: "authorize", form: "kasAgents", dangerous: false, describe: "Installs a COMPLETE new set of delegate rules for this treasury: every delegate, its cap per payment, its budget per period, the amount above which the treasury's approvers must co-sign, its network-fee cap and the recipients it may pay. The set REPLACES the installed rules; an omitted delegate can no longer pay." }),
      ownerSetApprovers: Object.freeze({ label: "Change approvers", rootAction: "authorize", form: "approvers", dangerous: false, describe: "Replaces the treasury's approver set and the number of approvals (M) a payment above a delegate's threshold needs. Approvers can only approve or ignore a payment — they cannot spend and hold no owner authority." }),
      ownerTopUp: Object.freeze({ label: "Add funds", rootAction: "authorize", form: "topUpPrincipal", dangerous: false, describe: "Adds KAS to the treasury's PROTECTED PRINCIPAL — the funds delegates may pay out under their rules — from the fee payer's wallet." }),
      ownerTopUpReserve: Object.freeze({ label: "Top up fee reserve", rootAction: "authorize", form: "topUp", dangerous: false, describe: "Adds KAS to the treasury's FEE RESERVE, which pays the network fee of each delegate payment so the delegate never needs KAS of its own." }),
      ownerPause: Object.freeze({ label: "Pause treasury", rootAction: "authorize", form: "confirm", dangerous: false, requiresPaused: false, describe: "Pauses this treasury: delegate payments stop once the pause is chain-verified. Nothing moves; the rules, budgets and approvers are kept." }),
      ownerUnpause: Object.freeze({ label: "Unpause treasury", rootAction: "authorize", form: "confirm", dangerous: false, requiresPaused: true, describe: "Unpauses this treasury: delegate payments resume under the installed rules and remaining budgets once chain-verified." }),
      ownerEmergencyPause: Object.freeze({ label: "Emergency-pause treasury", rootAction: "freeze", form: "confirm", dangerous: false, requiresPaused: false, describe: "Emergency-pauses this ONE treasury on the lighter emergency quorum. The same transaction FREEZES the organization's root: no governance action can be approved for any vault until the full approval quorum unfreezes it." }),
      ownerRecover: Object.freeze({ label: "Close & recover treasury", rootAction: "authorize", form: "confirm", dangerous: true, describe: "CLOSES this treasury permanently: its ENTIRE balance — protected principal AND fee reserve — is paid to the recovery key pinned when it was created. Nobody can change that destination and nothing can undo it." })
    });
    const VAULT_OP_ORDER = Object.freeze(["ownerSetAgentRoot", "ownerSetApprovers", "ownerTopUp", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"]);
    const VAULT_OP_LABEL = Object.freeze(Object.fromEntries(Object.entries(VAULT_OPS).map(([k, v]) => [k, v.label])));
    function vaultOpLabel(op) { return Object.prototype.hasOwnProperty.call(VAULT_OP_LABEL, String(op)) ? VAULT_OP_LABEL[op] : String(op || "operation"); }
    /* the root action each operation requires is the SHARED CORE's table; a disagreement means the op is never offered */
    function vaultOpInfo(op) {
      if (!Object.prototype.hasOwnProperty.call(VAULT_OPS, String(op))) return null;
      const info = VAULT_OPS[op];
      let authority = null;
      try { authority = core.vaultStateV7Kas && typeof core.vaultStateV7Kas.resolveOwnerOpAuthorityV7Kas === "function" ? core.vaultStateV7Kas.resolveOwnerOpAuthorityV7Kas(op) : null; } catch { authority = null; }
      if (!authority || String(authority.rootActionName) !== info.rootAction) return null;
      return info;
    }
    function vaultOpConfirmPhrase(op) { return op === "ownerRecover" ? "CONFIRM CLOSE TREASURY" : ""; }
    function vaultOpConfirmationMatches(op, typed) { const p = vaultOpConfirmPhrase(op); return !!p && String(typed || "").trim() === p; }

    /* ---- delegate rule rows (v0.4.1 policy fields, KAS amounts) ---- */
    function agentRowFrom(a, currentDaa) {
      const existing = !!(a && a.agentPk);
      return {
        existing,
        agentKey: existing ? String(a.agentPk) : "",
        maxPerSpendKas: existing && a.maxPerSpend !== undefined ? sompiToKas(a.maxPerSpend) : "",
        periodBudgetKas: existing && a.periodBudget !== undefined ? sompiToKas(a.periodBudget) : "",
        periodLengthDaa: existing ? String(a.periodLengthDaa ?? "") : "",
        periodStartDaa: existing ? String(a.periodStartDaa ?? "0") : (currentDaa !== null && currentDaa !== undefined ? String(currentDaa) : "0"),
        periodSpent: existing ? String(a.periodSpent ?? "0") : "0",
        approvalThresholdKas: existing && a.approvalThreshold !== undefined ? sompiToKas(a.approvalThreshold) : "",
        agentMaxFeePerTxKas: existing && a.agentMaxFeePerTx !== undefined ? sompiToKas(a.agentMaxFeePerTx) : "",
        recipients: existing && Array.isArray(a.recipients) ? a.recipients.map((r) => String(r)).join("\n") : ""
      };
    }
    async function validateAgentRows(rows) {
      const agents = [];
      const seen = new Set();
      const rowErrors = {};
      if (rows.length > MAX_AGENTS) return { agents, rowErrors, listError: `At most ${MAX_AGENTS} delegates are supported by this treasury profile.` };
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i] || {};
        const errs = {};
        let agentPk = null;
        try { agentPk = await resolveXOnlyKey(r.agentKey, "Delegate wallet", "AGENT_SET_INVALID"); } catch (e) { errs.agentKey = e.message; }
        if (agentPk && seen.has(agentPk)) errs.agentKey = "This delegate is already listed — one rule per delegate key.";
        if (agentPk) seen.add(agentPk);
        const recipientsRaw = String(r.recipients || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
        const recipients = [];
        if (!recipientsRaw.length) errs.recipients = "At least one allowed recipient is required — a delegate with no recipient can pay no one.";
        for (const rec of recipientsRaw) { try { recipients.push(await resolveXOnlyKey(rec, "Recipient", "AGENT_SET_INVALID")); } catch (e) { errs.recipients = e.message; break; } }
        if (!errs.recipients && new Set(recipients).size !== recipients.length) errs.recipients = "A recipient is listed twice.";
        let agentRecipientRoot = null;
        if (!errs.recipients) { try { agentRecipientRoot = core.recipientMerkle.buildRecipientTree(recipients).root; } catch (e) { errs.recipients = e.message; } }
        const kas = (v, name, positive) => { try { const s = kasToSompi(v, name); if (positive && BigInt(s) <= 0n) return { err: `${name} must be greater than 0 KAS.` }; return { sompi: BigInt(s).toString() }; } catch (e) { return { err: `${name}: ${e.message}` }; } };
        const cap = kas(r.maxPerSpendKas, "Cap per payment", true); if (cap.err) errs.maxPerSpendKas = cap.err;
        const budget = kas(r.periodBudgetKas, "Budget per period", true); if (budget.err) errs.periodBudgetKas = budget.err;
        const threshold = kas(r.approvalThresholdKas, "Approval threshold", false); if (threshold.err) errs.approvalThresholdKas = threshold.err;
        const feeCap = kas(r.agentMaxFeePerTxKas, "Network-fee cap per payment", false); if (feeCap.err) errs.agentMaxFeePerTxKas = feeCap.err;
        else if (BigInt(feeCap.sompi) < MIN_AGENT_FEE_CAP_SOMPI) errs.agentMaxFeePerTxKas = `A treasury payment costs about ${TYPICAL_PAYMENT_FEE_KAS} KAS in network fees (it carries the treasury's covenant script); a cap below 0.05 KAS would make every payment by this delegate impossible.`;
        const plen = String(r.periodLengthDaa ?? "").trim(); if (!DIGITS.test(plen) || BigInt(plen) <= 0n) errs.periodLengthDaa = "Budget period must be a whole number of DAA score greater than 0.";
        const pstart = String(r.periodStartDaa ?? "0").trim(); if (!DIGITS.test(pstart)) errs.periodStartDaa = "Period start must be a whole DAA score.";
        const pspent = String(r.periodSpent ?? "0").trim(); if (!DIGITS.test(pspent)) errs.periodSpent = "Spent this period must be a whole number of sompi.";
        if (!errs.maxPerSpendKas && !errs.periodBudgetKas && BigInt(cap.sompi) > BigInt(budget.sompi)) errs.maxPerSpendKas = "Cap per payment cannot exceed the budget per period.";
        if (!Object.keys(errs).length) {
          const raw = { agentPk, maxPerSpend: cap.sompi, periodBudget: budget.sompi, periodLengthDaa: plen, periodStartDaa: pstart, periodSpent: pspent, approvalThreshold: threshold.sompi, agentMaxFeePerTx: feeCap.sompi, agentRecipientRoot };
          /* the EXACT normalizer the covenant's Merkle-leaf encoding relies on — a malformed policy is refused here */
          try { core.agentMerkle.normalizeAgentPolicyV4(raw); } catch (e) { errs.agentKey = e.message; }
          if (!Object.keys(errs).length) agents.push({ ...raw, recipients });
        }
        if (Object.keys(errs).length) rowErrors[i] = errs;
      }
      return { agents, rowErrors, listError: null };
    }
    function agentRoot(agents) {
      return core.agentMerkle.buildAgentTreeV4(agents.map(({ recipients, ...policy }) => { void recipients; return policy; })).root;
    }
    async function validateApproverRows(rows, approvalM, { allowEmpty = true } = {}) {
      const keys = [];
      const rowErrors = {};
      const seen = new Set();
      const list = Array.isArray(rows) ? rows : [];
      if (list.length > MAX_APPROVERS) return { keys, rowErrors, listError: `At most ${MAX_APPROVERS} approvers are supported.`, approvalM: null };
      for (let i = 0; i < list.length; i++) {
        const r = list[i] || {};
        const raw = String(r.publicKey || "").trim() || String(r.address || "").trim();
        if (!raw) { rowErrors[i] = list.length > 1 ? "Enter a wallet address or remove this row." : "Enter the approver's wallet address or remove the row."; continue; }
        let key;
        try { key = await resolveXOnlyKey(raw, "Approver wallet", "BUILD_FAILED"); } catch (e) { rowErrors[i] = e.message; continue; }
        if (seen.has(key)) { rowErrors[i] = "This approver is already listed."; continue; }
        seen.add(key); keys.push(key);
      }
      const m = String(approvalM ?? "").trim();
      let mError = null;
      /* pre-sign parity with core/model/vault-transitions-v4 setApproversSuccessorV4: the covenant cannot transition an
       * existing treasury to ZERO approvers (that tier exists only at genesis) — refused here before anything is built */
      if (keys.length === 0 && !allowEmpty) return { keys, rowErrors, listError: "An existing treasury cannot be changed to zero approvers — the covenant allows a no-approver tier only at creation. Keep at least one approver (1 of 1), or pause the treasury instead.", approvalM: null, mError: null };
      if (keys.length === 0) { if (m !== "" && m !== "0") mError = "With no approvers, the required approvals must be 0."; }
      else if (!DIGITS.test(m) || Number(m) < 1 || Number(m) > keys.length) mError = `Required approvals must be between 1 and ${keys.length} (the number of approvers).`;
      return { keys, rowErrors, listError: null, approvalM: keys.length === 0 ? "0" : m, mError };
    }

    function vaultOpDraftFrom({ op, vault, currentDaa = null } = {}) {
      const info = vaultOpInfo(op);
      if (!info) throw fail(`unknown KAS treasury owner operation ${JSON.stringify(op)} — failing closed`, "UNKNOWN_ACTION");
      if (info.form === "topUp" || info.form === "topUpPrincipal") return { op, amountKas: "" };
      if (info.form === "kasAgents") {
        const agents = Array.isArray(vault && vault.agents) ? vault.agents : [];
        return { op, agents: agents.length ? agents.map((a) => agentRowFrom(a, currentDaa)) : [agentRowFrom(null, currentDaa)], currentDaa: currentDaa === null || currentDaa === undefined ? null : String(currentDaa) };
      }
      if (info.form === "approvers") {
        const approvers = Array.isArray(vault && vault.approvers) ? vault.approvers : [];
        return { op, approvers: approvers.map((k) => ({ address: "", publicKey: String(k), keyMode: true })), approvalM: String(vault && vault.approvalM !== undefined && vault.approvalM !== null ? vault.approvalM : approvers.length ? "1" : "0") };
      }
      return { op, typed: "" };
    }
    async function validateVaultOpDraft({ op, draft, vault } = {}) {
      const info = vaultOpInfo(op);
      const errors = new Map();
      if (!info) { errors.set("op", `unknown KAS treasury owner operation ${JSON.stringify(op)} — failing closed`); return { ok: false, errors, vaultOperation: null }; }
      if (!vault || !vault.vaultId) { errors.set("op", "no treasury selected"); return { ok: false, errors, vaultOperation: null }; }
      const d = draft || {};
      if (info.form === "topUp" || info.form === "topUpPrincipal") {
        let sompi = null;
        try { sompi = kasToSompi(d.amountKas, info.form === "topUp" ? "top-up amount" : "amount to add"); } catch (e) { errors.set("amount", `Enter a KAS amount (up to 8 decimals): ${e.message}`); }
        if (sompi !== null && BigInt(sompi) <= 0n) errors.set("amount", "Enter a KAS amount greater than 0.");
        if (errors.size) return { ok: false, errors, vaultOperation: null };
        const params = info.form === "topUp" ? { topUpReserveAmountSompi: BigInt(sompi).toString() } : { topUpAmountSompi: BigInt(sompi).toString() };
        return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params } };
      }
      if (info.form === "kasAgents") {
        const { agents, rowErrors, listError } = await validateAgentRows(Array.isArray(d.agents) ? d.agents : []);
        if (listError) errors.set("agents", listError);
        if (Object.keys(rowErrors).length) errors.set("agentRows", rowErrors);
        if (errors.size) return { ok: false, errors, vaultOperation: null };
        return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: { agents } }, agentCount: agents.length, agentRoot: agentRoot(agents) };
      }
      if (info.form === "approvers") {
        const { keys, rowErrors, listError, approvalM, mError } = await validateApproverRows(d.approvers, d.approvalM, { allowEmpty: false });
        if (listError) errors.set("approvers", listError);
        if (Object.keys(rowErrors).length) errors.set("approverRows", rowErrors);
        if (mError) errors.set("approvalM", mError);
        if (errors.size) return { ok: false, errors, vaultOperation: null };
        return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: { approvers: keys, approvalM } } };
      }
      if (info.dangerous && !vaultOpConfirmationMatches(op, d.typed)) { errors.set("typed", `Type exactly "${vaultOpConfirmPhrase(op)}" to continue.`); return { ok: false, errors, vaultOperation: null }; }
      return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: {} } };
    }
    function renderAgentRowsHtml({ rows, rowErrors, listError, currentDaa }) {
      const SUI = requireSetup("renderAgentRowsHtml");
      const F = SUI.renderField;
      const rowHtml = (rows || []).map((r, i) => {
        const re = rowErrors[i] || {};
        const nm = (k) => `agent-${i}-${k}`;
        return (
          `<fieldset class="agent-row" data-agent-row="${i}" style="border:1px solid var(--border, #ccc);border-radius:6px;padding:0.6rem;margin:0.5rem 0">` +
          `<legend>Delegate ${i + 1}${r.existing ? " (currently installed)" : " (new)"}</legend>` +
          F({ name: nm("agentKey"), label: "Delegate wallet (address or 64-hex public key)", control: SUI.textInput({ name: nm("agentKey"), value: r.agentKey, mono: true, placeholder: "kaspa… or 64-hex key" }), error: re.agentKey, help: "The wallet (or AI agent key) allowed to pay from this treasury under the rule below." }) +
          F({ name: nm("maxPerSpendKas"), label: "Cap per payment (KAS)", control: SUI.kasInput({ name: nm("maxPerSpendKas"), value: r.maxPerSpendKas, placeholder: "10" }), error: re.maxPerSpendKas }) +
          F({ name: nm("periodBudgetKas"), label: "Budget per period (KAS)", control: SUI.kasInput({ name: nm("periodBudgetKas"), value: r.periodBudgetKas, placeholder: "100" }), error: re.periodBudgetKas }) +
          F({ name: nm("periodLengthDaa"), label: "Budget period (exact DAA score)", control: SUI.textInput({ name: nm("periodLengthDaa"), value: r.periodLengthDaa, inputmode: "numeric", mono: true, placeholder: "864000" }), help: "About 1 DAA score per second on Kaspa mainnet (864000 ≈ 10 days). The budget resets when a period ends.", error: re.periodLengthDaa }) +
          F({ name: nm("approvalThresholdKas"), label: "Approval threshold (KAS)", control: SUI.kasInput({ name: nm("approvalThresholdKas"), value: r.approvalThresholdKas, placeholder: "5" }), help: "Payments ABOVE this amount need M of the treasury's approvers to co-sign. 0 means every payment needs approvals; a threshold at or above the cap means none do.", error: re.approvalThresholdKas }) +
          F({ name: nm("agentMaxFeePerTxKas"), label: "Network-fee cap per payment (KAS)", control: SUI.kasInput({ name: nm("agentMaxFeePerTxKas"), value: r.agentMaxFeePerTxKas, placeholder: "0.1" }), help: `The most this delegate may take from the fee reserve for one payment's network fee. A treasury payment costs about ${TYPICAL_PAYMENT_FEE_KAS} KAS (it carries the treasury's covenant script) — the cap must be at least 0.05 KAS.`, error: re.agentMaxFeePerTxKas }) +
          `<div class="f f-wide${re.recipients ? " f-invalid" : ""}" data-field="${esc(nm("recipients"))}"><label class="f-label" for="f-${esc(nm("recipients"))}">Allowed recipients (one per line: address or 64-hex key)</label><textarea id="f-${esc(nm("recipients"))}" name="${esc(nm("recipients"))}" rows="3" class="mono">${esc(r.recipients)}</textarea><div class="f-help">The delegate may pay ONLY these destinations — enforced by the covenant.</div>${re.recipients ? `<div class="ferr" style="display:block">${esc(re.recipients)}</div>` : ""}</div>` +
          `<details class="adv f-tech"><summary>Technical detail (carried exactly)</summary><div class="f-help">period start DAA <span class="mono">${esc(r.periodStartDaa)}</span> · spent this period <span class="mono">${esc(r.periodSpent)}</span> sompi${currentDaa ? ` · current DAA ≈ ${esc(currentDaa)}` : ""}</div></details>` +
          `<input type="hidden" name="${esc(nm("periodStartDaa"))}" value="${esc(r.periodStartDaa)}" /><input type="hidden" name="${esc(nm("periodSpent"))}" value="${esc(r.periodSpent)}" /><input type="hidden" name="${esc(nm("existing"))}" value="${r.existing ? "1" : "0"}" />` +
          `<div class="actions"><button type="button" class="quiet" data-remove-agent="${i}" aria-label="Remove delegate ${i + 1}">Remove delegate</button></div>` +
          `</fieldset>`
        );
      }).join("");
      return (
        `<div class="ferr" data-err="agents"${listError ? ' style="display:block"' : ""}>${esc(listError || "")}</div>` +
        `<div data-agent-rows="1">${rowHtml}</div>` +
        `<div class="addr-actions"><button type="button" id="v4-add-agent" class="quiet">+ Add delegate</button></div>`
      );
    }
    function renderApproverRowsHtml({ rows, rowErrors, approvalM, mError, listError, allowEmpty = true }) {
      const SUI = requireSetup("renderApproverRowsHtml");
      const count = (rows || []).length;
      return (
        `<div class="f f-wide${listError ? " f-invalid" : ""}" data-field="approvers"><div class="f-label">Approvers</div>` +
        SUI.renderAddressRows({ kind: "approver", rows: rows || [], withLabel: false, allowKey: true, errors: rowErrors || {}, addLabel: "Add approver", placeholder: "kaspa…", min: allowEmpty ? 0 : 1, max: MAX_APPROVERS }) +
        `<div class="f-help">Wallets that can approve a payment above a delegate's threshold. They cannot spend, and they hold no owner authority. ${allowEmpty ? "Leave empty for a treasury whose delegates never need approvals." : "An existing treasury keeps at least one approver (the covenant allows a no-approver tier only at creation)."}</div>` +
        `<div class="ferr" data-err="approvers"${listError ? ' style="display:block"' : ""}>${esc(listError || "")}</div></div>` +
        SUI.renderField({ name: "approvalM", label: "Approvals needed above a threshold", control: count ? SUI.renderApprovalSelect({ name: "approvalM", count, value: approvalM, noun: "approvers", min: 1 }) : `<input type="hidden" name="approvalM" value="0" /><span class="mono">0 of 0 approvers</span>`, help: count ? "The covenant enforces exactly this many approver signatures on a payment above the delegate's threshold." : "No approvers: every payment within a delegate's rules needs only the delegate's signature.", error: mError || "" })
      );
    }
    function renderVaultOpFormHtml({ op, vault, orgRoot, draft, errors, connectedAddress, currentDaa = null } = {}) {
      const SUI = requireSetup("renderVaultOpFormHtml");
      const info = vaultOpInfo(op);
      if (!info) return statusRegion(`unknown KAS treasury owner operation ${esc(JSON.stringify(op))} — refusing to render a form`, "bad");
      const F = SUI.renderField;
      const err = (k) => (errors && errors.get(k)) || "";
      const v = vault || {};
      const st = (orgRoot && orgRoot.state) || {};
      const n = (orgRoot && orgRoot.slots ? orgRoot.slots.length : 0);
      const quorum = info.rootAction === "freeze" ? `${esc(String(st.emergencyK ?? "?"))} of ${n} owners (emergency quorum)` : `${esc(String(st.ownerM ?? "?"))} of ${n} owners`;
      const live = v.live || null;
      const head =
        `<h3 id="v4-vaultop-title" style="margin-top:0">${esc(info.label)} — ${esc(v.label || short(v.vaultId))}</h3>` +
        `<div class="f-help">${esc(info.describe)}</div>` +
        `<div class="f-help">Authorized by ${quorum} through the root's <b>${esc(info.rootAction)}</b> action. PolicyVault builds the exact transaction next; nothing is signed or sent on this screen.${live ? ` Current balance: ${esc(String(live.protectedValueKas))} KAS protected + ${esc(String(live.feeReserveKas))} KAS fee reserve.` : ""}</div>`;
      let body = "";
      if (info.form === "topUp") body = F({ name: "amount", label: "Amount to add to the fee reserve", control: SUI.kasInput({ name: "amount", value: draft && draft.amountKas, placeholder: "0.5" }), help: "Exact KAS; PolicyVault converts it to sompi (1 KAS = 100,000,000 sompi). Funded from the fee payer's wallet.", error: err("amount") });
      else if (info.form === "topUpPrincipal") body = F({ name: "amount", label: "Amount to add to the protected principal", control: SUI.kasInput({ name: "amount", value: draft && draft.amountKas, placeholder: "100" }), help: "Exact KAS added to the funds delegates may pay out. Funded from the fee payer's wallet.", error: err("amount") });
      else if (info.form === "kasAgents") {
        const rows = draft && Array.isArray(draft.agents) ? draft.agents : [];
        body = `<div class="f-help">These rules REPLACE the installed set completely${rows.length ? "" : " — an empty set means no delegate can pay until a new set is installed"}. Values are prefilled from the installed rules.</div>` +
          renderAgentRowsHtml({ rows, rowErrors: (errors && errors.get("agentRows")) || {}, listError: err("agents"), currentDaa: draft && draft.currentDaa });
      } else if (info.form === "approvers") {
        body = renderApproverRowsHtml({ rows: draft && draft.approvers, rowErrors: (errors && errors.get("approverRows")) || {}, approvalM: draft && draft.approvalM, mError: err("approvalM"), listError: err("approvers"), allowEmpty: false });
      } else {
        const balance = live ? `${esc(String(live.totalKas ?? ""))} KAS (${esc(String(live.protectedValueKas))} protected + ${esc(String(live.feeReserveKas))} reserve)` : "its entire balance";
        const consequences = {
          ownerPause: "Once chain-verified, every delegate payment from this treasury is refused by the covenant until the owners unpause it. Nothing moves; the rules, budgets and approvers are kept.",
          ownerUnpause: "Once chain-verified, delegate payments resume under the installed rules and remaining budgets.",
          ownerEmergencyPause: `Once chain-verified, this treasury is paused AND the organizational root is FROZEN: no governance action can be approved for any vault of this organization until ${esc(String(st.ownerM ?? "M"))} of ${n} owners unfreeze it. Delegate payments from OTHER vaults continue.`,
          ownerRecover: `IRREVERSIBLE. The treasury ends: ${balance} is paid to the pinned recovery key${v.recoveryPk ? ` ${esc(v.recoveryPk)}` : ""}, nowhere else. Every delegate rule and approver is void afterwards.`
        }[op] || "";
        body = `<div class="opbanner ${info.dangerous ? "bad" : "warn"}" role="status" aria-live="polite" aria-atomic="true" data-vaultop-confirm="${esc(op)}"><b>${esc(info.label)}</b><div style="margin-top:0.3rem">${consequences}</div>` +
          (info.dangerous ? `<div style="margin-top:0.5rem">Type <span class="mono">${esc(vaultOpConfirmPhrase(op))}</span> to continue. There is no other confirmation for this action.</div>` : "") + `</div>` +
          (info.dangerous ? `<div class="f f-wide${err("typed") ? " f-invalid" : ""}"><label class="f-label" for="v4-vaultop-typed">Type the confirmation phrase</label><input id="v4-vaultop-typed" name="typed" class="mono" value="${esc(draft && draft.typed)}" autocomplete="off" /><div class="ferr" data-err="typed"${err("typed") ? ' style="display:block"' : ""}>${esc(err("typed"))}</div></div>` : "");
      }
      const submitLabel = info.form === "confirm" ? (info.dangerous ? info.label : `${info.label} — build request`) : "Build the exact transaction & review";
      return head +
        `<form class="setup-form" data-vaultop-form="${esc(op)}" data-vault="${esc(v.vaultId)}" data-vault-profile="${PROFILE}" autocomplete="off" novalidate>` + body +
        `<div class="f-help">Started by <span class="mono">${esc(connectedAddress || "")}</span> (an owner of this root). Its wallet funds the network fee; the change returns to it.</div>` +
        `<div class="modal-actions"><button type="button" data-vaultop-cancel="1">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="${info.dangerous ? "warn" : "primary"}">${esc(submitLabel)}</button></div>` +
        `</form>`;
    }

    /* ================================================================
     * TREASURY PANEL (root detail) + request cards + participant list
     * ================================================================ */
    function agentEntryFor(vault, xonly) {
      const agents = Array.isArray(vault && vault.agents) ? vault.agents : [];
      return xonly ? agents.find((a) => a && String(a.agentPk).toLowerCase() === String(xonly).toLowerCase()) || null : null;
    }
    function isApproverOf(vault, xonly) {
      const approvers = Array.isArray(vault && vault.approvers) ? vault.approvers : [];
      return !!xonly && approvers.some((k) => String(k).toLowerCase() === String(xonly).toLowerCase());
    }
    function renderKasVaultPanelHtml(vault, orgRoot, opts = {}) {
      const { viewerXOnly = null, pendingRequest = null, loaded = true, availabilityOf = null, showOwnerOps = true } = opts || {};
      const v = vault || {};
      const rootId = (orgRoot && orgRoot.rootCovenantId) || v.orgRootCovenantId || "";
      const live = v.live && typeof v.live === "object" ? v.live : null;
      const paused = !!(live && live.paused === true);
      const terminal = !!(v.status && String(v.status) !== "ACTIVE" && String(v.status) !== "PAUSED");
      const badge = !loaded ? "PAUSED" : terminal ? "RECOVERED" : paused ? "PAUSED" : live ? "ACTIVE" : "PAUSED";
      const badgeText = !loaded ? "NOT LOADED" : terminal ? String(v.status) : paused ? "PAUSED" : live ? "ACTIVE" : "NO LIVE OUTPOINT";
      const guardedBy = pendingRequest && Array.isArray(pendingRequest.vaultOperations) && pendingRequest.vaultOperations.some((op) => op && op.vaultId === v.vaultId) ? pendingRequest : null;
      const agents = Array.isArray(v.agents) ? v.agents : [];
      const approvers = Array.isArray(v.approvers) ? v.approvers.filter((k) => k !== SENTINEL) : [];
      const statusLine = !loaded ? "This treasury's current state could not be loaded — reload before starting anything."
        : live ? `${String(live.protectedValueKas)} KAS protected · ${String(live.feeReserveKas)} KAS fee reserve · ${paused ? "PAUSED — delegate payments stopped" : "delegate payments allowed under the installed rules"} · generation ${String(v.generation ?? "?")}`
          : terminal ? `This treasury is ${String(v.status)} — it holds nothing and accepts no further operation.` : "No confirmed on-chain outpoint yet — use Verify state on the root after the creation lands.";
      const me = agentEntryFor(v, viewerXOnly);
      const buttons = showOwnerOps && loaded && typeof availabilityOf === "function"
        ? VAULT_OP_ORDER.map((op) => {
            const info = vaultOpInfo(op);
            if (!info) return "";
            const a = availabilityOf(op);
            if (!a || !a.offered) return "";
            return `<button type="button"${a.enabled ? "" : " disabled"} class="${info.dangerous ? "warn" : info.rootAction === "freeze" ? "warn" : ""}" data-rootvaultop="${esc(op)}" data-vault="${esc(v.vaultId)}" data-root="${esc(rootId)}" title="${esc(a.enabled ? info.describe : a.reason)}">${esc(info.label)}</button>`;
          }).join("")
        : "";
      const spendBtn = loaded && me && live && !paused && !terminal
        ? `<button type="button" class="primary" data-kasspend="${esc(v.vaultId)}" title="Pay from this treasury as delegate ${esc(short(me.agentPk))} under its installed rule">Pay from this treasury</button>`
        : "";
      const agentLines = agents.length
        ? agents.map((a) => `<div class="kv-line">delegate <span class="mono">${esc(short(a.agentPk))}</span>${viewerXOnly && String(a.agentPk).toLowerCase() === String(viewerXOnly).toLowerCase() ? " (you)" : ""}: up to ${esc(sompiToKas(a.maxPerSpend))} KAS per payment, ${esc(sompiToKas(a.periodBudget))} KAS per ${esc(String(a.periodLengthDaa))} DAA (spent ${esc(sompiToKas(a.periodSpent))} KAS), approvals above ${esc(sompiToKas(a.approvalThreshold))} KAS, ${Array.isArray(a.recipients) ? a.recipients.length : "?"} allowed recipient(s)</div>`).join("")
        : `<div class="kv-line">No delegate rules installed — no one can pay from this treasury until the owners install rules.</div>`;
      const approverLine = approvers.length
        ? `<div class="kv-line">Approvals above a delegate's threshold: ${esc(String(v.approvalM ?? "?"))} of ${approvers.length} approver(s)${isApproverOf(v, viewerXOnly) ? " (you are an approver)" : ""}: ${approvers.map((k) => `<span class="mono">${esc(short(k))}</span>`).join(", ")}</div>`
        : `<div class="kv-line">No approvers: every payment within a delegate's rules needs only the delegate's signature.</div>`;
      return (
        `<div class="panel" data-rooted-vault-owner-ops="${esc(v.vaultId)}" data-kas-vault="${esc(v.vaultId)}" data-root="${esc(rootId)}" data-vault-profile="${PROFILE}">` +
        `<div class="vault-head"><span class="vault-title">${esc(v.label || short(v.vaultId))}</span> <span><span class="badge ${badge}">${esc(badgeText)}</span> <span class="badge ver">KAS treasury · candidate profile</span></span></div>` +
        `<div class="kv-line mono" style="word-break:break-all">treasury ${esc(v.vaultId)}</div>` +
        `<div class="kv-line">${esc(statusLine)}</div>` +
        `<div class="hint">${esc(OWNERSHIP_STATEMENT)}</div>` +
        agentLines + approverLine +
        (v.recoveryPk ? `<div class="kv-line">Pinned recovery key — Close &amp; recover pays the ENTIRE balance here, nowhere else: <span class="mono" style="word-break:break-all">${esc(v.recoveryPk)}</span></div>` : "") +
        (guardedBy ? `<div class="opbanner warn" data-vault-guarded-by="${esc(guardedBy.id)}">This treasury is guarded by the pending request ${esc(vaultOpLabel(guardedBy.vaultOperations[0].action))} — open it from the root.</div>` : "") +
        `<div class="actions" data-rooted-vault-ops="${esc(v.vaultId)}">${spendBtn}${buttons}</div>` +
        `<div data-kas-requests="${esc(v.vaultId)}"></div>` +
        `</div>`
      );
    }
    const SPEND_OUTCOMES = Object.freeze({
      BUILT: "Built — the delegate has not signed yet; nothing has moved.",
      AWAITING_APPROVALS: "Awaiting approvals — approvers co-sign first; the delegate signs after the threshold is met.",
      SIGNED: "Signed and assembled — NOT yet broadcast.",
      SUBMITTING: "Broadcasting — NOT yet confirmed.",
      SUBMITTED: "Broadcast — NOT yet confirmed.",
      CHAIN_VERIFIED: "Chain-verified: the payment landed and the treasury advanced. This is proven.",
      SUBMISSION_REJECTED: "Rejected by the network — nothing happened.",
      RECONCILIATION_REQUIRED: "Outcome unknown — use Verify state on the root before anything else.",
      WALLET_REJECTED: "Withdrawn — nothing happened.",
      SIGNATURE_INVALID: "Signature refused — nothing happened.",
      STALE: "Stale — the treasury moved on; rebuild.",
      NOT_BROADCAST: "Never reached the network — nothing happened.",
      SUPERSEDED: "Superseded by another transaction — nothing from it happened."
    });
    function renderKasRequestCardHtml(vault, req, { viewerXOnly = null } = {}) {
      const p = req.approvalProgress || { collected: 0, required: 0, approverSlots: null, approvedSlots: [] };
      const slots = (p.approverSlots && p.approverSlots.length ? p.approverSlots : (Array.isArray(vault && vault.approvers) ? vault.approvers : [])).filter((s) => s !== SENTINEL);
      const myIdx = viewerXOnly ? slots.findIndex((s) => String(s).toLowerCase() === String(viewerXOnly).toLowerCase()) : -1;
      const iApproved = myIdx >= 0 && Array.isArray(p.approvedSlots) ? !!p.approvedSlots[myIdx] : false;
      const isAgent = !!(viewerXOnly && req.signerXOnly && String(req.signerXOnly).toLowerCase() === String(viewerXOnly).toLowerCase());
      const awaiting = req.state === "AWAITING_APPROVALS";
      const review = req.review || {};
      let action = "";
      if (awaiting && myIdx >= 0 && !iApproved) action = `<button type="button" class="primary" data-kasapprove="${esc(req.requestId)}">Review &amp; approve</button>`;
      else if (awaiting && myIdx >= 0 && iApproved) action = `<span class="hint" style="display:inline">You approved — waiting for the remaining approvals.</span>`;
      else if (req.state === "BUILT" && isAgent) action = `<button type="button" class="primary" data-kasagentsign="${esc(req.requestId)}">Review &amp; sign payment</button>`;
      else if (awaiting && isAgent) action = `<span class="hint" style="display:inline">Approvers sign first; you sign after the threshold is met.</span>`;
      else if (req.state === "SIGNED") action = `<button type="button" class="primary" data-kassubmit="${esc(req.requestId)}">Submit to network</button>`;
      const cancel = isAgent && (req.state === "BUILT" || awaiting) ? ` <button type="button" class="warn" data-kascancel="${esc(req.requestId)}">Withdraw</button>` : "";
      const level = req.state === "CHAIN_VERIFIED" ? "" : ["SUBMISSION_REJECTED", "SIGNATURE_INVALID", "STALE", "WALLET_REJECTED", "NOT_BROADCAST", "SUPERSEDED"].includes(req.state) ? "bad" : "warn";
      return (
        `<div class="opbanner ${level}" data-kasreq="${esc(req.requestId)}" data-kasreq-state="${esc(req.state)}">` +
        `<b>${esc(req.kind === "kasGenesis" ? "Treasury creation" : "Delegate payment")}</b> · ${esc(SPEND_OUTCOMES[req.state] || `${req.state} — not confirmed`)}` +
        (req.kind === "agentSpend" ? ` · ${esc(String(review.amountKas ?? "?"))} KAS to ${esc(short(review.recipient || ""))}${p.required ? ` · ${esc(String(p.collected))} of ${esc(String(p.required))} approved` : ""}` : "") +
        ` · request ${esc(short(req.requestId))} <button type="button" class="quiet" data-kasview="${esc(req.requestId)}">Details</button> ${action}${cancel}</div>`
      );
    }
    function renderParticipantVaultsHtml(vaults, { viewerXOnly = null } = {}) {
      const kas = (Array.isArray(vaults) ? vaults : []).filter((v) => v && v.contractVersion === PROFILE && (agentEntryFor(v, viewerXOnly) || isApproverOf(v, viewerXOnly)));
      if (!kas.length) return "";
      const cards = kas.map((v) => renderKasVaultPanelHtml(v, { rootCovenantId: v.orgRootCovenantId }, { viewerXOnly, loaded: true, showOwnerOps: false })).join("");
      return `<div class="panel" data-kas-participant-vaults="${kas.length}"><h4 style="margin-top:0">KAS treasuries you take part in</h4><div class="hint">You are a delegate or an approver of these treasuries. Owner operations are started by the organization's root owners.</div>${cards}</div>`;
    }

    /* ================================================================
     * CREATION — the guided setup (steps) + build + review + sign
     * ================================================================ */
    const KAS_STEPS = Object.freeze([
      { id: "treasury", label: "Treasury" }, { id: "delegates", label: "Delegates" }, { id: "approvals", label: "Approvals" }, { id: "recovery", label: "Recovery" }, { id: "review", label: "Review" }
    ]);
    function kasDraftDefaults(connectedAddress, currentDaa = null) {
      return { label: "", depositKas: "", feeReserveKas: "1", agents: [agentRowFrom(null, currentDaa)], approvers: [], approvalM: "0", recoveryAddress: "", signerAddress: connectedAddress || "", currentDaa: currentDaa === null || currentDaa === undefined ? null : String(currentDaa) };
    }
    function kasRulesSummary(d, orgRoot) {
      const out = [];
      const n = orgRoot && Array.isArray(orgRoot.slots) ? orgRoot.slots.length : null;
      const m = orgRoot && orgRoot.state ? orgRoot.state.ownerM : null;
      out.push(`This treasury is OWNED by the organization's root: ${m !== null && n !== null ? `${m} of ${n} owners` : "the root's owner quorum"} must approve every owner operation (rules, approvers, funding, pause, recovery). It has no owner key of its own.`);
      const dep = String(d.depositKas || "").trim(), res = String(d.feeReserveKas || "").trim();
      out.push(`${dep || "?"} KAS is locked as protected principal and ${res || "?"} KAS as fee reserve (pays delegates' network fees). Only the creation transaction's exact network fee leaves your wallet on top.`);
      const agents = (d.agents || []).filter((r) => r && String(r.agentKey || "").trim());
      out.push(agents.length ? `${agents.length} delegate${agents.length === 1 ? "" : "s"} may pay within their rules (cap per payment, budget per period, allowed recipients).` : "No delegates yet: nobody can pay from the treasury until the owners install rules.");
      const approvers = (d.approvers || []).filter((r) => r && (String(r.address || "").trim() || String(r.publicKey || "").trim()));
      out.push(approvers.length ? `Payments above a delegate's threshold need ${d.approvalM || "?"} of ${approvers.length} approver${approvers.length === 1 ? "" : "s"} to co-sign — a separate tier from the root's owners.` : "No approvers: a delegate's own signature is enough for every payment within its rules.");
      out.push(`Emergency: any ${orgRoot && orgRoot.state ? orgRoot.state.emergencyK : "K"} owner(s) can emergency-pause this treasury (freezing the root); ${m !== null && n !== null ? `${m} of ${n}` : "the full quorum"} unfreeze.`);
      out.push(`Recovery is IRREVERSIBLE: closing the treasury pays its ENTIRE balance to ${String(d.recoveryAddress || "").trim() || "the recovery wallet you choose"} — pinned at creation, changeable by no one.`);
      return out;
    }
    async function validateKasDraft(d, { resolve, step, connectedAddress } = {}) {
      const errors = new Map();
      const bad = (k, msg) => { if (!errors.has(k)) errors.set(k, msg); };
      const v = (x) => String(x ?? "").trim();
      const only = (s) => step === undefined || step === s;
      let protectedSompi = null, feeReserveSompi = null;
      if (only("treasury")) {
        if (v(d.label).length > 120) bad("label", "The name is too long (120 characters at most).");
        try { protectedSompi = BigInt(kasToSompi(d.depositKas, "deposit")); if (protectedSompi <= 0n) bad("depositKas", "Enter the amount to lock as protected principal: a KAS amount greater than 0."); } catch (e) { bad("depositKas", `Enter the protected principal in KAS: ${e.message}`); }
        try { feeReserveSompi = BigInt(kasToSompi(d.feeReserveKas, "fee reserve")); if (feeReserveSompi < 0n) bad("feeReserveKas", "The fee reserve cannot be negative."); } catch (e) { bad("feeReserveKas", `Enter the fee reserve in KAS (0 or more): ${e.message}`); }
      }
      let agents = null;
      if (only("delegates")) {
        const rows = (Array.isArray(d.agents) ? d.agents : []).filter((r) => r && (v(r.agentKey) || v(r.recipients) || v(r.maxPerSpendKas)));
        const res = await validateAgentRows(rows);
        if (res.listError) bad("agents", res.listError);
        if (Object.keys(res.rowErrors).length) { bad("agents", "Fix the highlighted delegate rows."); errors.set("agentRows", res.rowErrors); }
        agents = res.agents;
      }
      let approverKeys = null, approvalM = null;
      if (only("approvals")) {
        const res = await validateApproverRows(d.approvers, d.approvalM);
        if (res.listError) bad("approvers", res.listError);
        if (Object.keys(res.rowErrors).length) { bad("approvers", "Fix the highlighted approver rows."); errors.set("approverRows", res.rowErrors); }
        if (res.mError) bad("approvalM", res.mError);
        approverKeys = res.keys; approvalM = res.approvalM;
      }
      let recoveryPk = null;
      if (only("recovery")) {
        if (!v(d.recoveryAddress)) bad("recoveryAddress", "Enter the recovery wallet: the ONLY destination a closed treasury can ever pay to.");
        else { try { recoveryPk = await (resolve ? resolve(v(d.recoveryAddress)) : resolveXOnlyKey(v(d.recoveryAddress), "Recovery wallet")); recoveryPk = String(recoveryPk).toLowerCase(); if (!HEX64.test(recoveryPk)) bad("recoveryAddress", "The recovery wallet did not resolve to a public key."); } catch (e) { bad("recoveryAddress", `Recovery wallet rejected: ${e.message}`); } }
      }
      if (only("review")) {
        if (!v(d.signerAddress)) bad("signerAddress", "Connect the wallet that will fund this treasury.");
        else if (connectedAddress && v(d.signerAddress) !== connectedAddress) bad("signerAddress", "The funding wallet must be the connected wallet — it signs the creation transaction.");
      }
      if (errors.size || step !== undefined) return { ok: errors.size === 0, errors, form: null, norm: null };
      const norm = { label: v(d.label), protectedSompi, feeReserveSompi, agents, agentRoot: agentRoot(agents), approvers: approverKeys, approvalM, recoveryPk };
      const form = { label: v(d.label), agents: agents.map((a) => ({ ...a })), approvers: [...approverKeys], approvalM, recoveryAddress: v(d.recoveryAddress), depositKas: sompiToKas(protectedSompi), feeReserveKas: sompiToKas(feeReserveSompi), signerAddress: v(d.signerAddress) };
      return { ok: true, errors, form, norm };
    }
    function renderKasSetupHtml({ draft, step, errors, connectedAddress, busy, orgRoot, network }) {
      const SUI = requireSetup("renderKasSetupHtml");
      const d = draft;
      const err = (k) => (errors && errors.get(k)) || "";
      const F = SUI.renderField;
      const hidden = (i) => (i === step ? "" : " hidden");
      const panel = (i, inner) => `<section class="setup-step" data-setup-step="${KAS_STEPS[i].id}"${hidden(i)}><h3>${esc(KAS_STEPS[i].label)}</h3>${inner}${SUI.renderNav({ index: i, total: KAS_STEPS.length, finalLabel: "Build the exact transaction & review", cancelLabel: "Cancel", busy })}</section>`;
      const treasury =
        `<div class="f-help">${esc(OWNERSHIP_STATEMENT)}</div>` +
        F({ name: "label", label: "Name", control: SUI.textInput({ name: "label", value: d.label, placeholder: "Operations treasury", maxlength: 120 }), help: "A label for this app only.", error: err("label"), optional: true }) +
        F({ name: "depositKas", label: "Protected principal", control: SUI.kasInput({ name: "depositKas", value: d.depositKas, placeholder: "1000" }), help: "KAS locked under the treasury's rules — what delegates may pay out. Owners can add more later (Add funds).", error: err("depositKas") }) +
        F({ name: "feeReserveKas", label: "Fee reserve", control: SUI.kasInput({ name: "feeReserveKas", value: d.feeReserveKas, placeholder: "1" }), help: "Pays the network fee of each delegate payment (a few thousandths of a KAS each) so delegates need no KAS of their own. Owners can top it up later.", error: err("feeReserveKas") }) +
        `<div class="f f-wide"><div class="f-label">Wallet funding this treasury</div><div class="addr-display"><span class="mono">${esc(connectedAddress || "")}</span> <span class="badge ver">Connected wallet</span></div><div class="f-help">This wallet pays the principal, the reserve and the creation fee, and signs the creation transaction. ${esc(network || "")}</div></div>`;
      const delegates =
        `<div class="f-help">Delegates (people or AI agents) may pay from the treasury ONLY within these rules, enforced by the covenant. You can start without delegates and let the owners install rules later.</div>` +
        renderAgentRowsHtml({ rows: Array.isArray(d.agents) ? d.agents : [], rowErrors: (errors && errors.get("agentRows")) || {}, listError: err("agents"), currentDaa: d.currentDaa });
      const approvals = renderApproverRowsHtml({ rows: d.approvers, rowErrors: (errors && errors.get("approverRows")) || {}, approvalM: d.approvalM, mError: err("approvalM"), listError: err("approvers") }) +
        SUI.renderLiveSummary(kasRulesSummary(d, orgRoot), "v4-kas-summary");
      const recovery =
        `<div class="opbanner bad" role="status"><b>Irreversible recovery</b><div style="margin-top:0.3rem">If the owners ever close this treasury, its ENTIRE balance — protected principal and fee reserve — is paid to this wallet and to nothing else. The destination is pinned into the covenant at creation: no owner, no delegate, no server and no PolicyVault update can change it. Choose a wallet you control and will keep.</div></div>` +
        F({ name: "recoveryAddress", label: "Recovery wallet", control: SUI.textInput({ name: "recoveryAddress", value: d.recoveryAddress, mono: true, placeholder: "kaspa… (a wallet you keep)" }), error: err("recoveryAddress") });
      const review = `<div id="v4-kas-review">${renderKasDraftReviewHtml({ draft: d, connectedAddress, orgRoot })}</div>` +
        `<div class="f-help">The next screen shows the exact treasury PolicyVault built, checked value by value against these rules, before your wallet is asked to sign.</div>` +
        `<div class="ferr" data-err="signerAddress"${err("signerAddress") ? ' style="display:block"' : ""}>${esc(err("signerAddress"))}</div>`;
      return (
        `<h3 id="v4-kas-title" style="margin-top:0">Create KAS treasury</h3>` +
        `<div class="f-help">A native-KAS treasury owned by ${esc(orgRoot && orgRoot.label ? orgRoot.label : "this organizational root")} — the root's ${esc(String(orgRoot && orgRoot.state ? orgRoot.state.ownerM : "M"))} of ${esc(String(orgRoot && orgRoot.slots ? orgRoot.slots.length : "N"))} owners control it together. Candidate covenant profile (policyvault-0.7-kas).</div>` +
        SUI.renderStepper({ steps: KAS_STEPS, current: step }) +
        `<form class="setup-form" data-kas-wizard autocomplete="off" novalidate>` +
        panel(0, treasury) + panel(1, delegates) + panel(2, approvals) + panel(3, recovery) + panel(4, review) +
        `</form>`
      );
    }
    function renderKasDraftReviewHtml({ draft: d, connectedAddress, orgRoot }) {
      const SUI = requireSetup("renderKasDraftReviewHtml");
      const v = (x) => (String(x ?? "").trim() || "—");
      const agents = (d.agents || []).filter((r) => r && String(r.agentKey || "").trim());
      const approvers = (d.approvers || []).filter((r) => r && (String(r.address || "").trim() || String(r.publicKey || "").trim()));
      return (
        SUI.renderReviewSection({ title: "Treasury", editStep: 0, rows: [["Name", v(d.label)], ["Protected principal", `${v(d.depositKas)} KAS`], ["Fee reserve", `${v(d.feeReserveKas)} KAS`], ["Funding wallet", v(connectedAddress)]] }) +
        SUI.renderReviewSection({ title: "Delegates", editStep: 1, rows: agents.length ? agents.map((r, i) => [`Delegate ${i + 1}`, `${v(r.agentKey)} — up to ${v(r.maxPerSpendKas)} KAS per payment, ${v(r.periodBudgetKas)} KAS per ${v(r.periodLengthDaa)} DAA, approvals above ${v(r.approvalThresholdKas)} KAS, ${String(r.recipients || "").split(/[\n,]/).filter((s) => s.trim()).length} recipient(s)`]) : [["Delegates", "none yet — the owners can install rules later"]] }) +
        SUI.renderReviewSection({ title: "Approvals", editStep: 2, rows: [["Approvers", approvers.length ? approvers.map((r) => v(r.publicKey || r.address)).join(", ") : "none"], ["Needed above a threshold", approvers.length ? `${v(d.approvalM)} of ${approvers.length}` : "—"]] }) +
        SUI.renderReviewSection({ title: "Recovery (irreversible)", editStep: 3, rows: [["Recovery wallet", v(d.recoveryAddress)]] }) +
        SUI.renderLiveSummary(kasRulesSummary(d, orgRoot), "v4-kas-summary-review")
      );
    }
    async function createKasVaultRequest(rootId, form) {
      const { request } = await api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/vaults`, { ...form, profile: PROFILE });
      return request;
    }
    /* Snapshot the selected root BEFORE the asynchronous creation request. Derive its
     * immutable template identity from the frozen root definition and reviewed rules;
     * never accept pins supplied by the treasury creation response. */
    function kasRootPinsForReview(orgRoot) {
      if (!orgRoot || !HEX64.test(String(orgRoot.rootCovenantId || "")) ||
          !["mainnet", "testnet-10"].includes(orgRoot.networkId) || !orgRoot.template || !orgRoot.state) {
        throw fail("The selected organizational root has no complete reviewable identity — reopen its details.", "REVIEW_MISSING");
      }
      const template = { ...orgRoot.template, orgId: orgRoot.orgId };
      const script = core.rootScriptV7.reconstructRootScriptHexV7({ template, state: orgRoot.state });
      const prefix = core.rootScriptV7.ROOT_SCRIPT_PREFIX_HEX_V7;
      const stateLen = core.vaultStateV7Root.ROOT_STATE_LEN_V7;
      const suffix = script.slice(prefix.length + stateLen * 2);
      const bytes = (hex) => Uint8Array.from(hex.match(/../g) || [], (b) => parseInt(b, 16));
      return Object.freeze({
        orgRootCovenantId: orgRoot.rootCovenantId.toLowerCase(), networkId: orgRoot.networkId,
        rootPrefixLen: prefix.length / 2, rootStateLen: stateLen, rootSuffixLen: suffix.length / 2,
        rootTemplateVmHash: core.assets.blake2b.blake2bHex([bytes(prefix), bytes(suffix)], 32)
      });
    }
    /* the SERVER's genesis summary vs the LOCALLY normalized intent — a mismatch refuses signing */
    function genesisCrossCheck({ summary, norm }) {
      const mismatches = [];
      if (!summary || summary.kind !== "genesis-summary" || summary.contractVersion !== PROFILE) return { ok: false, mismatches: ["the server did not return a KAS treasury genesis summary"] };
      if (!norm || !norm.rootPins || !HEX64.test(String(norm.rootPins.orgRootCovenantId || "")) || !HEX64.test(String(norm.rootPins.rootTemplateVmHash || "")) || norm.rootPins.rootStateLen !== core.vaultStateV7Root.ROOT_STATE_LEN_V7) {
        return { ok: false, mismatches: ["the selected root's independently reviewed identity is missing"] };
      }
      const st = summary.initialState || {};
      const cmp = (label, a, b) => { if (String(a) !== String(b)) mismatches.push(`${label}: server ${a}, reviewed ${b}`); };
      cmp("root network", summary.networkId, norm.rootPins.networkId);
      cmp("owning root", summary.orgRootCovenantId, norm.rootPins.orgRootCovenantId);
      for (const key of ["orgRootCovenantId", "rootTemplateVmHash", "rootPrefixLen", "rootStateLen", "rootSuffixLen"]) {
        cmp(`root template ${key}`, summary.template && summary.template[key], norm.rootPins[key]);
      }
      cmp("protected principal (sompi)", st.protectedValue, norm.protectedSompi.toString());
      cmp("fee reserve (sompi)", st.feeReserve, norm.feeReserveSompi.toString());
      cmp("paused", st.paused, "0");
      cmp("policy nonce", st.policyNonce, "0");
      cmp("delegate rules root", String(st.agentRoot || "").toLowerCase(), norm.agentRoot);
      cmp("required approvals", st.approvalM, norm.approvalM);
      const slots = (Array.isArray(st.approverSlots) ? st.approverSlots : []).filter((k) => k !== SENTINEL).map((k) => String(k).toLowerCase()).sort();
      const local = [...norm.approvers].map((k) => k.toLowerCase()).sort();
      if (slots.join(",") !== local.join(",")) mismatches.push("approver set differs from the reviewed approvers");
      cmp("recovery key", String(summary.recoveryPk || "").toLowerCase(), norm.recoveryPk);
      cmp("recovery key (template)", String(summary.template && summary.template.recoveryPk || "").toLowerCase(), norm.recoveryPk);
      cmp("vault id (template)", String(summary.template && summary.template.vaultId || "").toLowerCase(), String(summary.vaultId || "").toLowerCase());
      const sa = Array.isArray(summary.agents) ? summary.agents : [];
      if (sa.length !== norm.agents.length) mismatches.push(`delegate count: server ${sa.length}, reviewed ${norm.agents.length}`);
      const byPk = new Map(norm.agents.map((a) => [a.agentPk, a]));
      for (const a of sa) {
        const l = byPk.get(String(a.agentPk).toLowerCase());
        if (!l) { mismatches.push(`delegate ${short(a.agentPk)} was not reviewed`); continue; }
        for (const f of ["maxPerSpend", "periodBudget", "periodLengthDaa", "periodStartDaa", "periodSpent", "approvalThreshold", "agentMaxFeePerTx", "agentRecipientRoot"]) cmp(`delegate ${short(a.agentPk)} ${f}`, a[f], l[f]);
        const sr = (Array.isArray(a.recipients) ? a.recipients : []).map((r) => String(r).toLowerCase()).sort().join(","), lr = [...l.recipients].sort().join(",");
        if (sr !== lr) mismatches.push(`delegate ${short(a.agentPk)} recipients differ from the reviewed list`);
      }
      if (summary.depositKas !== undefined) cmp("protected principal (KAS)", summary.depositKas, sompiToKas(norm.protectedSompi));
      if (summary.feeReserveKas !== undefined) cmp("fee reserve (KAS)", summary.feeReserveKas, sompiToKas(norm.feeReserveSompi));
      return { ok: mismatches.length === 0, mismatches };
    }
    function renderKasGenesisReviewHtml({ norm, summary, crossCheck, connectedAddress }) {
      const SUI = requireSetup("renderKasGenesisReviewHtml");
      const ok = crossCheck && crossCheck.ok;
      const st = (summary && summary.initialState) || {};
      const agents = Array.isArray(summary && summary.agents) ? summary.agents : [];
      const approvers = (Array.isArray(st.approverSlots) ? st.approverSlots : []).filter((k) => k !== SENTINEL);
      return (
        statusRegion(ok ? `<b>VERIFIED — the built treasury matches the rules you reviewed, value for value.</b>` : `<b>DO NOT SIGN — the built treasury does not match the reviewed rules:</b> ${(crossCheck && crossCheck.mismatches || []).map(esc).join("; ")}`, ok ? "" : "bad") +
        `<div class="f-help">${esc(OWNERSHIP_STATEMENT)}</div>` +
        SUI.renderReviewSection({ title: "What your wallet will sign", rows: [
          ["Protected principal", `${esc(sompiToKas(st.protectedValue || "0"))} KAS`],
          ["Fee reserve", `${esc(sompiToKas(st.feeReserve || "0"))} KAS`],
          ["Creation network fee", `${esc(sompiToKas(summary.requiredFeeSompi || "0"))} KAS (exact, from your wallet)`],
          ["Delegates", agents.length ? agents.map((a) => `${short(a.agentPk)}: ≤${sompiToKas(a.maxPerSpend)} KAS/payment, ${sompiToKas(a.periodBudget)} KAS/${a.periodLengthDaa} DAA, approvals above ${sompiToKas(a.approvalThreshold)} KAS, ${a.recipients.length} recipient(s)`).join(" · ") : "none"],
          ["Approvals", approvers.length ? `${st.approvalM} of ${approvers.length}: ${approvers.map(short).join(", ")}` : "none"],
          ["Recovery key (irreversible destination)", String(summary.recoveryPk || "")],
          ["Owned by root", String(summary.orgRootCovenantId || "")],
          ["Treasury id", String(summary.vaultId || "")],
          ["Transaction id", String(summary.txId || "")],
          ["Funding wallet", String(connectedAddress || "")]
        ] }) +
        `<div class="f-help">Your wallet signs the funding inputs only. The treasury output's locking script is rebuilt locally from these rules and must match before the wallet is invoked; a substituted destination refuses.</div>`
      );
    }
    function bindKasGenesisSigningPayload({ request, unsignedSafeJson, signInputs, network, connectedXOnly, crossCheck, norm }) {
      const P = requirePayload("bindKasGenesisSigningPayload");
      const refuse = (msg, code) => { throw fail(`${msg} — refusing to invoke the wallet`, code || "SIGNING_BINDING_REFUSED"); };
      if (!request || request.kind !== "kasGenesis") refuse("not a KAS treasury creation request", "REQUEST_NOT_SIGNABLE");
      const sum = request.summary;
      if (!sum || sum.kind !== "genesis-summary" || sum.contractVersion !== PROFILE) refuse("the request carries no KAS genesis summary to bind the transaction to", "REVIEW_MISSING");
      if (!crossCheck || crossCheck.ok !== true) refuse(`the reviewed rules do not match PolicyVault's description of this treasury (${crossCheck && Array.isArray(crossCheck.mismatches) ? crossCheck.mismatches.join("; ") : "no cross-check"})`, "REVIEW_REFUSED");
      if (!norm || typeof norm.protectedSompi !== "bigint") refuse("the reviewed rules are not available to rebuild the treasury script", "REVIEW_MISSING");
      const currentReview = genesisCrossCheck({ summary: sum, norm });
      if (!currentReview.ok) refuse(`the current transaction no longer matches the selected root and reviewed rules (${currentReview.mismatches.join("; ")})`, "REVIEW_REFUSED");
      const xonly = String(connectedXOnly || "").toLowerCase();
      if (!HEX64.test(xonly)) refuse("the connected wallet's public key is unknown", "WALLET_NOT_READY");
      const safe = P.parseSigningPayload(unsignedSafeJson);
      const list = Array.isArray(signInputs) ? signInputs.map((x) => Number(x && x.index)) : null;
      if (!list || !list.length || list.some((i) => !Number.isInteger(i) || i < 0 || i >= safe.inputs.length) || new Set(list).size !== list.length) refuse("the inputs to sign are missing, repeated or outside the transaction", "PAYLOAD_INVALID");
      if (String(sum.networkId) !== String(network)) refuse(`this transaction is for ${sum.networkId}, the wallet is on ${network}`, "NETWORK_MISMATCH");
      if (!HEX64.test(String(sum.txId || "").toLowerCase()) || safe.id !== String(sum.txId).toLowerCase()) refuse("the signing payload is not the transaction the review described (transaction id differs)", "PAYLOAD_MISMATCH");
      if (typeof sum.requiredFeeSompi !== "string" || !DIGITS.test(sum.requiredFeeSompi)) refuse("the genesis summary carries no exact network fee", "REVIEW_MISSING");
      if (safe.fee !== BigInt(sum.requiredFeeSompi)) refuse(`the network fee ${sompiToKas(safe.fee)} KAS differs from the reviewed ${sompiToKas(sum.requiredFeeSompi)} KAS`, "FEE_MISMATCH");
      if (request.transaction && typeof request.transaction.frozenCanonicalJson === "string") { const mism = P.frozenMismatches(request.transaction.frozenCanonicalJson, safe); if (mism.length) refuse(`the signing payload differs from the built transaction: ${mism.join("; ")}`, "PAYLOAD_MISMATCH"); }
      if (safe.lockTime !== "0") refuse("the transaction carries a lock time — a treasury creation never does", "PAYLOAD_MISMATCH");
      const out0 = safe.outputs[0];
      if (!isP2shWire(out0.spk)) refuse("output 0 is not a covenant (P2SH) treasury output", "PAYLOAD_MISMATCH");
      if (out0.value !== norm.protectedSompi + norm.feeReserveSompi) refuse(`the treasury output carries ${sompiToKas(out0.value)} KAS, the review says ${sompiToKas(norm.protectedSompi + norm.feeReserveSompi)} KAS`, "PAYLOAD_MISMATCH");
      /* the treasury's locking script is REBUILT LOCALLY from the reviewed rules (candidate v0.7-kas skeleton, proven against the compiler); its P2SH must be the destination */
      let expectedSpk = null;
      try { expectedSpk = "0000" + core.vaultScriptV7Kas.reconstructVaultScriptSpkHexV7Kas({ template: sum.template, state: sum.initialState }); } catch (e) { refuse(`the treasury script could not be rebuilt from the reviewed rules (${e.message})`, "REVIEW_REFUSED"); }
      if (out0.spk !== expectedSpk) refuse("the treasury output's locking script is NOT the script of the rules you reviewed — the transaction would lock the funds under different rules", "PAYLOAD_MISMATCH");
      if (!HEX64.test(String(sum.covenantId || "").toLowerCase())) refuse("the genesis summary carries no covenant id", "REVIEW_MISSING");
      if (!out0.covenant || out0.covenant.covenantId !== String(sum.covenantId).toLowerCase() || out0.covenant.authorizingInput !== 0) refuse("the treasury output's covenant identity differs from the reviewed one", "PAYLOAD_MISMATCH");
      safe.outputs.slice(1).forEach((o, n) => { if (o.spk !== p2pkWire(xonly) || o.covenant) refuse(`output ${n + 1} does not return to your wallet`, "PAYLOAD_MISMATCH"); });
      if (safe.outputs.length > 2) refuse("a treasury creation has at most one change output", "PAYLOAD_MISMATCH");
      const ordinary = core.computeBudgetV7Kas && core.computeBudgetV7Kas.V7_KAS_BUDGET ? core.computeBudgetV7Kas.V7_KAS_BUDGET.ORDINARY_INPUT : null;
      safe.inputs.forEach((i, n) => {
        if (i.spk !== p2pkWire(xonly) || i.covenantId !== null) refuse(`funding input ${n} is not your wallet's — the funder signs only its own funds`, "PAYLOAD_MISMATCH");
        if (i.sequence !== "0") refuse(`funding input ${n} carries sequence ${i.sequence} — a funding input is never relatively locked`, "PAYLOAD_MISMATCH");
        if (Number.isInteger(ordinary) && i.computeBudget !== ordinary) refuse(`funding input ${n} commits compute budget ${i.computeBudget}; an ordinary input commits exactly ${ordinary}`, "PAYLOAD_MISMATCH");
      });
      if (list.length !== safe.inputs.length) refuse("the wallet must sign every funding input of the creation", "PAYLOAD_MISMATCH");
      return Object.freeze({ ok: true, role: "genesis", txId: safe.id, feeSompi: safe.fee.toString(), vaultSpk: expectedSpk });
    }
    async function signKasGenesisRequest({ request, adapter, network, expectedSignerAddress, connectedXOnly, crossCheck, norm, isCurrent = () => true }) {
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      if (!isCurrent()) throw fail("treasury review was interrupted", "REVIEW_INTERRUPTED");
      const t = request.transaction || {};
      bindKasGenesisSigningPayload({ request, unsignedSafeJson: t.unsignedSafeJson, signInputs: t.signInputs, network, connectedXOnly, crossCheck, norm });
      const signed = await adapter.signInputs(t.unsignedSafeJson, t.signInputs, { network, expectedSignerAddress });
      if (!isCurrent()) throw fail("treasury review was interrupted while the wallet was open; signature was not uploaded", "REVIEW_INTERRUPTED");
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/v7/requests/${encodeURIComponent(request.requestId)}/signature`, { signedSafeJson: signed });
    }
    const submitKasRequest = (requestId) => api.postJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}/submit`, {});
    const rejectKasRequest = (requestId) => api.postJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}/reject`, {});
    const fetchKasRequests = async (vaultId) => { const { requests } = await api.getJSON(vaultId === undefined ? "/wallet/v7/requests" : `/wallet/v7/requests?vaultId=${encodeURIComponent(vaultId)}`); return (Array.isArray(requests) ? requests : []).filter((r) => r && r.contractVersion === PROFILE); };
    const fetchKasRequest = async (requestId) => { const { request } = await api.getJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}`); if (!request || request.requestId !== requestId) throw fail("the returned treasury request does not match the requested identity", "REQUEST_MISMATCH"); return request; };
    const fetchParticipantVaults = async () => { const { vaults } = await api.getJSON("/wallet/v7/vaults"); return Array.isArray(vaults) ? vaults : []; };

    /* ================================================================
     * DELEGATE PAYMENT (agent) + APPROVAL (vault-level tier)
     * ================================================================ */
    function spendDraftFrom({ vault, viewerXOnly } = {}) {
      const me = agentEntryFor(vault, viewerXOnly);
      const recipients = me && Array.isArray(me.recipients) ? me.recipients : [];
      return { amountKas: "", recipient: recipients.length ? String(recipients[0]) : "", recipientAddress: "" };
    }
    async function validateSpendDraft({ draft, vault, viewerXOnly } = {}) {
      const errors = new Map();
      const d = draft || {};
      const me = agentEntryFor(vault, viewerXOnly);
      if (!me) { errors.set("agent", "The connected wallet is not a delegate of this treasury — nothing can be built."); return { ok: false, errors, params: null, preview: null }; }
      let pay = null;
      try { pay = BigInt(kasToSompi(d.amountKas, "amount")); if (pay <= 0n) errors.set("amountKas", "Enter a KAS amount greater than 0."); } catch (e) { errors.set("amountKas", `Enter the amount in KAS: ${e.message}`); }
      const allow = (Array.isArray(me.recipients) ? me.recipients : []).map((r) => String(r).toLowerCase());
      let recipient = String(d.recipient || "").trim().toLowerCase();
      if (String(d.recipientAddress || "").trim()) { try { recipient = await resolveXOnlyKey(d.recipientAddress, "Recipient", "RECIPIENT_NOT_ALLOWED"); } catch (e) { errors.set("recipient", e.message); } }
      if (!errors.has("recipient")) { if (!HEX64.test(recipient)) errors.set("recipient", "Choose one of this delegate's allowed recipients."); else if (!allow.includes(recipient)) errors.set("recipient", "That destination is not on this delegate's allowed-recipient list — the covenant would refuse it."); }
      if (pay !== null && !errors.has("amountKas")) {
        if (pay > BigInt(me.maxPerSpend)) errors.set("amountKas", `Above this delegate's cap of ${sompiToKas(me.maxPerSpend)} KAS per payment.`);
        const remaining = BigInt(me.periodBudget) - BigInt(me.periodSpent);
        if (pay > remaining) errors.set("amountKas", `Above the remaining budget of ${sompiToKas(remaining < 0n ? 0n : remaining)} KAS for this period (the budget resets when the period ends).`);
      }
      if (errors.size) return { ok: false, errors, params: null, preview: null };
      const above = pay > BigInt(me.approvalThreshold);
      return { ok: true, errors, params: { payAmountSompi: pay.toString(), recipient }, preview: { aboveThreshold: above, approvalsRequired: above ? Number(vault.approvalM || 0) : 0, approverCount: (Array.isArray(vault.approvers) ? vault.approvers : []).length, amountKas: sompiToKas(pay), recipient } };
    }
    function renderSpendFormHtml({ vault, draft, errors, connectedAddress, viewerXOnly } = {}) {
      const SUI = requireSetup("renderSpendFormHtml");
      const F = SUI.renderField;
      const err = (k) => (errors && errors.get(k)) || "";
      const v = vault || {};
      const me = agentEntryFor(v, viewerXOnly);
      if (!me) return statusRegion("The connected wallet is not a delegate of this treasury.", "bad");
      const recipients = Array.isArray(me.recipients) ? me.recipients : [];
      const remaining = BigInt(me.periodBudget) - BigInt(me.periodSpent);
      return (
        `<h3 id="v4-kasspend-title" style="margin-top:0">Pay from ${esc(v.label || short(v.vaultId))}</h3>` +
        `<div class="f-help">Your rule: up to ${esc(sompiToKas(me.maxPerSpend))} KAS per payment, ${esc(sompiToKas(remaining < 0n ? 0n : remaining))} KAS left in this ${esc(String(me.periodLengthDaa))}-DAA period. Payments above ${esc(sompiToKas(me.approvalThreshold))} KAS need ${esc(String(v.approvalM ?? "?"))} of ${(Array.isArray(v.approvers) ? v.approvers.length : 0)} approver(s). The network fee comes from the treasury's reserve (cap ${esc(sompiToKas(me.agentMaxFeePerTx))} KAS).</div>` +
        `<form class="setup-form" data-kasspend-form="${esc(v.vaultId)}" autocomplete="off" novalidate>` +
        F({ name: "amountKas", label: "Amount (KAS)", control: SUI.kasInput({ name: "amountKas", value: draft && draft.amountKas, placeholder: "1" }), error: err("amountKas") }) +
        F({ name: "recipient", label: "Recipient (your allowed list)", control: SUI.select({ name: "recipient", options: recipients.map((r) => ({ value: String(r), label: short(r) })), value: draft && draft.recipient }), help: "Only these destinations are allowed by the covenant.", error: err("recipient") }) +
        `<div class="f-help">Started by <span class="mono">${esc(connectedAddress || "")}</span> (delegate). PolicyVault builds the exact transaction next; nothing is signed or sent on this screen.</div>` +
        `<div class="modal-actions"><button type="button" data-kasspend-cancel="1">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="primary">Build the exact payment &amp; review</button></div>` +
        `</form>`
      );
    }
    async function buildKasSpend({ vaultId, params, signerAddress }) {
      const { request } = await api.postJSON("/wallet/v7/requests", { vaultId, action: "agentSpend", params, signerAddress });
      return request;
    }
    function spendExplainArgs(request) {
      const covId = request && request.manifest && request.manifest.vault ? request.manifest.vault.covenantId : null;
      const redeemHex = request && request.redeemScripts && typeof request.redeemScripts === "object" && covId ? request.redeemScripts[covId] : null;
      return { manifest: request && request.manifest, frozen: request && request.transaction ? request.transaction.frozenCanonicalJson : null, redeemHex };
    }
    function renderSpendReviewHtml(request) {
      if (!request || !request.manifest) return statusRegion("No manifest is attached to this payment yet — refusing to render a review. Do not sign.", "bad");
      const args = spendExplainArgs(request);
      const doc = EX.structuredSpend(args);
      const lines = EX.humanReadableSpend(args);
      const verified = doc.verdict === "VERIFIED_EXACT";
      const lineDivs = lines.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      return `<div class="${verified ? "opbanner" : "opbanner bad"}" data-kas-spend-review="${verified ? "verified" : "refused"}" role="status" aria-live="polite" aria-atomic="true" style="border-width:2px"><b style="color:${verified ? "var(--good)" : "var(--bad)"}">${verified ? "VERIFIED — EXACT PAYMENT BEFORE SIGNING" : "DO NOT SIGN — LOCAL VERIFICATION REFUSED"}</b><div style="margin-top:0.4rem;font-size:0.8rem;max-height:18rem;overflow:auto">${lineDivs}</div></div>`;
    }
    function bindKasSpendSigningPayload({ role, request, unsignedSafeJson, signInputs, network, connectedXOnly }) {
      const P = requirePayload("bindKasSpendSigningPayload");
      const refuse = (msg, code) => { throw fail(`${msg} — refusing to invoke the wallet`, code || "SIGNING_BINDING_REFUSED"); };
      if (!request || request.kind !== "agentSpend" || !request.manifest) refuse("not a delegate payment request with a manifest", "REQUEST_NOT_SIGNABLE");
      const xonly = String(connectedXOnly || "").toLowerCase();
      if (!HEX64.test(xonly)) refuse("the connected wallet's public key is unknown", "WALLET_NOT_READY");
      const doc = EX.structuredSpend(spendExplainArgs(request));
      if (doc.verdict !== "VERIFIED_EXACT") refuse(`local verification refused this payment (${(doc.refusal && doc.refusal.failingChecks || []).join(", ") || "no verdict"})`, "REVIEW_REFUSED");
      const manifest = request.manifest;
      if (String(manifest.network && manifest.network.networkId) !== String(network)) refuse(`this transaction is for ${manifest.network && manifest.network.networkId}, the wallet is on ${network}`, "NETWORK_MISMATCH");
      const safe = P.parseSigningPayload(unsignedSafeJson);
      if (safe.id !== String(manifest.transaction.txId || "").toLowerCase()) refuse("the signing payload is not the reviewed transaction (transaction id differs)", "PAYLOAD_MISMATCH");
      const mism = P.frozenMismatches(request.transaction.frozenCanonicalJson, safe);
      if (mism.length) refuse(`the signing payload differs from the reviewed transaction: ${mism.join("; ")}`, "PAYLOAD_MISMATCH");
      const list = Array.isArray(signInputs) ? signInputs.map((x) => Number(x && x.index)) : null;
      if (!list || !list.length || list.some((i) => !Number.isInteger(i) || i < 0 || i >= safe.inputs.length) || new Set(list).size !== list.length) refuse("the inputs to sign are missing, repeated or outside the transaction", "PAYLOAD_INVALID");
      const covIdx = Number(request.transaction.covenantInputIndex ?? 0);
      if (!isP2shWire(safe.inputs[covIdx].spk)) refuse("the treasury input is not a covenant (P2SH) input", "PAYLOAD_MISMATCH");
      if (role === "agent") {
        if (String(manifest.policy.agentPolicy.agentPk).toLowerCase() !== xonly) refuse("the connected wallet is not the delegate this payment was built for", "NOT_THE_SIGNER");
        if (!list.includes(covIdx)) refuse("the delegate must sign the treasury input", "PAYLOAD_MISMATCH");
        safe.inputs.forEach((i, n) => { if (n !== covIdx && (i.spk !== p2pkWire(xonly) || i.covenantId !== null)) refuse(`input ${n} is neither the treasury input nor your own funds`, "PAYLOAD_MISMATCH"); });
        if (list.length !== safe.inputs.length) refuse("the delegate signs every input of its payment", "PAYLOAD_MISMATCH");
        if (manifest.approverTier && manifest.approverTier.aboveThreshold === true && request.state !== "BUILT") refuse(`approvals are still being collected (${request.state})`, "INSUFFICIENT_APPROVALS");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString() });
      }
      if (role === "approver") {
        const tier = manifest.approverTier;
        if (!tier || tier.aboveThreshold !== true) refuse("this payment is within the delegate's rules — it needs no approval", "NOT_AN_APPROVER");
        if (!(Array.isArray(tier.activeApprovers) ? tier.activeApprovers : []).some((k) => String(k).toLowerCase() === xonly)) refuse("the connected wallet is not one of this treasury's approvers", "NOT_AN_APPROVER");
        if (list.length !== 1 || list[0] !== covIdx) refuse("an approver signs the treasury input only", "PAYLOAD_MISMATCH");
        if (request.state !== "AWAITING_APPROVALS") refuse(`this payment is ${request.state} — approvals are collected only while it awaits them`, "REQUEST_NOT_SIGNABLE");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString() });
      }
      refuse(`unknown signing role ${role}`, "REQUEST_NOT_SIGNABLE");
    }
    async function signKasSpend({ request, adapter, network, expectedSignerAddress, connectedXOnly }) {
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const t = request.transaction || {};
      bindKasSpendSigningPayload({ role: "agent", request, unsignedSafeJson: t.unsignedSafeJson, signInputs: t.signInputs, network, connectedXOnly });
      const signed = await adapter.signInputs(t.unsignedSafeJson, t.signInputs, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/v7/requests/${encodeURIComponent(request.requestId)}/signature`, { signedSafeJson: signed });
    }
    async function approveKasSpend({ request, adapter, network, expectedSignerAddress, connectedXOnly }) {
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const t = request.transaction || {};
      const covIdx = Number(t.covenantInputIndex ?? 0);
      const entries = [{ index: covIdx, sighashType: 1 }];
      bindKasSpendSigningPayload({ role: "approver", request, unsignedSafeJson: t.unsignedSafeJson, signInputs: entries, network, connectedXOnly });
      const signed = await adapter.signInputs(t.unsignedSafeJson, entries, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/v7/requests/${encodeURIComponent(request.requestId)}/approvals`, { approverAddress: expectedSignerAddress, signedSafeJson: signed });
    }

    /* ================================================================
     * ROOT REQUESTS of the KAS family (owner operations) — review pieces
     * ================================================================ */
    function renderKasRootRequestReviewHtml(request) {
      if (!request || !request.manifest) return statusRegion("No manifest is attached to this request yet — refusing to render a review. Do not sign.", "bad");
      const redeemScripts = request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {};
      const doc = EX.structured({ manifest: request.manifest, redeemScripts });
      const lines = EX.humanReadable({ manifest: request.manifest, redeemScripts });
      const verified = doc.verdict === "VERIFIED_EXACT";
      const lineDivs = lines.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      return `<div class="${verified ? "opbanner" : "opbanner bad"}" data-org-root-review="${verified ? "verified" : "refused"}" data-kas-root-review="1" role="status" aria-live="polite" aria-atomic="true" style="border-width:2px"><b style="color:${verified ? "var(--good)" : "var(--bad)"}">${verified ? "VERIFIED — EXACT TREASURY OPERATION BEFORE SIGNING" : "DO NOT SIGN — LOCAL VERIFICATION REFUSED"}</b><div style="margin-top:0.4rem;font-size:0.8rem;max-height:18rem;overflow:auto">${lineDivs}</div></div>`;
    }
    function kasVaultOperationSummary(request) {
      if (!request || !request.manifest || !Array.isArray(request.manifest.vaultOperations) || !request.manifest.vaultOperations.length) return null;
      const redeemScripts = request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {};
      let doc;
      try { doc = EX.structured({ manifest: request.manifest, redeemScripts }); } catch (e) { return { ok: false, lines: [`the treasury operation could not be verified: ${e.message}`] }; }
      if (doc.verdict !== "VERIFIED_EXACT") return { ok: false, lines: [`the treasury operation FAILED verification (${(doc.refusal && doc.refusal.failingChecks || []).join(", ")}) — do not sign`] };
      const v = doc.vaultOperations[0];
      const lines = [];
      lines.push(`${vaultOpLabel(v.sdkAction)} on treasury ${v.vaultId}${v.summary ? ` — ${v.summary}` : ""}`);
      lines.push(`Authority: ${v.mutationClass}; requires the root to run ${v.requiredRootAction === null ? "no root action" : v.requiredRootAction}.`);
      lines.push(`Protected principal ${v.kas.protectedBefore.kas} KAS → ${v.kas.protectedAfter.kas} KAS · fee reserve ${v.kas.feeReserveBefore.kas} KAS → ${v.kas.feeReserveAfter.kas} KAS${v.kas.externalFunding.sompi !== "0" ? ` (funded ${v.kas.externalFunding.kas} KAS from the fee payer)` : ""}.`);
      if (v.approverTier.after && v.sdkAction === "ownerSetApprovers") lines.push(`Approvers after: ${v.approverTier.after.approvalM} of ${v.approverTier.after.approvers.length}${v.approverTier.after.approvers.length ? ` — ${v.approverTier.after.approvers.join(", ")}` : ""}.`);
      if (v.terminal) lines.push(`TERMINAL: this treasury is CLOSED; ${v.kas.terminalPayout.kas} KAS (its entire balance) is paid to the pinned recovery key ${v.recoveryPk}. Irreversible.`);
      if (v.agentSet !== null && v.agentSet !== undefined) {
        lines.push(v.agentSet.length ? `New delegate rules: ${v.agentSet.length} — the successor agent root is their Merkle root:` : "New delegate rules: EMPTY — after this operation no delegate can pay until a new set is installed.");
        for (const p of v.agentSet) lines.push(`delegate ${p.agentPk}: up to ${p.maxPerSpend.kas} KAS per payment, ${p.periodBudget.kas} KAS per ${p.periodLengthDaa} DAA, approvals above ${p.approvalThreshold.kas} KAS, fee cap ${p.agentMaxFeePerTx.kas} KAS, recipients: ${(p.recipients || []).join(", ")}`);
      }
      return { ok: true, sdkAction: v.sdkAction, vaultId: v.vaultId, terminal: !!v.terminal, lines };
    }

    return {
      PROFILE, OWNERSHIP_STATEMENT, KAS_STEPS, VAULT_OPS, VAULT_OP_ORDER, VAULT_OP_LABEL, MAX_AGENTS, MAX_APPROVERS,
      vaultOpInfo, vaultOpLabel, vaultOpConfirmPhrase, vaultOpConfirmationMatches, vaultOpDraftFrom, validateVaultOpDraft, renderVaultOpFormHtml, agentRowFrom,
      renderKasVaultPanelHtml, renderKasRequestCardHtml, renderParticipantVaultsHtml, agentEntryFor, isApproverOf,
      kasDraftDefaults, kasRulesSummary, validateKasDraft, renderKasSetupHtml, renderKasDraftReviewHtml, createKasVaultRequest, kasRootPinsForReview, genesisCrossCheck, renderKasGenesisReviewHtml, bindKasGenesisSigningPayload, signKasGenesisRequest,
      submitKasRequest, rejectKasRequest, fetchKasRequests, fetchKasRequest, fetchParticipantVaults,
      spendDraftFrom, validateSpendDraft, renderSpendFormHtml, buildKasSpend, renderSpendReviewHtml, bindKasSpendSigningPayload, signKasSpend, approveKasSpend,
      renderKasRootRequestReviewHtml, kasVaultOperationSummary,
      displayCodeFor
    };
  }

  const surface = { createModule, PROFILE, KAS_REFUSAL_CODES };
  if (typeof window !== "undefined") window.PolicyVaultKasVaultUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
