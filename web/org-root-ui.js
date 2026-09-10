"use strict";

/*
 * PolicyVault v0.7 ON-CHAIN ORGANIZATIONAL ROOT — web UI module (Wave 2,
 * Track B-web). Binding API contract:
 * docs/postlaunch/v0.7-app-surface-contract.md. Design record:
 * docs/postlaunch/v0.7-organizational-root-design.md.
 *
 * WHAT THIS MODULE IS. Same shape as web/org-controls-ui.js / governance-ui.js
 * / risk-ui.js: a headless, DOM-free `createModule({ api, core })` factory.
 * `api` is the network layer this app already uses ({ getJSON, postJSON,
 * resolveXOnly }); `core` is `window.PolicyVaultCore` (web/core-bundle.js) —
 * the SAME deterministic portable shared core the covenant, the SDK, and the
 * server agree with. Every funds-relevant computation in this file — owner-
 * set well-formedness, the 780-byte signature blob, the org-root intent
 * manifest and its LOCAL VERIFICATION, the signer-visible explanation, and
 * the slot signature extraction/response envelope — is delegated to `core`.
 * NOTHING here reimplements consensus arithmetic in browser-local code; this
 * module renders, validates shapes defensively, and wires the wallet.
 *
 * AUTHORITY BOUNDARY (unchanged, restated): AI MAY REQUEST · POLICYVAULT
 * DETERMINISTICALLY DECIDES · THE COVENANT ENFORCES · SIGNERS RETAIN
 * CUSTODY. Nothing in this module is itself an authority: every quorum
 * count, every WF check, and every signature is re-verified by the server
 * and, ultimately, by Kaspa consensus. A refusal here never has an override.
 *
 * TWO THINGS THAT MUST NEVER BE CONFUSED (contract §0):
 *   HOSTED ORGANIZATION   — a server-side grouping of vaults/members/roles.
 *                            Hosted-layer only. Grants NO covenant authority.
 *   ON-CHAIN ORGANIZATIONAL ROOT — a PolicyVault.v0.7-root.sil covenant UTXO
 *                            holding the real M-of-N owner quorum. Every
 *                            rendering function below labels which one it is
 *                            describing, and `authorityModel` from the
 *                            server is always displayed, never inferred.
 *
 * SLOT SIGNING (contract §3): a connected wallet signs ONLY the slot it
 * holds. `signOwnSlot()` refuses locally — before ever invoking the wallet —
 * when the connected identity does not hold the requested slot. Another
 * owner's approval is collected out of band (paste / file / QR through the
 * existing air-gap shuttle, `mobile/www/js/portable/airgap.js`'s envelope
 * format) and imported through `validateImportedEnvelope`, which performs
 * the same structural checks locally before the browser ever POSTs it — the
 * server's `verifyRootSlotSignatureResponse` remains the authority.
 *
 * SIGNATURE EXTRACTION: identical technique to
 * sdk/src/wallet-requests-v4.js `collectApprovalV4` — diff the wallet's
 * signed Safe JSON against the frozen unsigned one and pull the one changed
 * input's signature script, strip an optional 0x41 push prefix, and require
 * exactly 65 bytes ending 0x01 (SIGHASH_ALL). Here that diff/extract/gate
 * logic is `core.orgRootSlotV7.buildRootSlotSignatureResponse`, the PINNED
 * core module — never hand-rolled in this file.
 *
 * PENDING IS NOT SUCCESS: the v0.7 request state ladder (AUTHORIZED ->
 * SIGNED -> BROADCAST -> CHAIN_SEEN -> CHAIN_VERIFIED -> VERIFIED_OUTCOME;
 * terminal REFUSED / FAILED) is rendered through the SAME closed-table
 * discipline as v0.4 (web/refusal-explain.js OUTCOMES, extended for these
 * states) — an unrecognised state is always "pending", never success.
 *
 * No fetch, no storage, no wallet call outside the explicit `adapter`
 * argument the caller injects, no keys, no ambient state.
 */

(function () {
  function esc(s) {
    return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  const HEX64_RE = /^[0-9a-f]{64}$/i;

  function fail(message, code, extra) {
    return Object.assign(new Error(message), { code, ...(extra || {}) });
  }

  /* ------------------------------------------------------------------ *
   * The contract's closed v0.7 refusal vocabulary (docs/postlaunch/       *
   * v0.7-app-surface-contract.md §2). Some of these are genuinely thrown  *
   * BY THIS MODULE for conditions the browser can detect locally, fail   *
   * closed, before ever contacting the server or the wallet; the rest    *
   * are the SERVER's own codes, which this table maps display-wise so a  *
   * server refusal and a local pre-check refusal read identically. This  *
   * mapping is what web/refusal-explain.js's closed table explains.      *
   * ------------------------------------------------------------------ */
  const V7_REFUSAL_CODES = Object.freeze([
    "OWNER_SET_ILL_FORMED", "NOT_AN_ACTIVE_SLOT", "UNDER_QUORUM",
    "DUPLICATE_SLOT_SIGNATURE", "SLOT_KEY_MISMATCH", "RESPONSE_BINDING_MISMATCH",
    "ROOT_FROZEN", "ROOT_STALE_OUTPOINT", "ROOT_PENDING_REQUEST",
    "DELAY_NOT_ELAPSED", "ROOT_INPUT_REQUIRED", "OWNER_PATH_TAKES_NO_SIGNATURE",
    "HOSTED_ORG_IS_NOT_A_ROOT"
  ]);

  /* Map a caught error's LOCAL core code (owner-set-v7's `.code`) or a
   * signer-path error's `.signerCode`/`.details.reason`
   * (core/signer/org-root-slot-v7's SLOT_REFUSALS) onto the contract's
   * closed display vocabulary. A code already in V7_REFUSAL_CODES, or not
   * recognised at all, passes through unchanged — the server's exact code
   * always survives (web/refusal-explain.js rule 2). */
  const REASON_TO_DISPLAY_CODE = Object.freeze({
    SLOT_COUNT: "OWNER_SET_ILL_FORMED",
    NOT_CONTIGUOUS: "OWNER_SET_ILL_FORMED",
    NO_ACTIVE_SLOTS: "OWNER_SET_ILL_FORMED",
    DUPLICATE_OWNER_KEY: "OWNER_SET_ILL_FORMED",
    M_ABOVE_ACTIVE: "OWNER_SET_ILL_FORMED",
    K_ABOVE_M: "OWNER_SET_ILL_FORMED",
    R_ABOVE_M: "OWNER_SET_ILL_FORMED",
    SLOT_NOT_HELD: "NOT_AN_ACTIVE_SLOT",
    SLOT_INACTIVE: "NOT_AN_ACTIVE_SLOT",
    OWNER_NOT_IN_SET: "NOT_AN_ACTIVE_SLOT",
    DUPLICATE_SLOT: "DUPLICATE_SLOT_SIGNATURE",
    SIGNATURE_REUSED: "DUPLICATE_SLOT_SIGNATURE",
    RESPONSE_REPLAYED: "RESPONSE_BINDING_MISMATCH",
    MANIFEST_HASH_MISMATCH: "RESPONSE_BINDING_MISMATCH",
    TXID_DRIFT: "RESPONSE_BINDING_MISMATCH",
    ROOT_OUTPOINT_MISMATCH: "RESPONSE_BINDING_MISMATCH",
    FOREIGN_INPUT_SIGNED: "RESPONSE_BINDING_MISMATCH"
  });

  function displayCodeFor(e) {
    if (!e) return "UNKNOWN";
    const reason = (e.details && e.details.reason) || null;
    if (reason && REASON_TO_DISPLAY_CODE[reason]) return REASON_TO_DISPLAY_CODE[reason];
    if (reason && V7_REFUSAL_CODES.includes(reason)) return reason;
    if (e.code && REASON_TO_DISPLAY_CODE[e.code]) return REASON_TO_DISPLAY_CODE[e.code];
    if (e.code) return e.code;
    if (e.signerCode) return e.signerCode;
    return "UNKNOWN";
  }

  /* ==================================================================
   * createModule
   * ================================================================== */
  function createModule({ api, core, setup } = {}) {
    if (!api || typeof api.getJSON !== "function" || typeof api.postJSON !== "function" || typeof api.resolveXOnly !== "function") {
      throw new Error("org-root-ui: createModule requires api.{getJSON,postJSON,resolveXOnly}");
    }
    if (!core || !core.ownerSetV7 || !core.orgRootManifestV7 || !core.orgRootExplain || !core.orgRootSlotV7 || !core.vaultStateV7Root || !core.amounts) {
      throw new Error("org-root-ui: createModule requires the v0.7 core bundle (core.{ownerSetV7,orgRootManifestV7,orgRootExplain,orgRootSlotV7,vaultStateV7Root,amounts})");
    }
    const OWNER_SLOTS = core.ownerSetV7.OWNER_SLOTS_V7;
    const INACTIVE = core.ownerSetV7.INACTIVE_SLOT_KEY;

    /* ---------------- shared small helpers ---------------- */

    function statusRegion(inner, extraClass) {
      return `<div class="opbanner${extraClass ? ` ${extraClass}` : ""}" role="status" aria-live="polite" aria-atomic="true">${inner}</div>`;
    }

    async function resolveOwnerKey(entry) {
      const raw = String((entry && (entry.publicKey || entry.address)) || "").trim();
      if (!raw) throw fail("an owner slot needs an address or a 64-hex public key", "OWNER_SET_ILL_FORMED");
      if (HEX64_RE.test(raw)) return raw.toLowerCase();
      try {
        return (await api.resolveXOnly(raw)).toLowerCase();
      } catch (e) {
        throw fail(`owner "${raw}": ${e.message}`, "OWNER_SET_ILL_FORMED", { cause: e });
      }
    }

    /* Dense 12-slot array from an ordered list of ACTIVE owner entries
     * (slots are always contiguous from 1 at genesis and at every WF-checked
     * rotation — core.ownerSetV7 enforces this identically). */
    function denseOwners(activeKeysInOrder) {
      const out = new Array(OWNER_SLOTS).fill(INACTIVE);
      activeKeysInOrder.forEach((k, i) => { out[i] = k; });
      return out;
    }

    function smallIntField(value, field) {
      const s = String(value ?? "").trim();
      if (!/^[0-9]+$/.test(s)) throw fail(`${field} must be a whole number`, "OWNER_SET_ILL_FORMED");
      return Number(s);
    }

    /* ================================================================
     * (a) ROOT WIZARD — normalize + locally verify BEFORE building a body
     * ================================================================ */

    /*
     * `form` = { owners: [{ address|publicKey, label? }] (ordered, 1..12),
     *   ownerM, emergencyK, recoveryM, recoveryDelayDaa, successionDelayDaa,
     *   successorAddress (optional; blank = succession disabled),
     *   orgId (optional 32-hex; omitted = server derives it at genesis),
     *   rootValueKas, rootMaxFeePerTxKas, signerAddress, label }.
     *
     * Resolves every address to its x-only key via api.resolveXOnly (mirrors
     * org-controls-ui.js resolveApproverLine — the ONE address boundary
     * every form in this app uses), then re-derives the SAME well-formedness
     * check the covenant enforces (core.ownerSetV7.normalizeOwnerSetV7) so a
     * malformed set is refused here, locally, before any network round trip.
     * Returns { ownerSet (normalized), template (normalized, when orgId was
     * supplied), rootValueSompi, rootMaxFeePerTxSompi, body (the exact POST
     * /org-roots body) }.
     */
    async function normalizeWizardGenesis(form) {
      const rows = Array.isArray(form && form.owners) ? form.owners.filter((r) => r && (r.address || r.publicKey)) : [];
      if (rows.length === 0) throw fail("at least one owner slot is required", "OWNER_SET_ILL_FORMED");
      if (rows.length > OWNER_SLOTS) throw fail(`at most ${OWNER_SLOTS} owner slots are supported`, "OWNER_SET_ILL_FORMED");
      const keys = [];
      for (const r of rows) keys.push(await resolveOwnerKey(r));

      const ownerM = smallIntField(form.ownerM, "Required approvals (M)");
      const emergencyK = smallIntField(form.emergencyK, "Emergency freeze quorum (K)");
      const recoveryM = smallIntField(form.recoveryM ?? 0, "Recovery quorum (R)");

      let ownerSet;
      try {
        ownerSet = core.ownerSetV7.normalizeOwnerSetV7({ owners: denseOwners(keys), ownerM, emergencyK, recoveryM });
      } catch (e) {
        throw fail(e.message, displayCodeFor(e), { cause: e });
      }

      const successorRaw = String(form.successorAddress || "").trim();
      let successorPk = INACTIVE;
      if (successorRaw) successorPk = HEX64_RE.test(successorRaw) ? successorRaw.toLowerCase() : await resolveOwnerKey({ address: successorRaw });

      const recoveryDelayDaa = smallIntField(form.recoveryDelayDaa, "Recovery delay (DAA)");
      const successionDelayDaa = smallIntField(form.successionDelayDaa, "Succession delay (DAA)");
      if (recoveryDelayDaa < 1) throw fail("Recovery delay must be at least 1 DAA score", "OWNER_SET_ILL_FORMED");
      if (successionDelayDaa < 1) throw fail("Succession delay must be at least 1 DAA score", "OWNER_SET_ILL_FORMED");

      const rootValueSompi = core.amounts.kasToSompi(form.rootValueKas, "root value");
      const rootMaxFeePerTxSompi = core.amounts.kasToSompi(form.rootMaxFeePerTxKas, "root max fee per transition");

      let template = null;
      const orgIdRaw = String(form.orgId || "").trim().toLowerCase();
      if (HEX64_RE.test(orgIdRaw)) {
        try {
          template = core.vaultStateV7Root.normalizeRootTemplateV7({
            orgId: orgIdRaw, recoveryDelayDaa, successorPk, successionDelayDaa, rootMaxFeePerTx: rootMaxFeePerTxSompi
          });
        } catch (e) {
          throw fail(e.message, displayCodeFor(e), { cause: e });
        }
      }

      const signerAddress = String(form.signerAddress || "").trim();
      if (!signerAddress) throw fail("a funder wallet address is required to sign the genesis transaction", "OWNER_SET_ILL_FORMED");

      const body = {
        label: String(form.label || "").trim() || null,
        owners: rows.map((r, i) => ({ slot: i + 1, ...(r.publicKey ? { publicKey: keys[i] } : { address: r.address }), ...(r.label ? { label: String(r.label).trim() } : {}) })),
        ownerM, emergencyK, recoveryM,
        /* canonical base-10 digit STRINGS — the server's canonicalAmountParam
         * refuses JS numbers (real-browser finding, 2026-09-05: the previous
         * wizard sent numbers and every root creation was refused
         * AMOUNT_INVALID) */
        recoveryDelayDaa: String(recoveryDelayDaa), successionDelayDaa: String(successionDelayDaa),
        successorAddress: successorRaw || null,
        ...(orgIdRaw ? { orgId: orgIdRaw } : {}),
        rootValueKas: String(form.rootValueKas), rootMaxFeePerTxKas: String(form.rootMaxFeePerTxKas),
        signerAddress
      };

      return { ownerSet, template, successorPk, recoveryDelayDaa, successionDelayDaa, rootValueSompi, rootMaxFeePerTxSompi, body };
    }

    /*
     * A NEW owner set only — reused as the `params` of ROTATE,
     * OWNER-RECOVER, and SUCCESSION requests (all three install a new set;
     * §2.4/§2.6 of the design record). Same local WF pre-check as genesis,
     * without the template/root-value fields a rotation never touches.
     */
    async function normalizeNewOwnerSet(form) {
      const rows = Array.isArray(form && form.owners) ? form.owners.filter((r) => r && (r.address || r.publicKey)) : [];
      if (rows.length === 0) throw fail("at least one owner slot is required", "OWNER_SET_ILL_FORMED");
      if (rows.length > OWNER_SLOTS) throw fail(`at most ${OWNER_SLOTS} owner slots are supported`, "OWNER_SET_ILL_FORMED");
      const keys = [];
      for (const r of rows) keys.push(await resolveOwnerKey(r));
      const ownerM = smallIntField(form.ownerM, "Required approvals (M)");
      const emergencyK = smallIntField(form.emergencyK, "Emergency freeze quorum (K)");
      const recoveryM = smallIntField(form.recoveryM ?? 0, "Recovery quorum (R)");
      let ownerSet;
      try {
        ownerSet = core.ownerSetV7.normalizeOwnerSetV7({ owners: denseOwners(keys), ownerM, emergencyK, recoveryM });
      } catch (e) {
        throw fail(e.message, displayCodeFor(e), { cause: e });
      }
      /* rc18 review R3-02: the SDK builder reads `params.newOwnerSet` (12 dense
       * x-only slots + M/K/R); the presentational rows are kept beside it for
       * the review, never posted as the request's parameters. */
      const params = {
        newOwnerSet: { owners: [...ownerSet.owners], ownerM: ownerSet.ownerM.toString(), emergencyK: ownerSet.emergencyK.toString(), recoveryM: ownerSet.recoveryM.toString() }
      };
      const ownerRows = rows.map((r, i) => ({ slot: i + 1, ...(r.publicKey ? { publicKey: keys[i] } : { address: r.address }), ...(r.label ? { label: String(r.label).trim() } : {}) }));
      return { ownerSet, params, ownerRows };
    }

    /*
     * "EXACT ROOT POLICY BEFORE SIGNING" — genesis preview. Rendered
     * ENTIRELY from the locally-normalized owner set + template (real core
     * output, never re-typed UI text): every active slot's FULL public key
     * (never truncated), M/K/R and what each unlocks, the two relative-age
     * delays, the successor key, and the root value / per-transition fee
     * bound in KAS via the canonical sompi<->KAS conversion.
     */
    function renderGenesisPolicyPanelHtml({ ownerSet, template, successorPk, recoveryDelayDaa, successionDelayDaa, rootValueSompi, rootMaxFeePerTxSompi }) {
      const slots = core.ownerSetV7.activeOwnerSlotsV7(ownerSet);
      const rows = slots.map((s) => `<tr><td>${s.slot}</td><td class="mono" style="word-break:break-all">${esc(s.publicKey)}</td></tr>`).join("");
      const req = (name) => { try { return core.ownerSetV7.requiredApprovalsV7(ownerSet, name).toString(); } catch { return "disabled"; } };
      const successionEnabled = successorPk && successorPk !== INACTIVE;
      // Prefer the fully-normalized template's own delay fields when a valid
      // orgId let the template build; otherwise fall back to the SAME
      // locally-validated integers the wizard collected (real core
      // smallIntField parsing either way — never UI-local arithmetic).
      const rDelay = template ? template.recoveryDelayDaa.toString() : String(recoveryDelayDaa);
      const sDelay = template ? template.successionDelayDaa.toString() : String(successionDelayDaa);
      return (
        `<div class="panel" data-org-root-policy="genesis">` +
        `<h4 style="margin-top:0">EXACT ROOT POLICY BEFORE SIGNING</h4>` +
        `<div class="hint">Recomputed locally from the same well-formedness rule the covenant enforces (core.ownerSetV7) — not typed UI text.</div>` +
        `<table class="mtable"><thead><tr><th>Slot</th><th>Owner public key (full)</th></tr></thead><tbody>${rows}</tbody></table>` +
        `<div class="kv-line">Required for AUTHORIZE / ROTATE / UNFREEZE / general owner operations: ${esc(req("authorize"))} of ${slots.length}.</div>` +
        `<div class="kv-line">Required for emergency FREEZE (the lighter quorum): ${esc(req("freeze"))} of ${slots.length}.</div>` +
        `<div class="kv-line">Owner recovery quorum: ${ownerSet.recoveryM > 0n ? `${esc(ownerSet.recoveryM.toString())} of ${slots.length} (enabled)` : "DISABLED — if owner keys are lost below quorum, no recovery path exists"}.</div>` +
        `<div class="kv-line">Recovery delay: ${esc(rDelay)} DAA score (relative; any root transaction resets it).</div>` +
        `<div class="kv-line">Succession delay: ${esc(sDelay)} DAA score (relative; any root transaction resets it).</div>` +
        `<div class="kv-line">Successor key: ${successionEnabled ? `<span class="mono">${esc(successorPk)}</span> (succession enabled)` : "none (succession DISABLED)"}.</div>` +
        `<div class="kv-line">Root value: ${esc(core.amounts.sompiToKas(rootValueSompi))} KAS. Maximum the root may lose per transition: ${esc(core.amounts.sompiToKas(rootMaxFeePerTxSompi))} KAS.</div>` +
        `<div class="hint">This organizational root is a NEW, separate covenant from every legacy single-owner vault. It grants covenant-enforced M-of-N authority only over vaults explicitly rooted to it.</div>` +
        `</div>`
      );
    }

    /* ================================================================
     * ROOT / REQUEST rendering (from server records; contract §1 shapes)
     * ================================================================ */

    /* (b/d) EXACT-POLICY / REVIEW panel for a REAL root-action request: the
     * request's own manifest, explained through core.orgRootExplain — the
     * SAME fixed lines an owner reads before signing, never re-derived. */
    function renderRequestReviewHtml(request, descriptors, redeemScripts) {
      if (!request || !request.manifest) {
        return statusRegion("No manifest is attached to this request yet — refusing to render a review. Do not sign.", "bad");
      }
      const carriedDescriptors = descriptors || (request.descriptors && typeof request.descriptors === "object" && !Array.isArray(request.descriptors) ? request.descriptors : {}); // rc21 review R6-02
      const carriedRedeems = redeemScripts || (request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {}); // Codex checkpoint 6
      const doc = core.orgRootExplain.structured({ manifest: request.manifest, descriptors: carriedDescriptors, redeemScripts: carriedRedeems });
      const lines = core.orgRootExplain.humanReadable({ manifest: request.manifest, descriptors: carriedDescriptors, redeemScripts: carriedRedeems });
      const lineDivs = lines.map((l) => `<div class="mono" style="padding:0.12rem 0;word-break:break-all">${esc(l)}</div>`).join("");
      const verified = doc.verdict === "VERIFIED_EXACT";
      return (
        `<div class="${verified ? "opbanner" : "opbanner bad"}" data-org-root-review="${verified ? "verified" : "refused"}" role="status" aria-live="polite" aria-atomic="true" style="border-width:2px">` +
        `<b style="color:${verified ? "var(--good)" : "var(--bad)"}">${verified ? "VERIFIED — EXACT ROOT POLICY BEFORE SIGNING" : "DO NOT SIGN — LOCAL VERIFICATION REFUSED"}</b>` +
        `<div style="margin-top:0.4rem;font-size:0.8rem;max-height:18rem;overflow:auto">${lineDivs}</div>` +
        `</div>`
      );
    }

    /* ================================================================
     * (d) REQUEST STATE LADDER — PENDING IS NOT SUCCESS
     * ================================================================ */
    const REQUEST_OUTCOMES = Object.freeze({
      AUTHORIZED: { level: "pending", title: "Authorized — collecting approvals", meaning: "PolicyVault built and froze the exact transaction. It is not finalized and nothing has moved." },
      SIGNED: { level: "pending", title: "Finalized — NOT yet broadcast", meaning: "Enough owner slots approved, the fee input is signed and the transaction is assembled. It has NOT been sent to the network and the root has not changed." },
      BROADCAST: { level: "pending", title: "Broadcast — NOT yet confirmed", meaning: "The transaction was sent to the network. That is not proof it is in the DAG and not proof the root changed." },
      CHAIN_SEEN: { level: "pending", title: "Seen on the DAG — NOT yet verified", meaning: "PolicyVault observed the transaction but has not yet proven the predecessor root state was consumed and the expected successor exists." },
      CHAIN_VERIFIED: { level: "verified", title: "Chain-verified", meaning: "PolicyVault confirmed the predecessor root state was consumed and the expected successor state exists on the Kaspa DAG. This is proven." },
      VERIFIED_OUTCOME: { level: "verified", title: "Verified outcome", meaning: "The transaction's real-world outcome was independently confirmed, in addition to chain verification." },
      REFUSED: { level: "failed", title: "Refused — nothing happened", meaning: "This request was refused before broadcast. The root is unchanged." },
      FAILED: { level: "failed", title: "Failed — nothing verified", meaning: "PolicyVault recorded a failure for this request. Use Verify state on the root before starting a replacement; the root may or may not have moved." },
      SUBMISSION_REJECTED: { level: "failed", title: "Rejected by the network — nothing happened", meaning: "The node refused the transaction; it was not accepted. The root is unchanged." },
      RECONCILIATION_REQUIRED: { level: "pending", title: "Outcome unknown — reconcile before anything else", meaning: "The transaction was handed to the network but PolicyVault could not prove whether it landed. Use Verify state on the root; do not build a replacement until this is resolved." },
      STALE: { level: "failed", title: "Stale — the root moved on", meaning: "Another transaction spent the root outpoint this request was built on, so this request can never be broadcast. Nothing from it happened." }
    });
    const UNKNOWN_REQUEST_OUTCOME = Object.freeze({ level: "pending", title: "Outcome NOT confirmed", meaning: "PolicyVault has no closed description for this request state, so it is treated as unconfirmed — never as success." });
    /* UX-09: the description follows the ACTUAL state AND the collected
     * approvals — "no owner has approved yet" is said only when that is true. */
    function requestOutcome(state, counts) {
      const base = Object.prototype.hasOwnProperty.call(REQUEST_OUTCOMES, String(state)) ? REQUEST_OUTCOMES[state] : UNKNOWN_REQUEST_OUTCOME;
      if (String(state) === "AUTHORIZED" && counts && Number.isFinite(Number(counts.present)) && Number.isFinite(Number(counts.required))) {
        const p = Number(counts.present), r = Number(counts.required);
        const title = p === 0 ? "Authorized — no owner has approved yet" : p < r ? `Authorized — ${p} of ${r} approvals collected` : `Authorized — ${p} of ${r} approvals collected, ready to finalize`;
        const meaning = p === 0 ? "PolicyVault built and froze the exact transaction. No owner has approved yet; it is not finalized and nothing has moved." : p < r ? `${p} owner slot${p === 1 ? "" : "s"} approved so far; ${r - p} more ${r - p === 1 ? "is" : "are"} needed. It is not finalized and nothing has moved.` : "Every required approval is collected. The transaction is NOT finalized (the fee input is unsigned) and nothing has moved.";
        return { level: "pending", title, meaning };
      }
      return base;
    }
    /* UX-09: the NESTED reconciliation outcome (POST /org-roots/:id/reconcile →
     * { reconcile: { root: { status }, vaults } }) rendered truthfully — a
     * green message only for a proven state. */
    function describeReconcileOutcome(res) {
      const root = res && res.reconcile && res.reconcile.root ? res.reconcile.root : null;
      const st = root ? String(root.status || "") : "";
      const vaults = res && res.reconcile && Array.isArray(res.reconcile.vaults) ? res.reconcile.vaults : [];
      const vaultNote = vaults.length ? ` Vaults: ${vaults.map((v) => `${String(v.vaultId || "?").slice(0, 8)}… ${v.status}`).join("; ")}.` : "";
      switch (st) {
        case "CONSISTENT": return { level: "good", status: st, text: `Root state verified against the chain (live outpoint consistent).${vaultNote}` };
        case "ADVANCED": return { level: "good", status: st, text: `Root state advanced: a submitted transaction${root.txId ? ` (${root.txId})` : ""} was proven on the chain and the root record now follows it.${vaultNote}` };
        case "CLAIM_PENDING": return { level: "warn", status: st, text: `NOT verified: a submitted transaction is still pending${root.claimTxId ? ` (${root.claimTxId})` : ""}${Number.isFinite(root.ageMs) ? `, ${Math.round(root.ageMs / 1000)} s old` : ""} — do not start another governance action until it resolves.${vaultNote}` };
        case "CLAIM_RELEASED": return { level: "warn", status: st, text: `A stale submission claim${root.claimTxId ? ` (${root.claimTxId})` : ""} was released: that transaction never landed. Check the request before retrying.${vaultNote}` };
        case "NO_LIVE_OUTPOINT": return { level: "warn", status: st, text: "The root has no live outpoint recorded yet — genesis not chain-verified.${vaultNote}".replace("${vaultNote}", vaultNote) };
        case "UNKNOWN": return { level: "bad", status: st, text: `Outcome UNKNOWN: the root's chain state could not be proven${root.reason ? ` (${root.reason})` : ""}. Do not treat any pending request as done and do not start a replacement until this is resolved.${vaultNote}` };
        default: return { level: "bad", status: st || "MISSING", text: `Reconciliation returned no recognized root status${st ? ` (${st})` : ""} — treated as NOT verified.${vaultNote}` };
      }
    }
    function isVerifiedRequestOutcome(state) { return requestOutcome(state).level === "verified"; }
    /* Codex checkpoint 6 (UX-09): a succession's closed descriptions — ONE successor signature, never owner approvals. */
    const SUCCESSION_OUTCOMES = Object.freeze({
      AUTHORIZED: { level: "pending", title: "Authorized — awaiting the designated successor's signature", meaning: "PolicyVault built and froze the exact succession transaction. Only the designated successor's signature authorizes it (no owner approvals are collected); it is not signed and nothing has moved." },
      SIGNED: { level: "pending", title: "Signed by the successor — NOT yet broadcast", meaning: "The designated successor signed the root input and the fee input and the transaction is assembled. It has NOT been sent to the network and the root has not changed." }
    });
    function successionOutcome(state) {
      const k = String(state);
      if (Object.prototype.hasOwnProperty.call(SUCCESSION_OUTCOMES, k)) return SUCCESSION_OUTCOMES[k];
      return requestOutcome(state);
    }
    /* "signed" / "unsigned" / "unknown" for the successor's single signature, by request state. */
    function successionSignatureState(state) {
      const k = String(state);
      if (k === "AUTHORIZED") return "unsigned";
      if (["SIGNED", "BROADCAST", "CHAIN_SEEN", "CHAIN_VERIFIED", "VERIFIED_OUTCOME", "RECONCILIATION_REQUIRED", "FAILED", "SUBMISSION_REJECTED", "STALE"].includes(k)) return "signed";
      return "unknown";
    }
    /* The root's pinned successor (x-only) from the request's manifest, cross-checked against the durable root record;
     * null when absent, zero, or when the two disagree (offer nothing). Mirrors app-v4's successionSignerOf. */
    function successionSignerOf(request, orgRoot) {
      const fromManifest = request && request.manifest && request.manifest.root && request.manifest.root.template ? String(request.manifest.root.template.successorPk || "").toLowerCase() : "";
      const fromRoot = orgRoot && orgRoot.template ? String(orgRoot.template.successorPk || "").toLowerCase() : "";
      const pinned = fromManifest || fromRoot;
      if (!/^[0-9a-f]{64}$/.test(pinned) || pinned === "00".repeat(32)) return null;
      if (fromManifest && fromRoot && fromManifest !== fromRoot) return null;
      return pinned;
    }

    /* ================================================================
     * (d) FINALIZE GATING — a UI convenience only; the server/covenant is
     * the real gate. Never trust the client count as authority.
     * ================================================================ */
    function finalizeGate(request) {
      if (!request) return { enabled: false, reason: "no request" };
      // rc15 review F-01: ONLY an AUTHORIZED request may be finalized. A SIGNED
      // request is already finalized (its fee input is signed) — offering
      // Finalize again would consume a wallet signature on a pre-detectable
      // conflict the server then refuses. Submit is the next step there.
      if (request.state === "SIGNED") return { enabled: false, reason: "already finalized — submit it to the network" };
      if (request.state !== "AUTHORIZED") return { enabled: false, reason: `request is ${request.state}, not ready to finalize` };
      // UX-09: the server's counter is cross-checked against the ACTUAL slot
      // statuses; on a mismatch the smaller count is used (fail closed).
      const serverPresent = Number(request.signaturesPresent ?? 0);
      const slots = Array.isArray(request.slots) ? request.slots : null;
      if (!slots) return { enabled: false, reason: "the request carries no owner slot statuses — reload it; finalize is disabled until the approvals can be verified" }; // rc18 review R3-09: never fail open
      const slotSigned = slots.filter((sl) => sl && sl.status === "SIGNED").length;
      const present = Math.min(serverPresent, slotSigned);
      // rc19 review R4-08: the quorum comes from the VERIFIED manifest, never
      // from the server record alone (a record claiming '0' must not enable).
      const ma = request.manifest && request.manifest.action;
      if (!ma || typeof ma.requiredApprovals !== "string" || !/^(0|[1-9][0-9]*)$/.test(ma.requiredApprovals)) return { enabled: false, reason: "the request carries no verified quorum (manifest.action.requiredApprovals) — finalize is disabled" }; // rc21 review R6-07: a digit STRING, never a coerced array/number
      const required = Number(ma.requiredApprovals);
      const srv = request.requiredApprovals;
      if (srv !== undefined && srv !== null && !((typeof srv === "string" && /^[0-9]+$/.test(srv) && Number(srv) === required) || (typeof srv === "number" && Number.isInteger(srv) && srv === required))) return { enabled: false, reason: `the server's quorum (${JSON.stringify(srv)}) disagrees with the verified manifest (${required}) — finalize is disabled` };
      if (required < 1) return { enabled: false, reason: "a zero-approval quorum is never finalized" };
      if (slotSigned !== serverPresent) return { enabled: false, reason: `approval count mismatch (server ${serverPresent}, owner slots signed ${slotSigned}) — reload the request; finalize is disabled until the counts agree` };
      if (present < required) return { enabled: false, reason: `${present} of ${required} slot signatures collected — finalize is disabled until quorum is met` };
      return { enabled: true, reason: "quorum met" };
    }

    /* ================================================================
     * (c′) THE SIGNING BOUNDARY (Codex checkpoint 2, UX-02 / UX-13).
     * Every root signing path — genesis funder, owner slot, successor,
     * and the fee (fuel) input at finalize — passes through
     * bindRootSigningPayload() BEFORE a wallet is invoked. It binds:
     *   • the REVIEW: the request's manifest must verify through the
     *     pinned core (rootAction) or the genesis cross-check must have
     *     passed (rootGenesis) — a DO-NOT-SIGN review refuses HERE, not
     *     only in the displayed control;
     *   • the PAYLOAD: the exact unsignedSafeJson string the wallet will
     *     sign — its embedded id equals the manifest's txId and its inputs
     *     (previous outpoints, amounts, scripts) and outputs (values,
     *     scripts) equal the manifest's frozen transaction byte for byte;
     *   • the NETWORK, the FEE (Σ inputs − Σ outputs must equal the
     *     manifest's requiredFeeSompi), the ROOT input (the declared index
     *     spends the manifest's root outpoint);
     *   • the SIGNER: the inputs handed to the wallet are exactly the ones
     *     this role may sign — owner slot: the root input only, key in the
     *     expected signer set; fee payer: the last, non-root input whose
     *     script is the connected wallet's own P2PK; successor: the root
     *     input plus its own P2PK inputs; genesis funder: every input is
     *     its own P2PK, output 0 is the P2SH root output carrying exactly
     *     the reviewed governance funding, every other output returns to
     *     the funder.
     * Anything missing, stale, or mismatched refuses with ZERO wallet calls.
     * ================================================================ */
    const HEX64 = /^[0-9a-f]{64}$/;
    const p2pkWire = (xonly) => `000020${String(xonly || "").toLowerCase()}ac`;
    const isP2shWire = (spk) => /^0000aa20[0-9a-f]{64}87$/.test(String(spk || ""));
    const SAFE_TOP_KEYS = Object.freeze(["id", "version", "inputs", "outputs", "subnetworkId", "lockTime", "gas", "storageMass", "payload"]);
    const SAFE_INPUT_KEYS = Object.freeze(["transactionId", "index", "sequence", "sigOpCount", "computeBudget", "signatureScript", "utxo"]);
    const SAFE_UTXO_KEYS = Object.freeze(["address", "amount", "scriptPublicKey", "blockDaaScore", "isCoinbase", "covenantId"]);
    const SAFE_OUTPUT_KEYS = Object.freeze(["value", "scriptPublicKey", "covenant"]);
    const NATIVE_SUBNETWORK = "00".repeat(20);
    function closedKeys(obj, allowed, label) {
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw fail(`${label} is not an object`, "PAYLOAD_INVALID");
      for (const k of Object.keys(obj)) if (!allowed.includes(k)) throw fail(`${label} carries an unexpected field "${k}" — refusing a payload this boundary cannot compare in full`, "PAYLOAD_INVALID");
    }
    /* Codex checkpoint 3 (UX-02/UX-13): EVERY consensus field of the kaspa
     * Safe JSON is parsed under a CLOSED schema — an unknown field anywhere
     * refuses, so nothing the wallet would sign can escape the comparison. */
    function parseSigningPayload(unsignedSafeJson) {
      if (typeof unsignedSafeJson !== "string" || !unsignedSafeJson.trim()) throw fail("the request carries no frozen transaction to sign", "REQUEST_NOT_SIGNABLE");
      let safe;
      try { safe = JSON.parse(unsignedSafeJson); } catch { throw fail("the signing payload is not valid JSON", "PAYLOAD_INVALID"); }
      closedKeys(safe, SAFE_TOP_KEYS, "the signing payload");
      if (!HEX64.test(String(safe.id || "").toLowerCase())) throw fail("the signing payload carries no transaction id", "PAYLOAD_INVALID");
      if (safe.version !== 1) throw fail(`the signing payload has transaction version ${safe.version}; only version 1 is signed`, "PAYLOAD_INVALID");
      if (String(safe.subnetworkId).toLowerCase() !== NATIVE_SUBNETWORK) throw fail("the signing payload is not on the native subnetwork", "PAYLOAD_INVALID");
      if (!/^[0-9]+$/.test(String(safe.lockTime))) throw fail("the signing payload lockTime is malformed", "PAYLOAD_INVALID");
      if (String(safe.gas) !== "0") throw fail("the signing payload carries gas", "PAYLOAD_INVALID");
      if (String(safe.storageMass) !== "0") throw fail("the signing payload carries a non-zero storageMass — not a frozen PolicyVault transaction", "PAYLOAD_INVALID");
      if (safe.payload !== "") throw fail("the signing payload carries a payload — refusing", "PAYLOAD_INVALID");
      if (!Array.isArray(safe.inputs) || !safe.inputs.length || !Array.isArray(safe.outputs) || !safe.outputs.length) throw fail("the signing payload has no inputs or no outputs", "PAYLOAD_INVALID");
      const inputs = safe.inputs.map((i, n) => {
        closedKeys(i, SAFE_INPUT_KEYS, `signing payload input ${n}`);
        closedKeys(i.utxo, SAFE_UTXO_KEYS, `signing payload input ${n} utxo`);
        if (!HEX64.test(String(i.transactionId || "").toLowerCase()) || !Number.isInteger(i.index) || i.index < 0) throw fail(`signing payload input ${n} outpoint is malformed`, "PAYLOAD_INVALID");
        if (!/^[0-9]+$/.test(String(i.sequence)) || !Number.isInteger(i.computeBudget) || i.computeBudget < 0) throw fail(`signing payload input ${n} sequence/computeBudget malformed`, "PAYLOAD_INVALID");
        if (i.sigOpCount !== 0) throw fail(`signing payload input ${n} sigOpCount must be 0 for a frozen transaction`, "PAYLOAD_INVALID");
        if (i.signatureScript !== "") throw fail(`signing payload input ${n} already carries a signature — refusing to sign a non-frozen transaction`, "PAYLOAD_INVALID");
        if (!/^[0-9]+$/.test(String(i.utxo.amount)) || typeof i.utxo.scriptPublicKey !== "string" || !/^[0-9a-f]{6,}$/i.test(i.utxo.scriptPublicKey)) throw fail(`signing payload input ${n} utxo is malformed`, "PAYLOAD_INVALID");
        if (i.utxo.isCoinbase !== false) throw fail(`signing payload input ${n} claims a coinbase utxo`, "PAYLOAD_INVALID");
        if (i.utxo.covenantId !== null && !HEX64.test(String(i.utxo.covenantId).toLowerCase())) throw fail(`signing payload input ${n} covenantId malformed`, "PAYLOAD_INVALID");
        if (!/^[0-9]+$/.test(String(i.utxo.blockDaaScore))) throw fail(`signing payload input ${n} blockDaaScore malformed`, "PAYLOAD_INVALID");
        return { transactionId: String(i.transactionId).toLowerCase(), index: i.index, sequence: String(i.sequence), computeBudget: i.computeBudget, amount: BigInt(i.utxo.amount), spk: String(i.utxo.scriptPublicKey).toLowerCase(), covenantId: i.utxo.covenantId === null ? null : String(i.utxo.covenantId).toLowerCase(), blockDaaScore: String(i.utxo.blockDaaScore) };
      });
      const outputs = safe.outputs.map((o, n) => {
        closedKeys(o, SAFE_OUTPUT_KEYS, `signing payload output ${n}`);
        if (!/^[0-9]+$/.test(String(o.value)) || typeof o.scriptPublicKey !== "string" || !/^[0-9a-f]{6,}$/i.test(o.scriptPublicKey)) throw fail(`signing payload output ${n} is malformed`, "PAYLOAD_INVALID");
        let covenant = null;
        if (o.covenant !== null && o.covenant !== undefined) {
          closedKeys(o.covenant, ["authorizingInput", "covenantId"], `signing payload output ${n} covenant`);
          if (!Number.isInteger(o.covenant.authorizingInput) || !HEX64.test(String(o.covenant.covenantId || "").toLowerCase())) throw fail(`signing payload output ${n} covenant metadata malformed`, "PAYLOAD_INVALID");
          covenant = { authorizingInput: o.covenant.authorizingInput, covenantId: String(o.covenant.covenantId).toLowerCase() };
        }
        return { value: BigInt(o.value), spk: String(o.scriptPublicKey).toLowerCase(), covenant };
      });
      const sumIn = inputs.reduce((a, i) => a + i.amount, 0n);
      const sumOut = outputs.reduce((a, o) => a + o.value, 0n);
      if (sumOut > sumIn) throw fail("the signing payload spends more than it funds", "PAYLOAD_INVALID");
      return { id: String(safe.id).toLowerCase(), version: safe.version, lockTime: String(safe.lockTime), subnetworkId: String(safe.subnetworkId).toLowerCase(), gas: String(safe.gas), payload: safe.payload, inputs, outputs, fee: sumIn - sumOut };
    }
    const spkWireOf = (spk) => (spk && typeof spk === "object" ? `${Number(spk.version || 0).toString(16).padStart(4, "0")}${String(spk.scriptHex || "")}` : String(spk || "")).toLowerCase();
    /* EVERY consensus field of the reviewed frozen transaction must equal the
     * payload: version, lockTime, subnetworkId, gas, payload, and per input the
     * previous outpoint, sequence, computeBudget and the referenced utxo
     * (amount, script, covenantId, blockDaaScore), per output the value, the
     * destination script and the covenant metadata. Counts must match. */
    function frozenMismatches(frozenCanonicalJson, safe) {
      const out = [];
      let frozen;
      try { frozen = JSON.parse(frozenCanonicalJson); } catch { return ["the manifest's frozen transaction is not valid JSON"]; }
      if (!frozen || typeof frozen !== "object" || !Array.isArray(frozen.inputs) || !Array.isArray(frozen.outputs)) return ["the manifest's frozen transaction has no inputs/outputs"];
      if (Number(frozen.version) !== Number(safe.version)) out.push(`transaction version ${safe.version} differs from the reviewed ${frozen.version}`);
      if (String(frozen.lockTime ?? "0") !== safe.lockTime) out.push("lockTime differs from the reviewed transaction");
      if (String(frozen.subnetworkId ?? NATIVE_SUBNETWORK).toLowerCase() !== safe.subnetworkId) out.push("subnetwork differs from the reviewed transaction");
      if (String(frozen.gas ?? "0") !== safe.gas) out.push("gas differs from the reviewed transaction");
      if (String(frozen.payload ?? "") !== safe.payload) out.push("payload differs from the reviewed transaction");
      if (frozen.inputs.length !== safe.inputs.length) out.push(`input count ${safe.inputs.length} differs from the reviewed ${frozen.inputs.length}`);
      if (frozen.outputs.length !== safe.outputs.length) out.push(`output count ${safe.outputs.length} differs from the reviewed ${frozen.outputs.length}`);
      frozen.inputs.forEach((fi, n) => {
        const si = safe.inputs[n];
        if (!si) return;
        const po = fi.previousOutpoint || {};
        if (String(po.transactionId || "").toLowerCase() !== si.transactionId || Number(po.index) !== si.index) out.push(`input ${n} spends a different outpoint than reviewed`);
        if (String(fi.sequence ?? "0") !== si.sequence) out.push(`input ${n} sequence differs from the reviewed transaction`);
        if (String(fi.computeBudget ?? 0) !== String(si.computeBudget)) out.push(`input ${n} computeBudget differs from the reviewed transaction`); // small integers; compared as canonical strings (no Number() on a consensus field)
        const fu = fi.utxo || {};
        if (String(fu.amount) !== si.amount.toString()) out.push(`input ${n} amount differs from the reviewed transaction`);
        if (spkWireOf(fu.scriptPublicKey) !== si.spk) out.push(`input ${n} script differs from the reviewed transaction`);
        const fcov = fu.covenantId === undefined || fu.covenantId === null ? null : String(fu.covenantId).toLowerCase();
        // The SDK's real Safe JSON (kaspa WASM UtxoEntry) carries NO covenant id
        // on a covenant INPUT (`utxo.covenantId: null`; the identity is bound by
        // the outpoint, amount and script compared above and proven live). A
        // payload that DECLARES a covenant id must match the review exactly.
        if (si.covenantId !== null && fcov !== si.covenantId) out.push(`input ${n} covenant id differs from the reviewed transaction`);
        if (fu.blockDaaScore !== undefined && String(fu.blockDaaScore) !== si.blockDaaScore) out.push(`input ${n} blockDaaScore differs from the reviewed transaction`);
      });
      frozen.outputs.forEach((fo, n) => {
        const so = safe.outputs[n];
        if (!so) return;
        if (String(fo.value) !== so.value.toString()) out.push(`output ${n} value differs from the reviewed transaction`);
        if (spkWireOf(fo.scriptPublicKey) !== so.spk) out.push(`output ${n} destination differs from the reviewed transaction`);
        const fc = fo.covenant && typeof fo.covenant === "object" ? { authorizingInput: Number(fo.covenant.authorizingInput), covenantId: String(fo.covenant.covenantId || "").toLowerCase() } : null;
        if (JSON.stringify(fc) !== JSON.stringify(so.covenant)) out.push(`output ${n} covenant metadata differs from the reviewed transaction`);
      });
      return out;
    }
    const p2pkOwnerOf = (spk) => { const m = /^000020([0-9a-f]{64})ac$/.exec(String(spk || "").toLowerCase()); return m ? m[1] : null; };
    function bindRootSigningPayload({ role, request, unsignedSafeJson, signInputs, network, connectedXOnly, slotEnvelope, crossCheck, norm }) {
      const refuse = (msg, code) => { throw fail(`${msg} — refusing to invoke the wallet`, code || "SIGNING_BINDING_REFUSED"); };
      if (!request) refuse("no request", "REQUEST_NOT_SIGNABLE");
      const xonly = String(connectedXOnly || "").toLowerCase();
      if (!HEX64.test(xonly)) refuse("the connected wallet's public key is unknown", "WALLET_NOT_READY");
      const safe = parseSigningPayload(unsignedSafeJson);
      const list = Array.isArray(signInputs) ? signInputs.map((x) => Number(x && x.index)) : null;
      if (!list || !list.length || list.some((i) => !Number.isInteger(i) || i < 0 || i >= safe.inputs.length)) refuse("the inputs to sign are missing or outside the transaction", "PAYLOAD_INVALID");
      if (new Set(list).size !== list.length) refuse("the inputs to sign repeat an index", "PAYLOAD_INVALID");
      if (role === "genesis") {
        if (request.kind !== "rootGenesis") refuse(`a ${request.kind || "non-genesis"} request cannot be signed as a root genesis`, "REQUEST_NOT_SIGNABLE");
        const sum = request.manifest;
        if (!sum || sum.kind !== "genesis-summary") refuse("the request carries no genesis summary to bind the transaction to", "REVIEW_MISSING");
        if (!crossCheck || crossCheck.ok !== true) refuse(`the reviewed rules do not match PolicyVault's description of this transaction (${crossCheck && Array.isArray(crossCheck.mismatches) ? crossCheck.mismatches.join("; ") : "no review recorded"})`, "REVIEW_REFUSED");
        if (String(sum.networkId) !== String(network)) refuse(`this transaction is for ${sum.networkId}, the wallet is on ${network}`, "NETWORK_MISMATCH");
        if (!HEX64.test(String(sum.txId || "").toLowerCase()) || safe.id !== String(sum.txId).toLowerCase()) refuse("the signing payload is not the transaction the review described (transaction id differs)", "PAYLOAD_MISMATCH");
        let rootValue = null;
        try { rootValue = core.amounts.kasToSompi(String(sum.rootValueKas)); } catch { rootValue = null; }
        if (rootValue === null || rootValue === undefined) refuse("the genesis summary carries no governance funding amount", "REVIEW_MISSING");
        if (typeof sum.requiredFeeSompi !== "string" || !/^[0-9]+$/.test(sum.requiredFeeSompi)) refuse("the genesis summary carries no exact network fee — the fee cannot be bound", "REVIEW_MISSING"); // rc20 review R5-05: a string of digits, never a coerced array/number
        if (safe.fee !== BigInt(String(sum.requiredFeeSompi))) refuse(`the network fee ${core.amounts.sompiToKas(safe.fee)} KAS differs from the reviewed ${core.amounts.sompiToKas(BigInt(String(sum.requiredFeeSompi)))} KAS`, "FEE_MISMATCH");
        if (!isP2shWire(safe.outputs[0].spk)) refuse("output 0 is not a covenant (P2SH) root output", "PAYLOAD_MISMATCH");
        if (safe.outputs[0].value !== BigInt(rootValue)) refuse(`the root output carries ${core.amounts.sompiToKas(safe.outputs[0].value)} KAS, the review says ${sum.rootValueKas} KAS`, "PAYLOAD_MISMATCH");
        /* Codex checkpoint 3 (UX-02): the root output's locking script is
         * REBUILT LOCALLY from the rules the owner reviewed (owner slots,
         * M/K/R, waiting periods, successor, fee cap) through the shared
         * core's exact reconstruction of the frozen v0.7 root script, and its
         * P2SH hash must be the destination — a substituted P2SH hash refuses. */
        if (!norm || !norm.ownerSet) refuse("the reviewed governance rules are not available to rebuild the root script", "REVIEW_MISSING");
        const orgId = String((sum.template && sum.template.orgId) || sum.orgId || "").toLowerCase();
        if (!HEX64.test(orgId) || (sum.template && sum.template.orgId && String(sum.template.orgId).toLowerCase() !== orgId) || (sum.orgId && String(sum.orgId).toLowerCase() !== orgId)) refuse("the genesis summary carries no consistent organization id", "REVIEW_MISSING");
        let expectedRootSpk = null;
        try {
          expectedRootSpk = "0000" + core.rootScriptV7.genesisRootSpkHexV7({
            template: { orgId, recoveryDelayDaa: String(norm.recoveryDelayDaa), successorPk: String(norm.successorPk), successionDelayDaa: String(norm.successionDelayDaa), rootMaxFeePerTx: String(norm.rootMaxFeePerTxSompi) },
            ownerSet: { owners: [...norm.ownerSet.owners], ownerM: norm.ownerSet.ownerM.toString(), emergencyK: norm.ownerSet.emergencyK.toString(), recoveryM: norm.ownerSet.recoveryM.toString() }
          });
        } catch (e) { refuse(`the root script could not be rebuilt from the reviewed rules (${e.message})`, "REVIEW_REFUSED"); }
        if (safe.outputs[0].spk !== expectedRootSpk) refuse("the root output's locking script is NOT the script of the rules you reviewed — the transaction would lock the funding under different governance", "PAYLOAD_MISMATCH");
        if (!HEX64.test(String(sum.covenantId || ""))) refuse("the genesis summary carries no root covenant id — the root output's covenant identity cannot be bound", "REVIEW_MISSING"); // rc19 review R4-07
        if (safe.lockTime !== "0") refuse("the transaction carries a lock time — PolicyVault transactions never do", "PAYLOAD_MISMATCH");
        if ((!safe.outputs[0].covenant || safe.outputs[0].covenant.covenantId !== String(sum.covenantId).toLowerCase() || safe.outputs[0].covenant.authorizingInput !== 0)) refuse("the root output's covenant identity differs from the review", "PAYLOAD_MISMATCH");
        safe.outputs.slice(1).forEach((o, n) => { if (o.spk !== p2pkWire(xonly) || o.covenant) refuse(`output ${n + 1} does not return to your wallet`, "PAYLOAD_MISMATCH"); });
        if (safe.outputs.length > 2) refuse("a genesis has at most one change output", "PAYLOAD_MISMATCH");
        safe.inputs.forEach((i, n) => { if (i.spk !== p2pkWire(xonly) || i.covenantId !== null) refuse(`funding input ${n} is not your wallet's — the funder signs only its own funds`, "PAYLOAD_MISMATCH"); });
        safe.inputs.forEach((i, n) => { if (i.sequence !== "0") refuse(`funding input ${n} carries sequence ${i.sequence} — a genesis funding input is spendable now, never relatively locked`, "PAYLOAD_MISMATCH"); }); // rc26 round-7 review R7-01
        /* Codex checkpoint 6 (UX-02 / UX-13): every funding input of a genesis is an ordinary single-key input and commits exactly the
         * ORDINARY compute budget the shared core derives (core/model/compute-budget-v7) — a substituted budget (0, 100, …) is refused. */
        if (!core.computeBudgetV7 || !core.computeBudgetV7.V7_BUDGET || !Number.isInteger(core.computeBudgetV7.V7_BUDGET.ORDINARY_INPUT)) refuse("the shared core carries no compute-budget model — the funding inputs' budgets cannot be bound", "REVIEW_MISSING");
        safe.inputs.forEach((i, n) => { if (i.computeBudget !== core.computeBudgetV7.V7_BUDGET.ORDINARY_INPUT) refuse(`funding input ${n} commits compute budget ${i.computeBudget}; an ordinary input commits exactly ${core.computeBudgetV7.V7_BUDGET.ORDINARY_INPUT}`, "PAYLOAD_MISMATCH"); });
        if (list.length !== safe.inputs.length) refuse("the wallet must sign every funding input of the genesis", "PAYLOAD_MISMATCH");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString(), rootSpk: expectedRootSpk });
      }
      const manifest = request.manifest;
      if (!manifest || !manifest.transaction || !manifest.action) refuse("the request carries no verified manifest to bind the transaction to", "REVIEW_MISSING");
      // rc21 review R6-02: the vault descriptors the SDK verified with travel on the request (their hash and the token
      // UTXO's script bind them); a token position spent without a descriptor now fails closed inside the verifier.
      const descriptors = request.descriptors && typeof request.descriptors === "object" && !Array.isArray(request.descriptors) ? request.descriptors : {};
      // Codex checkpoint 6 (UX-02 / UX-13): the vault's predecessor redeem script travels on the request too; the verifier rebuilds the
      // vault SUCCESSOR script from it around the reviewed successor state and refuses a substituted continuation (fail closed when absent).
      const redeemScripts = request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {};
      const ver = core.orgRootManifestV7.verifyOrgRootIntentManifest({ manifest, descriptors, redeemScripts });
      if (!ver || ver.verdict !== "VERIFIED") refuse(`local verification refused this root request (${((ver && ver.failures) || []).map((f) => f.name).join(", ") || "no verdict"})`, "REVIEW_REFUSED");
      if (String(manifest.network && manifest.network.networkId) !== String(network)) refuse(`this transaction is for ${manifest.network && manifest.network.networkId}, the wallet is on ${network}`, "NETWORK_MISMATCH");
      if (safe.id !== String(manifest.transaction.txId || "").toLowerCase()) refuse("the signing payload is not the reviewed transaction (transaction id differs)", "PAYLOAD_MISMATCH");
      const mism = frozenMismatches(manifest.transaction.frozenCanonicalJson, safe);
      if (mism.length) refuse(`the signing payload differs from the reviewed transaction: ${mism.join("; ")}`, "PAYLOAD_MISMATCH");
      const rootIdx = Number(request.rootInputIndex ?? 0);
      const rootIn = safe.inputs[rootIdx];
      const ro = manifest.root && manifest.root.outpoint;
      if (!rootIn || !ro || rootIn.transactionId !== String(ro.transactionId || "").toLowerCase() || rootIn.index !== Number(ro.index)) refuse("the declared root input does not spend the reviewed root outpoint", "PAYLOAD_MISMATCH");
      if (!manifest.fee || typeof manifest.fee.requiredFeeSompi !== "string" || !/^[0-9]+$/.test(manifest.fee.requiredFeeSompi)) refuse("the manifest carries no exact network fee — the fee cannot be bound", "REVIEW_MISSING");
      if (safe.fee !== BigInt(String(manifest.fee.requiredFeeSompi))) refuse(`the network fee ${core.amounts.sompiToKas(safe.fee)} KAS differs from the reviewed ${core.amounts.sompiToKas(BigInt(String(manifest.fee.requiredFeeSompi)))} KAS`, "FEE_MISMATCH");
      /* rc18 review R3-01 / rc19 review R4-01 + R4-02 / Codex checkpoint 3:
       * DESTINATIONS and INPUT CLOSURE. The declared covenant families are the
       * organizational root and every declared vault operation (its vault
       * covenant and, if any, its token position). The pinned verifier binds
       * every covenant input and every covenant-metadata output to a declared
       * family (noHiddenCovenantOperations / noHiddenCovenantOutputs) and the
       * rooted-vault manifests bind their own outputs (root continuation, vault
       * successor, token position, a terminal payout to the vault's pinned
       * recovery key). What nothing else binds is the FEE PAYER's change and
       * bare script outputs: every output without covenant metadata must be
       * the fee-input owner's own P2PK (at most one change) or a declared
       * terminal payout; a bare P2SH output (no covenant metadata) is never
       * legitimate; every input that is not the root input or a declared
       * covenant input must be the fee payer's own P2PK. Declared covenant ids
       * of the inputs are read from the frozen transaction (already compared
       * field by field to the payload above; the SDK's Safe JSON carries none). */
      if (safe.lockTime !== "0") refuse("the transaction carries a lock time — PolicyVault transactions never do", "PAYLOAD_MISMATCH");
      const frozenTx = JSON.parse(manifest.transaction.frozenCanonicalJson);
      const rootCov = String(manifest.root.covenantId || "").toLowerCase();
      if (!HEX64.test(rootCov)) refuse("the manifest carries no root covenant id", "REVIEW_MISSING");
      /* rc20 review R5-01: the declared families come from the INNER (hash-checked, byte-verified) vault manifests, and
       * the outer declaration must agree with them; the payout rule (R5-03) is bound to the verifier's own field
       * (`vault.recoveryPk`), index 0, the predecessor fee reserve, exactly once, only for a terminal operation. */
      const declared = new Set([rootCov]);
      const terminalPayouts = [];
      const terminalFamilies = new Set();
      for (const op of (Array.isArray(manifest.vaultOperations) ? manifest.vaultOperations : [])) {
        const iv = op && op.manifest && op.manifest.vault ? op.manifest.vault : null;
        if (!iv) refuse("a declared vault operation carries no inner manifest", "REVIEW_REFUSED");
        const innerCov = String(iv.covenantId || "").toLowerCase(), innerTok = iv.tokenCovenantId ? String(iv.tokenCovenantId).toLowerCase() : null;
        if (!HEX64.test(innerCov) || String(op.covenantId || "").toLowerCase() !== innerCov) refuse("a declared vault operation's covenant id is not its inner manifest's", "REVIEW_REFUSED");
        if ((op.tokenCovenantId ? String(op.tokenCovenantId).toLowerCase() : null) !== innerTok || (innerTok !== null && !HEX64.test(innerTok))) refuse("a declared vault operation's token covenant id is not its inner manifest's", "REVIEW_REFUSED");
        declared.add(innerCov);
        if (innerTok) declared.add(innerTok);
        if (op.manifest.action && op.manifest.action.terminal === true) {
          terminalFamilies.add(innerCov);
          const rk = String(iv.recoveryPk || "").toLowerCase();
          const reserve = op.manifest.accounting && op.manifest.accounting.kas ? String(op.manifest.accounting.kas.predecessorFeeReserve) : "";
          if (!HEX64.test(rk) || !/^[0-9]+$/.test(reserve)) refuse("a terminal vault operation carries no verifiable payout (recovery key / fee reserve)", "REVIEW_REFUSED");
          terminalPayouts.push({ spk: p2pkWire(rk), value: BigInt(reserve) });
        }
      }
      const frozenCov = (n) => { const fu = frozenTx.inputs[n] && frozenTx.inputs[n].utxo; return fu && fu.covenantId ? String(fu.covenantId).toLowerCase() : null; };
      const fuelIdx = safe.inputs.length - 1;
      const fuelOwner = fuelIdx !== rootIdx ? p2pkOwnerOf(safe.inputs[fuelIdx].spk) : null;
      if (safe.inputs.length > 1 && !fuelOwner) refuse("the fee input is not an ordinary single-key (P2PK) input", "PAYLOAD_MISMATCH");
      if (frozenCov(rootIdx) !== rootCov) refuse("the declared root input does not carry the root covenant id in the reviewed transaction", "PAYLOAD_MISMATCH");
      /* rc26 round-7 review R7-01: a hidden RELATIVE LOCK (non-zero input sequence) or a lockTime is a waiting condition the
       * review never names — a hostile server could make an approved emergency pause unminable for 2^32 DAA. Only the root
       * input of an AGE-GATED action (ownerRecover / succession) carries a sequence, and exactly the covenant's own delay
       * the verified manifest declares (action.minSequence); every other input is spendable NOW. */
      {
        const ageGated = manifest.action && typeof manifest.action.minSequence === "string" && /^[1-9][0-9]*$/.test(manifest.action.minSequence) && (manifest.action.name === "ownerRecover" || manifest.action.name === "succession");
        safe.inputs.forEach((i, n) => {
          const expectedSeq = n === rootIdx && ageGated ? manifest.action.minSequence : "0";
          if (i.sequence !== expectedSeq) refuse(n === rootIdx ? `the root input carries sequence ${i.sequence}; this action allows exactly ${expectedSeq} (${ageGated ? "the covenant's idle delay" : "no relative lock"})` : `input ${n} carries sequence ${i.sequence} — a hidden relative lock; every non-root input must be spendable now`, "PAYLOAD_MISMATCH");
        });
      }
      safe.inputs.forEach((i, n) => {
        if (n === rootIdx) return;
        const cov = frozenCov(n);
        if (cov !== null) {
          if (!declared.has(cov) || !isP2shWire(i.spk)) refuse(`input ${n} spends a covenant output that no declared operation accounts for`, "PAYLOAD_MISMATCH");
          if (i.covenantId !== null && i.covenantId !== cov) refuse(`input ${n} declares a different covenant id than the reviewed transaction`, "PAYLOAD_MISMATCH");
          return;
        }
        if (i.covenantId !== null) refuse(`input ${n} declares a covenant id the reviewed transaction does not have`, "PAYLOAD_MISMATCH");
        if (!fuelOwner || i.spk !== p2pkWire(fuelOwner)) refuse(`input ${n} is neither the root input, a declared vault-operation input nor the fee payer's own funds`, "PAYLOAD_MISMATCH");
      });
      let rootOutputs = 0, changeOutputs = 0, payoutOutputs = 0;
      const continued = new Set();
      safe.outputs.forEach((o, n) => {
        if (o.covenant) {
          if (!isP2shWire(o.spk)) refuse(`output ${n} declares covenant metadata but is not a covenant (P2SH) output`, "PAYLOAD_MISMATCH");
          if (!declared.has(o.covenant.covenantId)) refuse(`output ${n} continues a covenant that no declared operation accounts for`, "PAYLOAD_MISMATCH");
          // rc20 review R5-01: a root action never CREATES a covenant — the output must continue the covenant carried by the input it names, once
          const ai = Number(o.covenant.authorizingInput);
          if (!Number.isInteger(ai) || frozenCov(ai) !== o.covenant.covenantId) refuse(`output ${n} would CREATE a covenant (its authorizing input does not carry ${o.covenant.covenantId.slice(0, 8)}…) — a root action only continues existing covenants`, "PAYLOAD_MISMATCH");
          if (continued.has(ai)) refuse(`output ${n} continues an input that another output already continues`, "PAYLOAD_MISMATCH");
          continued.add(ai);
          if (terminalFamilies.has(o.covenant.covenantId)) refuse(`output ${n} continues a vault that this transaction closes`, "PAYLOAD_MISMATCH");
          if (o.covenant.covenantId === rootCov) rootOutputs += 1;
          return;
        }
        if (isP2shWire(o.spk)) refuse(`output ${n} sends ${core.amounts.sompiToKas(o.value)} KAS to a script destination that is neither the organization's root nor a declared vault operation`, "PAYLOAD_MISMATCH"); // rc19 review R4-01: a bare P2SH is never legitimate
        const payout = terminalPayouts.find((tp) => tp.spk === o.spk && tp.value === o.value);
        if (n === 0 && payout && payoutOutputs === 0 && terminalPayouts.length === 1) { payoutOutputs += 1; return; } // the ONE terminal payout: index 0, the pinned recovery key, exactly the predecessor fee reserve (bound by the rooted-vault verifier)
        if (fuelOwner && o.spk === p2pkWire(fuelOwner)) { changeOutputs += 1; return; }
        refuse(`output ${n} sends ${core.amounts.sompiToKas(o.value)} KAS to a destination that is neither the organization's root, a declared vault operation nor the fee payer's own wallet`, "PAYLOAD_MISMATCH");
      });
      if (terminalPayouts.length > 1) refuse("more than one terminal vault operation in one transaction", "PAYLOAD_MISMATCH");
      if (terminalPayouts.length === 1 && payoutOutputs !== 1) refuse("the terminal operation's payout to the pinned recovery key is missing", "PAYLOAD_MISMATCH");
      if (rootOutputs !== 1) refuse("the transaction does not continue the organizational root exactly once", "PAYLOAD_MISMATCH");
      if (changeOutputs > 1) refuse("more than one change output", "PAYLOAD_MISMATCH");
      if (role === "slot") {
        const env = slotEnvelope;
        if (!env || !env.slot || !env.root) refuse("no owner slot signing request", "REQUEST_NOT_SIGNABLE");
        if (String(env.txId || "").toLowerCase() !== safe.id) refuse("the slot signing request is for a different transaction", "PAYLOAD_MISMATCH");
        if (String(env.manifestHash || "") !== String(manifest.manifestHash || "")) refuse("the slot signing request is bound to a different review (manifest hash)", "PAYLOAD_MISMATCH");
        if (String(env.network) !== String(network)) refuse(`the slot signing request is for ${env.network}`, "NETWORK_MISMATCH");
        if (typeof env.unsignedSafeJson === "string" && env.unsignedSafeJson !== unsignedSafeJson) refuse("the slot signing request carries a different payload than the one being signed", "PAYLOAD_MISMATCH");
        if (!env.root.outpoint || String(env.root.outpoint.transactionId || "").toLowerCase() !== rootIn.transactionId || Number(env.root.outpoint.index) !== rootIn.index || Number(env.root.inputIndex) !== rootIdx) refuse("the slot signing request names a different root outpoint or input", "PAYLOAD_MISMATCH");
        if (list.length !== 1 || list[0] !== rootIdx) refuse("an owner slot signs the root input only", "PAYLOAD_MISMATCH");
        if (String(env.slot.publicKey || "").toLowerCase() !== xonly) refuse("the slot signing request is for another owner's key", "NOT_AN_ACTIVE_SLOT");
        const expected = Array.isArray(manifest.action.expectedSignerSlots) ? manifest.action.expectedSignerSlots : [];
        if (!expected.some((sl) => String(sl.publicKey || "").toLowerCase() === xonly && Number(sl.slot) === Number(env.slot.number))) refuse("your key is not one of this action's expected signer slots", "NOT_AN_ACTIVE_SLOT");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString() });
      }
      if (role === "fuel") {
        if (list.length !== 1) refuse("finalize signs exactly one fee input", "PAYLOAD_MISMATCH");
        const idx = list[0];
        if (idx === rootIdx || idx !== safe.inputs.length - 1) refuse("the fee input must be the last, non-root input", "PAYLOAD_MISMATCH");
        if (safe.inputs[idx].spk !== p2pkWire(xonly)) refuse("the fee input is not your wallet's own funds", "NOT_THE_SIGNER");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString(), fuelInputIndex: idx });
      }
      if (role === "succession") {
        if (String(manifest.action.name) !== "succession") refuse(`a ${manifest.action.name} action is not signed by a successor`, "REQUEST_NOT_SIGNABLE");
        /* rc18 review R3-03 / Codex UX-10: succession is authorized by the
         * root's PINNED successor key (manifest.root.template.successorPk),
         * whatever owner set (1..12, owner 1 changed — D1) it installs. */
        const pinned = String((manifest.root && manifest.root.template && manifest.root.template.successorPk) || "").toLowerCase();
        if (!HEX64.test(pinned) || pinned === "00".repeat(32)) refuse("this root has no designated successor", "REQUEST_NOT_SIGNABLE");
        if (pinned !== xonly) refuse("the connected wallet is not this root's designated successor", "NOT_THE_SIGNER");
        const after = manifest.ownerSet && manifest.ownerSet.after;
        const installed = after && Array.isArray(after.slots) ? after.slots.filter((sl) => sl && sl.publicKey) : [];
        if (installed.length < 1 || installed.length > 12) refuse("the succession installs no valid owner set", "REVIEW_REFUSED");
        for (const i of list) {
          if (i === rootIdx) continue;
          if (safe.inputs[i].spk !== p2pkWire(xonly)) refuse(`input ${i} is neither the root input nor your own funds`, "PAYLOAD_MISMATCH");
        }
        if (!list.includes(rootIdx)) refuse("the successor must sign the root input", "PAYLOAD_MISMATCH");
        return Object.freeze({ ok: true, role, txId: safe.id, feeSompi: safe.fee.toString() });
      }
      refuse(`unknown signing role ${role}`, "REQUEST_NOT_SIGNABLE");
    }

    /* ================================================================
     * (d) SLOT SIGNING — own slot only, through the pinned core.
     * ================================================================ */

    /*
     * `slotEnvelope` = the server's GET .../slot-request/:slot response (the
     * core.orgRootSlotV7.createRootSlotSigningRequest output). `request` =
     * the containing ORG_ROOT_REQUEST record (carries `.manifest`).
     * `adapter` = the connected wallet's signer adapter (the SAME
     * `session().adapter` app-v4.js already uses; must expose
     * `signInputs(unsignedSafeJson, signInputsList, {network,
     * expectedSignerAddress})`, exactly as web/wallet.js's canonical wallet
     * session wraps web/signer-kasware-adapter.js).
     *
     * Refuses BEFORE invoking the wallet when:
     *   - the manifest does not independently re-verify locally, or
     *   - the connected wallet's own resolved x-only key is not the slot's
     *     key (a FOREIGN-SLOT attempt — "sign only your own slot").
     */
    async function signOwnSlot({ request, slotEnvelope, adapter, connectedXOnly, network, expectedSignerAddress, descriptors }) {
      if (!request || !request.manifest) throw fail("no manifest on this request — refusing to sign", "OWNER_PATH_TAKES_NO_SIGNATURE");
      // rc16 review N-02: owner approvals are collected ONLY while the request
      // is AUTHORIZED. Once it is finalized (SIGNED) or beyond, a still-PENDING
      // slot has nothing to sign — refuse here, before the wallet is ever
      // invoked (the server would refuse the posted signature anyway).
      if (request.state !== "AUTHORIZED") throw fail(`this request is ${request.state || "in an unknown state"} — owner approvals are only collected while it is AUTHORIZED; there is nothing to sign`, "REQUEST_NOT_SIGNABLE");
      const verification = core.orgRootManifestV7.verifyOrgRootIntentManifest({ manifest: request.manifest, descriptors: descriptors || (request.descriptors && typeof request.descriptors === "object" && !Array.isArray(request.descriptors) ? request.descriptors : {}), redeemScripts: request.redeemScripts && typeof request.redeemScripts === "object" && !Array.isArray(request.redeemScripts) ? request.redeemScripts : {} }); // Codex checkpoint 6: successor-script carriage
      if (verification.verdict !== "VERIFIED") {
        throw fail(`local verification refused this root request (${verification.failures.map((f) => f.name).join(", ")}) — refusing to invoke the wallet`, "RESPONSE_BINDING_MISMATCH");
      }
      if (typeof connectedXOnly !== "string" || connectedXOnly.toLowerCase() !== String(slotEnvelope.slot.publicKey).toLowerCase()) {
        throw fail(
          `the connected wallet does not hold slot ${slotEnvelope.slot.number} of this root — an owner may sign ONLY their own slot`,
          "NOT_AN_ACTIVE_SLOT"
        );
      }
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const signInputsList = slotEnvelope.signerRequest && slotEnvelope.signerRequest.signInputs;
      // UX-02: the envelope, the reviewed manifest and the exact payload are bound before the wallet
      bindRootSigningPayload({ role: "slot", request, unsignedSafeJson: slotEnvelope.unsignedSafeJson, signInputs: signInputsList, network, connectedXOnly, slotEnvelope });
      const signed = await adapter.signInputs(slotEnvelope.unsignedSafeJson, signInputsList, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      let response;
      try {
        response = core.orgRootSlotV7.buildRootSlotSignatureResponse({ request: slotEnvelope, signedSafeJson: signed, signerAddress: expectedSignerAddress });
      } catch (e) {
        throw fail(e.message, displayCodeFor(e), { cause: e });
      }
      return response;
    }

    /*
     * (d) IMPORT another owner's response envelope (paste / file / QR via
     * the existing air-gap shuttle). Structural pre-check ONLY — the server
     * remains the authority (verifyRootSlotSignatureResponse, with the real
     * predecessor owner set). Refuses closed on anything malformed, on a
     * slot already signed, or on a response that names a different request.
     */
    function validateImportedEnvelope(request, rawText) {
      let parsed;
      try {
        parsed = typeof rawText === "string" ? JSON.parse(rawText) : rawText;
      } catch (e) {
        return { ok: false, code: "RESPONSE_BINDING_MISMATCH", message: `not valid JSON: ${e.message}` };
      }
      if (!parsed || typeof parsed !== "object") return { ok: false, code: "RESPONSE_BINDING_MISMATCH", message: "empty envelope" };
      if (parsed.responseVersion !== core.orgRootSlotV7.ORG_ROOT_SLOT_RESPONSE_VERSION_1) {
        return { ok: false, code: "RESPONSE_BINDING_MISMATCH", message: `unknown response version ${JSON.stringify(parsed.responseVersion)} — failing closed` };
      }
      if (request && request.manifestHash && parsed.manifestHash !== request.manifestHash) {
        return { ok: false, code: "RESPONSE_BINDING_MISMATCH", message: "this envelope describes a different manifest than the request you are collecting signatures for" };
      }
      const slotNo = parsed.slot && Number(parsed.slot.number);
      const known = (request && request.slots || []).find((s) => Number(s.slot) === slotNo);
      if (!known) return { ok: false, code: "NOT_AN_ACTIVE_SLOT", message: `slot ${slotNo} is not one of this request's expected signer slots` };
      if (known.status === "SIGNED") return { ok: false, code: "DUPLICATE_SLOT_SIGNATURE", message: `slot ${slotNo} has already signed` };
      try {
        core.ownerSetV7.normalizeSlotSignatureHex(parsed.signatureHex, "imported slot signature");
      } catch (e) {
        return { ok: false, code: displayCodeFor(e), message: e.message };
      }
      return { ok: true, response: parsed, slot: slotNo };
    }

    /* ================================================================
     * Network operations (contract §2 routes, exactly)
     * ================================================================ */
    const fetchOrgRoots = () => api.getJSON("/org-roots");
    const fetchOrgRoot = (rootId) => api.getJSON(`/org-roots/${encodeURIComponent(rootId)}`);
    const fetchRequests = (rootId) => api.getJSON(`/org-roots/${encodeURIComponent(rootId)}/requests`);
    const fetchRequest = (rootId, requestId) => api.getJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}`);
    /* The server answers { slotRequest: <envelope> } (server/src/org-roots.js);
     * the bare envelope is what signOwnSlot consumes. Real-browser finding
     * 2026-09-05: the wrapper was passed through, so no owner slot could be
     * approved from the web UI. A bare envelope (older shape) still passes. */
    const fetchSlotRequest = async (rootId, requestId, slot) => {
      const body = await api.getJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}/slot-request/${encodeURIComponent(slot)}`);
      const env = body && body.slotRequest && typeof body.slotRequest === "object" ? body.slotRequest : body;
      if (!env || !env.slot || !env.signerRequest || typeof env.unsignedSafeJson !== "string") throw fail("the server did not return a slot signing request envelope — refusing to sign", "RESPONSE_BINDING_MISMATCH");
      return env;
    };
    const fetchRootedVaults = (rootId) => api.getJSON(`/org-roots/${encodeURIComponent(rootId)}/vaults`);

    async function createGenesisRequest(form) {
      const normalized = await normalizeWizardGenesis(form);
      const { request } = await api.postJSON("/org-roots", normalized.body);
      return { request, preview: normalized };
    }

    /*
     * (d) create a root action / vault-owner-operation request. Two LOCAL
     * fail-closed guards mirror the covenant's own rules before any network
     * call: ROOT_PENDING_REQUEST (one owner-op transaction per root
     * transition) and ROOT_FROZEN (an action other than the ones the frozen
     * root still accepts). Both are re-enforced server-side and by the
     * covenant; this only avoids a round trip for an outcome that is
     * already known locally.
     */
    async function createRootRequest(orgRoot, { action, params, vaultOperations, signerAddress }) {
      if (!orgRoot) throw fail("no root loaded", "HOSTED_ORG_IS_NOT_A_ROOT");
      if (orgRoot.pendingRequestId) throw fail("a request is already pending on this root — only one owner-operation transaction may be in flight per root transition", "ROOT_PENDING_REQUEST");
      const frozen = !!(orgRoot.state && Number(orgRoot.state.frozen) === 1);
      const info = core.ownerSetV7.ROOT_ACTIONS_V7[action];
      if (frozen && info && info.requiresUnfrozen) {
        throw fail(`the root is FROZEN — ${action} is refused until it is unfrozen`, "ROOT_FROZEN");
      }
      const body = { action, params: params || {}, ...(vaultOperations ? { vaultOperations } : {}), signerAddress };
      const { request } = await api.postJSON(`/org-roots/${encodeURIComponent(orgRoot.rootCovenantId)}/requests`, body);
      return request;
    }

    const postSlotSignature = (rootId, requestId, slot, response) =>
      api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}/slot-signatures`, { slot, response });

    /* The fuel input of every root transaction is its LAST input (SDK
     * finalizers: root-only [root, fuel]; rooted owner op [vault, root,
     * fuel]). Codex checkpoint 6 (UX-03): the wallet that FINALIZES is the
     * OWNER OF THAT FEE INPUT — read from the frozen transaction's own
     * previous-output script — never the request's `createdBy`, which is
     * metadata only: the SDK explicitly supports fuel supplied by a wallet
     * other than the initiating owner (change returns to the fuel owner). */
    const ORDINARY_SIGSCRIPT_LEN = 66; // 0x41 push + 64-byte Schnorr signature + SIGHASH_ALL byte
    function fuelInputIndex(request) {
      const list = request && request.transaction && Array.isArray(request.transaction.signInputs) ? request.transaction.signInputs : null;
      if (!list || list.length < 2) return null;
      const idx = list[list.length - 1].index;
      if (Number(idx) === Number(request.rootInputIndex)) return null;
      return Number(idx);
    }
    /* The fee payer of a request: the x-only key whose P2PK script the LAST (fee) input spends, plus the owner slot
     * that holds it when it is one (for display). null when the request carries no verifiable single-key fee input. */
    function feePayerOf(request) {
      const idx = fuelInputIndex(request);
      if (idx === null || !request || !request.transaction || typeof request.transaction.unsignedSafeJson !== "string") return null;
      let safe = null;
      try { safe = JSON.parse(request.transaction.unsignedSafeJson); } catch { return null; }
      const inp = safe && Array.isArray(safe.inputs) ? safe.inputs[idx] : null;
      const key = inp && inp.utxo ? p2pkOwnerOf(spkWireOf(inp.utxo.scriptPublicKey)) : null;
      if (!key) return null;
      const slot = (request.slots || []).find((sl) => sl && sl.publicKey && String(sl.publicKey).toLowerCase() === key) || null;
      return Object.freeze({ xonly: key, inputIndex: idx, slot: slot ? slot.slot : null, address: slot && slot.address ? String(slot.address) : null, label: slot && slot.label ? String(slot.label) : "" });
    }
    function describeFeePayer(payer) {
      if (!payer) return "the wallet that funds the network fee";
      const slotText = payer.slot !== null ? ` (owner slot ${payer.slot}${payer.label ? `, ${payer.label}` : ""})` : " (not an owner slot)";
      return payer.address ? `${payer.address}${slotText}` : `the wallet holding key ${payer.xonly}${slotText}`;
    }
    function fuelOwnerGate(request, viewerXOnly) {
      if (!request) return { ok: false, reason: "no request", payer: null };
      const payer = feePayerOf(request);
      if (!payer) return { ok: false, reason: "this request carries no verifiable fee input (its previous-output script is not a single-key P2PK) — finalize is disabled", payer: null };
      const me = String(viewerXOnly || "").toLowerCase();
      if (!HEX64.test(me) || me !== payer.xonly) {
        return { ok: false, reason: `only the wallet that funds the network fee — ${describeFeePayer(payer)} — can finalize this request: its wallet signs the fee input${request.createdBy ? ` (the request was started by ${request.createdBy})` : ""}`, payer };
      }
      return { ok: true, reason: "", payer };
    }
    /*
     * FINALIZE = quorum met → the starting owner's wallet signs the fee
     * (fuel) input → POST /finalize with that signature script. Real-browser
     * finding 2026-09-05: the previous UI posted an empty body, so every
     * M-of-N request was refused SIGNATURE_INVALID at finalize. With no
     * adapter (in-process callers holding a pre-signed fuel script) the
     * caller may pass `fuelSignatureScriptHex` directly.
     */
    async function finalizeRequest(rootId, requestId, request, { adapter, network, expectedSignerAddress, connectedXOnly, fuelSignatureScriptHex } = {}) {
      const gate = finalizeGate(request);
      if (!gate.enabled) throw fail(gate.reason, "UNDER_QUORUM");
      const body = {};
      let fuelSig = fuelSignatureScriptHex;
      if (!fuelSig && adapter) {
        if (typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
        const owner = fuelOwnerGate(request, connectedXOnly); // Codex checkpoint 6 (UX-03): the connected KEY must own the fee input
        if (!owner.ok) throw fail(owner.reason, "NOT_THE_SIGNER");
        const idx = fuelInputIndex(request);
        if (idx === null || !request.transaction || typeof request.transaction.unsignedSafeJson !== "string") throw fail("this request carries no fee input to sign — refusing to invoke the wallet", "REQUEST_NOT_SIGNABLE");
        // UX-13: the review verdict, the exact payload, the fee-input selection,
        // its previous-output script and the funding identity are enforced at
        // the signing boundary, not only in the displayed control.
        bindRootSigningPayload({ role: "fuel", request, unsignedSafeJson: request.transaction.unsignedSafeJson, signInputs: [{ index: idx, sighashType: 1 }], network, connectedXOnly });
        const signed = await adapter.signInputs(request.transaction.unsignedSafeJson, [{ index: idx, sighashType: 1 }], { network, expectedSignerAddress });
        let parsed;
        try { parsed = JSON.parse(signed); } catch (e) { throw fail(`wallet returned malformed signed JSON: ${e.message}`, "INVALID_SIGNATURE_RESPONSE"); }
        fuelSig = parsed && Array.isArray(parsed.inputs) && parsed.inputs[idx] ? String(parsed.inputs[idx].signatureScript || "").toLowerCase() : "";
      }
      if (fuelSig !== undefined && fuelSig !== null && fuelSig !== "") {
        if (!/^[0-9a-f]+$/.test(fuelSig) || fuelSig.length / 2 !== ORDINARY_SIGSCRIPT_LEN) throw fail(`the fee-input signature script must be exactly ${ORDINARY_SIGSCRIPT_LEN} bytes — refusing to finalize`, "INVALID_SIGNATURE_RESPONSE");
        body.fuelSignatureScriptHex = fuelSig;
      }
      return api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}/finalize`, body);
    }
    async function submitRequest(rootId, requestId, request) {
      if (request && request.state !== "SIGNED") throw fail(`request is ${request.state}, not SIGNED — cannot submit`, "UNDER_QUORUM");
      return api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}/submit`, {});
    }
    const rejectRequest = (rootId, requestId, reason) =>
      api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/requests/${encodeURIComponent(requestId)}/reject`, { reason });
    const reconcileRoot = (rootId) => api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/reconcile`, {});

    /*
     * (b) GENESIS SIGNING — the ONE funder signature (contract §2: "the
     * funder wallet signs its own UTXO via the existing wallet signature
     * route pattern"). This is NOT a slot signature: the funder pays for
     * root creation and need not be one of the N owners, so it never goes
     * through the M-of-N slot-signature collection path. `request.build`
     * carries the frozen unsigned transaction exactly like a v0.4.1
     * request's `request.transaction` does; the endpoint name mirrors
     * `/wallet/v4/requests/:id/signature` (singular — one signer, one
     * signature), distinct from the plural `/slot-signatures` M-of-N path.
     *
     * The SAME single-signer shape also authorizes SUCCESSION: the
     * covenant's `rootSuccession` entrypoint takes ONE `successorSig`
     * directly, never the 12-slot owner blob —
     * core.orgRootSlotV7.createRootSlotSigningRequest explicitly refuses a
     * succession action with SUCCESSION_TAKES_NO_SLOTS, so succession is
     * signed here, not through signOwnSlot. `signSingleSignerRequest` is
     * the general name; `signGenesisRequest` is kept as an alias for the
     * genesis call site's readability.
     */
    async function signSingleSignerRequest({ request, adapter, network, expectedSignerAddress, connectedXOnly, crossCheck, norm }) {
      /* The API presents the frozen unsigned transaction as `request.transaction`
       * ({ unsignedSafeJson, signInputs }) and STRIPS the SDK `build` object
       * (server/src/org-roots.js presentOrgRootRequest). Real-browser finding
       * 2026-09-05: this function read `request.build`, so a root genesis could
       * never be signed from the web UI. `build` is accepted as a fallback for
       * in-process callers that hold the raw record. */
      const tx = request && (request.transaction && request.transaction.unsignedSafeJson ? request.transaction : request.build && request.build.unsignedSafeJson ? request.build : null);
      if (!tx) throw fail("this request carries no frozen transaction to sign — refusing to invoke the wallet", "REQUEST_NOT_SIGNABLE");
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      // UX-02: genesis (funder) and succession (successor) are bound to the
      // review and the exact payload before the wallet; anything else is not
      // a single-signer request and is refused.
      const role = request.kind === "rootGenesis" ? "genesis" : request.action === "succession" ? "succession" : null;
      if (!role) throw fail(`a ${request.kind || "?"}/${request.action || "?"} request is not signed by a single signer — refusing to invoke the wallet`, "REQUEST_NOT_SIGNABLE");
      bindRootSigningPayload({ role, request, unsignedSafeJson: tx.unsignedSafeJson, signInputs: tx.signInputs, network, connectedXOnly, crossCheck, norm });
      const signed = await adapter.signInputs(tx.unsignedSafeJson, tx.signInputs, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/org-roots/${encodeURIComponent(request.rootCovenantId)}/requests/${encodeURIComponent(request.id)}/signature`, { signedSafeJson: signed });
    }
    const signGenesisRequest = signSingleSignerRequest;

    /* ================================================================
     * (e) ROOTED VAULTS — owner ops are ROOT REQUESTS, never a single-
     * owner button; delegate spend/deposit is /wallet/v7/requests.
     * ================================================================ */
    async function createRootedVault(rootId, body) {
      const { request } = await api.postJSON(`/org-roots/${encodeURIComponent(rootId)}/vaults`, body);
      return request;
    }

    /* Rooted-vault OWNER operations always route through createRootRequest
     * with vaultOperations — this renderer exists so a caller never wires a
     * single-owner-signature button for a rooted vault by mistake.
     *
     * rc26 round-7 review R7-05 (owner-approved browser initiation, launch
     * scope 2026-09-08): the panel renders ONE control per SUPPORTED owner
     * operation of a policyvault-0.7-payment vault, wired by app-v4.js
     * (`[data-rootvaultop]` → openRootedVaultOpFlow). Every control is
     * offered only when vaultOpAvailability() allows it (viewer holds an
     * owner slot, the root is not reserved or frozen, the vault is live and
     * in the right paused/unpaused state); a disabled control carries the
     * exact reason in its title. The server and the covenant re-decide all
     * of it — this is presentation, never authority. */
    function renderRootedVaultOwnerOpsHtml(vault, orgRoot, opts = {}) {
      const { viewerXOnly = null, pendingRequest = null, networkId = null, loaded = true } = opts || {};
      const v = vault || {};
      const rootId = orgRoot && orgRoot.rootCovenantId;
      const live = v.live && typeof v.live === "object" ? v.live : null;
      const supported = v.contractVersion === SUPPORTED_ROOTED_PROFILE;
      const guardedBy = pendingRequest && Array.isArray(pendingRequest.vaultOperations) && pendingRequest.vaultOperations.some((op) => op && op.vaultId === v.vaultId) ? pendingRequest : null;
      const paused = !!(live && live.paused === true);
      const terminal = !!(v.status && String(v.status) !== "ACTIVE" && String(v.status) !== "PAUSED");
      const badge = !loaded ? "PAUSED" : terminal ? "RECOVERED" : paused ? "PAUSED" : live ? "ACTIVE" : "PAUSED";
      const badgeText = !loaded ? "NOT LOADED" : terminal ? String(v.status) : paused ? "PAUSED" : live ? "ACTIVE" : "NO LIVE OUTPOINT";
      const tokenLine = live ? (live.tokenPosition && live.tokenPosition.state ? `token position ${String(live.tokenPosition.state.amount)} atomic units` : "no token position yet") : "";
      const statusLine = !loaded
        ? "This vault's current state could not be loaded — reload before starting an owner operation."
        : live
          ? `Fee reserve ${String(live.feeReserveKas)} KAS · ${paused ? "PAUSED — agent payments stopped" : "agent payments allowed under the installed rules"} · ${tokenLine} · generation ${String(v.generation ?? "?")}`
          : terminal ? `This vault is ${String(v.status)} — it holds nothing and accepts no further owner operation.` : "No confirmed on-chain outpoint yet — use Verify state on the root after the genesis lands.";
      const agents = Array.isArray(v.agents) ? v.agents : null;
      const agentLine = agents ? (agents.length ? `${agents.length} delegate rule${agents.length === 1 ? "" : "s"} installed (${agents.map((a) => `agent ${short(a.agentPk)} → ${Array.isArray(a.recipients) ? a.recipients.length : 0} recipient${Array.isArray(a.recipients) && a.recipients.length === 1 ? "" : "s"}`).join("; ")})` : "no delegate rules installed — no agent can pay from this vault") : "";
      const buttons = supported && loaded
        ? VAULT_OP_ORDER.map((op) => {
            const info = vaultOpInfo(op);
            if (!info) return "";
            const a = vaultOpAvailability({ op, vault: v, orgRoot, viewerXOnly, pendingRequestId: pendingRequest ? pendingRequest.id : (orgRoot && orgRoot.pendingRequestId) || null, networkId });
            if (!a.offered) return "";
            return `<button type="button"${a.enabled ? "" : " disabled"} class="${info.dangerous ? "warn" : info.rootAction === "freeze" ? "warn" : ""}" data-rootvaultop="${esc(op)}" data-vault="${esc(v.vaultId)}" data-root="${esc(rootId)}" title="${esc(a.enabled ? info.describe : a.reason)}">${esc(info.label)}</button>`;
          }).join("")
        : "";
      return (
        `<div class="panel" data-rooted-vault-owner-ops="${esc(v.vaultId)}" data-root="${esc(rootId)}" data-vault-profile="${esc(v.contractVersion || "")}">` +
        `<div class="vault-head"><span class="vault-title">${esc(v.label || short(v.vaultId))}</span> <span><span class="badge ${badge}">${esc(badgeText)}</span> <span class="badge ver">${esc(v.contractVersion || "rooted vault")}</span></span></div>` +
        `<div class="kv-line mono" style="word-break:break-all">vault ${esc(v.vaultId)}</div>` +
        `<div class="kv-line">${esc(statusLine)}</div>` +
        (agentLine ? `<div class="kv-line">${esc(agentLine)}</div>` : "") +
        (v.recoveryPk ? `<div class="kv-line">Pinned recovery key — Close &amp; recover pays everything here, nowhere else: <span class="mono" style="word-break:break-all">${esc(v.recoveryPk)}</span></div>` : "") +
        `<div class="hint">Owner operations on this vault are authorized by the organizational root's M-of-N owner quorum — they are created as ROOT REQUESTS, never a single-owner signature. Choose one, enter its values, PolicyVault builds the exact transaction; every owner reviews and signs their own slot here, the wallet that funds the network fee finalizes, anyone submits. ONE vault operation per root transition.</div>` +
        (guardedBy
          ? `<div class="opbanner warn" data-vault-guarded-by="${esc(guardedBy.id)}">This vault is guarded by the pending request ${esc(actionLabel(guardedBy.action))} — ${esc(vaultOpLabel(guardedBy.vaultOperations[0].action))} (${esc(guardedBy.id)}), state ${esc(guardedBy.state)}: no other owner operation or agent payment build can start on it until that request completes or is withdrawn. <button type="button" data-vieworequest="${esc(guardedBy.id)}">Open that request</button></div>`
          : "") +
        (!loaded
          ? ""
          : !supported
            ? `<div class="hint">${esc(v.contractVersion === "policyvault-0.7-payment-hd" ? "Hierarchical-delegation vaults are a CANDIDATE profile — owner operations are not offered in this browser." : `Owner operations are offered only for ${SUPPORTED_ROOTED_PROFILE} vaults.`)}</div>`
            : `<div class="actions" data-rooted-vault-ops="${esc(v.vaultId)}">${buttons}</div>`) +
        `</div>`
      );
    }

    /* Delegate spend/deposit — single-signature, no root input (contract
     * §2 `/wallet/v7/requests`). Same intent -> build -> sign -> submit
     * shape as the v0.4.1 agent path, over the v0.7 endpoint. */
    async function buildDelegateRequest({ vaultId, action, params, signerAddress }) {
      const { request } = await api.postJSON("/wallet/v7/requests", { vaultId, action, params, signerAddress });
      return request;
    }
    async function signDelegateRequest({ request, adapter, network, expectedSignerAddress }) {
      if (!adapter || typeof adapter.signInputs !== "function") throw fail("wallet is not connected", "WALLET_NOT_READY");
      const signed = await adapter.signInputs(request.transaction.unsignedSafeJson, request.transaction.signInputs, { network, expectedSignerAddress });
      if (typeof signed !== "string" || !signed.trim()) throw fail("wallet returned no signed transaction", "INVALID_SIGNATURE_RESPONSE");
      return api.postJSON(`/wallet/v7/requests/${encodeURIComponent(request.requestId)}/signature`, { signedSafeJson: signed });
    }
    const submitDelegateRequest = (requestId) => api.postJSON(`/wallet/v7/requests/${encodeURIComponent(requestId)}/submit`, {});

    /* ================================================================
     * (a) hosted-vs-root Organizations section split
     * ================================================================ */
    // Discovery controls what the UI offers; the SDK remains authoritative.
    // Root genesis currently requires both the root and payment generation.
    function rootCreationAvailability({ networkId, capabilities } = {}) {
      const unavailable = (reason) => ({ enabled: false, reason });
      if (!["mainnet", "testnet-10"].includes(networkId) || !capabilities || capabilities.networkId !== networkId ||
          !Array.isArray(capabilities.contract && capabilities.contract.creatableCovenantVersions)) {
        return unavailable("Organizational root creation availability could not be confirmed. Reopen Organizations to check again. Existing roots and hosted organization grouping remain available.");
      }
      const versions = capabilities.contract.creatableCovenantVersions;
      if (!versions.includes("policyvault-0.7-root") || !versions.includes("policyvault-0.7-payment")) {
        return unavailable(`On-chain organizational roots are not available for creation on ${networkId} in this release. Use Create Vault for a single-owner vault, or create a hosted organization below to group vaults.`);
      }
      return { enabled: true, reason: "" };
    }

    function renderOnChainRootSummaryHtml(orgRoots, availabilityContext) {
      const creation = rootCreationAvailability(availabilityContext);
      const rows = (orgRoots || []).map((r) => {
        const frozen = !!r.frozen;
        return (
          `<tr><td>${esc(r.label || r.rootCovenantId)}</td><td>${esc(r.ownerSlotsActive)}</td>` +
          `<td>${esc(r.ownerM)} of ${esc(r.ownerSlotsActive)} owners</td>` +
          `<td><span class="badge ${frozen ? "PAUSED" : "ACTIVE"}">${frozen ? "FROZEN" : "ACTIVE"}</span></td>` +
          `<td><button data-viewroot="${esc(r.rootCovenantId)}">Open</button></td></tr>`
        );
      }).join("");
      return (
        `<div class="panel" data-org-root-section="on-chain">` +
        `<h4 style="margin-top:0">On-chain organizational root (covenant-enforced M-of-N)</h4>` +
        `<div class="hint">Shared ownership that is real: several owners approve changes together (for example 2 of 3), enforced by the covenant on Kaspa — a NEW covenant generation (policyvault-0.7-root), independent of hosted organization metadata. Legacy vaults keep exactly ONE on-chain owner key and are never presented as M-of-N.</div>` +
        (rows ? `<table class="mtable"><thead><tr><th>Root</th><th>Owners</th><th>Changes need</th><th>Status</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty">No organizational roots yet.</div>`) +
        (!creation.enabled ? `<div class="opbanner warn" id="v4-orgroot-availability" role="status">${esc(creation.reason)}</div>` : "") +
        `<button id="v4-orgroot-create-btn" class="primary" style="margin-top:0.6rem"${creation.enabled ? "" : ' disabled aria-describedby="v4-orgroot-availability"'}>Create organizational root</button>` +
        `</div>`
      );
    }

    /* ================================================================
     * PLAIN-LANGUAGE GOVERNANCE (owner UX directive 2026-09-05)
     * Every sentence below states what the FROZEN v0.7-root covenant
     * actually does (docs/postlaunch/v0.7-organizational-root-design.md
     * §2.4–2.6, core/model/owner-set-v7.js, core/model/vault-state-v7.js
     * OWNER_OP_ROOT_AUTHORITY_V7): what each quorum unlocks, what a freeze
     * does and does NOT stop, how recovery and succession are gated by the
     * root output's relative age, and that both land frozen.
     * ================================================================ */
    const DUR = core.durationDaa || null;
    const SETUP = setup || null;
    function requireSetup(fn) {
      if (!SETUP) throw fail(`org-root-ui: ${fn} requires the setup components (web/setup-ui.js)`, "SETUP_UNAVAILABLE");
      return SETUP;
    }
    function describeDelay(daa) {
      if (!DUR) return `${daa} DAA score`;
      try { return `${DUR.describeDaa(String(daa), { largestUnit: "day" }).text} (exactly ${daa} DAA score)`; } catch { return `${daa} DAA score`; }
    }
    /* Approximate only — for rows whose exact value lives in a technical panel. */
    function approxDelay(daa) {
      if (!DUR) return `${daa} DAA score`;
      try { return DUR.describeDaa(String(daa), { largestUnit: "day" }).text; } catch { return `${daa} DAA score`; }
    }
    /* Measured relay-floor fees (design §14.5, production bytes on the real
     * engine): presentation ESTIMATES for planning; the exact fee of a built
     * transaction always comes from the frozen bytes. */
    const FEE_ESTIMATE = Object.freeze({ rootGenesisKas: "0.002083", rootActionKas: "0.0264", vaultOwnerOpKas: "0.0461" });
    const ACTION_LABEL = Object.freeze({
      authorize: "Authorize (heartbeat)",
      rotate: "Change owners or rules",
      freeze: "Emergency freeze",
      unfreeze: "Unfreeze",
      ownerRecover: "Recover control",
      succession: "Succession",
      rootGenesis: "Organizational root creation",
      rootAction: "Governance action",
      rootedVaultGenesis: "Rooted vault creation"
    });
    function actionLabel(action) {
      return Object.prototype.hasOwnProperty.call(ACTION_LABEL, String(action)) ? ACTION_LABEL[action] : String(action || "action");
    }
    const ROOT_COPY = Object.freeze({
      OWNERS: "Owners hold this organization's governance authority on the Kaspa chain. Each owner signs with their own wallet; PolicyVault never holds a key. Between 1 and 12 owners.",
      APPROVE: (m, n) => `Any ${m} of these ${n} owner${n === 1 ? "" : "s"} must sign to approve a governance action: a vault owner operation (changing an agent's rules, topping up a fee reserve, pausing or unpausing, closing a vault), a change of owners or rules, an unfreeze, and the routine heartbeat authorization.`,
      FREEZE: (k, m, n) => `Any ${k} of the ${n} owner${n === 1 ? "" : "s"} can freeze governance in an emergency. While frozen, no governance action can be approved for any vault of this organization; the root itself accepts only a change of owners or rules, an unfreeze, recovery and succession. A freeze does NOT stop agent payments — every agent keeps paying within its existing rules. The freeze can emergency-pause at most ONE vault in the same transaction; to stop other vaults, ${m} of ${n} owners must unfreeze and then pause each vault. Owners who freeze gain no other power: they cannot spend, change owners, or unfreeze (unfreezing needs ${m} of ${n}).`,
      RECOVERY: (r, n, wait) => `If no governance transaction touches this root for ${wait}, any ${r} of the ${n} owner${n === 1 ? "" : "s"} can install a new set of owners (typically to replace lost keys). Any governance transaction restarts the wait, so a routine heartbeat authorization keeps recovery closed while the owners are active. Recovery lands the root FROZEN: the installed owners must unfreeze with their own approval quorum (M of N of the new set) before normal governance resumes. The waiting period is fixed at creation; whether recovery is on, and how many owners it needs, can be changed later by changing owners and rules.`,
      RECOVERY_OFF: (successionOn) => `Recovery is off. If too many owner keys are lost, ${successionOn ? "only the designated successor can regain control, after its waiting period. The installed owners must unfreeze with their own approval quorum before they can manage and close the organization's vaults" : "no one can regain control, and whatever remains in the vaults can no longer be closed out or recovered — it stays locked"}. Agents keep paying within their rules until the fee reserve or the deposit is exhausted (budgets reset every period). Recovery can be switched on later by changing owners and rules; it would then use the root's fixed recovery waiting period.`,
      SUCCESSION: (wait) => `A designated successor is one wallet that can take over the whole organization on its own if no governance transaction touches this root for ${wait}. Until then it has no power at all. Succession installs the set of owners the successor chooses — owner 1 must change, and a previous owner keeps authority only if the successor lists that key again — and lands the root FROZEN: the installed owners then unfreeze with their own approval quorum (M of N of the new set). This choice is permanent: the successor and its waiting period cannot be changed after creation.`,
      SUCCESSION_OFF: "No successor. This cannot be added later: the successor and its waiting period are fixed when the root is created.",
      WAIT_RESET: "The wait is counted from the age of the current root output on the Kaspa chain, not from a login, a payment, or a calendar date. Any governance transaction creates a new root output and restarts it.",
      FUNDING: `The KAS locked in this organization's on-chain root. It is not spending money: the root never pays anyone, and this amount can never be withdrawn — it stays locked for the life of the organization. Governance actions are paid for by the wallet that starts them (about ${FEE_ESTIMATE.rootActionKas} KAS each; about ${FEE_ESTIMATE.vaultOwnerOpKas} KAS for a vault owner operation — measured relay-floor fees, estimates), never from this amount. PolicyVault checks the amount against Kaspa's minimum-output rule when it builds the transaction.`,
      MAX_LOSS: "A covenant safety cap on how much one governance transaction may take from the governance funding. PolicyVault's own transactions take nothing (the starting wallet pays the network fee), so the root normally loses 0 KAS; the cap bounds what any owner-signed transaction could ever take. Keep the default unless you have a reason.",
      FUNDER: "This wallet pays the governance funding plus the network fee and signs the creation transaction. Paying for the setup grants no ownership: only the owners listed hold authority.",
      LABEL: "A name for this organization root in PolicyVault. It is not written to the chain.",
      HOSTED_VS_ROOT: "An on-chain organizational root is different from a hosted organization: the root holds real, covenant-enforced authority; a hosted organization only groups vaults and grants nobody owner authority. Creating or joining a hosted organization does not create a root."
    });

    const ROOT_STEPS = Object.freeze([
      { id: "owners", label: "Owners" },
      { id: "approvals", label: "Approval rules" },
      { id: "emergency", label: "Emergency access" },
      { id: "funding", label: "Funding" },
      { id: "review", label: "Review governance" }
    ]);

    function ownersOf(d) {
      return (Array.isArray(d.owners) ? d.owners : []).filter((r) => r && ((r.address && String(r.address).trim()) || (r.publicKey && String(r.publicKey).trim())));
    }
    function delayText(SU, setting, sel) {
      try { return SU.readDurationSelection(setting, sel).describe.text; } catch { return "the waiting period"; }
    }
    /* The explanation under each toggle — recomputed live by the caller. */
    function recoveryHelpText(d) {
      const SU = requireSetup("recoveryHelpText");
      const n = ownersOf(d).length;
      return d.recoveryEnabled ? ROOT_COPY.RECOVERY(/^[0-9]+$/.test(String(d.recoveryM)) ? Number(d.recoveryM) : "k", n || "N", delayText(SU, SU.RECOVERY_SETTING, d.recoveryDelay)) : ROOT_COPY.RECOVERY_OFF(!!d.successionEnabled);
    }
    function successionHelpText(d) {
      const SU = requireSetup("successionHelpText");
      return d.successionEnabled ? ROOT_COPY.SUCCESSION(delayText(SU, SU.SUCCESSION_SETTING, d.successionDelay)) : ROOT_COPY.SUCCESSION_OFF;
    }
    function newOwnerSetRecoveryHelp(d, orgRoot) {
      return d.recoveryEnabled ? `Uses this root's fixed recovery waiting period (${describeDelay((orgRoot && orgRoot.template && orgRoot.template.recoveryDelayDaa) || "?")}).` : ROOT_COPY.RECOVERY_OFF(!!(orgRoot && orgRoot.template && orgRoot.template.successorPk && String(orgRoot.template.successorPk) !== "00".repeat(32)));
    }

    /* The guided root setup: every step panel rendered, inactive ones hidden. */
    function renderGenesisSetupHtml({ draft, step, errors, connectedAddress, busy, network }) {
      const SU = requireSetup("renderGenesisSetupHtml");
      const d = draft;
      const err = (k) => (errors && errors.get(k)) || "";
      const F = SU.renderField;
      const n = ownersOf(d).length;
      const m = /^[0-9]+$/.test(String(d.ownerM)) ? Number(d.ownerM) : 0;
      const hidden = (i) => (i === step ? "" : " hidden");
      const panel = (i, inner) => `<section class="setup-step" data-setup-step="${ROOT_STEPS[i].id}"${hidden(i)}><h3>${esc(ROOT_STEPS[i].label)}</h3>${inner}${SU.renderNav({ index: i, total: ROOT_STEPS.length, finalLabel: "Build governance root & review", cancelLabel: "Cancel", busy })}</section>`;

      const owners =
        `<div class="f-help">${esc(ROOT_COPY.OWNERS)}</div>` +
        `<div class="f f-wide${err("owners") ? " f-invalid" : ""}" data-field="owners"><div class="f-label">Owners</div>` +
        SU.renderAddressRows({ kind: "owner", rows: d.owners, withLabel: true, allowKey: true, errors: (errors && errors.get("ownerRows")) || {}, addLabel: "Add owner", placeholder: network && String(network).startsWith("mainnet") ? "kaspa:…" : "kaspatest:…", min: 1, max: 12, connectedAddress, useConnectedLabel: "Use connected wallet" }) +
        `<div class="f-help">Names are labels for this app only. Use a wallet address; the advanced "Use public key" option is for an owner whose 64-hex public key you were given instead of an address. Two rows naming the same signing key (as an address and as a key) are refused.</div>` +
        `<div class="ferr" data-err="owners"${err("owners") ? ' style="display:block"' : ""}>${esc(err("owners"))}</div></div>` +
        `<div class="f-help">${esc(ROOT_COPY.HOSTED_VS_ROOT)}</div>`;

      const approvals =
        F({ name: "ownerM", label: "Owners needed to approve changes", control: SU.renderApprovalSelect({ name: "ownerM", count: n, value: d.ownerM, noun: "owners" }), help: n ? esc(ROOT_COPY.APPROVE(m || "k", n)) + " Example: 2 of 3 — any two of the three owners. If you remove an owner later, this number is never lowered for you." : "Add owners first.", error: err("ownerM"), wide: true }) +
        SU.renderLiveSummary(SU.rootRulesSummary(d), "v4-orgroot-summary");

      const emergency =
        F({ name: "emergencyK", label: "Owners needed for an emergency freeze", control: SU.renderApprovalSelect({ name: "emergencyK", count: n, value: d.emergencyK, noun: "owners", max: m || undefined }), help: esc(ROOT_COPY.FREEZE(/^[0-9]+$/.test(String(d.emergencyK)) ? Number(d.emergencyK) : "k", m || "M", n || "N")), error: err("emergencyK"), wide: true }) +
        `<div class="f f-wide"><div class="f-label">Recovery of control</div>${SU.checkbox({ name: "recoveryEnabled", checked: !!d.recoveryEnabled, label: "Allow the remaining owners to recover control if keys are lost" })}` +
        `<div class="f-help" data-help="recovery">${esc(recoveryHelpText(d))}</div>` +
        `<div data-recovery-fields="1"${d.recoveryEnabled ? "" : " hidden"}>` +
        F({ name: "recoveryM", label: "Owners needed to recover control", control: SU.renderApprovalSelect({ name: "recoveryM", count: n, value: d.recoveryM, noun: "owners", max: m || undefined }), help: "At most the normal approval quorum, so the surviving owners can act. It can never be more than the owners needed to approve changes.", error: err("recoveryM") }) +
        `</div>` +
        F({ name: "recoveryDelay", label: "Recovery waiting period", control: SU.renderDurationControl({ name: "recoveryDelay", setting: SU.RECOVERY_SETTING, selection: d.recoveryDelay }), help: `${esc(ROOT_COPY.WAIT_RESET)} ${esc(SU.COPY.UNITS)}${d.recoveryEnabled ? "" : " (Stored even while recovery is off, because it cannot be changed later.)"}`, error: err("recoveryDelay"), wide: true }) +
        `</div>` +
        `<div class="f f-wide"><div class="f-label">Designated successor</div>${SU.checkbox({ name: "successionEnabled", checked: !!d.successionEnabled, label: "Designate a successor who can take over after a long silence" })}` +
        `<div class="f-help" data-help="succession">${esc(successionHelpText(d))}</div>` +
        `<div data-succession-fields="1"${d.successionEnabled ? "" : " hidden"}>` +
        F({ name: "successorAddress", label: "Successor wallet address", control: SU.textInput({ name: "successorAddress", value: d.successorAddress, placeholder: network && String(network).startsWith("mainnet") ? "kaspa:…" : "kaspatest:…", mono: true }), help: "A wallet address on this network. PolicyVault derives the successor's signing key from it. The successor need not be an owner.", error: err("successorAddress"), wide: true }) +
        F({ name: "successionDelay", label: "Successor waiting period", control: SU.renderDurationControl({ name: "successionDelay", setting: SU.SUCCESSION_SETTING, selection: d.successionDelay }), help: `${esc(ROOT_COPY.WAIT_RESET)} ${esc(SU.COPY.UNITS)}`, error: err("successionDelay"), wide: true }) +
        `</div></div>`;

      const funding =
        F({ name: "rootValueKas", label: "Governance funding", control: SU.kasInput({ name: "rootValueKas", value: d.rootValueKas, placeholder: "1" }), help: esc(ROOT_COPY.FUNDING), error: err("rootValueKas"), wide: true }) +
        `<div class="f f-wide"><div class="f-label">Wallet funding this setup</div><div class="addr-display"><span class="mono">${esc(connectedAddress || "")}</span> <span class="badge ver">Connected wallet</span> <button type="button" class="quiet addr-copy" data-copy="${esc(connectedAddress || "")}">Copy</button></div><div class="f-help">${esc(ROOT_COPY.FUNDER)} Estimated network fee for creation: about ${esc(FEE_ESTIMATE.rootGenesisKas)} KAS (the exact fee is shown on the review).</div><div class="ferr" data-err="signerAddress"${err("signerAddress") ? ' style="display:block"' : ""}>${esc(err("signerAddress"))}</div></div>` +
        F({ name: "label", label: "Name", control: SU.textInput({ name: "label", value: d.label, placeholder: "Acme Treasury", maxlength: 120 }), help: esc(ROOT_COPY.LABEL), error: err("label"), optional: true, wide: true }) +
        `<details class="adv"><summary>Advanced</summary>` +
        F({ name: "rootMaxFeePerTxKas", label: "Maximum the root may lose per governance action", control: SU.kasInput({ name: "rootMaxFeePerTxKas", value: d.rootMaxFeePerTxKas, placeholder: "0.001" }), help: esc(ROOT_COPY.MAX_LOSS), error: err("rootMaxFeePerTxKas"), wide: true }) +
        `</details>`;

      const review = `<div id="v4-orgroot-review">${renderGenesisDraftReviewHtml({ draft: d, connectedAddress })}</div>` +
        `<div class="f-help">The next screen shows the exact governance rules PolicyVault built, checked against these values, before your wallet is asked to sign.</div>`;

      return (
        `<h3 id="v4-orgroot-title" style="margin-top:0">Create organizational root</h3>` +
        `<div class="f-help">A new on-chain governance root whose owners approve changes together (for example 2 of 3). The rules are enforced by the covenant on Kaspa. Vaults created under this root are governed by its owners instead of a single owner key.</div>` +
        SU.renderStepper({ steps: ROOT_STEPS, current: step }) +
        `<form class="setup-form" data-orgroot-wizard autocomplete="off" novalidate>` +
        panel(0, owners) + panel(1, approvals) + panel(2, emergency) + panel(3, funding) + panel(4, review) +
        `</form>`
      );
    }

    /* The draft review (step 5) with Edit links — the INTENT to build from. */
    function renderGenesisDraftReviewHtml({ draft: d, connectedAddress }) {
      const SU = requireSetup("renderGenesisDraftReviewHtml");
      const n = ownersOf(d).length;
      const v = (x) => (String(x ?? "").trim() || "—");
      const ownerLines = ownersOf(d).map((r, i) => `${i + 1}. ${r.label ? esc(r.label) + " — " : ""}<span class="mono">${esc(r.publicKey && String(r.publicKey).trim() ? `public key ${r.publicKey}` : r.address)}</span>`).join("<br/>");
      const rDelay = delayText(SU, SU.RECOVERY_SETTING, d.recoveryDelay);
      const sDelay = delayText(SU, SU.SUCCESSION_SETTING, d.successionDelay);
      return (
        `<h4 class="review-title">Review before building</h4>` +
        SU.renderReviewSection({ title: "Owners", editStep: 0, rows: [["Owners", ownerLines ? SU.html(ownerLines) : "—"]] }) +
        SU.renderReviewSection({ title: "Approval rules", editStep: 1, rows: [["Changes need", `${v(d.ownerM)} of ${n} owners`]] }) +
        SU.renderReviewSection({ title: "Emergency access", editStep: 2, rows: [
          ["Emergency freeze", `${v(d.emergencyK)} of ${n} owners — stops governance actions, not agent payments`],
          ["Recovery of control", d.recoveryEnabled ? `${v(d.recoveryM)} of ${n} owners after the root is untouched for ${rDelay}` : "off"],
          ["Recovery waiting period", `${rDelay}${d.recoveryEnabled ? "" : " (stored; not in effect while recovery is off)"}`],
          ["Designated successor", d.successionEnabled && v(d.successorAddress) !== "—" ? SU.html(`<span class="mono">${esc(v(d.successorAddress))}</span> after the root is untouched for ${esc(sDelay)}`) : "none (permanent)"]
        ] }) +
        SU.renderReviewSection({ title: "Funding", editStep: 3, rows: [
          ["Governance funding", `${v(d.rootValueKas)} KAS — locked for the life of the organization`],
          ["Paid by", SU.html(`<span class="mono">${esc(connectedAddress || v(d.signerAddress))}</span> (grants no ownership)`)],
          ["Maximum the root may lose per action", `${v(d.rootMaxFeePerTxKas)} KAS (covenant cap; normally 0 is lost)`],
          ["Name", v(d.label)]
        ], note: "The exact network fee is shown once the transaction is built." })
      );
    }

    /* Validate the root draft: field-local checks through the setup module,
     * then (for a full validation) the core's own well-formedness rule via
     * normalizeWizardGenesis — core refusals are mapped back onto fields. */
    async function validateGenesisDraft(draft, { step, connectedAddress } = {}) {
      const SU = requireSetup("validateGenesisDraft");
      const v = await SU.validateRootDraft(draft, { resolve: (a) => api.resolveXOnly(a), step, connectedAddress });
      if (!v.ok || step !== undefined) return { ok: v.ok, errors: v.errors, form: v.form || null, norm: null };
      try {
        const norm = await normalizeWizardGenesis(v.form);
        return { ok: true, errors: v.errors, form: v.form, norm };
      } catch (e) {
        const reason = (e.cause && e.cause.code) || e.code || "";
        const field = { M_ABOVE_ACTIVE: "ownerM", K_ABOVE_M: "emergencyK", R_ABOVE_M: "recoveryM", DUPLICATE_OWNER_KEY: "owners", NOT_CONTIGUOUS: "owners", NO_ACTIVE_SLOTS: "owners", SLOT_COUNT: "owners" }[reason] || "owners";
        const errors = new Map(v.errors);
        errors.set(field, e.message);
        return { ok: false, errors, form: null, norm: null };
      }
    }

    /* The exact governance review before signing: plain-language sections
     * rendered from the LOCALLY normalized rules, cross-checked field by
     * field against the SERVER's genesis summary (the description of the
     * transaction the wallet will sign); the technical exact-policy panel
     * stays available. A mismatch renders DO NOT SIGN and no signing action
     * is offered by the caller. */
    function renderGenesisReviewHtml({ norm, summary, crossCheck, connectedAddress }) {
      const SU = requireSetup("renderGenesisReviewHtml");
      const slots = core.ownerSetV7.activeOwnerSlotsV7(norm.ownerSet);
      const n = slots.length;
      const meta = (summary && Array.isArray(summary.slots) ? summary.slots : []);
      const ownerLines = slots.map((s, i) => { const mt = meta[i] || {}; return `${s.slot}. ${mt.label ? esc(mt.label) + " — " : ""}<span class="mono">${esc(mt.address || s.publicKey)}</span>`; }).join("<br/>");
      const m = norm.ownerSet.ownerM.toString(), k = norm.ownerSet.emergencyK.toString(), r = norm.ownerSet.recoveryM.toString();
      const successionOn = norm.successorPk && norm.successorPk !== INACTIVE;
      // rc19 review R4-05: a malformed server fee renders a refusal, never a throw.
      const feeValid = !!(summary && typeof summary.requiredFeeSompi === "string" && /^[0-9]+$/.test(summary.requiredFeeSompi));
      const feeMalformed = !!(summary && !feeValid); // rc20 review R5-05: an OMITTED fee is as unsignable as a malformed one
      const feeKas = feeValid ? core.amounts.sompiToKas(BigInt(String(summary.requiredFeeSompi))) : null;
      const rootValueKas = core.amounts.sompiToKas(norm.rootValueSompi);
      const total = feeValid ? core.amounts.sompiToKas(norm.rootValueSompi + BigInt(String(summary.requiredFeeSompi))) : null;
      const check = feeMalformed
        ? statusRegion(`<b style="color:var(--bad)">DO NOT SIGN — the server reported no valid network fee for this transaction</b><div class="f-help">The exact fee could not be read (${esc(summary.requiredFeeSompi === undefined ? "missing" : JSON.stringify(summary.requiredFeeSompi))}); the transaction cannot be bound to a fee and will not be signed.</div>`, "bad")
        : crossCheck && crossCheck.ok
        ? statusRegion(`<b style="color:var(--good)">CHECKED — PolicyVault's description of the built transaction matches the rules you reviewed</b><div class="f-help">Owner keys, approval counts, waiting periods, successor and governance funding were compared field by field against PolicyVault's description of the transaction to be signed (digest ${esc(summary && summary.txId ? summary.txId : "")}). Your wallet signs the funding input; the covenant itself is compiled by PolicyVault and verified on-chain when the root is reconciled.</div>`)
        : statusRegion(`<b style="color:var(--bad)">DO NOT SIGN — the built transaction does not match the rules you reviewed</b><div class="f-help">${(crossCheck && crossCheck.mismatches || ["no cross-check result"]).map(esc).join("<br/>")}</div>`, "bad");
      return (
        check +
        SU.renderReviewSection({ title: "Owners", rows: [["Owners", SU.html(ownerLines)]] }) +
        SU.renderReviewSection({ title: "Approval rules", rows: [["Changes need", `${m} of ${n} owners`]], note: esc(ROOT_COPY.APPROVE(m, n)) }) +
        SU.renderReviewSection({ title: "Emergency access", rows: [
          ["Emergency freeze", `${k} of ${n} owners`],
          ["Recovery of control", norm.ownerSet.recoveryM > 0n ? `${r} of ${n} owners after the root is untouched for ${approxDelay(norm.recoveryDelayDaa)}` : "off"],
          ["Recovery waiting period", SU.html(`${esc(approxDelay(norm.recoveryDelayDaa))}${norm.ownerSet.recoveryM > 0n ? "" : " (stored; not in effect while recovery is off)"}<details class="adv f-tech"><summary>Technical detail</summary>exactly ${esc(String(norm.recoveryDelayDaa))} DAA score</details>`)],
          ["Designated successor", successionOn ? SU.html(`<span class="mono">${esc(norm.successorPk)}</span> after the root is untouched for ${esc(approxDelay(norm.successionDelayDaa))}<details class="adv f-tech"><summary>Technical detail</summary>exactly ${esc(String(norm.successionDelayDaa))} DAA score</details>`) : "none (permanent)"]
        ], note: `${esc(ROOT_COPY.FREEZE(k, m, n))} ${esc(ROOT_COPY.WAIT_RESET)} Recovery and succession both land the root frozen; the installed owners unfreeze with ${m} of the new set. Exact DAA values, full keys and the exact policy are under Technical details below.` }) +
        SU.renderFundingBreakdown({ title: "What leaves your wallet", rows: [
          { label: "Governance funding (locked in the root; never withdrawable)", kas: rootValueKas },
          { label: "Network fee for creating the root", kas: feeKas === null ? "unknown" : feeKas, note: "exact, from the built transaction" }
        ], total: total !== null ? { label: "Total leaving your wallet", kas: total } : null, note: `Paid by <span class="mono">${esc(connectedAddress || "")}</span>; any remaining value of the funding input returns as change. Paying grants no ownership. Maximum the root may lose per governance action: ${esc(core.amounts.sompiToKas(norm.rootMaxFeePerTxSompi))} KAS (covenant cap; PolicyVault's transactions take 0).` }) +
        `<details class="adv"><summary>Technical details (exact policy, full keys, DAA values)</summary>${renderGenesisPolicyPanelHtml(norm)}</details>`
      );
    }

    /* Rooted-vault owner operations, named for humans. Delegate spending
     * never needs the root (contract §2: /wallet/v7/requests). */
    const VAULT_OP_LABEL = Object.freeze({ ownerSetAgentRoot: "Change agent rules", ownerTopUpReserve: "Top up fee reserve", ownerPause: "Pause vault", ownerUnpause: "Unpause vault", ownerEmergencyPause: "Emergency-pause vault", ownerRecover: "Close & recover vault", tokenAgentSpend: "Agent payment" });
    function vaultOpLabel(op) { return Object.prototype.hasOwnProperty.call(VAULT_OP_LABEL, String(op)) ? VAULT_OP_LABEL[op] : String(op || "operation"); }
    const short = (s) => { const t = String(s ?? ""); return t.length > 12 ? `${t.slice(0, 8)}…${t.slice(-4)}` : t; };

    /* ================================================================
     * (e′) ROOTED-VAULT OWNER OPERATIONS — BROWSER INITIATION (rc26
     * round-7 review R7-05; owner-approved; launch scope 2026-09-08).
     * A rooted-vault owner operation is ONE vault operation riding ONE
     * root transition: the browser collects the operation's parameters,
     * the SERVER builds the frozen transaction (the SDK derives every
     * consensus value — the successor agent root, budgets, the successor
     * state — never this module), every owner reviews the manifest through
     * core.orgRootExplain and signs their own slot, the fee input's owner
     * finalizes, anyone submits. Nothing here grants or infers authority:
     * a control is offered only when the viewer holds an owner slot, the
     * root is not otherwise reserved or frozen and the vault's live state
     * permits the operation; the server and the covenant re-decide all of
     * it, and a refusal has no override.
     * ================================================================ */
    const SUPPORTED_ROOTED_PROFILE = "policyvault-0.7-payment";
    const VAULT_OPS = Object.freeze({
      ownerSetAgentRoot: Object.freeze({ label: "Change agent rules", rootAction: "authorize", form: "agents", dangerous: false, describe: "Installs a COMPLETE new set of delegate (agent) rules for this vault: every agent, its cap per payment, its budget per period, its network-fee cap, its KAS carry cap and the exact recipients it may pay. An agent left out loses access once the change is chain-verified." }),
      ownerTopUpReserve: Object.freeze({ label: "Top up fee reserve", rootAction: "authorize", form: "topUp", dangerous: false, describe: "Adds KAS to this vault's fee reserve, which pays the network fee of each agent payment so the token position is never reduced by fees. The KAS comes from the wallet that funds this request's fee input." }),
      ownerPause: Object.freeze({ label: "Pause vault", rootAction: "authorize", form: "confirm", dangerous: false, requiresPaused: false, describe: "Pauses this vault: delegate (agent) payments stop once the pause is chain-verified, until the owners unpause it. Nothing moves and no rule changes." }),
      ownerUnpause: Object.freeze({ label: "Unpause vault", rootAction: "authorize", form: "confirm", dangerous: false, requiresPaused: true, describe: "Unpauses this vault: delegate payments resume under the installed rules once the change is chain-verified." }),
      ownerEmergencyPause: Object.freeze({ label: "Emergency-pause vault", rootAction: "freeze", form: "confirm", dangerous: false, requiresPaused: false, describe: "Emergency-pauses this ONE vault on the lighter emergency quorum and FREEZES the organizational root in the same transaction. Other vaults of this organization keep paying under their rules; unfreezing later needs the full approval quorum." }),
      ownerRecover: Object.freeze({ label: "Close & recover vault", rootAction: "authorize", form: "confirm", dangerous: true, describe: "CLOSES this vault permanently: its entire fee reserve and its whole token position are paid to the recovery key pinned when the vault was created. Every agent loses access; the vault cannot be reopened." })
    });
    const VAULT_OP_ORDER = Object.freeze(["ownerSetAgentRoot", "ownerTopUpReserve", "ownerPause", "ownerUnpause", "ownerEmergencyPause", "ownerRecover"]);
    const OPERABLE_VAULT_STATUSES = Object.freeze(["ACTIVE", "PAUSED"]);
    /* The root action each vault operation requires is the SHARED CORE's own
     * table (core/model/vault-state-v7 OWNER_OP_ROOT_AUTHORITY_V7); this
     * module's copy must agree with it or the operation is not offered. */
    function vaultOpInfo(op) {
      if (!Object.prototype.hasOwnProperty.call(VAULT_OPS, String(op))) return null;
      const info = VAULT_OPS[op];
      const table = core.vaultStateV7 && core.vaultStateV7.OWNER_OP_ROOT_AUTHORITY_V7;
      const authority = table && Object.prototype.hasOwnProperty.call(table, op) ? table[op] : null;
      if (!authority || String(authority.rootActionName) !== info.rootAction) return null;
      return info;
    }
    function vaultOpAvailability({ op, vault, orgRoot, viewerXOnly, pendingRequestId, networkId } = {}) {
      const info = vaultOpInfo(op);
      if (!info) return { enabled: false, offered: false, reason: "this operation is not supported by the approved rooted-vault profile" };
      const v = vault || {};
      const off = (reason) => ({ enabled: false, offered: true, reason });
      if (v.contractVersion !== SUPPORTED_ROOTED_PROFILE) return { enabled: false, offered: false, reason: `owner operations are offered only for ${SUPPORTED_ROOTED_PROFILE} vaults (this vault is ${v.contractVersion || "of an unknown profile"})` };
      const net = String(networkId || (orgRoot && orgRoot.networkId) || "");
      if (net.startsWith("mainnet")) return off("policyvault-0.7 organizational roots are not mainnet-authorized — no owner operation can be built on mainnet");
      const role = viewerRole(orgRoot || {}, viewerXOnly);
      if (role.kind !== "owner") return off("Only an owner of this root can start this");
      if (!v.live || !v.live.outpoint) return off(v.status && !OPERABLE_VAULT_STATUSES.includes(String(v.status)) ? `this vault is ${v.status} — no further owner operation exists` : "this vault has no confirmed on-chain outpoint yet — use Verify state on the root first");
      if (v.status && !OPERABLE_VAULT_STATUSES.includes(String(v.status))) return off(`this vault is ${v.status} — no further owner operation exists`);
      const pending = pendingRequestId !== undefined ? pendingRequestId : (orgRoot && orgRoot.pendingRequestId) || null;
      if (pending) return off("A request is already pending on this root — only one governance transaction can be in flight per root transition");
      const frozen = !!(orgRoot && orgRoot.state && Number(orgRoot.state.frozen) === 1);
      if (frozen) return off(info.rootAction === "freeze" ? "the root is already FROZEN — an emergency pause freezes it; unfreeze first (approval quorum), then pause the vault" : `the root is FROZEN — ${info.label.toLowerCase()} needs the root to run ${info.rootAction}, which a frozen root refuses until it is unfrozen`);
      const paused = !!(v.live && v.live.paused === true);
      if (info.requiresPaused === false && paused) return off("this vault is already paused");
      if (info.requiresPaused === true && !paused) return off("this vault is not paused");
      return { enabled: true, offered: true, reason: "" };
    }
    /* The ONE typed phrase for the one irreversible vault operation (distinct from the root's "Recover control"). */
    function vaultOpConfirmPhrase(op) { return op === "ownerRecover" ? "CONFIRM CLOSE VAULT" : ""; }
    function vaultOpConfirmationMatches(op, typed) { const p = vaultOpConfirmPhrase(op); return !!p && String(typed || "").trim() === p; }

    /* ---- drafts: prefilled from the vault's CURRENT presented state (exact values; never re-typed) ---- */
    function agentRowFrom(a, currentDaa) {
      const existing = !!(a && a.agentPk);
      return {
        existing,
        agentKey: existing ? String(a.agentPk) : "",
        tokenMaxPerSpend: existing ? String(a.tokenMaxPerSpend ?? "") : "",
        tokenPeriodBudget: existing ? String(a.tokenPeriodBudget ?? "") : "",
        periodLengthDaa: existing ? String(a.periodLengthDaa ?? "") : "",
        periodStartDaa: existing ? String(a.periodStartDaa ?? "0") : (currentDaa !== null && currentDaa !== undefined ? String(currentDaa) : "0"),
        tokenPeriodSpent: existing ? String(a.tokenPeriodSpent ?? "0") : "0",
        agentMaxFeePerTxKas: existing && a.agentMaxFeePerTx !== undefined ? core.amounts.sompiToKas(BigInt(String(a.agentMaxFeePerTx))) : "",
        agentMaxCarryKas: existing && a.agentMaxCarryKas !== undefined ? core.amounts.sompiToKas(BigInt(String(a.agentMaxCarryKas))) : "",
        recipients: existing && Array.isArray(a.recipients) ? a.recipients.map((r) => String(r)).join("\n") : ""
      };
    }
    function vaultOpDraftFrom({ op, vault, currentDaa = null } = {}) {
      const info = vaultOpInfo(op);
      if (!info) throw fail(`unknown rooted-vault owner operation ${JSON.stringify(op)} — failing closed`, "UNKNOWN_ACTION");
      if (info.form === "topUp") return { op, amountKas: "" };
      if (info.form === "agents") {
        const agents = Array.isArray(vault && vault.agents) ? vault.agents : [];
        return { op, agents: agents.length ? agents.map((a) => agentRowFrom(a, currentDaa)) : [agentRowFrom(null, currentDaa)], currentDaa: currentDaa === null || currentDaa === undefined ? null : String(currentDaa) };
      }
      return { op, typed: "" };
    }

    /* ---- validation: the SAME normalizers the SDK builder runs, locally, before any network call ---- */
    const DIGITS_RE = /^(0|[1-9][0-9]*)$/;
    async function resolveXOnlyKey(raw, what) {
      const s = String(raw || "").trim();
      if (!s) throw fail(`${what} is required`, "AGENT_SET_INVALID");
      if (HEX64_RE.test(s)) return s.toLowerCase();
      try { return (await api.resolveXOnly(s)).toLowerCase(); } catch (e) { throw fail(`${what} "${s}": ${e.message}`, "AGENT_SET_INVALID", { cause: e }); }
    }
    async function validateVaultOpDraft({ op, draft, vault, currentDaa = null } = {}) {
      const info = vaultOpInfo(op);
      const errors = new Map();
      if (!info) { errors.set("op", `unknown rooted-vault owner operation ${JSON.stringify(op)} — failing closed`); return { ok: false, errors, vaultOperation: null }; }
      if (!vault || !vault.vaultId) { errors.set("op", "no vault selected"); return { ok: false, errors, vaultOperation: null }; }
      const d = draft || {};
      if (info.form === "topUp") {
        let sompi = null;
        try { sompi = core.amounts.kasToSompi(String(d.amountKas ?? "").trim(), "top-up amount"); } catch (e) { errors.set("amount", `Enter a KAS amount (up to 8 decimals): ${e.message}`); }
        if (sompi !== null && BigInt(sompi) <= 0n) errors.set("amount", "Enter a KAS amount greater than 0.");
        if (errors.size) return { ok: false, errors, vaultOperation: null };
        return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: { topUpReserveAmountSompi: BigInt(sompi).toString() } } };
      }
      if (info.form === "agents") {
        const rows = Array.isArray(d.agents) ? d.agents : [];
        const agents = [];
        const seen = new Set();
        const rowErrors = {};
        const maxAgents = core.agentMerkleV5 && Number.isInteger(core.agentMerkleV5.MAX_AGENTS) ? core.agentMerkleV5.MAX_AGENTS : null;
        if (maxAgents !== null && rows.length > maxAgents) errors.set("agents", `At most ${maxAgents} agents are supported.`);
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i] || {};
          const errs = {};
          let agentPk = null;
          try { agentPk = await resolveXOnlyKey(r.agentKey, "Agent wallet"); } catch (e) { errs.agentKey = e.message; }
          if (agentPk && seen.has(agentPk)) errs.agentKey = "This agent is already listed — one rule per agent key.";
          if (agentPk) seen.add(agentPk);
          const recipientsRaw = String(r.recipients || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
          const recipients = [];
          if (!recipientsRaw.length) errs.recipients = "At least one allowed recipient is required — an agent with no recipient can pay no one.";
          for (const rec of recipientsRaw) { try { recipients.push(await resolveXOnlyKey(rec, "Recipient")); } catch (e) { errs.recipients = e.message; break; } }
          if (!errs.recipients && new Set(recipients).size !== recipients.length) errs.recipients = "A recipient is listed twice.";
          let agentRecipientRoot = null;
          if (!errs.recipients) { try { agentRecipientRoot = core.recipientMerkle.buildRecipientTree(recipients).root; } catch (e) { errs.recipients = e.message; } }
          const atomic = (v, name, positive) => { const s = String(v ?? "").trim(); if (!DIGITS_RE.test(s)) return `${name} must be a whole number of atomic token units.`; if (positive && BigInt(s) <= 0n) return `${name} must be greater than 0.`; return null; };
          const e1 = atomic(r.tokenMaxPerSpend, "Cap per payment", true); if (e1) errs.tokenMaxPerSpend = e1;
          const e2 = atomic(r.tokenPeriodBudget, "Budget per period", true); if (e2) errs.tokenPeriodBudget = e2;
          const e3 = atomic(r.periodLengthDaa, "Budget period (DAA score)", true); if (e3) errs.periodLengthDaa = e3.replace("atomic token units", "DAA score");
          const e4 = atomic(r.periodStartDaa, "Period start (DAA score)", false); if (e4) errs.periodStartDaa = e4;
          const e5 = atomic(r.tokenPeriodSpent, "Spent this period", false); if (e5) errs.tokenPeriodSpent = e5;
          let agentMaxFeePerTx = null, agentMaxCarryKas = null;
          try { agentMaxFeePerTx = BigInt(core.amounts.kasToSompi(String(r.agentMaxFeePerTxKas ?? "").trim() || "0", "agent max fee per transaction")).toString(); } catch (e) { errs.agentMaxFeePerTxKas = e.message; }
          try { agentMaxCarryKas = BigInt(core.amounts.kasToSompi(String(r.agentMaxCarryKas ?? "").trim() || "0", "agent KAS carry cap")).toString(); } catch (e) { errs.agentMaxCarryKas = e.message; }
          if (!Object.keys(errs).length) {
            const raw = { agentPk, tokenMaxPerSpend: String(r.tokenMaxPerSpend).trim(), tokenPeriodBudget: String(r.tokenPeriodBudget).trim(), periodLengthDaa: String(r.periodLengthDaa).trim(), periodStartDaa: String(r.periodStartDaa).trim(), tokenPeriodSpent: String(r.tokenPeriodSpent).trim(), agentMaxFeePerTx, agentMaxCarryKas, agentRecipientRoot };
            /* the EXACT normalizer the covenant's Merkle-leaf encoding relies on — a malformed policy is refused here */
            try { core.agentMerkleV5.normalizeTokenAgentPolicyV5(raw); } catch (e) { errs.agentKey = e.message; }
            if (!Object.keys(errs).length) agents.push({ ...raw, recipients });
          }
          if (Object.keys(errs).length) rowErrors[i] = errs;
        }
        if (Object.keys(rowErrors).length) errors.set("agentRows", rowErrors);
        if (errors.size) return { ok: false, errors, vaultOperation: null };
        /* the SDK derives the successor agent root from these entries (never from a caller-supplied root) */
        return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: { agents } }, agentCount: agents.length };
      }
      if (info.dangerous && !vaultOpConfirmationMatches(op, d.typed)) { errors.set("typed", `Type exactly "${vaultOpConfirmPhrase(op)}" to continue.`); return { ok: false, errors, vaultOperation: null }; }
      void currentDaa;
      return { ok: true, errors, vaultOperation: { vaultId: vault.vaultId, action: op, params: {} } };
    }

    /* ---- forms (headless HTML; app-v4.js wires the DOM and reads values back into the draft) ---- */
    function renderVaultOpFormHtml({ op, vault, orgRoot, draft, errors, connectedAddress, currentDaa = null } = {}) {
      const SU = requireSetup("renderVaultOpFormHtml");
      const info = vaultOpInfo(op);
      if (!info) return statusRegion(`unknown rooted-vault owner operation ${esc(JSON.stringify(op))} — refusing to render a form`, "bad");
      const F = SU.renderField;
      const err = (k) => (errors && errors.get(k)) || "";
      const v = vault || {};
      const st = (orgRoot && orgRoot.state) || {};
      const n = (orgRoot && orgRoot.slots ? orgRoot.slots.length : 0);
      const quorum = info.rootAction === "freeze" ? `${esc(String(st.emergencyK ?? "?"))} of ${n} owners (emergency quorum)` : `${esc(String(st.ownerM ?? "?"))} of ${n} owners`;
      const head =
        `<h3 id="v4-vaultop-title" style="margin-top:0">${esc(info.label)} — ${esc(v.label || short(v.vaultId))}</h3>` +
        `<div class="f-help">${esc(info.describe)}</div>` +
        `<div class="f-help">Authorized by ${quorum} through the root's <b>${esc(info.rootAction)}</b> action. PolicyVault builds the exact transaction next; nothing is signed or sent on this screen.${v.live ? ` Current fee reserve ${esc(String(v.live.feeReserveKas))} KAS; the vault is ${v.live.paused ? "PAUSED" : "not paused"}.` : ""}</div>`;
      let body = "";
      if (info.form === "topUp") {
        body = F({ name: "amount", label: "Amount to add to the fee reserve", control: SU.kasInput({ name: "amount", value: draft && draft.amountKas, placeholder: "0.5" }), help: "Exact KAS; PolicyVault converts it to sompi (1 KAS = 100,000,000 sompi) with the canonical parser. The amount and the network fee come from the wallet that funds the request's fee input.", error: err("amount"), wide: true });
      } else if (info.form === "agents") {
        const rows = draft && Array.isArray(draft.agents) ? draft.agents : [];
        const rowErrs = (errors && errors.get("agentRows")) || {};
        const rowHtml = rows.map((r, i) => {
          const re = rowErrs[i] || {};
          const nm = (k) => `agent-${i}-${k}`;
          return (
            `<fieldset class="agent-row" data-agent-row="${i}" style="border:1px solid var(--border, #ccc);border-radius:6px;padding:0.6rem;margin:0.5rem 0">` +
            `<legend>Agent ${i + 1}${r.existing ? " (currently installed)" : " (new)"}</legend>` +
            F({ name: nm("agentKey"), label: "Agent wallet (address or 64-hex public key)", control: SU.textInput({ name: nm("agentKey"), value: r.agentKey, mono: true, placeholder: "kaspa… or 64-hex key" }), error: re.agentKey, wide: true }) +
            F({ name: nm("tokenMaxPerSpend"), label: "Cap per payment (atomic token units)", control: SU.textInput({ name: nm("tokenMaxPerSpend"), value: r.tokenMaxPerSpend, inputmode: "numeric", mono: true }), error: re.tokenMaxPerSpend }) +
            F({ name: nm("tokenPeriodBudget"), label: "Budget per period (atomic token units)", control: SU.textInput({ name: nm("tokenPeriodBudget"), value: r.tokenPeriodBudget, inputmode: "numeric", mono: true }), error: re.tokenPeriodBudget }) +
            F({ name: nm("periodLengthDaa"), label: "Budget period (exact DAA score)", control: SU.textInput({ name: nm("periodLengthDaa"), value: r.periodLengthDaa, inputmode: "numeric", mono: true }), help: r.periodLengthDaa && DIGITS_RE.test(String(r.periodLengthDaa)) && BigInt(r.periodLengthDaa) > 0n ? `about ${esc(approxDelay(r.periodLengthDaa))}` : "1 DAA score ≈ 1/10 second; 864000 ≈ 1 day.", error: re.periodLengthDaa }) +
            F({ name: nm("agentMaxFeePerTxKas"), label: "Network-fee cap per payment", control: SU.kasInput({ name: nm("agentMaxFeePerTxKas"), value: r.agentMaxFeePerTxKas, placeholder: "0.01" }), error: re.agentMaxFeePerTxKas }) +
            F({ name: nm("agentMaxCarryKas"), label: "KAS carry cap per payment", control: SU.kasInput({ name: nm("agentMaxCarryKas"), value: r.agentMaxCarryKas, placeholder: "0" }), help: "The most KAS one payment may carry to the recipient beside the token amount.", error: re.agentMaxCarryKas }) +
            `<div class="f f-wide${re.recipients ? " f-invalid" : ""}" data-field="${esc(nm("recipients"))}"><label class="f-label" for="f-${esc(nm("recipients"))}">Allowed recipients (one per line: address or 64-hex key)</label><textarea id="f-${esc(nm("recipients"))}" name="${esc(nm("recipients"))}" rows="3" class="mono" aria-describedby="f-${esc(nm("recipients"))}-help">${esc(r.recipients)}</textarea><div class="f-help" id="f-${esc(nm("recipients"))}-help">The agent may pay ONLY these destinations; PolicyVault commits them as a Merkle root the covenant enforces.</div><div class="ferr" data-err="${esc(nm("recipients"))}"${re.recipients ? ' style="display:block"' : ""}>${esc(re.recipients || "")}</div></div>` +
            `<details class="adv f-tech"><summary>Technical detail (carried exactly)</summary><div class="f-help">period start DAA <span class="mono">${esc(r.periodStartDaa)}</span> · spent this period <span class="mono">${esc(r.tokenPeriodSpent)}</span>${r.existing ? " — the installed values, carried unchanged" : currentDaa !== null && currentDaa !== undefined ? " — a new agent's period starts at the current network DAA" : ""}</div>` +
            `<input type="hidden" name="${esc(nm("periodStartDaa"))}" value="${esc(r.periodStartDaa)}" /><input type="hidden" name="${esc(nm("tokenPeriodSpent"))}" value="${esc(r.tokenPeriodSpent)}" /><input type="hidden" name="${esc(nm("existing"))}" value="${r.existing ? "1" : "0"}" /></details>` +
            `<div class="actions"><button type="button" class="quiet" data-remove-agent="${i}" aria-label="Remove agent ${i + 1}">Remove agent</button></div>` +
            `</fieldset>`
          );
        }).join("");
        body =
          `<div class="f-help">These rules REPLACE the installed set completely${rows.length ? "" : " — an empty set means no agent can pay from this vault until a new set is installed"}. Values are prefilled from the installed rules; a value you do not change is carried exactly.</div>` +
          `<div class="ferr" data-err="agents"${err("agents") ? ' style="display:block"' : ""}>${esc(err("agents"))}</div>` +
          `<div data-agent-rows="1">${rowHtml}</div>` +
          `<div class="addr-actions"><button type="button" id="v4-add-agent" class="quiet">+ Add agent</button></div>`;
      } else {
        const consequences = {
          ownerPause: "Once chain-verified, every agent payment from this vault is refused by the covenant until the owners unpause it. Nothing moves; the rules and budgets are kept.",
          ownerUnpause: "Once chain-verified, agent payments resume under the installed rules and remaining budgets.",
          ownerEmergencyPause: `Once chain-verified, this vault is paused AND the organizational root is FROZEN: no governance action can be approved for any vault of this organization until ${esc(String(st.ownerM ?? "M"))} of ${n} owners unfreeze it. Other vaults keep paying under their rules. Only this one vault is paused by this transaction.`,
          ownerRecover: `IRREVERSIBLE. The vault ends: ${v.live ? `${esc(String(v.live.feeReserveKas))} KAS of fee reserve` : "the fee reserve"}${v.live && v.live.tokenPosition && v.live.tokenPosition.state ? ` and the token position of ${esc(String(v.live.tokenPosition.state.amount))} atomic units` : " and any token position"} go to the pinned recovery key${v.recoveryPk ? ` <span class="mono" style="word-break:break-all">${esc(v.recoveryPk)}</span>` : ""} — no other destination is possible. Every agent loses access at once; the vault cannot be reopened.`
        }[op] || "";
        body =
          `<div class="opbanner ${info.dangerous ? "bad" : "warn"}" role="status" aria-live="polite" aria-atomic="true" data-vaultop-confirm="${esc(op)}"><b>${esc(info.label)}</b><div style="margin-top:0.3rem">${consequences}</div>` +
          (info.dangerous ? `<div style="margin-top:0.5rem">Type <span class="mono">${esc(vaultOpConfirmPhrase(op))}</span> to continue. There is no other confirmation for this action.</div>` : "") +
          `</div>` +
          (info.dangerous ? `<div class="f f-wide${err("typed") ? " f-invalid" : ""}"><label class="f-label" for="v4-vaultop-typed">Type the confirmation phrase</label><input id="v4-vaultop-typed" name="typed" class="mono" value="${esc(draft && draft.typed)}" placeholder="${esc(vaultOpConfirmPhrase(op))}" autocomplete="off" /><div class="ferr" data-err="typed"${err("typed") ? ' style="display:block"' : ""}>${esc(err("typed"))}</div></div>` : "");
      }
      const submitLabel = info.form === "confirm" ? (info.dangerous ? info.label : `${info.label} — build request`) : "Build the exact transaction & review";
      return (
        head +
        `<form class="setup-form" data-vaultop-form="${esc(op)}" data-vault="${esc(v.vaultId)}" autocomplete="off" novalidate>` +
        body +
        `<div class="f-help">Started by <span class="mono">${esc(connectedAddress || "")}</span> (an owner of this root). Its wallet funds the network fee unless a different fee input is supplied through the API; the change returns to the fee payer.</div>` +
        `<div class="modal-actions"><button type="button" data-vaultop-cancel="1">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="${info.dangerous ? "warn" : "primary"}">${esc(submitLabel)}</button></div>` +
        `</form>`
      );
    }

    /* ---- the PLAIN-LANGUAGE consequences of a request's vault operation, from the VERIFIED manifest (core.orgRootExplain) ---- */
    function vaultOperationSummary(request) {
      if (!request || !request.manifest || !Array.isArray(request.manifest.vaultOperations) || !request.manifest.vaultOperations.length) return null;
      const carried = (x) => (x && typeof x === "object" && !Array.isArray(x) ? x : {});
      let doc;
      try { doc = core.orgRootExplain.structured({ manifest: request.manifest, descriptors: carried(request.descriptors), redeemScripts: carried(request.redeemScripts) }); } catch (e) { return { ok: false, lines: [`the vault operation could not be described from the verified manifest (${e.message}) — do not sign`] }; }
      const v = doc && Array.isArray(doc.vaultOperations) ? doc.vaultOperations[0] : null;
      if (!v) return { ok: false, lines: ["the verified description carries no vault operation — do not sign"] };
      const lines = [];
      lines.push(`${vaultOpLabel(v.sdkAction)} on vault ${v.vaultId}${v.summary ? ` — ${v.summary}` : ""}`);
      lines.push(`Authority: ${v.mutationClass}; requires the root to run ${v.requiredRootAction === null ? "no root action" : v.requiredRootAction}.`);
      if (v.kas && v.kas.feeReserveBefore && v.kas.feeReserveAfter) lines.push(`Fee reserve: ${v.kas.feeReserveBefore.kas} KAS → ${v.kas.feeReserveAfter.kas} KAS${v.kas.reserveConsumed ? ` (consumed by this transaction: ${v.kas.reserveConsumed.kas} KAS)` : ""}.`);
      if (v.terminal) {
        lines.push(`TERMINAL: this vault is CLOSED; ${v.kas && v.kas.terminalPayout ? `${v.kas.terminalPayout.kas} KAS` : "its fee reserve"} is paid to the pinned recovery key ${v.recoveryPk}.`);
        if (v.token && v.token.recoveredToRecoveryPk && v.token.recoveredToRecoveryPk.atomic !== "0") lines.push(`The entire token position of ${v.token.recoveredToRecoveryPk.atomic} atomic units goes to the same recovery key.`);
      }
      if (v.agentSet !== null && v.agentSet !== undefined) {
        lines.push(v.agentSet.length ? `New delegate rules: ${v.agentSet.length} agent polic${v.agentSet.length === 1 ? "y" : "ies"} — the successor agent root is their Merkle root:` : "New delegate rules: EMPTY — after this operation no agent can pay from this vault until a new set is installed.");
        for (const p of v.agentSet) lines.push(`agent ${p.agentPk}: up to ${p.tokenMaxPerSpend.atomic} per payment, ${p.tokenPeriodBudget.atomic} per ${p.periodLengthDaa} DAA (period starts ${p.periodStartDaa}, spent so far ${p.tokenPeriodSpent.atomic}), fee cap ${p.agentMaxFeePerTx.kas} KAS, KAS carry cap ${p.agentMaxCarryKas.kas} KAS; may pay ONLY ${p.recipients.length} recipient${p.recipients.length === 1 ? "" : "s"}: ${p.recipients.join(", ")}`);
      }
      if (v.asset) lines.push(`Asset: ${v.asset.displayName} (assetId ${v.asset.assetId}).`);
      return { ok: true, sdkAction: v.sdkAction, vaultId: v.vaultId, terminal: !!v.terminal, lines };
    }

    /* ================================================================
     * F-6 — RESERVATION GUIDANCE AND AUTHORIZED WITHDRAWAL (owner-approved
     * backend semantics, sdk/src/wallet-requests-v7.js rejectOrgRootRequest
     * / pendingRootRequests / assertVaultCompletionAvailable): ONE durable
     * pending root transition per root, unsigned-below-quorum included; an
     * owner request naming a vault also guards that vault; ONLY an unsigned,
     * never-attempted request may be withdrawn (the server refuses anything
     * else with CANNOT_REJECT); a finalized request resumes its ORIGINAL
     * submission; an attempted or uncertain request needs outcome recovery
     * (Verify state) before anything can replace it. Dismissing a wallet
     * prompt never releases a reservation. No expiry, no quorum relaxation.
     * ================================================================ */
    const ATTEMPTED_STATES = Object.freeze(["BROADCAST", "CHAIN_SEEN", "SUBMITTING", "SUBMITTED", "RECONCILIATION_REQUIRED"]);
    const TERMINAL_REQUEST_STATES = Object.freeze(["REFUSED", "CHAIN_VERIFIED", "VERIFIED_OUTCOME", "SUBMISSION_REJECTED", "STALE", "FAILED"]);
    function withdrawEligibility(request) {
      if (!request) return { kind: "none", reason: "no request" };
      const st = String(request.state || "");
      const signedSlots = (request.slots || []).filter((s) => s && s.status === "SIGNED").length;
      const attempted = !!(request.submissionAttempt || request.submissionOutcome);
      if (TERMINAL_REQUEST_STATES.includes(st)) return { kind: "none", reason: `this request is ${st} — it holds no reservation` };
      if (ATTEMPTED_STATES.includes(st) || attempted) return { kind: "recover", reason: "this request was handed to the network (or its outcome is unknown): use Verify state on the root — it cannot be withdrawn or replaced until its outcome is proven" };
      if (st === "SIGNED") return { kind: "resume", reason: "this request is finalized (its fee input is signed) — resume it by submitting; a finalized request is never withdrawn" };
      if (st === "AUTHORIZED" && signedSlots > 0) {
        const required = /^[1-9][0-9]*$/.test(String(request.requiredApprovals ?? "")) ? Number(request.requiredApprovals) : null;
        const atQuorum = required !== null && signedSlots >= required;
        return { kind: "collect", reason: `${signedSlots} owner signature${signedSlots === 1 ? "" : "s"} already attached — a request carrying a signature is not withdrawn; ${atQuorum ? "every required approval is collected: the wallet that funds the network fee finalizes it, then anyone submits it" : "collect the remaining approvals, then finalize and submit"}` };
      }
      if (st === "AUTHORIZED") return { kind: "withdraw", reason: "unsigned and never attempted — withdrawing it releases only this request's reservation" };
      return { kind: "none", reason: `this request is ${st || "in an unknown state"} — no withdrawal path is offered` };
    }
    function reservationGuidance({ request, orgRoot } = {}) {
      if (!request) return null;
      const elig = withdrawEligibility(request);
      const vaultOps = Array.isArray(request.vaultOperations) ? request.vaultOperations : [];
      const guardedVaultIds = vaultOps.map((op) => op && op.vaultId).filter(Boolean);
      const label = `${actionLabel(request.action || request.kind)}${vaultOps.length ? ` — ${vaultOpLabel(vaultOps[0].action)} on vault ${short(vaultOps[0].vaultId)}` : ""}`;
      const next = elig.kind === "withdraw"
        ? "Withdraw it (safe: it is unsigned and was never attempted; only its own reservation is released) or continue collecting approvals."
        : elig.kind === "collect"
          ? "Collect the remaining owner approvals, then finalize and submit — a request with a signature attached is not withdrawn."
          : elig.kind === "resume"
            ? "Submit it to the network — the ORIGINAL finalized transaction is resumed, never rebuilt or replaced."
            : elig.kind === "recover"
              ? "Use Verify state (outcome recovery) — nothing new can start on this root until its outcome is proven."
              : "Open it to see its state.";
      void orgRoot;
      return {
        requestId: request.id, label, state: request.state, guardedVaultIds, eligibility: elig, next,
        text: `Request ${label} (${request.id}, ${request.state}) holds this root's transition reservation${guardedVaultIds.length ? ` and guards vault ${guardedVaultIds.map(short).join(", ")}` : ""}: no other governance action or owner operation can be started on this root${guardedVaultIds.length ? " or that vault" : ""} until it completes or is withdrawn. Dismissing a wallet prompt, closing this window or disconnecting the wallet does NOT release it — only a durable withdrawal of an unsigned request, or its proven outcome, does. This reservation is PolicyVault's local coordination, not an on-chain freeze: agent payments continue under the vault's rules. Next: ${next}`
      };
    }

    /* Owner table shared by root detail and requests. */
    function ownerTable(slots, viewerXOnly, statusOf) {
      const rows = (slots || []).map((s) => {
        const mine = viewerXOnly && s.publicKey && String(s.publicKey).toLowerCase() === String(viewerXOnly).toLowerCase();
        return `<tr><td>${esc(s.slot)}</td><td>${esc(s.label || "")}${mine ? ` <span class="badge ver">you</span>` : ""}</td><td class="mono" style="word-break:break-all">${esc(s.address || "—")}</td>` +
          (statusOf ? `<td>${statusOf(s)}</td>` : "") +
          `<td><details class="adv"><summary>key</summary><span class="mono" style="word-break:break-all">${esc(s.publicKey)}</span></details></td></tr>`;
      }).join("");
      return `<table class="mtable"><thead><tr><th>#</th><th>Owner</th><th>Wallet address</th>${statusOf ? "<th>Status</th>" : ""}<th>Public key</th></tr></thead><tbody>${rows}</tbody></table>`;
    }

    function viewerRole(orgRoot, viewerXOnly) {
      if (!viewerXOnly) return { kind: "none", text: "No wallet identity resolved — read-only." };
      const slot = (orgRoot.slots || []).find((s) => s.publicKey && String(s.publicKey).toLowerCase() === String(viewerXOnly).toLowerCase());
      if (slot) return { kind: "owner", slot: slot.slot, text: `You hold owner slot ${slot.slot}${slot.label ? ` (${slot.label})` : ""}: your signature counts toward every quorum.` };
      const succ = orgRoot.template && orgRoot.template.successorPk && String(orgRoot.template.successorPk).toLowerCase() === String(viewerXOnly).toLowerCase();
      if (succ) return { kind: "successor", text: "You are the designated successor: no power now; you can take over alone once the root has been untouched for the successor waiting period." };
      return { kind: "none", text: "This wallet is not an owner of this root — read-only; it cannot approve, freeze, or recover." };
    }

    /* Idle-age progress (ESTIMATE) toward the recovery / succession waits. */
    function idleProgress(orgRoot, currentDaa) {
      const live = orgRoot.live;
      if (!live || live.blockDaaScore === undefined || live.blockDaaScore === null || currentDaa === undefined || currentDaa === null) return null;
      let age;
      try { age = BigInt(String(currentDaa)) - BigInt(String(live.blockDaaScore)); } catch { return null; }
      if (age < 0n) age = 0n;
      const t = orgRoot.template || {};
      const approx = (daa) => (DUR ? DUR.describeDaa(String(daa), { largestUnit: "day" }).text : `${daa} DAA score`);
      const line = (label, delay) => {
        if (delay === undefined || delay === null) return null;
        const d = BigInt(String(delay));
        if (age >= d) return `${label}: the waiting period has passed (root untouched for ${approx(age)}) — eligibility is decided by the chain when the transaction is submitted.`;
        return `${label}: ${approx(d - age)} still to wait (root untouched for ${approx(age)}; estimate).`;
      };
      return { ageDaa: age.toString(), recovery: line("Recovery of control", t.recoveryDelayDaa), succession: line("Succession", t.successionDelayDaa) };
    }

    /* (c) ROOT DETAIL — plain language first, technical details available. */
    function renderRootDetailHtml(orgRoot, opts = {}) {
      /* rootedVaults = the summaries of GET /org-roots/:id/vaults (null when they could not be loaded — the panel then
       * says so and offers nothing); pendingRequest = the pending request record when one is pending (F-6 guidance). */
      const { viewerXOnly = null, currentDaa = null, rootedVaults = null, pendingRequest = null } = opts || {};
      const st = orgRoot.state || {};
      const t = orgRoot.template || {};
      const frozen = !!(st && Number(st.frozen) === 1);
      const pending = orgRoot.pendingRequestId || null;
      const n = (orgRoot.slots || []).length;
      const m = st.ownerM ?? "—", k = st.emergencyK ?? "—", r = Number(st.recoveryM || 0);
      const successionOn = !!(t.successorPk && t.successorPk !== INACTIVE);
      const role = viewerRole(orgRoot, viewerXOnly);
      const progress = idleProgress(orgRoot, currentDaa);
      const canAct = role.kind === "owner";
      const actionBtn = (action, cls, why) => {
        const off = !!pending || !canAct || (frozen && action === "authorize") || (frozen && action === "freeze") || (!frozen && action === "unfreeze") || (action === "ownerRecover" && r === 0) || (action === "succession" && !successionOn);
        const title = pending ? "A request is already pending on this root" : !canAct ? "Only an owner of this root can start this" : why || "";
        return `<button${off ? " disabled" : ""} class="${cls || ""}" data-rootaction="${esc(action)}" data-root="${esc(orgRoot.rootCovenantId)}" title="${esc(title)}">${esc(actionLabel(action))}</button>`;
      };
      const succBtn = successionOn && role.kind === "successor" ? `<button${pending ? " disabled" : ""} class="warn" data-rootaction="succession" data-root="${esc(orgRoot.rootCovenantId)}">${esc(actionLabel("succession"))}</button>` : actionBtn("succession", "warn");
      return (
        `<div class="panel" data-org-root-detail="${esc(orgRoot.rootCovenantId)}">` +
        `<div class="vault-head"><span class="vault-title">${esc(orgRoot.label || orgRoot.rootCovenantId)}</span> ` +
        `<span><span class="badge ${frozen ? "PAUSED" : "ACTIVE"}">${frozen ? "FROZEN" : "ACTIVE"}</span> <span class="badge ver">on-chain organizational root</span></span></div>` +
        statusRegion(`authorityModel: ON_CHAIN_ORGANIZATIONAL_ROOT — this root holds the organization's real owner authority, enforced by the covenant on Kaspa. ${esc(role.text)}`) +
        `<div class="review-sec"><div class="review-head"><h4>Governance at a glance</h4></div>` +
        `<div class="rv-row"><div class="rv-k">Owners</div><div class="rv-v">${n}</div></div>` +
        `<div class="rv-row"><div class="rv-k">Changes need</div><div class="rv-v">${esc(m)} of ${n} owners</div></div>` +
        `<div class="rv-row"><div class="rv-k">Emergency freeze</div><div class="rv-v">${esc(k)} of ${n} owners — stops governance actions; agent payments continue</div></div>` +
        `<div class="rv-row"><div class="rv-k">Recovery of control</div><div class="rv-v">${r > 0 ? `${r} of ${n} owners after the root is untouched for ${esc(approxDelay(t.recoveryDelayDaa ?? "?"))}` : successionOn ? "off — if too many keys are lost, only the designated successor can regain control (after its waiting period)" : "off — if too many keys are lost, control cannot be regained"}</div></div>` +
        `<div class="rv-row"><div class="rv-k">Designated successor</div><div class="rv-v">${successionOn ? `<span class="mono" style="word-break:break-all">${esc(t.successorPk)}</span> after the root is untouched for ${esc(approxDelay(t.successionDelayDaa ?? "?"))}` : "none"}</div></div>` +
        `<div class="rv-row"><div class="rv-k">Status</div><div class="rv-v">${frozen ? `FROZEN — no governance action can be approved for any vault of this organization until ${esc(m)} of ${n} owners unfreeze. Agent payments continue under their existing rules. Owners can still be changed while frozen.` : "Active — governance actions can be approved."}</div></div>` +
        (progress ? `<div class="rv-row"><div class="rv-k">Waiting periods</div><div class="rv-v">${[progress.recovery, progress.succession].filter(Boolean).map(esc).join("<br/>") || "not applicable"}</div></div>` : "") +
        `</div>` +
        ownerTable(orgRoot.slots || [], viewerXOnly) +
        /* R7-05 (browser initiation, launch scope 2026-09-08): one panel per linked vault, rendered from the vault's
         * PRESENTED summary (GET /org-roots/:id/vaults); the owner operations are offered there as ROOT REQUESTS.
         * When the summaries could not be loaded the panel says so and offers no control. */
        ((orgRoot.vaults || []).length
          ? `<div class="review-sec" data-rooted-vaults="${(orgRoot.vaults || []).length}"><div class="review-head"><h4>Rooted vaults (${(orgRoot.vaults || []).length})</h4></div>` +
            (orgRoot.vaults || []).map((vaultId) => {
              const summary = Array.isArray(rootedVaults) ? rootedVaults.find((x) => x && x.vaultId === vaultId) || null : null;
              return renderRootedVaultOwnerOpsHtml(summary || { vaultId }, orgRoot, { viewerXOnly, pendingRequest, networkId: orgRoot.networkId || null, loaded: !!summary });
            }).join("") +
            `</div>`
          : "") +
        (pending
          ? (() => {
              const g = pendingRequest && pendingRequest.id === pending ? reservationGuidance({ request: pendingRequest, orgRoot }) : null;
              return `<div class="opbanner warn" data-root-reservation="${esc(pending)}"${g ? ` data-reservation-next="${esc(g.eligibility.kind)}"` : ""}>${g ? esc(g.text) : "A request is already pending on this root — only one governance transaction can be in flight per root transition. Dismissing a wallet prompt does not release it. Open it below to approve, finalize, submit, verify or withdraw it."}</div>`;
            })()
          : "") +
        `<div class="actions">` +
        actionBtn("authorize", "", "A heartbeat authorization that changes nothing but restarts the recovery and succession waits") +
        actionBtn("rotate", "warn", "Install a new set of owners and rules (allowed while frozen)") +
        actionBtn("freeze", "", "Stops governance actions on every vault; agent payments continue") +
        actionBtn("unfreeze", "warn", "Returns the root to normal operation") +
        actionBtn("ownerRecover", "warn", r === 0 ? "Recovery is off for this root" : "Install new owners after the waiting period (lands frozen)") +
        succBtn +
        `<button data-rootreconcile="${esc(orgRoot.rootCovenantId)}">Verify state</button>` +
        `</div>` +
        `<details class="adv"><summary>Technical details</summary><div class="mono id">` +
        `contract policyvault-0.7-root · generation ${esc(orgRoot.generation ?? 0)} · root nonce ${esc(st.rootNonce ?? "0")} · frozen ${frozen ? "1" : "0"}<br/>` +
        `root covenant id ${esc(orgRoot.rootCovenantId)}<br/>org id ${esc(orgRoot.orgId || "")}<br/>` +
        (orgRoot.live && orgRoot.live.outpoint ? `live outpoint ${esc(orgRoot.live.outpoint.transactionId)}:${esc(orgRoot.live.outpoint.index)}${orgRoot.live.blockDaaScore !== undefined ? ` (created at DAA ${esc(orgRoot.live.blockDaaScore)})` : ""}` : "No live outpoint recorded yet — creation may still be broadcasting. Verify state after the funder signs.") +
        `<br/>recovery delay ${esc(t.recoveryDelayDaa ?? "—")} DAA · succession delay ${esc(t.successionDelayDaa ?? "—")} DAA · max loss per action ${esc(t.rootMaxFeePerTx ?? "—")} sompi` +
        (progress ? `<br/>root output age ${esc(progress.ageDaa)} DAA (estimate from the node's virtual DAA)` : "") +
        `</div></details>` +
        `</div>`
      );
    }

    /* (c) request status: plain language, the viewer's role, collected
     * approvals, remaining waiting conditions, next possible action. */
    function renderRequestDetailHtml(request, opts = {}) {
      const { orgRoot = null, viewerXOnly = null, currentDaa = null } = opts || {};
      // UX-09: approvals are derived from the ACTUAL slot statuses; the
      // server's counter is cross-checked and the smaller count wins (fail
      // closed) with a visible warning when they disagree.
      const slotSigned = (request.slots || []).filter((sl) => sl && sl.status === "SIGNED").length;
      const serverPresent = request.signaturesPresent === undefined || request.signaturesPresent === null ? null : Number(request.signaturesPresent);
      const present = serverPresent === null ? slotSigned : Math.min(serverPresent, slotSigned);
      const countMismatch = serverPresent !== null && serverPresent !== slotSigned;
      const required = request.requiredApprovals ?? "?";
      const outcome = String(request.action || "") === "succession" ? successionOutcome(request.state) : requestOutcome(request.state, { present, required: Number(required) }); // Codex checkpoint 6 (UX-09)
      const statusOf = (s) => `<span class="badge ${s.status === "SIGNED" ? "ACTIVE" : s.status === "REFUSED" ? "PAUSED" : ""}">${esc(s.status === "SIGNED" ? "approved" : s.status === "REFUSED" ? "refused" : "waiting")}</span>`;
      const mySlot = (request.slots || []).find((s) => s.publicKey && viewerXOnly && String(s.publicKey).toLowerCase() === String(viewerXOnly).toLowerCase());
      const successionRoleText = (() => {
        if (String(request.action || "") !== "succession") return null;
        const pinned = successionSignerOf(request, orgRoot);
        const mine = !!(pinned && viewerXOnly && String(viewerXOnly).toLowerCase() === pinned);
        const sig = successionSignatureState(request.state);
        if (!pinned) return "This succession names no consistent designated successor — refusing to describe a signer; do not sign.";
        if (mine) return sig === "signed" ? "You are the designated successor and have signed this succession (root input + your fee input); no owner approval is involved." : sig === "unsigned" ? "You are the designated successor: this succession is authorized by YOUR signature alone (the root input and your own fee input) — no owner-slot approvals are collected." : "You are the designated successor: this succession is authorized by your signature alone.";
        return `This succession is authorized by the designated successor's signature alone (key ${pinned}) — not by owner slots; this wallet is not the successor and only reads it.`;
      })();
      const roleTextOwner = mySlot ? (mySlot.status === "SIGNED" ? `You (owner slot ${mySlot.slot}) have approved.` : mySlot.status === "PENDING" && request.state === "AUTHORIZED" ? `You hold owner slot ${mySlot.slot}: your approval is needed.` : mySlot.status === "PENDING" ? `You hold owner slot ${mySlot.slot}; no further approval is collected — the request is ${request.state === "SIGNED" ? "already finalized" : String(request.state || "").toLowerCase()}.` : `You hold owner slot ${mySlot.slot}.`) : request.kind === "rootGenesis" ? "The funding wallet signs this creation." : "This wallet is not one of the expected signers — read-only.";
      const gate = finalizeGate(request);
      const fuelOwner = fuelOwnerGate(request, viewerXOnly); // Codex checkpoint 6 (UX-03): authority from the fee input's owner key
      /* Codex checkpoint 6 (UX-09): a SUCCESSION is authorized by the pinned successor's ONE signature (root input + its own
       * fee input) — it has no owner slots, collects no owner approvals and is never "finalized" by a fee payer. Its role,
       * progress and next-step text follow that action; an owner-slot description here would be wrong for every viewer. */
      const isSuccession = String(request.action || "") === "succession";
      const pinnedSuccessor = isSuccession ? successionSignerOf(request, orgRoot) : null;
      const viewerIsSuccessor = !!(pinnedSuccessor && viewerXOnly && String(viewerXOnly).toLowerCase() === pinnedSuccessor);
      const successorSigned = isSuccession ? successionSignatureState(request.state) : null;
      let next;
      if (isSuccession) {
        if (request.state === "AUTHORIZED") next = viewerIsSuccessor ? "Approve in wallet (designated successor): your wallet signs the root input and your own fee input in one step and PolicyVault submits it. The network accepts it only once the root has been untouched for the succession waiting period; nothing else is collected." : "Waiting for the designated successor to sign in their wallet — no owner approval is needed or collected. Anyone may submit it afterwards.";
        else if (request.state === "SIGNED") next = "Signed by the designated successor and assembled — submit it to the network.";
        else if (outcome.level === "verified") next = "Complete — verified on the chain.";
        else if (request.state === "RECONCILIATION_REQUIRED") next = "Reconcile first: use Verify state on the root. Do not start a replacement until this request is CHAIN_VERIFIED or closed.";
        else if (request.state === "FAILED") next = "Use Verify state on the root, then start a new request only if the root did not move.";
        else if (outcome.level === "failed") next = "Nothing happened; start a new request if still needed.";
        else next = "Waiting for the network; use Verify state on the root to check.";
      }
      else if (request.state === "AUTHORIZED" && present < Number(required)) next = `Collect ${Number(required) - present} more owner approval${Number(required) - present === 1 ? "" : "s"}, then finalize.`;
      else if (gate.enabled && !fuelOwner.ok) next = `Enough approvals: ${describeFeePayer(fuelOwner.payer)} finalizes it — that wallet funds the network fee and signs the fee input${request.createdBy ? ` (the request was started by ${request.createdBy})` : ""} — then anyone submits it.`;
      else if (gate.enabled) next = "Enough approvals: Finalize — your wallet funds the network fee and signs the fee input, PolicyVault assembles the transaction — then submit it to the network.";
      else if (request.state === "SIGNED") next = "Finalized: submit it to the network.";
      else if (outcome.level === "verified") next = "Complete — verified on the chain.";
      else if (request.state === "RECONCILIATION_REQUIRED") next = "Reconcile first: use Verify state on the root. Do not start a replacement until this request is CHAIN_VERIFIED or closed.";
      else if (request.state === "FAILED") next = "Use Verify state on the root, then start a new request only if the root did not move.";
      else if (outcome.level === "failed") next = "Nothing happened; start a new request if still needed.";
      else next = "Waiting for the network; use Verify state on the root to check.";
      const chainLine = request.chain && typeof request.chain === "object"
        ? `<div class="rv-row"><div class="rv-k">Chain outcome</div><div class="rv-v">predecessor ${esc(String(request.chain.predecessorOutpoint || "?"))} consumed; successor ${esc(String(request.chain.successorOutpoint || "?"))} observed${request.chain.observedAt ? ` at ${esc(String(request.chain.observedAt))}` : ""}</div></div>`
        : outcome.level === "verified" ? `<div class="rv-row"><div class="rv-k">Chain outcome</div><div class="rv-v">recorded as verified, but no chain outpoints are attached to this request — use Verify state on the root to confirm.</div></div>` : "";
      const errorLine = request.error ? `<div class="rv-row"><div class="rv-k">Recorded error</div><div class="rv-v">${esc(String(request.error))}</div></div>` : "";
      let waitLine = "";
      if ((request.action === "ownerRecover" || request.action === "succession") && orgRoot) {
        const p = idleProgress(orgRoot, currentDaa);
        if (p) waitLine = `<div class="rv-row"><div class="rv-k">Waiting condition</div><div class="rv-v">${esc(request.action === "ownerRecover" ? p.recovery : p.succession)}</div></div>`;
      }
      const vaultOps = (request.vaultOperations || []).map((op) => `${VAULT_OP_LABEL[op.action] || op.action} on vault ${op.vaultId}`);
      /* R7-05: the vault operation's consequences from the VERIFIED manifest (fee reserve before/after, terminal payout
       * and recovery key, every installed agent rule and its recipients) — never only the operation's name. */
      const opSummary = vaultOps.length ? vaultOperationSummary(request) : null;
      /* F-6: the authorized next step for the reservation this request holds; withdrawal is offered ONLY when eligible. */
      const elig = isSuccession ? { kind: "none", reason: "" } : withdrawEligibility(request);
      const reservationText = TERMINAL_REQUEST_STATES.includes(String(request.state)) ? null
        : `${elig.reason ? `${elig.reason.charAt(0).toUpperCase()}${elig.reason.slice(1)}. ` : ""}While this request is pending it reserves the root's next transition${vaultOps.length ? " and guards the named vault" : ""}; dismissing a wallet prompt, closing this window or disconnecting the wallet does not release it. This is PolicyVault's local coordination, not an on-chain freeze.`;
      return (
        `<div class="panel" data-org-root-request="${esc(request.id)}">` +
        `<div class="vault-head"><span class="vault-title">${esc(actionLabel(request.action || request.kind))}</span> <span class="badge ${outcome.level === "verified" ? "ACTIVE" : outcome.level === "failed" ? "RECOVERED" : "PAUSED"}">${esc(outcome.title)}</span></div>` +
        statusRegion(`<b>${esc(outcome.title)}</b><div class="f-help">${esc(outcome.meaning)}</div>`, outcome.level === "verified" ? "" : outcome.level === "failed" ? "bad" : "warn") +
        `<div class="review-sec">` +
        (isSuccession
          ? `<div class="rv-row"><div class="rv-k">Authorization</div><div class="rv-v">${esc(successorSigned === "signed" ? "signed by the designated successor (one signature: the root input and the successor's fee input)" : successorSigned === "unsigned" ? "not yet signed by the designated successor — no owner approvals are collected for a succession" : "the successor's signature state is not recorded for this request state")}</div></div>`
          : `<div class="rv-row"><div class="rv-k">Approvals</div><div class="rv-v">${esc(String(present))} of ${esc(String(required))} collected${countMismatch ? ` — <b>warning:</b> the server counts ${esc(String(serverPresent))} but ${esc(String(slotSigned))} owner slot${slotSigned === 1 ? "" : "s"} actually carry a signature; the smaller count is used` : ""}</div></div>`) +
        chainLine + errorLine +
        `<div class="rv-row"><div class="rv-k">Your role</div><div class="rv-v">${esc(successionRoleText || roleTextOwner)}</div></div>` +
        (vaultOps.length ? `<div class="rv-row"><div class="rv-k">Vault operation</div><div class="rv-v" data-vault-operation-summary="${opSummary && opSummary.ok ? "verified" : "refused"}">${opSummary ? opSummary.lines.map((l) => `<div${/^agent [0-9a-f]{64}:/.test(l) ? ' class="mono" style="word-break:break-all;font-size:0.8rem"' : ""}>${esc(l)}</div>`).join("") : vaultOps.map(esc).join("<br/>")}</div></div>` : "") +
        waitLine +
        `<div class="rv-row"><div class="rv-k">Next</div><div class="rv-v">${esc(next)}</div></div>` +
        (reservationText ? `<div class="rv-row"><div class="rv-k">Reservation</div><div class="rv-v" data-reservation-next="${esc(elig.kind)}">${esc(reservationText)}</div></div>` : "") +
        `</div>` +
        ((request.slots || []).length ? ownerTable(request.slots, viewerXOnly, statusOf) : "") +
        ((request.warnings || []).length ? `<div class="f-help">Warnings: ${request.warnings.map(esc).join(", ")}</div>` : "") +
        `<div class="actions">` +
        (isSuccession ? "" : `<button${gate.enabled && fuelOwner.ok ? "" : " disabled"} data-rootfinalize="${esc(request.id)}" title="${esc(gate.enabled ? fuelOwner.reason : gate.reason)}">Finalize (sign the fee input)</button>`) +
        `<button${request.state === "SIGNED" ? "" : " disabled"} data-rootsubmit="${esc(request.id)}" class="primary">Submit to network</button>` +
        /* F-6: withdrawal ONLY for an unsigned, never-attempted request (the server refuses everything else with CANNOT_REJECT);
         * a succession keeps the pinned successor's existing withdrawal offer (single-signer path, no owner slots). */
        (isSuccession
          ? (request.state === "AUTHORIZED" ? `<button class="warn" data-rootreject="${esc(request.id)}">Withdraw request</button>` : "")
          : elig.kind === "withdraw"
            ? `<button class="warn" data-rootreject="${esc(request.id)}" title="${esc(elig.reason)}">Withdraw request</button>`
            : elig.kind === "recover"
              ? `<button data-rootreconcile="${esc(request.rootCovenantId)}" data-rootreconcile-request="${esc(request.id)}">Verify state (recover outcome)</button>`
              : "") +
        `</div>` +
        `<details class="adv"><summary>Technical details</summary><div class="mono id">kind ${esc(request.kind)}${request.action ? ` · action ${esc(request.action)}` : ""}${request.actionClass ? ` · ${esc(request.actionClass)}` : ""} · state ${esc(request.state)}` +
        (request.signerVisibleDigest ? `<br/>signer-visible digest ${esc(request.signerVisibleDigest)}` : "") + (request.manifestHash ? `<br/>manifest hash ${esc(request.manifestHash)}` : "") + (request.txId ? `<br/>txid ${esc(request.txId)}` : "") + `</div></details>` +
        `</div>`
      );
    }

    /* ================================================================
     * (f) DANGEROUS ACTIONS — typed confirmation (plain language first,
     * the fixed warning texts kept verbatim)
     * ================================================================ */
    const DANGEROUS_ACTIONS = Object.freeze(new Set(["ownerRecover", "succession", "rotate", "unfreeze"]));
    function isDangerousAction(action) { return DANGEROUS_ACTIONS.has(action); }
    function dangerousConfirmPhrase(action) { return `CONFIRM ${String(action || "").toUpperCase()}`; }
    function typedConfirmationMatches(action, typed) { return String(typed || "").trim() === dangerousConfirmPhrase(action); }

    const AGE_GATED = new Set(["ownerRecover", "succession"]);
    function renderDangerousConfirmHtml({ action, rootLabel, delayDaa, orgRoot }) {
      const W = core.orgRootExplain.WARNING_TEXT;
      const st = (orgRoot && orgRoot.state) || {};
      const n = orgRoot && orgRoot.slots ? orgRoot.slots.length : null;
      const human = {
        ownerRecover: `Recover control installs a NEW set of owners on the ${st.recoveryM ? `${st.recoveryM} of ${n}` : "recovery"} quorum after the root has been untouched for ${delayDaa ? describeDelay(delayDaa) : "the recovery waiting period"}. It does not move any funds; it changes who governs. The root lands frozen: the installed owners must unfreeze with their own approval quorum (M of N of the new set).`,
        succession: `Succession lets the designated successor install the set of owners it chooses after the root has been untouched for ${delayDaa ? describeDelay(delayDaa) : "the successor waiting period"}. Owner 1 must change; a previous owner keeps authority only if the successor lists that key again. The root lands frozen: the installed owners must unfreeze with their own approval quorum (M of N of the new set).`,
        rotate: `Change owners or rules installs a new set of owners and/or new approval counts on this root. Check every added and removed owner. It is allowed while frozen (to rotate out a compromised key before unfreezing).`,
        unfreeze: `Unfreeze returns the root to normal operation: governance actions on every vault of this organization can be approved again. It needs ${st.ownerM ? `${st.ownerM} of ${n}` : "the approval quorum (M of N of the installed set) of"} owners.`
      }[action] || "";
      const parts = [];
      parts.push(`<div class="opbanner bad" style="border-width:2px" role="status" aria-live="polite" aria-atomic="true" data-dangerous-confirm="${esc(action)}">`);
      parts.push(`<b style="color:var(--bad)">${esc(actionLabel(action))}${rootLabel ? ` — ${esc(rootLabel)}` : ""}</b>`);
      if (human) parts.push(`<div style="margin-top:0.3rem">${esc(human)}</div>`);
      if (action === "ownerRecover") parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.RECOVERY_INSTALLS_NEW_SET)}</div>`);
      if (action === "succession") parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.SUCCESSION_TERMINAL_FOR_PREVIOUS_SET)}</div>`);
      if (action === "rotate") parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.OWNER_SET_CHANGES)} ${esc(W.THRESHOLDS_CHANGE)}</div>`);
      if (action === "unfreeze") parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.AUTHORITY_EXPANDING)} This returns the root to normal operation.</div>`);
      if (AGE_GATED.has(action)) {
        parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.LANDS_FROZEN)}</div>`);
        parts.push(`<div class="hint" style="margin-top:0.3rem">${esc(W.RELATIVE_AGE_GATE)}${delayDaa ? ` The configured delay here is ${esc(String(delayDaa))} DAA score (${esc(describeDelay(delayDaa).replace(/ \(exactly .*\)$/, ""))}).` : ""}</div>`);
        parts.push(`<div class="hint" style="margin-top:0.3rem">While the root is unfrozen, a heartbeat AUTHORIZE signed by its approval quorum resets the idle clock like any other root transaction.</div>`);
      }
      parts.push(`<div style="margin-top:0.5rem">Type <span class="mono">${esc(dangerousConfirmPhrase(action))}</span> to continue. There is no other confirmation for this action.</div>`);
      parts.push(`</div>`);
      return parts.join("");
    }

    /* ================================================================
     * NEW OWNER SET forms (change owners or rules / recover control /
     * succession) — the same rows and "k of N owners" selects as setup.
     * ================================================================ */
    function newOwnerSetDraftFrom(orgRoot, { action, connectedAddress } = {}) {
      const st = (orgRoot && orgRoot.state) || {};
      const slots = (orgRoot && orgRoot.slots) || [];
      const owners = action === "succession"
        ? [{ address: connectedAddress || "", label: "", publicKey: "" }]
        : slots.map((s) => (s.address ? { address: s.address, label: s.label || "", publicKey: "" } : { address: "", label: s.label || "", publicKey: s.publicKey, keyMode: true }));
      return {
        owners: owners.length ? owners : [{ address: "", label: "", publicKey: "" }],
        ownerM: st.ownerM ? String(st.ownerM) : "1",
        emergencyK: st.emergencyK ? String(st.emergencyK) : "1",
        recoveryEnabled: Number(st.recoveryM || 0) > 0,
        recoveryM: Number(st.recoveryM || 0) > 0 ? String(st.recoveryM) : "1",
        successorAddress: connectedAddress || ""
      };
    }
    function newOwnerSetSummary(d, orgRoot) {
      const SU = requireSetup("newOwnerSetSummary");
      const n = ownersOf(d).length;
      const successorPk = orgRoot && orgRoot.template && orgRoot.template.successorPk;
      const successionEnabled = !!successorPk && String(successorPk) !== "00".repeat(32);
      const out = SU.rootRulesSummary({ ...d, successionEnabled, successorAddress: successionEnabled ? String(successorPk) : "", recoveryDelay: { preset: "existing", existingDaa: orgRoot && orgRoot.template && orgRoot.template.recoveryDelayDaa }, successionDelay: { preset: "existing", existingDaa: orgRoot && orgRoot.template && orgRoot.template.successionDelayDaa } });
      const before = (orgRoot && orgRoot.slots ? orgRoot.slots.length : null);
      if (before !== null) out.unshift(`Owners: ${before} now → ${n} after this change.`);
      // Keep the recovery-off sentence; omit only the separate fixed-successor
      // setting, whose delay is not editable on this form.
      return out.filter((s) => !/^(A designated successor|No successor:)/.test(s));
    }
    function renderNewOwnerSetHtml({ action, orgRoot, draft: d, errors, connectedAddress }) {
      const SU = requireSetup("renderNewOwnerSetHtml");
      const err = (k) => (errors && errors.get(k)) || "";
      const F = SU.renderField;
      const n = ownersOf(d).length;
      const m = /^[0-9]+$/.test(String(d.ownerM)) ? Number(d.ownerM) : 0;
      const intro = {
        rotate: "Installs a new set of owners and rules on this root. Every owner listed here holds authority after the change; anyone left out loses it. Allowed while frozen.",
        ownerRecover: "Recover control installs a new set of owners on the recovery quorum after the waiting period. The root lands frozen; the installed owners unfreeze with their own approval quorum (M of N of the new set).",
        succession: "Succession installs the set of owners the designated successor chooses, signed by the successor alone. Owner 1 must differ from the current owner 1; a previous owner keeps authority only if listed again. The root lands frozen; the installed owners unfreeze with their own approval quorum."
      }[action] || "";
      return (
        `<h3 style="margin-top:0">${esc(actionLabel(action))} — new owners and rules</h3>` +
        `<div class="f-help">${esc(intro)}</div>` +
        `<form class="setup-form" data-orgroot-newset autocomplete="off" novalidate>` +
        `<div class="f f-wide${err("owners") ? " f-invalid" : ""}" data-field="owners"><div class="f-label">Owners after the change</div>` +
        SU.renderAddressRows({ kind: "owner", rows: d.owners, withLabel: true, allowKey: true, errors: (errors && errors.get("ownerRows")) || {}, addLabel: "Add owner", placeholder: "kaspa…", min: 1, max: 12, connectedAddress, useConnectedLabel: "Use connected wallet" }) +
        `<div class="ferr" data-err="owners"${err("owners") ? ' style="display:block"' : ""}>${esc(err("owners"))}</div></div>` +
        F({ name: "ownerM", label: "Owners needed to approve changes", control: SU.renderApprovalSelect({ name: "ownerM", count: n, value: d.ownerM, noun: "owners" }), help: n ? esc(ROOT_COPY.APPROVE(m || "k", n)) : "Add owners first.", error: err("ownerM"), wide: true }) +
        F({ name: "emergencyK", label: "Owners needed for an emergency freeze", control: SU.renderApprovalSelect({ name: "emergencyK", count: n, value: d.emergencyK, noun: "owners", max: m || undefined }), help: "Never more than the owners needed to approve changes.", error: err("emergencyK"), wide: true }) +
        `<div class="f f-wide"><div class="f-label">Recovery of control</div>${SU.checkbox({ name: "recoveryEnabled", checked: !!d.recoveryEnabled, label: "Allow the remaining owners to recover control if keys are lost" })}` +
        `<div class="f-help" data-help="recovery">${esc(newOwnerSetRecoveryHelp(d, orgRoot))}</div>` +
        `<div data-recovery-fields="1"${d.recoveryEnabled ? "" : " hidden"}>` + F({ name: "recoveryM", label: "Owners needed to recover control", control: SU.renderApprovalSelect({ name: "recoveryM", count: n, value: d.recoveryM, noun: "owners", max: m || undefined }), help: "Never more than the owners needed to approve changes.", error: err("recoveryM") }) + `</div></div>` +
        (action === "succession" ? F({ name: "successorAddress", label: "Successor wallet (signs this succession)", control: SU.textInput({ name: "successorAddress", value: d.successorAddress, mono: true }), help: "Must be this root's designated successor; the connected wallet signs.", error: err("successorAddress"), wide: true }) : "") +
        SU.renderLiveSummary(newOwnerSetSummary(d, orgRoot), "v4-newset-summary") +
        `<div class="modal-actions"><button type="button" data-setup-cancel="1">Cancel</button><span class="setup-nav-spacer"></span><button type="submit" class="primary">Continue</button></div>` +
        `</form>`
      );
    }
    async function validateNewOwnerSetDraft(d, { action, orgRoot } = {}) {
      const SU = requireSetup("validateNewOwnerSetDraft");
      const full = { ...d, recoveryDelay: { preset: SU.RECOVERY_SETTING.defaultPreset }, successionDelay: { preset: SU.SUCCESSION_SETTING.defaultPreset }, successionEnabled: false, rootValueKas: "1", rootMaxFeePerTxKas: "0", signerAddress: "x", label: "" };
      const errors = new Map();
      for (const step of ["owners", "approvals", "emergency"]) {
        const v = await SU.validateRootDraft(full, { resolve: (a) => api.resolveXOnly(a), step });
        for (const [k, val] of v.errors) if (k !== "recoveryDelay" && k !== "successionDelay" && k !== "successorAddress") errors.set(k, val);
      }
      if (action === "succession") {
        const s = String(d.successorAddress || "").trim();
        if (!s) errors.set("successorAddress", "Enter the successor's wallet address.");
        else { try { await api.resolveXOnly(s); } catch (e) { errors.set("successorAddress", `Successor address rejected: ${e.message}`); } }
      }
      if (errors.size) return { ok: false, errors, params: null };
      const v = await SU.validateRootDraft(full, { resolve: (a) => api.resolveXOnly(a) });
      if (!v.ok) return { ok: false, errors: v.errors, params: null };
      try {
        const norm = await normalizeNewOwnerSet({ owners: v.form.owners, ownerM: v.form.ownerM, emergencyK: v.form.emergencyK, recoveryM: v.form.recoveryM });
        if (action === "succession" && orgRoot && orgRoot.slots && orgRoot.slots[0] && norm.ownerSet.owners[0] === String(orgRoot.slots[0].publicKey).toLowerCase()) {
          errors.set("owners", "Owner 1 must change in a succession (the covenant requires a different first owner).");
          return { ok: false, errors, params: null };
        }
        return { ok: true, errors, params: norm.params, ownerRows: norm.ownerRows };
      } catch (e) {
        const reason = (e.cause && e.cause.code) || e.code || "";
        const field = { M_ABOVE_ACTIVE: "ownerM", K_ABOVE_M: "emergencyK", R_ABOVE_M: "recoveryM" }[reason] || "owners";
        errors.set(field, e.message);
        return { ok: false, errors, params: null };
      }
    }

    return {
      /* rendering */
      renderGenesisPolicyPanelHtml,
      renderRootDetailHtml,
      renderRequestReviewHtml,
      renderRequestDetailHtml,
      renderDangerousConfirmHtml,
      renderOnChainRootSummaryHtml,
      rootCreationAvailability,
      renderRootedVaultOwnerOpsHtml,
      /* rooted-vault owner operations — browser initiation (R7-05) and reservation / withdrawal guidance (F-6) */
      VAULT_OPS, VAULT_OP_ORDER, SUPPORTED_ROOTED_PROFILE, vaultOpLabel, vaultOpInfo, vaultOpAvailability, vaultOpConfirmPhrase, vaultOpConfirmationMatches,
      vaultOpDraftFrom, validateVaultOpDraft, renderVaultOpFormHtml, vaultOperationSummary, withdrawEligibility, reservationGuidance,
      /* guided setup (owner UX directive 2026-09-05) */
      ROOT_STEPS, ROOT_COPY, FEE_ESTIMATE, VAULT_OP_LABEL,
      actionLabel, describeDelay, approxDelay, recoveryHelpText, successionHelpText, newOwnerSetRecoveryHelp, fuelInputIndex, fuelOwnerGate,
      renderGenesisSetupHtml, renderGenesisDraftReviewHtml, validateGenesisDraft, renderGenesisReviewHtml,
      genesisCrossCheck: (args) => requireSetup("genesisCrossCheck").genesisCrossCheck(args),
      newOwnerSetDraftFrom, newOwnerSetSummary, renderNewOwnerSetHtml, validateNewOwnerSetDraft,
      /* wizard / normalization */
      normalizeWizardGenesis,
      normalizeNewOwnerSet,
      /* dangerous-action confirmation */
      isDangerousAction,
      dangerousConfirmPhrase,
      typedConfirmationMatches,
      /* outcome ladder */
      requestOutcome,
      isVerifiedRequestOutcome,
      finalizeGate, describeReconcileOutcome, requestOutcome, successionOutcome, successionSignatureState, successionSignerOf, feePayerOf, describeFeePayer,
      /* network */
      fetchOrgRoots, fetchOrgRoot, fetchRequests, fetchRequest, fetchSlotRequest, fetchRootedVaults,
      createGenesisRequest, signGenesisRequest, signSingleSignerRequest, createRootRequest, postSlotSignature, finalizeRequest, submitRequest, rejectRequest, reconcileRoot,
      createRootedVault, buildDelegateRequest, signDelegateRequest, submitDelegateRequest,
      /* slot signing */
      signOwnSlot, validateImportedEnvelope, bindRootSigningPayload, parseSigningPayload,
      /* error display mapping */
      displayCodeFor,
      V7_REFUSAL_CODES
    };
  }

  const surface = { createModule };
  if (typeof window !== "undefined") window.PolicyVaultOrgRootUI = surface;
  if (typeof module !== "undefined" && module.exports) module.exports = surface;
})();
